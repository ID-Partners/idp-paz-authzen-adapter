# Autonomous agent demo — Kafka-triggered payment, authorised by Bob via CIBA + PingOne MFA

An autonomous variant of the interactive demo. A payment event arrives on a **Kafka** topic;
a **stream processor** hands it to a headless **orchestration agent** whose principal is
**Bob** (a bank employee). Before the agent can act, Bob must approve — out of band — via a
**FAPI-CIBA** flow: PingFederate sends a **PingOne MFA** push to Bob's phone showing the
specific payment; Bob approves with Face ID; the agent receives a delegated token
(`sub=bob, act={agent}`) carrying the governed payment, and executes it through the existing
Kong PEPs + bank-api.

```
Kafka payment.requested ─▶ stream-processor ─▶ autonomous-agent (principal=Bob)
                                                   │ CIBA backchannel (signed request, RAR, binding_message)
                                                   ▼
                                          PingFederate (CIBA OP) ─▶ PingOne MFA ─push─▶ Bob's phone (Face ID)
                                                   │ poll → delegated token (sub=bob, act=agent)
                                                   ▼
                                          execute payment via Kong PEP + bank-api
```

## Components
| Dir | Role | Status |
|-----|------|--------|
| [`ciba-cli/`](ciba-cli) | throwaway CIBA test client (Phase-1 proof) | ✅ scaffolded |
| [`stream-processor/`](stream-processor) | Kafka consumer → dispatches to the agent | ✅ scaffolded |
| `autonomous-agent/` | headless agent + **live dashboard**: CIBA-authorise Bob, then execute | ✅ built (sim mode) |
| iOS app | Bob's approval app (Phase 3) — stock PingOne/PingID app first, then custom (PingOne MFA SDK) | ⏳ later |

## Live dashboard (Phase 4 — observability)

The `autonomous-agent` service serves a live dashboard at **`/`** that visualises a payment
flowing through the identity plane in real time (SSE): *event on the stream → CIBA backchannel
→ PingOne MFA push to Bob's phone → Bob approves (Face ID) → delegated token (sub=bob,
act={agent}, RAR) → execute via Kong PEP*. Deployed:
**https://autonomous-agent-production-56b9.up.railway.app/**

Two modes, chosen at boot:
- **SIMULATE** (default; `SIMULATE=1`) — scripts the stages and lets you approve/deny as "Bob"
  from the dashboard's phone mock, minting a **real ES256** delegated token so the token panel
  shows a genuine `sub=bob` / `act={agent}` / RFC-9396 `authorization_details` chain. Demoable
  now, before the CIBA identity plane is wired.
- **REAL** (`SIMULATE=0` + `PF_BASE` + `CIBA_CLIENT_ID`) — performs the actual FAPI-CIBA flow
  against the live PingFederate/PingOne (mirrors `ciba-cli`), polling the token endpoint until
  Bob approves the real push. Swaps in once Phase-1 (below) lands.

The `stream-processor` `POST /process` and the dashboard's **Inject** button share one code
path — the dashboard is just Kafka-minus-Kafka for demoing without a broker.

> ⚠️ Railway bind: the service must bind **`0.0.0.0`** (not `::`) — the public edge routes over
> IPv4, so an IPv6-only bind 502s. `PORT=8000` matches the domain's target port.

---

# Phase 1 — stand up CIBA + PingOne MFA (do this first)

Goal: prove the identity flow end-to-end with the **stock Ping mobile app** and the
[`ciba-cli`](ciba-cli) test client, before any Kafka/agent/iOS code. Split of work: **you**
configure PingOne; **I** configure PingFederate; we verify together with `ciba-cli`.

## A. PingOne (you) — what I need + the steps

**Send me:** your PingOne **region** (NA/EU/CA/AP) and **Environment ID**.

1. **User "Bob"** — Directory → Users → add a user (note the exact `username`/`email`; that's
   the CIBA `login_hint`).
2. **MFA policy** — Authentication → MFA → add a policy that enables a **mobile app / push**
   method, with **pairing allowed**. (For Phase 1 use the stock **PingID** mobile app method;
   the custom app comes in Phase 3.)
3. **Worker application** (this is what PingFederate uses to drive MFA) — Applications → add →
   **Worker**. After creating it, grant it the **Identity Data Admin** role scoped to this
   environment (Roles → Grant Roles). Send me its **Client ID + Client Secret + Environment ID**
   (or the "credential blob" PingOne shows for PingFederate connections).
4. **Pair Bob's device** — install the **PingID** app on the test phone, sign in as Bob, and
   pair it per the MFA policy (scan the QR / enter the pairing key). Confirm a test push
   works.
5. *(Phase-3 only, can wait)* **Native application + APNs** — for the custom iOS app: add a
   **Native** app, Configure for iOS (Bundle ID), Add Push Notifications, upload the APNs
   **.p8** key + **Key ID** + Apple **Team ID**.

## B. PingFederate (me) — status + the one thing I need from you

**✅ Already done / confirmed on the live PF:**
- **CIBA is enabled.** OP metadata advertises `backchannel_authentication_endpoint:
  /as/bc-auth.ciba`, the `urn:openid:params:grant-type:ciba` grant, delivery modes
  **poll + ping**, and request-object signing incl. **ES256** (what our client uses). So the
  CIBA *grant plumbing* is on — no change needed there.
- **Agent CIBA client** — key minted (`ciba-cli/ciba-key.pem`, gitignored; public JWK in
  `ciba-cli/ciba-pub-jwk.json`) and its registration is scripted in
  `ciba-cli/register-ciba-client.sh` (CIBA grant, private_key_jwt, poll, signed requests,
  `payment_initiation` RAR enabled). I'll apply it once the request policy exists.

**⛔ The dependency I need from you (besides the worker creds):** the **PingOne MFA Integration
Kit** (the add-on that provides the *PingOne MFA CIBA Authenticator*). It's a PingFederate
add-on you download from the Ping downloads/marketplace with your Ping account — please grab
it and share the zip, so I can bake it into the PF image (same way we baked the RAR plugin).
Without it there's no OOB push authenticator.

**Then (me), once the IK jar + worker creds are in hand:**
1. **PingOne Connection** — System → External Systems → PingOne Connections → add (worker
   Client ID + Secret + Environment ID from A.3).
2. **CIBA Authenticator** — a **PingOne MFA CIBA Authenticator** instance → the PingOne
   Connection + a notification template.
3. **CIBA Request Policy** — bound to that authenticator; user from `login_hint`; require a
   signed request (FAPI).
4. **Apply the agent CIBA client** (`register-ciba-client.sh` with the policy id).

**⚠️ Issuer/aud nuance:** the PF issuer is `https://localhost:9031` (internal runtime baseUrl),
even though we reach it on the public host. The signed request object's `aud` may need to be
that issuer value rather than the public URL — `ciba-cli` exposes `ISSUER=` for exactly this;
we'll confirm empirically in step C.

## C. Verify (together) with `ciba-cli`

```bash
cd demo/ciba-cli && pip install -r requirements.txt
python ciba.py genkey                       # → paste the JWK into the PF client (step B.4)
PF_BASE=https://<pf-host> CLIENT_ID=<agent-ciba-client> LOGIN_HINT=<bob> \
  AMOUNT=150 FROM=CHK-1001 TO=SAV-1002 python ciba.py run
# → Bob gets a push "Approve payment 150.00 AUD from CHK-1001 to SAV-1002" → Face ID →
#   the CLI prints the delegated token: sub=bob, act={agent}, authorization_details=[…]
```

## ⚠️ Open risk to resolve in Phase 1: RAR over CIBA

RFC 9396 permits `authorization_details` in a CIBA backchannel request, **but PingFederate's
CIBA endpoint docs don't list it** — so PF accepting our per-payment RAR is *unverified*. The
`ciba-cli` carries the RAR inside the FAPI **signed request object** (best chance PF honours
it). If PF rejects/ignores it, the fallbacks are: (a) carry the payment in `binding_message`
+ scope for Bob's approval, and apply RAR governance at a later token-exchange hop instead of
on the CIBA token; or (b) confirm RAR-on-CIBA support with Ping. We'll know as soon as we run
step C. `--flat` on the CLI drops the signed request object if the PF request policy isn't in
FAPI mode while debugging.

## Key facts (verified against Ping docs / specs)
- Backchannel endpoint: **`/as/bc-auth.ciba`**; token `grant_type=urn:openid:params:grant-type:ciba`.
- Delivery: **poll** or **ping** only (FAPI-CIBA prohibits push).
- Client auth: **private_key_jwt** (or mTLS); FAPI-CIBA **requires a signed request object**.
- Poll errors: `authorization_pending`, `slow_down`. Response: `auth_req_id`, `expires_in`, `interval`.
- MFA plumbing: PingOne **MFA Integration Kit** → **PingOne MFA CIBA Authenticator**; PF↔PingOne
  via a **Worker app** (Identity Data Admin role) + a **PingOne Connection**.
