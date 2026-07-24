# Plan — Unified step-up & proofing, Ping-native

**Status:** design locked 2026-07-21. **Spikes done 2026-07-22 (findings below) — building next.**
Supersedes the old "Phase F: Real CIBA push" (task #41) and reshapes P2/P3/P7 (#46/#47/#51).
Companion memory: `agentic-authz-ceremony-vs-token-architecture`, `pf-rar-over-ciba-gap`.

## 0. Progress & findings (2026-07-22) — read this before §4

Both spikes ran on local ephemeral PF; results **change the payment plan**:

- **Payment "auto-issue" is the BFF/app layer, NOT PingFederate.** PF's CIBA gates correctly —
  the token endpoint holds at `authorization_pending` until a real approval. The full stack
  (`autoCiba` request policy → `p1CibaAuth` PingOne MFA CIBA authenticator → `rarPazProc` +
  `payment_initiation` type) **already exists in `data.zip`**; Phase F was ~built at the PF layer.
  The auto-continue is the ROPC **sim bridge** / premature `/stepup/status` in `demo/app/app.py`.
  → The core fix is BFF-layer, not a PF rebuild.
- **RAR over CIBA WORKS on PingFederate with FLAT delivery** (empirically, stub-proven on 13.0.3
  and 13.1.0.5): flat-parameter `authorization_details` runs the full pipeline (processor
  `enrich()` → authenticator receives the detail → **issued token carries the RFC 9396
  `authorization_details` claim**). It is **BROKEN only when the details ride inside the SIGNED
  request object** — a localized PF product defect. Since FAPI-CIBA mandates signed requests, the
  original plan's "RAR inside the signed CIBA `request` JWT" (§4 P3) is **not achievable on
  current PF**; use **flat delivery** (`cibaRequireSignedRequests=false`, confidential client
  auth still applies) to carry the real governed RAR in the token — or lodged-intent / Grant
  Management for a FAPI-conformant path. A minimal from-scratch reproduction of the defect lives
  at `~/Source/pf-ciba-rar-repro` (to file with Ping). See memory `pf-rar-over-ciba-gap` and the
  `rar-over-ciba` skill.
- **Proofing Q1 DONE:** the verifier's `/op` facade now emits OIDC4IDA `verified_claims` for the
  mDL path (`~/Source/idp-pf-vcs/services/verifier/src/index.ts`, uncommitted, `tsc` clean).
  Q1b (the PF OIDC IdP connection that federates it) is the remaining proofing spike.

## 1. Goal

Make the interactive step-up **highly secure and internally consistent**, replacing two weak seams:

- **Payment** appears to auto-issue in ~8s with no real tap. **Root cause (proven §0): the BFF/app
  layer** — the demo leans on a **password-grant sim bridge** / premature `/stepup/status`, never
  redeeming the real CIBA outcome (which *does* gate at `authorization_pending`). PF's CIBA stack
  is present and gates correctly; the fix is in `demo/app/app.py`, not PF.
- **Proofing** is correctly gated on the verifier's cryptographic result, but via a **BFF-side
  poll + self-asserted directory write** (`demo/app/app.py:210-256`, esp. `:244-247`) — the
  proofing "truth" is a mutable row the client writes, not a signed assertion from an authority.

## 2. Architecture (locked)

Separate **the human's act of authorizing** (a ceremony that yields a *signed assertion*) from
**issuing the delegated token** that carries it.

- **PingOne / DaVinci = ceremony + orchestration layer.** DaVinci is the **browser front-door
  orchestration brain** (login, signup, passkey enrolment, consent, step-up, risk) and may call
  our services over HTTP.
- **PingFederate = token + delegation layer** (RAR `authorization_details`, RFC 8693 exchange,
  `act`/`may_act` nesting, CIBA, sender-constraint, audience). PF **consumes assertions; it does
  not run ceremonies.**
- **Ping Authorize (PDP)** consumes the PF token.

**Organising principle:** *leverage the Ping product as much as possible — custom code ONLY where
Ping has a genuine product gap.*

**Path decision = A (lean on Ping), not B (own the device stack):** keep the **PingOne Mobile SDK**
in the ios-approver (its device pairing + "mobile-payload" device-identity JWT are
proprietary/undocumented — not supportably reimplementable), so **no custom PF OOB authenticator**.

| Concern | Owner | Ping / custom |
|---|---|---|
| Browser front door (login, signup, enrolment, consent, step-up, risk) | DaVinci | Ping |
| Payment approval (decoupled) | PingOne MFA CIBA authenticator (PF Integration Kit) | Ping |
| Token / delegation / federation | PingFederate | Ping |
| Authorization decision | Ping Authorize | Ping |
| Identity proofing — mDL over DC-API | our verifier | **custom — the one real gap** |
| Device app (push, attestation, approve/deny) | PingOne Mobile SDK in the app | Ping |

## 3. Research verdicts grounding this (2025–26 docs)

- **PingOne MFA = approve/deny + assurance signals only** (biometric, number-match, device
  attestation). Can *display* txn detail (template vars) + carry a short `binding_message` / opaque
  `clientContext` string, but **cannot** push a structured OpenID4VP/RAR request out, nor return a
  txn-bound signed artifact. Confirms our ~20-char `binding_message` ceiling. But it **is** a
  shipping **PF CIBA OOB authenticator** (PingOne MFA Integration Kit).
- **PingOne Credentials/Neo** verifies **W3C JWT-VC / DID only** — no ISO mdoc/mDL, no DC-API, no
  IACA, no `verified_claims`. Cannot replace our verifier.
- **PingOne Verify** = document+selfie IDV; emits **OIDC4IDA `verified_claims`** and federates via
  the **Verify Integration Kit** IdP adapter (attribute-contract mapping). Not a wallet mDL
  presentation. Notably, even Verify does **not** emit IDA in OIDC out-of-the-box
  (https://docs.pingidentity.com/pingone/identity_verification_using_pingone_verify/p1_verify_ida.html).
- **RAR on CIBA (EMPIRICALLY RESOLVED, supersedes the docs guess):** PF lists CIBA as RAR-supported,
  but behaviour is: **works with FLAT `authorization_details`** (full pipeline + token claim,
  proven), **broken inside the SIGNED `request` JWT** (dropped before type resolution — a PF product
  defect, confirmed 13.0.3 + 13.1.0.5 with a stub authenticator). FAPI-CIBA mandates signed requests
  → the "RAR inside the signed CIBA request JWT" path is blocked on current PF. **Use flat delivery**
  (`cibaRequireSignedRequests=false`) to carry real RAR in the token, or lodged-intent/Grant
  Management for FAPI conformance. The earlier `ciba.tf:125-127` "authorization-endpoint-only" note
  was a wrong generalisation from an ROPC test. Repro: `~/Source/pf-ciba-rar-repro`.

## 4. Workstreams

Each is led by a cheap **de-risking spike** that settles the one unproven thing, then the build.
**Everything is config-as-code + the ephemeral-PF loop; nothing via the admin console.** Run the
probe-level Alice/any-user regression after every shared-component deploy.

### Workstream P — Payment: real gated CIBA + flat-RAR in the token

**P0 spike: DONE (§0).** Findings retire most of the original P1/P2 (the PF stack already exists and
gates correctly) and change P3 (flat, not signed, delivery). Remaining work:

- **P-fix-1 (the core bug — BFF layer).** In `demo/app/app.py`, make the payment step-up consume the
  **real gated CIBA outcome**: fire `/as/bc-auth.ciba` and poll `/as/token.oauth2`
  (`grant_type=urn:openid:params:grant-type:ciba`) — which correctly returns `authorization_pending`
  until the phone approves — instead of the ROPC sim bridge / a premature `/stepup/status` approval.
  This is the fix for "immediately continues". Assurance = **device-approved** on a real
  approve+biometric via the existing `p1CibaAuth` PingOne MFA authenticator (already in `data.zip`).
- **P-fix-2 (real RAR in the token — optional but the whole point).** Switch the payment CIBA to
  **flat `authorization_details`** delivery (`cibaRequireSignedRequests=false` on the payment CIBA
  client; confidential client auth stays) so the pipeline runs and the **issued token carries the
  governed `payment_initiation` RAR** (`rarPazProc` → Ping Authorize at issuance, RFC 9396 §9.1
  claim). This replaces the identity-hint workaround with the real auditable object. *Do NOT put the
  RAR inside a signed request object — that path is the PF defect (§0). Keep the client confidential
  (private_key_jwt/secret); only the request-object signing requirement is dropped.*
- **P-fix-3 (only if FAPI-CIBA conformance is required).** Flat delivery sacrifices the signed-request
  guarantee. For a conformance claim, use **lodged-intent / Grant Management** (`grant_id` reference
  in the request) — converges with the GM workstream (tasks #78–84). Otherwise flat is fine for the
  internal/agentic demo.
- **Retired from the old plan:** building the PingOne MFA CIBA authenticator + request policy (P1) —
  they already exist (`autoCiba`/`p1CibaAuth`); a CIBA-context RAR token mapping via the *enrich* path
  (P2) — not needed on the flat path, where PF adds the §9.1 claim itself; the client-attestation
  `requested ⊆ attested` backchannel ceiling — unproven and secondary; verify separately if wanted.
- **Honest ceiling:** device-approved, not device-signed. On-device dynamic-linking *display* is
  unreachable (20-char `binding_message`; no txn-bound signature from MFA). **Device-signed is the
  FIDO2 follow-on** (WebAuthn challenge = txn hash), still Ping — out of scope here (§6). Load the
  `transaction-authorization` skill before finalizing the payment section.

### Workstream Q — Proofing: verifier → PF `verified_claims` federation

- **Q1. DONE (2026-07-22, uncommitted, `tsc` clean).** Upgraded the verifier's **existing OIDC OP
  facade** (`~/Source/idp-pf-vcs/services/verifier/src/index.ts`): `OpSession` carries
  `credentialKind`; `/op/authorize` selects mDL via `?cred=mdl` or an `mdl` scope (default `pid`,
  unchanged); `/op/token` emits the OIDC4IDA `verified_claims` object for the mDL path +
  `document_number`, `sub=mdl:{document_number}`; `claims_supported` extended. Target structure:
  ```json
  { "verified_claims": {
      "verification": {
        "trust_framework": "au_tdif", "assurance_level": "IP2",
        "time": "<verifiedAt>", "verification_process": "<session.id>",
        "evidence": [{ "type": "document", "method": "oid4vp", "time": "<verifiedAt>",
          "check_details": [{ "check_method": "vcrypt", "organization": "IDPARTNERS-VERIFIER" }],
          "document_details": { "type": "driving_permit", "document_number": "<num>",
            "issuer": { "name": "<issuing_authority>", "country": "AU" },
            "date_of_expiry": "<expiry_date>" } }] },
      "claims": { "given_name": "<gn>", "family_name": "<fn>" } } }
  ```
  (OIDC4IDA 1.0: https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html)
- **Q2.** Add `issuing_authority`, `issuing_country`, `expiry_date` to the mDL **issuance profile**
  (`~/Source/idp-pf-vcs/packages/shared/src/index.ts:121`) **and** the verifier **DCQL**
  (`index.ts:248-252`) — prereq for the rich `document_details`. Until then emit `document_details`
  with `type` + `document_number` only.
- **Q3.** PF: add an **OpenID Connect IdP connection** consuming the verifier OP; map
  `verified_claims` (nested → one connection attribute + a short OGNL re-emit) into the authn
  session → assertion / ATM. Terraform (`pingidentity/pingfederate` provider). This is the seam that
  **structurally removes the BFF self-assertion** — PF is the RP establishing the subject +
  `verified_claims` from a signed IdP assertion. (Mirrors the Verify IK propagation:
  https://docs.pingidentity.com/integrations/pingone/pingone_verify_integration_kit/pf_p1_verify_ik_configuring_an_adapter_instance.html)
- **Q4.** DaVinci (front-door brain) orchestrates the browser-present proofing via its HTTP
  connector → verifier / the OP redirect.
- **Q5.** Remove the BFF self-assertion (`demo/app/app.py:210-256`, `:244-247`). Keep a
  **write-back sink**: PF (or the verifier under PF's established subject) persists the same IDA into
  the proofing-directory / IDM `identityProofingRecord` (`demo/proofing-directory/idm_store.py:101-117`)
  for the PDP gate + audit — the mirror of PingOne Verify's "Store Verified Claims."
- **Q6.** Adapter / PDP: source `identity_proofing_present` from the **PF-established
  `verified_claims`** (or the PF-written record) rather than a BFF-written row
  (`authzen-adapter/authzen-pdp.go`).

## 5. Sequencing

1. **P0 and Q1 spikes: DONE (§0).** P0 resolved RAR-over-CIBA (flat works, signed is a PF defect) and
   proved PF gates correctly; Q1 emitted `verified_claims`. Q3 (OP-facade→PF federation) is the one
   remaining spike; `demo-pf-p0` (ports 9995/9036) is up for it.
2. **Build next:** **P-fix-1** (BFF real-CIBA gating — the highest-visibility bug fix) → **P-fix-2**
   (flat-RAR in the token) → **Q3** (PF OIDC connection, removes the self-assertion) → **Q2/Q4–Q6**.
3. DaVinci stays the browser front-door brain throughout; PF is the pure token/delegation/federation
   layer.
4. **Everything so far was local/ephemeral — the live staging demo is unchanged.** Each fix lands via
   the config-as-code + ephemeral-PF loop (PF) and the per-service Railway deploy (BFF/verifier), with
   the probe-level regression after each shared-component deploy.

## 6. Out of scope / follow-ons

- **Device-signed / dynamic linking** for payment: FIDO2/WebAuthn with challenge = txn hash (still
  PingOne). The top assurance rung; deferred by explicit decision.
- **Consent (generic)** already runs via the DaVinci consent flow.
- **Intent** — future, not now.

## 7. Dependencies & risks

- **PingOne MFA env + approver enrolled as a PingOne MFA device.** `p1CibaAuth` + `autoCiba` already
  exist in `data.zip` and gate correctly on the ephemeral PF; confirm the staging PingOne MFA env +
  the approver device are wired so a real tap resolves the poll (the last live-E2E unknown).
- **Flat delivery drops the FAPI-CIBA signed-request guarantee** (P-fix-2). Acceptable for the
  internal/agentic demo; for a conformance claim use lodged-intent/Grant Management (P-fix-3).
- **RAR-in-signed-request is a PF product defect** (§0) — do not build on it; repro filed at
  `~/Source/pf-ciba-rar-repro`.
- Operational traps to respect: `paz-pap-version-skew`, `ping-license-monthly-expiry` (next due
  ~2026-08-12), `pingfederate-deploy-flakiness` (per-service `--path-as-root` rules),
  `banking-policy-package-lineage` (author on `banking-mdl-gate`, not AuthZEN.snapshot),
  `rule-dont-break-interactive-demo`.

## 8. Verification

- Probe-level any-authenticated-user payment (both amounts) + origination green through the two
  stacks after each shared-component deploy.
- Payment: **no auto-issue** — the step-up holds at `authorization_pending` and the token only issues
  after a real approve+biometric; the issued token carries the governed `payment_initiation` RAR
  (flat delivery, RFC 9396 §9.1 claim).
- Proofing: the BFF no longer POSTs proofing; `identity_proofing_present` derives from a
  PF-established `verified_claims`; second origination for the same account permits without
  re-proofing until expiry.
- Staging PF attestation log line present. Production untouched.
