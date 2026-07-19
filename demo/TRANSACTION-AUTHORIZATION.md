# Design note — transaction authorization for agentic banking

**Status:** design review, 2026-07-20. Supersedes the implicit design in the passkey step-up.
**Audience:** whoever next touches payment approval, consent, or the payments policy.

Every normative claim below was checked against the live specification text on 2026-07-20; where a
claim could not be verified it says so explicitly. Two claims I asserted verbally during the review
turned out to be **wrong** and are corrected here (§3.4, §3.5).

---

## 1. What prompted this

Alice's agent initiates a payment. The gateway denies, the user is stepped up, approves with a
passkey — and the payment is denied again. The loop is real, and diagnosing it exposed something
more important than the bug.

## 2. The defect: there is no non-repudiation today

Observed directly from the running PDP payload:

```
user_scope           : "... banking:payments:transfer"      ← scope IS present
authorization_details: []                                    ← empty
rar_amount_ok        : false
rar_creditor_ok      : false
→ decision DENY, obligation "step-up-required"
```

The scope is fine. The policy denies because the **transaction detail never reaches it**. And the
deeper problem is *why* it can't: in the current design

- the passkey signs a **random challenge** (`generate_authentication_options()`),
- the payment detail lives in a **separate signed cookie**,
- the consent is a **separate row** the application writes to its own directory after the fact.

So the authenticator's signature **does not cover the transaction**. The user signed *something*;
the application asserts it was AUD 550 to SAV-1017. In a dispute that proves nothing — the
application is both the witness and the beneficiary.

**Test for this smell anywhere:** *can the consent record be produced without the signature?* If
yes, there is no binding. Here, trivially yes.

**Corollary that matters for planning:** moving the consent screen (app → hosted → DaVinci flow)
does **not** fix this. Relocating the UI changes who renders the pixels, not what the signature
covers. Placement and binding are independent problems, and only the second one is the hard one.

## 3. Standards baseline (cross-checked)

### 3.1 The requirement has a regulatory name: dynamic linking
**PSD2 RTS Article 5.** The authentication code must be **dynamically linked to the amount and the
payee**, and **any change to either invalidates it**; the payer must be made aware of both at the
time of authorization. That is the shape of a defensible transaction authorization. Three
obligations fall out: the instruction is *displayed on something trustworthy*, the user's key
*signs over it*, and the AS *verifies that binding* before issuing anything that moves money — and
the artefact is *retained*.

### 3.2 FAPI 2.0 Security Profile does not give non-repudiation
FAPI 2.0 Security Profile (Final, Feb 2025) mandates PAR, PKCE S256, sender-constrained tokens and
`iss` — it does **not** sign HTTP messages. Non-repudiation requires layering **FAPI 2.0 Message
Signing** (Final, Aug 2025). Claiming non-repudiation from the Security Profile alone is a
conformance error.

*Local relevance:* **AU CDR** does not mandate PAR and **does** mandate **JARM** (with JAR request
objects). If CDR alignment matters here, signed request/response objects are already the idiom and
Message Signing is a shorter walk than for a PAR-only FAPI 2.0 deployment.

### 3.3 RAR is the carrier, not the proof
RFC 9396 `authorization_details` is the correct way to *express* the instruction and bind it to the
grant. But a RAR inside a token proves only that the AS put it there. The proof is the signature
over it. RAR without a signature over the same content is structured intent, not evidence.

### 3.4 CORRECTION — WebAuthn has *no* transaction-authorization mechanism (verified)
I said during review that `txAuthSimple` "was removed in WebAuthn Level 2". That framing is wrong.
**Verified against the W3C WebAuthn Level 3 specification:** there is no `txAuthSimple` or
`txAuthGeneric` extension, and no reference to their removal in the Level 3 revision history. The
defined extensions are exactly: `appid`, `appidExclude`, `credProps`, `prf`, `largeBlob`. There is
**no standard mechanism for a relying party to have the authenticator display transaction text**
during an assertion.

The consequence is unchanged and is the single most important constraint in this note:

> **A browser passkey cannot perform compliant dynamic linking.** The best achievable is to place a
> hash of the transaction in the `challenge` and display the detail in application UI — but that UI
> is untrusted and the authenticator never attests to what was shown.

That is a property of the platform, not a gap in our implementation, and it is what pushes real
transaction authorization **off the agent's channel onto a separate authenticator**.

### 3.5 CORRECTION — OpenID4VP `transaction_data` exists, but does not define the binding
I flagged this as unverified during review; it has now been checked against **OpenID for Verifiable
Presentations 1.0 (Final, July 2025)**.

It **does** define `transaction_data`: a non-empty array of strings, each a **base64url-encoded JSON
object**, each object carrying at minimum `type` (REQUIRED) and `credential_ids` (REQUIRED, naming
which requested Credentials may authorize the transaction). The Wallet **MUST** error on an
unrecognized transaction data type.

But — and this is the part that changes the plan — **the core specification does not define how the
presentation is bound to the transaction data.** It defers that to the document defining each
transaction data *type*: *"Each document specifying details of a transaction data type defines what
Credential(s) can be used to authorize those transactions."* There is no normative requirement in
the core spec for how hashes are computed, where they appear in the KB-JWT, or what the wallet
signs.

**So `transaction_data` is a framework, not a turnkey answer.** Adopting it means adopting (or
authoring) a transaction-data *type definition* that specifies the binding — otherwise you have a
displayed transaction with no defined cryptographic linkage, which is the same defect as today
wearing better clothes.

### 3.6 CIBA — decoupled authorization
CIBA moves the authorization to a separate device out of band. For **agentic** systems this is
structurally strong: the agent's own channel cannot fabricate the confirmation because the
confirmation does not happen there.

Two traps, both observed here:
- **`binding_message` is a correlation hint, not the instruction.** It is short and
  charset-restricted (PingFederate rejected >20 chars / spaces in our testing). The real detail must
  ride as **RAR on the CIBA request** and be rendered by the authenticator app from the AS.
- **Verify what the issued token carries.** We proved that PF's `signupTE` token-exchange **drops
  `authorization_details` entirely** (HTTP 200, no RAR in the token). Do not assume a CIBA- or
  exchange-minted token carries the RAR the way an authorization-code grant does — test it.

---

## 4. The unenrolled user (the case that breaks these designs in production)

Everything above assumes the user *has* a registered authenticator. Most real populations
partially don't — new customers, lost/replaced devices, users who never enrolled.

### 4.1 Enrolment and authentication are different operations
A native PingOne sign-on MFA action **authenticates an existing device; it never enrols one.** A
device-less user hits `NO_USABLE_DEVICES` and is **blocked before any ceremony starts** — so it
presents as a mysterious failure rather than an enrolment prompt. Any flow must **branch on device
presence**: *has a usable authenticator → authenticate; has none → enrol*. A flow that always
authenticates blocks every new user.

### 4.2 Enrolment assurance caps every future signature
This is the point most designs miss. **The strength of every transaction signature the user will
ever produce is capped by the assurance of the enrolment that bound the authenticator to them.** A
beautifully bound, dynamically-linked, wallet-signed AUD 50,000 payment is worthless if an attacker
enrolled the authenticator in the first place. Enrolment and recovery are where attacks concentrate,
precisely because everything downstream trusts them.

Practical consequences:
- **Proof the identity at enrolment, proportionate to what the authenticator will later authorize.**
  This is where the demo's mDL / identity-proofing work earns its architectural place: it binds a
  new authenticator to a *proofed person*, not merely to a session.
- **Record the enrolment evidence** — what proofing backed it, when, at what level — as a
  first-class record, not a boolean. The dispute layer needs the authenticator's provenance, not
  just its existence. (Our object model already has `identityProofingRecord` and
  `verifiablePresentationEvidence` for exactly this.)
- **Recovery is re-enrolment.** Treat "lost my device" with the same rigour as first enrolment, or
  it becomes the bypass.

### 4.3 Never silently downgrade
The tempting failure: user has no device → fall back to a weaker channel (SMS, email link, "confirm
in app") → policy treats the result as equivalent. That converts a strong design into its weakest
path, invisibly.

The rule: **if the required assurance is unavailable, either enrol to that assurance, or refuse the
transaction.** If a lower-assurance path is genuinely offered, the resulting authorization must be
*labelled with the assurance actually achieved* and the policy must be able to decline it for
high-value operations. Assurance must be an attribute the PDP sees, never an assumption.

---

## 5. Options for the target architecture

| | Binding strength | Unenrolled user | Cost |
|---|---|---|---|
| **A. App-captured consent** (today) | **None** — app asserts | n/a | shipped |
| **B. CIBA + RAR** | Signature on a trusted device, out of band from the agent | Needs enrolment branch | Moderate — flow + token-mapping work |
| **C. Wallet / OID4VP `transaction_data`** | Potentially highest — holder key signs | Needs wallet + credential | High — **plus authoring a transaction-data type that defines the binding** (§3.5) |

**A is not a target state.** It is acceptable only as demo narrative and must be labelled as such,
because it produces an audit record that looks like consent and isn't.

---

## 6. Recommended sequence

1. **Unblock the loop (now).** Give the payments policy a policy-information provider over the
   consent directory so a recorded, authorized consent can satisfy the payment — matching on
   subject + amount ≤ consented + creditor. **Label it honestly**: this makes the demo work and is
   *not* non-repudiable, because the consent is app-asserted (§2).
2. **Make the instruction real (next).** Move to **CIBA + RAR**: the transaction detail rides as RAR
   on the CIBA request, the authenticator app renders it from the AS, and the AS binds the grant to
   it. Add the **enrolment branch** (§4.1) at the same time — CIBA is unusable for a device-less
   user, so the two land together.
3. **Raise assurance (later).** Wallet-bound authorization via `transaction_data`, once a
   transaction-data type definition specifying the binding exists (author one if necessary).

Independently and cheaply: **retain the artefact**, not a boolean. Whatever is signed should be
stored intact so a dispute can be reconstructed.

## 7. Open questions

- Which `transaction_data` **type definition** do we adopt or author? Without one there is no binding (§3.5).
- Does PF attach `authorization_details` to a **CIBA-minted** token? (We proved it does *not* for `signupTE`; CIBA is untested.)
- What proofing level is required to enrol an authenticator that may authorize payments, and who decides — policy or product?
- Is CDR alignment in scope? If so, JAR/JARM (§3.2) shapes the whole approach.

## 8. Skills to generate from this

- **`transaction-authorization`** — *written* (dynamic linking, the binding smell, FAPI overclaim,
  WebAuthn constraint, CIBA vs wallet). **Needs updating** with the two corrections in §3.4 and §3.5.
- **`authenticator-enrolment-and-recovery`** — *not yet written*. §4 is the seed: enrolment vs
  authentication as distinct operations, enrolment assurance capping downstream signatures, evidence
  as a record not a boolean, recovery as re-enrolment, and the never-silently-downgrade rule.

## 9. Sources

- PSD2 RTS Art. 5 (dynamic linking)
- FAPI 2.0 Security Profile (Final, 22 Feb 2025); FAPI 2.0 Message Signing (Final, Aug 2025)
- RFC 9396 (RAR); RFC 9126 (PAR); RFC 9449 (DPoP)
- W3C WebAuthn **Level 3** — verified 2026-07-20: no transaction-authorization extension
- OpenID for Verifiable Presentations **1.0 (Final, July 2025)** — verified 2026-07-20:
  `transaction_data` defined; binding mechanism deferred to per-type documents
- OpenID CIBA / FAPI-CIBA; AU CDR standards (JAR/JARM)
