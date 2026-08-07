# Linking the PingOne Recognize Mobile SDK

The approver ships today with `SimulatedRecognizeVerifier` — a `LAContext` device unlock. That
proves someone knew the passcode, nothing more: no server-verifiable evidence, and no way to bind
the check to the payment. Linking the real SDK replaces it with a server-verified face match whose
result JWT carries the transaction in a `td` claim.

**No code change is required to switch it on.** `MFAManager.swift` guards the real conformer with
`#if canImport(Keyless)`; linking the package is what compiles it in.

## 1. Registry (once per machine)

```bash
KEYLESS_DOWNLOAD_KEY=xxxx ./setup-keyless-sdk.sh
```

Then in Xcode: **File → Add Package Dependencies…** → search `keyless.mobile-sdk` → add to the
IDPApprover target.

`./setup-keyless-sdk.sh --check` reports state without changing anything.

## 2. Runtime config

Separate from the Download Key above, and supplied at build time so nothing lands in git:

```bash
xcodebuild … RECOGNIZE_API_KEY=xxxx RECOGNIZE_HOSTS=https://host-a,https://host-b
```

These substitute into `Info.plist` (`RecognizeApiKey` / `RecognizeHosts`). Unset → empty →
`RecognizeConfig.fromBundle()` returns nil → simulated. **Fail-closed by design**: a half-configured
build must not render "verified by PingOne Recognize" over a check that never happened.

## Traps that cost real time

**Three different keys, none interchangeable.** Download Key = Cloudsmith entitlement, build-time
only. Mobile API Key = `RecognizeApiKey`, runtime. Secret API Key = backend REST only, never goes
near the app. Using the wrong one gives a 401 that reads like a bad token rather than the wrong
*kind* of token.

**There are THREE different names, and the docs get one of them wrong.** Package id
`keyless.mobile-sdk` (renamed from `keyless.KeylessSDK`); Swift module **`KeylessSDK`**; SDK entry
type `Keyless`. Every iOS sample in the vendor docs says `import Keyless` — **that is wrong**,
verified against the shipped `.swiftinterface` (`-module-name KeylessSDK`, v6.0.1). It matters
more than a typo: guarding on `#if canImport(Keyless)` compiles the real verifier out silently, so
the app keeps using the simulated one while looking correctly wired, with no warning.

**`Keyless.configure` is completion-based**, not the synchronous `if let error = configure(…)` the
docs show. Real signature: `configure(setupConfiguration:onCompletion:)`. And the signed JWT is
`Keyless.AuthenticationSuccess.signedJwt` (Optional; nil unless `jwtSigningInfo` was supplied).

## What a "node host" actually is — and how to test one

`KEYLESS_HOSTS` are **core-daemon / node** hosts, not the operations-service. The node API is
`/api/v1/*` (extracted from the shipped framework binary), and `configure` calls
`/api/v1/customer-properties`. So a candidate host is testable in one request:

```sh
curl -s -o /dev/null -w '%{http_code}\n' https://<candidate>/api/v1/customer-properties
```

Anything that 404s is not a node. Tested and REJECTED: `api.sg.keyless.technology`,
`api.keyless.io`, the US/LATAM operations-services, and both `authentication-service` hosts —
none serve `/api/v1/*`. `api.sg` is reachable and correctly formatted (the SDK error moves from
`"The base host is not valid"`, code 20010, to an HTTP 404, code 10000) but it is the wrong
service.

Useful sibling endpoints in the same surface: `/api/v1/psd2/biom-jwt` (the PSD2 dynamic-linking
JWT), `/api/v1/devices`, `/api/v1/user-authentication`, `/api/v2/enroll`.

**Quit Xcode before running the setup script.** It caches registry configuration at launch and will
keep failing to resolve the package, with no useful error, until restarted. Registry config must
also be `--global`; Xcode ignores project-local registry configuration entirely.

**`KEYLESS_HOSTS` must have no trailing slashes.** An explicit requirement in the vendor docs, and
a silent misconfiguration if violated. The script's config path strips them defensively.

## Why mobile rather than the Web SDK

The Mobile SDK takes only `SetupConfig(apiKey:hosts:)` — no customer name, no username, and it does
**not** go through the Authentication Service (the docs scope that to "IDV Bridge SaaS and WebSDK").
Those `hosts` are core-backend node URLs. That matters here: this tenant lives in a region with a
live operations plane but **no Authentication Service**, which blocks the Web SDK outright and does
not block mobile.

Dynamic linking on SDK 5.2/6.0 is `JwtSigningInfo(claimTransactionData:)` passed as
`BiomAuthConfig(jwtSigningInfo:)`. The 4.6-era `DynamicLinkingInfo(transactionData:)` pages are
stale — their iOS snippet is not even valid Swift. Payload must be an array of **single-pair**
objects, which `RecognizeTransaction.transactionDataJSON` produces:

```json
[{"Amount":"AUD 9000.00"},{"To":"ACME Pty Ltd"},{"From":"Alice Smith"},{"Reference":"NW-4821"}]
```

## The values for this tenant

```
RECOGNIZE_API_KEY = <the dashboard's Mobile API Key>
RECOGNIZE_HOSTS   = https://auth.sg.keyless.technology
```

Both verified: `GET /api/v1/customer-properties` with header `X-Keyless-Apikey` returns 200 and
`{"customerName":"idpartners","customerId":286,"loggingEnv":"kl-sg"}`, and the SDK's own
`Keyless.configure` returns SUCCESS against that host. The same key against EU production returns
`404 "Sdk customer not found"`, which confirms the key and tenant are Singapore-scoped.

Nothing further is needed from Ping for the mobile path.
