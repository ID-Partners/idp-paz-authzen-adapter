# DaVinci flows (config-as-code)

Source of truth for the DaVinci flows this demo depends on. The tenant is disposable;
these files are not. Re-apply with the DaVinci API (see the `davinci-flow-builder`
skill, `references/api-authoring.md`).

| File | Flow | Tenant id |
|---|---|---|
| `payment-consent-rar.flow.json` | Payment Consent (RAR) - Demo Bank | `e58cea11d8a5c6239060b1d2f7e0ab6f` |
| `recognize-signon.flow.json` | Recognize Sign-On (simulated) | `dde392a8046c8787211f886afe44e848` |

Environment: **P1AS** (`fe8ab8dc-0dbb-4da4-8ee5-004cb3a6f21d`), app
`PingOne SSO Connection` (`74e432a9f7c4aaa657332b1a10282b61`).

## Flow policies on that app — RESTORE LIST

`GET /apps/{appId}` reports `policies: []` even when policies exist; only `GET /apps`
lists them. A read-modify-write against the single-app GET therefore DELETES them (it
happened on 2026-07-20). Keep this table current and snapshot before any PUT.

| policyId | Name | flowId |
|---|---|---|
| `5eccfe79c581a8890d07cb7a217b25bd` | Bank Signup Passkey Registration | `21d1edd60400b6a2ad87b398fe65f3e0` |
| `f0245209d0fed91c282fb1396f06fd2e` | Bank Signup Passkey Live (BFF `DAVINCI_POLICY_ID`) | `774001f77c9b2e470fa0b6bce9fe3931` |
| `122354553b1301f114619a576c4e57fc` | Payment Consent (RAR) | `e58cea11d8a5c6239060b1d2f7e0ab6f` |
| `8376b8aadec32fcdaa4ccdb2911b6c4c` | Recognize Sign-On (BFF `DAVINCI_RECOGNIZE_SIGNIN_POLICY_ID`) | `dde392a8046c8787211f886afe44e848` |

## Re-applying

```
POST /flows              {name, description, flowColor, graphData}   → new flowId
PUT  /flows/{flowId}     {name, graphData}   ONLY (others → 422)
deploy_flow {flowId}                          # DaVinci runs the DEPLOYED version
PUT  /apps/{appId}       {"policies":[ …complete array, incl. your own 32-hex policyId… ]}
```

`import_flow` and `POST /apps/{id}/policies` are SigV4-gated and return 403
`IncompleteSignatureException` — that is the wrong endpoint family, not bad credentials.

## Assurance note

A DaVinci-rendered consent screen changes WHERE consent is captured, not what the
signature covers. It is not non-repudiable on its own — see
`demo/TRANSACTION-AUTHORIZATION.md` sections 2 and 6.
