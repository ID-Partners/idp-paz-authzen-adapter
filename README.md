# ⚠️ This repo has been split up and moved

Everything that lived here is now maintained in three sibling repos under
`~/Source`, each extracted with full git history preserved:

| Was here | Now lives in | Notes |
|---|---|---|
| `authzen-adapter/` | **`idp-authzen-adapter-go`** | The Go AuthZEN adapter for Ping Authorize (evaluation/search APIs + SSF receiver feed). Also now hosts the COAZ package as `coaz-pep/` (merged from the old standalone `authzen-coaz-pep` repo). |
| `demo/` | **`idp-agentic-demo`** | The agentic banking demo — all services, gateways, Ping config-as-code, policy packages, compose files, and `scripts/railway-up.sh`. `docker-compose.yml` builds the adapter from the sibling checkout. |
| `demo/ios-approver/` | **`idp-approver-ios`** | The IDPApprover iOS authenticator (passkeys, YubiKey, PingOne MFA push, PingOne Recognize/Keyless SDK) — a standalone authenticator usable across projects. |

Do not commit new work here. This repo is kept as the historical record (the
GitHub remote `ID-Partners/idp-paz-authzen-adapter` still holds the full
pre-split history and branches).

Local working-tree remnants under `demo/` and `authzen-adapter/` are
gitignored-only artifacts (licences, keys, terraform state, build outputs).
Copies of all of them were carried into the new repos; the leftovers here can
be deleted once the new checkouts are verified working.
