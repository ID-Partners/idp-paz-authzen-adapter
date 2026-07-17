---
name: pingfederate-config-as-code
description: >-
  Use when changing PingFederate configuration (OAuth clients, access token managers/mappings,
  token exchange processor policies, IdP adapters/token processors, IdP/SP connections, OGNL
  attribute mappings) in ANY project. Enforces declarative config-as-code via the
  pingidentity/pingfederate Terraform provider instead of the admin console/REST API, and covers
  the ephemeral-server pattern (export the config archive as the deploy artifact). Fires on
  "PingFederate", "PF admin", "data.zip", "access token mapping", "token exchange", "act claim",
  "OGNL", or a request to change/deploy PF config.
---

# PingFederate config-as-code (Terraform)

**Principle: PingFederate config is declarative code in the repo, applied via Terraform — never
hand-poked through the admin UI or REST API.** UI/API changes are unversioned and lost on
redeploy; Terraform config is reviewable, reproducible, and diffable. Do NOT reach for
`/pf-admin-api` curl calls or the console to make changes. (`terraform apply` DOES call the admin
API under the hood — that's fine; the point is that the *source of truth* is the `.tf`, not the
running server.)

## Tool

The official provider: [`pingidentity/pingfederate`](https://registry.terraform.io/providers/pingidentity/pingfederate/latest).
(There is also a legacy `iwarapter/pingfederate` — prefer the `pingidentity` one.)

```hcl
terraform {
  required_version = ">= 1.5.0"  # need import {} blocks
  required_providers {
    pingfederate = { source = "pingidentity/pingfederate", version = "~> 1.5" }
  }
}
provider "pingfederate" {
  https_host                          = var.pf_admin_host      # https://host:9999
  admin_api_path                      = "/pf-admin-api/v1"
  username                            = var.pf_admin_username  # e.g. administrator
  password                            = var.pf_admin_password  # TF_VAR_pf_admin_password, sensitive, never commit
  insecure_trust_all_tls              = true   # dev/self-signed only
  x_bypass_external_validation_header = true   # skip connection-validation probes on apply
}
```

## Validate WITHOUT a running PingFederate (do this first, every time)

`terraform init` + `terraform validate` check config against the provider's real schema with **no
PF connection** — this catches wrong field names, missing required blocks, and bad source-type
enums before you ever touch a server. Always author → `init` → `validate` → fix → only then
`plan`/`apply`. (`validate` still needs a value for required vars: `TF_VAR_pf_admin_password=dummy`.)

## Adopting an EXISTING hand-built PF (don't recreate — import)

Most PF servers were built by hand. To modify without clobbering:

1. Write `import {}` blocks (TF 1.5+) for each resource you touch, using its PF id:
   ```hcl
   import { to = pingfederate_oauth_token_exchange_processor_policy.x  id = "policyId" }
   ```
2. `terraform plan -generate-config-out=generated.tf` → Terraform writes the EXACT current bodies.
3. Fold those into your `.tf`, apply your edits, `plan` again until the diff is only your change.

Get real ids from the admin API list endpoints (e.g. `GET /oauth/accessTokenMappings`,
`/oauth/tokenExchange/processor/policies`, `/idp/tokenProcessors`).

**Check what's already managed before assuming.** Run `terraform state list` first: on a
partially-adopted PF some resources are already imported (edit them in place) while others exist
only in `data.zip` and still need an `import {}` block. Don't recreate a managed resource, and
don't hand-author a `data.zip`-only one blind — importing it captures the exact live body so your
change is the only diff. (In this project, e.g., the agent clients + several ATMs are managed, but
`userJwtATM` and `oauth_server_settings` were data.zip-only and needed importing.)

## Ephemeral / no-volume PingFederate (Railway, containers)

If PF loads its config from a **config archive** at boot (`data.zip` via drop-in-deployer) and has
no persistent volume, Terraform-applied config is lost on redeploy. Pattern:

**author `.tf` → `terraform apply` (to a running PF) → export `configArchive` → overwrite the
committed `data.zip` → commit `.tf` + `data.zip` → deploy.**

So `.tf` is the human-readable **source**; `data.zip` is the built **artifact**.

### WHERE you apply — pick the target deliberately (this is the #1 time-sink)

`terraform apply` needs a **running PF admin API** to talk to. There are two targets; the
project's runbook uses the first, and reaching for the second unprompted causes the
admin-password mismatch below.

1. **Canonical: the DEPLOYED PF, over a tunnel.** The admin API (`:9999`) isn't publicly
   proxied. `railway ssh --service pingfederate` and forward `:9999` (or add an admin TCP proxy),
   then `export TF_VAR_pf_admin_host='https://localhost:9999'`. This is what the project README
   documents. Apply → export → commit → redeploy.
2. **Alternative: a LOCAL PF built from the same image + `data.zip`.** Useful when you can't
   tunnel. `docker build` the PF image, `docker run` it (map admin `:9999` and runtime `:9031` to
   free host ports — other PF stacks may already hold the defaults), wait for
   `Config archive import completed successfully`, apply against it, export, redeploy the real one.

**Export (GET, not import — the endpoint name is the confusing part):**
```sh
curl -sk -u administrator:$PW -H 'X-XSRF-Header: PingFederate' \
  -o data.zip https://localhost:9999/pf-admin-api/v1/configArchive/export
```
On the deployed PF the runbook pulls it off over ssh:
```sh
railway ssh --service pingfederate -- \
  curl -sk -u administrator:$PW -H 'X-XSRF-Header: PingFederate' \
  -o /tmp/data.zip https://localhost:9999/pf-admin-api/v1/configArchive/export
```

### The admin password is a property of `data.zip`, not of the environment

The admin user's password **hash is baked into the config archive** (`pingfederate-admin-user.xml`
inside `data.zip`). Every PF that boots from that archive — deployed or local — has the *same*
admin credential. So:

- A password that `401`s (`invalid_credentials`) against a PF that logged
  `Config archive import completed successfully` for **your** `data.zip` is simply the wrong
  password for that archive — not a tunnel glitch, not "local vs deployed". Both boot the same
  hash; if it fails on one it fails on both.
- `TF_VAR_pf_admin_password` lives **out-of-band only** (never in repo or `terraform.tfstate` —
  provider config isn't stored in state). Keep it in a `chmod 600` file outside the repo and
  reference it as `$(cat ~/.pf-admin-pw)` so its value never lands in a transcript.
- If the archive's password is genuinely unknown, the config-as-code fix is to set a known admin
  password *in the archive* and redeploy — a deliberate change to the artifact, not a guess-loop.

### The deploy command (this project) is exact and non-obvious

```sh
railway up demo/pingfederate --path-as-root --service pingfederate --no-gitignore
```
`--no-gitignore` is load-bearing: gitignored build inputs (the licence file if used, the PingOne
MFA Integration Kit zip, any `.war`) must reach the build context or the image is missing pieces.

### Add-on WARs (servlets) ride in the image, not in terraform

A servlet add-on (e.g. `gm-api.war`) is a Dockerfile `COPY … server/default/deploy/<name>.war`.
PF's `PFWebAppProvider` serves it at a context path == the WAR name (same mechanism as PF's own
`/pf-ws`). Two facts that read as errors but aren't: a servlet using `java.util.logging` prints
its *INFO* startup line as `ERROR [SystemErr]` in PF's log (read the next line — `INFO: … ready`),
and each `deploy/` artifact gets its own classloader, so bundle nothing PF already ships.

## Attribute-mapping cheatsheet (the part people get wrong)

`attribute_contract_fulfillment` is a **map** of attr-name → `{ source = { type, id? }, value }`.
Source `type` enum includes: `TEXT`, `EXPRESSION`, `CONTEXT`, `SUBJECT_TOKEN`, `ACTOR_TOKEN`,
`TOKEN_EXCHANGE_PROCESSOR_POLICY`, `CLAIMS`, `MAPPED_ATTRIBUTES`, `NO_MAPPING`, plus datastore types.

- **Static value / templating:** `source.type = "TEXT"`, `value = "literal ${AttrName}"`.
- **OGNL transform:** `source.type = "EXPRESSION"`, `value = "<ognl>"`. Reference an available
  attribute's value as `#this.get("attrName").getValue()`; guard null (`#this.get("x") == null ? …`).
- **Access token mapping context:** `context = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY",
  context_ref = { id = <policyId> } }` (or `DEFAULT`, `CLIENT_CREDENTIALS`, `IDP_ADAPTER`, …), and
  `access_token_manager_ref = { id = <atmId> }`.
- A token processor / TEPP exposes extra claims only if you add them to its
  `attribute_contract.extended_attributes` (`core_attributes` is required, even if read-only).

## RFC 8693 actor-chain (`act`) patterns — agentic identity

- **Nest/derive `act` (grow the chain):** map the inbound `act` through the token-exchange policy
  (`source SUBJECT_TOKEN, value "act"`, declared as an extended attribute on both the JWT subject
  processor and the TEPP), then in the access-token mapping wrap it:
  ```
  EXPRESSION: "{\"sub\":\"<this-agent>\"" + (#this.get("act") == null ? "" : ",\"act\":" + #this.get("act").getValue()) + "}"
  ```
  Never hard-code the nested chain as a per-agent literal — that doesn't grow with new hops.
- **Flatten (promote actor → sub, drop act)** for an audience where the agent acts as itself:
  a separate audience-scoped ATM/mapping whose `sub` = an actor from the chain and which omits
  `act`. Hard-scope it to that one audience; it's the deliberate opposite of delegation.
- `act` is commonly emitted as a JSON **string** claim (consumers json-decode it) — keep the format
  consistent across hops.

## Provider gaps — things you CANNOT do in Terraform (drop to the admin API)

The provider does not cover every admin surface. When there is no resource, `terraform
apply` cannot help and you use `POST /pf-admin-api/v1/...` directly (wrap in a
`null_resource` + `local-exec` if you want it in the graph). Confirmed absent as of
provider ~> 1.5 / PF 13.0.3:

- **Authorization detail types and processors** (`/oauth/authorizationDetailTypes`,
  `/oauth/authorizationDetailProcessors`). No resource. `authorization_detail_types` on
  `oauth_client` works, but the types must already exist — created via the admin API,
  and only after a processor plugin is deployed (below).
- The provider version gates which fields it sends: set `product_version` on the provider
  block (e.g. `"13.0"`) or apply fails with `product_version is required`.

## PF has native RAR but ships NO processor

PF 13 fully supports RFC 9396 `authorization_details` — `AccessGrant.getAuthorizationDetails()`
is typed, the token carries it, the approval page renders it. But **no
AuthorizationDetailProcessor ships with the product**, and a type cannot be declared
without one:

```
POST /oauth/authorizationDetailTypes  → 422 authorizationDetailProcessorRef is required
GET  /oauth/authorizationDetailProcessors/descriptors  → {"items":[]}
```

So on a stock PF a client **cannot request RAR at all**. Options: write/deploy a processor
plugin (Java SDK — see the pingfederate-java-extensions skill / pf-rar-paz-plugin), or as
an interim carry the consent as a persistent-grant **extended attribute** (declare it in
`oauth_server_settings.persistent_grant_contract`, fulfil it in the adapter mapping with a
`TEXT` source). The attribute form is a constant, not user-chosen consent — mark it as such.

## Enums bite; `validate` catches them

Source-type enums are exact and not always the obvious word. The persistent-grant source is
`OAUTH_PERSISTENT_GRANT`, not `PERSISTENT_GRANT`. Always `init` + `validate` before `plan` —
it prints the full allowed set on a mismatch, which is faster than reading docs.

## Diagnosing a deployed PF that looks broken — confirm the HOST first

Before concluding a deployed PF is down/misconfigured, verify you are hitting the **right server**.
Two traps, both of which sent this project in circles:

- **Never treat a hostname from a Terraform variable/default as "the live server".** A var like
  `pf_issuer` can be a *symbolic* RFC 9068 `iss` string that deliberately matches no live host
  (nothing dials it; key material comes from a separate JWKS URL). Chasing it as if it were the
  runtime URL means probing a dead/unrelated host and misreading its errors as your outage. The
  real runtime host comes from `railway domain --service pingfederate` or from what the clients
  actually use (`RAILWAY_SERVICE_PINGFEDERATE_URL` / the agents' `PF_*_URL` vars) — **not** from
  `variables.tf`. A tell you're on the wrong host: PF's own log shows **zero** requests arriving
  while you probe.
- **A 503 on the runtime is NOT automatically a licence problem.** Diagnose by symptom, and check
  the licence model first (below) before redeploying. An unnecessary redeploy of an ephemeral PF
  **wipes in-memory persistent grants** — costly if grants were the thing you were about to use.

### Licence model: DevOps-fetched at boot ≠ the `.lic` file

For a DevOps-licensed image (`PING_IDENTITY_DEVOPS_USER`/`_KEY` + `PING_IDENTITY_ACCEPT_EULA=YES`,
no `.lic` baked), PF **fetches a fresh eval licence at every boot** — the log says
`Successfully pulled evaluation license` and `Server licensing status is now: OK`. Consequences:

- A committed `pingfederate.lic` **disables** the DevOps fetch (an existing file takes precedence).
  Don't "fix" a licence 503 by adding one unless you mean to switch models.
- Redeploy re-fetches, so a *genuine* licence expiry is cured by redeploy — but only diagnose it
  as licence after reading the log for the licensing line. A local `.lic` file's `ExpirationDate`
  tells you nothing about a running DevOps container.

## Gotchas that cost real time

- **Requesting `openid` with no OIDC policy configured → `server_error`** at the
  authorization endpoint ("No default OpenID Connect Policy found"). If you only need an
  access token / a grant, do not request `openid`.
- **`/pf-ws/rest/oauth/...` (Persistent Grant Management API) wants HTTP Basic**, via
  `oauth_server_settings.admin_web_service_pcv_ref` (a password credential validator) — NOT
  the bearer from `atm_id_for_oauth_grant_management`, which governs a different surface. A
  bearer there returns "HTTP Basic authentication is required".
- **A DevOps container regenerates its signing keys on restart** (no persistent keystore),
  invalidating every previously issued token. `401`/`Unable to find a suitable verification
  key` right after a restart is expected — mint a fresh token.

## Reference

- Provider docs (raw, fetch with curl when the registry is JS-rendered):
  `https://raw.githubusercontent.com/pingidentity/terraform-provider-pingfederate/main/docs/resources/<name>.md`
- Key resources: `oauth_access_token_mapping`, `oauth_access_token_manager`,
  `oauth_token_exchange_processor_policy`, `idp_token_processor`, `oauth_client`,
  `oauth_server_settings`, `idp_adapter`, `oauth_idp_adapter_mapping`,
  `password_credential_validator`.
- Worked examples: `demo/pingfederate/terraform/` in idp-paz-authzen-adapter;
  `deploy/pingfederate/terraform/` in idp-gm-api.
