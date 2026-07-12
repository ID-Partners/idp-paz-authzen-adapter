# PingFederate config-as-code (Terraform) — token-exchange plane

Declarative source for the RFC 8693 **actor-chain** behaviour, using the
[`pingidentity/pingfederate`](https://registry.terraform.io/providers/pingidentity/pingfederate/latest)
provider. This replaces the per-agent **hard-coded `act` literal** in `../data.zip` with an `act`
that is **derived from the incoming token** — so the delegation chain grows itself:

- `subjectJwtProc` now exposes the inbound `act` claim,
- the `userToAgentTE` token-exchange policy carries `sub` **and** `act` through,
- each task-agent access-token mapping sets `act = {this-agent, act={…incoming…}}` via an OGNL
  expression (the concierge stays the root, so its mapping is unchanged).

## Why Terraform + why it still ends in data.zip

The Railway PingFederate is **ephemeral** — it boots its config from `../data.zip`. So Terraform is
the **authoring** tool (declarative, reviewable, versioned), and the realised config is exported
back into `../data.zip`, which is the **deploy artifact**. Flow: **author `.tf` → apply → export →
commit `.tf` + `data.zip` → deploy**. The running server is never the source of truth.

## Prerequisites

- Terraform ≥ 1.5 (for `import {}` blocks).
- Reachability to the PF **admin API** (`:9999`). It isn't publicly proxied; tunnel it:
  ```sh
  railway ssh --service pingfederate        # then, in another shell, forward :9999
  # or add an admin TCP proxy and set pf_admin_host to it
  ```
- Admin password out-of-band (never commit):
  ```sh
  export TF_VAR_pf_admin_password='…'
  export TF_VAR_pf_admin_host='https://localhost:9999'   # your tunnel/proxy
  ```

## Apply

```sh
terraform init

# 1) Capture the EXACT current bodies of the imported resources, then reconcile the hand-authored
#    resources in token-exchange.tf against them (confirm the JWT plugin id + the mapping import IDs).
terraform plan -generate-config-out=generated.tf

# 2) Apply the act-derivation change.
terraform apply

# 3) Persist it into the deploy artifact (config survives the next ephemeral redeploy):
railway ssh --service pingfederate -- \
  curl -sk -u administrator:$TF_VAR_pf_admin_password -H 'X-XSRF-Header: PingFederate' \
  -o /tmp/data.zip https://localhost:9999/pf-admin-api/v1/configArchive/export
#   pull /tmp/data.zip out, overwrite ../data.zip, and commit it alongside the .tf.
```

> First run only: the `import {}` blocks adopt the existing hand-built resources so Terraform
> **modifies** them (never recreates). Two IDs need confirming against the live PF on that first
> `plan` — the `subjectJwtProc` JWT-plugin `id`, and the two access-token-mapping import IDs
> (`GET /oauth/accessTokenMappings`). Fix them in `token-exchange.tf`, re-plan, apply.

## Verify without a browser login

The derivation is testable with chained client-credential → exchange → exchange calls (no Alice):

1. get a base token (client_credentials),
2. exchange it **as the concierge client** → expect `act = {concierge}` (empty incoming → root),
3. exchange **that** token **as the payments client** → expect `act = {payments, act={concierge}}`
   — proving the chain was **derived from the incoming token**, not baked.

## Still to add (next file)

`flatten.tf` — the audience-scoped event-endpoint exchange: a new ATM + mapping for
`aud=https://events.northwind.example` that promotes the **root** actor (innermost `act.sub`) into
`sub` and drops `act`. Needs an OGNL that walks to the last `"sub"` in the act JSON; authored here
once the nesting change above is confirmed green.
