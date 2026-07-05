# PingFederate (agentic demo AS)

Real PingFederate 13.0.3 + the `pf-oidf-modules` client-attestation module, acting as the
**Authorization Server** for the agentic banking demo. It validates each agent's OAuth 2.0
client attestation (attested + signed by the [attester](../attester) service) and issues a
**real delegated JWT** — `sub=cust-alice`, a per-agent `act` claim, and a `cnf.jkt`
DPoP binding — which the agent then presents at the Kong gateway.

Deployed as the `pingfederate` service in the agentic Railway project (`ac9af096…`), reached
by the agents at the token endpoint via its public TCP proxy. `TOKEN_MODE=pingfederate` on
the agent services switches them from the local self-issued IdP to this real AS.

## What's baked in

| File | Purpose |
|---|---|
| `Dockerfile` | Stock PF 13.0.3-alpine + license + the OIDF module jars + config drop-in |
| `data.zip` | **The config snapshot** — a PF config-archive (encrypted) carrying the 3 agent clients, 3 JWT ATMs, and 3 access-token mappings. Dropped into the drop-in-deployer so it imports at boot. |
| `oidf.war`, `pf-oidf-modules.jar`, `jose4j-0.9.6.jar` | The `pf-oidf-modules` attestation module + its runtime dep |
| `oidf-mock-attesters.json` | DEV attester trust — maps the attester issuer to its public JWK (bypasses full OIDF federation resolution) |
| `overlay/` | PF master key + system keys, so `data.zip`'s encrypted secrets decrypt natively **(git-ignored — secret)** |
| `pingfederate.lic` | PF evaluation license, expires **2026-07-13** **(git-ignored)** |

### The OAuth config in `data.zip` (the 3-client approach)

Each agent authenticates as its **own** OAuth client, so PF stamps its own `act.sub`:

| Client (`client_id`) | Access Token Manager | Mapping |
|---|---|---|
| `urn:agent:northwind-concierge:v1` | `attestJwtATM` | `client_credentials\|attestJwtATM` |
| `urn:agent:northwind-account:v1` | `attestJwtAcct` | `client_credentials\|attestJwtAcct` |
| `urn:agent:northwind-payments:v1` | `attestJwtPmts` | `client_credentials\|attestJwtPmts` |

Each JWT ATM emits `sub=cust-alice`, the client's own `act` (as a JSON **string** — Kong's
plugin json-decodes it), and the presented `cnf.jkt`.

## ⚠️ PingFederate on Railway is EPHEMERAL — no volume

Any OAuth config created live via the admin API is **lost on redeploy**. The two ways config
survives:

1. **Baked (default).** `data.zip` here is the snapshot of the live config; the Dockerfile
   drops it into `.../data/drop-in-deployer/data.zip`, so a `railway up` from this directory
   boots a fully-configured PF. Keep `data.zip` current — see "Re-snapshotting" below.
2. **Restored (safety net).** [`restore-config.sh`](restore-config.sh) imports `data.zip`
   into an already-running PF via the admin API in ~30s. Use it if a redeploy ever lands
   without the config.

## Re-snapshotting after admin-API changes

If you change PF config live (admin console / API), re-capture it so the change survives:

```sh
# from inside the PF container (railway ssh --service pingfederate):
curl -sk -u administrator:<pass> -H 'X-XSRF-Header: PingFederate' \
  -o /tmp/data.zip https://localhost:9999/pf-admin-api/v1/configArchive/export
# then pull /tmp/data.zip out (base64 over ssh) and overwrite this data.zip, and commit.
```

## Secrets (not in git)

`overlay/pf.jwk`, `overlay/pingfederate-system-keys.xml`, and `pingfederate.lic` are
git-ignored. They must be present in the build context to deploy. `data.zip` is committed
because it is encrypted with `pf.jwk` — useless without the master key. For CI/CD, supply
the three secret files as pipeline secrets materialised into this directory before build.
