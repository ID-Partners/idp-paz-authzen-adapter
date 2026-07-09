# PingFederate (agentic demo AS)

Real PingFederate 13.0.3 + the `pf-oidf-modules` client-attestation module, acting as the
**Authorization Server** for the agentic banking demo. It validates each agent's OAuth 2.0
client attestation (attested + signed by the [attester](../attester) service) and issues a
**real delegated JWT** — `sub=alice` (the authenticated user, derived from her login
token via RFC 8693 token exchange), a per-agent `act` claim, and a `cnf.jkt`
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
| `pf.plugins.pf-rar-paz-plugin.jar` + `template/oauth.approval.page.template.html` | **Vendored from the standalone `pf-rar-paz-plugin` repo** (`~/Source/pf-rar-paz-plugin`) — do NOT edit here. Rebuild + re-stage with `./vendor-plugin.sh` after pulling plugin changes, then commit. The RFC 9396 RAR → PingAuthorize processor + its attribute-focused consent page. |
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

Each JWT ATM emits `sub=alice` (from the exchanged subject token — the authenticated
user), the client's own `act` (as a JSON **string** — Kong's plugin json-decodes it),
and the presented `cnf.jkt`.

## Environment configuration — public URLs (set per deployment, NOT baked)

PingFederate's public-facing URLs are read from **environment variables** at boot, via the stock image's
`run.properties.subst` templating. This deploy ships **no custom `run.properties`** — the Dockerfile only
*appends* to `run.properties.subst.default` — so these env vars are authoritative and MUST be set on each
Railway service, or PF falls back to `localhost` defaults.

| Env var | PF property | Controls | Set to |
|---|---|---|---|
| `PF_ADMIN_PUBLIC_BASEURL` | `pf.admin.baseurl` | Admin-console redirects & links | `https://<admin-proxy-host>:<port>` |
| `PF_ADMIN_PUBLIC_HOSTNAME` | `pf.admin.hostname` | Admin-console host | `<admin-proxy-host>` |
| `PF_ENGINE_PUBLIC_HOSTNAME` | `pf.engine.hostname` | **Runtime** issuer / discovery / approval-page `$action` | `<runtime-proxy-host>` |

**The localhost trap (why this section exists):**
- **Unset admin vars →** the admin console `302`-redirects to `https://localhost:9999/pingfederate/app`
  (unreachable). Fix = set the two `PF_ADMIN_PUBLIC_*` vars to the admin service's TCP-proxy `host:port`.
- **Unset engine var →** the runtime advertises `localhost:9031` as its base, so the OAuth **issuer** and the
  `private_key_jwt` **`aud`** are `localhost`. The demo currently pins `aud=https://localhost:9031/as/token.oauth2`
  (`PF_TOKEN_AUD` on `pf-demo-ui`) to match. To make the runtime advertise its **real** public URL instead,
  set `PF_ENGINE_PUBLIC_HOSTNAME` to the runtime proxy host **and** update `PF_TOKEN_AUD` to the same base
  **in lockstep** — they must agree or the token endpoint rejects the assertion.

> Do NOT bake a custom `run.properties` with these values (as the `idp-openbanking-demo` PF-AS does with
> `pf.admin.baseurl=https://localhost:9999`) — a shipped `run.properties` **overrides** the env vars and
> re-introduces the localhost trap.

Current staging (`pingfederate` project): `PF_ADMIN_PUBLIC_*` are set on both `pingfederate` (admin) and
`pingfederate-runtime`; the engine var is intentionally left unset (the demo uses the `localhost` `aud`).

## ⚠️ PingFederate on Railway is EPHEMERAL — no volume

Any OAuth config created live via the admin API is **lost on redeploy**. Two mechanisms:

1. **Restore via admin API — VALIDATED, the primary path.**
   [`restore-config.sh`](restore-config.sh) imports `data.zip` into an already-running PF via
   `POST /pf-admin-api/v1/configArchive/import`. Verified against the live server (2026-07-05):
   returns `success`, all 3 agent clients back, in ~1s, with zero disruption to in-flight token
   issuance. Run it after any redeploy that lands without the config, or after a container
   restart.

2. **Baked drop-in on boot — armed but UNVERIFIED.** The Dockerfile drops `data.zip` into
   `.../data/drop-in-deployer/data.zip` so PF imports it at boot. A verification redeploy
   (2026-07-05) **built fine but failed the runtime healthcheck** — PF's boot + config-import
   exceeded the healthcheck window (the previous image booted from a config-less `data.zip`, so
   it came up faster). The old deploy kept serving, so nothing broke. Before relying on this
   path, extend the service's healthcheck timeout (PF cold-boot + import can take several
   minutes) and confirm on a throwaway service. Until then, treat drop-in as best-effort and
   use mechanism (1) as the source of truth.

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
