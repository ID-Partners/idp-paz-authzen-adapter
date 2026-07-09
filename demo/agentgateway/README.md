# agentgateway (solo.io) — alternative gateway with an AuthZEN PEP extension

This directory makes [agentgateway](https://github.com/agentgateway/agentgateway)
a drop-in replacement for the demo's Kong gateway: same two PEPs, same
challenges, same AuthZEN PDP (Ping Authorize via the Go `authzen-adapter`).

## Run the demo with agentgateway

```bash
cd demo
docker compose -f docker-compose.yml -f docker-compose.agentgateway.yml up --build
# open http://localhost:8000   (agentgateway proxy is on host :8002, same as Kong was)
```

The override parks Kong, brings up `agentgateway` + `authzen-extauthz`, and
repoints the two governed hops (`bank-agent → /mcp`, `bank-mcp → /bank`).
Nothing else in the demo changes — the app, agent, MCP server, Bank API and
policies are untouched.

## How the AuthZEN extension works

agentgateway doesn't have an in-process plugin system like Kong's Lua plugins;
its extension point for authorization is the **Envoy-compatible External
Authorization (`extAuthz`) policy**. So the "AuthZEN plugin" is a tiny gRPC
sidecar, [`authzen-ext/`](authzen-ext/), that implements
`envoy.service.auth.v3.Authorization/Check` and is attached per-route in
[`config.yaml.template`](config.yaml.template):

```
bank-agent ──▶ agentgateway ──ext_authz gRPC──▶ authzen-extauthz ──AuthZEN──▶ authzen-adapter ──▶ Ping Authorize
                    │                                   │
                    ▼ (PERMIT)                          ▼ (DENY)
               bank-mcp / bank-api          exact 401/403 challenge passthrough
```

It is a 1:1 port of the Kong `authzen-pdp` plugin (`demo/kong/plugins/authzen-pdp`):

| Kong plugin concept | agentgateway equivalent |
|---|---|
| per-route plugin `config` block | `extAuthz.protocol.grpc.context` map, delivered as ext_authz `context_extensions` |
| token/claims extraction (`sub`, `act.sub`, `scope`, `cnf.jkt`) | same logic in Go (`main.go`, `jwt.go`) |
| DPoP sender-constraint check (RFC 9449) | same (`checkDpop`) |
| RFC 9470 `login_required` / `insufficient_scope` step-up challenges | returned via Envoy `DeniedHttpResponse` (status + `WWW-Authenticate` + JSON body pass through verbatim) |
| request → AuthZEN action/resource/context mapping | same patterns (`mapping.go`) — the PDP receives identical evaluation requests |
| `X-Auth-Principal/-Agent/-Scope` upstream headers | `OkHttpResponse.headers` |
| `X-PDP-PEP/-Decision/-Action/-Reason` response headers | `OkHttpResponse.response_headers_to_add` (and on the 403 deny) |
| `strip_path: true` on `/bank` | route `urlRewrite.path.prefix: /` |
| fail-closed on PDP outage | 503 from the extension + `extAuthz.failureMode: deny` |

The extension needs only two env vars: `AUTHZEN_URL` (the adapter) and
`AUTHZEN_API_KEY`. Everything route-specific (PEP label, `mcp`/`rest` style,
`require_dpop`, `require_user_login`, `stepup_scope`) lives in the gateway
config's `context` maps, so policy placement stays a gateway concern — exactly
as it was with Kong.

## Files

* `config.yaml.template` — agentgateway config: `/mcp` (PEP #1) and `/bank`
  (PEP #2) routes, each with its `extAuthz` policy. `__HOST__` placeholders are
  substituted at container start so the image works in docker-compose and on
  Railway (`*.railway.internal`).
* `docker-entrypoint.sh` — renders the template, execs `agentgateway -f`.
* `Dockerfile` — re-plates the upstream distroless binary onto `debian:trixie-slim`
  (glibc ≥ 2.39, and we need a shell for the entrypoint).
* `authzen-ext/` — the AuthZEN ext-authz extension (Go, self-contained module).

## Verified behaviour (smoke-tested against a stub PDP)

* `/mcp` without `X-User-Token` → `401 login_required` + `WWW-Authenticate`
  step-up challenge.
* `/mcp` `initialize` → PDP `access_mcp`; other JSON-RPC traffic → allowed on a
  valid token (`mcp-handshake`), matching Kong's session-preserving behaviour.
* `/bank/customers/alice/accounts` → `list_accounts` PERMIT, `/bank` prefix
  stripped upstream, `X-Auth-*` injected.
* Payment over limit → `403` with the PDP reason in body and `X-PDP-Reason`.
* Payment without the consented `banking:payments:transfer` scope →
  `401 insufficient_scope` challenge.
