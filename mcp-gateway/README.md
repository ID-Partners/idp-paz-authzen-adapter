# MCP AuthZEN Gateway (PEP)

A standalone reverse-proxy gateway that adds **AuthZEN fine-grained authorization** in front of any Model Context Protocol (MCP) server. It acts as a Policy Enforcement Point (PEP): it intercepts MCP JSON-RPC requests, maps each one to an AuthZEN Access Evaluation request, calls a standards-compliant **AuthZEN PDP**, and either forwards the call upstream or rejects it.

It implements the **Default AuthZEN Mappings for MCP JSON-RPC Messages** (MCP Specification 2025-11-25) and supports the **COAZ** `x-coaz-mapping` override for `tools/call`.

```
MCP client ──HTTP──▶ [ MCP AuthZEN Gateway ] ──▶ MCP server (upstream)
                            │
                            ▼  AuthZEN Access Evaluation
                     AuthZEN PDP  ──▶ { "decision": true|false }
```

## How it works

For each MCP request the gateway:

1. Accepts the MCP **Streamable HTTP** request (`POST` of a JSON-RPC message, single or batch).
2. Decodes the caller's JWT access-token claims from the `Authorization: Bearer` header (`sub`, `aud`, `client_id`).
3. Builds an AuthZEN evaluation request using the [default mappings](#default-mappings) (or the tool's `x-coaz-mapping` for `tools/call`, when configured).
4. Calls the configured AuthZEN PDP `/access/v1/evaluation` endpoint.
5. On `decision: true`, **forwards** the original request upstream and streams the response back (JSON or SSE). On `decision: false`, returns a JSON-RPC error with code **`-32401`** (the reason from the PDP, if any).

Requests that are **not** authorization targets are passed straight through: notifications (no `id`), client→server responses (no `method`), skip-listed methods (`initialize`, `ping` by default), and non-JSON / `GET` (SSE) / `DELETE` traffic.

> **Security model.** The gateway decodes JWT claims **without verifying the signature** — they are only used to build the AuthZEN request; the PDP makes the authoritative decision. Token validation (signature/introspection/audience checks) must be enforced by the MCP server's OAuth resource-server layer or added here before production use. Set `REQUIRE_TOKEN=true` (the default) to reject requests with no bearer token. PDP errors **fail closed** by default.

## Configuration

| Variable               | Default                | Description                                                                 |
|------------------------|------------------------|-----------------------------------------------------------------------------|
| `PORT`                 | `8080`                 | Port the gateway listens on.                                                |
| `MCP_UPSTREAM_URL`     | — (**required**)       | Base URL of the MCP server to protect, e.g. `http://mcp-server:9000`.       |
| `PDP_URL`              | — (**required**)       | AuthZEN evaluation endpoint, e.g. `https://pdp/access/v1/evaluation`.        |
| `PDP_API_KEY`          | —                      | Bearer key for the PDP (sent as `Authorization: Bearer <key>`).             |
| `PDP_AUTH_HEADER`      | `Authorization`        | Header used to authenticate to the PDP.                                      |
| `PDP_AUTH_SCHEME`      | `Bearer`               | Scheme prefix used with `PDP_API_KEY`.                                       |
| `PDP_AUTH_VALUE`       | —                      | Full raw value for the PDP auth header (overrides `PDP_API_KEY`).            |
| `PDP_TIMEOUT_MS`       | `5000`                 | PDP request timeout in milliseconds.                                         |
| `PDP_FAIL_OPEN`        | `false`                | If `true`, allow requests when the PDP is unreachable (default fails closed).|
| `REQUIRE_TOKEN`        | `true`                 | Reject requests without a bearer token (HTTP 401).                          |
| `SKIP_METHODS`         | `initialize,ping`      | Comma-separated methods that bypass authorization.                          |
| `COAZ_MAPPINGS_FILE`   | —                      | JSON file of `{ "<toolName>": <x-coaz-mapping> }` for `tools/call` overrides.|
| `MAX_BODY_BYTES`       | `4194304`              | Maximum request body size (bytes).                                          |
| `INSECURE_SKIP_VERIFY` | `false`                | Skip TLS verification for upstream and PDP (testing only).                  |
| `GATEWAY_HEALTH_PATH`  | `/healthz`             | Local health endpoint (returns `200 OK`, not proxied).                      |

## Default mappings

`subject = { type: "identity", id: <JWT sub> }`, `context.agent = <JWT client_id>`, `action.name = <method>` (the **tool name** for `tools/call`).

| MCP method(s)                                                  | `resource.type`                | `resource.id`        |
|---------------------------------------------------------------|--------------------------------|----------------------|
| `tools/call`                                                  | `tool`                         | tool name            |
| `resources/read`, `resources/subscribe`, `resources/unsubscribe` | `resource`                  | resource URI         |
| `prompts/get` (`subject.type` = `user`)                       | `prompt`                       | prompt name          |
| `tasks/get`, `tasks/result`, `tasks/cancel`                   | `task`                         | task id              |
| `completion/complete`                                         | `ref/prompt` or `ref/resource` | prompt name or URI   |
| `*/list`, `initialize`, `ping`, `sampling/createMessage`, `elicitation/create`, `logging/setLevel`, `roots/list` | `mcp_server` | JWT `aud` claim |

Method-specific context is added where applicable (`max_tokens`, `mode`/`elicitation_id`/`url`, `level`, `protocol_version`, `task_ttl`).

### COAZ overrides

To override the default `tools/call` mapping for COAZ-aware tools, provide a `COAZ_MAPPINGS_FILE`:

```json
{
  "get_customer": {
    "resource": { "id": "$.properties['id']", "type": "customer" },
    "subject":  { "type": "user", "id": "$.token['sub']" },
    "context":  { "agent": "$.token['client_id']", "case": "$.properties['case']" }
  }
}
```

`$.properties[...]` references the tool-call `arguments`; `$.token[...]` references the JWT claims.

## Running

```sh
export MCP_UPSTREAM_URL=http://localhost:9000
export PDP_URL=https://localhost:8443/access/v1/evaluation
export PDP_API_KEY=Password1
go run .
```

Point your MCP client at the gateway instead of the MCP server. Docker:

```sh
docker build -t mcp-authzen-gateway .
docker run -p 8080:8080 \
  -e MCP_UPSTREAM_URL=http://mcp-server:9000 \
  -e PDP_URL=https://pdp/access/v1/evaluation \
  -e PDP_API_KEY=... \
  mcp-authzen-gateway
```

## Limitations / future work

- JWT signatures are not verified (see security model above).
- COAZ overrides are loaded from a static file; auto-discovery of `x-coaz-mapping` by sniffing `tools/list` responses is not yet implemented.
- Authorization is enforced on client→server requests over Streamable HTTP. Server→client requests (sampling, elicitation, `roots/list`) carried on the SSE stream are proxied without per-message checks.
- In a JSON-RPC **batch**, a single denial fails the whole batch (each request id receives a `-32401`).
