# Authorization Proxy Service

## Overview
This project is an authorization proxy service that integrates with Ping Authorize and provides a set of APIs for evaluating access control policies, searching for subjects and resources, and making authorization decisions. The service is built in Go and acts as an intermediary between clients and a Policy Decision Point (PDP).

This implementation conforms to the [AuthZen Interop Specification](https://authzen-interop.net/docs/intro/), ensuring interoperability with authorization frameworks and standardized access control mechanisms.

It also implements the **Default AuthZEN Mappings for MCP JSON-RPC Messages** (MCP Specification 2025-11-25) and the **AuthZEN Profile for Model Context Protocol Tool Authorization (COAZ)**, mapping Model Context Protocol (MCP) operations onto the AuthZEN Subject-Action-Resource-Context model. See [MCP Support](#mcp-support) below.

## Components

This repository contains two components:

- **`authzen-adapter/`** — the AuthZEN PDP-side adapter described in this document. It exposes AuthZEN APIs and translates them to Ping Authorize, and includes helper endpoints for the MCP default mappings and COAZ resolution.
- **`mcp-gateway/`** — a standalone reverse-proxy **gateway / PEP** that sits in front of an MCP server, enforces AuthZEN authorization on MCP JSON-RPC requests by calling an AuthZEN PDP, and returns JSON-RPC `-32401` on denial. See [`mcp-gateway/README.md`](mcp-gateway/README.md).

## Features
- **Authorization Evaluation API**: Evaluates access requests based on subject, action, resource, and context.
- **Subject Search API**: Retrieves subjects matching a given action-resource pair.
- **Resource Search API**: Retrieves resources matching a given subject-action pair.
- **MCP Support**: Maps MCP JSON-RPC messages onto AuthZEN requests via the default mappings, and resolves `x-coaz-mapping` tool mappings (COAZ) into AuthZEN evaluation requests.
- **Ping Authorize Integration**: Queries Ping Authorize for policy decisions.
- **Environment Configuration**: Uses environment variables for configuration.
- **Secure API Key Authentication**: Validates API requests with Bearer token authentication.
- **Batch Evaluation Support**: Handles batch evaluation requests for multiple access queries.

## API Endpoints
### Authorization Evaluation
**Endpoint:** `/access/v1/evaluation`  
**Method:** `POST`  
**Description:** Evaluates a subject's authorization to perform an action on a resource.

### Batch Authorization Evaluation
**Endpoint:** `/access/v1/evaluations`  
**Method:** `POST`  
**Description:** Processes multiple evaluation requests in a single batch.

### Subject Search
**Endpoint:** `/access/v1/subjectsearch`  
**Method:** `POST`  
**Description:** Searches for subjects that match the given action and resource.

### Resource Search
**Endpoint:** `/access/v1/resourcesearch`  
**Method:** `POST`  
**Description:** Searches for resources that match the given subject and action.

### MCP JSON-RPC Mapping
**Endpoint:** `/access/v1/mcp/evaluate`  
**Method:** `POST`  
**Description:** Maps an MCP JSON-RPC message onto an AuthZEN evaluation request using the default mappings, optionally evaluating it against the PDP. See [MCP Support](#mcp-support).

### COAZ Mapping Resolution
**Endpoint:** `/access/v1/coaz/resolve`  
**Method:** `POST`  
**Description:** Resolves an MCP tool's `x-coaz-mapping` into an AuthZEN evaluation request, optionally evaluating it against the PDP. See [MCP Support](#mcp-support).

### Health Check
**Endpoint:** `/health`  
**Method:** `GET`  
**Description:** Returns `200 OK` to indicate service health.

## MCP Support

The adapter implements the **Default AuthZEN Mappings for MCP JSON-RPC Messages** (MCP Specification 2025-11-25) and the [AuthZEN Profile for Model Context Protocol Tool Authorization (COAZ)](https://openid.net/wg/authzen/specifications/). Together these let an MCP server/gateway act as a Policy Enforcement Point (PEP) and externalize authorization to an AuthZEN PDP.

### Default mappings

Each MCP JSON-RPC method maps onto the AuthZEN Subject-Action-Resource-Context (SARC) model. Common defaults:

- `subject.type` = `identity` (the identity on whose behalf the agent acts), `subject.id` = JWT `sub` claim
- `action.name` = the JSON-RPC method name (for `tools/call`, the **tool name**)
- `context.agent` = JWT `client_id` claim (the AI agent / MCP client)

`resource` varies by method:

| MCP method(s)                                                                 | `resource.type` | `resource.id`        |
|-------------------------------------------------------------------------------|-----------------|----------------------|
| `tools/call`                                                                  | `tool`          | tool name            |
| `resources/read`, `resources/subscribe`, `resources/unsubscribe`             | `resource`      | resource URI         |
| `prompts/get`                                                                 | `prompt`        | prompt name          |
| `tasks/get`, `tasks/result`, `tasks/cancel`                                   | `task`          | task id              |
| `completion/complete`                                                         | `ref/prompt` or `ref/resource` | prompt name or URI |
| `*/list`, `initialize`, `ping`, `sampling/createMessage`, `elicitation/create`, `logging/setLevel`, `roots/list`, notifications | `mcp_server` | JWT `aud` claim |

Method-specific context is also added where applicable (e.g. `max_tokens` for `sampling/createMessage`, `mode`/`elicitation_id`/`url` for `elicitation/create`, `level` for `logging/setLevel`, `protocol_version` for `initialize`, `task_ttl` for task-augmented `tools/call`). Per the spec, `prompts/get` uses `subject.type` = `user`.

Use the `/access/v1/mcp/evaluate` endpoint to map a JSON-RPC message and token claims into an AuthZEN request:

```sh
curl -X POST "http://localhost:8080/access/v1/mcp/evaluate" \
  -H "Authorization: Bearer <API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
        "message": {
          "jsonrpc": "2.0", "id": 1, "method": "tools/call",
          "params": { "name": "fintech_approve_expense", "arguments": { "expense_id": "exp-123", "amount": 5000 } }
        },
        "token": { "sub": "1234567890", "aud": "https://mcp.example.com", "client_id": "agent-app" },
        "evaluate": false
      }'
```

This yields the AuthZEN request:

```json
{
  "subject": { "type": "identity", "id": "1234567890" },
  "action": { "name": "fintech_approve_expense" },
  "resource": { "type": "tool", "id": "fintech_approve_expense" },
  "context": { "agent": "agent-app" }
}
```

Request fields:

| Field          | Description                                                                   |
|----------------|-------------------------------------------------------------------------------|
| `message`      | The MCP JSON-RPC message (`method` + `params`). Alternatively pass `method`/`params` directly. |
| `token`        | Decoded OAuth/JWT claims (`sub`, `aud`, `client_id`, ...).                     |
| `coaz_mapping` | Optional `x-coaz-mapping` for the called tool; overrides the default for `tools/call`. |
| `evaluate`     | If `true`, the mapped request is forwarded to the PDP and the decision is returned. |

The response contains the mapped `evaluation_request`, plus the `decision` (and any `context`) when `evaluate` is `true`. For tools that declare `coaz: true`, supply the tool's `x-coaz-mapping` in `coaz_mapping` to override the default `tools/call` mapping.

> Note: the standard `/access/v1/evaluation` endpoint decodes the AuthZEN subject id from the `identity` field (a Ping Authorize convention). The MCP mapping endpoints emit canonical AuthZEN `subject.id`; when feeding a mapped request to a generic AuthZEN PDP this is correct, but route MCP traffic through `/access/v1/mcp/evaluate` (with `evaluate: true`) to have this adapter perform the decision.

### Resolving `x-coaz-mapping`

A COAZ-aware tool declares an `x-coaz-mapping` object inside its `inputSchema`, projecting tool arguments and OAuth token claims onto the AuthZEN model using JSONPath-style references:

- `$.properties[...]` — the tool-call arguments (the `inputSchema` properties)
- `$.token[...]` — claims from the caller's (JWT) OAuth access token

The `/access/v1/coaz/resolve` endpoint resolves a mapping against concrete arguments and token claims:

```sh
curl -X POST "http://localhost:8080/access/v1/coaz/resolve" \
  -H "Authorization: Bearer <API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
        "tool": "get_customer",
        "mapping": {
          "resource": { "id": "$.properties['id']", "type": "customer" },
          "subject":  { "type": "user", "id": "$.token['sub']" },
          "context":  { "agent": "$.token['client_id']", "case": "$.properties['case']" }
        },
        "properties": { "id": "cust-1", "case": "case-42" },
        "token": { "sub": "u-9", "client_id": "agent-app" },
        "evaluate": false
      }'
```

Request fields:

| Field        | Description                                                                 |
|--------------|-----------------------------------------------------------------------------|
| `mapping`    | The tool's `x-coaz-mapping` object (required).                              |
| `tool`       | Tool name; used as the default `action.name` when the mapping omits one.    |
| `properties` | The resolved tool-call arguments (`$.properties` source).                   |
| `token`      | Decoded OAuth/JWT claims (`$.token` source).                                |
| `action`     | Optional override for `action.name` (e.g. `tools/call`).                    |
| `evaluate`   | If `true`, the resolved request is forwarded to the PDP and the decision is returned. |

The response contains the resolved `evaluation_request`, plus the `decision` (and any `context`) when `evaluate` is `true`.

## Environment Variables
| Variable               | Description                                      |
|------------------------|--------------------------------------------------|
| `PORT`                 | Port on which the service listens (default: 8080) |
| `API_KEY`              | API key required for authentication            |
| `QUERY_URL`            | URL of the PDP query endpoint                  |
| `PDP_URL`              | URL of the authorization decision endpoint      |
| `PDP_SECRET_HEADER`    | HTTP header name for PDP authentication token  |
| `PDP_SECRET`           | Secret token for PDP authentication            |
| `PDP_DOMAIN_PREFIX`    | Domain prefix used in PDP requests             |
| `PDP_ATTRIBUTE_PREFIX` | Attribute prefix for query parameters          |
| `PDP_SERVICE`          | PDP service identifier                         |
| `PDP_ACTION`           | PDP action identifier                          |

## Running the Service
### Prerequisites
- Go 1.18+
- Ping Authorize setup with governance policies
- Compliance with [AuthZen Interop Specification](https://authzen-interop.net/docs/intro/)

### Installation
1. Clone the repository:
   ```sh
   git clone <repository-url>
   cd <repository-folder>
   ```
2. Install dependencies:
   ```sh
   go mod tidy
   ```

### Running the Service
1. Set environment variables in a `.env` file or export them in your shell.
2. Start the service:
   ```sh
   go run main.go
   ```
3. The service will be available on `http://localhost:8080` by default.

### Docker Support
To run the service in a Docker container:
```sh
docker build -t auth-proxy .
docker run -p 8080:8080 --env-file .env auth-proxy
```

## Authentication
All API endpoints require a Bearer token in the `Authorization` header:
```sh
curl -X POST "http://localhost:8080/access/v1/evaluation" \
  -H "Authorization: Bearer <API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{ "subject": {"type": "user", "identity": "12345"}, "action": {"name": "read"}, "resource": {"type": "document", "id": "abc-123"} }'
```

## Logging and Debugging
- Logs include request details, environment variables, and decision responses.
- Debugging can be enabled by setting the appropriate log levels in the Go application.

## Contributing
- Fork the repository
- Create a feature branch
- Submit a pull request with changes

## License
This project is licensed under the MIT License.

---
For more details, contact the repository maintainer.

