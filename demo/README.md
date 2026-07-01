# Agentic Banking Demo — AWS AgentCore + MCP + Ping Authorize (AuthZEN)

An AI agent helps an existing bank customer **open a new account** and then
**make a payment** into it. Every action the agent takes is authorized by
**Ping Authorize**, reached through the AuthZEN PDP adapter in this repo. The
demo makes agent governance visible: you can watch each tool call get a
**PERMIT** or **DENY** decision from policy in real time.

```
┌────────────┐   invoke    ┌─────────────────────┐   MCP    ┌──────────────┐  AuthZEN  ┌──────────────┐   Ping    ┌───────────────┐
│  Web UI /  │ ──────────▶ │  Bank Agent         │ ───────▶ │  Bank MCP    │ ────────▶ │ AuthZEN PDP  │ ────────▶ │ Ping Authorize│
│  API call  │             │  (AgentCore-shaped, │  tools   │  service     │  /access/ │  adapter     │ query/    │  (policy)     │
└────────────┘             │   Claude via API)   │          │  (tools +    │  v1/eval  │  (Go)        │ decision  └───────────────┘
                           └─────────────────────┘          │   PDP calls) │           └──────────────┘
                                                             └──────────────┘
```

## Components

| Component | Path | What it is |
|-----------|------|------------|
| **Bank Agent** | `agent/` | The AI agent. Implements the **Amazon Bedrock AgentCore Runtime contract** (`POST /invocations`, `GET /ping`) so it runs anywhere as a container today and lifts to AgentCore Runtime unchanged. Uses **Claude via the Anthropic API**. Connects to the Bank MCP service, discovers tools, and drives the scenario. Serves the demo web UI. |
| **Bank MCP service** | `mcp-server/` | A **Model Context Protocol** server (streamable HTTP) exposing banking tools: `list_accounts`, `open_account`, `get_balance`, `make_payment`. **Before every action it calls the AuthZEN PDP** — this is where Ping Authorize governs the agent. |
| **AuthZEN PDP adapter** | `../authzen-adapter/` | The existing Go service. Implements the [AuthZEN](https://authzen-interop.net) Authorization API and proxies decisions to **Ping Authorize**. |

### Why "AgentCore-shaped" and not literally AgentCore Runtime?

Amazon Bedrock AgentCore Runtime is an AWS-hosted service and cannot run on
Railway. So the agent is written to the **exact AgentCore programming model** —
an `/invocations` + `/ping` HTTP contract (`agent/app.py`) — which:

* runs as a plain container on Railway (this demo), and
* promotes to AWS AgentCore Runtime with **no code change** via
  `agent/agentcore_entrypoint.py`, which wraps the same `run_agent()` in the
  `bedrock-agentcore` SDK (`BedrockAgentCoreApp`). See that file for the
  `agentcore configure` / `agentcore launch` steps.

## The scenario

Customer **Alice** (`cust-alice`) already has a checking account `CHK-1001`
(AUD 5,000). She asks the agent:

> *"Open a new savings account and move \$500 into it from my checking account."*

The agent:
1. connects to the MCP service and lists tools;
2. calls `open_account` → PDP **PERMIT** → savings account created;
3. calls `make_payment` (CHK-1001 → new savings) → PDP decision applied;
4. reports back, relaying any policy denial verbatim.

Try the **\$9,000** example button to see a policy denial (e.g. an amount limit
or step-up requirement) block the payment while the account still opens — the
governance story in one screen.

## Ping Authorize policy inputs

Each tool sends the PDP an AuthZEN evaluation request. Policy can branch on:

* **subject** — `type: "agent"`, `identity`, `properties.on_behalf_of` (the human
  principal), `properties.agent_type: "ai_assistant"`
* **action** — `list_accounts` | `open_account` | `get_balance` | `make_payment`
* **resource** — `type: account|customer`, `id`, `properties` (account type,
  from/to accounts, kyc_verified)
* **context** — `channel: "ai-agent"`, `amount`, `currency`, `internal_transfer`, …

Example policy intent to demo (author these in Ping Authorize):
* Permit an AI-agent to `open_account` for a KYC-verified customer.
* Permit `make_payment` on an internal transfer up to a limit (e.g. 2,000 AUD).
* Deny `make_payment` above the limit via the `ai-agent` channel (require human
  step-up), returning a `reason` the agent will relay.

## Run locally

```bash
export ANTHROPIC_API_KEY=sk-ant-...
# point the adapter at your Ping Authorize:
export PDP_URL=https://<ping-authorize>/governance-engine
export QUERY_URL=https://<ping-authorize>/governance-engine/query
export PDP_SECRET=...           # CLIENT_TOKEN value

cd demo
docker compose up --build
# open http://localhost:8000
```

## Deploy to Railway

The three services deploy as three Railway services in one project (see
`RAILWAY.md` for the exact wiring, or the deploy performed by the assistant).
Required variables:

* `authzen-adapter`: `API_KEY`, `PDP_URL`, `QUERY_URL`, `PDP_SECRET`,
  `PDP_SECRET_HEADER`, `PDP_DOMAIN_PREFIX`, `PDP_ATTRIBUTE_PREFIX`,
  `PDP_SERVICE`, `PDP_ACTION`
* `bank-mcp`: `AUTHZEN_PDP_URL` (→ adapter, private URL), `AUTHZEN_API_KEY`
* `bank-agent`: `MCP_SERVER_URL` (→ mcp, private URL + `/mcp`),
  `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`
