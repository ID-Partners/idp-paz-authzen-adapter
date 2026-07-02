# Agentic Banking Demo — Agent identity, token exchange & gateway-enforced policy

An AI agent helps an existing bank customer **open a new account** and **make a
payment** into it. The point of the demo is to make the **identity and
authorization mechanics of AI agents** visible:

1. **The agent authenticates and gets a token.** The agent is a first-class
   OAuth identity, distinct from the human it acts for and from the software
   vendor that operates it.
2. **Token exchange (RFC 8693).** The agent obtains a *delegated* token that
   carries the human as `sub` **and** the agent as `act.sub` — **delegation, not
   impersonation**. The agent never presents the customer's identity as its own.
3. **DPoP (RFC 9449).** Tokens are sender-constrained: bound to the agent's key,
   so a stolen token is useless without the key.
4. **Policy enforced at the gateway (PEP), not in app code.** A **Kong** gateway
   sits in front of **both** the MCP surface *and* a classic REST **Bank API**,
   and calls **Ping Authorize** (via the AuthZEN adapter) for a decision on every
   request. You watch each action get PERMIT/DENY from policy in real time.

```
                         (1) client-credentials (agent actor token, DPoP)   ┌──────────────┐
              ┌──────────────────────────────────────────────────────────▶ │ PingFederate │
              │         (2) RFC 8693 token exchange:                        │  (real AS)   │
              │             subject=alice + actor=agent → delegated token   │ TE·PAR·DPoP  │
┌─────────┐   │                                                             └──────────────┘
│ Web UI  │─▶┌────────────┐  DPoP token  ┌──────────┐  token  ┌──────────┐   ┌──────────┐
│ /invoke │  │ bank-agent │─────────────▶│  KONG    │────────▶│ bank-mcp │──▶│  KONG    │──▶ bank-api
└─────────┘  │  (Claude)  │   MCP call   │ (PEP #1) │  tools  │ (tools)  │   │ (PEP #2) │    (RS)
             └────────────┘              └────┬─────┘         └──────────┘   └────┬─────┘
                                              │ AuthZEN eval                       │ AuthZEN eval
                                              ▼                                    ▼
                                       ┌────────────────┐  query/decision  ┌────────────────┐
                                       │ authzen-adapter │ ───────────────▶ │ Ping Authorize │
                                       │   (Go PDP)      │                  │    (policy)    │
                                       └────────────────┘                  └────────────────┘
```

## Components

| Component | Path | What it is |
|-----------|------|------------|
| **Bank Agent** | `agent/` | The AI agent (Claude via the Anthropic API), AgentCore-shaped (`POST /invocations`, `GET /ping`). `auth.py` obtains a **delegated, DPoP-bound token** (real PingFederate token exchange, or a local-mint mode). It connects to the MCP service **through Kong**, presenting the token on every call, and serves the web UI. |
| **Kong gateway** | `kong/` | Kong OSS (DB-less) running the custom **`authzen-pdp`** Lua plugin as **two PEPs**: PEP #1 at the MCP edge, PEP #2 at the Bank API edge. Each reads the token claims (`sub`, `act.sub`, `scope`, `cnf.jkt`), checks the DPoP binding, and calls the AuthZEN PDP before forwarding. |
| **Bank MCP service** | `mcp-server/` | A **Model Context Protocol** server exposing banking tools (`list_accounts`, `open_account`, `get_balance`, `make_payment`). It holds **no policy** — each tool calls the Bank API **through Kong (PEP #2)**, forwarding the delegated identity. |
| **Bank API** | `bank-api/` | The **Resource Server**: a plain REST banking API (accounts, balance, open, payments). No policy of its own; it trusts the gateway and records the `sub`/`act` delegation chain for its audit log. |
| **AuthZEN PDP adapter** | `../authzen-adapter/` | The existing Go service. Implements the [AuthZEN](https://authzen-interop.net) Authorization API and proxies decisions to **Ping Authorize**. Unchanged. |

### Two enforcement points, on purpose

* **PEP #1 (MCP edge)** is **coarse**: is this agent, on behalf of this
  principal, allowed to use the banking toolset at all? (It can also read the
  invoked tool name from the JSON-RPC body.)
* **PEP #2 (Bank API edge)** is **fine-grained**: it maps method + path + body to
  an action/resource/context (e.g. payment amount, from/to accounts) — this is
  where the amount-limit denial happens.

### Honest notes on the security model (demo simplifications)

* **DPoP is enforced at the agent→gateway hop (PEP #1).** The internal
  MCP→API hop forwards the delegated token as a **bearer** inside the trust
  boundary (PEP #2 still authorizes on the `sub`/`act` claims). A stricter build
  would have the MCP server do its own token exchange, adding itself to the
  `act` chain (`act:{sub: mcp, act:{sub: agent}}`) — noted as a future extension.
* **The `authzen-pdp` plugin reads JWT claims but does not verify the token
  signature itself.** In production, pair it with Kong's bundled
  `openid-connect`/`jwt` plugin (validating against the AS JWKS) so signatures
  are checked before these claims are trusted. The authorization *decision* is
  always Ping Authorize's.

## The scenario

Customer **Alice** (`cust-alice`) already has a checking account `CHK-1001`
(AUD 5,000). She asks the agent:

> *"Open a new savings account and move \$500 into it from my checking account."*

The transcript now shows: **① agent authenticates → ② token exchange (the
`sub`/`act` delegation chain) → connect via PEP #1 → open_account (PEP #2 PERMIT)
→ make_payment (PEP #2 decision)**. Try the **\$9,000** button to watch the
payment get **denied at the gateway** (amount limit / step-up) while the account
still opens — the whole governance story on one screen.

## Token modes

`TOKEN_MODE=local` (default) — the agent self-issues an equivalently-shaped
delegated, DPoP-bound token via a local demo IdP, so the demo runs immediately.

`TOKEN_MODE=pingfederate` — the agent performs the genuine flow against the
deployed PingFederate. This requires PF to be configured with:

1. an **Agent-Operator client** (`AGENT_CLIENT_ID`), confidential, grant types
   `client_credentials` + `urn:ietf:params:oauth:grant-type:token-exchange`,
   DPoP required;
2. a way to mint **Alice's subject token** carrying `may_act:{sub: <agent>}`;
3. a **token-exchange processor policy**: `subject_token`(Alice) +
   `actor_token`(agent) → token with `sub: alice`, `act:{sub: agent}`, attenuated
   scope + RAR `authorization_details`, sender-constrained to the agent key;
4. the RAR `type` (default
   `https://schemas.idpartners.com.au/agentic/payment_initiation/v1`);
5. the Bank API audience (`RS_AUDIENCE`).

## Ping Authorize policy inputs

Each PEP sends the PDP an AuthZEN evaluation request. Policy can branch on:

* **subject** — `type:"agent"`, `identity` (the agent `act.sub`),
  `properties.on_behalf_of` (the principal `sub`), `properties.scope`,
  `properties.client_id`, `properties.agent_type:"ai_assistant"`
* **action** — `access_mcp` / `invoke_tool` (PEP #1); `list_accounts` |
  `open_account` | `get_balance` | `make_payment` (PEP #2)
* **resource** — `type: account|customer|mcp-tool|mcp-service`, `id`, `properties`
* **context** — `channel:"ai-agent"`, `amount`, `currency`, `internal_transfer`, …

Example policy intent to author in Ping Authorize:
* Permit an AI agent to `open_account` for a KYC-verified customer.
* Permit `make_payment` on an internal transfer up to a limit (e.g. 2,000 AUD).
* Deny `make_payment` above the limit via the `ai-agent` channel (require human
  step-up), returning a `reason` the agent relays.

## Run locally

```bash
export ANTHROPIC_API_KEY=sk-ant-...
# point the adapter at your Ping Authorize:
export PDP_URL=https://<ping-authorize>/governance-engine
export QUERY_URL=https://<ping-authorize>/governance-engine/query
export PDP_SECRET=...           # CLIENT_TOKEN value

cd demo
docker compose up --build
# open http://localhost:8000   (Kong is on host :8002, admin :8001)
```

Runs in `TOKEN_MODE=local` by default. Set `TOKEN_MODE=pingfederate` (plus
`AGENT_CLIENT_ID`/`AGENT_CLIENT_SECRET`) once PF is configured.

## Deploy to Railway

Five services in the `idp-agentic-banking-demo` project. Required variables:

* `authzen-adapter`: `API_KEY`, `PDP_URL`, `QUERY_URL`, `PDP_SECRET`,
  `PDP_SECRET_HEADER`, `PDP_DOMAIN_PREFIX`, `PDP_ATTRIBUTE_PREFIX`,
  `PDP_SERVICE`, `PDP_ACTION`
* `kong`: `AUTHZEN_URL` (→ adapter private URL), `AUTHZEN_API_KEY`
* `bank-api`: (none required)
* `bank-mcp`: `BANK_API_BASE_URL` (→ `http://kong.railway.internal:8000/bank`),
  `AGENT_ID`
* `bank-agent`: `MCP_SERVER_URL` (→ `http://kong.railway.internal:8000/mcp`),
  `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`, `TOKEN_MODE`, `OIDC_ISSUER`,
  `AGENT_CLIENT_ID`/`AGENT_CLIENT_SECRET` (pingfederate mode), `RS_AUDIENCE`

## Verify

* **Gateway auth**: `curl` the Bank API through Kong with no token → `401`; with
  a delegated token for a permitted op → `200`; the \$9,000 payment → `403`
  carrying the Ping Authorize reason.
* **Delegation**: decode the issued token — assert `sub == cust-alice` **and**
  `act.sub == <agent>`, `cnf.jkt` present.
* **Full demo**: open the agent URL; \$500 run permits end-to-end, \$9,000 run
  opens the account but the payment is denied at PEP #2.
