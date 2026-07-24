"""
Accounts MCP service (accounts/payments split — accounts domain).

Exposes the ACCOUNTS-domain retail-banking tools over the Model Context Protocol
(streamable HTTP transport): list_accounts, get_balance, open_account. It holds
**no authorization policy of its own** — that lives at the accounts gateway. This
MCP server sits behind the accounts gateway (PEP #1) and each tool calls the
Accounts REST API **through the accounts gateway (PEP #2)**, forwarding the
caller's delegated identity. Ping Authorize (via the AuthZEN adapter) is consulted
at both hops.

`BANK_API_BASE_URL` points at the accounts gateway's route to the accounts-api
(e.g. http://kong-accounts:8000/accounts).
"""
from __future__ import annotations

import logging
import os

from mcp.server.fastmcp import Context, FastMCP

import rs_client

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("accounts-mcp")

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8090"))

mcp = FastMCP(
    name="northwind-accounts",
    instructions=(
        "Retail banking ACCOUNTS tools for an AI assistant acting on behalf of a "
        "bank customer. Use list_accounts to discover a customer's accounts, "
        "get_balance to read a balance, and open_account to open a new account. "
        "Every action is authorized by the bank's policy gateway; a tool may "
        "return \"authorized\": false with a POLICY DENIED message, which you must "
        "relay to the customer without retrying."
    ),
    host=HOST,
    port=PORT,
    stateless_http=True,
)


def _incoming_token(ctx: Context | None, principal: str) -> str:
    """The delegated token to forward to the Accounts API through the gateway.

    Prefer the access token that arrived on the inbound MCP request (true
    end-to-end identity pass-through). Fall back to a claims-only token carrying
    the principal + agent so the API-edge PEP still has an identity to authorize.
    """
    try:
        req = ctx.request_context.request  # type: ignore[union-attr]
        auth = req.headers.get("authorization") if req else None
        if auth and " " in auth:
            return auth.split(" ", 1)[1]
    except Exception:  # noqa: BLE001 - transport may not expose the raw request
        pass
    return rs_client.mint_claims_token(principal)


def _incoming_user_token(ctx: Context | None) -> str | None:
    """The logged-in principal's (Alice's) PF token, forwarded on so the API-edge
    PEP can check her consented scopes (X-User-Token from the inbound request)."""
    try:
        req = ctx.request_context.request  # type: ignore[union-attr]
        return req.headers.get("x-user-token") if req else None
    except Exception:  # noqa: BLE001
        return None


@mcp.tool()
async def list_accounts(customer_id: str, ctx: Context = None) -> dict:
    """List the accounts held by a customer.

    Args:
        customer_id: The bank customer identifier — the authenticated principal, e.g. "alice".
    """
    token = _incoming_token(ctx, customer_id)
    resp = await rs_client.call("GET", f"/customers/{customer_id}/accounts", token,
                                user_token=_incoming_user_token(ctx))
    return rs_client.summarize(resp)


@mcp.tool()
async def get_balance(customer_id: str, account_id: str, ctx: Context = None) -> dict:
    """Get the balance of one of the customer's accounts.

    Args:
        customer_id: The bank customer identifier.
        account_id: The account to read, e.g. "CHK-1001".
    """
    token = _incoming_token(ctx, customer_id)
    resp = await rs_client.call("GET", f"/accounts/{account_id}/balance", token,
                                user_token=_incoming_user_token(ctx))
    return rs_client.summarize(resp)


@mcp.tool()
async def open_account(customer_id: str, account_type: str = "savings",
                       nickname: str = "", ctx: Context = None) -> dict:
    """Open a new bank account for an existing customer.

    Args:
        customer_id: The bank customer identifier.
        account_type: The kind of account to open, e.g. "savings" or "checking".
        nickname: An optional friendly name for the account.
    """
    token = _incoming_token(ctx, customer_id)
    resp = await rs_client.call("POST", "/accounts", token, json_body={
        "customer_id": customer_id, "account_type": account_type, "nickname": nickname},
        user_token=_incoming_user_token(ctx))
    return rs_client.summarize(resp)


# ---------------------------------------------------------------------------
# COAZ (OpenID AuthZEN MCP profile) declarations — accounts domain only.
# Each tool advertises `coaz: true` plus an `x-coaz-mapping` in its inputSchema,
# telling the gateway PEP (coaz-pep) how the tool's arguments and the caller's
# token claims map to an AuthZEN evaluation request. String values are CEL
# expressions over `params` (the tools/call params) and `token` (decoded
# access-token claims); static values are CEL string literals. The shapes match
# the REST-edge PEP so the existing Ping Authorize policies govern MCP calls
# unchanged.
# ---------------------------------------------------------------------------
from mcp import types as mcp_types  # noqa: E402

_AGENT_EXPR = ("has(token.act) ? token.act.sub : "
               "(has(token.client_id) ? token.client_id : 'unknown-agent')")
_COAZ_SUBJECT = [{
    "type": "'agent'",
    "identity": _AGENT_EXPR,
    "properties": {
        "on_behalf_of": "has(token.sub) ? token.sub : ''",
        "agent_type": "'ai_assistant'",
        "scope": "has(token.scope) ? token.scope : ''",
        "client_id": "has(token.client_id) ? token.client_id : ''",
    },
}]
_COAZ_CONTEXT_BASE = {"channel": "'ai-agent'", "agent": _AGENT_EXPR}

COAZ_MAPPINGS: dict[str, dict] = {
    "list_accounts": {
        "subject": _COAZ_SUBJECT,
        "action": [{"name": "'list_accounts'"}],
        "resource": [{"type": "'customer'", "id": "params.arguments.customer_id"}],
        "context": [dict(_COAZ_CONTEXT_BASE)],
    },
    "get_balance": {
        "subject": _COAZ_SUBJECT,
        "action": [{"name": "'get_balance'"}],
        "resource": [{"type": "'account'", "id": "params.arguments.account_id"}],
        "context": [dict(_COAZ_CONTEXT_BASE)],
    },
    "open_account": {
        "subject": _COAZ_SUBJECT,
        "action": [{"name": "'open_account'"}],
        "resource": [{
            "type": "'account'",
            "id": ("'new:' + (has(params.arguments.account_type) ? "
                   "params.arguments.account_type : 'savings')"),
            "properties": {
                "account_type": ("has(params.arguments.account_type) ? "
                                 "params.arguments.account_type : 'savings'"),
            },
        }],
        "context": [dict(_COAZ_CONTEXT_BASE)],
    },
}


@mcp._mcp_server.list_tools()
async def _coaz_list_tools() -> list[mcp_types.Tool]:
    """tools/list with COAZ declarations attached (replaces the stock handler)."""
    tools = []
    for info in mcp._tool_manager.list_tools():
        schema = dict(info.parameters)
        extra: dict = {}
        if info.name in COAZ_MAPPINGS:
            schema = {**schema, "x-coaz-mapping": COAZ_MAPPINGS[info.name]}
            extra["coaz"] = True
        tools.append(mcp_types.Tool(
            name=info.name, description=info.description,
            inputSchema=schema, **extra))
    return tools


if __name__ == "__main__":
    logger.info("Starting Accounts MCP server on %s:%s (Accounts API via %s)",
                HOST, PORT, rs_client.BANK_API_BASE_URL)
    # Streamable HTTP transport -> tools reachable at http://<host>:<port>/mcp
    mcp.run(transport="streamable-http")
