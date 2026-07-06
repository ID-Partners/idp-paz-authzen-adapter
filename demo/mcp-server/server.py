"""
Bank MCP service.

Exposes a small set of retail-banking tools over the Model Context Protocol
(streamable HTTP transport). It holds **no authorization policy of its own** —
that moved to the Kong gateway. This MCP server itself sits behind Kong (PEP #1),
and each tool calls the Bank REST API **through Kong (PEP #2)**, forwarding the
caller's delegated identity. Ping Authorize (via the AuthZEN adapter) is consulted
at both gateway hops.

Scenario the tools support:
  An existing customer (Alice) asks an AI agent to open a new savings account
  with her bank and then move an opening deposit into it. Opening the account is
  routine; the payment is governed by policy at the Bank API edge (amount limits,
  KYC, agent-channel rules) — enforced by Kong, not by this server.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from mcp.server.fastmcp import Context, FastMCP

import rs_client

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("bank-mcp")

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8090"))

mcp = FastMCP(
    name="northwind-bank",
    instructions=(
        "Retail banking tools for an AI assistant acting on behalf of a bank "
        "customer. Use list_accounts to discover a customer's accounts, "
        "open_account to open a new account, get_balance to read a balance, and "
        "make_payment to move money between accounts. Every action is authorized "
        "by the bank's policy gateway; a tool may return \"authorized\": false "
        "with a POLICY DENIED message, which you must relay to the customer "
        "without retrying."
    ),
    host=HOST,
    port=PORT,
    stateless_http=True,
)


def _incoming_token(ctx: Context | None, principal: str) -> str:
    """The delegated token to forward to the Bank API through Kong.

    Prefer the access token that arrived on the inbound MCP request (true
    end-to-end identity pass-through). Fall back to a claims-only token carrying
    the principal + agent so PEP #2 still has an identity to authorize.
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
    """The logged-in principal's (Alice's) PF token, forwarded on so PEP #2 can
    check her consented scopes (X-User-Token from the inbound MCP request)."""
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


@mcp.tool()
async def make_payment(customer_id: str, from_account: str, to_account: str,
                       amount: float, currency: str = "AUD",
                       description: str = "", ctx: Context = None) -> dict:
    """Move money from one of the customer's accounts to another account.

    Args:
        customer_id: The bank customer identifier.
        from_account: Source account id, e.g. "CHK-1001".
        to_account: Destination account id.
        amount: Amount to transfer.
        currency: ISO currency code, default AUD.
        description: Optional payment reference.
    """
    token = _incoming_token(ctx, customer_id)
    resp = await rs_client.call("POST", "/payments", token, json_body={
        "customer_id": customer_id, "from_account": from_account,
        "to_account": to_account, "amount": amount, "currency": currency,
        "description": description}, user_token=_incoming_user_token(ctx))
    return rs_client.summarize(resp)


if __name__ == "__main__":
    logger.info("Starting Bank MCP server on %s:%s (Bank API via %s)",
                HOST, PORT, rs_client.BANK_API_BASE_URL)
    # Streamable HTTP transport -> tools reachable at http://<host>:<port>/mcp
    mcp.run(transport="streamable-http")
