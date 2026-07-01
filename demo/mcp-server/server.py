"""
Bank MCP service.

Exposes a small set of retail-banking tools over the Model Context Protocol
(streamable HTTP transport). Before performing ANY state-changing or
sensitive-read action, each tool asks the AuthZEN PDP (the Go `authzen-adapter`
in front of Ping Authorize) for a decision. If policy denies, the tool returns a
human-readable denial instead of acting — so the AI agent can explain to the
user why it couldn't proceed.

Scenario the tools support:
  An existing customer (Alice) asks an AI agent to open a new savings account
  with her bank and then move an opening deposit into it. Opening the account is
  routine; the payment is governed by Ping Authorize policy (e.g. amount limits,
  KYC, agent-channel rules).
"""
from __future__ import annotations

import logging
import os

from mcp.server.fastmcp import FastMCP

import pdp
from bank_store import store

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
        "make_payment to move money between accounts. Every action is subject to "
        "the bank's authorization policy; a tool may return a POLICY DENIED "
        "result, which you must relay to the customer without retrying."
    ),
    host=HOST,
    port=PORT,
    stateless_http=True,
)


def _denied(decision: pdp.Decision) -> str:
    return f"POLICY DENIED by Ping Authorize: {decision.reason}"


@mcp.tool()
async def list_accounts(customer_id: str) -> dict:
    """List the accounts held by a customer.

    Args:
        customer_id: The bank customer identifier, e.g. "cust-alice".
    """
    customer = store.get_customer(customer_id)
    if customer is None:
        return {"error": f"Unknown customer {customer_id}"}

    decision = await pdp.evaluate(
        action="list_accounts",
        resource_type="customer",
        resource_id=customer_id,
        on_behalf_of=customer_id,
        resource_properties={"kyc_verified": customer.kyc_verified},
    )
    if decision.denied:
        return {"authorized": False, "message": _denied(decision)}

    return {
        "authorized": True,
        "policy_reason": decision.reason,
        "customer": {"id": customer.id, "name": customer.name},
        "accounts": [a.to_dict() for a in store.list_accounts(customer_id)],
    }


@mcp.tool()
async def get_balance(customer_id: str, account_id: str) -> dict:
    """Get the balance of one of the customer's accounts.

    Args:
        customer_id: The bank customer identifier.
        account_id: The account to read, e.g. "CHK-1001".
    """
    acct = store.get_account(account_id)
    if acct is None or acct.customer_id != customer_id:
        return {"error": f"Account {account_id} not found for customer {customer_id}"}

    decision = await pdp.evaluate(
        action="get_balance",
        resource_type="account",
        resource_id=account_id,
        on_behalf_of=customer_id,
        resource_properties={"account_type": acct.type},
    )
    if decision.denied:
        return {"authorized": False, "message": _denied(decision)}

    return {
        "authorized": True,
        "policy_reason": decision.reason,
        "account_id": acct.id,
        "balance": acct.balance,
        "currency": acct.currency,
    }


@mcp.tool()
async def open_account(customer_id: str, account_type: str = "savings",
                       nickname: str = "") -> dict:
    """Open a new bank account for an existing customer.

    Args:
        customer_id: The bank customer identifier.
        account_type: The kind of account to open, e.g. "savings" or "checking".
        nickname: An optional friendly name for the account.
    """
    customer = store.get_customer(customer_id)
    if customer is None:
        return {"error": f"Unknown customer {customer_id}"}

    decision = await pdp.evaluate(
        action="open_account",
        resource_type="account",
        resource_id=f"new:{account_type}",
        on_behalf_of=customer_id,
        resource_properties={"account_type": account_type},
        context={"kyc_verified": customer.kyc_verified},
    )
    if decision.denied:
        return {"authorized": False, "message": _denied(decision)}

    acct = store.open_account(customer_id, account_type, nickname)
    return {
        "authorized": True,
        "policy_reason": decision.reason,
        "message": f"Opened {account_type} account {acct.id} for {customer.name}.",
        "account": acct.to_dict(),
    }


@mcp.tool()
async def make_payment(customer_id: str, from_account: str, to_account: str,
                       amount: float, currency: str = "AUD",
                       description: str = "") -> dict:
    """Move money from one of the customer's accounts to another account.

    Args:
        customer_id: The bank customer identifier.
        from_account: Source account id, e.g. "CHK-1001".
        to_account: Destination account id.
        amount: Amount to transfer.
        currency: ISO currency code, default AUD.
        description: Optional payment reference.
    """
    src = store.get_account(from_account)
    if src is None or src.customer_id != customer_id:
        return {"error": f"Source account {from_account} not found for customer {customer_id}"}
    dst = store.get_account(to_account)
    if dst is None:
        return {"error": f"Destination account {to_account} not found"}

    decision = await pdp.evaluate(
        action="make_payment",
        resource_type="account",
        resource_id=from_account,
        on_behalf_of=customer_id,
        resource_properties={
            "from_account": from_account,
            "to_account": to_account,
            "account_type": src.type,
        },
        context={
            "amount": amount,
            "currency": currency,
            "description": description,
            "internal_transfer": dst.customer_id == customer_id,
        },
    )
    if decision.denied:
        return {"authorized": False, "message": _denied(decision)}

    try:
        store.transfer(from_account, to_account, amount)
    except ValueError as exc:
        return {"authorized": True, "success": False, "message": str(exc)}

    return {
        "authorized": True,
        "success": True,
        "policy_reason": decision.reason,
        "message": f"Transferred {amount:.2f} {currency} from {from_account} to {to_account}.",
        "from_balance": src.balance,
        "to_balance": dst.balance,
    }


if __name__ == "__main__":
    logger.info("Starting Bank MCP server on %s:%s (PDP=%s)", HOST, PORT, pdp.AUTHZEN_PDP_URL)
    # Streamable HTTP transport -> tools reachable at http://<host>:<port>/mcp
    mcp.run(transport="streamable-http")
