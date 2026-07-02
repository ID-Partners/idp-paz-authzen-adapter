"""
Bank REST API — the Resource Server (RS).

This is a plain retail-banking API: list accounts, read a balance, open an
account, make a payment. It holds NO authorization policy of its own — every
request reaches it only after the Kong gateway (PEP #2) has already asked the
AuthZEN PDP (Ping Authorize) for a decision. The RS's job is to (a) do the
banking operation and (b) record who did it on whose behalf for the audit trail.

Kong forwards the delegation identity as headers derived from the delegated
access token's claims:

    X-Auth-Principal : the human principal   (token `sub`,   e.g. cust-alice)
    X-Auth-Agent     : the acting agent      (token `act.sub`)
    X-Auth-Scope     : the granted scope(s)

So the RS can log "Agent <act.sub> acted on behalf of Principal <sub>" without
re-doing authentication. In a hardened deployment the RS would also independently
validate the token audience; here it trusts the gateway and records the chain.
"""
from __future__ import annotations

import logging
import os

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from bank_store import store

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("bank-api")

app = FastAPI(title="Northwind Bank API (Resource Server)")


def _audit(action: str, principal: str | None, agent: str | None, detail: str) -> None:
    """Record the delegation chain for the action (who, on whose behalf)."""
    logger.info("AUDIT action=%s principal=%s agent=%s :: %s",
                action, principal or "?", agent or "?", detail)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/customers/{customer_id}/accounts")
def list_accounts(customer_id: str,
                  x_auth_principal: str | None = Header(default=None),
                  x_auth_agent: str | None = Header(default=None)):
    customer = store.get_customer(customer_id)
    if customer is None:
        return JSONResponse(status_code=404, content={"error": f"Unknown customer {customer_id}"})
    _audit("list_accounts", x_auth_principal, x_auth_agent, f"customer={customer_id}")
    return {
        "customer": {"id": customer.id, "name": customer.name},
        "accounts": [a.to_dict() for a in store.list_accounts(customer_id)],
    }


@app.get("/accounts/{account_id}/balance")
def get_balance(account_id: str,
                x_auth_principal: str | None = Header(default=None),
                x_auth_agent: str | None = Header(default=None)):
    acct = store.get_account(account_id)
    if acct is None:
        return JSONResponse(status_code=404, content={"error": f"Account {account_id} not found"})
    _audit("get_balance", x_auth_principal, x_auth_agent, f"account={account_id}")
    return {"account_id": acct.id, "balance": acct.balance, "currency": acct.currency}


class OpenAccountBody(BaseModel):
    customer_id: str
    account_type: str = "savings"
    nickname: str = ""


@app.post("/accounts")
def open_account(body: OpenAccountBody,
                 x_auth_principal: str | None = Header(default=None),
                 x_auth_agent: str | None = Header(default=None)):
    customer = store.get_customer(body.customer_id)
    if customer is None:
        return JSONResponse(status_code=404, content={"error": f"Unknown customer {body.customer_id}"})
    acct = store.open_account(body.customer_id, body.account_type, body.nickname)
    _audit("open_account", x_auth_principal, x_auth_agent,
           f"opened {acct.id} ({body.account_type}) for {body.customer_id}")
    return {
        "message": f"Opened {body.account_type} account {acct.id} for {customer.name}.",
        "account": acct.to_dict(),
    }


class PaymentBody(BaseModel):
    customer_id: str
    from_account: str
    to_account: str
    amount: float
    currency: str = "AUD"
    description: str = ""


@app.post("/payments")
def make_payment(body: PaymentBody,
                 x_auth_principal: str | None = Header(default=None),
                 x_auth_agent: str | None = Header(default=None)):
    src = store.get_account(body.from_account)
    if src is None or src.customer_id != body.customer_id:
        return JSONResponse(status_code=404,
                            content={"error": f"Source account {body.from_account} not found for {body.customer_id}"})
    dst = store.get_account(body.to_account)
    if dst is None:
        return JSONResponse(status_code=404, content={"error": f"Destination account {body.to_account} not found"})
    try:
        store.transfer(body.from_account, body.to_account, body.amount)
    except ValueError as exc:
        _audit("make_payment", x_auth_principal, x_auth_agent, f"FAILED: {exc}")
        return JSONResponse(status_code=422, content={"success": False, "message": str(exc)})
    _audit("make_payment", x_auth_principal, x_auth_agent,
           f"{body.amount:.2f} {body.currency} {body.from_account} -> {body.to_account}")
    return {
        "success": True,
        "message": f"Transferred {body.amount:.2f} {body.currency} "
                   f"from {body.from_account} to {body.to_account}.",
        "from_balance": src.balance,
        "to_balance": dst.balance,
    }


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8070"))
    logger.info("Starting Bank API (Resource Server) on 0.0.0.0:%s", port)
    uvicorn.run(app, host="0.0.0.0", port=port)
