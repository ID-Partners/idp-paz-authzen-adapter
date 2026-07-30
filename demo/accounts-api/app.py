"""
Accounts REST API — the ACCOUNTS-domain Resource Server (RS).

After the accounts/payments split this service is the system-of-record for
customers and accounts: list accounts, read a balance, open an account, and the
atomic money-move primitive (`POST /transfers`) that the payments-api calls. It
holds NO authorization policy of its own — every request reaches it only after
the ACCOUNTS gateway (PEP) has already asked the AuthZEN PDP (Ping Authorize) for
a decision. The RS's job is to (a) do the banking operation and (b) record who
did it on whose behalf for the audit trail.

The gateway forwards the delegation identity as headers derived from the
delegated access token's claims:

    X-Auth-Principal : the human principal   (token `sub`,   e.g. alice)
    X-Auth-Agent     : the acting agent      (token `act.sub`)
    X-Auth-Scope     : the granted scope(s)

So the RS can log "Agent <act.sub> acted on behalf of Principal <sub>" without
re-doing authentication, and it ENFORCES that the customer_id in each request is
the authenticated principal (X-Auth-Principal) — the token, not an agent-supplied
parameter, decides whose accounts are in scope.

`POST /transfers` is the internal money-move endpoint. The payments-api owns the
`make_payment` action (authorized at the payments gateway) and then calls this
endpoint THROUGH the accounts gateway, so the debit is independently authorized
in the accounts domain too (layered per-domain authz).
"""
from __future__ import annotations

import logging
import os

import httpx
from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from bank_store import store

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("accounts-api")

app = FastAPI(title="Northwind Accounts API (Resource Server)")


def _audit(action: str, principal: str | None, agent: str | None, detail: str) -> None:
    """Record the delegation chain for the action (who, on whose behalf)."""
    logger.info("AUDIT action=%s principal=%s agent=%s :: %s",
                action, principal or "?", agent or "?", detail)


# Bank STAFF principals: may act on a NAMED customer's data (the autonomous demo —
# Bob, the agent owner, operating on Alice's accounts under an authorized, policy-
# governed flow). Every such access is audited as staff access. Customers can only
# ever act on themselves.
STAFF_PRINCIPALS = set((os.environ.get("STAFF_PRINCIPALS", "bob")).split(","))


def _proofing_state(customer_id: str, account_type: str) -> tuple[str, str | None]:
    """Ask the directory about this customer's identity-proofing for this account type. Returns
    (reason, consumedByAccount):

        "active"    a fresh, unconsumed proofing exists — a genuinely NEW origination is
                    authorised (open a new account and bind the proofing to it).
        "consumed"  the proofing was already spent to open an account — this call is a step-up
                    RESUME replaying an already-completed open; return the account it opened
                    (consumedByAccount) rather than stacking a duplicate.
        "none"      no proofing on record — either the gate is off for this type, or the gateway
                    would already have challenged (so we just open).
    """
    if not PROOFING_DIRECTORY_URL:
        return "none", None
    try:
        r = httpx.get(f"{PROOFING_DIRECTORY_URL}/proofing/present", timeout=4.0,
                      params={"subject": customer_id, "account": account_type})
        if r.status_code >= 300:
            return "none", None
        d = r.json()
        return (d.get("reason") or "none"), d.get("consumedByAccount")
    except Exception as exc:  # noqa: BLE001
        logger.warning("proofing-state lookup failed for %s/%s: %s — treating as none",
                       customer_id, account_type, exc)
        return "none", None


def _forbid_foreign_customer(customer_id: str, principal: str | None) -> JSONResponse | None:
    """Enforce that the action targets the AUTHENTICATED principal's own data.

    The customer_id an agent supplies must equal the delegated token's `sub`
    (forwarded by the gateway as X-Auth-Principal). Otherwise an agent acting for
    one customer could reach another customer's accounts — the token, not the
    request parameter, decides whose data is in scope. Exception: a bank STAFF
    principal (STAFF_PRINCIPALS) may act on a named customer — the gateway/PDP
    already authorized the call and the access is audited. When no principal
    header is present (e.g. a direct dev call that didn't pass through the
    gateway) we don't block, so local testing without the gateway still works."""
    if principal and customer_id != principal:
        if principal in STAFF_PRINCIPALS:
            logger.info("AUDIT staff-access: staff principal=%s acting on customer=%s",
                        principal, customer_id)
            return None
        logger.warning("DENY foreign customer: principal=%s attempted customer=%s",
                       principal, customer_id)
        return JSONResponse(status_code=403, content={
            "success": False,
            "error": "forbidden",
            "message": (f"The authenticated user '{principal}' may not act on behalf "
                        f"of customer '{customer_id}'."),
        })
    return None


# The identity-proofing directory. An mDL proofing is SINGLE-USE: it authorises ONE origination
# and is spent by it, so the record becomes the proofing for the account it opened and the next
# account needs a fresh one. We spend it here — once the account genuinely exists — rather than at
# the PDP permit, so a permitted-but-failed origination doesn't burn the customer's proofing.
PROOFING_DIRECTORY_URL = os.environ.get("PROOFING_DIRECTORY_URL", "").rstrip("/")


def _consume_proofing(customer_id: str, account_type: str, account_id: str) -> None:
    """Spend the proofing that authorised this origination. Best-effort: the account is already
    open and the PDP already authorised it, so a directory blip must not fail the customer's
    request — but it IS loud, because a proofing that silently isn't spent is reusable."""
    if not PROOFING_DIRECTORY_URL:
        return
    try:
        r = httpx.post(f"{PROOFING_DIRECTORY_URL}/proofing/consume", timeout=4.0,
                       json={"subject": customer_id, "account": account_type,
                             "account_id": account_id})
        if r.status_code == 404:
            # Nothing to spend: the gate is off, or this type needs no proofing.
            logger.info("No proofing to spend for %s/%s (account %s)",
                        customer_id, account_type, account_id)
        elif r.status_code >= 300:
            logger.warning("Proofing NOT spent for %s/%s (account %s): HTTP %s — it stays reusable",
                           customer_id, account_type, account_id, r.status_code)
        else:
            logger.info("Proofing spent by account %s (%s/%s)", account_id, customer_id, account_type)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Proofing NOT spent for %s/%s (account %s): %s — it stays reusable",
                       customer_id, account_type, account_id, exc)


def _customer_or_provision(customer_id: str, principal: str | None):
    """The customer's file, opening one on first touch for a NEW signed-in user.

    Self-provision ONLY: we open a file when the requested customer IS the authenticated
    principal, so a newly signed-up passkey user becomes a customer owning everything under
    their own `sub`. A staff principal (who may legitimately act on a NAMED customer) can never
    conjure a customer that doesn't exist, and an unauthenticated/dev call can't either — both
    still get the 404."""
    existing = store.get_customer(customer_id)
    if existing is not None:
        return existing
    if principal and customer_id == principal:
        cust = store.get_or_create_customer(customer_id)
        logger.info("Opened a customer file for new user %s (accounts=%s)",
                    customer_id, cust.accounts)
        return cust
    return None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/admin/reset")
def admin_reset():
    """Re-seed the in-memory bank to its starting state (fresh balances, only the
    two seeded accounts). Demo convenience — not a real banking operation."""
    store.reset()
    accts = store.list_accounts("alice")
    logger.info("Accounts store reset to seed state")
    return {"status": "reset",
            "accounts": [{"id": a.id, "balance": a.balance} for a in accts]}


@app.get("/customers/{customer_id}/accounts")
def list_accounts(customer_id: str,
                  x_auth_principal: str | None = Header(default=None),
                  x_auth_agent: str | None = Header(default=None)):
    denied = _forbid_foreign_customer(customer_id, x_auth_principal)
    if denied is not None:
        _audit("list_accounts", x_auth_principal, x_auth_agent,
               f"DENIED foreign customer={customer_id}")
        return denied
    customer = _customer_or_provision(customer_id, x_auth_principal)
    if customer is None:
        return JSONResponse(status_code=404, content={"error": f"Unknown customer {customer_id}"})
    _audit("list_accounts", x_auth_principal, x_auth_agent, f"customer={customer_id}")
    return {
        "customer": {"id": customer.id, "name": customer.name},
        "accounts": [a.to_dict() for a in store.list_accounts(customer_id)],
    }


@app.get("/customers/{customer_id}/entitlement")
def check_entitlement(customer_id: str, account: str = "", action: str = ""):
    """Entitlement source for the Grant Evaluation PDP. Answers the one thing the grant itself
    cannot: does this customer STILL HOLD this account, and is it OPEN? The Ping Authorize
    'AccountHoldings' PIP calls this (keyed on the authenticated subject + the resource account)
    and reads {held_open}. Read-only, no auth header — the query subject IS the lookup key,
    mirroring the proofing-directory /consents/check PIP. The bank is system-of-record for
    holdings; scopes/RAR are the AS's. Never held, or since closed -> held_open false (fail
    closed), which the AS servlet renders as 'subject_not_entitled' (re-consent won't help)."""
    subject = (customer_id or "").strip()
    acct_id = (account or "").strip()
    match = None
    if store.get_customer(subject) is not None:
        match = next((a for a in store.list_accounts(subject) if a.id == acct_id), None)
    held = match is not None
    is_open = bool(match and (match.status or "").lower() == "open")
    held_open = held and is_open
    logger.info("entitlement check subject=%s account=%s action=%s -> held=%s open=%s held_open=%s",
                subject, acct_id, action, held, is_open, held_open)
    return {"subject": subject, "account": acct_id, "action": action,
            "held": held, "open": is_open, "held_open": held_open,
            "reason": None if held_open else "subject_not_entitled"}


@app.post("/admin/accounts/{account_id}/close")
def admin_close_account(account_id: str):
    """Demo convenience: mark an account CLOSED so the grant-evaluation flow can show a customer
    who HELD an account and no longer does (held_open -> false). Not a real banking operation."""
    acct = store.get_account(account_id)
    if acct is None:
        return JSONResponse(status_code=404, content={"error": f"Account {account_id} not found"})
    acct.status = "closed"
    logger.info("admin closed account %s (customer=%s)", account_id, acct.customer_id)
    return {"account_id": account_id, "status": acct.status, "customer_id": acct.customer_id}


@app.get("/accounts/{account_id}/balance")
def get_balance(account_id: str,
                x_auth_principal: str | None = Header(default=None),
                x_auth_agent: str | None = Header(default=None)):
    acct = store.get_account(account_id)
    if acct is None:
        return JSONResponse(status_code=404, content={"error": f"Account {account_id} not found"})
    denied = _forbid_foreign_customer(acct.customer_id, x_auth_principal)
    if denied is not None:
        _audit("get_balance", x_auth_principal, x_auth_agent,
               f"DENIED account={account_id} owned by {acct.customer_id}")
        return denied
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
    denied = _forbid_foreign_customer(body.customer_id, x_auth_principal)
    if denied is not None:
        _audit("open_account", x_auth_principal, x_auth_agent,
               f"DENIED foreign customer={body.customer_id}")
        return denied
    customer = _customer_or_provision(body.customer_id, x_auth_principal)
    if customer is None:
        return JSONResponse(status_code=404, content={"error": f"Unknown customer {body.customer_id}"})

    # Origination is FREE: opening an account requires no proofing. The identity gate now lives on
    # the PAYMENT — money cannot move INTO an account until that destination account holds a
    # verified mDL proofing record. So this simply creates the account; a customer may hold as many
    # accounts as they like. (Proofing is bound to the account at first funding, not at open.)
    acct = store.open_account(body.customer_id, body.account_type, body.nickname)
    _audit("open_account", x_auth_principal, x_auth_agent,
           f"opened {acct.id} ({body.account_type}) for {body.customer_id}")
    return {
        "message": f"Opened {body.account_type} account {acct.id} for {customer.name}.",
        "account": acct.to_dict(),
    }


class TransferBody(BaseModel):
    customer_id: str
    from_account: str
    to_account: str
    amount: float
    currency: str = "AUD"
    description: str = ""


@app.post("/transfers")
def transfer(body: TransferBody,
             x_auth_principal: str | None = Header(default=None),
             x_auth_agent: str | None = Header(default=None)):
    """Atomic money move between two accounts — the accounts-domain primitive the
    payments-api calls (through the accounts gateway) to execute a payment. It
    re-validates ownership and funds here so the accounts domain independently
    authorizes and enforces the debit, regardless of what the payments domain
    already checked."""
    denied = _forbid_foreign_customer(body.customer_id, x_auth_principal)
    if denied is not None:
        _audit("transfer", x_auth_principal, x_auth_agent,
               f"DENIED foreign customer={body.customer_id}")
        return denied
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
        _audit("transfer", x_auth_principal, x_auth_agent, f"FAILED: {exc}")
        return JSONResponse(status_code=422, content={"success": False, "message": str(exc)})
    _audit("transfer", x_auth_principal, x_auth_agent,
           f"{body.amount:.2f} {body.currency} {body.from_account} -> {body.to_account}")
    return {
        "success": True,
        "message": f"Transferred {body.amount:.2f} {body.currency} "
                   f"from {body.from_account} to {body.to_account}.",
        "from_balance": src.balance,
        "to_balance": dst.balance,
    }


if __name__ == "__main__":
    import socket
    import uvicorn

    port = int(os.environ.get("PORT", "8070"))
    host = os.environ.get("HOST", "::")
    logger.info("Starting Accounts API (Resource Server) on %s:%s", host, port)

    # Railway dual-stacks private networking: *.railway.internal resolves to BOTH
    # an IPv6 and an IPv4 address, and the gateway's resolver may pick the IPv4
    # one. A plain `::` bind is IPv6-only on Linux, so that IPv4 connect() is
    # refused -> gateway 502 "connection refused". Hand uvicorn a pre-bound
    # DUAL-STACK socket (IPV6_V6ONLY=0) via fd= so it accepts both families while
    # keeping uvicorn.run's normal startup path.
    if ":" in host or host in ("", "::"):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except (AttributeError, OSError):
            pass
        sock.bind((host or "::", port))
        sock.listen(128)
        sock.set_inheritable(True)
        uvicorn.run(app, fd=sock.fileno())
    else:
        uvicorn.run(app, host=host, port=port)
