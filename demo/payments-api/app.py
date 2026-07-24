"""
Payments REST API — the PAYMENTS-domain Resource Server (RS).

After the accounts/payments split this service owns the `make_payment` action.
It holds NO account state of its own: the ACCOUNTS API is the system-of-record.
To execute a payment it calls the accounts-api's atomic `POST /transfers`
primitive, forwarding the delegated identity. The payment is fully authorized at
the PAYMENTS gateway against a policy that carries a copy of the account rules
(so the payment PDP already enforces what the account domain would), and the
transfer then executes directly against the accounts system-of-record.

Like the accounts-api, it holds no policy of its own — every request reaches it
only after the PAYMENTS gateway (PEP) has already asked Ping Authorize for a
decision, and it enforces that the customer_id is the authenticated principal
(X-Auth-Principal) at this edge as well.

    ACCOUNTS_API_BASE — base URL for the accounts-api's /transfers. Normally the
                        accounts-api directly (e.g. http://accounts-api.railway.internal:8070);
                        may point at the accounts gateway route if a deployment wants
                        the debit independently policy-checked in the accounts domain.
"""
from __future__ import annotations

import logging
import os

import httpx
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("payments-api")

app = FastAPI(title="Northwind Payments API (Resource Server)")

# Where the accounts-domain money-move primitive lives. Normally the accounts-api
# directly (the payment is already authorized at the payments gateway by a policy
# that carries a copy of the account rules); may point at the accounts gateway if
# a deployment wants the debit independently policy-checked in the accounts domain.
ACCOUNTS_API_BASE = os.environ.get(
    "ACCOUNTS_API_BASE", "http://localhost:8070").rstrip("/")

STAFF_PRINCIPALS = set((os.environ.get("STAFF_PRINCIPALS", "bob")).split(","))

# The consent directory: payment authorization consents live here, keyed by the
# transaction id that rides in the token's authorization_details.
CONSENT_DIRECTORY_URL = os.environ.get(
    "CONSENT_DIRECTORY_URL",
    os.environ.get("PROOFING_DIRECTORY_URL",
                   "http://proofing-directory.railway.internal:8075")).rstrip("/")


def _audit(action: str, principal: str | None, agent: str | None, detail: str) -> None:
    logger.info("AUDIT action=%s principal=%s agent=%s :: %s",
                action, principal or "?", agent or "?", detail)


def _token_transaction_id(request: Request) -> str | None:
    """Pull the consent's transaction id from the bearer token's RFC 9396
    authorization_details (payment_initiation). The gateway (PEP) has already
    verified the token — this is claim EXTRACTION, not validation."""
    auth = request.headers.get("authorization", "")
    tok = auth[7:] if auth.lower().startswith("bearer ") else ""
    if tok.count(".") != 2:
        return None
    try:
        import base64
        import json as _json
        payload = tok.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = _json.loads(base64.urlsafe_b64decode(payload))
        for d in claims.get("authorization_details") or []:
            if isinstance(d, dict) and d.get("transactionId"):
                return str(d["transactionId"])
    except Exception:  # noqa: BLE001 — absence of a txn id is not an error
        return None
    return None


async def _consent_executed(txn: str, result: dict) -> None:
    """Advance the consent record to 'executed' with the payment outcome (best-effort)."""
    try:
        async with httpx.AsyncClient(timeout=6.0) as c:
            await c.patch(f"{CONSENT_DIRECTORY_URL}/consents/{txn}",
                          json={"status": "executed", "payment_result": result})
    except Exception:  # noqa: BLE001
        pass


async def _consent_consume(subject: str | None, creditor: str, amount: float,
                           currency: str) -> None:
    """Make the covering consent SINGLE-USE. The interactive (scope-elevated) payment token
    carries no RFC 9396 transaction id, so the token-linked path above can't spend the consent
    and it would otherwise authorize EVERY future matching payment. Here we spend — mark
    'executed' — every AUTHORIZED consent that covered this payment, matched by attributes, so
    the next payment finds none and is challenged for a fresh device approval.

    Best-effort: a directory hiccup must not fail a payment that already moved money, but it
    does mean the consent could be reused until the directory catches up (logged)."""
    if not subject:
        return
    try:
        async with httpx.AsyncClient(timeout=6.0) as c:
            r = await c.post(f"{CONSENT_DIRECTORY_URL}/consents/consume",
                             json={"subject": subject, "creditor": creditor,
                                   "amount": amount, "currency": currency})
            n = (r.json() or {}).get("consumed") if r.status_code == 200 else "?"
        logger.info("consent consume subject=%s creditor=%s amount=%.2f -> %s spent",
                    subject, creditor, amount, n)
    except Exception:  # noqa: BLE001
        logger.warning("consent consume failed subject=%s (consent may be reusable until "
                       "retried)", subject)


def _forbid_foreign_customer(customer_id: str, principal: str | None) -> JSONResponse | None:
    """Enforce that the payment targets the AUTHENTICATED principal's own data
    (same rule as the accounts-api; see that service for the full rationale)."""
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


@app.get("/health")
def health():
    return {"status": "ok"}


class PaymentBody(BaseModel):
    customer_id: str
    from_account: str
    to_account: str
    amount: float
    currency: str = "AUD"
    description: str = ""


@app.post("/payments")
async def make_payment(body: PaymentBody, request: Request,
                       x_auth_principal: str | None = Header(default=None),
                       x_auth_agent: str | None = Header(default=None)):
    denied = _forbid_foreign_customer(body.customer_id, x_auth_principal)
    if denied is not None:
        _audit("make_payment", x_auth_principal, x_auth_agent,
               f"DENIED foreign customer={body.customer_id}")
        return denied

    # Execute the money move via the accounts domain. Forward the delegated
    # identity (bearer + X-User-Token + the X-Auth-* headers the accounts gateway
    # will re-derive) so the accounts gateway independently authorizes the debit.
    fwd_headers: dict[str, str] = {}
    for h in ("authorization", "x-user-token", "x-auth-principal",
              "x-auth-agent", "x-auth-scope"):
        v = request.headers.get(h)
        if v:
            fwd_headers[h] = v

    url = f"{ACCOUNTS_API_BASE}/transfers"
    payload = {
        "customer_id": body.customer_id,
        "from_account": body.from_account,
        "to_account": body.to_account,
        "amount": body.amount,
        "currency": body.currency,
        "description": body.description,
    }
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, json=payload, headers=fwd_headers)
    except httpx.HTTPError as exc:
        logger.error("transfer call to accounts domain failed: %s", exc)
        _audit("make_payment", x_auth_principal, x_auth_agent, f"UPSTREAM-ERROR: {exc}")
        return JSONResponse(status_code=502, content={
            "success": False,
            "message": f"Could not reach the accounts service to execute the transfer: {exc}",
        })

    # Relay the accounts domain's decision/result verbatim (including a policy
    # DENY or insufficient-funds 422) so the caller sees the real outcome.
    try:
        upstream = resp.json()
    except ValueError:
        upstream = {"success": False, "message": resp.text}

    # Stamp the executed payment with the consent's transaction id (carried in the
    # token's authorization_details) and advance the consent record to 'executed' —
    # closing the consent → grant → token → action audit chain.
    txn = _token_transaction_id(request)
    if txn:
        if isinstance(upstream, dict):
            upstream["transactionId"] = txn
        await _consent_executed(txn, {
            "status_code": resp.status_code,
            "success": bool(isinstance(upstream, dict) and upstream.get("success")),
            "amount": body.amount, "currency": body.currency,
            "from_account": body.from_account, "to_account": body.to_account,
            "payment_id": (upstream or {}).get("payment_id")
            if isinstance(upstream, dict) else None,
        })

    # Single-use consent: once the money has actually moved, spend the covering consent(s) so a
    # device approval authorizes exactly ONE payment. Only on success — a failed/denied transfer
    # must not burn the consent. Covers the interactive flow (no txn id in the token) and clears
    # any stale authorized consents that matched.
    payment_ok = resp.status_code < 300 and isinstance(upstream, dict) and upstream.get("success")
    if payment_ok:
        await _consent_consume(x_auth_principal, body.to_account, body.amount, body.currency)

    _audit("make_payment", x_auth_principal, x_auth_agent,
           f"{body.amount:.2f} {body.currency} {body.from_account} -> {body.to_account} "
           f"txn={txn or '-'} (accounts-domain status={resp.status_code})")
    return JSONResponse(status_code=resp.status_code, content=upstream)


if __name__ == "__main__":
    import socket
    import uvicorn

    port = int(os.environ.get("PORT", "8071"))
    host = os.environ.get("HOST", "::")
    logger.info("Starting Payments API (Resource Server) on %s:%s (accounts via %s)",
                host, port, ACCOUNTS_API_BASE)

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
