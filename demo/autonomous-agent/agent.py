"""Autonomous orchestration agent — headless, stream-triggered, with a live dashboard.

Principal = Bob (a bank employee). For each payment handed in by the stream processor:
  received → CIBA backchannel (PingFederate → PingOne MFA push to Bob) → Bob approves
  (Face ID) → delegated token (sub=bob, act={agent}, RAR = the governed payment) →
  execute the payment through the existing Kong PEP + bank-api.

No human is at a keyboard driving the agent — the trigger is a Kafka payment event. The one
human touchpoint is Bob's *out-of-band* approval on his phone, which is the whole point:
an autonomous agent still can't move money until its principal approves THIS payment.

Every stage is published on an in-memory event bus; `/events` (SSE) streams them to the
dashboard at `/`, so you can watch a payment flow through the identity plane in real time.

Two modes:
  • REAL      — PF_BASE + CIBA_CLIENT_ID set AND SIMULATE=0: performs the actual FAPI-CIBA
                flow (mirrors demo/ciba-cli/ciba.py) against the live PingFederate/PingOne.
  • SIMULATE  — the default until the CIBA identity plane is wired (PingOne MFA Integration
                Kit in PF + Bob's device paired). Scripts the stages and lets you approve/deny
                as "Bob" from the dashboard's phone mock, minting a real ES256 delegated token
                so the token panel shows a genuine sub=bob / act={agent} / RAR chain.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
import uuid
from pathlib import Path

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("autonomous-agent")

PF_BASE = os.environ.get("PF_BASE", "").rstrip("/")
CIBA_CLIENT_ID = os.environ.get("CIBA_CLIENT_ID", "") or "urn:agent:northwind-autonomous:v1"
CIBA_KEY_PATH = os.environ.get("CIBA_KEY", "ciba-key.pem")
BOB_LOGIN_HINT = os.environ.get("BOB_LOGIN_HINT", "bob")
KONG_BASE = os.environ.get("KONG_BASE", "").rstrip("/")   # payment execution goes through the PEP
RAR_TYPE = os.environ.get("RAR_TYPE", "payment_initiation")
AGENT_SUB = os.environ.get("AGENT_SUB", "urn:agent:northwind-autonomous:v1")

# Real CIBA only when explicitly enabled AND configured; otherwise simulate so the pipeline
# and dashboard are demoable before the identity plane is up.
SIMULATE = os.environ.get("SIMULATE", "1").lower() not in ("0", "false", "no")
REAL_CIBA = (not SIMULATE) and bool(PF_BASE and os.environ.get("CIBA_CLIENT_ID"))

STATIC = Path(__file__).parent / "static"
app = FastAPI(title="autonomous-agent")

# A throwaway signing key so the SIMULATE mode still mints a genuine ES256 token (the dashboard
# can decode a real JWT rather than a hand-waved blob). Not a security boundary — sim only.
_SIM_KEY = ec.generate_private_key(ec.SECP256R1())
_SIM_PEM = _SIM_KEY.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())

# ── event bus ─────────────────────────────────────────────────────────────────────
_subscribers: set[asyncio.Queue] = set()
_history: list[dict] = []          # recent events, replayed to a freshly-connected dashboard
_PENDING: dict[str, asyncio.Future] = {}   # paymentId → future resolved by Bob's decision (sim)


async def emit(pid: str, stage: str, status: str, detail: str, data: dict | None = None) -> None:
    """Publish one pipeline event to every connected dashboard."""
    evt = {"id": uuid.uuid4().hex[:8], "ts": time.time(), "paymentId": pid,
           "stage": stage, "status": status, "detail": detail, "data": data or {}}
    _history.append(evt)
    del _history[:-300]
    for q in list(_subscribers):
        q.put_nowait(evt)
    log.info("[%s] %s/%s — %s", pid, stage, status, detail)


def _sse(evt: dict) -> str:
    return f"event: stage\ndata: {json.dumps(evt)}\n\n"


# ── RAR + token helpers ─────────────────────────────────────────────────────────────
def _rar(payment: dict) -> list[dict]:
    return [{
        "type": RAR_TYPE,
        "purpose": RAR_TYPE,
        "amount": float(payment.get("amount", 0) or 0),
        "currency": payment.get("currency", "AUD"),
        "debtorAccount": payment.get("debtorAccount", ""),
        "creditorAccount": payment.get("creditorAccount", ""),
    }]


def _binding(payment: dict) -> str:
    r = _rar(payment)[0]
    return (f"Approve payment {r['amount']:.2f} {r['currency']} "
            f"from {r['debtorAccount']} to {r['creditorAccount']}")[:100]


def _decode(token: str) -> dict:
    try:
        parts = token.split(".")
        pad = lambda s: s + "=" * (-len(s) % 4)
        claims = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
        return {k: claims[k] for k in
                ("sub", "act", "client_id", "scope", "authorization_details", "cnf", "iss", "exp")
                if k in claims}
    except Exception:  # noqa: BLE001
        return {}


def _mint_sim_token(payment: dict) -> str:
    now = int(time.time())
    claims = {
        "iss": f"{PF_BASE or 'https://pingfederate.example'}/as (SIMULATED)",
        "sub": BOB_LOGIN_HINT,                       # the principal — Bob, not the agent
        "aud": "bank-api",
        "iat": now, "exp": now + 300, "jti": uuid.uuid4().hex,
        "client_id": AGENT_SUB,                       # the agent operator (OAuth client)
        "act": {"sub": AGENT_SUB},                    # delegation, not impersonation
        "scope": "openid banking:payments:transfer",
        "authorization_details": _rar(payment),       # RFC 9396 — the governed payment
        "cnf": {"jkt": "sim-" + uuid.uuid4().hex[:22]},  # DPoP sender-constraint (sim thumbprint)
    }
    return jwt.encode(claims, _SIM_PEM, algorithm="ES256", headers={"typ": "at+jwt"})


# ── CIBA: simulated ────────────────────────────────────────────────────────────────
async def _ciba_sim(payment: dict) -> str | None:
    pid = payment["paymentId"]
    binding = _binding(payment)
    await emit(pid, "ciba_request", "ok",
               "Backchannel auth request → PingFederate (private_key_jwt, FAPI signed request "
               "object carrying login_hint=Bob + binding_message + RFC 9396 authorization_details)",
               {"login_hint": BOB_LOGIN_HINT, "binding_message": binding,
                "authorization_details": _rar(payment)})
    await asyncio.sleep(0.7)
    await emit(pid, "push_sent", "ok",
               "PingFederate → PingOne MFA → push notification to Bob's device",
               {"binding_message": binding})
    fut: asyncio.Future = asyncio.get_event_loop().create_future()
    _PENDING[pid] = fut
    await emit(pid, "awaiting_approval", "wait",
               "Waiting for Bob to approve the payment on his phone (Face ID)…",
               {"binding_message": binding, "interactive": True})
    try:
        decision = await asyncio.wait_for(fut, timeout=180)
    except asyncio.TimeoutError:
        decision = "timeout"
    finally:
        _PENDING.pop(pid, None)
    if decision != "approve":
        await emit(pid, "denied", "deny",
                   "Bob declined the payment" if decision == "deny" else "Approval timed out",
                   {})
        return None
    await emit(pid, "approved", "ok", "Bob approved with Face ID — CIBA poll returns the token", {})
    return _mint_sim_token(payment)


# ── CIBA: real (mirrors demo/ciba-cli/ciba.py; runs only when SIMULATE=0 + configured) ──
def _pem_key():
    with open(CIBA_KEY_PATH, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)


def _client_assertion(key, aud: str) -> str:
    now = int(time.time())
    return jwt.encode({"iss": CIBA_CLIENT_ID, "sub": CIBA_CLIENT_ID, "aud": aud,
                       "jti": uuid.uuid4().hex, "iat": now, "exp": now + 300},
                      key.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()),
                      algorithm="ES256")


async def _ciba_real(payment: dict) -> str | None:
    pid = payment["paymentId"]
    binding = _binding(payment)
    ciba_ep = os.environ.get("CIBA_ENDPOINT", f"{PF_BASE}/as/bc-auth.ciba")
    token_ep = os.environ.get("TOKEN_ENDPOINT", f"{PF_BASE}/as/token.oauth2")
    issuer = os.environ.get("ISSUER", PF_BASE)
    key = _pem_key()
    req_claims = {"iss": CIBA_CLIENT_ID, "aud": issuer, "jti": uuid.uuid4().hex,
                  "iat": int(time.time()), "exp": int(time.time()) + 300, "nbf": int(time.time()),
                  "scope": "openid banking:payments:transfer", "login_hint": BOB_LOGIN_HINT,
                  "binding_message": binding, "authorization_details": _rar(payment)}
    form = {"request": jwt.encode(req_claims, key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()), algorithm="ES256"),
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": _client_assertion(key, ciba_ep)}
    async with httpx.AsyncClient(timeout=30.0) as c:
        await emit(pid, "ciba_request", "ok",
                   f"POST {ciba_ep} (login_hint=Bob, signed request object, RAR)",
                   {"binding_message": binding, "authorization_details": _rar(payment)})
        r = await c.post(ciba_ep, data=form)
        if r.status_code != 200:
            await emit(pid, "denied", "deny", f"backchannel request failed: {r.status_code} {r.text[:200]}")
            return None
        body = r.json()
        auth_req_id = body["auth_req_id"]
        interval = int(body.get("interval", 5))
        await emit(pid, "push_sent", "ok", "PingOne MFA push sent to Bob's device",
                   {"binding_message": binding, "expires_in": body.get("expires_in")})
        await emit(pid, "awaiting_approval", "wait", "Polling token endpoint until Bob approves…", {})
        deadline = time.time() + int(body.get("expires_in", 300))
        while time.time() < deadline:
            await asyncio.sleep(interval)
            tr = await c.post(token_ep, data={
                "grant_type": "urn:openid:params:grant-type:ciba", "auth_req_id": auth_req_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": _client_assertion(key, token_ep)})
            if tr.status_code == 200:
                await emit(pid, "approved", "ok", "Bob approved — delegated token issued", {})
                return tr.json().get("access_token", "")
            err = tr.json().get("error") if tr.headers.get("content-type", "").startswith("application/json") else tr.text
            if err == "authorization_pending":
                continue
            if err == "slow_down":
                interval += 5
                continue
            await emit(pid, "denied", "deny", f"token error: {err}", {})
            return None
        await emit(pid, "denied", "deny", "timed out waiting for approval", {})
        return None


# ── execution (Kong PEP + bank-api; mocked in sim) ──────────────────────────────────
async def _execute(token: str, payment: dict) -> dict:
    pid = payment["paymentId"]
    if REAL_CIBA and KONG_BASE:
        async with httpx.AsyncClient(timeout=30.0) as c:
            r = await c.post(f"{KONG_BASE}/payments",
                             headers={"Authorization": f"Bearer {token}"}, json=payment)
            return {"status": r.status_code, "body": r.json() if r.headers.get(
                "content-type", "").startswith("application/json") else r.text[:300]}
    await asyncio.sleep(0.6)
    r = _rar(payment)[0]
    return {"status": 201, "body": {
        "paymentId": pid, "state": "SETTLED",
        "debtorAccount": r["debtorAccount"], "creditorAccount": r["creditorAccount"],
        "amount": r["amount"], "currency": r["currency"], "simulated": True}}


# ── orchestration ───────────────────────────────────────────────────────────────────
async def orchestrate(payment: dict) -> None:
    pid = payment["paymentId"]
    try:
        await emit(pid, "received", "ok",
                   f"Payment event received from the stream (initiatedBy={payment.get('initiatedBy','?')}) "
                   "— no human at the keyboard; authorising Bob out-of-band before acting.",
                   {"payment": payment, "mode": "real" if REAL_CIBA else "simulate"})
        token = await (_ciba_real(payment) if REAL_CIBA else _ciba_sim(payment))
        if not token:
            await emit(pid, "halted", "deny", "Payment NOT executed — no delegated authority.", {})
            return
        await emit(pid, "token_issued", "ok",
                   "Delegated token issued: sub=bob (principal), act={agent} (delegation, not "
                   "impersonation), authorization_details = the governed payment.",
                   {"token": token, "claims": _decode(token)})
        await emit(pid, "executing", "ok",
                   "Presenting the delegated token at the Kong PEP → Ping Authorize governs → bank-api.", {})
        result = await _execute(token, payment)
        await emit(pid, "executed", "ok" if result.get("status", 500) < 400 else "deny",
                   f"Payment executed (bank-api {result.get('status')}).", {"result": result})
    except Exception as exc:  # noqa: BLE001
        log.exception("orchestrate failed")
        await emit(pid, "error", "deny", f"orchestration error: {exc}", {})


# ── routes ──────────────────────────────────────────────────────────────────────────
@app.get("/ping")
def ping() -> dict:
    return {"status": "ok", "principal": BOB_LOGIN_HINT,
            "mode": "real" if REAL_CIBA else "simulate",
            "ciba_configured": bool(PF_BASE and os.environ.get("CIBA_CLIENT_ID"))}


@app.get("/")
def dashboard() -> FileResponse:
    return FileResponse(STATIC / "dashboard.html")


@app.get("/events")
async def events(request: Request) -> StreamingResponse:
    q: asyncio.Queue = asyncio.Queue()
    _subscribers.add(q)

    async def gen():
        try:
            yield f"event: hello\ndata: {json.dumps({'mode': 'real' if REAL_CIBA else 'simulate'})}\n\n"
            for e in _history[-60:]:               # replay the current/last run
                yield _sse(e)
            while True:
                try:
                    e = await asyncio.wait_for(q.get(), timeout=15)
                    yield _sse(e)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"       # keep the connection open through proxies
                if await request.is_disconnected():
                    break
        finally:
            _subscribers.discard(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/process")
async def process(request: Request) -> JSONResponse:
    """Stream-processor entrypoint: trigger orchestration, return immediately (the dashboard
    watches progress over SSE)."""
    payment = await request.json()
    payment.setdefault("paymentId", "pay-" + uuid.uuid4().hex[:8])
    asyncio.create_task(orchestrate(payment))
    return JSONResponse(status_code=202, content={"paymentId": payment["paymentId"], "status": "processing"})


@app.post("/inject")
async def inject(request: Request) -> JSONResponse:
    """Dashboard 'inject a payment' button — same path as a Kafka event, minus Kafka."""
    body = {}
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        pass
    payment = {
        "paymentId": "pay-" + uuid.uuid4().hex[:8],
        "debtorAccount": body.get("debtorAccount", "CHK-1001"),
        "creditorAccount": body.get("creditorAccount", "SAV-2002"),
        "amount": float(body.get("amount", 500)),
        "currency": body.get("currency", "AUD"),
        "initiatedBy": body.get("initiatedBy", "batch:payroll-run"),
    }
    asyncio.create_task(orchestrate(payment))
    return JSONResponse(status_code=202, content=payment)


@app.post("/sim/decision")
async def sim_decision(request: Request) -> JSONResponse:
    """Bob's phone approve/deny in SIMULATE mode."""
    body = await request.json()
    pid, decision = body.get("paymentId"), body.get("decision")
    fut = _PENDING.get(pid)
    if fut and not fut.done():
        fut.set_result("approve" if decision == "approve" else "deny")
        return JSONResponse({"ok": True})
    return JSONResponse(status_code=404, content={"ok": False, "detail": "no pending approval"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
