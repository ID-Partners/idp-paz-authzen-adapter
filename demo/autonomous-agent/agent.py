"""Autonomous orchestration agent — headless, stream-triggered, with a live dashboard.

STAFF-AUTHORIZED MODE: a banking operation lands on Kafka (payment / account opening) and the
SAME agent chain as the interactive demo executes it — concierge → task agents → gateways →
Ping Authorize → bank-api. The difference is who authorizes: there is no Alice at a browser.
BOB — the bank staff member who owns/operates the agent — is the internal authority. His
identity IS the user context (sub=bob; the delegated tokens grow the same nested act chain
over it), and when the PDP raises the SAME step-up it raises for Alice (payment > AUD 500),
the challenge is resolved out-of-band: a CIBA push to Bob's phone instead of a browser
redirect. Alice remains the ACCOUNT OWNER — her accounts are the resource being operated on.

Every stage is published on an in-memory event bus; `/events` (SSE) streams them to the
dashboard at `/`, including the full relayed transcript of the concierge chain.

Two approval modes — this switch covers ONLY Bob's phone tap; every token is a real
PingFederate token and the whole chain/PDP plane is always real:
  • SIMULATE (default) — the dashboard's phone mock stands in for the push: you approve/deny
    as Bob, and the approval is swapped for a real PF password-grant token (the staff-approval
    bridge; acr=urn:northwind:loa:staff-approval).
  • REAL (SIMULATE=0) — the actual FAPI-CIBA flow (signed request object, login_hint=bob,
    binding_message + RAR) → PingOne MFA push → Bob approves with Face ID → poll → token.
    Needs the PingOne MFA Integration Kit configured in PF (Phase F).
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
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("autonomous-agent")

# ── config ────────────────────────────────────────────────────────────────────────
PF_TOKEN_URL = os.environ.get(
    "PF_TOKEN_URL", "https://pingfederate.railway.internal:9031/as/token.oauth2")
PF_BASE = os.environ.get("PF_BASE", "").rstrip("/")
CIBA_CLIENT_ID = os.environ.get("CIBA_CLIENT_ID", "") or "urn:agent:northwind-autonomous:v1"
BOB_USERNAME = os.environ.get("BOB_USERNAME", os.environ.get("BOB_LOGIN_HINT", "bob"))
BOB_PASSWORD = os.environ.get("BOB_PASSWORD", "2Federate")
CONCIERGE_URL = os.environ.get(
    "CONCIERGE_URL", "http://bank-agent.railway.internal:8000").rstrip("/")
RAR_TYPE = os.environ.get("RAR_TYPE", "payment_initiation")
BASIC_SCOPE = os.environ.get(
    "BASIC_SCOPE", "openid banking:accounts:list banking:accounts:originate")
ELEVATED_SCOPE = os.environ.get("ELEVATED_SCOPE", "banking:payments:transfer")

# SIMULATE covers ONLY Bob's phone tap (mock vs real PingOne MFA push).
SIMULATE = os.environ.get("SIMULATE", "1").lower() not in ("0", "false", "no")

STATIC = Path(__file__).parent / "static"
app = FastAPI(title="autonomous-agent")


def _client_key():
    """The autonomous client's private_key_jwt signing key: env PEM (Railway) or file (local)."""
    pem = os.environ.get("CIBA_CLIENT_KEY_PEM")
    if pem:
        return serialization.load_pem_private_key(pem.encode(), password=None)
    with open(os.environ.get("CIBA_KEY", "ciba-key.pem"), "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)


# ── event bus ─────────────────────────────────────────────────────────────────────
_subscribers: set[asyncio.Queue] = set()
_history: list[dict] = []          # recent events, replayed to a freshly-connected dashboard
_PENDING: dict[str, asyncio.Future] = {}   # opId → future resolved by Bob's decision (sim)


async def emit(pid: str, stage: str, status: str, detail: str, data: dict | None = None) -> None:
    """Publish one pipeline event to every connected dashboard."""
    evt = {"id": uuid.uuid4().hex[:8], "ts": time.time(), "paymentId": pid,
           "stage": stage, "status": status, "detail": detail, "data": data or {}}
    _history.append(evt)
    del _history[:-400]
    for q in list(_subscribers):
        q.put_nowait(evt)
    log.info("[%s] %s/%s — %s", pid, stage, status, detail)


def _sse(evt: dict) -> str:
    return f"event: stage\ndata: {json.dumps(evt)}\n\n"


# ── event → operation ────────────────────────────────────────────────────────────
def _op_of(event: dict) -> dict:
    """Normalise a stream event into {id, kind, prompt, payment?}."""
    kind = (event.get("eventType") or ("account_opening" if event.get("accountType")
                                       else "payment")).lower()
    # The ACCOUNT OWNER whose accounts the operation targets (Alice). The concierge
    # honours this only because the authenticated principal (Bob) is bank staff.
    owner = event.get("customerId") or event.get("accountOwner") or "alice"
    if kind == "account_opening":
        oid = event.get("requestId") or "open-" + uuid.uuid4().hex[:8]
        acct = event.get("accountType", "savings")
        return {"id": oid, "kind": kind, "event": event, "owner": owner,
                "prompt": f"Open a new {acct} account for customer {owner}."}
    oid = event.get("paymentId") or "pay-" + uuid.uuid4().hex[:8]
    amt = float(event.get("amount", 0) or 0)
    cur = event.get("currency", "AUD")
    frm = event.get("debtorAccount", "CHK-1001")
    to = event.get("creditorAccount", "SAV-1002")
    return {"id": oid, "kind": "payment", "event": event, "owner": owner,
            "payment": {"amount": amt, "currency": cur, "from": frm, "to": to},
            "prompt": (f"Move ${amt:g} from account {frm} to {to} "
                       f"(accounts of customer {owner}).")}


def _rar(p: dict) -> list[dict]:
    return [{"type": RAR_TYPE, "purpose": RAR_TYPE,
             "amount": float(p.get("amount", 0) or 0), "currency": p.get("currency", "AUD"),
             "debtorAccount": p.get("from", ""), "creditorAccount": p.get("to", "")}]


def _binding(p: dict) -> str:
    return (f"Approve payment {float(p.get('amount', 0) or 0):.2f} {p.get('currency','AUD')} "
            f"from {p.get('from','')} to {p.get('to','')}")[:100]


def _decode(token: str) -> dict:
    try:
        parts = token.split(".")
        pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
        claims = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
        out = {k: claims[k] for k in
               ("sub", "act", "client_id", "scope", "acr", "authorization_details",
                "aud", "iss", "exp") if k in claims}
        if isinstance(out.get("act"), str):
            try:
                out["act"] = json.loads(out["act"])
            except Exception:  # noqa: BLE001
                pass
        return out
    except Exception:  # noqa: BLE001
        return {}


# ── PF tokens for Bob (the staff authority) ──────────────────────────────────────
def _assertion(key, endpoint: str) -> str:
    now = int(time.time())
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    return jwt.encode(
        {"iss": CIBA_CLIENT_ID, "sub": CIBA_CLIENT_ID,
         # PF accepts the token endpoint or the issuer as the assertion audience; the
         # issuer string in this deployment is the internal https://localhost:9031.
         "aud": [endpoint, "https://localhost:9031/as/token.oauth2", "https://localhost:9031"],
         "jti": uuid.uuid4().hex, "iat": now, "exp": now + 120},
        pem, algorithm="ES256", headers={"kid": "d4c67a35a199"})


async def _bob_password_token(scope: str) -> tuple[str | None, str]:
    """STAFF-APPROVAL BRIDGE (sim mode): a real PF token for Bob via the resource-owner
    password grant on the autonomous client (private_key_jwt). The PCV-context mapping
    stamps acr=urn:northwind:loa:staff-approval — the marker the step-up policy accepts
    as the staff channel's approval evidence."""
    key = _client_key()
    data = {"grant_type": "password", "username": BOB_USERNAME, "password": BOB_PASSWORD,
            "scope": scope,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": _assertion(key, PF_TOKEN_URL)}
    async with httpx.AsyncClient(timeout=20.0, verify=False) as c:
        r = await c.post(PF_TOKEN_URL, data=data)
        if r.status_code != 200:
            return None, f"PF {r.status_code}: {r.text[:200]}"
        return r.json()["access_token"], ""


# ── REAL CIBA (mirrors demo/ciba-cli/ciba.py; SIMULATE=0, needs the PingOne MFA IK) ──
async def _ciba_real(pid: str, payment: dict) -> str | None:
    binding = _binding(payment)
    ciba_ep = os.environ.get("CIBA_ENDPOINT",
                             (PF_BASE or PF_TOKEN_URL.rsplit("/as/", 1)[0]) + "/as/bc-auth.ciba")
    issuer = os.environ.get("ISSUER", "https://localhost:9031")
    key = _client_key()
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    now = int(time.time())
    req_claims = {"iss": CIBA_CLIENT_ID, "aud": issuer, "jti": uuid.uuid4().hex,
                  "iat": now, "exp": now + 300, "nbf": now,
                  "scope": f"openid {ELEVATED_SCOPE}", "login_hint": BOB_USERNAME,
                  "binding_message": binding, "authorization_details": _rar(payment)}
    form = {"request": jwt.encode(req_claims, pem, algorithm="ES256",
                                  headers={"kid": "d4c67a35a199"}),
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": _assertion(key, ciba_ep)}
    async with httpx.AsyncClient(timeout=30.0, verify=False) as c:
        r = await c.post(ciba_ep, data=form)
        if r.status_code != 200:
            await emit(pid, "denied", "deny",
                       f"CIBA backchannel request failed: {r.status_code} {r.text[:200]}")
            return None
        body = r.json()
        auth_req_id, interval = body["auth_req_id"], int(body.get("interval", 5))
        await emit(pid, "push_sent", "ok", "PingOne MFA push sent to Bob's device",
                   {"binding_message": binding, "expires_in": body.get("expires_in")})
        await emit(pid, "awaiting_approval", "wait",
                   "Polling the token endpoint until Bob approves on his phone…", {})
        deadline = time.time() + int(body.get("expires_in", 300))
        while time.time() < deadline:
            await asyncio.sleep(interval)
            tr = await c.post(PF_TOKEN_URL, data={
                "grant_type": "urn:openid:params:grant-type:ciba", "auth_req_id": auth_req_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": _assertion(key, PF_TOKEN_URL)})
            if tr.status_code == 200:
                await emit(pid, "approved", "ok", "Bob approved with Face ID — token issued", {})
                return tr.json().get("access_token", "")
            err = (tr.json().get("error")
                   if tr.headers.get("content-type", "").startswith("application/json")
                   else tr.text)
            if err == "authorization_pending":
                continue
            if err == "slow_down":
                interval += 5
                continue
            await emit(pid, "denied", "deny", f"CIBA token error: {err}", {})
            return None
        await emit(pid, "denied", "deny", "Timed out waiting for Bob's approval", {})
        return None


# ── the approval gate (Bob authorizes the sensitive operation, out-of-band) ─────────
async def _staff_approval(pid: str, payment: dict) -> str | None:
    """Returns Bob's ELEVATED token (scope banking:payments:transfer,
    acr=staff-approval) once he approves — via the real CIBA push, or the dashboard's
    phone mock + password-grant bridge while the push plane isn't wired."""
    if not SIMULATE:
        return await _ciba_real(pid, payment)
    binding = _binding(payment)
    await emit(pid, "ciba_request", "ok",
               "Backchannel authorization → PingFederate (private_key_jwt; login_hint=bob; "
               "binding_message + RFC 9396 authorization_details = THIS payment). "
               "[phone tap SIMULATED — the push plane swaps in with the PingOne MFA IK]",
               {"login_hint": BOB_USERNAME, "binding_message": binding,
                "authorization_details": _rar(payment)})
    await asyncio.sleep(0.5)
    await emit(pid, "push_sent", "ok",
               "Push to Bob's device (dashboard phone mock stands in for PingOne MFA)",
               {"binding_message": binding})
    fut: asyncio.Future = asyncio.get_event_loop().create_future()
    _PENDING[pid] = fut
    await emit(pid, "awaiting_approval", "wait",
               "Waiting for Bob to approve the payment on his phone…",
               {"binding_message": binding, "interactive": True})
    try:
        decision = await asyncio.wait_for(fut, timeout=180)
    except asyncio.TimeoutError:
        decision = "timeout"
    finally:
        _PENDING.pop(pid, None)
    if decision != "approve":
        await emit(pid, "denied", "deny",
                   "Bob DECLINED the payment" if decision == "deny" else "Approval timed out", {})
        return None
    token, err = await _bob_password_token(f"openid {ELEVATED_SCOPE}")
    if not token:
        await emit(pid, "denied", "deny", f"Elevated staff token failed: {err}", {})
        return None
    await emit(pid, "approved", "ok",
               "Bob approved — PingFederate issued his ELEVATED staff token "
               f"(scope {ELEVATED_SCOPE}, acr=urn:northwind:loa:staff-approval).",
               {"claims": _decode(token)})
    return token


# ── drive the concierge chain (the SAME pipeline as the interactive demo) ───────────
async def _drive_chain(pid: str, prompt: str, token: str, session_id: str,
                       owner: str) -> dict:
    """POST the concierge /stream with Bob's token as the user context (and the
    account owner as the staff-context target); relay every transcript step to
    the dashboard. Returns {outcome: final|scope_challenge|error, ...}."""
    url = f"{CONCIERGE_URL}/stream"
    out: dict = {"outcome": "error", "detail": "no events received"}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=15.0)) as c:
            async with c.stream("POST", url,
                                json={"prompt": prompt, "session_id": session_id,
                                      # the ACCOUNT OWNER (honoured because sub=bob is staff)
                                      "customer_id": owner},
                                headers={"x-user-token": token}) as r:
                if r.status_code != 200:
                    body = (await r.aread()).decode()[:200]
                    return {"outcome": "error", "detail": f"concierge {r.status_code}: {body}"}
                buf = ""
                async for chunk in r.aiter_text():
                    buf += chunk
                    while "\n\n" in buf:
                        frame, buf = buf.split("\n\n", 1)
                        line = next((l for l in frame.split("\n") if l.startswith("data:")), None)
                        if not line:
                            continue
                        try:
                            ev = json.loads(line[5:].strip())
                        except Exception:  # noqa: BLE001
                            continue
                        etype = ev.get("type", "")
                        if etype == "scope_challenge":
                            return {"outcome": "scope_challenge", "ev": ev}
                        if etype == "login_challenge":
                            return {"outcome": "error",
                                    "detail": "login challenge — Bob's token was not accepted: "
                                              + str(ev.get("detail", ""))[:200]}
                        if etype == "final":
                            out = {"outcome": "final", "final": ev.get("final", "")}
                            continue
                        # relay the transcript step verbatim; the dashboard renders it
                        await emit(pid, "chain", "ok",
                                   ev.get("title") or ev.get("detail", "")[:140] or etype,
                                   {"step": ev})
    except Exception as exc:  # noqa: BLE001
        return {"outcome": "error", "detail": f"concierge stream failed: {exc}"}
    return out


# ── orchestration ───────────────────────────────────────────────────────────────────
async def orchestrate(event: dict) -> None:
    op = _op_of(event)
    pid = op["id"]
    session_id = "auto-" + pid
    try:
        await emit(pid, "received", "ok",
                   f"{'Payment' if op['kind'] == 'payment' else 'Account-opening'} event from the "
                   f"stream (initiatedBy={event.get('initiatedBy', '?')}) — no human at a "
                   "keyboard. Running the SAME agent chain as the interactive demo, in the "
                   "context of BOB, the staff member who owns this agent. Alice is the account "
                   "owner; Bob is the internal authority who approves the operation.",
                   {"event": event, "kind": op["kind"], "prompt": op["prompt"],
                    "mode": "real-push" if not SIMULATE else "sim-tap"})

        # 1) Bob's BASIC staff token — the user context for the chain.
        token, err = await _bob_password_token(BASIC_SCOPE)
        if not token:
            await emit(pid, "error", "deny", f"Could not establish Bob's staff context: {err}", {})
            return
        await emit(pid, "staff_context", "ok",
                   "PingFederate issued Bob's STAFF context token (sub=bob) — the agent chain "
                   "acts under the staff authority; the delegated tokens grow the same nested "
                   "act chain over it.",
                   {"claims": _decode(token)})

        # 2) Drive the concierge chain; resolve at most one step-up via Bob's approval.
        for attempt in (1, 2):
            res = await _drive_chain(pid, op["prompt"], token, session_id, op["owner"])
            if res["outcome"] == "final":
                await emit(pid, "executed", "ok",
                           "Operation completed by the agent chain.", {"final": res["final"]})
                return
            if res["outcome"] == "scope_challenge" and attempt == 1:
                ev = res["ev"]
                pay = ev.get("payment") or (op.get("payment") and {
                    "amount": op["payment"]["amount"], "currency": op["payment"]["currency"],
                    "from_account": op["payment"]["from"], "to_account": op["payment"]["to"]})
                payment = {"amount": (pay or {}).get("amount", 0),
                           "currency": (pay or {}).get("currency", "AUD"),
                           "from": (pay or {}).get("from_account", ""),
                           "to": (pay or {}).get("to_account", "")}
                await emit(pid, "stepup_challenge", "wait",
                           "Ping Authorize raised the SAME step-up as the interactive demo "
                           f"(scope {ev.get('scope', ELEVATED_SCOPE)}) — resolving it via BOB's "
                           "out-of-band approval instead of a browser redirect.",
                           {"scope": ev.get("scope"), "detail": ev.get("detail"),
                            "payment": pay})
                elevated = await _staff_approval(pid, payment)
                if not elevated:
                    await emit(pid, "halted", "deny",
                               "Operation NOT executed — Bob did not approve.", {})
                    return
                token = elevated
                continue
            await emit(pid, "error", "deny",
                       f"Chain did not complete: {res.get('detail', res['outcome'])}", {})
            return
        await emit(pid, "error", "deny",
                   "Step-up loop: the chain challenged again after Bob's approval.", {})
    except Exception as exc:  # noqa: BLE001
        log.exception("orchestrate failed")
        await emit(pid, "error", "deny", f"orchestration error: {exc}", {})


# ── routes ──────────────────────────────────────────────────────────────────────────
@app.get("/ping")
def ping() -> dict:
    return {"status": "ok", "staff_authority": BOB_USERNAME,
            "mode": "real-push" if not SIMULATE else "sim-tap",
            "concierge": CONCIERGE_URL, "pf_token_url": PF_TOKEN_URL}


@app.get("/")
def dashboard() -> FileResponse:
    return FileResponse(STATIC / "dashboard.html")


@app.get("/events")
async def events(request: Request) -> StreamingResponse:
    q: asyncio.Queue = asyncio.Queue()
    _subscribers.add(q)

    async def gen():
        try:
            yield ("event: hello\ndata: "
                   + json.dumps({"mode": "real-push" if not SIMULATE else "sim-tap"}) + "\n\n")
            for e in _history[-120:]:              # replay the current/last run
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
    event = await request.json()
    op = _op_of(event)
    asyncio.create_task(orchestrate(event))
    return JSONResponse(status_code=202, content={"paymentId": op["id"], "status": "processing"})


@app.post("/inject")
async def inject(request: Request) -> JSONResponse:
    """Dashboard 'inject' button — same path as a Kafka event, minus Kafka."""
    body = {}
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        pass
    if (body.get("eventType") or "").lower() == "account_opening":
        event = {"eventType": "account_opening",
                 "requestId": "open-" + uuid.uuid4().hex[:8],
                 "customerId": body.get("customerId", "alice"),
                 "accountType": body.get("accountType", "savings"),
                 "initiatedBy": body.get("initiatedBy", "batch:onboarding")}
    else:
        event = {"eventType": "payment",
                 "paymentId": "pay-" + uuid.uuid4().hex[:8],
                 "debtorAccount": body.get("debtorAccount", "CHK-1001"),
                 "creditorAccount": body.get("creditorAccount", "SAV-1002"),
                 "amount": float(body.get("amount", 600)),
                 "currency": body.get("currency", "AUD"),
                 "initiatedBy": body.get("initiatedBy", "batch:payroll-run")}
    asyncio.create_task(orchestrate(event))
    return JSONResponse(status_code=202, content=event)


@app.post("/sim/decision")
async def sim_decision(request: Request) -> JSONResponse:
    """Bob's phone approve/deny (the mock tap while the real push plane isn't wired)."""
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
