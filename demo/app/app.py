"""
Northwind Web App (BFF) — the app server, separate from the principal agent.

This is the public front door Alice uses. It is an OpenID Connect client of the
real PingFederate: it redirects Alice to PingFederate's hosted login page, and on
return holds her session (her PF id_token + access_token). It then proxies chat
requests to the (headless) principal agent over the private network, forwarding
Alice's identity and her PF access token so the downstream gateway can enforce
that a real user is logged in (RFC 9470 step-up challenge — see Phase 3).

    GET  /                → the web UI
    GET  /login           → redirect to PingFederate (authorization code + PKCE)
    GET  /callback        → exchange the code, establish the session, back to /
    GET  /me              → the signed-in principal (or 401)
    POST /logout          → clear the session
    POST /stream          → proxy (SSE) to the principal agent, carrying Alice's identity
    POST /invocations     → proxy (JSON) to the principal agent
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import urllib.parse

import httpx
import jwt  # PyJWT
from fastapi import FastAPI, Request
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               RedirectResponse, StreamingResponse)
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Northwind Web App (BFF)")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# --- config ------------------------------------------------------------------
# Public PingFederate base (its TCP proxy). The app talks to PF over the public
# endpoint because the browser is redirected there for login.
PF_BASE = os.environ.get("PF_BASE_URL", "https://hayabusa.proxy.rlwy.net:49245").rstrip("/")
PF_AUTHORIZE = os.environ.get("PF_AUTHORIZE_URL", PF_BASE + "/as/authorization.oauth2")
PF_TOKEN = os.environ.get("PF_TOKEN_URL", PF_BASE + "/as/token.oauth2")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "northwind-webapp")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "webapp-secret-123")
# This app's own public base URL — the redirect_uri is <APP_BASE_URL>/callback.
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:8090").rstrip("/")
REDIRECT_URI = APP_BASE_URL + "/callback"
# The headless principal agent (private network).
PRINCIPAL_AGENT_URL = os.environ.get("PRINCIPAL_AGENT_URL",
                                     "http://bank-agent.railway.internal:8000").rstrip("/")
APP_SECRET = os.environ.get("APP_SECRET", "northwind-bff-secret")
SESSION_TTL = int(os.environ.get("SESSION_TTL", "28800"))  # 8h
# Everyday scopes Alice consents to at first login. The sensitive
# banking:payments:transfer is NOT here — it requires a step-up (re-auth).
DEFAULT_SCOPES = os.environ.get("DEFAULT_SCOPES",
                                "openid banking:accounts:list banking:accounts:originate")
SESSION_COOKIE = "nw_session"
TX_COOKIE = "nw_oidc_tx"  # short-lived: holds PKCE verifier + state during the redirect


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _sign(payload: dict, ttl: int) -> str:
    now = int(time.time())
    return jwt.encode({**payload, "iat": now, "exp": now + ttl}, APP_SECRET, algorithm="HS256")


def _verify(token: str | None) -> dict | None:
    if not token:
        return None
    try:
        return jwt.decode(token, APP_SECRET, algorithms=["HS256"])
    except Exception:  # noqa: BLE001
        return None


def _session(request: Request) -> dict | None:
    return _verify(request.cookies.get(SESSION_COOKIE))


@app.get("/ping")
def ping():
    return {"status": "healthy"}


@app.get("/health")
def health():
    return {"status": "ok"}


PF_PAR = os.environ.get("PF_PAR_URL", PF_BASE + "/as/par.oauth2")
RAR_TYPE = os.environ.get("PAYMENT_RAR_TYPE", "payment_initiation")


def _payment_rar(request: Request) -> list | None:
    """Build an RFC 9396 authorization_details entry from the step-up payment
    params, so Alice consents to THIS specific payment at PingFederate (governed
    by Ping Authorize at issuance) rather than to a coarse scope."""
    amount = (request.query_params.get("amount") or "").strip()
    if not amount:
        return None
    try:
        amt = float(amount)
    except ValueError:
        return None
    return [{
        "type": RAR_TYPE,
        "purpose": RAR_TYPE,                       # dot-free marker the PAZ policy reads
        "amount": amt,
        "currency": (request.query_params.get("cur") or "AUD").strip(),
        "debtorAccount": (request.query_params.get("from") or "").strip(),
        "creditorAccount": (request.query_params.get("to") or "").strip(),
    }]


@app.get("/login")
async def login(request: Request):
    """Kick off the OIDC authorization-code + PKCE flow at PingFederate.

    By default Alice consents to the everyday scopes. A `?stepup=<scope>` request
    is a step-up: it adds the elevated scope (e.g. banking:payments:transfer) and
    forces re-authentication (prompt=login) — RFC 9470 step-up for a risky action.
    For a payment, the specific operation is attached as RFC 9396 authorization_details
    and pushed via PAR (RFC 9126) so Alice consents to THIS payment at the AS.
    """
    verifier = _b64u(secrets.token_bytes(40))
    challenge = _b64u(hashlib.sha256(verifier.encode()).digest())
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    stepup = (request.query_params.get("stepup") or "").strip()
    scope = DEFAULT_SCOPES + ((" " + stepup) if stepup else "")
    params = {"client_id": OIDC_CLIENT_ID, "response_type": "code",
              "redirect_uri": REDIRECT_URI, "scope": scope,
              "code_challenge": challenge, "code_challenge_method": "S256",
              "state": state, "nonce": nonce}
    if stepup:
        params["prompt"] = "login consent"   # force re-auth AND the consent/approval page
    # Assert the authenticated principal so the RAR governance decision is attributed to Alice, not the
    # OAuth client. PingFederate's AuthorizationDetailProcessor SDK exposes no resource-owner accessor, so
    # the pf-rar-paz-plugin reads this login_hint as the decision's UserID (the agent stays the 'actor').
    sess = _session(request)
    principal_sub = sess.get("sub") if sess else None
    if principal_sub:
        params["login_hint"] = principal_sub   # carries on the non-PAR path
    rar = _payment_rar(request)
    if rar:
        # Fold the authenticated principal into each authorization_details entry. PingFederate does not
        # surface PAR-pushed request params (login_hint) to the AuthorizationDetailProcessor, but it DOES
        # hand it the authorization_details — the reliable PAR-surviving channel for the pf-rar-paz-plugin
        # to attribute the governance decision to Alice as UserID (agent recorded as 'actor'). The plugin
        # reads '_principal_sub' then strips it, so it never reaches the consent page or the issued token.
        if principal_sub:
            for entry in rar:
                entry["_principal_sub"] = principal_sub
        params["authorization_details"] = json.dumps(rar)

    authz = None
    if rar:
        # PAR: push the request (incl. authorization_details) to PF, reference it by
        # request_uri — keeps the RAR payload off the browser URL.
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=False) as c:
                pr = await c.post(PF_PAR, data={**params, "client_secret": OIDC_CLIENT_SECRET})
                pr.raise_for_status()
                request_uri = pr.json()["request_uri"]
            authz = (PF_AUTHORIZE + "?" +
                     urllib.parse.urlencode({"client_id": OIDC_CLIENT_ID, "request_uri": request_uri}))
        except Exception:  # noqa: BLE001 - fall back to a plain (non-PAR) request
            authz = PF_AUTHORIZE + "?" + urllib.parse.urlencode(params)
    else:
        authz = PF_AUTHORIZE + "?" + urllib.parse.urlencode(params)

    resp = RedirectResponse(authz, status_code=302)
    # Stash the PKCE verifier + state in a short-lived signed cookie.
    resp.set_cookie(TX_COOKIE, _sign({"v": verifier, "state": state, "nonce": nonce}, 600),
                    httponly=True, secure=True, samesite="lax", max_age=600)
    return resp


@app.get("/callback")
async def callback(request: Request):
    """Handle the redirect back from PingFederate: exchange the code, set the session."""
    tx = _verify(request.cookies.get(TX_COOKIE))
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    if not tx or not code or state != tx.get("state"):
        return JSONResponse(status_code=400, content={"error": "invalid login state"})
    try:
        async with httpx.AsyncClient(timeout=20.0, verify=False) as c:
            tr = await c.post(PF_TOKEN, data={
                "grant_type": "authorization_code", "code": code,
                "redirect_uri": REDIRECT_URI, "client_id": OIDC_CLIENT_ID,
                "client_secret": OIDC_CLIENT_SECRET, "code_verifier": tx["v"]})
            tr.raise_for_status()
            tok = tr.json()
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=502, content={"error": f"token exchange failed: {exc}"})

    # We received the tokens directly from PF over TLS in the code exchange, so we
    # trust them without re-verifying the signature (demo BFF).
    id_claims = jwt.decode(tok["id_token"], options={"verify_signature": False}) \
        if tok.get("id_token") else {}
    sub = id_claims.get("sub", "alice")
    pf_access = tok.get("access_token", "")
    at_claims = {}
    if pf_access.count(".") == 2:
        at_claims = jwt.decode(pf_access, options={"verify_signature": False})
    session = {"sub": sub, "name": id_claims.get("name") or sub,
               "acr": at_claims.get("acr"), "pf_at": pf_access}
    resp = RedirectResponse("/", status_code=302)
    resp.set_cookie(SESSION_COOKIE, _sign(session, SESSION_TTL),
                    httponly=True, secure=True, samesite="lax", max_age=SESSION_TTL)
    resp.delete_cookie(TX_COOKIE)
    return resp


@app.get("/me")
def me(request: Request):
    s = _session(request)
    if not s:
        return JSONResponse(status_code=401, content={"error": "not signed in"})
    return {"principal": {"sub": s.get("sub"), "name": s.get("name"), "acr": s.get("acr")}}


@app.get("/session/token")
def session_token(request: Request):
    """Return the decoded details of Alice's PingFederate token held in her
    session, so the UI can pop it open and show the real claims."""
    s = _session(request)
    if not s:
        return JSONResponse(status_code=401, content={"error": "not signed in"})
    pf_at = s.get("pf_at", "")
    out: dict = {"principal": {"sub": s.get("sub"), "name": s.get("name"), "acr": s.get("acr")},
                 "has_token": bool(pf_at), "issued_by": "PingFederate (OIDC login)"}
    if pf_at.count(".") == 2:
        out["header"] = jwt.get_unverified_header(pf_at)
        out["claims"] = jwt.decode(pf_at, options={"verify_signature": False})
        out["token_preview"] = pf_at[:32] + "…" + pf_at[-20:]
    return out


@app.post("/logout")
def logout():
    resp = JSONResponse({"status": "logged out"})
    resp.delete_cookie(SESSION_COOKIE)
    return resp


def _forward_headers(s: dict) -> dict:
    """Headers that carry Alice's identity + her PF token to the agent chain."""
    return {"Content-Type": "application/json",
            "X-Principal-Sub": s.get("sub", ""),
            "X-User-Token": s.get("pf_at", "")}


@app.post("/invocations")
async def invocations(request: Request):
    # Not gated at the app: a logged-out request is allowed through so the GATEWAY
    # enforces the login (RFC 9470) and challenges. The user token is forwarded
    # only when Alice has a session.
    s = _session(request) or {}
    body = await request.body()
    try:
        async with httpx.AsyncClient(timeout=180.0) as c:
            r = await c.post(PRINCIPAL_AGENT_URL + "/invocations",
                             content=body, headers=_forward_headers(s))
            return JSONResponse(status_code=r.status_code, content=r.json())
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=502, content={"error": str(exc)})


@app.post("/stream")
async def stream(request: Request):
    # See /invocations: the gateway, not the app, enforces the login challenge.
    s = _session(request) or {}
    body = await request.body()

    async def gen():
        async with httpx.AsyncClient(timeout=180.0) as c:
            async with c.stream("POST", PRINCIPAL_AGENT_URL + "/stream",
                                content=body, headers=_forward_headers(s)) as r:
                async for chunk in r.aiter_raw():
                    yield chunk

    return StreamingResponse(gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"})


@app.post("/reset")
async def reset(request: Request):
    s = _session(request)
    if not s:
        return JSONResponse(status_code=401, content={"error": "login required"})
    body = await request.body()
    async with httpx.AsyncClient(timeout=20.0) as c:
        r = await c.post(PRINCIPAL_AGENT_URL + "/reset", content=body,
                         headers=_forward_headers(s))
        return JSONResponse(status_code=r.status_code, content=r.json())


@app.post("/reset-bank")
async def reset_bank(request: Request):
    s = _session(request)
    if not s:
        return JSONResponse(status_code=401, content={"error": "login required"})
    async with httpx.AsyncClient(timeout=20.0) as c:
        r = await c.post(PRINCIPAL_AGENT_URL + "/reset-bank", headers=_forward_headers(s))
        return JSONResponse(status_code=r.status_code, content=r.json())


# ── PingOne MFA device enrolment (autonomous demo: bootstrap Bob's approver app) ──
P1_ENV = os.environ.get("PINGONE_ENV", "")
P1_AUTH = os.environ.get("PINGONE_AUTH", "https://auth.pingone.asia").rstrip("/")
P1_API = os.environ.get("PINGONE_API", "https://api.pingone.asia").rstrip("/")
P1_CLIENT = os.environ.get("PINGONE_CLIENT_ID", "")
P1_SECRET = os.environ.get("PINGONE_SECRET", "")
P1_BOB = os.environ.get("PINGONE_BOB_ID", "")
P1_APP = os.environ.get("PINGONE_NATIVE_APP_ID", "")


async def _pingone_pairing_key() -> dict:
    """Mint a one-time MFA pairing key for Bob via the PingOne Management API."""
    async with httpx.AsyncClient(timeout=20.0) as c:
        tr = await c.post(f"{P1_AUTH}/{P1_ENV}/as/token",
                          data={"grant_type": "client_credentials"}, auth=(P1_CLIENT, P1_SECRET))
        tok = tr.json().get("access_token")
        r = await c.post(f"{P1_API}/v1/environments/{P1_ENV}/users/{P1_BOB}/pairingKeys",
                         headers={"Authorization": f"Bearer {tok}"},
                         json={"applications": [{"id": P1_APP}]})
        return r.json()


@app.get("/enroll")
async def enroll():
    """Branded page that mints + displays a pairing key for Bob's iOS approver app."""
    if not (P1_ENV and P1_CLIENT and P1_BOB and P1_APP):
        return HTMLResponse("Enrolment not configured — set PINGONE_ENV / PINGONE_CLIENT_ID / "
                            "PINGONE_SECRET / PINGONE_BOB_ID / PINGONE_NATIVE_APP_ID.", status_code=503)
    try:
        pk = await _pingone_pairing_key()
    except Exception as exc:  # noqa: BLE001
        return HTMLResponse(f"Enrolment error: {exc}", status_code=502)
    code = pk.get("code")
    if not code:
        return HTMLResponse(f"Could not mint pairing key: {json.dumps(pk)[:400]}", status_code=502)
    return HTMLResponse(_ENROLL_HTML.replace("__CODE__", code).replace("__EXP__", pk.get("expiresAt", "")))


_ENROLL_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ID Partners Bank — Enrol device</title><style>
:root{--bg:#0d1117;--panel:#161b22;--border:#2d333b;--text:#e6edf3;--muted:#9198a1;--accent:#ff6600}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);
 font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;display:flex;align-items:center;justify-content:center;padding:24px}
.card{width:100%;max-width:440px;background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:30px 28px}
.idp-mark{display:inline-flex;align-items:center;gap:.42em;font-weight:800;letter-spacing:.05em;font-size:20px}
.idp-mark .sq{width:.66em;height:.66em;background:var(--accent);border-radius:2px}
.idp-mark .pa{color:var(--accent)} .bank{color:var(--muted);font-weight:600;margin-left:4px}
h1{font-size:19px;margin:22px 0 4px}.sub{color:var(--muted);font-size:13px;margin:0 0 22px}
.code{font-family:ui-monospace,Menlo,monospace;font-size:30px;font-weight:700;letter-spacing:.12em;
 text-align:center;background:#06090d;border:1px solid #2c4a2f;border-radius:10px;padding:20px;color:#fff;user-select:all}
.exp{text-align:center;color:var(--muted);font-size:12.5px;margin:12px 0 0}
ol{color:var(--muted);font-size:13.5px;line-height:1.6;padding-left:18px;margin:22px 0 4px}
ol b{color:var(--text)}
.btn{display:block;width:100%;margin-top:20px;padding:12px;text-align:center;text-decoration:none;
 background:var(--accent);color:#fff;font-weight:600;border-radius:9px}
.foot{text-align:center;color:var(--muted);font-size:11px;margin-top:16px}
</style></head><body><div class="card">
<div><span class="idp-mark"><span class="sq"></span>ID<span class="pa">PARTNERS</span></span><span class="bank">Bank</span></div>
<h1>Enrol this device for approvals</h1>
<p class="sub">Bob's phone pairs once, then approves payments with Face&nbsp;ID.</p>
<div class="code" id="code">__CODE__</div>
<p class="exp" id="exp">Pairing key · one-time · expires <span id="cd">soon</span></p>
<ol>
 <li>Open the <b>ID Partners Bank Approver</b> app on Bob's iPhone.</li>
 <li>Tap <b>Pair this device</b> and enter the key above.</li>
 <li>Approve the test push to confirm.</li>
</ol>
<a class="btn" href="/enroll">Generate a new key</a>
<div class="foot">Secured by PingOne MFA</div>
</div><script>
(function(){var exp=new Date("__EXP__").getTime();function t(){var s=Math.max(0,Math.floor((exp-Date.now())/1000));
document.getElementById('cd').textContent=s>0?('in '+Math.floor(s/60)+'m '+(s%60)+'s'):'— expired, generate a new one';}
if(!isNaN(exp)){t();setInterval(t,1000);}})();
</script></body></html>"""


# The gateway/PEP product shown in the UI. Default Kong; the agentgateway (solo.io) staging
# env sets GATEWAY_LABEL=agentgateway so the diagram + transcript name the real gateway.
GATEWAY_LABEL = os.environ.get("GATEWAY_LABEL", "Kong")

# The bank MCP server whose tools/list carries the COAZ declarations shown in
# the UI's COAZ popup (fetched live so the popup always matches reality).
MCP_TOOLS_URL = os.environ.get("MCP_TOOLS_URL",
                               "http://bank-mcp.railway.internal:8090/mcp")


@app.get("/coaz/tools")
async def coaz_tools():
    """Live tools/list from the bank MCP server, for the COAZ popup: which
    tools declare coaz:true and what their x-coaz-mapping says."""
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.post(MCP_TOOLS_URL, json=payload, headers=headers)
        if r.headers.get("content-type", "").startswith("text/event-stream"):
            line = next(l for l in r.text.splitlines() if l.startswith("data:"))
            data = json.loads(line[len("data:"):])
        else:
            data = r.json()
        return JSONResponse({"tools": data.get("result", {}).get("tools", [])})
    except Exception as exc:  # noqa: BLE001 - popup is informational
        return JSONResponse({"error": str(exc), "tools": []}, status_code=502)


@app.get("/")
def index():
    with open(os.path.join(STATIC_DIR, "index.html"), encoding="utf-8") as fh:
        html = fh.read()
    return HTMLResponse(html.replace("__GATEWAY__", GATEWAY_LABEL))


if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8090")))
