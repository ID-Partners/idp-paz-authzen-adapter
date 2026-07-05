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
import os
import secrets
import time

import httpx
import jwt  # PyJWT
from fastapi import FastAPI, Request
from fastapi.responses import (FileResponse, JSONResponse, RedirectResponse,
                               StreamingResponse)
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


@app.get("/login")
def login():
    """Kick off the OIDC authorization-code + PKCE flow at PingFederate."""
    verifier = _b64u(secrets.token_bytes(40))
    challenge = _b64u(hashlib.sha256(verifier.encode()).digest())
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    authz = (f"{PF_AUTHORIZE}?client_id={OIDC_CLIENT_ID}&response_type=code"
             f"&redirect_uri={REDIRECT_URI}&scope=openid"
             f"&code_challenge={challenge}&code_challenge_method=S256"
             f"&state={state}&nonce={nonce}")
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


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8090")))
