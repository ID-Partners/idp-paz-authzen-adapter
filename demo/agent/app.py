"""
HTTP host for the banking agent.

Exposes the Amazon Bedrock AgentCore Runtime contract so the same container can
run on Railway now and be promoted to AgentCore Runtime later:

    POST /invocations   -> run the agent, return the transcript (AgentCore contract)
    GET  /ping          -> health check (AgentCore contract)

It also serves a small web UI at `/` to drive the demo, and `/health` for
Railway health checks.
"""
from __future__ import annotations

import os
import time

import httpx
import jwt  # PyJWT
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import json as _json

from fastapi.responses import StreamingResponse

from agent_core import agent_events, reset_session, run_agent

app = FastAPI(title="Northwind Bank Agent (AgentCore-compatible)")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
# The Bank API's admin reset (direct, internal — a demo convenience, not governed).
BANK_API_URL = os.environ.get("BANK_API_URL", "http://bank-api.railway.internal:8070")

# --- Principal login ---------------------------------------------------------
# The human (principal) authenticates to the app before any agent acts on their
# behalf. In production this is a real IdP (OIDC redirect to PingFederate); here
# it's a small demo credential store + a signed session token, so Alice can sign
# in and the chat is gated behind her authenticated session. The principal `sub`
# (cust-alice) matches the subject the delegated tokens already carry.
SESSION_SECRET = os.environ.get("SESSION_SECRET", "northwind-demo-session-secret")
SESSION_TTL = int(os.environ.get("SESSION_TTL", "28800"))  # 8 hours
DEMO_USERS = {
    "alice": {"password": os.environ.get("ALICE_PASSWORD", "demo"),
              "sub": "cust-alice", "name": "Alice Anderson",
              "email": "alice@northwind.example"},
}


def _issue_session(user: dict, username: str) -> str:
    now = int(time.time())
    return jwt.encode({"sub": user["sub"], "name": user["name"], "email": user["email"],
                       "preferred_username": username, "iat": now, "exp": now + SESSION_TTL},
                      SESSION_SECRET, algorithm="HS256")


def _principal(request: Request) -> dict | None:
    """Return the authenticated principal claims from the session bearer, or None."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    try:
        return jwt.decode(auth.split(" ", 1)[1].strip(), SESSION_SECRET, algorithms=["HS256"])
    except Exception:  # noqa: BLE001 - any invalid/expired token = not signed in
        return None


@app.post("/login")
async def login(request: Request):
    """Authenticate the principal and return a signed session token."""
    body = await request.json()
    username = (body.get("username") or "").strip().lower()
    user = DEMO_USERS.get(username)
    if not user or (body.get("password") or "") != user["password"]:
        return JSONResponse(status_code=401, content={"error": "Invalid username or password"})
    return {"token": _issue_session(user, username),
            "principal": {"sub": user["sub"], "name": user["name"],
                          "email": user["email"], "username": username}}


@app.get("/me")
async def me(request: Request):
    """Return the current signed-in principal (used by the UI to restore a session)."""
    p = _principal(request)
    if not p:
        return JSONResponse(status_code=401, content={"error": "not signed in"})
    return {"principal": {"sub": p.get("sub"), "name": p.get("name"),
                          "email": p.get("email"), "username": p.get("preferred_username")}}


@app.get("/ping")
def ping():
    """AgentCore Runtime health contract."""
    return {"status": "healthy"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/invocations")
async def invocations(request: Request):
    """AgentCore Runtime invocation contract.

    Body: {"prompt": "...", "session_id": "..."} (also accepts AgentCore's
    {"input": {...}} envelope).
    """
    if not _principal(request):
        return JSONResponse(status_code=401, content={"error": "login required"})
    body = await request.json()
    payload = body.get("input", body)
    prompt = payload.get("prompt") or payload.get("message") or ""
    session_id = payload.get("session_id", "demo")
    if not prompt:
        return JSONResponse(status_code=400, content={"error": "missing 'prompt'"})
    try:
        result = await run_agent(prompt, session_id)
    except Exception as exc:  # noqa: BLE001 - surface errors to the demo UI
        return JSONResponse(status_code=500, content={"error": str(exc)})
    return result


@app.post("/stream")
async def stream(request: Request):
    """Stream the agent's steps as Server-Sent Events so the UI can reflect
    activity live. Each event is a transcript step; the last is {"type":"final"}."""
    if not _principal(request):
        return JSONResponse(status_code=401, content={"error": "login required"})
    body = await request.json()
    payload = body.get("input", body)
    prompt = payload.get("prompt") or payload.get("message") or ""
    session_id = payload.get("session_id", "demo")
    if not prompt:
        return JSONResponse(status_code=400, content={"error": "missing 'prompt'"})

    async def gen():
        try:
            async for ev in agent_events(prompt, session_id):
                yield f"data: {_json.dumps(ev)}\n\n"
        except Exception as exc:  # noqa: BLE001
            yield "data: " + _json.dumps({
                "type": "final", "session_id": session_id,
                "final": "The agent hit an error: " + str(exc)}) + "\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache", "Connection": "keep-alive",
        "X-Accel-Buffering": "no"})


@app.post("/reset-bank")
async def reset_bank():
    """Reset the bank's demo data (balances/accounts) back to the seeded start."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.post(BANK_API_URL.rstrip("/") + "/admin/reset")
            r.raise_for_status()
            return r.json()
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=502, content={"error": f"reset failed: {exc}"})


@app.post("/reset")
async def reset(request: Request):
    """Clear a session's conversation memory (the UI's 'New conversation')."""
    body = await request.json()
    session_id = (body.get("input", body)).get("session_id", "demo")
    reset_session(session_id)
    return {"status": "reset", "session_id": session_id}


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
