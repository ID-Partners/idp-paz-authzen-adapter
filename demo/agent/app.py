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

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import json as _json

from fastapi.responses import StreamingResponse

from agent_core import agent_events, reset_session, run_agent

app = FastAPI(title="Northwind Bank Agent (AgentCore-compatible)")

# The Bank API's admin reset (direct, internal — a demo convenience, not governed).
BANK_API_URL = os.environ.get("BANK_API_URL", "http://bank-api.railway.internal:8070")

# Login is handled by the separate app/BFF service (real OIDC to PingFederate);
# this principal-agent service is headless and reached over the private network.
# The BFF forwards Alice's identity + PF token as X-Principal-Sub / X-User-Token.


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
    body = await request.json()
    payload = body.get("input", body)
    prompt = payload.get("prompt") or payload.get("message") or ""
    session_id = payload.get("session_id", "demo")
    if not prompt:
        return JSONResponse(status_code=400, content={"error": "missing 'prompt'"})
    user_token = request.headers.get("x-user-token") or None
    # A token re-audienced for the Grant Management API (aud=https://gm-api.demo/grants),
    # minted by the BFF from the SAME login grant. Presented to the GM API only.
    gm_token = request.headers.get("x-gm-token") or None
    # Optional STAFF-context target: the account owner the operation is for. Only
    # honoured by agent_core when the authenticated principal is bank staff.
    customer_id = payload.get("customer_id") or None
    try:
        result = await run_agent(prompt, session_id, user_token=user_token,
                                 gm_token=gm_token, customer_id=customer_id)
    except Exception as exc:  # noqa: BLE001 - surface errors to the demo UI
        return JSONResponse(status_code=500, content={"error": str(exc)})
    return result


@app.post("/stream")
async def stream(request: Request):
    """Stream the agent's steps as Server-Sent Events so the UI can reflect
    activity live. Each event is a transcript step; the last is {"type":"final"}."""
    body = await request.json()
    payload = body.get("input", body)
    prompt = payload.get("prompt") or payload.get("message") or ""
    session_id = payload.get("session_id", "demo")
    if not prompt:
        return JSONResponse(status_code=400, content={"error": "missing 'prompt'"})
    user_token = request.headers.get("x-user-token") or None
    gm_token = request.headers.get("x-gm-token") or None  # GM-API-audienced token (see /invocations)
    # Optional STAFF-context target (see /invocations) — staff principals only.
    customer_id = payload.get("customer_id") or None

    async def gen():
        try:
            async for ev in agent_events(prompt, session_id, user_token=user_token,
                                         gm_token=gm_token, customer_id=customer_id):
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
    """Headless principal agent — the UI + login live in the separate app/BFF."""
    return {"service": "principal-agent", "role": "concierge",
            "note": "UI and login are served by the app/BFF service"}


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
