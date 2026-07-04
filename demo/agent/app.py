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

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from agent_core import reset_session, run_agent

app = FastAPI(title="Northwind Bank Agent (AgentCore-compatible)")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


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
    try:
        result = await run_agent(prompt, session_id)
    except Exception as exc:  # noqa: BLE001 - surface errors to the demo UI
        return JSONResponse(status_code=500, content={"error": str(exc)})
    return result


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
