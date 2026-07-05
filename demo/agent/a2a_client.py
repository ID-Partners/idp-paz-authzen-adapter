"""
A2A (Agent2Agent) client — how the Principal Agent (concierge) discovers and
invokes the Task Agents over the wire.

Discovery is the task agent's **Agent Card** (`/.well-known/agent-card.json`);
invocation is JSON-RPC `message/send`. The concierge presents its delegated
(RFC 8693, DPoP-bound) token as the A2A bearer credential, which the task agent
uses as the subject of its own downstream token exchange.
"""
from __future__ import annotations

import uuid
from typing import Any

import httpx


async def fetch_agent_card(base_url: str) -> dict[str, Any]:
    url = base_url.rstrip("/") + "/.well-known/agent-card.json"
    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.get(url)
        r.raise_for_status()
        return r.json()


async def a2a_send(a2a_url: str, operation: str, arguments: dict[str, Any],
                   bearer: str | None = None) -> dict[str, Any]:
    """A2A message/send carrying {operation, arguments}. Returns the JSON-RPC
    `result` (message + metadata). Raises on transport or JSON-RPC error."""
    payload = {
        "jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": "message/send",
        "params": {"message": {"role": "user", "messageId": str(uuid.uuid4()),
                               "parts": [{"kind": "data",
                                          "data": {"operation": operation, "arguments": arguments}}]}},
    }
    headers = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    async with httpx.AsyncClient(timeout=60.0) as c:
        r = await c.post(a2a_url, json=payload, headers=headers)
        r.raise_for_status()
        data = r.json()
    if "error" in data:
        raise RuntimeError((data["error"] or {}).get("message", "A2A error"))
    return data.get("result", {})
