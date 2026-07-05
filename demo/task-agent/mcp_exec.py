"""Call a bank tool through Kong (PEP #1 → MCP → PEP #2 → Bank API) using this
task agent's own delegated, DPoP-bound token."""
from __future__ import annotations

import inspect
import json
import os
from typing import Any

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from identity import Credential

MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://kong.railway.internal:8000/mcp")


class LoginRequired(Exception):
    """The gateway required a logged-in user (401) and none was presented."""


def _extract_text(content) -> str:
    if isinstance(content, str):
        return content
    parts = []
    for part in content:
        text = getattr(part, "text", None)
        parts.append(text if text is not None else json.dumps(getattr(part, "__dict__", str(part))))
    return "\n".join(parts)


def _safe_json(text: str) -> dict[str, Any] | None:
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except (json.JSONDecodeError, TypeError):
        return None


def _client_kwargs(cred: Credential, user_token: str | None) -> dict[str, Any]:
    # X-User-Token carries the logged-in principal (Alice)'s PF token; the gateway
    # requires it (RFC 9470 step-up) and challenges with 401 if it's absent.
    extra = {"X-User-Token": user_token} if user_token else {}
    proof = cred._dpop_proof("POST", MCP_SERVER_URL)
    headers = {"Authorization": f"DPoP {cred.access_token}", "DPoP": proof, **extra}
    if "auth" in inspect.signature(streamablehttp_client).parameters:
        return {"auth": cred.httpx_auth(), "headers": extra or None}
    return {"headers": headers}


async def _preflight_login_gate(cred: Credential, user_token: str | None) -> None:
    """Probe the gateway's step-up gate directly. The MCP client wraps a 401 in an
    opaque ExceptionGroup, so we make a plain request first to read Kong's
    login_required challenge cleanly and raise LoginRequired for it."""
    proof = cred._dpop_proof("POST", MCP_SERVER_URL)
    headers = {"Authorization": f"DPoP {cred.access_token}", "DPoP": proof,
               "Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    if user_token:
        headers["X-User-Token"] = user_token
    ping = {"jsonrpc": "2.0", "id": "preflight", "method": "ping"}
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.post(MCP_SERVER_URL, json=ping, headers=headers)
    except Exception:  # noqa: BLE001 - network issues surface on the real call
        return
    if r.status_code == 401:
        body = {}
        try:
            body = r.json()
        except Exception:  # noqa: BLE001
            pass
        if body.get("error") == "login_required":
            raise LoginRequired(body.get("reason", "login required"))


async def call_tool(cred: Credential, tool: str, arguments: dict[str, Any],
                    user_token: str | None = None) -> dict[str, Any]:
    """Open this agent's own MCP session and invoke one tool. Returns
    {result, authorized, pep, policy_reason, connected}. Raises LoginRequired if
    the gateway challenges for a logged-in user (401)."""
    await _preflight_login_gate(cred, user_token)
    try:
        async with streamablehttp_client(MCP_SERVER_URL, **_client_kwargs(cred, user_token)) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await session.list_tools()
                result = await session.call_tool(tool, arguments)
                text = _extract_text(result.content)
                parsed = _safe_json(text)
                return {
                    "result": parsed if parsed is not None else text,
                    "authorized": (parsed or {}).get("authorized"),
                    "policy_reason": (parsed or {}).get("policy_reason") or (parsed or {}).get("message"),
                    "pep": (parsed or {}).get("pep"),
                    "pep_action": (parsed or {}).get("pep_action"),
                }
    except LoginRequired:
        raise
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        if "401" in msg or "login_required" in msg.lower() or "Unauthorized" in msg:
            raise LoginRequired(msg) from exc
        raise
