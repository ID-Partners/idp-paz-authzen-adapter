"""Call a bank tool through Kong (PEP #1 → MCP → PEP #2 → Bank API) using this
task agent's own delegated, DPoP-bound token."""
from __future__ import annotations

import inspect
import json
import os
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from identity import Credential

MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://kong.railway.internal:8000/mcp")


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


def _client_kwargs(cred: Credential) -> dict[str, Any]:
    if "auth" in inspect.signature(streamablehttp_client).parameters:
        return {"auth": cred.httpx_auth()}
    proof = cred._dpop_proof("POST", MCP_SERVER_URL)
    return {"headers": {"Authorization": f"DPoP {cred.access_token}", "DPoP": proof}}


async def call_tool(cred: Credential, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Open this agent's own MCP session and invoke one tool. Returns
    {result, authorized, pep, policy_reason, connected}."""
    async with streamablehttp_client(MCP_SERVER_URL, **_client_kwargs(cred)) as (read, write, _):
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
