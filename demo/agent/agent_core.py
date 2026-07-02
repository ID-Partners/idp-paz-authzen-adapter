"""
The banking agent.

This module holds the agent logic independent of how it is hosted:

  * On Railway (and locally) it is served by `app.py` (FastAPI) which exposes the
    Amazon Bedrock AgentCore Runtime contract (`POST /invocations`, `GET /ping`).
  * On AWS it can be served by `agentcore_entrypoint.py`, which wraps the exact
    same `run_agent()` in the `bedrock-agentcore` SDK's `BedrockAgentCoreApp`.

The agent connects to the Bank MCP service over the Model Context Protocol,
discovers the banking tools, and uses Claude (via the Anthropic API) to plan and
call those tools. Every tool call is authorized by Ping Authorize through the
AuthZEN PDP inside the MCP service, so the transcript shows real policy
decisions.
"""
from __future__ import annotations

import inspect
import json
import logging
import os
from typing import Any

import anthropic
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from auth import acquire_delegated_token

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("bank-agent")

# The MCP endpoint the agent connects to. In the governed demo this points at
# the Kong gateway's /mcp route (PEP #1), not the MCP server directly.
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://localhost:8090/mcp")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5")
MAX_TURNS = int(os.environ.get("AGENT_MAX_TURNS", "12"))

SYSTEM_PROMPT = """\
You are a helpful banking assistant for Northwind Bank. You act on behalf of an
authenticated customer and can open accounts and move money using the tools
provided over MCP.

Rules:
- The current customer's id is "cust-alice". Always pass customer_id="cust-alice".
- Be concise and explain each step you take to the customer.
- Every tool enforces the bank's authorization policy (Ping Authorize). If a tool
  returns "authorized": false or a message beginning "POLICY DENIED", do NOT
  retry. Clearly tell the customer the action was blocked and relay the policy
  reason, then stop or suggest a compliant alternative.
- When opening a new account and funding it, first open the account, then make
  the payment into the new account from the customer's existing checking account
  (CHK-1001).
"""


def _anthropic_client() -> anthropic.Anthropic:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set")
    return anthropic.Anthropic(api_key=api_key)


def _mcp_tools_to_anthropic(mcp_tools) -> list[dict[str, Any]]:
    tools = []
    for t in mcp_tools:
        tools.append({
            "name": t.name,
            "description": t.description or "",
            "input_schema": t.inputSchema or {"type": "object", "properties": {}},
        })
    return tools


def _extract_text(content_block) -> str:
    if isinstance(content_block, str):
        return content_block
    # MCP tool result content is a list of content parts
    parts = []
    for part in content_block:
        text = getattr(part, "text", None)
        if text is not None:
            parts.append(text)
        else:
            parts.append(json.dumps(getattr(part, "__dict__", str(part))))
    return "\n".join(parts)


async def run_agent(prompt: str, session_id: str = "demo") -> dict[str, Any]:
    """Run one agent turn against the user's prompt.

    Returns a structured transcript describing the agent's reasoning text, each
    tool call, and each tool result (including the Ping Authorize decision), plus
    the final assistant message.
    """
    transcript: list[dict[str, Any]] = []
    client = _anthropic_client()

    # 1) Establish the agent's authority: authenticate and obtain a delegated,
    #    DPoP-bound token via token exchange (sub=principal, act.sub=agent).
    cred = acquire_delegated_token()
    transcript.extend(cred.steps)

    # 2) Present the token (DPoP-bound) on every MCP request to Kong (PEP #1).
    #    Prefer per-request DPoP proofs via httpx auth; fall back to a static
    #    Authorization header if the installed MCP SDK lacks an `auth` param.
    client_kwargs: dict[str, Any] = {}
    if "auth" in inspect.signature(streamablehttp_client).parameters:
        client_kwargs["auth"] = cred.httpx_auth()
        dpop_note = "per-request DPoP proofs"
    else:
        proof = cred._dpop_proof("POST", MCP_SERVER_URL)
        client_kwargs["headers"] = {
            "Authorization": f"DPoP {cred.access_token}", "DPoP": proof}
        dpop_note = "static DPoP header (SDK has no auth hook)"

    logger.info("Connecting to MCP server at %s (%s)", MCP_SERVER_URL, dpop_note)
    try:
        async with streamablehttp_client(MCP_SERVER_URL, **client_kwargs) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                tools = _mcp_tools_to_anthropic(listed.tools)
                transcript.append({
                    "type": "connect",
                    "detail": f"Connected via Kong gateway (PEP #1) to MCP service "
                              f"'{MCP_SERVER_URL}' using {dpop_note}. "
                              f"Discovered tools: {', '.join(t['name'] for t in tools)}.",
                })

                messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]

                for _turn in range(MAX_TURNS):
                    resp = client.messages.create(
                        model=ANTHROPIC_MODEL,
                        max_tokens=1024,
                        system=SYSTEM_PROMPT,
                        tools=tools,
                        messages=messages,
                    )

                    assistant_content: list[dict[str, Any]] = []
                    tool_uses = []
                    for block in resp.content:
                        if block.type == "text":
                            assistant_content.append({"type": "text", "text": block.text})
                            if block.text.strip():
                                transcript.append({"type": "agent", "text": block.text})
                        elif block.type == "tool_use":
                            assistant_content.append({
                                "type": "tool_use", "id": block.id,
                                "name": block.name, "input": block.input,
                            })
                            tool_uses.append(block)

                    messages.append({"role": "assistant", "content": assistant_content})

                    if resp.stop_reason != "tool_use":
                        break

                    tool_results = []
                    for tu in tool_uses:
                        transcript.append({
                            "type": "tool_call",
                            "name": tu.name,
                            "input": tu.input,
                        })
                        result = await session.call_tool(tu.name, tu.input)
                        text = _extract_text(result.content)
                        parsed = _safe_json(text)
                        transcript.append({
                            "type": "tool_result",
                            "name": tu.name,
                            "authorized": (parsed or {}).get("authorized"),
                            "policy_reason": (parsed or {}).get("policy_reason")
                                             or (parsed or {}).get("message"),
                            "pep": (parsed or {}).get("pep"),
                            "pep_action": (parsed or {}).get("pep_action"),
                            "result": parsed if parsed is not None else text,
                        })
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tu.id,
                            "content": text,
                        })

                    messages.append({"role": "user", "content": tool_results})
    except Exception as exc:  # noqa: BLE001 - surface a clean gateway denial to the UI
        detail = _describe_connect_error(exc)
        logger.warning("MCP connect/session failed: %s", exc)
        transcript.append({"type": "connect_error", "detail": detail})
        return {
            "session_id": session_id,
            "final": "I authenticated and obtained a delegated, DPoP-bound token, but the "
                     "policy gateway refused the MCP connection, so I couldn't run any "
                     "banking tools. " + detail,
            "transcript": transcript,
        }

    final_text = "\n\n".join(
        s["text"] for s in transcript if s["type"] == "agent"
    ) or "Done."
    return {"session_id": session_id, "final": final_text, "transcript": transcript}


def _describe_connect_error(exc: BaseException) -> str:
    """Turn an MCP transport failure into a clear, demo-friendly explanation."""
    text = str(exc)
    for sub in (getattr(exc, "exceptions", None) or []):
        text += " | " + str(sub)
    if "403" in text or "Forbidden" in text:
        return ("PEP #1 (Kong, MCP edge) returned 403 Forbidden — the PDP denied MCP "
                "access. In this demo that happens when Ping Authorize is not yet "
                "reachable and the gateway fails closed. The identity and token "
                "exchange steps above completed successfully.")
    if "401" in text or "Unauthorized" in text:
        return ("PEP #1 rejected the token (401) — the gateway could not validate the "
                "delegated/DPoP-bound token.")
    return f"Could not open the MCP session via the gateway: {text[:200]}"


def _safe_json(text: str) -> dict[str, Any] | None:
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except (json.JSONDecodeError, TypeError):
        return None
