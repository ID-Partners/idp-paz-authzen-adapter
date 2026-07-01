"""
AuthZEN PDP client.

Talks to the existing Go `authzen-adapter` service, which implements the
AuthZEN Authorization API (https://authzen-interop.net) as a proxy in front of
Ping Authorize. Every banking tool in the MCP server calls `evaluate()` before
performing an action, so Ping Authorize policy governs what the AI agent may do
on behalf of a customer.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger("bank-mcp.pdp")

# URL of the AuthZEN adapter (the Go service in ../../authzen-adapter).
# e.g. https://authzen-adapter.up.railway.app
AUTHZEN_PDP_URL = os.environ.get("AUTHZEN_PDP_URL", "http://localhost:8080").rstrip("/")
# Bearer token expected by the adapter (its API_KEY env var).
AUTHZEN_API_KEY = os.environ.get("AUTHZEN_API_KEY", "Password1")
# The identity the agent presents to the PDP.
AGENT_ID = os.environ.get("AGENT_ID", "bank-account-opening-agent")
# If true, a PDP that is unreachable/errors results in DENY (fail closed).
PDP_FAIL_CLOSED = os.environ.get("PDP_FAIL_CLOSED", "true").lower() == "true"

EVAL_ENDPOINT = f"{AUTHZEN_PDP_URL}/access/v1/evaluation"


@dataclass
class Decision:
    allow: bool
    reason: str
    raw: dict[str, Any]

    @property
    def denied(self) -> bool:
        return not self.allow


async def evaluate(
    *,
    action: str,
    resource_type: str,
    resource_id: str,
    on_behalf_of: str,
    resource_properties: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> Decision:
    """Ask the AuthZEN PDP whether the agent may perform `action` on a resource.

    The subject is the AI agent, carrying an `on_behalf_of` property so policy can
    reason about the human principal the agent is acting for.
    """
    payload = {
        "subject": {
            "type": "agent",
            "identity": AGENT_ID,
            "properties": {
                "on_behalf_of": on_behalf_of,
                "agent_type": "ai_assistant",
            },
        },
        "action": {"name": action},
        "resource": {
            "type": resource_type,
            "id": resource_id,
            "properties": resource_properties or {},
        },
        "context": {
            "channel": "ai-agent",
            **(context or {}),
        },
    }

    headers = {
        "Authorization": f"Bearer {AUTHZEN_API_KEY}",
        "Content-Type": "application/json",
    }

    logger.info("PDP evaluate action=%s resource=%s/%s on_behalf_of=%s",
                action, resource_type, resource_id, on_behalf_of)

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.post(EVAL_ENDPOINT, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:  # noqa: BLE001 - demo: surface any PDP failure
        logger.error("PDP call failed: %s", exc)
        if PDP_FAIL_CLOSED:
            return Decision(allow=False,
                            reason=f"Authorization service unavailable ({exc}); denying by policy (fail-closed).",
                            raw={"error": str(exc)})
        return Decision(allow=True, reason="PDP unreachable; fail-open (demo only).", raw={"error": str(exc)})

    allow = bool(data.get("decision", False))
    reason = ""
    ctx = data.get("context") or {}
    if isinstance(ctx, dict):
        reason = str(ctx.get("reason", ""))
    if not reason:
        reason = "Permitted by policy." if allow else "Denied by policy."

    logger.info("PDP decision=%s reason=%s", allow, reason)
    return Decision(allow=allow, reason=reason, raw=data)
