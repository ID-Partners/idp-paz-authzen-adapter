"""
Bank API client for the MCP tools.

The MCP server no longer talks to the PDP itself — enforcement moved to the Kong
gateway. Each tool calls the Bank REST API (the Resource Server) **through Kong
(PEP #2)**, forwarding the caller's delegated identity. Kong asks Ping Authorize
(via the AuthZEN adapter) for a decision before the request ever reaches the API.

Identity forwarding:
  * Preferred — pass through the delegated access token that arrived on the
    inbound MCP request (so `sub`=principal, `act.sub`=agent reach PEP #2 intact).
  * Fallback — if the inbound token can't be read, build a claims-only token
    carrying the principal + agent so PEP #2 still has an identity to authorize.
    (PEP #2 reads claims; it does not verify the signature — see the plugin note.)
"""
from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger("bank-mcp.rs")

# Kong's Bank API route, e.g. http://kong:8000/bank  (PEP #2 fronts the RS).
BANK_API_BASE_URL = os.environ.get("BANK_API_BASE_URL", "http://localhost:8000/bank").rstrip("/")
AGENT_ID = os.environ.get("AGENT_ID", "urn:agent:northwind-onboarding:v1")
DEFAULT_SCOPE = os.environ.get(
    "AGENT_SCOPE", "bank:accounts.read bank:accounts.write bank:payments.initiate")


def _b64url(obj: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def mint_claims_token(principal: str, agent: str = AGENT_ID) -> str:
    """Build a JWT-shaped, claims-only token (sub=principal, act.sub=agent).

    Used only as a fallback when the inbound delegated token is unavailable. The
    gateway plugin reads the claims; it does not verify the signature.
    """
    header = _b64url({"alg": "none", "typ": "JWT"})
    payload = _b64url({
        "sub": principal,
        "act": {"sub": agent},
        "scope": DEFAULT_SCOPE,
        "client_id": os.environ.get("AGENT_CLIENT_ID", "bank-agent"),
    })
    return f"{header}.{payload}."


async def call(method: str, path: str, token: str,
               json_body: dict[str, Any] | None = None,
               user_token: str | None = None) -> httpx.Response:
    url = f"{BANK_API_BASE_URL}{path}"
    headers = {"Authorization": f"Bearer {token}"}
    # Forward the logged-in principal's (Alice's) token so PEP #2 can check the
    # scopes she consented to (e.g. banking:payments:transfer for a transfer).
    if user_token:
        headers["X-User-Token"] = user_token
    logger.info("RS call via Kong (PEP #2): %s %s", method, url)
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        return await client.request(method, url, headers=headers, json=json_body)


def summarize(resp: httpx.Response) -> dict[str, Any]:
    """Turn a gateway/RS response into a tool result that reports the PEP decision."""
    pep = resp.headers.get("X-PDP-PEP", "PEP#2 (Bank API edge)")
    decision = resp.headers.get("X-PDP-Decision")
    reason = resp.headers.get("X-PDP-Reason")
    pep_action = resp.headers.get("X-PDP-Action")

    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        body = {}

    # A step-up scope challenge: the gateway needs a scope Alice hasn't consented
    # to yet (e.g. banking:payments:transfer). Surface it so the agent can push a
    # step-up back to the app → PingFederate.
    if body.get("error") == "insufficient_scope":
        return {"authorized": False, "insufficient_scope": True,
                "scope_required": body.get("scope"), "pep": body.get("pep") or pep,
                "message": f"STEP-UP REQUIRED at {pep}: scope '{body.get('scope')}' needed",
                "policy_reason": body.get("reason") or "insufficient scope"}
    # mDL identity-proofing challenge: origination needs a verified identity-proofing
    # activity for the customer. Surface it so the agent relays an identity challenge
    # (CIBA push → app2app wallet presentation) instead of narrating a flat denial.
    if body.get("error") == "identity_verification_required":
        return {"authorized": False, "identity_proofing_required": True,
                "doctype": body.get("doctype"), "pep": body.get("pep") or pep,
                "message": f"IDENTITY PROOFING REQUIRED at {pep}: present {body.get('doctype')}",
                "policy_reason": body.get("reason") or "identity proofing required"}
    if resp.status_code == 401:
        return {"authorized": False, "pep": pep,
                "message": f"UNAUTHENTICATED at {pep}: {body.get('reason', 'no valid token')}",
                "policy_reason": body.get("reason")}
    if resp.status_code == 403:
        r = body.get("reason") or reason or "Denied by policy."
        p = body.get("pep") or pep
        return {"authorized": False, "pep": p, "pep_action": pep_action,
                "message": f"POLICY DENIED by {p}: {r}", "policy_reason": r}
    if resp.status_code >= 400:
        return {"authorized": True, "success": False, "pep": pep, "pep_action": pep_action,
                "message": body.get("error") or body.get("message") or f"HTTP {resp.status_code}",
                "result": body}

    result = dict(body)
    result.update({"authorized": True, "pep": pep, "pep_action": pep_action,
                   "policy_reason": reason or "Permitted by policy."})
    return result
