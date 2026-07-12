"""
A Task Agent as its own service, invoked by the Principal Agent (concierge) over
**A2A** (Agent2Agent — JSON-RPC over HTTP with an Agent Card).

Run as the Account Agent or the Payments Agent via AGENT_ROLE. On each A2A
`message/send`, this agent establishes its OWN identity (entity + local keys,
client attestation, a delegated DPoP-bound token whose nested `act` chain adds it
over the concierge), opens its OWN MCP session to the bank through Kong, executes
the requested operation, and returns the result plus its identity/wire steps so
the concierge can surface them.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from identity import EVENT_SINK_URL, PFExchangeError, establish_identity, exchange_for_events
from mcp_exec import MCP_SERVER_URL, LoginRequired, call_tool
from token_verify import verify_bearer

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("task-agent")

ROLES = {
    "account": {
        "id": os.environ.get("ACCOUNT_AGENT_ID", "urn:agent:northwind-account:v1"),
        "type": "account-opening", "label": "Account Agent",
        "skills": ["list_accounts", "get_balance", "open_account"],
        "description": "Opens accounts and reads balances on behalf of the customer."},
    "payments": {
        "id": os.environ.get("PAYMENTS_AGENT_ID", "urn:agent:northwind-payments:v1"),
        "type": "payments", "label": "Payments Agent",
        "skills": ["make_payment"],
        "description": "Initiates payments/transfers on behalf of the customer."},
}

AGENT_ROLE = os.environ.get("AGENT_ROLE", "account").lower()
CFG = ROLES.get(AGENT_ROLE, ROLES["account"])
PUBLIC_URL = os.environ.get("PUBLIC_URL", "")   # this service's own base URL (for the card)

app = FastAPI(title=f"Northwind {CFG['label']}")


def _presented(cred, url: str) -> dict[str, Any]:
    tp = cred.access_token
    tp = (tp[:28] + "…" + tp[-14:]) if len(tp) > 44 else tp
    proof = cred._dpop_proof("POST", url)
    # The full delegation chain the PEP receives, read outside-in from the token's
    # nested act: principal ◀ earliest delegator ◀ … ◀ current actor. actor_chain
    # is [current, …, earliest], so reverse it and prepend the principal.
    chain = list(getattr(cred, "actor_chain", None) or [cred.agent_sub])
    parties = [cred.principal_sub, *reversed(chain)]
    return {"scheme": "DPoP", "authorization": f"DPoP {tp}",
            "dpop_proof": proof[:28] + "…" + proof[-14:], "jkt": cred.jkt,
            "sub": cred.principal_sub, "act": cred.agent_sub,
            "actor_chain": chain, "act_chain": " ◀ ".join(parties)}


@app.get("/ping")
def ping():
    return {"status": "healthy", "role": AGENT_ROLE}


@app.get("/health")
def health():
    return {"status": "ok", "role": AGENT_ROLE, "agent": CFG["id"]}


@app.get("/.well-known/agent-card.json")
def agent_card(request: Request):
    """A2A Agent Card — how the concierge discovers this agent and its skills."""
    base = PUBLIC_URL or str(request.base_url).rstrip("/")
    return {
        "protocolVersion": "0.2.0",
        "name": CFG["label"],
        "description": CFG["description"],
        "url": f"{base}/a2a",
        "preferredTransport": "JSONRPC",
        "provider": {"organization": "Northwind Bank"},
        "version": "1.0.0",
        "capabilities": {"streaming": False},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [{"id": s, "name": s.replace("_", " "),
                    "description": f"{s} at Northwind Bank", "tags": ["banking", AGENT_ROLE]}
                   for s in CFG["skills"]],
        "securitySchemes": {"delegatedToken": {"type": "http", "scheme": "bearer",
                            "description": "The concierge's delegated (RFC 8693) DPoP-bound token"}},
        "security": [{"delegatedToken": []}],
    }


def _rpc_error(rpc_id, code, message):
    return JSONResponse(status_code=200, content={
        "jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}})


@app.post("/a2a")
async def a2a(request: Request):
    """A2A JSON-RPC endpoint. Supports message/send carrying {operation, arguments}."""
    body = await request.json()
    rpc_id = body.get("id")
    if body.get("method") != "message/send":
        return _rpc_error(rpc_id, -32601, f"unsupported method '{body.get('method')}'")

    params = body.get("params", {})
    message = params.get("message", {})
    data = {}
    for part in message.get("parts", []):
        if part.get("kind") == "data" and isinstance(part.get("data"), dict):
            data = part["data"]
            break
    operation = data.get("operation")
    arguments = data.get("arguments", {}) or {}
    if operation not in CFG["skills"]:
        return _rpc_error(rpc_id, -32602,
                          f"{CFG['label']} does not handle '{operation}' "
                          f"(skills: {', '.join(CFG['skills'])})")

    # The concierge's delegated token arrives as the A2A bearer credential.
    subj = request.headers.get("authorization", "")
    subj_note = "present" if subj else "absent"
    # The logged-in principal (Alice)'s PF token rides along as X-User-Token; the
    # gateway requires it and will challenge for a login if it's missing.
    user_token = request.headers.get("x-user-token") or None
    logger.info("A2A message/send op=%s (delegation token %s, user token %s)",
                operation, subj_note, "present" if user_token else "absent")

    # 0) VERIFY the tokens presented to this agent before acting — the calling
    #    agent's A2A bearer and Alice's forwarded PF token — with token_validator
    #    (signature vs PingFederate JWKS, issuer, expiry). Don't trust; verify.
    _bearer = subj.split(" ", 1)[1] if " " in subj else (subj or None)
    verify_steps = [
        verify_bearer(_bearer, kind="agent", presenter="the calling agent (A2A bearer)"),
        verify_bearer(user_token, kind="user", presenter="the app (Alice's PF token)"),
    ]

    # 1) This task agent establishes its own identity + delegated token — a real
    #    RFC 8693 exchange of Alice's login token when she's signed in.
    try:
        cred = establish_identity(agent_id=CFG["id"], agent_type=CFG["type"],
                                  agent_label=CFG["label"], role=AGENT_ROLE, mcp_url=MCP_SERVER_URL,
                                  user_token=user_token, delegator_token=_bearer)
    except PFExchangeError as exc:
        # Surface the failure in the transcript (curl + decoded subject token + PF error) instead
        # of a bare 500, so the identity failure is visible + debuggable in the activity log.
        steps = verify_steps + [exc.diagnostic]
        return JSONResponse(status_code=200, content={
            "jsonrpc": "2.0", "id": rpc_id, "result": {
                "message": {"role": "agent", "parts": [{"kind": "data",
                    "data": {"error": "token_exchange_failed", "detail": exc.diagnostic["summary"]}}]},
                "metadata": {"agent": CFG["id"], "agent_label": CFG["label"], "role": AGENT_ROLE,
                             "steps": steps}}})
    steps: list[dict[str, Any]] = verify_steps + list(cred.steps)
    steps.append({
        "type": "connect", "role": AGENT_ROLE, "agent": CFG["id"], "agent_label": CFG["label"],
        "detail": f"{CFG['label']} ({CFG['id']}) opened its own MCP session via Kong (PEP #1) "
                  f"with its own DPoP-bound token.",
        "mcp_url": MCP_SERVER_URL, "token_preview": _presented(cred, MCP_SERVER_URL)["authorization"],
        "presented": _presented(cred, MCP_SERVER_URL)})
    steps.append({
        "type": "tool_call", "name": operation, "input": arguments, "role": AGENT_ROLE,
        "agent": CFG["id"], "agent_label": CFG["label"], "mcp_url": MCP_SERVER_URL,
        "presented": _presented(cred, MCP_SERVER_URL)})

    # 2) Execute the banking operation through the gateways.
    try:
        outcome = await call_tool(cred, operation, arguments, user_token=user_token)
    except LoginRequired:
        # The gateway (PEP #1) required a logged-in user and none was presented.
        # Relay a login challenge so the app can send Alice to PingFederate.
        logger.info("Gateway challenged for login (op=%s, no user token)", operation)
        steps.append({
            "type": "login_challenge", "role": AGENT_ROLE, "agent_label": CFG["label"],
            "detail": f"Kong (PEP #1) rejected {CFG['label']}'s call: the gateway policy "
                      f"requires a signed-in user (RFC 9470 step-up). Challenging for login."})
        return JSONResponse(status_code=200, content={
            "jsonrpc": "2.0", "id": rpc_id, "result": {
                "message": {"role": "agent", "parts": [{"kind": "data",
                    "data": {"error": "login_required"}}]},
                "metadata": {"agent": CFG["id"], "agent_label": CFG["label"], "role": AGENT_ROLE,
                             "steps": steps,
                             "login_challenge": {"login_url": "/login",
                                 "detail": "The account gateway requires you to sign in."}}}})
    except Exception as exc:  # noqa: BLE001
        logger.warning("MCP call failed: %s", exc)
        return _rpc_error(rpc_id, -32000, f"{CFG['label']} could not reach the bank: {exc}")

    # The gateway needs a scope the signed-in user hasn't consented to yet
    # (e.g. banking:payments:transfer). Relay a scope step-up so the app can send
    # Alice back to PingFederate to approve it, then retry.
    if outcome.get("insufficient_scope"):
        scope = outcome.get("scope_required")
        # This is a DISPLAY step only (type != 'scope_challenge') so it renders in
        # the transcript without tripping the app's scope_challenge redirect handler.
        # The concierge emits the single, authoritative 'scope_challenge' event
        # (carrying the payment authorization_details) that drives the RAR step-up.
        steps.append({
            "type": "scope_stepup", "role": AGENT_ROLE, "agent_label": CFG["label"],
            "scope": scope, "pep": outcome.get("pep"),
            "detail": f"PEP #2 rejected {operation} with 401 insufficient_scope: it needs the "
                      f"'{scope}' scope, which the signed-in user hasn't approved. Step-up required."})
        return JSONResponse(status_code=200, content={
            "jsonrpc": "2.0", "id": rpc_id, "result": {
                "message": {"role": "agent", "parts": [{"kind": "data",
                    "data": {"error": "insufficient_scope", "scope": scope}}]},
                "metadata": {"agent": CFG["id"], "agent_label": CFG["label"], "role": AGENT_ROLE,
                             "steps": steps,
                             "scope_challenge": {"scope": scope, "pep": outcome.get("pep"),
                                 "detail": f"This action needs the '{scope}' scope."}}}})

    steps.append({
        "type": "tool_result", "name": operation, "role": AGENT_ROLE, "agent_label": CFG["label"],
        "authorized": outcome.get("authorized"), "policy_reason": outcome.get("policy_reason"),
        "pep": outcome.get("pep"), "pep_action": outcome.get("pep_action"),
        "bank_response": outcome.get("result"), "result": outcome.get("result")})

    # After a successful payment, publish an event using a FLATTENED token (sub=root actor, no
    # act) obtained via a 2nd audience-scoped exchange. Guarded: a no-op unless EVENT_SINK_URL is
    # set AND the events ATM/mapping has been applied in PF (Terraform flatten.tf).
    if EVENT_SINK_URL and outcome.get("authorized") and "payment" in operation.lower():
        try:
            etok, eclaims, estep = exchange_for_events(agent_id=CFG["id"], subject_token=cred.access_token)
            steps.append(estep)
            er = httpx.post(EVENT_SINK_URL.rstrip("/") + "/events",
                            headers={"Authorization": f"Bearer {etok}"},
                            json={"paymentId": arguments.get("paymentId"), **arguments},
                            timeout=15.0, verify=False)
            ebody = er.json() if er.headers.get("content-type", "").startswith("application/json") else er.text[:300]
            steps.append({
                "type": "event_published", "role": AGENT_ROLE, "agent_label": CFG["label"],
                "accepted": er.status_code < 400, "status": er.status_code,
                "producer": eclaims.get("sub"), "audience": eclaims.get("aud"),
                "detail": (f"Event-sink {'accepted' if er.status_code < 400 else 'rejected'} the flattened "
                           f"token (HTTP {er.status_code}) — producer={eclaims.get('sub')}, no act chain."),
                "response": ebody})
        except PFExchangeError as exc:
            # Surface the flatten-exchange ATTEMPT (curl + nested-act subject token + PF error) so the
            # activity log shows the event-sync token exchange even before the events ATM is applied.
            exc.diagnostic["agent_label"] = CFG["label"]
            steps.append(exc.diagnostic)
        except Exception as exc:  # noqa: BLE001
            steps.append({
                "type": "event_publish_skipped", "role": AGENT_ROLE, "agent_label": CFG["label"],
                "detail": f"Event publish skipped ({exc}) — the events ATM/mapping may not be applied yet."})

    return JSONResponse(status_code=200, content={
        "jsonrpc": "2.0", "id": rpc_id, "result": {
            "message": {"role": "agent", "parts": [{"kind": "data", "data": outcome.get("result")}]},
            "metadata": {"agent": CFG["id"], "agent_label": CFG["label"], "role": AGENT_ROLE,
                         "authorized": outcome.get("authorized"), "pep": outcome.get("pep"),
                         "policy_reason": outcome.get("policy_reason"), "steps": steps}}})


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8100"))
    host = os.environ.get("HOST", "::")   # IPv6 for Railway private networking
    logger.info("Starting %s (%s) on %s:%s → MCP %s", CFG["label"], CFG["id"], host, port, MCP_SERVER_URL)
    uvicorn.run(app, host=host, port=port)
