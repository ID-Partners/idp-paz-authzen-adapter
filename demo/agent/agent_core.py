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

import asyncio
import json
import logging
import os
from typing import Any, AsyncIterator

import anthropic

from a2a_client import a2a_send, fetch_agent_card
from auth import TASK_AGENTS, acquire_principal_credential
from token_verify import verify_bearer

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("bank-agent")

ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5")
MAX_TURNS = int(os.environ.get("AGENT_MAX_TURNS", "12"))

# The banking capabilities the concierge exposes to the LLM. It does NOT call the
# bank itself — each capability is fulfilled by delegating over A2A to the task
# agent whose Agent Card advertises that skill (see TASK_AGENTS / agent_events).
BANK_TOOLS = [
    {"name": "list_accounts", "description": "List the customer's accounts and balances.",
     "input_schema": {"type": "object", "properties": {"customer_id": {"type": "string"}},
                      "required": ["customer_id"]}},
    {"name": "get_balance", "description": "Get the balance of one of the customer's accounts.",
     "input_schema": {"type": "object", "properties": {
         "customer_id": {"type": "string"}, "account_id": {"type": "string"}},
                      "required": ["customer_id", "account_id"]}},
    {"name": "open_account", "description": "Open a new bank account for the customer.",
     "input_schema": {"type": "object", "properties": {
         "customer_id": {"type": "string"},
         "account_type": {"type": "string", "description": "e.g. savings or checking"},
         "nickname": {"type": "string"}}, "required": ["customer_id", "account_type"]}},
    {"name": "make_payment", "description": "Move money between the customer's accounts.",
     "input_schema": {"type": "object", "properties": {
         "customer_id": {"type": "string"}, "from_account": {"type": "string"},
         "to_account": {"type": "string"}, "amount": {"type": "number"},
         "currency": {"type": "string"}, "description": {"type": "string"}},
                      "required": ["customer_id", "from_account", "to_account", "amount"]}},
]

# --- conversation memory ------------------------------------------------------
# Per-session conversation history so the agent remembers earlier turns. This is
# an in-process store (fine for the single-replica demo; not shared across
# replicas and cleared on restart). Keyed by session_id sent from the UI.
_SESSIONS: dict[str, list[dict[str, Any]]] = {}
MAX_HISTORY_MESSAGES = int(os.environ.get("AGENT_HISTORY_MESSAGES", "40"))
MAX_SESSIONS = int(os.environ.get("AGENT_MAX_SESSIONS", "100"))


def _trim_history(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Cap history length, trimming to a real user-turn boundary so the first
    message is a plain user prompt (never an orphaned tool_result), which the
    Anthropic API requires."""
    if len(messages) <= MAX_HISTORY_MESSAGES:
        return messages
    tail = messages[-MAX_HISTORY_MESSAGES:]
    for i, m in enumerate(tail):
        if m.get("role") == "user" and isinstance(m.get("content"), str):
            return tail[i:]
    return tail


def reset_session(session_id: str) -> None:
    _SESSIONS.pop(session_id, None)

SYSTEM_PROMPT_TEMPLATE = """\
You are the Principal Agent (a banking concierge) for Northwind Bank. You act on
behalf of an authenticated customer and orchestrate specialist task agents (an
account agent and a payments agent) to open accounts and move money using the
tools provided.

Rules:
- The current customer's id is "{customer_id}" (the authenticated user you are
  acting for). Always pass customer_id="{customer_id}". You may not act for any
  other customer; the bank rejects a customer_id that isn't the signed-in user.
- Be concise and explain each step you take to the customer.
- Every tool enforces the bank's authorization policy (Ping Authorize). If a tool
  returns "authorized": false or a message beginning "POLICY DENIED", do NOT
  retry. Clearly tell the customer the action was blocked and relay the policy
  reason, then stop or suggest a compliant alternative.
- When opening a new account and funding it: first LIST the customer's accounts to
  find their existing everyday/checking account, then open the new account, then pay
  into it from that account. Never assume an account id — every customer has their
  own (the seeded demo customer's checking is CHK-1001, but a new customer's is not),
  so read it from their account list rather than guessing.
"""


def _token_sub(token: str | None) -> str | None:
    """The `sub` (authenticated principal) of a JWT, without verifying signature —
    for deriving who the concierge is acting for. Display/routing use only."""
    if not token:
        return None
    try:
        import jwt  # PyJWT (already a dependency via auth.py)
        return jwt.decode(token, options={"verify_signature": False}).get("sub")
    except Exception:  # noqa: BLE001
        return None


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


async def agent_events(prompt: str, session_id: str = "demo",
                       user_token: str | None = None,
                       customer_id: str | None = None) -> AsyncIterator[dict[str, Any]]:
    """Run one agent turn, yielding each transcript step AS IT HAPPENS.

    Emits identity steps, the gateway connect, the agent's reasoning, each tool
    call and its Ping Authorize decision, and finally a `{"type":"final", ...}`
    event with the assistant's answer. Consumers (the SSE endpoint, or the
    `run_agent` collector below) render each event the moment it arrives so the
    UI can reflect activity live.
    """
    client = _anthropic_client()

    # 0) Policy at the token exchange: the Principal Agent can only get a token to
    #    act FOR Alice by exchanging one at the AS, and issuance requires an
    #    AUTHENTICATED USER PRINCIPAL (the subject) plus the delegated scopes.
    #    If Alice isn't signed in there is no subject to exchange — challenge for
    #    login up front, before any agent work, rather than deep at the gateway.
    if not user_token:
        yield {"type": "login_challenge", "role": "principal", "agent_label": "Principal Agent",
               "login_url": "/login", "stage": "token_exchange",
               "detail": "The Principal Agent must exchange a token at PingFederate to act on your "
                         "behalf. Ping Authorize governs issuance and requires an authenticated user "
                         "principal (the subject) with the delegated scopes — and you're not signed in."}
        yield {"type": "final", "session_id": session_id,
               "final": "🔒 Before I can act on your behalf I have to exchange a token at the "
                        "authorization server, and policy requires you to be signed in first. "
                        "Taking you to the PingFederate login…"}
        return

    # 0) VERIFY Alice's forwarded PF token before acting on it — signature vs
    #    PingFederate's JWKS, issuer, expiry — with token_validator. Don't trust; verify.
    vstep = verify_bearer(user_token, kind="user", presenter="the app (BFF)")
    yield vstep
    if not vstep.get("verified"):
        yield {"type": "final", "session_id": session_id,
               "final": f"🛑 I couldn't verify your session token ({vstep.get('error')}), so I won't "
                        f"act on it. Please sign in again."}
        return

    # 1) Establish the Principal Agent (concierge)'s own authority: attestation +
    #    a REAL RFC 8693 token exchange at the AS — Alice's login token is the
    #    subject_token, so the issued token's sub is her authenticated identity.
    principal = acquire_principal_credential(user_token=user_token)
    for step in principal.steps:
        yield step

    # The customer the concierge acts for IS the authenticated principal — the
    # `sub` of the delegated token (derived from the login token via RFC 8693), not
    # a hardcoded id. This is the customer_id passed to every bank tool; the Bank
    # API enforces it equals the authenticated principal (X-Auth-Principal).
    #
    # STAFF CONTEXT (the autonomous demo): when the authenticated principal is a
    # bank STAFF member (e.g. bob, the agent owner), the operation targets a NAMED
    # customer's accounts — the account owner from the triggering event — not the
    # staff member's own (staff have no bank accounts). The caller supplies that
    # target as `customer_id`, honoured ONLY for staff principals; a customer
    # principal can never act on anyone but themselves. The Bank API applies the
    # same rule server-side (staff principals may act on a customer, audited).
    sub = _token_sub(principal.token) or _token_sub(user_token) or "alice"
    staff_subs = set((os.environ.get("STAFF_SUBS", "bob")).split(","))
    staff_note = ""
    if customer_id and sub in staff_subs:
        staff_note = (
            f"\n- STAFF CONTEXT: you are operating under the authority of bank staff "
            f"member \"{sub}\" (the agent owner), ON BEHALF OF account owner "
            f"\"{customer_id}\". The accounts belong to {customer_id}, not {sub}.")
    else:
        customer_id = sub
    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(customer_id=customer_id) + staff_note

    # 2) Discover the task agents over A2A (their Agent Cards). Build a
    #    skill → task-agent routing table from what each agent advertises.
    skill_route: dict[str, dict[str, Any]] = {}
    for cfg in TASK_AGENTS:
        try:
            card = await fetch_agent_card(cfg["url"])
        except Exception as exc:  # noqa: BLE001
            logger.warning("A2A discovery failed for %s: %s", cfg["label"], exc)
            yield {"type": "connect_error",
                   "detail": f"Could not reach {cfg['label']} at {cfg['url']} over A2A: {exc}"}
            continue
        skills = [s.get("id") for s in card.get("skills", []) if s.get("id")]
        a2a_url = card.get("url") or (cfg["url"].rstrip("/") + "/a2a")
        for sk in skills:
            skill_route[sk] = {"url": a2a_url, "role": cfg["role"],
                               "label": cfg["label"], "agent_id": cfg["id"]}
        yield {"type": "agent_card", "role": cfg["role"], "agent_label": cfg["label"],
               "agent": cfg["id"], "base_url": cfg["url"], "a2a_url": a2a_url,
               "skills": skills, "card": card,
               "detail": f"Discovered {cfg['label']} via its A2A Agent Card at "
                         f"{cfg['url']}/.well-known/agent-card.json ({len(skills)} skills)."}

    tools = [t for t in BANK_TOOLS if t["name"] in skill_route]
    agent_texts: list[str] = []
    if not tools:
        yield {"type": "final", "session_id": session_id,
               "final": "No task agents were reachable over A2A, so I couldn't act on the "
                        "bank. The concierge authenticated, but its specialist agents are down."}
        return

    # 3) Seed conversation memory, then run the LLM loop.
    messages: list[dict[str, Any]] = list(_SESSIONS.get(session_id, []))
    messages.append({"role": "user", "content": prompt})
    if len(messages) > 1:
        yield {"type": "memory",
               "detail": f"Continuing session '{session_id}' with "
                         f"{len(messages) - 1} prior message(s) of context.",
               "prior_messages": len(messages) - 1}

    for _turn in range(MAX_TURNS):
        resp = await asyncio.to_thread(
            lambda: client.messages.create(
                model=ANTHROPIC_MODEL, max_tokens=1024,
                system=system_prompt, tools=tools, messages=messages))

        assistant_content: list[dict[str, Any]] = []
        tool_uses = []
        for block in resp.content:
            if block.type == "text":
                assistant_content.append({"type": "text", "text": block.text})
                if block.text.strip():
                    agent_texts.append(block.text)
                    yield {"type": "agent", "text": block.text}
            elif block.type == "tool_use":
                assistant_content.append({"type": "tool_use", "id": block.id,
                                          "name": block.name, "input": block.input})
                tool_uses.append(block)

        messages.append({"role": "assistant", "content": assistant_content})
        if resp.stop_reason != "tool_use":
            break

        tool_results = []
        for tu in tool_uses:
            route = skill_route.get(tu.name)
            if not route:
                text = json.dumps({"error": f"no task agent advertises '{tu.name}'"})
                tool_results.append({"type": "tool_result", "tool_use_id": tu.id, "content": text})
                continue

            # The concierge invokes the owning task agent over A2A, presenting its
            # delegated token as the bearer (the task agent's exchange subject).
            yield {"type": "a2a_call", "tool": tu.name, "input": tu.input, "role": route["role"],
                   "agent_label": route["label"], "agent": route["agent_id"], "a2a_url": route["url"],
                   "detail": f"Concierge → {route['label']} over A2A (message/send): {tu.name}."}
            try:
                result = await a2a_send(route["url"], tu.name, tu.input,
                                        bearer=principal.token, user_token=user_token)
            except Exception as exc:  # noqa: BLE001
                yield {"type": "a2a_result", "tool": tu.name, "role": route["role"],
                       "agent_label": route["label"], "ok": False,
                       "detail": f"{route['label']} A2A call failed: {exc}"}
                text = json.dumps({"error": str(exc)})
                tool_results.append({"type": "tool_result", "tool_use_id": tu.id, "content": text})
                continue

            md = result.get("metadata", {}) or {}
            # Surface the task agent's own identity/gateway/tool steps.
            for st in md.get("steps", []):
                yield st

            # The gateway required a logged-in user and none was presented — it
            # pushed back a login challenge (RFC 9470). Relay it so the app can
            # send Alice to PingFederate to authenticate, then retry.
            if md.get("login_challenge"):
                lc = md["login_challenge"]
                yield {"type": "login_challenge", "role": route["role"],
                       "agent_label": route["label"], "login_url": lc.get("login_url", "/login"),
                       "detail": lc.get("detail", "The gateway requires a signed-in user.")}
                yield {"type": "final", "session_id": session_id,
                       "final": "🔒 The account gateway requires you to sign in before I can act "
                                "on your behalf. Redirecting you to the PingFederate login…"}
                return

            # Account opening needs a verified mDL identity-proofing activity. Relay an
            # identity challenge: the app pushes the customer's phone (CIBA), the approver
            # opens the wallet app2app, the mDL is presented, and origination resumes.
            if md.get("identity_challenge"):
                ic = md["identity_challenge"]
                yield {"type": "identity_challenge", "role": route["role"],
                       "agent_label": route["label"], "doctype": ic.get("doctype"),
                       "pep": ic.get("pep"), "tool": tu.name,
                       "account": tu.input if tu.name == "open_account" else None,
                       "detail": ic.get("detail", "Identity proofing required.")}
                yield {"type": "final", "session_id": session_id,
                       "final": "🪪 Opening an account needs identity verification. "
                                "Check your phone — present your mobile Driver's Licence "
                                "(mDL) from your wallet, then I'll continue."}
                return

            # The gateway needs a scope the user hasn't consented to (a sensitive
            # transfer). Relay a step-up so the app sends Alice to PingFederate to
            # approve that scope, then resumes.
            if md.get("scope_challenge"):
                sc = md["scope_challenge"]
                scope = sc.get("scope")
                # Carry the specific operation (amount, accounts) so the app can
                # turn it into an RFC 9396 authorization_details (RAR) entry Alice
                # consents to at PingFederate — consent to THIS payment, governed
                # by Ping Authorize at issuance, not just to a coarse scope.
                pay = tu.input if tu.name == "make_payment" else None
                yield {"type": "scope_challenge", "role": route["role"],
                       "agent_label": route["label"], "scope": scope, "pep": sc.get("pep"),
                       "tool": tu.name, "payment": pay,
                       "detail": sc.get("detail", "A step-up scope is required.")}
                yield {"type": "final", "session_id": session_id,
                       "final": f"🔒 That transfer needs your approval for the '{scope}' scope. "
                                f"Taking you to PingFederate to sign in and approve it…"}
                return
            yield {"type": "a2a_result", "tool": tu.name, "role": route["role"],
                   "agent_label": route["label"], "ok": True,
                   "authorized": md.get("authorized"), "pep": md.get("pep"),
                   "detail": f"{route['label']} completed the task and returned over A2A."}

            parts = (result.get("message", {}) or {}).get("parts", [])
            bank = next((p.get("data") for p in parts if p.get("kind") == "data"), None)
            text = json.dumps(bank) if bank is not None else json.dumps(md)
            tool_results.append({"type": "tool_result", "tool_use_id": tu.id, "content": text})

        messages.append({"role": "user", "content": tool_results})

    # Persist the conversation so the next turn has memory.
    _SESSIONS[session_id] = _trim_history(messages)
    if len(_SESSIONS) > MAX_SESSIONS:
        _SESSIONS.pop(next(iter(_SESSIONS)))

    yield {"type": "final", "session_id": session_id,
           "final": "\n\n".join(agent_texts) or "Done."}


async def run_agent(prompt: str, session_id: str = "demo",
                    user_token: str | None = None,
                    customer_id: str | None = None) -> dict[str, Any]:
    """Non-streaming wrapper (AgentCore /invocations contract): collect the
    streamed events into a full transcript + final answer."""
    transcript: list[dict[str, Any]] = []
    final = "Done."
    async for ev in agent_events(prompt, session_id, user_token=user_token,
                                 customer_id=customer_id):
        if ev.get("type") == "final":
            final = ev.get("final", final)
        else:
            transcript.append(ev)
    return {"session_id": session_id, "final": final, "transcript": transcript}


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
