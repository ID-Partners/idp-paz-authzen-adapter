"""Tests for the concierge's Grant Management API client.

The unit under test is `_gm_call`: the one place the agent talks to the authorization
server. Its job is narrow but unforgiving — send a well-formed AuthZEN request with NO
subject (the AS infers that from the token), and turn whatever comes back into a dict the
dispatch loop can read without crashing the turn.

Two properties are load-bearing and get most of the attention here:

  * It must never return a non-dict. A bare string leaking out is what previously killed a
    whole agent turn with "'str' object has no attribute 'get'".
  * An error must stay distinguishable from a decision. "I could not ask" rendered as
    "denied" (or as an empty entitlement set) tells the customer something false.

No network: httpx.AsyncClient is replaced with a stub, so every branch is reachable and
the suite is hermetic.
"""
from __future__ import annotations

import asyncio
import json
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))


# --- stub the heavy imports agent_core pulls in at module load ---------------------
def _stub(name, **attrs):
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    sys.modules.setdefault(name, mod)


_stub("anthropic", Anthropic=object)
_stub("a2a_client", a2a_send=None, fetch_agent_card=None)
_stub("auth", TASK_AGENTS=[], acquire_principal_credential=None)
_stub("token_verify", verify_bearer=None)

import agent_core  # noqa: E402


# --- httpx stub -------------------------------------------------------------------
class _Resp:
    def __init__(self, payload, status=200, text=None):
        self._payload = payload
        self.status_code = status
        self.text = text if text is not None else json.dumps(payload)

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _Client:
    """Stands in for httpx.AsyncClient; records the last request."""

    last_url = None
    last_json = None
    last_headers = None

    def __init__(self, response=None, raise_on_post=None):
        self._response = response
        self._raise = raise_on_post

    def __call__(self, *a, **kw):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, json=None, headers=None):
        type(self).last_url = url
        type(self).last_json = json
        type(self).last_headers = headers
        if self._raise:
            raise self._raise
        return self._response


def _install(monkeypatch, response=None, raise_on_post=None):
    client = _Client(response, raise_on_post)
    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(AsyncClient=client))
    return client


def _mcp(payload_obj):
    """A well-formed MCP tools/call result carrying JSON in a text content block."""
    return _Resp({"result": {"content": [{"type": "text", "text": json.dumps(payload_obj)}]}})


def call(monkeypatch, response=None, raise_on_post=None, token="tok", tool="evaluate_grant",
         args=None):
    _install(monkeypatch, response, raise_on_post)
    return asyncio.run(agent_core._gm_call(
        token, tool, args if args is not None else
        {"action": {"name": "read_balance"}, "resource": {"type": "account", "id": "CHK-1001"}}))


# ----------------------------------------------------------------------------------
# the request that goes out
# ----------------------------------------------------------------------------------

def test_sends_an_authzen_request_with_no_subject(monkeypatch):
    call(monkeypatch, _mcp({"permitted": True}))

    body = _Client.last_json
    assert body["method"] == "tools/call"
    assert body["params"]["name"] == "evaluate_grant"
    args = body["params"]["arguments"]
    assert args["action"] == {"name": "read_balance"}
    assert args["resource"] == {"type": "account", "id": "CHK-1001"}
    # The whole point: a caller cannot ask about anyone but itself.
    assert "subject" not in args
    assert "grant_id" not in args


def test_presents_the_token_as_a_bearer(monkeypatch):
    call(monkeypatch, _mcp({"permitted": True}), token="gm-token")
    assert _Client.last_headers["Authorization"] == "Bearer gm-token"


def test_no_token_means_no_authorization_header(monkeypatch):
    call(monkeypatch, _mcp({"permitted": True}), token=None)
    assert _Client.last_headers == {}


# ----------------------------------------------------------------------------------
# the wire block the transcript renders
# ----------------------------------------------------------------------------------

def test_wire_block_carries_curl_request_and_redacted_token(monkeypatch):
    token = "header.payload.signature-that-is-quite-long-indeed"
    ans = call(monkeypatch, _mcp({"permitted": True}), token=token)

    wire = ans["_wire"]
    assert wire["url"] == agent_core.GM_MCP_URL
    assert wire["request"]["params"]["name"] == "evaluate_grant"
    assert "curl -X POST" in wire["curl"]
    # redacted: a stub, never the whole credential
    assert token not in wire["curl"]
    assert token[:24] in wire["curl"]


def test_wire_block_handles_a_missing_token(monkeypatch):
    ans = call(monkeypatch, _mcp({"permitted": True}), token=None)
    assert "<none>" in ans["_wire"]["curl"]


# ----------------------------------------------------------------------------------
# response coercion — every shape must yield a dict
# ----------------------------------------------------------------------------------

def test_a_decision_object_passes_through(monkeypatch):
    ans = call(monkeypatch, _mcp({"permitted": False, "reason": "subject_not_entitled",
                                  "consent_would_help": False}))
    assert ans["permitted"] is False
    assert ans["reason"] == "subject_not_entitled"


def test_a_permitted_set_passes_through(monkeypatch):
    ans = call(monkeypatch, _mcp({"permitted": ["CHK-1001", "SAV-1002"], "count": 2}),
               tool="list_entitlements",
               args={"action": {"name": "search_accounts"}, "resource": {"type": "account"}})
    assert ans["permitted"] == ["CHK-1001", "SAV-1002"]
    assert ans["count"] == 2


def test_non_json_text_becomes_a_dict_not_a_string(monkeypatch):
    # The regression that once killed a turn: a bare string reaching the dispatch loop.
    resp = _Resp({"result": {"content": [{"type": "text", "text": "not json at all"}]}})
    ans = call(monkeypatch, resp)
    assert isinstance(ans, dict)
    assert ans["text"] == "not json at all"


def test_double_encoded_non_object_json_is_wrapped(monkeypatch):
    resp = _Resp({"result": {"content": [{"type": "text", "text": '["CHK-1001"]'}]}})
    ans = call(monkeypatch, resp)
    assert isinstance(ans, dict)
    assert ans["result"] == ["CHK-1001"]


def test_a_flat_error_object_is_surfaced_as_an_error(monkeypatch):
    # What the GM API returns on a rejected token — NOT a policy denial.
    ans = call(monkeypatch, _Resp({"error": "invalid_token"}, status=401))
    assert ans["error"] == "invalid_token"
    assert "permitted" not in ans


def test_a_structured_jsonrpc_error_is_surfaced(monkeypatch):
    ans = call(monkeypatch, _Resp({"error": {"code": -32602, "message": "grant_id is required"}}))
    assert ans["message"] == "grant_id is required"


def test_a_non_dict_document_becomes_an_error(monkeypatch):
    ans = call(monkeypatch, _Resp(["unexpected"], status=200, text='["unexpected"]'))
    assert isinstance(ans, dict)
    assert "error" in ans


def test_undecodable_body_becomes_an_error(monkeypatch):
    ans = call(monkeypatch, _Resp(ValueError("no json"), status=502, text="<html>gateway</html>"))
    assert "gm-api 502" in ans["error"]
    assert ans["raw"].startswith("<html>")


def test_an_unreachable_pdp_is_an_error_never_a_decision(monkeypatch):
    ans = call(monkeypatch, raise_on_post=OSError("connection refused"))
    assert "unreachable" in ans["error"]
    # Must not look like "denied" or "you hold nothing".
    assert "permitted" not in ans


def test_a_result_without_content_still_yields_a_dict(monkeypatch):
    ans = call(monkeypatch, _Resp({"result": {"isError": False}}))
    assert isinstance(ans, dict)


def test_a_non_dict_result_field_yields_a_dict(monkeypatch):
    ans = call(monkeypatch, _Resp({"result": "surprise"}, text='{"result": "surprise"}'))
    assert isinstance(ans, dict)
    assert "raw" in ans


def test_non_text_content_blocks_are_skipped(monkeypatch):
    resp = _Resp({"result": {"content": [{"type": "image", "data": "x"}]}})
    ans = call(monkeypatch, resp)
    assert isinstance(ans, dict)


# ----------------------------------------------------------------------------------
# token claim reading (used to route/display only)
# ----------------------------------------------------------------------------------

def test_token_claim_returns_none_for_a_missing_or_bad_token():
    assert agent_core._token_claim(None, "aud") is None
    assert agent_core._token_claim("not-a-jwt", "aud") is None


def test_token_claim_reads_a_claim():
    import jwt
    t = jwt.encode({"aud": "https://gm-api.demo/grants", "sub": "alice"}, "k", algorithm="HS256")
    assert agent_core._token_claim(t, "aud") == "https://gm-api.demo/grants"
    assert agent_core._token_sub(t) == "alice"
    assert agent_core._token_sub(None) is None
    assert agent_core._token_sub("nope") is None


# ----------------------------------------------------------------------------------
# the tools the model sees
# ----------------------------------------------------------------------------------

def test_both_authority_tools_are_offered():
    names = {t["name"] for t in agent_core.BANK_TOOLS}
    assert {"check_grant", "list_entitlements"} <= names


def test_the_prompt_forbids_answering_authority_from_memory():
    # This instruction is the whole behavioural fix; assert it survives edits.
    prompt = agent_core.SYSTEM_PROMPT_TEMPLATE
    assert "NEVER ANSWER AUTHORITY QUESTIONS FROM MEMORY" in prompt
    assert "list_entitlements" in prompt
