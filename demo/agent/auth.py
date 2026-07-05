"""
Agent identity, token exchange, and DPoP for the banking agent.

This module is where the agent obtains the authority it uses to call the bank.
It demonstrates the real agentic-identity mechanics:

  1. The agent is a distinct identity from both the human Principal and the
     Agent Operator (the OAuth client). See `AGENT_ID` vs `AGENT_CLIENT_ID`.
  2. It obtains a delegated token via RFC 8693 Token Exchange so the token
     carries the Principal as `sub` AND the agent as `act.sub` — DELEGATION,
     not impersonation. (The agent never presents the Principal's identity as
     its own.)
  3. Every call to a protected resource is sender-constrained with DPoP
     (RFC 9449): the token's `cnf.jkt` is the thumbprint of the agent's key,
     and each request carries a fresh DPoP proof signed by that key.

Two modes (TOKEN_MODE):

  * "pingfederate" — perform the genuine flow against the deployed PingFederate:
      client-credentials (actor token) + subject token → RFC 8693 exchange,
      DPoP-bound. Requires PF to be configured with the agent-operator client and
      a token-exchange processor policy (see demo/README.md).

  * "local" (default) — self-issue an equivalently-shaped DPoP-bound delegated
      token signed by a local key, so the demo runs end-to-end before PF is
      configured. The wire format (claims, act chain, cnf.jkt, DPoP proofs) is
      identical, so the agent, Kong, and Bank API code paths are unchanged.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Generator

import httpx
import jwt  # PyJWT
from cryptography.hazmat.primitives.asymmetric import ec

from attestation import mint_agent_attestation

logger = logging.getLogger("bank-agent.auth")

# --- identities (three distinct parties; see module docstring) ---
PRINCIPAL_SUB = os.environ.get("PRINCIPAL_SUB", "cust-alice")        # the human
AGENT_ID = os.environ.get("AGENT_ID", "urn:agent:northwind-onboarding:v1")  # act.sub
# The delegation chain: Alice authorises a Principal Agent (concierge), which
# delegates to a Task Agent that does the actual bank work. Each token-exchange
# hop nests the `act` claim (RFC 8693) so the exchanged token records the whole
# chain — sub=Alice, act={task-agent, act={principal-agent}} — delegation, not
# impersonation, at every hop. Ordered earliest-delegator → current-actor.
PRINCIPAL_AGENT_ID = os.environ.get("PRINCIPAL_AGENT_ID", "urn:agent:northwind-concierge:v1")
TASK_AGENT_ID = os.environ.get("TASK_AGENT_ID", AGENT_ID)
DELEGATION_CHAIN = [PRINCIPAL_AGENT_ID, TASK_AGENT_ID]

# The Principal Agent (concierge) delegates to TWO specialised task agents — an
# Account Agent and a Payments Agent — each getting its own key, attestation and
# nested actor chain (sub=Alice, act={task-agent, act={concierge}}). Each banking
# tool is owned by exactly one task agent, so the concierge routes each operation
# to the right agent (see tool_role / acquire_agent_fleet).
ACCOUNT_AGENT_ID = os.environ.get("ACCOUNT_AGENT_ID", "urn:agent:northwind-account:v1")
PAYMENTS_AGENT_ID = os.environ.get("PAYMENTS_AGENT_ID", "urn:agent:northwind-payments:v1")
# Task agents now run as their OWN services; the concierge reaches them over A2A.
ACCOUNT_AGENT_URL = os.environ.get("ACCOUNT_AGENT_URL", "http://localhost:8100")
PAYMENTS_AGENT_URL = os.environ.get("PAYMENTS_AGENT_URL", "http://localhost:8101")
TASK_AGENTS = [
    {"role": "account", "id": ACCOUNT_AGENT_ID, "type": "account-opening",
     "label": "Account Agent", "url": ACCOUNT_AGENT_URL,
     "tools": ["list_accounts", "get_balance", "open_account"]},
    {"role": "payments", "id": PAYMENTS_AGENT_ID, "type": "payments",
     "label": "Payments Agent", "url": PAYMENTS_AGENT_URL, "tools": ["make_payment"]},
]


def tool_role(tool_name: str) -> str:
    """Which task agent owns this banking tool (defaults to the account agent)."""
    for a in TASK_AGENTS:
        if tool_name in a["tools"]:
            return a["role"]
    return TASK_AGENTS[0]["role"]


AGENT_TYPE = os.environ.get("AGENT_TYPE", "ai_assistant")            # agent classification
AGENT_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5")   # the model it runs
AGENT_CLIENT_ID = os.environ.get("AGENT_CLIENT_ID", "bank-agent")    # Agent Operator (client_id)
AGENT_CLIENT_SECRET = os.environ.get("AGENT_CLIENT_SECRET", "")

# --- token shape ---
TOKEN_MODE = os.environ.get("TOKEN_MODE", "local").lower()
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "https://pingfederate-production.up.railway.app")
RS_AUDIENCE = os.environ.get("RS_AUDIENCE", "https://api.northwind.example/bank")
DEFAULT_SCOPE = os.environ.get(
    "AGENT_SCOPE",
    "bank:accounts.read bank:accounts.write bank:payments.initiate",
)
RAR_TYPE = os.environ.get(
    "RAR_TYPE", "https://schemas.idpartners.com.au/agentic/payment_initiation/v1")
TOKEN_TTL = int(os.environ.get("TOKEN_TTL", "900"))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_to_b64url(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return _b64url(n.to_bytes(length, "big"))


@dataclass
class AgentCredential:
    """A delegated, DPoP-bound access token plus the key that constrains it."""
    access_token: str
    principal_sub: str
    agent_sub: str
    scope: str
    jkt: str
    mode: str
    _key: ec.EllipticCurvePrivateKey
    steps: list[dict[str, Any]] = field(default_factory=list)

    def public_jwk(self) -> dict[str, str]:
        nums = self._key.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _int_to_b64url(nums.x),
            "y": _int_to_b64url(nums.y),
        }

    def _dpop_proof(self, method: str, url: str) -> str:
        """A fresh DPoP proof (RFC 9449) bound to this credential's key."""
        ath = _b64url(hashlib.sha256(self.access_token.encode()).digest())
        payload = {
            "jti": str(uuid.uuid4()),
            "htm": method.upper(),
            "htu": url.split("?")[0],
            "iat": int(time.time()),
            "ath": ath,
        }
        return jwt.encode(
            payload, self._key, algorithm="ES256",
            headers={"typ": "dpop+jwt", "jwk": self.public_jwk()},
        )

    def httpx_auth(self) -> "DPoPAuth":
        return DPoPAuth(self)

    def claims(self) -> dict[str, Any]:
        # decode without verifying signature — for display/transcript only
        return jwt.decode(self.access_token, options={"verify_signature": False})


class DPoPAuth(httpx.Auth):
    """httpx auth that attaches `Authorization: DPoP <token>` and a fresh
    per-request `DPoP: <proof>` header — the correct way to present a
    sender-constrained token across the several requests an MCP session makes."""

    requires_request_body = False

    def __init__(self, cred: AgentCredential) -> None:
        self._cred = cred

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        proof = self._cred._dpop_proof(request.method, str(request.url))
        request.headers["Authorization"] = f"DPoP {self._cred.access_token}"
        request.headers["DPoP"] = proof
        yield request


def _new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _jkt(key: ec.EllipticCurvePrivateKey) -> str:
    """RFC 7638 JWK thumbprint of the EC public key."""
    nums = key.public_key().public_numbers()
    canon = (
        '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}'
        % (_int_to_b64url(nums.x), _int_to_b64url(nums.y))
    )
    return _b64url(hashlib.sha256(canon.encode()).digest())


def _build_act_chain(actor_subs: list[str]) -> dict[str, Any]:
    """Nest an RFC 8693 `act` claim from a delegation chain.

    `actor_subs` is ordered earliest-delegator → current-actor. The current
    (most recent) actor is the OUTERMOST `act`; each prior delegator nests inside:

        ["principal-agent", "task-agent"]  ->
        {"sub": "task-agent", "act": {"sub": "principal-agent"}}
    """
    act: dict[str, Any] | None = None
    for sub in actor_subs:
        act = {"sub": sub, **({"act": act} if act else {})}
    return act or {}


def _actor_chain_labels(act: dict[str, Any]) -> list[str]:
    """Flatten a nested `act` to [current-actor, …, earliest-delegator] for display."""
    labels: list[str] = []
    node: dict[str, Any] | None = act
    while node and node.get("sub"):
        labels.append(node["sub"])
        node = node.get("act")
    return labels


def _authorization_details() -> list[dict[str, Any]]:
    return [{
        "type": RAR_TYPE,
        "actions": ["initiate"],
        "locations": [RS_AUDIENCE],
        "instructedAmount": {"currency": "AUD"},
    }]


# --------------------------------------------------------------------------
# local mode: self-issue an equivalently-shaped delegated, DPoP-bound token
# --------------------------------------------------------------------------

def _acquire_local() -> AgentCredential:
    key = _new_key()
    jkt = _jkt(key)
    now = int(time.time())
    signing_key = _new_key()          # throwaway demo IdP signing key
    token_header = {"alg": "ES256", "typ": "JWT"}
    pub = key.public_key().public_numbers()
    public_jwk = {"kty": "EC", "crv": "P-256",
                  "x": _int_to_b64url(pub.x), "y": _int_to_b64url(pub.y)}

    # Client attestation: a trusted attester vouches for the acting (task) agent's
    # AgentCore attributes and binds its DPoP key (cnf.jwk == public_jwk). This is
    # what the agent presents to the AS as `attest_jwt_client_auth_dpop`.
    attestation = mint_agent_attestation(
        client_id=AGENT_CLIENT_ID, agent_id=TASK_AGENT_ID, agent_type=AGENT_TYPE,
        principal_sub=PRINCIPAL_SUB, agent_public_jwk=public_jwk,
        authorization_details=_authorization_details(), model=AGENT_MODEL)

    steps: list[dict[str, Any]] = [
        {"type": "attestation", "title": "Client attestation",
         "detail": f"Attester '{attestation.attester_issuer}' issued an attestation "
                   f"JWT vouching for the agent's identity and AgentCore attributes, "
                   f"binding its DPoP key (cnf.jwk) and authority ceiling.",
         "attester": attestation.attester_issuer, "client_id": AGENT_CLIENT_ID,
         "agent": TASK_AGENT_ID, "agent_type": AGENT_TYPE,
         "auth_method": "attest_jwt_client_auth_dpop",
         "typ": attestation.header.get("typ"),
         "workload": attestation.claims.get("workload"),
         "attestation_header": attestation.header, "attestation_claims": attestation.claims,
         "attestation_preview": attestation.jwt[:24] + "…" + attestation.jwt[-12:],
         "presentation_headers": {
             "OAuth-Client-Attestation": attestation.jwt[:24] + "…" + attestation.jwt[-12:],
             "DPoP": "<proof signed by cnf.jwk>"},
         "attester_jwks": attestation.attester_jwks, "mode": "local"},
        {"type": "auth", "title": "Agent authenticates",
         "detail": f"Agent Operator client '{AGENT_CLIENT_ID}' authenticated to the "
                   f"IdP with the attestation (attest_jwt_client_auth_dpop) and a "
                   f"fresh DPoP key — no client secret.",
         "client_id": AGENT_CLIENT_ID, "agent": TASK_AGENT_ID, "jkt": jkt,
         "grant": "client_credentials", "auth_method": "attest_jwt_client_auth_dpop",
         "mode": "local"},
    ]

    # Chained RFC 8693 token exchange: one hop per delegation link. Each hop nests
    # the `act` claim, so the actor chain BUILDS UP — sub=Alice stays fixed while
    # act grows to {task-agent, act={principal-agent}} (delegation, not impersonation).
    token = ""
    claims: dict[str, Any] = {}
    prev_subject = "<principal access token — Alice>"
    for i, actor in enumerate(DELEGATION_CHAIN):
        act = _build_act_chain(DELEGATION_CHAIN[:i + 1])
        chain_labels = _actor_chain_labels(act)         # [current, …, earliest]
        claims = {
            "iss": "https://local-demo-idp.northwind.example",
            "sub": PRINCIPAL_SUB,                       # the human principal (fixed)
            "act": act,                                 # the nested delegation chain
            "aud": RS_AUDIENCE,
            "client_id": AGENT_CLIENT_ID,
            "azp": AGENT_CLIENT_ID,
            "scope": DEFAULT_SCOPE,
            "authorization_details": _authorization_details(),
            "cnf": {"jkt": jkt},                        # DPoP sender-constraint
            "iat": now,
            "exp": now + TOKEN_TTL,
        }
        token = jwt.encode(claims, signing_key, algorithm="ES256", headers=token_header)
        ath = _b64url(hashlib.sha256(token.encode()).digest())
        te_request = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": prev_subject,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "actor_token": f"<actor token — {actor}>",
            "actor_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": DEFAULT_SCOPE,
            "resource": RS_AUDIENCE,
        }
        dpop_example = {
            "header": {"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk},
            "payload": {"jti": str(uuid.uuid4()), "htm": "POST",
                        "htu": "https://<kong-gateway>/mcp", "iat": now, "ath": ath},
        }
        delegator = PRINCIPAL_SUB if i == 0 else DELEGATION_CHAIN[i - 1]
        steps.append({
            "type": "token_exchange",
            "title": f"Token exchange · hop {i + 1} of {len(DELEGATION_CHAIN)}",
            "detail": (f"{delegator} delegates to {actor}: the exchanged token now "
                       f"carries act = {' ◀ '.join(chain_labels)} under sub={PRINCIPAL_SUB} "
                       f"— delegation, not impersonation."),
            "sub": PRINCIPAL_SUB, "act": act, "act_sub": (act or {}).get("sub"),
            "actor_chain": chain_labels, "hop": i + 1, "hops": len(DELEGATION_CHAIN),
            "delegator": (None if i == 0 else delegator),
            "scope": DEFAULT_SCOPE, "cnf_jkt": jkt, "aud": RS_AUDIENCE,
            "client_id": AGENT_CLIENT_ID,
            "authorization_details": _authorization_details(),
            "token_preview": token[:20] + "…" + token[-12:], "claims": claims,
            "token_header": token_header, "te_request": te_request,
            "te_endpoint": "https://<local-demo-idp>/as/token.oauth2",
            "dpop_example": dpop_example, "mode": "local"})
        prev_subject = f"<delegated token from hop {i + 1}>"

    return AgentCredential(access_token=token, principal_sub=PRINCIPAL_SUB,
                           agent_sub=TASK_AGENT_ID, scope=DEFAULT_SCOPE, jkt=jkt,
                           mode="local", _key=key, steps=steps)


# --------------------------------------------------------------------------
# pingfederate mode: genuine client-credentials + RFC 8693 token exchange
# --------------------------------------------------------------------------

def _discover_token_endpoint() -> str:
    url = OIDC_ISSUER.rstrip("/") + "/.well-known/openid-configuration"
    with httpx.Client(timeout=10.0, verify=False) as c:
        meta = c.get(url).json()
    return meta["token_endpoint"]


def _acquire_pingfederate() -> AgentCredential:
    key = _new_key()
    jkt = _jkt(key)
    pub0 = key.public_key().public_numbers()
    agent_jwk = {"kty": "EC", "crv": "P-256",
                 "x": _int_to_b64url(pub0.x), "y": _int_to_b64url(pub0.y)}
    token_endpoint = _discover_token_endpoint()
    steps: list[dict[str, Any]] = []

    # Client attestation presented as attest_jwt_client_auth_dpop: the
    # OAuth-Client-Attestation header + the DPoP proof (signed by cnf.jwk) replace
    # the client secret at PingFederate's token endpoint. pf-oidf-modules validates
    # it via the OIDF trust chain and enforces requested ⊆ attested.
    attestation = mint_agent_attestation(
        client_id=AGENT_CLIENT_ID, agent_id=AGENT_ID, agent_type=AGENT_TYPE,
        principal_sub=PRINCIPAL_SUB, agent_public_jwk=agent_jwk,
        authorization_details=_authorization_details(), model=AGENT_MODEL)
    steps.append({
        "type": "attestation", "title": "Client attestation",
        "detail": f"Attester '{attestation.attester_issuer}' issued an attestation "
                  f"JWT vouching for the agent's AgentCore attributes and DPoP key; "
                  f"presented to PingFederate as attest_jwt_client_auth_dpop.",
        "attester": attestation.attester_issuer, "client_id": AGENT_CLIENT_ID,
        "agent": AGENT_ID, "agent_type": AGENT_TYPE,
        "auth_method": "attest_jwt_client_auth_dpop", "typ": attestation.header.get("typ"),
        "workload": attestation.claims.get("workload"),
        "attestation_header": attestation.header, "attestation_claims": attestation.claims,
        "attestation_preview": attestation.jwt[:24] + "…" + attestation.jwt[-12:],
        "attester_jwks": attestation.attester_jwks, "mode": "pingfederate"})
    attest_headers = {"OAuth-Client-Attestation": attestation.jwt}

    def dpop_for(method: str, url: str, access_token: str | None = None) -> str:
        payload = {"jti": str(uuid.uuid4()), "htm": method.upper(),
                   "htu": url.split("?")[0], "iat": int(time.time())}
        if access_token:
            payload["ath"] = _b64url(hashlib.sha256(access_token.encode()).digest())
        pub = key.public_key().public_numbers()
        jwk = {"kty": "EC", "crv": "P-256",
               "x": _int_to_b64url(pub.x), "y": _int_to_b64url(pub.y)}
        return jwt.encode(payload, key, algorithm="ES256",
                          headers={"typ": "dpop+jwt", "jwk": jwk})

    with httpx.Client(timeout=15.0, verify=False) as c:
        # 1) Agent Operator authenticates -> actor token (client_credentials, DPoP)
        actor_resp = c.post(token_endpoint, data={
            "grant_type": "client_credentials",
            "client_id": AGENT_CLIENT_ID,
            "client_secret": AGENT_CLIENT_SECRET,
            "scope": "agent",
        }, headers={"DPoP": dpop_for("POST", token_endpoint), **attest_headers})
        actor_resp.raise_for_status()
        actor_token = actor_resp.json()["access_token"]
        steps.append({"type": "auth", "title": "Agent authenticates",
                      "detail": f"client '{AGENT_CLIENT_ID}' obtained an actor "
                                f"token via client_credentials (DPoP).",
                      "client_id": AGENT_CLIENT_ID, "agent": AGENT_ID, "jkt": jkt,
                      "grant": "client_credentials", "mode": "pingfederate",
                      "token_endpoint": token_endpoint})

        # 2) Principal subject token (demo: pre-provisioned or password grant)
        subject_token = os.environ.get("PRINCIPAL_SUBJECT_TOKEN")
        if not subject_token:
            sub_resp = c.post(token_endpoint, data={
                "grant_type": "password",
                "client_id": AGENT_CLIENT_ID,
                "client_secret": AGENT_CLIENT_SECRET,
                "username": os.environ.get("PRINCIPAL_USERNAME", PRINCIPAL_SUB),
                "password": os.environ.get("PRINCIPAL_PASSWORD", ""),
                "scope": "openid",
            })
            sub_resp.raise_for_status()
            subject_token = sub_resp.json()["access_token"]

        # 3) RFC 8693 token exchange: subject (Alice) + actor (agent) -> delegated
        te = c.post(token_endpoint, data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": AGENT_CLIENT_ID,
            "client_secret": AGENT_CLIENT_SECRET,
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "actor_token": actor_token,
            "actor_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": DEFAULT_SCOPE,
            "resource": RS_AUDIENCE,
        }, headers={"DPoP": dpop_for("POST", token_endpoint), **attest_headers})
        te.raise_for_status()
        access_token = te.json()["access_token"]

    decoded = jwt.decode(access_token, options={"verify_signature": False})
    try:
        token_header = jwt.get_unverified_header(access_token)
    except Exception:  # noqa: BLE001
        token_header = {"alg": "?", "typ": "at+jwt"}
    pub = key.public_key().public_numbers()
    dpop_example = {
        "header": {"typ": "dpop+jwt", "alg": "ES256",
                   "jwk": {"kty": "EC", "crv": "P-256",
                           "x": _int_to_b64url(pub.x), "y": _int_to_b64url(pub.y)}},
        "payload": {"jti": str(uuid.uuid4()), "htm": "POST",
                    "htu": "https://<kong-gateway>/mcp", "iat": int(time.time()),
                    "ath": _b64url(hashlib.sha256(access_token.encode()).digest())},
    }
    te_request = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": AGENT_CLIENT_ID,
        "subject_token": "<principal access token — Alice>",
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "actor_token": "<agent actor token>",
        "actor_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "scope": DEFAULT_SCOPE,
        "resource": RS_AUDIENCE,
    }
    steps.append({
        "type": "token_exchange", "title": "Token exchange (RFC 8693)",
        "detail": f"PingFederate issued a delegated token: sub={decoded.get('sub')} "
                  f"act.sub={(decoded.get('act') or {}).get('sub')}.",
        "sub": decoded.get("sub"), "act": (decoded.get("act") or {}).get("sub"),
        "scope": decoded.get("scope"), "cnf_jkt": (decoded.get("cnf") or {}).get("jkt"),
        "aud": decoded.get("aud"), "client_id": decoded.get("client_id") or decoded.get("azp"),
        "authorization_details": decoded.get("authorization_details"),
        "token_preview": access_token[:20] + "…" + access_token[-12:],
        "claims": decoded, "token_header": token_header, "te_request": te_request,
        "te_endpoint": token_endpoint, "dpop_example": dpop_example,
        "mode": "pingfederate"})
    return AgentCredential(
        access_token=access_token, principal_sub=decoded.get("sub", PRINCIPAL_SUB),
        agent_sub=(decoded.get("act") or {}).get("sub", AGENT_ID),
        scope=decoded.get("scope", DEFAULT_SCOPE),
        jkt=(decoded.get("cnf") or {}).get("jkt", jkt), mode="pingfederate",
        _key=key, steps=steps)


def acquire_delegated_token() -> AgentCredential:
    """Obtain a delegated, DPoP-bound access token for the agent to act with."""
    if TOKEN_MODE == "pingfederate":
        logger.info("Acquiring delegated token via PingFederate token exchange")
        return _acquire_pingfederate()
    logger.info("Acquiring delegated token via local demo IdP (TOKEN_MODE=local)")
    return _acquire_local()


# --------------------------------------------------------------------------
# Agent fleet: one Principal Agent (concierge) delegating to TWO task agents
# (Account Agent + Payments Agent), each with its own key, attestation and
# nested actor chain. Used by the demo so the concierge is shown calling two.
# --------------------------------------------------------------------------

def _pub_jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    p = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256",
            "x": _int_to_b64url(p.x), "y": _int_to_b64url(p.y)}


def _attestation_step(att, agent_id: str, agent_type: str, entity_jkt: str,
                      local_jkt: str, role: str | None = None) -> dict[str, Any]:
    step = {
        "type": "attestation", "title": "Client attestation",
        "detail": f"Attester '{att.attester_issuer}' issued an attestation JWT for {agent_id} "
                  f"({agent_type}): it binds the agent's LOCAL DPoP key (cnf.jwk) to its "
                  f"ENTITY key and states its ceiling.",
        "attester": att.attester_issuer, "client_id": AGENT_CLIENT_ID,
        "agent": agent_id, "agent_type": agent_type,
        "entity_jkt": entity_jkt, "local_jkt": local_jkt,
        "auth_method": "attest_jwt_client_auth_dpop", "typ": att.header.get("typ"),
        "workload": att.claims.get("workload"),
        "attestation_header": att.header, "attestation_claims": att.claims,
        "attestation_preview": att.jwt[:24] + "…" + att.jwt[-12:],
        "attester_jwks": att.attester_jwks, "mode": "local",
    }
    if role:
        step["role"] = role
    return step


def _auth_step(agent_id: str, entity_jkt: str, local_jkt: str, role: str | None = None) -> dict[str, Any]:
    step = {
        "type": "auth", "title": "Agent authenticates",
        "detail": f"{agent_id} authenticated with its attestation (attest_jwt_client_auth_dpop): "
                  f"its stable entity key identifies it, and a fresh local DPoP key sender-"
                  f"constrains this session — no client secret.",
        "client_id": AGENT_CLIENT_ID, "agent": agent_id,
        "jkt": local_jkt, "entity_jkt": entity_jkt, "local_jkt": local_jkt,
        "grant": "client_credentials", "auth_method": "attest_jwt_client_auth_dpop", "mode": "local",
    }
    if role:
        step["role"] = role
    return step


def _mint_token(signing_key, header, act, jkt, now) -> tuple[str, dict[str, Any]]:
    claims = {
        "iss": "https://local-demo-idp.northwind.example", "sub": PRINCIPAL_SUB,
        "act": act, "aud": RS_AUDIENCE, "client_id": AGENT_CLIENT_ID, "azp": AGENT_CLIENT_ID,
        "scope": DEFAULT_SCOPE, "authorization_details": _authorization_details(),
        "cnf": {"jkt": jkt}, "iat": now, "exp": now + TOKEN_TTL,
    }
    return jwt.encode(claims, signing_key, algorithm="ES256", headers=header), claims


def _te_step(*, actor, delegator, hop, hops, token, claims, jkt, jwk, now,
             title, subject_desc, role=None, label=None) -> dict[str, Any]:
    act = claims["act"]
    chain_labels = _actor_chain_labels(act)
    ath = _b64url(hashlib.sha256(token.encode()).digest())
    te_request = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": subject_desc,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "actor_token": f"<actor token — {actor}>",
        "actor_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "scope": DEFAULT_SCOPE, "resource": RS_AUDIENCE,
    }
    dpop_example = {
        "header": {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk},
        "payload": {"jti": str(uuid.uuid4()), "htm": "POST",
                    "htu": "https://<kong-gateway>/mcp", "iat": now, "ath": ath},
    }
    step = {
        "type": "token_exchange", "title": title,
        "detail": f"{delegator} delegates to {actor}: the exchanged token now carries "
                  f"act = {' ◀ '.join(chain_labels)} under sub={PRINCIPAL_SUB} — "
                  f"delegation, not impersonation.",
        "sub": PRINCIPAL_SUB, "act": act, "act_sub": (act or {}).get("sub"),
        "actor_chain": chain_labels, "hop": hop, "hops": hops,
        "delegator": (None if hop == 1 else delegator),
        "scope": DEFAULT_SCOPE, "cnf_jkt": jkt, "aud": RS_AUDIENCE, "client_id": AGENT_CLIENT_ID,
        "authorization_details": _authorization_details(),
        "token_preview": token[:20] + "…" + token[-12:], "claims": claims,
        "token_header": {"alg": "ES256", "typ": "JWT"}, "te_request": te_request,
        "te_endpoint": "https://<local-demo-idp>/as/token.oauth2",
        "dpop_example": dpop_example, "mode": "local",
    }
    if role:
        step["role"] = role
    if label:
        step["agent_label"] = label
    return step


@dataclass
class AgentFleet:
    """The concierge + its task agents: per-role credentials, the tool→role map,
    and the combined identity transcript steps to display."""
    roles: dict[str, AgentCredential]
    tool_role: dict[str, str]
    role_label: dict[str, str]
    steps: list[dict[str, Any]]


def acquire_agent_fleet() -> AgentFleet:
    """Provision the Principal Agent (concierge) and both task agents.

    The concierge is attested and takes Alice's delegation (hop 1); it then
    delegates to the Account Agent and the Payments Agent, each getting its own
    key, attestation and a token whose nested `act` chain is
    {task-agent, act={concierge}}. Tools are routed to the owning agent.
    """
    now = int(time.time())
    signing_key = _new_key()          # throwaway demo IdP signing key
    header = {"alg": "ES256", "typ": "JWT"}
    steps: list[dict[str, Any]] = []

    # Each agent has its OWN entity key (stable federation identity) AND a fresh
    # local DPoP key (ephemeral, sender-constrains the session); the attester binds
    # the local key to the entity in the attestation.
    # Principal Agent (concierge): entity + local keys, attestation, Alice → concierge.
    conc_entity = _new_key(); conc_entity_jkt = _jkt(conc_entity)
    conc_key = _new_key(); conc_jkt = _jkt(conc_key); conc_jwk = _pub_jwk(conc_key)
    conc_att = mint_agent_attestation(
        client_id=AGENT_CLIENT_ID, agent_id=PRINCIPAL_AGENT_ID, agent_type="orchestrator",
        principal_sub=PRINCIPAL_SUB, agent_public_jwk=conc_jwk,
        authorization_details=_authorization_details(), model=AGENT_MODEL,
        entity_key_thumbprint=conc_entity_jkt)
    steps.append(_attestation_step(conc_att, PRINCIPAL_AGENT_ID, "orchestrator",
                                   conc_entity_jkt, conc_jkt, role="principal"))
    steps.append(_auth_step(PRINCIPAL_AGENT_ID, conc_entity_jkt, conc_jkt, role="principal"))
    act1 = _build_act_chain([PRINCIPAL_AGENT_ID])
    tok1, claims1 = _mint_token(signing_key, header, act1, conc_jkt, now)
    steps.append(_te_step(actor=PRINCIPAL_AGENT_ID, delegator=PRINCIPAL_SUB, hop=1, hops=2,
                          token=tok1, claims=claims1, jkt=conc_jkt, jwk=conc_jwk, now=now,
                          role="principal", title="Alice → Principal Agent (token exchange @ AS)",
                          subject_desc="<principal access token — Alice>"))

    # Each task agent: the Principal Agent calls the AS to exchange its token for a
    # task-agent-scoped delegated token (nested act). Each task agent has its own
    # entity + local keys and attestation → its own credential.
    roles: dict[str, AgentCredential] = {}
    tool_role_map: dict[str, str] = {}
    role_label: dict[str, str] = {}
    for cfg in TASK_AGENTS:
        entity = _new_key(); entity_jkt = _jkt(entity)
        key = _new_key(); jkt = _jkt(key); jwk = _pub_jwk(key)
        att = mint_agent_attestation(
            client_id=AGENT_CLIENT_ID, agent_id=cfg["id"], agent_type=cfg["type"],
            principal_sub=PRINCIPAL_SUB, agent_public_jwk=jwk,
            authorization_details=_authorization_details(), model=AGENT_MODEL,
            entity_key_thumbprint=entity_jkt)
        steps.append(_attestation_step(att, cfg["id"], cfg["type"], entity_jkt, jkt, role=cfg["role"]))
        act = _build_act_chain([PRINCIPAL_AGENT_ID, cfg["id"]])
        tok, claims = _mint_token(signing_key, header, act, jkt, now)
        steps.append(_te_step(actor=cfg["id"], delegator=PRINCIPAL_AGENT_ID, hop=2, hops=2,
                              token=tok, claims=claims, jkt=jkt, jwk=jwk, now=now,
                              role=cfg["role"], label=cfg["label"],
                              title=f"Principal Agent exchanges @ AS → {cfg['label']} token",
                              subject_desc="<Principal Agent's delegated token (hop 1)>"))
        roles[cfg["role"]] = AgentCredential(
            access_token=tok, principal_sub=PRINCIPAL_SUB, agent_sub=cfg["id"],
            scope=DEFAULT_SCOPE, jkt=jkt, mode="local", _key=key, steps=[])
        role_label[cfg["role"]] = cfg["label"]
        for t in cfg["tools"]:
            tool_role_map[t] = cfg["role"]

    return AgentFleet(roles=roles, tool_role=tool_role_map, role_label=role_label, steps=steps)


@dataclass
class PrincipalCredential:
    """The Principal Agent (concierge)'s own identity: its delegated token (used
    as the A2A bearer to invoke task agents) plus the transcript steps."""
    token: str
    steps: list[dict[str, Any]]


def acquire_principal_credential() -> PrincipalCredential:
    """Establish ONLY the concierge's authority: attestation + the Alice →
    Principal Agent token exchange at the AS. The concierge presents this token to
    the task agents over A2A; each task agent then exchanges it for its own."""
    now = int(time.time())
    signing_key = _new_key()
    header = {"alg": "ES256", "typ": "JWT"}
    entity = _new_key(); entity_jkt = _jkt(entity)
    key = _new_key(); jkt = _jkt(key); jwk = _pub_jwk(key)
    att = mint_agent_attestation(
        client_id=AGENT_CLIENT_ID, agent_id=PRINCIPAL_AGENT_ID, agent_type="orchestrator",
        principal_sub=PRINCIPAL_SUB, agent_public_jwk=jwk,
        authorization_details=_authorization_details(), model=AGENT_MODEL,
        entity_key_thumbprint=entity_jkt)
    steps = [
        _attestation_step(att, PRINCIPAL_AGENT_ID, "orchestrator", entity_jkt, jkt, role="principal"),
        _auth_step(PRINCIPAL_AGENT_ID, entity_jkt, jkt, role="principal"),
    ]
    act = _build_act_chain([PRINCIPAL_AGENT_ID])
    tok, claims = _mint_token(signing_key, header, act, jkt, now)
    steps.append(_te_step(actor=PRINCIPAL_AGENT_ID, delegator=PRINCIPAL_SUB, hop=1, hops=1,
                          token=tok, claims=claims, jkt=jkt, jwk=jwk, now=now, role="principal",
                          title="Alice → Principal Agent (token exchange @ AS)",
                          subject_desc="<principal access token — Alice>"))
    return PrincipalCredential(token=tok, steps=steps)
