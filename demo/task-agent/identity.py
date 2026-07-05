"""
Identity for a Task Agent running as its own service.

When the Principal Agent (concierge) invokes this task agent over A2A, the task
agent establishes its OWN authority to call the bank:

  * its own ENTITY key (stable federation identity) + a fresh LOCAL DPoP key,
    with a client attestation binding the local key (attest_jwt_client_auth_dpop);
  * a delegated, DPoP-bound access token obtained by RFC 8693 token exchange —
    subject = the concierge's delegated token, actor = this task agent — so the
    token's nested `act` chain records {this-agent, act={concierge}} under
    sub=Alice (delegation, not impersonation), extending the chain the concierge
    started.

In "local" mode the equivalently-shaped token is self-issued (no live AS), so the
wire format (claims, act chain, cnf.jkt, DPoP) is identical to the real flow.
"""
from __future__ import annotations

import base64
import hashlib
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Generator

import httpx
import jwt  # PyJWT
from cryptography.hazmat.primitives.asymmetric import ec

from attestation import mint_agent_attestation

PRINCIPAL_SUB = os.environ.get("PRINCIPAL_SUB", "cust-alice")
PRINCIPAL_AGENT_ID = os.environ.get("PRINCIPAL_AGENT_ID", "urn:agent:northwind-concierge:v1")
AGENT_CLIENT_ID = os.environ.get("AGENT_CLIENT_ID", "bank-agent")
AGENT_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5")
# The MCP resource this agent calls — the token it mints is audience-scoped to it.
RS_AUDIENCE = os.environ.get("RS_AUDIENCE", "https://api.northwind.example/bank")
MCP_RESOURCE = os.environ.get("MCP_RESOURCE", "https://mcp.northwind.example/bank")
DEFAULT_SCOPE = os.environ.get(
    "AGENT_SCOPE", "bank:accounts.read bank:accounts.write bank:payments.initiate")
RAR_TYPE = os.environ.get(
    "RAR_TYPE", "https://schemas.idpartners.com.au/agentic/payment_initiation/v1")
TOKEN_TTL = int(os.environ.get("TOKEN_TTL", "900"))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_to_b64url(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return _b64url(n.to_bytes(length, "big"))


def _new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _pub_jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    p = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": _int_to_b64url(p.x), "y": _int_to_b64url(p.y)}


def _jkt(key: ec.EllipticCurvePrivateKey) -> str:
    p = key.public_key().public_numbers()
    canon = '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' % (
        _int_to_b64url(p.x), _int_to_b64url(p.y))
    return _b64url(hashlib.sha256(canon.encode()).digest())


def _build_act_chain(actor_subs: list[str]) -> dict[str, Any]:
    """Nest an RFC 8693 act claim; current actor outermost."""
    act: dict[str, Any] | None = None
    for sub in actor_subs:
        act = {"sub": sub, **({"act": act} if act else {})}
    return act or {}


def _actor_chain_labels(act: dict[str, Any]) -> list[str]:
    labels: list[str] = []
    node: dict[str, Any] | None = act
    while node and node.get("sub"):
        labels.append(node["sub"])
        node = node.get("act")
    return labels


def _authorization_details() -> list[dict[str, Any]]:
    return [{"type": RAR_TYPE, "actions": ["initiate"],
             "locations": [RS_AUDIENCE], "instructedAmount": {"currency": "AUD"}}]


@dataclass
class Credential:
    access_token: str
    principal_sub: str
    agent_sub: str
    jkt: str
    _key: ec.EllipticCurvePrivateKey
    steps: list[dict[str, Any]] = field(default_factory=list)

    def public_jwk(self) -> dict[str, str]:
        return _pub_jwk(self._key)

    def _dpop_proof(self, method: str, url: str) -> str:
        ath = _b64url(hashlib.sha256(self.access_token.encode()).digest())
        payload = {"jti": str(uuid.uuid4()), "htm": method.upper(),
                   "htu": url.split("?")[0], "iat": int(time.time()), "ath": ath}
        return jwt.encode(payload, self._key, algorithm="ES256",
                          headers={"typ": "dpop+jwt", "jwk": self.public_jwk()})

    def httpx_auth(self) -> "DPoPAuth":
        return DPoPAuth(self)


class DPoPAuth(httpx.Auth):
    requires_request_body = False

    def __init__(self, cred: Credential) -> None:
        self._cred = cred

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers["Authorization"] = f"DPoP {self._cred.access_token}"
        request.headers["DPoP"] = self._cred._dpop_proof(request.method, str(request.url))
        yield request


def establish_identity(*, agent_id: str, agent_type: str, agent_label: str,
                       role: str, mcp_url: str) -> Credential:
    """Mint this task agent's identity + its delegated, DPoP-bound token.

    The token's `act` chain nests this agent over the concierge; its audience is
    the MCP resource this agent calls. Returns a Credential plus the transcript
    steps (attestation, authenticate, token exchange) for the UI.
    """
    now = int(time.time())
    entity = _new_key(); entity_jkt = _jkt(entity)
    local = _new_key(); local_jkt = _jkt(local); local_jwk = _pub_jwk(local)

    att = mint_agent_attestation(
        client_id=AGENT_CLIENT_ID, agent_id=agent_id, agent_type=agent_type,
        principal_sub=PRINCIPAL_SUB, agent_public_jwk=local_jwk,
        authorization_details=_authorization_details(), model=AGENT_MODEL,
        entity_key_thumbprint=entity_jkt)

    act = _build_act_chain([PRINCIPAL_AGENT_ID, agent_id])
    claims = {
        "iss": "https://local-demo-idp.northwind.example", "sub": PRINCIPAL_SUB,
        "act": act, "aud": MCP_RESOURCE, "client_id": AGENT_CLIENT_ID, "azp": AGENT_CLIENT_ID,
        "scope": DEFAULT_SCOPE, "authorization_details": _authorization_details(),
        "cnf": {"jkt": local_jkt}, "iat": now, "exp": now + TOKEN_TTL,
    }
    token = jwt.encode(claims, _new_key(), algorithm="ES256", headers={"alg": "ES256", "typ": "JWT"})
    chain_labels = _actor_chain_labels(act)

    steps = [
        {"type": "attestation", "title": "Client attestation",
         "detail": f"Attester '{att.attester_issuer}' issued an attestation JWT for {agent_id} "
                   f"({agent_type}), binding its LOCAL DPoP key to its ENTITY key.",
         "attester": att.attester_issuer, "client_id": AGENT_CLIENT_ID, "agent": agent_id,
         "agent_type": agent_type, "entity_jkt": entity_jkt, "local_jkt": local_jkt,
         "auth_method": "attest_jwt_client_auth_dpop", "typ": att.header.get("typ"),
         "workload": att.claims.get("workload"), "attestation_header": att.header,
         "attestation_claims": att.claims, "attestation_preview": att.jwt[:24] + "…" + att.jwt[-12:],
         "attester_jwks": att.attester_jwks, "role": role, "mode": "local"},
        {"type": "auth", "title": "Agent authenticates",
         "detail": f"{agent_id} authenticated with its attestation (attest_jwt_client_auth_dpop): "
                   f"stable entity key + fresh local DPoP key, no secret.",
         "client_id": AGENT_CLIENT_ID, "agent": agent_id, "jkt": local_jkt,
         "entity_jkt": entity_jkt, "local_jkt": local_jkt, "grant": "client_credentials",
         "auth_method": "attest_jwt_client_auth_dpop", "role": role, "mode": "local"},
        {"type": "token_exchange",
         "title": f"Token exchange @ AS → {agent_label} token (aud=MCP)",
         "detail": f"{PRINCIPAL_AGENT_ID} delegates to {agent_id}: the exchanged token carries "
                   f"act = {' ◀ '.join(chain_labels)} under sub={PRINCIPAL_SUB}, "
                   f"audience-scoped to the MCP resource — delegation, not impersonation.",
         "sub": PRINCIPAL_SUB, "act": act, "act_sub": (act or {}).get("sub"),
         "actor_chain": chain_labels, "hop": 2, "hops": 2, "delegator": PRINCIPAL_AGENT_ID,
         "scope": DEFAULT_SCOPE, "cnf_jkt": local_jkt, "aud": MCP_RESOURCE,
         "client_id": AGENT_CLIENT_ID, "authorization_details": _authorization_details(),
         "token_preview": token[:20] + "…" + token[-12:], "claims": claims,
         "token_header": {"alg": "ES256", "typ": "JWT"},
         "te_request": {
             "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
             "subject_token": "<concierge's delegated token (from A2A)>",
             "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
             "actor_token": f"<actor token — {agent_id}>",
             "actor_token_type": "urn:ietf:params:oauth:token-type:access_token",
             "resource": MCP_RESOURCE, "scope": DEFAULT_SCOPE},
         "te_endpoint": "https://<local-demo-idp>/as/token.oauth2",
         "role": role, "agent_label": agent_label, "mode": "local"},
    ]
    return Credential(access_token=token, principal_sub=PRINCIPAL_SUB, agent_sub=agent_id,
                      jkt=local_jkt, _key=local, steps=steps)
