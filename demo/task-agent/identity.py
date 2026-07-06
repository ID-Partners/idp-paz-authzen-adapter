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
import json
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
# "pingfederate" mode: get a REAL delegated token from PingFederate — the attester
# service signs the attestation, PF validates it and issues the token. "local"
# (default) self-issues an equivalently-shaped token.
TOKEN_MODE = os.environ.get("TOKEN_MODE", "local").lower()
ATTESTER_URL = os.environ.get("ATTESTER_URL", "http://attester.railway.internal:8110")
PF_TOKEN_URL = os.environ.get("PF_TOKEN_URL", "")
PF_CLIENT_SECRET = os.environ.get("PF_CLIENT_SECRET", "demo-secret-123")
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
    # The delegated actor chain [current actor, …, earliest delegator] as read
    # from the token's nested `act` — so downstream steps can show the whole
    # chain the gateway/PEP actually receives, not just the current actor.
    actor_chain: list[str] = field(default_factory=list)

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


def _establish_pf(*, agent_id: str, agent_type: str, agent_label: str, role: str,
                  user_token: str | None = None) -> Credential:
    """Get a REAL delegated token from PingFederate: the attester service signs an
    attestation binding this agent's DPoP key, then PF (as this agent's own OAuth
    client) validates it and issues the token.

    With `user_token` (Alice's PF login token), this is a real RFC 8693 TOKEN
    EXCHANGE: her token is the subject_token, PF validates it and derives the
    issued token's sub from HER authenticated identity. Without it, fall back to
    client_credentials (static sub)."""
    now = int(time.time())
    local = _new_key(); local_jkt = _jkt(local); local_jwk = _pub_jwk(local)
    workload = {"software_id": agent_id, "agent_type": agent_type,
                "on_behalf_of": PRINCIPAL_SUB,
                "environment": os.environ.get("RAILWAY_ENVIRONMENT_NAME", "production")}
    ad = _authorization_details()
    with httpx.Client(timeout=20.0, verify=False) as c:
        # 1) Attester service signs the attestation (its key never leaves it).
        ar = c.post(ATTESTER_URL.rstrip("/") + "/attest",
                    json={"client_id": agent_id, "cnf": local_jwk,
                          "workload": workload, "authorization_details": ad})
        ar.raise_for_status()
        att = ar.json()
        attestation = att["attestation"]
        # 2) Present the attestation + a DPoP proof to PingFederate's token endpoint.
        dpop = jwt.encode({"htm": "POST", "htu": PF_TOKEN_URL,
                           "jti": str(uuid.uuid4()), "iat": now},
                          local, algorithm="ES256",
                          headers={"typ": "dpop+jwt", "jwk": local_jwk})
        if user_token:
            grant = "urn:ietf:params:oauth:grant-type:token-exchange"
            data = {"grant_type": grant,
                    "subject_token": user_token,
                    "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "client_id": agent_id, "client_secret": PF_CLIENT_SECRET}
        else:
            grant = "client_credentials"
            data = {"grant_type": grant, "client_id": agent_id,
                    "client_secret": PF_CLIENT_SECRET}
        tr = c.post(PF_TOKEN_URL, data=data,
                    headers={"OAuth-Client-Attestation": attestation, "DPoP": dpop})
        tr.raise_for_status()
        token = tr.json()["access_token"]

    claims = jwt.decode(token, options={"verify_signature": False})
    act = claims.get("act")
    if isinstance(act, str):
        try:
            act = json.loads(act)
        except Exception:  # noqa: BLE001
            act = {"sub": act}
    chain_labels = _actor_chain_labels(act) if isinstance(act, dict) else [agent_id]
    tp = token[:20] + "…" + token[-12:]
    steps = [
        {"type": "attestation", "title": "Client attestation (signed by the attester service)",
         "detail": f"Attester '{att.get('attester_issuer')}' signed an attestation JWT for "
                   f"{agent_id}, binding its DPoP key (cnf) — the private key stays in the attester.",
         "attester": att.get("attester_issuer"), "client_id": agent_id, "agent": agent_id,
         "agent_type": agent_type, "local_jkt": local_jkt,
         "auth_method": "attest_jwt_client_auth_dpop", "typ": (att.get("header") or {}).get("typ"),
         "workload": (att.get("claims") or {}).get("workload"),
         "attestation_header": att.get("header"), "attestation_claims": att.get("claims"),
         "attestation_preview": attestation[:24] + "…" + attestation[-12:],
         "attester_jwks": att.get("attester_jwks"), "role": role, "mode": "pingfederate"},
        {"type": "auth", "title": "Agent authenticates to PingFederate",
         "detail": f"{agent_id} authenticated to PingFederate as its own OAuth client using the "
                   f"attestation (attest_jwt_client_auth_dpop) — no client secret exposed to the model.",
         "client_id": agent_id, "agent": agent_id, "jkt": local_jkt, "local_jkt": local_jkt,
         "grant": grant, "auth_method": "attest_jwt_client_auth_dpop",
         "role": role, "mode": "pingfederate"},
        {"type": "token_exchange",
         "title": (f"Token exchange (RFC 8693) @ PingFederate → {agent_label} token"
                   if user_token else f"PingFederate issued {agent_label}'s delegated token"),
         "detail": (f"REAL RFC 8693 exchange: {agent_id} presented Alice's login token as the "
                    f"subject_token; PingFederate VALIDATED it and derived sub={claims.get('sub')} from her "
                    f"authenticated identity, act = {' ◀ '.join(chain_labels)} — delegation, not impersonation."
                    if user_token else
                    f"PingFederate validated the attestation and issued a REAL delegated token: "
                    f"sub={claims.get('sub')}, act = {' ◀ '.join(chain_labels)} — delegation, not impersonation."),
         "sub": claims.get("sub"), "act": act, "act_sub": (act or {}).get("sub") if isinstance(act, dict) else act,
         "actor_chain": chain_labels, "hop": 2, "hops": 2, "delegator": PRINCIPAL_AGENT_ID,
         "scope": claims.get("scope"), "cnf_jkt": (claims.get("cnf") or {}).get("jkt"),
         "aud": claims.get("aud"), "client_id": claims.get("client_id"),
         "authorization_details": claims.get("authorization_details"),
         "grant": grant,
         "subject_token_preview": (user_token[:20] + "…" + user_token[-12:]) if user_token else None,
         "te_request": ({"grant_type": grant,
                         "subject_token": "<Alice's PF login token>",
                         "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                         "client_id": agent_id} if user_token else None),
         "token_preview": tp, "claims": claims, "token_header": jwt.get_unverified_header(token),
         "te_endpoint": PF_TOKEN_URL, "role": role, "agent_label": agent_label, "mode": "pingfederate"},
    ]
    return Credential(access_token=token, principal_sub=claims.get("sub", PRINCIPAL_SUB),
                      agent_sub=agent_id, jkt=local_jkt, _key=local, steps=steps,
                      actor_chain=chain_labels)


def establish_identity(*, agent_id: str, agent_type: str, agent_label: str,
                       role: str, mcp_url: str, user_token: str | None = None) -> Credential:
    """Mint this task agent's identity + its delegated, DPoP-bound token.

    In pingfederate mode, get a REAL token from PF via the attester — an RFC 8693
    token exchange when Alice's login token is available; otherwise self-issue an
    equivalently-shaped token. Returns a Credential + transcript steps.
    """
    if TOKEN_MODE == "pingfederate" and PF_TOKEN_URL:
        return _establish_pf(agent_id=agent_id, agent_type=agent_type,
                             agent_label=agent_label, role=role, user_token=user_token)
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
                      jkt=local_jkt, _key=local, steps=steps, actor_chain=chain_labels)
