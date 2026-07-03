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
    claims = {
        "iss": "https://local-demo-idp.northwind.example",
        "sub": PRINCIPAL_SUB,                 # the human principal
        "act": {"sub": AGENT_ID},             # the acting agent — DELEGATION
        "aud": RS_AUDIENCE,
        "client_id": AGENT_CLIENT_ID,         # the Agent Operator
        "azp": AGENT_CLIENT_ID,
        "scope": DEFAULT_SCOPE,
        "authorization_details": _authorization_details(),
        "cnf": {"jkt": jkt},                  # DPoP sender-constraint
        "iat": now,
        "exp": now + TOKEN_TTL,
    }
    # a throwaway signing key for the demo IdP (token signature is not verified
    # by the PDP plugin; the point here is the claim shape + DPoP binding)
    signing_key = _new_key()
    token_header = {"alg": "ES256", "typ": "JWT"}
    token = jwt.encode(claims, signing_key, algorithm="ES256", headers=token_header)

    token_preview = token[:20] + "…" + token[-12:]
    pub = key.public_key().public_numbers()
    public_jwk = {"kty": "EC", "crv": "P-256",
                  "x": _int_to_b64url(pub.x), "y": _int_to_b64url(pub.y)}

    # Client attestation: a trusted attester vouches for the agent's AgentCore
    # attributes (workload) and binds the agent's DPoP key (cnf.jwk == public_jwk),
    # ceilinged by authorization_details. This is what the agent presents to the
    # AS as `attest_jwt_client_auth_dpop` instead of a client secret.
    attestation = mint_agent_attestation(
        client_id=AGENT_CLIENT_ID, agent_id=AGENT_ID, agent_type=AGENT_TYPE,
        principal_sub=PRINCIPAL_SUB, agent_public_jwk=public_jwk,
        authorization_details=_authorization_details(), model=AGENT_MODEL)

    ath = _b64url(hashlib.sha256(token.encode()).digest())
    dpop_example = {
        "header": {"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk},
        "payload": {"jti": str(uuid.uuid4()), "htm": "POST",
                    "htu": "https://<kong-gateway>/mcp", "iat": now, "ath": ath},
    }
    te_request = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": "<principal access token — Alice>",
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "actor_token": "<agent actor token>",
        "actor_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "scope": DEFAULT_SCOPE,
        "resource": RS_AUDIENCE,
    }
    steps = [
        {"type": "attestation", "title": "Client attestation",
         "detail": f"Attester '{attestation.attester_issuer}' issued an attestation "
                   f"JWT vouching for the agent's identity and AgentCore attributes, "
                   f"binding its DPoP key (cnf.jwk) and authority ceiling.",
         "attester": attestation.attester_issuer, "client_id": AGENT_CLIENT_ID,
         "agent": AGENT_ID, "agent_type": AGENT_TYPE,
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
         "client_id": AGENT_CLIENT_ID, "agent": AGENT_ID, "jkt": jkt,
         "grant": "client_credentials", "auth_method": "attest_jwt_client_auth_dpop",
         "mode": "local"},
        {"type": "token_exchange", "title": "Token exchange (RFC 8693)",
         "detail": f"Delegated token issued: sub={PRINCIPAL_SUB} "
                   f"act.sub={AGENT_ID} (delegation, not impersonation).",
         "sub": PRINCIPAL_SUB, "act": AGENT_ID, "scope": DEFAULT_SCOPE,
         "cnf_jkt": jkt, "aud": RS_AUDIENCE, "client_id": AGENT_CLIENT_ID,
         "authorization_details": _authorization_details(),
         "token_preview": token_preview, "claims": claims,
         "token_header": token_header, "te_request": te_request,
         "te_endpoint": "https://<local-demo-idp>/as/token.oauth2",
         "dpop_example": dpop_example, "mode": "local"},
    ]
    return AgentCredential(access_token=token, principal_sub=PRINCIPAL_SUB,
                           agent_sub=AGENT_ID, scope=DEFAULT_SCOPE, jkt=jkt,
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
