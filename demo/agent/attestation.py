"""
Client attestation for the AgentCore agent — OAuth 2.0 Attestation-Based Client
Authentication (draft-ietf-oauth-attestation-based-client-auth).

Instead of authenticating with a shared client secret, the agent presents a
signed **Attestation JWT** issued by a trusted *attester*. The attestation binds,
in one verifiable object:

  * the agent's identity and **AgentCore attributes** — carried in the `workload`
    claim (agent id, type, runtime, environment, instance, the principal it acts
    for, the model it runs);
  * the agent's **DPoP instance key** — `cnf.jwk` — so the very key that
    sender-constrains every request is the key the attestation vouches for;
  * the **authority ceiling** the agent may request — `authorization_details`
    (RFC 9396).

PingFederate with the `pf-oidf-modules` plugin validates this attestation against
an OpenID Federation trust chain and enforces `requested ⊆ attested`. This module
mints attestations shaped EXACTLY as that verifier expects
(`com.pingidentity.ps.oidf.common.ClientAttestation`):

    header.typ = "oauth-client-attestation+jwt"
    claims     = { iss, sub(=client_id), iat, exp, cnf:{jwk}, workload{…},
                   authorization_details[…] }

For `attest_jwt_client_auth_dpop`, the attestation travels in the
`OAuth-Client-Attestation` header and the DPoP proof (signed by `cnf.jwk`)
doubles as the proof of possession — so no separate PoP header is needed.

Trust: in a full deployment the attester publishes an OpenID Federation entity
statement at `<iss>/.well-known/openid-federation` whose chain reaches a trust
anchor PingFederate trusts (`FederationAttesterKeyResolver`). Here we also expose
the attester's public JWK set so that entity statement can be generated later.
"""
from __future__ import annotations

import base64
import os
import platform
import time
import uuid
from dataclasses import dataclass
from typing import Any

import jwt  # PyJWT
from cryptography.hazmat.primitives.asymmetric import ec

# The exact media type the pf-oidf-modules verifier requires on the attestation
# JWT header (ClientAttestationVerifier.ATTESTATION_TYP).
ATTESTATION_TYP = "oauth-client-attestation+jwt"

# --- attester identity ---------------------------------------------------------
# In a real deployment this is a distinct, OIDF-trusted entity. For the demo the
# attester issuer defaults to a stable URL; its signing key is loaded from env if
# provided, else generated per-process (and its public JWK exposed for the UI /
# for building the OIDF entity statement later).
ATTESTER_ISSUER = os.environ.get("ATTESTER_ISSUER", "https://attester.northwind.example")
ATTESTATION_TTL = int(os.environ.get("ATTESTATION_TTL", "300"))
AGENT_VERSION = os.environ.get("AGENT_VERSION", "1.0.0")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _int_to_b64url(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return _b64url(n.to_bytes(length, "big"))


def _public_jwk(key: ec.EllipticCurvePrivateKey, *, kid: str | None = None) -> dict[str, str]:
    nums = key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _int_to_b64url(nums.x),
        "y": _int_to_b64url(nums.y),
    }
    if kid:
        jwk["kid"] = kid
    return jwk


def _load_attester_key() -> ec.EllipticCurvePrivateKey:
    pem = os.environ.get("ATTESTER_PRIVATE_KEY_PEM")
    if pem:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        return load_pem_private_key(pem.encode(), password=None)  # type: ignore[return-value]
    return ec.generate_private_key(ec.SECP256R1())


# The attester's signing key is process-stable so every attestation this instance
# issues is verifiable against one published JWK set.
_ATTESTER_KEY = _load_attester_key()
_ATTESTER_KID = "attester-" + _b64url(os.urandom(6))


def attester_jwks() -> dict[str, Any]:
    """The attester's public JWK Set — what an OIDF entity statement would publish
    under `metadata.oauth_client_attester.jwks` for PingFederate to resolve."""
    return {"keys": [_public_jwk(_ATTESTER_KEY, kid=_ATTESTER_KID)]}


def _agentcore_workload(*, agent_id: str, agent_type: str, principal_sub: str,
                        instance_id: str, model: str | None,
                        entity_key_thumbprint: str | None = None) -> dict[str, Any]:
    """Assemble the `workload` claim from the AgentCore agent's attributes.

    These are the attributes an attester vouches for about the running agent —
    picked up from the AgentCore runtime environment and the agent's config.
    """
    workload: dict[str, Any] = {
        # agent identity + classification
        "software_id": agent_id,
        "software_version": AGENT_VERSION,
        "agent_type": agent_type,
        # the agent's stable ENTITY key (its federation identity), distinct from
        # the ephemeral local/DPoP key that cnf.jwk binds below.
        **({"entity_key_thumbprint": entity_key_thumbprint} if entity_key_thumbprint else {}),
        # runtime / deployment context (AgentCore runtime attributes)
        "environment": os.environ.get("RAILWAY_ENVIRONMENT_NAME")
        or os.environ.get("ENVIRONMENT", "production"),
        "runtime": f"python/{platform.python_version()}",
        "instance_id": instance_id,
        "host": os.environ.get("RAILWAY_REPLICA_ID")
        or os.environ.get("HOSTNAME") or platform.node(),
        # who the agent is acting for (delegation context)
        "on_behalf_of": principal_sub,
    }
    if model:
        workload["model"] = model
    git = os.environ.get("RAILWAY_GIT_COMMIT_SHA")
    if git:
        workload["git_commit"] = git[:12]
    return workload


@dataclass
class Attestation:
    """A minted client-attestation JWT plus the material to display/verify it."""
    jwt: str
    claims: dict[str, Any]
    header: dict[str, Any]
    attester_issuer: str
    attester_jwks: dict[str, Any]

    def header_name(self) -> str:
        return "OAuth-Client-Attestation"


def mint_agent_attestation(*, client_id: str, agent_id: str, agent_type: str,
                           principal_sub: str, agent_public_jwk: dict[str, Any],
                           authorization_details: list[dict[str, Any]],
                           instance_id: str | None = None,
                           model: str | None = None,
                           entity_key_thumbprint: str | None = None) -> Attestation:
    """Issue an Attestation JWT for the agent, shaped as pf-oidf-modules validates.

    `agent_public_jwk` MUST be the agent's LOCAL DPoP instance key — it becomes
    `cnf.jwk`, so the DPoP proof (signed by that key) proves possession.
    `entity_key_thumbprint` is the agent's stable ENTITY key (its federation
    identity), recorded in the workload. `authorization_details` is the RFC 9396
    ceiling the attester entitles.
    """
    now = int(time.time())
    instance_id = instance_id or str(uuid.uuid4())
    claims: dict[str, Any] = {
        "iss": ATTESTER_ISSUER,                 # the trusted attester
        "sub": client_id,                       # the agent client_id (== request client_id)
        "iat": now,
        "exp": now + ATTESTATION_TTL,
        "cnf": {"jwk": agent_public_jwk},       # binds the agent's LOCAL/DPoP key
        "workload": _agentcore_workload(
            agent_id=agent_id, agent_type=agent_type, principal_sub=principal_sub,
            instance_id=instance_id, model=model, entity_key_thumbprint=entity_key_thumbprint),
        "authorization_details": authorization_details,  # the attested ceiling
    }
    header = {"alg": "ES256", "typ": ATTESTATION_TYP, "kid": _ATTESTER_KID}
    token = jwt.encode(claims, _ATTESTER_KEY, algorithm="ES256", headers=header)
    return Attestation(jwt=token, claims=claims, header=header,
                       attester_issuer=ATTESTER_ISSUER, attester_jwks=attester_jwks())
