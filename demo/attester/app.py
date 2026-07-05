"""
Attester — a signing service (key store) for client attestations.

The private attestation-signing key lives ONLY here, never in the agents. When an
agent needs to authenticate to PingFederate, it asks this service to mint a client
attestation (OAuth 2.0 Attestation-Based Client Authentication) binding the
agent's own DPoP key. PingFederate trusts this attester (its public key is
pre-trusted in PF's mock-attesters file; a real deployment would trust it through
an OpenID Federation trust chain — see /.well-known/openid-federation).

  POST /attest          {client_id, cnf, workload?, authorization_details?}
                        -> {attestation: <oauth-client-attestation+jwt>}
  GET  /jwks            -> the attester's public JWK Set
  GET  /.well-known/openid-federation  -> a (self-issued) OIDF Entity Statement
"""
from __future__ import annotations

import base64
import json
import logging
import os
import time
import uuid
from typing import Any

import jwt  # PyJWT
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("attester")

ATTESTER_ISSUER = os.environ.get("ATTESTER_ISSUER", "https://attester.example.com")
ATTESTATION_TTL = int(os.environ.get("ATTESTATION_TTL", "600"))
TRUST_ANCHOR = os.environ.get("TRUST_ANCHOR", "https://anchor.example.com")
ATTESTATION_TYP = "oauth-client-attestation+jwt"

# The signing key — the ONLY place the private key lives. Provided as a JWK (with
# the private `d`) via env so it's never in source or an image layer.
_PRIV_JWK: dict[str, Any] = json.loads(os.environ["ATTESTER_PRIVATE_JWK"])
_KID = _PRIV_JWK.get("kid", "attester-1")


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _load_signing_key() -> ec.EllipticCurvePrivateKey:
    d = int.from_bytes(_b64u_dec(_PRIV_JWK["d"]), "big")
    return ec.derive_private_key(d, ec.SECP256R1())


_KEY = _load_signing_key()
_PUB_JWK = {k: _PRIV_JWK[k] for k in ("kty", "crv", "x", "y")}
_PUB_JWK["kid"] = _KID

app = FastAPI(title="Northwind Attester")


@app.get("/ping")
def ping():
    return {"status": "healthy", "issuer": ATTESTER_ISSUER, "kid": _KID}


@app.get("/health")
def health():
    return {"status": "ok", "issuer": ATTESTER_ISSUER}


@app.get("/jwks")
def jwks():
    """The attester's public JWK Set — what PingFederate resolves to verify."""
    return {"keys": [_PUB_JWK]}


@app.get("/.well-known/openid-federation")
def entity_statement():
    """A self-issued OpenID Federation Entity Statement so a real PF can trust this
    attester via a federation trust chain (metadata.oauth_client_attester.jwks)."""
    now = int(time.time())
    claims = {
        "iss": ATTESTER_ISSUER, "sub": ATTESTER_ISSUER, "iat": now, "exp": now + 3600,
        "jwks": {"keys": [_PUB_JWK]},
        "authority_hints": [TRUST_ANCHOR],
        "metadata": {"oauth_client_attester": {"jwks": {"keys": [_PUB_JWK]}}},
    }
    stmt = jwt.encode(claims, _KEY, algorithm="ES256",
                      headers={"typ": "entity-statement+jwt", "kid": _KID})
    return JSONResponse(content=stmt, media_type="application/entity-statement+jwt")


@app.post("/attest")
async def attest(request: Request):
    """Mint a client attestation JWT binding the agent's DPoP key (cnf)."""
    body = await request.json()
    client_id = body.get("client_id")
    cnf = body.get("cnf")
    if not client_id or not isinstance(cnf, dict):
        return JSONResponse(status_code=400,
                            content={"error": "client_id and cnf (public JWK) are required"})
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ATTESTER_ISSUER,
        "sub": client_id,                       # == the OAuth client_id at the token endpoint
        "iat": now,
        "exp": now + ATTESTATION_TTL,
        "jti": str(uuid.uuid4()),
        "cnf": {"jwk": cnf},                    # binds the agent's DPoP key
        "workload": body.get("workload", {}),
        "authorization_details": body.get("authorization_details", []),
    }
    header = {"alg": "ES256", "typ": ATTESTATION_TYP, "kid": _KID}
    token = jwt.encode(claims, _KEY, algorithm="ES256", headers=header)
    logger.info("Attested client_id=%s (cnf bound)", client_id)
    return {"attestation": token, "header": header, "claims": claims,
            "attester_issuer": ATTESTER_ISSUER, "attester_jwks": {"keys": [_PUB_JWK]}}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8110"))
    host = os.environ.get("HOST", "::")   # IPv6 for Railway private networking
    logger.info("Starting Attester (%s, kid=%s) on %s:%s", ATTESTER_ISSUER, _KID, host, port)
    uvicorn.run(app, host=host, port=port)
