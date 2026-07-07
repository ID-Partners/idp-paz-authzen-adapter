"""Verify inbound bearer tokens with the vendored token_validator
(github.com/dphhyland/client-attestation-sdk-polyglot · Python `token_validator`).

Each agent independently validates a token presented to it — signature against
PingFederate's JWKS, issuer, and expiry — instead of blindly trusting it. Returns
a transcript-step dict so the UI can show the verification as a real step.

Two validators: user tokens (userJwtATM) carry iss = the public PF domain, so iss
is enforced; the agent-to-agent tokens (attestJwt ATMs) have an empty issuer claim,
so those are validated on signature + expiry only.
"""
from __future__ import annotations

import os

from token_validator import AccessTokenValidator, ValidatorConfig

PF_ISSUER = os.environ.get("PF_ISSUER", "https://pingfederate-production-cb0a.up.railway.app")
PF_JWKS_URI = os.environ.get("PF_JWKS_URI", PF_ISSUER.rstrip("/") + "/pf/JWKS")

_user_validator = AccessTokenValidator(ValidatorConfig(issuer=PF_ISSUER, audiences=[], jwks_uri=PF_JWKS_URI))
# attestJwt ATMs issue with an empty Issuer Claim Value -> don't enforce iss.
_agent_validator = AccessTokenValidator(ValidatorConfig(issuer="", audiences=[], jwks_uri=PF_JWKS_URI))


def verify_bearer(token: str | None, *, kind: str, presenter: str) -> dict:
    """Validate a bearer token presented to this agent.

    kind = "user" (Alice's PF token) or "agent" (a delegating agent's token).
    Returns a transcript step describing the verification outcome.
    """
    checks = ["signature (PingFederate JWKS)"] + (["issuer"] if kind == "user" else []) + ["expiry"]
    step: dict = {"type": "token_verification", "kind": kind, "presenter": presenter,
                  "checks": checks, "validator": "client-attestation-sdk-polyglot · token_validator"}
    if not token:
        step.update(verified=False, error="missing_token",
                    detail=f"No {kind} token was presented by {presenter}.")
        return step
    validator = _user_validator if kind == "user" else _agent_validator
    try:
        r = validator.validate(token)
    except Exception as exc:  # noqa: BLE001 - JWKS fetch / decode errors
        step.update(verified=False, error="validation_error", detail=f"Could not validate the {kind} token: {exc}")
        return step
    step["verified"] = bool(r)
    if r:
        step["sub"] = r.subject
        step["scope"] = " ".join(r.scopes)
        step["detail"] = (f"Verified the {kind} bearer presented by {presenter}: the signature checks out "
                          f"against PingFederate's JWKS"
                          f"{', the issuer matches' if kind == 'user' else ''}, and it hasn't expired "
                          f"(sub={r.subject}).")
    else:
        step["error"] = r.error
        step["detail"] = (f"REJECTED the {kind} bearer from {presenter}: {r.error}"
                          + (f" — {r.error_description}" if r.error_description else ""))
    return step
