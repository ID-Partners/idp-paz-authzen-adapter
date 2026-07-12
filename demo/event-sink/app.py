"""Event-sink — a resource server for the interactive demo's "flattened" token.

The payments agent normally holds a DELEGATED token (`sub=alice, act={payments, act={concierge}}`)
— delegation, not impersonation, everywhere else in the demo. This endpoint is the ONE place that
takes a deliberately different token: a **flattened** token minted by a special audience-scoped
RFC 8693 exchange that PROMOTES the root actor (the orchestration agent, the innermost `act.sub`)
into `sub` and drops `act` entirely.

Why: an emitted event is authored by the *agent itself*, not by Alice — the agent is the principal
of the event, acting as itself for machine-to-machine publishing. So this endpoint REQUIRES:
  • `aud` = this event audience (the token was minted for HERE, nowhere else),
  • `sub` = an agent identity (the orchestration agent),
  • NO `act` claim (the delegation chain was intentionally flattened for this hop).

A normal delegated token (with `act`, or `sub=alice`) is REJECTED — that keeps the flatten strictly
scoped to this audience and makes the "acts as itself" boundary explicit, not accidental impersonation.
"""
from __future__ import annotations

import logging
import os
import time

import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from jwt import PyJWKClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("event-sink")

PF_ISSUER = os.environ.get("PF_ISSUER", "https://pingfederate-production-cb0a.up.railway.app")
PF_JWKS_URI = os.environ.get("PF_JWKS_URI", PF_ISSUER.rstrip("/") + "/pf/JWKS")
EVENTS_AUDIENCE = os.environ.get("EVENTS_AUDIENCE", "https://events.northwind.example")
# The identity we EXPECT in sub (the orchestration/root agent). Informational — the hard
# requirement is "sub is an agent + no act", not a specific id.
ORCH_AGENT_ID = os.environ.get("ORCH_AGENT_ID", "urn:agent:northwind-concierge:v1")

app = FastAPI(title="event-sink")
_jwks = PyJWKClient(PF_JWKS_URI)


@app.get("/ping")
def ping() -> dict:
    return {"status": "ok", "audience": EVENTS_AUDIENCE, "jwks": PF_JWKS_URI}


def _verify_flattened(token: str) -> tuple[dict | None, list[dict], str | None]:
    """Verify the flattened event token. Returns (claims, checks, error).

    Signature is validated against PingFederate's JWKS; then we enforce the three
    properties that make this a *flattened* token, not a delegated one."""
    checks: list[dict] = []

    def rec(name: str, ok: bool, note: str) -> None:
        checks.append({"check": name, "ok": ok, "note": note})

    try:
        key = _jwks.get_signing_key_from_jwt(token).key
        # attestation-family ATMs issue with an empty issuer claim, so don't pin iss;
        # aud is what actually scopes this token to us. Verify sig + exp + aud here.
        claims = jwt.decode(token, key, algorithms=["ES256", "RS256"],
                            audience=EVENTS_AUDIENCE,
                            options={"verify_iss": False, "require": ["sub", "aud", "exp"]})
    except jwt.ExpiredSignatureError:
        rec("signature + expiry (PF JWKS)", False, "token expired")
        return None, checks, "token_expired"
    except jwt.InvalidAudienceError:
        rec("audience == event endpoint", False,
            f"token aud is not {EVENTS_AUDIENCE} — it was not minted for this endpoint")
        return None, checks, "wrong_audience"
    except Exception as exc:  # noqa: BLE001
        rec("signature (PF JWKS)", False, f"could not verify: {exc}")
        return None, checks, "invalid_token"

    rec("signature + expiry (PF JWKS)", True, "signed by PingFederate, not expired")
    rec("audience == event endpoint", True, f"aud = {EVENTS_AUDIENCE} (minted for HERE only)")

    # The defining checks: sub is an AGENT and there is NO act chain (flattened).
    sub = claims.get("sub", "")
    has_act = "act" in claims and claims.get("act")
    sub_is_agent = sub.startswith("urn:agent:")

    if has_act:
        rec("no act claim (flattened)", False,
            "token still carries an act chain — this is a delegated token, not a flattened one")
        return None, checks, "not_flattened"
    rec("no act claim (flattened)", True, "act was promoted into sub and dropped — agent acts as itself")

    if not sub_is_agent:
        rec("sub is the agent identity", False,
            f"sub={sub!r} is not an agent — a flattened event token must name the agent, not Alice")
        return None, checks, "sub_not_agent"
    rec("sub is the agent identity", True,
        f"sub = {sub}" + ("  (the orchestration agent, as expected)" if sub == ORCH_AGENT_ID else ""))

    return claims, checks, None


@app.post("/events")
async def events(request: Request) -> JSONResponse:
    auth = request.headers.get("authorization", "")
    token = auth.split(" ", 1)[1] if " " in auth else (auth or "")
    try:
        payload = await request.json()
    except Exception:  # noqa: BLE001
        payload = {}

    if not token:
        return JSONResponse(status_code=401, content={"error": "missing_token",
            "detail": "The event endpoint requires a flattened bearer token (sub=agent, no act, aud=events)."})

    claims, checks, err = _verify_flattened(token)
    if err:
        log.info("event REJECTED (%s)", err)
        return JSONResponse(status_code=401, content={
            "accepted": False, "error": err, "checks": checks,
            "detail": "Rejected — this endpoint only accepts a token flattened for its audience "
                      "(agent as sub, no delegation chain)."})

    event_id = f"evt-{int(time.time())}-{abs(hash(str(payload))) % 10000:04d}"
    log.info("event ACCEPTED %s from sub=%s", event_id, claims.get("sub"))
    return JSONResponse(status_code=201, content={
        "accepted": True, "eventId": event_id,
        "producer": claims.get("sub"),          # the agent, acting as itself
        "audience": claims.get("aud"),
        "actChainPresent": False,
        "receivedPayload": payload,
        "checks": checks,
        "detail": (f"Event accepted. Producer = {claims.get('sub')} (the agent asserting its own "
                   f"identity; Alice and the delegation chain were flattened away by the "
                   f"audience-scoped exchange). Delegation is preserved everywhere else — this one "
                   f"hop is the deliberate exception, scoped to aud={EVENTS_AUDIENCE}.")})


if __name__ == "__main__":
    import uvicorn
    # Railway's public edge reaches the container over IPv4 — bind 0.0.0.0, not ::.
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8120")))
