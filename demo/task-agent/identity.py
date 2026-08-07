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

log = logging.getLogger("task-agent-identity")

PRINCIPAL_SUB = os.environ.get("PRINCIPAL_SUB", "alice")   # the human (== OIDC sub)
PRINCIPAL_AGENT_ID = os.environ.get("PRINCIPAL_AGENT_ID", "urn:agent:northwind-concierge:v1")
# "pingfederate" mode: get a REAL delegated token from PingFederate — the attester
# service signs the attestation, PF validates it and issues the token. "local"
# (default) self-issues an equivalently-shaped token.
TOKEN_MODE = os.environ.get("TOKEN_MODE", "local").lower()
PF_TOKEN_URL = os.environ.get("PF_TOKEN_URL", "")
# No PF_CLIENT_SECRET: agents are PUBLIC clients authenticated by SELF-SIGNED client attestation
# (stable entity key, public key pre-registered in the AS trust file). No shared attester service,
# no OpenID Federation, no client secret. (The legacy remote-attester URL is likewise unused.)
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
# Audience-scoped FLATTEN exchange (event endpoint). The payments agent does a 2nd exchange for
# this audience → a token whose sub is the ROOT actor and which has NO act (agent acts as itself).
EVENTS_AUDIENCE = os.environ.get("EVENTS_AUDIENCE", "https://events.northwind.example")
EVENT_SINK_URL = os.environ.get("EVENT_SINK_URL", "")  # unset → event publishing is skipped


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


def _normalize_ad(ad: Any) -> list[dict[str, Any]]:
    """Coerce an authorization_details value (list, JSON string, or single object)
    into a list of RAR entries; [] if absent/unparseable."""
    if not ad:
        return []
    if isinstance(ad, str):
        try:
            ad = json.loads(ad)
        except Exception:  # noqa: BLE001
            return []
    if isinstance(ad, dict):
        return [ad]
    return ad if isinstance(ad, list) else []


def _subject_authorization_details(user_token: str | None) -> list[dict[str, Any]]:
    """The RFC 9396 authorization_details Alice consented to, read from her subject
    token. RFC 8693 bounds the exchanged token's authority by the subject's grant, so
    this governed payment is exactly what the delegated hop is entitled to carry."""
    if not user_token:
        return []
    try:
        return _normalize_ad(jwt.decode(user_token, options={"verify_signature": False})
                             .get("authorization_details"))
    except Exception:  # noqa: BLE001
        return []


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


class PFExchangeError(Exception):
    """Token exchange at PingFederate failed; carries a transcript-ready diagnostic."""
    def __init__(self, diagnostic: dict[str, Any]) -> None:
        self.diagnostic = diagnostic
        super().__init__(diagnostic.get("summary", "token exchange failed"))


ENTRA_ISSUER_HINT = os.environ.get("ENTRA_ISSUER_HINT", "login.microsoftonline.com")


def _subject_token_type(subject_token: str | None) -> str:
    """RFC 8693 subject_token_type, chosen by who ISSUED the subject token.

    One PF token-exchange policy (userToAgentTE) now serves both flows, and PF selects
    the token processor by subject_token_type — it refuses two mappings sharing a type.
    So the two issuers must declare different types:

      * Alice's PF login token   -> …:access_token -> subjectJwtProc      (concierge flow)
      * Alice's Entra token      -> …:jwt          -> entraSubjectJwtProc (Copilot flow)

    Sending access_token for an Entra-issued subject is what produced PF's
    "Invalid Issuer" — subjectJwtProc only trusts PF's own issuer.
    """
    try:
        iss = jwt.decode(subject_token, options={"verify_signature": False}).get("iss", "")
    except Exception:  # noqa: BLE001 - undecodable: fall back to the historical default
        return "urn:ietf:params:oauth:token-type:access_token"
    if ENTRA_ISSUER_HINT and ENTRA_ISSUER_HINT in str(iss):
        return "urn:ietf:params:oauth:token-type:jwt"
    return "urn:ietf:params:oauth:token-type:access_token"


def _decode_jwt(token: str | None) -> dict[str, Any]:
    """Decode a JWT WITHOUT verifying (for display/diagnosis) → header + key claims."""
    if not token:
        return {"error": "no token"}
    try:
        h = jwt.get_unverified_header(token)
        c = jwt.decode(token, options={"verify_signature": False})
        return {"header": {k: h.get(k) for k in ("alg", "kid", "typ") if k in h},
                "claims": {k: c.get(k) for k in
                           ("iss", "sub", "aud", "exp", "iat", "scope", "act", "client_id", "jti", "cnf")
                           if k in c},
                "preview": token[:16] + "…" + token[-10:]}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"undecodable: {exc}", "preview": token[:16] + "…"}


def _curl_for(url: str, data: dict[str, str], attest: bool, dpop: bool) -> str:
    """A copy-pasteable curl for the token-exchange request (secrets/tokens elided)."""
    lines = [f"curl -sk -X POST '{url}'"]
    if attest:
        lines.append("-H 'OAuth-Client-Attestation: <attestation JWT>'")
    if dpop:
        lines.append("-H 'DPoP: <proof signed by cnf.jwk>'")
    for k, v in data.items():
        vv = "<…>" if k in ("subject_token", "actor_token", "client_secret") else str(v)
        lines.append(f"--data-urlencode '{k}={vv}'")
    return " \\\n  ".join(lines)


def _exchange_diagnostic(agent_id: str, data: dict[str, str], subject_token: str | None,
                         tr: "httpx.Response") -> dict[str, Any]:
    try:
        body = tr.json()
    except Exception:  # noqa: BLE001
        body = tr.text[:400]
    subj = _decode_jwt(subject_token)
    exp = subj.get("claims", {}).get("exp")
    now = int(time.time())
    if isinstance(exp, int):
        note = (f"subject token EXPIRED {now - exp}s ago" if exp < now
                else f"subject token still valid for {exp - now}s")
    else:
        note = "no exp claim on subject token"
    err = body.get("error") if isinstance(body, dict) else body
    return {
        "type": "token_exchange_failed", "role": "task_agent", "agent": agent_id,
        "title": f"Token exchange FAILED at PingFederate ({tr.status_code})",
        "summary": f"PF {tr.status_code}: {err}",
        "detail": (f"PingFederate rejected the RFC 8693 exchange: {err}. "
                   f"Subject = the presented bearer (Alice's login token). {note}."),
        "te_endpoint": PF_TOKEN_URL, "pf_status": tr.status_code, "pf_response": body,
        "curl": _curl_for(PF_TOKEN_URL, data, attest=True, dpop=True),
        "subject_token_decoded": subj, "subject_token_note": note,
    }


def _establish_pf(*, agent_id: str, agent_type: str, agent_label: str, role: str,
                  user_token: str | None = None, delegator_token: str | None = None) -> Credential:
    """Get a REAL delegated token from PingFederate: the attester service signs an
    attestation binding this agent's DPoP key, then PF (as this agent's own OAuth
    client) validates it and issues the token.

    RFC 8693 token exchange, chained for a GROWING actor chain: the subject_token is
    the DELEGATOR's delegated token (the concierge's token, which already carries
    act={concierge}) when present, else Alice's login token. PingFederate reads the
    incoming token's `act` and WRAPS it — {this-agent, act={…incoming…}} — so the
    chain is derived from the token, not baked per agent. `sub` (Alice) rides through
    unchanged. The RAR is still read from Alice's `user_token` (her consent).
    Without any subject token, fall back to client_credentials (static sub)."""
    now = int(time.time())
    local = _new_key(); local_jkt = _jkt(local); local_jwk = _pub_jwk(local)
    workload = {"software_id": agent_id, "agent_type": agent_type,
                "on_behalf_of": PRINCIPAL_SUB,
                "environment": os.environ.get("RAILWAY_ENVIRONMENT_NAME", "production")}
    ad = _authorization_details()
    with httpx.Client(timeout=20.0, verify=False) as c:
        # 1) SELF-ATTESTATION: the agent signs its OWN client-attestation JWT with its stable
        #    entity key (AGENT_ENTITY_KEY_PEM). The matching PUBLIC key is pre-registered in the
        #    AS static trust file (demo/pingfederate/oidf-mock-attesters.json), keyed by the
        #    agent's client_id — so PF resolves iss=client_id → that key and verifies the
        #    signature. No attester service, no OpenID Federation, no client secret.
        att = mint_agent_attestation(
            client_id=agent_id, agent_id=agent_id, agent_type=agent_type,
            principal_sub=PRINCIPAL_SUB, agent_public_jwk=local_jwk,
            authorization_details=ad)
        attestation = att.jwt
        # 2) Present the attestation + a DPoP proof to PingFederate's token endpoint.
        dpop = jwt.encode({"htm": "POST", "htu": PF_TOKEN_URL,
                           "jti": str(uuid.uuid4()), "iat": now},
                          local, algorithm="ES256",
                          headers={"typ": "dpop+jwt", "jwk": local_jwk})
        # Exchange ALICE's login token as the subject. (Chaining on the concierge's delegated
        # token — to derive a growing act — is deferred: PF's subjectJwtProc requires
        # iss=<PF-URL>, but the attestJwt ATMs issue agent tokens with an EMPTY issuer, so the
        # concierge token is rejected as a subject. That needs the agent ATMs to stamp iss first;
        # until then the nested act comes from the per-agent ATM mapping, not from re-exchange.)
        subject_token = user_token or delegator_token
        # Read Alice's consented payment RAR from her subject token FOR DISPLAY ONLY.
        # We do NOT re-send authorization_details on the exchange: PF's token-exchange grant has
        # no RAR processor, so any authorization_details → 400 invalid_authorization_details (and
        # for a non-payment agent like account-opening it's the wrong RAR entirely). The payment
        # RAR is governed once, at Alice's consent (the authorization endpoint), not per hop.
        subject_ad = _subject_authorization_details(user_token)
        # NO client_secret: the agent is a PUBLIC client (PF client_auth = NONE) authenticated
        # by client attestation (attest_jwt_client_auth_dpop) — the attester-signed
        # OAuth-Client-Attestation JWT + the DPoP proof (cnf-bound key) below ARE the client
        # credential. PF enforces it via the validateClientAttestation issuance criterion on the
        # exchange mapping; a request without a valid attestation is refused. The agent clients
        # are token-exchange-only (no CLIENT_CREDENTIALS grant — PF forbids NONE auth with it),
        # so the real flow always exchanges a subject token (Alice's login, or the delegator's).
        if subject_token:
            grant = "urn:ietf:params:oauth:grant-type:token-exchange"
            data = {"grant_type": grant,
                    "subject_token": subject_token,
                    "subject_token_type": _subject_token_type(subject_token),
                    "client_id": agent_id}
        else:
            grant = "client_credentials"
            data = {"grant_type": grant, "client_id": agent_id}
        tr = c.post(PF_TOKEN_URL, data=data,
                    headers={"OAuth-Client-Attestation": attestation, "DPoP": dpop})
        if tr.status_code != 200:
            diag = _exchange_diagnostic(agent_id, data, subject_token, tr)
            # Server-side: log the decoded subject token so the reason is visible in the logs.
            _sd = diag["subject_token_decoded"]
            log.warning("token exchange FAILED (%s) for %s | %s | subject hdr=%s claims=%s",
                        tr.status_code, agent_id, diag["subject_token_note"],
                        _sd.get("header"), _sd.get("claims"))
            raise PFExchangeError(diag)
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
    # Prefer the RAR PingFederate stamped into the issued token; otherwise show the
    # governed payment carried from Alice's subject token (what this hop is entitled
    # to exercise). ad_source lets the UI label which it is, truthfully.
    issued_ad = _normalize_ad(claims.get("authorization_details"))
    effective_ad = issued_ad or subject_ad
    ad_source = ("issued token" if issued_ad
                 else "carried from Alice's consent (subject token)" if subject_ad else None)
    steps = [
        {"type": "attestation", "title": "Client attestation (self-signed, pre-registered key)",
         "detail": f"{agent_id} self-signed a client-attestation JWT with its stable entity key "
                   f"(iss = its own client_id), binding its DPoP key (cnf). PingFederate verifies it "
                   f"against the agent's pre-registered public key — no attester service, no "
                   f"federation, no client secret.",
         "attester": att.attester_issuer, "client_id": agent_id, "agent": agent_id,
         "agent_type": agent_type, "local_jkt": local_jkt,
         "auth_method": "attest_jwt_client_auth_dpop", "typ": att.header.get("typ"),
         "workload": att.claims.get("workload"),
         "attestation_header": att.header, "attestation_claims": att.claims,
         "attestation_preview": attestation[:24] + "…" + attestation[-12:],
         "attester_jwks": att.attester_jwks, "role": role, "mode": "pingfederate"},
        {"type": "auth", "title": "Agent authenticates to PingFederate",
         "detail": f"{agent_id} authenticated to PingFederate as its own OAuth client using the "
                   f"attestation (attest_jwt_client_auth_dpop) — no client secret exposed to the model.",
         "client_id": agent_id, "agent": agent_id, "jkt": local_jkt, "local_jkt": local_jkt,
         "grant": grant, "auth_method": "attest_jwt_client_auth_dpop",
         "role": role, "mode": "pingfederate"},
        {"type": "token_exchange",
         "title": (f"Token exchange (RFC 8693) @ PingFederate → {agent_label} token"
                   if user_token else f"PingFederate issued {agent_label}'s delegated token"),
         "detail": (f"REAL RFC 8693 exchange: {agent_id} presented the authenticated user's login "
                    f"token as the subject_token; PingFederate VALIDATED it and derived "
                    f"sub={claims.get('sub')} from that authenticated identity, "
                    f"act = {' ◀ '.join(chain_labels)} — delegation, not impersonation."
                    if user_token else
                    f"PingFederate validated the attestation and issued a REAL delegated token: "
                    f"sub={claims.get('sub')}, act = {' ◀ '.join(chain_labels)} — delegation, not impersonation."),
         "sub": claims.get("sub"), "act": act, "act_sub": (act or {}).get("sub") if isinstance(act, dict) else act,
         "actor_chain": chain_labels, "hop": 2, "hops": 2, "delegator": PRINCIPAL_AGENT_ID,
         "scope": claims.get("scope"), "cnf_jkt": (claims.get("cnf") or {}).get("jkt"),
         "aud": claims.get("aud"), "client_id": claims.get("client_id"),
         "authorization_details": effective_ad,
         "authorization_details_source": ad_source,
         "grant": grant,
         "subject_token_preview": (subject_token[:20] + "…" + subject_token[-12:]) if subject_token else None,
         "te_request": ({"grant_type": grant,
                         "subject_token": "<Alice's PF login token>",
                         "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                         "client_id": agent_id} if subject_token else None),
         "token_preview": tp, "claims": claims, "token_header": jwt.get_unverified_header(token),
         "curl": _curl_for(PF_TOKEN_URL, data, attest=True, dpop=True),
         "subject_token_decoded": _decode_jwt(subject_token) if subject_token else None,
         "issued_token_decoded": {"header": jwt.get_unverified_header(token), "claims": claims},
         "te_endpoint": PF_TOKEN_URL, "role": role, "agent_label": agent_label, "mode": "pingfederate"},
    ]
    return Credential(access_token=token, principal_sub=claims.get("sub", PRINCIPAL_SUB),
                      agent_sub=agent_id, jkt=local_jkt, _key=local, steps=steps,
                      actor_chain=chain_labels)


def exchange_for_events(*, agent_id: str, subject_token: str) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """2nd RFC 8693 exchange scoped to the events audience → a FLATTENED token: PingFederate
    promotes the ROOT actor (innermost act.sub) into `sub` and drops `act`. The agent asserts
    its OWN identity for event publishing — deliberately NOT delegation, scoped to this audience.

    Requires the events ATM + audience-scoped mapping applied in PF (Terraform `flatten.tf`).
    Returns (flattened_token, claims, transcript_step)."""
    now = int(time.time())
    local = _new_key()
    local_jwk = _pub_jwk(local)
    with httpx.Client(timeout=20.0, verify=False) as c:
        # Self-signed attestation (stable entity key; pre-registered public key) — no attester
        # service, no federation, no secret. Binds this request's local DPoP key via cnf.
        attestation = mint_agent_attestation(
            client_id=agent_id, agent_id=agent_id, agent_type="event-publisher",
            principal_sub=PRINCIPAL_SUB, agent_public_jwk=local_jwk,
            authorization_details=[]).jwt
        dpop = jwt.encode({"htm": "POST", "htu": PF_TOKEN_URL, "jti": str(uuid.uuid4()), "iat": now},
                          local, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": local_jwk})
        edata = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "resource": EVENTS_AUDIENCE,  # ← selects the events ATM → flatten mapping
            # Public client — attestation (below) is the credential, no client_secret.
            "client_id": agent_id}
        curl = _curl_for(PF_TOKEN_URL, edata, attest=True, dpop=True)
        tr = c.post(PF_TOKEN_URL, data=edata,
                    headers={"OAuth-Client-Attestation": attestation, "DPoP": dpop})
        if tr.status_code >= 400:
            # No flattened token yet — surface the ATTEMPT so the activity log still shows the
            # audience-scoped event exchange (curl + the nested-act subject going in) and WHY it
            # can't flatten: the events ATM + act→sub mapping (Terraform flatten.tf) isn't applied.
            try:
                body = tr.json()
            except Exception:  # noqa: BLE001
                body = tr.text[:400]
            err = body.get("error") if isinstance(body, dict) else body
            raise PFExchangeError({
                "type": "token_exchange_flatten", "pending": True, "role": "task_agent",
                "agent": agent_id,
                "title": "Audience-scoped exchange (RFC 8693) → FLATTENED event token (attempt)",
                "summary": f"PF {tr.status_code}: {err}",
                "detail": (f"Attempted the audience-scoped flatten exchange for aud={EVENTS_AUDIENCE}: the "
                           f"agent presents its delegated (nested-act) token and asks PingFederate to promote "
                           f"the ROOT actor into sub and drop the act chain. PF returned {tr.status_code} "
                           f"({err}) — the events ATM + act→sub flatten mapping (Terraform flatten.tf) isn't "
                           f"applied yet, so PF can't mint the flattened token."),
                "resource": EVENTS_AUDIENCE, "curl": curl,
                "subject_token_decoded": _decode_jwt(subject_token)})
        token = tr.json()["access_token"]
    claims = jwt.decode(token, options={"verify_signature": False})
    step = {
        "type": "token_exchange_flatten",
        "title": "Audience-scoped exchange (RFC 8693) → FLATTENED event token",
        "detail": (f"Exchanged for aud={EVENTS_AUDIENCE}: PingFederate promoted the ROOT actor into "
                   f"sub={claims.get('sub')} and dropped the act chain — the agent acts as ITSELF to "
                   f"publish the event (deliberately NOT delegation, scoped to this one audience)."),
        "sub": claims.get("sub"), "aud": claims.get("aud"), "has_act": "act" in claims,
        "resource": EVENTS_AUDIENCE, "client_id": claims.get("client_id"),
        "curl": _curl_for(PF_TOKEN_URL, edata, attest=True, dpop=True),
        "subject_token_decoded": _decode_jwt(subject_token),
        "issued_token_decoded": {"header": jwt.get_unverified_header(token), "claims": claims},
        "token_preview": token[:20] + "…" + token[-12:], "claims": claims, "mode": "pingfederate"}
    return token, claims, step


def establish_identity(*, agent_id: str, agent_type: str, agent_label: str,
                       role: str, mcp_url: str, user_token: str | None = None,
                       delegator_token: str | None = None) -> Credential:
    """Mint this task agent's identity + its delegated, DPoP-bound token.

    In pingfederate mode, get a REAL token from PF via the attester — an RFC 8693
    token exchange when Alice's login token is available; otherwise self-issue an
    equivalently-shaped token. Returns a Credential + transcript steps.
    """
    if TOKEN_MODE == "pingfederate" and PF_TOKEN_URL:
        return _establish_pf(agent_id=agent_id, agent_type=agent_type,
                             agent_label=agent_label, role=role, user_token=user_token,
                             delegator_token=delegator_token)
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
