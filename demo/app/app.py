"""
Northwind Web App (BFF) — the app server, separate from the principal agent.

This is the public front door Alice uses. It is an OpenID Connect client of the
real PingFederate: it redirects Alice to PingFederate's hosted login page, and on
return holds her session (her PF id_token + access_token). It then proxies chat
requests to the (headless) principal agent over the private network, forwarding
Alice's identity and her PF access token so the downstream gateway can enforce
that a real user is logged in (RFC 9470 step-up challenge — see Phase 3).

    GET  /                → the web UI
    GET  /login           → start the PASSKEY ceremony (/signup); ?stepup carries the
                            elevated scope + the payment across it in a signed cookie
    GET  /me              → the signed-in principal (or 401)
    POST /logout          → clear the session
    POST /stream          → proxy (SSE) to the principal agent, carrying Alice's identity
    POST /invocations     → proxy (JSON) to the principal agent
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import secrets
import time
import urllib.parse
from collections import deque
from datetime import datetime, timezone

import httpx
import jwt  # PyJWT
from fastapi import FastAPI, Request
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               RedirectResponse, StreamingResponse)
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Northwind Web App (BFF)")
# Module logger. Every logger.* call in this file used to NameError — including inside the
# except: handlers that were supposed to make consent-recording best-effort, so a failure there
# escaped and 500'd /signin/passkey/finish AFTER a perfectly good passkey ceremony. The browser
# then showed Safari's JSON.parse message ("The string did not match the expected pattern")
# because it tried to r.json() the HTML 500 — a server crash disguised as a WebAuthn error.
# Without basicConfig the root logger has no handler, so logging falls back to the WARNING-level
# handler of last resort and every logger.info() in this file is silently discarded. That is not
# cosmetic: it made a fail-closed Recognize verdict indistinguishable from "the code never ran"
# and cost several debugging rounds. The sibling service (autonomous-agent) has always done this,
# which is why only ITS logs were ever visible.
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("northwind-app")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# --- config ------------------------------------------------------------------
# Public PingFederate base (its TCP proxy). The app talks to PF over the public
# endpoint because the browser is redirected there for login.
PF_BASE = os.environ.get("PF_BASE_URL", "https://hayabusa.proxy.rlwy.net:49245").rstrip("/")
PF_AUTHORIZE = os.environ.get("PF_AUTHORIZE_URL", PF_BASE + "/as/authorization.oauth2")
PF_TOKEN = os.environ.get("PF_TOKEN_URL", PF_BASE + "/as/token.oauth2")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "northwind-webapp")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "webapp-secret-123")
# This app's own public base URL.
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:8090").rstrip("/")
# The headless principal agent (private network).
PRINCIPAL_AGENT_URL = os.environ.get("PRINCIPAL_AGENT_URL",
                                     "http://bank-agent.railway.internal:8000").rstrip("/")
APP_SECRET = os.environ.get("APP_SECRET", "northwind-bff-secret")
SESSION_TTL = int(os.environ.get("SESSION_TTL", "28800"))  # 8h
# Everyday scopes Alice consents to at first login. The sensitive
# banking:payments:transfer is NOT here — it requires a step-up (re-auth).
DEFAULT_SCOPES = os.environ.get("DEFAULT_SCOPES",
                                "openid banking:accounts:list banking:accounts:originate "
                                "grant_management_evaluate")
SESSION_COOKIE = "nw_session"
STEPUP_COOKIE = "nw_stepup"  # short-lived: carries the requested step-up scope across the passkey ceremony
# RFC 8707 resource for the Grant Management API. Requesting it on the broker exchange
# selects the gmJwtATM, which mints a token AUDIENCED for the GM API (aud=this value) from
# the SAME login grant — so agid/sub/client_id are preserved but aud satisfies the servlet.
GM_RESOURCE = os.environ.get("GM_RESOURCE", "https://gm-api.demo/grants")


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _sign(payload: dict, ttl: int) -> str:
    now = int(time.time())
    return jwt.encode({**payload, "iat": now, "exp": now + ttl}, APP_SECRET, algorithm="HS256")


def _verify(token: str | None) -> dict | None:
    if not token:
        return None
    try:
        return jwt.decode(token, APP_SECRET, algorithms=["HS256"])
    except Exception:  # noqa: BLE001
        return None


def _session(request: Request) -> dict | None:
    return _verify(request.cookies.get(SESSION_COOKIE))


# ── Device authorization ──────────────────────────────────────────────────────────────────
# The approver app is NOT privileged. It holds a device token — a BFF-signed JWT that authorizes
# it to act ONLY for one user — minted when THAT signed-in user generates the pairing QR, carried
# in the QR, stored on the phone, and presented as a Bearer on every device→BFF call. Endpoints
# below enforce that the token authorizes the user/resource being touched, so a device can never
# mint keys, reconcile, or read proofing for anyone but its own paired user.
DEVICE_TOKEN_TTL = int(os.environ.get("DEVICE_TOKEN_TTL", str(90 * 24 * 3600)))  # 90d
# Device tokens use their OWN secret (not the session APP_SECRET) so it can be SHARED with the
# autonomous-agent service — which also verifies these tokens on its consent endpoints — without
# handing that service the power to forge session cookies. Defaults to APP_SECRET for local dev.
DEVICE_TOKEN_SECRET = os.environ.get("DEVICE_TOKEN_SECRET", APP_SECRET)


def _mint_device_token(user: str) -> str:
    now = int(time.time())
    return jwt.encode({"device_sub": (user or "").lower(), "typ": "device",
                       "iat": now, "exp": now + DEVICE_TOKEN_TTL},
                      DEVICE_TOKEN_SECRET, algorithm="HS256")


def _device_user(request: Request) -> str | None:
    """The user a valid device Bearer token authorizes, else None."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    try:
        claims = jwt.decode(auth.split(" ", 1)[1].strip(), DEVICE_TOKEN_SECRET, algorithms=["HS256"])
    except Exception:  # noqa: BLE001
        return None
    if claims.get("typ") != "device":
        return None
    return (claims.get("device_sub") or "").lower() or None


def _require_device(request: Request, user: str | None = None) -> JSONResponse | None:
    """Guard: require a valid device token; if `user` is given, require the token authorizes
    exactly that user. Returns an error JSONResponse to return, or None when authorized."""
    du = _device_user(request)
    if not du:
        return JSONResponse(status_code=401, content={"error": "device_auth_required"})
    if user is not None and du != (user or "").lower():
        return JSONResponse(status_code=403, content={"error": "forbidden_for_user"})
    return None


@app.get("/ping")
def ping():
    return {"status": "healthy"}


@app.get("/health")
def health():
    return {"status": "ok"}



# The OID4VP verifier that runs the mDL identity-proofing presentation (idp-pf-vcs — a
# different Railway project, so reached over its PUBLIC URL) and the proofing directory
# (internal) where a verified presentation is recorded for the PDP origination gate to read.
VERIFIER_URL = os.environ.get(
    "VERIFIER_URL", "https://verifier-production-9118.up.railway.app").rstrip("/")
PROOFING_DIRECTORY_URL = os.environ.get(
    "PROOFING_DIRECTORY_URL", "http://proofing-directory.railway.internal:8075").rstrip("/")
PROOFING_DOCTYPE = os.environ.get("PROOFING_DOCTYPE", "org.iso.18013.5.1.mDL")
# The AuthZEN adapter, which owns the mDL identity-proofing gate SWITCH (/admin/proofing-gate).
AUTHZEN_ADAPTER_URL = os.environ.get(
    "AUTHZEN_ADAPTER_URL", "http://authzen-adapter.railway.internal:8080").rstrip("/")


@app.get("/proofing/gate")
async def proofing_gate_get():
    """Read the mDL identity-proofing gate switch state (proxies the adapter)."""
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.get(f"{AUTHZEN_ADAPTER_URL}/admin/proofing-gate")
            return r.json()
    except Exception as e:
        return JSONResponse(status_code=502,
                            content={"error": "adapter_unreachable", "detail": str(e)})


@app.post("/proofing/gate")
async def proofing_gate_set(request: Request):
    """Flip the mDL identity-proofing gate on/off (proxies the adapter). Demo control plane."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.post(f"{AUTHZEN_ADAPTER_URL}/admin/proofing-gate",
                             json={"enabled": bool(body.get("enabled"))})
            return r.json()
    except Exception as e:
        return JSONResponse(status_code=502,
                            content={"error": "adapter_unreachable", "detail": str(e)})


@app.post("/proofing/start")
async def proofing_start(request: Request):
    """Begin an mDL identity-proofing presentation: ask the OID4VP verifier for a request
    and hand the browser the openid4vp:// request + QR so the customer presents from their
    wallet (app2app). Requires a signed-in principal — that's the subject we proof."""
    s = _session(request)
    if not s:
        return JSONResponse(status_code=401, content={"error": "login_required"})
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as c:
            r = await c.post(f"{VERIFIER_URL}/verify/start", json={"credential": "mdl"})
            r.raise_for_status()
            d = r.json()
    except Exception as e:
        return JSONResponse(status_code=502,
                            content={"error": "verifier_unreachable", "detail": str(e)})
    return {"session_id": d.get("session_id"), "request_uri": d.get("request_uri"),
            "wallet_link": d.get("wallet_link"), "qr_svg": d.get("qr_svg")}


@app.get("/proofing/status/{session_id}")
async def proofing_status(session_id: str, request: Request):
    """Poll the verifier for the presentation result. On 'verified', record the
    identity-proofing activity in the directory keyed by the signed-in principal —
    SERVER-SIDE, so the browser can't forge a proofing — so the origination retry then
    passes the PDP gate (the adapter reads identity_proofing_present for this subject)."""
    s = _session(request)
    if not s:
        return JSONResponse(status_code=401, content={"error": "login_required"})
    subject = s.get("sub") or ""
    if not subject:
        # Never substitute a default subject. In a system whose whole claim is WHO
        # authorised WHAT, a fallback manufactures a wrong answer instead of refusing.
        return JSONResponse(status_code=401, content={"error": "no_subject"})
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as c:
            r = await c.get(f"{VERIFIER_URL}/verify/status/{session_id}")
            r.raise_for_status()
            d = r.json()
    except Exception as e:
        return JSONResponse(status_code=502,
                            content={"error": "verifier_unreachable", "detail": str(e)})
    recorded = False
    if d.get("status") == "verified":
        # Scope the record to the account this proofing was FOR. _PROOFINGS is in-memory, so
        # after a restart the account is gone; fall back to what the verifier session recorded,
        # then to "savings" (the demo default) so the write STILL lands scoped rather than being
        # dropped. A verified mDL must never be lost because the process bounced.
        account = next((p.get("account") or "" for p in _PROOFINGS.values()
                        if p.get("session_id") == session_id), "")
        if not account:
            account = str((d.get("claims") or {}).get("account") or "savings")
        try:
            async with httpx.AsyncClient(timeout=8.0) as c:
                pr = await c.post(f"{PROOFING_DIRECTORY_URL}/proofing", json={
                    "subject": subject, "doctype": PROOFING_DOCTYPE, "method": "oid4vp",
                    "claims": d.get("claims") or {}, "session_id": session_id,
                    "account": account})
                recorded = pr.status_code < 300
            logger.info("proofing VERIFIED subject=%s account=%s recorded=%s (http %s)",
                        subject, account, recorded, pr.status_code)
        except Exception as exc:  # noqa: BLE001
            logger.warning("proofing write FAILED subject=%s: %s", subject, exc)
    elif d.get("status") not in ("pending", None):
        logger.info("proofing status subject=%s session=%s -> %s", subject, session_id, d.get("status"))
    return {"status": d.get("status"), "claims": d.get("claims"),
            "error": d.get("error"), "recorded": recorded, "subject": subject}


# ── mDL proofing via CIBA push (the corrected flow: push to the customer's phone, the
# approver opens the wallet app2app, the wallet presents to the verifier, we record it) ──
CIBA_CLIENT_ID = os.environ.get("CIBA_CLIENT_ID", "urn:agent:northwind-autonomous:v1")
CIBA_ENDPOINT = os.environ.get("CIBA_ENDPOINT", PF_BASE + "/as/bc-auth.ciba")
CIBA_ISSUER = os.environ.get("CIBA_ISSUER", "https://localhost:9031")
CIBA_KID = os.environ.get("CIBA_KID", "d4c67a35a199")

# In-flight proofings keyed by the ≤20-char reference code that rides the CIBA
# binding_message: the push shows only the code; the approver app fetches the full
# request (the openid4vp:// URI) from GET /proofing/code/{code}. Mirrors the
# autonomous-agent's consent-by-code store.
_PROOFINGS: dict[str, dict] = {}


def _ciba_assertion(endpoint: str) -> str:
    pem = os.environ.get("CIBA_CLIENT_KEY_PEM", "")
    now = int(time.time())
    # PF validates the private_key_jwt audience against its ISSUER / token endpoint, which
    # in this deployment is the INTERNAL https://localhost:9031 (not the public Railway host).
    # Send the same audience array the working autonomous-agent uses, or PF 400s invalid_client.
    return jwt.encode({"iss": CIBA_CLIENT_ID, "sub": CIBA_CLIENT_ID,
                       "aud": [endpoint, "https://localhost:9031/as/token.oauth2",
                               "https://localhost:9031"],
                       "jti": secrets.token_hex(8), "iat": now, "exp": now + 120},
                      pem, algorithm="ES256", headers={"kid": CIBA_KID})


async def _ciba_push(login_hint: str, binding: str) -> tuple[bool, str]:
    """Fire a FAPI-CIBA backchannel request purely as the PUSH + approval channel — we
    never redeem the token (proofing completion is signalled by the verifier, and the PF
    CIBA DEFAULT token mapping is staff-specific). Signed request object, private_key_jwt."""
    pem = os.environ.get("CIBA_CLIENT_KEY_PEM", "")
    if not pem:
        return False, "CIBA_CLIENT_KEY_PEM not configured"
    now = int(time.time())
    req = {"iss": CIBA_CLIENT_ID, "aud": CIBA_ISSUER, "jti": secrets.token_hex(8),
           "iat": now, "exp": now + 300, "nbf": now,
           "scope": "openid", "login_hint": login_hint, "binding_message": binding}
    form = {"request": jwt.encode(req, pem, algorithm="ES256", headers={"kid": CIBA_KID}),
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": _ciba_assertion(CIBA_ENDPOINT)}
    async with httpx.AsyncClient(timeout=30.0, verify=False) as c:
        r = await c.post(CIBA_ENDPOINT, data=form)
        if r.status_code != 200:
            return False, f"bc-auth {r.status_code}: {r.text[:200]}"
        return True, r.json().get("auth_req_id", "")


@app.post("/proofing/begin")
async def proofing_begin(request: Request, user: str = ""):
    """Kick off the CIBA-push mDL proofing for the signed-in customer: create the OID4VP
    verifier session, register the reference code, and push to the customer's phone. The
    browser then polls /proofing/status/{session_id} and resumes origination on verified.
    Demo convenience: without a browser session, an explicit ?user= may trigger it — the
    real authorization is the push approval + mDL presentation on that user's phone."""
    s = _session(request)
    if not s and not user:
        return JSONResponse(status_code=401, content={"error": "login_required"})
    subject = (s.get("sub") if s else None) or user.strip().lower()
    if not subject:
        return JSONResponse(status_code=401, content={"error": "no_subject"})
    # The proofing is scoped to the SPECIFIC account being originated (its type, e.g.
    # "savings") — carried from the identity challenge's open_account arguments. A
    # proofing for one account does not satisfy the gate for another.
    account = ""
    try:
        body = await request.json()
        account = str(body.get("account_type") or body.get("account") or "")
    except Exception:  # noqa: BLE001 — body is optional
        pass
    account = (account or request.query_params.get("account", "")).strip().lower()
    # Same branch as the payment step-up: paired device -> cross-device push into the wallet
    # app2app; no device -> SAME-DEVICE Digital Credentials API picker. Never a QR, because a
    # user with no paired phone cannot scan one.
    channel = await _authz_channel(subject)
    start_path = "/verify/start" if channel == "device" else "/verify/start/dcapi"
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as c:
            r = await c.post(f"{VERIFIER_URL}{start_path}",
                             json={"credential": "mdl"} if channel == "device" else {})
            r.raise_for_status()
            v = r.json()
    except Exception as e:
        return JSONResponse(status_code=502,
                            content={"error": "verifier_unreachable", "detail": str(e)})
    code = "MDL-" + secrets.token_hex(3)  # ≤20 chars, CIBA binding_message charset-safe
    _PROOFINGS[code] = {"code": code, "session_id": v.get("session_id"),
                        "request_uri": v.get("request_uri"), "subject": subject,
                        "doctype": PROOFING_DOCTYPE, "account": account,
                        "authz_type": AUTHZ_TYPE_PROOFING, "channel": channel,
                        "created": int(time.time())}
    if channel == "local":
        # Nothing to push: hand the browser the DC-API request so the OS wallet picker opens
        # on THIS device. dcApiRequest is what navigator.credentials.get() consumes.
        logger.info("proofing -> LOCAL dc-api (no paired device) subject=%s code=%s", subject, code)
        return {"code": code, "session_id": v.get("session_id"),
                "type": AUTHZ_TYPE_PROOFING, "channel": "local",
                "dcApiRequest": v.get("dcApiRequest") or v.get("request"),
                "subject": subject, "account": account}
    pushed, detail = await _ciba_push(subject, code)
    return {"code": code, "session_id": v.get("session_id"),
            "type": AUTHZ_TYPE_PROOFING, "channel": "device",
            "push": "sent" if pushed else "failed", "push_detail": detail if not pushed else "",
            "subject": subject, "account": account}


@app.get("/proofing/code/{code}")
async def proofing_by_code(code: str, request: Request):
    """The approver app resolves the push's reference code to the full proofing request —
    most importantly the openid4vp:// request_uri it opens app2app into the wallet.
    Device-token scoped: a phone may only read proofings for ITS user."""
    du = _device_user(request)
    if not du:
        return JSONResponse(status_code=401, content={"error": "device_auth_required"})
    p = _PROOFINGS.get(code)
    if not p:
        return JSONResponse(status_code=404, content={"error": "unknown_code"})
    if (p.get("subject") or "").lower() != du:
        return JSONResponse(status_code=403, content={"error": "forbidden_for_user"})
    return p


@app.get("/proofing/latest")
async def proofing_latest(request: Request):
    """The approver's no-code fallback: the pi.flow push can't reliably deliver even the
    20-char reference code to the app (clientContext is dropped; the alert text is
    template-dependent), so on any push the app asks for the most recent FRESH proofing
    request and opens its openid4vp:// link app2app. Device-token scoped: only the device's
    OWN user's pending proofing is returned — never another customer's."""
    du = _device_user(request)
    if not du:
        return JSONResponse(status_code=401, content={"error": "device_auth_required"})
    now = int(time.time())
    fresh = [p for p in _PROOFINGS.values()
             if now - p.get("created", 0) < 300 and (p.get("subject") or "").lower() == du]
    if not fresh:
        return JSONResponse(status_code=404, content={"error": "no_pending_proofing"})
    newest = sorted(fresh, key=lambda p: p["created"])[-1]

    # DO NOT answer when the newest pending request for this user is a RESOURCE
    # AUTHORISATION (a payment). The approver app asks this endpoint on ANY push whose code
    # is not MDL-…, so a proofing from minutes ago would otherwise capture the payment push
    # and open the mDL screen instead — observed exactly that. The app's own comment assumed
    # "payment consents never register a proofing"; that stopped being true once payments
    # started pushing to the same device.
    newest_payment = max((su.get("created", 0) for su in _STEPUPS.values()
                          if (su.get("subject") or "").lower() == du
                          and su.get("status") == "pending"), default=0)
    if newest_payment > newest.get("created", 0):
        logger.info("proofing/latest yielding to a newer resource authorisation for %s", du)
        return JSONResponse(status_code=404, content={"error": "newer_resource_authorisation"})
    return newest


# ── Identity roster for the approver app (proxies the SCIM directory; the app can't
# reach the internal network) ──
# NOTE: there is deliberately NO GET /identities roster endpoint. The approver app is not
# entitled to enumerate the bank's directory — it only ever knows accounts it was explicitly
# paired to (scanned QR / username enrol), tracked on the device. Pairing state for a SINGLE
# named user is available via /identities/{user}/reconcile below (scoped, not a roster read).


@app.post("/identities/{user_name}/reconcile")
async def identities_reconcile(user_name: str, request: Request):
    """Sync the directory's pairing state from PingOne (source of truth). Recovers the
    approver-app case where pair() reported an error but the device actually enrolled
    (e.g. racing pairing keys). Device-token scoped: a phone may only reconcile ITS user."""
    if (err := _require_device(request, user_name)):
        return err
    user = (user_name or "").strip().lower()
    try:
        async with httpx.AsyncClient(timeout=20.0) as c:
            tok = await _p1_token(c)
            uid = await _p1_ensure_user(c, tok, user)
            r = await c.get(f"{P1_API}/v1/environments/{P1_ENV}/users/{uid}/devices",
                            headers={"Authorization": f"Bearer {tok}"})
            devices = (r.json().get("_embedded") or {}).get("devices") or []
            paired = any(d.get("status") == "ACTIVE" for d in devices)
    except Exception as e:  # noqa: BLE001
        return JSONResponse(status_code=502, content={"error": "pingone_unreachable",
                                                      "detail": str(e)})
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            sr = await c.get(f"{PROOFING_DIRECTORY_URL}/scim/v2/Users",
                             params={"filter": f'userName eq "{user}"'})
            users = sr.json().get("Resources", [])
            if users:
                await c.patch(f"{PROOFING_DIRECTORY_URL}/scim/v2/Users/{users[0]['id']}",
                              json={"Operations": [{"op": "replace", "path": "devicePaired",
                                                    "value": paired}]})
    except Exception:  # noqa: BLE001 — directory sync is best-effort
        pass
    return {"user": user, "paired": paired, "devices": len(devices)}


@app.post("/identities/{user_name}/pairing")
async def identities_pairing(user_name: str, request: Request):
    """The approver app reports pairing state changes (sign-in/sign-out) → SCIM PATCH.
    Device-token scoped: a phone may only report pairing for ITS user."""
    if (err := _require_device(request, user_name)):
        return err
    try:
        body = await request.json()
    except Exception:
        body = {}
    paired = bool(body.get("paired"))
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.get(f"{PROOFING_DIRECTORY_URL}/scim/v2/Users",
                            params={"filter": f'userName eq "{user_name}"'})
            users = r.json().get("Resources", [])
            if not users:
                return JSONResponse(status_code=404, content={"error": "unknown_user"})
            pr = await c.patch(f"{PROOFING_DIRECTORY_URL}/scim/v2/Users/{users[0]['id']}",
                               json={"Operations": [{"op": "replace", "path": "devicePaired",
                                                     "value": paired}]})
            return pr.json()
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": "directory_unreachable",
                                                      "detail": str(e)})


async def _record_stepup_consent(su: dict, subject: str) -> str:
    """Record the passkey step-up payment as an AUTHORIZED consent in the consent directory.

    The passkey ceremony that just completed IS the acceptance of THIS payment (amount/creditor
    came from the step-up cookie). The PDP looks this consent up when the payment request returns
    through the gateway (a policy information provider on the directory), so the policy passes
    without the RAR being carried in the token. Returns the minted transaction id (best-effort)."""
    if not PROOFING_DIRECTORY_URL:
        return ""
    txn = "txn_" + secrets.token_hex(6)
    try:
        amt = float(su.get("amount") or 0)
    except (TypeError, ValueError):
        amt = 0.0
    # Carry the assurance ACTUALLY achieved on this path. Before Recognize this was never
    # written here at all (only the paired-device /stepup/approve path wrote it), so the
    # directory's consent-check always fell back to "app-asserted" for every passkey-stepup
    # consent — correct for a plain passkey, but silently flattened a Recognize-verified
    # no-device approval down to the SAME level as an unverified one. See stepup_consent_finish.
    assurance = su.get("assurance") or ASSURANCE_APP_ASSERTED
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            await c.post(f"{PROOFING_DIRECTORY_URL}/consents", json={
                "transaction_id": txn,
                "subject": subject, "actor": subject,
                # Where the consent was ACTUALLY captured. The DaVinci flow renders the
                # amount/payee on the no-device path; the app's own page is the fallback.
                # Do not hardcode this: an audit record that names the wrong surface is
                # the same class of defect as one that overstates assurance.
                "channel": su.get("channel") or "passkey-stepup",
                "amount": amt, "currency": su.get("currency") or "AUD",
                "debtor_account": su.get("debtor") or "",
                "creditor_account": su.get("creditor") or "",
                "status": "authorized",
                "authorization_details": [{"type": "payment_initiation", "assurance": assurance}]})
        logger.info("recorded passkey-stepup consent txn=%s subject=%s amount=%s creditor=%s assurance=%s",
                    txn, subject, amt, su.get("creditor"), assurance)
    except Exception as exc:  # noqa: BLE001 — must never block the passkey sign-in
        logger.warning("stepup consent record failed: %s", exc)
    return txn


async def _record_consent_decision(su: dict, subject: str, status: str) -> None:
    """Persist a consent DECISION that does not become an authorization (e.g. declined).
    Kept separate from _record_stepup_consent so a decline can never be mistaken for one."""
    if not PROOFING_DIRECTORY_URL or not subject:
        return
    try:
        amt = float(su.get("amount") or 0)
    except (TypeError, ValueError):
        amt = 0.0
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            await c.post(f"{PROOFING_DIRECTORY_URL}/consents", json={
                "transaction_id": "txn_" + secrets.token_hex(6),
                "subject": subject, "actor": subject, "channel": "davinci-consent",
                "amount": amt, "currency": su.get("currency") or "AUD",
                "debtor_account": su.get("debtor") or "",
                "creditor_account": su.get("creditor") or "",
                "status": status})
        logger.info("recorded davinci consent decision=%s subject=%s", status, subject)
    except Exception as exc:  # noqa: BLE001
        logger.warning("consent decision record failed: %s", exc)


async def _project_delegation_grant(subject: str, scope: str, consent_txn: str,
                                    assurance: str | None = None) -> None:
    """Project the delegation grant into the identity store when the step-up authorises the agent
    to act for the principal. oauthGrant + agentDelegation (principal=subject, agent=concierge),
    linked to the consent that authorised it — the consent→grant→token→action chain, now held in
    the Identity Object Model. Idempotent per (principal, agent): one grant relationship, upserted.
    Best-effort; never blocks the sign-in.

    A STANDING delegation (an agent trusted to act for this principal across future requests,
    not just this one payment) is a materially bigger grant of authority than a single-payment
    step-up — so the FIRST time a (subject, agent) grant is created, it requires the top of the
    assurance ladder: a Recognize-verified human, not merely a device tap or an app-asserted
    passkey. Once the grant exists, later step-ups keep refreshing/upserting it as before (an
    already-standing delegation doesn't need re-approving on every payment — Phase 1's
    Recognize check on the payment itself is what gates THAT). See demo/TRANSACTION-AUTHORIZATION.md
    for why 'a device tapped approve' and 'a person was biometrically confirmed' are not the
    same evidence."""
    assurance = assurance or ASSURANCE_APP_ASSERTED
    if not PROOFING_DIRECTORY_URL:
        return
    agent = "urn:agent:northwind-concierge:v1"
    guid = f"g_{subject}:{agent}"
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            existing = await c.get(f"{PROOFING_DIRECTORY_URL}/grants/{guid}")
            is_new = existing.status_code == 404
            if is_new and assurance != ASSURANCE_RECOGNIZE_VERIFIED:
                logger.info("standing delegation grant NOT created for %s -> %s: assurance=%s "
                            "insufficient for a first-time grant (need recognize-verified)",
                            subject, agent, assurance)
                return
            await c.post(f"{PROOFING_DIRECTORY_URL}/grants", json={
                "grant_guid": guid,   # one grant per delegation relationship
                "principal_id": subject, "agent_id": agent,
                "client_id": OIDC_CLIENT_ID, "agent_operator_id": OIDC_CLIENT_ID,
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "scope": scope, "consent_ref": consent_txn})
            if is_new:
                logger.info("standing delegation grant CREATED for %s -> %s (recognize-verified)",
                            subject, agent)
    except Exception as exc:  # noqa: BLE001
        logger.warning("grant projection failed: %s", exc)


# ── Adaptive step-up ────────────────────────────────────────────────────────────────
# ONE entry point for every step-up, which BRANCHES on whether the user has a usable
# authenticator (the enrolment-vs-authentication split — a flow that always authenticates
# blocks every device-less user):
#
#   paired device  → CIBA push to that device. The push carries only a ≤20-char code;
#                    the approver app PULLS the amount + payee from /stepup/code/{code}
#                    and signs over the transaction hash. THIS is the binding: the
#                    signature covers the instruction, so it is dynamically linked
#                    (PSD2 RTS Art.5) and the artefact is retained for a dispute.
#   no device      → local browser passkey (and, for origination, an mDL QR). This path
#                    CANNOT bind — a browser passkey signs a random challenge (WebAuthn
#                    has no transaction-authorization extension). It is a real DOWNGRADE.
#
# Both outcomes carry the assurance ACTUALLY ACHIEVED, so the PDP can decline the weak
# path for high-value operations instead of silently accepting it.
# See demo/TRANSACTION-AUTHORIZATION.md sections 2-4.

# AUTHORISATION TYPE — what KIND of decision this is. Orthogonal to the assurance ladder
# below (which says how STRONGLY it was made). The phone currently infers the type from a
# code prefix and a fallback lookup, which is why a payment push can be read as a proofing
# request; carrying the type explicitly removes the guess.
#
#   resource_authorisation  fine-grained, a SPECIFIC protected resource (RFC 9396 RAR):
#                           this amount, this payee, this account. A payment is this.
#   consent                 coarse-grained or non-OAuth agreement (ToS, data sharing, scope)
#   identity_proofing       an attribute claim to be verified (VC/VP, mDL)
#
# NOTE: payments are recorded today under "consent"-named endpoints and the consent_covered
# PDP attribute. That naming predates this taxonomy and is WRONG — a payment is a resource
# authorisation. Renaming the store/PIP is a separate change; the type is carried explicitly
# here so the record is at least self-describing.
AUTHZ_TYPE_RESOURCE = "resource_authorisation"   # RAR — fine-grained, a specific resource
AUTHZ_TYPE_CONSENT = "consent"                   # coarse-grained / non-OAuth agreement
AUTHZ_TYPE_PROOFING = "identity_proofing"        # VC/VP presentation request

# assurance ladder, weakest → strongest. The PDP sees this verbatim.
ASSURANCE_APP_ASSERTED = "app-asserted"    # local passkey; signature does NOT cover the payment
ASSURANCE_DEVICE_APPROVED = "device-approved"  # paired device approved, but sent no signature
ASSURANCE_DEVICE_SIGNED = "device-signed"      # paired device signed over the transaction hash
# PingOne Recognize verified the PERSON (liveness + face match), not just the device or a
# signature. Ranked top of the ladder: it is evidence about WHO is present, which the other
# rungs (device possession, device signature) do not give you on their own. See
# demo/pingfederate/README.md's Recognize integration note for how a verdict gets here.
ASSURANCE_RECOGNIZE_VERIFIED = "recognize-verified"

# PingOne Recognize / Keyless integration. SIMULATE (default) accepts a client-asserted
# {"recognizeVerified": true} — the Keyless DaVinci connector / Recognize Mobile SDK aren't
# wired to a real tenant yet, so this lets the whole assurance→PDP pipeline be built and
# demoed today. REAL (RECOGNIZE_SIMULATE=0) requires recognizeAssertion: a JWT signed by the
# Recognize/Keyless tenant, verified against RECOGNIZE_JWKS_URL before the verdict is trusted.
# Mirrors the SIMULATE convention already used for Bob's phone tap (demo/autonomous-agent/agent.py).
RECOGNIZE_SIMULATE = os.environ.get("RECOGNIZE_SIMULATE", "1").lower() not in ("0", "false", "no")
RECOGNIZE_JWKS_URL = os.environ.get("RECOGNIZE_JWKS_URL", "")
# Audience we require on the Recognize assertion. Must equal the iOS build's
# RECOGNIZE_JWT_AUDIENCE. Unset = no audience check (the old, weaker behaviour) — so this is
# additive and safe to roll out before the phone starts stamping it.
RECOGNIZE_JWT_AUDIENCE = os.environ.get("RECOGNIZE_JWT_AUDIENCE", "")
RECOGNIZE_ISSUER = os.environ.get("RECOGNIZE_ISSUER", "")

# The REAL Keyless/Recognize Web SDK. These two values are provisioned by Keyless when the tenant
# is created and are NOT discoverable from the customer dashboard or the public docs — the docs
# list them as things you must already have ("CUSTOMER_NAME to define the customer,
# KEYLESS_AUTHENTICATION_SERVICE_URL to establish a connection"). Until both are set the demo
# serves the simulated screen instead, so an unprovisioned environment still runs end to end.
#
# The contract below was read off the SDK's own published TypeScript definitions
# (@keyless/sdk-web@3.0.0 index.d.ts) rather than guessed:
#   KeylessOptions { customer:{name}, service:{url}, username, transaction?:{data}, ... }
# and the web component mirrors it as the attributes customer / service-url / username /
# transaction-data. The SDK posts to <service.url>/v2/sessions to open a session, and on success
# emits a `success` event whose detail carries a signed **jwt** — that JWT is what
# _recognize_verdict() verifies in REAL mode, which is why RECOGNIZE_JWKS_URL exists.
RECOGNIZE_CUSTOMER_NAME = os.environ.get("RECOGNIZE_CUSTOMER_NAME", "")
RECOGNIZE_SERVICE_URL = os.environ.get("RECOGNIZE_SERVICE_URL", "").rstrip("/")
RECOGNIZE_SDK_URL = os.environ.get(
    "RECOGNIZE_SDK_URL",
    "https://d3hz8ozgrmhn4r.cloudfront.net/sdk-web-components/3.0.0/index.js")

# Keyless runs ONE authentication service per region; a tenant lives in exactly one of them, and
# the dashboard does not say which. All of these answer `POST /v2/sessions` with 201 for ANY
# customer name, so the region cannot be identified by probing — only by getting far enough into
# the encrypted exchange for the tenant lookup to succeed or fail. Hence the ?region= override on
# /recognize/enrol: it lets us try each one against a real camera without a redeploy per attempt.
# Naming convention: authentication-service.eks.core-production.<region>.keyless.technology
RECOGNIZE_REGIONS = {
    "us": "https://authentication-service.eks.core-production.saas-us-east.keyless.technology",
    "eu": "https://authentication-service.eks.core-production.keyless.technology",
    "latam": "https://authentication-service.eks.core-production.latam.keyless.technology",
    "sandbox": "https://authentication-service-sandbox.eks.core-production.keyless.technology",
    "staging": "https://authentication-service.eks.core-staging.keyless.technology",
}

# ── Recognize "User Authorization" — the first factor, minted by PingFederate ─────────────────
# Recognize can require an integrator-supplied JWT before it will run ANY biometric processing:
# sub = the username handed to the SDK, aud = "authentication-service", short-lived, single-use.
# Keyless validates it against a JWKS we publish (tenant config User Authorization Type =
# RemoteJWKSet, which only Keyless staff can set), so it is a genuine first factor rather than a
# client-side claim: it stops someone driving the Keyless service directly with a username that
# was never authenticated here.
#
# PF mints it (recognizeUserAuthATM, see pingfederate/terraform/recognize-user-auth.tf) off the
# SAME BFF assertion + signupTE exchange the passkey path already uses — which is what makes it
# work at SIGN-ON, where there is no session yet to exchange. The RESOURCE below is an internal
# ATM-selection key only; PF rejects a non-absolute resource URI, so it is a URN and is never
# dialed. The token's audience is set by the ATM, not by this value.
RECOGNIZE_USERAUTH_RESOURCE = os.environ.get(
    "RECOGNIZE_USERAUTH_RESOURCE", "urn:northwind:recognize:authentication-service")
# Off by default: sending an authorization token to a tenant that is NOT configured for
# RemoteJWKSet is harmless, but minting one costs a PF round-trip per page load. Turn on when
# Keyless confirms the tenant setting.
RECOGNIZE_USERAUTH_ENABLED = os.environ.get(
    "RECOGNIZE_USERAUTH_ENABLED", "0").lower() not in ("0", "false", "no", "")


def recognize_real_configured() -> bool:
    """True when a real Keyless tenant is wired up. Both values are required: a customer name
    without a service URL (or vice versa) cannot open a session, and silently falling back to
    'simulated' while claiming a real biometric check is exactly the overstatement this demo's
    assurance ladder exists to prevent."""
    return bool(RECOGNIZE_CUSTOMER_NAME and RECOGNIZE_SERVICE_URL)


def _td_amount(v) -> str:
    """Normalise an amount for comparison: '"AUD 9,000.00"' / '9000' / 9000.0 -> '9000.00'."""
    s = re.sub(r"[^0-9.]", "", str(v or ""))
    if not s:
        return ""
    try:
        return f"{float(s):.2f}"
    except ValueError:
        return ""


def _td_flatten(td) -> dict:
    """The `td` claim reaches us in more than one shape and both are legitimate:
      - Mobile SDK: the array-of-single-pair-objects Recognize mandates for display, e.g.
        [{"Amount":"AUD 9000.00"},{"To":"ACME"},{"From":"Alice"},{"Reference":"NW-1"}]
      - Web SDK: whatever object was passed as transaction-data, e.g.
        {"amount":"9000","currency":"AUD","creditor":"ACME","debtor":"Alice"}
    Either may arrive as a JSON *string* (JwtSigningInfo takes a String). Flatten to one
    lower-cased dict so the comparison below does not care which surface produced it."""
    if isinstance(td, str):
        try:
            td = json.loads(td)
        except Exception:  # noqa: BLE001 — a non-JSON td simply yields no comparable fields
            return {}
    out: dict = {}
    if isinstance(td, list):
        for item in td:
            if isinstance(item, dict):
                for k, v in item.items():
                    out[str(k).strip().lower()] = v
    elif isinstance(td, dict):
        out = {str(k).strip().lower(): v for k, v in td.items()}
    return out


def _td_matches(td, su: dict) -> bool:
    """Is the SIGNED transaction data the payment we are actually approving?

    This is the dynamic-linking check, and it is the difference between "a real person passed a
    face match" and "a real person approved THIS payment". Without it a valid assertion captured
    for a $10 coffee would authorise a $9,000 transfer — the assertion is genuine, it is simply
    not *about* this instruction. PSD2 RTS Art. 5 requires the binding to cover the **amount and
    the payee**, so those are the two fields enforced here; reference/debtor are display detail
    and deliberately not required to match.

    Fails CLOSED: an absent, unparseable, or non-matching `td` is not a verdict for this payment.
    """
    flat = _td_flatten(td)
    if not flat:
        logger.warning("recognize td missing/unparseable — refusing to treat as bound")
        return False

    want_amt = _td_amount(su.get("amount"))
    got_amt = _td_amount(next((flat[k] for k in ("amount", "amt", "value") if k in flat), ""))
    if want_amt and got_amt != want_amt:
        logger.warning("recognize td AMOUNT mismatch: signed=%r expected=%r", got_amt, want_amt)
        return False

    want_payee = str(su.get("creditor") or "").strip().lower()
    got_payee = str(next((flat[k] for k in ("to", "payee", "creditor") if k in flat), "")).strip().lower()
    if want_payee and got_payee and want_payee not in got_payee and got_payee not in want_payee:
        logger.warning("recognize td PAYEE mismatch: signed=%r expected=%r", got_payee, want_payee)
        return False
    if want_payee and not got_payee:
        logger.warning("recognize td carries no payee — refusing to treat as bound")
        return False

    logger.info("recognize td BOUND to this payment: amount=%s payee=%s", got_amt, got_payee)
    return True


def _recognize_verdict(body: dict, expected: dict | None = None) -> bool:
    """True if `body` carries evidence of a completed Recognize verification. In SIMULATE
    mode any client-asserted `recognizeVerified: true` is accepted — good enough to prove out
    the assurance→PDP wiring, NOT non-repudiable (the client could lie). In REAL mode a signed
    `recognizeAssertion` JWT is required and verified against the tenant's JWKS; an unverifiable
    or absent assertion is NOT a verified verdict, full stop — this must fail closed."""
    if RECOGNIZE_SIMULATE:
        return bool(body.get("recognizeVerified"))
    token = str(body.get("recognizeAssertion") or "")
    if not (token and RECOGNIZE_JWKS_URL):
        # Was silent, which made a fail-closed look identical to "never called" in the logs and
        # cost a whole debugging round. Say WHICH half is missing: a client that reports
        # recognizeVerified:true with no assertion is the interesting case — the biometric ran
        # on the device but produced nothing a server can check.
        logger.warning(
            "recognize REAL mode refused: assertion=%s jwks_url=%s client_claimed_verified=%s",
            "present" if token else "MISSING",
            "set" if RECOGNIZE_JWKS_URL else "MISSING",
            bool(body.get("recognizeVerified")))
        return False
    try:
        jwks_client = jwt.PyJWKClient(RECOGNIZE_JWKS_URL)
        key = jwks_client.get_signing_key_from_jwt(token)
        # Verify `aud` when we have pinned one. Without it (verify_aud False) an assertion
        # minted for a DIFFERENT relying party on the same tenant verifies here perfectly well —
        # right signature, right issuer, wrong audience. The phone stamps this via
        # JwtSigningInfo(audience:); the two values must match exactly.
        claims = jwt.decode(token, key.key, algorithms=["RS256", "ES256"],
                            issuer=RECOGNIZE_ISSUER or None,
                            audience=RECOGNIZE_JWT_AUDIENCE or None,
                            options={"verify_aud": bool(RECOGNIZE_JWT_AUDIENCE)})
    except Exception as exc:  # noqa: BLE001 — an unverifiable assertion is simply not a verdict
        logger.warning("recognize assertion verification failed: %s", exc)
        return False

    # THE SIGNATURE IS THE VERDICT. Recognize mints this JWT only on a successful match, so a
    # token that verifies against the tenant's JWKS *is* the evidence — there is no boolean to
    # read. The real claim set is {iat, td, version, sub, external_user_id} (mobile) with kid
    # PIN|FACE; earlier code here looked for a `verified`/`result` claim that Recognize has never
    # emitted, which made REAL mode fail closed on every genuine assertion.
    #
    # Honour an explicit negative if a future/other issuer ever emits one, but never REQUIRE it.
    if claims.get("verified") is False or claims.get("result") in ("fail", "failed"):
        return False

    # DYNAMIC LINKING. When there is a specific instruction in flight, the signed `td` must BE
    # that instruction — a valid assertion about some other payment is not authorisation for this
    # one. Only enforced when `expected` describes a payment, so sign-on (nothing to bind to) is
    # unaffected. See demo/TRANSACTION-AUTHORIZATION.md for why this is the whole argument for
    # Recognize over a browser passkey.
    if expected and expected.get("amount"):
        if not _td_matches(claims.get("td"), expected):
            return False
        logger.info("recognize assertion verified AND bound: sub=%s", claims.get("sub"))
    else:
        logger.info("recognize assertion verified (nothing to bind to): sub=%s", claims.get("sub"))
    return True


def _deep_recognize_field(o) -> bool:
    """Scan a DaVinci flow's (nested, shape-varies-by-node) success response for a captured
    `recognizeVerified` form field that reads true. Used for the widget-embedded flows (payment
    consent, sign-on) — unlike _recognize_verdict, which reads a flat client-posted body, a
    flow's success payload nests captured fields under whichever node produced them, so a
    fixed-shape lookup misses it (see stepup_consent_finish's original comment on why _decision
    needed the same treatment for buttonValue)."""
    if isinstance(o, dict):
        for k, v in o.items():
            if k.lower() in ("recognizeverified", "recognize_verified") and (
                    v is True or (isinstance(v, str) and v.lower() in ("true", "1", "pass", "passed"))):
                return True
            if _deep_recognize_field(v):
                return True
    elif isinstance(o, list):
        for v in o:
            if _deep_recognize_field(v):
                return True
    return False


# In-flight step-ups keyed by the ≤20-char code that rides the CIBA binding_message.
_STEPUPS: dict[str, dict] = {}


def _txn_hash(su: dict) -> str:
    """Canonical hash of the INSTRUCTION. This is what the device signs, and what the
    dispute layer re-derives to prove what the user actually approved."""
    canon = json.dumps({"subject": su.get("subject", ""), "amount": str(su.get("amount", "")),
                        "currency": su.get("currency", ""), "debtor": su.get("debtor", ""),
                        "creditor": su.get("creditor", "")},
                       sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()


APPROVER_CONSENT_URL = os.environ.get(
    "APPROVER_CONSENT_URL", "https://autonomous-agent-staging.up.railway.app").rstrip("/")
APPROVER_REGISTER_SECRET = os.environ.get("APPROVER_REGISTER_SECRET", "")


async def _persist_stepup(su: dict) -> None:
    """Write the PENDING resource authorisation to the directory, keyed by its code.

    _STEPUPS is an in-memory dict, but the approval window is minutes long and spans a
    container restart (a deploy mid-window wiped it: /stepup/status then 404'd forever while
    the user had already approved). The directory is the durable store, so the step-up is
    written at creation and rehydrated on poll. The CODE is the transaction reference, so one
    record covers requested -> authorized rather than two."""
    if not PROOFING_DIRECTORY_URL:
        return
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            await c.post(f"{PROOFING_DIRECTORY_URL}/consents", json={
                "transaction_id": su["code"], "subject": su["subject"], "actor": su["subject"],
                "channel": "ciba-device", "status": "requested",
                "amount": float(su.get("amount") or 0), "currency": su.get("currency") or "AUD",
                "debtor_account": su.get("debtor") or "",
                "creditor_account": su.get("creditor") or "",
                # carries what the poll needs to resume after a restart
                "authorization_details": [{"type": "payment_initiation",
                                           "authzType": AUTHZ_TYPE_RESOURCE,
                                           "authReqId": su.get("auth_req_id", ""),
                                           "transactionHash": su.get("hash", ""),
                                           "scope": su.get("scope", "")}]})
    except Exception as exc:  # noqa: BLE001 — never block the push
        logger.warning("stepup persist failed for %s: %s", su.get("code"), exc)


async def _rehydrate_stepup(code: str) -> dict | None:
    """Rebuild an in-flight step-up from the directory after a restart."""
    if not PROOFING_DIRECTORY_URL:
        return None
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.get(f"{PROOFING_DIRECTORY_URL}/consents/{code}")
        if r.status_code != 200:
            return None
        d = r.json()
        det = (d.get("authorizationDetails") or d.get("authorization_details") or [{}])[0]
        su = {"code": code, "txn": code, "subject": d.get("subject", ""),
              "amount": str(d.get("amount") or ""), "currency": d.get("currency") or "AUD",
              "debtor": d.get("debtorAccount") or "", "creditor": d.get("creditorAccount") or "",
              "scope": det.get("scope", ""), "hash": det.get("transactionHash", ""),
              "auth_req_id": det.get("authReqId", ""),
              "authz_type": AUTHZ_TYPE_RESOURCE,
              "status": "approved" if d.get("status") == "authorized" else "pending",
              "created": int(time.time())}
        _STEPUPS[code] = su
        logger.info("rehydrated step-up %s from the directory after restart", code)
        return su
    except Exception as exc:  # noqa: BLE001
        logger.warning("stepup rehydrate failed for %s: %s", code, exc)
        return None


async def _register_for_device(su: dict) -> None:
    """Publish the pending RESOURCE AUTHORISATION where the approver app resolves pushed codes.
    The app reads consent detail from the autonomous-agent, not from here, so without this the
    phone receives the push and finds nothing for the code."""
    try:
        headers = {"X-Register-Secret": APPROVER_REGISTER_SECRET} if APPROVER_REGISTER_SECRET else {}
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.post(f"{APPROVER_CONSENT_URL}/consent", headers=headers, json={
                "code": su["code"], "approver": su["subject"], "paymentId": su["txn"],
                "transactionId": su["txn"], "amount": su.get("amount") or 0,
                "currency": su.get("currency") or "AUD",
                "debtorAccount": su.get("debtor") or "",
                "creditorAccount": su.get("creditor") or "",
                "requestedBy": "Demo Bank (interactive step-up)"})
            logger.info("registered step-up %s for device: %s", su["code"], r.status_code)
    except Exception as exc:  # noqa: BLE001 — never block the push
        logger.warning("device registration failed for %s: %s", su.get("code"), exc)


async def _ciba_poll(auth_req_id: str) -> str:
    """Has the user approved on their device yet? RFC-correct CIBA: the client POLLS the token
    endpoint with the auth_req_id.

        "pending"   authorization_pending / slow_down  -> keep waiting
        "approved"  200                                -> the user tapped approve
        "denied"    access_denied
        "expired"   expired_token

    We do NOT keep the minted token: PF's CIBA grant falls through to a DEFAULT mapping whose
    subject is fixed (ciba.tf), so the token is not usable as this user. We only need the
    APPROVAL SIGNAL — the evidence is the device interaction, not the token."""
    pem = os.environ.get("CIBA_CLIENT_KEY_PEM", "")
    if not pem or not auth_req_id:
        return "pending"
    token_url = CIBA_ENDPOINT.replace("/as/bc-auth.ciba", "/as/token.oauth2")
    form = {"grant_type": "urn:openid:params:grant-type:ciba", "auth_req_id": auth_req_id,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": _ciba_assertion(token_url)}
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as c:
            r = await c.post(token_url, data=form)
        if r.status_code == 200:
            return "approved"
        err = ""
        try:
            err = (r.json() or {}).get("error", "")
        except Exception:  # noqa: BLE001
            err = r.text[:80]
        if err in ("authorization_pending", "slow_down"):
            return "pending"
        if err == "access_denied":
            return "denied"
        if err in ("expired_token", "invalid_grant"):
            return "expired"
        logger.info("ciba poll %s: %s %s", auth_req_id[:8], r.status_code, err)
        return "pending"
    except Exception as exc:  # noqa: BLE001
        logger.warning("ciba poll failed: %s", exc)
        return "pending"


async def _authz_channel(user: str) -> str:
    """Which channel should carry an authorisation request for this user?

        "device"  a paired authenticator exists -> CIBA push, cross-device
        "local"   no usable authenticator      -> do it HERE, on this device

    ONE decision for every authorisation type (resource_authorisation, consent,
    identity_proofing) so the branch cannot drift per flow — /proofing/begin used to push
    unconditionally, which sent a device-less user a notification that could never arrive.

    Local must mean SAME-DEVICE, never a QR to a second device: if the user has no phone
    paired, telling them to scan something with a phone is the one instruction guaranteed
    not to help. For mDL that means the browser's Digital Credentials API picker."""
    return "device" if await _device_paired(user) else "local"


async def _device_paired(user: str) -> bool:
    """Does this user have a usable (paired) authenticator right now? The identity store
    is the record; /identities/{user}/reconcile refreshes it from PingOne."""
    if not user:
        return False
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.get(f"{PROOFING_DIRECTORY_URL}/scim/v2/Users",
                            params={"filter": f'userName eq "{user}"'})
            for u in (r.json().get("Resources") or []):
                # Read the extension by SHAPE, not by a hardcoded URN. The directory emits
                # urn:idpartners:scim:1.0:BankUser; hardcoding a different URN here made this
                # silently return False for EVERY user, so nobody ever took the device path.
                for k, v in u.items():
                    if k.startswith("urn:") and isinstance(v, dict) and "devicePaired" in v:
                        return bool(v.get("devicePaired"))
                return False
    except Exception as exc:  # noqa: BLE001
        logger.warning("device-paired lookup failed for %s: %s", user, exc)
    return False  # fail to the LOCAL path: never assume a device exists


@app.post("/stepup/begin")
async def stepup_begin(request: Request):
    """Adaptive step-up entry. Returns the mode the caller must drive."""
    s = _session(request)
    subject = (s or {}).get("sub") or ""
    if not subject:
        return JSONResponse(status_code=401, content={"error": "login_required"})
    body = {}
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        pass
    su = {"subject": subject, "scope": body.get("scope") or "banking:payments:transfer",
          "amount": str(body.get("amount") or ""), "currency": body.get("currency") or "AUD",
          "debtor": body.get("from") or "", "creditor": body.get("to") or ""}

    if await _authz_channel(subject) != "device":
        # No usable authenticator → local passkey. Labelled as the weaker path.
        return {"mode": "local", "assurance": ASSURANCE_APP_ASSERTED, "bound": False,
                "reason": "no paired device",
                "note": "browser passkey signs a random challenge; it does not bind to this payment"}

    code = "PAY-" + secrets.token_hex(3)  # ≤20 chars, CIBA binding_message charset-safe
    su.update({"code": code, "txn": "txn_" + secrets.token_hex(6),
               "hash": _txn_hash(su), "status": "pending", "created": int(time.time()),
               "authz_type": AUTHZ_TYPE_RESOURCE})
    _STEPUPS[code] = su
    await _register_for_device(su)                  # so the phone can resolve the code
    pushed, detail = await _ciba_push(subject, code)
    su["auth_req_id"] = detail if pushed else ""    # needed to poll for the approval
    await _persist_stepup(su)                       # survive a restart mid-approval
    if not pushed:
        logger.warning("stepup ciba push failed for %s: %s", subject, detail)
        return {"mode": "local", "assurance": ASSURANCE_APP_ASSERTED, "bound": False,
                "reason": f"push failed: {detail}"}
    return {"mode": "ciba", "code": code, "txn": su["txn"], "hash": su["hash"],
            "assurance": ASSURANCE_DEVICE_SIGNED, "bound": True}


@app.get("/stepup/code/{code}")
async def stepup_code(code: str, request: Request):
    """The approver app pulls the FULL instruction by the pushed code — the push itself
    carries only 20 characters, so the detail the user sees comes from here."""
    user = _device_user(request)
    su = _STEPUPS.get(code)
    if not su:
        return JSONResponse(status_code=404, content={"error": "unknown code"})
    if user and user != su["subject"]:
        return JSONResponse(status_code=403, content={"error": "not your step-up"})
    return {"code": code, "type": su.get("authz_type", AUTHZ_TYPE_RESOURCE),
            "txn": su["txn"], "hash": su["hash"], "subject": su["subject"],
            "amount": su["amount"], "currency": su["currency"],
            "debtorAccount": su["debtor"], "creditorAccount": su["creditor"],
            "status": su["status"]}


@app.post("/stepup/approve")
async def stepup_approve(request: Request):
    """The paired device approves. A signature over `hash` is what makes this binding;
    without one the approval is recorded at the WEAKER device-approved level. A Recognize
    verdict (recognizeVerified / recognizeAssertion — see _recognize_verdict) OUTRANKS both:
    it is evidence of WHO approved, not just that a paired device did, and takes the top
    rung of the ladder regardless of whether a signature also came along."""
    user = _device_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "device token required"})
    body = await request.json()
    su = _STEPUPS.get(str(body.get("code") or ""))
    if not su:
        return JSONResponse(status_code=404, content={"error": "unknown code"})
    if user != su["subject"]:
        return JSONResponse(status_code=403, content={"error": "not your step-up"})

    signature = str(body.get("signature") or "")
    # Pass the step-up record so the assertion is checked against THIS payment, not merely
    # verified as genuine. `su` is the server's own copy (from the CIBA push) — never anything
    # the approving device supplied, or the binding would be self-attested and worthless.
    recognized = _recognize_verdict(body, expected=su)
    su["status"] = "approved"
    if recognized:
        su["assurance"] = ASSURANCE_RECOGNIZE_VERIFIED
    else:
        su["assurance"] = ASSURANCE_DEVICE_SIGNED if signature else ASSURANCE_DEVICE_APPROVED
    su["signature"] = signature
    su["recognize_verified"] = recognized
    su["approved_at"] = int(time.time())

    # Retain the ARTEFACT, not a boolean: the dispute layer needs what was signed.
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            await c.post(f"{PROOFING_DIRECTORY_URL}/consents", json={
                "transaction_id": su["txn"], "subject": su["subject"], "actor": su["subject"],
                "channel": "ciba-device", "status": "authorized",
                "amount": float(su["amount"] or 0), "currency": su["currency"],
                "debtor_account": su["debtor"], "creditor_account": su["creditor"],
                "authorization_details": [{"type": "payment_initiation",
                                           "transactionHash": su["hash"],
                                           "signature": signature,
                                           "assurance": su["assurance"]}]})
    except Exception as exc:  # noqa: BLE001 — never block the approval
        logger.warning("stepup consent record failed: %s", exc)
    return {"ok": True, "txn": su["txn"], "assurance": su["assurance"]}


@app.get("/stepup/status/{code}")
async def stepup_status(code: str):
    """The browser polls this while the phone is being tapped.

    The approver app completes the PingOne device authentication and reports to the
    autonomous-agent — it never calls /stepup/approve, so waiting for that alone left the
    browser polling forever after a successful approval. We ask the AS instead: CIBA is
    defined as the client polling the token endpoint for the outcome."""
    su = _STEPUPS.get(code) or await _rehydrate_stepup(code)
    if not su:
        return JSONResponse(status_code=404, content={"error": "unknown code"})

    if su.get("status") == "pending" and su.get("auth_req_id"):
        outcome = await _ciba_poll(su["auth_req_id"])
        if outcome == "approved":
            su["status"] = "approved"
            # device-APPROVED, not device-SIGNED: the phone proved presence and intent on a
            # trusted device, but it did not sign over _txn_hash, so this is not dynamically
            # linked to THIS payment. Recording it as signed would overstate the evidence.
            su.setdefault("assurance", ASSURANCE_DEVICE_APPROVED)
            su["approved_at"] = int(time.time())
            logger.info("stepup %s approved on device (assurance=%s)", code, su["assurance"])
            try:
                async with httpx.AsyncClient(timeout=8.0) as c:
                    await c.patch(f"{PROOFING_DIRECTORY_URL}/consents/{code}",
                                  json={"status": "authorized"})
            except Exception as exc:  # noqa: BLE001
                logger.warning("consent advance failed for %s: %s", code, exc)
        elif outcome in ("denied", "expired"):
            su["status"] = outcome
            logger.info("stepup %s %s on device", code, outcome)

    return {"code": code, "status": su["status"], "txn": su["txn"],
            "type": su.get("authz_type", AUTHZ_TYPE_RESOURCE),
            "assurance": su.get("assurance", "")}


# The DaVinci-hosted consent screen, used on the NO-DEVICE path. The amount and payee are
# rendered by a DaVinci flow (config-as-code, demo/davinci/) rather than by this app, so the
# consent screen is owned by the orchestration layer and is consistent with the passkey UX.
#
# ASSURANCE: this changes WHERE consent is captured, not what the signature covers. The
# browser passkey that follows still signs a RANDOM challenge, so this path remains
# app-asserted and NOT non-repudiable. Only the paired-device path binds (see _txn_hash).
# demo/TRANSACTION-AUTHORIZATION.md sections 2 and 6.
DAVINCI_CONSENT_POLICY_ID = os.environ.get(
    "DAVINCI_CONSENT_POLICY_ID", "122354553b1301f114619a576c4e57fc")

_DAVINCI_CONSENT_HTML = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approve payment — Demo Bank</title>
<style>body{font-family:-apple-system,system-ui,sans-serif;background:#101418;color:#e8e8e8;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1a2027;border:1px solid #2a323c;border-radius:14px;padding:28px;width:420px}
.brand{font-size:20px;font-weight:700;margin:0 0 4px}
.sub{color:#9aa5b1;font-size:13px;margin:0 0 18px}
#widget{min-height:200px}#msg{font-size:13px;margin-top:12px;min-height:18px;color:#ff8b7b}
.vendor{margin-top:18px;padding-top:14px;border-top:1px solid #2a323c;color:#9aa5b1;
font-size:11px;display:flex;align-items:center;justify-content:center;gap:7px}.vendor img{height:18px}</style>
</head><body>
<div class="card">
  <div class="brand">🏦 Demo Bank</div>
  <div class="sub">Payment approval — presented by <b>PingOne DaVinci</b>.</div>
  <div id="detail" style="background:#141a22;border:1px solid #2a323c;border-radius:10px;
       padding:16px;margin-bottom:16px">
    <div id="amt" style="font-size:26px;font-weight:600"></div>
    <div id="to" style="color:#9aa5b1;font-size:13px;margin-top:4px"></div>
    <div id="from" style="color:#6b7684;font-size:12px;margin-top:2px"></div>
  </div>
  <div id="widget"></div>
  <div id="msg"></div>
  <div class="vendor">Powered by <img src="/static/idp-wordmark.svg" alt="ID Partners"></div>
</div>
<script src="__ASSETS__/davinci/latest/davinci.js"></script>
<script>
const msg = t => { document.getElementById('msg').textContent = t || ''; };
async function run(){
  let cfg;
  try { cfg = await fetch('/stepup/consent/token').then(r=>r.json()); }
  catch(e){ msg('Could not reach the flow service.'); return; }
  if(cfg.error){ msg('Consent flow is not configured.'); return; }
  const p = cfg.parameters || {};
  document.getElementById('amt').textContent  = (p.currency||'') + ' ' + (p.amount||'');
  document.getElementById('to').textContent   = p.creditor ? ('to ' + p.creditor) : '';
  document.getElementById('from').textContent = p.debtor ? ('from ' + p.debtor) : '';
  if(!window.davinci || !window.davinci.skRenderScreen){ msg('Widget SDK failed to load.'); return; }
  window.davinci.skRenderScreen(document.getElementById('widget'), {
    // NOTE: no `parameters` key here. DaVinci rejects unknown keys in the runFlow body
    // ("Flow error: Body contains additional parameters"), the same way PUT /flows rejects
    // extra properties. The payment detail is rendered by THIS page instead (below); the
    // flow owns the decision, not the display, until the flow fetches the detail itself.
    config: { method:'runFlow', apiRoot: cfg.apiRoot, accessToken: cfg.accessToken,
              companyId: cfg.companyId, policyId: cfg.policyId },
    useModal: false,
    successCallback: async function(response){
      try {
        const r = await fetch('/stepup/consent/finish', {method:'POST',
          headers:{'content-type':'application/json'},
          body: JSON.stringify(response||{})}).then(r=>r.json());
        location.href = r.next || '/';
      } catch(e){ msg('Could not record the decision: '+e.message); }
    },
    errorCallback: function(e){ msg('Flow error: '+(e && e.message ? e.message : JSON.stringify(e))); }
  });
}
run();
</script></body></html>"""


@app.get("/stepup/consent")
async def stepup_consent(request: Request):
    """Render the DaVinci consent screen for the pending step-up (no-device path)."""
    if not _verify(request.cookies.get(STEPUP_COOKIE)):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(_DAVINCI_CONSENT_HTML.replace("__ASSETS__", DAVINCI_ASSETS_ROOT))


@app.get("/stepup/consent/token")
async def stepup_consent_token(request: Request):
    """sdkToken + the payment the flow must display. The SK API key never reaches JS."""
    su = _verify(request.cookies.get(STEPUP_COOKIE)) or {}
    if not DAVINCI_CONSENT_POLICY_ID:
        return JSONResponse(status_code=502, content={"error": "consent_policy_unconfigured"})
    tok = await _davinci_sdktoken()
    if not tok:
        return JSONResponse(status_code=502, content={"error": "davinci_unconfigured"})
    return {"accessToken": tok, "companyId": DAVINCI_COMPANY_ID,
            "policyId": DAVINCI_CONSENT_POLICY_ID, "apiRoot": DAVINCI_API_ROOT + "/",
            "parameters": {"amount": su.get("amount", ""), "currency": su.get("currency", "AUD"),
                           "creditor": su.get("creditor", ""), "debtor": su.get("debtor", "")}}


@app.post("/stepup/consent/finish")
async def stepup_consent_finish(request: Request):
    """The DaVinci flow returned approve or decline. Approve continues to the passkey
    ceremony, which authenticates the user and records the consent as today."""
    su = _verify(request.cookies.get(STEPUP_COOKIE)) or {}
    body = {}
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        pass
    # Read the DECISION, not a substring of the whole payload. The screen defines BOTH an
    # "approve" and a "decline" button, and the flow's success response echoes both, so a
    # blob scan for "decline not in blob" flagged EVERY approval as a decline — the payment
    # loop. The skbutton writes the clicked value into a "buttonValue" field; find that.
    def _decision(o) -> str:
        if isinstance(o, dict):
            for k, v in o.items():
                if k.lower() in ("buttonvalue", "svalue", "value") and isinstance(v, str) \
                   and v.lower() in ("approve", "decline"):
                    return v.lower()
                d = _decision(v)
                if d:
                    return d
        elif isinstance(o, list):
            for v in o:
                d = _decision(v)
                if d:
                    return d
        return ""
    decision = _decision(body)
    approved = decision == "approve"

    # Was there ALSO a Recognize verification screen in this flow, and did it pass? This is
    # additive to the button decision — Recognize failing does not itself imply "decline";
    # the flow's own screen decides whether a failed check blocks the Approve button at all.
    recognized = _deep_recognize_field(body)

    logger.info("davinci consent decision=%r approved=%s recognized=%s subject=%s | raw=%s",
                decision or "unknown", approved, recognized, su.get("subject"), json.dumps(body)[:400])
    if not approved:
        # A DECLINE is a real decision and belongs in the directory. Recording only
        # approvals leaves a record that cannot distinguish "refused" from "never asked".
        await _record_consent_decision(su, su.get("subject", ""), "declined")
        return {"ok": False, "decision": "declined", "next": "/"}
    hint = "?stepup=1" + (("&u=" + urllib.parse.quote(su.get("subject", ""))) if su.get("subject") else "")
    resp = JSONResponse({"ok": True, "decision": "approved", "next": "/signup" + hint})
    if recognized:
        # Carry the verdict forward on the SAME cookie the passkey ceremony reads (su, +600s
        # TTL matching the original set_cookie calls) so _record_stepup_consent — which runs
        # after the ceremony, not here — writes recognize-verified instead of defaulting to
        # app-asserted. Without this, a passed Recognize check on the no-device path would be
        # thrown away the moment the flow handed off to the passkey ceremony.
        resp.set_cookie(STEPUP_COOKIE, _sign({**su, "assurance": ASSURANCE_RECOGNIZE_VERIFIED}, 600),
                        httponly=True, secure=True, samesite="lax", max_age=600)
    return resp


@app.get("/stepup/complete")
async def stepup_complete(code: str = ""):
    """After the device approves, elevate the browser session — same signupTE broker the
    passkey path uses, so the elevated scope reaches the gateway PEP identically. The
    DIFFERENCE from the passkey path is the evidence behind it: a signature over this
    payment, not a random challenge."""
    su = _STEPUPS.get(code)
    if not su:
        return JSONResponse(status_code=404, content={"error": "unknown code"})
    if su.get("status") != "approved":
        return JSONResponse(status_code=409, content={"error": "not approved yet"})
    user = su["subject"]
    await _project_delegation_grant(user, su["scope"], su["txn"],
                                    assurance=su.get("assurance", ASSURANCE_APP_ASSERTED))
    pf_at = await _broker_passkey_to_pf(user, extra_scope=su["scope"])
    logger.info("stepup complete via device: subject=%s txn=%s assurance=%s",
                user, su["txn"], su.get("assurance"))
    return _passkey_session_response(user, pf_at)


# The browser's "check your phone" page. It polls the step-up, then completes (which
# elevates the session) and returns to the chat, where resumePending() replays the payment.
_STEPUP_WAIT_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>Approve on your phone</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0b1020;color:#e8ecf7;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.c{max-width:420px;text-align:center;padding:32px;background:#141a2f;border-radius:16px}
.a{font-size:32px;font-weight:600;margin:12px 0}.m{color:#94a3b8;font-size:14px;line-height:1.5}
.code{letter-spacing:2px;font-family:ui-monospace,monospace;background:#0b1020;padding:8px 14px;
border-radius:8px;display:inline-block;margin-top:14px}.s{margin-top:18px;font-size:13px;color:#7dd3fc}</style>
</head><body><div class="c">
<div style="font-size:40px">📲</div>
<div class="a">__AMOUNT__ __CUR__</div>
<div class="m">to <b>__TO__</b><br><br>We've sent this payment to your paired device.
Open the approver app to see the full details and approve it there.</div>
<div class="code">__CODE__</div>
<div class="s" id="s">Waiting for approval…</div></div>
<script>
const code = "__CODE__";
async function poll(){
  try{
    const r = await fetch('/stepup/status/'+code);
    if(r.ok){
      const d = await r.json();
      if(d.status === 'denied' || d.status === 'expired'){
        document.getElementById('s').textContent = 'Declined or expired — returning…';
        setTimeout(()=>location.href='/', 1200); return;
      }
      if(d.status === 'approved'){
        document.getElementById('s').textContent = 'Approved ('+(d.assurance||'')+') — continuing…';
        await fetch('/stepup/complete?code='+encodeURIComponent(code));
        location.href = '/';
        return;
      }
    }
  }catch(e){}
  setTimeout(poll, 2000);
}
poll();
</script></body></html>"""


@app.get("/login")
async def login(request: Request):
    """Send the user to the PASSKEY ceremony (/signup) — the only authentication path.

    A `?stepup=<scope>` request is a step-up (RFC 9470) for a risky action: the elevated
    scope AND the specific payment ride across the ceremony in a short-lived signed cookie,
    and the scope is granted on the signupTE exchange in the passkey-finish handler.

    NOTE — no RAR here. The PF authorization-code + PAR (RFC 9126) + RFC 9396
    authorization_details step-up was REMOVED when this went passwordless, so the payment
    detail does NOT reach the token. The PDP instead reads a recorded consent via the
    ConsentDirectory policy-information provider — which is app-asserted and NOT
    non-repudiable. See demo/TRANSACTION-AUTHORIZATION.md sections 2 and 6; restoring real
    binding is the CIBA + RAR work in section 6 step 2.
    """
    stepup = (request.query_params.get("stepup") or "").strip()
    # BOTH the front door AND the payment step-up are now PASSWORDLESS via the same WebAuthn
    # passkey page. There are no passwords anywhere. The step-up difference is only the OUTCOME:
    # the passkey ceremony (assertion acr=urn:northwind:loa:passkey) is the step-up authentication,
    # and the requested elevated scope is carried across it in a short-lived signed cookie, then
    # granted on the signupTE exchange in the passkey-finish handler. The old PF authorization-code
    # + PAR/RAR redirect (which forced PF's htmlform password page) is retired for the step-up;
    # RAR consent no longer lives on a PF page (accepted trade-off — the elevated scope is what
    # gates the payment at the gateway PEP).
    # Carry the step-up across the passkey ceremony in a signed cookie: the elevated scope
    # AND the specific payment (amount/creditor/debtor). On passkey-finish we record this as an
    # AUTHORIZED consent in the consent directory — the passkey IS the acceptance. The payment
    # request then returns through the gateway to the PDP, which looks the consent up (a policy
    # information provider on the consent directory) and permits. The consent lives in the DB,
    # not in the token — mirroring the mDL identity-proofing gate.
    sess = _session(request)
    subject = (sess or {}).get("sub") or ""

    # ADAPTIVE BRANCH. A step-up for a user who HAS a paired device goes to that device
    # over CIBA — the phone shows the amount + payee it pulled from us and signs over the
    # transaction hash. Only a user with NO usable device falls through to the local
    # browser passkey, which cannot bind to the payment.
    fallback_from_device = False
    if stepup and subject:
        qp = request.query_params
        su = {"subject": subject, "scope": stepup,
              "amount": (qp.get("amount") or "").strip(),
              "currency": (qp.get("cur") or "AUD").strip(),
              "debtor": (qp.get("from") or "").strip(),
              "creditor": (qp.get("to") or "").strip()}
        if await _authz_channel(subject) == "device":
            code = "PAY-" + secrets.token_hex(3)
            su.update({"code": code, "txn": "txn_" + secrets.token_hex(6),
                       "hash": _txn_hash(su), "status": "pending",
                       "created": int(time.time())})
            _STEPUPS[code] = su
            await _register_for_device(su)          # so the phone can resolve the code
            pushed, detail = await _ciba_push(subject, code)
            su["auth_req_id"] = detail if pushed else ""   # needed to poll for the approval
            await _persist_stepup(su)                       # survive a restart mid-approval
            if pushed:
                logger.info("stepup -> CIBA device push subject=%s code=%s", subject, code)
                return HTMLResponse(_STEPUP_WAIT_HTML
                                    .replace("__CODE__", code)
                                    .replace("__AMOUNT__", su["amount"])
                                    .replace("__CUR__", su["currency"])
                                    .replace("__TO__", su["creditor"]))
            # PUSH FAILED for a PAIRED user. Fall back to a LOCAL check on this device rather
            # than dead-ending — but do NOT pretend it was a clean local flow. We have LOST the
            # cross-device security property (the approval no longer happens on a separate
            # trusted device). Record that explicitly so:
            #   - the audit trail shows a downgraded authorisation, not a normal one, and
            #   - a future compensating control (a re-auth, a lower amount cap, a second factor
            #     on THIS device) can key off channel == "local-fallback-from-device".
            logger.warning("stepup push failed (%s) — DOWNGRADING to a local check for %s",
                           detail, subject)
            try:
                async with httpx.AsyncClient(timeout=8.0) as c:
                    await c.patch(f"{PROOFING_DIRECTORY_URL}/consents/{code}",
                                  json={"status": "failed"})   # retire the un-pushed device record
            except Exception:  # noqa: BLE001
                pass
            fallback_from_device = True

    # No usable device (or a push that could not be delivered). Capture the consent in the
    # DaVinci flow FIRST (config-as-code, consistent with the passkey UX), then continue to the
    # passkey ceremony which authenticates and records it. Falls through to the passkey directly
    # if the consent flow isn't configured, so an unconfigured tenant can't dead-end the demo.
    if stepup and subject and DAVINCI_CONSENT_POLICY_ID:
        resp = RedirectResponse("/stepup/consent", status_code=302)
        qp = request.query_params
        resp.set_cookie(STEPUP_COOKIE, _sign(
            {"scope": stepup, "subject": subject,
             "channel": "local-fallback-from-device" if fallback_from_device else "davinci-consent",
             "amount": (qp.get("amount") or "").strip(),
             "currency": (qp.get("cur") or "AUD").strip(),
             "debtor": (qp.get("from") or "").strip(),
             "creditor": (qp.get("to") or "").strip()}, 600),
            httponly=True, secure=True, samesite="lax", max_age=600)
        return resp

    hint = "?stepup=1" + (("&u=" + urllib.parse.quote(subject)) if subject else "")
    resp = RedirectResponse("/signup" + (hint if stepup else ""), status_code=302)
    if stepup:
        qp = request.query_params
        payload = {"scope": stepup, "subject": subject,
                   "amount": (qp.get("amount") or "").strip(),
                   "currency": (qp.get("cur") or "AUD").strip(),
                   "debtor": (qp.get("from") or "").strip(),
                   "creditor": (qp.get("to") or "").strip()}
        resp.set_cookie(STEPUP_COOKIE, _sign(payload, 600),
                        httponly=True, secure=True, samesite="lax", max_age=600)
    return resp


@app.get("/me")
def me(request: Request):
    s = _session(request)
    if not s:
        return JSONResponse(status_code=401, content={"error": "not signed in"})
    return {"principal": {"sub": s.get("sub"), "name": s.get("name"), "acr": s.get("acr")}}


# ── Sign-up: self-service registration + PASSKEY at PingOne, brokered into PF ────────
# New customers register at PingOne (sign-on policy Bank_Signup_Passkey: create account →
# enrol a passkey). The BFF then EXCHANGES the PingOne ID token at PF (RFC 8693, policy
# signupTE) for a first-class PF user token — same userJwtATM shape as alice's login —
# so the whole delegation chain works for the new user unchanged.
SIGNUP_CLIENT_ID = os.environ.get("SIGNUP_CLIENT_ID", "")
SIGNUP_CLIENT_SECRET = os.environ.get("SIGNUP_CLIENT_SECRET", "")
SIGNUP_TX_COOKIE = "nw_signup_tx"

# ── DaVinci-hosted passkeys (the WIDGET path) ──────────────────────────────────────────────
# The PingOne↔DaVinci /as/authorize bridge is dead in this env (no console/API repair exists —
# see the davinci-pingone-integration skill), so the demo can't reach DaVinci passkey flows via
# the hosted redirect. The WIDGET path bypasses the bridge: the BFF mints a DaVinci sdkToken with
# the "PingOne SSO Connection" app's SK API key and embeds the DaVinci widget, which runs the
# flow (Bank Signup Passkey Live) directly. PingOne MFA verifies the WebAuthn assertion inside the
# flow — so PingOne is AUTHORITATIVE for the passkey, unlike the BFF-native front door. On flow
# success the BFF brokers to PF via signupTE, unchanged. Gated behind ?davinci=1 so the working
# native front door is untouched.
DAVINCI_SK_API_KEY = os.environ.get("DAVINCI_SK_API_KEY", "")
DAVINCI_COMPANY_ID = os.environ.get("DAVINCI_COMPANY_ID", "")
DAVINCI_POLICY_ID = os.environ.get("DAVINCI_POLICY_ID", "")
DAVINCI_API_ROOT = os.environ.get("DAVINCI_API_ROOT", "https://auth.pingone.asia").rstrip("/")
DAVINCI_ASSETS_ROOT = os.environ.get("DAVINCI_ASSETS_ROOT", "https://assets.pingone.asia").rstrip("/")

# Third sign-on option: PingOne Recognize (biometric), via the "Recognize Sign-On (simulated)"
# DaVinci flow — same widget-embed mechanism as the passkey-via-DaVinci option above, pointed at
# a different flow policy. Unlike that option, PingOne is NOT what's authenticating here (there's
# no real Recognize tenant yet — see RECOGNIZE_SIMULATE); the flow only carries the verification
# UX, and /signup/recognize/finish (below) still requires the named user to already exist and
# have a passkey before brokering a session, so a Recognize pass alone can't sign in as anyone.
DAVINCI_RECOGNIZE_SIGNIN_POLICY_ID = os.environ.get(
    "DAVINCI_RECOGNIZE_SIGNIN_POLICY_ID", "8376b8aadec32fcdaa4ccdb2911b6c4c")


async def _davinci_sdktoken() -> str:
    """Mint a DaVinci sdkToken (usage=startSpecificFlowOrPolicyNonUserContext) with the SK API
    key. The key stays server-side; only the short-lived (30 min) token reaches the browser.
    NOTE: the path is lowercase `sdktoken` — wrong case = APIGW 403 'Missing Authentication'."""
    if not (DAVINCI_SK_API_KEY and DAVINCI_COMPANY_ID):
        return ""
    root = DAVINCI_API_ROOT.replace("://auth.", "://orchestrate-api.")
    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.get(f"{root}/v1/company/{DAVINCI_COMPANY_ID}/sdktoken",
                        headers={"X-SK-API-KEY": DAVINCI_SK_API_KEY})
        if r.status_code != 200:
            logger.warning("davinci sdktoken %s: %s", r.status_code, r.text[:200])
            return ""
        return r.json().get("access_token", "")


# DaVinci widget front door (PingOne verifies the passkey). Loads the DaVinci widget SDK, fetches
# a server-minted sdkToken, runs the policy, and on success brokers the user into PF via the BFF.
_DAVINCI_HTML = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in — Demo Bank</title>
<style>body{font-family:-apple-system,system-ui,sans-serif;background:#101418;color:#e8e8e8;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1a2027;border:1px solid #2a323c;border-radius:14px;padding:28px;width:400px}
.brand{font-size:20px;font-weight:700;margin:0 0 4px}
.sub{color:#9aa5b1;font-size:13px;margin:0 0 18px}
#widget{min-height:120px}
#msg{font-size:13px;margin-top:12px;min-height:18px;color:#ff8b7b}
.vendor{margin-top:18px;padding-top:14px;border-top:1px solid #2a323c;color:#9aa5b1;
font-size:11px;display:flex;align-items:center;justify-content:center;gap:7px}.vendor img{height:18px}
a.alt{color:#7fb0ff;font-size:12px;text-decoration:none;display:block;margin-top:10px;text-align:center}</style>
</head><body>
<div class="card">
  <div class="brand">🏦 Demo Bank</div>
  <div class="sub">Passwordless — your passkey is verified by <b>PingOne</b> (DaVinci flow).</div>
  <div id="widget"></div>
  <div id="msg"></div>
  <a class="alt" href="/signup">Use the app-native passkey instead →</a>
  <div class="vendor">Powered by <img src="/static/idp-wordmark.svg" alt="ID Partners"></div>
</div>
<script src="__ASSETS__/davinci/latest/davinci.js"></script>
<script>
const msg = t => { document.getElementById('msg').textContent = t || ''; };
async function run(){
  let cfg;
  try { cfg = await fetch('/signup/davinci/token').then(r=>r.json()); }
  catch(e){ msg('Could not reach the flow service.'); return; }
  if(cfg.error){ msg('DaVinci is not configured for this environment.'); return; }
  if(!window.davinci || !window.davinci.skRenderScreen){ msg('Widget SDK failed to load.'); return; }
  window.davinci.skRenderScreen(document.getElementById('widget'), {
    config: { method:'runFlow', apiRoot: cfg.apiRoot, accessToken: cfg.accessToken,
              companyId: cfg.companyId, policyId: cfg.policyId },
    useModal: false,
    successCallback: async function(response){
      try {
        const r = await fetch('/signup/davinci/finish', {method:'POST',
          headers:{'content-type':'application/json'}, body: JSON.stringify(response||{})}).then(r=>r.json());
        if(r.ok){ msg('✓ Signed in…'); setTimeout(()=>location.href=(r.next||'/'), 400); }
        else { msg((r.detail||r.error||'Sign-in failed')); }
      } catch(e){ msg('Broker failed: '+e.message); }
    },
    errorCallback: function(e){ msg('Flow error: '+(e && e.message ? e.message : JSON.stringify(e))); }
  });
}
run();
</script></body></html>"""


# PingOne Recognize sign-in widget. Same skRenderScreen embed mechanism as _DAVINCI_HTML, pointed
# at DAVINCI_RECOGNIZE_SIGNIN_POLICY_ID instead. The username is rendered SERVER-SIDE (like
# _payment_summary_html does for the payment amount) rather than passed into the flow itself —
# the widget's runFlow config has no `parameters` key (DaVinci rejects unknown keys in the runFlow
# body), so per-request personalisation has to happen on this wrapper page, not inside the flow.
_RECOGNIZE_SIGNIN_HTML = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in with Recognize — Demo Bank</title>
<style>body{font-family:-apple-system,system-ui,sans-serif;background:#101418;color:#e8e8e8;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1a2027;border:1px solid #2a323c;border-radius:14px;padding:28px;width:400px}
.brand{font-size:20px;font-weight:700;margin:0 0 4px}
.sub{color:#9aa5b1;font-size:13px;margin:0 0 18px}.sub b{color:#e8e8e8}
#widget{min-height:120px}
#msg{font-size:13px;margin-top:12px;min-height:18px;color:#ff8b7b}
.vendor{margin-top:18px;padding-top:14px;border-top:1px solid #2a323c;color:#9aa5b1;
font-size:11px;display:flex;align-items:center;justify-content:center;gap:7px}.vendor img{height:18px}
a.alt{color:#7fb0ff;font-size:12px;text-decoration:none;display:block;margin-top:10px;text-align:center}</style>
</head><body>
<div class="card">
  <div class="brand">🏦 Demo Bank</div>
  <div class="sub">Signing in as <b>__USER__</b> — verified by <b>PingOne Recognize</b>.</div>
  <div id="widget"></div>
  <div id="msg"></div>
  <a class="alt" href="/signup">Use a passkey instead →</a>
  <div class="vendor">Powered by <img src="/static/idp-wordmark.svg" alt="ID Partners"></div>
</div>
<script src="__ASSETS__/davinci/latest/davinci.js"></script>
<script>
const msg = t => { document.getElementById('msg').textContent = t || ''; };
const username = "__USER__";
async function run(){
  let cfg;
  try { cfg = await fetch('/signup/recognize/token').then(r=>r.json()); }
  catch(e){ msg('Could not reach the flow service.'); return; }
  if(cfg.error){ msg('Recognize sign-in is not configured for this environment.'); return; }
  if(!window.davinci || !window.davinci.skRenderScreen){ msg('Widget SDK failed to load.'); return; }
  window.davinci.skRenderScreen(document.getElementById('widget'), {
    config: { method:'runFlow', apiRoot: cfg.apiRoot, accessToken: cfg.accessToken,
              companyId: cfg.companyId, policyId: cfg.policyId },
    useModal: false,
    successCallback: async function(response){
      try {
        const r = await fetch('/signup/recognize/finish', {method:'POST',
          headers:{'content-type':'application/json'},
          body: JSON.stringify({response: response||{}, username})}).then(r=>r.json());
        if(r.ok){ msg('✓ Signed in…'); setTimeout(()=>location.href=(r.next||'/'), 400); }
        else { msg((r.detail||r.error||'Sign-in failed')); }
      } catch(e){ msg('Broker failed: '+e.message); }
    },
    errorCallback: function(e){ msg('Flow error: '+(e && e.message ? e.message : JSON.stringify(e))); }
  });
}
run();
</script></body></html>"""


# The REAL PingOne Recognize screen: the actual Keyless Web SDK doing a live face match, not a
# DaVinci stand-in. Served only when recognize_real_configured() (see above); otherwise the
# simulated DaVinci screen above is used.
#
# `transaction-data` is the PSD2 dynamic-linking hook: the SDK binds the biometric check to THIS
# instruction, so the resulting JWT attests to what was approved rather than merely that someone
# passed a face match at some point. That is the property demo/TRANSACTION-AUTHORIZATION.md says
# the browser-passkey path can never have, so it is passed whenever a payment is in flight.
_RECOGNIZE_REAL_HTML = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verify it's you — Demo Bank</title>
<style>body{font-family:-apple-system,system-ui,sans-serif;background:#101418;color:#e8e8e8;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1a2027;border:1px solid #2a323c;border-radius:14px;padding:28px;width:430px}
.brand{font-size:20px;font-weight:700;margin:0 0 4px}
.sub{color:#9aa5b1;font-size:13px;margin:0 0 16px}.sub b{color:#e8e8e8}
.txn{background:#101418;border:1px solid #2a323c;border-left:3px solid #f26a1b;border-radius:10px;
padding:14px 16px;margin:0 0 16px}
.txn .amt{font-size:22px;font-weight:700;color:#fff;letter-spacing:-.5px}
.txn .row{display:flex;justify-content:space-between;font-size:12.5px;color:#9aa5b1;margin-top:7px}
.txn .row b{color:#e8e8e8;font-weight:600}
#widget{min-height:320px}
#msg{font-size:13px;margin-top:12px;min-height:18px;color:#ff8b7b}
.vendor{margin-top:18px;padding-top:14px;border-top:1px solid #2a323c;color:#9aa5b1;
font-size:11px;display:flex;align-items:center;justify-content:center;gap:7px}.vendor img{height:18px}
a.alt{color:#7fb0ff;font-size:12px;text-decoration:none;display:block;margin-top:10px;text-align:center}</style>
</head><body>
<div class="card">
  <div class="brand">🏦 Demo Bank</div>
  <div class="sub">Verifying <b>__USER__</b> with <b>PingOne Recognize</b> — a live face match.</div>
  __TXN__
  <kl-auth id="klauth" customer="__CUSTOMER__" service-url="__SERVICEURL__"
           username="__USER__" __TXNATTR__ __TOKENATTR__ enable-close-button></kl-auth>
  <div id="msg"></div>
  <a class="alt" href="/signup">Use a passkey instead →</a>
  <div class="vendor">Powered by <img src="/static/idp-wordmark.svg" alt="ID Partners"></div>
</div>
<script type="module" src="__SDK__"></script>
<script>
const msg = t => { document.getElementById('msg').textContent = t || ''; };
const el = document.getElementById('klauth');
// The SDK emits `success` with detail.jwt — a token signed by the Recognize tenant. We send the
// JWT itself, never a bare boolean: the server verifies it against RECOGNIZE_JWKS_URL, so a
// tampered client cannot assert a pass it did not earn (see _recognize_verdict, REAL mode).
el.addEventListener('success', async (e) => {
  const jwt = (e.detail && e.detail.jwt) || '';
  if (!jwt) { msg('Verification returned no assertion — cannot proceed.'); return; }
  msg('✓ Verified — signing you in…');
  try {
    const r = await fetch('/signup/recognize/finish', {method:'POST',
      headers:{'content-type':'application/json'},
      body: JSON.stringify({ username: "__USER__", recognizeAssertion: jwt })}).then(r=>r.json());
    if (r.ok) { location.href = r.next || '/'; }
    else { msg(r.detail || r.error || 'Sign-in failed'); }
  } catch (err) { msg('Could not complete sign-in: ' + err.message); }
});
el.addEventListener('error', (e) => {
  const d = e.detail || {};
  const detail = JSON.stringify(d || {});
  // A user who has never enrolled has no template to match against, and the service reports that
  // as a generic internal error — which reads like an outage rather than "you need to enrol".
  // Offer the enrolment path instead of leaving them on a dead end.
  const looksUnenrolled = /SERVER_INTERNAL_ERROR|NOT_FOUND|NO_USER/i.test(detail);
  msg('Verification failed: ' + (d.message || d.reason || 'unknown error'));
  if (looksUnenrolled) {
    const a = document.createElement('a');
    a.className = 'alt';
    a.href = '/recognize/enrol?user=' + encodeURIComponent("__USER__");
    a.textContent = 'Not enrolled yet? Enrol your face first →';
    document.getElementById('msg').after(a);
  }
});
el.addEventListener('close', () => { location.href = '/signup'; });
</script></body></html>"""


# Enrolment — the step that has to happen ONCE before any face match can succeed. Authenticating
# a user who has never enrolled fails with SERVER_INTERNAL_ERROR from the Recognize service (it
# has no template to match against), which is a confusing way to learn this, hence a first-class
# page for it. Same component contract as kl-auth (KeylessEnrollElement extends the same
# RootElement), just the enrolling tag.
_RECOGNIZE_ENROL_HTML = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Enrol your face — Demo Bank</title>
<style>body{font-family:-apple-system,system-ui,sans-serif;background:#101418;color:#e8e8e8;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1a2027;border:1px solid #2a323c;border-radius:14px;padding:28px;width:430px}
.brand{font-size:20px;font-weight:700;margin:0 0 4px}
.sub{color:#9aa5b1;font-size:13px;margin:0 0 16px}.sub b{color:#e8e8e8}
.note{background:#141a22;border:1px solid #2a323c;border-radius:8px;padding:12px 14px;
margin:0 0 16px;font-size:12.5px;color:#9aa5b1;line-height:1.45}
#widget{min-height:320px}
#msg{font-size:13px;margin-top:12px;min-height:18px;color:#ff8b7b}
#msg.ok{color:#5fd08a}
.vendor{margin-top:18px;padding-top:14px;border-top:1px solid #2a323c;color:#9aa5b1;
font-size:11px;display:flex;align-items:center;justify-content:center;gap:7px}.vendor img{height:18px}
a.alt{color:#7fb0ff;font-size:12px;text-decoration:none;display:block;margin-top:10px;text-align:center}</style>
</head><body>
<div class="card">
  <div class="brand">🏦 Demo Bank</div>
  <div class="sub">Enrolling <b>__USER__</b> with <b>PingOne Recognize</b>.</div>
  <div class="note">This registers your face once so it can be matched later. Recognize stores a
    privacy-preserving representation, not a photograph. You need to do this before
    "Sign in with Recognize" can work for this username.</div>
  <kl-enroll id="klenroll" customer="__CUSTOMER__" service-url="__SERVICEURL__"
             username="__USER__" __TOKENATTR__ enable-close-button></kl-enroll>
  <div class="note" style="margin-top:10px">Target: <b>__SERVICEURL__</b> · customer <b>__CUSTOMER__</b></div>
  <div id="msg"></div>
  <a class="alt" href="/signup?recognize=1&amp;user=__USER__">Already enrolled? Sign in →</a>
  <div class="vendor">Powered by <img src="/static/idp-wordmark.svg" alt="ID Partners"></div>
</div>
<!-- Diagnostic capture. A classic inline script runs BEFORE a deferred module script, so this
     wraps fetch before the SDK grabs its own reference — the only way to see the SDK's real
     request/response. Read it from window.__klnet. Harmless to leave: it only records calls to
     the Recognize host and never alters them. -->
<script>
window.__klnet = [];
(function () {
  var OF = window.fetch;
  window.fetch = function (u, o) {
    var url = String(u && u.url ? u.url : u);
    if (url.indexOf('keyless') === -1) return OF.apply(this, arguments);
    var h = {};
    try { if (o && o.headers) new Headers(o.headers).forEach(function (v, k) { h[k] = v; }); } catch (e) {}
    var rec = { url: url, method: (o && o.method) || 'GET', headers: h,
                body: o && o.body ? String(o.body).slice(0, 1200) : null };
    window.__klnet.push(rec);
    return OF.apply(this, arguments).then(function (r) {
      rec.status = r.status;
      r.clone().text().then(function (t) { rec.resp = t.slice(0, 1200); }).catch(function () {});
      return r;
    }).catch(function (e) { rec.err = String(e); throw e; });
  };
})();
</script>
<script type="module" src="__SDK__"></script>
<script>
const m = document.getElementById('msg');
const say = (t, ok) => { m.textContent = t || ''; m.className = ok ? 'ok' : ''; };
const el = document.getElementById('klenroll');
el.addEventListener('success', () => {
  say('✓ Enrolled. You can now sign in with Recognize.', true);
  setTimeout(() => { location.href = '/signup?recognize=1&user=' + encodeURIComponent("__USER__"); }, 1600);
});
el.addEventListener('error', (e) => {
  const d = e.detail || {};
  say('Enrolment failed: ' + (d.message || d.reason || d.code || 'unknown error'));
  // Dump EVERYTHING. The Keyless payloads are end-to-end encrypted, so the decrypted client-side
  // error object is the only place the real reason can surface — a one-line summary throws away
  // exactly the fields (code/httpStatus/details) that distinguish "wrong tenant" from "wrong
  // region" from "missing authorization token".
  const dump = { detail: null, calls: (window.__klnet || []).map(r => ({
                   path: (r.url.split('keyless.technology')[1] || r.url), method: r.method,
                   status: r.status, err: r.err })) };
  try { dump.detail = JSON.parse(JSON.stringify(d, Object.getOwnPropertyNames(d))); }
  catch (_) { dump.detail = String(d); }
  const pre = document.createElement('pre');
  pre.style.cssText = 'white-space:pre-wrap;word-break:break-all;background:#0d1117;border:1px solid #2a323c;'
    + 'border-radius:8px;padding:10px;margin-top:10px;font-size:11px;color:#9aa5b1;max-height:280px;overflow:auto';
  pre.textContent = JSON.stringify(dump, null, 1);
  document.getElementById('msg').after(pre);
  window.__enrolError = dump;   // also readable programmatically
});
el.addEventListener('close', () => { location.href = '/signup'; });
</script></body></html>"""


_SIGNUP_HTML = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign up — Demo Bank</title>
<style>body{font-family:-apple-system,system-ui,sans-serif;background:#101418;color:#e8e8e8;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1a2027;border:1px solid #2a323c;border-radius:14px;padding:32px;width:370px}
.brand{font-size:20px;font-weight:700;margin:0 0 2px}.brand .o{color:#f26a1b}
h1{font-size:17px;margin:14px 0 6px}p{color:#9aa5b1;font-size:13px;line-height:1.5;margin:6px 0}
input{width:100%;box-sizing:border-box;padding:11px;border-radius:8px;border:1px solid #2a323c;
background:#101418;color:#e8e8e8;font-size:15px;margin:10px 0 4px}
button{width:100%;padding:12px;border:0;border-radius:8px;color:#fff;font-size:15px;
font-weight:600;cursor:pointer;margin-top:8px}button:disabled{opacity:.45;cursor:default}
.primary{background:#2d7a4f}.secondary{background:#2a3340}.ghost{background:transparent;
color:#7fb0ff;font-weight:500;margin-top:14px;padding:4px}
#msg{font-size:13px;margin-top:12px;min-height:18px}.err{color:#ff8b7b}.ok{color:#5fd08a}
.hint{font-size:12px;margin:2px 0 0}.avail{color:#5fd08a}.taken{color:#ffcf6a}
.vendor{margin-top:18px;padding-top:14px;border-top:1px solid #2a323c;color:#9aa5b1;
font-size:11px;display:flex;align-items:center;justify-content:center;gap:7px}
.vendor img{height:18px;width:auto}
/* The consent being captured: the payment the passkey is about to authorise. */
.paysum{background:#101418;border:1px solid #2a323c;border-left:3px solid #f26a1b;
border-radius:10px;padding:14px 16px;margin:12px 0 4px}
.paysum .amt{font-size:22px;font-weight:700;color:#fff;letter-spacing:-.5px}
.paysum .row{display:flex;justify-content:space-between;font-size:12.5px;color:#9aa5b1;margin-top:7px}
.paysum .row b{color:#e8e8e8;font-weight:600}
.paysum .lbl{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#7d8894;margin-bottom:2px}
.hidden{display:none}</style>
</head><body>
<div class="card">
  <div class="brand">🏦 Demo Bank</div>

  <!-- CHOOSE -->
  <div id="choose">
    <h1>Welcome</h1>
    <p>Bank with a passkey — Face&nbsp;ID, a security key, or your phone. No passwords.</p>
    <button class="primary" id="toCreate">🔑 Create a new account</button>
    <button class="secondary" id="toSignin">Sign in to an existing account</button>
  </div>

  <!-- CREATE -->
  <div id="create" class="hidden">
    <h1>Create your account</h1>
    <p>Pick a username. We'll check it's free, then create your passkey.</p>
    <input id="cu" placeholder="username (e.g. carol)" autocomplete="off" autocapitalize="none">
    <div id="chint" class="hint"></div>
    <button class="primary" id="createBtn" disabled>Create passkey</button>
    <button class="ghost" data-to="choose">← Back</button>
  </div>

  <!-- SIGN IN -->
  <div id="signin" class="hidden">
    <h1>Sign in</h1>
    <p>Use your passkey. Leave the username blank to let your device pick a saved one.</p>
    __PAYMENT__
    <input id="su" placeholder="username (optional)" autocomplete="username webauthn"
           autocapitalize="none">
    <button class="primary" id="signinBtn">Sign in with passkey</button>
    __RECOGNIZEBTN__
    <button class="ghost" data-to="choose">← Back</button>
  </div>

  <div id="msg"></div>
  <div class="vendor">Powered by <img src="/static/idp-wordmark.svg" alt="ID Partners"></div>
</div>
<script>
const b64uToBuf = s => { s = s.replace(/-/g,'+').replace(/_/g,'/'); s += '='.repeat((4-s.length%4)%4);
  const bin = atob(s); const b = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) b[i]=bin.charCodeAt(i); return b.buffer; };
const bufToB64u = buf => { const b = new Uint8Array(buf); let s='';
  for (let i=0;i<b.length;i++) s+=String.fromCharCode(b[i]);
  return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,''); };
const $ = id => document.getElementById(id);
const msg = (t,c) => { const m=$('msg'); m.textContent=t; m.className=c||''; };
const valid = u => /^[a-z0-9._-]{2,30}$/.test(u);
function show(which){
  ['choose','create','signin'].forEach(s => $(s).classList.toggle('hidden', s!==which));
  msg('');
}
$('toCreate').onclick = () => { show('create'); $('cu').focus(); };
$('toSignin').onclick = () => { show('signin'); $('su').focus(); };
document.querySelectorAll('[data-to]').forEach(b => b.onclick = () => show(b.dataset.to));

// live username uniqueness check (debounced)
let chkTimer, lastFree = false;
$('cu').addEventListener('input', () => {
  const u = $('cu').value.trim().toLowerCase();
  $('createBtn').disabled = true; lastFree = false;
  clearTimeout(chkTimer);
  const h = $('chint');
  if(!valid(u)){ h.textContent = u ? 'Lowercase letters, digits, . _ - (2–30).' : ''; h.className='hint'; return; }
  h.textContent = 'Checking…'; h.className='hint';
  chkTimer = setTimeout(async () => {
    try {
      const c = await fetch('/signup/check?user='+encodeURIComponent(u)).then(r=>r.json());
      if(c.hasPasskey){ h.textContent='✗ Taken — that account already has a passkey. Sign in instead.'; h.className='hint taken'; }
      else if(c.exists){ h.textContent='✗ Taken — this username already exists.'; h.className='hint taken'; }
      else { h.textContent='✓ Available'; h.className='hint avail'; lastFree=true; $('createBtn').disabled=false; }
    } catch(e){ h.textContent=''; }
  }, 350);
});

async function doCreate(user){
  msg('Setting up your account…');
  const beg = await fetch('/signup/passkey/begin', {method:'POST',
    headers:{'content-type':'application/json'}, body: JSON.stringify({user})}).then(r=>r.json());
  if(beg.error){ msg(beg.error+(beg.detail?': '+beg.detail:''), 'err'); return; }
  const o = beg.creationOptions; const challenge = o.challenge;
  o.challenge = b64uToBuf(o.challenge); o.user.id = b64uToBuf(o.user.id);
  (o.excludeCredentials||[]).forEach(c => c.id = b64uToBuf(c.id));
  msg('Follow your device prompt to create the passkey…');
  const cred = await navigator.credentials.create({publicKey: o});
  const att = { id: cred.id, type: cred.type, rawId: bufToB64u(cred.rawId),
    response: { clientDataJSON: bufToB64u(cred.response.clientDataJSON),
                attestationObject: bufToB64u(cred.response.attestationObject) } };
  msg('Finishing…');
  const fin = await fetch('/signup/passkey/finish', {method:'POST',
    headers:{'content-type':'application/json'},
    body: JSON.stringify({userId: beg.userId, deviceId: beg.deviceId, user, challenge,
                          origin: location.origin, attestation: JSON.stringify(att)})}).then(r=>r.json());
  if(fin.ok){ msg('✓ Passkey created — signing you in…', 'ok');
    setTimeout(()=>location.href=(fin.next||'/?signedup=1'), 500); }
  else msg(fin.error+(fin.detail?': '+fin.detail:''), 'err');
}

async function doSignin(user){
  msg('Requesting your passkey…');
  const beg = await fetch('/signin/passkey/begin', {method:'POST',
    headers:{'content-type':'application/json'}, body: JSON.stringify({user})}).then(r=>r.json());
  if(beg.error){ msg(beg.error+(beg.detail?': '+beg.detail:''), 'err'); return; }
  const o = beg.requestOptions; o.challenge = b64uToBuf(o.challenge);
  (o.allowCredentials||[]).forEach(c => c.id = b64uToBuf(c.id));
  msg('Use Face ID / your passkey…');
  const cred = await navigator.credentials.get({publicKey: o});
  const asr = { id: cred.id, type: cred.type, rawId: bufToB64u(cred.rawId),
    response: { clientDataJSON: bufToB64u(cred.response.clientDataJSON),
                authenticatorData: bufToB64u(cred.response.authenticatorData),
                signature: bufToB64u(cred.response.signature),
                userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null } };
  // Parse defensively: if the server 500s, the body is HTML and r.json() throws a SyntaxError
  // whose message ("The string did not match the expected pattern" on Safari) looks exactly like
  // a WebAuthn failure. Surface the real status instead.
  const finRes = await fetch('/signin/passkey/finish', {method:'POST',
    headers:{'content-type':'application/json'},
    body: JSON.stringify({origin: location.origin, assertion: JSON.stringify(asr)})});
  let fin;
  try { fin = await finRes.json(); }
  catch(e){ msg('Server error completing sign-in (HTTP '+finRes.status+'). The passkey was fine.', 'err'); return; }
  if(fin.ok){ msg('✓ Signed in — welcome back…', 'ok'); setTimeout(()=>location.href=(fin.next||'/'), 500); }
  else if(fin.error==='unknown passkey' || fin.error==='no_passkey'){
    msg('No passkey found for that account on this device. Create an account instead?', 'err'); }
  else msg(fin.error+(fin.detail?': '+fin.detail:''), 'err');
}

$('createBtn').onclick = async () => {
  const u = $('cu').value.trim().toLowerCase();
  if(!valid(u) || !lastFree){ msg('Pick an available username first.', 'err'); return; }
  $('createBtn').disabled = true;
  try { await doCreate(u); } catch(e){ msg('Passkey cancelled or failed: '+e.message, 'err'); }
  $('createBtn').disabled = false;
};
$('signinBtn').onclick = async () => {
  const u = $('su').value.trim().toLowerCase();
  if(u && !valid(u)){ msg('Enter a valid username, or leave it blank.', 'err'); return; }
  $('signinBtn').disabled = true;
  try { await doSignin(u); } catch(e){ msg('Sign-in cancelled or failed: '+e.message, 'err'); }
  $('signinBtn').disabled = false;
};
// Recognize sign-in needs to know WHO to verify (unlike discoverable-passkey sign-in, a face
// match has nothing to look up a username by), so — unlike the passkey button — this one
// requires the field to be filled in before it will proceed.
if ($('recognizeBtn')) $('recognizeBtn').onclick = () => {
  const u = $('su').value.trim().toLowerCase();
  if(!u || !valid(u)){ msg('Enter your username first, then Sign in with Recognize.', 'err'); return; }
  location.href = '/signup?recognize=1&user=' + encodeURIComponent(u);
};

// Step-up: /login?stepup=1&u=<user> sent an ALREADY signed-in user here to approve a payment.
// Skip the create/choose screen (they have an account) and go straight to a pre-filled passkey
// sign-in, relabelled as payment approval. One tap — WebAuthn needs a user gesture, so we don't
// auto-fire it. This is the "login hint" so the step-up never offers 'create a new account'.
(function(){
  const q = new URLSearchParams(location.search);
  if(q.get('stepup') !== '1') return;
  const u = (q.get('u')||'').toLowerCase();
  show('signin');
  // DISCOVERABLE sign-in — leave the username blank so the browser offers whatever passkey
  // exists, exactly like the working front door. Do NOT force allowCredentials to a stored
  // credential_id: it fails ("string did not match the expected pattern") for users whose stored
  // id is stale or was registered elsewhere (e.g. a PingOne passkey under a different rpId).
  $('su').value = '';
  $('su').style.display = 'none';
  const h = $('signin').querySelector('h1'); if(h) h.textContent = 'Approve this payment';
  const p = $('signin').querySelector('p'); if(p) p.textContent =
    (u ? 'Signed in as ' + u + '. ' : '') + 'Confirm with your passkey to authorise the payment.';
  $('signinBtn').textContent = 'Approve with passkey';
})();
</script></body></html>"""


def _payment_summary_html(request: Request) -> str:
    """Render WHAT the passkey is about to authorise, from the signed step-up cookie.

    This is the consent capture made visible: without it the user taps 'Approve with passkey'
    against an unstated payment — the passkey signs a blind consent. The cookie is httpOnly and
    signed, so the page can't read it in JS; the server renders it. Values are HTML-escaped."""
    su = _verify(request.cookies.get(STEPUP_COOKIE)) or {}
    amount = str(su.get("amount") or "").strip()
    if not amount:
        return ""
    esc = lambda s: (str(s or "").replace("&", "&amp;").replace("<", "&lt;")
                     .replace(">", "&gt;").replace('"', "&quot;"))
    try:
        amt = f"{float(amount):,.2f}"
    except ValueError:
        amt = esc(amount)
    cur, debtor, creditor = esc(su.get("currency") or "AUD"), esc(su.get("debtor")), esc(su.get("creditor"))
    return (f'<div class="paysum"><div class="lbl">Payment to authorise</div>'
            f'<div class="amt">{cur} {amt}</div>'
            f'<div class="row"><span>From</span><b>{debtor or "—"}</b></div>'
            f'<div class="row"><span>To</span><b>{creditor or "—"}</b></div></div>')


@app.get("/signup")
async def signup(request: Request, user: str = "", davinci: str = "", recognize: str = ""):
    """Front door = PASSWORDLESS passkey / security-key (WebAuthn on this BFF). Create an
    account or sign in with a passkey or YubiKey — no password anywhere. The whole ceremony
    runs on this origin so the browser's WebAuthn works directly (Safari Face ID + save-to-
    iPhone QR, or a roaming security key): the BFF creates the PingOne user, PingOne's FIDO2
    device API issues the creationOptions (rp.id = this host), the browser creates the
    credential, and the BFF activates it. PingOne holds the identity; PF is brokered via
    signupTE. No DaVinci, no hosted password page.

    ?davinci=1 serves the DaVinci WIDGET variant instead: PingOne (not the BFF) verifies the
    passkey, via the embedded flow. Gated so the native front door above is untouched.

    ?recognize=1&user=<username> serves the PingOne Recognize sign-in variant — but ONLY when a
    real browser-usable tenant is configured (recognize_real_configured()). Otherwise it falls
    through to the normal passkey page and the Recognize button is not rendered at all: this
    tenant's face matching lives on the paired phone via the Mobile SDK, and a simulated browser
    screen on the login path would look like a security control without being one.
    When it IS served, /signup/recognize/finish still requires that named user to already exist
    with a passkey before brokering a session — the username must be supplied up front (there's
    no discoverable-credential equivalent for a face match)."""
    # Only when Recognize is genuinely usable in a BROWSER. There used to be an
    # `or DAVINCI_SK_API_KEY` fallback here that served a DaVinci screen which merely
    # SIMULATED a face match — on the normal login path that is worse than not offering it:
    # it looks like a security control and is not one. The real face match is on the paired
    # phone (Mobile SDK); this browser surface needs an Authentication Service the tenant
    # does not have, so the honest behaviour is to fall through to passkey sign-in.
    if recognize == "1" and recognize_real_configured():
        u = (user or "").strip().lower()
        if not u or not re.match(r"^[a-z0-9._-]{2,30}$", u):
            return HTMLResponse("<p>Missing or invalid username for Recognize sign-in. "
                                "<a href='/signup'>Back</a></p>", status_code=400)
        esc = lambda s: (str(s or "").replace("&", "&amp;").replace("<", "&lt;")
                         .replace(">", "&gt;").replace('"', "&quot;"))
        esc_u = esc(u)
        if recognize_real_configured():
            # Bind the check to the payment when one is in flight (PSD2 dynamic linking). The
            # step-up cookie is the authoritative source for what is being approved — never a
            # query param, which the user could edit to have the biometric attest to a payment
            # different from the one the PDP will actually see.
            su = _verify(request.cookies.get(STEPUP_COOKIE)) or {}
            txn_html, txn_attr = "", ""
            if su.get("amount"):
                txn_data = json.dumps({"amount": su.get("amount", ""),
                                       "currency": su.get("currency", "AUD"),
                                       "creditor": su.get("creditor", ""),
                                       "debtor": su.get("debtor", "")}, separators=(",", ":"))
                txn_attr = 'transaction-data="' + esc(txn_data) + '"'
                txn_html = ('<div class="txn"><div class="amt">' + esc(su.get("currency") or "AUD")
                            + " " + esc(su.get("amount")) + "</div>"
                            + '<div class="row"><span>To</span><b>' + (esc(su.get("creditor")) or "—") + "</b></div>"
                            + '<div class="row"><span>From</span><b>' + (esc(su.get("debtor")) or "—") + "</b></div></div>")
            # First factor: a PF-minted, 5-minute, single-use assertion binding this session to
            # THIS username. Empty when the tenant does not enforce it (see the helper) — the
            # attribute is then simply absent, which is what an unenforced tenant expects.
            ua_tok = await _mint_recognize_user_authorization(u)
            tok_attr = ('authorization-token="' + esc(ua_tok) + '"') if ua_tok else ""
            return HTMLResponse(_RECOGNIZE_REAL_HTML
                                .replace("__SDK__", RECOGNIZE_SDK_URL)
                                .replace("__CUSTOMER__", esc(RECOGNIZE_CUSTOMER_NAME))
                                .replace("__SERVICEURL__", esc(RECOGNIZE_SERVICE_URL))
                                .replace("__TXNATTR__", txn_attr)
                                .replace("__TOKENATTR__", tok_attr)
                                .replace("__TXN__", txn_html)
                                .replace("__USER__", esc_u))
        return HTMLResponse(_RECOGNIZE_SIGNIN_HTML
                            .replace("__ASSETS__", DAVINCI_ASSETS_ROOT)
                            .replace("__USER__", esc_u))
    if davinci == "1" and DAVINCI_SK_API_KEY:
        return HTMLResponse(_DAVINCI_HTML
                            .replace("__ASSETS__", DAVINCI_ASSETS_ROOT)
                            .replace("__APIROOT__", DAVINCI_API_ROOT)
                            .replace("__COMPANY__", DAVINCI_COMPANY_ID)
                            .replace("__POLICY__", DAVINCI_POLICY_ID))
    # Offer the Recognize button ONLY when it would do something real. Otherwise it is omitted
    # entirely rather than rendered-and-disabled: a greyed-out "Sign in with Recognize" still
    # implies the capability exists here, and it does not — it lives on the paired phone.
    recognize_btn = ('<button class="secondary" id="recognizeBtn">👤 Sign in with Recognize</button>'
                     if recognize_real_configured() else "")
    return HTMLResponse(_SIGNUP_HTML
                        .replace("__RECOGNIZEBTN__", recognize_btn)
                        .replace("__PAYMENT__", _payment_summary_html(request)))


@app.get("/signup/davinci/token")
async def davinci_token():
    """Server-mint a fresh DaVinci sdkToken for the widget (the SK API key never reaches JS)."""
    tok = await _davinci_sdktoken()
    if not tok:
        return JSONResponse(status_code=502, content={"error": "davinci_unconfigured"})
    return {"accessToken": tok, "companyId": DAVINCI_COMPANY_ID,
            "policyId": DAVINCI_POLICY_ID, "apiRoot": DAVINCI_API_ROOT + "/"}


@app.post("/signup/davinci/finish")
async def davinci_finish(request: Request):
    """The DaVinci flow verified the passkey (PingOne-authoritative) and returned the user in its
    success payload. Broker that user into a PF session via signupTE — the same wire the native
    front door uses — so the delegation demo works identically."""
    body = await request.json()
    # The flow's createSuccessResponse shape varies; accept the common places the username lands.
    user = (body.get("user") or body.get("username")
            or (body.get("output") or {}).get("username")
            or ((body.get("user") or {}) if isinstance(body.get("user"), dict) else {}).get("username")
            or "")
    user = str(user).strip().lower()
    if not user or not re.match(r"^[a-z0-9._-]{2,30}$", user):
        return JSONResponse(status_code=400, content={"error": "no_user_in_flow_result",
                            "detail": "flow success payload carried no usable username"})
    pf_at = await _broker_passkey_to_pf(user)
    return _passkey_session_response(user, pf_at, new_signup=True)


@app.get("/recognize/enrol")
async def recognize_enrol(user: str = "", region: str = "", customer: str = "", token: str = ""):
    """One-time face enrolment. Only meaningful with a real tenant — there is nothing to enrol
    into in simulate mode, so rather than render a fake 'enrolled!' screen (which would leave
    someone believing a biometric exists when it does not), this says so plainly.

    ?region= / ?customer= / ?token= are DIAGNOSTIC overrides. Keyless does not tell you which
    regional service holds your tenant, and every region answers session-creation identically,
    so the only way to find out is to try each one against a real camera. Overriding by query
    param makes that a page reload instead of an env change + redeploy per attempt.
    ?token= sets the SDK's authorization token, to test whether enrolment needs one."""
    u = (user or "").strip().lower()
    if not u or not re.match(r"^[a-z0-9._-]{2,30}$", u):
        return HTMLResponse("<p>Pass a username, e.g. <code>/recognize/enrol?user=alice</code></p>",
                            status_code=400)
    svc = RECOGNIZE_REGIONS.get((region or "").strip().lower(), "") or RECOGNIZE_SERVICE_URL
    cust = (customer or "").strip() or RECOGNIZE_CUSTOMER_NAME
    if not (svc and cust):
        return HTMLResponse(
            "<p>Recognize enrolment needs a real tenant: set <code>RECOGNIZE_CUSTOMER_NAME</code> "
            "and <code>RECOGNIZE_SERVICE_URL</code>, or pass <code>?region=us|eu|latam|sandbox|"
            "staging</code>. <a href='/signup'>Back</a></p>", status_code=503)
    esc = lambda s: (str(s or "").replace("&", "&amp;").replace("<", "&lt;")
                     .replace(">", "&gt;").replace('"', "&quot;"))
    # ?token= stays a manual DIAGNOSTIC override and wins outright — the point of that knob is to
    # test a token we chose. With no override, mint the real first factor (empty when the tenant
    # does not enforce it, in which case the attribute is simply omitted).
    ua_tok = token or await _mint_recognize_user_authorization(u)
    tok_attr = ('authorization-token="' + esc(ua_tok) + '"') if ua_tok else ""
    return HTMLResponse(_RECOGNIZE_ENROL_HTML
                        .replace("__SDK__", RECOGNIZE_SDK_URL)
                        .replace("__CUSTOMER__", esc(cust))
                        .replace("__SERVICEURL__", esc(svc))
                        .replace("__TOKENATTR__", tok_attr)
                        .replace("__USER__", esc(u)))


RECOGNIZE_SECRET_API_KEY = os.environ.get("RECOGNIZE_SECRET_API_KEY", "")
# Server API (operations plane) — NOT the node host the SDK talks to. Different service, and
# a different key: X-Api-Key + the SECRET key here, vs X-Keyless-Apikey + the MOBILE key on the node.
RECOGNIZE_SERVER_API = os.environ.get(
    "RECOGNIZE_SERVER_API", "https://api.sg.keyless.technology").rstrip("/")


@app.post("/recognize/bind")
async def recognize_bind(request: Request):
    """Bind a freshly enrolled Recognize user to this device's bank identity.

    The Mobile SDK enrols a *biometric*, not an account: it returns a `keylessId` and knows
    nothing about "alice". Nothing ties the two together until this call. (Web-SDK tenants get
    that mapping free because the Authentication Service keys on username — the mobile/node path
    has no username at all, so we do it explicitly.)

    Runs SERVER-side on purpose. Binding needs the Secret API Key, which is a backend credential:
    a phone holding it could re-point any keylessId at any account. The device proves who it is
    with its own device token, and the username comes from THAT — never from the request body,
    or a paired phone could enrol a face against someone else's identity."""
    user = _device_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "device token required"})
    if not RECOGNIZE_SECRET_API_KEY:
        return JSONResponse(status_code=503, content={"error": "recognize_server_api_unconfigured"})
    body = await request.json()
    keyless_id = str(body.get("keylessId") or "").strip()
    # The Server API documents userId as an uppercase HEX string; reject anything else rather
    # than forwarding junk into a path segment.
    if not re.fullmatch(r"[0-9A-Fa-f]{8,128}", keyless_id):
        return JSONResponse(status_code=400, content={"error": "invalid keylessId"})
    try:
        async with httpx.AsyncClient(timeout=20.0) as c:
            r = await c.post(
                f"{RECOGNIZE_SERVER_API}/v2/users/{keyless_id}/external-user",
                headers={"X-Api-Key": RECOGNIZE_SECRET_API_KEY,
                         "Content-Type": "application/json"},
                json={"externalUserId": user})
    except Exception as exc:  # noqa: BLE001
        logger.warning("recognize bind error for %s: %s", user, exc)
        return JSONResponse(status_code=502, content={"error": "bind_failed"})
    # Recovery material, if the ceremony produced it. Stored server-side ON PURPOSE: the whole
    # point is that it survives the loss of the phone that generated it. Best-effort — a storage
    # failure must not fail an otherwise-good enrolment, it only costs the ability to recover
    # onto a new device later, which is recoverable by re-enrolling.
    client_state = str(body.get("clientState") or "")
    if client_state and PROOFING_DIRECTORY_URL:
        try:
            async with httpx.AsyncClient(timeout=15.0) as c:
                cr = await c.post(f"{PROOFING_DIRECTORY_URL}/recognize-recovery/{user}",
                                  json={"keylessId": keyless_id, "clientState": client_state})
            logger.info("recognize recovery material stored for %s (%s bytes, http %s)",
                        user, len(client_state), cr.status_code)
        except Exception as exc:  # noqa: BLE001
            logger.warning("recognize recovery store failed for %s: %s", user, exc)
    elif not client_state:
        logger.info("recognize enrolment for %s carried NO client state — "
                    "new-device recovery will not be possible for this enrolment", user)

    if r.status_code in (200, 201):
        logger.info("recognize BOUND keylessId=%s -> %s", keyless_id[:8] + "…", user)
        return {"ok": True, "user": user, "recoverable": bool(client_state)}
    # 409 = this user already has an external id bound; treat as success so a re-enrol is idempotent.
    if r.status_code == 409:
        logger.info("recognize bind: already bound (%s)", user)
        return {"ok": True, "user": user, "note": "already bound"}
    logger.warning("recognize bind failed %s: %s", r.status_code, r.text[:200])
    return JSONResponse(status_code=502,
                        content={"error": "bind_rejected", "status": r.status_code})


# Enrolment hand-off screen. The browser never touches a camera here — it explains, deep-links to
# the approver app, and polls until the TENANT confirms a bound enrolment. Deliberately has no
# "mark me as done" affordance: the only thing that advances this screen is server-side truth.
_RECOGNIZE_HANDOFF_HTML = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Set up face verification — Demo Bank</title>
<style>body{font-family:-apple-system,system-ui,sans-serif;background:#101418;color:#e8e8e8;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1a2027;border:1px solid #2a323c;border-radius:14px;padding:28px;width:430px}
.brand{font-size:20px;font-weight:700;margin:0 0 4px}
.sub{color:#9aa5b1;font-size:13px;margin:0 0 18px}.sub b{color:#e8e8e8}
ol{margin:0 0 18px;padding-left:20px;color:#cfd6de;font-size:13.5px;line-height:1.7}
.btn{display:block;text-align:center;background:#f26a1b;color:#fff;text-decoration:none;
font-weight:600;padding:12px;border-radius:9px;margin:0 0 12px}
#msg{font-size:13px;min-height:20px;color:#9aa5b1;text-align:center}
#msg.ok{color:#5ad18b}#msg.err{color:#ff8b7b}
a.alt{color:#7fb0ff;font-size:12px;text-decoration:none;display:block;margin-top:12px;text-align:center}
.why{margin-top:16px;padding-top:14px;border-top:1px solid #2a323c;color:#7b8794;font-size:11.5px;line-height:1.6}
</style></head><body>
<div class="card">
  <div class="brand">🏦 Demo Bank</div>
  <div class="sub">Set up face verification for <b>__USER__</b></div>
  <ol>
    <li>Open the <b>Demo Bank Approver</b> app on your phone</li>
    <li>Tap the <b>profile icon</b>, then <b>Face verification</b></li>
    <li>Tap <b>Enrol my face</b></li>
  </ol>
  <a class="btn" href="idpapprover://enrol?user=__USER__">Open the app on this phone</a>
  <div id="msg">Waiting for your enrolment…</div>
  <a class="alt" href="__NEXT__">Skip for now →</a>
  <div class="why">Your face is captured on your phone, never in this browser. The bank stores no
  image — only a public key. This page advances when the biometric service confirms your
  enrolment, not when you say it is done.</div>
</div>
<script>
const msg = document.getElementById('msg');
let tries = 0;
async function poll() {
  tries++;
  try {
    const r = await fetch('/recognize/status?user=' + encodeURIComponent("__USER__"),
                          {headers:{'accept':'application/json'}});
    if (r.status === 401) { msg.textContent = 'Session expired — sign in again.'; msg.className='err'; return; }
    const j = await r.json();
    if (j.enrolled) {
      msg.textContent = '✓ Face enrolled. Continuing…'; msg.className = 'ok';
      setTimeout(() => { location.href = "__NEXT__"; }, 1200);
      return;
    }
  } catch (e) { /* transient — keep polling rather than failing the onboarding */ }
  // Give up politely after ~5 minutes rather than hammering the tenant forever.
  if (tries > 100) { msg.textContent = 'Still waiting. Finish on your phone, then reload.'; return; }
  setTimeout(poll, 3000);
}
poll();
</script></body></html>"""


@app.get("/recognize/enrol-start")
async def recognize_enrol_start(request: Request, user: str = "", next: str = "/"):
    """Onboarding hand-off: the browser asks for a face enrolment, the PHONE performs it.

    This is the honest shape of enrolment for this tenant. A browser step cannot capture a face
    here (no regional Authentication Service), so rather than simulate one, the page deep-links
    into the approver app and waits for the tenant to report a real, bound enrolment via
    /recognize/status. The user is never shown a 'verified' state the server cannot corroborate."""
    caller = (_session(request) or {}).get("sub") or _device_user(request)
    if not caller:
        return HTMLResponse("<p>Sign in first. <a href='/signup'>Back</a></p>", status_code=401)
    u = (user or caller).strip().lower()
    if not re.match(r"^[a-z0-9._-]{2,30}$", u):
        return HTMLResponse("<p>Invalid username.</p>", status_code=400)
    esc = lambda s: (str(s or "").replace("&", "&amp;").replace("<", "&lt;")
                     .replace(">", "&gt;").replace('"', "&quot;"))
    return HTMLResponse(_RECOGNIZE_HANDOFF_HTML
                        .replace("__USER__", esc(u))
                        .replace("__NEXT__", esc(next if next.startswith("/") else "/")))


@app.post("/recognize/unenrol")
async def recognize_unenrol(request: Request):
    """Destroy this user's Recognize enrolment(s) SERVER-side.

    Needed because the SDK's own deEnroll only works while the DEVICE still holds state: sign out
    (which clears local state) and the tenant-side template becomes unreachable from the phone —
    it survives, invisible, and a later re-enrolment silently creates a SECOND template for the
    same person. Two templates for one face is ambiguous: an authenticate may match either, and
    only one carries recovery material.

    Deletes EVERY user bound to this username, not just the newest, because that duplication is
    exactly the mess this exists to clean up. Also drops the stored recovery material — keeping
    recovery state for a template that no longer exists would just fail confusingly later."""
    caller = (_session(request) or {}).get("sub") or _device_user(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "session or device token required"})
    body = {}
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        pass
    # Only ever your own enrolment. A device token scopes to one identity; letting the body pick
    # the target would let a paired phone delete someone else's biometric.
    user = caller.strip().lower()
    if not RECOGNIZE_SECRET_API_KEY:
        return JSONResponse(status_code=503, content={"error": "recognize_server_api_unconfigured"})
    deleted, failed = [], []
    try:
        async with httpx.AsyncClient(timeout=25.0) as c:
            hdr = {"X-Api-Key": RECOGNIZE_SECRET_API_KEY}
            lr = await c.get(f"{RECOGNIZE_SERVER_API}/v2/external-users/{user}/users", headers=hdr)
            users = lr.json() if lr.status_code == 200 and isinstance(lr.json(), list) else []
            for u in users:
                uid = u.get("userId") or ""
                if not uid:
                    continue
                dr = await c.delete(f"{RECOGNIZE_SERVER_API}/v2/users/{uid}", headers=hdr)
                (deleted if dr.status_code in (200, 202, 204) else failed).append(
                    {"userId": uid, "status": dr.status_code})
            if PROOFING_DIRECTORY_URL:
                try:
                    await c.post(f"{PROOFING_DIRECTORY_URL}/recognize-recovery/{user}",
                                 json={"keylessId": None, "clientState": None})
                except Exception:  # noqa: BLE001 — best effort; the templates are what matter
                    pass
    except Exception as exc:  # noqa: BLE001
        logger.warning("recognize unenrol error for %s: %s", user, exc)
        return JSONResponse(status_code=502, content={"error": "unenrol_failed"})
    logger.info("recognize UNENROLLED %s: deleted=%s failed=%s", user, deleted, failed)
    return {"ok": not failed, "user": user, "deleted": deleted, "failed": failed}


@app.get("/recognize/status")
async def recognize_status(request: Request, user: str = ""):
    """Has this user completed a face enrolment, and is it bound to their bank identity?

    The onboarding flow polls this while the customer enrols on their PHONE — the browser
    cannot capture a face for this tenant (no regional Authentication Service), so the web
    orchestrates and the device does the biometric.

    Truth comes from the Recognize Server API, never from anything the client asserts: an
    enrolment the tenant has no record of is not an enrolment. Requires a session or a device
    token — an unauthenticated 'is <username> enrolled?' oracle is a user-enumeration vector,
    and this is exactly the sort of endpoint that quietly becomes one."""
    caller = (_session(request) or {}).get("sub") or _device_user(request)
    if not caller:
        return JSONResponse(status_code=401, content={"error": "session or device token required"})
    u = (user or caller).strip().lower()
    if not re.match(r"^[a-z0-9._-]{2,30}$", u):
        return JSONResponse(status_code=400, content={"error": "invalid username"})
    if not RECOGNIZE_SECRET_API_KEY:
        return JSONResponse(status_code=503, content={"error": "recognize_server_api_unconfigured"})
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.get(f"{RECOGNIZE_SERVER_API}/v2/external-users/{u}/users",
                            headers={"X-Api-Key": RECOGNIZE_SECRET_API_KEY})
    except Exception as exc:  # noqa: BLE001
        logger.warning("recognize status error for %s: %s", u, exc)
        return JSONResponse(status_code=502, content={"error": "status_unavailable"})
    if r.status_code != 200:
        logger.warning("recognize status %s for %s: %s", r.status_code, u, r.text[:150])
        return JSONResponse(status_code=502, content={"error": "status_unavailable"})
    users = r.json() if isinstance(r.json(), list) else []
    enrolled = bool(users)
    logger.info("recognize status user=%s enrolled=%s", u, enrolled)
    # Deliberately NOT returning the keylessId: the flow only needs to know whether to advance,
    # and the internal id is not something a browser page has any use for.
    return {"user": u, "enrolled": enrolled,
            "enrolledAt": (users[0].get("createdAt") if enrolled else None)}


@app.get("/signup/recognize/token")
async def recognize_signin_token():
    """Server-mint a fresh DaVinci sdkToken for the Recognize sign-in widget."""
    if not DAVINCI_RECOGNIZE_SIGNIN_POLICY_ID:
        return JSONResponse(status_code=502, content={"error": "recognize_unconfigured"})
    tok = await _davinci_sdktoken()
    if not tok:
        return JSONResponse(status_code=502, content={"error": "davinci_unconfigured"})
    return {"accessToken": tok, "companyId": DAVINCI_COMPANY_ID,
            "policyId": DAVINCI_RECOGNIZE_SIGNIN_POLICY_ID, "apiRoot": DAVINCI_API_ROOT + "/"}


@app.post("/signup/recognize/finish")
async def recognize_signin_finish(request: Request):
    """The Recognize flow (real or simulated — see RECOGNIZE_SIMULATE) reported a verdict for
    the username the BROWSER supplied — unlike davinci_finish, PingOne itself never asserted
    who this is, so this endpoint must independently confirm the named user is real and already
    has a passkey before brokering a session. Without that check, a 'pass' verdict for an
    arbitrary typed username would sign in as anyone; requiring an existing passkey-enrolled
    account means Recognize is an additional factor here, not a bypass for account creation."""
    body = await request.json()
    user = str(body.get("username") or "").strip().lower()
    if not user or not re.match(r"^[a-z0-9._-]{2,30}$", user):
        return JSONResponse(status_code=400, content={"error": "username required"})
    if not _deep_recognize_field(body.get("response") or {}):
        return JSONResponse(status_code=401, content={"error": "recognize_verification_failed"})
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            tok = await _p1_token(c)
            r = await c.get(f"{P1_API}/v1/environments/{P1_ENV}/users",
                            headers={"Authorization": f"Bearer {tok}"},
                            params={"filter": f'username eq "{user}"'})
            exists = bool((r.json().get("_embedded") or {}).get("users"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("recognize signin user lookup failed for %s: %s", user, exc)
        exists = False
    if not exists:
        return JSONResponse(status_code=404, content={"error": "unknown_user",
                            "detail": "no account with that username"})
    pf_at = await _broker_passkey_to_pf(user)
    return _passkey_session_response(user, pf_at)


# WebAuthn RP id = this BFF's host (the passkey binds to it; the browser ceremony must run
# on this exact origin). PingOne's FIDO2 policy default was pointed at a host-matching rp.
def _rp_id() -> str:
    return urllib.parse.urlparse(APP_BASE_URL).hostname or "localhost"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _bytes_to_b64u(arr: list) -> str:
    """PingOne returns challenge/user.id as Java signed-byte arrays; the browser needs
    base64url. Fold negatives into 0-255 first."""
    return _b64u(bytes((x + 256) if x < 0 else x for x in arr))


@app.get("/signup/check")
async def signup_check(user: str = ""):
    """Does this username already exist, and does it already have a passkey? Drives the UI:
    existing+passkey → offer sign-in; existing-no-passkey → add a passkey; new → create."""
    user = (user or "").strip().lower()
    if not user:
        return {"user": "", "exists": False, "hasPasskey": False}
    exists = False
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            tok = await _p1_token(c)
            r = await c.get(f"{P1_API}/v1/environments/{P1_ENV}/users",
                            headers={"Authorization": f"Bearer {tok}"},
                            params={"filter": f'username eq "{user}"'})
            exists = bool((r.json().get("_embedded") or {}).get("users"))
    except Exception:  # noqa: BLE001
        pass
    has_passkey = False
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            pr = await c.get(f"{PROOFING_DIRECTORY_URL}/passkey/{user}")
            has_passkey = bool(pr.json().get("credentials"))
    except Exception:  # noqa: BLE001
        pass
    return {"user": user, "exists": exists, "hasPasskey": has_passkey}


@app.post("/signup/passkey/begin")
async def passkey_begin(request: Request):
    """Create the PingOne user (passwordless) + a FIDO2 device, and return WebAuthn
    creationOptions the browser hands to navigator.credentials.create()."""
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    user = str(body.get("user") or "").strip().lower()
    if not user or not P1_ENV:
        return JSONResponse(status_code=400, content={"error": "username required"})
    # Guard: if this user already has a passkey, don't silently re-enrol — tell the UI.
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            pr = await c.get(f"{PROOFING_DIRECTORY_URL}/passkey/{user}")
            if pr.json().get("credentials"):
                return JSONResponse(status_code=409, content={
                    "error": "already_registered",
                    "detail": f"{user} already has a passkey — sign in instead."})
    except Exception:  # noqa: BLE001
        pass
    try:
        async with httpx.AsyncClient(timeout=25.0) as c:
            tok = await _p1_token(c)
            uid = await _p1_ensure_user(c, tok, user)
            # provision SCIM (best-effort)
            try:
                sr = await c.get(f"{PROOFING_DIRECTORY_URL}/scim/v2/Users",
                                 params={"filter": f'userName eq "{user}"'})
                if not sr.json().get("Resources"):
                    await c.post(f"{PROOFING_DIRECTORY_URL}/scim/v2/Users",
                                 json={"userName": user, "displayName": user.title(),
                                       "active": True})
                await _scim_set_p1id(user, uid)
            except Exception:  # noqa: BLE001
                pass
            # clear any stale pending FIDO2 devices, then create a fresh one
            dr = await c.get(f"{P1_API}/v1/environments/{P1_ENV}/users/{uid}/devices",
                             headers={"Authorization": f"Bearer {tok}"})
            for d in (dr.json().get("_embedded") or {}).get("devices") or []:
                if d.get("status") == "ACTIVATION_REQUIRED":
                    await c.delete(f"{P1_API}/v1/environments/{P1_ENV}/users/{uid}/devices/{d['id']}",
                                   headers={"Authorization": f"Bearer {tok}"})
            r = await c.post(
                f"{P1_API}/v1/environments/{P1_ENV}/users/{uid}/devices",
                headers={"Authorization": f"Bearer {tok}",
                         "Content-Type": "application/vnd.pingidentity.device.fido2+json"},
                json={"type": "FIDO2",
                      "rp": {"id": _rp_id(), "name": "Demo Bank"}})
            if r.status_code >= 300:
                return JSONResponse(status_code=502, content={
                    "error": "device create failed", "detail": r.text[:300]})
            dev = r.json()
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=502, content={"error": str(exc)})
    # creationOptions arrives as a JSON string with signed-byte arrays; convert the two
    # binary fields (challenge, user.id) to base64url for the browser.
    opts = json.loads(dev.get("publicKeyCredentialCreationOptions") or "{}")
    opts["challenge"] = _bytes_to_b64u(opts["challenge"])
    opts["user"]["id"] = _bytes_to_b64u(opts["user"]["id"])
    for ec in opts.get("excludeCredentials") or []:
        if isinstance(ec.get("id"), list):
            ec["id"] = _bytes_to_b64u(ec["id"])
    return {"userId": uid, "deviceId": dev["id"], "user": user, "creationOptions": opts}


@app.post("/signup/passkey/finish")
async def passkey_finish(request: Request):
    """Verify the browser's attestation (the BFF is the WebAuthn RP), store the credential
    so we can later verify sign-in assertions, register the device in PingOne (registry),
    and sign the user in."""
    import webauthn
    body = await request.json()
    uid = body.get("userId"); did = body.get("deviceId")
    attestation = body.get("attestation"); user = str(body.get("user") or "").lower()
    origin = body.get("origin") or APP_BASE_URL
    challenge = body.get("challenge")
    if not (uid and attestation and challenge):
        return JSONResponse(status_code=400, content={"error": "missing fields"})
    # 1. WebAuthn RP verification of the registration (webauthn 3.x takes the JSON string).
    try:
        verification = webauthn.verify_registration_response(
            credential=attestation,
            expected_challenge=base64.urlsafe_b64decode(challenge + "=" * (-len(challenge) % 4)),
            expected_origin=origin,
            expected_rp_id=_rp_id(),
            require_user_verification=True)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=400, content={"error": "verification failed",
                                                      "detail": str(exc)[:200]})
    cred = {"credential_id": _b64u(verification.credential_id),
            "public_key": _b64u(verification.credential_public_key),
            "sign_count": verification.sign_count,
            "pingone_device_id": did}
    # 2. Register the FIDO2 device in PingOne (best-effort — the credential registry).
    try:
        async with httpx.AsyncClient(timeout=20.0) as c:
            tok = await _p1_token(c)
            await c.post(
                f"{P1_API}/v1/environments/{P1_ENV}/users/{uid}/devices/{did}",
                headers={"Authorization": f"Bearer {tok}",
                         "Content-Type": "application/vnd.pingidentity.device.activate+json"},
                json={"origin": origin, "attestation": attestation})
    except Exception:  # noqa: BLE001
        pass
    # 3. Persist the credential for sign-in.
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            await c.put(f"{PROOFING_DIRECTORY_URL}/passkey/{user}", json=cred)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=502, content={"error": "could not save passkey",
                                                      "detail": str(exc)[:200]})
    pf_at = await _broker_passkey_to_pf(user)
    return _passkey_session_response(user, pf_at, new_signup=True)


# ── Federation: after the BFF verifies the passkey it mints a short-lived JWT signed with
# its own key; PingFederate's signupTE token-exchange trusts the BFF JWKS + issuer and mints a
# PF user token (same shape as alice's login). So a passkey sign-in ends as a real PF session —
# the user is logged into the website with full agent/gateway access. ────────────────────────
BFF_PASSKEY_KID = os.environ.get("BFF_PASSKEY_KID", "")
BFF_ISSUER = os.environ.get("BFF_ISSUER", APP_BASE_URL)


@app.get("/passkey/jwks")
def passkey_jwks():
    """JWKS PingFederate fetches to validate the BFF-signed passkey assertion JWT."""
    return {"keys": [{"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256",
                      "kid": BFF_PASSKEY_KID,
                      "x": os.environ.get("BFF_PASSKEY_X", ""),
                      "y": os.environ.get("BFF_PASSKEY_Y", "")}]}


def _mint_passkey_jwt(user: str, acr: str = "urn:northwind:loa:passkey") -> str:
    """`acr` is overridable because not every caller has actually seen a passkey ceremony.
    The Recognize first factor (below) mints the same assertion shape BEFORE any authentication
    has happened, so it must not claim the passkey LoA — it asserts only that this BFF started a
    session for this username. Stamping passkey there would put a false authentication strength
    into a token PF will happily believe."""
    pem = os.environ.get("BFF_PASSKEY_KEY_PEM", "")
    now = int(time.time())
    return jwt.encode(
        {"iss": BFF_ISSUER, "sub": user, "preferred_username": user,
         "aud": SIGNUP_CLIENT_ID or "0ce9dbdf-7d86-461a-b531-0a4afcb508d0",
         "iat": now, "exp": now + 120, "acr": acr},
        pem, algorithm="ES256", headers={"kid": BFF_PASSKEY_KID})


async def _broker_passkey_to_pf(user: str, extra_scope: str = "", resource: str = "") -> str:
    """Exchange the BFF-signed passkey JWT at PF (signupTE) for a PF user access token.

    extra_scope elevates the token for a step-up: the passkey ceremony IS the step-up
    authentication (the assertion carries acr=urn:northwind:loa:passkey), so a payment's
    elevated scope (e.g. banking:payments:transfer) is granted off the SAME passwordless
    passkey the front door uses — no PF password page. The client (northwind-webapp) is
    unrestricted on scopes, so PF grants what's requested here."""
    if not (BFF_PASSKEY_KID and os.environ.get("BFF_PASSKEY_KEY_PEM")):
        return ""
    assertion = _mint_passkey_jwt(user)
    scope = DEFAULT_SCOPES + ((" " + extra_scope) if extra_scope.strip() else "")
    form = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": assertion,
        "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
        "client_id": OIDC_CLIENT_ID, "client_secret": OIDC_CLIENT_SECRET,
        "scope": scope}
    # RFC 8707: request a specific resource → PF selects the ATM whose resource_uris match
    # (e.g. gmJwtATM for the GM API), setting the token's audience accordingly. Empirically
    # PF 13's resource matching lost to the client's default ATM here, so we ALSO pass PF's
    # explicit access_token_manager_id selector (highest precedence) for the GM resource.
    if resource.strip():
        form["resource"] = resource.strip()
        if resource.strip() == GM_RESOURCE:
            form["access_token_manager_id"] = os.environ.get("GM_ATM_ID", "gmJwtATM")
    try:
        async with httpx.AsyncClient(timeout=20.0, verify=False) as c:
            r = await c.post(PF_TOKEN, data=form)
            if r.status_code == 200:
                return r.json().get("access_token", "")
            logger.warning("passkey PF broker failed %s: %s", r.status_code, r.text[:200])
    except Exception as exc:  # noqa: BLE001
        logger.warning("passkey PF broker error: %s", exc)
    return ""


async def _mint_recognize_user_authorization(user: str) -> str:
    """Mint the Recognize "User Authorization" first-factor JWT at PingFederate.

    Returns "" when unavailable — the caller then simply omits the SDK attribute, which is the
    correct behaviour for a tenant that does not enforce the factor. It is deliberately NOT an
    error path: enforcement is a tenant setting only Keyless staff can change, so the demo has to
    work either way.

    The exchange goes through signupTE (not userToAgentTE) so it works with NO existing session —
    at sign-on the user is by definition not authenticated yet, which is the whole point of the
    factor. PF selects recognizeUserAuthATM via the `resource` URN and stamps
    aud=authentication-service, iat/exp (5 min), and sub = preferred_username.

    ⚠ `sub` MUST equal the username handed to the SDK. Both come from the one normalised `user`
    argument here, and the callers pass that same value into the kl-auth/kl-enroll `username`
    attribute. Do not let those two drift: a mismatch is rejected as SERVER_FORBIDDEN before any
    biometric processing, and the wire cannot tell you why (the bodies are end-to-end encrypted).
    """
    if not RECOGNIZE_USERAUTH_ENABLED:
        return ""
    if not (BFF_PASSKEY_KID and os.environ.get("BFF_PASSKEY_KEY_PEM")):
        logger.warning("recognize user-authorization: BFF signing key not configured")
        return ""
    assertion = _mint_passkey_jwt(user, acr="urn:northwind:loa:app-asserted")
    form = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": assertion,
        "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
        "client_id": OIDC_CLIENT_ID, "client_secret": OIDC_CLIENT_SECRET,
        # Selects recognizeUserAuthATM. PF 13 IGNORED access_token_manager_id on this exchange
        # (verified — it returned the client's default userJwtATM instead), so the resource URN
        # is what actually does the work here, not a belt-and-braces extra.
        "resource": RECOGNIZE_USERAUTH_RESOURCE,
    }
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as c:
            r = await c.post(PF_TOKEN, data=form)
            if r.status_code == 200:
                return r.json().get("access_token", "")
            logger.warning("recognize user-authorization mint failed %s: %s",
                           r.status_code, r.text[:200])
    except Exception as exc:  # noqa: BLE001
        logger.warning("recognize user-authorization mint error: %s", exc)
    return ""


# Pending passkey sessions keyed by a one-time code. The finish endpoint runs as a fetch
# (it must POST the assertion), and Safari's ITP does NOT reliably persist a Set-Cookie on a
# fetch/XHR response. Alice's login works because /callback sets the cookie on a top-level 302
# navigation — so we mirror that: finish stashes the session under a code and returns a URL the
# browser navigates to top-level (/passkey/complete), which sets the cookie on a 302 to the app.
_PENDING_SESSIONS: dict[str, tuple[dict, float, bool]] = {}


def _passkey_session_response(user: str, pf_at: str = "", new_signup: bool = False) -> JSONResponse:
    session = {"sub": user, "name": user.title(), "acr": "urn:northwind:loa:passkey"}
    if pf_at:
        session["pf_at"] = pf_at   # real PF token → full website/agent access
    code = secrets.token_urlsafe(24)
    now = time.time()
    for k in [k for k, v in _PENDING_SESSIONS.items() if now - v[1] > 120]:
        _PENDING_SESSIONS.pop(k, None)
    _PENDING_SESSIONS[code] = (session, now, new_signup)
    return JSONResponse({"ok": True, "sub": user, "federated": bool(pf_at),
                         "next": f"/passkey/complete?t={code}"})


@app.get("/passkey/complete")
async def passkey_complete(t: str = ""):
    """Top-level navigation that sets the session cookie on a 302 (Safari-reliable), then
    lands the user in the app signed-in."""
    entry = _PENDING_SESSIONS.pop(t, None)
    if not entry or time.time() - entry[1] > 120:
        return RedirectResponse("/?passkey=expired", status_code=302)
    session, _, new_signup = entry
    dest = "/?signedup=1" if new_signup else "/"
    # NEW USER → face enrolment hand-off. Deliberately here rather than as a node inside the
    # DaVinci registration flow: BOTH new-user paths (the DaVinci flow and the native passkey
    # ceremony) funnel through this one line, so one change covers both, and it avoids surgery on
    # a live 174-node out-of-the-box flow with six subflows. The journey is identical either way —
    # the browser cannot capture a face for this tenant regardless, so a DaVinci node could only
    # ever have redirected here too.
    # Gated on the Server API key because the hand-off page polls /recognize/status; without it
    # the page could never advance and would strand a new user on a dead screen.
    if new_signup and RECOGNIZE_SECRET_API_KEY:
        dest = ("/recognize/enrol-start?user=" + urllib.parse.quote(session["sub"])
                + "&next=" + urllib.parse.quote("/?signedup=1"))
    resp = RedirectResponse(dest, status_code=302)
    resp.set_cookie(SESSION_COOKIE, _sign(session, SESSION_TTL),
                    httponly=True, secure=True, samesite="lax", max_age=SESSION_TTL)
    return resp


# ── Passkey SIGN-IN (returning users). BFF is the WebAuthn RP: it challenges, the browser
# asserts with the stored passkey, the BFF verifies against the stored public key. ─────────
@app.post("/signin/passkey/begin")
async def signin_begin(request: Request):
    import webauthn
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor
    body = await request.json()
    user = str(body.get("user") or "").strip().lower()
    creds = []
    if user:
        try:
            async with httpx.AsyncClient(timeout=8.0) as c:
                pr = await c.get(f"{PROOFING_DIRECTORY_URL}/passkey/{user}")
                creds = pr.json().get("credentials") or []
        except Exception:  # noqa: BLE001
            creds = []
    if user and not creds:
        return JSONResponse(status_code=404, content={"error": "no_passkey",
                            "detail": f"No passkey for {user} — sign up first."})
    allow = [PublicKeyCredentialDescriptor(
                id=base64.urlsafe_b64decode(c["credential_id"] + "=" * (-len(c["credential_id"]) % 4)))
             for c in creds]
    from webauthn.helpers.structs import UserVerificationRequirement
    opts = webauthn.generate_authentication_options(
        rp_id=_rp_id(), allow_credentials=allow or None,
        user_verification=UserVerificationRequirement.REQUIRED)
    optsd = json.loads(webauthn.options_to_json(opts))
    resp = JSONResponse({"user": user, "requestOptions": optsd})
    # remember the challenge for verification (signed, short-lived)
    resp.set_cookie("nw_pk_ch", _sign({"c": optsd["challenge"], "u": user}, 300),
                    httponly=True, secure=True, samesite="lax", max_age=300)
    return resp


@app.post("/signin/passkey/finish")
async def signin_finish(request: Request):
    import webauthn
    body = await request.json()
    assertion = body.get("assertion")
    origin = body.get("origin") or APP_BASE_URL
    tx = _verify(request.cookies.get("nw_pk_ch"))
    if not tx or not assertion:
        return JSONResponse(status_code=400, content={"error": "invalid state"})
    try:
        asr = json.loads(assertion)
        cred_id_b64 = asr["rawId"].replace("+", "-").replace("/", "_").rstrip("=")
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=400, content={"error": "bad assertion", "detail": str(exc)[:150]})
    # find the credential that matches this assertion's id (across users if usernameless)
    user = tx.get("u") or ""
    match = None
    async with httpx.AsyncClient(timeout=8.0) as c:
        candidates = [user] if user else [
            u.get("userName") for u in (await c.get(f"{PROOFING_DIRECTORY_URL}/scim/v2/Users")).json().get("Resources", [])]
        for u in candidates:
            if not u:
                continue
            pr = await c.get(f"{PROOFING_DIRECTORY_URL}/passkey/{u}")
            for cr in pr.json().get("credentials") or []:
                if cr["credential_id"] == cred_id_b64:
                    match = (u, cr); break
            if match:
                break
    if not match:
        return JSONResponse(status_code=404, content={"error": "unknown passkey"})
    u, cr = match
    try:
        webauthn.verify_authentication_response(
            credential=assertion,
            expected_challenge=base64.urlsafe_b64decode(tx["c"] + "=" * (-len(tx["c"]) % 4)),
            expected_origin=origin, expected_rp_id=_rp_id(),
            credential_public_key=base64.urlsafe_b64decode(cr["public_key"] + "=" * (-len(cr["public_key"]) % 4)),
            credential_current_sign_count=int(cr.get("sign_count") or 0),
            require_user_verification=True)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=401, content={"error": "verification failed",
                                                      "detail": str(exc)[:200]})
    # Step-up: /login?stepup stashed the elevated scope + the specific payment in a signed cookie.
    # The passkey ceremony that just succeeded IS the acceptance, so we (a) record the payment as
    # an AUTHORIZED consent in the consent directory — which the PDP looks up when the payment
    # request returns, so the policy passes without the RAR being in the token — and (b) broker a
    # PF token carrying the elevated scope. Then clear the cookie so it can't elevate a later
    # ordinary sign-in.
    su = _verify(request.cookies.get(STEPUP_COOKIE))
    stepup = (su or {}).get("scope", "")
    if stepup and (su or {}).get("amount"):
        txn = await _record_stepup_consent(su, u)
        await _project_delegation_grant(u, stepup, txn,
                                        assurance=(su or {}).get("assurance", ASSURANCE_APP_ASSERTED))
    pf_at = await _broker_passkey_to_pf(u, extra_scope=stepup)
    resp = _passkey_session_response(u, pf_at)
    if stepup:
        resp.delete_cookie(STEPUP_COOKIE)
    return resp


# ── Native passkey sign-in for the approver app ─────────────────────────────────────────────
# The iOS app signs in with the SAME passkey the user created on the web front door (rp.id = this
# host). iOS reaches that credential via Associated Domains — this host serves the AASA below with
# the app's webcredentials entry. On a verified assertion we mint a pairing key + device token, so
# the passkey IS the device sign-in and drives pairing (no QR needed).
IOS_TEAM_ID = os.environ.get("IOS_TEAM_ID", "JH6RX4DRG2")
IOS_BUNDLE_ID = os.environ.get("IOS_BUNDLE_ID", "com.idpartners.bankapprover")
_AASA = {"webcredentials": {"apps": [f"{IOS_TEAM_ID}.{IOS_BUNDLE_ID}"]}}


@app.get("/.well-known/apple-app-site-association")
def apple_app_site_association():
    """Associated Domains manifest: authorizes the approver app to use passkeys whose rp.id is
    this host (webcredentials), so it signs in with the user's existing web passkey."""
    return JSONResponse(_AASA)


@app.get("/apple-app-site-association")
def apple_app_site_association_root():
    return JSONResponse(_AASA)


@app.post("/device/passkey/begin")
async def device_passkey_begin(request: Request):
    """Native app: start a passkey assertion to sign in on THIS device. Returns the WebAuthn
    request options + a signed challenge token the app echoes on finish (no cookies)."""
    import webauthn
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement
    body = await request.json()
    user = str(body.get("user") or "").strip().lower()
    creds = []
    if user:
        try:
            async with httpx.AsyncClient(timeout=8.0) as c:
                pr = await c.get(f"{PROOFING_DIRECTORY_URL}/passkey/{user}")
                creds = pr.json().get("credentials") or []
        except Exception:  # noqa: BLE001
            creds = []
    if user and not creds:
        return JSONResponse(status_code=404, content={"error": "no_passkey",
                            "detail": f"No passkey for {user} — create an account on the web first."})
    allow = [PublicKeyCredentialDescriptor(
                id=base64.urlsafe_b64decode(c["credential_id"] + "=" * (-len(c["credential_id"]) % 4)))
             for c in creds]
    opts = webauthn.generate_authentication_options(
        rp_id=_rp_id(), allow_credentials=allow or None,
        user_verification=UserVerificationRequirement.REQUIRED)
    optsd = json.loads(webauthn.options_to_json(opts))
    return {"requestOptions": optsd, "rpId": _rp_id(),
            "challengeToken": _sign({"c": optsd["challenge"], "u": user}, 300)}


@app.post("/device/passkey/finish")
async def device_passkey_finish(request: Request):
    """Verify the native passkey assertion; on success mint a pairing key + device token for the
    signed-in user so the app pairs (PingOne) and scopes itself to that user."""
    import webauthn
    body = await request.json()
    assertion = body.get("assertion")
    tx = _verify(body.get("challengeToken"))
    origin = body.get("origin") or f"https://{_rp_id()}"
    if not tx or not assertion:
        return JSONResponse(status_code=400, content={"error": "invalid state"})
    try:
        asr = json.loads(assertion) if isinstance(assertion, str) else assertion
        assertion_json = json.dumps(asr)
        cred_id_b64 = str(asr["rawId"]).replace("+", "-").replace("/", "_").rstrip("=")
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=400, content={"error": "bad assertion", "detail": str(exc)[:150]})
    user = tx.get("u") or ""
    match = None
    async with httpx.AsyncClient(timeout=8.0) as c:
        candidates = [user] if user else [
            u.get("userName") for u in (await c.get(f"{PROOFING_DIRECTORY_URL}/scim/v2/Users")).json().get("Resources", [])]
        for u in candidates:
            if not u:
                continue
            pr = await c.get(f"{PROOFING_DIRECTORY_URL}/passkey/{u}")
            for cr in pr.json().get("credentials") or []:
                if cr["credential_id"] == cred_id_b64:
                    match = (u, cr); break
            if match:
                break
    if not match:
        return JSONResponse(status_code=404, content={"error": "unknown passkey"})
    u, cr = match
    try:
        webauthn.verify_authentication_response(
            credential=assertion_json,
            expected_challenge=base64.urlsafe_b64decode(tx["c"] + "=" * (-len(tx["c"]) % 4)),
            expected_origin=origin, expected_rp_id=_rp_id(),
            credential_public_key=base64.urlsafe_b64decode(cr["public_key"] + "=" * (-len(cr["public_key"]) % 4)),
            credential_current_sign_count=int(cr.get("sign_count") or 0),
            require_user_verification=True)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=401, content={"error": "verification failed",
                                                      "detail": str(exc)[:200]})
    # Passkey verified → provision THIS device for the user: a PingOne pairing key + a device token.
    try:
        pk = await _pingone_pairing_key(u)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=502, content={"error": "pairing_key_failed", "detail": str(exc)[:150]})
    key = pk.get("code")
    if not key:
        return JSONResponse(status_code=502, content={"error": "no_pairing_key"})
    return {"user": u, "pairingKey": key, "deviceToken": _mint_device_token(u),
            "expiresAt": pk.get("expiresAt", "")}


@app.get("/signup/callback")
async def signup_callback(request: Request):
    """PingOne redirect: exchange the code, broker the ID token into a PF user token."""
    tx = _verify(request.cookies.get(SIGNUP_TX_COOKIE))
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    if not tx or not code or state != tx.get("state"):
        return JSONResponse(status_code=400, content={"error": "invalid signup state"})
    try:
        async with httpx.AsyncClient(timeout=20.0) as c:
            tr = await c.post(f"{P1_AUTH}/{P1_ENV}/as/token",
                              auth=(SIGNUP_CLIENT_ID, SIGNUP_CLIENT_SECRET),
                              data={"grant_type": "authorization_code", "code": code,
                                    "redirect_uri": APP_BASE_URL + "/signup/callback"})
            tr.raise_for_status()
            p1_tokens = tr.json()
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=502,
                            content={"error": f"PingOne token exchange failed: {exc}"})
    id_token = p1_tokens.get("id_token", "")
    id_claims = jwt.decode(id_token, options={"verify_signature": False}) if id_token else {}
    username = (id_claims.get("preferred_username") or id_claims.get("sub") or "").lower()
    if not username:
        return JSONResponse(status_code=502,
                            content={"error": "no username in PingOne id_token"})

    # Federate the PingOne authentication into PingFederate. PingOne (the OP) authenticated the
    # user at its hosted page; the id_token came straight from PingOne's token endpoint over TLS
    # in this code exchange, so we trust it. The BFF then vouches for that identity with its own
    # short-lived JWT — the key PF's signupTE trusts — and token-exchanges it for a PF user token
    # (same userJwtATM shape as alice's login). Keeping the broker BFF-signed means PF needs no
    # redeploy; the BFF only ever mints it behind a completed PingOne sign-in.
    pf_access = await _broker_passkey_to_pf(username)
    if not pf_access:
        return JSONResponse(status_code=502, content={"error": "PF brokering failed"})
    at_claims = jwt.decode(pf_access, options={"verify_signature": False}) \
        if pf_access.count(".") == 2 else {}
    sub = at_claims.get("sub") or username

    # Provision the customer in the bank's SCIM directory (idempotent). A returning user
    # already exists → plain sign-in; a first-time user is created → "account created" framing.
    is_new = False
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            sr = await c.get(f"{PROOFING_DIRECTORY_URL}/scim/v2/Users",
                             params={"filter": f'userName eq "{sub}"'})
            if not sr.json().get("Resources"):
                is_new = True
                await c.post(f"{PROOFING_DIRECTORY_URL}/scim/v2/Users",
                             json={"userName": sub, "displayName": sub.title(),
                                   "active": True})
    except Exception:  # noqa: BLE001 — directory provisioning is best-effort
        pass

    session = {"sub": sub, "name": id_claims.get("name") or sub.title(),
               "acr": at_claims.get("acr"), "pf_at": pf_access}
    resp = RedirectResponse("/?signedup=1" if is_new else "/", status_code=302)
    resp.set_cookie(SESSION_COOKIE, _sign(session, SESSION_TTL),
                    httponly=True, secure=True, samesite="lax", max_age=SESSION_TTL)
    resp.delete_cookie(SIGNUP_TX_COOKIE)
    return resp


@app.get("/onboarding/qr")
async def onboarding_qr(request: Request):
    """Onboard the customer's PHONE: mint a pairing key for the signed-in user and render
    it as a QR encoding idpapprover://enroll?... — scanning it with the iPhone camera opens
    the approver app, which pairs automatically. That enables the identity-proofing and
    payment-approval pushes for this user."""
    s = _session(request)
    if not s:
        return JSONResponse(status_code=401, content={"error": "login_required"})
    user = (s.get("sub") or "").lower()
    try:
        pk = await _pingone_pairing_key(user)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=502, content={"error": str(exc)})
    key = pk.get("code")
    if not key:
        return JSONResponse(status_code=502, content={"error": "no_pairing_key",
                                                      "detail": json.dumps(pk)[:200]})
    # The QR also carries a DEVICE TOKEN scoped to this signed-in user. The phone stores it and
    # presents it as a Bearer on every BFF call — so the device can only ever act for this user.
    dt = _mint_device_token(user)
    uri = _pairing_uri(user, key, dt)
    return {"user": user, "uri": uri, "svg": _qr_svg(uri), "expiresAt": pk.get("expiresAt", "")}


def _pairing_uri(user: str, key: str, dt: str) -> str:
    return (f"idpapprover://enroll?user={urllib.parse.quote(user)}"
            f"&key={urllib.parse.quote(key)}&dt={urllib.parse.quote(dt)}")


def _qr_svg(uri: str) -> str:
    try:
        import io
        import re
        import qrcode
        import qrcode.image.svg
        # The URI carries a ~170-char device-token JWT, so use LOW error correction to keep the
        # QR from getting too dense to scan (it's a short-lived code scanned up close, not print).
        img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage,
                          error_correction=qrcode.constants.ERROR_CORRECT_L,
                          box_size=14, border=2)
        buf = io.BytesIO()
        img.save(buf)
        svg = buf.getvalue().decode()
        # The library emits a FIXED intrinsic size (e.g. width="91mm" ≈ 344px) that overflows a
        # small container — worse now the QR encodes a long device token, so it grew. Drop the mm
        # dimensions and let the container size it; the viewBox preserves the aspect ratio.
        svg = re.sub(r'\s+(?:width|height)="[0-9.]+mm"', "", svg, count=2)
        svg = svg.replace("<svg ", '<svg style="width:100%;height:auto;display:block" ', 1)
        return svg
    except Exception:  # noqa: BLE001
        return ""


ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")


@app.get("/admin/pairing-qr")
async def admin_pairing_qr(request: Request, user: str = ""):
    """Provision a pairing QR (pairing key + device token) for a STAFF / headless user (e.g.
    bob) who has no browser session to visit /onboarding/qr. Admin-token gated (X-Admin-Token
    header). This is the AUTHENTICATED replacement for the old arbitrary-?user /enroll hole:
    only an operator holding ADMIN_TOKEN can mint a pairing QR for someone else."""
    if not ADMIN_TOKEN or request.headers.get("x-admin-token") != ADMIN_TOKEN:
        return JSONResponse(status_code=401, content={"error": "admin_auth_required"})
    user = (user or "").strip().lower()
    if not user:
        return JSONResponse(status_code=400, content={"error": "user_required"})
    try:
        pk = await _pingone_pairing_key(user)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=502, content={"error": str(exc)})
    key = pk.get("code")
    if not key:
        return JSONResponse(status_code=502, content={"error": "no_pairing_key",
                                                      "detail": json.dumps(pk)[:200]})
    dt = _mint_device_token(user)
    uri = _pairing_uri(user, key, dt)
    return {"user": user, "uri": uri, "svg": _qr_svg(uri), "expiresAt": pk.get("expiresAt", "")}


@app.get("/session/token")
def session_token(request: Request):
    """Return the decoded details of Alice's PingFederate token held in her
    session, so the UI can pop it open and show the real claims."""
    s = _session(request)
    if not s:
        return JSONResponse(status_code=401, content={"error": "not signed in"})
    pf_at = s.get("pf_at", "")
    out: dict = {"principal": {"sub": s.get("sub"), "name": s.get("name"), "acr": s.get("acr")},
                 "has_token": bool(pf_at), "issued_by": "PingFederate (OIDC login)"}
    if pf_at.count(".") == 2:
        out["header"] = jwt.get_unverified_header(pf_at)
        out["claims"] = jwt.decode(pf_at, options={"verify_signature": False})
        out["token_preview"] = pf_at[:32] + "…" + pf_at[-20:]
    return out


@app.post("/logout")
def logout():
    resp = JSONResponse({"status": "logged out"})
    resp.delete_cookie(SESSION_COOKIE)
    return resp


def _forward_headers(s: dict) -> dict:
    """Headers that carry Alice's identity + her PF token to the agent chain."""
    return {"Content-Type": "application/json",
            "X-Principal-Sub": s.get("sub", ""),
            "X-User-Token": s.get("pf_at", "")}


async def _forward_headers_gm(s: dict) -> dict:
    """As _forward_headers, plus X-GM-Token: a token re-audienced for the Grant Management
    API (aud=GM_RESOURCE), minted on demand from the SAME login grant via RFC 8707. The
    session token is aud-less and the GM servlet would reject it; this one satisfies its
    audience check while keeping sub/client_id/agid. Best-effort — absent if the mint fails."""
    h = _forward_headers(s)
    if s.get("pf_at") and s.get("sub"):
        try:
            gm = await _broker_passkey_to_pf(s["sub"], resource=GM_RESOURCE)
            if gm:
                h["X-GM-Token"] = gm
        except Exception as exc:  # noqa: BLE001
            logger.warning("gm-token mint failed: %s", exc)
    return h


@app.post("/invocations")
async def invocations(request: Request):
    # Not gated at the app: a logged-out request is allowed through so the GATEWAY
    # enforces the login (RFC 9470) and challenges. The user token is forwarded
    # only when Alice has a session.
    s = _session(request) or {}
    body = await request.body()
    hdrs = await _forward_headers_gm(s)
    try:
        async with httpx.AsyncClient(timeout=180.0) as c:
            r = await c.post(PRINCIPAL_AGENT_URL + "/invocations",
                             content=body, headers=hdrs)
            return JSONResponse(status_code=r.status_code, content=r.json())
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=502, content={"error": str(exc)})


@app.post("/stream")
async def stream(request: Request):
    # See /invocations: the gateway, not the app, enforces the login challenge.
    s = _session(request) or {}
    body = await request.body()
    hdrs = await _forward_headers_gm(s)

    async def gen():
        async with httpx.AsyncClient(timeout=180.0) as c:
            async with c.stream("POST", PRINCIPAL_AGENT_URL + "/stream",
                                content=body, headers=hdrs) as r:
                async for chunk in r.aiter_raw():
                    yield chunk

    return StreamingResponse(gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"})


@app.post("/reset")
async def reset(request: Request):
    s = _session(request)
    if not s:
        return JSONResponse(status_code=401, content={"error": "login required"})
    body = await request.body()
    async with httpx.AsyncClient(timeout=20.0) as c:
        r = await c.post(PRINCIPAL_AGENT_URL + "/reset", content=body,
                         headers=_forward_headers(s))
        return JSONResponse(status_code=r.status_code, content=r.json())


@app.post("/reset-bank")
async def reset_bank(request: Request):
    s = _session(request)
    if not s:
        return JSONResponse(status_code=401, content={"error": "login required"})
    async with httpx.AsyncClient(timeout=20.0) as c:
        r = await c.post(PRINCIPAL_AGENT_URL + "/reset-bank", headers=_forward_headers(s))
        return JSONResponse(status_code=r.status_code, content=r.json())


# ── PingOne MFA device enrolment (autonomous demo: bootstrap Bob's approver app) ──
P1_ENV = os.environ.get("PINGONE_ENV", "")
P1_AUTH = os.environ.get("PINGONE_AUTH", "https://auth.pingone.asia").rstrip("/")
P1_API = os.environ.get("PINGONE_API", "https://api.pingone.asia").rstrip("/")
P1_CLIENT = os.environ.get("PINGONE_CLIENT_ID", "")
P1_SECRET = os.environ.get("PINGONE_SECRET", "")
P1_BOB = os.environ.get("PINGONE_BOB_ID", "")
P1_APP = os.environ.get("PINGONE_NATIVE_APP_ID", "")


async def _p1_token(c: httpx.AsyncClient) -> str:
    tr = await c.post(f"{P1_AUTH}/{P1_ENV}/as/token",
                      data={"grant_type": "client_credentials"}, auth=(P1_CLIENT, P1_SECRET))
    return tr.json().get("access_token", "")


async def _p1_ensure_user(c: httpx.AsyncClient, tok: str, username: str) -> str:
    """Find-or-create the PingOne user for a bank identity and make sure MFA is enabled.
    Returns the PingOne user id. bob short-circuits to P1_BOB when configured."""
    h = {"Authorization": f"Bearer {tok}"}
    if username == "bob" and P1_BOB:
        return P1_BOB
    r = await c.get(f"{P1_API}/v1/environments/{P1_ENV}/users",
                    params={"filter": f'username eq "{username}"'}, headers=h)
    found = (r.json().get("_embedded") or {}).get("users") or []
    if found:
        uid = found[0]["id"]
    else:
        pr = await c.get(f"{P1_API}/v1/environments/{P1_ENV}/populations", headers=h)
        pops = (pr.json().get("_embedded") or {}).get("populations") or []
        if not pops:
            raise RuntimeError("no PingOne population to create the user in")
        pop = next((p for p in pops if p.get("default")), pops[0])
        # No placeholder email — the passkey/user display would otherwise show the fake
        # "<username>@idpartners.example". A username-only account is fine for the demo.
        cr = await c.post(f"{P1_API}/v1/environments/{P1_ENV}/users", headers=h,
                          json={"username": username,
                                "name": {"given": username.title()},
                                "population": {"id": pop["id"]}})
        if cr.status_code not in (200, 201):
            raise RuntimeError(f"PingOne user create failed: {cr.status_code} {cr.text[:200]}")
        uid = cr.json()["id"]
    # MFA must be enabled or the CIBA push can't target the user's device.
    await c.put(f"{P1_API}/v1/environments/{P1_ENV}/users/{uid}/mfaEnabled",
                headers=h, json={"mfaEnabled": True})
    return uid


async def _scim_set_p1id(user_name: str, p1id: str) -> None:
    """Record the PingOne linkage on the SCIM identity (best-effort)."""
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.get(f"{PROOFING_DIRECTORY_URL}/scim/v2/Users",
                            params={"filter": f'userName eq "{user_name}"'})
            users = r.json().get("Resources", [])
            if users:
                await c.patch(f"{PROOFING_DIRECTORY_URL}/scim/v2/Users/{users[0]['id']}",
                              json={"Operations": [{"op": "replace", "path": "pingOneUserId",
                                                    "value": p1id}]})
    except Exception:  # noqa: BLE001 — SCIM linkage is advisory for the demo
        pass


async def _pingone_pairing_key(user: str) -> dict:
    """Mint a one-time MFA pairing key for a bank identity via the PingOne Management API."""
    async with httpx.AsyncClient(timeout=25.0) as c:
        tok = await _p1_token(c)
        uid = await _p1_ensure_user(c, tok, user)
        await _scim_set_p1id(user, uid)
        r = await c.post(f"{P1_API}/v1/environments/{P1_ENV}/users/{uid}/pairingKeys",
                         headers={"Authorization": f"Bearer {tok}"},
                         json={"applications": [{"id": P1_APP}]})
        return r.json()


@app.get("/enroll")
async def enroll(request: Request, format: str = "html"):
    """Mint + show a pairing key for the SIGNED-IN user's approver app. There is deliberately
    NO arbitrary ?user= — a caller can only ever enrol their OWN identity (the session subject),
    so this can't be used to mint a pairing key for someone else. format=json returns
    {user, code, expiresAt}. (Phones normally pair via the /onboarding/qr QR, which also carries
    a device token; this page is the signed-in user's manual fallback.)"""
    if not (P1_ENV and P1_CLIENT and P1_APP):
        return HTMLResponse("Enrolment not configured — set PINGONE_ENV / PINGONE_CLIENT_ID / "
                            "PINGONE_SECRET / PINGONE_NATIVE_APP_ID.", status_code=503)
    s = _session(request)
    if not s:
        if format == "json":
            return JSONResponse(status_code=401, content={"error": "login_required"})
        return RedirectResponse("/", status_code=302)
    user = (s.get("sub") or "").strip().lower()
    try:
        pk = await _pingone_pairing_key(user)
    except Exception as exc:  # noqa: BLE001
        if format == "json":
            return JSONResponse(status_code=502, content={"error": str(exc)})
        return HTMLResponse(f"Enrolment error: {exc}", status_code=502)
    code = pk.get("code")
    if not code:
        if format == "json":
            return JSONResponse(status_code=502, content={"error": "no_pairing_key",
                                                          "detail": json.dumps(pk)[:300]})
        return HTMLResponse(f"Could not mint pairing key: {json.dumps(pk)[:400]}", status_code=502)
    if format == "json":
        return {"user": user, "code": code, "expiresAt": pk.get("expiresAt", "")}
    return HTMLResponse(_ENROLL_HTML.replace("__CODE__", code)
                        .replace("__EXP__", pk.get("expiresAt", ""))
                        .replace("__USER__", user.title()))


_ENROLL_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Demo Bank — Enrol device</title><style>
:root{--bg:#0d1117;--panel:#161b22;--border:#2d333b;--text:#e6edf3;--muted:#9198a1;--accent:#ff6600}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);
 font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;display:flex;align-items:center;justify-content:center;padding:24px}
.card{width:100%;max-width:440px;background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:30px 28px}
.idp-mark{display:inline-flex;align-items:center;gap:.42em;font-weight:800;letter-spacing:.05em;font-size:20px}
.idp-mark .sq{width:.66em;height:.66em;background:var(--accent);border-radius:2px}
.idp-mark .pa{color:var(--accent)} .bank{color:var(--muted);font-weight:600;margin-left:4px}
h1{font-size:19px;margin:22px 0 4px}.sub{color:var(--muted);font-size:13px;margin:0 0 22px}
.code{font-family:ui-monospace,Menlo,monospace;font-size:30px;font-weight:700;letter-spacing:.12em;
 text-align:center;background:#06090d;border:1px solid #2c4a2f;border-radius:10px;padding:20px;color:#fff;user-select:all}
.exp{text-align:center;color:var(--muted);font-size:12.5px;margin:12px 0 0}
ol{color:var(--muted);font-size:13.5px;line-height:1.6;padding-left:18px;margin:22px 0 4px}
ol b{color:var(--text)}
.btn{display:block;width:100%;margin-top:20px;padding:12px;text-align:center;text-decoration:none;
 background:var(--accent);color:#fff;font-weight:600;border-radius:9px}
.foot{text-align:center;color:var(--muted);font-size:11px;margin-top:16px}
</style></head><body><div class="card">
<div style="display:flex;align-items:center;justify-content:space-between;gap:12px">
  <span style="font-size:20px;font-weight:800">🏦 Demo Bank</span>
  <img src="/static/idp-wordmark.svg" alt="ID Partners" style="height:18px;width:auto;opacity:.9">
</div>
<h1>Enrol this device for approvals</h1>
<p class="sub">__USER__'s phone pairs once, then approves with Face&nbsp;ID.</p>
<div class="code" id="code">__CODE__</div>
<p class="exp" id="exp">Pairing key · one-time · expires <span id="cd">soon</span></p>
<ol>
 <li>Open the <b>ID Partners Bank Approver</b> app on Bob's iPhone.</li>
 <li>Tap <b>Pair this device</b> and enter the key above.</li>
 <li>Approve the test push to confirm.</li>
</ol>
<a class="btn" href="/enroll">Generate a new key</a>
<div class="foot">Secured by PingOne MFA</div>
</div><script>
(function(){var exp=new Date("__EXP__").getTime();function t(){var s=Math.max(0,Math.floor((exp-Date.now())/1000));
document.getElementById('cd').textContent=s>0?('in '+Math.floor(s/60)+'m '+(s%60)+'s'):'— expired, generate a new one';}
if(!isNaN(exp)){t();setInterval(t,1000);}})();
</script></body></html>"""


# The gateway/PEP product shown in the UI. Default Kong; the agentgateway (solo.io) staging
# env sets GATEWAY_LABEL=agentgateway so the diagram + transcript name the real gateway.
GATEWAY_LABEL = os.environ.get("GATEWAY_LABEL", "Kong")

# The bank MCP server whose tools/list carries the COAZ declarations shown in
# the UI's COAZ popup (fetched live so the popup always matches reality).
MCP_TOOLS_URL = os.environ.get("MCP_TOOLS_URL",
                               "http://bank-mcp.railway.internal:8090/mcp")

# --- PDP decisions sidebar, fed by an OpenID Shared Signals Framework (SSF) 1.0 stream ---
#
# PingAuthorize's native AuthZEN servlet is itself an SSF Transmitter: it publishes one
# Security Event Token (RFC 8417) per decision, over every PEP that calls it (Kong,
# coaz-pep, the Grant Management API) — no Go adapter, and no bespoke feed protocol,
# in this path. This app is the (only) SSF Receiver: it registers a push stream on
# startup, accepts the pushed SETs at /ssf/receiver, and rebroadcasts the decisions to
# the browser over the SAME SSE shape the sidebar already rendered, so only the
# transport underneath changed.
PDP_URL = os.environ.get("PDP_URL", "http://pingauthorize.railway.internal:1080").rstrip("/")
PDP_API_KEY = os.environ.get("PDP_API_KEY", "Password1")
SSF_SHARED_SECRET = os.environ.get("SSF_SHARED_SECRET", "")
SSF_EVENT_TYPE = "https://schemas.idpartners.com.au/ssf/authzen-decision"
SSF_RECEIVER_URL = os.environ.get(
    "SSF_RECEIVER_URL",
    "http://{host}:{port}/ssf/receiver".format(
        host=os.environ.get("RAILWAY_PRIVATE_DOMAIN", "localhost"),
        port=os.environ.get("PORT", "8090")))

_PDP_FEED_RING_SIZE = 200
_pdp_ring: deque = deque(maxlen=_PDP_FEED_RING_SIZE)
_pdp_seq = 0
_pdp_subscribers: set = set()


def _pdp_publish(event: dict) -> None:
    """Appends to the ring and fans out to live SSE subscribers. Never raises — a bad
    subscriber queue is dropped from, never lets a slow browser tab back up the feed."""
    global _pdp_seq
    _pdp_seq += 1
    event = {**event, "seq": _pdp_seq}
    _pdp_ring.append(event)
    for q in list(_pdp_subscribers):
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass


@app.on_event("startup")
async def _register_ssf_stream():
    """Registers this app as the PDP's one SSF Receiver (SSF 1.0 section 8.1.1). Without
    SSF_SHARED_SECRET the PDP's SSF surface does not exist at all, so there is nothing to
    register against — the sidebar simply stays empty rather than erroring."""
    if not SSF_SHARED_SECRET:
        logger.info("SSF_SHARED_SECRET not set; the PDP-decisions sidebar will stay empty")
        return
    body = {
        "aud": SSF_RECEIVER_URL,
        "events_requested": [SSF_EVENT_TYPE],
        "delivery": {"method": "urn:ietf:rfc:8935", "endpoint_url": SSF_RECEIVER_URL},
    }
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            r = await c.post(PDP_URL + "/ssf/stream", json=body,
                             headers={"Authorization": f"Bearer {PDP_API_KEY}"})
            r.raise_for_status()
            logger.info("SSF stream registered: stream_id=%s", r.json().get("stream_id"))
    except Exception as exc:  # noqa: BLE001 - the sidebar is informational, never fatal to boot
        logger.warning("SSF stream registration failed (sidebar will stay empty): %s", exc)


@app.post("/ssf/receiver")
async def ssf_receiver(request: Request):
    """SSF push delivery endpoint (RFC 8935): the PDP POSTs one Security Event Token per
    decision here. Verifies the HS256 signature against the shared secret, unwraps the one
    event type this demo cares about, and republishes it to the SSE sidebar. A malformed
    or unverifiable token is rejected (400) rather than silently dropped, so a genuine
    wiring problem is visible in the logs instead of just an empty sidebar."""
    if not SSF_SHARED_SECRET:
        return JSONResponse({"error": "ssf_disabled"}, status_code=404)
    raw = (await request.body()).decode("utf-8")
    try:
        claims = jwt.decode(raw, SSF_SHARED_SECRET, algorithms=["HS256"],
                            audience=SSF_RECEIVER_URL,
                            options={"require": ["iss", "iat", "aud", "events"]})
    except jwt.PyJWTError as exc:
        return JSONResponse({"error": "invalid_set", "detail": str(exc)}, status_code=400)

    event = claims.get("events", {}).get(SSF_EVENT_TYPE)
    if not isinstance(event, dict):
        # A well-formed SET carrying some OTHER event type — not an error, just nothing
        # this Receiver asked for.
        return JSONResponse({"status": "ignored"}, status_code=202)

    try:
        ts = datetime.fromtimestamp(claims.get("iat", time.time()), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        ts = datetime.now(tz=timezone.utc).isoformat()

    _pdp_publish({
        "ts": ts,
        "action": event.get("action"),
        "resource": event.get("resource"),
        "subject": event.get("subject"),
        "decision": event.get("decision"),
        "step_up": bool(event.get("step_up_required")),
        "scope": event.get("step_up_scope"),
        "reason": event.get("reason"),
        "attrs": event.get("attrs"),
    })
    return JSONResponse({"status": "accepted"}, status_code=202)


@app.get("/coaz/tools")
async def coaz_tools():
    """Live tools/list from the bank MCP server, for the COAZ popup: which
    tools declare coaz:true and what their x-coaz-mapping says."""
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.post(MCP_TOOLS_URL, json=payload, headers=headers)
        if r.headers.get("content-type", "").startswith("text/event-stream"):
            line = next(l for l in r.text.splitlines() if l.startswith("data:"))
            data = json.loads(line[len("data:"):])
        else:
            data = r.json()
        return JSONResponse({"tools": data.get("result", {}).get("tools", [])})
    except Exception as exc:  # noqa: BLE001 - popup is informational
        return JSONResponse({"error": str(exc), "tools": []}, status_code=502)


@app.get("/pdp/stream")
async def pdp_stream():
    """Streams decisions to the browser's PDP sidebar from the local ring buffer that
    /ssf/receiver fills — the PDP's own SSF Transmitter is the source, not a proxied
    Go-adapter feed. Replays the recent ring first so a freshly-opened sidebar is not
    empty, then pushes live decisions until the client disconnects."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=64)
    _pdp_subscribers.add(queue)

    async def gen():
        try:
            for event in list(_pdp_ring):
                yield ("event: decision\ndata: " + json.dumps(event) + "\n\n").encode()
            yield b": connected\n\n"
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=20)
                    yield ("event: decision\ndata: " + json.dumps(event) + "\n\n").encode()
                except asyncio.TimeoutError:
                    yield b": ping\n\n"
        finally:
            _pdp_subscribers.discard(queue)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"})


@app.get("/pdp/recent")
async def pdp_recent():
    """One-shot snapshot of recent PDP decisions (polling fallback for the sidebar)."""
    return JSONResponse({"events": list(_pdp_ring)})


@app.get("/")
def index():
    with open(os.path.join(STATIC_DIR, "index.html"), encoding="utf-8") as fh:
        html = fh.read()
    return HTMLResponse(html.replace("__GATEWAY__", GATEWAY_LABEL))


if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8090")))
