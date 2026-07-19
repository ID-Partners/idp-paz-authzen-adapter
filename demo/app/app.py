"""
Northwind Web App (BFF) — the app server, separate from the principal agent.

This is the public front door Alice uses. It is an OpenID Connect client of the
real PingFederate: it redirects Alice to PingFederate's hosted login page, and on
return holds her session (her PF id_token + access_token). It then proxies chat
requests to the (headless) principal agent over the private network, forwarding
Alice's identity and her PF access token so the downstream gateway can enforce
that a real user is logged in (RFC 9470 step-up challenge — see Phase 3).

    GET  /                → the web UI
    GET  /login           → redirect to PingFederate (authorization code + PKCE)
    GET  /callback        → exchange the code, establish the session, back to /
    GET  /me              → the signed-in principal (or 401)
    POST /logout          → clear the session
    POST /stream          → proxy (SSE) to the principal agent, carrying Alice's identity
    POST /invocations     → proxy (JSON) to the principal agent
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import urllib.parse

import httpx
import jwt  # PyJWT
from fastapi import FastAPI, Request
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               RedirectResponse, StreamingResponse)
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Northwind Web App (BFF)")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# --- config ------------------------------------------------------------------
# Public PingFederate base (its TCP proxy). The app talks to PF over the public
# endpoint because the browser is redirected there for login.
PF_BASE = os.environ.get("PF_BASE_URL", "https://hayabusa.proxy.rlwy.net:49245").rstrip("/")
PF_AUTHORIZE = os.environ.get("PF_AUTHORIZE_URL", PF_BASE + "/as/authorization.oauth2")
PF_TOKEN = os.environ.get("PF_TOKEN_URL", PF_BASE + "/as/token.oauth2")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "northwind-webapp")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "webapp-secret-123")
# This app's own public base URL — the redirect_uri is <APP_BASE_URL>/callback.
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:8090").rstrip("/")
REDIRECT_URI = APP_BASE_URL + "/callback"
# The headless principal agent (private network).
PRINCIPAL_AGENT_URL = os.environ.get("PRINCIPAL_AGENT_URL",
                                     "http://bank-agent.railway.internal:8000").rstrip("/")
APP_SECRET = os.environ.get("APP_SECRET", "northwind-bff-secret")
SESSION_TTL = int(os.environ.get("SESSION_TTL", "28800"))  # 8h
# Everyday scopes Alice consents to at first login. The sensitive
# banking:payments:transfer is NOT here — it requires a step-up (re-auth).
DEFAULT_SCOPES = os.environ.get("DEFAULT_SCOPES",
                                "openid banking:accounts:list banking:accounts:originate")
SESSION_COOKIE = "nw_session"
TX_COOKIE = "nw_oidc_tx"  # short-lived: holds PKCE verifier + state during the redirect
STEPUP_COOKIE = "nw_stepup"  # short-lived: carries the requested step-up scope across the passkey ceremony


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


PF_PAR = os.environ.get("PF_PAR_URL", PF_BASE + "/as/par.oauth2")
RAR_TYPE = os.environ.get("PAYMENT_RAR_TYPE", "payment_initiation")

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
    subject = s.get("sub") or "alice"
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
        # Scope the record to the account this proofing was FOR (from the in-flight
        # proofing registered by /proofing/begin, matched by verifier session).
        account = next((p.get("account") or "" for p in _PROOFINGS.values()
                        if p.get("session_id") == session_id), "")
        try:
            async with httpx.AsyncClient(timeout=8.0) as c:
                pr = await c.post(f"{PROOFING_DIRECTORY_URL}/proofing", json={
                    "subject": subject, "doctype": PROOFING_DOCTYPE, "method": "oid4vp",
                    "claims": d.get("claims") or {}, "session_id": session_id,
                    "account": account})
                recorded = pr.status_code < 300
        except Exception:
            recorded = False
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
    subject = (s.get("sub") if s else None) or user.strip().lower() or "alice"
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
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as c:
            r = await c.post(f"{VERIFIER_URL}/verify/start", json={"credential": "mdl"})
            r.raise_for_status()
            v = r.json()
    except Exception as e:
        return JSONResponse(status_code=502,
                            content={"error": "verifier_unreachable", "detail": str(e)})
    code = "MDL-" + secrets.token_hex(3)  # ≤20 chars, CIBA binding_message charset-safe
    _PROOFINGS[code] = {"code": code, "session_id": v.get("session_id"),
                        "request_uri": v.get("request_uri"), "subject": subject,
                        "doctype": PROOFING_DOCTYPE, "account": account,
                        "created": int(time.time())}
    pushed, detail = await _ciba_push(subject, code)
    return {"code": code, "session_id": v.get("session_id"),
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
    return sorted(fresh, key=lambda p: p["created"])[-1]


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


def _payment_rar(request: Request) -> list | None:
    """Build an RFC 9396 authorization_details entry from the step-up payment
    params, so Alice consents to THIS specific payment at PingFederate (governed
    by Ping Authorize at issuance) rather than to a coarse scope."""
    amount = (request.query_params.get("amount") or "").strip()
    if not amount:
        return None
    try:
        amt = float(amount)
    except ValueError:
        return None
    return [{
        "type": RAR_TYPE,
        "purpose": RAR_TYPE,                       # dot-free marker the PAZ policy reads
        "amount": amt,
        "currency": (request.query_params.get("cur") or "AUD").strip(),
        "debtorAccount": (request.query_params.get("from") or "").strip(),
        "creditorAccount": (request.query_params.get("to") or "").strip(),
        # The consent's TRANSACTION ID: minted here, recorded in the consent directory,
        # and carried inside the authorization_details through PAR → PF → the issued
        # token → the gateways → the payments RS, which stamps the executed payment
        # with it. This is the consent→grant→token→action audit link.
        "transactionId": "txn_" + secrets.token_hex(6),
    }]


async def _record_consent(rar: list, subject: str, status: str = "requested") -> None:
    """Persist the payment authorization consent to the directory (best-effort)."""
    if not rar:
        return
    e = rar[0]
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            await c.post(f"{PROOFING_DIRECTORY_URL}/consents", json={
                "transaction_id": e.get("transactionId"),
                "subject": subject, "actor": subject, "channel": "rar-stepup",
                "amount": e.get("amount"), "currency": e.get("currency"),
                "debtor_account": e.get("debtorAccount"),
                "creditor_account": e.get("creditorAccount"),
                "authorization_details": [
                    {k: v for k, v in d.items() if k != "_principal_sub"} for d in rar],
                "status": status})
    except Exception:  # noqa: BLE001 — consent persistence must never block the login
        pass


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
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            await c.post(f"{PROOFING_DIRECTORY_URL}/consents", json={
                "transaction_id": txn,
                "subject": subject, "actor": subject, "channel": "passkey-stepup",
                "amount": amt, "currency": su.get("currency") or "AUD",
                "debtor_account": su.get("debtor") or "",
                "creditor_account": su.get("creditor") or "",
                "status": "authorized"})
        logger.info("recorded passkey-stepup consent txn=%s subject=%s amount=%s creditor=%s",
                    txn, subject, amt, su.get("creditor"))
    except Exception as exc:  # noqa: BLE001 — must never block the passkey sign-in
        logger.warning("stepup consent record failed: %s", exc)
    return txn


@app.get("/login")
async def login(request: Request):
    """Kick off the OIDC authorization-code + PKCE flow at PingFederate.

    By default Alice consents to the everyday scopes. A `?stepup=<scope>` request
    is a step-up: it adds the elevated scope (e.g. banking:payments:transfer) and
    forces re-authentication (prompt=login) — RFC 9470 step-up for a risky action.
    For a payment, the specific operation is attached as RFC 9396 authorization_details
    and pushed via PAR (RFC 9126) so Alice consents to THIS payment at the AS.
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


@app.get("/callback")
async def callback(request: Request):
    """Handle the redirect back from PingFederate: exchange the code, set the session."""
    tx = _verify(request.cookies.get(TX_COOKIE))
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    if not tx or not code or state != tx.get("state"):
        return JSONResponse(status_code=400, content={"error": "invalid login state"})
    try:
        async with httpx.AsyncClient(timeout=20.0, verify=False) as c:
            tr = await c.post(PF_TOKEN, data={
                "grant_type": "authorization_code", "code": code,
                "redirect_uri": REDIRECT_URI, "client_id": OIDC_CLIENT_ID,
                "client_secret": OIDC_CLIENT_SECRET, "code_verifier": tx["v"]})
            tr.raise_for_status()
            tok = tr.json()
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=502, content={"error": f"token exchange failed: {exc}"})

    # We received the tokens directly from PF over TLS in the code exchange, so we
    # trust them without re-verifying the signature (demo BFF).
    id_claims = jwt.decode(tok["id_token"], options={"verify_signature": False}) \
        if tok.get("id_token") else {}
    sub = id_claims.get("sub", "alice")
    pf_access = tok.get("access_token", "")
    at_claims = {}
    if pf_access.count(".") == 2:
        at_claims = jwt.decode(pf_access, options={"verify_signature": False})
    session = {"sub": sub, "name": id_claims.get("name") or sub,
               "acr": at_claims.get("acr"), "pf_at": pf_access}

    # The issued token carrying our authorization_details = Alice consented at PF and
    # the RAR passed governance. Advance the consent record(s) to 'authorized' by the
    # transaction id riding in the details (best-effort; never blocks the login).
    for d in (at_claims.get("authorization_details") or []):
        txn = isinstance(d, dict) and d.get("transactionId")
        if txn:
            try:
                async with httpx.AsyncClient(timeout=8.0) as c:
                    await c.patch(f"{PROOFING_DIRECTORY_URL}/consents/{txn}", json={
                        "status": "authorized",
                        "authorization_details": at_claims["authorization_details"]})
            except Exception:  # noqa: BLE001
                pass

    resp = RedirectResponse("/", status_code=302)
    resp.set_cookie(SESSION_COOKIE, _sign(session, SESSION_TTL),
                    httponly=True, secure=True, samesite="lax", max_age=SESSION_TTL)
    resp.delete_cookie(TX_COOKIE)
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
    <input id="su" placeholder="username (optional)" autocomplete="username webauthn"
           autocapitalize="none">
    <button class="primary" id="signinBtn">Sign in with passkey</button>
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
  const fin = await fetch('/signin/passkey/finish', {method:'POST',
    headers:{'content-type':'application/json'},
    body: JSON.stringify({origin: location.origin, assertion: JSON.stringify(asr)})}).then(r=>r.json());
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

// Step-up: /login?stepup=1&u=<user> sent an ALREADY signed-in user here to approve a payment.
// Skip the create/choose screen (they have an account) and go straight to a pre-filled passkey
// sign-in, relabelled as payment approval. One tap — WebAuthn needs a user gesture, so we don't
// auto-fire it. This is the "login hint" so the step-up never offers 'create a new account'.
(function(){
  const q = new URLSearchParams(location.search);
  if(q.get('stepup') !== '1') return;
  const u = (q.get('u')||'').toLowerCase();
  show('signin');
  if(u && valid(u)) $('su').value = u;
  const h = $('signin').querySelector('h1'); if(h) h.textContent = 'Approve this payment';
  const p = $('signin').querySelector('p'); if(p) p.textContent = 'Confirm with your passkey to authorise the payment.';
  $('signinBtn').textContent = 'Approve with passkey';
})();
</script></body></html>"""


@app.get("/signup")
async def signup(user: str = ""):
    """Front door = PASSWORDLESS passkey / security-key (WebAuthn on this BFF). Create an
    account or sign in with a passkey or YubiKey — no password anywhere. The whole ceremony
    runs on this origin so the browser's WebAuthn works directly (Safari Face ID + save-to-
    iPhone QR, or a roaming security key): the BFF creates the PingOne user, PingOne's FIDO2
    device API issues the creationOptions (rp.id = this host), the browser creates the
    credential, and the BFF activates it. PingOne holds the identity; PF is brokered via
    signupTE. No DaVinci, no hosted password page."""
    return HTMLResponse(_SIGNUP_HTML)


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


def _mint_passkey_jwt(user: str) -> str:
    pem = os.environ.get("BFF_PASSKEY_KEY_PEM", "")
    now = int(time.time())
    return jwt.encode(
        {"iss": BFF_ISSUER, "sub": user, "preferred_username": user,
         "aud": SIGNUP_CLIENT_ID or "0ce9dbdf-7d86-461a-b531-0a4afcb508d0",
         "iat": now, "exp": now + 120, "acr": "urn:northwind:loa:passkey"},
        pem, algorithm="ES256", headers={"kid": BFF_PASSKEY_KID})


async def _broker_passkey_to_pf(user: str, extra_scope: str = "") -> str:
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
    try:
        async with httpx.AsyncClient(timeout=20.0, verify=False) as c:
            r = await c.post(PF_TOKEN, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": assertion,
                "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                "client_id": OIDC_CLIENT_ID, "client_secret": OIDC_CLIENT_SECRET,
                "scope": scope})
            if r.status_code == 200:
                return r.json().get("access_token", "")
            logger.warning("passkey PF broker failed %s: %s", r.status_code, r.text[:200])
    except Exception as exc:  # noqa: BLE001
        logger.warning("passkey PF broker error: %s", exc)
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
        await _record_stepup_consent(su, u)
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


@app.post("/invocations")
async def invocations(request: Request):
    # Not gated at the app: a logged-out request is allowed through so the GATEWAY
    # enforces the login (RFC 9470) and challenges. The user token is forwarded
    # only when Alice has a session.
    s = _session(request) or {}
    body = await request.body()
    try:
        async with httpx.AsyncClient(timeout=180.0) as c:
            r = await c.post(PRINCIPAL_AGENT_URL + "/invocations",
                             content=body, headers=_forward_headers(s))
            return JSONResponse(status_code=r.status_code, content=r.json())
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=502, content={"error": str(exc)})


@app.post("/stream")
async def stream(request: Request):
    # See /invocations: the gateway, not the app, enforces the login challenge.
    s = _session(request) or {}
    body = await request.body()

    async def gen():
        async with httpx.AsyncClient(timeout=180.0) as c:
            async with c.stream("POST", PRINCIPAL_AGENT_URL + "/stream",
                                content=body, headers=_forward_headers(s)) as r:
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

# The AuthZEN PDP adapter (the front door to Ping Authorize's governance engine).
# Its /pdp/events SSE stream feeds the UI's live "PDP decisions" sidebar so you can
# watch each PERMIT / DENY / step-up as the demo runs.
ADAPTER_URL = os.environ.get("ADAPTER_URL",
                             "http://authzen-adapter.railway.internal:8080").rstrip("/")


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
    """Proxy the adapter's live decision SSE feed to the browser's PDP sidebar.
    Each event is one Ping Authorize decision (PERMIT / DENY / step-up)."""
    async def gen():
        try:
            async with httpx.AsyncClient(timeout=None) as c:
                async with c.stream("GET", ADAPTER_URL + "/pdp/events") as r:
                    async for chunk in r.aiter_raw():
                        yield chunk
        except Exception as exc:  # noqa: BLE001 - sidebar is informational
            yield ("event: error\ndata: " +
                   json.dumps({"error": str(exc)}) + "\n\n").encode()

    return StreamingResponse(gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"})


@app.get("/pdp/recent")
async def pdp_recent():
    """One-shot snapshot of recent PDP decisions (polling fallback for the sidebar)."""
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            r = await c.get(ADAPTER_URL + "/pdp/recent")
        return JSONResponse(r.json())
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc), "events": []}, status_code=502)


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
