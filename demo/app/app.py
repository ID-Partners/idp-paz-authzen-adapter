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
async def proofing_by_code(code: str):
    """The approver app resolves the push's reference code to the full proofing request —
    most importantly the openid4vp:// request_uri it opens app2app into the wallet."""
    p = _PROOFINGS.get(code)
    if not p:
        return JSONResponse(status_code=404, content={"error": "unknown_code"})
    return p


@app.get("/proofing/latest")
async def proofing_latest():
    """The approver's no-code fallback: the pi.flow push can't reliably deliver even the
    20-char reference code to the app (clientContext is dropped; the alert text is
    template-dependent), so on any push the app asks for the most recent FRESH proofing
    request and opens its openid4vp:// link app2app. Mirrors the payment flow's
    latest-pending-consent fallback."""
    now = int(time.time())
    fresh = [p for p in _PROOFINGS.values() if now - p.get("created", 0) < 300]
    if not fresh:
        return JSONResponse(status_code=404, content={"error": "no_pending_proofing"})
    return sorted(fresh, key=lambda p: p["created"])[-1]


# ── Identity roster for the approver app (proxies the SCIM directory; the app can't
# reach the internal network) ──
@app.get("/identities")
async def identities():
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.get(f"{PROOFING_DIRECTORY_URL}/scim/v2/Users")
            users = r.json().get("Resources", [])
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": "directory_unreachable",
                                                      "detail": str(e)})
    ext = "urn:idpartners:scim:1.0:BankUser"
    return {"identities": [{"userName": u.get("userName"),
                            "displayName": u.get("displayName"),
                            "paired": (u.get(ext) or {}).get("devicePaired", False),
                            "pingOneUserId": (u.get(ext) or {}).get("pingOneUserId")}
                           for u in users]}


@app.post("/identities/{user_name}/reconcile")
async def identities_reconcile(user_name: str):
    """Sync the directory's pairing state from PingOne (source of truth). Recovers the
    approver-app case where pair() reported an error but the device actually enrolled
    (e.g. racing pairing keys)."""
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
    """The approver app reports pairing state changes (sign-in/sign-out) → SCIM PATCH."""
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


@app.get("/login")
async def login(request: Request):
    """Kick off the OIDC authorization-code + PKCE flow at PingFederate.

    By default Alice consents to the everyday scopes. A `?stepup=<scope>` request
    is a step-up: it adds the elevated scope (e.g. banking:payments:transfer) and
    forces re-authentication (prompt=login) — RFC 9470 step-up for a risky action.
    For a payment, the specific operation is attached as RFC 9396 authorization_details
    and pushed via PAR (RFC 9126) so Alice consents to THIS payment at the AS.
    """
    verifier = _b64u(secrets.token_bytes(40))
    challenge = _b64u(hashlib.sha256(verifier.encode()).digest())
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    stepup = (request.query_params.get("stepup") or "").strip()
    scope = DEFAULT_SCOPES + ((" " + stepup) if stepup else "")
    params = {"client_id": OIDC_CLIENT_ID, "response_type": "code",
              "redirect_uri": REDIRECT_URI, "scope": scope,
              "code_challenge": challenge, "code_challenge_method": "S256",
              "state": state, "nonce": nonce}
    if stepup:
        params["prompt"] = "login consent"   # force re-auth AND the consent/approval page
    # Assert the authenticated principal so the RAR governance decision is attributed to Alice, not the
    # OAuth client. PingFederate's AuthorizationDetailProcessor SDK exposes no resource-owner accessor, so
    # the pf-rar-paz-plugin reads this login_hint as the decision's UserID (the agent stays the 'actor').
    sess = _session(request)
    principal_sub = sess.get("sub") if sess else None
    if principal_sub:
        params["login_hint"] = principal_sub   # carries on the non-PAR path
    rar = _payment_rar(request)
    if rar:
        # Fold the authenticated principal into each authorization_details entry. PingFederate does not
        # surface PAR-pushed request params (login_hint) to the AuthorizationDetailProcessor, but it DOES
        # hand it the authorization_details — the reliable PAR-surviving channel for the pf-rar-paz-plugin
        # to attribute the governance decision to Alice as UserID (agent recorded as 'actor'). The plugin
        # reads '_principal_sub' then strips it, so it never reaches the consent page or the issued token.
        if principal_sub:
            for entry in rar:
                entry["_principal_sub"] = principal_sub
        params["authorization_details"] = json.dumps(rar)
        # Record the consent (status=requested) keyed by the minted transaction id.
        await _record_consent(rar, principal_sub or "alice")

    authz = None
    if rar:
        # PAR: push the request (incl. authorization_details) to PF, reference it by
        # request_uri — keeps the RAR payload off the browser URL.
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=False) as c:
                pr = await c.post(PF_PAR, data={**params, "client_secret": OIDC_CLIENT_SECRET})
                pr.raise_for_status()
                request_uri = pr.json()["request_uri"]
            authz = (PF_AUTHORIZE + "?" +
                     urllib.parse.urlencode({"client_id": OIDC_CLIENT_ID, "request_uri": request_uri}))
        except Exception:  # noqa: BLE001 - fall back to a plain (non-PAR) request
            authz = PF_AUTHORIZE + "?" + urllib.parse.urlencode(params)
    else:
        authz = PF_AUTHORIZE + "?" + urllib.parse.urlencode(params)

    resp = RedirectResponse(authz, status_code=302)
    # Stash the PKCE verifier + state in a short-lived signed cookie.
    resp.set_cookie(TX_COOKIE, _sign({"v": verifier, "state": state, "nonce": nonce}, 600),
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
<title>Sign up — ID Partners Bank</title>
<style>body{font-family:-apple-system,system-ui,sans-serif;background:#101418;color:#e8e8e8;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#1a2027;border:1px solid #2a323c;border-radius:14px;padding:34px;width:360px}
h1{font-size:19px;margin:0 0 6px}p{color:#9aa5b1;font-size:13px;line-height:1.5}
input{width:100%;box-sizing:border-box;padding:11px;border-radius:8px;border:1px solid #2a323c;
background:#101418;color:#e8e8e8;font-size:15px;margin:12px 0}
button{width:100%;padding:12px;border:0;border-radius:8px;background:#2d7a4f;color:#fff;
font-size:15px;font-weight:600;cursor:pointer}button:disabled{opacity:.5}
#msg{font-size:13px;margin-top:12px;min-height:18px}.err{color:#ff8b7b}.ok{color:#5fd08a}</style>
</head><body>
<div class="card"><h1>🔑 Bank passkey</h1>
<p>Enter your username. New here? We'll create a <b>passkey</b> (Face&nbsp;ID, or scan the QR to
save it to your iPhone). Already registered? Sign in with your passkey.</p>
<input id="u" placeholder="username (e.g. carol)" pattern="[a-z0-9._-]{2,30}" autofocus>
<button id="go">Continue</button>
<button id="signin" style="background:#2a3340;margin-top:8px;display:none">Sign in with passkey</button>
<div id="msg"></div></div>
<script>
const b64uToBuf = s => { s = s.replace(/-/g,'+').replace(/_/g,'/'); s += '='.repeat((4-s.length%4)%4);
  const bin = atob(s); const b = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) b[i]=bin.charCodeAt(i); return b.buffer; };
const bufToB64u = buf => { const b = new Uint8Array(buf); let s='';
  for (let i=0;i<b.length;i++) s+=String.fromCharCode(b[i]);
  return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,''); };
const msg = (t,c) => { const m=document.getElementById('msg'); m.textContent=t; m.className=c||''; };
const uname = () => document.getElementById('u').value.trim().toLowerCase();

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
    setTimeout(()=>location.href='/?signedup=1', 700); }
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
  if(fin.ok){ msg('✓ Signed in — welcome back…', 'ok'); setTimeout(()=>location.href='/', 600); }
  else msg(fin.error+(fin.detail?': '+fin.detail:''), 'err');
}

document.getElementById('go').onclick = async () => {
  const user = uname();
  if(!/^[a-z0-9._-]{2,30}$/.test(user)){ msg('Pick a valid username.', 'err'); return; }
  const btn = document.getElementById('go'); btn.disabled = true;
  try {
    const chk = await fetch('/signup/check?user='+encodeURIComponent(user)).then(r=>r.json());
    if(chk.hasPasskey){ msg('That account has a passkey — signing you in…'); await doSignin(user); }
    else if(chk.exists){ msg('Account exists — adding a passkey…'); await doCreate(user); }
    else { await doCreate(user); }
  } catch(e){ msg('Passkey cancelled or failed: '+e.message, 'err'); }
  btn.disabled = false;
};
// usernameless sign-in (discoverable credential) — let Safari offer any saved passkey
document.getElementById('signin').style.display='block';
document.getElementById('signin').onclick = async () => {
  const btn = document.getElementById('signin'); btn.disabled = true;
  try { await doSignin(''); } catch(e){ msg('Sign-in failed: '+e.message,'err'); }
  btn.disabled = false;
};
</script></body></html>"""


@app.get("/signup")
async def signup(user: str = ""):
    """Passkey sign-up (BFF-orchestrated WebAuthn). The whole passkey ceremony runs on THIS
    origin so the browser's WebAuthn works directly (Safari Face ID + save-to-iPhone QR):
    the BFF creates the PingOne user, PingOne's FIDO2 device API issues the
    publicKeyCredentialCreationOptions (rp.id = this host), the browser creates the passkey,
    and the BFF activates it. No password, no DaVinci, no PingOne hosted redirect."""
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
                      "rp": {"id": _rp_id(), "name": "ID Partners Bank"}})
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
    return _passkey_session_response(user)


def _passkey_session_response(user: str) -> JSONResponse:
    session = {"sub": user, "name": user.title(), "acr": "urn:northwind:loa:passkey"}
    resp = JSONResponse({"ok": True, "sub": user})
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
    return _passkey_session_response(u)


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

    # Broker into PF: the PingOne ID token is the RFC 8693 subject token; PF validates
    # iss/signature/audience (signupTE) and mints a userJwtATM token, sub = username.
    try:
        async with httpx.AsyncClient(timeout=20.0, verify=False) as c:
            xr = await c.post(PF_TOKEN, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": id_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                "client_id": OIDC_CLIENT_ID, "client_secret": OIDC_CLIENT_SECRET,
                "scope": DEFAULT_SCOPES})
            if xr.status_code != 200:
                return JSONResponse(status_code=502, content={
                    "error": "PF brokering failed", "detail": xr.text[:300]})
            pf_access = xr.json().get("access_token", "")
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(status_code=502,
                            content={"error": f"PF brokering failed: {exc}"})
    at_claims = jwt.decode(pf_access, options={"verify_signature": False}) \
        if pf_access.count(".") == 2 else {}
    sub = at_claims.get("sub") or username

    # Provision the new customer in the bank's SCIM directory (idempotent).
    try:
        async with httpx.AsyncClient(timeout=8.0) as c:
            sr = await c.get(f"{PROOFING_DIRECTORY_URL}/scim/v2/Users",
                             params={"filter": f'userName eq "{sub}"'})
            if not sr.json().get("Resources"):
                await c.post(f"{PROOFING_DIRECTORY_URL}/scim/v2/Users",
                             json={"userName": sub, "displayName": sub.title(),
                                   "active": True})
    except Exception:  # noqa: BLE001 — directory provisioning is best-effort
        pass

    session = {"sub": sub, "name": id_claims.get("name") or sub.title(),
               "acr": at_claims.get("acr"), "pf_at": pf_access}
    resp = RedirectResponse("/?signedup=1", status_code=302)
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
    uri = f"idpapprover://enroll?user={urllib.parse.quote(user)}&key={urllib.parse.quote(key)}"
    try:
        import io
        import qrcode
        import qrcode.image.svg
        img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage,
                          box_size=14, border=2)
        buf = io.BytesIO()
        img.save(buf)
        svg = buf.getvalue().decode()
    except Exception as exc:  # noqa: BLE001
        svg = ""
    return {"user": user, "uri": uri, "svg": svg, "expiresAt": pk.get("expiresAt", "")}


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
        cr = await c.post(f"{P1_API}/v1/environments/{P1_ENV}/users", headers=h,
                          json={"username": username, "email": f"{username}@idpartners.example",
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
async def enroll(user: str = "bob", format: str = "html"):
    """Mint + show a pairing key for an identity's approver app (?user=alice|bob).
    format=json returns {user, code, expiresAt} for the app's in-app sign-in flow."""
    if not (P1_ENV and P1_CLIENT and P1_APP):
        return HTMLResponse("Enrolment not configured — set PINGONE_ENV / PINGONE_CLIENT_ID / "
                            "PINGONE_SECRET / PINGONE_NATIVE_APP_ID.", status_code=503)
    user = (user or "bob").strip().lower()
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
<title>ID Partners Bank — Enrol device</title><style>
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
<div><span class="idp-mark"><span class="sq"></span>ID<span class="pa">PARTNERS</span></span><span class="bank">Bank</span></div>
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
