#!/usr/bin/env python3
"""Throwaway CIBA test client — proves the Phase-1 identity flow before we build the
autonomous agent / iOS app.

FAPI-style OpenID Connect CIBA (Client Initiated Backchannel Authentication) against
PingFederate as the OP, with PingOne MFA as the out-of-band approver:

  1. this client POSTs a backchannel authentication request to PingFederate identifying
     Bob (login_hint), asking for the payment scope, carrying the payment as RFC 9396
     authorization_details, and a human-readable binding_message;
  2. PingFederate triggers a PingOne MFA push to Bob's device; Bob approves with Face ID;
  3. this client polls the token endpoint (grant_type urn:openid:params:grant-type:ciba)
     until it gets the delegated token, then decodes it (sub=bob, act={agent},
     authorization_details = the governed payment).

Client authentication is private_key_jwt (FAPI-CIBA requires confidential-client auth).

Usage:
  python ciba.py genkey                 # make an EC key + print the public JWK to register
                                        # on the PingFederate CIBA client
  python ciba.py run                    # run the CIBA flow (reads config from env / flags)

Config via env (or flags):
  PF_BASE                 e.g. https://pingfederate-production-....up.railway.app
  CIBA_ENDPOINT           default: $PF_BASE/as/bc-auth.oauth2   (confirm for your PF)
  TOKEN_ENDPOINT          default: $PF_BASE/as/token.oauth2
  CLIENT_ID               the CIBA client id registered in PF
  PRIVATE_KEY             path to the EC private key PEM (from `genkey`); default ./ciba-key.pem
  LOGIN_HINT              Bob's identifier as PF/PingOne expects it (username/email)
  SCOPE                   default: openid banking:payments:transfer
  AMOUNT / FROM / TO / CURRENCY   the payment to authorize (RAR authorization_details)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

RAR_TYPE = os.environ.get("RAR_TYPE", "payment_initiation")


# ── key handling (EC P-256 / ES256 for private_key_jwt) ──────────────────────────
def _load_key(path: str) -> ec.EllipticCurvePrivateKey:
    with open(path, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)


def _public_jwk(key: ec.EllipticCurvePrivateKey, kid: str) -> dict:
    nums = key.public_key().public_numbers()
    b = lambda n: __import__("base64").urlsafe_b64encode(
        n.to_bytes(32, "big")).rstrip(b"=").decode()
    return {"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256",
            "kid": kid, "x": b(nums.x), "y": b(nums.y)}


def cmd_genkey(args: argparse.Namespace) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    with open(args.key, "wb") as fh:
        fh.write(pem)
    kid = uuid.uuid4().hex[:12]
    print(f"# wrote private key → {args.key}")
    print("# register this JWK on the PingFederate CIBA client's JWKS (client auth = private_key_jwt):")
    print(json.dumps({"keys": [_public_jwk(key, kid)]}, indent=2))


# ── private_key_jwt client assertion ─────────────────────────────────────────────
def _client_assertion(key: ec.EllipticCurvePrivateKey, client_id: str, aud: str) -> str:
    now = int(time.time())
    claims = {"iss": client_id, "sub": client_id, "aud": aud,
              "jti": uuid.uuid4().hex, "iat": now, "exp": now + 300}
    return jwt.encode(claims, _pem(key), algorithm="ES256")


def _pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _rar() -> list[dict]:
    return [{
        "type": RAR_TYPE,
        "purpose": RAR_TYPE,
        "amount": float(os.environ.get("AMOUNT", "150")),
        "currency": os.environ.get("CURRENCY", "AUD"),
        "debtorAccount": os.environ.get("FROM", "CHK-1001"),
        "creditorAccount": os.environ.get("TO", "SAV-1002"),
    }]


# ── the CIBA flow ────────────────────────────────────────────────────────────────
def cmd_run(args: argparse.Namespace) -> None:
    pf_base = os.environ.get("PF_BASE", "").rstrip("/")
    if not pf_base:
        sys.exit("set PF_BASE")
    # PingFederate's backchannel authentication endpoint is /as/bc-auth.ciba (confirmed
    # against PF 13.0 OP metadata: backchannel_authentication_endpoint).
    ciba_ep = os.environ.get("CIBA_ENDPOINT", f"{pf_base}/as/bc-auth.ciba")
    token_ep = os.environ.get("TOKEN_ENDPOINT", f"{pf_base}/as/token.oauth2")
    issuer = os.environ.get("ISSUER", pf_base)   # aud of the signed request object
    client_id = os.environ.get("CLIENT_ID") or sys.exit("set CLIENT_ID")
    login_hint = os.environ.get("LOGIN_HINT") or sys.exit("set LOGIN_HINT (Bob)")
    scope = os.environ.get("SCOPE", "openid banking:payments:transfer")
    key = _load_key(args.key)

    rar = _rar()
    binding = (f"Approve payment {rar[0]['amount']:.2f} {rar[0]['currency']} "
               f"from {rar[0]['debtorAccount']} to {rar[0]['creditorAccount']}")

    with httpx.Client(timeout=30.0, verify=not args.insecure) as c:
        # 1) backchannel authentication request (private_key_jwt client auth).
        # FAPI-CIBA REQUIRES a signed request object (the `request` param) — the auth
        # params ride inside a client-signed JWT. authorization_details (RFC 9396 RAR) is
        # spec-legal in a CIBA request but PF's acceptance is unconfirmed, so we carry it
        # inside the signed request object (best chance PF honours it) and can also flip
        # to flat params with --flat for a non-FAPI PF request policy while debugging.
        req_claims = {
            "iss": client_id, "aud": issuer, "jti": uuid.uuid4().hex,
            "iat": int(time.time()), "exp": int(time.time()) + 300, "nbf": int(time.time()),
            "scope": scope, "login_hint": login_hint,
            "binding_message": binding[:100],   # PF caps binding_message length
            "authorization_details": rar,
        }
        if args.flat:
            form = {"scope": scope, "login_hint": login_hint,
                    "binding_message": binding[:100], "authorization_details": json.dumps(rar)}
        else:
            form = {"request": jwt.encode(req_claims, _pem(key), algorithm="ES256")}
        form.update({
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": _client_assertion(key, client_id, ciba_ep),
        })
        print(f"→ POST {ciba_ep}\n  login_hint={login_hint}  binding='{binding}'")
        r = c.post(ciba_ep, data=form)
        if r.status_code != 200:
            sys.exit(f"backchannel request failed: {r.status_code} {r.text}")
        body = r.json()
        auth_req_id = body["auth_req_id"]
        interval = int(body.get("interval", 5))
        print(f"← auth_req_id={auth_req_id[:16]}…  expires_in={body.get('expires_in')}  "
              f"interval={interval}\n  ⏳ waiting for Bob to approve the push on his device…")

        # 2) poll the token endpoint
        deadline = time.time() + int(body.get("expires_in", 300))
        while time.time() < deadline:
            time.sleep(interval)
            tr = c.post(token_ep, data={
                "grant_type": "urn:openid:params:grant-type:ciba",
                "auth_req_id": auth_req_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": _client_assertion(key, client_id, token_ep),
            })
            if tr.status_code == 200:
                tok = tr.json()
                print("\n✅ approved — delegated token issued")
                _dump_token(tok)
                return
            err = tr.json().get("error") if tr.headers.get("content-type", "").startswith("application/json") else tr.text
            if err == "authorization_pending":
                print("  … pending"); continue
            if err == "slow_down":
                interval += 5; print(f"  … slow_down (interval→{interval})"); continue
            sys.exit(f"\n✖ token error: {err}  ({tr.status_code} {tr.text})")
        sys.exit("\n✖ timed out waiting for approval")


def _dump_token(tok: dict) -> None:
    at = tok.get("access_token", "")
    print(f"  token_type={tok.get('token_type')}  expires_in={tok.get('expires_in')}")
    parts = at.split(".")
    if len(parts) == 3:
        import base64
        pad = lambda s: s + "=" * (-len(s) % 4)
        claims = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
        keep = {k: claims[k] for k in ("sub", "act", "client_id", "scope", "authorization_details") if k in claims}
        print("  access_token claims (decoded, unverified):")
        print("   " + json.dumps(keep, indent=2).replace("\n", "\n   "))


def main() -> None:
    ap = argparse.ArgumentParser(description="CIBA test client (Phase-1 proof)")
    ap.add_argument("--key", default=os.environ.get("PRIVATE_KEY", "ciba-key.pem"))
    ap.add_argument("--insecure", action="store_true", help="skip TLS verify (dev PF)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("genkey").set_defaults(fn=cmd_genkey)
    run_p = sub.add_parser("run")
    run_p.add_argument("--flat", action="store_true",
                       help="send flat params instead of a FAPI signed request object (debug)")
    run_p.set_defaults(fn=cmd_run)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
