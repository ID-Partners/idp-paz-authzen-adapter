"""Resolves issuer signing keys — from a static JWKS or a ``jwks_uri`` (fetched and cached, refreshed on an
unknown ``kid``)."""
from __future__ import annotations

import json
import threading
import urllib.request

import jwt


def _default_get(url):
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.read().decode("utf-8")


def _algorithm_for(jwk):
    kty = jwk.get("kty")
    if kty == "EC":
        return {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}.get(jwk.get("crv"), "ES256")
    if kty == "RSA":
        return "RS256"
    if kty == "OKP":
        return "EdDSA"
    return "RS256"


class JwksProvider:
    def __init__(self, jwks=None, jwks_uri=None, http_get=None):
        self._static = jwks is not None
        self._jwks_uri = jwks_uri
        self._http_get = http_get or _default_get
        self._lock = threading.Lock()
        self._keys = {}
        if jwks is not None:
            self._load(jwks)

    def _load(self, jwks):
        keys = {}
        for jwk in jwks.get("keys", []):
            alg = jwk.get("alg") or _algorithm_for(jwk)
            try:
                keys[jwk.get("kid")] = jwt.get_algorithm_by_name(alg).from_jwk(json.dumps(jwk))
            except Exception:
                continue
        with self._lock:
            self._keys = keys

    def resolve(self, kid, alg=None):
        with self._lock:
            if kid in self._keys:
                return self._keys[kid]
            if kid is None and len(self._keys) == 1:
                return next(iter(self._keys.values()))
        if not self._static and self._jwks_uri:
            self._load(json.loads(self._http_get(self._jwks_uri)))
            with self._lock:
                return self._keys.get(kid)
        return None
