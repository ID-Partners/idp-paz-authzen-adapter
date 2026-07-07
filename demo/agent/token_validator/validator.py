"""Access-token validation: JWT signature + claim checks, and optional RFC 7662 introspection."""
from __future__ import annotations

import base64
import json
import time
import urllib.parse
import urllib.request

import jwt

from . import errors
from .jwks import JwksProvider
from .result import ValidationResult


def _default_post(url, body, headers):
    request = urllib.request.Request(url, data=body.encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


class AccessTokenValidator:
    """Validates access tokens for a resource server.

    ``validate`` does local JWT validation in a fixed order — algorithm accepted, key resolvable, signature,
    ``iss``, ``exp``, ``nbf``, audience, then scope — returning the first failure's stable error code. That
    order is part of the cross-language contract so every port reports the same verdict. ``validate_active``
    instead uses RFC 7662 introspection.
    """

    def __init__(self, config, http_post=None, http_get=None):
        self.config = config
        self._jwks = JwksProvider(jwks=config.jwks, jwks_uri=config.jwks_uri, http_get=http_get)
        self._http_post = http_post or _default_post

    def validate(self, token, required_scopes=None):
        required = self.config.required_scopes if required_scopes is None else list(required_scopes)

        try:
            header = jwt.get_unverified_header(token)
        except Exception as exc:
            return ValidationResult.failure(errors.INVALID_TOKEN, f"malformed token: {exc}")

        alg = header.get("alg")
        if alg not in self.config.accepted_algorithms:
            return ValidationResult.failure(errors.UNSUPPORTED_ALGORITHM, f"algorithm '{alg}' not accepted")

        key = self._jwks.resolve(header.get("kid"), alg)
        if key is None:
            return ValidationResult.failure(errors.KEY_NOT_FOUND, f"no signing key for kid '{header.get('kid')}'")

        try:
            claims = jwt.decode(token, key, algorithms=[alg], options={
                "verify_signature": True, "verify_exp": False, "verify_nbf": False,
                "verify_iat": False, "verify_aud": False, "verify_iss": False,
            })
        except jwt.InvalidSignatureError:
            return ValidationResult.failure(errors.INVALID_SIGNATURE, "signature verification failed")
        except jwt.DecodeError as exc:
            return ValidationResult.failure(errors.INVALID_SIGNATURE, str(exc))
        except jwt.PyJWTError as exc:
            return ValidationResult.failure(errors.INVALID_TOKEN, str(exc))

        if self.config.issuer and claims.get("iss") != self.config.issuer:
            return ValidationResult.failure(errors.INVALID_ISSUER, f"unexpected issuer '{claims.get('iss')}'")

        now = int(time.time())
        leeway = self.config.leeway_seconds
        exp = claims.get("exp")
        if exp is not None and now > int(exp) + leeway:
            return ValidationResult.failure(errors.EXPIRED, "token has expired")
        nbf = claims.get("nbf")
        if nbf is not None and now + leeway < int(nbf):
            return ValidationResult.failure(errors.NOT_YET_VALID, "token is not yet valid")

        audience = _as_list(claims.get("aud"))
        if self.config.audiences and not any(a in audience for a in self.config.audiences):
            return ValidationResult.failure(errors.INVALID_AUDIENCE, "token audience is not accepted")

        granted = _scopes(claims)
        missing = [s for s in required if s not in granted]
        if missing:
            return ValidationResult.failure(errors.INSUFFICIENT_SCOPE, "missing scopes: " + " ".join(missing))

        return ValidationResult.success(claims, granted, audience)

    def introspect(self, token, token_type_hint="access_token"):
        """RFC 7662: POST the token to the AS introspection endpoint and return the parsed response."""
        cfg = self.config.introspection
        if cfg is None:
            raise ValueError("no introspection endpoint configured")
        form = {"token": token, "token_type_hint": token_type_hint}
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        if cfg.auth_method == "client_secret_basic":
            raw = f"{cfg.client_id}:{cfg.client_secret}".encode("utf-8")
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        else:
            form["client_id"] = cfg.client_id
            form["client_secret"] = cfg.client_secret
        return self._http_post(cfg.endpoint, urllib.parse.urlencode(form), headers)

    def validate_active(self, token, required_scopes=None):
        """Introspect the token and enforce ``active`` plus scope/audience from the response."""
        data = self.introspect(token)
        if not data.get("active"):
            return ValidationResult.failure(errors.INACTIVE, "token is not active")
        required = self.config.required_scopes if required_scopes is None else list(required_scopes)
        granted = _scopes(data)
        missing = [s for s in required if s not in granted]
        if missing:
            return ValidationResult.failure(errors.INSUFFICIENT_SCOPE, "missing scopes: " + " ".join(missing))
        audience = _as_list(data.get("aud"))
        if self.config.audiences and audience and not any(a in audience for a in self.config.audiences):
            return ValidationResult.failure(errors.INVALID_AUDIENCE, "token audience is not accepted")
        return ValidationResult.success(data, granted, audience)


def _as_list(value):
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def _scopes(claims):
    scope = claims.get("scope")
    if isinstance(scope, str):
        return scope.split()
    scp = claims.get("scp")
    if isinstance(scp, list):
        return list(scp)
    return []
