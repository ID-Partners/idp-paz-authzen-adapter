"""Validator configuration."""
from __future__ import annotations

DEFAULT_ALGORITHMS = ("ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512")


class IntrospectionConfig:
    """RFC 7662 introspection endpoint + client credentials (the resource server authenticating to the AS)."""

    def __init__(self, endpoint, client_id, client_secret, auth_method="client_secret_basic"):
        self.endpoint = endpoint
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_method = auth_method  # "client_secret_basic" | "client_secret_post"


class ValidatorConfig:
    """What this resource server accepts: the trusted issuer, its own audience identifier(s), the signing
    keys (static ``jwks`` or a ``jwks_uri`` to fetch), required scopes, accepted algorithms, clock leeway,
    and optional introspection."""

    def __init__(self, issuer, audiences, *, jwks=None, jwks_uri=None, required_scopes=None,
                 accepted_algorithms=DEFAULT_ALGORITHMS, leeway_seconds=60, introspection=None):
        self.issuer = issuer
        self.audiences = [audiences] if isinstance(audiences, str) else list(audiences or [])
        self.jwks = jwks
        self.jwks_uri = jwks_uri
        self.required_scopes = list(required_scopes or [])
        self.accepted_algorithms = tuple(accepted_algorithms)
        self.leeway_seconds = leeway_seconds
        self.introspection = introspection
