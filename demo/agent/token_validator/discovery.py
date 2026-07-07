"""Minimal AS-metadata discovery (RFC 8414 / OpenID Connect Discovery)."""
from __future__ import annotations

import json
import urllib.request


def _default_get(url):
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.read().decode("utf-8")


def discover(metadata_url, http_get=None):
    """Fetch an authorization-server metadata document, e.g.
    ``https://issuer.example.com/.well-known/oauth-authorization-server``. The returned dict carries
    ``issuer``, ``jwks_uri`` and ``introspection_endpoint`` to feed into a
    :class:`~token_validator.config.ValidatorConfig`."""
    get = http_get or _default_get
    return json.loads(get(metadata_url))
