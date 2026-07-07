"""Stable validation outcome codes, shared across the Python / TypeScript / Go ports so their verdicts can
be compared directly."""

VALID = "valid"

EXPIRED = "expired"
NOT_YET_VALID = "not_yet_valid"
INVALID_SIGNATURE = "invalid_signature"
INVALID_ISSUER = "invalid_issuer"
INVALID_AUDIENCE = "invalid_audience"
INSUFFICIENT_SCOPE = "insufficient_scope"
INVALID_TOKEN = "invalid_token"
UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
KEY_NOT_FOUND = "key_not_found"
INACTIVE = "inactive"
