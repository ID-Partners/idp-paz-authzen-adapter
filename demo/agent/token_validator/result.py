"""The outcome of validating an access token."""
from __future__ import annotations


class ValidationResult:
    """Either a valid token (with its subject, granted scopes, audience and claims) or a failure carrying a
    stable ``error`` code (see :mod:`token_validator.errors`)."""

    def __init__(self, valid, *, error=None, error_description=None, subject=None,
                 scopes=None, audience=None, claims=None, expires_at=None):
        self.valid = valid
        self.error = error
        self.error_description = error_description
        self.subject = subject
        self.scopes = list(scopes or [])
        self.audience = list(audience or [])
        self.claims = dict(claims or {})
        self.expires_at = expires_at

    def __bool__(self):
        return self.valid

    @classmethod
    def success(cls, claims, scopes, audience):
        return cls(True, subject=claims.get("sub"), scopes=scopes, audience=audience,
                   claims=claims, expires_at=claims.get("exp"))

    @classmethod
    def failure(cls, error, description=None):
        return cls(False, error=error, error_description=description)

    def __repr__(self):
        if self.valid:
            return f"ValidationResult(valid, sub={self.subject!r}, scopes={self.scopes})"
        return f"ValidationResult(invalid, error={self.error!r}: {self.error_description})"
