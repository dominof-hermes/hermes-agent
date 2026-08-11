"""Credential helpers for DAOS Memory.

Credentials are opaque random values. Only deterministic digests are persisted;
callers must supply a deployment-specific pepper through secret injection.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets


def new_credential(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def hash_credential(value: str, pepper: str) -> str:
    return hmac.new(pepper.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def credential_matches(value: str, expected: str) -> bool:
    return hmac.compare_digest(value, expected)
