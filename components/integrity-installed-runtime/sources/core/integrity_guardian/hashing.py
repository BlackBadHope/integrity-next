"""Domain-separated object identifiers."""

from __future__ import annotations

import hashlib
from typing import Any

from .canonical import canonical_bytes

PROFILE = "guardian-json-v1"


def sha256_digest(payload: bytes) -> str:
    """Return an algorithm-qualified digest."""

    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def digest_object(value: Any, *, domain: str) -> str:
    """Hash one canonical protocol object in an explicit semantic domain."""

    if not domain or any(char.isspace() for char in domain):
        raise ValueError("domain must be a non-empty token without whitespace")
    prefix = f"integrity-guardian\\x00{PROFILE}\\x00{domain}\\x00".encode()
    return sha256_digest(prefix + canonical_bytes(value))
