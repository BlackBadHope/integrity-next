"""Domain-separated object identifiers."""

from __future__ import annotations

import hashlib
from typing import Any

from .canonical import canonical_bytes

PROFILE = "guardian-json-v1"

# guardian-json-v1 frames digest input with the four ASCII characters
# ``\\x00`` (backslash, "x", "0", "0"), not with a NUL byte. Every retained
# digest depends on these bytes, so the frame is frozen for this profile.
# Domains may not contain a backslash, which keeps the frame unambiguous.
FRAME_SEPARATOR = "\\x00"


def sha256_digest(payload: bytes) -> str:
    """Return an algorithm-qualified digest."""

    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def validate_domain(domain: str) -> None:
    """Reject a domain that could blur the digest frame."""

    if (
        not isinstance(domain, str)
        or not domain
        or any(char.isspace() or not char.isprintable() or char == "\\" for char in domain)
    ):
        raise ValueError(
            "domain must be a non-empty printable token without whitespace or backslash"
        )


def digest_object(value: Any, *, domain: str) -> str:
    """Hash one canonical protocol object in an explicit semantic domain."""

    validate_domain(domain)
    frame = FRAME_SEPARATOR
    prefix = f"integrity-guardian{frame}{PROFILE}{frame}{domain}{frame}".encode()
    return sha256_digest(prefix + canonical_bytes(value))
