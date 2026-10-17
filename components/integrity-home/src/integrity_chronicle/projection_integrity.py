"""Canonical projection integrity helpers.

The embedded ``projection_sha256`` is evidence to verify, not an identifier to
trust. All callers compute the digest over the stable projection with that
field removed and reject a mismatching embedded value.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Any, Mapping
import json


def _stable_json(payload: Any) -> str:
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError, UnicodeEncodeError) as err:
        raise ValueError(f"projection is not stable JSON: {err}") from err


def canonical_projection_sha256(projection: Mapping[str, Any]) -> str:
    """Return and, when present, verify the canonical projection digest."""

    if not isinstance(projection, Mapping):
        raise TypeError("projection must be an object")
    unsigned = dict(projection)
    explicit = unsigned.pop("projection_sha256", None)
    try:
        computed = sha256(
            _stable_json(unsigned).encode("utf-8", errors="strict")
        ).hexdigest()
    except UnicodeEncodeError as err:
        raise ValueError("projection contains text that is not valid UTF-8") from err
    if explicit is not None:
        if not isinstance(explicit, str) or not explicit:
            raise ValueError("projection_sha256 must be a non-empty string")
        if explicit != computed:
            raise ValueError("projection_sha256 does not match canonical projection")
    return computed


__all__ = ["canonical_projection_sha256"]
