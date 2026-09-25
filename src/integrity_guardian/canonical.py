"""Deterministic Guardian JSON profile.

The protocol intentionally rejects floating-point values. Cross-runtime float
formatting is not needed by the Guardian wire model and would weaken exact
byte-for-byte verification.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any


class CanonicalizationError(ValueError):
    """Raised when a value is outside the Guardian canonical JSON profile."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalizationError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def parse_json_strict(document: str | bytes | bytearray) -> Any:
    """Parse JSON while rejecting duplicate keys, floats and non-finite values."""

    def reject_float(value: str) -> None:
        raise CanonicalizationError(f"floating-point JSON number is prohibited: {value}")

    def reject_constant(value: str) -> None:
        raise CanonicalizationError(f"non-finite JSON number is prohibited: {value}")

    try:
        return json.loads(
            document,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except CanonicalizationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CanonicalizationError(f"invalid JSON: {exc}") from exc


def _validate(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise CanonicalizationError(f"{path}: floating-point values are prohibited")
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path}: object key must be a string")
            _validate(child, f"{path}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _validate(child, f"{path}[{index}]")
        return
    raise CanonicalizationError(f"{path}: unsupported value type {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Return the unique UTF-8 encoding for a Guardian protocol value."""

    _validate(value)
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalizationError(str(exc)) from exc
    return rendered.encode("utf-8")
