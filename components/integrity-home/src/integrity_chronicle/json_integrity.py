"""Strict JSON decoding helpers for evidence and control-plane artifacts."""

from __future__ import annotations

from typing import Any, Dict, IO, List, Tuple
import json


class DuplicateJsonKeyError(ValueError):
    """Raised instead of silently applying JSON last-key-wins semantics."""


def _object_without_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def load_json_strict(stream: IO[str]) -> Any:
    return json.load(stream, object_pairs_hook=_object_without_duplicates)


def loads_json_strict(value: str) -> Any:
    return json.loads(value, object_pairs_hook=_object_without_duplicates)


__all__ = ["DuplicateJsonKeyError", "load_json_strict", "loads_json_strict"]
