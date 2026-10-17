"""Strict canonical JSON and typed failures. No I/O, no ambient state."""
from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any

MAX_DOCUMENT_BYTES = 256 * 1024
MAX_DEPTH = 32
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


class Rejected(ValueError):
    """Refused before any effect; the code is content-free."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class Unknown(RuntimeError):
    """An effect may have happened; never convert this into permission to retry."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def need(condition: object, code: str) -> None:
    if not condition:
        raise Rejected(code)


def identifier(value: Any, code: str = "identifier") -> str:
    need(type(value) is str and _IDENTIFIER.fullmatch(value) is not None, code)
    return value


def session_uuid(value: Any) -> str:
    need(type(value) is str and _UUID.fullmatch(value) is not None, "session_uuid")
    return value


def digest_value(value: Any, code: str = "digest") -> str:
    need(type(value) is str and _DIGEST.fullmatch(value) is not None, code)
    return value


def bounded_int(value: Any, low: int, high: int, code: str) -> int:
    need(type(value) is int and low <= value <= high, code)
    return value


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _check_tree(node: Any, depth: int = 0) -> None:
    need(depth <= MAX_DEPTH, "json_depth")
    kind = type(node)
    if node is None or kind in (bool, int):
        need(kind is not int or -(2**63) <= node < 2**63, "json_integer_range")
        return
    if kind is str:
        try:
            node.encode("utf-8", errors="strict")
        except UnicodeError:
            raise Rejected("json_lone_surrogate") from None
        return
    if kind is list:
        for item in node:
            _check_tree(item, depth + 1)
        return
    if kind is dict:
        for key, item in node.items():
            need(type(key) is str, "json_key_type")
            _check_tree(key, depth + 1)
            _check_tree(item, depth + 1)
        return
    # Floats are excluded from bound identities: they have no single canonical text.
    raise Rejected("json_type")


def canonical_bytes(value: Any, limit: int = MAX_DOCUMENT_BYTES) -> bytes:
    _check_tree(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                     allow_nan=False).encode("utf-8")
    need(len(raw) <= limit, "json_size")
    return raw


def digest_object(domain: str, value: Any) -> str:
    identifier(domain, "digest_domain")
    return sha256_bytes(domain.encode("ascii") + b"\x00" + canonical_bytes(value))


def strict_loads(raw: bytes, limit: int = MAX_DOCUMENT_BYTES) -> Any:
    """Parse untrusted JSON; reject duplicates, NaN/Infinity, bad UTF-8 and lone surrogates."""
    need(type(raw) is bytes and len(raw) <= limit, "json_size")

    def pairs(items):
        result = {}
        for key, item in items:
            need(key not in result, "json_duplicate_key")
            result[key] = item
        return result

    def constant(_):
        raise Rejected("json_nonfinite")

    def finite(text):
        value = float(text)
        need(math.isfinite(value), "json_nonfinite")
        return value

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        raise Rejected("json_utf8") from None
    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant,
                           parse_float=finite)
    except Rejected:
        raise
    except (ValueError, RecursionError):
        raise Rejected("json_syntax") from None
    _check_tree_untrusted(value)
    return value


def _check_tree_untrusted(node: Any, depth: int = 0) -> None:
    need(depth <= MAX_DEPTH, "json_depth")
    if type(node) is float:
        return
    if type(node) is str:
        try:
            node.encode("utf-8", errors="strict")
        except UnicodeError:
            raise Rejected("json_lone_surrogate") from None
    elif type(node) is list:
        for item in node:
            _check_tree_untrusted(item, depth + 1)
    elif type(node) is dict:
        for key, item in node.items():
            _check_tree_untrusted(key, depth + 1)
            _check_tree_untrusted(item, depth + 1)
