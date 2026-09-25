"""Closed request contracts; correlation is never authority."""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any

MAX_FRAME = 262144
MAX_OUTPUT = 65536
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,95}\Z")
SHA = re.compile(r"[a-f0-9]{64}\Z")


class Rejected(ValueError):
    """Content-free rejection code safe to return to the model."""


class Unknown(RuntimeError):
    """A sent operation must be reconciled, never blindly retried."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Rejected(code)


def identifier(value: Any) -> str:
    require(type(value) is str and ID.fullmatch(value) is not None, "invalid_identity")
    return value


def integer(value: Any, low: int = 0, high: int = 2**53 - 1) -> int:
    require(type(value) is int and low <= value <= high, "invalid_integer")
    return value


def finite(value: Any) -> float:
    require(type(value) in (int, float) and math.isfinite(value) and value > 0, "invalid_time")
    return float(value)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def _constant(value: str) -> Any:
    raise Rejected("nonfinite_json")


def decode(raw: bytes) -> Any:
    require(type(raw) is bytes and len(raw) <= MAX_FRAME, "frame_limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=_constant)
        # Also rejects floats overflowing from exponent notation and surrogate strings.
        encode(value)
        return value
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise Rejected("invalid_json") from None


def encode(value: Any) -> bytes:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError):
        raise Rejected("invalid_json") from None
    require(len(raw) <= MAX_FRAME, "frame_limit")
    return raw


def freeze(value: Any) -> Any:
    return decode(encode(value))


@dataclass(frozen=True)
class Control:
    """Trusted coordinator observation. No model-owned generation changes."""
    generation: int
    snapshot_id: str
    state: str = "ACTIVE"
    read_allowed: bool = True

    def __post_init__(self):
        integer(self.generation)
        identifier(self.snapshot_id)
        require(self.state in {"ACTIVE", "PAUSED", "STOPPED"}, "invalid_control")
        require(type(self.read_allowed) is bool, "invalid_read_policy")


@dataclass(frozen=True)
class Task:
    """Host registration. Does not grant execution or verify a launch receipt."""
    principal: str
    task_id: str
    generation: int
    snapshot_id: str
    deadline_epoch: float

    def __post_init__(self):
        identifier(self.principal)
        identifier(self.task_id)
        integer(self.generation)
        identifier(self.snapshot_id)
        finite(self.deadline_epoch)
