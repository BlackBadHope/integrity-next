"""Pure normalized accounting. Input records are observations, never permissions."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import re
from typing import Any

MAX_COUNT = 10**15
MAX_EVENTS = 4096


class AdviceError(ValueError):
    """Closed, content-free validation failure."""


def integer(value: Any, low: int = 0, high: int = MAX_COUNT) -> int:
    if type(value) is not int or not low <= value <= high:
        raise AdviceError("invalid-integer")
    return value


def symbol(value: Any) -> str:
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", value):
        raise AdviceError("invalid-identifier")
    return value


def digest(value: Any) -> str:
    if type(value) is not str or not re.fullmatch(r"sha256:[a-f0-9]{64}", value):
        raise AdviceError("invalid-digest")
    return value


def identity(value: Any, domain: str) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
    return "sha256:" + sha256(domain.encode("ascii") + b"\0" + raw).hexdigest()


def matches_document(candidate: Any, template: Any) -> bool:
    """Compare a caller document against a bounded, freshly computed JSON tree.

    Walk only the trusted template's shape. Reject custom containers/scalars
    before equality, and distinguish bool/int/float rather than Python's numeric
    coercions. This is not a parser, signature check or input-authentication gate.
    """
    if type(candidate) is not type(template):
        return False
    if type(template) is dict:
        if len(candidate) != len(template) or any(type(key) is not str for key in candidate):
            return False
        return all(key in candidate and matches_document(candidate[key], value)
                   for key, value in template.items())
    if type(template) is list:
        return len(candidate) == len(template) and all(
            matches_document(left, right) for left, right in zip(candidate, template, strict=True))
    return type(template) in (str, int, bool, type(None)) and candidate == template


def optional_count(value: Any) -> None:
    if value is not None:
        integer(value)


@dataclass(frozen=True)
class Tokens:
    """Disjoint charged buckets; reasoning is an output subset, not an extra bill."""

    uncached_input: int | None
    cache_read: int | None
    cache_write: int | None
    output: int | None
    reasoning: int | None = None

    def __post_init__(self) -> None:
        for value in asdict(self).values():
            optional_count(value)
        if self.output is not None and self.reasoning is not None and self.reasoning > self.output:
            raise AdviceError("reasoning-exceeds-output")

    @property
    def charged(self) -> tuple[int | None, ...]:
        return (self.uncached_input, self.cache_read, self.cache_write, self.output)

    @property
    def input_total(self) -> int | None:
        values = self.charged[:3]
        return None if None in values else sum(values)

    @property
    def total(self) -> int | None:
        return None if None in self.charged else sum(self.charged)


def normalize_tokens(*, input_tokens: int | None, output_tokens: int | None,
                     cache_read: int | None, cache_write: int | None,
                     reasoning: int | None, input_includes_cache: bool,
                     output_includes_reasoning: bool) -> Tokens:
    """Provider semantics must be supplied explicitly by the admitted host adapter."""
    if type(input_includes_cache) is not bool or type(output_includes_reasoning) is not bool:
        raise AdviceError("invalid-accounting-semantics")
    for value in (input_tokens, output_tokens, cache_read, cache_write, reasoning):
        optional_count(value)
    uncached = input_tokens
    if input_includes_cache:
        if input_tokens is not None and sum(v or 0 for v in (cache_read, cache_write)) > input_tokens:
            raise AdviceError("cache-exceeds-input")
        uncached = (None if None in (input_tokens, cache_read, cache_write)
                    else input_tokens - cache_read - cache_write)
    output = output_tokens
    if not output_includes_reasoning:
        output = None if None in (output_tokens, reasoning) else output_tokens + reasoning
    return Tokens(uncached, cache_read, cache_write, output, reasoning)


@dataclass(frozen=True)
class Rates:
    """Integer minor units per million tokens; dated, exact-configuration evidence."""

    configuration_id: str
    unit: str
    per_million: tuple[int | None, int | None, int | None, int | None]
    valid_from: int
    valid_until: int
    source_digest: str

    def __post_init__(self) -> None:
        digest(self.configuration_id)
        symbol(self.unit)
        digest(self.source_digest)
        integer(self.valid_from)
        integer(self.valid_until, self.valid_from + 1)
        if type(self.per_million) is not tuple or len(self.per_million) != 4:
            raise AdviceError("invalid-rate-buckets")
        for value in self.per_million:
            optional_count(value)

    def quote(self, usage: Tokens, *, configuration_id: str, now: int) -> int | None:
        integer(now)
        if configuration_id != self.configuration_id:
            raise AdviceError("rate-configuration-mismatch")
        if not self.valid_from <= now < self.valid_until:
            return None
        numerator = 0
        for count, rate in zip(usage.charged, self.per_million, strict=True):
            if count is None or (count != 0 and rate is None):
                return None
            numerator += count * (rate or 0)
        # Round ONCE after summing all disjoint components.
        return integer((numerator + 999_999) // 1_000_000)


@dataclass(frozen=True)
class UsageEvent:
    """One terminal leaf invocation, not a parent total or a streaming delta."""

    invocation_id: str
    root_task_id: str
    task_id: str
    configuration_id: str
    unit: str
    measured_amount: int | None
    tokens: Tokens
    outcome: str
    source_digest: str
    record_kind: str = "leaf-invocation"

    def __post_init__(self) -> None:
        for value in (self.invocation_id, self.root_task_id, self.task_id, self.unit):
            symbol(value)
        digest(self.configuration_id)
        digest(self.source_digest)
        optional_count(self.measured_amount)
        if type(self.tokens) is not Tokens:
            raise AdviceError("invalid-token-record")
        if self.record_kind != "leaf-invocation":
            raise AdviceError("aggregate-usage-not-a-leaf")
        if self.outcome not in ("completed", "failed", "unknown"):
            raise AdviceError("invalid-outcome")


@dataclass(frozen=True)
class UsageSummary:
    root_task_id: str
    unit: str
    known_amount: int
    amount_complete: bool
    known_tokens: int
    tokens_complete: bool
    missing_invocations: tuple[str, ...]
    unknown_operations: tuple[str, ...]
    input_digest: str

    def __post_init__(self) -> None:
        symbol(self.root_task_id)
        symbol(self.unit)
        integer(self.known_amount)
        integer(self.known_tokens)
        digest(self.input_digest)
        for value in (self.amount_complete, self.tokens_complete):
            if type(value) is not bool:
                raise AdviceError("invalid-accounting-completeness")
        for values in (self.missing_invocations, self.unknown_operations):
            if type(values) is not tuple or len(values) > MAX_EVENTS:
                raise AdviceError("invalid-operation-inventory")
            if values != tuple(sorted(set(values))):
                raise AdviceError("noncanonical-operation-inventory")
            for value in values:
                symbol(value)
        if self.missing_invocations and (self.amount_complete or self.tokens_complete):
            raise AdviceError("missing-usage-cannot-be-complete")


def summarize_usage(*, root_task_id: str, unit: str, expected: tuple[str, ...],
                    events: tuple[UsageEvent, ...]) -> UsageSummary:
    """The host's complete invocation inventory is required; omissions remain unknown."""
    symbol(root_task_id)
    symbol(unit)
    if type(expected) is not tuple or type(events) is not tuple:
        raise AdviceError("immutable-inventory-required")
    if len(expected) > MAX_EVENTS or len(events) > MAX_EVENTS:
        raise AdviceError("inventory-too-large")
    for key in expected:
        symbol(key)
    if len(set(expected)) != len(expected):
        raise AdviceError("duplicate-expected-invocation")
    wanted = set(expected)
    observed: dict[str, UsageEvent] = {}
    for event in events:
        if type(event) is not UsageEvent:
            raise AdviceError("invalid-usage-event")
        if event.root_task_id != root_task_id or event.unit != unit:
            raise AdviceError("usage-scope-mismatch")
        if event.invocation_id not in wanted:
            raise AdviceError("undeclared-invocation")
        old = observed.get(event.invocation_id)
        if old is not None and old != event:
            raise AdviceError("conflicting-invocation-record")
        observed[event.invocation_id] = event
    rows = tuple(observed[k] for k in sorted(observed))
    missing = tuple(sorted(wanted - observed.keys()))
    return UsageSummary(
        root_task_id, unit,
        sum(row.measured_amount or 0 for row in rows),
        not missing and all(row.measured_amount is not None for row in rows),
        sum(sum(v or 0 for v in row.tokens.charged) for row in rows),
        not missing and all(row.tokens.total is not None for row in rows),
        missing, tuple(row.invocation_id for row in rows if row.outcome == "unknown"),
        identity({"root": root_task_id, "unit": unit, "expected": sorted(expected),
                  "events": [asdict(row) for row in rows]}, "resource-usage-v1"),
    )
