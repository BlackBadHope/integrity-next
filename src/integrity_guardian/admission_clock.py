"""Strict RFC3339 activation window for agent session admissions.

An admission may be declared for the future, but it is not live before its
activation instant.  Explicit expiry may only narrow the five-hour default;
it can never widen it or invert the interval.
"""

from __future__ import annotations

import datetime as dt
import re

ADMISSION_TTL_HOURS = 5
RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:\d{2})$"
)


class AdmissionClockError(ValueError):
    """Raised before an invalid time value can open an admission window."""


def parse_rfc3339(value: str, *, field: str) -> dt.datetime:
    if not isinstance(value, str) or not value:
        raise AdmissionClockError(f"{field} is required")
    if RFC3339.fullmatch(value) is None:
        raise AdmissionClockError(f"{field} is not RFC3339")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise AdmissionClockError(f"{field} is not RFC3339") from exc
    if parsed.tzinfo is None:
        raise AdmissionClockError(f"{field} must be timezone-aware")
    return parsed


def admission_clock_valid_until(*, declared_at: str, expires_at: str = "") -> dt.datetime:
    declared = parse_rfc3339(declared_at, field="declared_at")
    default_deadline = declared + dt.timedelta(hours=ADMISSION_TTL_HOURS)
    if not expires_at:
        return default_deadline
    explicit = parse_rfc3339(expires_at, field="expires_at")
    if explicit <= declared:
        raise AdmissionClockError("expires_at must be after declared_at")
    if explicit > default_deadline:
        raise AdmissionClockError("expires_at cannot exceed the five-hour admission window")
    return explicit


def admission_is_live(*, now: str, declared_at: str, expires_at: str = "") -> bool:
    current = parse_rfc3339(now, field="now")
    declared = parse_rfc3339(declared_at, field="declared_at")
    valid_until = admission_clock_valid_until(
        declared_at=declared_at,
        expires_at=expires_at,
    )
    return declared <= current < valid_until
