"""Per-job settings, not launch permission or verified runtime configuration."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
FINITE_EFFORTS = frozenset({"none", "minimal", "low", "medium", "high", "xhigh", "max"})
ROLES = frozenset({"worker", "classifier", "curator", "synthesis", "arbiter"})


def identifier(value: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("invalid opaque identifier")
    return value


def integer(value: int, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError("invalid nonnegative integer")
    return value


def positive(value: float) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise ValueError("invalid positive finite duration or timestamp")
    return float(value)


@dataclass(frozen=True)
class JobPolicy:
    """No environment/global fallback. Persistent is an explicit worker choice."""

    model: str
    role: str = "worker"
    enabled: bool = False
    finite_effort: str = "high"
    supported_efforts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        identifier(self.model)
        if self.role not in ROLES or type(self.enabled) is not bool:
            raise ValueError("invalid job policy")
        if self.finite_effort not in FINITE_EFFORTS:
            raise ValueError("a finite fallback is required")
        if type(self.supported_efforts) is not tuple or any(
            not isinstance(value, str) for value in self.supported_efforts
        ):
            raise ValueError("invalid capability inventory")
        if self.enabled and (self.role != "worker" or "persistent" not in self.supported_efforts):
            raise ValueError("persistent requires an opted-in worker and model capability")

    @property
    def effort(self) -> str:
        return "persistent" if self.enabled else self.finite_effort

    def overrides(self) -> dict[str, object]:
        # The host must merge, then independently verify effective configuration.
        # Never replace mandatory Integrity MCP or managed hooks with an empty map.
        return {
            "model": self.model,
            "model_reasoning_effort": self.effort,
            "features.multi_agent": False,
            "features.multi_agent_v2": False,
            "features.goals": False,
            "approval_policy": "never",
            "sandbox_mode": "read-only",
        }


@dataclass(frozen=True)
class Binding:
    """Correlation from the existing coordinator, explicitly not an admission receipt."""

    job_id: str
    thread_id: str
    turn_id: str
    snapshot_id: str
    control_generation: int

    def __post_init__(self) -> None:
        for value in (self.job_id, self.thread_id, self.turn_id, self.snapshot_id):
            identifier(value)
        integer(self.control_generation)


@dataclass(frozen=True)
class ControlView:
    """Obtained from the trusted host control plane, never from a model event."""

    generation: int
    state: str
    snapshot_id: str

    def __post_init__(self) -> None:
        integer(self.generation)
        identifier(self.snapshot_id)
        if self.state not in {"ACTIVE", "PAUSED", "STOPPED"}:
            raise ValueError("invalid owner control state")


@dataclass(frozen=True)
class Budget:
    """Absolute mission budget supplied afresh by the existing coordinator.

    Persist deadline_epoch and used_tokens across process replacement. Baseline
    is the admitted thread's cumulative usage at attachment, NOT mission usage.
    This event-based token guard can overshoot between provider notifications.
    """

    deadline_epoch: float
    max_tokens: int
    used_tokens: int = 0
    thread_baseline_tokens: int = 0
    max_events: int = 10000
    poll_seconds: float = 0.25
    stop_grace_seconds: float = 2.0

    def __post_init__(self) -> None:
        positive(self.deadline_epoch)
        integer(self.max_tokens, minimum=1)
        integer(self.used_tokens)
        integer(self.thread_baseline_tokens)
        integer(self.max_events, minimum=1)
        if self.max_events > 1000000:
            raise ValueError("event budget is too large")
        if positive(self.poll_seconds) > 1 or positive(self.stop_grace_seconds) > 10:
            raise ValueError("unbounded control or reconciliation interval")
