"""Deterministic L0 alarm-to-model routing for Guardian Atlas.

This module chooses a capability class and records the decision. It never calls
a model, opens a network connection or grants production authority.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .hashing import digest_object
from .schemas import validate


class CognitiveTier(StrEnum):
    SENTINEL = "L1"
    ANALYST = "L2"
    ARBITER = "L3"


class ReasoningClass(StrEnum):
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MAXIMUM = "maximum"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlarmKind(StrEnum):
    ROUTINE_DELTA = "routine_delta"
    CORRELATED_CHANGE = "correlated_change"
    SENSOR_GAP = "sensor_gap"
    STALE_EVIDENCE = "stale_evidence"
    SIGNATURE_FAILURE = "signature_failure"
    CHECKPOINT_SPLIT_VIEW = "checkpoint_split_view"
    LEDGER_GAP = "ledger_gap"
    CROSS_TENANT = "cross_tenant"
    AGENT_SPLIT_BRAIN = "agent_split_brain"
    SCOPE_BREACH = "scope_breach"
    CRITICAL_FINDING = "critical_finding"
    BLAST_RADIUS_UNKNOWN = "blast_radius_unknown"
    TRUSTED_SOURCE_CONTRADICTION = "trusted_source_contradiction"
    REPEATED_INCIDENT = "repeated_incident"
    MODEL_INSUFFICIENT = "model_insufficient"
    OWNER_ESCALATION = "owner_escalation"


TIER_RANK = {
    CognitiveTier.SENTINEL: 1,
    CognitiveTier.ANALYST: 2,
    CognitiveTier.ARBITER: 3,
}
REASONING_RANK = {
    ReasoningClass.MINIMAL: 1,
    ReasoningClass.LOW: 2,
    ReasoningClass.MEDIUM: 3,
    ReasoningClass.HIGH: 4,
    ReasoningClass.MAXIMUM: 5,
}
SEVERITY_RANK = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}
MANDATORY_ARBITER_ALARMS = {
    AlarmKind.SIGNATURE_FAILURE,
    AlarmKind.CHECKPOINT_SPLIT_VIEW,
    AlarmKind.LEDGER_GAP,
    AlarmKind.CROSS_TENANT,
    AlarmKind.AGENT_SPLIT_BRAIN,
    AlarmKind.SCOPE_BREACH,
    AlarmKind.CRITICAL_FINDING,
    AlarmKind.BLAST_RADIUS_UNKNOWN,
    AlarmKind.TRUSTED_SOURCE_CONTRADICTION,
    AlarmKind.REPEATED_INCIDENT,
    AlarmKind.MODEL_INSUFFICIENT,
    AlarmKind.OWNER_ESCALATION,
}


class ModelRoutingError(ValueError):
    """Raised when routing inputs are ambiguous or outside policy."""


@dataclass(frozen=True)
class AlarmSignal:
    tenant_id: str
    incident_id: str
    alarm_id: str
    kind: AlarmKind
    severity: Severity
    protected_scope: bool = False
    evidence_complete: bool = True
    blast_radius: str = "small"
    age_seconds: int = 0
    recurrence_count: int = 0
    optional_budget_exhausted: bool = False

    def __post_init__(self) -> None:
        if not self.tenant_id.startswith("tenant:"):
            raise ModelRoutingError("alarm tenant identity is not canonical")
        if not self.incident_id.startswith("incident:"):
            raise ModelRoutingError("alarm incident identity is not canonical")
        if not self.alarm_id.startswith("alarm:"):
            raise ModelRoutingError("alarm identity is not canonical")
        if self.blast_radius not in {"small", "medium", "large", "unknown"}:
            raise ModelRoutingError("alarm blast radius is not recognized")
        if self.age_seconds < 0 or self.recurrence_count < 0:
            raise ModelRoutingError("alarm counters cannot be negative")


@dataclass(frozen=True)
class ModelDescriptor:
    model_id: str
    provider: str
    capability_tier: CognitiveTier
    max_reasoning: ReasoningClass
    capability_rank: int
    generation: int
    cost_rank: int
    local: bool
    available: bool = True

    def __post_init__(self) -> None:
        if not self.model_id or not self.provider:
            raise ModelRoutingError("model identity and provider are required")
        if min(self.capability_rank, self.generation, self.cost_rank) < 0:
            raise ModelRoutingError("model ranks cannot be negative")

    def record(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "provider": self.provider,
            "capability_tier": self.capability_tier.value,
            "max_reasoning": self.max_reasoning.value,
            "capability_rank": self.capability_rank,
            "generation": self.generation,
            "cost_rank": self.cost_rank,
            "local": self.local,
            "available": self.available,
        }


@dataclass(frozen=True)
class ModelRoutePolicy:
    policy_id: str
    approved_providers: tuple[str, ...]
    local_only: bool = False
    l1_input_tokens: int = 8_000
    l1_output_tokens: int = 1_000
    l2_input_tokens: int = 32_000
    l2_output_tokens: int = 4_000
    l3_input_tokens: int = 128_000
    l3_output_tokens: int = 16_000
    max_specialist_agents: int = 4
    protected_gap_arbiter_seconds: int = 900

    def __post_init__(self) -> None:
        if not self.policy_id.startswith("policy:"):
            raise ModelRoutingError("model route policy identity is not canonical")
        if not self.approved_providers:
            raise ModelRoutingError("at least one model provider must be approved")
        if len(set(self.approved_providers)) != len(self.approved_providers):
            raise ModelRoutingError("approved model providers must be unique")
        token_limits = (
            self.l1_input_tokens,
            self.l1_output_tokens,
            self.l2_input_tokens,
            self.l2_output_tokens,
            self.l3_input_tokens,
            self.l3_output_tokens,
        )
        if min(token_limits) <= 0:
            raise ModelRoutingError("model token budgets must be positive")
        if not 0 <= self.max_specialist_agents <= 16:
            raise ModelRoutingError("specialist fan-out is outside the bounded range")
        if self.protected_gap_arbiter_seconds < 0:
            raise ModelRoutingError("gap escalation threshold cannot be negative")

    def record(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "approved_providers": sorted(self.approved_providers),
            "local_only": self.local_only,
            "l1_input_tokens": self.l1_input_tokens,
            "l1_output_tokens": self.l1_output_tokens,
            "l2_input_tokens": self.l2_input_tokens,
            "l2_output_tokens": self.l2_output_tokens,
            "l3_input_tokens": self.l3_input_tokens,
            "l3_output_tokens": self.l3_output_tokens,
            "max_specialist_agents": self.max_specialist_agents,
            "protected_gap_arbiter_seconds": self.protected_gap_arbiter_seconds,
        }


def _required_route(
    signal: AlarmSignal,
    policy: ModelRoutePolicy,
) -> tuple[CognitiveTier, ReasoningClass, bool, list[str]]:
    reasons: list[str] = [f"alarm:{signal.kind.value}"]
    if signal.kind in MANDATORY_ARBITER_ALARMS:
        return (
            CognitiveTier.ARBITER,
            ReasoningClass.MAXIMUM,
            True,
            reasons + ["mandatory:arbiter"],
        )
    if signal.severity == Severity.CRITICAL:
        return (
            CognitiveTier.ARBITER,
            ReasoningClass.MAXIMUM,
            True,
            reasons + ["severity:critical"],
        )
    if signal.blast_radius in {"large", "unknown"}:
        return (
            CognitiveTier.ARBITER,
            ReasoningClass.MAXIMUM,
            True,
            reasons + [f"blast-radius:{signal.blast_radius}"],
        )
    if signal.recurrence_count >= 2:
        return (
            CognitiveTier.ARBITER,
            ReasoningClass.MAXIMUM,
            True,
            reasons + ["incident:repeated"],
        )
    if signal.kind in {AlarmKind.SENSOR_GAP, AlarmKind.STALE_EVIDENCE}:
        if (
            signal.protected_scope
            and signal.age_seconds >= policy.protected_gap_arbiter_seconds
        ):
            return (
                CognitiveTier.ARBITER,
                ReasoningClass.MAXIMUM,
                True,
                reasons + ["protected-gap:expired"],
            )
        return (
            CognitiveTier.ANALYST,
            ReasoningClass.HIGH,
            signal.protected_scope,
            reasons + ["evidence:incomplete"],
        )
    if not signal.evidence_complete or signal.severity == Severity.HIGH:
        return (
            CognitiveTier.ANALYST,
            ReasoningClass.HIGH,
            False,
            reasons + ["analysis:high"],
        )
    if (
        signal.kind == AlarmKind.CORRELATED_CHANGE
        or signal.severity == Severity.MEDIUM
        or signal.blast_radius == "medium"
    ):
        return (
            CognitiveTier.ANALYST,
            ReasoningClass.MEDIUM,
            False,
            reasons + ["analysis:correlated"],
        )
    return (
        CognitiveTier.SENTINEL,
        ReasoningClass.MINIMAL,
        False,
        reasons + ["analysis:routine"],
    )


def _select_model(
    *,
    required_tier: CognitiveTier,
    minimum_reasoning: ReasoningClass,
    policy: ModelRoutePolicy,
    registry: list[ModelDescriptor],
) -> ModelDescriptor | None:
    eligible = [
        model
        for model in registry
        if model.available
        and model.provider in policy.approved_providers
        and (not policy.local_only or model.local)
        and TIER_RANK[model.capability_tier] >= TIER_RANK[required_tier]
        and REASONING_RANK[model.max_reasoning]
        >= REASONING_RANK[minimum_reasoning]
    ]
    if not eligible:
        return None
    if required_tier == CognitiveTier.SENTINEL:
        return min(eligible, key=lambda model: (
                model.cost_rank,
                TIER_RANK[model.capability_tier],
                -model.capability_rank,
                -model.generation,
                model.model_id,
            ))
    if required_tier == CognitiveTier.ANALYST:
        return min(eligible, key=lambda model: (
                TIER_RANK[model.capability_tier],
                -model.capability_rank,
                model.cost_rank,
                -model.generation,
                model.model_id,
            ))
    return min(eligible, key=lambda model: (
            -model.capability_rank,
            -model.generation,
            -REASONING_RANK[model.max_reasoning],
            model.cost_rank,
            model.model_id,
        ))


def route_model(
    *,
    signal: AlarmSignal,
    policy: ModelRoutePolicy,
    registry: list[ModelDescriptor],
) -> dict[str, Any]:
    """Return a deterministic route receipt without invoking a model."""

    model_ids = [model.model_id for model in registry]
    if len(set(model_ids)) != len(model_ids):
        raise ModelRoutingError("model registry identities must be unique")
    required_tier, reasoning, mandatory, reasons = _required_route(signal, policy)
    selected = _select_model(
        required_tier=required_tier,
        minimum_reasoning=reasoning,
        policy=policy,
        registry=registry,
    )
    if signal.optional_budget_exhausted and not mandatory:
        selected = None
        reasons.append("budget:optional-exhausted")
    if selected is None:
        reasons.append("model:unavailable")

    if required_tier == CognitiveTier.SENTINEL:
        max_input = policy.l1_input_tokens
        max_output = policy.l1_output_tokens
        specialists = 0
    elif required_tier == CognitiveTier.ANALYST:
        max_input = policy.l2_input_tokens
        max_output = policy.l2_output_tokens
        specialists = 0
    else:
        max_input = policy.l3_input_tokens
        max_output = policy.l3_output_tokens
        specialists = policy.max_specialist_agents

    policy_digest = digest_object(policy.record(), domain="model-route-policy-v1")
    registry_records = sorted(
        (model.record() for model in registry),
        key=lambda record: record["model_id"],
    )
    registry_digest = digest_object(
        registry_records, domain="model-capability-registry-v1"
    )
    receipt: dict[str, Any] = {
        "protocol": "integrity-guardian/model-route-receipt/v1",
        "route_id": "route:pending",
        "tenant_id": signal.tenant_id,
        "incident_id": signal.incident_id,
        "alarm_id": signal.alarm_id,
        "alarm_kind": signal.kind.value,
        "severity": signal.severity.value,
        "mandatory": mandatory,
        "required_tier": required_tier.value,
        "minimum_reasoning": reasoning.value,
        "status": "ready" if selected is not None else "analysis_pending",
        "selected_model": (
            None
            if selected is None
            else {
                "model_id": selected.model_id,
                "provider": selected.provider,
                "capability_tier": selected.capability_tier.value,
                "reasoning": reasoning.value,
                "capability_rank": selected.capability_rank,
                "generation": selected.generation,
                "cost_rank": selected.cost_rank,
                "local": selected.local,
            }
        ),
        "reason_codes": sorted(set(reasons)),
        "budgets": {
            "max_input_tokens": max_input,
            "max_output_tokens": max_output,
            "max_model_calls": 1 if selected is not None else 0,
            "max_specialist_agents": specialists,
        },
        "policy_digest": policy_digest,
        "registry_digest": registry_digest,
        "production_authority": False,
    }
    identity = digest_object(receipt, domain="model-route-receipt-identity-v1").split(
        ":", 1
    )[1]
    receipt["route_id"] = f"route:{identity}"
    validate("model-route-receipt", receipt)
    return receipt


def _verify_model_route_receipt(
    receipt: dict[str, Any],
    *,
    signal: AlarmSignal,
    policy: ModelRoutePolicy,
    registry: list[ModelDescriptor],
) -> dict[str, Any]:
    """Verify structure and exact recomputation from trusted routing inputs."""

    validate("model-route-receipt", receipt)
    selected = receipt["selected_model"]
    if receipt["status"] == "ready":
        if selected is None or receipt["budgets"]["max_model_calls"] != 1:
            raise ModelRoutingError("ready route has no callable selected model")
        if (
            TIER_RANK[CognitiveTier(selected["capability_tier"])]
            < TIER_RANK[CognitiveTier(receipt["required_tier"])]
        ):
            raise ModelRoutingError("selected model is below the required tier")
        if selected["reasoning"] != receipt["minimum_reasoning"]:
            raise ModelRoutingError("selected reasoning differs from route requirement")
    elif selected is not None or receipt["budgets"]["max_model_calls"] != 0:
        raise ModelRoutingError("pending route unexpectedly selects a model")
    if receipt["reason_codes"] != sorted(receipt["reason_codes"]):
        raise ModelRoutingError("route reason codes are not canonical")

    unsigned = deepcopy(receipt)
    actual_route_id = unsigned["route_id"]
    unsigned["route_id"] = "route:pending"
    expected_route_id = "route:" + digest_object(
        unsigned, domain="model-route-receipt-identity-v1"
    ).split(":", 1)[1]
    if actual_route_id != expected_route_id:
        raise ModelRoutingError("model route receipt identity mismatch")
    expected_receipt = route_model(
        signal=signal,
        policy=policy,
        registry=registry,
    )
    if receipt != expected_receipt:
        raise ModelRoutingError("model route receipt differs from trusted inputs")
    return {
        "ok": True,
        "authorized": True,
        "route_id": actual_route_id,
        "tenant_id": receipt["tenant_id"],
        "incident_id": receipt["incident_id"],
        "required_tier": receipt["required_tier"],
        "status": receipt["status"],
        "production_authority": False,
    }
