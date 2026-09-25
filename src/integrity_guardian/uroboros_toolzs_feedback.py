"""Pure post-route feedback admission for Integrity 5.5 Uroboros.

The module accepts one already verified theoretical route memory and one later
observer-signed completed trace.  Only an exact structural replay of the Fog
route may produce a new observed-success memory.  The fresh trace remains
evidence, never tool, browser, storage or execution authority.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from .hashing import digest_object
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)
from .uroboros_toolzs import (
    ToolzCyberEvidence,
    ToolzFogRouteEvidence,
    ToolzRouteMemoryDecision,
    ToolzRouteMemoryOutcome,
    ToolzRouteMemoryPolicy,
    build_toolz_route_memory_receipt,
    evaluate_toolz_route_memory,
    toolz_route_memory_digest,
    toolz_route_memory_policy_digest,
    verify_toolz_route_memory_receipt,
)
from .uroboros_toolzs_admission import (
    _freeze_cyber_evidence,
    _freeze_fog_evidence,
    _freeze_mapping,
)
from .uroboros_toolzs_trace import (
    TOOLZ_TRACE_RELATION_TYPE,
    ToolzActionTracePolicy,
    ToolzTracePath,
    describe_toolz_action_trace_path,
    toolz_action_trace_policy_digest,
)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_FEEDBACK_BOUNDARY = {
    "browser_control": False,
    "credentials": False,
    "execution": False,
    "global_publish": False,
    "local_storage": False,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
    "raw_ui_data": False,
    "retroactive_success": False,
    "store_write": False,
    "tool_invocation": False,
}


class ToolzPostRouteFeedbackError(ValueError):
    """Raised before an ambiguous trace can promote theoretical memory."""


class ToolzPostRouteFeedbackDecision(StrEnum):
    """The sole success state; it remains guidance, never execution."""

    ADMIT_OBSERVED_SUCCESS = "admit-observed-success"


@dataclass(frozen=True)
class ToolzPostRouteFeedbackPolicy:
    """Exact trace/memory context and bounded post-route causal windows."""

    policy_id: str
    trace_policy: ToolzActionTracePolicy
    memory_policy: ToolzRouteMemoryPolicy
    max_memory_to_trace_seconds: int = 3_600
    max_trace_to_feedback_seconds: int = 3_600

    def __post_init__(self) -> None:
        if (
            not isinstance(self.policy_id, str)
            or _ID.fullmatch(self.policy_id) is None
            or "synthetic" not in self.policy_id
        ):
            raise ToolzPostRouteFeedbackError("Toolzs post-route feedback policy id rejected")
        if not isinstance(self.trace_policy, ToolzActionTracePolicy):
            raise ToolzPostRouteFeedbackError("Toolzs post-route feedback trace policy rejected")
        if not isinstance(self.memory_policy, ToolzRouteMemoryPolicy):
            raise ToolzPostRouteFeedbackError("Toolzs post-route feedback memory policy rejected")
        if (
            self.trace_policy.subject != self.memory_policy.subject
            or self.trace_policy.environment != self.memory_policy.environment
            or self.trace_policy.ui_context_digest != self.memory_policy.ui_context_digest
        ):
            raise ToolzPostRouteFeedbackError("Toolzs post-route feedback local context mismatch")
        for field, value in (
            ("memory-to-trace lag", self.max_memory_to_trace_seconds),
            ("trace-to-feedback lag", self.max_trace_to_feedback_seconds),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 86_400:
                raise ToolzPostRouteFeedbackError(f"Toolzs post-route feedback {field} rejected")


@dataclass(frozen=True)
class ToolzPostRouteFeedback:
    """Signed admission and its still-local observed-success a1 memory."""

    receipt: dict[str, Any]
    memory_receipt: dict[str, Any]
    decision: ToolzPostRouteFeedbackDecision

    @property
    def execution_authority(self) -> bool:
        return False

    @property
    def storage_performed(self) -> bool:
        return False


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ToolzPostRouteFeedbackError(f"Toolzs post-route feedback {field} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolzPostRouteFeedbackError(f"Toolzs post-route feedback {field} rejected") from exc
    if parsed.tzinfo is None:
        raise ToolzPostRouteFeedbackError(f"Toolzs post-route feedback {field} rejected")
    return parsed


def _freeze_inputs(
    *,
    trace: Mapping[str, Any],
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    theoretical_memory: Mapping[str, Any],
) -> tuple[
    dict[str, Any],
    ToolzFogRouteEvidence,
    ToolzCyberEvidence,
    dict[str, Any],
]:
    try:
        return (
            _freeze_mapping(trace, "post-route trace"),
            _freeze_fog_evidence(fog_evidence),
            _freeze_cyber_evidence(cyber_evidence),
            _freeze_mapping(theoretical_memory, "theoretical memory"),
        )
    except Exception as exc:
        raise ToolzPostRouteFeedbackError("Toolzs post-route feedback input rejected") from exc


def _policy_document(
    policy: ToolzPostRouteFeedbackPolicy,
) -> dict[str, Any]:
    return {
        "policy_id": policy.policy_id,
        "trace_policy_digest": toolz_action_trace_policy_digest(policy.trace_policy),
        "memory_policy_digest": toolz_route_memory_policy_digest(policy.memory_policy),
        "max_memory_to_trace_seconds": policy.max_memory_to_trace_seconds,
        "max_trace_to_feedback_seconds": (policy.max_trace_to_feedback_seconds),
        "path_semantics": ("exact-entities-relations-endpoints-zones-with-fresh-trace-evidence"),
        "causality_semantics": (
            "route-then-theoretical-memory-then-trace-then-observed-memory-then-feedback"
        ),
        "expiry_semantics": "observed-memory-cannot-outlive-theoretical-memory",
    }


def toolz_post_route_feedback_policy_digest(
    policy: ToolzPostRouteFeedbackPolicy,
) -> str:
    """Return the exact post-route feedback policy identity."""

    if not isinstance(policy, ToolzPostRouteFeedbackPolicy):
        raise ToolzPostRouteFeedbackError("Toolzs post-route feedback policy rejected")
    return digest_object(
        _policy_document(policy),
        domain="toolz-post-route-feedback-policy-v1",
    )


def _receipt_core(receipt: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(receipt))
    core.pop("receipt_id", None)
    core.pop("signature", None)
    return core


def toolz_post_route_feedback_identity(
    receipt: Mapping[str, Any],
) -> str:
    """Return the domain-separated identity of one unsigned feedback receipt."""

    digest = digest_object(
        _receipt_core(receipt),
        domain="toolz-post-route-feedback-receipt-identity-v1",
    )
    return f"toolz-post-route-feedback-receipt:{digest.split(':', 1)[1]}"


def toolz_post_route_feedback_digest(
    receipt: Mapping[str, Any],
) -> str:
    """Return the exact signed feedback receipt digest."""

    return digest_object(
        dict(receipt),
        domain="toolz-post-route-feedback-signed-receipt-v1",
    )


def _verify_exact_route_structure(
    path: ToolzTracePath,
    route: Mapping[str, Any],
) -> None:
    try:
        if route["status"] != "candidate":
            raise ToolzPostRouteFeedbackError(
                "Toolzs post-route feedback unresolved route rejected"
            )
        if (
            route["from_entity_id"] != path.from_entity_id
            or route["to_entity_id"] != path.to_entity_id
            or tuple(route["route_entity_ids"]) != path.entity_ids
            or len(route["hops"]) != len(path.hops)
        ):
            raise ToolzPostRouteFeedbackError("Toolzs post-route feedback route path mismatch")
        for route_hop, trace_hop in zip(
            route["hops"],
            path.hops,
            strict=True,
        ):
            if (
                route_hop["relation_type"] != TOOLZ_TRACE_RELATION_TYPE
                or route_hop["relation_id"] != trace_hop.relation_id
                or route_hop["from_entity_id"] != trace_hop.from_entity_id
                or route_hop["to_entity_id"] != trace_hop.to_entity_id
                or route_hop["from_zone_id"] != trace_hop.from_zone_id
                or route_hop["to_zone_id"] != trace_hop.to_zone_id
            ):
                raise ToolzPostRouteFeedbackError("Toolzs post-route feedback route hop mismatch")
        if not set(path.invalidation_zone_ids).issubset(route["invalidation_zone_ids"]):
            raise ToolzPostRouteFeedbackError("Toolzs post-route feedback route zones mismatch")
    except (KeyError, TypeError) as exc:
        raise ToolzPostRouteFeedbackError(
            "Toolzs post-route feedback route shape rejected"
        ) from exc


def _validate_causality(
    *,
    route_created_at: str,
    theoretical_created_at: str,
    theoretical_expires_at: str,
    trace_started_at: str,
    trace_completed_at: str,
    memory_created_at: str,
    feedback_created_at: str,
    observed_expires_at: str,
    policy: ToolzPostRouteFeedbackPolicy,
) -> None:
    route_time = _parse_time(route_created_at, "route creation time")
    theoretical_time = _parse_time(
        theoretical_created_at,
        "theoretical memory creation time",
    )
    expiry_time = _parse_time(
        theoretical_expires_at,
        "theoretical memory expiry",
    )
    started_time = _parse_time(trace_started_at, "trace start time")
    completed_time = _parse_time(trace_completed_at, "trace completion time")
    memory_time = _parse_time(memory_created_at, "memory creation time")
    feedback_time = _parse_time(feedback_created_at, "creation time")
    observed_expiry = _parse_time(
        observed_expires_at,
        "observed memory expiry",
    )
    if not (
        route_time
        <= theoretical_time
        < started_time
        < completed_time
        <= memory_time
        <= feedback_time
        < expiry_time
    ):
        raise ToolzPostRouteFeedbackError("Toolzs post-route feedback causal ordering rejected")
    if observed_expiry != expiry_time:
        raise ToolzPostRouteFeedbackError("Toolzs post-route feedback expiry extension rejected")
    if (started_time - theoretical_time).total_seconds() > policy.max_memory_to_trace_seconds:
        raise ToolzPostRouteFeedbackError("Toolzs post-route feedback memory-to-trace lag rejected")
    if (feedback_time - completed_time).total_seconds() > policy.max_trace_to_feedback_seconds:
        raise ToolzPostRouteFeedbackError(
            "Toolzs post-route feedback trace-to-feedback lag rejected"
        )


def _trace_reference(
    trace: Mapping[str, Any],
    path: ToolzTracePath,
    policy: ToolzPostRouteFeedbackPolicy,
) -> dict[str, Any]:
    return {
        "trace_id": path.trace_id,
        "trace_digest": path.trace_digest,
        "policy_digest": toolz_action_trace_policy_digest(policy.trace_policy),
        "started_at": trace["started_at"],
        "completed_at": trace["completed_at"],
        "from_entity_id": path.from_entity_id,
        "to_entity_id": path.to_entity_id,
        "entity_ids": list(path.entity_ids),
        "relation_ids": list(path.relation_ids),
        "hops": [
            {
                "relation_id": hop.relation_id,
                "from_entity_id": hop.from_entity_id,
                "to_entity_id": hop.to_entity_id,
                "from_zone_id": hop.from_zone_id,
                "to_zone_id": hop.to_zone_id,
                "observed_at": hop.observed_at,
                "evidence_digest": hop.evidence_digest,
                "confidence_ppm": hop.confidence_ppm,
            }
            for hop in path.hops
        ],
        "invalidation_zone_ids": list(path.invalidation_zone_ids),
    }


def _route_reference(
    route: Mapping[str, Any],
    memory: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "proposal_id": route["proposal_id"],
        "route_digest": memory["fog_route"]["route_digest"],
        "snapshot_id": route["snapshot_id"],
        "snapshot_digest": route["snapshot_digest"],
        "route_created_at": route["created_at"],
        "from_entity_id": route["from_entity_id"],
        "to_entity_id": route["to_entity_id"],
        "entity_ids": list(route["route_entity_ids"]),
        "relation_ids": [hop["relation_id"] for hop in route["hops"]],
        "invalidation_zone_ids": list(route["invalidation_zone_ids"]),
    }


def _memory_reference(memory: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "receipt_id": memory["receipt_id"],
        "receipt_digest": toolz_route_memory_digest(memory),
        "policy_digest": memory["policy_digest"],
        "outcome": memory["observation"]["outcome"],
        "observed_at": memory["observation"]["observed_at"],
        "evidence_digest": memory["observation"]["evidence_digest"],
        "created_at": memory["created_at"],
        "expires_at": memory["expires_at"],
    }


def _expected_core(
    *,
    policy: ToolzPostRouteFeedbackPolicy,
    theoretical_memory: Mapping[str, Any],
    trace: Mapping[str, Any],
    path: ToolzTracePath,
    route: Mapping[str, Any],
    observed_memory: Mapping[str, Any],
    created_at: str,
) -> dict[str, Any]:
    return {
        "protocol": "integrity-guardian/toolz-post-route-feedback-receipt/v1",
        "tenant_id": policy.memory_policy.subject.tenant_id,
        "policy_id": policy.policy_id,
        "policy_digest": toolz_post_route_feedback_policy_digest(policy),
        "theoretical_memory": _memory_reference(theoretical_memory),
        "feedback_trace": _trace_reference(trace, path, policy),
        "fog_route": _route_reference(route, theoretical_memory),
        "observed_memory": _memory_reference(observed_memory),
        "decision": (ToolzPostRouteFeedbackDecision.ADMIT_OBSERVED_SUCCESS.value),
        "causality": {
            "route_created_at": route["created_at"],
            "theoretical_memory_created_at": theoretical_memory["created_at"],
            "feedback_trace_started_at": trace["started_at"],
            "feedback_trace_completed_at": trace["completed_at"],
            "observed_memory_created_at": observed_memory["created_at"],
            "feedback_created_at": created_at,
            "ordering": (
                "route-before-or-at-theoretical-memory-before-trace-start-"
                "before-trace-completion-before-or-at-observed-memory-"
                "before-or-at-feedback"
            ),
        },
        "created_at": created_at,
        "authority_boundary": deepcopy(_FEEDBACK_BOUNDARY),
    }


def _verified_inputs(
    *,
    policy: ToolzPostRouteFeedbackPolicy,
    theoretical_memory: Mapping[str, Any],
    trace: Mapping[str, Any],
    observer_key: TrustedKey,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    memory_key: TrustedKey,
) -> tuple[dict[str, Any], ToolzTracePath]:
    memory = verify_toolz_route_memory_receipt(
        theoretical_memory,
        expected_policy=policy.memory_policy,
        fog_evidence=fog_evidence,
        cyber_evidence=cyber_evidence,
        authority_key=memory_key,
    )
    if memory["observation"] != {
        "outcome": ToolzRouteMemoryOutcome.THEORETICAL.value,
        "observed_at": None,
        "evidence_digest": None,
    }:
        raise ToolzPostRouteFeedbackError(
            "Toolzs post-route feedback non-theoretical input rejected"
        )
    path = describe_toolz_action_trace_path(
        trace,
        expected_policy=policy.trace_policy,
        observer_key=observer_key,
    )
    _verify_exact_route_structure(path, fog_evidence.route)
    for evaluated_at in (trace["started_at"], trace["completed_at"]):
        if (
            evaluate_toolz_route_memory(
                memory,
                expected_policy=policy.memory_policy,
                fog_evidence=fog_evidence,
                cyber_evidence=cyber_evidence,
                authority_key=memory_key,
                evaluated_at=evaluated_at,
            )
            is not ToolzRouteMemoryDecision.EXPLORE
        ):
            raise ToolzPostRouteFeedbackError(
                "Toolzs post-route feedback theoretical state rejected"
            )
    return memory, path


def verify_toolz_post_route_feedback_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_policy: ToolzPostRouteFeedbackPolicy,
    theoretical_memory: Mapping[str, Any],
    trace: Mapping[str, Any],
    observer_key: TrustedKey,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    observed_memory: Mapping[str, Any],
    memory_key: TrustedKey,
    feedback_key: TrustedKey,
) -> ToolzPostRouteFeedback:
    """Recompute every memory, route, trace, time and signer binding."""

    if not isinstance(expected_policy, ToolzPostRouteFeedbackPolicy):
        raise ToolzPostRouteFeedbackError("Toolzs post-route feedback policy rejected")
    if not all(isinstance(key, TrustedKey) for key in (observer_key, memory_key, feedback_key)):
        raise ToolzPostRouteFeedbackError("Toolzs post-route feedback trust binding rejected")
    (
        stable_trace,
        stable_fog,
        stable_cyber,
        stable_theoretical,
    ) = _freeze_inputs(
        trace=trace,
        fog_evidence=fog_evidence,
        cyber_evidence=cyber_evidence,
        theoretical_memory=theoretical_memory,
    )
    try:
        candidate = _freeze_mapping(receipt, "post-route feedback receipt")
        stable_observed = _freeze_mapping(
            observed_memory,
            "observed memory",
        )
        validate("toolz-post-route-feedback-receipt", candidate)
    except Exception as exc:
        if isinstance(exc, ToolzPostRouteFeedbackError):
            raise
        raise ToolzPostRouteFeedbackError(
            "Toolzs post-route feedback receipt schema rejected"
        ) from exc
    if candidate["receipt_id"] != toolz_post_route_feedback_identity(candidate):
        raise ToolzPostRouteFeedbackError("Toolzs post-route feedback identity mismatch")
    if candidate["signature"]["key_id"] != feedback_key.key_id or not verify_signature(
        candidate, feedback_key.public_key
    ):
        raise ToolzPostRouteFeedbackError("Toolzs post-route feedback signature rejected")
    if candidate["authority_boundary"] != _FEEDBACK_BOUNDARY:
        raise ToolzPostRouteFeedbackError("Toolzs post-route feedback authority mismatch")
    theoretical, path = _verified_inputs(
        policy=expected_policy,
        theoretical_memory=stable_theoretical,
        trace=stable_trace,
        observer_key=observer_key,
        fog_evidence=stable_fog,
        cyber_evidence=stable_cyber,
        memory_key=memory_key,
    )
    observed = verify_toolz_route_memory_receipt(
        stable_observed,
        expected_policy=expected_policy.memory_policy,
        fog_evidence=stable_fog,
        cyber_evidence=stable_cyber,
        authority_key=memory_key,
    )
    expected_observation = {
        "outcome": ToolzRouteMemoryOutcome.OBSERVED_SUCCESS.value,
        "observed_at": stable_trace["completed_at"],
        "evidence_digest": path.trace_digest,
    }
    if observed["observation"] != expected_observation:
        raise ToolzPostRouteFeedbackError("Toolzs post-route feedback observation mismatch")
    _validate_causality(
        route_created_at=stable_fog.route["created_at"],
        theoretical_created_at=theoretical["created_at"],
        theoretical_expires_at=theoretical["expires_at"],
        trace_started_at=stable_trace["started_at"],
        trace_completed_at=stable_trace["completed_at"],
        memory_created_at=observed["created_at"],
        feedback_created_at=candidate["created_at"],
        observed_expires_at=observed["expires_at"],
        policy=expected_policy,
    )
    if (
        evaluate_toolz_route_memory(
            observed,
            expected_policy=expected_policy.memory_policy,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            authority_key=memory_key,
            evaluated_at=candidate["created_at"],
        )
        is not ToolzRouteMemoryDecision.REUSE_CANDIDATE
    ):
        raise ToolzPostRouteFeedbackError("Toolzs post-route feedback observed state rejected")
    expected = _expected_core(
        policy=expected_policy,
        theoretical_memory=theoretical,
        trace=stable_trace,
        path=path,
        route=stable_fog.route,
        observed_memory=observed,
        created_at=candidate["created_at"],
    )
    if _receipt_core(candidate) != expected:
        raise ToolzPostRouteFeedbackError("Toolzs post-route feedback recomputation mismatch")
    return ToolzPostRouteFeedback(
        receipt=candidate,
        memory_receipt=observed,
        decision=ToolzPostRouteFeedbackDecision.ADMIT_OBSERVED_SUCCESS,
    )


def build_toolz_post_route_feedback(
    *,
    policy: ToolzPostRouteFeedbackPolicy,
    theoretical_memory: Mapping[str, Any],
    trace: Mapping[str, Any],
    observer_key: TrustedKey,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    memory_key: TrustedKey,
    memory_created_at: str,
    expires_at: str,
    feedback_created_at: str,
    memory_signer: Ed25519Signer,
    feedback_signer: Ed25519Signer,
) -> ToolzPostRouteFeedback:
    """Admit one exact later trace without invoking or storing a Toolz."""

    if not isinstance(policy, ToolzPostRouteFeedbackPolicy):
        raise ToolzPostRouteFeedbackError("Toolzs post-route feedback policy rejected")
    if not all(isinstance(key, TrustedKey) for key in (observer_key, memory_key)):
        raise ToolzPostRouteFeedbackError("Toolzs post-route feedback trust binding rejected")
    if not isinstance(memory_signer, Ed25519Signer) or not isinstance(
        feedback_signer,
        Ed25519Signer,
    ):
        raise ToolzPostRouteFeedbackError("Toolzs post-route feedback signer rejected")
    if memory_signer.key_id != memory_key.key_id or public_key_fingerprint(
        memory_signer.public_key
    ) != public_key_fingerprint(memory_key.public_key):
        raise ToolzPostRouteFeedbackError("Toolzs post-route feedback memory signer mismatch")
    (
        stable_trace,
        stable_fog,
        stable_cyber,
        stable_theoretical,
    ) = _freeze_inputs(
        trace=trace,
        fog_evidence=fog_evidence,
        cyber_evidence=cyber_evidence,
        theoretical_memory=theoretical_memory,
    )
    theoretical, path = _verified_inputs(
        policy=policy,
        theoretical_memory=stable_theoretical,
        trace=stable_trace,
        observer_key=observer_key,
        fog_evidence=stable_fog,
        cyber_evidence=stable_cyber,
        memory_key=memory_key,
    )
    _validate_causality(
        route_created_at=stable_fog.route["created_at"],
        theoretical_created_at=theoretical["created_at"],
        theoretical_expires_at=theoretical["expires_at"],
        trace_started_at=stable_trace["started_at"],
        trace_completed_at=stable_trace["completed_at"],
        memory_created_at=memory_created_at,
        feedback_created_at=feedback_created_at,
        observed_expires_at=expires_at,
        policy=policy,
    )
    observed = build_toolz_route_memory_receipt(
        policy=policy.memory_policy,
        fog_evidence=stable_fog,
        cyber_evidence=stable_cyber,
        outcome=ToolzRouteMemoryOutcome.OBSERVED_SUCCESS,
        observed_at=stable_trace["completed_at"],
        observation_evidence_digest=path.trace_digest,
        created_at=memory_created_at,
        expires_at=expires_at,
        memory_signer=memory_signer,
    )
    core = _expected_core(
        policy=policy,
        theoretical_memory=theoretical,
        trace=stable_trace,
        path=path,
        route=stable_fog.route,
        observed_memory=observed,
        created_at=feedback_created_at,
    )
    unsigned = {
        "receipt_id": toolz_post_route_feedback_identity(core),
        **core,
    }
    signed = feedback_signer.sign(unsigned)
    return verify_toolz_post_route_feedback_receipt(
        signed,
        expected_policy=policy,
        theoretical_memory=theoretical,
        trace=stable_trace,
        observer_key=observer_key,
        fog_evidence=stable_fog,
        cyber_evidence=stable_cyber,
        observed_memory=observed,
        memory_key=memory_key,
        feedback_key=TrustedKey(
            key_id=feedback_signer.key_id,
            public_key=feedback_signer.public_key,
        ),
    )
