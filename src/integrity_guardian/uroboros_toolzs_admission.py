"""Causality-safe trace-to-memory admission for Integrity 5.5 Uroboros.

The module binds one completed a3 action trace to the exact verified Fog route
that was synthesized from it and creates an a1 *theoretical* memory receipt.
It deliberately cannot claim that a route synthesized after the action was
already observed as a route.  No store, adapter, tool, browser or network is
invoked.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from jsonschema import ValidationError

from .canonical import canonical_bytes, parse_json_strict
from .discovery_feedback import (
    TrustedDiscoveryFeedback,
    verify_discovery_feedback_overlay,
    verify_discovery_theory_route_with_feedback,
)
from .discovery_theory import verify_discovery_theory_route
from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_signature
from .uroboros_toolzs import (
    ToolzCyberEvidence,
    ToolzFogRouteEvidence,
    ToolzRouteMemoryOutcome,
    ToolzRouteMemoryPolicy,
    build_toolz_route_memory_receipt,
    toolz_route_memory_digest,
    toolz_route_memory_policy_digest,
    verify_toolz_route_memory_receipt,
)
from .uroboros_toolzs_trace import (
    TOOLZ_TRACE_RELATION_TYPE,
    ToolzActionTracePolicy,
    ToolzTracePath,
    describe_toolz_action_trace_path,
    toolz_action_trace_policy_digest,
)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_TRACE_PROTOCOLS = {
    "integrity-guardian/discovery-theory-route/v1",
    "integrity-guardian/discovery-feedback-ranked-route/v1",
}
_ADMISSION_BOUNDARY = {
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
    "tool_invocation": False,
}


class ToolzTraceAdmissionError(ValueError):
    """Raised when trace-to-memory admission violates causal safety."""


class ToolzTraceAdmissionDecision(StrEnum):
    """Only safe first-observation result for a post-hoc synthesized route."""

    ADMIT_THEORETICAL = "admit-theoretical"


@dataclass(frozen=True)
class ToolzTraceAdmissionPolicy:
    """Exact trace, memory and bounded causal-lag policy."""

    policy_id: str
    trace_policy: ToolzActionTracePolicy
    memory_policy: ToolzRouteMemoryPolicy
    max_trace_to_route_seconds: int = 3_600
    max_route_to_admission_seconds: int = 3_600

    def __post_init__(self) -> None:
        if (
            not isinstance(self.policy_id, str)
            or _ID.fullmatch(self.policy_id) is None
            or "synthetic" not in self.policy_id
        ):
            raise ToolzTraceAdmissionError("Toolzs admission policy id rejected")
        if not isinstance(self.trace_policy, ToolzActionTracePolicy):
            raise ToolzTraceAdmissionError("Toolzs admission trace policy rejected")
        if not isinstance(self.memory_policy, ToolzRouteMemoryPolicy):
            raise ToolzTraceAdmissionError("Toolzs admission memory policy rejected")
        if (
            self.trace_policy.subject != self.memory_policy.subject
            or self.trace_policy.environment != self.memory_policy.environment
            or self.trace_policy.ui_context_digest
            != self.memory_policy.ui_context_digest
        ):
            raise ToolzTraceAdmissionError("Toolzs admission local context mismatch")
        for field, value in (
            ("trace-to-route lag", self.max_trace_to_route_seconds),
            ("route-to-admission lag", self.max_route_to_admission_seconds),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 1 <= value <= 86_400
            ):
                raise ToolzTraceAdmissionError(
                    f"Toolzs admission {field} rejected"
                )


@dataclass(frozen=True)
class ToolzTraceAdmission:
    """Signed admission plus the store-ready theoretical a1 memory."""

    receipt: dict[str, Any]
    memory_receipt: dict[str, Any]
    decision: ToolzTraceAdmissionDecision

    @property
    def execution_authority(self) -> bool:
        return False

    @property
    def storage_performed(self) -> bool:
        return False


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ToolzTraceAdmissionError(f"Toolzs admission {field} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolzTraceAdmissionError(
            f"Toolzs admission {field} rejected"
        ) from exc
    if parsed.tzinfo is None:
        raise ToolzTraceAdmissionError(f"Toolzs admission {field} rejected")
    return parsed


def _freeze_mapping(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ToolzTraceAdmissionError(f"Toolzs admission {field} rejected")
    try:
        detached = parse_json_strict(canonical_bytes(dict(value)))
    except Exception as exc:
        raise ToolzTraceAdmissionError(
            f"Toolzs admission {field} rejected"
        ) from exc
    if not isinstance(detached, dict):
        raise ToolzTraceAdmissionError(f"Toolzs admission {field} rejected")
    return detached


def _freeze_feedback(
    evidence: TrustedDiscoveryFeedback,
) -> TrustedDiscoveryFeedback:
    if not isinstance(evidence, TrustedDiscoveryFeedback):
        raise ToolzTraceAdmissionError("Toolzs admission feedback rejected")
    return TrustedDiscoveryFeedback(
        proposal=_freeze_mapping(evidence.proposal, "feedback proposal"),
        receipt=_freeze_mapping(evidence.receipt, "feedback receipt"),
        proposal_policy=evidence.proposal_policy,
        trusted_theory_key=evidence.trusted_theory_key,
        trusted_feedback_key=evidence.trusted_feedback_key,
        expected_observer_id=evidence.expected_observer_id,
    )


def _freeze_fog_evidence(
    evidence: ToolzFogRouteEvidence,
) -> ToolzFogRouteEvidence:
    if not isinstance(evidence, ToolzFogRouteEvidence):
        raise ToolzTraceAdmissionError("Toolzs admission Fog evidence rejected")
    return ToolzFogRouteEvidence(
        snapshot=_freeze_mapping(evidence.snapshot, "Fog snapshot"),
        route=_freeze_mapping(evidence.route, "Fog route"),
        trusted_snapshot_key=evidence.trusted_snapshot_key,
        trusted_sources=tuple(evidence.trusted_sources),
        trusted_theory_key=evidence.trusted_theory_key,
        expected_snapshot_id=evidence.expected_snapshot_id,
        expected_tenant_id=evidence.expected_tenant_id,
        expected_policy=evidence.expected_policy,
        overlay=(
            None
            if evidence.overlay is None
            else _freeze_mapping(evidence.overlay, "Fog overlay")
        ),
        trusted_overlay_key=evidence.trusted_overlay_key,
        feedback_policy=evidence.feedback_policy,
        feedback_evidence=tuple(
            _freeze_feedback(item) for item in evidence.feedback_evidence
        ),
    )


def _freeze_cyber_evidence(
    evidence: ToolzCyberEvidence,
) -> ToolzCyberEvidence:
    if not isinstance(evidence, ToolzCyberEvidence):
        raise ToolzTraceAdmissionError("Toolzs admission cyber evidence rejected")
    return ToolzCyberEvidence(
        decision_receipt=_freeze_mapping(
            evidence.decision_receipt,
            "cyber decision",
        ),
        expected_policy=evidence.expected_policy,
        provenance_receipt=_freeze_mapping(
            evidence.provenance_receipt,
            "cyber provenance",
        ),
        assessment_receipt=_freeze_mapping(
            evidence.assessment_receipt,
            "cyber assessment",
        ),
        containment_receipt=(
            None
            if evidence.containment_receipt is None
            else _freeze_mapping(
                evidence.containment_receipt,
                "cyber containment",
            )
        ),
        provenance_key=evidence.provenance_key,
        assessment_key=evidence.assessment_key,
        containment_key=evidence.containment_key,
        authority_key=evidence.authority_key,
    )


def _policy_document(policy: ToolzTraceAdmissionPolicy) -> dict[str, Any]:
    return {
        "policy_id": policy.policy_id,
        "trace_policy_digest": toolz_action_trace_policy_digest(
            policy.trace_policy
        ),
        "memory_policy_digest": toolz_route_memory_policy_digest(
            policy.memory_policy
        ),
        "max_trace_to_route_seconds": policy.max_trace_to_route_seconds,
        "max_route_to_admission_seconds": (
            policy.max_route_to_admission_seconds
        ),
        "path_semantics": (
            "exact-entities-hops-source-epoch-projection-record-evidence-zones"
        ),
        "causality_semantics": (
            "trace-then-snapshot-then-route-then-memory-then-admission"
        ),
    }


def toolz_trace_admission_policy_digest(
    policy: ToolzTraceAdmissionPolicy,
) -> str:
    """Return the exact causal admission policy identity."""

    if not isinstance(policy, ToolzTraceAdmissionPolicy):
        raise ToolzTraceAdmissionError("Toolzs admission policy rejected")
    return digest_object(
        _policy_document(policy),
        domain="toolz-trace-admission-policy-v1",
    )


def _receipt_core(receipt: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(receipt))
    core.pop("receipt_id", None)
    core.pop("signature", None)
    return core


def toolz_trace_admission_identity(receipt: Mapping[str, Any]) -> str:
    """Return the identity of one unsigned admission decision."""

    digest = digest_object(
        _receipt_core(receipt),
        domain="toolz-trace-admission-receipt-identity-v1",
    )
    return f"toolz-trace-admission-receipt:{digest.split(':', 1)[1]}"


def toolz_trace_admission_digest(receipt: Mapping[str, Any]) -> str:
    """Return the exact signed admission digest."""

    return digest_object(
        dict(receipt),
        domain="toolz-trace-admission-signed-receipt-v1",
    )


def _verify_full_fog_route(
    evidence: ToolzFogRouteEvidence,
) -> dict[str, Any]:
    protocol = evidence.route.get("protocol")
    if protocol not in _TRACE_PROTOCOLS:
        raise ToolzTraceAdmissionError("Toolzs admission Fog protocol rejected")
    if protocol == "integrity-guardian/discovery-theory-route/v1":
        return verify_discovery_theory_route(
            evidence.route,
            evidence.snapshot,
            trusted_snapshot_key=evidence.trusted_snapshot_key,
            trusted_sources=evidence.trusted_sources,
            trusted_theory_key=evidence.trusted_theory_key,
            expected_snapshot_id=evidence.expected_snapshot_id,
            expected_tenant_id=evidence.expected_tenant_id,
            expected_policy=evidence.expected_policy,
        )
    overlay = verify_discovery_feedback_overlay(
        evidence.overlay,
        evidence.snapshot,
        trusted_snapshot_key=evidence.trusted_snapshot_key,
        trusted_sources=evidence.trusted_sources,
        trusted_overlay_key=evidence.trusted_overlay_key,
        expected_snapshot_id=evidence.expected_snapshot_id,
        expected_tenant_id=evidence.expected_tenant_id,
        expected_policy=evidence.expected_policy,
        feedback_policy=evidence.feedback_policy,
        feedback_evidence=evidence.feedback_evidence,
    )
    return verify_discovery_theory_route_with_feedback(
        evidence.route,
        evidence.snapshot,
        overlay,
        trusted_snapshot_key=evidence.trusted_snapshot_key,
        trusted_sources=evidence.trusted_sources,
        trusted_overlay_key=evidence.trusted_overlay_key,
        trusted_theory_key=evidence.trusted_theory_key,
        expected_snapshot_id=evidence.expected_snapshot_id,
        expected_tenant_id=evidence.expected_tenant_id,
        expected_policy=evidence.expected_policy,
        feedback_policy=evidence.feedback_policy,
        feedback_evidence=evidence.feedback_evidence,
    )


def _verify_exact_trace_route(
    path: ToolzTracePath,
    snapshot: Mapping[str, Any],
    route: Mapping[str, Any],
    policy: ToolzTraceAdmissionPolicy,
) -> None:
    if route["status"] != "candidate":
        raise ToolzTraceAdmissionError("Toolzs admission unresolved route rejected")
    if (
        route["from_entity_id"] != path.from_entity_id
        or route["to_entity_id"] != path.to_entity_id
    ):
        raise ToolzTraceAdmissionError("Toolzs admission route endpoints mismatch")
    hops = route["hops"]
    if tuple(route["route_entity_ids"]) != path.entity_ids:
        raise ToolzTraceAdmissionError("Toolzs admission route path mismatch")
    if len(hops) != len(path.hops):
        raise ToolzTraceAdmissionError("Toolzs admission route path mismatch")
    records_by_id = {
        record["record_id"]: record for record in snapshot["active_records"]
    }
    for hop, expected_hop in zip(hops, path.hops, strict=True):
        record = records_by_id.get(hop["record_id"])
        if (
            record is None
            or hop["relation_id"] != expected_hop.relation_id
            or hop["from_entity_id"] != expected_hop.from_entity_id
            or hop["to_entity_id"] != expected_hop.to_entity_id
            or hop["from_zone_id"] != expected_hop.from_zone_id
            or hop["to_zone_id"] != expected_hop.to_zone_id
            or hop["confidence_ppm"] != expected_hop.confidence_ppm
            or hop["relation_type"] != TOOLZ_TRACE_RELATION_TYPE
            or hop["source_id"]
            != policy.trace_policy.discovery_source_id
            or hop["source_epoch"]
            != policy.trace_policy.discovery_source_epoch
            or hop["coverage_scope_digest"] != path.projection_digest
            or hop["coverage_state"] != "partial"
            or hop["provenance"] != "LEARNED"
            or record["observed_at"] != expected_hop.observed_at
            or record["zone_id"] != expected_hop.from_zone_id
            or record["evidence"]["content_digest"]
            != expected_hop.evidence_digest
            or record["evidence"]["source_artifact_digest"]
            != policy.trace_policy.discovery_source_artifact_digest
        ):
            raise ToolzTraceAdmissionError("Toolzs admission route evidence mismatch")
    if not set(path.invalidation_zone_ids).issubset(
        route["invalidation_zone_ids"]
    ):
        raise ToolzTraceAdmissionError("Toolzs admission route zones mismatch")


def _validate_causality(
    *,
    trace_completed_at: str,
    snapshot_created_at: str,
    route_created_at: str,
    memory_created_at: str,
    admission_created_at: str,
    policy: ToolzTraceAdmissionPolicy,
) -> None:
    trace_time = _parse_time(trace_completed_at, "trace completion time")
    snapshot_time = _parse_time(snapshot_created_at, "snapshot creation time")
    route_time = _parse_time(route_created_at, "route creation time")
    memory_time = _parse_time(memory_created_at, "memory creation time")
    admission_time = _parse_time(admission_created_at, "creation time")
    if not (
        trace_time
        <= snapshot_time
        <= route_time
        <= memory_time
        <= admission_time
    ):
        raise ToolzTraceAdmissionError("Toolzs admission causal ordering rejected")
    if (
        route_time - trace_time
    ).total_seconds() > policy.max_trace_to_route_seconds:
        raise ToolzTraceAdmissionError("Toolzs admission trace-to-route lag rejected")
    if (
        admission_time - route_time
    ).total_seconds() > policy.max_route_to_admission_seconds:
        raise ToolzTraceAdmissionError(
            "Toolzs admission route-to-admission lag rejected"
        )


def _trace_reference(
    trace: Mapping[str, Any],
    path: ToolzTracePath,
) -> dict[str, Any]:
    return {
        "trace_id": path.trace_id,
        "trace_digest": path.trace_digest,
        "projection_digest": path.projection_digest,
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
        "hop_record_ids": [hop["record_id"] for hop in route["hops"]],
        "hop_relation_ids": [hop["relation_id"] for hop in route["hops"]],
        "invalidation_zone_ids": list(route["invalidation_zone_ids"]),
    }


def _memory_reference(memory: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "receipt_id": memory["receipt_id"],
        "receipt_digest": toolz_route_memory_digest(memory),
        "policy_id": memory["policy_id"],
        "policy_digest": memory["policy_digest"],
        "outcome": memory["observation"]["outcome"],
        "created_at": memory["created_at"],
        "expires_at": memory["expires_at"],
    }


def _expected_core(
    *,
    policy: ToolzTraceAdmissionPolicy,
    trace: Mapping[str, Any],
    path: ToolzTracePath,
    route: Mapping[str, Any],
    memory: Mapping[str, Any],
    snapshot_created_at: str,
    created_at: str,
) -> dict[str, Any]:
    return {
        "protocol": "integrity-guardian/toolz-trace-admission-receipt/v1",
        "tenant_id": policy.memory_policy.subject.tenant_id,
        "policy_id": policy.policy_id,
        "policy_digest": toolz_trace_admission_policy_digest(policy),
        "trace": _trace_reference(trace, path),
        "fog_route": _route_reference(route, memory),
        "memory": _memory_reference(memory),
        "decision": ToolzTraceAdmissionDecision.ADMIT_THEORETICAL.value,
        "causality": {
            "trace_completed_at": trace["completed_at"],
            "snapshot_created_at": snapshot_created_at,
            "route_created_at": route["created_at"],
            "memory_created_at": memory["created_at"],
            "admission_created_at": created_at,
            "ordering": (
                "trace-before-or-at-snapshot-before-or-at-route-"
                "before-or-at-memory-before-or-at-admission"
            ),
        },
        "created_at": created_at,
        "authority_boundary": deepcopy(_ADMISSION_BOUNDARY),
    }


def verify_toolz_trace_admission_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_policy: ToolzTraceAdmissionPolicy,
    trace: Mapping[str, Any],
    observer_key: TrustedKey,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    memory_receipt: Mapping[str, Any],
    memory_key: TrustedKey,
    admission_key: TrustedKey,
) -> ToolzTraceAdmission:
    """Recompute every trace, Fog, memory, causal and signer binding."""

    if not isinstance(expected_policy, ToolzTraceAdmissionPolicy):
        raise ToolzTraceAdmissionError("Toolzs admission policy rejected")
    if not all(
        isinstance(key, TrustedKey)
        for key in (observer_key, memory_key, admission_key)
    ):
        raise ToolzTraceAdmissionError("Toolzs admission trust binding rejected")
    stable_trace = _freeze_mapping(trace, "trace")
    stable_fog = _freeze_fog_evidence(fog_evidence)
    stable_cyber = _freeze_cyber_evidence(cyber_evidence)
    stable_memory = _freeze_mapping(memory_receipt, "memory receipt")
    try:
        candidate = _freeze_mapping(receipt, "receipt")
        validate("toolz-trace-admission-receipt", candidate)
    except ValidationError as exc:
        raise ToolzTraceAdmissionError(
            "Toolzs admission receipt schema rejected"
        ) from exc
    if candidate["receipt_id"] != toolz_trace_admission_identity(candidate):
        raise ToolzTraceAdmissionError("Toolzs admission identity mismatch")
    if (
        candidate["signature"]["key_id"] != admission_key.key_id
        or not verify_signature(candidate, admission_key.public_key)
    ):
        raise ToolzTraceAdmissionError("Toolzs admission signature rejected")
    if candidate["authority_boundary"] != _ADMISSION_BOUNDARY:
        raise ToolzTraceAdmissionError("Toolzs admission authority mismatch")

    path = describe_toolz_action_trace_path(
        stable_trace,
        expected_policy=expected_policy.trace_policy,
        observer_key=observer_key,
    )
    route = _verify_full_fog_route(stable_fog)
    _verify_exact_trace_route(
        path,
        stable_fog.snapshot,
        route,
        expected_policy,
    )
    memory = verify_toolz_route_memory_receipt(
        stable_memory,
        expected_policy=expected_policy.memory_policy,
        fog_evidence=stable_fog,
        cyber_evidence=stable_cyber,
        authority_key=memory_key,
    )
    if memory["observation"] != {
        "outcome": ToolzRouteMemoryOutcome.THEORETICAL.value,
        "observed_at": None,
        "evidence_digest": None,
    }:
        raise ToolzTraceAdmissionError(
            "Toolzs admission retroactive success rejected"
        )
    _validate_causality(
        trace_completed_at=stable_trace["completed_at"],
        snapshot_created_at=stable_fog.snapshot["created_at"],
        route_created_at=route["created_at"],
        memory_created_at=memory["created_at"],
        admission_created_at=candidate["created_at"],
        policy=expected_policy,
    )
    expected = _expected_core(
        policy=expected_policy,
        trace=stable_trace,
        path=path,
        route=route,
        memory=memory,
        snapshot_created_at=stable_fog.snapshot["created_at"],
        created_at=candidate["created_at"],
    )
    if _receipt_core(candidate) != expected:
        raise ToolzTraceAdmissionError("Toolzs admission recomputation mismatch")
    return ToolzTraceAdmission(
        receipt=candidate,
        memory_receipt=memory,
        decision=ToolzTraceAdmissionDecision.ADMIT_THEORETICAL,
    )


def build_toolz_trace_admission(
    *,
    policy: ToolzTraceAdmissionPolicy,
    trace: Mapping[str, Any],
    observer_key: TrustedKey,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    created_at: str,
    expires_at: str,
    memory_signer: Ed25519Signer,
    admission_signer: Ed25519Signer,
) -> ToolzTraceAdmission:
    """Build one signed theoretical admission without storage or execution."""

    if not isinstance(policy, ToolzTraceAdmissionPolicy):
        raise ToolzTraceAdmissionError("Toolzs admission policy rejected")
    if not isinstance(observer_key, TrustedKey):
        raise ToolzTraceAdmissionError("Toolzs admission observer key rejected")
    if not isinstance(memory_signer, Ed25519Signer) or not isinstance(
        admission_signer,
        Ed25519Signer,
    ):
        raise ToolzTraceAdmissionError("Toolzs admission signer rejected")
    stable_trace = _freeze_mapping(trace, "trace")
    stable_fog = _freeze_fog_evidence(fog_evidence)
    stable_cyber = _freeze_cyber_evidence(cyber_evidence)
    path = describe_toolz_action_trace_path(
        stable_trace,
        expected_policy=policy.trace_policy,
        observer_key=observer_key,
    )
    route = _verify_full_fog_route(stable_fog)
    _verify_exact_trace_route(path, stable_fog.snapshot, route, policy)
    _validate_causality(
        trace_completed_at=stable_trace["completed_at"],
        snapshot_created_at=stable_fog.snapshot["created_at"],
        route_created_at=route["created_at"],
        memory_created_at=created_at,
        admission_created_at=created_at,
        policy=policy,
    )
    memory = build_toolz_route_memory_receipt(
        policy=policy.memory_policy,
        fog_evidence=stable_fog,
        cyber_evidence=stable_cyber,
        outcome=ToolzRouteMemoryOutcome.THEORETICAL,
        observed_at=None,
        observation_evidence_digest=None,
        created_at=created_at,
        expires_at=expires_at,
        memory_signer=memory_signer,
    )
    core = _expected_core(
        policy=policy,
        trace=stable_trace,
        path=path,
        route=route,
        memory=memory,
        snapshot_created_at=stable_fog.snapshot["created_at"],
        created_at=created_at,
    )
    unsigned = {
        "receipt_id": toolz_trace_admission_identity(core),
        **core,
    }
    signed = admission_signer.sign(unsigned)
    return verify_toolz_trace_admission_receipt(
        signed,
        expected_policy=policy,
        trace=stable_trace,
        observer_key=observer_key,
        fog_evidence=stable_fog,
        cyber_evidence=stable_cyber,
        memory_receipt=memory,
        memory_key=TrustedKey(
            key_id=memory_signer.key_id,
            public_key=memory_signer.public_key,
        ),
        admission_key=TrustedKey(
            key_id=admission_signer.key_id,
            public_key=admission_signer.public_key,
        ),
    )
