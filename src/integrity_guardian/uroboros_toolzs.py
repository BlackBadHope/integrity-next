"""Signed, authority-free Toolzs route memory for Integrity 5.5 Uroboros.

This module composes already signed Fog of War route evidence with the existing
project-wide security admission chain. It performs no tool invocation,
collection, browser control, storage, network access or global publication.
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

from .discovery import TrustedDiscoverySource
from .discovery_feedback import (
    DiscoveryFeedbackPolicy,
    TrustedDiscoveryFeedback,
    discovery_feedback_overlay_digest,
    verify_discovery_feedback_overlay,
    verify_discovery_theory_route_with_feedback,
)
from .discovery_theory import (
    DiscoveryTheoryPolicy,
    verify_discovery_theory_route,
)
from .hashing import digest_object
from .schemas import validate
from .security_admission import (
    ProjectSecurityAdmissionPolicy,
    SecurityArtifact,
    SecurityEnvironment,
    project_security_policy_digest,
    security_receipt_digest,
    verify_promotion_decision_receipt,
)
from .signing import Ed25519Signer, TrustedKey, verify_signature

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_ROUTE_PROTOCOLS = {
    "integrity-guardian/discovery-theory-route/v1": "theory",
    "integrity-guardian/discovery-feedback-ranked-route/v1": "feedback-ranked",
}
_AUTHORITY_BOUNDARY = {
    "browser_control": False,
    "credentials": False,
    "execution": False,
    "global_publish": False,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
    "raw_ui_data": False,
    "storage": False,
    "tool_invocation": False,
}


class ToolzRouteMemoryError(ValueError):
    """Raised when Uroboros route memory violates its fail-closed contract."""


class ToolzRouteMemoryOutcome(StrEnum):
    """Lifecycle state asserted by the trusted local memory signer."""

    THEORETICAL = "theoretical"
    OBSERVED_SUCCESS = "observed-success"
    OBSERVED_FAILURE = "observed-failure"
    STALE = "stale"
    INVALIDATED = "invalidated"


class ToolzRouteMemoryDecision(StrEnum):
    """Bounded reuse guidance; never execution authority."""

    EXPLORE = "explore"
    REUSE_CANDIDATE = "reuse-candidate"
    REDISCOVER = "rediscover"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class ToolzRouteMemoryPolicy:
    """Exact local Toolz, environment, UI and `/cyber` reuse policy."""

    policy_id: str
    subject: SecurityArtifact
    environment: SecurityEnvironment
    ui_context_digest: str
    required_cyber_channel: str
    require_feedback_ranked: bool = False
    max_validity_seconds: int = 3_600

    def __post_init__(self) -> None:
        if (
            not isinstance(self.policy_id, str)
            or _ID.fullmatch(self.policy_id) is None
            or "synthetic" not in self.policy_id
        ):
            raise ToolzRouteMemoryError("Toolzs memory policy id rejected")
        if not isinstance(self.subject, SecurityArtifact):
            raise ToolzRouteMemoryError("Toolzs memory subject rejected")
        if not isinstance(self.environment, SecurityEnvironment):
            raise ToolzRouteMemoryError("Toolzs memory environment rejected")
        if (
            not isinstance(self.ui_context_digest, str)
            or _DIGEST.fullmatch(self.ui_context_digest) is None
        ):
            raise ToolzRouteMemoryError("Toolzs memory UI context rejected")
        if self.required_cyber_channel not in {"rc", "stable"}:
            raise ToolzRouteMemoryError("Toolzs memory cyber channel rejected")
        if not isinstance(self.require_feedback_ranked, bool):
            raise ToolzRouteMemoryError("Toolzs memory feedback requirement rejected")
        if (
            not isinstance(self.max_validity_seconds, int)
            or isinstance(self.max_validity_seconds, bool)
            or not 1 <= self.max_validity_seconds <= 86_400
        ):
            raise ToolzRouteMemoryError("Toolzs memory validity limit rejected")


@dataclass(frozen=True)
class ToolzFogRouteEvidence:
    """Out-of-band trust bindings for one exact Fog route."""

    snapshot: Mapping[str, Any]
    route: Mapping[str, Any]
    trusted_snapshot_key: TrustedKey
    trusted_sources: tuple[TrustedDiscoverySource, ...]
    trusted_theory_key: TrustedKey
    expected_snapshot_id: str
    expected_tenant_id: str
    expected_policy: DiscoveryTheoryPolicy
    overlay: Mapping[str, Any] | None = None
    trusted_overlay_key: TrustedKey | None = None
    feedback_policy: DiscoveryFeedbackPolicy | None = None
    feedback_evidence: tuple[TrustedDiscoveryFeedback, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, Mapping) or not isinstance(self.route, Mapping):
            raise ToolzRouteMemoryError("Toolzs Fog evidence rejected")
        if not isinstance(self.trusted_snapshot_key, TrustedKey) or not isinstance(
            self.trusted_theory_key,
            TrustedKey,
        ):
            raise ToolzRouteMemoryError("Toolzs Fog trust binding rejected")
        if (
            not isinstance(self.trusted_sources, tuple)
            or not self.trusted_sources
            or any(
                not isinstance(source, TrustedDiscoverySource) for source in self.trusted_sources
            )
        ):
            raise ToolzRouteMemoryError("Toolzs Fog sources rejected")
        if (
            not isinstance(self.expected_snapshot_id, str)
            or not isinstance(self.expected_tenant_id, str)
            or self.expected_tenant_id != "tenant:public-6e3cdbebaafc8efa"
            or not isinstance(self.expected_policy, DiscoveryTheoryPolicy)
        ):
            raise ToolzRouteMemoryError("Toolzs Fog expectation rejected")
        protocol = self.route.get("protocol")
        if protocol not in _ROUTE_PROTOCOLS:
            raise ToolzRouteMemoryError("Toolzs Fog route protocol rejected")
        if protocol == "integrity-guardian/discovery-theory-route/v1":
            if (
                self.overlay is not None
                or self.trusted_overlay_key is not None
                or self.feedback_policy is not None
                or self.feedback_evidence
            ):
                raise ToolzRouteMemoryError("Toolzs base route feedback rejected")
        elif (
            not isinstance(self.overlay, Mapping)
            or not isinstance(self.trusted_overlay_key, TrustedKey)
            or not isinstance(self.feedback_policy, DiscoveryFeedbackPolicy)
            or not isinstance(self.feedback_evidence, tuple)
            or not self.feedback_evidence
            or any(
                not isinstance(item, TrustedDiscoveryFeedback) for item in self.feedback_evidence
            )
        ):
            raise ToolzRouteMemoryError("Toolzs feedback route evidence rejected")


@dataclass(frozen=True)
class ToolzCyberEvidence:
    """Complete out-of-band trust chain for one local `/cyber` decision."""

    decision_receipt: Mapping[str, Any]
    expected_policy: ProjectSecurityAdmissionPolicy
    provenance_receipt: Mapping[str, Any]
    assessment_receipt: Mapping[str, Any]
    containment_receipt: Mapping[str, Any] | None
    provenance_key: TrustedKey
    assessment_key: TrustedKey
    containment_key: TrustedKey | None
    authority_key: TrustedKey

    def __post_init__(self) -> None:
        if (
            not isinstance(self.decision_receipt, Mapping)
            or not isinstance(self.provenance_receipt, Mapping)
            or not isinstance(self.assessment_receipt, Mapping)
            or not isinstance(self.expected_policy, ProjectSecurityAdmissionPolicy)
        ):
            raise ToolzRouteMemoryError("Toolzs cyber evidence rejected")
        if not all(
            isinstance(key, TrustedKey)
            for key in (
                self.provenance_key,
                self.assessment_key,
                self.authority_key,
            )
        ):
            raise ToolzRouteMemoryError("Toolzs cyber trust binding rejected")
        if (self.containment_receipt is None) != (self.containment_key is None):
            raise ToolzRouteMemoryError("Toolzs cyber containment binding rejected")
        if self.containment_receipt is not None and not isinstance(
            self.containment_receipt,
            Mapping,
        ):
            raise ToolzRouteMemoryError("Toolzs cyber containment evidence rejected")
        if self.containment_key is not None and not isinstance(
            self.containment_key,
            TrustedKey,
        ):
            raise ToolzRouteMemoryError("Toolzs cyber containment trust rejected")


def toolz_route_memory_policy_digest(policy: ToolzRouteMemoryPolicy) -> str:
    """Return the exact local reuse-policy identity."""

    if not isinstance(policy, ToolzRouteMemoryPolicy):
        raise ToolzRouteMemoryError("Toolzs memory policy rejected")
    return digest_object(
        {
            "policy_id": policy.policy_id,
            "subject": {
                "artifact_id": policy.subject.artifact_id,
                "artifact_digest": policy.subject.artifact_digest,
            },
            "environment": {
                "profile_id": policy.environment.profile_id,
                "fingerprint_digest": policy.environment.fingerprint_digest,
            },
            "ui_context_digest": policy.ui_context_digest,
            "required_cyber_channel": policy.required_cyber_channel,
            "require_feedback_ranked": policy.require_feedback_ranked,
            "max_validity_seconds": policy.max_validity_seconds,
            "reuse_semantics": ("exact-context-observed-success-is-candidate-not-authority"),
        },
        domain="toolz-route-memory-policy-v1",
    )


def _receipt_core(receipt: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(receipt))
    core.pop("receipt_id", None)
    core.pop("signature", None)
    return core


def toolz_route_memory_identity(receipt: Mapping[str, Any]) -> str:
    """Return the domain-separated identity of one unsigned memory claim."""

    digest = digest_object(
        _receipt_core(receipt),
        domain="toolz-route-memory-receipt-identity-v1",
    )
    return f"toolz-route-memory-receipt:{digest.split(':', 1)[1]}"


def toolz_route_memory_digest(receipt: Mapping[str, Any]) -> str:
    """Return the exact signed receipt digest."""

    return digest_object(
        dict(receipt),
        domain="toolz-route-memory-signed-receipt-v1",
    )


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ToolzRouteMemoryError(f"Toolzs memory {field} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolzRouteMemoryError(f"Toolzs memory {field} rejected") from exc
    if parsed.tzinfo is None:
        raise ToolzRouteMemoryError(f"Toolzs memory {field} rejected")
    return parsed


def _verify_fog_route(evidence: ToolzFogRouteEvidence) -> dict[str, Any]:
    if not isinstance(evidence, ToolzFogRouteEvidence):
        raise ToolzRouteMemoryError("Toolzs Fog evidence rejected")
    protocol = evidence.route["protocol"]
    if protocol == "integrity-guardian/discovery-theory-route/v1":
        verified_route = verify_discovery_theory_route(
            evidence.route,
            evidence.snapshot,
            trusted_snapshot_key=evidence.trusted_snapshot_key,
            trusted_sources=evidence.trusted_sources,
            trusted_theory_key=evidence.trusted_theory_key,
            expected_snapshot_id=evidence.expected_snapshot_id,
            expected_tenant_id=evidence.expected_tenant_id,
            expected_policy=evidence.expected_policy,
        )
        overlay_id = None
        overlay_digest = None
    else:
        verified_overlay = verify_discovery_feedback_overlay(
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
        verified_route = verify_discovery_theory_route_with_feedback(
            evidence.route,
            evidence.snapshot,
            verified_overlay,
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
        overlay_id = verified_overlay["overlay_id"]
        overlay_digest = discovery_feedback_overlay_digest(verified_overlay)
    return {
        "route_kind": _ROUTE_PROTOCOLS[protocol],
        "proposal_id": verified_route["proposal_id"],
        "route_digest": digest_object(
            verified_route,
            domain="toolz-fog-route-reference-v1",
        ),
        "snapshot_id": verified_route["snapshot_id"],
        "snapshot_digest": verified_route["snapshot_digest"],
        "route_created_at": verified_route["created_at"],
        "route_status": verified_route["status"],
        "invalidation_zone_ids": list(verified_route["invalidation_zone_ids"]),
        "feedback_overlay_id": overlay_id,
        "feedback_overlay_digest": overlay_digest,
    }


def _verify_cyber_decision(evidence: ToolzCyberEvidence) -> dict[str, Any]:
    if not isinstance(evidence, ToolzCyberEvidence):
        raise ToolzRouteMemoryError("Toolzs cyber evidence rejected")
    return verify_promotion_decision_receipt(
        evidence.decision_receipt,
        expected_policy=evidence.expected_policy,
        provenance_receipt=evidence.provenance_receipt,
        assessment_receipt=evidence.assessment_receipt,
        containment_receipt=evidence.containment_receipt,
        provenance_key=evidence.provenance_key,
        assessment_key=evidence.assessment_key,
        containment_key=evidence.containment_key,
        authority_key=evidence.authority_key,
    )


def _cyber_reference(
    decision: Mapping[str, Any],
    evidence: ToolzCyberEvidence,
) -> dict[str, Any]:
    return {
        "decision_receipt_id": decision["receipt_id"],
        "decision_receipt_digest": security_receipt_digest(
            decision,
            receipt_kind="promotion-decision",
        ),
        "policy_id": decision["policy_id"],
        "policy_digest": project_security_policy_digest(evidence.expected_policy),
        "requested_channel": decision["requested_channel"],
        "decision": decision["decision"],
        "evaluated_at": decision["evaluated_at"],
        "expires_at": decision["expires_at"],
    }


def _tool_context(policy: ToolzRouteMemoryPolicy) -> dict[str, Any]:
    return {
        "artifact_id": policy.subject.artifact_id,
        "artifact_digest": policy.subject.artifact_digest,
        "environment_profile_id": policy.environment.profile_id,
        "environment_fingerprint_digest": policy.environment.fingerprint_digest,
        "ui_context_digest": policy.ui_context_digest,
    }


def _validate_observation(
    observation: Mapping[str, Any],
    *,
    route_status: str,
    route_created_at: str,
    receipt_created_at: str,
) -> None:
    try:
        outcome = ToolzRouteMemoryOutcome(observation["outcome"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ToolzRouteMemoryError("Toolzs memory outcome rejected") from exc
    observed_at = observation["observed_at"]
    evidence_digest = observation["evidence_digest"]
    if outcome is ToolzRouteMemoryOutcome.THEORETICAL:
        if observed_at is not None or evidence_digest is not None:
            raise ToolzRouteMemoryError("Toolzs theoretical observation rejected")
        return
    if not isinstance(evidence_digest, str) or _DIGEST.fullmatch(evidence_digest) is None:
        raise ToolzRouteMemoryError("Toolzs observation evidence rejected")
    observed_time = _parse_time(observed_at, "observation time")
    if not (
        _parse_time(route_created_at, "route creation time")
        <= observed_time
        <= _parse_time(receipt_created_at, "creation time")
    ):
        raise ToolzRouteMemoryError("Toolzs observation time window rejected")
    if outcome is ToolzRouteMemoryOutcome.OBSERVED_SUCCESS and route_status != "candidate":
        raise ToolzRouteMemoryError("Toolzs successful unresolved route rejected")


def _expected_fields(
    policy: ToolzRouteMemoryPolicy,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
) -> tuple[dict[str, Any], dict[str, Any]]:
    route = _verify_fog_route(fog_evidence)
    decision = _verify_cyber_decision(cyber_evidence)
    if (
        cyber_evidence.expected_policy.subject != policy.subject
        or cyber_evidence.expected_policy.environment != policy.environment
    ):
        raise ToolzRouteMemoryError("Toolzs local cyber context mismatch")
    if (
        decision["requested_channel"] != policy.required_cyber_channel
        or cyber_evidence.expected_policy.requested_channel != policy.required_cyber_channel
    ):
        raise ToolzRouteMemoryError("Toolzs local cyber channel mismatch")
    if policy.require_feedback_ranked and route["route_kind"] != "feedback-ranked":
        raise ToolzRouteMemoryError("Toolzs feedback-ranked route required")
    return route, _cyber_reference(decision, cyber_evidence)


def verify_toolz_route_memory_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_policy: ToolzRouteMemoryPolicy,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    authority_key: TrustedKey,
) -> dict[str, Any]:
    """Verify every Fog, `/cyber`, context and signer binding."""

    if not isinstance(expected_policy, ToolzRouteMemoryPolicy):
        raise ToolzRouteMemoryError("Toolzs memory policy rejected")
    try:
        candidate = deepcopy(dict(receipt))
        validate("toolz-route-memory-receipt", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise ToolzRouteMemoryError("Toolzs memory receipt schema rejected") from exc
    if not isinstance(authority_key, TrustedKey):
        raise ToolzRouteMemoryError("Toolzs memory authority rejected")
    if candidate["receipt_id"] != toolz_route_memory_identity(candidate):
        raise ToolzRouteMemoryError("Toolzs memory receipt identity mismatch")
    if candidate["signature"]["key_id"] != authority_key.key_id or not verify_signature(
        candidate, authority_key.public_key
    ):
        raise ToolzRouteMemoryError("Toolzs memory receipt signature rejected")
    if candidate["authority_boundary"] != _AUTHORITY_BOUNDARY:
        raise ToolzRouteMemoryError("Toolzs memory authority boundary mismatch")
    route, cyber = _expected_fields(expected_policy, fog_evidence, cyber_evidence)
    expected = {
        "tenant_id": expected_policy.subject.tenant_id,
        "policy_id": expected_policy.policy_id,
        "policy_digest": toolz_route_memory_policy_digest(expected_policy),
        "tool_context": _tool_context(expected_policy),
        "fog_route": route,
        "cyber_admission": cyber,
    }
    for field, value in expected.items():
        if candidate[field] != value:
            raise ToolzRouteMemoryError(f"Toolzs memory {field} mismatch")
    created = _parse_time(candidate["created_at"], "creation time")
    expires = _parse_time(candidate["expires_at"], "expiry time")
    cyber_evaluated = _parse_time(
        cyber["evaluated_at"],
        "cyber evaluation time",
    )
    cyber_expires = _parse_time(
        cyber["expires_at"],
        "cyber expiry time",
    )
    route_created = _parse_time(
        route["route_created_at"],
        "route creation time",
    )
    if (
        created >= expires
        or (expires - created).total_seconds() > expected_policy.max_validity_seconds
        or created < route_created
        or created < cyber_evaluated
        or expires > cyber_expires
    ):
        raise ToolzRouteMemoryError("Toolzs memory validity window rejected")
    _validate_observation(
        candidate["observation"],
        route_status=route["route_status"],
        route_created_at=route["route_created_at"],
        receipt_created_at=candidate["created_at"],
    )
    return candidate


def build_toolz_route_memory_receipt(
    *,
    policy: ToolzRouteMemoryPolicy,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    outcome: ToolzRouteMemoryOutcome,
    observed_at: str | None,
    observation_evidence_digest: str | None,
    created_at: str,
    expires_at: str,
    memory_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Sign one local route-memory claim without invoking or storing a Toolz."""

    if not isinstance(outcome, ToolzRouteMemoryOutcome):
        raise ToolzRouteMemoryError("Toolzs memory outcome rejected")
    if not isinstance(memory_signer, Ed25519Signer):
        raise ToolzRouteMemoryError("Toolzs memory signer rejected")
    route, cyber = _expected_fields(policy, fog_evidence, cyber_evidence)
    observation = {
        "outcome": outcome.value,
        "observed_at": observed_at,
        "evidence_digest": observation_evidence_digest,
    }
    _validate_observation(
        observation,
        route_status=route["route_status"],
        route_created_at=route["route_created_at"],
        receipt_created_at=created_at,
    )
    core = {
        "protocol": "integrity-guardian/toolz-route-memory-receipt/v1",
        "tenant_id": policy.subject.tenant_id,
        "policy_id": policy.policy_id,
        "policy_digest": toolz_route_memory_policy_digest(policy),
        "tool_context": _tool_context(policy),
        "fog_route": route,
        "cyber_admission": cyber,
        "observation": observation,
        "created_at": created_at,
        "expires_at": expires_at,
        "authority_boundary": deepcopy(_AUTHORITY_BOUNDARY),
    }
    unsigned = {
        "receipt_id": toolz_route_memory_identity(core),
        **core,
    }
    signed = memory_signer.sign(unsigned)
    return verify_toolz_route_memory_receipt(
        signed,
        expected_policy=policy,
        fog_evidence=fog_evidence,
        cyber_evidence=cyber_evidence,
        authority_key=TrustedKey(memory_signer.key_id, memory_signer.public_key),
    )


def evaluate_toolz_route_memory(
    receipt: Mapping[str, Any],
    *,
    expected_policy: ToolzRouteMemoryPolicy,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    authority_key: TrustedKey,
    evaluated_at: str,
) -> ToolzRouteMemoryDecision:
    """Return bounded reuse guidance after complete receipt re-verification."""

    verified = verify_toolz_route_memory_receipt(
        receipt,
        expected_policy=expected_policy,
        fog_evidence=fog_evidence,
        cyber_evidence=cyber_evidence,
        authority_key=authority_key,
    )
    current = _parse_time(evaluated_at, "evaluation time")
    if not (
        _parse_time(verified["created_at"], "creation time")
        <= current
        <= _parse_time(verified["expires_at"], "expiry time")
    ):
        return ToolzRouteMemoryDecision.REDISCOVER
    if verified["fog_route"]["route_status"] != "candidate":
        return ToolzRouteMemoryDecision.BLOCKED
    expected_eligibility = f"{expected_policy.required_cyber_channel}-eligible"
    if verified["cyber_admission"]["decision"] != expected_eligibility:
        return ToolzRouteMemoryDecision.BLOCKED
    outcome = ToolzRouteMemoryOutcome(verified["observation"]["outcome"])
    if outcome is ToolzRouteMemoryOutcome.THEORETICAL:
        return ToolzRouteMemoryDecision.EXPLORE
    if outcome is ToolzRouteMemoryOutcome.OBSERVED_SUCCESS:
        return ToolzRouteMemoryDecision.REUSE_CANDIDATE
    return ToolzRouteMemoryDecision.REDISCOVER
