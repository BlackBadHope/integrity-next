"""Signed feedback assimilation for deterministic Fog of War route theory.

The overlay is derived only from already signed proposals and receipts.  It
never mutates discovery evidence, collects data, executes a route, or grants
Synapse/production authority.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from jsonschema import ValidationError

from .discovery import (
    MAX_DISCOVERY_CHANGED_ZONES,
    DiscoveryAssertionKind,
    TrustedDiscoverySource,
    discovery_index_snapshot_digest,
    verify_discovery_index_snapshot_sources,
)
from .discovery_theory import (
    DiscoveryFeedbackOutcome,
    DiscoveryTheoryError,
    DiscoveryTheoryPolicy,
    DiscoveryTheoryStatus,
    _build_route_core,
    _proposal_core,
    _verify_theory_route_envelope,
    discovery_theory_policy_digest,
    discovery_theory_route_digest,
    verify_discovery_theory_feedback,
)
from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_signature

MAX_FEEDBACK_EVIDENCE = 1_000
MAX_FEEDBACK_QUORUM = 1_000

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_OVERLAY_BOUNDARY = {
    "credentials": False,
    "execution": False,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
    "source_evidence_mutated": False,
    "synapse_authority": False,
}


class DiscoveryFeedbackError(DiscoveryTheoryError):
    """Raised when feedback assimilation violates its fail-closed contract."""


@dataclass(frozen=True)
class DiscoveryFeedbackPolicy:
    """Out-of-band quorum policy for one immutable feedback overlay."""

    policy_id: str
    min_refutations_to_exclude: int = 1
    min_stale_observers_to_invalidate: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.policy_id, str) or _ID.fullmatch(self.policy_id) is None:
            raise DiscoveryFeedbackError("discovery feedback policy id rejected")
        for field, value in (
            ("refutation quorum", self.min_refutations_to_exclude),
            ("stale quorum", self.min_stale_observers_to_invalidate),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 1 <= value <= MAX_FEEDBACK_QUORUM
            ):
                raise DiscoveryFeedbackError(f"discovery feedback {field} rejected")


@dataclass(frozen=True)
class TrustedDiscoveryFeedback:
    """Out-of-band observer/key binding plus its signed route and receipt."""

    proposal: Mapping[str, Any]
    receipt: Mapping[str, Any]
    proposal_policy: DiscoveryTheoryPolicy
    trusted_theory_key: TrustedKey
    trusted_feedback_key: TrustedKey
    expected_observer_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.proposal, Mapping) or not isinstance(self.receipt, Mapping):
            raise DiscoveryFeedbackError("discovery feedback evidence rejected")
        if not isinstance(self.proposal_policy, DiscoveryTheoryPolicy):
            raise DiscoveryFeedbackError("discovery feedback proposal policy rejected")
        if not isinstance(self.trusted_theory_key, TrustedKey):
            raise DiscoveryFeedbackError("discovery theory trust binding rejected")
        if not isinstance(self.trusted_feedback_key, TrustedKey):
            raise DiscoveryFeedbackError("discovery observer trust binding rejected")
        if (
            not isinstance(self.expected_observer_id, str)
            or _ID.fullmatch(self.expected_observer_id) is None
        ):
            raise DiscoveryFeedbackError("discovery observer id binding rejected")


def discovery_feedback_policy_digest(policy: DiscoveryFeedbackPolicy) -> str:
    if not isinstance(policy, DiscoveryFeedbackPolicy):
        raise DiscoveryFeedbackError("discovery feedback policy rejected")
    return digest_object(
        {
            "policy_id": policy.policy_id,
            "min_refutations_to_exclude": policy.min_refutations_to_exclude,
            "min_stale_observers_to_invalidate": (
                policy.min_stale_observers_to_invalidate
            ),
            "confirmation_semantics": "unique-observer-preference-only",
            "conflict_semantics": "refutation-wins-and-no-preference",
        },
        domain="discovery-feedback-policy-v1",
    )


def _overlay_core(overlay: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(overlay))
    core.pop("overlay_id", None)
    core.pop("signature", None)
    return core


def discovery_feedback_overlay_identity(overlay: Mapping[str, Any]) -> str:
    digest = digest_object(
        _overlay_core(overlay),
        domain="discovery-feedback-overlay-identity-v1",
    )
    return f"discovery-feedback-overlay:{digest.split(':', 1)[1]}"


def discovery_feedback_overlay_digest(overlay: Mapping[str, Any]) -> str:
    return digest_object(
        dict(overlay),
        domain="discovery-feedback-overlay-reference-v1",
    )


def _verified_route_and_receipt(
    evidence: TrustedDiscoveryFeedback,
    snapshot: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    route = _verify_theory_route_envelope(
        evidence.proposal,
        evidence.trusted_theory_key,
    )
    if (
        route["tenant_id"] != snapshot["tenant_id"]
        or route["snapshot_id"] != snapshot["snapshot_id"]
        or route["snapshot_digest"] != discovery_index_snapshot_digest(snapshot)
        or route["policy_id"] != evidence.proposal_policy.policy_id
        or route["policy_digest"]
        != discovery_theory_policy_digest(evidence.proposal_policy)
    ):
        raise DiscoveryFeedbackError("discovery feedback route binding mismatch")
    expected_core = _build_route_core(
        snapshot,
        policy=evidence.proposal_policy,
        from_entity_id=route["from_entity_id"],
        to_entity_id=route["to_entity_id"],
        created_at=route["created_at"],
    )
    if _proposal_core(route) != expected_core:
        raise DiscoveryFeedbackError("discovery feedback route recomputation mismatch")
    receipt = verify_discovery_theory_feedback(
        evidence.receipt,
        route,
        trusted_feedback_key=evidence.trusted_feedback_key,
        trusted_theory_key=evidence.trusted_theory_key,
        expected_observer_id=evidence.expected_observer_id,
    )
    return route, receipt


def _compute_overlay_core(
    snapshot: Mapping[str, Any],
    *,
    expected_policy: DiscoveryTheoryPolicy,
    feedback_policy: DiscoveryFeedbackPolicy,
    feedback_evidence: Sequence[TrustedDiscoveryFeedback],
    created_at: str,
) -> dict[str, Any]:
    if not isinstance(expected_policy, DiscoveryTheoryPolicy):
        raise DiscoveryFeedbackError("discovery theory policy rejected")
    if not isinstance(feedback_policy, DiscoveryFeedbackPolicy):
        raise DiscoveryFeedbackError("discovery feedback policy rejected")
    if (
        not isinstance(feedback_evidence, Sequence)
        or isinstance(feedback_evidence, (str, bytes))
        or not feedback_evidence
        or len(feedback_evidence) > MAX_FEEDBACK_EVIDENCE
    ):
        raise DiscoveryFeedbackError("discovery feedback evidence count rejected")

    relation_records = {
        record["record_id"]: record
        for record in snapshot["active_records"]
        if record["assertion"]["kind"] == DiscoveryAssertionKind.RELATION.value
    }
    record_observers: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )
    zone_observers: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )
    proposals: dict[str, dict[str, Any]] = {}
    receipt_ids: set[str] = set()

    for raw_evidence in feedback_evidence:
        if not isinstance(raw_evidence, TrustedDiscoveryFeedback):
            raise DiscoveryFeedbackError("discovery feedback trust evidence rejected")
        route, receipt = _verified_route_and_receipt(
            raw_evidence,
            snapshot,
        )
        receipt_id = receipt["receipt_id"]
        if receipt_id in receipt_ids:
            raise DiscoveryFeedbackError("duplicate discovery feedback receipt")
        receipt_ids.add(receipt_id)
        proposals[route["proposal_id"]] = route
        observer_id = receipt["observer_id"]
        outcome = receipt["outcome"]
        for record_id in receipt["affected_record_ids"]:
            record_observers[record_id][outcome].add(observer_id)
        if outcome in {
            DiscoveryFeedbackOutcome.REFUTED.value,
            DiscoveryFeedbackOutcome.STALE.value,
        }:
            for zone_id in receipt["invalidated_zone_ids"]:
                zone_observers[zone_id][outcome].add(observer_id)
        if len(zone_observers) > MAX_DISCOVERY_CHANGED_ZONES:
            raise DiscoveryFeedbackError("discovery feedback zone limit exceeded")

    zone_effects: list[dict[str, Any]] = []
    invalidated_zones: set[str] = set()
    for zone_id in sorted(zone_observers):
        refutations = zone_observers[zone_id][
            DiscoveryFeedbackOutcome.REFUTED.value
        ]
        stale = zone_observers[zone_id][DiscoveryFeedbackOutcome.STALE.value]
        invalidated = (
            len(refutations) >= feedback_policy.min_refutations_to_exclude
            or len(stale) >= feedback_policy.min_stale_observers_to_invalidate
        )
        if invalidated:
            invalidated_zones.add(zone_id)
        zone_effects.append(
            {
                "zone_id": zone_id,
                "refutation_observer_count": len(refutations),
                "stale_observer_count": len(stale),
                "invalidated": invalidated,
            }
        )

    record_effects: list[dict[str, Any]] = []
    excluded_records: set[str] = set()
    feedback_scores: dict[str, int] = {}
    all_effect_record_ids = set(record_observers)
    for record_id, record in relation_records.items():
        assertion = record["assertion"]
        if {
            assertion["from_zone_id"],
            assertion["to_zone_id"],
        } & invalidated_zones:
            all_effect_record_ids.add(record_id)

    for record_id in sorted(all_effect_record_ids):
        record = relation_records.get(record_id)
        if record is None:
            raise DiscoveryFeedbackError("feedback references inactive relation record")
        observers = record_observers[record_id]
        confirmed = observers[DiscoveryFeedbackOutcome.CONFIRMED.value]
        refuted = observers[DiscoveryFeedbackOutcome.REFUTED.value]
        inconclusive = observers[DiscoveryFeedbackOutcome.INCONCLUSIVE.value]
        conflicts = confirmed & (refuted | inconclusive)
        effective_confirmations = confirmed - refuted - inconclusive
        assertion = record["assertion"]
        invalidated_by_zones = sorted(
            {
                assertion["from_zone_id"],
                assertion["to_zone_id"],
            }
            & invalidated_zones
        )
        excluded = (
            len(refuted) >= feedback_policy.min_refutations_to_exclude
            or bool(invalidated_by_zones)
        )
        preference_score = 0 if excluded else len(effective_confirmations)
        if excluded:
            excluded_records.add(record_id)
        elif preference_score:
            feedback_scores[record_id] = preference_score
        record_effects.append(
            {
                "record_id": record_id,
                "confirmation_observer_count": len(confirmed),
                "refutation_observer_count": len(refuted),
                "inconclusive_observer_count": len(inconclusive),
                "conflicted_observer_count": len(conflicts),
                "preference_score": preference_score,
                "excluded": excluded,
                "invalidated_by_zone_ids": invalidated_by_zones,
            }
        )

    dependency_invalidations: list[dict[str, Any]] = []
    for proposal_id in sorted(proposals):
        route = proposals[proposal_id]
        invalidated_record_ids = sorted(
            {hop["record_id"] for hop in route["hops"]} & excluded_records
        )
        invalidated_zone_ids = sorted(
            set(route["invalidation_zone_ids"]) & invalidated_zones
        )
        if invalidated_record_ids or invalidated_zone_ids:
            dependency_invalidations.append(
                {
                    "proposal_id": proposal_id,
                    "proposal_digest": discovery_theory_route_digest(route),
                    "record_ids": invalidated_record_ids,
                    "zone_ids": invalidated_zone_ids,
                }
            )

    return {
        "protocol": "integrity-guardian/discovery-feedback-overlay/v1",
        "tenant_id": snapshot["tenant_id"],
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_digest": discovery_index_snapshot_digest(snapshot),
        "theory_policy_id": expected_policy.policy_id,
        "theory_policy_digest": discovery_theory_policy_digest(expected_policy),
        "feedback_policy_id": feedback_policy.policy_id,
        "feedback_policy_digest": discovery_feedback_policy_digest(feedback_policy),
        "created_at": created_at,
        "feedback_receipt_ids": sorted(receipt_ids),
        "record_effects": record_effects,
        "zone_effects": zone_effects,
        "excluded_record_ids": sorted(excluded_records),
        "record_feedback_scores": [
            {"record_id": record_id, "score": feedback_scores[record_id]}
            for record_id in sorted(feedback_scores)
        ],
        "invalidated_zone_ids": sorted(invalidated_zones),
        "dependency_invalidations": dependency_invalidations,
        "overlay_boundary": deepcopy(_OVERLAY_BOUNDARY),
    }


def build_discovery_feedback_overlay(
    snapshot: Mapping[str, Any],
    *,
    trusted_snapshot_key: TrustedKey,
    trusted_sources: Sequence[TrustedDiscoverySource],
    expected_snapshot_id: str,
    expected_tenant_id: str,
    expected_policy: DiscoveryTheoryPolicy,
    feedback_policy: DiscoveryFeedbackPolicy,
    feedback_evidence: Sequence[TrustedDiscoveryFeedback],
    created_at: str,
    overlay_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Build one signed immutable overlay from exact verified feedback."""

    if not isinstance(overlay_signer, Ed25519Signer):
        raise DiscoveryFeedbackError("discovery feedback overlay signer rejected")
    verified_snapshot = verify_discovery_index_snapshot_sources(
        snapshot,
        trusted_snapshot_key,
        trusted_sources=trusted_sources,
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
    )
    core = _compute_overlay_core(
        verified_snapshot,
        expected_policy=expected_policy,
        feedback_policy=feedback_policy,
        feedback_evidence=feedback_evidence,
        created_at=created_at,
    )
    unsigned = {
        "overlay_id": discovery_feedback_overlay_identity(core),
        **core,
    }
    overlay = overlay_signer.sign(unsigned)
    return verify_discovery_feedback_overlay(
        overlay,
        verified_snapshot,
        trusted_snapshot_key=trusted_snapshot_key,
        trusted_sources=trusted_sources,
        trusted_overlay_key=TrustedKey(
            key_id=overlay_signer.key_id,
            public_key=overlay_signer.public_key,
        ),
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
        expected_policy=expected_policy,
        feedback_policy=feedback_policy,
        feedback_evidence=feedback_evidence,
    )


def verify_discovery_feedback_overlay(
    overlay: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    *,
    trusted_snapshot_key: TrustedKey,
    trusted_sources: Sequence[TrustedDiscoverySource],
    trusted_overlay_key: TrustedKey,
    expected_snapshot_id: str,
    expected_tenant_id: str,
    expected_policy: DiscoveryTheoryPolicy,
    feedback_policy: DiscoveryFeedbackPolicy,
    feedback_evidence: Sequence[TrustedDiscoveryFeedback],
) -> dict[str, Any]:
    """Verify signature, source state, receipts, quorums and all effects."""

    try:
        candidate = deepcopy(dict(overlay))
        validate("discovery-feedback-overlay", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise DiscoveryFeedbackError("discovery feedback overlay schema is invalid") from exc
    if candidate["overlay_id"] != discovery_feedback_overlay_identity(candidate):
        raise DiscoveryFeedbackError("discovery feedback overlay identity mismatch")
    if (
        candidate["signature"]["key_id"] != trusted_overlay_key.key_id
        or not verify_signature(candidate, trusted_overlay_key.public_key)
    ):
        raise DiscoveryFeedbackError("discovery feedback overlay signature rejected")
    if candidate["overlay_boundary"] != _OVERLAY_BOUNDARY:
        raise DiscoveryFeedbackError("discovery feedback overlay boundary mismatch")

    verified_snapshot = verify_discovery_index_snapshot_sources(
        snapshot,
        trusted_snapshot_key,
        trusted_sources=trusted_sources,
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
    )
    expected_core = _compute_overlay_core(
        verified_snapshot,
        expected_policy=expected_policy,
        feedback_policy=feedback_policy,
        feedback_evidence=feedback_evidence,
        created_at=candidate["created_at"],
    )
    if _overlay_core(candidate) != expected_core:
        raise DiscoveryFeedbackError("discovery feedback overlay recomputation mismatch")
    return candidate


def _feedback_route_core(
    snapshot: Mapping[str, Any],
    *,
    expected_policy: DiscoveryTheoryPolicy,
    overlay: Mapping[str, Any],
    from_entity_id: str,
    to_entity_id: str,
    created_at: str,
) -> dict[str, Any]:
    excluded = frozenset(overlay["excluded_record_ids"])
    scores = {
        item["record_id"]: item["score"]
        for item in overlay["record_feedback_scores"]
    }
    base = _build_route_core(
        snapshot,
        policy=expected_policy,
        from_entity_id=from_entity_id,
        to_entity_id=to_entity_id,
        created_at=created_at,
    )
    selected = _build_route_core(
        snapshot,
        policy=expected_policy,
        from_entity_id=from_entity_id,
        to_entity_id=to_entity_id,
        created_at=created_at,
        excluded_record_ids=excluded,
        record_feedback_scores=scores,
    )
    base_record_ids = [hop["record_id"] for hop in base["hops"]]
    selected_record_ids = [hop["record_id"] for hop in selected["hops"]]
    selected_score = sum(scores.get(record_id, 0) for record_id in selected_record_ids)
    if (
        base["status"] == DiscoveryTheoryStatus.CANDIDATE.value
        and selected["status"] == DiscoveryTheoryStatus.UNRESOLVED.value
    ):
        effect = "excluded-route"
    elif base_record_ids != selected_record_ids:
        effect = "rerouted"
    elif selected_score:
        effect = "preferred"
    else:
        effect = "unchanged"
    selected["protocol"] = "integrity-guardian/discovery-feedback-ranked-route/v1"
    selected["feedback_overlay_id"] = overlay["overlay_id"]
    selected["feedback_overlay_digest"] = discovery_feedback_overlay_digest(overlay)
    selected["feedback_score"] = selected_score
    selected["feedback_effect"] = effect
    selected["selection_objective"] = (
        "fewest-hops/highest-bottleneck/highest-feedback/lexicographic"
    )
    return selected


def _feedback_route_core_without_identity(
    proposal: Mapping[str, Any],
) -> dict[str, Any]:
    core = deepcopy(dict(proposal))
    core.pop("proposal_id", None)
    core.pop("signature", None)
    return core


def discovery_feedback_route_identity(proposal: Mapping[str, Any]) -> str:
    digest = digest_object(
        _feedback_route_core_without_identity(proposal),
        domain="discovery-feedback-ranked-route-identity-v1",
    )
    return f"discovery-feedback-ranked-route:{digest.split(':', 1)[1]}"


def synthesize_discovery_theory_route_with_feedback(
    snapshot: Mapping[str, Any],
    overlay: Mapping[str, Any],
    *,
    trusted_snapshot_key: TrustedKey,
    trusted_sources: Sequence[TrustedDiscoverySource],
    trusted_overlay_key: TrustedKey,
    expected_snapshot_id: str,
    expected_tenant_id: str,
    expected_policy: DiscoveryTheoryPolicy,
    feedback_policy: DiscoveryFeedbackPolicy,
    feedback_evidence: Sequence[TrustedDiscoveryFeedback],
    from_entity_id: str,
    to_entity_id: str,
    created_at: str,
    theory_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Select a route using one exact verified feedback overlay."""

    if not isinstance(theory_signer, Ed25519Signer):
        raise DiscoveryFeedbackError("discovery theory signer rejected")
    verified_overlay = verify_discovery_feedback_overlay(
        overlay,
        snapshot,
        trusted_snapshot_key=trusted_snapshot_key,
        trusted_sources=trusted_sources,
        trusted_overlay_key=trusted_overlay_key,
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
        expected_policy=expected_policy,
        feedback_policy=feedback_policy,
        feedback_evidence=feedback_evidence,
    )
    verified_snapshot = verify_discovery_index_snapshot_sources(
        snapshot,
        trusted_snapshot_key,
        trusted_sources=trusted_sources,
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
    )
    core = _feedback_route_core(
        verified_snapshot,
        expected_policy=expected_policy,
        overlay=verified_overlay,
        from_entity_id=from_entity_id,
        to_entity_id=to_entity_id,
        created_at=created_at,
    )
    unsigned = {
        "proposal_id": discovery_feedback_route_identity(core),
        **core,
    }
    proposal = theory_signer.sign(unsigned)
    return verify_discovery_theory_route_with_feedback(
        proposal,
        verified_snapshot,
        verified_overlay,
        trusted_snapshot_key=trusted_snapshot_key,
        trusted_sources=trusted_sources,
        trusted_overlay_key=trusted_overlay_key,
        trusted_theory_key=TrustedKey(
            key_id=theory_signer.key_id,
            public_key=theory_signer.public_key,
        ),
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
        expected_policy=expected_policy,
        feedback_policy=feedback_policy,
        feedback_evidence=feedback_evidence,
    )


def verify_discovery_theory_route_with_feedback(
    proposal: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    overlay: Mapping[str, Any],
    *,
    trusted_snapshot_key: TrustedKey,
    trusted_sources: Sequence[TrustedDiscoverySource],
    trusted_overlay_key: TrustedKey,
    trusted_theory_key: TrustedKey,
    expected_snapshot_id: str,
    expected_tenant_id: str,
    expected_policy: DiscoveryTheoryPolicy,
    feedback_policy: DiscoveryFeedbackPolicy,
    feedback_evidence: Sequence[TrustedDiscoveryFeedback],
) -> dict[str, Any]:
    """Recompute the overlay and ranked route; reject signer-only forgery."""

    try:
        candidate = deepcopy(dict(proposal))
        validate("discovery-feedback-ranked-route", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise DiscoveryFeedbackError("feedback-ranked route schema is invalid") from exc
    if candidate["proposal_id"] != discovery_feedback_route_identity(candidate):
        raise DiscoveryFeedbackError("feedback-ranked route identity mismatch")
    if (
        candidate["signature"]["key_id"] != trusted_theory_key.key_id
        or not verify_signature(candidate, trusted_theory_key.public_key)
    ):
        raise DiscoveryFeedbackError("feedback-ranked route signature rejected")

    verified_overlay = verify_discovery_feedback_overlay(
        overlay,
        snapshot,
        trusted_snapshot_key=trusted_snapshot_key,
        trusted_sources=trusted_sources,
        trusted_overlay_key=trusted_overlay_key,
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
        expected_policy=expected_policy,
        feedback_policy=feedback_policy,
        feedback_evidence=feedback_evidence,
    )
    verified_snapshot = verify_discovery_index_snapshot_sources(
        snapshot,
        trusted_snapshot_key,
        trusted_sources=trusted_sources,
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
    )
    expected_core = _feedback_route_core(
        verified_snapshot,
        expected_policy=expected_policy,
        overlay=verified_overlay,
        from_entity_id=candidate["from_entity_id"],
        to_entity_id=candidate["to_entity_id"],
        created_at=candidate["created_at"],
    )
    if _feedback_route_core_without_identity(candidate) != expected_core:
        raise DiscoveryFeedbackError("feedback-ranked route recomputation mismatch")
    return candidate
