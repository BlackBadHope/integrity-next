"""Deterministic, non-authoritative route theory over verified discovery state."""

from __future__ import annotations

import heapq
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from itertools import count
from typing import Any

from jsonschema import ValidationError

from .discovery import (
    MAX_DISCOVERY_CHANGED_ZONES,
    CoverageState,
    DiscoveryAssertionKind,
    DiscoveryProvenance,
    TrustedDiscoverySource,
    discovery_index_snapshot_digest,
    verify_discovery_index_snapshot_sources,
)
from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_signature

MAX_THEORY_HOPS = 32
MAX_THEORY_EXPANSIONS = 10_000
MAX_THEORY_GAPS = 1_000

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_THEORY_BOUNDARY = {
    "credentials": False,
    "execution": False,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
    "synapse_authority": False,
}
_FEEDBACK_BOUNDARY = {
    "credentials": False,
    "execution": False,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
    "source_evidence_mutated": False,
}


class DiscoveryTheoryError(ValueError):
    """Raised when route theory violates its deterministic safety contract."""


class DiscoveryTheoryStatus(StrEnum):
    CANDIDATE = "candidate"
    UNRESOLVED = "unresolved"


class DiscoveryFeedbackOutcome(StrEnum):
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    STALE = "stale"


@dataclass(frozen=True)
class DiscoveryTheoryPolicy:
    """Bounded deterministic search policy, never an execution policy."""

    policy_id: str
    allowed_relation_types: tuple[str, ...] = ()
    allowed_provenance: tuple[DiscoveryProvenance, ...] = (
        DiscoveryProvenance.OBSERVED,
        DiscoveryProvenance.DERIVED,
        DiscoveryProvenance.LEARNED,
        DiscoveryProvenance.PROPOSED,
    )
    min_confidence_ppm: int = 0
    max_hops: int = 8
    max_expansions: int = 1_000

    def __post_init__(self) -> None:
        if not isinstance(self.policy_id, str) or _ID.fullmatch(self.policy_id) is None:
            raise DiscoveryTheoryError("discovery theory policy id rejected")
        if not isinstance(self.allowed_relation_types, tuple):
            raise DiscoveryTheoryError("discovery theory relation types rejected")
        for relation_type in self.allowed_relation_types:
            if not isinstance(relation_type, str) or _ID.fullmatch(relation_type) is None:
                raise DiscoveryTheoryError("discovery theory relation type rejected")
        if len(set(self.allowed_relation_types)) != len(self.allowed_relation_types):
            raise DiscoveryTheoryError("duplicate discovery theory relation type")
        if (
            not isinstance(self.allowed_provenance, tuple)
            or not self.allowed_provenance
            or any(
                not isinstance(provenance, DiscoveryProvenance)
                for provenance in self.allowed_provenance
            )
        ):
            raise DiscoveryTheoryError("discovery theory provenance rejected")
        if len(set(self.allowed_provenance)) != len(self.allowed_provenance):
            raise DiscoveryTheoryError("duplicate discovery theory provenance")
        if (
            not isinstance(self.min_confidence_ppm, int)
            or isinstance(self.min_confidence_ppm, bool)
            or not 0 <= self.min_confidence_ppm <= 1_000_000
        ):
            raise DiscoveryTheoryError("discovery theory confidence rejected")
        if (
            not isinstance(self.max_hops, int)
            or isinstance(self.max_hops, bool)
            or not 1 <= self.max_hops <= MAX_THEORY_HOPS
        ):
            raise DiscoveryTheoryError("discovery theory hop limit rejected")
        if (
            not isinstance(self.max_expansions, int)
            or isinstance(self.max_expansions, bool)
            or not 1 <= self.max_expansions <= MAX_THEORY_EXPANSIONS
        ):
            raise DiscoveryTheoryError("discovery theory expansion limit rejected")


def discovery_theory_policy_digest(policy: DiscoveryTheoryPolicy) -> str:
    """Return a canonical digest of the complete route-selection policy."""

    if not isinstance(policy, DiscoveryTheoryPolicy):
        raise DiscoveryTheoryError("discovery theory policy rejected")
    document = {
        "policy_id": policy.policy_id,
        "allowed_relation_types": sorted(policy.allowed_relation_types),
        "allowed_provenance": sorted(
            provenance.value for provenance in policy.allowed_provenance
        ),
        "min_confidence_ppm": policy.min_confidence_ppm,
        "max_hops": policy.max_hops,
        "max_expansions": policy.max_expansions,
        "objective": "fewest-hops/highest-bottleneck/lexicographic",
    }
    return digest_object(document, domain="discovery-theory-policy-v1")


def _proposal_core(proposal: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(proposal))
    core.pop("proposal_id", None)
    core.pop("signature", None)
    return core


def discovery_theory_route_identity(proposal: Mapping[str, Any]) -> str:
    digest = digest_object(
        _proposal_core(proposal),
        domain="discovery-theory-route-identity-v1",
    )
    return f"discovery-theory-route:{digest.split(':', 1)[1]}"


def discovery_theory_route_digest(proposal: Mapping[str, Any]) -> str:
    return digest_object(
        dict(proposal),
        domain="discovery-theory-route-reference-v1",
    )


def _edge_sort_key(record: Mapping[str, Any]) -> tuple[str, str, str, str]:
    assertion = record["assertion"]
    return (
        assertion["relation_id"],
        assertion["to_entity_id"],
        record["source_id"],
        record["record_id"],
    )


def _select_route(
    records: Sequence[Mapping[str, Any]],
    *,
    from_entity_id: str,
    to_entity_id: str,
    policy: DiscoveryTheoryPolicy,
    excluded_record_ids: frozenset[str] = frozenset(),
    record_feedback_scores: Mapping[str, int] | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    if from_entity_id == to_entity_id:
        return [], False

    allowed_types = set(policy.allowed_relation_types)
    allowed_provenance = {
        provenance.value for provenance in policy.allowed_provenance
    }
    adjacency: dict[str, list[dict[str, Any]]] = defaultdict(list)
    feedback_scores = record_feedback_scores or {}
    for raw_record in records:
        record = dict(raw_record)
        assertion = record["assertion"]
        if assertion["kind"] != DiscoveryAssertionKind.RELATION.value:
            continue
        if record["record_id"] in excluded_record_ids:
            continue
        if (
            allowed_types
            and assertion["relation_type"] not in allowed_types
        ):
            continue
        if record["evidence"]["provenance"] not in allowed_provenance:
            continue
        if record["evidence"]["confidence_ppm"] < policy.min_confidence_ppm:
            continue
        adjacency[assertion["from_entity_id"]].append(record)
    for edges in adjacency.values():
        edges.sort(key=_edge_sort_key)

    serial = count()
    start_priority: tuple[
        int,
        int,
        int,
        tuple[tuple[str, str, str], ...],
    ] = (
        0,
        -1_000_000,
        0,
        (),
    )
    queue: list[
        tuple[
            tuple[
                int,
                int,
                int,
                tuple[tuple[str, str, str], ...],
            ],
            int,
            str,
            tuple[str, ...],
            tuple[dict[str, Any], ...],
        ]
    ] = [
        (
            start_priority,
            next(serial),
            from_entity_id,
            (from_entity_id,),
            (),
        )
    ]
    best_seen = {from_entity_id: start_priority}
    expansions = 0
    expansion_exhausted = False

    while queue:
        priority, _, entity_id, entity_path, route_records = heapq.heappop(queue)
        if best_seen.get(entity_id) != priority:
            continue
        if entity_id == to_entity_id:
            return list(route_records), False
        if len(route_records) >= policy.max_hops:
            continue

        for record in adjacency.get(entity_id, []):
            if expansions >= policy.max_expansions:
                expansion_exhausted = True
                break
            expansions += 1
            assertion = record["assertion"]
            next_entity = assertion["to_entity_id"]
            if next_entity in entity_path:
                continue
            route_key = priority[3] + (
                (
                    assertion["relation_id"],
                    record["source_id"],
                    record["record_id"],
                ),
            )
            next_priority = (
                priority[0] + 1,
                -min(-priority[1], record["evidence"]["confidence_ppm"]),
                priority[2] - feedback_scores.get(record["record_id"], 0),
                route_key,
            )
            previous = best_seen.get(next_entity)
            if previous is not None and previous <= next_priority:
                continue
            best_seen[next_entity] = next_priority
            heapq.heappush(
                queue,
                (
                    next_priority,
                    next(serial),
                    next_entity,
                    entity_path + (next_entity,),
                    route_records + (record,),
                ),
            )
    return [], expansion_exhausted


def _route_hop(record: Mapping[str, Any]) -> dict[str, Any]:
    assertion = record["assertion"]
    return {
        "record_id": record["record_id"],
        "source_id": record["source_id"],
        "source_epoch": record["source_epoch"],
        "relation_id": assertion["relation_id"],
        "relation_type": assertion["relation_type"],
        "from_entity_id": assertion["from_entity_id"],
        "to_entity_id": assertion["to_entity_id"],
        "from_zone_id": assertion["from_zone_id"],
        "to_zone_id": assertion["to_zone_id"],
        "provenance": record["evidence"]["provenance"],
        "confidence_ppm": record["evidence"]["confidence_ppm"],
        "coverage_state": record["evidence"]["coverage"]["state"],
        "coverage_scope_digest": record["evidence"]["coverage"]["scope_digest"],
    }


def _relevant_gaps(
    records: Sequence[Mapping[str, Any]],
    *,
    entity_ids: set[str],
    zone_ids: set[str],
) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for record in records:
        assertion = record["assertion"]
        if assertion["kind"] != DiscoveryAssertionKind.GAP.value:
            continue
        subject_id = assertion["subject_id"]
        if (
            subject_id not in entity_ids
            and subject_id not in zone_ids
            and record["zone_id"] not in zone_ids
        ):
            continue
        gaps.append(
            {
                "record_id": record["record_id"],
                "source_id": record["source_id"],
                "gap_id": assertion["gap_id"],
                "classification": assertion["classification"],
                "subject_id": subject_id,
                "zone_id": record["zone_id"],
            }
        )
    gaps.sort(key=lambda gap: (gap["gap_id"], gap["source_id"], gap["record_id"]))
    if len(gaps) > MAX_THEORY_GAPS:
        raise DiscoveryTheoryError("discovery theory relevant gap limit exceeded")
    return gaps


def _build_route_core(
    snapshot: Mapping[str, Any],
    *,
    policy: DiscoveryTheoryPolicy,
    from_entity_id: str,
    to_entity_id: str,
    created_at: str,
    excluded_record_ids: frozenset[str] = frozenset(),
    record_feedback_scores: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    records = snapshot["active_records"]
    route_records, search_bound_reached = _select_route(
        records,
        from_entity_id=from_entity_id,
        to_entity_id=to_entity_id,
        policy=policy,
        excluded_record_ids=excluded_record_ids,
        record_feedback_scores=record_feedback_scores,
    )
    hops = [_route_hop(record) for record in route_records]
    status = (
        DiscoveryTheoryStatus.CANDIDATE
        if route_records or from_entity_id == to_entity_id
        else DiscoveryTheoryStatus.UNRESOLVED
    )

    route_entity_ids: list[str] = []
    if status is DiscoveryTheoryStatus.CANDIDATE:
        route_entity_ids = [from_entity_id]
        route_entity_ids.extend(hop["to_entity_id"] for hop in hops)
    relevant_entities = set(route_entity_ids) or {
        from_entity_id,
        to_entity_id,
    }
    route_zones = {
        zone_id
        for hop in hops
        for zone_id in (hop["from_zone_id"], hop["to_zone_id"])
    }
    gaps = _relevant_gaps(
        records,
        entity_ids=relevant_entities,
        zone_ids=route_zones,
    )
    invalidation_zones = set(route_zones)
    invalidation_zones.update(gap["zone_id"] for gap in gaps)
    if len(invalidation_zones) > MAX_DISCOVERY_CHANGED_ZONES:
        raise DiscoveryTheoryError("discovery theory invalidation zone limit exceeded")

    entity_evidence = {
        record["assertion"]["entity_id"]
        for record in records
        if record["assertion"]["kind"] == DiscoveryAssertionKind.ENTITY.value
    }
    assumptions: set[str] = set()
    if status is DiscoveryTheoryStatus.CANDIDATE:
        if hops:
            assumptions.add("relation-evidence-is-not-live-reachability")
        if any(
            hop["provenance"] != DiscoveryProvenance.OBSERVED.value
            for hop in hops
        ):
            assumptions.add("non-observed-relation")
        if any(
            hop["coverage_state"] != CoverageState.COMPLETE.value
            for hop in hops
        ):
            assumptions.add("incomplete-coverage")
        if any(entity_id not in entity_evidence for entity_id in route_entity_ids):
            assumptions.add("missing-entity-evidence")
    else:
        assumptions.add("no-route-within-policy")
        if search_bound_reached:
            assumptions.add("search-bound-reached")
    if gaps:
        assumptions.add("unknowns-intersect-route")

    return {
        "protocol": "integrity-guardian/discovery-theory-route/v1",
        "tenant_id": snapshot["tenant_id"],
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_digest": discovery_index_snapshot_digest(snapshot),
        "policy_id": policy.policy_id,
        "policy_digest": discovery_theory_policy_digest(policy),
        "created_at": created_at,
        "from_entity_id": from_entity_id,
        "to_entity_id": to_entity_id,
        "status": status.value,
        "route_entity_ids": route_entity_ids,
        "hops": hops,
        "bottleneck_confidence_ppm": (
            min(hop["confidence_ppm"] for hop in hops)
            if hops
            else (1_000_000 if status is DiscoveryTheoryStatus.CANDIDATE else 0)
        ),
        "assumptions": sorted(assumptions),
        "gaps": gaps,
        "invalidation_zone_ids": sorted(invalidation_zones),
        "theory_boundary": deepcopy(_THEORY_BOUNDARY),
    }


def synthesize_discovery_theory_route(
    snapshot: Mapping[str, Any],
    *,
    trusted_snapshot_key: TrustedKey,
    trusted_sources: Sequence[TrustedDiscoverySource],
    expected_snapshot_id: str,
    expected_tenant_id: str,
    policy: DiscoveryTheoryPolicy,
    from_entity_id: str,
    to_entity_id: str,
    created_at: str,
    theory_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Create one signed proposal without executing or inventing an edge."""

    for field, value in (
        ("from_entity_id", from_entity_id),
        ("to_entity_id", to_entity_id),
    ):
        if not isinstance(value, str) or _ID.fullmatch(value) is None:
            raise DiscoveryTheoryError(f"discovery theory {field} rejected")
    if not isinstance(policy, DiscoveryTheoryPolicy):
        raise DiscoveryTheoryError("discovery theory policy rejected")
    if not isinstance(theory_signer, Ed25519Signer):
        raise DiscoveryTheoryError("discovery theory signer rejected")

    verified_snapshot = verify_discovery_index_snapshot_sources(
        snapshot,
        trusted_snapshot_key,
        trusted_sources=trusted_sources,
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
    )
    core = _build_route_core(
        verified_snapshot,
        policy=policy,
        from_entity_id=from_entity_id,
        to_entity_id=to_entity_id,
        created_at=created_at,
    )
    unsigned = {
        "proposal_id": discovery_theory_route_identity(core),
        **core,
    }
    proposal = theory_signer.sign(unsigned)
    return verify_discovery_theory_route(
        proposal,
        verified_snapshot,
        trusted_snapshot_key=trusted_snapshot_key,
        trusted_sources=trusted_sources,
        trusted_theory_key=TrustedKey(
            key_id=theory_signer.key_id,
            public_key=theory_signer.public_key,
        ),
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
        expected_policy=policy,
    )


def _verify_theory_route_envelope(
    proposal: Mapping[str, Any],
    trusted_theory_key: TrustedKey,
) -> dict[str, Any]:
    try:
        candidate = deepcopy(dict(proposal))
        validate("discovery-theory-route", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise DiscoveryTheoryError("discovery theory route schema is invalid") from exc
    if candidate["proposal_id"] != discovery_theory_route_identity(candidate):
        raise DiscoveryTheoryError("discovery theory route identity mismatch")
    if (
        candidate["signature"]["key_id"] != trusted_theory_key.key_id
        or not verify_signature(candidate, trusted_theory_key.public_key)
    ):
        raise DiscoveryTheoryError("discovery theory route signature rejected")
    if candidate["theory_boundary"] != _THEORY_BOUNDARY:
        raise DiscoveryTheoryError("discovery theory boundary mismatch")
    return candidate


def verify_discovery_theory_route(
    proposal: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    *,
    trusted_snapshot_key: TrustedKey,
    trusted_sources: Sequence[TrustedDiscoverySource],
    trusted_theory_key: TrustedKey,
    expected_snapshot_id: str,
    expected_tenant_id: str,
    expected_policy: DiscoveryTheoryPolicy,
) -> dict[str, Any]:
    """Recompute route selection and verify the signed proposal exactly."""

    if not isinstance(expected_policy, DiscoveryTheoryPolicy):
        raise DiscoveryTheoryError("discovery theory policy rejected")
    candidate = _verify_theory_route_envelope(proposal, trusted_theory_key)

    verified_snapshot = verify_discovery_index_snapshot_sources(
        snapshot,
        trusted_snapshot_key,
        trusted_sources=trusted_sources,
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
    )
    expected_core = _build_route_core(
        verified_snapshot,
        policy=expected_policy,
        from_entity_id=candidate["from_entity_id"],
        to_entity_id=candidate["to_entity_id"],
        created_at=candidate["created_at"],
    )
    if _proposal_core(candidate) != expected_core:
        raise DiscoveryTheoryError("discovery theory route recomputation mismatch")
    return candidate


def _feedback_core(receipt: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(receipt))
    core.pop("receipt_id", None)
    core.pop("signature", None)
    return core


def discovery_theory_feedback_identity(receipt: Mapping[str, Any]) -> str:
    digest = digest_object(
        _feedback_core(receipt),
        domain="discovery-theory-feedback-identity-v1",
    )
    return f"discovery-theory-feedback:{digest.split(':', 1)[1]}"


def verify_discovery_theory_feedback(
    receipt: Mapping[str, Any],
    proposal: Mapping[str, Any],
    *,
    trusted_feedback_key: TrustedKey,
    trusted_theory_key: TrustedKey,
    expected_observer_id: str | None = None,
) -> dict[str, Any]:
    """Verify signed feedback without promoting or mutating source evidence."""

    try:
        candidate = deepcopy(dict(receipt))
        validate("discovery-theory-feedback", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise DiscoveryTheoryError("discovery theory feedback schema is invalid") from exc
    route = _verify_theory_route_envelope(proposal, trusted_theory_key)
    if candidate["receipt_id"] != discovery_theory_feedback_identity(candidate):
        raise DiscoveryTheoryError("discovery theory feedback identity mismatch")
    if (
        candidate["signature"]["key_id"] != trusted_feedback_key.key_id
        or not verify_signature(candidate, trusted_feedback_key.public_key)
    ):
        raise DiscoveryTheoryError("discovery theory feedback signature rejected")
    if candidate["feedback_boundary"] != _FEEDBACK_BOUNDARY:
        raise DiscoveryTheoryError("discovery theory feedback boundary mismatch")
    if (
        candidate["proposal_id"] != route["proposal_id"]
        or candidate["proposal_digest"] != discovery_theory_route_digest(route)
        or candidate["tenant_id"] != route["tenant_id"]
        or candidate["snapshot_id"] != route["snapshot_id"]
    ):
        raise DiscoveryTheoryError("discovery theory feedback proposal mismatch")
    if (
        expected_observer_id is not None
        and candidate["observer_id"] != expected_observer_id
    ):
        raise DiscoveryTheoryError("discovery theory feedback observer mismatch")

    record_ids = {hop["record_id"] for hop in route["hops"]}
    route_zones = set(route["invalidation_zone_ids"])
    if not set(candidate["affected_record_ids"]).issubset(record_ids):
        raise DiscoveryTheoryError("discovery theory feedback record scope mismatch")
    if not set(candidate["invalidated_zone_ids"]).issubset(route_zones):
        raise DiscoveryTheoryError("discovery theory feedback zone scope mismatch")
    outcome = candidate["outcome"]
    evidence_digest = candidate["evidence_digest"]
    if outcome in {
        DiscoveryFeedbackOutcome.CONFIRMED.value,
        DiscoveryFeedbackOutcome.REFUTED.value,
    } and evidence_digest is None:
        raise DiscoveryTheoryError("discovery theory feedback evidence required")
    if (
        outcome == DiscoveryFeedbackOutcome.REFUTED.value
        and not candidate["affected_record_ids"]
        and not candidate["invalidated_zone_ids"]
    ):
        raise DiscoveryTheoryError("refuted discovery theory scope required")
    if (
        outcome == DiscoveryFeedbackOutcome.STALE.value
        and not candidate["invalidated_zone_ids"]
    ):
        raise DiscoveryTheoryError("stale discovery theory zones required")
    if (
        route["status"] == DiscoveryTheoryStatus.UNRESOLVED.value
        and outcome
        in {
            DiscoveryFeedbackOutcome.CONFIRMED.value,
            DiscoveryFeedbackOutcome.REFUTED.value,
        }
    ):
        raise DiscoveryTheoryError("unresolved discovery theory outcome rejected")
    return candidate


def build_discovery_theory_feedback(
    proposal: Mapping[str, Any],
    *,
    observer_id: str,
    observed_at: str,
    outcome: DiscoveryFeedbackOutcome,
    evidence_digest: str | None,
    affected_record_ids: Sequence[str] = (),
    invalidated_zone_ids: Sequence[str] = (),
    feedback_signer: Ed25519Signer,
    trusted_theory_key: TrustedKey,
) -> dict[str, Any]:
    """Sign already collected feedback; never execute or update the route."""

    route = _verify_theory_route_envelope(proposal, trusted_theory_key)
    if not isinstance(observer_id, str) or _ID.fullmatch(observer_id) is None:
        raise DiscoveryTheoryError("discovery theory observer id rejected")
    if not isinstance(outcome, DiscoveryFeedbackOutcome):
        raise DiscoveryTheoryError("discovery theory feedback outcome rejected")
    if (
        evidence_digest is not None
        and (
            not isinstance(evidence_digest, str)
            or _DIGEST.fullmatch(evidence_digest) is None
        )
    ):
        raise DiscoveryTheoryError("discovery theory feedback evidence rejected")
    if not isinstance(feedback_signer, Ed25519Signer):
        raise DiscoveryTheoryError("discovery theory feedback signer rejected")
    try:
        records = sorted(set(affected_record_ids))
        zones = sorted(set(invalidated_zone_ids))
    except TypeError as exc:
        raise DiscoveryTheoryError("discovery theory feedback scope rejected") from exc

    core: dict[str, Any] = {
        "protocol": "integrity-guardian/discovery-theory-feedback/v1",
        "tenant_id": route["tenant_id"],
        "snapshot_id": route["snapshot_id"],
        "proposal_id": route["proposal_id"],
        "proposal_digest": discovery_theory_route_digest(route),
        "observer_id": observer_id,
        "observed_at": observed_at,
        "outcome": outcome.value,
        "evidence_digest": evidence_digest,
        "affected_record_ids": records,
        "invalidated_zone_ids": zones,
        "feedback_boundary": deepcopy(_FEEDBACK_BOUNDARY),
    }
    unsigned = {
        "receipt_id": discovery_theory_feedback_identity(core),
        **core,
    }
    receipt = feedback_signer.sign(unsigned)
    return verify_discovery_theory_feedback(
        receipt,
        route,
        trusted_feedback_key=TrustedKey(
            key_id=feedback_signer.key_id,
            public_key=feedback_signer.public_key,
        ),
        trusted_theory_key=trusted_theory_key,
        expected_observer_id=observer_id,
    )
