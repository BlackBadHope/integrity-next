"""Append-only signed deltas between exact Fog of War feedback overlays."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from jsonschema import ValidationError

from .discovery import TrustedDiscoverySource
from .discovery_feedback import (
    DiscoveryFeedbackError,
    DiscoveryFeedbackPolicy,
    TrustedDiscoveryFeedback,
    discovery_feedback_overlay_digest,
    verify_discovery_feedback_overlay,
)
from .discovery_theory import DiscoveryTheoryPolicy
from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_signature

MAX_FEEDBACK_DELTA_SEQUENCE = 2**63 - 1

_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_TENANT_ID = re.compile(r"^tenant:[A-Za-z0-9][A-Za-z0-9._:/-]{0,248}$")
_SNAPSHOT_ID = re.compile(r"^discovery-index-snapshot:[a-f0-9]{64}$")
_OVERLAY_ID = re.compile(r"^discovery-feedback-overlay:[a-f0-9]{64}$")
_DELTA_BOUNDARY = {
    "credentials": False,
    "execution": False,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
    "source_evidence_mutated": False,
    "synapse_authority": False,
}


class DiscoveryFeedbackDeltaError(DiscoveryFeedbackError):
    """Raised when an incremental overlay transition is not exact or append-only."""


@dataclass(frozen=True)
class DiscoveryFeedbackDeltaCursor:
    """Caller-persisted continuation state for one exact overlay chain."""

    tenant_id: str
    snapshot_id: str
    theory_policy_digest: str
    feedback_policy_digest: str
    next_sequence: int
    current_overlay_id: str
    current_overlay_digest: str
    previous_delta_digest: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, str) or _TENANT_ID.fullmatch(self.tenant_id) is None:
            raise DiscoveryFeedbackDeltaError("feedback delta cursor tenant rejected")
        if (
            not isinstance(self.snapshot_id, str)
            or _SNAPSHOT_ID.fullmatch(self.snapshot_id) is None
        ):
            raise DiscoveryFeedbackDeltaError("feedback delta cursor snapshot rejected")
        for field, value in (
            ("theory policy", self.theory_policy_digest),
            ("feedback policy", self.feedback_policy_digest),
            ("overlay", self.current_overlay_digest),
        ):
            if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
                raise DiscoveryFeedbackDeltaError(
                    f"feedback delta cursor {field} digest rejected"
                )
        if (
            not isinstance(self.current_overlay_id, str)
            or _OVERLAY_ID.fullmatch(self.current_overlay_id) is None
        ):
            raise DiscoveryFeedbackDeltaError("feedback delta cursor overlay id rejected")
        if (
            not isinstance(self.next_sequence, int)
            or isinstance(self.next_sequence, bool)
            or not 0 <= self.next_sequence <= MAX_FEEDBACK_DELTA_SEQUENCE
        ):
            raise DiscoveryFeedbackDeltaError("feedback delta cursor sequence rejected")
        if (
            self.previous_delta_digest is not None
            and (
                not isinstance(self.previous_delta_digest, str)
                or _DIGEST.fullmatch(self.previous_delta_digest) is None
            )
        ):
            raise DiscoveryFeedbackDeltaError(
                "feedback delta cursor previous digest rejected"
            )
        if (self.next_sequence == 0) != (self.previous_delta_digest is None):
            raise DiscoveryFeedbackDeltaError("feedback delta cursor continuity rejected")

    @classmethod
    def from_overlay(
        cls,
        overlay: Mapping[str, Any],
    ) -> DiscoveryFeedbackDeltaCursor:
        try:
            return cls(
                tenant_id=overlay["tenant_id"],
                snapshot_id=overlay["snapshot_id"],
                theory_policy_digest=overlay["theory_policy_digest"],
                feedback_policy_digest=overlay["feedback_policy_digest"],
                next_sequence=0,
                current_overlay_id=overlay["overlay_id"],
                current_overlay_digest=discovery_feedback_overlay_digest(overlay),
            )
        except (KeyError, TypeError) as exc:
            raise DiscoveryFeedbackDeltaError(
                "feedback delta cursor overlay rejected"
            ) from exc

    def to_document(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "snapshot_id": self.snapshot_id,
            "theory_policy_digest": self.theory_policy_digest,
            "feedback_policy_digest": self.feedback_policy_digest,
            "next_sequence": self.next_sequence,
            "current_overlay_id": self.current_overlay_id,
            "current_overlay_digest": self.current_overlay_digest,
            "previous_delta_digest": self.previous_delta_digest,
        }

    @classmethod
    def from_document(
        cls,
        document: Mapping[str, Any],
    ) -> DiscoveryFeedbackDeltaCursor:
        fields = {
            "tenant_id",
            "snapshot_id",
            "theory_policy_digest",
            "feedback_policy_digest",
            "next_sequence",
            "current_overlay_id",
            "current_overlay_digest",
            "previous_delta_digest",
        }
        if not isinstance(document, Mapping) or set(document) != fields:
            raise DiscoveryFeedbackDeltaError("feedback delta cursor document rejected")
        return cls(**dict(document))


def _delta_core(delta: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(delta))
    core.pop("delta_id", None)
    core.pop("signature", None)
    return core


def discovery_feedback_delta_identity(delta: Mapping[str, Any]) -> str:
    digest = digest_object(
        _delta_core(delta),
        domain="discovery-feedback-overlay-delta-identity-v1",
    )
    return f"discovery-feedback-overlay-delta:{digest.split(':', 1)[1]}"


def discovery_feedback_delta_digest(delta: Mapping[str, Any]) -> str:
    return digest_object(
        dict(delta),
        domain="discovery-feedback-overlay-delta-chain-v1",
    )


def _effect_map(
    overlay: Mapping[str, Any],
    field: str,
    identity_field: str,
) -> dict[str, dict[str, Any]]:
    return {
        item[identity_field]: dict(item)
        for item in overlay[field]
    }


def _score_map(overlay: Mapping[str, Any]) -> dict[str, int]:
    return {
        item["record_id"]: item["score"]
        for item in overlay["record_feedback_scores"]
    }


def _dependency_map(
    overlay: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    return {
        item["proposal_id"]: dict(item)
        for item in overlay["dependency_invalidations"]
    }


def _assert_monotonic_dependencies(
    previous: Mapping[str, Any],
    following: Mapping[str, Any],
) -> None:
    for proposal_id, prior in previous.items():
        current = following.get(proposal_id)
        if current is None:
            raise DiscoveryFeedbackDeltaError(
                "feedback delta dependency removal rejected"
            )
        if prior["proposal_digest"] != current["proposal_digest"]:
            raise DiscoveryFeedbackDeltaError(
                "feedback delta proposal digest drift rejected"
            )
        if not set(prior["record_ids"]).issubset(current["record_ids"]):
            raise DiscoveryFeedbackDeltaError(
                "feedback delta record invalidation rollback rejected"
            )
        if not set(prior["zone_ids"]).issubset(current["zone_ids"]):
            raise DiscoveryFeedbackDeltaError(
                "feedback delta zone invalidation rollback rejected"
            )


def _compute_delta_core(
    previous_overlay: Mapping[str, Any],
    next_overlay: Mapping[str, Any],
    *,
    cursor: DiscoveryFeedbackDeltaCursor,
    created_at: str,
) -> dict[str, Any]:
    binding_fields = (
        "tenant_id",
        "snapshot_id",
        "snapshot_digest",
        "theory_policy_id",
        "theory_policy_digest",
        "feedback_policy_id",
        "feedback_policy_digest",
    )
    if any(
        previous_overlay[field] != next_overlay[field]
        for field in binding_fields
    ):
        raise DiscoveryFeedbackDeltaError("feedback delta overlay binding drift rejected")
    if (
        cursor.tenant_id != previous_overlay["tenant_id"]
        or cursor.snapshot_id != previous_overlay["snapshot_id"]
        or cursor.theory_policy_digest != previous_overlay["theory_policy_digest"]
        or cursor.feedback_policy_digest != previous_overlay["feedback_policy_digest"]
        or cursor.current_overlay_id != previous_overlay["overlay_id"]
        or cursor.current_overlay_digest
        != discovery_feedback_overlay_digest(previous_overlay)
    ):
        raise DiscoveryFeedbackDeltaError("feedback delta cursor binding mismatch")
    if cursor.next_sequence >= MAX_FEEDBACK_DELTA_SEQUENCE:
        raise DiscoveryFeedbackDeltaError("feedback delta sequence exhausted")

    previous_receipts = set(previous_overlay["feedback_receipt_ids"])
    next_receipts = set(next_overlay["feedback_receipt_ids"])
    if not previous_receipts < next_receipts:
        raise DiscoveryFeedbackDeltaError(
            "feedback delta requires a strict append-only receipt superset"
        )
    added_receipts = sorted(next_receipts - previous_receipts)

    previous_excluded = set(previous_overlay["excluded_record_ids"])
    next_excluded = set(next_overlay["excluded_record_ids"])
    if not previous_excluded.issubset(next_excluded):
        raise DiscoveryFeedbackDeltaError("feedback delta exclusion rollback rejected")
    newly_excluded = sorted(next_excluded - previous_excluded)

    previous_zones = set(previous_overlay["invalidated_zone_ids"])
    next_zones = set(next_overlay["invalidated_zone_ids"])
    if not previous_zones.issubset(next_zones):
        raise DiscoveryFeedbackDeltaError("feedback delta zone rollback rejected")
    newly_invalidated_zones = sorted(next_zones - previous_zones)

    previous_record_effects = _effect_map(
        previous_overlay,
        "record_effects",
        "record_id",
    )
    next_record_effects = _effect_map(
        next_overlay,
        "record_effects",
        "record_id",
    )
    changed_record_ids = sorted(
        record_id
        for record_id in set(previous_record_effects) | set(next_record_effects)
        if previous_record_effects.get(record_id)
        != next_record_effects.get(record_id)
    )

    previous_scores = _score_map(previous_overlay)
    next_scores = _score_map(next_overlay)
    changed_score_record_ids = sorted(
        record_id
        for record_id in set(previous_scores) | set(next_scores)
        if previous_scores.get(record_id) != next_scores.get(record_id)
    )
    recheck_record_ids = sorted(
        set(newly_excluded) | set(changed_score_record_ids)
    )

    previous_dependencies = _dependency_map(previous_overlay)
    next_dependencies = _dependency_map(next_overlay)
    _assert_monotonic_dependencies(previous_dependencies, next_dependencies)
    newly_invalidated_proposals = sorted(
        set(next_dependencies) - set(previous_dependencies)
    )
    widened_proposals = sorted(
        proposal_id
        for proposal_id in set(previous_dependencies) & set(next_dependencies)
        if (
            previous_dependencies[proposal_id]["record_ids"]
            != next_dependencies[proposal_id]["record_ids"]
            or previous_dependencies[proposal_id]["zone_ids"]
            != next_dependencies[proposal_id]["zone_ids"]
        )
    )

    return {
        "protocol": "integrity-guardian/discovery-feedback-overlay-delta/v1",
        "tenant_id": previous_overlay["tenant_id"],
        "snapshot_id": previous_overlay["snapshot_id"],
        "snapshot_digest": previous_overlay["snapshot_digest"],
        "theory_policy_id": previous_overlay["theory_policy_id"],
        "theory_policy_digest": previous_overlay["theory_policy_digest"],
        "feedback_policy_id": previous_overlay["feedback_policy_id"],
        "feedback_policy_digest": previous_overlay["feedback_policy_digest"],
        "sequence": cursor.next_sequence,
        "previous_delta_digest": cursor.previous_delta_digest,
        "previous_overlay_id": previous_overlay["overlay_id"],
        "previous_overlay_digest": discovery_feedback_overlay_digest(
            previous_overlay
        ),
        "next_overlay_id": next_overlay["overlay_id"],
        "next_overlay_digest": discovery_feedback_overlay_digest(next_overlay),
        "created_at": created_at,
        "added_feedback_receipt_ids": added_receipts,
        "changed_record_ids": changed_record_ids,
        "changed_feedback_score_record_ids": changed_score_record_ids,
        "newly_excluded_record_ids": newly_excluded,
        "newly_invalidated_zone_ids": newly_invalidated_zones,
        "newly_invalidated_proposal_ids": newly_invalidated_proposals,
        "widened_invalidation_proposal_ids": widened_proposals,
        "recheck_record_ids": recheck_record_ids,
        "recheck_zone_ids": newly_invalidated_zones,
        "recheck_proposal_ids": sorted(
            set(newly_invalidated_proposals) | set(widened_proposals)
        ),
        "delta_boundary": deepcopy(_DELTA_BOUNDARY),
    }


def _advance_cursor(
    cursor: DiscoveryFeedbackDeltaCursor,
    delta: Mapping[str, Any],
) -> DiscoveryFeedbackDeltaCursor:
    return DiscoveryFeedbackDeltaCursor(
        tenant_id=cursor.tenant_id,
        snapshot_id=cursor.snapshot_id,
        theory_policy_digest=cursor.theory_policy_digest,
        feedback_policy_digest=cursor.feedback_policy_digest,
        next_sequence=cursor.next_sequence + 1,
        current_overlay_id=delta["next_overlay_id"],
        current_overlay_digest=delta["next_overlay_digest"],
        previous_delta_digest=discovery_feedback_delta_digest(delta),
    )


def build_discovery_feedback_delta(
    previous_overlay: Mapping[str, Any],
    next_overlay: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    *,
    trusted_snapshot_key: TrustedKey,
    trusted_sources: Sequence[TrustedDiscoverySource],
    trusted_previous_overlay_key: TrustedKey,
    trusted_next_overlay_key: TrustedKey,
    expected_snapshot_id: str,
    expected_tenant_id: str,
    expected_policy: DiscoveryTheoryPolicy,
    feedback_policy: DiscoveryFeedbackPolicy,
    previous_feedback_evidence: Sequence[TrustedDiscoveryFeedback],
    next_feedback_evidence: Sequence[TrustedDiscoveryFeedback],
    cursor: DiscoveryFeedbackDeltaCursor,
    created_at: str,
    delta_signer: Ed25519Signer,
) -> tuple[dict[str, Any], DiscoveryFeedbackDeltaCursor]:
    """Build and verify one strict append-only overlay transition."""

    if not isinstance(cursor, DiscoveryFeedbackDeltaCursor):
        raise DiscoveryFeedbackDeltaError("feedback delta cursor rejected")
    if not isinstance(delta_signer, Ed25519Signer):
        raise DiscoveryFeedbackDeltaError("feedback delta signer rejected")
    verified_previous = verify_discovery_feedback_overlay(
        previous_overlay,
        snapshot,
        trusted_snapshot_key=trusted_snapshot_key,
        trusted_sources=trusted_sources,
        trusted_overlay_key=trusted_previous_overlay_key,
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
        expected_policy=expected_policy,
        feedback_policy=feedback_policy,
        feedback_evidence=previous_feedback_evidence,
    )
    verified_next = verify_discovery_feedback_overlay(
        next_overlay,
        snapshot,
        trusted_snapshot_key=trusted_snapshot_key,
        trusted_sources=trusted_sources,
        trusted_overlay_key=trusted_next_overlay_key,
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
        expected_policy=expected_policy,
        feedback_policy=feedback_policy,
        feedback_evidence=next_feedback_evidence,
    )
    core = _compute_delta_core(
        verified_previous,
        verified_next,
        cursor=cursor,
        created_at=created_at,
    )
    unsigned = {
        "delta_id": discovery_feedback_delta_identity(core),
        **core,
    }
    delta = delta_signer.sign(unsigned)
    return verify_discovery_feedback_delta(
        delta,
        verified_previous,
        verified_next,
        snapshot,
        trusted_snapshot_key=trusted_snapshot_key,
        trusted_sources=trusted_sources,
        trusted_previous_overlay_key=trusted_previous_overlay_key,
        trusted_next_overlay_key=trusted_next_overlay_key,
        trusted_delta_key=TrustedKey(
            key_id=delta_signer.key_id,
            public_key=delta_signer.public_key,
        ),
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
        expected_policy=expected_policy,
        feedback_policy=feedback_policy,
        previous_feedback_evidence=previous_feedback_evidence,
        next_feedback_evidence=next_feedback_evidence,
        cursor=cursor,
    )


def verify_discovery_feedback_delta(
    delta: Mapping[str, Any],
    previous_overlay: Mapping[str, Any],
    next_overlay: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    *,
    trusted_snapshot_key: TrustedKey,
    trusted_sources: Sequence[TrustedDiscoverySource],
    trusted_previous_overlay_key: TrustedKey,
    trusted_next_overlay_key: TrustedKey,
    trusted_delta_key: TrustedKey,
    expected_snapshot_id: str,
    expected_tenant_id: str,
    expected_policy: DiscoveryTheoryPolicy,
    feedback_policy: DiscoveryFeedbackPolicy,
    previous_feedback_evidence: Sequence[TrustedDiscoveryFeedback],
    next_feedback_evidence: Sequence[TrustedDiscoveryFeedback],
    cursor: DiscoveryFeedbackDeltaCursor,
) -> tuple[dict[str, Any], DiscoveryFeedbackDeltaCursor]:
    """Recompute both overlays and every delta/cache-recheck field exactly."""

    try:
        candidate = deepcopy(dict(delta))
        validate("discovery-feedback-overlay-delta", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise DiscoveryFeedbackDeltaError(
            "feedback overlay delta schema is invalid"
        ) from exc
    if candidate["delta_id"] != discovery_feedback_delta_identity(candidate):
        raise DiscoveryFeedbackDeltaError("feedback overlay delta identity mismatch")
    if (
        candidate["signature"]["key_id"] != trusted_delta_key.key_id
        or not verify_signature(candidate, trusted_delta_key.public_key)
    ):
        raise DiscoveryFeedbackDeltaError("feedback overlay delta signature rejected")
    if candidate["delta_boundary"] != _DELTA_BOUNDARY:
        raise DiscoveryFeedbackDeltaError("feedback overlay delta boundary mismatch")

    verified_previous = verify_discovery_feedback_overlay(
        previous_overlay,
        snapshot,
        trusted_snapshot_key=trusted_snapshot_key,
        trusted_sources=trusted_sources,
        trusted_overlay_key=trusted_previous_overlay_key,
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
        expected_policy=expected_policy,
        feedback_policy=feedback_policy,
        feedback_evidence=previous_feedback_evidence,
    )
    verified_next = verify_discovery_feedback_overlay(
        next_overlay,
        snapshot,
        trusted_snapshot_key=trusted_snapshot_key,
        trusted_sources=trusted_sources,
        trusted_overlay_key=trusted_next_overlay_key,
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
        expected_policy=expected_policy,
        feedback_policy=feedback_policy,
        feedback_evidence=next_feedback_evidence,
    )
    expected_core = _compute_delta_core(
        verified_previous,
        verified_next,
        cursor=cursor,
        created_at=candidate["created_at"],
    )
    if _delta_core(candidate) != expected_core:
        raise DiscoveryFeedbackDeltaError(
            "feedback overlay delta recomputation mismatch"
        )
    return candidate, _advance_cursor(cursor, candidate)
