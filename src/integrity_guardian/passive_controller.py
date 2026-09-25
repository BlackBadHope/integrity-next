"""Controller-owned orchestration for native passive capture candidates.

The controller composes the existing digest-only source compiler, cohort
verifier and external checkpoint protocol. It performs no collection,
persistence, admission or external action.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from jsonschema import ValidationError

from .discovery import DiscoveryCursor, DiscoveryError
from .discovery_cohort import (
    PassiveCohortError,
    PassiveCohortPolicy,
    build_passive_cohort_receipt,
)
from .hashing import digest_object
from .passive_checkpoint import (
    PassiveControllerError,
    parse_controller_time,
    passive_controller_boundary,
    passive_controller_capture_id,
    passive_controller_checkpoint_cursors,
    passive_controller_checkpoint_digest,
    passive_controller_checkpoint_identity,
    passive_controller_source_epoch,
    verify_passive_controller_checkpoint,
)
from .passive_source import (
    PassiveSourceCompilation,
    PassiveSourceError,
    PassiveSourcePolicy,
    compile_passive_source_snapshot,
    passive_source_boundary,
)
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
)


@dataclass(frozen=True)
class PassiveControllerCandidate:
    """One non-admitted compilation, cohort receipt and checkpoint candidate."""

    compilation: PassiveSourceCompilation
    cohort_receipt: Mapping[str, Any]
    checkpoint: Mapping[str, Any]
    boundary: Mapping[str, Any]

    def __post_init__(self) -> None:
        if dict(self.boundary) != passive_controller_boundary():
            raise PassiveControllerError("passive controller boundary mismatch")


@dataclass(frozen=True)
class _ContinuationState:
    input_cursors: tuple[DiscoveryCursor, ...]
    input_policy_digest: str | None
    previous_checkpoint_digest: str | None
    generation: int


def _validated_capture(
    envelope: Mapping[str, Any],
    *,
    source_policy: PassiveSourcePolicy,
    cohort_policy: PassiveCohortPolicy,
    trusted_controller_key: TrustedKey,
) -> tuple[dict[str, Any], str]:
    try:
        candidate = deepcopy(dict(envelope))
        validate("native-passive-capture-envelope", candidate)
    except (TypeError, ValueError, ValidationError) as exc:
        raise PassiveControllerError(
            "passive controller capture envelope schema rejected"
        ) from exc
    if candidate["boundary"] != passive_controller_boundary():
        raise PassiveControllerError("passive controller capture boundary mismatch")
    if candidate["collector_artifact_digest"] != (
        source_policy.collector_artifact_digest
    ):
        raise PassiveControllerError("passive controller collector artifact mismatch")
    started = parse_controller_time(
        candidate["capture_started_at"],
        "capture start time",
    )
    completed = parse_controller_time(
        candidate["capture_completed_at"],
        "capture completion time",
    )
    if completed < started:
        raise PassiveControllerError("passive controller capture clock moved backwards")
    source_epoch = passive_controller_source_epoch(
        candidate,
        source_policy=source_policy,
        cohort_policy=cohort_policy,
        trusted_controller_key=trusted_controller_key,
    )
    if candidate["capture_id"] != passive_controller_capture_id(
        source_epoch,
        candidate["capture_sequence"],
    ):
        raise PassiveControllerError("passive controller capture identity mismatch")
    return candidate, source_epoch


def _continuation_state(
    candidate: Mapping[str, Any],
    *,
    source_epoch: str,
    source_policy: PassiveSourcePolicy,
    cohort_policy: PassiveCohortPolicy,
    trusted_controller_key: TrustedKey,
    input_checkpoint: Mapping[str, Any] | None,
) -> _ContinuationState:
    if input_checkpoint is None:
        if candidate["capture_sequence"] != 0:
            raise PassiveControllerError(
                "passive controller continuation checkpoint required"
            )
        return _ContinuationState(
            input_cursors=tuple(
                DiscoveryCursor(
                    source_id=binding.source_id,
                    source_epoch=source_epoch,
                )
                for binding in source_policy.bindings
            ),
            input_policy_digest=None,
            previous_checkpoint_digest=None,
            generation=0,
        )
    prior = verify_passive_controller_checkpoint(
        input_checkpoint,
        trusted_controller_key=trusted_controller_key,
        source_policy=source_policy,
        cohort_policy=cohort_policy,
        expected_tenant_id=candidate["tenant_id"],
        expected_platform_family=candidate["platform_family"],
        expected_platform_instance_id=candidate["platform_instance_id"],
        expected_boot_identity_digest=candidate["boot_identity_digest"],
    )
    if candidate["capture_sequence"] != prior["next_capture_sequence"]:
        raise PassiveControllerError("passive controller capture sequence mismatch")
    if candidate["capture_id"] == prior["capture_id"]:
        raise PassiveControllerError("passive controller capture replay rejected")
    started = parse_controller_time(
        candidate["capture_started_at"],
        "capture start time",
    )
    prior_completed = parse_controller_time(
        prior["capture_completed_at"],
        "prior checkpoint completion time",
    )
    if started <= prior_completed:
        raise PassiveControllerError(
            "passive controller capture overlaps prior checkpoint"
        )
    return _ContinuationState(
        input_cursors=passive_controller_checkpoint_cursors(
            prior,
            source_policy=source_policy,
            source_epoch=source_epoch,
        ),
        input_policy_digest=prior["source_policy_digest"],
        previous_checkpoint_digest=passive_controller_checkpoint_digest(prior),
        generation=prior["generation"] + 1,
    )


def _compile_and_verify_cohort(
    candidate: Mapping[str, Any],
    *,
    source_epoch: str,
    continuation: _ContinuationState,
    source_policy: PassiveSourcePolicy,
    cohort_policy: PassiveCohortPolicy,
    source_signer: Ed25519Signer,
    controller_signer: Ed25519Signer,
) -> tuple[PassiveSourceCompilation, dict[str, Any]]:
    snapshot = {
        "protocol": "integrity-guardian/passive-source-snapshot/v1",
        "tenant_id": candidate["tenant_id"],
        "capture_id": candidate["capture_id"],
        "platform_family": candidate["platform_family"],
        "source_epoch": source_epoch,
        "collector_artifact_digest": candidate["collector_artifact_digest"],
        "source_summaries": deepcopy(candidate["source_summaries"]),
        "boundary": passive_source_boundary(),
    }
    try:
        compilation = compile_passive_source_snapshot(
            snapshot,
            policy=source_policy,
            input_cursors=continuation.input_cursors,
            input_policy_digest=continuation.input_policy_digest,
            signer=source_signer,
        )
        cohort_receipt = build_passive_cohort_receipt(
            tenant_id=candidate["tenant_id"],
            capture_id=candidate["capture_id"],
            capture_started_at=candidate["capture_started_at"],
            capture_completed_at=candidate["capture_completed_at"],
            records=compilation.records,
            trusted_sources=compilation.trusted_sources,
            input_cursors=compilation.input_cursors,
            policy=cohort_policy,
            signer=controller_signer,
        )
    except (DiscoveryError, PassiveCohortError, PassiveSourceError) as exc:
        raise PassiveControllerError(
            "passive controller candidate rejected"
        ) from exc
    return compilation, cohort_receipt


def _sign_checkpoint(
    candidate: Mapping[str, Any],
    *,
    source_epoch: str,
    continuation: _ContinuationState,
    compilation: PassiveSourceCompilation,
    cohort_receipt: Mapping[str, Any],
    source_policy: PassiveSourcePolicy,
    cohort_policy: PassiveCohortPolicy,
    controller_signer: Ed25519Signer,
    trusted_controller_key: TrustedKey,
) -> dict[str, Any]:
    checkpoint_core = {
        "protocol": "integrity-guardian/passive-controller-checkpoint/v1",
        "tenant_id": candidate["tenant_id"],
        "platform_family": candidate["platform_family"],
        "platform_instance_id": candidate["platform_instance_id"],
        "boot_identity_digest": candidate["boot_identity_digest"],
        "source_epoch": source_epoch,
        "collector_artifact_digest": candidate["collector_artifact_digest"],
        "source_policy_digest": source_policy.digest,
        "cohort_policy_digest": cohort_policy.digest,
        "source_key_id": source_policy.source_key.key_id,
        "source_key_fingerprint": public_key_fingerprint(
            source_policy.source_key.public_key
        ),
        "controller_key_id": trusted_controller_key.key_id,
        "controller_key_fingerprint": public_key_fingerprint(
            trusted_controller_key.public_key
        ),
        "generation": continuation.generation,
        "previous_checkpoint_digest": continuation.previous_checkpoint_digest,
        "capture_id": candidate["capture_id"],
        "capture_completed_at": candidate["capture_completed_at"],
        "next_capture_sequence": candidate["capture_sequence"] + 1,
        "cohort_receipt_digest": digest_object(
            dict(cohort_receipt),
            domain="native-passive-cohort-receipt-v1",
        ),
        "output_cursors": [
            cursor.to_document() for cursor in compilation.output_cursors
        ],
        "boundary": passive_controller_boundary(),
    }
    unsigned = {
        **checkpoint_core,
        "checkpoint_id": passive_controller_checkpoint_identity(checkpoint_core),
    }
    checkpoint = controller_signer.sign(unsigned)
    return verify_passive_controller_checkpoint(
        checkpoint,
        trusted_controller_key=trusted_controller_key,
        source_policy=source_policy,
        cohort_policy=cohort_policy,
        expected_tenant_id=candidate["tenant_id"],
        expected_platform_family=candidate["platform_family"],
        expected_platform_instance_id=candidate["platform_instance_id"],
        expected_boot_identity_digest=candidate["boot_identity_digest"],
    )


def build_native_passive_candidate(
    envelope: Mapping[str, Any],
    *,
    source_policy: PassiveSourcePolicy,
    cohort_policy: PassiveCohortPolicy,
    source_signer: Ed25519Signer,
    controller_signer: Ed25519Signer,
    trusted_controller_key: TrustedKey,
    input_checkpoint: Mapping[str, Any] | None = None,
) -> PassiveControllerCandidate:
    """Compile one native envelope and return a non-persisted checkpoint."""

    if not isinstance(source_policy, PassiveSourcePolicy):
        raise PassiveControllerError("passive controller source policy rejected")
    if not isinstance(cohort_policy, PassiveCohortPolicy):
        raise PassiveControllerError("passive controller cohort policy rejected")
    if not isinstance(source_signer, Ed25519Signer):
        raise PassiveControllerError("passive controller source signer rejected")
    if not isinstance(controller_signer, Ed25519Signer):
        raise PassiveControllerError("passive controller signer rejected")
    if not isinstance(trusted_controller_key, TrustedKey):
        raise PassiveControllerError("passive controller trusted key rejected")
    if (
        controller_signer.key_id != trusted_controller_key.key_id
        or public_key_fingerprint(controller_signer.public_key)
        != public_key_fingerprint(trusted_controller_key.public_key)
    ):
        raise PassiveControllerError("passive controller signer trust mismatch")
    candidate, source_epoch = _validated_capture(
        envelope,
        source_policy=source_policy,
        cohort_policy=cohort_policy,
        trusted_controller_key=trusted_controller_key,
    )
    continuation = _continuation_state(
        candidate,
        source_epoch=source_epoch,
        source_policy=source_policy,
        cohort_policy=cohort_policy,
        trusted_controller_key=trusted_controller_key,
        input_checkpoint=input_checkpoint,
    )
    compilation, cohort_receipt = _compile_and_verify_cohort(
        candidate,
        source_epoch=source_epoch,
        continuation=continuation,
        source_policy=source_policy,
        cohort_policy=cohort_policy,
        source_signer=source_signer,
        controller_signer=controller_signer,
    )
    checkpoint = _sign_checkpoint(
        candidate,
        source_epoch=source_epoch,
        continuation=continuation,
        compilation=compilation,
        cohort_receipt=cohort_receipt,
        source_policy=source_policy,
        cohort_policy=cohort_policy,
        controller_signer=controller_signer,
        trusted_controller_key=trusted_controller_key,
    )
    return PassiveControllerCandidate(
        compilation=compilation,
        cohort_receipt=cohort_receipt,
        checkpoint=checkpoint,
        boundary=passive_controller_boundary(),
    )
