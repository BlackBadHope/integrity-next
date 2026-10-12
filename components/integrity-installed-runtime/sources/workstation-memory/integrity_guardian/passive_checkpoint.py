"""Pure epoch derivation and checkpoint verification for passive controllers."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime
from typing import Any

from jsonschema import ValidationError

from .discovery import DiscoveryCursor, DiscoveryError
from .discovery_cohort import PassiveCohortPolicy
from .hashing import digest_object
from .passive_source import PassiveSourcePolicy
from .schemas import validate
from .signing import (
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)

_CONTROLLER_BOUNDARY = {
    "active_probe": False,
    "atlas_admission": False,
    "checkpoint_commit": False,
    "collection_inside_core": False,
    "execution": False,
    "external_checkpoint_required": True,
    "memory_admission": False,
    "model_calls": 0,
    "mutation": False,
    "network": False,
    "production_authority": False,
    "raw_rows_present": False,
}


class PassiveControllerError(ValueError):
    """Raised before an incoherent native capture can cross the controller."""


def passive_controller_boundary() -> dict[str, Any]:
    """Return the closed controller authority boundary."""

    return deepcopy(_CONTROLLER_BOUNDARY)


def parse_controller_time(value: object, field: str) -> datetime:
    """Parse one timezone-aware controller timestamp."""

    if not isinstance(value, str):
        raise PassiveControllerError(f"passive controller {field} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise PassiveControllerError(
            f"passive controller {field} rejected"
        ) from exc
    if parsed.tzinfo is None:
        raise PassiveControllerError(f"passive controller {field} rejected")
    return parsed


def _source_epoch_material(
    *,
    tenant_id: str,
    platform_family: str,
    platform_instance_id: str,
    boot_identity_digest: str,
    source_policy_digest: str,
    cohort_policy_digest: str,
    collector_artifact_digest: str,
    source_key_fingerprint: str,
    controller_key_id: str,
    controller_key_fingerprint: str,
) -> dict[str, str]:
    return {
        "tenant_id": tenant_id,
        "platform_family": platform_family,
        "platform_instance_id": platform_instance_id,
        "boot_identity_digest": boot_identity_digest,
        "source_policy_digest": source_policy_digest,
        "cohort_policy_digest": cohort_policy_digest,
        "collector_artifact_digest": collector_artifact_digest,
        "source_key_fingerprint": source_key_fingerprint,
        "controller_key_id": controller_key_id,
        "controller_key_fingerprint": controller_key_fingerprint,
    }


def _source_epoch(material: Mapping[str, str]) -> str:
    suffix = digest_object(
        dict(material),
        domain="native-passive-source-epoch-v1",
    ).split(":", 1)[1]
    return f"epoch:passive:{suffix}"


def passive_controller_capture_id(
    source_epoch: str,
    capture_sequence: int,
) -> str:
    """Return the unique controller identity for one epoch capture sequence."""

    prefix = "epoch:passive:"
    suffix = source_epoch.removeprefix(prefix) if isinstance(source_epoch, str) else ""
    if (
        not isinstance(source_epoch, str)
        or not source_epoch.startswith(prefix)
        or len(suffix) != 64
        or any(character not in "0123456789abcdef" for character in suffix)
    ):
        raise PassiveControllerError("passive controller source epoch rejected")
    if (
        isinstance(capture_sequence, bool)
        or not isinstance(capture_sequence, int)
        or capture_sequence < 0
        or capture_sequence > 1_000_000_000
    ):
        raise PassiveControllerError("passive controller capture sequence rejected")
    identity_suffix = digest_object(
        {
            "source_epoch": source_epoch,
            "capture_sequence": capture_sequence,
        },
        domain="native-passive-capture-identity-v1",
    ).split(":", 1)[1]
    return f"capture:native:{identity_suffix}"


def passive_controller_source_epoch(
    envelope: Mapping[str, Any],
    *,
    source_policy: PassiveSourcePolicy,
    cohort_policy: PassiveCohortPolicy,
    trusted_controller_key: TrustedKey,
) -> str:
    """Derive one source epoch from boot identity and exact trust material."""

    if not isinstance(source_policy, PassiveSourcePolicy):
        raise PassiveControllerError("passive controller source policy rejected")
    if not isinstance(cohort_policy, PassiveCohortPolicy):
        raise PassiveControllerError("passive controller cohort policy rejected")
    if not isinstance(trusted_controller_key, TrustedKey):
        raise PassiveControllerError("passive controller trusted key rejected")
    if not isinstance(trusted_controller_key.key_id, str):
        raise PassiveControllerError("passive controller trusted key rejected")
    try:
        candidate = deepcopy(dict(envelope))
        validate("native-passive-capture-envelope", candidate)
    except (TypeError, ValueError, ValidationError) as exc:
        raise PassiveControllerError(
            "passive controller capture envelope schema rejected"
        ) from exc
    if candidate["boundary"] != _CONTROLLER_BOUNDARY:
        raise PassiveControllerError("passive controller capture boundary mismatch")
    return _source_epoch(
        _source_epoch_material(
            tenant_id=candidate["tenant_id"],
            platform_family=candidate["platform_family"],
            platform_instance_id=candidate["platform_instance_id"],
            boot_identity_digest=candidate["boot_identity_digest"],
            source_policy_digest=source_policy.digest,
            cohort_policy_digest=cohort_policy.digest,
            collector_artifact_digest=source_policy.collector_artifact_digest,
            source_key_fingerprint=public_key_fingerprint(
                source_policy.source_key.public_key
            ),
            controller_key_id=trusted_controller_key.key_id,
            controller_key_fingerprint=public_key_fingerprint(
                trusted_controller_key.public_key
            ),
        )
    )


def _checkpoint_core(checkpoint: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(checkpoint))
    core.pop("checkpoint_id", None)
    core.pop("signature", None)
    return core


def passive_controller_checkpoint_identity(
    checkpoint: Mapping[str, Any],
) -> str:
    """Return the content identity of a native passive checkpoint."""

    suffix = digest_object(
        _checkpoint_core(checkpoint),
        domain="native-passive-controller-checkpoint-identity-v1",
    ).split(":", 1)[1]
    return f"passive-controller-checkpoint:{suffix}"


def passive_controller_checkpoint_digest(
    checkpoint: Mapping[str, Any],
) -> str:
    """Return the digest of the complete signed checkpoint."""

    return digest_object(
        dict(checkpoint),
        domain="native-passive-controller-checkpoint-v1",
    )


def passive_controller_checkpoint_cursors(
    checkpoint: Mapping[str, Any],
    *,
    source_policy: PassiveSourcePolicy,
    source_epoch: str,
) -> tuple[DiscoveryCursor, ...]:
    """Return the exact ordered cursor set after closed coverage checks."""

    expected_ids = {binding.source_id for binding in source_policy.bindings}
    indexed: dict[str, DiscoveryCursor] = {}
    try:
        for document in checkpoint["output_cursors"]:
            cursor = DiscoveryCursor.from_document(document)
            if cursor.source_id in indexed:
                raise PassiveControllerError(
                    "passive controller checkpoint cursor duplicate"
                )
            indexed[cursor.source_id] = cursor
    except (DiscoveryError, KeyError, TypeError) as exc:
        if isinstance(exc, PassiveControllerError):
            raise
        raise PassiveControllerError(
            "passive controller checkpoint cursor rejected"
        ) from exc
    if set(indexed) != expected_ids:
        raise PassiveControllerError(
            "passive controller checkpoint cursor coverage mismatch"
        )
    expected_next_sequence = checkpoint.get("next_capture_sequence")
    if any(
        cursor.source_epoch != source_epoch
        or cursor.next_sequence != expected_next_sequence
        for cursor in indexed.values()
    ):
        raise PassiveControllerError(
            "passive controller checkpoint cursor continuity mismatch"
        )
    return tuple(indexed[binding.source_id] for binding in source_policy.bindings)


def _expected_checkpoint_bindings(
    *,
    trusted_controller_key: TrustedKey,
    source_policy: PassiveSourcePolicy,
    cohort_policy: PassiveCohortPolicy,
    tenant_id: str,
    platform_family: str,
    platform_instance_id: str,
    boot_identity_digest: str,
) -> tuple[dict[str, str], str]:
    if not isinstance(trusted_controller_key.key_id, str):
        raise PassiveControllerError("passive controller trusted key rejected")
    source_key_fingerprint = public_key_fingerprint(
        source_policy.source_key.public_key
    )
    exact = {
        "tenant_id": tenant_id,
        "platform_family": platform_family,
        "platform_instance_id": platform_instance_id,
        "boot_identity_digest": boot_identity_digest,
        "source_policy_digest": source_policy.digest,
        "cohort_policy_digest": cohort_policy.digest,
        "collector_artifact_digest": source_policy.collector_artifact_digest,
        "source_key_id": source_policy.source_key.key_id,
        "source_key_fingerprint": source_key_fingerprint,
        "controller_key_id": trusted_controller_key.key_id,
        "controller_key_fingerprint": public_key_fingerprint(
            trusted_controller_key.public_key
        ),
    }
    source_epoch = _source_epoch(
        _source_epoch_material(
            tenant_id=tenant_id,
            platform_family=platform_family,
            platform_instance_id=platform_instance_id,
            boot_identity_digest=boot_identity_digest,
            source_policy_digest=source_policy.digest,
            cohort_policy_digest=cohort_policy.digest,
            collector_artifact_digest=source_policy.collector_artifact_digest,
            source_key_fingerprint=source_key_fingerprint,
            controller_key_id=trusted_controller_key.key_id,
            controller_key_fingerprint=public_key_fingerprint(
                trusted_controller_key.public_key
            ),
        )
    )
    return exact, source_epoch


def verify_passive_controller_checkpoint(
    checkpoint: Mapping[str, Any],
    *,
    trusted_controller_key: TrustedKey,
    source_policy: PassiveSourcePolicy,
    cohort_policy: PassiveCohortPolicy,
    expected_tenant_id: str,
    expected_platform_family: str,
    expected_platform_instance_id: str,
    expected_boot_identity_digest: str,
) -> dict[str, Any]:
    """Verify one exact externally retained passive controller checkpoint."""

    if not isinstance(trusted_controller_key, TrustedKey):
        raise PassiveControllerError("passive controller trusted key rejected")
    if not isinstance(source_policy, PassiveSourcePolicy):
        raise PassiveControllerError("passive controller source policy rejected")
    if not isinstance(cohort_policy, PassiveCohortPolicy):
        raise PassiveControllerError("passive controller cohort policy rejected")
    try:
        candidate = deepcopy(dict(checkpoint))
        validate("passive-controller-checkpoint", candidate)
    except (TypeError, ValueError, ValidationError) as exc:
        raise PassiveControllerError(
            "passive controller checkpoint schema rejected"
        ) from exc
    if candidate["boundary"] != _CONTROLLER_BOUNDARY:
        raise PassiveControllerError("passive controller checkpoint boundary mismatch")
    if (
        candidate["signature"]["key_id"] != trusted_controller_key.key_id
        or not verify_signature(candidate, trusted_controller_key.public_key)
    ):
        raise PassiveControllerError("passive controller checkpoint signature rejected")
    if candidate["checkpoint_id"] != passive_controller_checkpoint_identity(candidate):
        raise PassiveControllerError("passive controller checkpoint identity mismatch")
    exact, expected_epoch = _expected_checkpoint_bindings(
        trusted_controller_key=trusted_controller_key,
        source_policy=source_policy,
        cohort_policy=cohort_policy,
        tenant_id=expected_tenant_id,
        platform_family=expected_platform_family,
        platform_instance_id=expected_platform_instance_id,
        boot_identity_digest=expected_boot_identity_digest,
    )
    if any(candidate[field] != value for field, value in exact.items()):
        raise PassiveControllerError("passive controller checkpoint binding mismatch")
    if candidate["source_epoch"] != expected_epoch:
        raise PassiveControllerError("passive controller source epoch mismatch")
    if candidate["next_capture_sequence"] != candidate["generation"] + 1:
        raise PassiveControllerError("passive controller capture sequence mismatch")
    if (candidate["generation"] == 0) != (
        candidate["previous_checkpoint_digest"] is None
    ):
        raise PassiveControllerError("passive controller checkpoint chain mismatch")
    parse_controller_time(
        candidate["capture_completed_at"],
        "checkpoint completion time",
    )
    passive_controller_checkpoint_cursors(
        candidate,
        source_policy=source_policy,
        source_epoch=expected_epoch,
    )
    return candidate
