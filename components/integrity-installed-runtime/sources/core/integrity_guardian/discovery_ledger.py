"""Portable Ledger inclusion evidence for Fog of War discovery snapshots."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from jsonschema import ValidationError

from .discovery import (
    discovery_index_snapshot_digest,
    verify_discovery_index_snapshot,
)
from .hashing import digest_object
from .ledger import (
    LedgerStore,
    LedgerVerificationError,
    build_ledger_event,
    event_digest,
    verify_ledger_event,
    verify_ledger_inclusion_proof,
)
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_signature

_INCLUSION_BOUNDARY = {
    "credentials": False,
    "execution_performed": False,
    "local_storage_read": True,
    "model_calls": 0,
    "network": False,
    "production_authority": False,
    "tool_calls": 0,
}


class DiscoveryLedgerError(ValueError):
    """Raised when snapshot-to-ledger inclusion cannot be proven exactly."""


def _inclusion_core(inclusion: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(inclusion))
    core.pop("inclusion_id", None)
    return core


def discovery_snapshot_inclusion_identity(
    inclusion: Mapping[str, Any],
) -> str:
    """Return the content identity of one portable inclusion package."""

    digest = digest_object(
        _inclusion_core(inclusion),
        domain="discovery-snapshot-inclusion-identity-v1",
    )
    return f"discovery-snapshot-inclusion:{digest.split(':', 1)[1]}"


def _checkpoint_digest(checkpoint: Mapping[str, Any]) -> str:
    return digest_object(
        dict(checkpoint),
        domain="discovery-snapshot-checkpoint-reference-v1",
    )


def _verify_checkpoint(
    checkpoint: Mapping[str, Any],
    trusted_key: TrustedKey,
    *,
    expected_tenant_id: str,
    expected_ledger_id: str,
) -> dict[str, Any]:
    try:
        candidate = deepcopy(dict(checkpoint))
        validate("checkpoint", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise DiscoveryLedgerError("discovery inclusion checkpoint schema is invalid") from exc
    if (
        candidate["signer_id"] != trusted_key.key_id
        or candidate["signature"]["key_id"] != trusted_key.key_id
        or not verify_signature(candidate, trusted_key.public_key)
    ):
        raise DiscoveryLedgerError("discovery inclusion checkpoint signature rejected")
    if candidate["tenant_id"] != expected_tenant_id:
        raise DiscoveryLedgerError("discovery inclusion checkpoint tenant mismatch")
    if candidate["ledger_id"] != expected_ledger_id:
        raise DiscoveryLedgerError("discovery inclusion checkpoint ledger mismatch")
    return candidate


def build_discovery_snapshot_ledger_event(
    snapshot: Mapping[str, Any],
    *,
    trusted_snapshot_key: TrustedKey,
    expected_snapshot_id: str,
    expected_tenant_id: str,
    ledger_source_id: str,
    source_sequence: int,
    previous_event_digest: str | None,
    ledger_signer: Ed25519Signer,
    recorded_at: str,
) -> dict[str, Any]:
    """Commit one exactly pinned signed snapshot digest to a Ledger source."""

    verified_snapshot = verify_discovery_index_snapshot(
        snapshot,
        trusted_snapshot_key,
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
    )
    return build_ledger_event(
        tenant_id=expected_tenant_id,
        source_id=ledger_source_id,
        source_sequence=source_sequence,
        event_type="discovery-index-snapshot",
        payload_digest=discovery_index_snapshot_digest(verified_snapshot),
        previous_event_digest=previous_event_digest,
        signer=ledger_signer,
        recorded_at=recorded_at,
    )


def verify_discovery_snapshot_inclusion(
    inclusion: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    *,
    trusted_snapshot_key: TrustedKey,
    trusted_ledger_event_key: TrustedKey,
    trusted_checkpoint_key: TrustedKey,
    expected_snapshot_id: str,
    expected_tenant_id: str,
    expected_ledger_id: str,
    expected_ledger_source_id: str,
    expected_checkpoint_id: str | None = None,
) -> dict[str, Any]:
    """Independently verify snapshot, event, Merkle path and checkpoint."""

    try:
        candidate = deepcopy(dict(inclusion))
        validate("discovery-snapshot-inclusion", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise DiscoveryLedgerError("discovery snapshot inclusion schema is invalid") from exc
    if candidate["inclusion_id"] != discovery_snapshot_inclusion_identity(candidate):
        raise DiscoveryLedgerError("discovery snapshot inclusion identity mismatch")
    if candidate["verification_boundary"] != _INCLUSION_BOUNDARY:
        raise DiscoveryLedgerError("discovery snapshot inclusion boundary mismatch")

    verified_snapshot = verify_discovery_index_snapshot(
        snapshot,
        trusted_snapshot_key,
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
    )
    snapshot_digest = discovery_index_snapshot_digest(verified_snapshot)
    expected_top_level = {
        "tenant_id": expected_tenant_id,
        "snapshot_id": expected_snapshot_id,
        "snapshot_digest": snapshot_digest,
        "ledger_id": expected_ledger_id,
        "ledger_source_id": expected_ledger_source_id,
    }
    for field, value in expected_top_level.items():
        if candidate[field] != value:
            raise DiscoveryLedgerError(f"discovery snapshot inclusion {field} mismatch")

    try:
        ledger_event = verify_ledger_event(
            candidate["ledger_event"],
            trusted_ledger_event_key,
            expected_tenant_id=expected_tenant_id,
            expected_source_id=expected_ledger_source_id,
            expected_event_type="discovery-index-snapshot",
            expected_payload_digest=snapshot_digest,
        )
    except LedgerVerificationError as exc:
        raise DiscoveryLedgerError("discovery inclusion ledger event rejected") from exc
    ledger_event_digest = event_digest(ledger_event)
    if (
        candidate["ledger_event_id"] != ledger_event["event_id"]
        or candidate["ledger_event_digest"] != ledger_event_digest
    ):
        raise DiscoveryLedgerError("discovery inclusion ledger event reference mismatch")

    checkpoint = _verify_checkpoint(
        candidate["checkpoint"],
        trusted_checkpoint_key,
        expected_tenant_id=expected_tenant_id,
        expected_ledger_id=expected_ledger_id,
    )
    if (
        candidate["checkpoint_id"] != checkpoint["checkpoint_id"]
        or candidate["checkpoint_digest"] != _checkpoint_digest(checkpoint)
    ):
        raise DiscoveryLedgerError("discovery inclusion checkpoint reference mismatch")
    if (
        expected_checkpoint_id is not None
        and checkpoint["checkpoint_id"] != expected_checkpoint_id
    ):
        raise DiscoveryLedgerError("discovery inclusion checkpoint pin mismatch")
    if checkpoint["last_event_digest"] != ledger_event_digest:
        raise DiscoveryLedgerError("discovery inclusion event is not the checkpoint tip")

    try:
        verify_ledger_inclusion_proof(
            candidate["proof"],
            expected_tenant_id=expected_tenant_id,
            expected_ledger_id=expected_ledger_id,
            expected_event_digest=ledger_event_digest,
            expected_root_digest=checkpoint["root_digest"],
            expected_tree_size=checkpoint["tree_size"],
        )
    except LedgerVerificationError as exc:
        raise DiscoveryLedgerError("discovery inclusion Merkle proof rejected") from exc
    return candidate


def build_discovery_snapshot_inclusion(
    snapshot: Mapping[str, Any],
    *,
    trusted_snapshot_key: TrustedKey,
    expected_snapshot_id: str,
    expected_tenant_id: str,
    ledger: LedgerStore,
    ledger_event: Mapping[str, Any],
    source_public_keys: dict[str, TrustedKey],
    checkpoint: Mapping[str, Any],
    trusted_checkpoint_key: TrustedKey,
) -> dict[str, Any]:
    """Build a portable proof only after full local Ledger verification."""

    if not isinstance(ledger, LedgerStore):
        raise DiscoveryLedgerError("discovery inclusion ledger store rejected")
    if ledger.tenant_id != expected_tenant_id:
        raise DiscoveryLedgerError("discovery inclusion ledger tenant mismatch")
    try:
        event_candidate = deepcopy(dict(ledger_event))
        checkpoint_candidate = deepcopy(dict(checkpoint))
        verification = ledger.verify(
            source_public_keys=source_public_keys,
            checkpoint=checkpoint_candidate,
            checkpoint_key=trusted_checkpoint_key,
        )
    except (TypeError, ValueError, LedgerVerificationError) as exc:
        raise DiscoveryLedgerError("discovery inclusion Ledger verification failed") from exc
    if not verification["ok"] or not verification["checkpoint_verified"]:
        raise DiscoveryLedgerError("discovery inclusion requires a verified checkpoint")

    source_id = event_candidate.get("source_id")
    trusted_event_key = source_public_keys.get(str(source_id))
    if trusted_event_key is None:
        raise DiscoveryLedgerError("discovery inclusion ledger source is untrusted")
    try:
        event_candidate = verify_ledger_event(
            event_candidate,
            trusted_event_key,
            expected_tenant_id=expected_tenant_id,
            expected_source_id=str(source_id),
            expected_event_type="discovery-index-snapshot",
        )
    except LedgerVerificationError as exc:
        raise DiscoveryLedgerError("discovery inclusion ledger event rejected") from exc
    event_digest_value = event_digest(event_candidate)
    try:
        proof = ledger.inclusion_proof(event_digest_value)
    except LedgerVerificationError as exc:
        raise DiscoveryLedgerError("discovery inclusion event is absent from Ledger") from exc

    snapshot_candidate = verify_discovery_index_snapshot(
        snapshot,
        trusted_snapshot_key,
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
    )
    snapshot_digest = discovery_index_snapshot_digest(snapshot_candidate)
    if event_candidate["payload_digest"] != snapshot_digest:
        raise DiscoveryLedgerError("discovery inclusion event payload mismatch")

    core: dict[str, Any] = {
        "protocol": "integrity-guardian/discovery-snapshot-inclusion/v1",
        "tenant_id": expected_tenant_id,
        "snapshot_id": expected_snapshot_id,
        "snapshot_digest": snapshot_digest,
        "ledger_id": ledger.ledger_id,
        "ledger_source_id": event_candidate["source_id"],
        "ledger_event_id": event_candidate["event_id"],
        "ledger_event_digest": event_digest_value,
        "ledger_event": event_candidate,
        "checkpoint_id": checkpoint_candidate["checkpoint_id"],
        "checkpoint_digest": _checkpoint_digest(checkpoint_candidate),
        "checkpoint": checkpoint_candidate,
        "proof": proof,
        "verification_boundary": deepcopy(_INCLUSION_BOUNDARY),
    }
    inclusion = {
        "inclusion_id": discovery_snapshot_inclusion_identity(core),
        **core,
    }
    return verify_discovery_snapshot_inclusion(
        inclusion,
        snapshot_candidate,
        trusted_snapshot_key=trusted_snapshot_key,
        trusted_ledger_event_key=trusted_event_key,
        trusted_checkpoint_key=trusted_checkpoint_key,
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
        expected_ledger_id=ledger.ledger_id,
        expected_ledger_source_id=event_candidate["source_id"],
        expected_checkpoint_id=checkpoint_candidate["checkpoint_id"],
    )
