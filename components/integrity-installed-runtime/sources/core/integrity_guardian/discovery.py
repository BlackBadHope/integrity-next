"""Signed, bounded discovery deltas for Integrity 5.0 Fog of War.

Discovery is evidence, never authority.  This module accepts no DECLARED
provenance, performs no collection, network access, adapter execution or model
invocation, and cannot create a production-capable Synapse edge.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Any

from jsonschema import ValidationError

from .discovery_admission import (
    DiscoveryAdmissionAction,
    DiscoveryAdmissionPolicy,
    discovery_semantic_identity,
    evaluate_discovery_admission,
)
from .hashing import digest_object
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)

MAX_DISCOVERY_BATCH_RECORDS = 1_000
MAX_DISCOVERY_ACTIVE_ASSERTIONS = 25_000
MAX_DISCOVERY_CHANGED_ZONES = 256
MAX_DISCOVERY_TRUSTED_SOURCE_EPOCHS = 1_000

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_TENANT_ID = re.compile(r"^tenant:[A-Za-z0-9][A-Za-z0-9._:/-]{0,248}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_DISCOVERY_BOUNDARY = {
    "credentials": False,
    "execution": False,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
}
_INDEX_BOUNDARY = {
    "execution_performed": False,
    "model_calls": 0,
    "network": False,
    "production_authority": False,
    "tool_calls": 0,
}


class DiscoveryError(ValueError):
    """Raised when discovery evidence violates its fail-closed contract."""


class DiscoveryAssertionKind(StrEnum):
    ENTITY = "entity"
    RELATION = "relation"
    GAP = "gap"


class DiscoveryChange(StrEnum):
    UPSERT = "upsert"
    DELETE = "delete"


class DiscoveryProvenance(StrEnum):
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    LEARNED = "LEARNED"
    PROPOSED = "PROPOSED"


class DiscoveryState(StrEnum):
    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"
    SENSOR_GAP = "sensor-gap"


class CoverageState(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    DENIED = "denied"
    UNKNOWN = "unknown"


class UnknownClass(StrEnum):
    UNKNOWN_ENTITY = "unknown-entity"
    UNKNOWN_RELATION = "unknown-relation"
    CONFLICTING_IDENTITY = "conflicting-identity"
    UNOBSERVED_ZONE = "unobserved-zone"
    UNSUPPORTED_PROTOCOL = "unsupported-protocol"
    DENIED_COVERAGE = "denied-coverage"
    STALE_SOURCE = "stale-source"
    AMBIGUOUS_OWNER = "ambiguous-owner"
    MODEL_GAP = "model-gap"


def _require_id(value: str, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise DiscoveryError(f"{field} rejected")
    return value


def _require_tenant_id(value: str) -> str:
    if not isinstance(value, str) or _TENANT_ID.fullmatch(value) is None:
        raise DiscoveryError("tenant_id rejected")
    return value


def _require_digest(value: str | None, field: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise DiscoveryError(f"{field} rejected")
    return value


def build_entity_assertion(*, entity_id: str, entity_type: str) -> dict[str, Any]:
    """Build a privacy-minimal entity assertion with no arbitrary metadata."""

    return {
        "kind": DiscoveryAssertionKind.ENTITY.value,
        "entity_id": _require_id(entity_id, "entity_id"),
        "entity_type": _require_id(entity_type, "entity_type"),
    }


def build_relation_assertion(
    *,
    relation_id: str,
    relation_type: str,
    from_entity_id: str,
    to_entity_id: str,
    from_zone_id: str,
    to_zone_id: str,
) -> dict[str, Any]:
    """Build one typed relation, including both invalidation zones."""

    return {
        "kind": DiscoveryAssertionKind.RELATION.value,
        "relation_id": _require_id(relation_id, "relation_id"),
        "relation_type": _require_id(relation_type, "relation_type"),
        "from_entity_id": _require_id(from_entity_id, "from_entity_id"),
        "to_entity_id": _require_id(to_entity_id, "to_entity_id"),
        "from_zone_id": _require_id(from_zone_id, "from_zone_id"),
        "to_zone_id": _require_id(to_zone_id, "to_zone_id"),
    }


def build_gap_assertion(
    *,
    gap_id: str,
    classification: UnknownClass,
    subject_id: str | None = None,
) -> dict[str, Any]:
    """Build an explicit unknown instead of inventing topology."""

    if not isinstance(classification, UnknownClass):
        raise DiscoveryError("unknown classification rejected")
    if subject_id is not None:
        _require_id(subject_id, "subject_id")
    return {
        "kind": DiscoveryAssertionKind.GAP.value,
        "gap_id": _require_id(gap_id, "gap_id"),
        "classification": classification.value,
        "subject_id": subject_id,
    }


def _assertion_identity(assertion: Mapping[str, Any]) -> str:
    try:
        kind = assertion["kind"]
        field = {
            DiscoveryAssertionKind.ENTITY.value: "entity_id",
            DiscoveryAssertionKind.RELATION.value: "relation_id",
            DiscoveryAssertionKind.GAP.value: "gap_id",
        }[kind]
        return str(assertion[field])
    except (KeyError, TypeError) as exc:
        raise DiscoveryError("discovery assertion identity rejected") from exc


def _record_core(record: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(record))
    core.pop("record_id", None)
    core.pop("signature", None)
    return core


def discovery_record_identity(record: Mapping[str, Any]) -> str:
    """Return the content identity of one unsigned discovery statement."""

    digest = digest_object(_record_core(record), domain="discovery-record-identity-v1")
    return f"discovery-record:{digest.split(':', 1)[1]}"


def discovery_record_digest(record: Mapping[str, Any]) -> str:
    """Return the source-chain digest of one signed record."""

    return digest_object(dict(record), domain="discovery-record-chain-v1")


@dataclass(frozen=True)
class DiscoveryCursor:
    """Externally persistable source-chain continuation state."""

    source_id: str
    source_epoch: str
    next_sequence: int = 0
    previous_record_digest: str | None = None

    def __post_init__(self) -> None:
        _require_id(self.source_id, "source_id")
        _require_id(self.source_epoch, "source_epoch")
        if (
            not isinstance(self.next_sequence, int)
            or isinstance(self.next_sequence, bool)
            or self.next_sequence < 0
        ):
            raise DiscoveryError("next_sequence rejected")
        _require_digest(
            self.previous_record_digest,
            "previous_record_digest",
            nullable=True,
        )
        if (self.next_sequence == 0) != (self.previous_record_digest is None):
            raise DiscoveryError("discovery cursor continuity rejected")

    def to_document(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_epoch": self.source_epoch,
            "next_sequence": self.next_sequence,
            "previous_record_digest": self.previous_record_digest,
        }

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> DiscoveryCursor:
        if not isinstance(document, Mapping) or set(document) != {
            "source_id",
            "source_epoch",
            "next_sequence",
            "previous_record_digest",
        }:
            raise DiscoveryError("discovery cursor field set rejected")
        return cls(
            source_id=document["source_id"],
            source_epoch=document["source_epoch"],
            next_sequence=document["next_sequence"],
            previous_record_digest=document["previous_record_digest"],
        )


@dataclass(frozen=True)
class TrustedDiscoverySource:
    """Out-of-band binding of source, epoch, key and exact collector artifact."""

    source_id: str
    source_epoch: str
    source_artifact_digest: str
    trusted_key: TrustedKey

    def __post_init__(self) -> None:
        _require_id(self.source_id, "source_id")
        _require_id(self.source_epoch, "source_epoch")
        _require_digest(self.source_artifact_digest, "source_artifact_digest")
        if not isinstance(self.trusted_key, TrustedKey):
            raise DiscoveryError("trusted discovery key rejected")


class DiscoveryEmitter:
    """Create a signed source chain from already sanitized assertions."""

    def __init__(
        self,
        *,
        tenant_id: str,
        cursor: DiscoveryCursor,
        signer: Ed25519Signer,
    ) -> None:
        self.tenant_id = _require_tenant_id(tenant_id)
        self.signer = signer
        self._cursor = cursor

    @property
    def cursor(self) -> DiscoveryCursor:
        return self._cursor

    def emit(
        self,
        *,
        assertion: Mapping[str, Any],
        observed_at: str,
        zone_id: str,
        source_artifact_digest: str,
        coverage_digest: str,
        change: DiscoveryChange = DiscoveryChange.UPSERT,
        provenance: DiscoveryProvenance = DiscoveryProvenance.OBSERVED,
        state: DiscoveryState = DiscoveryState.PRESENT,
        coverage: CoverageState = CoverageState.PARTIAL,
        confidence_ppm: int = 0,
        content_digest: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(change, DiscoveryChange):
            raise DiscoveryError("discovery change rejected")
        if not isinstance(provenance, DiscoveryProvenance):
            raise DiscoveryError("discovery provenance rejected")
        if not isinstance(state, DiscoveryState):
            raise DiscoveryError("discovery state rejected")
        if not isinstance(coverage, CoverageState):
            raise DiscoveryError("coverage state rejected")
        if (
            not isinstance(confidence_ppm, int)
            or isinstance(confidence_ppm, bool)
            or not 0 <= confidence_ppm <= 1_000_000
        ):
            raise DiscoveryError("confidence_ppm rejected")
        _require_id(zone_id, "zone_id")
        _require_digest(source_artifact_digest, "source_artifact_digest")
        _require_digest(coverage_digest, "coverage_digest")
        _require_digest(content_digest, "content_digest", nullable=True)

        core: dict[str, Any] = {
            "protocol": "integrity-guardian/discovery-record/v1",
            "tenant_id": self.tenant_id,
            "source_id": self._cursor.source_id,
            "source_epoch": self._cursor.source_epoch,
            "sequence": self._cursor.next_sequence,
            "observed_at": observed_at,
            "zone_id": zone_id,
            "change": change.value,
            "assertion": deepcopy(dict(assertion)),
            "evidence": {
                "state": state.value,
                "provenance": provenance.value,
                "confidence_ppm": confidence_ppm,
                "content_digest": content_digest,
                "source_artifact_digest": source_artifact_digest,
                "coverage": {
                    "state": coverage.value,
                    "scope_digest": coverage_digest,
                },
            },
            "previous_record_digest": self._cursor.previous_record_digest,
            "collector_boundary": deepcopy(_DISCOVERY_BOUNDARY),
        }
        unsigned = {
            "record_id": discovery_record_identity(core),
            **core,
        }
        signed = self.signer.sign(unsigned)
        verify_discovery_record(
            signed,
            TrustedKey(key_id=self.signer.key_id, public_key=self.signer.public_key),
            expected_tenant_id=self.tenant_id,
            expected_source_id=self._cursor.source_id,
            expected_source_epoch=self._cursor.source_epoch,
        )
        self._cursor = DiscoveryCursor(
            source_id=self._cursor.source_id,
            source_epoch=self._cursor.source_epoch,
            next_sequence=self._cursor.next_sequence + 1,
            previous_record_digest=discovery_record_digest(signed),
        )
        return signed


def verify_discovery_record(
    record: Mapping[str, Any],
    trusted_key: TrustedKey,
    *,
    expected_tenant_id: str | None = None,
    expected_source_id: str | None = None,
    expected_source_epoch: str | None = None,
    expected_source_artifact_digest: str | None = None,
) -> dict[str, Any]:
    """Verify schema, identity, signature and non-authoritative semantics."""

    try:
        candidate = deepcopy(dict(record))
        validate("discovery-record", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise DiscoveryError("discovery record schema is invalid") from exc
    if candidate["collector_boundary"] != _DISCOVERY_BOUNDARY:
        raise DiscoveryError("discovery collector boundary mismatch")
    if candidate["record_id"] != discovery_record_identity(candidate):
        raise DiscoveryError("discovery record identity mismatch")
    if (
        candidate["signature"]["key_id"] != trusted_key.key_id
        or not verify_signature(candidate, trusted_key.public_key)
    ):
        raise DiscoveryError("discovery record signature rejected")
    if expected_tenant_id is not None and candidate["tenant_id"] != expected_tenant_id:
        raise DiscoveryError("cross-tenant discovery record rejected")
    if expected_source_id is not None and candidate["source_id"] != expected_source_id:
        raise DiscoveryError("discovery source identity mismatch")
    if (
        expected_source_epoch is not None
        and candidate["source_epoch"] != expected_source_epoch
    ):
        raise DiscoveryError("discovery source epoch mismatch")
    if (
        expected_source_artifact_digest is not None
        and candidate["evidence"]["source_artifact_digest"]
        != expected_source_artifact_digest
    ):
        raise DiscoveryError("discovery source artifact mismatch")

    assertion = candidate["assertion"]
    kind = assertion["kind"]
    change = candidate["change"]
    state = candidate["evidence"]["state"]
    content_digest = candidate["evidence"]["content_digest"]
    _assertion_identity(assertion)

    if change == DiscoveryChange.DELETE.value:
        if state != DiscoveryState.ABSENT.value or content_digest is not None:
            raise DiscoveryError("discovery deletion must be an empty tombstone")
    elif kind == DiscoveryAssertionKind.GAP.value:
        if state not in {
            DiscoveryState.UNKNOWN.value,
            DiscoveryState.SENSOR_GAP.value,
        } or content_digest is not None:
            raise DiscoveryError("discovery gap evidence rejected")
    elif state != DiscoveryState.PRESENT.value:
        raise DiscoveryError("discovery assertion must be present")
    return candidate


def _record_zones(record: Mapping[str, Any]) -> set[str]:
    zones = {str(record["zone_id"])}
    assertion = record["assertion"]
    if assertion["kind"] == DiscoveryAssertionKind.RELATION.value:
        zones.add(str(assertion["from_zone_id"]))
        zones.add(str(assertion["to_zone_id"]))
    return zones


def _active_key(record: Mapping[str, Any]) -> tuple[str, str, str]:
    assertion = record["assertion"]
    return (
        str(record["source_id"]),
        str(assertion["kind"]),
        _assertion_identity(assertion),
    )


def _receipt_core(receipt: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(receipt))
    core.pop("receipt_id", None)
    core.pop("signature", None)
    return core


def discovery_delta_receipt_identity(receipt: Mapping[str, Any]) -> str:
    digest = digest_object(
        _receipt_core(receipt),
        domain="discovery-delta-receipt-identity-v1",
    )
    return f"discovery-delta-receipt:{digest.split(':', 1)[1]}"


def verify_discovery_delta_receipt(
    receipt: Mapping[str, Any],
    trusted_key: TrustedKey,
    *,
    expected_tenant_id: str | None = None,
) -> dict[str, Any]:
    """Verify one signed, canonical delta-application receipt."""

    try:
        candidate = deepcopy(dict(receipt))
        validate("discovery-delta-receipt", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise DiscoveryError("discovery delta receipt schema is invalid") from exc
    if candidate["receipt_id"] != discovery_delta_receipt_identity(candidate):
        raise DiscoveryError("discovery delta receipt identity mismatch")
    if (
        candidate["signature"]["key_id"] != trusted_key.key_id
        or not verify_signature(candidate, trusted_key.public_key)
    ):
        raise DiscoveryError("discovery delta receipt signature rejected")
    if expected_tenant_id is not None and candidate["tenant_id"] != expected_tenant_id:
        raise DiscoveryError("cross-tenant discovery delta receipt rejected")
    if candidate["index_boundary"] != _INDEX_BOUNDARY:
        raise DiscoveryError("discovery delta index boundary mismatch")
    if candidate["changed_zone_ids"] != sorted(set(candidate["changed_zone_ids"])):
        raise DiscoveryError("discovery changed zones are not canonical")
    if candidate["cross_zone_relation_ids"] != sorted(
        set(candidate["cross_zone_relation_ids"])
    ):
        raise DiscoveryError("cross-zone relation ids are not canonical")
    if candidate["source_tips"] != sorted(
        candidate["source_tips"],
        key=lambda tip: (tip["source_id"], tip["source_epoch"]),
    ):
        raise DiscoveryError("discovery source tips are not canonical")
    counted = sum(
        candidate[field]
        for field in (
            "inserted_count",
            "updated_count",
            "deleted_count",
            "no_op_count",
        )
    )
    if candidate["accepted_count"] != counted:
        raise DiscoveryError("discovery delta receipt counts disagree")
    return candidate


def _snapshot_core(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(snapshot))
    core.pop("snapshot_id", None)
    core.pop("signature", None)
    return core


def discovery_index_snapshot_identity(snapshot: Mapping[str, Any]) -> str:
    """Return the content identity of one discovery index checkpoint."""

    digest = digest_object(
        _snapshot_core(snapshot),
        domain="discovery-index-snapshot-identity-v1",
    )
    return f"discovery-index-snapshot:{digest.split(':', 1)[1]}"


def discovery_index_snapshot_digest(snapshot: Mapping[str, Any]) -> str:
    """Return the signed checkpoint digest used by the snapshot chain."""

    return digest_object(
        dict(snapshot),
        domain="discovery-index-snapshot-chain-v1",
    )


def _trusted_source_document(source: TrustedDiscoverySource) -> dict[str, Any]:
    return {
        "source_id": source.source_id,
        "source_epoch": source.source_epoch,
        "source_artifact_digest": source.source_artifact_digest,
        "key_id": source.trusted_key.key_id,
        "public_key_fingerprint": public_key_fingerprint(
            source.trusted_key.public_key
        ),
    }


def verify_discovery_index_snapshot(
    snapshot: Mapping[str, Any],
    trusted_key: TrustedKey,
    *,
    expected_snapshot_id: str | None = None,
    expected_tenant_id: str | None = None,
) -> dict[str, Any]:
    """Verify a signed, canonical discovery index checkpoint.

    Exact source-key verification is completed by ``ZonedDiscoveryIndex.restore``
    because public source keys deliberately do not travel inside the checkpoint.
    """

    try:
        candidate = deepcopy(dict(snapshot))
        validate("discovery-index-snapshot", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise DiscoveryError("discovery index snapshot schema is invalid") from exc
    if candidate["snapshot_id"] != discovery_index_snapshot_identity(candidate):
        raise DiscoveryError("discovery index snapshot identity mismatch")
    if (
        candidate["signature"]["key_id"] != trusted_key.key_id
        or not verify_signature(candidate, trusted_key.public_key)
    ):
        raise DiscoveryError("discovery index snapshot signature rejected")
    if (
        expected_snapshot_id is not None
        and candidate["snapshot_id"] != expected_snapshot_id
    ):
        raise DiscoveryError("discovery index snapshot pin mismatch")
    if expected_tenant_id is not None and candidate["tenant_id"] != expected_tenant_id:
        raise DiscoveryError("cross-tenant discovery index snapshot rejected")
    if candidate["index_boundary"] != _INDEX_BOUNDARY:
        raise DiscoveryError("discovery index snapshot boundary mismatch")
    if (candidate["snapshot_sequence"] == 0) != (
        candidate["previous_snapshot_digest"] is None
    ):
        raise DiscoveryError("discovery index snapshot chain continuity rejected")

    trusted_sources = candidate["trusted_sources"]
    if trusted_sources != sorted(
        trusted_sources,
        key=lambda source: (source["source_id"], source["source_epoch"]),
    ):
        raise DiscoveryError("discovery snapshot source bindings are not canonical")
    source_bindings: dict[tuple[str, str], dict[str, Any]] = {}
    for binding in trusted_sources:
        source_key = (binding["source_id"], binding["source_epoch"])
        if source_key in source_bindings:
            raise DiscoveryError("duplicate discovery snapshot source binding")
        source_bindings[source_key] = binding

    source_tips = candidate["source_tips"]
    if source_tips != sorted(
        source_tips,
        key=lambda tip: (tip["source_id"], tip["source_epoch"]),
    ):
        raise DiscoveryError("discovery snapshot source tips are not canonical")
    tips_by_source: dict[tuple[str, str], dict[str, Any]] = {}
    for tip in source_tips:
        source_key = (tip["source_id"], tip["source_epoch"])
        if source_key in tips_by_source:
            raise DiscoveryError("duplicate discovery snapshot source tip")
        binding = source_bindings.get(source_key)
        if binding is None:
            raise DiscoveryError("unbound discovery snapshot source tip")
        if tip["source_artifact_digest"] != binding["source_artifact_digest"]:
            raise DiscoveryError("discovery snapshot source artifact mismatch")
        tip_record = tip["record"]
        try:
            validate("discovery-record", tip_record)
        except (TypeError, KeyError, ValueError, ValidationError) as exc:
            raise DiscoveryError("discovery snapshot tip record schema is invalid") from exc
        if (
            tip_record["tenant_id"] != candidate["tenant_id"]
            or (tip_record["source_id"], tip_record["source_epoch"]) != source_key
            or tip_record["sequence"] != tip["sequence"]
            or tip_record["evidence"]["source_artifact_digest"]
            != tip["source_artifact_digest"]
            or discovery_record_digest(tip_record) != tip["record_digest"]
        ):
            raise DiscoveryError("discovery snapshot tip record mismatch")
        tips_by_source[source_key] = tip

    active_records = candidate["active_records"]
    try:
        active_keys = [_active_key(record) for record in active_records]
    except (KeyError, TypeError, DiscoveryError) as exc:
        raise DiscoveryError("discovery snapshot active record rejected") from exc
    if active_keys != sorted(active_keys):
        raise DiscoveryError("discovery snapshot active records are not canonical")
    if len(set(active_keys)) != len(active_keys):
        raise DiscoveryError("duplicate discovery snapshot active assertion")

    for record in active_records:
        try:
            validate("discovery-record", record)
        except (TypeError, KeyError, ValueError, ValidationError) as exc:
            raise DiscoveryError("discovery snapshot active record schema is invalid") from exc
        if record["tenant_id"] != candidate["tenant_id"]:
            raise DiscoveryError("cross-tenant discovery snapshot record rejected")
        if record["change"] != DiscoveryChange.UPSERT.value:
            raise DiscoveryError("discovery snapshot contains a tombstone")
        source_key = (record["source_id"], record["source_epoch"])
        binding = source_bindings.get(source_key)
        tip = tips_by_source.get(source_key)
        if binding is None or tip is None:
            raise DiscoveryError("unbound discovery snapshot active record")
        if (
            record["evidence"]["source_artifact_digest"]
            != binding["source_artifact_digest"]
        ):
            raise DiscoveryError("discovery snapshot active artifact mismatch")
        if record["sequence"] > tip["sequence"]:
            raise DiscoveryError("discovery snapshot active record exceeds source tip")
        if (
            record["sequence"] == tip["sequence"]
            and discovery_record_digest(record) != tip["record_digest"]
        ):
            raise DiscoveryError("discovery snapshot source tip digest mismatch")

    expected_state_digest = digest_object(
        active_records,
        domain="discovery-active-state-v1",
    )
    if candidate["active_state_digest"] != expected_state_digest:
        raise DiscoveryError("discovery snapshot active state digest mismatch")
    return candidate


def verify_discovery_index_snapshot_sources(
    snapshot: Mapping[str, Any],
    trusted_snapshot_key: TrustedKey,
    *,
    trusted_sources: Sequence[TrustedDiscoverySource],
    expected_snapshot_id: str,
    expected_tenant_id: str,
) -> dict[str, Any]:
    """Verify a checkpoint against the complete out-of-band source trust set."""

    candidate = verify_discovery_index_snapshot(
        snapshot,
        trusted_snapshot_key,
        expected_snapshot_id=expected_snapshot_id,
        expected_tenant_id=expected_tenant_id,
    )
    if (
        not isinstance(trusted_sources, Sequence)
        or isinstance(trusted_sources, (str, bytes))
        or len(trusted_sources) > MAX_DISCOVERY_TRUSTED_SOURCE_EPOCHS
    ):
        raise DiscoveryError("trusted discovery source count rejected")

    trusted_by_source: dict[tuple[str, str], TrustedDiscoverySource] = {}
    for source in trusted_sources:
        if not isinstance(source, TrustedDiscoverySource):
            raise DiscoveryError("trusted discovery source rejected")
        source_key = (source.source_id, source.source_epoch)
        if source_key in trusted_by_source:
            raise DiscoveryError("duplicate trusted discovery source epoch")
        trusted_by_source[source_key] = source
    expected_bindings = [
        _trusted_source_document(trusted_by_source[source_key])
        for source_key in sorted(trusted_by_source)
    ]
    if candidate["trusted_sources"] != expected_bindings:
        raise DiscoveryError("discovery snapshot trust configuration mismatch")

    for tip in candidate["source_tips"]:
        source_key = (tip["source_id"], tip["source_epoch"])
        trusted_source = trusted_by_source[source_key]
        verify_discovery_record(
            tip["record"],
            trusted_source.trusted_key,
            expected_tenant_id=expected_tenant_id,
            expected_source_id=source_key[0],
            expected_source_epoch=source_key[1],
            expected_source_artifact_digest=(
                trusted_source.source_artifact_digest
            ),
        )
    for record in candidate["active_records"]:
        source_key = (record["source_id"], record["source_epoch"])
        trusted_source = trusted_by_source[source_key]
        verify_discovery_record(
            record,
            trusted_source.trusted_key,
            expected_tenant_id=expected_tenant_id,
            expected_source_id=source_key[0],
            expected_source_epoch=source_key[1],
            expected_source_artifact_digest=(
                trusted_source.source_artifact_digest
            ),
        )
    return candidate


class ZonedDiscoveryIndex:
    """Atomically apply signed source deltas and return bounded invalidation."""

    def __init__(
        self,
        *,
        tenant_id: str,
        trusted_sources: Sequence[TrustedDiscoverySource],
        receipt_signer: Ed25519Signer,
        admission_policy: DiscoveryAdmissionPolicy | None = None,
    ) -> None:
        self.tenant_id = _require_tenant_id(tenant_id)
        self.receipt_signer = receipt_signer
        if admission_policy is not None and not isinstance(
            admission_policy,
            DiscoveryAdmissionPolicy,
        ):
            raise DiscoveryError("discovery admission policy rejected")
        self._admission_policy = admission_policy
        self._last_admission_decisions: list[dict[str, Any]] = []
        if (
            not isinstance(trusted_sources, Sequence)
            or isinstance(trusted_sources, (str, bytes))
            or len(trusted_sources) > MAX_DISCOVERY_TRUSTED_SOURCE_EPOCHS
        ):
            raise DiscoveryError("trusted discovery source count rejected")
        self._trusted_sources: dict[
            tuple[str, str],
            TrustedDiscoverySource,
        ] = {}
        for source in trusted_sources:
            if not isinstance(source, TrustedDiscoverySource):
                raise DiscoveryError("trusted discovery source rejected")
            key = (source.source_id, source.source_epoch)
            if key in self._trusted_sources:
                raise DiscoveryError("duplicate trusted discovery source epoch")
            self._trusted_sources[key] = source
        self._source_tips: dict[tuple[str, str], tuple[int, str]] = {}
        self._source_tip_records: dict[
            tuple[str, str],
            dict[str, Any],
        ] = {}
        self._active: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._admission_semantic_history: dict[
            tuple[str, str, str],
            str,
        ] = {}
        self._next_snapshot_sequence = 0
        self._previous_snapshot_digest: str | None = None
        self._lock = RLock()

    def active_records(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                deepcopy(self._active[key])
                for key in sorted(self._active)
            ]

    @property
    def admission_policy_digest(self) -> str | None:
        return (
            None
            if self._admission_policy is None
            else self._admission_policy.digest
        )

    def last_admission_decisions(self) -> list[dict[str, Any]]:
        with self._lock:
            return deepcopy(self._last_admission_decisions)

    def apply(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        review_priority: int = 0,
    ) -> dict[str, Any]:
        if (
            not isinstance(records, Sequence)
            or isinstance(records, (str, bytes))
            or not 1 <= len(records) <= MAX_DISCOVERY_BATCH_RECORDS
        ):
            raise DiscoveryError("discovery delta batch size rejected")

        with self._lock:
            staged_tips = dict(self._source_tips)
            staged_tip_records = deepcopy(self._source_tip_records)
            staged_active = deepcopy(self._active)
            staged_semantic_history = dict(
                self._admission_semantic_history
            )
            accepted: list[dict[str, Any]] = []
            touched_sources: set[tuple[str, str]] = set()
            changed_zones: set[str] = set()
            cross_zone_relation_ids: set[str] = set()
            inserted = updated = deleted = no_op = 0
            admission_decisions: list[dict[str, Any]] = []

            for raw_record in records:
                try:
                    source_key = (
                        str(raw_record["source_id"]),
                        str(raw_record["source_epoch"]),
                    )
                except (KeyError, TypeError) as exc:
                    raise DiscoveryError("discovery source epoch cannot be read") from exc
                trusted_source = self._trusted_sources.get(source_key)
                if trusted_source is None:
                    raise DiscoveryError("untrusted discovery source epoch rejected")
                record = verify_discovery_record(
                    raw_record,
                    trusted_source.trusted_key,
                    expected_tenant_id=self.tenant_id,
                    expected_source_id=source_key[0],
                    expected_source_epoch=source_key[1],
                    expected_source_artifact_digest=(
                        trusted_source.source_artifact_digest
                    ),
                )

                previous_tip = staged_tips.get(source_key)
                expected_sequence = 0 if previous_tip is None else previous_tip[0] + 1
                expected_digest = None if previous_tip is None else previous_tip[1]
                if record["sequence"] < expected_sequence:
                    raise DiscoveryError("discovery record replay rejected")
                if record["sequence"] > expected_sequence:
                    raise DiscoveryError("discovery source sequence discontinuity")
                if record["previous_record_digest"] != expected_digest:
                    raise DiscoveryError("discovery source chain discontinuity")

                key = _active_key(record)
                old = staged_active.get(key)
                record_digest = discovery_record_digest(record)
                staged_tips[source_key] = (record["sequence"], record_digest)
                staged_tip_records[source_key] = record
                touched_sources.add(source_key)
                if self._admission_policy is not None:
                    decision = evaluate_discovery_admission(
                        policy=self._admission_policy,
                        candidate=record,
                        current=old,
                        historical_semantic_identity=(
                            staged_semantic_history.get(key)
                        ),
                        review_priority=review_priority,
                    )
                    admission_decisions.append(decision.document())
                    if decision.action is DiscoveryAdmissionAction.QUARANTINE:
                        self._source_tips = staged_tips
                        self._source_tip_records = staged_tip_records
                        self._admission_semantic_history = (
                            staged_semantic_history
                        )
                        self._last_admission_decisions = admission_decisions
                        raise DiscoveryError(
                            f"discovery admission quarantined: {decision.reason}"
                        )
                    if decision.semantic_identity is not None:
                        staged_semantic_history[key] = (
                            decision.semantic_identity
                        )
                if old is not None:
                    changed_zones.update(_record_zones(old))
                    old_assertion = old["assertion"]
                    if (
                        old_assertion["kind"] == DiscoveryAssertionKind.RELATION.value
                        and old_assertion["from_zone_id"] != old_assertion["to_zone_id"]
                    ):
                        cross_zone_relation_ids.add(old_assertion["relation_id"])
                changed_zones.update(_record_zones(record))
                assertion = record["assertion"]
                if (
                    assertion["kind"] == DiscoveryAssertionKind.RELATION.value
                    and assertion["from_zone_id"] != assertion["to_zone_id"]
                ):
                    cross_zone_relation_ids.add(assertion["relation_id"])

                if record["change"] == DiscoveryChange.DELETE.value:
                    if old is None:
                        no_op += 1
                    else:
                        del staged_active[key]
                        deleted += 1
                else:
                    staged_active[key] = record
                    if old is None:
                        inserted += 1
                    else:
                        updated += 1

                accepted.append(record)

            if len(staged_active) > MAX_DISCOVERY_ACTIVE_ASSERTIONS:
                raise DiscoveryError("discovery active assertion limit exceeded")
            if (
                len(staged_semantic_history)
                > MAX_DISCOVERY_ACTIVE_ASSERTIONS
            ):
                raise DiscoveryError(
                    "discovery semantic history limit exceeded"
                )
            if len(changed_zones) > MAX_DISCOVERY_CHANGED_ZONES:
                raise DiscoveryError("discovery changed zone limit exceeded")

            source_tips = [
                {
                    "source_id": source_id,
                    "source_epoch": source_epoch,
                    "sequence": staged_tips[(source_id, source_epoch)][0],
                    "record_digest": staged_tips[(source_id, source_epoch)][1],
                    "source_artifact_digest": self._trusted_sources[
                        (source_id, source_epoch)
                    ].source_artifact_digest,
                }
                for source_id, source_epoch in sorted(touched_sources)
            ]
            core: dict[str, Any] = {
                "protocol": "integrity-guardian/discovery-delta-receipt/v1",
                "tenant_id": self.tenant_id,
                "batch_digest": digest_object(
                    accepted,
                    domain="discovery-delta-batch-v1",
                ),
                "accepted_count": len(accepted),
                "inserted_count": inserted,
                "updated_count": updated,
                "deleted_count": deleted,
                "no_op_count": no_op,
                "active_assertion_count": len(staged_active),
                "changed_zone_ids": sorted(changed_zones),
                "cross_zone_relation_ids": sorted(cross_zone_relation_ids),
                "source_tips": source_tips,
                "index_boundary": deepcopy(_INDEX_BOUNDARY),
            }
            unsigned = {
                "receipt_id": discovery_delta_receipt_identity(core),
                **core,
            }
            receipt = self.receipt_signer.sign(unsigned)
            verify_discovery_delta_receipt(
                receipt,
                TrustedKey(
                    key_id=self.receipt_signer.key_id,
                    public_key=self.receipt_signer.public_key,
                ),
                expected_tenant_id=self.tenant_id,
            )

            self._source_tips = staged_tips
            self._source_tip_records = staged_tip_records
            self._active = staged_active
            self._admission_semantic_history = staged_semantic_history
            self._last_admission_decisions = admission_decisions
            return receipt

    def export_snapshot(self, *, created_at: str) -> dict[str, Any]:
        """Export and chain one signed, self-contained index checkpoint."""

        with self._lock:
            active_records = self.active_records()
            trusted_sources = [
                _trusted_source_document(self._trusted_sources[source_key])
                for source_key in sorted(self._trusted_sources)
            ]
            source_tips = [
                {
                    "source_id": source_id,
                    "source_epoch": source_epoch,
                    "sequence": sequence,
                    "record_digest": record_digest,
                    "source_artifact_digest": self._trusted_sources[
                        (source_id, source_epoch)
                    ].source_artifact_digest,
                    "record": deepcopy(
                        self._source_tip_records[(source_id, source_epoch)]
                    ),
                }
                for (source_id, source_epoch), (sequence, record_digest) in sorted(
                    self._source_tips.items()
                )
            ]
            core: dict[str, Any] = {
                "protocol": "integrity-guardian/discovery-index-snapshot/v1",
                "tenant_id": self.tenant_id,
                "created_at": created_at,
                "snapshot_sequence": self._next_snapshot_sequence,
                "previous_snapshot_digest": self._previous_snapshot_digest,
                "active_state_digest": digest_object(
                    active_records,
                    domain="discovery-active-state-v1",
                ),
                "trusted_sources": trusted_sources,
                "source_tips": source_tips,
                "active_records": active_records,
                "index_boundary": deepcopy(_INDEX_BOUNDARY),
            }
            if self._admission_policy is not None:
                core["admission_state"] = {
                    "policy_digest": self._admission_policy.digest,
                    "semantic_history": [
                        {
                            "source_id": source_id,
                            "assertion_kind": assertion_kind,
                            "assertion_id": assertion_id,
                            "semantic_identity": semantic_identity,
                        }
                        for (
                            source_id,
                            assertion_kind,
                            assertion_id,
                        ), semantic_identity in sorted(
                            self._admission_semantic_history.items()
                        )
                    ],
                }
            unsigned = {
                "snapshot_id": discovery_index_snapshot_identity(core),
                **core,
            }
            snapshot = self.receipt_signer.sign(unsigned)
            verify_discovery_index_snapshot(
                snapshot,
                TrustedKey(
                    key_id=self.receipt_signer.key_id,
                    public_key=self.receipt_signer.public_key,
                ),
                expected_tenant_id=self.tenant_id,
            )
            self._next_snapshot_sequence += 1
            self._previous_snapshot_digest = discovery_index_snapshot_digest(snapshot)
            return snapshot

    @classmethod
    def restore(
        cls,
        snapshot: Mapping[str, Any],
        *,
        expected_snapshot_id: str,
        expected_tenant_id: str,
        trusted_snapshot_key: TrustedKey,
        trusted_sources: Sequence[TrustedDiscoverySource],
        receipt_signer: Ed25519Signer,
        admission_policy: DiscoveryAdmissionPolicy | None = None,
        expected_admission_policy_digest: str | None = None,
    ) -> ZonedDiscoveryIndex:
        """Restore only an exactly pinned checkpoint and exact out-of-band trust."""

        if (admission_policy is None) != (
            expected_admission_policy_digest is None
        ):
            raise DiscoveryError(
                "discovery restore admission policy and digest must be supplied together"
            )
        if admission_policy is not None:
            _require_digest(
                expected_admission_policy_digest,
                "expected_admission_policy_digest",
            )
            if admission_policy.digest != expected_admission_policy_digest:
                raise DiscoveryError("discovery restore admission policy pin mismatch")
        candidate = verify_discovery_index_snapshot_sources(
            snapshot,
            trusted_snapshot_key,
            trusted_sources=trusted_sources,
            expected_snapshot_id=expected_snapshot_id,
            expected_tenant_id=expected_tenant_id,
        )
        if (
            receipt_signer.key_id != trusted_snapshot_key.key_id
            or public_key_fingerprint(receipt_signer.public_key)
            != public_key_fingerprint(trusted_snapshot_key.public_key)
        ):
            raise DiscoveryError("discovery snapshot continuation signer mismatch")

        restored = cls(
            tenant_id=expected_tenant_id,
            trusted_sources=trusted_sources,
            receipt_signer=receipt_signer,
            admission_policy=admission_policy,
        )
        verified_active: dict[tuple[str, str, str], dict[str, Any]] = {}
        verified_tip_records: dict[tuple[str, str], dict[str, Any]] = {}
        for tip in candidate["source_tips"]:
            source_key = (tip["source_id"], tip["source_epoch"])
            trusted_source = restored._trusted_sources[source_key]
            verified_tip_records[source_key] = verify_discovery_record(
                tip["record"],
                trusted_source.trusted_key,
                expected_tenant_id=expected_tenant_id,
                expected_source_id=source_key[0],
                expected_source_epoch=source_key[1],
                expected_source_artifact_digest=(
                    trusted_source.source_artifact_digest
                ),
            )
        for raw_record in candidate["active_records"]:
            source_key = (raw_record["source_id"], raw_record["source_epoch"])
            trusted_source = restored._trusted_sources[source_key]
            record = verify_discovery_record(
                raw_record,
                trusted_source.trusted_key,
                expected_tenant_id=expected_tenant_id,
                expected_source_id=source_key[0],
                expected_source_epoch=source_key[1],
                expected_source_artifact_digest=(
                    trusted_source.source_artifact_digest
                ),
            )
            verified_active[_active_key(record)] = record

        restored._source_tips = {
            (tip["source_id"], tip["source_epoch"]): (
                tip["sequence"],
                tip["record_digest"],
            )
            for tip in candidate["source_tips"]
        }
        restored._source_tip_records = verified_tip_records
        restored._active = verified_active
        admission_state = candidate.get("admission_state")
        if admission_state is not None and admission_policy is None:
            raise DiscoveryError(
                "discovery snapshot admission state requires policy"
            )
        if admission_policy is not None:
            if admission_state is None:
                restored._admission_semantic_history = {
                    key: discovery_semantic_identity(
                        admission_policy,
                        record,
                    )
                    for key, record in verified_active.items()
                }
            else:
                if admission_state["policy_digest"] != admission_policy.digest:
                    raise DiscoveryError(
                        "discovery snapshot admission state policy mismatch"
                    )
                restored_history = {
                    (
                        item["source_id"],
                        item["assertion_kind"],
                        item["assertion_id"],
                    ): item["semantic_identity"]
                    for item in admission_state["semantic_history"]
                }
                if len(restored_history) != len(
                    admission_state["semantic_history"]
                ):
                    raise DiscoveryError(
                        "duplicate discovery admission semantic history"
                    )
                for key, record in verified_active.items():
                    expected_identity = discovery_semantic_identity(
                        admission_policy,
                        record,
                    )
                    if restored_history.get(key) != expected_identity:
                        raise DiscoveryError(
                            "discovery admission active semantic history mismatch"
                        )
                restored._admission_semantic_history = restored_history
        restored._next_snapshot_sequence = candidate["snapshot_sequence"] + 1
        restored._previous_snapshot_digest = discovery_index_snapshot_digest(candidate)
        return restored
