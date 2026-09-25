"""Pure protocol conformance for pre-collected synthetic discovery fixtures.

This module never launches a collector.  It verifies a bounded signed record
chain supplied by the caller, applies it to an in-memory discovery index, and
returns a signed receipt about protocol behavior only.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from jsonschema import ValidationError

from .discovery import (
    MAX_DISCOVERY_BATCH_RECORDS,
    DiscoveryAssertionKind,
    DiscoveryChange,
    DiscoveryError,
    TrustedDiscoverySource,
    UnknownClass,
    ZonedDiscoveryIndex,
)
from .hashing import digest_object
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)

_CONFORMANCE_BOUNDARY = {
    "collector_execution": False,
    "credentials": False,
    "model_calls": 0,
    "network": False,
    "production_authority": False,
    "tool_calls": 0,
}
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_SYNTHETIC_ID_FIELDS = frozenset(
    {
        "entity_id",
        "from_entity_id",
        "from_zone_id",
        "gap_id",
        "relation_id",
        "source_epoch",
        "source_id",
        "subject_id",
        "to_entity_id",
        "to_zone_id",
        "zone_id",
    }
)


@dataclass(frozen=True)
class DiscoveryConformanceProfile:
    """Out-of-band requirements for one synthetic collector fixture."""

    profile_id: str
    tenant_id: str
    trusted_source: TrustedDiscoverySource
    fixture_scope_digest: str
    required_assertion_kinds: tuple[DiscoveryAssertionKind, ...] = ()
    required_gap_classes: tuple[UnknownClass, ...] = ()
    require_cross_zone_relation: bool = False
    require_tombstone: bool = False
    max_records: int = MAX_DISCOVERY_BATCH_RECORDS

    def __post_init__(self) -> None:
        if (
            not isinstance(self.profile_id, str)
            or _ID.fullmatch(self.profile_id) is None
            or "synthetic" not in self.profile_id
        ):
            raise DiscoveryError("synthetic conformance profile id required")
        if self.tenant_id != "tenant:public-6e3cdbebaafc8efa":
            raise DiscoveryError("synthetic conformance tenant required")
        if not isinstance(self.trusted_source, TrustedDiscoverySource):
            raise DiscoveryError("conformance trusted source rejected")
        if (
            "synthetic" not in self.trusted_source.source_id
            or "synthetic" not in self.trusted_source.source_epoch
        ):
            raise DiscoveryError("synthetic conformance source required")
        if (
            not isinstance(self.fixture_scope_digest, str)
            or _DIGEST.fullmatch(self.fixture_scope_digest) is None
        ):
            raise DiscoveryError("conformance fixture scope digest rejected")
        if (
            not isinstance(self.max_records, int)
            or isinstance(self.max_records, bool)
            or not 1 <= self.max_records <= MAX_DISCOVERY_BATCH_RECORDS
        ):
            raise DiscoveryError("conformance record limit rejected")
        if not isinstance(self.required_assertion_kinds, tuple) or any(
            not isinstance(kind, DiscoveryAssertionKind)
            for kind in self.required_assertion_kinds
        ):
            raise DiscoveryError("conformance assertion requirement rejected")
        if len(set(self.required_assertion_kinds)) != len(
            self.required_assertion_kinds
        ):
            raise DiscoveryError("duplicate conformance assertion requirement")
        if not isinstance(self.required_gap_classes, tuple) or any(
            not isinstance(gap_class, UnknownClass)
            for gap_class in self.required_gap_classes
        ):
            raise DiscoveryError("conformance gap requirement rejected")
        if len(set(self.required_gap_classes)) != len(self.required_gap_classes):
            raise DiscoveryError("duplicate conformance gap requirement")
        if not isinstance(self.require_cross_zone_relation, bool):
            raise DiscoveryError("cross-zone conformance requirement rejected")
        if not isinstance(self.require_tombstone, bool):
            raise DiscoveryError("tombstone conformance requirement rejected")


def discovery_conformance_profile_digest(
    profile: DiscoveryConformanceProfile,
) -> str:
    """Bind a receipt to the complete out-of-band conformance contract."""

    if not isinstance(profile, DiscoveryConformanceProfile):
        raise DiscoveryError("discovery conformance profile rejected")
    source = profile.trusted_source
    document = {
        "profile_id": profile.profile_id,
        "tenant_id": profile.tenant_id,
        "source_id": source.source_id,
        "source_epoch": source.source_epoch,
        "source_artifact_digest": source.source_artifact_digest,
        "source_key_id": source.trusted_key.key_id,
        "source_public_key_fingerprint": public_key_fingerprint(
            source.trusted_key.public_key
        ),
        "fixture_scope_digest": profile.fixture_scope_digest,
        "required_assertion_kinds": sorted(
            kind.value for kind in profile.required_assertion_kinds
        ),
        "required_gap_classes": sorted(
            gap_class.value for gap_class in profile.required_gap_classes
        ),
        "require_cross_zone_relation": profile.require_cross_zone_relation,
        "require_tombstone": profile.require_tombstone,
        "max_records": profile.max_records,
    }
    return digest_object(
        document,
        domain="discovery-conformance-profile-v1",
    )


def _receipt_core(receipt: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(receipt))
    core.pop("receipt_id", None)
    core.pop("signature", None)
    return core


def discovery_conformance_receipt_identity(receipt: Mapping[str, Any]) -> str:
    """Return the content identity of one synthetic conformance receipt."""

    digest = digest_object(
        _receipt_core(receipt),
        domain="discovery-conformance-receipt-identity-v1",
    )
    return f"discovery-conformance-receipt:{digest.split(':', 1)[1]}"


def _assert_synthetic_values(value: Any, *, field: str | None = None) -> None:
    if isinstance(value, Mapping):
        for child_field, child in value.items():
            _assert_synthetic_values(child, field=str(child_field))
        return
    if isinstance(value, list):
        for child in value:
            _assert_synthetic_values(child, field=field)
        return
    if (
        field in _SYNTHETIC_ID_FIELDS
        and value is not None
        and (not isinstance(value, str) or "synthetic" not in value)
    ):
        raise DiscoveryError(f"non-synthetic conformance {field} rejected")


def verify_discovery_conformance_receipt(
    receipt: Mapping[str, Any],
    trusted_key: TrustedKey,
    *,
    expected_profile: DiscoveryConformanceProfile | None = None,
) -> dict[str, Any]:
    """Verify a signed collector protocol-conformance receipt."""

    try:
        candidate = deepcopy(dict(receipt))
        validate("discovery-conformance-receipt", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise DiscoveryError("discovery conformance receipt schema is invalid") from exc
    if candidate["receipt_id"] != discovery_conformance_receipt_identity(candidate):
        raise DiscoveryError("discovery conformance receipt identity mismatch")
    if (
        candidate["signature"]["key_id"] != trusted_key.key_id
        or not verify_signature(candidate, trusted_key.public_key)
    ):
        raise DiscoveryError("discovery conformance receipt signature rejected")
    if candidate["harness_boundary"] != _CONFORMANCE_BOUNDARY:
        raise DiscoveryError("discovery conformance harness boundary mismatch")
    if candidate["gap_classes"] != sorted(set(candidate["gap_classes"])):
        raise DiscoveryError("discovery conformance gap classes are not canonical")
    if sum(candidate["assertion_counts"].values()) != candidate["record_count"]:
        raise DiscoveryError("discovery conformance assertion counts disagree")
    if candidate["cross_zone_relation_count"] > candidate["assertion_counts"]["relation"]:
        raise DiscoveryError("discovery conformance relation counts disagree")
    if candidate["tombstone_count"] > candidate["record_count"]:
        raise DiscoveryError("discovery conformance tombstone counts disagree")
    if expected_profile is not None:
        source = expected_profile.trusted_source
        expected = {
            "profile_id": expected_profile.profile_id,
            "profile_digest": discovery_conformance_profile_digest(
                expected_profile
            ),
            "tenant_id": expected_profile.tenant_id,
            "source_id": source.source_id,
            "source_epoch": source.source_epoch,
            "source_artifact_digest": source.source_artifact_digest,
            "fixture_scope_digest": expected_profile.fixture_scope_digest,
        }
        for field, value in expected.items():
            if candidate[field] != value:
                raise DiscoveryError(f"discovery conformance {field} mismatch")
    return candidate


def verify_discovery_conformance(
    records: Sequence[Mapping[str, Any]],
    *,
    profile: DiscoveryConformanceProfile,
    harness_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Verify pre-collected synthetic records without executing their collector."""

    if not isinstance(profile, DiscoveryConformanceProfile):
        raise DiscoveryError("discovery conformance profile rejected")
    if not isinstance(harness_signer, Ed25519Signer):
        raise DiscoveryError("discovery conformance harness signer rejected")
    if (
        not isinstance(records, Sequence)
        or isinstance(records, (str, bytes))
        or not 1 <= len(records) <= profile.max_records
    ):
        raise DiscoveryError("discovery conformance fixture size rejected")

    try:
        fixture = [deepcopy(dict(record)) for record in records]
    except (TypeError, ValueError) as exc:
        raise DiscoveryError("discovery conformance fixture record rejected") from exc
    for record in fixture:
        _assert_synthetic_values(record)

    index = ZonedDiscoveryIndex(
        tenant_id=profile.tenant_id,
        trusted_sources=[profile.trusted_source],
        receipt_signer=harness_signer,
    )
    index_receipt = index.apply(fixture)

    assertion_counts = {
        kind.value: sum(
            record["assertion"]["kind"] == kind.value
            for record in fixture
        )
        for kind in DiscoveryAssertionKind
    }
    gap_classes = sorted(
        {
            record["assertion"]["classification"]
            for record in fixture
            if record["assertion"]["kind"] == DiscoveryAssertionKind.GAP.value
        }
    )
    cross_zone_relation_count = sum(
        record["assertion"]["kind"] == DiscoveryAssertionKind.RELATION.value
        and record["assertion"]["from_zone_id"]
        != record["assertion"]["to_zone_id"]
        for record in fixture
    )
    tombstone_count = sum(
        record["change"] == DiscoveryChange.DELETE.value
        for record in fixture
    )

    missing_kinds = {
        kind.value
        for kind in profile.required_assertion_kinds
        if assertion_counts[kind.value] == 0
    }
    if missing_kinds:
        raise DiscoveryError(
            f"discovery conformance missing assertion kinds: {sorted(missing_kinds)}"
        )
    missing_gaps = {
        gap_class.value
        for gap_class in profile.required_gap_classes
        if gap_class.value not in gap_classes
    }
    if missing_gaps:
        raise DiscoveryError(
            f"discovery conformance missing gap classes: {sorted(missing_gaps)}"
        )
    if profile.require_cross_zone_relation and cross_zone_relation_count == 0:
        raise DiscoveryError("discovery conformance cross-zone relation required")
    if profile.require_tombstone and tombstone_count == 0:
        raise DiscoveryError("discovery conformance tombstone required")

    source = profile.trusted_source
    core: dict[str, Any] = {
        "protocol": "integrity-guardian/discovery-conformance-receipt/v1",
        "profile_id": profile.profile_id,
        "profile_digest": discovery_conformance_profile_digest(profile),
        "tenant_id": profile.tenant_id,
        "source_id": source.source_id,
        "source_epoch": source.source_epoch,
        "source_artifact_digest": source.source_artifact_digest,
        "fixture_scope_digest": profile.fixture_scope_digest,
        "records_digest": digest_object(
            fixture,
            domain="discovery-conformance-records-v1",
        ),
        "index_receipt_digest": digest_object(
            index_receipt,
            domain="discovery-conformance-index-receipt-v1",
        ),
        "record_count": len(fixture),
        "assertion_counts": assertion_counts,
        "gap_classes": gap_classes,
        "cross_zone_relation_count": cross_zone_relation_count,
        "tombstone_count": tombstone_count,
        "checks": {
            "cross_zone_requirement": True,
            "gap_requirements": True,
            "kind_requirements": True,
            "source_binding": True,
            "source_chain": True,
            "synthetic_scope": True,
            "tombstone_requirement": True,
        },
        "harness_boundary": deepcopy(_CONFORMANCE_BOUNDARY),
    }
    unsigned = {
        "receipt_id": discovery_conformance_receipt_identity(core),
        **core,
    }
    receipt = harness_signer.sign(unsigned)
    verify_discovery_conformance_receipt(
        receipt,
        TrustedKey(
            key_id=harness_signer.key_id,
            public_key=harness_signer.public_key,
        ),
        expected_profile=profile,
    )
    return receipt
