"""Fail-closed multi-source passive discovery cohort receipts.

This module binds already signed discovery records into one controller-defined
capture window.  It performs no collection, index mutation, Atlas projection,
memory admission, cursor commit, network access or model call.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from jsonschema import ValidationError

from .discovery import (
    DiscoveryCursor,
    DiscoveryError,
    TrustedDiscoverySource,
    discovery_record_digest,
    verify_discovery_record,
)
from .hashing import digest_object
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)

MAX_PASSIVE_COHORT_SOURCES = 64
MAX_PASSIVE_COHORT_RECORDS = 10_000

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_TENANT_ID = re.compile(r"^tenant:[A-Za-z0-9][A-Za-z0-9._:/-]{0,248}$")
_COHORT_BOUNDARY = {
    "active_probe": False,
    "atlas_admission": False,
    "cursor_commit": False,
    "execution": False,
    "memory_admission": False,
    "model_calls": 0,
    "mutation": False,
    "network": False,
    "priority_is_authority": False,
    "production_authority": False,
    "theory_is_observation": False,
}


class PassiveCohortError(ValueError):
    """Raised when a passive multi-source cohort cannot be trusted."""


@dataclass(frozen=True)
class PassiveCohortPolicy:
    """Closed timing and cardinality limits for one passive capture cohort."""

    policy_id: str
    max_capture_duration_seconds: int
    max_observation_skew_seconds: int
    max_source_age_seconds: int
    max_sources: int = MAX_PASSIVE_COHORT_SOURCES
    max_records: int = MAX_PASSIVE_COHORT_RECORDS

    def __post_init__(self) -> None:
        if not isinstance(self.policy_id, str) or _ID.fullmatch(self.policy_id) is None:
            raise PassiveCohortError("passive cohort policy id rejected")
        for field_name, value, upper_bound in (
            (
                "max_capture_duration_seconds",
                self.max_capture_duration_seconds,
                86_400,
            ),
            (
                "max_observation_skew_seconds",
                self.max_observation_skew_seconds,
                86_400,
            ),
            ("max_source_age_seconds", self.max_source_age_seconds, 604_800),
            ("max_sources", self.max_sources, MAX_PASSIVE_COHORT_SOURCES),
            ("max_records", self.max_records, MAX_PASSIVE_COHORT_RECORDS),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 1 <= value <= upper_bound
            ):
                raise PassiveCohortError(f"passive cohort {field_name} rejected")

    def document(self) -> dict[str, Any]:
        return {
            "protocol": "integrity-guardian/passive-cohort-policy/v1",
            "policy_id": self.policy_id,
            "max_capture_duration_seconds": self.max_capture_duration_seconds,
            "max_observation_skew_seconds": self.max_observation_skew_seconds,
            "max_source_age_seconds": self.max_source_age_seconds,
            "max_sources": self.max_sources,
            "max_records": self.max_records,
            "boundary": deepcopy(_COHORT_BOUNDARY),
        }

    @property
    def digest(self) -> str:
        return digest_object(self.document(), domain="passive-cohort-policy-v1")


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise PassiveCohortError(f"passive cohort {field_name} rejected")
    return value


def _require_tenant_id(value: str) -> str:
    if not isinstance(value, str) or _TENANT_ID.fullmatch(value) is None:
        raise PassiveCohortError("passive cohort tenant id rejected")
    return value


def _parse_time(value: Any, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise PassiveCohortError(f"passive cohort {field_name} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise PassiveCohortError(
            f"passive cohort {field_name} rejected"
        ) from exc
    if parsed.tzinfo is None:
        raise PassiveCohortError(f"passive cohort {field_name} rejected")
    return parsed


def _trusted_source_index(
    trusted_sources: Sequence[TrustedDiscoverySource],
    *,
    policy: PassiveCohortPolicy,
) -> dict[str, TrustedDiscoverySource]:
    if (
        not isinstance(trusted_sources, Sequence)
        or isinstance(trusted_sources, (str, bytes))
        or not trusted_sources
        or len(trusted_sources) > policy.max_sources
    ):
        raise PassiveCohortError("passive cohort trusted sources rejected")
    by_source: dict[str, TrustedDiscoverySource] = {}
    for source in trusted_sources:
        if not isinstance(source, TrustedDiscoverySource):
            raise PassiveCohortError("passive cohort trusted source rejected")
        if source.source_id in by_source:
            raise PassiveCohortError(
                "passive cohort source has multiple or duplicate epochs"
            )
        by_source[source.source_id] = source
    return by_source


def _cursor_index(
    input_cursors: Sequence[DiscoveryCursor],
    *,
    trusted_sources: Mapping[str, TrustedDiscoverySource],
) -> dict[str, DiscoveryCursor]:
    if (
        not isinstance(input_cursors, Sequence)
        or isinstance(input_cursors, (str, bytes))
        or len(input_cursors) != len(trusted_sources)
    ):
        raise PassiveCohortError("passive cohort input cursor set rejected")
    by_source: dict[str, DiscoveryCursor] = {}
    for cursor in input_cursors:
        if not isinstance(cursor, DiscoveryCursor):
            raise PassiveCohortError("passive cohort input cursor rejected")
        source = trusted_sources.get(cursor.source_id)
        if source is None or cursor.source_epoch != source.source_epoch:
            raise PassiveCohortError("passive cohort cursor source epoch mismatch")
        if cursor.source_id in by_source:
            raise PassiveCohortError("passive cohort duplicate input cursor")
        by_source[cursor.source_id] = cursor
    if set(by_source) != set(trusted_sources):
        raise PassiveCohortError("passive cohort input cursor coverage mismatch")
    return by_source


def _evaluate_passive_cohort(
    *,
    tenant_id: str,
    capture_id: str,
    capture_started_at: str,
    capture_completed_at: str,
    records: Sequence[Mapping[str, Any]],
    trusted_sources: Sequence[TrustedDiscoverySource],
    input_cursors: Sequence[DiscoveryCursor],
    policy: PassiveCohortPolicy,
) -> dict[str, Any]:
    _require_tenant_id(tenant_id)
    _require_id(capture_id, "capture id")
    if not isinstance(policy, PassiveCohortPolicy):
        raise PassiveCohortError("passive cohort policy rejected")
    started = _parse_time(capture_started_at, "capture_started_at")
    completed = _parse_time(capture_completed_at, "capture_completed_at")
    capture_duration = (completed - started).total_seconds()
    if capture_duration < 0:
        raise PassiveCohortError("passive cohort capture clock moved backwards")
    if capture_duration > policy.max_capture_duration_seconds:
        raise PassiveCohortError("passive cohort capture duration exceeded")
    if (
        not isinstance(records, Sequence)
        or isinstance(records, (str, bytes))
        or not records
        or len(records) > policy.max_records
    ):
        raise PassiveCohortError("passive cohort records rejected")

    sources = _trusted_source_index(trusted_sources, policy=policy)
    cursors = _cursor_index(input_cursors, trusted_sources=sources)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if not isinstance(record, Mapping):
            raise PassiveCohortError("passive cohort record rejected")
        source_id = record.get("source_id")
        source = sources.get(source_id) if isinstance(source_id, str) else None
        if source is None:
            raise PassiveCohortError("passive cohort untrusted source rejected")
        try:
            verified = verify_discovery_record(
                record,
                source.trusted_key,
                expected_tenant_id=tenant_id,
                expected_source_id=source.source_id,
                expected_source_epoch=source.source_epoch,
                expected_source_artifact_digest=source.source_artifact_digest,
            )
        except DiscoveryError as exc:
            raise PassiveCohortError(
                "passive cohort discovery record verification failed"
            ) from exc
        grouped[source.source_id].append(verified)
    if set(grouped) != set(sources):
        raise PassiveCohortError("passive cohort source coverage mismatch")

    all_observed: list[datetime] = []
    source_windows: list[dict[str, Any]] = []
    ordered_records: list[dict[str, Any]] = []
    output_cursors: list[dict[str, Any]] = []
    for source_id in sorted(sources):
        source = sources[source_id]
        cursor = cursors[source_id]
        source_records = sorted(grouped[source_id], key=lambda item: item["sequence"])
        if source_records[0]["sequence"] != cursor.next_sequence:
            raise PassiveCohortError("passive cohort first sequence mismatch")
        expected_previous = cursor.previous_record_digest
        expected_sequence = cursor.next_sequence
        observed_values: list[datetime] = []
        previous_observed: datetime | None = None
        coverage_digests: set[str] = set()
        for record in source_records:
            if record["sequence"] != expected_sequence:
                raise PassiveCohortError("passive cohort source sequence gap")
            if record["previous_record_digest"] != expected_previous:
                raise PassiveCohortError("passive cohort source chain mismatch")
            observed = _parse_time(record["observed_at"], "record observed_at")
            if observed < started or observed > completed:
                raise PassiveCohortError(
                    "passive cohort observation outside capture window"
                )
            if previous_observed is not None and observed < previous_observed:
                raise PassiveCohortError(
                    "passive cohort source observation clock moved backwards"
                )
            previous_observed = observed
            observed_values.append(observed)
            all_observed.append(observed)
            coverage_digests.add(record["evidence"]["coverage"]["scope_digest"])
            expected_previous = discovery_record_digest(record)
            expected_sequence += 1

        latest_age = (completed - observed_values[-1]).total_seconds()
        if latest_age > policy.max_source_age_seconds:
            raise PassiveCohortError("passive cohort source is stale")
        first_digest = discovery_record_digest(source_records[0])
        last_digest = discovery_record_digest(source_records[-1])
        coverage = sorted(coverage_digests)
        output_cursor = DiscoveryCursor(
            source_id=source.source_id,
            source_epoch=source.source_epoch,
            next_sequence=expected_sequence,
            previous_record_digest=expected_previous,
        )
        source_windows.append(
            {
                "source_id": source.source_id,
                "source_epoch": source.source_epoch,
                "source_key_fingerprint": public_key_fingerprint(
                    source.trusted_key.public_key
                ),
                "source_artifact_digest": source.source_artifact_digest,
                "record_count": len(source_records),
                "first_sequence": source_records[0]["sequence"],
                "last_sequence": source_records[-1]["sequence"],
                "first_record_digest": first_digest,
                "last_record_digest": last_digest,
                "observed_from": source_records[0]["observed_at"],
                "observed_through": source_records[-1]["observed_at"],
                "coverage_digests": coverage,
                "coverage_set_digest": digest_object(
                    coverage,
                    domain="passive-cohort-coverage-set-v1",
                ),
                "input_cursor": cursor.to_document(),
                "output_cursor": output_cursor.to_document(),
            }
        )
        output_cursors.append(output_cursor.to_document())
        ordered_records.extend(source_records)

    observation_skew = (max(all_observed) - min(all_observed)).total_seconds()
    if observation_skew > policy.max_observation_skew_seconds:
        raise PassiveCohortError("passive cohort observation skew exceeded")

    trusted_source_documents = [
        {
            "source_id": source.source_id,
            "source_epoch": source.source_epoch,
            "source_artifact_digest": source.source_artifact_digest,
            "source_key_id": source.trusted_key.key_id,
            "source_key_fingerprint": public_key_fingerprint(
                source.trusted_key.public_key
            ),
        }
        for source in sorted(sources.values(), key=lambda item: item.source_id)
    ]
    cohort_material = {
        "tenant_id": tenant_id,
        "capture_id": capture_id,
        "capture_started_at": capture_started_at,
        "capture_completed_at": capture_completed_at,
        "policy_digest": policy.digest,
        "trusted_sources": trusted_source_documents,
        "input_cursors": [
            cursors[source_id].to_document() for source_id in sorted(cursors)
        ],
        "records": ordered_records,
    }
    cohort_digest = digest_object(
        cohort_material,
        domain="passive-discovery-cohort-v1",
    )
    core = {
        "protocol": "integrity-guardian/passive-discovery-cohort-receipt/v1",
        "tenant_id": tenant_id,
        "capture_id": capture_id,
        "capture_started_at": capture_started_at,
        "capture_completed_at": capture_completed_at,
        "capture_duration_seconds": math.ceil(capture_duration),
        "observation_skew_seconds": math.ceil(observation_skew),
        "policy_digest": policy.digest,
        "trusted_source_set_digest": digest_object(
            trusted_source_documents,
            domain="passive-cohort-trusted-source-set-v1",
        ),
        "input_cursor_set_digest": digest_object(
            [cursors[source_id].to_document() for source_id in sorted(cursors)],
            domain="passive-cohort-input-cursor-set-v1",
        ),
        "records_digest": digest_object(
            ordered_records,
            domain="passive-cohort-record-set-v1",
        ),
        "cohort_digest": cohort_digest,
        "source_count": len(source_windows),
        "record_count": len(ordered_records),
        "source_windows": source_windows,
        "output_cursors": output_cursors,
        "boundary": deepcopy(_COHORT_BOUNDARY),
    }
    suffix = digest_object(core, domain="passive-cohort-receipt-identity-v1").split(
        ":", 1
    )[1]
    return {
        **core,
        "receipt_id": f"passive-cohort-receipt:{suffix}",
    }


def build_passive_cohort_receipt(
    *,
    tenant_id: str,
    capture_id: str,
    capture_started_at: str,
    capture_completed_at: str,
    records: Sequence[Mapping[str, Any]],
    trusted_sources: Sequence[TrustedDiscoverySource],
    input_cursors: Sequence[DiscoveryCursor],
    policy: PassiveCohortPolicy,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Build a signed, non-admitting receipt for one coherent passive cohort."""

    if not isinstance(signer, Ed25519Signer):
        raise PassiveCohortError("passive cohort signer rejected")
    unsigned = _evaluate_passive_cohort(
        tenant_id=tenant_id,
        capture_id=capture_id,
        capture_started_at=capture_started_at,
        capture_completed_at=capture_completed_at,
        records=records,
        trusted_sources=trusted_sources,
        input_cursors=input_cursors,
        policy=policy,
    )
    signed = signer.sign(unsigned)
    verify_passive_cohort_receipt(
        signed,
        TrustedKey(key_id=signer.key_id, public_key=signer.public_key),
        records=records,
        trusted_sources=trusted_sources,
        input_cursors=input_cursors,
        policy=policy,
        expected_tenant_id=tenant_id,
        expected_capture_id=capture_id,
    )
    return signed


def verify_passive_cohort_receipt(
    receipt: Mapping[str, Any],
    trusted_controller_key: TrustedKey,
    *,
    records: Sequence[Mapping[str, Any]],
    trusted_sources: Sequence[TrustedDiscoverySource],
    input_cursors: Sequence[DiscoveryCursor],
    policy: PassiveCohortPolicy,
    expected_tenant_id: str | None = None,
    expected_capture_id: str | None = None,
) -> dict[str, Any]:
    """Verify signature and independently rebuild every cohort binding."""

    if not isinstance(trusted_controller_key, TrustedKey):
        raise PassiveCohortError("passive cohort trusted controller key rejected")
    try:
        candidate = deepcopy(dict(receipt))
        validate("passive-discovery-cohort-receipt", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise PassiveCohortError("passive cohort receipt schema is invalid") from exc
    if candidate["boundary"] != _COHORT_BOUNDARY:
        raise PassiveCohortError("passive cohort boundary mismatch")
    if (
        candidate["signature"]["key_id"] != trusted_controller_key.key_id
        or not verify_signature(candidate, trusted_controller_key.public_key)
    ):
        raise PassiveCohortError("passive cohort receipt signature rejected")
    if (
        expected_tenant_id is not None
        and candidate["tenant_id"] != expected_tenant_id
    ):
        raise PassiveCohortError("passive cohort tenant mismatch")
    if (
        expected_capture_id is not None
        and candidate["capture_id"] != expected_capture_id
    ):
        raise PassiveCohortError("passive cohort capture mismatch")
    rebuilt = _evaluate_passive_cohort(
        tenant_id=candidate["tenant_id"],
        capture_id=candidate["capture_id"],
        capture_started_at=candidate["capture_started_at"],
        capture_completed_at=candidate["capture_completed_at"],
        records=records,
        trusted_sources=trusted_sources,
        input_cursors=input_cursors,
        policy=policy,
    )
    unsigned = deepcopy(candidate)
    unsigned.pop("signature", None)
    if unsigned != rebuilt:
        raise PassiveCohortError("passive cohort receipt binding mismatch")
    return candidate
