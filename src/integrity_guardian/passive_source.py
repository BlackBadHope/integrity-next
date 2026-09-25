"""Controller-held passive source compilation for Fog of War.

The adapter accepts digest-only summaries created outside Guardian Core and
emits one signed discovery source chain per explicitly classified source.
It never receives raw source rows and cannot collect, probe, admit or mutate.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from jsonschema import ValidationError

from .discovery import (
    CoverageState,
    DiscoveryCursor,
    DiscoveryEmitter,
    DiscoveryProvenance,
    DiscoveryState,
    TrustedDiscoverySource,
    UnknownClass,
    build_entity_assertion,
    build_gap_assertion,
)
from .discovery_admission import (
    DiscoveryAdmissionPolicy,
    DiscoveryFactClass,
    DiscoveryLifecycle,
    DiscoverySourceBinding,
)
from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, public_key_fingerprint

MAX_PASSIVE_SOURCE_SUMMARIES = 256
MAX_PASSIVE_SOURCE_RECORDS = 4_096

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_PASSIVE_SOURCE_BOUNDARY = {
    "active_probe": False,
    "atlas_admission": False,
    "collection": False,
    "cursor_commit": False,
    "execution": False,
    "memory_admission": False,
    "model_calls": 0,
    "mutation": False,
    "network": False,
    "production_authority": False,
    "raw_rows_present": False,
}
_FACT_LIFECYCLES = {
    DiscoveryFactClass.STATIC: {DiscoveryLifecycle.PERSISTENT},
    DiscoveryFactClass.QUASI_STATIC: {
        DiscoveryLifecycle.PERSISTENT,
        DiscoveryLifecycle.ACTIVE,
    },
    DiscoveryFactClass.DYNAMIC: {
        DiscoveryLifecycle.ACTIVE,
        DiscoveryLifecycle.EPHEMERAL,
    },
    DiscoveryFactClass.CACHE: {DiscoveryLifecycle.EPHEMERAL},
    DiscoveryFactClass.DERIVED: {DiscoveryLifecycle.DERIVED},
    DiscoveryFactClass.THEORETICAL: {DiscoveryLifecycle.THEORETICAL},
    DiscoveryFactClass.UNKNOWN: {DiscoveryLifecycle.UNKNOWN},
}
_PASSIVE_SOURCE_UNKNOWN_REASONS = {
    UnknownClass.AMBIGUOUS_OWNER.value,
    UnknownClass.CONFLICTING_IDENTITY.value,
    UnknownClass.STALE_SOURCE.value,
    UnknownClass.UNOBSERVED_ZONE.value,
    UnknownClass.UNSUPPORTED_PROTOCOL.value,
}


class PassiveSourceError(ValueError):
    """Raised when a digest-only passive source snapshot is unsafe."""


class PassiveSourceSensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SECRET_METADATA = "secret-metadata"


class PassiveSourceStatus(StrEnum):
    OBSERVED = "OBSERVED"
    UNKNOWN = "UNKNOWN"
    DENIED = "DENIED"


def passive_source_boundary() -> dict[str, Any]:
    """Return the closed Core boundary used by passive source snapshots."""

    return deepcopy(_PASSIVE_SOURCE_BOUNDARY)


@dataclass(frozen=True)
class PassiveSourceBinding:
    """Out-of-band classification for one logical passive source chain."""

    source_name: str
    source_id: str
    source_class: str
    zone_id: str
    fact_class: DiscoveryFactClass
    lifecycle: DiscoveryLifecycle
    sensitivity: PassiveSourceSensitivity

    def __post_init__(self) -> None:
        for field_name, value in (
            ("source_name", self.source_name),
            ("source_id", self.source_id),
            ("source_class", self.source_class),
            ("zone_id", self.zone_id),
        ):
            if not isinstance(value, str) or _ID.fullmatch(value) is None:
                raise PassiveSourceError(f"passive source {field_name} rejected")
        if _ID.fullmatch(f"passive-source-class:{self.source_class}") is None:
            raise PassiveSourceError("passive source class expansion rejected")
        if not isinstance(self.fact_class, DiscoveryFactClass):
            raise PassiveSourceError("passive source fact class rejected")
        if not isinstance(self.lifecycle, DiscoveryLifecycle):
            raise PassiveSourceError("passive source lifecycle rejected")
        if self.lifecycle not in _FACT_LIFECYCLES[self.fact_class]:
            raise PassiveSourceError("passive source fact lifecycle mismatch")
        if not isinstance(self.sensitivity, PassiveSourceSensitivity):
            raise PassiveSourceError("passive source sensitivity rejected")

    def document(self) -> dict[str, str]:
        return {
            "source_name": self.source_name,
            "source_id": self.source_id,
            "source_class": self.source_class,
            "zone_id": self.zone_id,
            "fact_class": self.fact_class.value,
            "lifecycle": self.lifecycle.value,
            "sensitivity": self.sensitivity.value,
        }


@dataclass(frozen=True)
class PassiveSourcePolicy:
    """Closed expected source set and lifecycle classifications."""

    policy_id: str
    collector_artifact_digest: str
    source_key: TrustedKey
    bindings: tuple[PassiveSourceBinding, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.policy_id, str) or _ID.fullmatch(self.policy_id) is None:
            raise PassiveSourceError("passive source policy id rejected")
        if (
            not isinstance(self.collector_artifact_digest, str)
            or _DIGEST.fullmatch(self.collector_artifact_digest) is None
        ):
            raise PassiveSourceError("passive source collector artifact rejected")
        if (
            not isinstance(self.source_key, TrustedKey)
            or not isinstance(self.source_key.key_id, str)
            or _ID.fullmatch(self.source_key.key_id) is None
        ):
            raise PassiveSourceError("passive source key rejected")
        try:
            public_key_fingerprint(self.source_key.public_key)
        except (AttributeError, TypeError, ValueError) as exc:
            raise PassiveSourceError("passive source public key rejected") from exc
        if (
            not isinstance(self.bindings, tuple)
            or not self.bindings
            or len(self.bindings) > MAX_PASSIVE_SOURCE_SUMMARIES
        ):
            raise PassiveSourceError("passive source bindings rejected")
        for binding in self.bindings:
            if not isinstance(binding, PassiveSourceBinding):
                raise PassiveSourceError("passive source binding rejected")
        ordered = tuple(
            sorted(
                self.bindings,
                key=lambda item: (item.source_name, item.source_id),
            )
        )
        names = [item.source_name for item in ordered]
        source_ids = [item.source_id for item in ordered]
        if len(names) != len(set(names)):
            raise PassiveSourceError("duplicate passive source name")
        if len(source_ids) != len(set(source_ids)):
            raise PassiveSourceError("duplicate passive source id")
        object.__setattr__(self, "bindings", ordered)

    def document(self) -> dict[str, Any]:
        return {
            "protocol": "integrity-guardian/passive-source-policy/v1",
            "policy_id": self.policy_id,
            "collector_artifact_digest": self.collector_artifact_digest,
            "source_key_id": self.source_key.key_id,
            "source_key_fingerprint": public_key_fingerprint(
                self.source_key.public_key
            ),
            "bindings": [binding.document() for binding in self.bindings],
            "boundary": deepcopy(_PASSIVE_SOURCE_BOUNDARY),
        }

    @property
    def digest(self) -> str:
        return digest_object(self.document(), domain="passive-source-policy-v1")

    def admission_policy(self, *, source_epoch: str) -> DiscoveryAdmissionPolicy:
        if not isinstance(source_epoch, str) or _ID.fullmatch(source_epoch) is None:
            raise PassiveSourceError("passive source epoch rejected")
        suffix = self.digest.split(":", 1)[1]
        return DiscoveryAdmissionPolicy(
            policy_id=f"passive-admission:{suffix}",
            source_bindings=tuple(
                DiscoverySourceBinding(
                    source_id=binding.source_id,
                    source_epoch=source_epoch,
                    fact_class=binding.fact_class,
                    lifecycle=binding.lifecycle,
                )
                for binding in self.bindings
            ),
        )


@dataclass(frozen=True)
class PassiveSourceCompilation:
    """Signed source records and caller-retained continuation candidates."""

    records: tuple[dict[str, Any], ...]
    input_cursors: tuple[DiscoveryCursor, ...]
    output_cursors: tuple[DiscoveryCursor, ...]
    trusted_sources: tuple[TrustedDiscoverySource, ...]
    admission_policy: DiscoveryAdmissionPolicy
    policy_digest: str
    capture_id: str
    platform_family: str
    boundary: Mapping[str, Any]

    def __post_init__(self) -> None:
        if dict(self.boundary) != _PASSIVE_SOURCE_BOUNDARY:
            raise PassiveSourceError("passive source compilation boundary mismatch")


def _cursor_index(
    cursors: Sequence[DiscoveryCursor],
    *,
    policy: PassiveSourcePolicy,
    source_epoch: str,
) -> dict[str, DiscoveryCursor]:
    if (
        not isinstance(cursors, Sequence)
        or isinstance(cursors, (str, bytes))
        or len(cursors) != len(policy.bindings)
    ):
        raise PassiveSourceError("passive source cursor set rejected")
    expected_ids = {binding.source_id for binding in policy.bindings}
    indexed: dict[str, DiscoveryCursor] = {}
    for cursor in cursors:
        if not isinstance(cursor, DiscoveryCursor):
            raise PassiveSourceError("passive source cursor rejected")
        if cursor.source_id not in expected_ids or cursor.source_epoch != source_epoch:
            raise PassiveSourceError("passive source cursor identity mismatch")
        if cursor.source_id in indexed:
            raise PassiveSourceError("duplicate passive source cursor")
        indexed[cursor.source_id] = cursor
    if set(indexed) != expected_ids:
        raise PassiveSourceError("passive source cursor coverage mismatch")
    return indexed


def _snapshot_summaries(
    snapshot: Mapping[str, Any],
    *,
    policy: PassiveSourcePolicy,
) -> tuple[dict[str, Any], dict[str, Mapping[str, Any]]]:
    try:
        candidate = deepcopy(dict(snapshot))
        validate("passive-source-snapshot", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise PassiveSourceError("passive source snapshot schema is invalid") from exc
    if candidate["boundary"] != _PASSIVE_SOURCE_BOUNDARY:
        raise PassiveSourceError("passive source snapshot boundary mismatch")
    summaries: dict[str, Mapping[str, Any]] = {}
    for summary in candidate["source_summaries"]:
        source_name = summary["source_name"]
        if source_name in summaries:
            raise PassiveSourceError("duplicate passive source summary")
        summaries[source_name] = summary
    expected_names = {binding.source_name for binding in policy.bindings}
    if set(summaries) != expected_names:
        raise PassiveSourceError("passive source summary coverage mismatch")
    return candidate, summaries


def _validate_summary_semantics(summary: Mapping[str, Any]) -> PassiveSourceStatus:
    status = PassiveSourceStatus(summary["status"])
    payload_digest = summary["payload_digest"]
    record_count = summary["record_count"]
    reason_class = summary["reason_class"]
    truncated = summary["truncated"]
    if status is PassiveSourceStatus.OBSERVED:
        if not isinstance(payload_digest, str) or _DIGEST.fullmatch(payload_digest) is None:
            raise PassiveSourceError("observed passive source payload digest required")
        if reason_class is not None:
            raise PassiveSourceError("observed passive source reason rejected")
    else:
        if payload_digest is not None or record_count != 0 or truncated:
            raise PassiveSourceError("unobserved passive source payload rejected")
        if not isinstance(reason_class, str):
            raise PassiveSourceError("unobserved passive source reason required")
        if status is PassiveSourceStatus.DENIED:
            if reason_class != UnknownClass.DENIED_COVERAGE.value:
                raise PassiveSourceError("denied passive source reason mismatch")
        elif reason_class not in _PASSIVE_SOURCE_UNKNOWN_REASONS:
            raise PassiveSourceError("unknown passive source reason rejected")
    return status


def _dataset_identity(binding: PassiveSourceBinding) -> str:
    suffix = digest_object(
        binding.document(),
        domain="passive-source-dataset-identity-v1",
    ).split(":", 1)[1]
    return f"passive-dataset:{suffix}"


def compile_passive_source_snapshot(
    snapshot: Mapping[str, Any],
    *,
    policy: PassiveSourcePolicy,
    input_cursors: Sequence[DiscoveryCursor],
    input_policy_digest: str | None,
    signer: Ed25519Signer,
) -> PassiveSourceCompilation:
    """Compile digest-only summaries into isolated signed discovery chains."""

    if not isinstance(policy, PassiveSourcePolicy):
        raise PassiveSourceError("passive source policy rejected")
    if not isinstance(signer, Ed25519Signer):
        raise PassiveSourceError("passive source signer rejected")
    candidate, summaries = _snapshot_summaries(snapshot, policy=policy)
    if candidate["collector_artifact_digest"] != policy.collector_artifact_digest:
        raise PassiveSourceError("passive source collector artifact mismatch")
    if (
        signer.key_id != policy.source_key.key_id
        or public_key_fingerprint(signer.public_key)
        != public_key_fingerprint(policy.source_key.public_key)
    ):
        raise PassiveSourceError("passive source signer trust mismatch")
    source_epoch = candidate["source_epoch"]
    cursors = _cursor_index(
        input_cursors,
        policy=policy,
        source_epoch=source_epoch,
    )
    continuation_states = {
        cursor.next_sequence > 0 for cursor in cursors.values()
    }
    if len(continuation_states) != 1:
        raise PassiveSourceError("passive source cursor checkpoint is inconsistent")
    continuing = continuation_states.pop()
    if continuing:
        if input_policy_digest != policy.digest:
            raise PassiveSourceError("passive source policy checkpoint mismatch")
    elif input_policy_digest is not None:
        raise PassiveSourceError("fresh passive source epoch has prior policy checkpoint")
    records: list[dict[str, Any]] = []
    output_cursors: list[DiscoveryCursor] = []
    trusted_sources: list[TrustedDiscoverySource] = []
    for binding in policy.bindings:
        summary = summaries[binding.source_name]
        status = _validate_summary_semantics(summary)
        dataset_id = _dataset_identity(binding)
        if status is PassiveSourceStatus.OBSERVED:
            assertion = build_entity_assertion(
                entity_id=dataset_id,
                entity_type=f"passive-source-class:{binding.source_class}",
            )
            state = DiscoveryState.PRESENT
            coverage = (
                CoverageState.PARTIAL
                if summary["truncated"]
                else CoverageState.COMPLETE
            )
            content_digest = summary["payload_digest"]
            confidence_ppm = 1_000_000
        else:
            assertion = build_gap_assertion(
                gap_id=f"gap:{dataset_id}",
                classification=UnknownClass(summary["reason_class"]),
                subject_id=dataset_id,
            )
            state = DiscoveryState.UNKNOWN
            coverage = (
                CoverageState.DENIED
                if status is PassiveSourceStatus.DENIED
                else CoverageState.UNKNOWN
            )
            content_digest = None
            confidence_ppm = 0
        emitter = DiscoveryEmitter(
            tenant_id=candidate["tenant_id"],
            cursor=cursors[binding.source_id],
            signer=signer,
        )
        records.append(
            emitter.emit(
                assertion=assertion,
                observed_at=summary["observed_at"],
                zone_id=binding.zone_id,
                source_artifact_digest=candidate["collector_artifact_digest"],
                coverage_digest=summary["coverage_digest"],
                provenance=DiscoveryProvenance.OBSERVED,
                state=state,
                coverage=coverage,
                confidence_ppm=confidence_ppm,
                content_digest=content_digest,
            )
        )
        output_cursors.append(emitter.cursor)
        trusted_sources.append(
            TrustedDiscoverySource(
                source_id=binding.source_id,
                source_epoch=source_epoch,
                source_artifact_digest=candidate["collector_artifact_digest"],
                trusted_key=policy.source_key,
            )
        )
    return PassiveSourceCompilation(
        records=tuple(records),
        input_cursors=tuple(cursors[binding.source_id] for binding in policy.bindings),
        output_cursors=tuple(output_cursors),
        trusted_sources=tuple(trusted_sources),
        admission_policy=policy.admission_policy(source_epoch=source_epoch),
        policy_digest=policy.digest,
        capture_id=candidate["capture_id"],
        platform_family=candidate["platform_family"],
        boundary=deepcopy(_PASSIVE_SOURCE_BOUNDARY),
    )
