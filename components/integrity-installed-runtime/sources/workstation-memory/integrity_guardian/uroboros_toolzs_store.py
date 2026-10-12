"""Private, atomic local route-memory storage for Integrity 5.5 Uroboros.

SQLite is used only as a crash-atomic container. Trust comes from the signed
manifest chain, content-addressed route-memory receipts, complete re-verification
at lookup, and a caller-retained cursor that detects rollback to an older valid
database prefix.

The store performs local filesystem I/O. It has no browser, credential,
subprocess, network, model, publication, tool-invocation or production
authority.
"""

from __future__ import annotations

import os
import re
import sqlite3
import stat
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Self

from jsonschema import ValidationError

from .canonical import canonical_bytes, parse_json_strict
from .discovery import TrustedDiscoverySource
from .discovery_feedback import (
    DiscoveryFeedbackPolicy,
    TrustedDiscoveryFeedback,
)
from .discovery_feedback_delta import (
    DiscoveryFeedbackDeltaCursor,
    discovery_feedback_delta_digest,
    verify_discovery_feedback_delta,
)
from .discovery_theory import DiscoveryTheoryPolicy
from .hashing import digest_object
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)
from .uroboros_toolzs import (
    ToolzCyberEvidence,
    ToolzFogRouteEvidence,
    ToolzRouteMemoryDecision,
    ToolzRouteMemoryOutcome,
    ToolzRouteMemoryPolicy,
    evaluate_toolz_route_memory,
    toolz_route_memory_digest,
    toolz_route_memory_identity,
    verify_toolz_route_memory_receipt,
)

MAX_TOOLZ_STORE_ENTRIES = 4096
MAX_TOOLZ_STORE_FEEDBACK_HEADS = 4096
MAX_TOOLZ_STORE_SEQUENCE = 2**63 - 1
STORE_DATABASE_NAME = "toolz-store.sqlite3"

_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_STORE_ID = re.compile(r"^toolz-store:[A-Za-z0-9][A-Za-z0-9._:/-]{0,242}$")
_CONTEXT_ID = re.compile(r"^toolz-store-context:[a-f0-9]{64}$")
_FEEDBACK_CHAIN_ID = re.compile(r"^toolz-feedback-chain:[a-f0-9]{64}$")
_MANIFEST_ID = re.compile(r"^toolz-route-store-manifest:[a-f0-9]{64}$")
_STORE_BOUNDARY = {
    "browser_control": False,
    "credentials": False,
    "execution": False,
    "global_publish": False,
    "local_storage": True,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
    "raw_ui_data": False,
    "tool_invocation": False,
}


class ToolzRouteStoreError(RuntimeError):
    """Raised before untrusted or ambiguous local Toolz state can be used."""


class ToolzStoreLifecycle(StrEnum):
    """Persisted guidance state; none of these values grants execution."""

    THEORETICAL = "theoretical"
    REUSABLE = "reusable"
    REDISCOVER = "rediscover"
    BLOCKED = "blocked"
    INVALIDATED = "invalidated"


class ToolzStoreRecoveryStatus(StrEnum):
    """Bounded safe outcomes for one exact retained recovery anchor."""

    RETAINED_HEAD = "retained-head"
    RECOVERED_INSTALL = "recovered-install"
    RECOVERED_FEEDBACK_INSTALL = "recovered-feedback-install"


_DECISION_LIFECYCLE = {
    ToolzRouteMemoryDecision.EXPLORE: ToolzStoreLifecycle.THEORETICAL,
    ToolzRouteMemoryDecision.REUSE_CANDIDATE: ToolzStoreLifecycle.REUSABLE,
    ToolzRouteMemoryDecision.REDISCOVER: ToolzStoreLifecycle.REDISCOVER,
    ToolzRouteMemoryDecision.BLOCKED: ToolzStoreLifecycle.BLOCKED,
}


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ToolzRouteStoreError(f"Toolz store {field} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolzRouteStoreError(f"Toolz store {field} rejected") from exc
    if parsed.tzinfo is None:
        raise ToolzRouteStoreError(f"Toolz store {field} rejected")
    return parsed


def _validate_store_identity(store_id: str, tenant_id: str) -> None:
    if (
        not isinstance(store_id, str)
        or _STORE_ID.fullmatch(store_id) is None
        or "synthetic" not in store_id
    ):
        raise ToolzRouteStoreError("Toolz store identity rejected")
    if tenant_id != "tenant:public-6e3cdbebaafc8efa":
        raise ToolzRouteStoreError("Toolz store tenant rejected")


@dataclass(frozen=True)
class ToolzStoreCursor:
    """Externally retained rollback and concurrency anchor for one exact head."""

    store_id: str
    tenant_id: str
    sequence: int
    manifest_id: str
    manifest_digest: str

    def __post_init__(self) -> None:
        _validate_store_identity(self.store_id, self.tenant_id)
        if (
            not isinstance(self.sequence, int)
            or isinstance(self.sequence, bool)
            or not 0 <= self.sequence <= MAX_TOOLZ_STORE_SEQUENCE
        ):
            raise ToolzRouteStoreError("Toolz store cursor sequence rejected")
        if (
            not isinstance(self.manifest_id, str)
            or _MANIFEST_ID.fullmatch(self.manifest_id) is None
            or not isinstance(self.manifest_digest, str)
            or _DIGEST.fullmatch(self.manifest_digest) is None
        ):
            raise ToolzRouteStoreError("Toolz store cursor head rejected")

    def to_document(self) -> dict[str, Any]:
        return {
            "store_id": self.store_id,
            "tenant_id": self.tenant_id,
            "sequence": self.sequence,
            "manifest_id": self.manifest_id,
            "manifest_digest": self.manifest_digest,
        }

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> ToolzStoreCursor:
        fields = {
            "store_id",
            "tenant_id",
            "sequence",
            "manifest_id",
            "manifest_digest",
        }
        if not isinstance(document, Mapping) or set(document) != fields:
            raise ToolzRouteStoreError("Toolz store cursor document rejected")
        try:
            return cls(**dict(document))
        except TypeError as exc:
            raise ToolzRouteStoreError("Toolz store cursor document rejected") from exc


@dataclass(frozen=True)
class ToolzStoreLookup:
    """One fully re-verified local lookup result."""

    context_id: str
    lifecycle: ToolzStoreLifecycle
    decision: ToolzRouteMemoryDecision
    generation: int
    receipt: dict[str, Any]
    cursor: ToolzStoreCursor


@dataclass(frozen=True)
class ToolzStoreRecovery:
    """A fully verified open store and its bounded recovery classification."""

    store: ToolzRouteMemoryStore
    cursor: ToolzStoreCursor
    status: ToolzStoreRecoveryStatus
    manifest_created_at: str


@dataclass(frozen=True)
class ToolzFeedbackDeltaEvidence:
    """Complete evidence needed to verify one Fog feedback-overlay delta."""

    delta: Mapping[str, Any]
    previous_overlay: Mapping[str, Any]
    next_overlay: Mapping[str, Any]
    snapshot: Mapping[str, Any]
    trusted_snapshot_key: TrustedKey
    trusted_sources: tuple[TrustedDiscoverySource, ...]
    trusted_previous_overlay_key: TrustedKey
    trusted_next_overlay_key: TrustedKey
    trusted_delta_key: TrustedKey
    expected_snapshot_id: str
    expected_tenant_id: str
    expected_policy: DiscoveryTheoryPolicy
    feedback_policy: DiscoveryFeedbackPolicy
    previous_feedback_evidence: tuple[TrustedDiscoveryFeedback, ...]
    next_feedback_evidence: tuple[TrustedDiscoveryFeedback, ...]
    cursor: DiscoveryFeedbackDeltaCursor

    def __post_init__(self) -> None:
        mappings = (
            self.delta,
            self.previous_overlay,
            self.next_overlay,
            self.snapshot,
        )
        keys = (
            self.trusted_snapshot_key,
            self.trusted_previous_overlay_key,
            self.trusted_next_overlay_key,
            self.trusted_delta_key,
        )
        if any(not isinstance(value, Mapping) for value in mappings):
            raise ToolzRouteStoreError("Toolz store Fog delta evidence rejected")
        if any(not isinstance(value, TrustedKey) for value in keys):
            raise ToolzRouteStoreError("Toolz store Fog delta trust rejected")
        if (
            not isinstance(self.trusted_sources, tuple)
            or not self.trusted_sources
            or any(
                not isinstance(value, TrustedDiscoverySource)
                for value in self.trusted_sources
            )
        ):
            raise ToolzRouteStoreError("Toolz store Fog delta sources rejected")
        if (
            not isinstance(self.previous_feedback_evidence, tuple)
            or not isinstance(self.next_feedback_evidence, tuple)
            or not self.previous_feedback_evidence
            or not self.next_feedback_evidence
            or any(
                not isinstance(value, TrustedDiscoveryFeedback)
                for value in (
                    *self.previous_feedback_evidence,
                    *self.next_feedback_evidence,
                )
            )
        ):
            raise ToolzRouteStoreError("Toolz store Fog feedback evidence rejected")
        if (
            self.expected_tenant_id != "tenant:public-6e3cdbebaafc8efa"
            or not isinstance(self.expected_snapshot_id, str)
            or not isinstance(self.expected_policy, DiscoveryTheoryPolicy)
            or not isinstance(self.feedback_policy, DiscoveryFeedbackPolicy)
            or not isinstance(self.cursor, DiscoveryFeedbackDeltaCursor)
        ):
            raise ToolzRouteStoreError("Toolz store Fog delta expectation rejected")


@dataclass(frozen=True)
class ToolzDeltaApplication:
    """Receipt for one verified, local-only delta application."""

    store_cursor: ToolzStoreCursor
    feedback_cursor: DiscoveryFeedbackDeltaCursor
    matched_entries: int
    invalidated_entries: int
    retained_entries: int
    authority_boundary: Mapping[str, bool]


def _manifest_core(manifest: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(manifest))
    core.pop("manifest_id", None)
    core.pop("signature", None)
    return core


def toolz_store_manifest_identity(manifest: Mapping[str, Any]) -> str:
    digest = digest_object(
        _manifest_core(manifest),
        domain="toolz-route-store-manifest-identity-v1",
    )
    return f"toolz-route-store-manifest:{digest.split(':', 1)[1]}"


def toolz_store_manifest_digest(manifest: Mapping[str, Any]) -> str:
    return digest_object(
        dict(manifest),
        domain="toolz-route-store-signed-manifest-v1",
    )


def toolz_store_context_identity(receipt: Mapping[str, Any]) -> str:
    """Return the exact local policy/tool/environment/UI context identity."""

    try:
        core = {
            "tenant_id": receipt["tenant_id"],
            "policy_id": receipt["policy_id"],
            "policy_digest": receipt["policy_digest"],
            "tool_context": deepcopy(receipt["tool_context"]),
        }
    except (KeyError, TypeError) as exc:
        raise ToolzRouteStoreError("Toolz store receipt context rejected") from exc
    digest = digest_object(core, domain="toolz-route-store-context-v1")
    return f"toolz-store-context:{digest.split(':', 1)[1]}"


def _feedback_chain_identity(cursor: DiscoveryFeedbackDeltaCursor) -> str:
    digest = digest_object(
        {
            "tenant_id": cursor.tenant_id,
            "snapshot_id": cursor.snapshot_id,
            "theory_policy_digest": cursor.theory_policy_digest,
            "feedback_policy_digest": cursor.feedback_policy_digest,
        },
        domain="toolz-store-feedback-chain-v1",
    )
    return f"toolz-feedback-chain:{digest.split(':', 1)[1]}"


def _feedback_head_from_cursor(
    cursor: DiscoveryFeedbackDeltaCursor,
) -> dict[str, Any]:
    return {
        "feedback_chain_id": _feedback_chain_identity(cursor),
        **cursor.to_document(),
    }


def _feedback_cursor_from_head(
    head: Mapping[str, Any],
) -> DiscoveryFeedbackDeltaCursor:
    fields = {
        "feedback_chain_id",
        "tenant_id",
        "snapshot_id",
        "theory_policy_digest",
        "feedback_policy_digest",
        "next_sequence",
        "current_overlay_id",
        "current_overlay_digest",
        "previous_delta_digest",
    }
    if not isinstance(head, Mapping) or set(head) != fields:
        raise ToolzRouteStoreError("Toolz store feedback head rejected")
    document = {
        field: deepcopy(value)
        for field, value in head.items()
        if field != "feedback_chain_id"
    }
    try:
        cursor = DiscoveryFeedbackDeltaCursor.from_document(document)
    except Exception as exc:
        raise ToolzRouteStoreError("Toolz store feedback head rejected") from exc
    if (
        not isinstance(head["feedback_chain_id"], str)
        or _FEEDBACK_CHAIN_ID.fullmatch(head["feedback_chain_id"]) is None
        or head["feedback_chain_id"] != _feedback_chain_identity(cursor)
    ):
        raise ToolzRouteStoreError("Toolz store feedback head identity mismatch")
    return cursor


def _freeze_json_mapping(
    value: Mapping[str, Any],
    *,
    label: str,
) -> dict[str, Any]:
    """Detach one JSON protocol object from caller-owned Mapping behavior."""

    if not isinstance(value, Mapping):
        raise ToolzRouteStoreError(f"Toolz store {label} rejected")
    try:
        detached = parse_json_strict(canonical_bytes(dict(value)))
    except Exception as exc:
        raise ToolzRouteStoreError(f"Toolz store {label} rejected") from exc
    if not isinstance(detached, dict):
        raise ToolzRouteStoreError(f"Toolz store {label} rejected")
    return detached


def _freeze_trusted_feedback(
    evidence: TrustedDiscoveryFeedback,
) -> TrustedDiscoveryFeedback:
    if not isinstance(evidence, TrustedDiscoveryFeedback):
        raise ToolzRouteStoreError("Toolz store Fog feedback evidence rejected")
    return TrustedDiscoveryFeedback(
        proposal=_freeze_json_mapping(
            evidence.proposal,
            label="Fog feedback proposal",
        ),
        receipt=_freeze_json_mapping(
            evidence.receipt,
            label="Fog feedback receipt",
        ),
        proposal_policy=evidence.proposal_policy,
        trusted_theory_key=evidence.trusted_theory_key,
        trusted_feedback_key=evidence.trusted_feedback_key,
        expected_observer_id=evidence.expected_observer_id,
    )


def _freeze_fog_evidence(
    evidence: ToolzFogRouteEvidence,
) -> ToolzFogRouteEvidence:
    if not isinstance(evidence, ToolzFogRouteEvidence):
        raise ToolzRouteStoreError("Toolz store Fog evidence rejected")
    return ToolzFogRouteEvidence(
        snapshot=_freeze_json_mapping(
            evidence.snapshot,
            label="Fog snapshot",
        ),
        route=_freeze_json_mapping(
            evidence.route,
            label="Fog route",
        ),
        trusted_snapshot_key=evidence.trusted_snapshot_key,
        trusted_sources=tuple(evidence.trusted_sources),
        trusted_theory_key=evidence.trusted_theory_key,
        expected_snapshot_id=evidence.expected_snapshot_id,
        expected_tenant_id=evidence.expected_tenant_id,
        expected_policy=evidence.expected_policy,
        overlay=(
            None
            if evidence.overlay is None
            else _freeze_json_mapping(
                evidence.overlay,
                label="Fog overlay",
            )
        ),
        trusted_overlay_key=evidence.trusted_overlay_key,
        feedback_policy=evidence.feedback_policy,
        feedback_evidence=tuple(
            _freeze_trusted_feedback(item)
            for item in evidence.feedback_evidence
        ),
    )


def _freeze_cyber_evidence(
    evidence: ToolzCyberEvidence,
) -> ToolzCyberEvidence:
    if not isinstance(evidence, ToolzCyberEvidence):
        raise ToolzRouteStoreError("Toolz store cyber evidence rejected")
    return ToolzCyberEvidence(
        decision_receipt=_freeze_json_mapping(
            evidence.decision_receipt,
            label="cyber decision",
        ),
        expected_policy=evidence.expected_policy,
        provenance_receipt=_freeze_json_mapping(
            evidence.provenance_receipt,
            label="cyber provenance",
        ),
        assessment_receipt=_freeze_json_mapping(
            evidence.assessment_receipt,
            label="cyber assessment",
        ),
        containment_receipt=(
            None
            if evidence.containment_receipt is None
            else _freeze_json_mapping(
                evidence.containment_receipt,
                label="cyber containment",
            )
        ),
        provenance_key=evidence.provenance_key,
        assessment_key=evidence.assessment_key,
        containment_key=evidence.containment_key,
        authority_key=evidence.authority_key,
    )


def _freeze_feedback_delta_evidence(
    evidence: ToolzFeedbackDeltaEvidence,
) -> ToolzFeedbackDeltaEvidence:
    if not isinstance(evidence, ToolzFeedbackDeltaEvidence):
        raise ToolzRouteStoreError("Toolz store Fog delta evidence rejected")
    return ToolzFeedbackDeltaEvidence(
        delta=_freeze_json_mapping(evidence.delta, label="Fog delta"),
        previous_overlay=_freeze_json_mapping(
            evidence.previous_overlay,
            label="previous Fog overlay",
        ),
        next_overlay=_freeze_json_mapping(
            evidence.next_overlay,
            label="next Fog overlay",
        ),
        snapshot=_freeze_json_mapping(
            evidence.snapshot,
            label="Fog delta snapshot",
        ),
        trusted_snapshot_key=evidence.trusted_snapshot_key,
        trusted_sources=tuple(evidence.trusted_sources),
        trusted_previous_overlay_key=evidence.trusted_previous_overlay_key,
        trusted_next_overlay_key=evidence.trusted_next_overlay_key,
        trusted_delta_key=evidence.trusted_delta_key,
        expected_snapshot_id=evidence.expected_snapshot_id,
        expected_tenant_id=evidence.expected_tenant_id,
        expected_policy=evidence.expected_policy,
        feedback_policy=evidence.feedback_policy,
        previous_feedback_evidence=tuple(
            _freeze_trusted_feedback(item)
            for item in evidence.previous_feedback_evidence
        ),
        next_feedback_evidence=tuple(
            _freeze_trusted_feedback(item)
            for item in evidence.next_feedback_evidence
        ),
        cursor=evidence.cursor,
    )


def _verify_entry_semantics(entry: Mapping[str, Any]) -> None:
    try:
        lifecycle = ToolzStoreLifecycle(entry["lifecycle"])
        decision = ToolzRouteMemoryDecision(entry["decision"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ToolzRouteStoreError("Toolz store entry lifecycle rejected") from exc
    if lifecycle is ToolzStoreLifecycle.INVALIDATED:
        if (
            decision is not ToolzRouteMemoryDecision.REDISCOVER
            or entry["invalidation_reason"] != "fog-feedback-delta"
        ):
            raise ToolzRouteStoreError("Toolz store invalidation state rejected")
    elif (
        _DECISION_LIFECYCLE[decision] is not lifecycle
        or entry["invalidation_reason"] is not None
    ):
        raise ToolzRouteStoreError("Toolz store entry decision mismatch")
    if (entry["generation"] == 1) != (entry["previous_receipt_digest"] is None):
        raise ToolzRouteStoreError("Toolz store entry generation chain rejected")
    feedback_bindings = (
        entry["feedback_chain_id"],
        entry["feedback_overlay_id"],
        entry["feedback_overlay_digest"],
    )
    if any(value is None for value in feedback_bindings) and not all(
        value is None for value in feedback_bindings
    ):
        raise ToolzRouteStoreError("Toolz store entry overlay binding rejected")
    if (entry["last_delta_sequence"] is None) != (
        entry["last_delta_digest"] is None
    ):
        raise ToolzRouteStoreError("Toolz store entry delta binding rejected")
    if (
        entry["last_delta_digest"] is not None
        and entry["feedback_chain_id"] is None
    ):
        raise ToolzRouteStoreError("Toolz store base route delta rejected")
    sorted_fields = (
        "dependency_record_ids",
        "dependency_zone_ids",
        "source_proposal_ids",
    )
    for field in sorted_fields:
        if entry[field] != sorted(entry[field]):
            raise ToolzRouteStoreError(f"Toolz store entry {field} order rejected")
    _parse_time(entry["updated_at"], "entry update time")


def verify_toolz_store_manifest(
    manifest: Mapping[str, Any],
    *,
    expected_store_id: str,
    expected_tenant_id: str,
    authority_key: TrustedKey,
    expected_sequence: int | None = None,
    expected_previous_digest: str | None = None,
) -> dict[str, Any]:
    """Verify schema, identity, signature, ordering and lifecycle invariants."""

    _validate_store_identity(expected_store_id, expected_tenant_id)
    if not isinstance(authority_key, TrustedKey):
        raise ToolzRouteStoreError("Toolz store manifest authority rejected")
    try:
        candidate = deepcopy(dict(manifest))
        validate("toolz-route-store-manifest", candidate)
    except (TypeError, KeyError, ValueError, ValidationError) as exc:
        raise ToolzRouteStoreError("Toolz store manifest schema rejected") from exc
    if candidate["manifest_id"] != toolz_store_manifest_identity(candidate):
        raise ToolzRouteStoreError("Toolz store manifest identity mismatch")
    if (
        candidate["signature"]["key_id"] != authority_key.key_id
        or not verify_signature(candidate, authority_key.public_key)
    ):
        raise ToolzRouteStoreError("Toolz store manifest signature rejected")
    if (
        candidate["store_id"] != expected_store_id
        or candidate["tenant_id"] != expected_tenant_id
    ):
        raise ToolzRouteStoreError("Toolz store manifest scope mismatch")
    if candidate["authority_boundary"] != _STORE_BOUNDARY:
        raise ToolzRouteStoreError("Toolz store authority boundary mismatch")
    if (candidate["sequence"] == 0) != (
        candidate["previous_manifest_digest"] is None
    ):
        raise ToolzRouteStoreError("Toolz store manifest chain rejected")
    if candidate["sequence"] == 0 and (
        candidate["entries"] or candidate["feedback_heads"]
    ):
        raise ToolzRouteStoreError("Toolz store initial manifest is not empty")
    if (
        expected_sequence is not None
        and candidate["sequence"] != expected_sequence
    ):
        raise ToolzRouteStoreError("Toolz store manifest sequence mismatch")
    if (
        expected_sequence is not None
        and candidate["previous_manifest_digest"] != expected_previous_digest
    ):
        raise ToolzRouteStoreError("Toolz store manifest previous digest mismatch")
    context_ids = [entry["context_id"] for entry in candidate["entries"]]
    receipt_digests = [entry["receipt_digest"] for entry in candidate["entries"]]
    if (
        context_ids != sorted(context_ids)
        or len(context_ids) != len(set(context_ids))
        or len(receipt_digests) != len(set(receipt_digests))
    ):
        raise ToolzRouteStoreError("Toolz store manifest entry order rejected")
    feedback_head_ids = [
        head["feedback_chain_id"] for head in candidate["feedback_heads"]
    ]
    if (
        feedback_head_ids != sorted(feedback_head_ids)
        or len(feedback_head_ids) != len(set(feedback_head_ids))
        or len(feedback_head_ids) > MAX_TOOLZ_STORE_FEEDBACK_HEADS
    ):
        raise ToolzRouteStoreError("Toolz store feedback head order rejected")
    feedback_heads: dict[str, DiscoveryFeedbackDeltaCursor] = {}
    overlay_bindings: set[tuple[str, str]] = set()
    for head in candidate["feedback_heads"]:
        cursor = _feedback_cursor_from_head(head)
        if cursor.tenant_id != expected_tenant_id:
            raise ToolzRouteStoreError("Toolz store feedback head tenant mismatch")
        overlay_binding = (
            cursor.current_overlay_id,
            cursor.current_overlay_digest,
        )
        if overlay_binding in overlay_bindings:
            raise ToolzRouteStoreError("Toolz store feedback head overlay collision")
        overlay_bindings.add(overlay_binding)
        feedback_heads[head["feedback_chain_id"]] = cursor
    created = _parse_time(candidate["created_at"], "manifest creation time")
    for entry in candidate["entries"]:
        _verify_entry_semantics(entry)
        feedback_chain_id = entry["feedback_chain_id"]
        if feedback_chain_id is not None:
            feedback_cursor = feedback_heads.get(feedback_chain_id)
            if (
                feedback_cursor is None
                or entry["feedback_overlay_id"]
                != feedback_cursor.current_overlay_id
                or entry["feedback_overlay_digest"]
                != feedback_cursor.current_overlay_digest
                or entry["last_delta_sequence"]
                != (
                    None
                    if feedback_cursor.next_sequence == 0
                    else feedback_cursor.next_sequence - 1
                )
                or entry["last_delta_digest"]
                != feedback_cursor.previous_delta_digest
            ):
                raise ToolzRouteStoreError(
                    "Toolz store entry feedback head mismatch"
                )
        if _parse_time(entry["updated_at"], "entry update time") > created:
            raise ToolzRouteStoreError("Toolz store entry is newer than manifest")
    return candidate


def _sign_manifest(
    *,
    store_id: str,
    tenant_id: str,
    sequence: int,
    previous_manifest_digest: str | None,
    entries: list[dict[str, Any]],
    feedback_heads: list[dict[str, Any]],
    created_at: str,
    signer: Ed25519Signer,
    authority_key: TrustedKey,
) -> dict[str, Any]:
    core = {
        "protocol": "integrity-guardian/toolz-route-store-manifest/v1",
        "store_id": store_id,
        "tenant_id": tenant_id,
        "sequence": sequence,
        "previous_manifest_digest": previous_manifest_digest,
        "entries": sorted(
            (deepcopy(entry) for entry in entries),
            key=lambda entry: entry["context_id"],
        ),
        "feedback_heads": sorted(
            (deepcopy(head) for head in feedback_heads),
            key=lambda head: head["feedback_chain_id"],
        ),
        "created_at": created_at,
        "authority_boundary": deepcopy(_STORE_BOUNDARY),
    }
    unsigned = {
        "manifest_id": toolz_store_manifest_identity(core),
        **core,
    }
    signed = signer.sign(unsigned)
    return verify_toolz_store_manifest(
        signed,
        expected_store_id=store_id,
        expected_tenant_id=tenant_id,
        authority_key=authority_key,
        expected_sequence=sequence,
        expected_previous_digest=previous_manifest_digest,
    )


def _prepare_store_root(root: Path, *, create: bool) -> Path:
    root = root.absolute()
    if not root.is_absolute():
        raise ToolzRouteStoreError("Toolz store root must be absolute")
    if create:
        try:
            root.mkdir(mode=0o700, parents=False, exist_ok=False)
        except OSError as exc:
            raise ToolzRouteStoreError(
                "Toolz store root must be a new private directory"
            ) from exc
    try:
        details = root.lstat()
    except OSError as exc:
        raise ToolzRouteStoreError("Toolz store root is absent") from exc
    if (
        root.is_symlink()
        or not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
    ):
        raise ToolzRouteStoreError("Toolz store root is unsafe")
    if create:
        root.chmod(0o700)
        details = root.lstat()
    if stat.S_IMODE(details.st_mode) != 0o700:
        raise ToolzRouteStoreError("Toolz store root mode mismatch")
    return root


def _prepare_database(root: Path, *, create: bool) -> Path:
    path = root / STORE_DATABASE_NAME
    if create:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise ToolzRouteStoreError("Toolz store database creation rejected") from exc
        try:
            os.fchmod(descriptor, 0o600)
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.geteuid()
                or stat.S_IMODE(details.st_mode) != 0o600
            ):
                raise ToolzRouteStoreError("Toolz store database is unsafe")
        finally:
            os.close(descriptor)
    try:
        details = path.lstat()
    except OSError as exc:
        raise ToolzRouteStoreError("Toolz store database is absent") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != 0o600
    ):
        raise ToolzRouteStoreError("Toolz store database is unsafe")
    return path


def _open_connection(path: Path) -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA trusted_schema = OFF")
        check = connection.execute("PRAGMA quick_check").fetchone()
        if check is None or check[0] != "ok":
            raise ToolzRouteStoreError("Toolz store database integrity rejected")
        return connection
    except (sqlite3.Error, ToolzRouteStoreError) as exc:
        if "connection" in locals():
            connection.close()
        if isinstance(exc, ToolzRouteStoreError):
            raise
        raise ToolzRouteStoreError("Toolz store database open rejected") from exc


_SCHEMA = """
CREATE TABLE store_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    protocol TEXT NOT NULL,
    store_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    store_key_id TEXT NOT NULL,
    store_key_fingerprint TEXT NOT NULL
);
CREATE TABLE receipt_objects (
    receipt_digest TEXT PRIMARY KEY,
    receipt_id TEXT NOT NULL UNIQUE,
    payload BLOB NOT NULL
);
CREATE TABLE manifests (
    sequence INTEGER PRIMARY KEY CHECK (sequence >= 0),
    manifest_id TEXT NOT NULL UNIQUE,
    manifest_digest TEXT NOT NULL UNIQUE,
    payload BLOB NOT NULL
);
CREATE TABLE store_head (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    sequence INTEGER NOT NULL,
    manifest_id TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    FOREIGN KEY(sequence) REFERENCES manifests(sequence)
);
"""

_TABLES = {"store_meta", "receipt_objects", "manifests", "store_head"}


class ToolzRouteMemoryStore:
    """One private, cursor-pinned local Toolz route-memory catalog."""

    def __init__(
        self,
        *,
        root: Path,
        connection: sqlite3.Connection,
        store_id: str,
        tenant_id: str,
        authority_key: TrustedKey,
    ) -> None:
        self.root = root
        self.database_path = root / STORE_DATABASE_NAME
        self.store_id = store_id
        self.tenant_id = tenant_id
        self.authority_key = authority_key
        self._connection = connection
        self._closed = False
        self._cursor: ToolzStoreCursor | None = None
        self._manifest: dict[str, Any] | None = None
        self._objects: dict[str, dict[str, Any]] = {}

    @classmethod
    def initialize(
        cls,
        root: Path,
        *,
        store_id: str,
        tenant_id: str,
        store_signer: Ed25519Signer,
        created_at: str,
    ) -> ToolzRouteMemoryStore:
        """Create a new empty store and its first externally pinnable cursor."""

        _validate_store_identity(store_id, tenant_id)
        if not isinstance(store_signer, Ed25519Signer):
            raise ToolzRouteStoreError("Toolz store signer rejected")
        _parse_time(created_at, "initialization time")
        prepared_root = _prepare_store_root(root, create=True)
        path = _prepare_database(prepared_root, create=True)
        connection = _open_connection(path)
        authority_key = TrustedKey(store_signer.key_id, store_signer.public_key)
        store = cls(
            root=prepared_root,
            connection=connection,
            store_id=store_id,
            tenant_id=tenant_id,
            authority_key=authority_key,
        )
        try:
            connection.executescript(_SCHEMA)
            initial = _sign_manifest(
                store_id=store_id,
                tenant_id=tenant_id,
                sequence=0,
                previous_manifest_digest=None,
                entries=[],
                feedback_heads=[],
                created_at=created_at,
                signer=store_signer,
                authority_key=authority_key,
            )
            initial_digest = toolz_store_manifest_digest(initial)
            with connection:
                connection.execute(
                    """
                    INSERT INTO store_meta(
                        singleton, protocol, store_id, tenant_id,
                        store_key_id, store_key_fingerprint
                    ) VALUES(
                        1, 'integrity-guardian/toolz-route-store/v1', ?, ?, ?, ?
                    )
                    """,
                    (
                        store_id,
                        tenant_id,
                        authority_key.key_id,
                        public_key_fingerprint(authority_key.public_key),
                    ),
                )
                store._store_manifest(initial)
                store._set_head(initial, initial_digest)
            expected = ToolzStoreCursor(
                store_id=store_id,
                tenant_id=tenant_id,
                sequence=0,
                manifest_id=initial["manifest_id"],
                manifest_digest=initial_digest,
            )
            store._refresh(expected)
            return store
        except Exception:
            connection.close()
            store._closed = True
            raise

    @classmethod
    def open(
        cls,
        root: Path,
        *,
        store_id: str,
        tenant_id: str,
        authority_key: TrustedKey,
        expected_cursor: ToolzStoreCursor,
    ) -> ToolzRouteMemoryStore:
        """Open only the exact externally pinned store head."""

        _validate_store_identity(store_id, tenant_id)
        if not isinstance(authority_key, TrustedKey):
            raise ToolzRouteStoreError("Toolz store authority rejected")
        if not isinstance(expected_cursor, ToolzStoreCursor):
            raise ToolzRouteStoreError("Toolz store rollback cursor is required")
        prepared_root = _prepare_store_root(root, create=False)
        path = _prepare_database(prepared_root, create=False)
        connection = _open_connection(path)
        store = cls(
            root=prepared_root,
            connection=connection,
            store_id=store_id,
            tenant_id=tenant_id,
            authority_key=authority_key,
        )
        try:
            store._refresh(expected_cursor)
            return store
        except Exception:
            connection.close()
            store._closed = True
            raise

    @classmethod
    def recover_one_step_install(
        cls,
        root: Path,
        *,
        store_id: str,
        tenant_id: str,
        authority_key: TrustedKey,
        retained_cursor: ToolzStoreCursor,
        receipt: Mapping[str, Any],
        expected_policy: ToolzRouteMemoryPolicy,
        fog_evidence: ToolzFogRouteEvidence,
        cyber_evidence: ToolzCyberEvidence,
        memory_key: TrustedKey,
        evaluated_at: str,
    ) -> ToolzStoreRecovery:
        """Open only an unchanged head or one exact theoretical install child."""

        _validate_store_identity(store_id, tenant_id)
        if not isinstance(authority_key, TrustedKey) or not isinstance(
            memory_key,
            TrustedKey,
        ):
            raise ToolzRouteStoreError("Toolz store recovery trust rejected")
        if (
            not isinstance(retained_cursor, ToolzStoreCursor)
            or retained_cursor.store_id != store_id
            or retained_cursor.tenant_id != tenant_id
        ):
            raise ToolzRouteStoreError("Toolz store recovery cursor rejected")
        stable_receipt = _freeze_json_mapping(
            receipt,
            label="recovery route-memory receipt",
        )
        stable_fog = _freeze_fog_evidence(fog_evidence)
        stable_cyber = _freeze_cyber_evidence(cyber_evidence)
        verified = verify_toolz_route_memory_receipt(
            stable_receipt,
            expected_policy=expected_policy,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            authority_key=memory_key,
        )
        if verified["observation"] != {
            "outcome": ToolzRouteMemoryOutcome.THEORETICAL.value,
            "observed_at": None,
            "evidence_digest": None,
        }:
            raise ToolzRouteStoreError(
                "Toolz store recovery non-theoretical receipt rejected"
            )
        if (
            evaluate_toolz_route_memory(
                verified,
                expected_policy=expected_policy,
                fog_evidence=stable_fog,
                cyber_evidence=stable_cyber,
                authority_key=memory_key,
                evaluated_at=evaluated_at,
            )
            is not ToolzRouteMemoryDecision.EXPLORE
        ):
            raise ToolzRouteStoreError(
                "Toolz store recovery memory decision rejected"
            )

        prepared_root = _prepare_store_root(root, create=False)
        path = _prepare_database(prepared_root, create=False)
        connection = _open_connection(path)
        store = cls(
            root=prepared_root,
            connection=connection,
            store_id=store_id,
            tenant_id=tenant_id,
            authority_key=authority_key,
        )
        try:
            connection.execute("BEGIN")
            cursor, current, objects, manifests = store._verified_state()
            if _parse_time(
                current["created_at"],
                "recovery manifest creation time",
            ) > _parse_time(
                evaluated_at,
                "recovery evaluation time",
            ):
                raise ToolzRouteStoreError(
                    "Toolz store recovery manifest timing rejected"
                )
            if retained_cursor.sequence >= len(manifests):
                raise ToolzRouteStoreError(
                    "Toolz store recovery anchor is absent"
                )
            anchor = manifests[retained_cursor.sequence]
            anchor_digest = toolz_store_manifest_digest(anchor)
            if (
                anchor["manifest_id"] != retained_cursor.manifest_id
                or anchor_digest != retained_cursor.manifest_digest
            ):
                raise ToolzRouteStoreError(
                    "Toolz store recovery anchor mismatch"
                )
            if cursor == retained_cursor:
                status = ToolzStoreRecoveryStatus.RETAINED_HEAD
            else:
                if cursor.sequence != retained_cursor.sequence + 1:
                    raise ToolzRouteStoreError(
                        "Toolz store recovery descendant distance rejected"
                    )
                store._verify_one_step_install_delta(
                    before=anchor,
                    after=current,
                    receipt=verified,
                    fog_evidence=stable_fog,
                    objects=objects,
                    evaluated_at=evaluated_at,
                )
                status = ToolzStoreRecoveryStatus.RECOVERED_INSTALL
            store._activate_verified_state(cursor, current, objects)
            if status is ToolzStoreRecoveryStatus.RECOVERED_INSTALL:
                context_id = toolz_store_context_identity(verified)
                lookup = store.lookup(
                    context_id,
                    expected_cursor=cursor,
                    expected_policy=expected_policy,
                    fog_evidence=stable_fog,
                    cyber_evidence=stable_cyber,
                    memory_key=memory_key,
                    evaluated_at=evaluated_at,
                )
                if (
                    lookup is None
                    or lookup.lifecycle is not ToolzStoreLifecycle.THEORETICAL
                    or lookup.decision is not ToolzRouteMemoryDecision.EXPLORE
                    or toolz_route_memory_digest(lookup.receipt)
                    != toolz_route_memory_digest(verified)
                ):
                    raise ToolzRouteStoreError(
                        "Toolz store recovery post-check rejected"
                    )
            connection.commit()
            return ToolzStoreRecovery(
                store=store,
                cursor=cursor,
                status=status,
                manifest_created_at=current["created_at"],
            )
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            connection.close()
            store._closed = True
            raise

    @classmethod
    def recover_one_step_feedback_install(
        cls,
        root: Path,
        *,
        store_id: str,
        tenant_id: str,
        authority_key: TrustedKey,
        retained_cursor: ToolzStoreCursor,
        theoretical_receipt: Mapping[str, Any],
        observed_receipt: Mapping[str, Any],
        expected_policy: ToolzRouteMemoryPolicy,
        fog_evidence: ToolzFogRouteEvidence,
        cyber_evidence: ToolzCyberEvidence,
        memory_key: TrustedKey,
        feedback_created_at: str,
        evaluated_at: str,
    ) -> ToolzStoreRecovery:
        """Open an exact predecessor head or its sole feedback-promotion child."""

        _validate_store_identity(store_id, tenant_id)
        if not isinstance(authority_key, TrustedKey) or not isinstance(
            memory_key,
            TrustedKey,
        ):
            raise ToolzRouteStoreError("Toolz store feedback recovery trust rejected")
        if (
            not isinstance(retained_cursor, ToolzStoreCursor)
            or retained_cursor.store_id != store_id
            or retained_cursor.tenant_id != tenant_id
        ):
            raise ToolzRouteStoreError("Toolz store feedback recovery cursor rejected")
        stable_theoretical = _freeze_json_mapping(
            theoretical_receipt,
            label="feedback recovery theoretical receipt",
        )
        stable_observed = _freeze_json_mapping(
            observed_receipt,
            label="feedback recovery observed receipt",
        )
        stable_fog = _freeze_fog_evidence(fog_evidence)
        stable_cyber = _freeze_cyber_evidence(cyber_evidence)
        theoretical = verify_toolz_route_memory_receipt(
            stable_theoretical,
            expected_policy=expected_policy,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            authority_key=memory_key,
        )
        observed = verify_toolz_route_memory_receipt(
            stable_observed,
            expected_policy=expected_policy,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            authority_key=memory_key,
        )
        if theoretical["observation"] != {
            "outcome": ToolzRouteMemoryOutcome.THEORETICAL.value,
            "observed_at": None,
            "evidence_digest": None,
        }:
            raise ToolzRouteStoreError(
                "Toolz store feedback recovery theoretical receipt rejected"
            )
        if observed["observation"]["outcome"] != (
            ToolzRouteMemoryOutcome.OBSERVED_SUCCESS.value
        ):
            raise ToolzRouteStoreError(
                "Toolz store feedback recovery observed receipt rejected"
            )
        if toolz_store_context_identity(theoretical) != toolz_store_context_identity(
            observed
        ):
            raise ToolzRouteStoreError(
                "Toolz store feedback recovery context mismatch"
            )
        if (
            evaluate_toolz_route_memory(
                theoretical,
                expected_policy=expected_policy,
                fog_evidence=stable_fog,
                cyber_evidence=stable_cyber,
                authority_key=memory_key,
                evaluated_at=evaluated_at,
            )
            is not ToolzRouteMemoryDecision.EXPLORE
            or evaluate_toolz_route_memory(
                observed,
                expected_policy=expected_policy,
                fog_evidence=stable_fog,
                cyber_evidence=stable_cyber,
                authority_key=memory_key,
                evaluated_at=evaluated_at,
            )
            is not ToolzRouteMemoryDecision.REUSE_CANDIDATE
        ):
            raise ToolzRouteStoreError(
                "Toolz store feedback recovery memory decision rejected"
            )

        prepared_root = _prepare_store_root(root, create=False)
        path = _prepare_database(prepared_root, create=False)
        connection = _open_connection(path)
        store = cls(
            root=prepared_root,
            connection=connection,
            store_id=store_id,
            tenant_id=tenant_id,
            authority_key=authority_key,
        )
        try:
            connection.execute("BEGIN")
            cursor, current, objects, manifests = store._verified_state()
            if _parse_time(
                current["created_at"],
                "feedback recovery manifest creation time",
            ) > _parse_time(
                evaluated_at,
                "feedback recovery evaluation time",
            ):
                raise ToolzRouteStoreError(
                    "Toolz store feedback recovery manifest timing rejected"
                )
            if retained_cursor.sequence >= len(manifests):
                raise ToolzRouteStoreError(
                    "Toolz store feedback recovery anchor is absent"
                )
            anchor = manifests[retained_cursor.sequence]
            anchor_digest = toolz_store_manifest_digest(anchor)
            if (
                anchor["manifest_id"] != retained_cursor.manifest_id
                or anchor_digest != retained_cursor.manifest_digest
            ):
                raise ToolzRouteStoreError(
                    "Toolz store feedback recovery anchor mismatch"
                )
            store._verify_feedback_predecessor(
                manifest=anchor,
                receipt=theoretical,
                fog_evidence=stable_fog,
                objects=objects,
            )
            if cursor == retained_cursor:
                status = ToolzStoreRecoveryStatus.RETAINED_HEAD
            else:
                if cursor.sequence != retained_cursor.sequence + 1:
                    raise ToolzRouteStoreError(
                        "Toolz store feedback recovery descendant distance rejected"
                    )
                store._verify_one_step_feedback_install_delta(
                    before=anchor,
                    after=current,
                    theoretical_receipt=theoretical,
                    observed_receipt=observed,
                    fog_evidence=stable_fog,
                    objects=objects,
                    feedback_created_at=feedback_created_at,
                    evaluated_at=evaluated_at,
                )
                status = ToolzStoreRecoveryStatus.RECOVERED_FEEDBACK_INSTALL
            store._activate_verified_state(cursor, current, objects)
            lookup_receipt = (
                theoretical
                if status is ToolzStoreRecoveryStatus.RETAINED_HEAD
                else observed
            )
            lookup = store.lookup(
                toolz_store_context_identity(lookup_receipt),
                expected_cursor=cursor,
                expected_policy=expected_policy,
                fog_evidence=stable_fog,
                cyber_evidence=stable_cyber,
                memory_key=memory_key,
                evaluated_at=evaluated_at,
            )
            expected_lifecycle = (
                ToolzStoreLifecycle.THEORETICAL
                if status is ToolzStoreRecoveryStatus.RETAINED_HEAD
                else ToolzStoreLifecycle.REUSABLE
            )
            expected_decision = (
                ToolzRouteMemoryDecision.EXPLORE
                if status is ToolzStoreRecoveryStatus.RETAINED_HEAD
                else ToolzRouteMemoryDecision.REUSE_CANDIDATE
            )
            expected_generation = (
                1
                if status is ToolzStoreRecoveryStatus.RETAINED_HEAD
                else 2
            )
            if (
                lookup is None
                or lookup.generation != expected_generation
                or lookup.lifecycle is not expected_lifecycle
                or lookup.decision is not expected_decision
                or toolz_route_memory_digest(lookup.receipt)
                != toolz_route_memory_digest(lookup_receipt)
            ):
                raise ToolzRouteStoreError(
                    "Toolz store feedback recovery post-check rejected"
                )
            connection.commit()
            return ToolzStoreRecovery(
                store=store,
                cursor=cursor,
                status=status,
                manifest_created_at=current["created_at"],
            )
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            connection.close()
            store._closed = True
            raise

    @property
    def cursor(self) -> ToolzStoreCursor:
        if self._closed or self._cursor is None:
            raise ToolzRouteStoreError("Toolz store is closed")
        return self._cursor

    def close(self) -> None:
        if not self._closed:
            self._connection.close()
            self._closed = True

    def __enter__(self) -> Self:
        if self._closed:
            raise ToolzRouteStoreError("Toolz store is closed")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _assert_open(self) -> None:
        if self._closed:
            raise ToolzRouteStoreError("Toolz store is closed")

    def _assert_tables(self) -> None:
        rows = self._connection.execute(
            """
            SELECT name, type FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
        tables = {row["name"] for row in rows if row["type"] == "table"}
        if tables != _TABLES or any(row["type"] != "table" for row in rows):
            raise ToolzRouteStoreError("Toolz store database schema rejected")

    def _assert_meta(self) -> None:
        row = self._connection.execute(
            """
            SELECT protocol, store_id, tenant_id, store_key_id,
                   store_key_fingerprint
            FROM store_meta WHERE singleton = 1
            """
        ).fetchone()
        if row is None:
            raise ToolzRouteStoreError("Toolz store metadata is absent")
        expected = {
            "protocol": "integrity-guardian/toolz-route-store/v1",
            "store_id": self.store_id,
            "tenant_id": self.tenant_id,
            "store_key_id": self.authority_key.key_id,
            "store_key_fingerprint": public_key_fingerprint(
                self.authority_key.public_key
            ),
        }
        if dict(row) != expected:
            raise ToolzRouteStoreError("Toolz store metadata mismatch")
        count = self._connection.execute(
            "SELECT COUNT(*) FROM store_meta"
        ).fetchone()[0]
        if count != 1:
            raise ToolzRouteStoreError("Toolz store metadata cardinality rejected")

    @staticmethod
    def _parse_canonical_object(payload: object, *, label: str) -> dict[str, Any]:
        if not isinstance(payload, bytes):
            raise ToolzRouteStoreError(f"Toolz store {label} payload rejected")
        try:
            parsed = parse_json_strict(payload)
        except Exception as exc:
            raise ToolzRouteStoreError(
                f"Toolz store {label} JSON rejected"
            ) from exc
        if not isinstance(parsed, dict) or canonical_bytes(parsed) != payload:
            raise ToolzRouteStoreError(
                f"Toolz store {label} canonical bytes rejected"
            )
        return parsed

    def _load_receipt_objects(self) -> dict[str, dict[str, Any]]:
        objects: dict[str, dict[str, Any]] = {}
        rows = self._connection.execute(
            """
            SELECT receipt_digest, receipt_id, payload
            FROM receipt_objects ORDER BY receipt_digest
            """
        ).fetchall()
        for row in rows:
            receipt = self._parse_canonical_object(
                row["payload"],
                label="receipt object",
            )
            try:
                validate("toolz-route-memory-receipt", receipt)
            except Exception as exc:
                raise ToolzRouteStoreError(
                    "Toolz store receipt schema rejected"
                ) from exc
            digest = toolz_route_memory_digest(receipt)
            if (
                row["receipt_digest"] != digest
                or row["receipt_id"] != receipt.get("receipt_id")
                or receipt["receipt_id"] != toolz_route_memory_identity(receipt)
            ):
                raise ToolzRouteStoreError(
                    "Toolz store receipt content address mismatch"
                )
            objects[digest] = receipt
        return objects

    def _load_manifest_chain(self) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            """
            SELECT sequence, manifest_id, manifest_digest, payload
            FROM manifests ORDER BY sequence
            """
        ).fetchall()
        if not rows:
            raise ToolzRouteStoreError("Toolz store manifest chain is empty")
        manifests: list[dict[str, Any]] = []
        previous_digest: str | None = None
        for expected_sequence, row in enumerate(rows):
            if row["sequence"] != expected_sequence:
                raise ToolzRouteStoreError(
                    "Toolz store manifest sequence discontinuity"
                )
            manifest = self._parse_canonical_object(
                row["payload"],
                label="manifest",
            )
            verified = verify_toolz_store_manifest(
                manifest,
                expected_store_id=self.store_id,
                expected_tenant_id=self.tenant_id,
                authority_key=self.authority_key,
                expected_sequence=expected_sequence,
                expected_previous_digest=previous_digest,
            )
            digest = toolz_store_manifest_digest(verified)
            if (
                row["manifest_id"] != verified["manifest_id"]
                or row["manifest_digest"] != digest
            ):
                raise ToolzRouteStoreError(
                    "Toolz store manifest content address mismatch"
                )
            if manifests and _parse_time(
                verified["created_at"],
                "manifest creation time",
            ) < _parse_time(
                manifests[-1]["created_at"],
                "previous manifest creation time",
            ):
                raise ToolzRouteStoreError("Toolz store manifest clock rollback")
            manifests.append(verified)
            previous_digest = digest
        return manifests

    def _load_head(self) -> sqlite3.Row:
        row = self._connection.execute(
            """
            SELECT sequence, manifest_id, manifest_digest
            FROM store_head WHERE singleton = 1
            """
        ).fetchone()
        count = self._connection.execute(
            "SELECT COUNT(*) FROM store_head"
        ).fetchone()[0]
        if row is None or count != 1:
            raise ToolzRouteStoreError("Toolz store head rejected")
        return row

    @staticmethod
    def _entry_matches_receipt(
        entry: Mapping[str, Any],
        receipt: Mapping[str, Any],
    ) -> None:
        expected = {
            "context_id": toolz_store_context_identity(receipt),
            "receipt_id": receipt["receipt_id"],
            "receipt_digest": toolz_route_memory_digest(receipt),
            "route_proposal_id": receipt["fog_route"]["proposal_id"],
            "dependency_zone_ids": sorted(
                receipt["fog_route"]["invalidation_zone_ids"]
            ),
        }
        for field, value in expected.items():
            if entry[field] != value:
                raise ToolzRouteStoreError(
                    f"Toolz store entry {field} content mismatch"
                )

    def _verified_state(
        self,
    ) -> tuple[
        ToolzStoreCursor,
        dict[str, Any],
        dict[str, dict[str, Any]],
        list[dict[str, Any]],
    ]:
        self._assert_open()
        self._assert_tables()
        self._assert_meta()
        objects = self._load_receipt_objects()
        manifests = self._load_manifest_chain()
        head = self._load_head()
        current = manifests[-1]
        current_digest = toolz_store_manifest_digest(current)
        if (
            head["sequence"] != current["sequence"]
            or head["manifest_id"] != current["manifest_id"]
            or head["manifest_digest"] != current_digest
        ):
            raise ToolzRouteStoreError("Toolz store head/manifest mismatch")
        cursor = ToolzStoreCursor(
            store_id=self.store_id,
            tenant_id=self.tenant_id,
            sequence=current["sequence"],
            manifest_id=current["manifest_id"],
            manifest_digest=current_digest,
        )
        referenced = {
            entry["receipt_digest"]
            for manifest in manifests
            for entry in manifest["entries"]
        }
        if referenced != set(objects):
            raise ToolzRouteStoreError("Toolz store object reachability mismatch")
        for entry in current["entries"]:
            receipt = objects.get(entry["receipt_digest"])
            if receipt is None:
                raise ToolzRouteStoreError("Toolz store current receipt is absent")
            self._entry_matches_receipt(entry, receipt)
        return cursor, current, objects, manifests

    def _activate_verified_state(
        self,
        cursor: ToolzStoreCursor,
        manifest: Mapping[str, Any],
        objects: Mapping[str, Mapping[str, Any]],
    ) -> None:
        self._cursor = cursor
        self._manifest = deepcopy(dict(manifest))
        self._objects = {
            digest: deepcopy(dict(receipt))
            for digest, receipt in objects.items()
        }

    def _refresh(self, expected_cursor: ToolzStoreCursor) -> None:
        cursor, current, objects, _ = self._verified_state()
        if cursor != expected_cursor:
            raise ToolzRouteStoreError(
                "Toolz store rollback or concurrent head change rejected"
            )
        self._activate_verified_state(cursor, current, objects)

    def verify(self, *, expected_cursor: ToolzStoreCursor) -> dict[str, Any]:
        """Verify the complete stored chain against an external rollback pin."""

        if not isinstance(expected_cursor, ToolzStoreCursor):
            raise ToolzRouteStoreError("Toolz store rollback cursor is required")
        self._refresh(expected_cursor)
        return {
            "ok": True,
            "store_id": self.store_id,
            "tenant_id": self.tenant_id,
            "sequence": self.cursor.sequence,
            "entry_count": len(self._manifest["entries"]),
            "object_count": len(self._objects),
            "rollback_cursor_verified": True,
            "authority_boundary": deepcopy(_STORE_BOUNDARY),
        }

    def entries(
        self,
        *,
        expected_cursor: ToolzStoreCursor,
    ) -> list[dict[str, Any]]:
        self._refresh(expected_cursor)
        return deepcopy(self._manifest["entries"])

    def _assert_signer(self, signer: Ed25519Signer) -> None:
        if (
            not isinstance(signer, Ed25519Signer)
            or signer.key_id != self.authority_key.key_id
            or public_key_fingerprint(signer.public_key)
            != public_key_fingerprint(self.authority_key.public_key)
        ):
            raise ToolzRouteStoreError("Toolz store signer mismatch")

    def _store_receipt_object(self, receipt: Mapping[str, Any]) -> None:
        payload = canonical_bytes(receipt)
        digest = toolz_route_memory_digest(receipt)
        self._connection.execute(
            """
            INSERT OR IGNORE INTO receipt_objects(
                receipt_digest, receipt_id, payload
            ) VALUES(?, ?, ?)
            """,
            (digest, receipt["receipt_id"], payload),
        )
        row = self._connection.execute(
            """
            SELECT receipt_id, payload FROM receipt_objects
            WHERE receipt_digest = ?
            """,
            (digest,),
        ).fetchone()
        if (
            row is None
            or row["receipt_id"] != receipt["receipt_id"]
            or row["payload"] != payload
        ):
            raise ToolzRouteStoreError("Toolz store receipt identity collision")

    def _store_manifest(self, manifest: Mapping[str, Any]) -> None:
        self._connection.execute(
            """
            INSERT INTO manifests(sequence, manifest_id, manifest_digest, payload)
            VALUES(?, ?, ?, ?)
            """,
            (
                manifest["sequence"],
                manifest["manifest_id"],
                toolz_store_manifest_digest(manifest),
                canonical_bytes(manifest),
            ),
        )

    def _set_head(self, manifest: Mapping[str, Any], digest: str) -> None:
        self._connection.execute(
            """
            INSERT INTO store_head(
                singleton, sequence, manifest_id, manifest_digest
            ) VALUES(1, ?, ?, ?)
            ON CONFLICT(singleton) DO UPDATE SET
                sequence = excluded.sequence,
                manifest_id = excluded.manifest_id,
                manifest_digest = excluded.manifest_digest
            """,
            (manifest["sequence"], manifest["manifest_id"], digest),
        )

    def _transaction_current(
        self,
        expected_cursor: ToolzStoreCursor,
    ) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
        if not isinstance(expected_cursor, ToolzStoreCursor):
            raise ToolzRouteStoreError("Toolz store rollback cursor is required")
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._refresh(expected_cursor)
            return deepcopy(self._manifest), deepcopy(self._objects)
        except Exception:
            self._connection.rollback()
            raise

    def _commit_transition(
        self,
        *,
        expected_cursor: ToolzStoreCursor,
        manifest: dict[str, Any],
        receipt: Mapping[str, Any] | None,
    ) -> ToolzStoreCursor:
        try:
            if receipt is not None:
                self._store_receipt_object(receipt)
            self._store_manifest(manifest)
            digest = toolz_store_manifest_digest(manifest)
            self._set_head(manifest, digest)
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        cursor = ToolzStoreCursor(
            store_id=self.store_id,
            tenant_id=self.tenant_id,
            sequence=manifest["sequence"],
            manifest_id=manifest["manifest_id"],
            manifest_digest=toolz_store_manifest_digest(manifest),
        )
        self._refresh(cursor)
        return cursor

    @staticmethod
    def _feedback_heads(
        manifest: Mapping[str, Any],
    ) -> dict[str, dict[str, Any]]:
        return {
            head["feedback_chain_id"]: deepcopy(head)
            for head in manifest["feedback_heads"]
        }

    @staticmethod
    def _fog_feedback_cursor(
        fog_evidence: ToolzFogRouteEvidence,
    ) -> DiscoveryFeedbackDeltaCursor | None:
        if fog_evidence.overlay is None:
            return None
        try:
            return DiscoveryFeedbackDeltaCursor.from_overlay(
                fog_evidence.overlay
            )
        except Exception as exc:
            raise ToolzRouteStoreError(
                "Toolz store Fog feedback cursor rejected"
            ) from exc

    @staticmethod
    def _route_dependencies(
        fog_evidence: ToolzFogRouteEvidence,
    ) -> tuple[list[str], list[str], list[str]]:
        try:
            record_ids = sorted(
                {hop["record_id"] for hop in fog_evidence.route["hops"]}
            )
            zone_ids = sorted(
                set(fog_evidence.route["invalidation_zone_ids"])
            )
            if fog_evidence.route["protocol"] == (
                "integrity-guardian/discovery-feedback-ranked-route/v1"
            ):
                proposal_ids = sorted(
                    {
                        evidence.proposal["proposal_id"]
                        for evidence in fog_evidence.feedback_evidence
                    }
                )
            else:
                proposal_ids = [fog_evidence.route["proposal_id"]]
        except (KeyError, TypeError) as exc:
            raise ToolzRouteStoreError(
                "Toolz store route dependencies rejected"
            ) from exc
        if not proposal_ids:
            raise ToolzRouteStoreError("Toolz store source proposals are empty")
        return record_ids, zone_ids, proposal_ids

    def _verify_one_step_install_delta(
        self,
        *,
        before: Mapping[str, Any],
        after: Mapping[str, Any],
        receipt: Mapping[str, Any],
        fog_evidence: ToolzFogRouteEvidence,
        objects: Mapping[str, Mapping[str, Any]],
        evaluated_at: str,
    ) -> None:
        context_id = toolz_store_context_identity(receipt)
        receipt_digest = toolz_route_memory_digest(receipt)
        before_entries = {
            entry["context_id"]: deepcopy(entry)
            for entry in before["entries"]
        }
        after_entries = {
            entry["context_id"]: deepcopy(entry)
            for entry in after["entries"]
        }
        if (
            context_id in before_entries
            or set(after_entries) != {*before_entries, context_id}
        ):
            raise ToolzRouteStoreError(
                "Toolz store recovery entry delta rejected"
            )
        for existing_context, entry in before_entries.items():
            if after_entries[existing_context] != entry:
                raise ToolzRouteStoreError(
                    "Toolz store recovery unrelated entry change rejected"
                )

        record_ids, zone_ids, proposal_ids = self._route_dependencies(
            fog_evidence
        )
        feedback_cursor = self._fog_feedback_cursor(fog_evidence)
        feedback_chain_id = (
            None
            if feedback_cursor is None
            else _feedback_chain_identity(feedback_cursor)
        )
        expected_entry = {
            "context_id": context_id,
            "generation": 1,
            "receipt_id": receipt["receipt_id"],
            "receipt_digest": receipt_digest,
            "previous_receipt_digest": None,
            "route_proposal_id": receipt["fog_route"]["proposal_id"],
            "lifecycle": ToolzStoreLifecycle.THEORETICAL.value,
            "decision": ToolzRouteMemoryDecision.EXPLORE.value,
            "dependency_record_ids": record_ids,
            "dependency_zone_ids": zone_ids,
            "source_proposal_ids": proposal_ids,
            "feedback_chain_id": feedback_chain_id,
            "feedback_overlay_id": receipt["fog_route"][
                "feedback_overlay_id"
            ],
            "feedback_overlay_digest": receipt["fog_route"][
                "feedback_overlay_digest"
            ],
            "last_delta_sequence": (
                None
                if feedback_cursor is None
                or feedback_cursor.next_sequence == 0
                else feedback_cursor.next_sequence - 1
            ),
            "last_delta_digest": (
                None
                if feedback_cursor is None
                else feedback_cursor.previous_delta_digest
            ),
            "invalidation_reason": None,
            "updated_at": after["created_at"],
        }
        if after_entries[context_id] != expected_entry:
            raise ToolzRouteStoreError(
                "Toolz store recovery installed entry mismatch"
            )
        if objects.get(receipt_digest) != receipt:
            raise ToolzRouteStoreError(
                "Toolz store recovery receipt object mismatch"
            )
        receipt_created = _parse_time(
            receipt["created_at"],
            "recovery receipt creation time",
        )
        receipt_expires = _parse_time(
            receipt["expires_at"],
            "recovery receipt expiry",
        )
        manifest_created = _parse_time(
            after["created_at"],
            "recovery manifest creation time",
        )
        recovery_evaluated = _parse_time(
            evaluated_at,
            "recovery evaluation time",
        )
        if not (
            receipt_created
            <= manifest_created
            <= recovery_evaluated
            < receipt_expires
        ):
            raise ToolzRouteStoreError(
                "Toolz store recovery manifest timing rejected"
            )

        before_heads = self._feedback_heads(before)
        expected_heads = deepcopy(before_heads)
        if feedback_cursor is not None:
            expected_head = _feedback_head_from_cursor(feedback_cursor)
            existing_head = expected_heads.get(feedback_chain_id)
            if existing_head is None:
                expected_heads[feedback_chain_id] = expected_head
            elif existing_head != expected_head:
                raise ToolzRouteStoreError(
                    "Toolz store recovery feedback anchor mismatch"
                )
        if self._feedback_heads(after) != expected_heads:
            raise ToolzRouteStoreError(
                "Toolz store recovery unrelated feedback change rejected"
            )

    def _feedback_recovery_entry(
        self,
        *,
        receipt: Mapping[str, Any],
        fog_evidence: ToolzFogRouteEvidence,
        generation: int,
        previous_receipt_digest: str | None,
        lifecycle: ToolzStoreLifecycle,
        decision: ToolzRouteMemoryDecision,
        updated_at: str,
    ) -> dict[str, Any]:
        record_ids, zone_ids, proposal_ids = self._route_dependencies(
            fog_evidence
        )
        feedback_cursor = self._fog_feedback_cursor(fog_evidence)
        return {
            "context_id": toolz_store_context_identity(receipt),
            "generation": generation,
            "receipt_id": receipt["receipt_id"],
            "receipt_digest": toolz_route_memory_digest(receipt),
            "previous_receipt_digest": previous_receipt_digest,
            "route_proposal_id": receipt["fog_route"]["proposal_id"],
            "lifecycle": lifecycle.value,
            "decision": decision.value,
            "dependency_record_ids": record_ids,
            "dependency_zone_ids": zone_ids,
            "source_proposal_ids": proposal_ids,
            "feedback_chain_id": (
                None
                if feedback_cursor is None
                else _feedback_chain_identity(feedback_cursor)
            ),
            "feedback_overlay_id": receipt["fog_route"][
                "feedback_overlay_id"
            ],
            "feedback_overlay_digest": receipt["fog_route"][
                "feedback_overlay_digest"
            ],
            "last_delta_sequence": (
                None
                if feedback_cursor is None
                or feedback_cursor.next_sequence == 0
                else feedback_cursor.next_sequence - 1
            ),
            "last_delta_digest": (
                None
                if feedback_cursor is None
                else feedback_cursor.previous_delta_digest
            ),
            "invalidation_reason": None,
            "updated_at": updated_at,
        }

    def _verify_feedback_predecessor(
        self,
        *,
        manifest: Mapping[str, Any],
        receipt: Mapping[str, Any],
        fog_evidence: ToolzFogRouteEvidence,
        objects: Mapping[str, Mapping[str, Any]],
    ) -> None:
        context_id = toolz_store_context_identity(receipt)
        entries = {
            entry["context_id"]: deepcopy(entry)
            for entry in manifest["entries"]
        }
        entry = entries.get(context_id)
        if entry is None:
            raise ToolzRouteStoreError(
                "Toolz store feedback recovery predecessor mismatch"
            )
        expected = self._feedback_recovery_entry(
            receipt=receipt,
            fog_evidence=fog_evidence,
            generation=1,
            previous_receipt_digest=None,
            lifecycle=ToolzStoreLifecycle.THEORETICAL,
            decision=ToolzRouteMemoryDecision.EXPLORE,
            updated_at=entry["updated_at"],
        )
        if entry != expected:
            raise ToolzRouteStoreError(
                "Toolz store feedback recovery predecessor mismatch"
            )
        receipt_created = _parse_time(
            receipt["created_at"],
            "feedback recovery predecessor creation time",
        )
        entry_updated = _parse_time(
            entry["updated_at"],
            "feedback recovery predecessor update time",
        )
        manifest_created = _parse_time(
            manifest["created_at"],
            "feedback recovery predecessor manifest time",
        )
        if not receipt_created <= entry_updated <= manifest_created:
            raise ToolzRouteStoreError(
                "Toolz store feedback recovery predecessor timing rejected"
            )
        receipt_digest = toolz_route_memory_digest(receipt)
        if objects.get(receipt_digest) != receipt:
            raise ToolzRouteStoreError(
                "Toolz store feedback recovery predecessor object mismatch"
            )

    def _verify_one_step_feedback_install_delta(
        self,
        *,
        before: Mapping[str, Any],
        after: Mapping[str, Any],
        theoretical_receipt: Mapping[str, Any],
        observed_receipt: Mapping[str, Any],
        fog_evidence: ToolzFogRouteEvidence,
        objects: Mapping[str, Mapping[str, Any]],
        feedback_created_at: str,
        evaluated_at: str,
    ) -> None:
        context_id = toolz_store_context_identity(theoretical_receipt)
        before_entries = {
            entry["context_id"]: deepcopy(entry)
            for entry in before["entries"]
        }
        after_entries = {
            entry["context_id"]: deepcopy(entry)
            for entry in after["entries"]
        }
        if set(after_entries) != set(before_entries):
            raise ToolzRouteStoreError(
                "Toolz store feedback recovery entry delta rejected"
            )
        for existing_context, entry in before_entries.items():
            if (
                existing_context != context_id
                and after_entries[existing_context] != entry
            ):
                raise ToolzRouteStoreError(
                    "Toolz store feedback recovery unrelated entry change rejected"
                )
        expected = self._feedback_recovery_entry(
            receipt=observed_receipt,
            fog_evidence=fog_evidence,
            generation=2,
            previous_receipt_digest=toolz_route_memory_digest(
                theoretical_receipt
            ),
            lifecycle=ToolzStoreLifecycle.REUSABLE,
            decision=ToolzRouteMemoryDecision.REUSE_CANDIDATE,
            updated_at=after["created_at"],
        )
        if after_entries.get(context_id) != expected:
            raise ToolzRouteStoreError(
                "Toolz store feedback recovery promoted entry mismatch"
            )
        observed_digest = toolz_route_memory_digest(observed_receipt)
        if objects.get(observed_digest) != observed_receipt:
            raise ToolzRouteStoreError(
                "Toolz store feedback recovery observed object mismatch"
            )
        if self._feedback_heads(after) != self._feedback_heads(before):
            raise ToolzRouteStoreError(
                "Toolz store feedback recovery feedback head change rejected"
            )
        feedback_created = _parse_time(
            feedback_created_at,
            "feedback recovery feedback creation time",
        )
        manifest_created = _parse_time(
            after["created_at"],
            "feedback recovery manifest creation time",
        )
        recovery_evaluated = _parse_time(
            evaluated_at,
            "feedback recovery evaluation time",
        )
        observed_expires = _parse_time(
            observed_receipt["expires_at"],
            "feedback recovery observed expiry",
        )
        if not (
            feedback_created
            <= manifest_created
            <= recovery_evaluated
            < observed_expires
        ):
            raise ToolzRouteStoreError(
                "Toolz store feedback recovery manifest timing rejected"
            )

    def put(
        self,
        receipt: Mapping[str, Any],
        *,
        expected_cursor: ToolzStoreCursor,
        expected_policy: ToolzRouteMemoryPolicy,
        fog_evidence: ToolzFogRouteEvidence,
        cyber_evidence: ToolzCyberEvidence,
        memory_key: TrustedKey,
        evaluated_at: str,
        recorded_at: str,
        store_signer: Ed25519Signer,
    ) -> ToolzStoreCursor:
        """Verify and atomically install one exact route-memory generation."""

        self._assert_open()
        self._assert_signer(store_signer)
        stable_receipt = _freeze_json_mapping(
            receipt,
            label="route-memory receipt",
        )
        stable_fog = _freeze_fog_evidence(fog_evidence)
        stable_cyber = _freeze_cyber_evidence(cyber_evidence)
        verified = verify_toolz_route_memory_receipt(
            stable_receipt,
            expected_policy=expected_policy,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            authority_key=memory_key,
        )
        decision = evaluate_toolz_route_memory(
            verified,
            expected_policy=expected_policy,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            authority_key=memory_key,
            evaluated_at=evaluated_at,
        )
        recorded = _parse_time(recorded_at, "record time")
        evaluated = _parse_time(evaluated_at, "evaluation time")
        if (
            evaluated > recorded
            or _parse_time(verified["created_at"], "receipt creation time") > recorded
        ):
            raise ToolzRouteStoreError("Toolz store ingress time rejected")
        record_ids, zone_ids, proposal_ids = self._route_dependencies(stable_fog)
        ingress_feedback_cursor = self._fog_feedback_cursor(stable_fog)
        ingress_feedback_chain_id = (
            None
            if ingress_feedback_cursor is None
            else _feedback_chain_identity(ingress_feedback_cursor)
        )
        context_id = toolz_store_context_identity(verified)
        receipt_digest = toolz_route_memory_digest(verified)

        current, _ = self._transaction_current(expected_cursor)
        try:
            if recorded < _parse_time(
                current["created_at"],
                "current manifest creation time",
            ):
                raise ToolzRouteStoreError("Toolz store manifest clock rollback")
            entries = {
                entry["context_id"]: deepcopy(entry)
                for entry in current["entries"]
            }
            feedback_heads = self._feedback_heads(current)
            existing = entries.get(context_id)
            if existing is not None and existing["receipt_digest"] == receipt_digest:
                if existing["feedback_chain_id"] != ingress_feedback_chain_id:
                    raise ToolzRouteStoreError(
                        "Toolz store idempotent feedback chain mismatch"
                    )
                self._connection.rollback()
                return self.cursor
            if existing is None and len(entries) >= MAX_TOOLZ_STORE_ENTRIES:
                raise ToolzRouteStoreError("Toolz store entry limit reached")
            current_feedback_cursor = None
            if ingress_feedback_cursor is not None:
                current_head = feedback_heads.get(ingress_feedback_chain_id)
                if current_head is None:
                    current_feedback_cursor = ingress_feedback_cursor
                    feedback_heads[ingress_feedback_chain_id] = (
                        _feedback_head_from_cursor(current_feedback_cursor)
                    )
                else:
                    current_feedback_cursor = _feedback_cursor_from_head(
                        current_head
                    )
                    if (
                        current_feedback_cursor.current_overlay_id
                        != verified["fog_route"]["feedback_overlay_id"]
                        or current_feedback_cursor.current_overlay_digest
                        != verified["fog_route"]["feedback_overlay_digest"]
                    ):
                        raise ToolzRouteStoreError(
                            "Toolz store feedback head mismatch"
                        )
            generation = 1 if existing is None else existing["generation"] + 1
            if generation > MAX_TOOLZ_STORE_SEQUENCE:
                raise ToolzRouteStoreError("Toolz store generation exhausted")
            entry = {
                "context_id": context_id,
                "generation": generation,
                "receipt_id": verified["receipt_id"],
                "receipt_digest": receipt_digest,
                "previous_receipt_digest": (
                    None if existing is None else existing["receipt_digest"]
                ),
                "route_proposal_id": verified["fog_route"]["proposal_id"],
                "lifecycle": _DECISION_LIFECYCLE[decision].value,
                "decision": decision.value,
                "dependency_record_ids": record_ids,
                "dependency_zone_ids": zone_ids,
                "source_proposal_ids": proposal_ids,
                "feedback_chain_id": ingress_feedback_chain_id,
                "feedback_overlay_id": verified["fog_route"][
                    "feedback_overlay_id"
                ],
                "feedback_overlay_digest": verified["fog_route"][
                    "feedback_overlay_digest"
                ],
                "last_delta_sequence": (
                    None
                    if current_feedback_cursor is None
                    or current_feedback_cursor.next_sequence == 0
                    else current_feedback_cursor.next_sequence - 1
                ),
                "last_delta_digest": (
                    None
                    if current_feedback_cursor is None
                    else current_feedback_cursor.previous_delta_digest
                ),
                "invalidation_reason": None,
                "updated_at": recorded_at,
            }
            _verify_entry_semantics(entry)
            entries[context_id] = entry
            if current["sequence"] >= MAX_TOOLZ_STORE_SEQUENCE:
                raise ToolzRouteStoreError("Toolz store manifest sequence exhausted")
            manifest = _sign_manifest(
                store_id=self.store_id,
                tenant_id=self.tenant_id,
                sequence=current["sequence"] + 1,
                previous_manifest_digest=toolz_store_manifest_digest(current),
                entries=list(entries.values()),
                feedback_heads=list(feedback_heads.values()),
                created_at=recorded_at,
                signer=store_signer,
                authority_key=self.authority_key,
            )
            return self._commit_transition(
                expected_cursor=expected_cursor,
                manifest=manifest,
                receipt=verified,
            )
        except Exception:
            if self._connection.in_transaction:
                self._connection.rollback()
            raise

    def lookup(
        self,
        context_id: str,
        *,
        expected_cursor: ToolzStoreCursor,
        expected_policy: ToolzRouteMemoryPolicy,
        fog_evidence: ToolzFogRouteEvidence,
        cyber_evidence: ToolzCyberEvidence,
        memory_key: TrustedKey,
        evaluated_at: str,
    ) -> ToolzStoreLookup | None:
        """Return guidance only after complete receipt and cursor re-verification."""

        if not isinstance(context_id, str) or _CONTEXT_ID.fullmatch(context_id) is None:
            raise ToolzRouteStoreError("Toolz store lookup context rejected")
        self._refresh(expected_cursor)
        entries = {
            entry["context_id"]: entry for entry in self._manifest["entries"]
        }
        entry = entries.get(context_id)
        if entry is None:
            return None
        receipt = _freeze_json_mapping(
            self._objects[entry["receipt_digest"]],
            label="stored route-memory receipt",
        )
        stable_fog = _freeze_fog_evidence(fog_evidence)
        stable_cyber = _freeze_cyber_evidence(cyber_evidence)
        verified = verify_toolz_route_memory_receipt(
            receipt,
            expected_policy=expected_policy,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            authority_key=memory_key,
        )
        self._entry_matches_receipt(entry, verified)
        feedback_cursor = self._fog_feedback_cursor(stable_fog)
        if entry["feedback_chain_id"] is not None:
            if (
                feedback_cursor is None
                or _feedback_chain_identity(feedback_cursor)
                != entry["feedback_chain_id"]
            ):
                raise ToolzRouteStoreError(
                    "Toolz store lookup feedback chain mismatch"
                )
            feedback_head = self._feedback_heads(self._manifest).get(
                entry["feedback_chain_id"]
            )
            if feedback_head is None:
                raise ToolzRouteStoreError(
                    "Toolz store lookup feedback head is absent"
                )
            current_feedback_cursor = _feedback_cursor_from_head(feedback_head)
            if (
                entry["feedback_overlay_id"]
                != current_feedback_cursor.current_overlay_id
                or entry["feedback_overlay_digest"]
                != current_feedback_cursor.current_overlay_digest
            ):
                raise ToolzRouteStoreError(
                    "Toolz store lookup feedback head mismatch"
                )
        decision = evaluate_toolz_route_memory(
            verified,
            expected_policy=expected_policy,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            authority_key=memory_key,
            evaluated_at=evaluated_at,
        )
        lifecycle = ToolzStoreLifecycle(entry["lifecycle"])
        if lifecycle is ToolzStoreLifecycle.INVALIDATED:
            decision = ToolzRouteMemoryDecision.REDISCOVER
        return ToolzStoreLookup(
            context_id=context_id,
            lifecycle=lifecycle,
            decision=decision,
            generation=entry["generation"],
            receipt=verified,
            cursor=self.cursor,
        )

    @staticmethod
    def _verify_feedback_delta(
        evidence: ToolzFeedbackDeltaEvidence,
    ) -> tuple[
        dict[str, Any],
        DiscoveryFeedbackDeltaCursor,
        DiscoveryFeedbackDeltaCursor,
    ]:
        stable_evidence = _freeze_feedback_delta_evidence(evidence)
        try:
            delta, next_cursor = verify_discovery_feedback_delta(
                stable_evidence.delta,
                stable_evidence.previous_overlay,
                stable_evidence.next_overlay,
                stable_evidence.snapshot,
                trusted_snapshot_key=stable_evidence.trusted_snapshot_key,
                trusted_sources=stable_evidence.trusted_sources,
                trusted_previous_overlay_key=(
                    stable_evidence.trusted_previous_overlay_key
                ),
                trusted_next_overlay_key=(
                    stable_evidence.trusted_next_overlay_key
                ),
                trusted_delta_key=stable_evidence.trusted_delta_key,
                expected_snapshot_id=stable_evidence.expected_snapshot_id,
                expected_tenant_id=stable_evidence.expected_tenant_id,
                expected_policy=stable_evidence.expected_policy,
                feedback_policy=stable_evidence.feedback_policy,
                previous_feedback_evidence=(
                    stable_evidence.previous_feedback_evidence
                ),
                next_feedback_evidence=(
                    stable_evidence.next_feedback_evidence
                ),
                cursor=stable_evidence.cursor,
            )
            return delta, next_cursor, stable_evidence.cursor
        except Exception as exc:
            raise ToolzRouteStoreError(
                "Toolz store Fog delta verification rejected"
            ) from exc

    def apply_feedback_delta(
        self,
        evidence: ToolzFeedbackDeltaEvidence,
        *,
        expected_cursor: ToolzStoreCursor,
        applied_at: str,
        store_signer: Ed25519Signer,
    ) -> ToolzDeltaApplication:
        """Apply one verified delta to matching route dependencies atomically."""

        self._assert_open()
        self._assert_signer(store_signer)
        (
            delta,
            next_feedback_cursor,
            previous_feedback_cursor,
        ) = self._verify_feedback_delta(evidence)
        applied = _parse_time(applied_at, "delta application time")
        if applied < _parse_time(delta["created_at"], "delta creation time"):
            raise ToolzRouteStoreError("Toolz store delta application time rejected")
        delta_digest = discovery_feedback_delta_digest(delta)
        current, _ = self._transaction_current(expected_cursor)
        try:
            if applied < _parse_time(
                current["created_at"],
                "current manifest creation time",
            ):
                raise ToolzRouteStoreError("Toolz store manifest clock rollback")
            entries = [deepcopy(entry) for entry in current["entries"]]
            feedback_heads = self._feedback_heads(current)
            feedback_chain_id = _feedback_chain_identity(
                previous_feedback_cursor
            )
            current_head = feedback_heads.get(feedback_chain_id)
            if current_head is None:
                if (
                    previous_feedback_cursor.next_sequence != 0
                    or previous_feedback_cursor.previous_delta_digest is not None
                ):
                    raise ToolzRouteStoreError(
                        "Toolz store feedback head history gap rejected"
                    )
            elif (
                _feedback_cursor_from_head(current_head)
                != previous_feedback_cursor
            ):
                raise ToolzRouteStoreError(
                    "Toolz store feedback head mismatch"
                )
            feedback_heads[feedback_chain_id] = _feedback_head_from_cursor(
                next_feedback_cursor
            )
            matched = invalidated = retained = 0
            for entry in entries:
                if entry["feedback_chain_id"] != feedback_chain_id:
                    continue
                if (
                    entry["feedback_overlay_id"]
                    != delta["previous_overlay_id"]
                    or entry["feedback_overlay_digest"]
                    != delta["previous_overlay_digest"]
                ):
                    raise ToolzRouteStoreError(
                        "Toolz store entry feedback head mismatch"
                    )
                matched += 1
                prior_sequence = entry["last_delta_sequence"]
                prior_digest = entry["last_delta_digest"]
                if prior_sequence is None:
                    if delta["previous_delta_digest"] is not None:
                        raise ToolzRouteStoreError(
                            "Toolz store entry delta history gap rejected"
                        )
                elif (
                    delta["sequence"] != prior_sequence + 1
                    or delta["previous_delta_digest"] != prior_digest
                ):
                    raise ToolzRouteStoreError(
                        "Toolz store entry delta continuity rejected"
                    )
                affected = bool(
                    set(entry["dependency_record_ids"])
                    & set(delta["recheck_record_ids"])
                    or set(entry["dependency_zone_ids"])
                    & set(delta["recheck_zone_ids"])
                    or set(entry["source_proposal_ids"])
                    & set(delta["recheck_proposal_ids"])
                )
                entry["feedback_overlay_id"] = delta["next_overlay_id"]
                entry["feedback_overlay_digest"] = delta["next_overlay_digest"]
                entry["last_delta_sequence"] = delta["sequence"]
                entry["last_delta_digest"] = delta_digest
                entry["updated_at"] = applied_at
                if affected:
                    entry["lifecycle"] = ToolzStoreLifecycle.INVALIDATED.value
                    entry["decision"] = ToolzRouteMemoryDecision.REDISCOVER.value
                    entry["invalidation_reason"] = "fog-feedback-delta"
                    invalidated += 1
                else:
                    retained += 1
                _verify_entry_semantics(entry)
            if current["sequence"] >= MAX_TOOLZ_STORE_SEQUENCE:
                raise ToolzRouteStoreError("Toolz store manifest sequence exhausted")
            manifest = _sign_manifest(
                store_id=self.store_id,
                tenant_id=self.tenant_id,
                sequence=current["sequence"] + 1,
                previous_manifest_digest=toolz_store_manifest_digest(current),
                entries=entries,
                feedback_heads=list(feedback_heads.values()),
                created_at=applied_at,
                signer=store_signer,
                authority_key=self.authority_key,
            )
            cursor = self._commit_transition(
                expected_cursor=expected_cursor,
                manifest=manifest,
                receipt=None,
            )
            return ToolzDeltaApplication(
                store_cursor=cursor,
                feedback_cursor=next_feedback_cursor,
                matched_entries=matched,
                invalidated_entries=invalidated,
                retained_entries=retained,
                authority_boundary=deepcopy(_STORE_BOUNDARY),
            )
        except Exception:
            if self._connection.in_transaction:
                self._connection.rollback()
            raise
