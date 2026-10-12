"""Explicit admission-to-store installation for Integrity 5.5 Uroboros.

The module composes the causality-safe a4 admission boundary with the existing
crash-atomic a2 local store.  It rejects context replacement, delegates the
single SQLite transition to ``ToolzRouteMemoryStore.put``, re-verifies the
installed theoretical memory, and returns a store-authority-signed receipt.

Local storage is the only added capability.  The module has no browser,
credential, execution, network, publication, model or tool-invocation
authority.  The returned receipt is not itself persisted transactionally;
cross-process recovery after a caller loses the returned cursor remains out of
scope.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from jsonschema import ValidationError

from .canonical import canonical_bytes, parse_json_strict
from .discovery_feedback import TrustedDiscoveryFeedback
from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_signature
from .uroboros_toolzs import (
    ToolzCyberEvidence,
    ToolzFogRouteEvidence,
    ToolzRouteMemoryDecision,
    evaluate_toolz_route_memory,
    toolz_route_memory_digest,
)
from .uroboros_toolzs_admission import (
    ToolzTraceAdmissionPolicy,
    toolz_trace_admission_digest,
    toolz_trace_admission_policy_digest,
    verify_toolz_trace_admission_receipt,
)
from .uroboros_toolzs_store import (
    ToolzRouteMemoryStore,
    ToolzStoreCursor,
    ToolzStoreLifecycle,
    toolz_store_context_identity,
)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_STORE_ID = re.compile(r"^toolz-store:[A-Za-z0-9][A-Za-z0-9._:/-]{0,242}$")
_INSTALL_BOUNDARY = {
    "browser_control": False,
    "credentials": False,
    "cross_process_recovery": False,
    "execution": False,
    "global_publish": False,
    "local_storage": True,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
    "raw_ui_data": False,
    "receipt_persistence": False,
    "tool_invocation": False,
}


class ToolzAdmissionInstallError(RuntimeError):
    """Raised before ambiguous or substituted admission state can be stored."""


class ToolzAdmissionInstallStatus(StrEnum):
    """Observable result of one explicit local installation request."""

    INSTALLED = "installed"
    ALREADY_PRESENT = "already-present"


@dataclass(frozen=True)
class ToolzAdmissionInstallPolicy:
    """Exact admission policy, destination store and bounded ingress lag."""

    policy_id: str
    admission_policy: ToolzTraceAdmissionPolicy
    store_id: str
    max_evaluation_to_record_seconds: int = 60

    def __post_init__(self) -> None:
        if (
            not isinstance(self.policy_id, str)
            or _ID.fullmatch(self.policy_id) is None
            or "synthetic" not in self.policy_id
        ):
            raise ToolzAdmissionInstallError(
                "Toolzs admission install policy id rejected"
            )
        if not isinstance(self.admission_policy, ToolzTraceAdmissionPolicy):
            raise ToolzAdmissionInstallError(
                "Toolzs admission install policy rejected"
            )
        if (
            not isinstance(self.store_id, str)
            or _STORE_ID.fullmatch(self.store_id) is None
            or "synthetic" not in self.store_id
        ):
            raise ToolzAdmissionInstallError(
                "Toolzs admission install store id rejected"
            )
        if (
            not isinstance(self.max_evaluation_to_record_seconds, int)
            or isinstance(self.max_evaluation_to_record_seconds, bool)
            or not 0 <= self.max_evaluation_to_record_seconds <= 3_600
        ):
            raise ToolzAdmissionInstallError(
                "Toolzs admission install ingress lag rejected"
            )


@dataclass(frozen=True)
class ToolzAdmissionInstall:
    """Signed installation result plus its exact resulting store cursor."""

    receipt: dict[str, Any]
    memory_receipt: dict[str, Any]
    store_cursor: ToolzStoreCursor
    status: ToolzAdmissionInstallStatus

    @property
    def execution_authority(self) -> bool:
        return False

    @property
    def storage_performed(self) -> bool:
        return self.status is ToolzAdmissionInstallStatus.INSTALLED


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ToolzAdmissionInstallError(
            f"Toolzs admission install {field} rejected"
        )
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolzAdmissionInstallError(
            f"Toolzs admission install {field} rejected"
        ) from exc
    if parsed.tzinfo is None:
        raise ToolzAdmissionInstallError(
            f"Toolzs admission install {field} rejected"
        )
    return parsed


def _freeze_mapping(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ToolzAdmissionInstallError(
            f"Toolzs admission install {field} rejected"
        )
    try:
        detached = parse_json_strict(canonical_bytes(dict(value)))
    except Exception as exc:
        raise ToolzAdmissionInstallError(
            f"Toolzs admission install {field} rejected"
        ) from exc
    if not isinstance(detached, dict):
        raise ToolzAdmissionInstallError(
            f"Toolzs admission install {field} rejected"
        )
    return detached


def _freeze_feedback(
    evidence: TrustedDiscoveryFeedback,
) -> TrustedDiscoveryFeedback:
    if not isinstance(evidence, TrustedDiscoveryFeedback):
        raise ToolzAdmissionInstallError(
            "Toolzs admission install feedback rejected"
        )
    return TrustedDiscoveryFeedback(
        proposal=_freeze_mapping(evidence.proposal, "feedback proposal"),
        receipt=_freeze_mapping(evidence.receipt, "feedback receipt"),
        proposal_policy=evidence.proposal_policy,
        trusted_theory_key=evidence.trusted_theory_key,
        trusted_feedback_key=evidence.trusted_feedback_key,
        expected_observer_id=evidence.expected_observer_id,
    )


def _freeze_fog_evidence(
    evidence: ToolzFogRouteEvidence,
) -> ToolzFogRouteEvidence:
    if not isinstance(evidence, ToolzFogRouteEvidence):
        raise ToolzAdmissionInstallError(
            "Toolzs admission install Fog evidence rejected"
        )
    return ToolzFogRouteEvidence(
        snapshot=_freeze_mapping(evidence.snapshot, "Fog snapshot"),
        route=_freeze_mapping(evidence.route, "Fog route"),
        trusted_snapshot_key=evidence.trusted_snapshot_key,
        trusted_sources=tuple(evidence.trusted_sources),
        trusted_theory_key=evidence.trusted_theory_key,
        expected_snapshot_id=evidence.expected_snapshot_id,
        expected_tenant_id=evidence.expected_tenant_id,
        expected_policy=evidence.expected_policy,
        overlay=(
            None
            if evidence.overlay is None
            else _freeze_mapping(evidence.overlay, "Fog overlay")
        ),
        trusted_overlay_key=evidence.trusted_overlay_key,
        feedback_policy=evidence.feedback_policy,
        feedback_evidence=tuple(
            _freeze_feedback(item) for item in evidence.feedback_evidence
        ),
    )


def _freeze_cyber_evidence(
    evidence: ToolzCyberEvidence,
) -> ToolzCyberEvidence:
    if not isinstance(evidence, ToolzCyberEvidence):
        raise ToolzAdmissionInstallError(
            "Toolzs admission install cyber evidence rejected"
        )
    return ToolzCyberEvidence(
        decision_receipt=_freeze_mapping(
            evidence.decision_receipt,
            "cyber decision",
        ),
        expected_policy=evidence.expected_policy,
        provenance_receipt=_freeze_mapping(
            evidence.provenance_receipt,
            "cyber provenance",
        ),
        assessment_receipt=_freeze_mapping(
            evidence.assessment_receipt,
            "cyber assessment",
        ),
        containment_receipt=(
            None
            if evidence.containment_receipt is None
            else _freeze_mapping(
                evidence.containment_receipt,
                "cyber containment",
            )
        ),
        provenance_key=evidence.provenance_key,
        assessment_key=evidence.assessment_key,
        containment_key=evidence.containment_key,
        authority_key=evidence.authority_key,
    )


def _policy_document(policy: ToolzAdmissionInstallPolicy) -> dict[str, Any]:
    return {
        "policy_id": policy.policy_id,
        "admission_policy_digest": toolz_trace_admission_policy_digest(
            policy.admission_policy
        ),
        "store_id": policy.store_id,
        "max_evaluation_to_record_seconds": (
            policy.max_evaluation_to_record_seconds
        ),
        "transition_semantics": (
            "insert-theoretical-if-absent-or-confirm-identical-never-replace"
        ),
        "receipt_semantics": (
            "post-commit-store-signed-no-cross-process-cursor-recovery"
        ),
    }


def toolz_admission_install_policy_digest(
    policy: ToolzAdmissionInstallPolicy,
) -> str:
    """Return the exact admission-to-store policy identity."""

    if not isinstance(policy, ToolzAdmissionInstallPolicy):
        raise ToolzAdmissionInstallError(
            "Toolzs admission install policy rejected"
        )
    return digest_object(
        _policy_document(policy),
        domain="toolz-admission-install-policy-v1",
    )


def _receipt_core(receipt: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(receipt))
    core.pop("receipt_id", None)
    core.pop("signature", None)
    return core


def toolz_admission_install_identity(receipt: Mapping[str, Any]) -> str:
    """Return the domain-separated identity of one unsigned install receipt."""

    digest = digest_object(
        _receipt_core(receipt),
        domain="toolz-admission-install-receipt-identity-v1",
    )
    return f"toolz-admission-install-receipt:{digest.split(':', 1)[1]}"


def toolz_admission_install_digest(receipt: Mapping[str, Any]) -> str:
    """Return the exact signed installation receipt digest."""

    return digest_object(
        dict(receipt),
        domain="toolz-admission-install-signed-receipt-v1",
    )


def _validate_cursor(
    cursor: ToolzStoreCursor,
    *,
    policy: ToolzAdmissionInstallPolicy,
    tenant_id: str,
    field: str,
) -> None:
    if (
        not isinstance(cursor, ToolzStoreCursor)
        or cursor.store_id != policy.store_id
        or cursor.tenant_id != tenant_id
    ):
        raise ToolzAdmissionInstallError(
            f"Toolzs admission install {field} rejected"
        )


def _validate_timing(
    *,
    admission_created_at: str,
    memory_expires_at: str,
    evaluated_at: str,
    recorded_at: str,
    policy: ToolzAdmissionInstallPolicy,
) -> None:
    admission_time = _parse_time(admission_created_at, "admission time")
    expiry_time = _parse_time(memory_expires_at, "memory expiry")
    evaluated_time = _parse_time(evaluated_at, "evaluation time")
    recorded_time = _parse_time(recorded_at, "record time")
    if (
        not admission_time <= evaluated_time <= recorded_time
        or recorded_time >= expiry_time
    ):
        raise ToolzAdmissionInstallError(
            "Toolzs admission install causal timing rejected"
        )
    if (
        recorded_time - evaluated_time
    ).total_seconds() > policy.max_evaluation_to_record_seconds:
        raise ToolzAdmissionInstallError(
            "Toolzs admission install evaluation lag rejected"
        )


def _admission_reference(
    admission_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "receipt_id": admission_receipt["receipt_id"],
        "receipt_digest": toolz_trace_admission_digest(admission_receipt),
        "policy_id": admission_receipt["policy_id"],
        "policy_digest": admission_receipt["policy_digest"],
        "decision": admission_receipt["decision"],
        "created_at": admission_receipt["created_at"],
    }


def _memory_reference(memory_receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "receipt_id": memory_receipt["receipt_id"],
        "receipt_digest": toolz_route_memory_digest(memory_receipt),
        "context_id": toolz_store_context_identity(memory_receipt),
        "outcome": memory_receipt["observation"]["outcome"],
        "created_at": memory_receipt["created_at"],
        "expires_at": memory_receipt["expires_at"],
    }


def _expected_core(
    *,
    policy: ToolzAdmissionInstallPolicy,
    admission_receipt: Mapping[str, Any],
    memory_receipt: Mapping[str, Any],
    before_cursor: ToolzStoreCursor,
    after_cursor: ToolzStoreCursor,
    status: ToolzAdmissionInstallStatus,
    evaluated_at: str,
    recorded_at: str,
) -> dict[str, Any]:
    return {
        "protocol": "integrity-guardian/toolz-admission-install-receipt/v1",
        "tenant_id": policy.admission_policy.memory_policy.subject.tenant_id,
        "policy_id": policy.policy_id,
        "policy_digest": toolz_admission_install_policy_digest(policy),
        "admission": _admission_reference(admission_receipt),
        "memory": _memory_reference(memory_receipt),
        "store": {
            "store_id": policy.store_id,
            "before_cursor": before_cursor.to_document(),
            "after_cursor": after_cursor.to_document(),
            "transition": status.value,
        },
        "timing": {
            "evaluated_at": evaluated_at,
            "recorded_at": recorded_at,
        },
        "authority_boundary": deepcopy(_INSTALL_BOUNDARY),
    }


def _validate_transition(
    before_cursor: ToolzStoreCursor,
    after_cursor: ToolzStoreCursor,
    status: ToolzAdmissionInstallStatus,
) -> None:
    before = before_cursor.to_document()
    after = after_cursor.to_document()
    if status is ToolzAdmissionInstallStatus.ALREADY_PRESENT:
        if after != before:
            raise ToolzAdmissionInstallError(
                "Toolzs admission install idempotent cursor mismatch"
            )
        return
    if (
        after_cursor.sequence != before_cursor.sequence + 1
        or after_cursor.manifest_id == before_cursor.manifest_id
        or after_cursor.manifest_digest == before_cursor.manifest_digest
    ):
        raise ToolzAdmissionInstallError(
            "Toolzs admission install cursor transition rejected"
        )


def verify_toolz_admission_install_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_policy: ToolzAdmissionInstallPolicy,
    admission_receipt: Mapping[str, Any],
    trace: Mapping[str, Any],
    observer_key: TrustedKey,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    memory_receipt: Mapping[str, Any],
    memory_key: TrustedKey,
    admission_key: TrustedKey,
    store_key: TrustedKey,
    before_cursor: ToolzStoreCursor,
    after_cursor: ToolzStoreCursor,
) -> ToolzAdmissionInstall:
    """Verify every admission, memory, store, time and signer binding."""

    if not isinstance(expected_policy, ToolzAdmissionInstallPolicy):
        raise ToolzAdmissionInstallError(
            "Toolzs admission install policy rejected"
        )
    if not all(
        isinstance(key, TrustedKey)
        for key in (
            observer_key,
            memory_key,
            admission_key,
            store_key,
        )
    ):
        raise ToolzAdmissionInstallError(
            "Toolzs admission install trust binding rejected"
        )
    stable_admission = _freeze_mapping(admission_receipt, "admission receipt")
    stable_memory = _freeze_mapping(memory_receipt, "memory receipt")
    stable_trace = _freeze_mapping(trace, "trace")
    stable_fog = _freeze_fog_evidence(fog_evidence)
    stable_cyber = _freeze_cyber_evidence(cyber_evidence)
    try:
        candidate = _freeze_mapping(receipt, "receipt")
        validate("toolz-admission-install-receipt", candidate)
    except ValidationError as exc:
        raise ToolzAdmissionInstallError(
            "Toolzs admission install receipt schema rejected"
        ) from exc
    if candidate["receipt_id"] != toolz_admission_install_identity(candidate):
        raise ToolzAdmissionInstallError(
            "Toolzs admission install identity mismatch"
        )
    if (
        candidate["signature"]["key_id"] != store_key.key_id
        or not verify_signature(candidate, store_key.public_key)
    ):
        raise ToolzAdmissionInstallError(
            "Toolzs admission install signature rejected"
        )
    if candidate["authority_boundary"] != _INSTALL_BOUNDARY:
        raise ToolzAdmissionInstallError(
            "Toolzs admission install authority mismatch"
        )

    try:
        admission = verify_toolz_trace_admission_receipt(
            stable_admission,
            expected_policy=expected_policy.admission_policy,
            trace=stable_trace,
            observer_key=observer_key,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            memory_receipt=stable_memory,
            memory_key=memory_key,
            admission_key=admission_key,
        )
    except Exception as exc:
        raise ToolzAdmissionInstallError(
            "Toolzs admission install admission rejected"
        ) from exc
    tenant_id = admission.memory_receipt["tenant_id"]
    _validate_cursor(
        before_cursor,
        policy=expected_policy,
        tenant_id=tenant_id,
        field="before cursor",
    )
    _validate_cursor(
        after_cursor,
        policy=expected_policy,
        tenant_id=tenant_id,
        field="after cursor",
    )
    try:
        status = ToolzAdmissionInstallStatus(candidate["store"]["transition"])
    except ValueError as exc:
        raise ToolzAdmissionInstallError(
            "Toolzs admission install transition rejected"
        ) from exc
    _validate_transition(before_cursor, after_cursor, status)
    _validate_timing(
        admission_created_at=stable_admission["created_at"],
        memory_expires_at=stable_memory["expires_at"],
        evaluated_at=candidate["timing"]["evaluated_at"],
        recorded_at=candidate["timing"]["recorded_at"],
        policy=expected_policy,
    )
    try:
        decision = evaluate_toolz_route_memory(
            admission.memory_receipt,
            expected_policy=expected_policy.admission_policy.memory_policy,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            authority_key=memory_key,
            evaluated_at=candidate["timing"]["evaluated_at"],
        )
    except Exception as exc:
        raise ToolzAdmissionInstallError(
            "Toolzs admission install evaluation rejected"
        ) from exc
    if decision is not ToolzRouteMemoryDecision.EXPLORE:
        raise ToolzAdmissionInstallError(
            "Toolzs admission install non-theoretical decision rejected"
        )
    expected = _expected_core(
        policy=expected_policy,
        admission_receipt=stable_admission,
        memory_receipt=stable_memory,
        before_cursor=before_cursor,
        after_cursor=after_cursor,
        status=status,
        evaluated_at=candidate["timing"]["evaluated_at"],
        recorded_at=candidate["timing"]["recorded_at"],
    )
    if _receipt_core(candidate) != expected:
        raise ToolzAdmissionInstallError(
            "Toolzs admission install recomputation mismatch"
        )
    return ToolzAdmissionInstall(
        receipt=candidate,
        memory_receipt=admission.memory_receipt,
        store_cursor=after_cursor,
        status=status,
    )


def install_toolz_trace_admission(
    *,
    policy: ToolzAdmissionInstallPolicy,
    admission_receipt: Mapping[str, Any],
    trace: Mapping[str, Any],
    observer_key: TrustedKey,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    memory_receipt: Mapping[str, Any],
    memory_key: TrustedKey,
    admission_key: TrustedKey,
    store: ToolzRouteMemoryStore,
    expected_cursor: ToolzStoreCursor,
    evaluated_at: str,
    recorded_at: str,
    store_signer: Ed25519Signer,
) -> ToolzAdmissionInstall:
    """Explicitly install one exact a4 theoretical memory into one a2 store."""

    if not isinstance(policy, ToolzAdmissionInstallPolicy):
        raise ToolzAdmissionInstallError(
            "Toolzs admission install policy rejected"
        )
    if not isinstance(store, ToolzRouteMemoryStore):
        raise ToolzAdmissionInstallError(
            "Toolzs admission install store rejected"
        )
    if not isinstance(store_signer, Ed25519Signer):
        raise ToolzAdmissionInstallError(
            "Toolzs admission install signer rejected"
        )
    stable_admission = _freeze_mapping(admission_receipt, "admission receipt")
    stable_memory = _freeze_mapping(memory_receipt, "memory receipt")
    stable_trace = _freeze_mapping(trace, "trace")
    stable_fog = _freeze_fog_evidence(fog_evidence)
    stable_cyber = _freeze_cyber_evidence(cyber_evidence)
    try:
        admission = verify_toolz_trace_admission_receipt(
            stable_admission,
            expected_policy=policy.admission_policy,
            trace=stable_trace,
            observer_key=observer_key,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            memory_receipt=stable_memory,
            memory_key=memory_key,
            admission_key=admission_key,
        )
    except Exception as exc:
        raise ToolzAdmissionInstallError(
            "Toolzs admission install admission rejected"
        ) from exc
    tenant_id = admission.memory_receipt["tenant_id"]
    if store.store_id != policy.store_id or store.tenant_id != tenant_id:
        raise ToolzAdmissionInstallError(
            "Toolzs admission install store scope mismatch"
        )
    _validate_cursor(
        expected_cursor,
        policy=policy,
        tenant_id=tenant_id,
        field="expected cursor",
    )
    _validate_timing(
        admission_created_at=stable_admission["created_at"],
        memory_expires_at=stable_memory["expires_at"],
        evaluated_at=evaluated_at,
        recorded_at=recorded_at,
        policy=policy,
    )
    try:
        decision = evaluate_toolz_route_memory(
            admission.memory_receipt,
            expected_policy=policy.admission_policy.memory_policy,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            authority_key=memory_key,
            evaluated_at=evaluated_at,
        )
    except Exception as exc:
        raise ToolzAdmissionInstallError(
            "Toolzs admission install evaluation rejected"
        ) from exc
    if decision is not ToolzRouteMemoryDecision.EXPLORE:
        raise ToolzAdmissionInstallError(
            "Toolzs admission install non-theoretical decision rejected"
        )

    context_id = toolz_store_context_identity(admission.memory_receipt)
    memory_digest = toolz_route_memory_digest(admission.memory_receipt)
    try:
        entries = {
            entry["context_id"]: entry
            for entry in store.entries(expected_cursor=expected_cursor)
        }
    except Exception as exc:
        raise ToolzAdmissionInstallError(
            "Toolzs admission install store pre-check rejected"
        ) from exc
    existing = entries.get(context_id)
    if existing is not None and (
        existing["receipt_digest"] != memory_digest
        or existing["lifecycle"] != ToolzStoreLifecycle.THEORETICAL.value
        or existing["decision"] != ToolzRouteMemoryDecision.EXPLORE.value
        or existing["invalidation_reason"] is not None
    ):
        raise ToolzAdmissionInstallError(
            "Toolzs admission install context conflict"
        )

    before_cursor = expected_cursor
    try:
        after_cursor = store.put(
            admission.memory_receipt,
            expected_cursor=before_cursor,
            expected_policy=policy.admission_policy.memory_policy,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            memory_key=memory_key,
            evaluated_at=evaluated_at,
            recorded_at=recorded_at,
            store_signer=store_signer,
        )
    except Exception as exc:
        raise ToolzAdmissionInstallError(
            "Toolzs admission install store transition rejected"
        ) from exc
    status = (
        ToolzAdmissionInstallStatus.ALREADY_PRESENT
        if after_cursor == before_cursor
        else ToolzAdmissionInstallStatus.INSTALLED
    )
    _validate_transition(before_cursor, after_cursor, status)
    try:
        lookup = store.lookup(
            context_id,
            expected_cursor=after_cursor,
            expected_policy=policy.admission_policy.memory_policy,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            memory_key=memory_key,
            evaluated_at=evaluated_at,
        )
    except Exception as exc:
        raise ToolzAdmissionInstallError(
            "Toolzs admission install store post-check rejected"
        ) from exc
    if (
        lookup is None
        or lookup.lifecycle is not ToolzStoreLifecycle.THEORETICAL
        or lookup.decision is not ToolzRouteMemoryDecision.EXPLORE
        or toolz_route_memory_digest(lookup.receipt) != memory_digest
    ):
        raise ToolzAdmissionInstallError(
            "Toolzs admission install post-check rejected"
        )

    core = _expected_core(
        policy=policy,
        admission_receipt=stable_admission,
        memory_receipt=admission.memory_receipt,
        before_cursor=before_cursor,
        after_cursor=after_cursor,
        status=status,
        evaluated_at=evaluated_at,
        recorded_at=recorded_at,
    )
    unsigned = {
        "receipt_id": toolz_admission_install_identity(core),
        **core,
    }
    signed = store_signer.sign(unsigned)
    return verify_toolz_admission_install_receipt(
        signed,
        expected_policy=policy,
        admission_receipt=stable_admission,
        trace=stable_trace,
        observer_key=observer_key,
        fog_evidence=stable_fog,
        cyber_evidence=stable_cyber,
        memory_receipt=admission.memory_receipt,
        memory_key=memory_key,
        admission_key=admission_key,
        store_key=TrustedKey(
            key_id=store_signer.key_id,
            public_key=store_signer.public_key,
        ),
        before_cursor=before_cursor,
        after_cursor=after_cursor,
    )
