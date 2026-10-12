"""Explicit feedback-to-store installation for Integrity 5.5 Uroboros.

The module composes one exact a7 post-route feedback receipt with the existing
cursor-pinned a2 catalog.  It promotes only the exact installed generation-one
theoretical predecessor to its generation-two observed-success successor.
Local storage is the sole active capability; no tool, browser or route is
executed.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

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
from .uroboros_toolzs_feedback import (
    ToolzPostRouteFeedbackPolicy,
    toolz_post_route_feedback_digest,
    toolz_post_route_feedback_policy_digest,
    verify_toolz_post_route_feedback_receipt,
)
from .uroboros_toolzs_install import (
    _freeze_cyber_evidence,
    _freeze_fog_evidence,
    _freeze_mapping,
)
from .uroboros_toolzs_store import (
    ToolzRouteMemoryStore,
    ToolzStoreCursor,
    ToolzStoreLifecycle,
    toolz_store_context_identity,
)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_STORE_ID = re.compile(r"^toolz-store:[A-Za-z0-9][A-Za-z0-9._:/-]{0,242}$")
_FEEDBACK_INSTALL_BOUNDARY = {
    "browser_control": False,
    "credentials": False,
    "cross_process_recovery": False,
    "execution": False,
    "generic_overwrite": False,
    "global_publish": False,
    "local_storage": True,
    "model_sdk": False,
    "network": False,
    "predecessor_bypass": False,
    "production_authority": False,
    "raw_ui_data": False,
    "receipt_persistence": False,
    "store_write": True,
    "tool_invocation": False,
}


class ToolzFeedbackInstallError(RuntimeError):
    """Raised before an ambiguous feedback generation can enter the catalog."""


class ToolzFeedbackInstallStatus(StrEnum):
    """Observable result of one exact feedback installation request."""

    PROMOTED = "promoted"
    ALREADY_PRESENT = "already-present"


@dataclass(frozen=True)
class ToolzFeedbackInstallPolicy:
    """Exact a7 policy, destination catalog and bounded ingress lag."""

    policy_id: str
    feedback_policy: ToolzPostRouteFeedbackPolicy
    store_id: str
    max_evaluation_to_record_seconds: int = 60

    def __post_init__(self) -> None:
        if (
            not isinstance(self.policy_id, str)
            or _ID.fullmatch(self.policy_id) is None
            or "synthetic" not in self.policy_id
        ):
            raise ToolzFeedbackInstallError("Toolzs feedback install policy id rejected")
        if not isinstance(
            self.feedback_policy,
            ToolzPostRouteFeedbackPolicy,
        ):
            raise ToolzFeedbackInstallError("Toolzs feedback install policy rejected")
        if (
            not isinstance(self.store_id, str)
            or _STORE_ID.fullmatch(self.store_id) is None
            or "synthetic" not in self.store_id
        ):
            raise ToolzFeedbackInstallError("Toolzs feedback install store id rejected")
        if (
            not isinstance(self.max_evaluation_to_record_seconds, int)
            or isinstance(self.max_evaluation_to_record_seconds, bool)
            or not 0 <= self.max_evaluation_to_record_seconds <= 3_600
        ):
            raise ToolzFeedbackInstallError("Toolzs feedback install ingress lag rejected")


@dataclass(frozen=True)
class ToolzFeedbackInstall:
    """Signed catalog result plus its exact generation-two memory and cursor."""

    receipt: dict[str, Any]
    memory_receipt: dict[str, Any]
    store_cursor: ToolzStoreCursor
    status: ToolzFeedbackInstallStatus

    @property
    def execution_authority(self) -> bool:
        return False

    @property
    def storage_performed(self) -> bool:
        return self.status is ToolzFeedbackInstallStatus.PROMOTED


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ToolzFeedbackInstallError(f"Toolzs feedback install {field} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolzFeedbackInstallError(f"Toolzs feedback install {field} rejected") from exc
    if parsed.tzinfo is None:
        raise ToolzFeedbackInstallError(f"Toolzs feedback install {field} rejected")
    return parsed


def _freeze_inputs(
    *,
    feedback_receipt: Mapping[str, Any],
    theoretical_memory: Mapping[str, Any],
    trace: Mapping[str, Any],
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    observed_memory: Mapping[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    ToolzFogRouteEvidence,
    ToolzCyberEvidence,
    dict[str, Any],
]:
    try:
        return (
            _freeze_mapping(feedback_receipt, "feedback receipt"),
            _freeze_mapping(theoretical_memory, "theoretical memory"),
            _freeze_mapping(trace, "feedback trace"),
            _freeze_fog_evidence(fog_evidence),
            _freeze_cyber_evidence(cyber_evidence),
            _freeze_mapping(observed_memory, "observed memory"),
        )
    except Exception as exc:
        raise ToolzFeedbackInstallError("Toolzs feedback install input rejected") from exc


def _policy_document(
    policy: ToolzFeedbackInstallPolicy,
) -> dict[str, Any]:
    return {
        "policy_id": policy.policy_id,
        "feedback_policy_digest": toolz_post_route_feedback_policy_digest(policy.feedback_policy),
        "store_id": policy.store_id,
        "max_evaluation_to_record_seconds": (policy.max_evaluation_to_record_seconds),
        "transition_semantics": (
            "exact-generation-one-theoretical-to-generation-two-observed-"
            "success-or-confirm-identical-generation-two"
        ),
        "receipt_semantics": ("post-commit-store-signed-no-cross-process-cursor-recovery"),
    }


def toolz_feedback_install_policy_digest(
    policy: ToolzFeedbackInstallPolicy,
) -> str:
    """Return the exact feedback-to-store policy identity."""

    if not isinstance(policy, ToolzFeedbackInstallPolicy):
        raise ToolzFeedbackInstallError("Toolzs feedback install policy rejected")
    return digest_object(
        _policy_document(policy),
        domain="toolz-feedback-install-policy-v1",
    )


def _receipt_core(receipt: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(receipt))
    core.pop("receipt_id", None)
    core.pop("signature", None)
    return core


def toolz_feedback_install_identity(
    receipt: Mapping[str, Any],
) -> str:
    """Return the domain-separated identity of one unsigned install receipt."""

    digest = digest_object(
        _receipt_core(receipt),
        domain="toolz-feedback-install-receipt-identity-v1",
    )
    return f"toolz-feedback-install-receipt:{digest.split(':', 1)[1]}"


def toolz_feedback_install_digest(
    receipt: Mapping[str, Any],
) -> str:
    """Return the exact signed feedback installation digest."""

    return digest_object(
        dict(receipt),
        domain="toolz-feedback-install-signed-receipt-v1",
    )


def _validate_cursor(
    cursor: ToolzStoreCursor,
    *,
    policy: ToolzFeedbackInstallPolicy,
    tenant_id: str,
    field: str,
) -> None:
    if (
        not isinstance(cursor, ToolzStoreCursor)
        or cursor.store_id != policy.store_id
        or cursor.tenant_id != tenant_id
    ):
        raise ToolzFeedbackInstallError(f"Toolzs feedback install {field} rejected")


def _validate_timing(
    *,
    feedback_created_at: str,
    memory_expires_at: str,
    evaluated_at: str,
    recorded_at: str,
    policy: ToolzFeedbackInstallPolicy,
) -> None:
    feedback_time = _parse_time(feedback_created_at, "feedback time")
    expiry_time = _parse_time(memory_expires_at, "memory expiry")
    evaluated_time = _parse_time(evaluated_at, "evaluation time")
    recorded_time = _parse_time(recorded_at, "record time")
    if not feedback_time <= evaluated_time <= recorded_time or recorded_time >= expiry_time:
        raise ToolzFeedbackInstallError("Toolzs feedback install causal timing rejected")
    if (recorded_time - evaluated_time).total_seconds() > policy.max_evaluation_to_record_seconds:
        raise ToolzFeedbackInstallError("Toolzs feedback install evaluation lag rejected")


def _feedback_reference(
    feedback_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "receipt_id": feedback_receipt["receipt_id"],
        "receipt_digest": toolz_post_route_feedback_digest(feedback_receipt),
        "policy_id": feedback_receipt["policy_id"],
        "policy_digest": feedback_receipt["policy_digest"],
        "decision": feedback_receipt["decision"],
        "created_at": feedback_receipt["created_at"],
    }


def _memory_reference(
    memory_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "receipt_id": memory_receipt["receipt_id"],
        "receipt_digest": toolz_route_memory_digest(memory_receipt),
        "context_id": toolz_store_context_identity(memory_receipt),
        "outcome": memory_receipt["observation"]["outcome"],
        "observed_at": memory_receipt["observation"]["observed_at"],
        "evidence_digest": memory_receipt["observation"]["evidence_digest"],
        "created_at": memory_receipt["created_at"],
        "expires_at": memory_receipt["expires_at"],
    }


def _predecessor_entry(
    memory_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "context_id": toolz_store_context_identity(memory_receipt),
        "generation": 1,
        "receipt_id": memory_receipt["receipt_id"],
        "receipt_digest": toolz_route_memory_digest(memory_receipt),
        "previous_receipt_digest": None,
        "lifecycle": ToolzStoreLifecycle.THEORETICAL.value,
        "decision": ToolzRouteMemoryDecision.EXPLORE.value,
        "invalidation_reason": None,
    }


def _result_entry(
    *,
    theoretical_memory: Mapping[str, Any],
    observed_memory: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "context_id": toolz_store_context_identity(observed_memory),
        "generation": 2,
        "receipt_id": observed_memory["receipt_id"],
        "receipt_digest": toolz_route_memory_digest(observed_memory),
        "previous_receipt_digest": toolz_route_memory_digest(theoretical_memory),
        "lifecycle": ToolzStoreLifecycle.REUSABLE.value,
        "decision": ToolzRouteMemoryDecision.REUSE_CANDIDATE.value,
        "invalidation_reason": None,
    }


def _entry_projection(entry: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return {
            "context_id": entry["context_id"],
            "generation": entry["generation"],
            "receipt_id": entry["receipt_id"],
            "receipt_digest": entry["receipt_digest"],
            "previous_receipt_digest": entry["previous_receipt_digest"],
            "lifecycle": entry["lifecycle"],
            "decision": entry["decision"],
            "invalidation_reason": entry["invalidation_reason"],
        }
    except (KeyError, TypeError) as exc:
        raise ToolzFeedbackInstallError("Toolzs feedback install store entry rejected") from exc


def _classify_existing(
    entry: Mapping[str, Any] | None,
    *,
    theoretical_memory: Mapping[str, Any],
    observed_memory: Mapping[str, Any],
) -> ToolzFeedbackInstallStatus:
    if entry is None:
        raise ToolzFeedbackInstallError("Toolzs feedback install theoretical predecessor is absent")
    projected = _entry_projection(entry)
    if projected == _predecessor_entry(theoretical_memory):
        return ToolzFeedbackInstallStatus.PROMOTED
    if projected == _result_entry(
        theoretical_memory=theoretical_memory,
        observed_memory=observed_memory,
    ):
        return ToolzFeedbackInstallStatus.ALREADY_PRESENT
    raise ToolzFeedbackInstallError("Toolzs feedback install predecessor chain conflict")


def _validate_transition(
    before_cursor: ToolzStoreCursor,
    after_cursor: ToolzStoreCursor,
    status: ToolzFeedbackInstallStatus,
) -> None:
    before = before_cursor.to_document()
    after = after_cursor.to_document()
    if status is ToolzFeedbackInstallStatus.ALREADY_PRESENT:
        if after != before:
            raise ToolzFeedbackInstallError("Toolzs feedback install idempotent cursor mismatch")
        return
    if (
        after_cursor.sequence != before_cursor.sequence + 1
        or after_cursor.manifest_id == before_cursor.manifest_id
        or after_cursor.manifest_digest == before_cursor.manifest_digest
    ):
        raise ToolzFeedbackInstallError("Toolzs feedback install cursor transition rejected")


def _expected_core(
    *,
    policy: ToolzFeedbackInstallPolicy,
    feedback_receipt: Mapping[str, Any],
    theoretical_memory: Mapping[str, Any],
    observed_memory: Mapping[str, Any],
    before_cursor: ToolzStoreCursor,
    after_cursor: ToolzStoreCursor,
    status: ToolzFeedbackInstallStatus,
    evaluated_at: str,
    recorded_at: str,
) -> dict[str, Any]:
    return {
        "protocol": "integrity-guardian/toolz-feedback-install-receipt/v1",
        "tenant_id": policy.feedback_policy.memory_policy.subject.tenant_id,
        "policy_id": policy.policy_id,
        "policy_digest": toolz_feedback_install_policy_digest(policy),
        "feedback": _feedback_reference(feedback_receipt),
        "theoretical_memory": _memory_reference(theoretical_memory),
        "observed_memory": _memory_reference(observed_memory),
        "store": {
            "store_id": policy.store_id,
            "before_cursor": before_cursor.to_document(),
            "after_cursor": after_cursor.to_document(),
            "transition": status.value,
            "required_predecessor": _predecessor_entry(theoretical_memory),
            "result_entry": _result_entry(
                theoretical_memory=theoretical_memory,
                observed_memory=observed_memory,
            ),
        },
        "timing": {
            "evaluated_at": evaluated_at,
            "recorded_at": recorded_at,
        },
        "authority_boundary": deepcopy(_FEEDBACK_INSTALL_BOUNDARY),
    }


def _verified_feedback(
    *,
    policy: ToolzFeedbackInstallPolicy,
    feedback_receipt: Mapping[str, Any],
    theoretical_memory: Mapping[str, Any],
    trace: Mapping[str, Any],
    observer_key: TrustedKey,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    observed_memory: Mapping[str, Any],
    memory_key: TrustedKey,
    feedback_key: TrustedKey,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    try:
        feedback = verify_toolz_post_route_feedback_receipt(
            feedback_receipt,
            expected_policy=policy.feedback_policy,
            theoretical_memory=theoretical_memory,
            trace=trace,
            observer_key=observer_key,
            fog_evidence=fog_evidence,
            cyber_evidence=cyber_evidence,
            observed_memory=observed_memory,
            memory_key=memory_key,
            feedback_key=feedback_key,
        )
    except Exception as exc:
        raise ToolzFeedbackInstallError("Toolzs feedback install feedback rejected") from exc
    theoretical = deepcopy(dict(theoretical_memory))
    observed = feedback.memory_receipt
    if toolz_store_context_identity(theoretical) != toolz_store_context_identity(observed):
        raise ToolzFeedbackInstallError("Toolzs feedback install memory context mismatch")
    return feedback.receipt, theoretical, observed


def verify_toolz_feedback_install_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_policy: ToolzFeedbackInstallPolicy,
    feedback_receipt: Mapping[str, Any],
    theoretical_memory: Mapping[str, Any],
    trace: Mapping[str, Any],
    observer_key: TrustedKey,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    observed_memory: Mapping[str, Any],
    memory_key: TrustedKey,
    feedback_key: TrustedKey,
    store_key: TrustedKey,
    before_cursor: ToolzStoreCursor,
    after_cursor: ToolzStoreCursor,
) -> ToolzFeedbackInstall:
    """Recompute every feedback, generation, cursor, time and signer binding."""

    if not isinstance(expected_policy, ToolzFeedbackInstallPolicy):
        raise ToolzFeedbackInstallError("Toolzs feedback install policy rejected")
    if not all(
        isinstance(key, TrustedKey)
        for key in (
            observer_key,
            memory_key,
            feedback_key,
            store_key,
        )
    ):
        raise ToolzFeedbackInstallError("Toolzs feedback install trust binding rejected")
    (
        stable_feedback,
        stable_theoretical,
        stable_trace,
        stable_fog,
        stable_cyber,
        stable_observed,
    ) = _freeze_inputs(
        feedback_receipt=feedback_receipt,
        theoretical_memory=theoretical_memory,
        trace=trace,
        fog_evidence=fog_evidence,
        cyber_evidence=cyber_evidence,
        observed_memory=observed_memory,
    )
    try:
        candidate = _freeze_mapping(receipt, "install receipt")
        validate("toolz-feedback-install-receipt", candidate)
    except Exception as exc:
        raise ToolzFeedbackInstallError("Toolzs feedback install receipt schema rejected") from exc
    if candidate["receipt_id"] != toolz_feedback_install_identity(candidate):
        raise ToolzFeedbackInstallError("Toolzs feedback install identity mismatch")
    if candidate["signature"]["key_id"] != store_key.key_id or not verify_signature(
        candidate, store_key.public_key
    ):
        raise ToolzFeedbackInstallError("Toolzs feedback install signature rejected")
    if candidate["authority_boundary"] != _FEEDBACK_INSTALL_BOUNDARY:
        raise ToolzFeedbackInstallError("Toolzs feedback install authority mismatch")
    feedback, theoretical, observed = _verified_feedback(
        policy=expected_policy,
        feedback_receipt=stable_feedback,
        theoretical_memory=stable_theoretical,
        trace=stable_trace,
        observer_key=observer_key,
        fog_evidence=stable_fog,
        cyber_evidence=stable_cyber,
        observed_memory=stable_observed,
        memory_key=memory_key,
        feedback_key=feedback_key,
    )
    tenant_id = observed["tenant_id"]
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
        status = ToolzFeedbackInstallStatus(candidate["store"]["transition"])
    except ValueError as exc:
        raise ToolzFeedbackInstallError("Toolzs feedback install transition rejected") from exc
    _validate_transition(before_cursor, after_cursor, status)
    _validate_timing(
        feedback_created_at=feedback["created_at"],
        memory_expires_at=observed["expires_at"],
        evaluated_at=candidate["timing"]["evaluated_at"],
        recorded_at=candidate["timing"]["recorded_at"],
        policy=expected_policy,
    )
    try:
        decision = evaluate_toolz_route_memory(
            observed,
            expected_policy=expected_policy.feedback_policy.memory_policy,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            authority_key=memory_key,
            evaluated_at=candidate["timing"]["evaluated_at"],
        )
    except Exception as exc:
        raise ToolzFeedbackInstallError("Toolzs feedback install evaluation rejected") from exc
    if decision is not ToolzRouteMemoryDecision.REUSE_CANDIDATE:
        raise ToolzFeedbackInstallError("Toolzs feedback install non-reusable decision rejected")
    expected = _expected_core(
        policy=expected_policy,
        feedback_receipt=feedback,
        theoretical_memory=theoretical,
        observed_memory=observed,
        before_cursor=before_cursor,
        after_cursor=after_cursor,
        status=status,
        evaluated_at=candidate["timing"]["evaluated_at"],
        recorded_at=candidate["timing"]["recorded_at"],
    )
    if _receipt_core(candidate) != expected:
        raise ToolzFeedbackInstallError("Toolzs feedback install recomputation mismatch")
    return ToolzFeedbackInstall(
        receipt=candidate,
        memory_receipt=observed,
        store_cursor=after_cursor,
        status=status,
    )


def install_toolz_post_route_feedback(
    *,
    policy: ToolzFeedbackInstallPolicy,
    feedback_receipt: Mapping[str, Any],
    theoretical_memory: Mapping[str, Any],
    trace: Mapping[str, Any],
    observer_key: TrustedKey,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    observed_memory: Mapping[str, Any],
    memory_key: TrustedKey,
    feedback_key: TrustedKey,
    store: ToolzRouteMemoryStore,
    expected_cursor: ToolzStoreCursor,
    evaluated_at: str,
    recorded_at: str,
    store_signer: Ed25519Signer,
) -> ToolzFeedbackInstall:
    """Promote one exact installed theoretical memory without executing it."""

    if not isinstance(policy, ToolzFeedbackInstallPolicy):
        raise ToolzFeedbackInstallError("Toolzs feedback install policy rejected")
    if not isinstance(store, ToolzRouteMemoryStore):
        raise ToolzFeedbackInstallError("Toolzs feedback install store rejected")
    if not isinstance(store_signer, Ed25519Signer):
        raise ToolzFeedbackInstallError("Toolzs feedback install signer rejected")
    (
        stable_feedback,
        stable_theoretical,
        stable_trace,
        stable_fog,
        stable_cyber,
        stable_observed,
    ) = _freeze_inputs(
        feedback_receipt=feedback_receipt,
        theoretical_memory=theoretical_memory,
        trace=trace,
        fog_evidence=fog_evidence,
        cyber_evidence=cyber_evidence,
        observed_memory=observed_memory,
    )
    feedback, theoretical, observed = _verified_feedback(
        policy=policy,
        feedback_receipt=stable_feedback,
        theoretical_memory=stable_theoretical,
        trace=stable_trace,
        observer_key=observer_key,
        fog_evidence=stable_fog,
        cyber_evidence=stable_cyber,
        observed_memory=stable_observed,
        memory_key=memory_key,
        feedback_key=feedback_key,
    )
    tenant_id = observed["tenant_id"]
    if store.store_id != policy.store_id or store.tenant_id != tenant_id:
        raise ToolzFeedbackInstallError("Toolzs feedback install store scope mismatch")
    _validate_cursor(
        expected_cursor,
        policy=policy,
        tenant_id=tenant_id,
        field="expected cursor",
    )
    _validate_timing(
        feedback_created_at=feedback["created_at"],
        memory_expires_at=observed["expires_at"],
        evaluated_at=evaluated_at,
        recorded_at=recorded_at,
        policy=policy,
    )
    try:
        decision = evaluate_toolz_route_memory(
            observed,
            expected_policy=policy.feedback_policy.memory_policy,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            authority_key=memory_key,
            evaluated_at=evaluated_at,
        )
    except Exception as exc:
        raise ToolzFeedbackInstallError("Toolzs feedback install evaluation rejected") from exc
    if decision is not ToolzRouteMemoryDecision.REUSE_CANDIDATE:
        raise ToolzFeedbackInstallError("Toolzs feedback install non-reusable decision rejected")

    context_id = toolz_store_context_identity(observed)
    try:
        entries = {
            entry["context_id"]: entry for entry in store.entries(expected_cursor=expected_cursor)
        }
    except Exception as exc:
        raise ToolzFeedbackInstallError("Toolzs feedback install store pre-check rejected") from exc
    planned_status = _classify_existing(
        entries.get(context_id),
        theoretical_memory=theoretical,
        observed_memory=observed,
    )

    before_cursor = expected_cursor
    try:
        after_cursor = store.put(
            observed,
            expected_cursor=before_cursor,
            expected_policy=policy.feedback_policy.memory_policy,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            memory_key=memory_key,
            evaluated_at=evaluated_at,
            recorded_at=recorded_at,
            store_signer=store_signer,
        )
    except Exception as exc:
        raise ToolzFeedbackInstallError(
            "Toolzs feedback install store transition rejected"
        ) from exc
    status = (
        ToolzFeedbackInstallStatus.ALREADY_PRESENT
        if after_cursor == before_cursor
        else ToolzFeedbackInstallStatus.PROMOTED
    )
    if status is not planned_status:
        raise ToolzFeedbackInstallError(
            "Toolzs feedback install transition classification mismatch"
        )
    _validate_transition(before_cursor, after_cursor, status)
    try:
        entries = {
            entry["context_id"]: entry for entry in store.entries(expected_cursor=after_cursor)
        }
        lookup = store.lookup(
            context_id,
            expected_cursor=after_cursor,
            expected_policy=policy.feedback_policy.memory_policy,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            memory_key=memory_key,
            evaluated_at=evaluated_at,
        )
    except Exception as exc:
        raise ToolzFeedbackInstallError(
            "Toolzs feedback install store post-check rejected"
        ) from exc
    expected_result_entry = _result_entry(
        theoretical_memory=theoretical,
        observed_memory=observed,
    )
    current_entry = entries.get(context_id)
    if (
        current_entry is None
        or _entry_projection(current_entry) != expected_result_entry
        or lookup is None
        or lookup.generation != 2
        or lookup.lifecycle is not ToolzStoreLifecycle.REUSABLE
        or lookup.decision is not ToolzRouteMemoryDecision.REUSE_CANDIDATE
        or toolz_route_memory_digest(lookup.receipt) != toolz_route_memory_digest(observed)
    ):
        raise ToolzFeedbackInstallError("Toolzs feedback install post-check rejected")

    core = _expected_core(
        policy=policy,
        feedback_receipt=feedback,
        theoretical_memory=theoretical,
        observed_memory=observed,
        before_cursor=before_cursor,
        after_cursor=after_cursor,
        status=status,
        evaluated_at=evaluated_at,
        recorded_at=recorded_at,
    )
    unsigned = {
        "receipt_id": toolz_feedback_install_identity(core),
        **core,
    }
    signed = store_signer.sign(unsigned)
    return verify_toolz_feedback_install_receipt(
        signed,
        expected_policy=policy,
        feedback_receipt=feedback,
        theoretical_memory=theoretical,
        trace=stable_trace,
        observer_key=observer_key,
        fog_evidence=stable_fog,
        cyber_evidence=stable_cyber,
        observed_memory=observed,
        memory_key=memory_key,
        feedback_key=feedback_key,
        store_key=TrustedKey(
            key_id=store_signer.key_id,
            public_key=store_signer.public_key,
        ),
        before_cursor=before_cursor,
        after_cursor=after_cursor,
    )
