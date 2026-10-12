"""Rollback-safe feedback-install recovery for Integrity 5.5 Uroboros.

Recovery accepts an externally retained pre-install cursor only when the fully
verified store head is unchanged or is its sole immediate descendant and that
descendant is the exact generation-one theoretical to generation-two
observed-success promotion described by the supplied a7 feedback evidence.

The operation is read-only.  It does not replay the a8 write, reconstruct the
lost a8 install receipt, choose a generic newest head, or grant execution.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import ValidationError

from .canonical import canonical_bytes, parse_json_strict
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
    toolz_route_memory_digest,
)
from .uroboros_toolzs_feedback import (
    toolz_post_route_feedback_digest,
    verify_toolz_post_route_feedback_receipt,
)
from .uroboros_toolzs_feedback_install import (
    ToolzFeedbackInstallPolicy,
    toolz_feedback_install_policy_digest,
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
    ToolzStoreRecoveryStatus,
    toolz_store_context_identity,
)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_FEEDBACK_RECOVERY_BOUNDARY = {
    "browser_control": False,
    "credentials": False,
    "execution": False,
    "feedback_install_receipt_reconstruction": False,
    "generic_newest_head": False,
    "global_publish": False,
    "historical_feedback_install_invocation": False,
    "local_storage": True,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
    "raw_ui_data": False,
    "rollback_bypass": False,
    "store_write": False,
    "tool_invocation": False,
}


class ToolzFeedbackRecoveryError(RuntimeError):
    """Raised when a retained cursor cannot prove one exact feedback outcome."""


@dataclass(frozen=True)
class ToolzFeedbackRecoveryPolicy:
    """Exact a8 policy and bounded recovery observation lag."""

    policy_id: str
    install_policy: ToolzFeedbackInstallPolicy
    max_evaluation_to_recovery_seconds: int = 300

    def __post_init__(self) -> None:
        if (
            not isinstance(self.policy_id, str)
            or _ID.fullmatch(self.policy_id) is None
            or "synthetic" not in self.policy_id
        ):
            raise ToolzFeedbackRecoveryError("Toolzs feedback recovery policy id rejected")
        if not isinstance(self.install_policy, ToolzFeedbackInstallPolicy):
            raise ToolzFeedbackRecoveryError("Toolzs feedback recovery policy rejected")
        if (
            not isinstance(self.max_evaluation_to_recovery_seconds, int)
            or isinstance(self.max_evaluation_to_recovery_seconds, bool)
            or not 0 <= self.max_evaluation_to_recovery_seconds <= 3_600
        ):
            raise ToolzFeedbackRecoveryError("Toolzs feedback recovery lag rejected")


@dataclass(frozen=True)
class ToolzFeedbackRecovery:
    """Signed recovery result and the fully verified open local store."""

    receipt: dict[str, Any]
    store: ToolzRouteMemoryStore
    store_cursor: ToolzStoreCursor
    status: ToolzStoreRecoveryStatus

    @property
    def execution_authority(self) -> bool:
        return False

    @property
    def storage_performed(self) -> bool:
        return False


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ToolzFeedbackRecoveryError(f"Toolzs feedback recovery {field} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolzFeedbackRecoveryError(f"Toolzs feedback recovery {field} rejected") from exc
    if parsed.tzinfo is None:
        raise ToolzFeedbackRecoveryError(f"Toolzs feedback recovery {field} rejected")
    return parsed


def _policy_document(policy: ToolzFeedbackRecoveryPolicy) -> dict[str, Any]:
    return {
        "policy_id": policy.policy_id,
        "install_policy_digest": toolz_feedback_install_policy_digest(policy.install_policy),
        "max_evaluation_to_recovery_seconds": (policy.max_evaluation_to_recovery_seconds),
        "head_semantics": (
            "retained-exact-predecessor-or-one-exact-feedback-promotion-"
            "descendant-never-generic-open"
        ),
        "mutation_semantics": "read-only-no-store-write",
        "receipt_semantics": "no-historical-feedback-install-reconstruction",
    }


def toolz_feedback_recovery_policy_digest(
    policy: ToolzFeedbackRecoveryPolicy,
) -> str:
    """Return the exact retained-cursor feedback recovery policy identity."""

    if not isinstance(policy, ToolzFeedbackRecoveryPolicy):
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery policy rejected")
    return digest_object(
        _policy_document(policy),
        domain="toolz-feedback-recovery-policy-v1",
    )


def _receipt_core(receipt: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(receipt))
    core.pop("receipt_id", None)
    core.pop("signature", None)
    return core


def toolz_feedback_recovery_identity(receipt: Mapping[str, Any]) -> str:
    """Return the domain-separated identity of an unsigned recovery receipt."""

    digest = digest_object(
        _receipt_core(receipt),
        domain="toolz-feedback-recovery-receipt-identity-v1",
    )
    return f"toolz-feedback-recovery-receipt:{digest.split(':', 1)[1]}"


def toolz_feedback_recovery_digest(receipt: Mapping[str, Any]) -> str:
    """Return the exact signed feedback recovery receipt digest."""

    return digest_object(
        dict(receipt),
        domain="toolz-feedback-recovery-signed-receipt-v1",
    )


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
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery input rejected") from exc


def _verified_feedback(
    *,
    policy: ToolzFeedbackRecoveryPolicy,
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
            expected_policy=policy.install_policy.feedback_policy,
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
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery feedback rejected") from exc
    return (
        feedback.receipt,
        deepcopy(dict(theoretical_memory)),
        feedback.memory_receipt,
    )


def _feedback_reference(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "receipt_id": receipt["receipt_id"],
        "receipt_digest": toolz_post_route_feedback_digest(receipt),
        "policy_id": receipt["policy_id"],
        "policy_digest": receipt["policy_digest"],
        "decision": receipt["decision"],
        "created_at": receipt["created_at"],
    }


def _memory_reference(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "receipt_id": receipt["receipt_id"],
        "receipt_digest": toolz_route_memory_digest(receipt),
        "context_id": toolz_store_context_identity(receipt),
        "outcome": receipt["observation"]["outcome"],
        "observed_at": receipt["observation"]["observed_at"],
        "evidence_digest": receipt["observation"]["evidence_digest"],
        "created_at": receipt["created_at"],
        "expires_at": receipt["expires_at"],
    }


def _predecessor_entry(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "context_id": toolz_store_context_identity(receipt),
        "generation": 1,
        "receipt_id": receipt["receipt_id"],
        "receipt_digest": toolz_route_memory_digest(receipt),
        "previous_receipt_digest": None,
        "lifecycle": ToolzStoreLifecycle.THEORETICAL.value,
        "decision": "explore",
        "invalidation_reason": None,
    }


def _result_entry(
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
        "decision": "reuse-candidate",
        "invalidation_reason": None,
    }


def _validate_cursor(
    cursor: ToolzStoreCursor,
    *,
    policy: ToolzFeedbackRecoveryPolicy,
    tenant_id: str,
    field: str,
) -> None:
    if (
        not isinstance(cursor, ToolzStoreCursor)
        or cursor.store_id != policy.install_policy.store_id
        or cursor.tenant_id != tenant_id
    ):
        raise ToolzFeedbackRecoveryError(f"Toolzs feedback recovery {field} rejected")


def _validate_transition(
    retained_cursor: ToolzStoreCursor,
    recovered_cursor: ToolzStoreCursor,
    status: ToolzStoreRecoveryStatus,
) -> None:
    if status is ToolzStoreRecoveryStatus.RETAINED_HEAD:
        if recovered_cursor != retained_cursor:
            raise ToolzFeedbackRecoveryError("Toolzs feedback recovery retained cursor mismatch")
        return
    if status is not ToolzStoreRecoveryStatus.RECOVERED_FEEDBACK_INSTALL:
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery status rejected")
    if (
        recovered_cursor.sequence != retained_cursor.sequence + 1
        or recovered_cursor.manifest_id == retained_cursor.manifest_id
        or recovered_cursor.manifest_digest == retained_cursor.manifest_digest
    ):
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery descendant transition rejected")


def _validate_request_timing(
    *,
    feedback_created_at: str,
    memory_expires_at: str,
    evaluated_at: str,
    recovered_at: str,
    policy: ToolzFeedbackRecoveryPolicy,
) -> tuple[datetime, datetime, datetime, datetime]:
    feedback_time = _parse_time(feedback_created_at, "feedback time")
    expiry_time = _parse_time(memory_expires_at, "memory expiry")
    evaluated_time = _parse_time(evaluated_at, "evaluation time")
    recovered_time = _parse_time(recovered_at, "recovery time")
    if not feedback_time <= evaluated_time <= recovered_time or recovered_time >= expiry_time:
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery causal timing rejected")
    if (
        recovered_time - evaluated_time
    ).total_seconds() > policy.max_evaluation_to_recovery_seconds:
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery evaluation lag rejected")
    return feedback_time, expiry_time, evaluated_time, recovered_time


def _validate_timing(
    *,
    feedback_created_at: str,
    memory_expires_at: str,
    manifest_created_at: str,
    status: ToolzStoreRecoveryStatus,
    evaluated_at: str,
    recovered_at: str,
    policy: ToolzFeedbackRecoveryPolicy,
) -> None:
    feedback_time, expiry_time, evaluated_time, _ = _validate_request_timing(
        feedback_created_at=feedback_created_at,
        memory_expires_at=memory_expires_at,
        evaluated_at=evaluated_at,
        recovered_at=recovered_at,
        policy=policy,
    )
    manifest_time = _parse_time(
        manifest_created_at,
        "manifest creation time",
    )
    if manifest_time > evaluated_time:
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery causal timing rejected")
    if (
        status is ToolzStoreRecoveryStatus.RECOVERED_FEEDBACK_INSTALL
        and not feedback_time <= manifest_time < expiry_time
    ):
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery install timing rejected")


def _expected_core(
    *,
    policy: ToolzFeedbackRecoveryPolicy,
    feedback_receipt: Mapping[str, Any],
    theoretical_memory: Mapping[str, Any],
    observed_memory: Mapping[str, Any],
    retained_cursor: ToolzStoreCursor,
    recovered_cursor: ToolzStoreCursor,
    status: ToolzStoreRecoveryStatus,
    manifest_created_at: str,
    evaluated_at: str,
    recovered_at: str,
) -> dict[str, Any]:
    return {
        "protocol": "integrity-guardian/toolz-feedback-recovery-receipt/v1",
        "tenant_id": observed_memory["tenant_id"],
        "policy_id": policy.policy_id,
        "policy_digest": toolz_feedback_recovery_policy_digest(policy),
        "install_policy_digest": toolz_feedback_install_policy_digest(policy.install_policy),
        "feedback": _feedback_reference(feedback_receipt),
        "theoretical_memory": _memory_reference(theoretical_memory),
        "observed_memory": _memory_reference(observed_memory),
        "store": {
            "store_id": policy.install_policy.store_id,
            "retained_cursor": retained_cursor.to_document(),
            "recovered_cursor": recovered_cursor.to_document(),
            "status": status.value,
            "maximum_descendant_distance": 1,
            "recovered_manifest_created_at": manifest_created_at,
            "required_predecessor": _predecessor_entry(theoretical_memory),
            "expected_promoted_entry": _result_entry(
                theoretical_memory,
                observed_memory,
            ),
        },
        "timing": {
            "evaluated_at": evaluated_at,
            "recovered_at": recovered_at,
        },
        "authority_boundary": deepcopy(_FEEDBACK_RECOVERY_BOUNDARY),
    }


def verify_toolz_feedback_recovery_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_policy: ToolzFeedbackRecoveryPolicy,
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
    retained_cursor: ToolzStoreCursor,
    recovered_cursor: ToolzStoreCursor,
) -> dict[str, Any]:
    """Verify feedback, time, cursor, policy and store-signer bindings."""

    if not isinstance(expected_policy, ToolzFeedbackRecoveryPolicy):
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery policy rejected")
    if not all(
        isinstance(key, TrustedKey)
        for key in (
            observer_key,
            memory_key,
            feedback_key,
            store_key,
        )
    ):
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery trust binding rejected")
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
        candidate = parse_json_strict(canonical_bytes(dict(receipt)))
        validate("toolz-feedback-recovery-receipt", candidate)
    except (TypeError, ValueError, ValidationError) as exc:
        raise ToolzFeedbackRecoveryError(
            "Toolzs feedback recovery receipt schema rejected"
        ) from exc
    if candidate["receipt_id"] != toolz_feedback_recovery_identity(candidate):
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery identity mismatch")
    if candidate["signature"]["key_id"] != store_key.key_id or not (
        verify_signature(candidate, store_key.public_key)
    ):
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery signature rejected")
    if candidate["authority_boundary"] != _FEEDBACK_RECOVERY_BOUNDARY:
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery authority mismatch")
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
        retained_cursor,
        policy=expected_policy,
        tenant_id=tenant_id,
        field="retained cursor",
    )
    _validate_cursor(
        recovered_cursor,
        policy=expected_policy,
        tenant_id=tenant_id,
        field="recovered cursor",
    )
    try:
        status = ToolzStoreRecoveryStatus(candidate["store"]["status"])
    except ValueError as exc:
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery status rejected") from exc
    _validate_transition(retained_cursor, recovered_cursor, status)
    _validate_timing(
        feedback_created_at=feedback["created_at"],
        memory_expires_at=observed["expires_at"],
        manifest_created_at=candidate["store"]["recovered_manifest_created_at"],
        status=status,
        evaluated_at=candidate["timing"]["evaluated_at"],
        recovered_at=candidate["timing"]["recovered_at"],
        policy=expected_policy,
    )
    expected = _expected_core(
        policy=expected_policy,
        feedback_receipt=feedback,
        theoretical_memory=theoretical,
        observed_memory=observed,
        retained_cursor=retained_cursor,
        recovered_cursor=recovered_cursor,
        status=status,
        manifest_created_at=candidate["store"]["recovered_manifest_created_at"],
        evaluated_at=candidate["timing"]["evaluated_at"],
        recovered_at=candidate["timing"]["recovered_at"],
    )
    if _receipt_core(candidate) != expected:
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery recomputation mismatch")
    return candidate


def recover_toolz_feedback_install(
    *,
    policy: ToolzFeedbackRecoveryPolicy,
    feedback_receipt: Mapping[str, Any],
    theoretical_memory: Mapping[str, Any],
    trace: Mapping[str, Any],
    observer_key: TrustedKey,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    observed_memory: Mapping[str, Any],
    memory_key: TrustedKey,
    feedback_key: TrustedKey,
    store_root: Path,
    store_key: TrustedKey,
    store_signer: Ed25519Signer,
    retained_cursor: ToolzStoreCursor,
    evaluated_at: str,
    recovered_at: str,
) -> ToolzFeedbackRecovery:
    """Recover an unchanged predecessor or one exact lost a8 promotion."""

    if not isinstance(policy, ToolzFeedbackRecoveryPolicy):
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery policy rejected")
    if not isinstance(store_root, Path):
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery root rejected")
    if not isinstance(store_key, TrustedKey) or not isinstance(
        store_signer,
        Ed25519Signer,
    ):
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery store trust rejected")
    if store_signer.key_id != store_key.key_id or public_key_fingerprint(
        store_signer.public_key
    ) != public_key_fingerprint(store_key.public_key):
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery signer mismatch")
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
    _validate_request_timing(
        feedback_created_at=feedback["created_at"],
        memory_expires_at=observed["expires_at"],
        evaluated_at=evaluated_at,
        recovered_at=recovered_at,
        policy=policy,
    )
    try:
        store_recovery = ToolzRouteMemoryStore.recover_one_step_feedback_install(
            store_root,
            store_id=policy.install_policy.store_id,
            tenant_id=observed["tenant_id"],
            authority_key=store_key,
            retained_cursor=retained_cursor,
            theoretical_receipt=theoretical,
            observed_receipt=observed,
            expected_policy=(policy.install_policy.feedback_policy.memory_policy),
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            memory_key=memory_key,
            feedback_created_at=feedback["created_at"],
            evaluated_at=evaluated_at,
        )
    except Exception as exc:
        raise ToolzFeedbackRecoveryError("Toolzs feedback recovery store proof rejected") from exc
    try:
        if store_recovery.status not in {
            ToolzStoreRecoveryStatus.RETAINED_HEAD,
            ToolzStoreRecoveryStatus.RECOVERED_FEEDBACK_INSTALL,
        }:
            raise ToolzFeedbackRecoveryError("Toolzs feedback recovery status rejected")
        _validate_timing(
            feedback_created_at=feedback["created_at"],
            memory_expires_at=observed["expires_at"],
            manifest_created_at=store_recovery.manifest_created_at,
            status=store_recovery.status,
            evaluated_at=evaluated_at,
            recovered_at=recovered_at,
            policy=policy,
        )
        core = _expected_core(
            policy=policy,
            feedback_receipt=feedback,
            theoretical_memory=theoretical,
            observed_memory=observed,
            retained_cursor=retained_cursor,
            recovered_cursor=store_recovery.cursor,
            status=store_recovery.status,
            manifest_created_at=store_recovery.manifest_created_at,
            evaluated_at=evaluated_at,
            recovered_at=recovered_at,
        )
        unsigned = {
            "receipt_id": toolz_feedback_recovery_identity(core),
            **core,
        }
        signed = store_signer.sign(unsigned)
        verified = verify_toolz_feedback_recovery_receipt(
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
            store_key=store_key,
            retained_cursor=retained_cursor,
            recovered_cursor=store_recovery.cursor,
        )
        return ToolzFeedbackRecovery(
            receipt=verified,
            store=store_recovery.store,
            store_cursor=store_recovery.cursor,
            status=store_recovery.status,
        )
    except Exception:
        store_recovery.store.close()
        raise
