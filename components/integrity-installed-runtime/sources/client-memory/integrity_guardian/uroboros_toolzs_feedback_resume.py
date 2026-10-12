"""Crash-idempotent feedback resume composition for Integrity 5.5 Uroboros.

The coordinator composes the exact a9 retained-cursor proof with the existing
a8 feedback installer.  It writes only when a9 proves that the exact
generation-one predecessor is still current.  If the sole exact promotion
child already committed, the same request returns a read-only recovered
result.

No store format or direct write primitive is added.  The coordinator never
trusts a generic newest head, reconstructs a lost historical a8 receipt, or
grants execution authority.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
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
from .uroboros_toolzs import ToolzCyberEvidence, ToolzFogRouteEvidence
from .uroboros_toolzs_feedback import toolz_post_route_feedback_digest
from .uroboros_toolzs_feedback_install import (
    ToolzFeedbackInstallStatus,
    install_toolz_post_route_feedback,
    toolz_feedback_install_digest,
    toolz_feedback_install_policy_digest,
    verify_toolz_feedback_install_receipt,
)
from .uroboros_toolzs_feedback_recovery import (
    ToolzFeedbackRecoveryPolicy,
    recover_toolz_feedback_install,
    toolz_feedback_recovery_digest,
    toolz_feedback_recovery_policy_digest,
    verify_toolz_feedback_recovery_receipt,
)
from .uroboros_toolzs_install import (
    _freeze_cyber_evidence,
    _freeze_fog_evidence,
    _freeze_mapping,
)
from .uroboros_toolzs_store import (
    ToolzRouteMemoryStore,
    ToolzRouteStoreError,
    ToolzStoreCursor,
    ToolzStoreRecoveryStatus,
)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_FEEDBACK_RESUME_BOUNDARY = {
    "bounded_cross_process_recovery": True,
    "browser_control": False,
    "credentials": False,
    "execution": False,
    "generic_newest_head": False,
    "global_publish": False,
    "historical_install_receipt_reconstruction": False,
    "local_storage": True,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
    "raw_ui_data": False,
    "rollback_bypass": False,
    "store_write": True,
    "tool_invocation": False,
}


class ToolzFeedbackResumeError(RuntimeError):
    """Raised before an ambiguous feedback resume outcome can be accepted."""


class ToolzFeedbackResumeStatus(StrEnum):
    """Two exact outcomes of one crash-idempotent resume request."""

    INSTALLED = "installed"
    RECOVERED = "recovered"


@dataclass(frozen=True)
class ToolzFeedbackResumePolicy:
    """Exact a9/a8 composition plus a total bounded completion window."""

    policy_id: str
    recovery_policy: ToolzFeedbackRecoveryPolicy
    max_resume_seconds: int = 300

    def __post_init__(self) -> None:
        if (
            not isinstance(self.policy_id, str)
            or _ID.fullmatch(self.policy_id) is None
            or "synthetic" not in self.policy_id
        ):
            raise ToolzFeedbackResumeError("Toolzs feedback resume policy id rejected")
        if not isinstance(
            self.recovery_policy,
            ToolzFeedbackRecoveryPolicy,
        ):
            raise ToolzFeedbackResumeError("Toolzs feedback resume policy rejected")
        if (
            not isinstance(self.max_resume_seconds, int)
            or isinstance(self.max_resume_seconds, bool)
            or not 0 <= self.max_resume_seconds <= 3_600
        ):
            raise ToolzFeedbackResumeError("Toolzs feedback resume window rejected")


@dataclass(frozen=True)
class ToolzFeedbackResume:
    """Signed resume result, nested proofs and fully verified open store."""

    receipt: dict[str, Any]
    recovery_receipt: dict[str, Any]
    install_receipt: dict[str, Any] | None
    store: ToolzRouteMemoryStore
    store_cursor: ToolzStoreCursor
    status: ToolzFeedbackResumeStatus

    @property
    def execution_authority(self) -> bool:
        return False

    @property
    def storage_performed(self) -> bool:
        return self.status is ToolzFeedbackResumeStatus.INSTALLED


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ToolzFeedbackResumeError(f"Toolzs feedback resume {field} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolzFeedbackResumeError(f"Toolzs feedback resume {field} rejected") from exc
    if parsed.tzinfo is None:
        raise ToolzFeedbackResumeError(f"Toolzs feedback resume {field} rejected")
    return parsed


def _policy_document(policy: ToolzFeedbackResumePolicy) -> dict[str, Any]:
    return {
        "policy_id": policy.policy_id,
        "recovery_policy_digest": toolz_feedback_recovery_policy_digest(policy.recovery_policy),
        "install_policy_digest": toolz_feedback_install_policy_digest(
            policy.recovery_policy.install_policy
        ),
        "max_resume_seconds": policy.max_resume_seconds,
        "outcome_semantics": (
            "retained-head-invokes-exact-install-or-exact-child-returns-read-only-recovery"
        ),
        "persistence_semantics": "reuse-existing-a8-store-transaction-only",
    }


def toolz_feedback_resume_policy_digest(
    policy: ToolzFeedbackResumePolicy,
) -> str:
    """Return the exact a10 resume policy identity."""

    if not isinstance(policy, ToolzFeedbackResumePolicy):
        raise ToolzFeedbackResumeError("Toolzs feedback resume policy rejected")
    return digest_object(
        _policy_document(policy),
        domain="toolz-feedback-resume-policy-v1",
    )


def _receipt_core(receipt: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(receipt))
    core.pop("receipt_id", None)
    core.pop("signature", None)
    return core


def toolz_feedback_resume_identity(receipt: Mapping[str, Any]) -> str:
    """Return the domain-separated identity of an unsigned resume receipt."""

    digest = digest_object(
        _receipt_core(receipt),
        domain="toolz-feedback-resume-receipt-identity-v1",
    )
    return f"toolz-feedback-resume-receipt:{digest.split(':', 1)[1]}"


def toolz_feedback_resume_digest(receipt: Mapping[str, Any]) -> str:
    """Return the exact signed resume receipt digest."""

    return digest_object(
        dict(receipt),
        domain="toolz-feedback-resume-signed-receipt-v1",
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
        raise ToolzFeedbackResumeError("Toolzs feedback resume input rejected") from exc


def _feedback_reference(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "receipt_id": receipt["receipt_id"],
        "receipt_digest": toolz_post_route_feedback_digest(receipt),
        "policy_id": receipt["policy_id"],
        "policy_digest": receipt["policy_digest"],
        "decision": receipt["decision"],
        "created_at": receipt["created_at"],
    }


def _recovery_reference(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "receipt_id": receipt["receipt_id"],
        "receipt_digest": toolz_feedback_recovery_digest(receipt),
        "policy_digest": receipt["policy_digest"],
        "status": receipt["store"]["status"],
        "retained_cursor": deepcopy(receipt["store"]["retained_cursor"]),
        "recovered_cursor": deepcopy(receipt["store"]["recovered_cursor"]),
    }


def _install_reference(
    receipt: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if receipt is None:
        return {
            "performed": False,
            "receipt_id": None,
            "receipt_digest": None,
            "transition": None,
        }
    return {
        "performed": True,
        "receipt_id": receipt["receipt_id"],
        "receipt_digest": toolz_feedback_install_digest(receipt),
        "transition": receipt["store"]["transition"],
    }


def _validate_cursor(
    cursor: ToolzStoreCursor,
    *,
    policy: ToolzFeedbackResumePolicy,
    tenant_id: str,
    field: str,
) -> None:
    if (
        not isinstance(cursor, ToolzStoreCursor)
        or cursor.store_id != policy.recovery_policy.install_policy.store_id
        or cursor.tenant_id != tenant_id
    ):
        raise ToolzFeedbackResumeError(f"Toolzs feedback resume {field} rejected")


def _validate_timing(
    *,
    feedback_created_at: str,
    memory_expires_at: str,
    recovery_evaluated_at: str,
    resume_started_at: str,
    resume_completed_at: str,
    policy: ToolzFeedbackResumePolicy,
) -> None:
    feedback_time = _parse_time(feedback_created_at, "feedback time")
    expiry_time = _parse_time(memory_expires_at, "memory expiry")
    recovery_time = _parse_time(
        recovery_evaluated_at,
        "recovery evaluation time",
    )
    started_time = _parse_time(resume_started_at, "start time")
    completed_time = _parse_time(resume_completed_at, "completion time")
    if not (feedback_time <= recovery_time <= started_time <= completed_time < expiry_time):
        raise ToolzFeedbackResumeError("Toolzs feedback resume causal timing rejected")
    if (completed_time - recovery_time).total_seconds() > policy.max_resume_seconds:
        raise ToolzFeedbackResumeError("Toolzs feedback resume completion window rejected")


def _validate_input_timing(
    *,
    feedback_receipt: Mapping[str, Any],
    observed_memory: Mapping[str, Any],
    recovery_evaluated_at: str,
    resume_started_at: str,
    resume_completed_at: str,
    policy: ToolzFeedbackResumePolicy,
) -> None:
    try:
        feedback_created_at = feedback_receipt["created_at"]
        memory_expires_at = observed_memory["expires_at"]
    except (KeyError, TypeError) as exc:
        raise ToolzFeedbackResumeError("Toolzs feedback resume timing input rejected") from exc
    _validate_timing(
        feedback_created_at=feedback_created_at,
        memory_expires_at=memory_expires_at,
        recovery_evaluated_at=recovery_evaluated_at,
        resume_started_at=resume_started_at,
        resume_completed_at=resume_completed_at,
        policy=policy,
    )


def _validate_transition(
    *,
    status: ToolzFeedbackResumeStatus,
    retained_cursor: ToolzStoreCursor,
    recovery_cursor: ToolzStoreCursor,
    final_cursor: ToolzStoreCursor,
    recovery_status: ToolzStoreRecoveryStatus,
    install_status: ToolzFeedbackInstallStatus | None,
) -> None:
    if status is ToolzFeedbackResumeStatus.INSTALLED:
        if (
            recovery_status is not ToolzStoreRecoveryStatus.RETAINED_HEAD
            or recovery_cursor != retained_cursor
            or install_status is not ToolzFeedbackInstallStatus.PROMOTED
            or final_cursor.sequence != retained_cursor.sequence + 1
        ):
            raise ToolzFeedbackResumeError("Toolzs feedback resume installed transition rejected")
    elif (
        recovery_status is not ToolzStoreRecoveryStatus.RECOVERED_FEEDBACK_INSTALL
        or install_status is not None
        or recovery_cursor != final_cursor
        or final_cursor.sequence != retained_cursor.sequence + 1
    ):
        raise ToolzFeedbackResumeError("Toolzs feedback resume recovered transition rejected")
    if (
        final_cursor.manifest_id == retained_cursor.manifest_id
        or final_cursor.manifest_digest == retained_cursor.manifest_digest
    ):
        raise ToolzFeedbackResumeError("Toolzs feedback resume final cursor rejected")


def _expected_core(
    *,
    policy: ToolzFeedbackResumePolicy,
    feedback_receipt: Mapping[str, Any],
    recovery_receipt: Mapping[str, Any],
    install_receipt: Mapping[str, Any] | None,
    retained_cursor: ToolzStoreCursor,
    recovery_cursor: ToolzStoreCursor,
    final_cursor: ToolzStoreCursor,
    status: ToolzFeedbackResumeStatus,
    recovery_evaluated_at: str,
    resume_started_at: str,
    resume_completed_at: str,
) -> dict[str, Any]:
    return {
        "protocol": "integrity-guardian/toolz-feedback-resume-receipt/v1",
        "tenant_id": retained_cursor.tenant_id,
        "policy_id": policy.policy_id,
        "policy_digest": toolz_feedback_resume_policy_digest(policy),
        "recovery_policy_digest": toolz_feedback_recovery_policy_digest(policy.recovery_policy),
        "install_policy_digest": toolz_feedback_install_policy_digest(
            policy.recovery_policy.install_policy
        ),
        "feedback": _feedback_reference(feedback_receipt),
        "recovery": _recovery_reference(recovery_receipt),
        "installation": _install_reference(install_receipt),
        "store": {
            "store_id": policy.recovery_policy.install_policy.store_id,
            "retained_cursor": retained_cursor.to_document(),
            "recovery_cursor": recovery_cursor.to_document(),
            "final_cursor": final_cursor.to_document(),
            "status": status.value,
            "maximum_descendant_distance": 1,
        },
        "timing": {
            "recovery_evaluated_at": recovery_evaluated_at,
            "resume_started_at": resume_started_at,
            "resume_completed_at": resume_completed_at,
        },
        "authority_boundary": deepcopy(_FEEDBACK_RESUME_BOUNDARY),
    }


def verify_toolz_feedback_resume_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_policy: ToolzFeedbackResumePolicy,
    recovery_receipt: Mapping[str, Any],
    install_receipt: Mapping[str, Any] | None,
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
    final_cursor: ToolzStoreCursor,
) -> dict[str, Any]:
    """Recompute nested a9/a8 proofs and the exact two-outcome transition."""

    if not isinstance(expected_policy, ToolzFeedbackResumePolicy):
        raise ToolzFeedbackResumeError("Toolzs feedback resume policy rejected")
    if not all(
        isinstance(key, TrustedKey)
        for key in (
            observer_key,
            memory_key,
            feedback_key,
            store_key,
        )
    ):
        raise ToolzFeedbackResumeError("Toolzs feedback resume trust binding rejected")
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
        stable_recovery = _freeze_mapping(
            recovery_receipt,
            "recovery receipt",
        )
        stable_install = (
            None if install_receipt is None else _freeze_mapping(install_receipt, "install receipt")
        )
        validate("toolz-feedback-resume-receipt", candidate)
    except (TypeError, ValueError, ValidationError) as exc:
        raise ToolzFeedbackResumeError("Toolzs feedback resume receipt schema rejected") from exc
    if candidate["receipt_id"] != toolz_feedback_resume_identity(candidate):
        raise ToolzFeedbackResumeError("Toolzs feedback resume identity mismatch")
    if candidate["signature"]["key_id"] != store_key.key_id or not (
        verify_signature(candidate, store_key.public_key)
    ):
        raise ToolzFeedbackResumeError("Toolzs feedback resume signature rejected")
    if candidate["authority_boundary"] != _FEEDBACK_RESUME_BOUNDARY:
        raise ToolzFeedbackResumeError("Toolzs feedback resume authority mismatch")
    try:
        status = ToolzFeedbackResumeStatus(candidate["store"]["status"])
        recovery_cursor = ToolzStoreCursor.from_document(candidate["store"]["recovery_cursor"])
    except (ValueError, TypeError, ToolzRouteStoreError) as exc:
        raise ToolzFeedbackResumeError("Toolzs feedback resume status or cursor rejected") from exc
    try:
        verified_recovery = verify_toolz_feedback_recovery_receipt(
            stable_recovery,
            expected_policy=expected_policy.recovery_policy,
            feedback_receipt=stable_feedback,
            theoretical_memory=stable_theoretical,
            trace=stable_trace,
            observer_key=observer_key,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            observed_memory=stable_observed,
            memory_key=memory_key,
            feedback_key=feedback_key,
            store_key=store_key,
            retained_cursor=retained_cursor,
            recovered_cursor=recovery_cursor,
        )
    except Exception as exc:
        raise ToolzFeedbackResumeError("Toolzs feedback resume recovery proof rejected") from exc
    tenant_id = stable_observed["tenant_id"]
    _validate_cursor(
        retained_cursor,
        policy=expected_policy,
        tenant_id=tenant_id,
        field="retained cursor",
    )
    _validate_cursor(
        recovery_cursor,
        policy=expected_policy,
        tenant_id=tenant_id,
        field="recovery cursor",
    )
    _validate_cursor(
        final_cursor,
        policy=expected_policy,
        tenant_id=tenant_id,
        field="final cursor",
    )
    try:
        recovery_status = ToolzStoreRecoveryStatus(verified_recovery["store"]["status"])
    except ValueError as exc:
        raise ToolzFeedbackResumeError("Toolzs feedback resume recovery status rejected") from exc
    verified_install: dict[str, Any] | None = None
    install_status: ToolzFeedbackInstallStatus | None = None
    if status is ToolzFeedbackResumeStatus.INSTALLED:
        if stable_install is None:
            raise ToolzFeedbackResumeError("Toolzs feedback resume install proof is absent")
        try:
            installed = verify_toolz_feedback_install_receipt(
                stable_install,
                expected_policy=(expected_policy.recovery_policy.install_policy),
                feedback_receipt=stable_feedback,
                theoretical_memory=stable_theoretical,
                trace=stable_trace,
                observer_key=observer_key,
                fog_evidence=stable_fog,
                cyber_evidence=stable_cyber,
                observed_memory=stable_observed,
                memory_key=memory_key,
                feedback_key=feedback_key,
                store_key=store_key,
                before_cursor=recovery_cursor,
                after_cursor=final_cursor,
            )
        except Exception as exc:
            raise ToolzFeedbackResumeError("Toolzs feedback resume install proof rejected") from exc
        verified_install = installed.receipt
        install_status = installed.status
    elif stable_install is not None:
        raise ToolzFeedbackResumeError("Toolzs feedback resume unexpected install proof rejected")
    _validate_transition(
        status=status,
        retained_cursor=retained_cursor,
        recovery_cursor=recovery_cursor,
        final_cursor=final_cursor,
        recovery_status=recovery_status,
        install_status=install_status,
    )
    _validate_timing(
        feedback_created_at=stable_feedback["created_at"],
        memory_expires_at=stable_observed["expires_at"],
        recovery_evaluated_at=candidate["timing"]["recovery_evaluated_at"],
        resume_started_at=candidate["timing"]["resume_started_at"],
        resume_completed_at=candidate["timing"]["resume_completed_at"],
        policy=expected_policy,
    )
    if (
        verified_recovery["timing"]["evaluated_at"] != candidate["timing"]["recovery_evaluated_at"]
        or verified_recovery["timing"]["recovered_at"] != candidate["timing"]["resume_started_at"]
    ):
        raise ToolzFeedbackResumeError("Toolzs feedback resume recovery timing mismatch")
    if verified_install is not None and (
        verified_install["timing"]["evaluated_at"] != candidate["timing"]["resume_started_at"]
        or verified_install["timing"]["recorded_at"] != candidate["timing"]["resume_completed_at"]
    ):
        raise ToolzFeedbackResumeError("Toolzs feedback resume install timing mismatch")
    expected = _expected_core(
        policy=expected_policy,
        feedback_receipt=stable_feedback,
        recovery_receipt=verified_recovery,
        install_receipt=verified_install,
        retained_cursor=retained_cursor,
        recovery_cursor=recovery_cursor,
        final_cursor=final_cursor,
        status=status,
        recovery_evaluated_at=candidate["timing"]["recovery_evaluated_at"],
        resume_started_at=candidate["timing"]["resume_started_at"],
        resume_completed_at=candidate["timing"]["resume_completed_at"],
    )
    if _receipt_core(candidate) != expected:
        raise ToolzFeedbackResumeError("Toolzs feedback resume recomputation mismatch")
    return candidate


def resume_toolz_feedback_install(
    *,
    policy: ToolzFeedbackResumePolicy,
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
    recovery_evaluated_at: str,
    resume_started_at: str,
    resume_completed_at: str,
) -> ToolzFeedbackResume:
    """Install from the exact predecessor or recover its exact committed child."""

    if not isinstance(policy, ToolzFeedbackResumePolicy):
        raise ToolzFeedbackResumeError("Toolzs feedback resume policy rejected")
    if not isinstance(store_root, Path):
        raise ToolzFeedbackResumeError("Toolzs feedback resume root rejected")
    if not isinstance(store_key, TrustedKey) or not isinstance(
        store_signer,
        Ed25519Signer,
    ):
        raise ToolzFeedbackResumeError("Toolzs feedback resume store trust rejected")
    if store_signer.key_id != store_key.key_id or public_key_fingerprint(
        store_signer.public_key
    ) != public_key_fingerprint(store_key.public_key):
        raise ToolzFeedbackResumeError("Toolzs feedback resume signer mismatch")
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
    _validate_input_timing(
        feedback_receipt=stable_feedback,
        observed_memory=stable_observed,
        recovery_evaluated_at=recovery_evaluated_at,
        resume_started_at=resume_started_at,
        resume_completed_at=resume_completed_at,
        policy=policy,
    )
    try:
        recovery = recover_toolz_feedback_install(
            policy=policy.recovery_policy,
            feedback_receipt=stable_feedback,
            theoretical_memory=stable_theoretical,
            trace=stable_trace,
            observer_key=observer_key,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            observed_memory=stable_observed,
            memory_key=memory_key,
            feedback_key=feedback_key,
            store_root=store_root,
            store_key=store_key,
            store_signer=store_signer,
            retained_cursor=retained_cursor,
            evaluated_at=recovery_evaluated_at,
            recovered_at=resume_started_at,
        )
    except Exception as exc:
        raise ToolzFeedbackResumeError("Toolzs feedback resume recovery rejected") from exc
    try:
        install_receipt: dict[str, Any] | None
        if recovery.status is ToolzStoreRecoveryStatus.RETAINED_HEAD:
            try:
                install = install_toolz_post_route_feedback(
                    policy=policy.recovery_policy.install_policy,
                    feedback_receipt=stable_feedback,
                    theoretical_memory=stable_theoretical,
                    trace=stable_trace,
                    observer_key=observer_key,
                    fog_evidence=stable_fog,
                    cyber_evidence=stable_cyber,
                    observed_memory=stable_observed,
                    memory_key=memory_key,
                    feedback_key=feedback_key,
                    store=recovery.store,
                    expected_cursor=recovery.store_cursor,
                    evaluated_at=resume_started_at,
                    recorded_at=resume_completed_at,
                    store_signer=store_signer,
                )
            except Exception as exc:
                raise ToolzFeedbackResumeError("Toolzs feedback resume install rejected") from exc
            if install.status is not ToolzFeedbackInstallStatus.PROMOTED:
                raise ToolzFeedbackResumeError("Toolzs feedback resume install outcome rejected")
            status = ToolzFeedbackResumeStatus.INSTALLED
            final_cursor = install.store_cursor
            install_receipt = install.receipt
        elif recovery.status is ToolzStoreRecoveryStatus.RECOVERED_FEEDBACK_INSTALL:
            status = ToolzFeedbackResumeStatus.RECOVERED
            final_cursor = recovery.store_cursor
            install_receipt = None
        else:
            raise ToolzFeedbackResumeError("Toolzs feedback resume recovery outcome rejected")
        _validate_transition(
            status=status,
            retained_cursor=retained_cursor,
            recovery_cursor=recovery.store_cursor,
            final_cursor=final_cursor,
            recovery_status=recovery.status,
            install_status=(
                None if install_receipt is None else ToolzFeedbackInstallStatus.PROMOTED
            ),
        )
        core = _expected_core(
            policy=policy,
            feedback_receipt=stable_feedback,
            recovery_receipt=recovery.receipt,
            install_receipt=install_receipt,
            retained_cursor=retained_cursor,
            recovery_cursor=recovery.store_cursor,
            final_cursor=final_cursor,
            status=status,
            recovery_evaluated_at=recovery_evaluated_at,
            resume_started_at=resume_started_at,
            resume_completed_at=resume_completed_at,
        )
        unsigned = {
            "receipt_id": toolz_feedback_resume_identity(core),
            **core,
        }
        signed = store_signer.sign(unsigned)
        verified = verify_toolz_feedback_resume_receipt(
            signed,
            expected_policy=policy,
            recovery_receipt=recovery.receipt,
            install_receipt=install_receipt,
            feedback_receipt=stable_feedback,
            theoretical_memory=stable_theoretical,
            trace=stable_trace,
            observer_key=observer_key,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            observed_memory=stable_observed,
            memory_key=memory_key,
            feedback_key=feedback_key,
            store_key=store_key,
            retained_cursor=retained_cursor,
            final_cursor=final_cursor,
        )
        return ToolzFeedbackResume(
            receipt=verified,
            recovery_receipt=recovery.receipt,
            install_receipt=install_receipt,
            store=recovery.store,
            store_cursor=final_cursor,
            status=status,
        )
    except Exception:
        recovery.store.close()
        raise
