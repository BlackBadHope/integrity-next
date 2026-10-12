"""Rollback-safe one-step admission recovery for Integrity 5.5 Uroboros.

Recovery accepts an externally retained a2 cursor only when the fully verified
store head is unchanged or is its sole immediate descendant and that descendant
is exactly the theoretical a4 memory installation described by the supplied
evidence.  It never provides a generic unpinned store open.

The operation is read-only.  A matching store authority signs the returned
recovery receipt, but no store, tool, browser, network or production mutation is
performed.
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
from .uroboros_toolzs_admission import (
    toolz_trace_admission_digest,
    verify_toolz_trace_admission_receipt,
)
from .uroboros_toolzs_install import (
    ToolzAdmissionInstallPolicy,
    _freeze_cyber_evidence,
    _freeze_fog_evidence,
    _freeze_mapping,
    toolz_admission_install_policy_digest,
)
from .uroboros_toolzs_store import (
    ToolzRouteMemoryStore,
    ToolzStoreCursor,
    ToolzStoreRecoveryStatus,
)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_RECOVERY_BOUNDARY = {
    "browser_control": False,
    "credentials": False,
    "execution": False,
    "global_publish": False,
    "historical_install_invocation": False,
    "install_receipt_reconstruction": False,
    "local_storage": True,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
    "raw_ui_data": False,
    "rollback_bypass": False,
    "store_write": False,
    "tool_invocation": False,
}


class ToolzAdmissionRecoveryError(RuntimeError):
    """Raised when a retained cursor cannot prove one exact safe outcome."""


@dataclass(frozen=True)
class ToolzAdmissionRecoveryPolicy:
    """Exact a5 install policy and bounded recovery observation lag."""

    policy_id: str
    install_policy: ToolzAdmissionInstallPolicy
    max_evaluation_to_recovery_seconds: int = 300

    def __post_init__(self) -> None:
        if (
            not isinstance(self.policy_id, str)
            or _ID.fullmatch(self.policy_id) is None
            or "synthetic" not in self.policy_id
        ):
            raise ToolzAdmissionRecoveryError("Toolzs admission recovery policy id rejected")
        if not isinstance(self.install_policy, ToolzAdmissionInstallPolicy):
            raise ToolzAdmissionRecoveryError("Toolzs admission recovery policy rejected")
        if (
            not isinstance(self.max_evaluation_to_recovery_seconds, int)
            or isinstance(self.max_evaluation_to_recovery_seconds, bool)
            or not 0 <= self.max_evaluation_to_recovery_seconds <= 3_600
        ):
            raise ToolzAdmissionRecoveryError("Toolzs admission recovery lag rejected")


@dataclass(frozen=True)
class ToolzAdmissionRecovery:
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
        raise ToolzAdmissionRecoveryError(f"Toolzs admission recovery {field} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolzAdmissionRecoveryError(f"Toolzs admission recovery {field} rejected") from exc
    if parsed.tzinfo is None:
        raise ToolzAdmissionRecoveryError(f"Toolzs admission recovery {field} rejected")
    return parsed


def _policy_document(policy: ToolzAdmissionRecoveryPolicy) -> dict[str, Any]:
    return {
        "policy_id": policy.policy_id,
        "install_policy_digest": toolz_admission_install_policy_digest(policy.install_policy),
        "max_evaluation_to_recovery_seconds": (policy.max_evaluation_to_recovery_seconds),
        "head_semantics": ("retained-head-or-one-exact-install-descendant-never-generic-open"),
        "mutation_semantics": "read-only-no-store-write",
    }


def toolz_admission_recovery_policy_digest(
    policy: ToolzAdmissionRecoveryPolicy,
) -> str:
    """Return the exact retained-cursor recovery policy identity."""

    if not isinstance(policy, ToolzAdmissionRecoveryPolicy):
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery policy rejected")
    return digest_object(
        _policy_document(policy),
        domain="toolz-admission-recovery-policy-v1",
    )


def _receipt_core(receipt: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(receipt))
    core.pop("receipt_id", None)
    core.pop("signature", None)
    return core


def toolz_admission_recovery_identity(receipt: Mapping[str, Any]) -> str:
    """Return the domain-separated identity of one unsigned recovery receipt."""

    digest = digest_object(
        _receipt_core(receipt),
        domain="toolz-admission-recovery-receipt-identity-v1",
    )
    return f"toolz-admission-recovery-receipt:{digest.split(':', 1)[1]}"


def toolz_admission_recovery_digest(receipt: Mapping[str, Any]) -> str:
    """Return the exact signed recovery receipt digest."""

    return digest_object(
        dict(receipt),
        domain="toolz-admission-recovery-signed-receipt-v1",
    )


def _validate_request_timing(
    *,
    admission_created_at: str,
    memory_expires_at: str,
    evaluated_at: str,
    recovered_at: str,
    policy: ToolzAdmissionRecoveryPolicy,
) -> tuple[datetime, datetime, datetime, datetime]:
    admission_time = _parse_time(admission_created_at, "admission time")
    expiry_time = _parse_time(memory_expires_at, "memory expiry")
    evaluated_time = _parse_time(evaluated_at, "evaluation time")
    recovered_time = _parse_time(recovered_at, "recovery time")
    if not admission_time <= evaluated_time <= recovered_time or recovered_time >= expiry_time:
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery causal timing rejected")
    if (
        recovered_time - evaluated_time
    ).total_seconds() > policy.max_evaluation_to_recovery_seconds:
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery evaluation lag rejected")
    return admission_time, expiry_time, evaluated_time, recovered_time


def _validate_timing(
    *,
    admission_created_at: str,
    memory_expires_at: str,
    manifest_created_at: str,
    status: ToolzStoreRecoveryStatus,
    evaluated_at: str,
    recovered_at: str,
    policy: ToolzAdmissionRecoveryPolicy,
) -> None:
    admission_time, expiry_time, evaluated_time, _ = _validate_request_timing(
        admission_created_at=admission_created_at,
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
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery causal timing rejected")
    if (
        status is ToolzStoreRecoveryStatus.RECOVERED_INSTALL
        and not admission_time <= manifest_time < expiry_time
    ):
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery install timing rejected")


def _validate_cursor(
    cursor: ToolzStoreCursor,
    *,
    policy: ToolzAdmissionRecoveryPolicy,
    tenant_id: str,
    field: str,
) -> None:
    if (
        not isinstance(cursor, ToolzStoreCursor)
        or cursor.store_id != policy.install_policy.store_id
        or cursor.tenant_id != tenant_id
    ):
        raise ToolzAdmissionRecoveryError(f"Toolzs admission recovery {field} rejected")


def _validate_transition(
    retained_cursor: ToolzStoreCursor,
    recovered_cursor: ToolzStoreCursor,
    status: ToolzStoreRecoveryStatus,
) -> None:
    if status is ToolzStoreRecoveryStatus.RETAINED_HEAD:
        if recovered_cursor != retained_cursor:
            raise ToolzAdmissionRecoveryError("Toolzs admission recovery retained cursor mismatch")
        return
    if (
        recovered_cursor.sequence != retained_cursor.sequence + 1
        or recovered_cursor.manifest_id == retained_cursor.manifest_id
        or recovered_cursor.manifest_digest == retained_cursor.manifest_digest
    ):
        raise ToolzAdmissionRecoveryError(
            "Toolzs admission recovery descendant transition rejected"
        )


def _expected_core(
    *,
    policy: ToolzAdmissionRecoveryPolicy,
    admission_receipt: Mapping[str, Any],
    memory_receipt: Mapping[str, Any],
    retained_cursor: ToolzStoreCursor,
    recovered_cursor: ToolzStoreCursor,
    status: ToolzStoreRecoveryStatus,
    manifest_created_at: str,
    evaluated_at: str,
    recovered_at: str,
) -> dict[str, Any]:
    return {
        "protocol": "integrity-guardian/toolz-admission-recovery-receipt/v1",
        "tenant_id": memory_receipt["tenant_id"],
        "policy_id": policy.policy_id,
        "policy_digest": toolz_admission_recovery_policy_digest(policy),
        "install_policy_digest": toolz_admission_install_policy_digest(policy.install_policy),
        "admission": {
            "receipt_id": admission_receipt["receipt_id"],
            "receipt_digest": toolz_trace_admission_digest(admission_receipt),
            "policy_digest": admission_receipt["policy_digest"],
        },
        "memory": {
            "receipt_id": memory_receipt["receipt_id"],
            "receipt_digest": toolz_route_memory_digest(memory_receipt),
            "outcome": memory_receipt["observation"]["outcome"],
            "expires_at": memory_receipt["expires_at"],
        },
        "store": {
            "store_id": policy.install_policy.store_id,
            "retained_cursor": retained_cursor.to_document(),
            "recovered_cursor": recovered_cursor.to_document(),
            "status": status.value,
            "maximum_descendant_distance": 1,
            "recovered_manifest_created_at": manifest_created_at,
        },
        "timing": {
            "evaluated_at": evaluated_at,
            "recovered_at": recovered_at,
        },
        "authority_boundary": deepcopy(_RECOVERY_BOUNDARY),
    }


def verify_toolz_admission_recovery_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_policy: ToolzAdmissionRecoveryPolicy,
    admission_receipt: Mapping[str, Any],
    trace: Mapping[str, Any],
    observer_key: TrustedKey,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    memory_receipt: Mapping[str, Any],
    memory_key: TrustedKey,
    admission_key: TrustedKey,
    store_key: TrustedKey,
    retained_cursor: ToolzStoreCursor,
    recovered_cursor: ToolzStoreCursor,
) -> dict[str, Any]:
    """Verify admission, time, cursor, policy and store-signer bindings."""

    if not isinstance(expected_policy, ToolzAdmissionRecoveryPolicy):
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery policy rejected")
    if not all(
        isinstance(key, TrustedKey)
        for key in (
            observer_key,
            memory_key,
            admission_key,
            store_key,
        )
    ):
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery trust binding rejected")
    stable_admission = _freeze_mapping(admission_receipt, "admission receipt")
    stable_memory = _freeze_mapping(memory_receipt, "memory receipt")
    stable_trace = _freeze_mapping(trace, "trace")
    stable_fog = _freeze_fog_evidence(fog_evidence)
    stable_cyber = _freeze_cyber_evidence(cyber_evidence)
    try:
        candidate = parse_json_strict(canonical_bytes(dict(receipt)))
        validate("toolz-admission-recovery-receipt", candidate)
    except (TypeError, ValueError, ValidationError) as exc:
        raise ToolzAdmissionRecoveryError(
            "Toolzs admission recovery receipt schema rejected"
        ) from exc
    if candidate["receipt_id"] != toolz_admission_recovery_identity(candidate):
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery identity mismatch")
    if candidate["signature"]["key_id"] != store_key.key_id or not verify_signature(
        candidate, store_key.public_key
    ):
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery signature rejected")
    if candidate["authority_boundary"] != _RECOVERY_BOUNDARY:
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery authority mismatch")
    try:
        admission = verify_toolz_trace_admission_receipt(
            stable_admission,
            expected_policy=expected_policy.install_policy.admission_policy,
            trace=stable_trace,
            observer_key=observer_key,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            memory_receipt=stable_memory,
            memory_key=memory_key,
            admission_key=admission_key,
        )
    except Exception as exc:
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery admission rejected") from exc
    tenant_id = admission.memory_receipt["tenant_id"]
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
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery status rejected") from exc
    _validate_transition(retained_cursor, recovered_cursor, status)
    _validate_timing(
        admission_created_at=stable_admission["created_at"],
        memory_expires_at=stable_memory["expires_at"],
        manifest_created_at=candidate["store"]["recovered_manifest_created_at"],
        status=status,
        evaluated_at=candidate["timing"]["evaluated_at"],
        recovered_at=candidate["timing"]["recovered_at"],
        policy=expected_policy,
    )
    expected = _expected_core(
        policy=expected_policy,
        admission_receipt=stable_admission,
        memory_receipt=admission.memory_receipt,
        retained_cursor=retained_cursor,
        recovered_cursor=recovered_cursor,
        status=status,
        manifest_created_at=candidate["store"]["recovered_manifest_created_at"],
        evaluated_at=candidate["timing"]["evaluated_at"],
        recovered_at=candidate["timing"]["recovered_at"],
    )
    if _receipt_core(candidate) != expected:
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery recomputation mismatch")
    return candidate


def recover_toolz_admission_install(
    *,
    policy: ToolzAdmissionRecoveryPolicy,
    admission_receipt: Mapping[str, Any],
    trace: Mapping[str, Any],
    observer_key: TrustedKey,
    fog_evidence: ToolzFogRouteEvidence,
    cyber_evidence: ToolzCyberEvidence,
    memory_receipt: Mapping[str, Any],
    memory_key: TrustedKey,
    admission_key: TrustedKey,
    store_root: Path,
    store_key: TrustedKey,
    store_signer: Ed25519Signer,
    retained_cursor: ToolzStoreCursor,
    evaluated_at: str,
    recovered_at: str,
) -> ToolzAdmissionRecovery:
    """Recover only an unchanged head or one exact lost a5 installation."""

    if not isinstance(policy, ToolzAdmissionRecoveryPolicy):
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery policy rejected")
    if not isinstance(store_root, Path):
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery root rejected")
    if not isinstance(store_key, TrustedKey) or not isinstance(
        store_signer,
        Ed25519Signer,
    ):
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery store trust rejected")
    if store_signer.key_id != store_key.key_id or public_key_fingerprint(
        store_signer.public_key
    ) != public_key_fingerprint(store_key.public_key):
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery signer mismatch")
    stable_admission = _freeze_mapping(admission_receipt, "admission receipt")
    stable_memory = _freeze_mapping(memory_receipt, "memory receipt")
    stable_trace = _freeze_mapping(trace, "trace")
    stable_fog = _freeze_fog_evidence(fog_evidence)
    stable_cyber = _freeze_cyber_evidence(cyber_evidence)
    try:
        admission = verify_toolz_trace_admission_receipt(
            stable_admission,
            expected_policy=policy.install_policy.admission_policy,
            trace=stable_trace,
            observer_key=observer_key,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            memory_receipt=stable_memory,
            memory_key=memory_key,
            admission_key=admission_key,
        )
    except Exception as exc:
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery admission rejected") from exc
    _validate_request_timing(
        admission_created_at=stable_admission["created_at"],
        memory_expires_at=stable_memory["expires_at"],
        evaluated_at=evaluated_at,
        recovered_at=recovered_at,
        policy=policy,
    )
    try:
        store_recovery = ToolzRouteMemoryStore.recover_one_step_install(
            store_root,
            store_id=policy.install_policy.store_id,
            tenant_id=admission.memory_receipt["tenant_id"],
            authority_key=store_key,
            retained_cursor=retained_cursor,
            receipt=admission.memory_receipt,
            expected_policy=policy.install_policy.admission_policy.memory_policy,
            fog_evidence=stable_fog,
            cyber_evidence=stable_cyber,
            memory_key=memory_key,
            evaluated_at=evaluated_at,
        )
    except Exception as exc:
        raise ToolzAdmissionRecoveryError("Toolzs admission recovery store proof rejected") from exc
    try:
        _validate_timing(
            admission_created_at=stable_admission["created_at"],
            memory_expires_at=stable_memory["expires_at"],
            manifest_created_at=store_recovery.manifest_created_at,
            status=store_recovery.status,
            evaluated_at=evaluated_at,
            recovered_at=recovered_at,
            policy=policy,
        )
        core = _expected_core(
            policy=policy,
            admission_receipt=stable_admission,
            memory_receipt=admission.memory_receipt,
            retained_cursor=retained_cursor,
            recovered_cursor=store_recovery.cursor,
            status=store_recovery.status,
            manifest_created_at=store_recovery.manifest_created_at,
            evaluated_at=evaluated_at,
            recovered_at=recovered_at,
        )
        unsigned = {
            "receipt_id": toolz_admission_recovery_identity(core),
            **core,
        }
        signed = store_signer.sign(unsigned)
        verified = verify_toolz_admission_recovery_receipt(
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
            store_key=store_key,
            retained_cursor=retained_cursor,
            recovered_cursor=store_recovery.cursor,
        )
        return ToolzAdmissionRecovery(
            receipt=verified,
            store=store_recovery.store,
            store_cursor=store_recovery.cursor,
            status=store_recovery.status,
        )
    except Exception:
        store_recovery.store.close()
        raise
