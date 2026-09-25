"""Signed, context-only continuity between distinct module agents."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any

from .agent_handoff import AgentHandoffError, verify_module_agent_successor_ack
from .canonical import canonical_bytes
from .hashing import digest_object
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)

MAX_PACKAGE_BYTES = 64 * 1024
MAX_ADMISSION_BYTES = 16 * 1024

_ROLE_BY_CLASS = {
    "KNOWN": {"read", "append"},
    "OBSERVED": {"observation"},
    "VERIFIED": {"observation"},
    "DECIDED": {"authority"},
    "ACTED": {"action"},
}
_UNEVIDENCED = {"ASSUMED", "UNKNOWN"}


class CrossAgentContinuityError(ValueError):
    """Raised when continuity context or provenance is ambiguous."""


def _time(value: str, *, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise CrossAgentContinuityError(f"{field} timestamp rejected") from exc
    if parsed.tzinfo is None:
        raise CrossAgentContinuityError(f"{field} timestamp rejected")
    return parsed


def _bounded(document: dict[str, Any], *, ceiling: int, label: str) -> None:
    if len(canonical_bytes(document)) > ceiling:
        raise CrossAgentContinuityError(f"{label} byte budget exceeded")


def _identity(
    document: dict[str, Any],
    *,
    field: str,
    pending: str,
    prefix: str,
    domain: str,
) -> str:
    unsigned = deepcopy(document)
    unsigned.pop("signature", None)
    actual = unsigned[field]
    unsigned[field] = pending
    expected = prefix + digest_object(unsigned, domain=domain).split(":", 1)[1]
    if actual != expected:
        raise CrossAgentContinuityError(f"{field.replace('_', ' ')} mismatch")
    return actual


def _same_signer(signer: Ed25519Signer, key: TrustedKey, *, label: str) -> None:
    if (
        signer.key_id != key.key_id
        or public_key_fingerprint(signer.public_key)
        != public_key_fingerprint(key.public_key)
    ):
        raise CrossAgentContinuityError(f"{label} signer rejected")


def continuity_statement_digest(statement: str) -> str:
    return digest_object(
        {"statement": statement},
        domain="cross-agent-continuity-statement-v1",
    )


def build_continuity_epistemic_record(
    *,
    sequence: int,
    classification: str,
    statement: str,
    actor_id: str,
    source_reference_id: str | None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "record_id": "epistemic:pending",
        "sequence": sequence,
        "classification": classification,
        "statement": statement,
        "statement_digest": continuity_statement_digest(statement),
        "actor_id": actor_id,
        "source_reference_id": source_reference_id,
    }
    identity = digest_object(
        record,
        domain="cross-agent-continuity-record-identity-v1",
    ).split(":", 1)[1]
    record["record_id"] = f"epistemic:{identity}"
    return record


def build_continuity_receipt_reference(
    *,
    checkpoint: dict[str, Any],
    receipt_id: str,
    receipt_protocol: str,
    receipt_type: str,
    receipt_digest: str,
    task_id: str,
    claim_digest: str,
    subject_actor_id: str,
    issuer_id: str,
    observed_at: str,
    issuer_signer: Ed25519Signer,
) -> dict[str, Any]:
    _time(observed_at, field="receipt reference")
    unsigned: dict[str, Any] = {
        "protocol": "integrity-guardian/continuity-receipt-reference/v1",
        "reference_id": "continuity-receipt-ref:pending",
        "checkpoint_id": checkpoint["checkpoint_id"],
        "checkpoint_digest": digest_object(
            checkpoint,
            domain="module-agent-handoff-checkpoint-reference-v1",
        ),
        "event_cursor": checkpoint["event_cursor"],
        "snapshot_digest": checkpoint["snapshot_digest"],
        "outstanding_work_digest": checkpoint["outstanding_work_digest"],
        "receipt_id": receipt_id,
        "receipt_protocol": receipt_protocol,
        "receipt_type": receipt_type,
        "receipt_digest": receipt_digest,
        "task_id": task_id,
        "claim_digest": claim_digest,
        "subject_actor_id": subject_actor_id,
        "issuer_id": issuer_id,
        "issuer_key_id": issuer_signer.key_id,
        "observed_at": observed_at,
        "production_authority": False,
    }
    identity = digest_object(
        unsigned,
        domain="continuity-receipt-reference-identity-v1",
    ).split(":", 1)[1]
    unsigned["reference_id"] = f"continuity-receipt-ref:{identity}"
    return issuer_signer.sign(unsigned)


def _verify_handoff(
    checkpoint: dict[str, Any],
    ack: dict[str, Any],
    *,
    predecessor_key: TrustedKey,
    successor_key: TrustedKey,
    at_time: str,
) -> dict[str, Any]:
    try:
        return verify_module_agent_successor_ack(
            checkpoint,
            ack,
            predecessor_key=predecessor_key,
            successor_key=successor_key,
            at_time=at_time,
        )
    except AgentHandoffError as exc:
        raise CrossAgentContinuityError("handoff evidence rejected") from exc


def _record_identity(record: dict[str, Any]) -> None:
    if record["statement_digest"] != continuity_statement_digest(record["statement"]):
        raise CrossAgentContinuityError("epistemic statement digest mismatch")
    unsigned = deepcopy(record)
    actual = unsigned["record_id"]
    unsigned["record_id"] = "epistemic:pending"
    expected = "epistemic:" + digest_object(
        unsigned,
        domain="cross-agent-continuity-record-identity-v1",
    ).split(":", 1)[1]
    if actual != expected:
        raise CrossAgentContinuityError("epistemic record identity mismatch")


def _reference_identity(
    reference: dict[str, Any],
    *,
    issuer_key: TrustedKey,
) -> None:
    if (
        reference["issuer_key_id"] != issuer_key.key_id
        or reference["signature"]["key_id"] != issuer_key.key_id
        or not verify_signature(reference, issuer_key.public_key)
    ):
        raise CrossAgentContinuityError("receipt reference signature rejected")
    _identity(
        reference,
        field="reference_id",
        pending="continuity-receipt-ref:pending",
        prefix="continuity-receipt-ref:",
        domain="continuity-receipt-reference-identity-v1",
    )


def _context_surface(package: dict[str, Any]) -> dict[str, Any]:
    return {
        key: package[key]
        for key in (
            "tenant_id",
            "module_id",
            "task_id",
            "predecessor_agent_id",
            "predecessor_generation",
            "successor_agent_id",
            "successor_generation",
            "event_cursor",
            "snapshot_digest",
            "outstanding_work_digest",
            "epistemic_records",
            "receipt_provenance",
            "stop_conditions",
            "authority",
        )
    }


def _verify_semantics(
    package: dict[str, Any],
    *,
    receipt_issuer_keys: dict[tuple[str, str], TrustedKey],
) -> None:
    references = package["receipt_provenance"]
    reference_ids = [item["reference_id"] for item in references]
    if reference_ids != sorted(reference_ids) or len(reference_ids) != len(
        set(reference_ids)
    ):
        raise CrossAgentContinuityError("receipt provenance is not canonical")

    verified: dict[str, dict[str, Any]] = {}
    receipt_ids: set[str] = set()
    receipt_digests: set[str] = set()
    created = _time(package["created_at"], field="package creation")
    expected_reference_binding = {
        "checkpoint_id": package["checkpoint_id"],
        "checkpoint_digest": package["checkpoint_digest"],
        "event_cursor": package["event_cursor"],
        "snapshot_digest": package["snapshot_digest"],
        "outstanding_work_digest": package["outstanding_work_digest"],
    }
    for reference in references:
        issuer_key = receipt_issuer_keys.get(
            (reference["receipt_type"], reference["issuer_id"])
        )
        if issuer_key is None:
            raise CrossAgentContinuityError("receipt issuer is not trusted for role")
        _reference_identity(reference, issuer_key=issuer_key)
        if any(
            reference[field] != value
            for field, value in expected_reference_binding.items()
        ):
            raise CrossAgentContinuityError("receipt reference does not match handoff")
        if reference["receipt_id"] in receipt_ids:
            raise CrossAgentContinuityError("duplicate receipt identity")
        if reference["receipt_digest"] in receipt_digests:
            raise CrossAgentContinuityError("receipt digest role collision")
        if _time(reference["observed_at"], field="receipt observation") > created:
            raise CrossAgentContinuityError("receipt reference is newer than package")
        receipt_ids.add(reference["receipt_id"])
        receipt_digests.add(reference["receipt_digest"])
        verified[reference["reference_id"]] = reference

    records = package["epistemic_records"]
    ordering = [(item["sequence"], item["record_id"]) for item in records]
    if ordering != sorted(ordering) or len(ordering) != len(set(ordering)):
        raise CrossAgentContinuityError("epistemic records are not canonical")
    stops = package["stop_conditions"]
    if stops != sorted(stops) or len(stops) != len(set(stops)):
        raise CrossAgentContinuityError("stop conditions are not canonical")
    used: set[str] = set()
    for record in records:
        _record_identity(record)
        reference_id = record["source_reference_id"]
        if record["classification"] in _UNEVIDENCED:
            if reference_id is not None:
                raise CrossAgentContinuityError("unevidenced state claims a receipt")
            if record["actor_id"] != package["predecessor_agent_id"]:
                raise CrossAgentContinuityError("unevidenced state has another actor")
            continue
        reference = verified.get(reference_id)
        allowed = _ROLE_BY_CLASS.get(record["classification"])
        if reference is None or allowed is None:
            raise CrossAgentContinuityError("epistemic receipt reference is absent")
        if reference["receipt_type"] not in allowed:
            raise CrossAgentContinuityError("receipt role is incompatible")
        if reference["subject_actor_id"] != record["actor_id"]:
            raise CrossAgentContinuityError("receipt subject differs from actor")
        if reference["task_id"] != package["task_id"]:
            raise CrossAgentContinuityError("receipt task differs from package")
        if reference["claim_digest"] != record["statement_digest"]:
            raise CrossAgentContinuityError("receipt does not bind the claim")
        if reference["reference_id"] in used:
            raise CrossAgentContinuityError("receipt reference is reused")
        used.add(reference["reference_id"])
    if used != set(verified):
        raise CrossAgentContinuityError("package contains unused receipt provenance")

    expected = digest_object(
        _context_surface(package),
        domain="cross-agent-continuity-context-v1",
    )
    if package["context_digest"] != expected:
        raise CrossAgentContinuityError("context digest mismatch")


def build_cross_agent_continuity_package(
    *,
    checkpoint: dict[str, Any],
    ack: dict[str, Any],
    predecessor_key: TrustedKey,
    successor_key: TrustedKey,
    receipt_issuer_keys: dict[tuple[str, str], TrustedKey],
    task_id: str,
    epistemic_records: list[dict[str, Any]],
    receipt_provenance: list[dict[str, Any]],
    stop_conditions: list[str],
    created_at: str,
    expires_at: str,
    predecessor_signer: Ed25519Signer,
) -> dict[str, Any]:
    handoff = _verify_handoff(
        checkpoint,
        ack,
        predecessor_key=predecessor_key,
        successor_key=successor_key,
        at_time=created_at,
    )
    _same_signer(predecessor_signer, predecessor_key, label="predecessor")
    created = _time(created_at, field="package creation")
    expires = _time(expires_at, field="package expiry")
    if (
        created < _time(ack["acknowledged_at"], field="handoff ACK")
        or created >= expires
        or expires > _time(ack["expires_at"], field="handoff expiry")
    ):
        raise CrossAgentContinuityError("package validity exceeds handoff")

    unsigned: dict[str, Any] = {
        "protocol": "integrity-guardian/cross-agent-continuity-package/v1",
        "package_id": "continuity-package:pending",
        "checkpoint_id": handoff["checkpoint_id"],
        "checkpoint_digest": digest_object(
            checkpoint, domain="module-agent-handoff-checkpoint-reference-v1"
        ),
        "ack_id": handoff["ack_id"],
        "ack_digest": digest_object(
            ack, domain="module-agent-successor-ack-reference-v1"
        ),
        "tenant_id": checkpoint["tenant_id"],
        "module_id": checkpoint["module_id"],
        "task_id": task_id,
        "predecessor_agent_id": checkpoint["predecessor_agent_id"],
        "predecessor_key_id": checkpoint["predecessor_key_id"],
        "predecessor_generation": checkpoint["predecessor_generation"],
        "successor_agent_id": checkpoint["successor_agent_id"],
        "successor_key_id": checkpoint["successor_key_id"],
        "successor_generation": checkpoint["successor_generation"],
        "event_cursor": checkpoint["event_cursor"],
        "snapshot_digest": checkpoint["snapshot_digest"],
        "outstanding_work_digest": checkpoint["outstanding_work_digest"],
        "epistemic_records": sorted(
            deepcopy(epistemic_records),
            key=lambda item: (item["sequence"], item["record_id"]),
        ),
        "receipt_provenance": sorted(
            deepcopy(receipt_provenance),
            key=lambda item: item["reference_id"],
        ),
        "stop_conditions": sorted(set(stop_conditions)),
        "authority": {
            "context_admission": "HANDOFF_BOUND",
            "read_authority": "NOT_GRANTED",
            "append_authority": "NOT_GRANTED",
            "production_authority": False,
        },
        "handoff_mode": "shadow",
        "handoff_commit_status": "NOT_ATTEMPTED",
        "context_digest": "sha256:" + "0" * 64,
        "created_at": created_at,
        "expires_at": expires_at,
        "production_authority": False,
    }
    unsigned["context_digest"] = digest_object(
        _context_surface(unsigned),
        domain="cross-agent-continuity-context-v1",
    )
    identity = digest_object(
        unsigned,
        domain="cross-agent-continuity-package-identity-v1",
    ).split(":", 1)[1]
    unsigned["package_id"] = f"continuity-package:{identity}"
    package = predecessor_signer.sign(unsigned)
    validate("cross-agent-continuity-package", package)
    _bounded(package, ceiling=MAX_PACKAGE_BYTES, label="continuity package")
    _verify_semantics(package, receipt_issuer_keys=receipt_issuer_keys)
    return package


def verify_cross_agent_continuity_package(
    package: dict[str, Any],
    checkpoint: dict[str, Any],
    ack: dict[str, Any],
    *,
    predecessor_key: TrustedKey,
    successor_key: TrustedKey,
    receipt_issuer_keys: dict[tuple[str, str], TrustedKey],
    at_time: str,
) -> dict[str, Any]:
    _bounded(package, ceiling=MAX_PACKAGE_BYTES, label="continuity package")
    validate("cross-agent-continuity-package", package)
    if (
        package["predecessor_key_id"] != predecessor_key.key_id
        or package["signature"]["key_id"] != predecessor_key.key_id
        or not verify_signature(package, predecessor_key.public_key)
    ):
        raise CrossAgentContinuityError("continuity package signature rejected")
    package_id = _identity(
        package,
        field="package_id",
        pending="continuity-package:pending",
        prefix="continuity-package:",
        domain="cross-agent-continuity-package-identity-v1",
    )
    _verify_handoff(
        checkpoint,
        ack,
        predecessor_key=predecessor_key,
        successor_key=successor_key,
        at_time=at_time,
    )
    now = _time(at_time, field="verification")
    created = _time(package["created_at"], field="package creation")
    expires = _time(package["expires_at"], field="package expiry")
    if (
        created < _time(ack["acknowledged_at"], field="handoff ACK")
        or created >= expires
        or expires > _time(ack["expires_at"], field="handoff expiry")
    ):
        raise CrossAgentContinuityError("package validity exceeds handoff")
    if not created <= now < expires:
        raise CrossAgentContinuityError("continuity package is not current")
    expected = {
        "checkpoint_id": checkpoint["checkpoint_id"],
        "checkpoint_digest": digest_object(
            checkpoint, domain="module-agent-handoff-checkpoint-reference-v1"
        ),
        "ack_id": ack["ack_id"],
        "ack_digest": digest_object(
            ack, domain="module-agent-successor-ack-reference-v1"
        ),
        "tenant_id": checkpoint["tenant_id"],
        "module_id": checkpoint["module_id"],
        "predecessor_agent_id": checkpoint["predecessor_agent_id"],
        "predecessor_key_id": checkpoint["predecessor_key_id"],
        "predecessor_generation": checkpoint["predecessor_generation"],
        "successor_agent_id": checkpoint["successor_agent_id"],
        "successor_key_id": checkpoint["successor_key_id"],
        "successor_generation": checkpoint["successor_generation"],
        "event_cursor": checkpoint["event_cursor"],
        "snapshot_digest": checkpoint["snapshot_digest"],
        "outstanding_work_digest": checkpoint["outstanding_work_digest"],
    }
    if any(package[field] != value for field, value in expected.items()):
        raise CrossAgentContinuityError("package does not match handoff")
    _verify_semantics(package, receipt_issuer_keys=receipt_issuer_keys)
    return {
        "ok": True,
        "package_id": package_id,
        "context_digest": package["context_digest"],
        "task_id": package["task_id"],
        "successor_agent_id": package["successor_agent_id"],
        "successor_generation": package["successor_generation"],
        "continuation_scope": "context-only",
        "read_authority": False,
        "append_authority": False,
        "production_authority": False,
    }


def acknowledge_cross_agent_continuity_package(
    package: dict[str, Any],
    checkpoint: dict[str, Any],
    ack: dict[str, Any],
    *,
    predecessor_key: TrustedKey,
    successor_key: TrustedKey,
    receipt_issuer_keys: dict[tuple[str, str], TrustedKey],
    successor_signer: Ed25519Signer,
    accepted_at: str,
    expires_at: str,
) -> dict[str, Any]:
    _same_signer(successor_signer, successor_key, label="successor")
    verified = verify_cross_agent_continuity_package(
        package,
        checkpoint,
        ack,
        predecessor_key=predecessor_key,
        successor_key=successor_key,
        receipt_issuer_keys=receipt_issuer_keys,
        at_time=accepted_at,
    )
    accepted = _time(accepted_at, field="admission acceptance")
    expires = _time(expires_at, field="admission expiry")
    if (
        accepted < _time(package["created_at"], field="package creation")
        or accepted >= expires
        or expires > _time(package["expires_at"], field="package expiry")
    ):
        raise CrossAgentContinuityError("admission validity exceeds package")
    unsigned: dict[str, Any] = {
        "protocol": "integrity-guardian/cross-agent-continuity-admission-receipt/v1",
        "receipt_id": "continuity-admission:pending",
        "package_id": verified["package_id"],
        "package_digest": digest_object(
            package, domain="cross-agent-continuity-package-reference-v1"
        ),
        "context_digest": verified["context_digest"],
        "task_id": verified["task_id"],
        "successor_agent_id": verified["successor_agent_id"],
        "successor_key_id": successor_signer.key_id,
        "successor_generation": verified["successor_generation"],
        "accepted_at": accepted_at,
        "expires_at": expires_at,
        "context_admitted": True,
        "continuation_scope": "context-only",
        "read_authority": False,
        "append_authority": False,
        "production_authority": False,
    }
    identity = digest_object(
        unsigned,
        domain="cross-agent-continuity-admission-identity-v1",
    ).split(":", 1)[1]
    unsigned["receipt_id"] = f"continuity-admission:{identity}"
    receipt = successor_signer.sign(unsigned)
    validate("cross-agent-continuity-admission-receipt", receipt)
    _bounded(receipt, ceiling=MAX_ADMISSION_BYTES, label="continuity admission")
    return receipt


def verify_cross_agent_continuity_admission(
    package: dict[str, Any],
    checkpoint: dict[str, Any],
    ack: dict[str, Any],
    receipt: dict[str, Any],
    *,
    predecessor_key: TrustedKey,
    successor_key: TrustedKey,
    receipt_issuer_keys: dict[tuple[str, str], TrustedKey],
    at_time: str,
) -> dict[str, Any]:
    package_result = verify_cross_agent_continuity_package(
        package,
        checkpoint,
        ack,
        predecessor_key=predecessor_key,
        successor_key=successor_key,
        receipt_issuer_keys=receipt_issuer_keys,
        at_time=at_time,
    )
    _bounded(receipt, ceiling=MAX_ADMISSION_BYTES, label="continuity admission")
    validate("cross-agent-continuity-admission-receipt", receipt)
    if (
        receipt["successor_key_id"] != successor_key.key_id
        or receipt["signature"]["key_id"] != successor_key.key_id
        or not verify_signature(receipt, successor_key.public_key)
    ):
        raise CrossAgentContinuityError("continuity admission signature rejected")
    receipt_id = _identity(
        receipt,
        field="receipt_id",
        pending="continuity-admission:pending",
        prefix="continuity-admission:",
        domain="cross-agent-continuity-admission-identity-v1",
    )
    now = _time(at_time, field="verification")
    accepted = _time(receipt["accepted_at"], field="admission acceptance")
    expires = _time(receipt["expires_at"], field="admission expiry")
    if (
        accepted < _time(package["created_at"], field="package creation")
        or accepted >= expires
        or expires > _time(package["expires_at"], field="package expiry")
    ):
        raise CrossAgentContinuityError("admission validity exceeds package")
    if not accepted <= now < expires:
        raise CrossAgentContinuityError("continuity admission is not current")
    expected = {
        "package_id": package["package_id"],
        "package_digest": digest_object(
            package, domain="cross-agent-continuity-package-reference-v1"
        ),
        "context_digest": package["context_digest"],
        "task_id": package["task_id"],
        "successor_agent_id": package["successor_agent_id"],
        "successor_key_id": package["successor_key_id"],
        "successor_generation": package["successor_generation"],
    }
    if any(receipt[field] != value for field, value in expected.items()):
        raise CrossAgentContinuityError("admission does not match package")
    return {
        **package_result,
        "receipt_id": receipt_id,
        "continuation_permitted": True,
    }
