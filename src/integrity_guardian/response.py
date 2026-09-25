"""Read-only M8 handoff protocol for separately authorized executors.

Guardian can verify an envelope and an executor receipt. This module contains
no action, preflight, compensation, post-check or transport implementation.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any

from .canonical import canonical_bytes
from .hashing import digest_object
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    verify_bytes,
    verify_signature,
)


class ResponseEnvelopeError(ValueError):
    """Raised when a restricted response envelope is not exact and trusted."""


class ExecutionReceiptError(ValueError):
    """Raised when an external executor receipt cannot be trusted."""


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (AttributeError, ValueError) as exc:
        raise ResponseEnvelopeError("invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise ResponseEnvelopeError("timestamp must include timezone")
    return parsed


def _envelope_signature_payload(document: dict[str, Any]) -> bytes:
    unsigned = deepcopy(document)
    authorization = unsigned.get("authorization")
    if not isinstance(authorization, dict):
        raise ResponseEnvelopeError("response authorization is missing")
    authorization.pop("signature", None)
    return b"integrity-guardian\x00response-envelope-v1\x00" + canonical_bytes(
        unsigned
    )


def sign_response_envelope(
    unsigned_envelope: dict[str, Any],
    signer: Ed25519Signer,
) -> dict[str, Any]:
    document = deepcopy(unsigned_envelope)
    authorization = document.get("authorization")
    if not isinstance(authorization, dict):
        raise ResponseEnvelopeError("response authorization is missing")
    if "signature" in authorization:
        raise ResponseEnvelopeError("response envelope is already signed")
    authorization["signature"] = {
        "algorithm": "ed25519",
        "key_id": signer.key_id,
        "value": signer.sign_bytes(_envelope_signature_payload(document)),
    }
    validate("response-envelope", document)
    return document


def verify_response_envelope(
    document: dict[str, Any],
    *,
    authority_key: TrustedKey,
    expected_target_id: str,
    expected_executor_id: str,
    expected_release_revision: str,
    expected_response_class: str,
    expected_artifacts: dict[str, str],
    now: str,
) -> dict[str, Any]:
    try:
        validate("response-envelope", document)
    except Exception as exc:
        raise ResponseEnvelopeError("response envelope schema rejected") from exc
    signature = document["authorization"]["signature"]
    if (
        document["authorization"]["authority_id"] != authority_key.key_id
        or signature["key_id"] != authority_key.key_id
        or not verify_bytes(
            _envelope_signature_payload(document),
            signature["value"],
            authority_key.public_key,
        )
    ):
        raise ResponseEnvelopeError("response envelope signature rejected")

    exact = (
        ("target", document["target_id"], expected_target_id),
        ("executor", document["executor_id"], expected_executor_id),
        ("release", document["release_revision"], expected_release_revision),
        ("response class", document["response_class"], expected_response_class),
        ("artifacts", document["artifacts"], expected_artifacts),
    )
    for label, actual, expected in exact:
        if actual != expected:
            raise ResponseEnvelopeError(f"response {label} does not match")

    created_at = _parse_time(document["created_at"])
    valid_from = _parse_time(document["valid_from"])
    valid_until = _parse_time(document["valid_until"])
    current = _parse_time(now)
    if not created_at <= valid_from <= valid_until:
        raise ResponseEnvelopeError("response authorization interval is invalid")
    if not valid_from <= current <= valid_until:
        raise ResponseEnvelopeError("response authorization is not currently valid")

    controls = document["controls"]
    if (
        controls["guardian_executes"] is not False
        or controls["requires_exact_go"] is not True
        or controls["dry_run_first"] is not True
    ):
        raise ResponseEnvelopeError("response separation controls are invalid")

    receipt = {
        "protocol": "integrity-guardian/response-handoff-receipt/v1",
        "response_id": document["response_id"],
        "tenant_id": document["tenant_id"],
        "finding_ids": sorted(document["finding_ids"]),
        "target_id": document["target_id"],
        "executor_id": document["executor_id"],
        "release_revision": document["release_revision"],
        "response_class": document["response_class"],
        "envelope_digest": digest_object(
            document,
            domain="response-envelope-reference-v1",
        ),
        "valid_until": document["valid_until"],
        "handoff_ready": True,
        "guardian_execution_capability": False,
    }
    receipt["receipt_digest"] = digest_object(
        receipt,
        domain="response-handoff-receipt-v1",
    )
    return receipt


def build_execution_receipt(
    *,
    envelope: dict[str, Any],
    status: str,
    preflight_evidence_digest: str,
    action_evidence_digest: str | None,
    compensation_evidence_digest: str | None,
    postcheck_evidence_digest: str | None,
    recorded_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    validate("response-envelope", envelope)
    unsigned: dict[str, Any] = {
        "protocol": "integrity-guardian/execution-receipt/v1",
        "receipt_id": "receipt:pending",
        "envelope_digest": digest_object(
            envelope,
            domain="response-envelope-reference-v1",
        ),
        "response_id": envelope["response_id"],
        "tenant_id": envelope["tenant_id"],
        "target_id": envelope["target_id"],
        "executor_id": envelope["executor_id"],
        "status": status,
        "preflight_evidence_digest": preflight_evidence_digest,
        "action_evidence_digest": action_evidence_digest,
        "compensation_evidence_digest": compensation_evidence_digest,
        "postcheck_evidence_digest": postcheck_evidence_digest,
        "recorded_at": recorded_at,
        "signer_id": signer.key_id,
    }
    identity = digest_object(
        unsigned,
        domain="execution-receipt-identity-v1",
    ).split(":", 1)[1]
    unsigned["receipt_id"] = f"receipt:{identity}"
    receipt = signer.sign(unsigned)
    validate("execution-receipt", receipt)
    _validate_receipt_semantics(receipt)
    return receipt


def _validate_receipt_semantics(receipt: dict[str, Any]) -> None:
    status = receipt["status"]
    action = receipt["action_evidence_digest"]
    compensation = receipt["compensation_evidence_digest"]
    postcheck = receipt["postcheck_evidence_digest"]
    if status == "preflight-denied" and any(
        value is not None for value in (action, compensation, postcheck)
    ):
        raise ExecutionReceiptError("preflight-denied receipt claims later evidence")
    if status == "apply-failed-no-change" and (
        action is not None or compensation is not None
    ):
        raise ExecutionReceiptError("no-change receipt claims action evidence")
    if status == "applied-postcheck-pass" and (
        action is None or postcheck is None or compensation is not None
    ):
        raise ExecutionReceiptError("successful receipt evidence is incomplete")
    if status == "applied-postcheck-fail-compensated" and (
        action is None or postcheck is None or compensation is None
    ):
        raise ExecutionReceiptError("compensated receipt evidence is incomplete")
    if status == "compensation-failed" and (
        action is None or postcheck is None or compensation is None
    ):
        raise ExecutionReceiptError("compensation-failed evidence is incomplete")


def verify_execution_receipt(
    receipt: dict[str, Any],
    *,
    envelope: dict[str, Any],
    executor_key: TrustedKey,
) -> None:
    try:
        validate("response-envelope", envelope)
        validate("execution-receipt", receipt)
        _validate_receipt_semantics(receipt)
    except Exception as exc:
        raise ExecutionReceiptError("execution receipt rejected") from exc
    expected_envelope_digest = digest_object(
        envelope,
        domain="response-envelope-reference-v1",
    )
    if receipt["envelope_digest"] != expected_envelope_digest:
        raise ExecutionReceiptError("execution receipt envelope mismatch")
    for field in ("response_id", "tenant_id", "target_id", "executor_id"):
        if receipt[field] != envelope[field]:
            raise ExecutionReceiptError(f"execution receipt {field} mismatch")
    if (
        receipt["signer_id"] != executor_key.key_id
        or receipt["signature"]["key_id"] != executor_key.key_id
        or envelope["executor_id"] != executor_key.key_id
        or not verify_signature(receipt, executor_key.public_key)
    ):
        raise ExecutionReceiptError("execution receipt signature rejected")
