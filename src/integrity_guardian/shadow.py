"""Fail-closed M7 production-shadow authorization primitives.

This module prepares and verifies authority. It cannot collect, deploy,
remediate, promote a baseline or publish a checkpoint over a network.
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


class ShadowAuthorizationError(ValueError):
    """Raised when an M7 observer lacks exact, valid, bounded authority."""


class RetentionReceiptError(ValueError):
    """Raised when external checkpoint retention cannot be verified."""


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (AttributeError, ValueError) as exc:
        raise ShadowAuthorizationError("invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise ShadowAuthorizationError("timestamp must include timezone")
    return parsed


def _authorization_payload(document: dict[str, Any]) -> bytes:
    unsigned = deepcopy(document)
    authorization = unsigned.get("authorization")
    if not isinstance(authorization, dict):
        raise ShadowAuthorizationError("authorization is missing")
    authorization.pop("signature", None)
    return (
        b"integrity-guardian\x00shadow-authorization-v1\x00"
        + canonical_bytes(unsigned)
    )


def sign_shadow_authorization(
    unsigned_authorization: dict[str, Any],
    signer: Ed25519Signer,
) -> dict[str, Any]:
    document = deepcopy(unsigned_authorization)
    authorization = document.get("authorization")
    if not isinstance(authorization, dict):
        raise ShadowAuthorizationError("authorization is missing")
    if "signature" in authorization:
        raise ShadowAuthorizationError("authorization is already signed")
    authorization["signature"] = {
        "algorithm": "ed25519",
        "key_id": signer.key_id,
        "value": signer.sign_bytes(_authorization_payload(document)),
    }
    validate("shadow-authorization", document)
    return document


def verify_shadow_authorization(
    document: dict[str, Any],
    *,
    authority_key: TrustedKey,
    expected_target_id: str,
    expected_release_revision: str,
    expected_config_digest: str,
    now: str,
) -> dict[str, Any]:
    """Verify exact production-shadow authority and return a safe receipt."""

    try:
        validate("shadow-authorization", document)
    except Exception as exc:
        raise ShadowAuthorizationError("shadow authorization schema rejected") from exc
    signature = document["authorization"]["signature"]
    if (
        signature["key_id"] != authority_key.key_id
        or document["authorization"]["authority_id"] != authority_key.key_id
        or not verify_bytes(
            _authorization_payload(document),
            signature["value"],
            authority_key.public_key,
        )
    ):
        raise ShadowAuthorizationError("shadow authorization signature rejected")
    if document["target_id"] != expected_target_id:
        raise ShadowAuthorizationError("shadow target does not match")
    if document["release_revision"] != expected_release_revision:
        raise ShadowAuthorizationError("shadow release does not match")
    if document["config_digest"] != expected_config_digest:
        raise ShadowAuthorizationError("shadow config digest does not match")

    created_at = _parse_time(document["created_at"])
    valid_from = _parse_time(document["valid_from"])
    valid_until = _parse_time(document["valid_until"])
    current = _parse_time(now)
    if not created_at <= valid_from <= valid_until:
        raise ShadowAuthorizationError("shadow authorization interval is invalid")
    if not valid_from <= current <= valid_until:
        raise ShadowAuthorizationError("shadow authorization is not currently valid")

    controls = document["controls"]
    if (
        controls["read_only"] is not True
        or controls["remediation_enabled"] is not False
        or controls["baseline_auto_promotion"] is not False
    ):
        raise ShadowAuthorizationError("shadow safety controls are not immutable")
    if document["external_checkpoint"]["required"] is not True:
        raise ShadowAuthorizationError("external checkpoint retention is required")

    receipt = {
        "protocol": "integrity-guardian/shadow-readiness-receipt/v1",
        "authorization_id": document["authorization_id"],
        "tenant_id": document["tenant_id"],
        "target_id": document["target_id"],
        "release_revision": document["release_revision"],
        "config_digest": document["config_digest"],
        "coverage": sorted(document["coverage"]),
        "budgets": deepcopy(document["budgets"]),
        "external_checkpoint": deepcopy(document["external_checkpoint"]),
        "valid_until": document["valid_until"],
        "ready": True,
        "read_only": True,
        "remediation_enabled": False,
        "baseline_auto_promotion": False,
    }
    receipt["receipt_digest"] = digest_object(
        receipt,
        domain="shadow-readiness-receipt-v1",
    )
    return receipt


def build_retention_receipt(
    *,
    checkpoint: dict[str, Any],
    store_id: str,
    retained_at: str,
    expires_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    """Build a signed ACK from an external checkpoint retention boundary."""

    validate("checkpoint", checkpoint)
    unsigned: dict[str, Any] = {
        "protocol": "integrity-guardian/checkpoint-retention-receipt/v1",
        "receipt_id": "receipt:pending",
        "tenant_id": checkpoint["tenant_id"],
        "store_id": store_id,
        "checkpoint_digest": digest_object(
            checkpoint,
            domain="checkpoint-retention-reference-v1",
        ),
        "tree_size": checkpoint["tree_size"],
        "retained_at": retained_at,
        "expires_at": expires_at,
        "signer_id": signer.key_id,
    }
    identity = digest_object(
        unsigned,
        domain="checkpoint-retention-receipt-identity-v1",
    ).split(":", 1)[1]
    unsigned["receipt_id"] = f"receipt:{identity}"
    receipt = signer.sign(unsigned)
    validate("checkpoint-retention-receipt", receipt)
    return receipt


def verify_retention_receipt(
    receipt: dict[str, Any],
    *,
    checkpoint: dict[str, Any],
    trusted_store_key: TrustedKey,
    expected_store_id: str,
    now: str,
) -> None:
    try:
        validate("checkpoint", checkpoint)
        validate("checkpoint-retention-receipt", receipt)
    except Exception as exc:
        raise RetentionReceiptError("retention receipt schema rejected") from exc
    if receipt["store_id"] != expected_store_id:
        raise RetentionReceiptError("retention store identity mismatch")
    if (
        receipt["signer_id"] != trusted_store_key.key_id
        or receipt["signature"]["key_id"] != trusted_store_key.key_id
        or not verify_signature(receipt, trusted_store_key.public_key)
    ):
        raise RetentionReceiptError("retention receipt signature rejected")
    expected_digest = digest_object(
        checkpoint,
        domain="checkpoint-retention-reference-v1",
    )
    if receipt["checkpoint_digest"] != expected_digest:
        raise RetentionReceiptError("retained checkpoint digest mismatch")
    if receipt["tenant_id"] != checkpoint["tenant_id"]:
        raise RetentionReceiptError("retention tenant mismatch")
    if receipt["tree_size"] != checkpoint["tree_size"]:
        raise RetentionReceiptError("retention tree size mismatch")

    retained_at = _parse_time(receipt["retained_at"])
    expires_at = _parse_time(receipt["expires_at"])
    current = _parse_time(now)
    if retained_at > expires_at:
        raise RetentionReceiptError("retention interval is inverted")
    if current > expires_at:
        raise RetentionReceiptError("retention receipt has expired")
