"""Signed retention policy verification and read-only eligibility decisions.

Guardian never deletes evidence. It can only produce a deterministic decision
that a separately authorized customer-local retention executor may review.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta
from typing import Any

from .canonical import canonical_bytes
from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_bytes


class RetentionPolicyError(ValueError):
    """Raised when a retention policy or decision is not trustworthy."""


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (AttributeError, ValueError) as exc:
        raise RetentionPolicyError("invalid retention timestamp") from exc
    if parsed.tzinfo is None:
        raise RetentionPolicyError("retention timestamp must include timezone")
    return parsed


def _signature_payload(document: dict[str, Any]) -> bytes:
    unsigned = deepcopy(document)
    authorization = unsigned.get("authorization")
    if not isinstance(authorization, dict):
        raise RetentionPolicyError("retention authorization is missing")
    authorization.pop("signature", None)
    return b"integrity-guardian\x00retention-policy-v1\x00" + canonical_bytes(unsigned)


def sign_retention_policy(
    unsigned_policy: dict[str, Any],
    signer: Ed25519Signer,
) -> dict[str, Any]:
    document = deepcopy(unsigned_policy)
    authorization = document.get("authorization")
    if not isinstance(authorization, dict):
        raise RetentionPolicyError("retention authorization is missing")
    if "signature" in authorization:
        raise RetentionPolicyError("retention policy is already signed")
    authorization["signature"] = {
        "algorithm": "ed25519",
        "key_id": signer.key_id,
        "value": signer.sign_bytes(_signature_payload(document)),
    }
    validate("retention-policy", document)
    return document


def verify_retention_policy(
    document: dict[str, Any],
    *,
    authority_key: TrustedKey,
    expected_tenant_id: str,
    now: str,
) -> str:
    try:
        validate("retention-policy", document)
    except Exception as exc:
        raise RetentionPolicyError("retention policy schema rejected") from exc
    signature = document["authorization"]["signature"]
    if (
        document["authorization"]["authority_id"] != authority_key.key_id
        or signature["key_id"] != authority_key.key_id
        or not verify_bytes(
            _signature_payload(document),
            signature["value"],
            authority_key.public_key,
        )
    ):
        raise RetentionPolicyError("retention policy signature rejected")
    if document["tenant_id"] != expected_tenant_id:
        raise RetentionPolicyError("cross-tenant retention policy prohibited")

    valid_from = _parse_time(document["valid_from"])
    valid_until = _parse_time(document["valid_until"])
    current = _parse_time(now)
    if valid_from > valid_until:
        raise RetentionPolicyError("retention policy interval is inverted")
    if not valid_from <= current <= valid_until:
        raise RetentionPolicyError("retention policy is not currently valid")

    controls = document["controls"]
    if (
        controls["guardian_deletes"] is not False
        or controls["deletion_executor"] != "external-customer-local"
        or controls["legal_hold_preserves"] is not True
        or controls["unknown_timestamp_action"] != "retain"
    ):
        raise RetentionPolicyError("retention safety controls are invalid")
    return digest_object(document, domain="retention-policy-reference-v1")


def retention_decision(
    policy: dict[str, Any],
    *,
    authority_key: TrustedKey,
    expected_tenant_id: str,
    artifact_class: str,
    created_at: str | None,
    now: str,
    legal_hold: bool,
) -> dict[str, Any]:
    """Return an eligibility statement from a currently trusted policy.

    Verification is intentionally repeated here so callers cannot accidentally
    turn a merely schema-valid or tampered policy into a pruning decision.
    """

    policy_digest = verify_retention_policy(
        policy,
        authority_key=authority_key,
        expected_tenant_id=expected_tenant_id,
        now=now,
    )
    if artifact_class not in policy["classes"]:
        raise RetentionPolicyError("unknown retention artifact class")

    decision = "retain"
    reason = "within-retention-window"
    eligible_at: str | None = None

    if legal_hold:
        reason = "legal-hold"
    elif created_at is None:
        reason = "unknown-timestamp"
    else:
        created = _parse_time(created_at)
        current = _parse_time(now)
        if current < created:
            reason = "future-timestamp"
        else:
            expiry = created + timedelta(days=policy["classes"][artifact_class])
            eligible_at = expiry.isoformat().replace("+00:00", "Z")
            if current >= expiry:
                decision = "eligible-for-external-prune"
                reason = "retention-window-expired"

    result = {
        "protocol": "integrity-guardian/retention-decision/v1",
        "tenant_id": policy["tenant_id"],
        "policy_id": policy["policy_id"],
        "policy_digest": policy_digest,
        "artifact_class": artifact_class,
        "decision": decision,
        "reason": reason,
        "eligible_at": eligible_at,
        "evaluated_at": now,
        "guardian_deleted": False,
        "requires_external_authorization": decision == "eligible-for-external-prune",
    }
    result["decision_digest"] = digest_object(
        result,
        domain="retention-decision-v1",
    )
    validate("retention-decision", result)
    return result
