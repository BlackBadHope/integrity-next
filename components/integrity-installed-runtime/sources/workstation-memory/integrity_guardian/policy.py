"""Signed customer-policy bindings for operational Guardian leases."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any

from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_signature


class CustomerPolicyError(ValueError):
    """Raised when customer policy authority cannot be established."""


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise CustomerPolicyError("customer policy timestamp requires a timezone")
    return parsed


def build_customer_policy_binding(
    *,
    tenant_id: str,
    policy_digest: str,
    valid_from: str,
    valid_until: str,
    authority_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Bind one policy digest to one tenant under an external authority."""

    if _time(valid_from) >= _time(valid_until):
        raise CustomerPolicyError("customer policy validity interval is not positive")
    unsigned: dict[str, Any] = {
        "protocol": "integrity-guardian/customer-policy-binding/v1",
        "binding_id": "policy-binding:pending",
        "tenant_id": tenant_id,
        "policy_digest": policy_digest,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "authority_id": authority_signer.key_id,
        "production_authority": False,
    }
    identity = digest_object(
        unsigned,
        domain="customer-policy-binding-identity-v1",
    ).split(":", 1)[1]
    unsigned["binding_id"] = f"policy-binding:{identity}"
    binding = authority_signer.sign(unsigned)
    validate("customer-policy-binding", binding)
    return binding


def verify_customer_policy_binding(
    binding: dict[str, Any],
    *,
    tenant_id: str,
    authority_key: TrustedKey,
    at_time: str,
) -> dict[str, Any]:
    """Verify signature, identity, tenant and active-time semantics."""

    validate("customer-policy-binding", binding)
    if binding["tenant_id"] != tenant_id:
        raise CustomerPolicyError("customer policy tenant mismatch")
    if (
        binding["authority_id"] != authority_key.key_id
        or binding["signature"]["key_id"] != authority_key.key_id
        or not verify_signature(binding, authority_key.public_key)
    ):
        raise CustomerPolicyError("customer policy authority signature rejected")
    unsigned = deepcopy(binding)
    unsigned.pop("signature")
    actual_id = unsigned["binding_id"]
    unsigned["binding_id"] = "policy-binding:pending"
    expected_id = "policy-binding:" + digest_object(
        unsigned,
        domain="customer-policy-binding-identity-v1",
    ).split(":", 1)[1]
    if actual_id != expected_id:
        raise CustomerPolicyError("customer policy binding identity mismatch")
    valid_from = _time(binding["valid_from"])
    valid_until = _time(binding["valid_until"])
    now = _time(at_time)
    if valid_from >= valid_until:
        raise CustomerPolicyError("customer policy validity interval is not positive")
    if not valid_from <= now < valid_until:
        raise CustomerPolicyError("customer policy binding is not active")
    return {
        "ok": True,
        "binding_id": actual_id,
        "tenant_id": tenant_id,
        "policy_digest": binding["policy_digest"],
        "authority_id": binding["authority_id"],
        "active": True,
        "production_authority": False,
    }
