"""Signed module leases and same-agent cognitive-engine continuation."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any

from .atlas import verify_atlas_projection
from .hashing import digest_object
from .model_router import (
    AlarmSignal,
    ModelDescriptor,
    ModelRoutePolicy,
    ModelRoutingError,
    _verify_model_route_receipt,
)
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_signature


class AgentContinuityError(ValueError):
    """Raised when module ownership or cognitive continuation is ambiguous."""


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise AgentContinuityError("continuity timestamp requires a timezone")
    return parsed


def build_module_agent_lease(
    *,
    tenant_id: str,
    module_id: str,
    agent_id: str,
    agent_key_id: str,
    generation: int,
    sequence: int,
    event_cursor: int,
    state_digest: str,
    valid_from: str,
    valid_until: str,
    status: str,
    authority_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Create one authority-signed primary lease."""

    unsigned: dict[str, Any] = {
        "protocol": "integrity-guardian/module-agent-lease/v1",
        "lease_id": "lease:pending",
        "tenant_id": tenant_id,
        "module_id": module_id,
        "agent_id": agent_id,
        "agent_key_id": agent_key_id,
        "generation": generation,
        "sequence": sequence,
        "event_cursor": event_cursor,
        "state_digest": state_digest,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "status": status,
        "authority_id": authority_signer.key_id,
        "production_authority": False,
    }
    identity = digest_object(unsigned, domain="module-agent-lease-identity-v1").split(
        ":", 1
    )[1]
    unsigned["lease_id"] = f"lease:{identity}"
    lease = authority_signer.sign(unsigned)
    validate("module-agent-lease", lease)
    if _time(valid_from) >= _time(valid_until):
        raise AgentContinuityError("module lease validity interval is not positive")
    return lease


def verify_module_agent_lease(
    lease: dict[str, Any],
    *,
    authority_key: TrustedKey,
    at_time: str,
) -> dict[str, Any]:
    """Verify signature, identity and active-time semantics."""

    validate("module-agent-lease", lease)
    if (
        lease["authority_id"] != authority_key.key_id
        or lease["signature"]["key_id"] != authority_key.key_id
        or not verify_signature(lease, authority_key.public_key)
    ):
        raise AgentContinuityError("module lease authority signature rejected")
    unsigned = deepcopy(lease)
    unsigned.pop("signature")
    actual_lease_id = unsigned["lease_id"]
    unsigned["lease_id"] = "lease:pending"
    expected_lease_id = "lease:" + digest_object(
        unsigned, domain="module-agent-lease-identity-v1"
    ).split(":", 1)[1]
    if actual_lease_id != expected_lease_id:
        raise AgentContinuityError("module lease identity mismatch")
    valid_from = _time(lease["valid_from"])
    valid_until = _time(lease["valid_until"])
    if valid_from >= valid_until:
        raise AgentContinuityError("module lease validity interval is not positive")
    now = _time(at_time)
    active = lease["status"] == "active" and valid_from <= now < valid_until
    return {
        "ok": True,
        "lease_id": actual_lease_id,
        "tenant_id": lease["tenant_id"],
        "module_id": lease["module_id"],
        "agent_id": lease["agent_id"],
        "generation": lease["generation"],
        "sequence": lease["sequence"],
        "event_cursor": lease["event_cursor"],
        "active": active,
        "freshness": "UNPROVEN",
        "production_authority": False,
    }


def build_module_agent_lease_head(
    *,
    lease: dict[str, Any],
    head_revision: int,
    previous_head_id: str | None,
    recorded_at: str,
    authority_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Pin one exact authority-signed lease as the current module head."""

    validate("module-agent-lease", lease)
    if (
        lease["authority_id"] != authority_signer.key_id
        or lease["signature"]["key_id"] != authority_signer.key_id
        or not verify_signature(lease, authority_signer.public_key)
    ):
        raise AgentContinuityError("lease head authority differs from lease authority")
    if head_revision < 0:
        raise AgentContinuityError("lease head revision cannot be negative")
    if (head_revision == 0) != (previous_head_id is None):
        raise AgentContinuityError("lease head predecessor does not match revision")
    _time(recorded_at)
    unsigned: dict[str, Any] = {
        "protocol": "integrity-guardian/module-agent-lease-head/v1",
        "head_id": "lease-head:pending",
        "tenant_id": lease["tenant_id"],
        "module_id": lease["module_id"],
        "head_revision": head_revision,
        "previous_head_id": previous_head_id,
        "state": "active",
        "lease_id": lease["lease_id"],
        "lease_digest": digest_object(
            lease,
            domain="module-agent-lease-reference-v1",
        ),
        "agent_id": lease["agent_id"],
        "agent_key_id": lease["agent_key_id"],
        "generation": lease["generation"],
        "sequence": lease["sequence"],
        "event_cursor": lease["event_cursor"],
        "state_digest": lease["state_digest"],
        "recorded_at": recorded_at,
        "authority_id": authority_signer.key_id,
        "production_authority": False,
    }
    identity = digest_object(
        unsigned,
        domain="module-agent-lease-head-identity-v1",
    ).split(":", 1)[1]
    unsigned["head_id"] = f"lease-head:{identity}"
    head = authority_signer.sign(unsigned)
    validate("module-agent-lease-head", head)
    return head


def verify_module_agent_lease_head(
    head: dict[str, Any],
    *,
    authority_key: TrustedKey,
) -> dict[str, Any]:
    """Verify one signed continuity head without claiming global freshness."""

    validate("module-agent-lease-head", head)
    if (
        head["authority_id"] != authority_key.key_id
        or head["signature"]["key_id"] != authority_key.key_id
        or not verify_signature(head, authority_key.public_key)
    ):
        raise AgentContinuityError("module lease head authority signature rejected")
    unsigned = deepcopy(head)
    unsigned.pop("signature")
    actual_head_id = unsigned["head_id"]
    unsigned["head_id"] = "lease-head:pending"
    expected_head_id = "lease-head:" + digest_object(
        unsigned,
        domain="module-agent-lease-head-identity-v1",
    ).split(":", 1)[1]
    if actual_head_id != expected_head_id:
        raise AgentContinuityError("module lease head identity mismatch")
    if (head["head_revision"] == 0) != (head["previous_head_id"] is None):
        raise AgentContinuityError("module lease head predecessor mismatch")
    _time(head["recorded_at"])
    return {
        "ok": True,
        "head_id": actual_head_id,
        "tenant_id": head["tenant_id"],
        "module_id": head["module_id"],
        "head_revision": head["head_revision"],
        "lease_id": head["lease_id"],
        "freshness": "UNPROVEN",
        "production_authority": False,
    }


def verify_current_module_agent_lease(
    lease: dict[str, Any],
    *,
    lease_head: dict[str, Any],
    trusted_head_id: str,
    authority_key: TrustedKey,
    at_time: str,
) -> dict[str, Any]:
    """Authorize a lease only relative to an independently retained head pin."""

    head_verification = verify_module_agent_lease_head(
        lease_head,
        authority_key=authority_key,
    )
    if head_verification["head_id"] != trusted_head_id:
        raise AgentContinuityError("module lease head differs from trusted pin")
    lease_verification = verify_module_agent_lease(
        lease,
        authority_key=authority_key,
        at_time=at_time,
    )
    if not lease_verification["active"]:
        raise AgentContinuityError("trusted module lease is not active")
    expected = {
        "tenant_id": lease["tenant_id"],
        "module_id": lease["module_id"],
        "lease_id": lease["lease_id"],
        "lease_digest": digest_object(
            lease,
            domain="module-agent-lease-reference-v1",
        ),
        "agent_id": lease["agent_id"],
        "agent_key_id": lease["agent_key_id"],
        "generation": lease["generation"],
        "sequence": lease["sequence"],
        "event_cursor": lease["event_cursor"],
        "state_digest": lease["state_digest"],
    }
    for field, value in expected.items():
        if lease_head[field] != value:
            raise AgentContinuityError(
                f"module lease head {field} does not match lease"
            )
    return {
        **lease_verification,
        "head_id": trusted_head_id,
        "head_revision": lease_head["head_revision"],
        "freshness": "PINNED",
    }


def select_single_primary_lease(
    leases: list[dict[str, Any]],
    *,
    tenant_id: str,
    module_id: str,
    authority_key: TrustedKey,
    at_time: str,
) -> dict[str, Any]:
    """Return the sole active lease or fail closed on absence/split-brain."""

    lease_ids = [lease.get("lease_id") for lease in leases]
    if len(set(lease_ids)) != len(lease_ids):
        raise AgentContinuityError("duplicate module lease identity")
    active: list[dict[str, Any]] = []
    for lease in leases:
        verification = verify_module_agent_lease(
            lease,
            authority_key=authority_key,
            at_time=at_time,
        )
        if (
            verification["tenant_id"] == tenant_id
            and verification["module_id"] == module_id
            and verification["active"]
        ):
            active.append(lease)
    if not active:
        raise AgentContinuityError("module has no active primary lease")
    if len(active) > 1:
        raise AgentContinuityError("module primary lease split-brain")
    return active[0]


def _build_cognitive_continuation(
    *,
    lease: dict[str, Any],
    lease_head: dict[str, Any],
    trusted_lease_head_id: str,
    authority_key: TrustedKey,
    at_time: str,
    atlas_projection: dict[str, Any],
    route_receipt: dict[str, Any],
    route_signal: AlarmSignal,
    route_policy: ModelRoutePolicy,
    model_registry: list[ModelDescriptor],
    source_model_id: str | None,
    unresolved_questions: list[str],
    stop_conditions: list[str],
) -> dict[str, Any]:
    """Internal builder for a route already authorized by Atlas L0."""

    lease_verification = verify_current_module_agent_lease(
        lease,
        lease_head=lease_head,
        trusted_head_id=trusted_lease_head_id,
        authority_key=authority_key,
        at_time=at_time,
    )
    if not lease_verification["active"]:
        raise AgentContinuityError("cognitive continuation requires an active lease")
    atlas_verification = verify_atlas_projection(atlas_projection)
    try:
        route_verification = _verify_model_route_receipt(
            route_receipt,
            signal=route_signal,
            policy=route_policy,
            registry=model_registry,
        )
    except ModelRoutingError as exc:
        raise AgentContinuityError(
            "model route receipt differs from trusted inputs"
        ) from exc
    if not route_verification["authorized"]:
        raise AgentContinuityError("model route has no trusted provenance")
    if atlas_verification["tenant_id"] != lease["tenant_id"]:
        raise AgentContinuityError("Atlas projection tenant differs from module lease")
    expected_state_digest = digest_object(
        atlas_projection, domain="atlas-module-state-v1"
    )
    if lease["state_digest"] != expected_state_digest:
        raise AgentContinuityError("Atlas projection state differs from module lease")
    if route_verification["tenant_id"] != lease["tenant_id"]:
        raise AgentContinuityError("model route tenant differs from module lease")
    if route_receipt["status"] != "ready" or route_receipt["selected_model"] is None:
        raise AgentContinuityError("model route is not ready for continuation")
    if route_receipt["incident_id"].split(":", 1)[0] != "incident":
        raise AgentContinuityError("model route incident identity is invalid")

    selected = route_receipt["selected_model"]
    package: dict[str, Any] = {
        "protocol": "integrity-guardian/cognitive-continuation/v1",
        "package_id": "continuation:pending",
        "tenant_id": lease["tenant_id"],
        "module_id": lease["module_id"],
        "agent_id": lease["agent_id"],
        "agent_key_id": lease["agent_key_id"],
        "generation": lease["generation"],
        "lease_id": lease["lease_id"],
        "lease_head_id": lease_verification["head_id"],
        "lease_head_revision": lease_verification["head_revision"],
        "event_cursor": lease["event_cursor"],
        "state_digest": lease["state_digest"],
        "atlas_projection_id": atlas_projection["projection_id"],
        "route_id": route_receipt["route_id"],
        "source_model_id": source_model_id,
        "target_model_id": selected["model_id"],
        "target_tier": route_receipt["required_tier"],
        "target_reasoning": route_receipt["minimum_reasoning"],
        "unresolved_questions": sorted(set(unresolved_questions)),
        "stop_conditions": sorted(set(stop_conditions)),
        "budgets": deepcopy(route_receipt["budgets"]),
        "production_authority": False,
    }
    identity = digest_object(
        package, domain="cognitive-continuation-identity-v1"
    ).split(":", 1)[1]
    package["package_id"] = f"continuation:{identity}"
    validate("cognitive-continuation", package)
    return package


def verify_cognitive_continuation(package: dict[str, Any]) -> dict[str, Any]:
    """Verify a continuation package's deterministic identity."""

    validate("cognitive-continuation", package)
    unsigned = deepcopy(package)
    actual_package_id = unsigned["package_id"]
    unsigned["package_id"] = "continuation:pending"
    expected_package_id = "continuation:" + digest_object(
        unsigned, domain="cognitive-continuation-identity-v1"
    ).split(":", 1)[1]
    if actual_package_id != expected_package_id:
        raise AgentContinuityError("cognitive continuation identity mismatch")
    return {
        "ok": True,
        "package_id": actual_package_id,
        "tenant_id": package["tenant_id"],
        "module_id": package["module_id"],
        "agent_id": package["agent_id"],
        "generation": package["generation"],
        "lease_id": package["lease_id"],
        "lease_head_id": package["lease_head_id"],
        "lease_head_revision": package["lease_head_revision"],
        "event_cursor": package["event_cursor"],
        "target_model_id": package["target_model_id"],
        "production_authority": False,
    }


def acknowledge_cognitive_continuation(
    package: dict[str, Any],
    *,
    agent_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Sign the stable agent identity's ACK after the target model resumes."""

    verification = verify_cognitive_continuation(package)
    if package["agent_key_id"] != agent_signer.key_id:
        raise AgentContinuityError("continuation agent key identity mismatch")
    unsigned: dict[str, Any] = {
        "protocol": "integrity-guardian/cognitive-continuation-receipt/v1",
        "receipt_id": "continuation-receipt:pending",
        "package_id": package["package_id"],
        "package_digest": digest_object(
            package, domain="cognitive-continuation-package-v1"
        ),
        "tenant_id": verification["tenant_id"],
        "module_id": verification["module_id"],
        "agent_id": verification["agent_id"],
        "generation": verification["generation"],
        "lease_id": verification["lease_id"],
        "event_cursor": verification["event_cursor"],
        "resumed_model_id": verification["target_model_id"],
        "accepted": True,
        "agent_key_id": agent_signer.key_id,
        "production_authority": False,
    }
    identity = digest_object(
        unsigned, domain="cognitive-continuation-receipt-identity-v1"
    ).split(":", 1)[1]
    unsigned["receipt_id"] = f"continuation-receipt:{identity}"
    receipt = agent_signer.sign(unsigned)
    validate("cognitive-continuation-receipt", receipt)
    return receipt


def verify_cognitive_continuation_receipt(
    package: dict[str, Any],
    receipt: dict[str, Any],
    *,
    agent_key: TrustedKey,
) -> dict[str, Any]:
    """Verify the target engine resumed as the same stable Atlas agent."""

    package_verification = verify_cognitive_continuation(package)
    validate("cognitive-continuation-receipt", receipt)
    if (
        receipt["agent_key_id"] != agent_key.key_id
        or receipt["signature"]["key_id"] != agent_key.key_id
        or not verify_signature(receipt, agent_key.public_key)
    ):
        raise AgentContinuityError("continuation receipt signature rejected")
    unsigned = deepcopy(receipt)
    unsigned.pop("signature")
    actual_receipt_id = unsigned["receipt_id"]
    unsigned["receipt_id"] = "continuation-receipt:pending"
    expected_receipt_id = "continuation-receipt:" + digest_object(
        unsigned, domain="cognitive-continuation-receipt-identity-v1"
    ).split(":", 1)[1]
    if actual_receipt_id != expected_receipt_id:
        raise AgentContinuityError("continuation receipt identity mismatch")
    expected = {
        "package_id": package["package_id"],
        "package_digest": digest_object(
            package, domain="cognitive-continuation-package-v1"
        ),
        "tenant_id": package_verification["tenant_id"],
        "module_id": package_verification["module_id"],
        "agent_id": package_verification["agent_id"],
        "generation": package_verification["generation"],
        "lease_id": package_verification["lease_id"],
        "event_cursor": package_verification["event_cursor"],
        "resumed_model_id": package_verification["target_model_id"],
        "agent_key_id": package["agent_key_id"],
    }
    for field, value in expected.items():
        if receipt[field] != value:
            raise AgentContinuityError(
                f"continuation receipt {field} does not match package"
            )
    return {
        "ok": True,
        "receipt_id": actual_receipt_id,
        "package_id": package["package_id"],
        "agent_id": receipt["agent_id"],
        "generation": receipt["generation"],
        "resumed_model_id": receipt["resumed_model_id"],
        "production_authority": False,
    }
