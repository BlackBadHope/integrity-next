"""Signed, no-authority evidence for a future module-agent handoff."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any

from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_signature


class AgentHandoffError(ValueError):
    """Raised when handoff evidence is invalid or ambiguously bound."""


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise AgentHandoffError("handoff timestamp requires a timezone")
    return parsed


def _identity(document: dict[str, Any], *, field: str, prefix: str, domain: str) -> str:
    unsigned = deepcopy(document)
    unsigned.pop("signature", None)
    actual = unsigned[field]
    unsigned[field] = f"{prefix}pending"
    expected = prefix + digest_object(unsigned, domain=domain).split(":", 1)[1]
    if actual != expected:
        raise AgentHandoffError(f"{field.replace('_', ' ')} identity mismatch")
    return actual


def build_module_agent_handoff_checkpoint(
    *,
    tenant_id: str,
    module_id: str,
    predecessor_agent_id: str,
    predecessor_generation: int,
    predecessor_lease_id: str,
    predecessor_head_id: str,
    predecessor_head_digest: str,
    successor_agent_id: str,
    successor_key_id: str,
    successor_generation: int,
    snapshot_digest: str,
    event_cursor: int,
    outstanding_work_digest: str,
    created_at: str,
    expires_at: str,
    predecessor_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Build predecessor evidence; this does not transfer a lease."""

    if successor_generation <= predecessor_generation:
        raise AgentHandoffError("successor generation must advance the chain")
    if _time(created_at) >= _time(expires_at):
        raise AgentHandoffError("handoff checkpoint validity interval is not positive")
    unsigned: dict[str, Any] = {
        "protocol": "integrity-guardian/module-agent-handoff-checkpoint/v1",
        "checkpoint_id": "handoff-checkpoint:pending",
        "tenant_id": tenant_id,
        "module_id": module_id,
        "predecessor_agent_id": predecessor_agent_id,
        "predecessor_key_id": predecessor_signer.key_id,
        "predecessor_generation": predecessor_generation,
        "predecessor_lease_id": predecessor_lease_id,
        "predecessor_head_id": predecessor_head_id,
        "predecessor_head_digest": predecessor_head_digest,
        "successor_agent_id": successor_agent_id,
        "successor_key_id": successor_key_id,
        "successor_generation": successor_generation,
        "snapshot_digest": snapshot_digest,
        "event_cursor": event_cursor,
        "outstanding_work_digest": outstanding_work_digest,
        "created_at": created_at,
        "expires_at": expires_at,
        "production_authority": False,
    }
    identity = digest_object(
        unsigned, domain="module-agent-handoff-checkpoint-identity-v1"
    ).split(":", 1)[1]
    unsigned["checkpoint_id"] = f"handoff-checkpoint:{identity}"
    checkpoint = predecessor_signer.sign(unsigned)
    validate("module-agent-handoff-checkpoint", checkpoint)
    return checkpoint


def verify_module_agent_handoff_checkpoint(
    checkpoint: dict[str, Any],
    *,
    predecessor_key: TrustedKey,
    at_time: str,
) -> dict[str, Any]:
    """Verify checkpoint bindings without claiming current-head freshness."""

    validate("module-agent-handoff-checkpoint", checkpoint)
    if (
        checkpoint["predecessor_key_id"] != predecessor_key.key_id
        or checkpoint["signature"]["key_id"] != predecessor_key.key_id
        or not verify_signature(checkpoint, predecessor_key.public_key)
    ):
        raise AgentHandoffError("handoff checkpoint signature rejected")
    checkpoint_id = _identity(
        checkpoint,
        field="checkpoint_id",
        prefix="handoff-checkpoint:",
        domain="module-agent-handoff-checkpoint-identity-v1",
    )
    created = _time(checkpoint["created_at"])
    expires = _time(checkpoint["expires_at"])
    now = _time(at_time)
    if created >= expires:
        raise AgentHandoffError("handoff checkpoint validity interval is not positive")
    if not created <= now < expires:
        raise AgentHandoffError("handoff checkpoint is not current")
    if checkpoint["successor_generation"] <= checkpoint["predecessor_generation"]:
        raise AgentHandoffError("successor generation does not advance the chain")
    return {
        "ok": True,
        "checkpoint_id": checkpoint_id,
        "tenant_id": checkpoint["tenant_id"],
        "module_id": checkpoint["module_id"],
        "successor_agent_id": checkpoint["successor_agent_id"],
        "successor_generation": checkpoint["successor_generation"],
        "event_cursor": checkpoint["event_cursor"],
        "freshness": "UNPROVEN",
        "commit_status": "NOT_ATTEMPTED",
        "production_authority": False,
    }


def acknowledge_module_agent_handoff(
    checkpoint: dict[str, Any],
    *,
    predecessor_key: TrustedKey,
    successor_signer: Ed25519Signer,
    acknowledged_at: str,
    expires_at: str,
) -> dict[str, Any]:
    """Create a shadow-only successor ACK bound to one exact checkpoint."""

    verification = verify_module_agent_handoff_checkpoint(
        checkpoint, predecessor_key=predecessor_key, at_time=acknowledged_at
    )
    if checkpoint["successor_key_id"] != successor_signer.key_id:
        raise AgentHandoffError("successor key identity mismatch")
    acknowledged = _time(acknowledged_at)
    expires = _time(expires_at)
    if acknowledged >= expires or expires > _time(checkpoint["expires_at"]):
        raise AgentHandoffError("successor ACK validity exceeds checkpoint")
    unsigned: dict[str, Any] = {
        "protocol": "integrity-guardian/module-agent-successor-ack/v1",
        "ack_id": "successor-ack:pending",
        "checkpoint_id": verification["checkpoint_id"],
        "checkpoint_digest": digest_object(
            checkpoint, domain="module-agent-handoff-checkpoint-reference-v1"
        ),
        "tenant_id": verification["tenant_id"],
        "module_id": verification["module_id"],
        "successor_agent_id": checkpoint["successor_agent_id"],
        "successor_key_id": successor_signer.key_id,
        "successor_generation": checkpoint["successor_generation"],
        "event_cursor": checkpoint["event_cursor"],
        "snapshot_digest": checkpoint["snapshot_digest"],
        "outstanding_work_digest": checkpoint["outstanding_work_digest"],
        "mode": "shadow",
        "accepted": True,
        "acknowledged_at": acknowledged_at,
        "expires_at": expires_at,
        "commit_status": "NOT_ATTEMPTED",
        "production_authority": False,
    }
    identity = digest_object(
        unsigned, domain="module-agent-successor-ack-identity-v1"
    ).split(":", 1)[1]
    unsigned["ack_id"] = f"successor-ack:{identity}"
    ack = successor_signer.sign(unsigned)
    validate("module-agent-successor-ack", ack)
    return ack


def verify_module_agent_successor_ack(
    checkpoint: dict[str, Any],
    ack: dict[str, Any],
    *,
    predecessor_key: TrustedKey,
    successor_key: TrustedKey,
    at_time: str,
) -> dict[str, Any]:
    """Verify exact checkpoint/ACK bindings; never claim a committed handoff."""

    checkpoint_verification = verify_module_agent_handoff_checkpoint(
        checkpoint, predecessor_key=predecessor_key, at_time=at_time
    )
    validate("module-agent-successor-ack", ack)
    if (
        ack["successor_key_id"] != successor_key.key_id
        or ack["signature"]["key_id"] != successor_key.key_id
        or not verify_signature(ack, successor_key.public_key)
    ):
        raise AgentHandoffError("successor ACK signature rejected")
    ack_id = _identity(
        ack,
        field="ack_id",
        prefix="successor-ack:",
        domain="module-agent-successor-ack-identity-v1",
    )
    acknowledged = _time(ack["acknowledged_at"])
    expires = _time(ack["expires_at"])
    if (
        acknowledged < _time(checkpoint["created_at"])
        or acknowledged >= expires
        or expires > _time(checkpoint["expires_at"])
    ):
        raise AgentHandoffError("successor ACK validity exceeds checkpoint")
    now = _time(at_time)
    if not acknowledged <= now < expires:
        raise AgentHandoffError("successor ACK is not current")
    expected = {
        "checkpoint_id": checkpoint["checkpoint_id"],
        "checkpoint_digest": digest_object(
            checkpoint, domain="module-agent-handoff-checkpoint-reference-v1"
        ),
        "tenant_id": checkpoint["tenant_id"],
        "module_id": checkpoint["module_id"],
        "successor_agent_id": checkpoint["successor_agent_id"],
        "successor_key_id": checkpoint["successor_key_id"],
        "successor_generation": checkpoint["successor_generation"],
        "event_cursor": checkpoint["event_cursor"],
        "snapshot_digest": checkpoint["snapshot_digest"],
        "outstanding_work_digest": checkpoint["outstanding_work_digest"],
        "mode": "shadow",
        "commit_status": "NOT_ATTEMPTED",
    }
    for field, value in expected.items():
        if ack[field] != value:
            raise AgentHandoffError(f"successor ACK {field} does not match checkpoint")
    return {
        "ok": True,
        "bindings_valid": True,
        "checkpoint_id": checkpoint_verification["checkpoint_id"],
        "ack_id": ack_id,
        "tenant_id": ack["tenant_id"],
        "module_id": ack["module_id"],
        "successor_agent_id": ack["successor_agent_id"],
        "successor_generation": ack["successor_generation"],
        "freshness": "UNPROVEN",
        "commit_status": "NOT_ATTEMPTED",
        "production_authority": False,
    }
