"""Tenant-bound public key lifecycle verification.

Private keys remain outside Guardian. This module verifies signed public key
enrollment, rotation, revocation and recovery records without generating,
persisting or exporting private key material.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .canonical import canonical_bytes
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    trusted_key_from_value,
    verify_bytes,
)
from .tenant import validate_tenant_id


class KeyLifecycleError(ValueError):
    """Raised when a key transition is invalid, ambiguous or unauthorized."""


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (AttributeError, ValueError) as exc:
        raise KeyLifecycleError("invalid key lifecycle timestamp") from exc
    if parsed.tzinfo is None:
        raise KeyLifecycleError("key lifecycle timestamp must include timezone")
    return parsed


def _signature_payload(document: dict[str, Any]) -> bytes:
    unsigned = deepcopy(document)
    authorization = unsigned.get("authorization")
    if not isinstance(authorization, dict):
        raise KeyLifecycleError("key transition authorization is missing")
    authorization.pop("signature", None)
    return b"integrity-guardian\x00key-transition-v1\x00" + canonical_bytes(unsigned)


def sign_key_transition(
    unsigned_transition: dict[str, Any],
    signer: Ed25519Signer,
) -> dict[str, Any]:
    document = deepcopy(unsigned_transition)
    authorization = document.get("authorization")
    if not isinstance(authorization, dict):
        raise KeyLifecycleError("key transition authorization is missing")
    if "signature" in authorization:
        raise KeyLifecycleError("key transition is already signed")
    authorization["signature"] = {
        "algorithm": "ed25519",
        "key_id": signer.key_id,
        "value": signer.sign_bytes(_signature_payload(document)),
    }
    validate("key-transition", document)
    return document


@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    public_key_value: str
    valid_from: str
    valid_until: str

    def trusted_key(self) -> TrustedKey:
        return trusted_key_from_value(self.key_id, self.public_key_value)


@dataclass(frozen=True)
class KeyLifecycleState:
    tenant_id: str
    purpose: str
    sequence: int = -1
    active: KeyRecord | None = None
    retired_key_ids: frozenset[str] = frozenset()
    revoked_key_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        validate_tenant_id(self.tenant_id)


def _verify_transition_authority(
    document: dict[str, Any],
    authority_key: TrustedKey,
) -> None:
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
        raise KeyLifecycleError("key transition authority signature rejected")


def _successor_record(document: dict[str, Any]) -> KeyRecord | None:
    successor = document["successor"]
    if successor is None:
        return None
    record = KeyRecord(
        key_id=successor["key_id"],
        public_key_value=successor["public_key"],
        valid_from=successor["valid_from"],
        valid_until=successor["valid_until"],
    )
    record.trusted_key()
    valid_from = _parse_time(record.valid_from)
    valid_until = _parse_time(record.valid_until)
    recorded_at = _parse_time(document["recorded_at"])
    if not valid_from <= recorded_at <= valid_until:
        raise KeyLifecycleError("successor key is not valid at transition time")
    return record


def apply_key_transition(
    state: KeyLifecycleState,
    document: dict[str, Any],
    *,
    authority_key: TrustedKey,
) -> KeyLifecycleState:
    """Verify and apply one exact public key transition."""

    try:
        validate("key-transition", document)
    except Exception as exc:
        raise KeyLifecycleError("key transition schema rejected") from exc
    _verify_transition_authority(document, authority_key)

    if document["tenant_id"] != state.tenant_id:
        raise KeyLifecycleError("cross-tenant key transition prohibited")
    if document["purpose"] != state.purpose:
        raise KeyLifecycleError("key purpose mismatch")
    if document["sequence"] != state.sequence + 1:
        raise KeyLifecycleError("key transition sequence mismatch")

    operation = document["operation"]
    predecessor = document["predecessor_key_id"]
    successor = _successor_record(document)
    retired = set(state.retired_key_ids)
    revoked = set(state.revoked_key_ids)
    active = state.active

    if successor is not None and (
        successor.key_id in retired
        or successor.key_id in revoked
        or (active is not None and successor.key_id == active.key_id)
    ):
        raise KeyLifecycleError("key identifier reuse is prohibited")

    if operation == "enroll":
        if state.sequence != -1 or active is not None or predecessor is not None:
            raise KeyLifecycleError("enrollment is allowed only for an empty lifecycle")
        active = successor
    elif operation == "rotate":
        if active is None or predecessor != active.key_id or successor is None:
            raise KeyLifecycleError("rotation predecessor does not match active key")
        retired.add(active.key_id)
        active = successor
    elif operation == "revoke":
        if active is None or predecessor != active.key_id or successor is not None:
            raise KeyLifecycleError("revocation predecessor does not match active key")
        revoked.add(active.key_id)
        active = None
    elif operation == "recover":
        if (
            state.sequence < 0
            or active is not None
            or not state.revoked_key_ids
            or predecessor is not None
            or successor is None
        ):
            raise KeyLifecycleError("recovery requires a previously revoked inactive lifecycle")
        active = successor
    else:  # schema validation should make this unreachable
        raise KeyLifecycleError("unsupported key transition operation")

    return KeyLifecycleState(
        tenant_id=state.tenant_id,
        purpose=state.purpose,
        sequence=document["sequence"],
        active=active,
        retired_key_ids=frozenset(retired),
        revoked_key_ids=frozenset(revoked),
    )


def trusted_active_key(state: KeyLifecycleState, *, at: str) -> TrustedKey:
    """Return the active public key only while its validity interval is current."""

    if state.active is None:
        raise KeyLifecycleError("key lifecycle has no active key")
    current = _parse_time(at)
    if not _parse_time(state.active.valid_from) <= current <= _parse_time(
        state.active.valid_until
    ):
        raise KeyLifecycleError("active key is outside its validity interval")
    return state.active.trusted_key()
