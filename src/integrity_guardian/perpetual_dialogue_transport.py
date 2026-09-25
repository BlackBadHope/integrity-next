"""Fail-closed PPv4 transport seam for one bounded continuation turn.

The adapter commits a signed, idempotent start request to an external transport
driver.  It proves only that a bounded turn was created or read back.  It never
starts model execution and it never carries authority from the predecessor
baton.  A recipient must call :meth:`admit_turn` immediately before work so
owner PAUSE/STOP and work-item fencing still dominate a previously created
transport turn.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any, Protocol

from .canonical import canonical_bytes
from .perpetual_dialogue import PerpetualDialogueStore
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_signature

REQUEST_PROTOCOL = "integrity-guardian/perpetual-dialogue-transport-request/v1"
RECEIPT_PROTOCOL = "integrity-guardian/perpetual-dialogue-transport-receipt/v1"
DRIVER_OUTCOMES = frozenset({"CREATED", "EXISTS", "COMMIT_UNKNOWN", "REJECTED"})


class PerpetualDialogueTransportError(ValueError):
    """One bounded PPv4 transport contract violation."""


class PerpetualDialogueTransportDriver(Protocol):
    """Idempotent transport boundary implemented outside Guardian Core."""

    def start_or_read(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Create or read one turn by ``dispatch_id`` without starting work."""

    def read_by_dispatch_id(self, dispatch_id: str) -> Mapping[str, Any] | None:
        """Read authoritative outcome after an ambiguous first response."""


def _digest(value: object, *, domain: str) -> str:
    import hashlib

    payload = domain.encode("utf-8") + b"\x00" + canonical_bytes(value)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _verify_signed(
    document: Mapping[str, Any],
    *,
    schema_name: str,
    protocol: str,
    trusted_key: TrustedKey,
    identity_field: str,
    identity_domain: str,
) -> dict[str, Any]:
    candidate = deepcopy(dict(document))
    validate(schema_name, candidate)
    if candidate["protocol"] != protocol:
        raise PerpetualDialogueTransportError("transport protocol mismatch")
    if candidate["signature"]["key_id"] != trusted_key.key_id or not verify_signature(
        candidate, trusted_key.public_key
    ):
        raise PerpetualDialogueTransportError("transport signature rejected")
    unsigned = deepcopy(candidate)
    unsigned.pop("signature")
    identity = unsigned.pop(identity_field)
    if identity != _digest(unsigned, domain=identity_domain):
        raise PerpetualDialogueTransportError("transport identity mismatch")
    return candidate


def _dispatch_material(request: Mapping[str, Any]) -> dict[str, Any]:
    """Return immutable lineage only; owner control must not fork dispatch identity."""

    return {
        "protocol": request["protocol"],
        "tenant_id": request["tenant_id"],
        "conversation_id": request["conversation_id"],
        "work_item_id": request["work_item_id"],
        "wake_id": request["wake_id"],
        "baton_id": request["baton_id"],
    }


def verify_perpetual_dialogue_transport_request(
    request: Mapping[str, Any], *, trusted_key: TrustedKey
) -> dict[str, Any]:
    """Verify one signed, authority-free turn start request."""

    candidate = deepcopy(dict(request))
    validate("perpetual-dialogue-transport-request", candidate)
    if candidate["protocol"] != REQUEST_PROTOCOL:
        raise PerpetualDialogueTransportError("transport protocol mismatch")
    if candidate["signature"]["key_id"] != trusted_key.key_id or not verify_signature(
        candidate, trusted_key.public_key
    ):
        raise PerpetualDialogueTransportError("transport signature rejected")
    if candidate["dispatch_id"] != _digest(
        _dispatch_material(candidate),
        domain="perpetual-dialogue-transport-dispatch-v1",
    ):
        raise PerpetualDialogueTransportError("transport identity mismatch")
    if candidate["authority_inherited"] or candidate["production_authority"]:
        raise PerpetualDialogueTransportError("transport authority boundary rejected")
    return candidate


def verify_perpetual_dialogue_transport_receipt(
    receipt: Mapping[str, Any], *, trusted_key: TrustedKey
) -> dict[str, Any]:
    """Verify one signed receipt that proves only bounded turn creation."""

    candidate = _verify_signed(
        receipt,
        schema_name="perpetual-dialogue-transport-receipt",
        protocol=RECEIPT_PROTOCOL,
        trusted_key=trusted_key,
        identity_field="receipt_id",
        identity_domain="perpetual-dialogue-transport-receipt-v1",
    )
    if (
        candidate["execution_started"]
        or candidate["authority_inherited"]
        or candidate["production_authority"]
    ):
        raise PerpetualDialogueTransportError("transport receipt exceeds bounded turn creation")
    return candidate


class PerpetualDialogueTransportAdapter:
    """Bind a durable wake to one idempotently created external transport turn."""

    def __init__(
        self,
        *,
        store: PerpetualDialogueStore,
        signer: Ed25519Signer,
        driver: PerpetualDialogueTransportDriver,
    ) -> None:
        self.store = store
        self.signer = signer
        self.trusted_key = TrustedKey(signer.key_id, signer.public_key)
        if self.trusted_key != store.trusted_key:
            raise PerpetualDialogueTransportError(
                "transport signer is not bound to the dialogue store"
            )
        self.driver = driver

    def _require_current_request(self, request: Mapping[str, Any]) -> dict[str, Any]:
        snapshot = self.store.snapshot(conversation_id=request["conversation_id"])
        if (
            snapshot["conversation_state"] != "ACTIVE"
            or snapshot["control_generation"] != request["control_generation"]
        ):
            raise PerpetualDialogueTransportError("owner control superseded transport turn")
        wakes = [wake for wake in snapshot["wakes"] if wake["wake_id"] == request["wake_id"]]
        batons = [
            baton for baton in snapshot["batons"] if baton["baton_id"] == request["baton_id"]
        ]
        work_items = [
            work
            for work in snapshot["work_items"]
            if work["work_item_id"] == request["work_item_id"]
        ]
        if len(wakes) != 1 or len(batons) != 1 or len(work_items) != 1:
            raise PerpetualDialogueTransportError("transport admission state missing")
        wake = wakes[0]
        baton = batons[0]
        work = work_items[0]
        if (
            wake["wake_state"] != "CONSUMED"
            or wake["next_baton_id"] != request["baton_id"]
            or wake["target_agent_id"] != request["target_agent_id"]
            or wake["lease_fence"] != request["lease_fence"]
            or baton["baton_state"] != "OPEN"
            or baton["work_item_id"] != request["work_item_id"]
            or baton["recipient_id"] != request["target_agent_id"]
            or baton["processing_turn_id"] != request["processing_turn_id"]
            or baton["claim_digest"] != request["claim_digest"]
            or baton["authority_digest"] is not None
            or work["work_state"] != "OPEN"
            or work["fence"] != request["lease_fence"]
        ):
            raise PerpetualDialogueTransportError("transport turn is stale or unauthorized")
        return snapshot

    def build_request(
        self,
        *,
        conversation_id: str,
        wake_id: str,
        baton_id: str,
        target_agent_id: str,
        processing_turn_id: str,
        lease_fence: int,
        claim_digest: str,
    ) -> dict[str, Any]:
        snapshot = self.store.snapshot(conversation_id=conversation_id)
        wakes = [wake for wake in snapshot["wakes"] if wake["wake_id"] == wake_id]
        batons = [baton for baton in snapshot["batons"] if baton["baton_id"] == baton_id]
        if len(wakes) != 1 or len(batons) != 1:
            raise PerpetualDialogueTransportError("transport wake or baton is missing")
        wake = wakes[0]
        baton = batons[0]
        if (
            snapshot["conversation_state"] != "ACTIVE"
            or wake["wake_state"] != "CONSUMED"
            or wake["next_baton_id"] != baton_id
            or wake["target_agent_id"] != target_agent_id
            or wake["lease_fence"] != lease_fence
            or baton["baton_state"] != "OPEN"
            or baton["recipient_id"] != target_agent_id
            or baton["processing_turn_id"] != processing_turn_id
            or baton["claim_digest"] != claim_digest
            or baton["authority_digest"] is not None
        ):
            raise PerpetualDialogueTransportError("transport request state binding rejected")
        work_items = [
            work for work in snapshot["work_items"] if work["work_item_id"] == baton["work_item_id"]
        ]
        if len(work_items) != 1 or (
            work_items[0]["work_state"] != "OPEN"
            or work_items[0]["fence"] != lease_fence
        ):
            raise PerpetualDialogueTransportError("transport work fence rejected")
        unsigned = {
            "protocol": REQUEST_PROTOCOL,
            "dispatch_id": "sha256:pending",
            "tenant_id": snapshot["tenant_id"],
            "conversation_id": conversation_id,
            "work_item_id": baton["work_item_id"],
            "wake_id": wake_id,
            "baton_id": baton_id,
            "target_agent_id": target_agent_id,
            "processing_turn_id": processing_turn_id,
            "lease_fence": lease_fence,
            "claim_digest": claim_digest,
            "control_generation": snapshot["control_generation"],
            "authority_inherited": False,
            "production_authority": False,
        }
        unsigned["dispatch_id"] = _digest(
            _dispatch_material(unsigned),
            domain="perpetual-dialogue-transport-dispatch-v1",
        )
        signed = self.signer.sign(unsigned)
        return verify_perpetual_dialogue_transport_request(
            signed, trusted_key=self.trusted_key
        )

    def dispatch(self, request: Mapping[str, Any]) -> dict[str, Any]:
        verified = verify_perpetual_dialogue_transport_request(
            request, trusted_key=self.trusted_key
        )
        self._require_current_request(verified)
        first = dict(self.driver.start_or_read(deepcopy(verified)))
        outcome = first.get("outcome")
        if outcome not in DRIVER_OUTCOMES:
            raise PerpetualDialogueTransportError("transport driver outcome rejected")
        reconciled = False
        if outcome == "COMMIT_UNKNOWN":
            readback = self.driver.read_by_dispatch_id(verified["dispatch_id"])
            if readback is None:
                raise PerpetualDialogueTransportError("TRANSPORT_COMMIT_UNKNOWN")
            first = dict(readback)
            outcome = first.get("outcome")
            reconciled = True
        if outcome not in {"CREATED", "EXISTS"}:
            raise PerpetualDialogueTransportError("transport turn creation rejected")
        if first.get("dispatch_id") != verified["dispatch_id"]:
            raise PerpetualDialogueTransportError("transport readback dispatch mismatch")
        if first.get("execution_started") is not False:
            raise PerpetualDialogueTransportError("transport driver started execution")
        if first.get("authority_applied") is not False:
            raise PerpetualDialogueTransportError("transport driver applied authority")
        turn_id = first.get("transport_turn_id")
        if not isinstance(turn_id, str) or not turn_id or len(turn_id) > 256:
            raise PerpetualDialogueTransportError("transport turn identity rejected")
        unsigned = {
            "protocol": RECEIPT_PROTOCOL,
            "receipt_id": "sha256:pending",
            "dispatch_id": verified["dispatch_id"],
            "conversation_id": verified["conversation_id"],
            "work_item_id": verified["work_item_id"],
            "wake_id": verified["wake_id"],
            "baton_id": verified["baton_id"],
            "transport_turn_id": turn_id,
            "driver_outcome": outcome,
            "reconciled_after_unknown": reconciled,
            "execution_started": False,
            "authority_inherited": False,
            "production_authority": False,
        }
        material = deepcopy(unsigned)
        material.pop("receipt_id")
        unsigned["receipt_id"] = _digest(
            material, domain="perpetual-dialogue-transport-receipt-v1"
        )
        signed = self.signer.sign(unsigned)
        return verify_perpetual_dialogue_transport_receipt(
            signed, trusted_key=self.trusted_key
        )

    def admit_turn(
        self,
        *,
        request: Mapping[str, Any],
        receipt: Mapping[str, Any],
    ) -> dict[str, Any]:
        verified_request = verify_perpetual_dialogue_transport_request(
            request, trusted_key=self.trusted_key
        )
        verified_receipt = verify_perpetual_dialogue_transport_receipt(
            receipt, trusted_key=self.trusted_key
        )
        for field in ("dispatch_id", "conversation_id", "work_item_id", "wake_id", "baton_id"):
            if verified_receipt[field] != verified_request[field]:
                raise PerpetualDialogueTransportError("transport receipt binding rejected")
        self._require_current_request(verified_request)
        return {
            "admitted": True,
            "dispatch_id": verified_request["dispatch_id"],
            "transport_turn_id": verified_receipt["transport_turn_id"],
            "baton_id": verified_request["baton_id"],
            "authority_inherited": False,
            "production_authority": False,
        }


__all__ = [
    "PerpetualDialogueTransportAdapter",
    "PerpetualDialogueTransportDriver",
    "PerpetualDialogueTransportError",
    "verify_perpetual_dialogue_transport_receipt",
    "verify_perpetual_dialogue_transport_request",
]
