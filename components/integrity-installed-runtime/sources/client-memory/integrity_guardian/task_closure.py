"""Receipt-bound task completion over the canonical append-only Action Log.

This module performs no I/O.  It turns an authenticated owner-instruction
chain, one deterministic terminal-event request and the existing Action Log
append receipt into a closed completion receipt.  Phase constraints cannot
leak into later phases, and an append with an uncertain response can only move
through content-free reconciliation by its immutable event UID.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Any

from jsonschema import ValidationError

from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .schemas import validate
from .seed_catalog import ACTION_LOG_ALIAS, SEED_NAMESPACE, validate_seed_namespace
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)

INSTRUCTION_PROTOCOL = "integrity-guardian/task-instruction-envelope/v1"
RECONCILIATION_PROTOCOL = (
    "integrity-guardian/action-log-event-uid-reconciliation/v1"
)
APPEND_ATTEMPT_PROTOCOL = (
    "integrity-guardian/action-log-append-attempt-receipt/v1"
)
CLOSURE_EVENT_PROTOCOL = "integrity-guardian/task-closure-event/v1"
CLOSURE_RECEIPT_PROTOCOL = "integrity-guardian/task-closure-receipt/v1"
client_APPEND_RECEIPT_PROTOCOL = "integrity-client-memory-mcp/v2/append-receipt"

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_HEX_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_EVENT_UID = re.compile(r"^client:[A-Za-z0-9][A-Za-z0-9._:-]{7,154}$")
_CONFIRMED_APPEND_STATES = {
    "confirmed-created",
    "confirmed-duplicate",
    "reconciled-created",
}
_MUTATION_BOUNDARY = {
    "update": False,
    "delete": False,
    "import": False,
    "overwrite": False,
    "bulk_write": False,
}


class TaskClosureError(ValueError):
    """Raised before task completion can be overstated or replayed."""


def _freeze(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    try:
        frozen = parse_json_strict(canonical_bytes(dict(value)))
    except Exception as exc:
        raise TaskClosureError(f"task closure {field} rejected") from exc
    if not isinstance(frozen, dict):
        raise TaskClosureError(f"task closure {field} rejected")
    return frozen


def _require_id(value: object, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise TaskClosureError(f"task closure {field} rejected")
    return value


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise TaskClosureError(f"task closure {field} rejected")
    return value


def _require_hex_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _HEX_DIGEST.fullmatch(value) is None:
        raise TaskClosureError(f"task closure {field} rejected")
    return value


def _require_event_uid(value: object) -> str:
    if not isinstance(value, str) or _EVENT_UID.fullmatch(value) is None:
        raise TaskClosureError("task closure event UID rejected")
    return value


def _identity(document: Mapping[str, Any], *, prefix: str, domain: str) -> str:
    digest = digest_object(dict(document), domain=domain)
    return f"{prefix}{digest.split(':', 1)[1]}"


def build_task_instruction(
    *,
    task_id: str,
    issued_at: str,
    owner_instruction_digest: str,
    terminal_event_append: str,
    scope: str = "task",
    phase_id: str | None = None,
    previous: Mapping[str, Any] | None = None,
    owner_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Build one content-free, hash-linked owner-instruction envelope."""

    _require_id(task_id, "task id")
    _require_digest(owner_instruction_digest, "owner instruction digest")
    if terminal_event_append not in {"allow", "deny", "unchanged"}:
        raise TaskClosureError("task closure terminal event constraint rejected")
    if scope not in {"task", "phase"}:
        raise TaskClosureError("task closure instruction scope rejected")
    if scope == "task" and phase_id is not None:
        raise TaskClosureError("task-scoped instruction cannot name a phase")
    if scope == "phase":
        _require_id(phase_id, "phase id")

    prior: dict[str, Any] | None = None
    if previous is not None:
        prior = verify_task_instruction(
            previous,
            owner_key=TrustedKey(owner_signer.key_id, owner_signer.public_key),
        )
        if prior["task_id"] != task_id:
            raise TaskClosureError("task closure instruction task changed")
    sequence = 1 if prior is None else int(prior["sequence"]) + 1
    core = {
        "protocol": INSTRUCTION_PROTOCOL,
        "task_id": task_id,
        "sequence": sequence,
        "issued_at": issued_at,
        "authority_source": "owner-explicit",
        "owner_key_fingerprint": public_key_fingerprint(owner_signer.public_key),
        "owner_instruction_digest": owner_instruction_digest,
        "scope": scope,
        "phase_id": phase_id,
        "supersedes_digest": prior["instruction_digest"] if prior else None,
        "constraints": {"terminal_event_append": terminal_event_append},
        "mutation_boundary": dict(_MUTATION_BOUNDARY),
    }
    instruction_digest = digest_object(core, domain="task-instruction-envelope-v1")
    unsigned = {
        **core,
        "instruction_id": _identity(
            core,
            prefix="task-instruction:",
            domain="task-instruction-identity-v1",
        ),
        "instruction_digest": instruction_digest,
    }
    instruction = owner_signer.sign(unsigned)
    try:
        validate("task-instruction-envelope", instruction)
    except ValidationError as exc:
        raise TaskClosureError("task closure instruction schema rejected") from exc
    return instruction


def verify_task_instruction(
    instruction: Mapping[str, Any],
    *,
    owner_key: TrustedKey,
) -> dict[str, Any]:
    """Verify one instruction without treating it as a complete chain."""

    frozen = _freeze(instruction, "instruction")
    try:
        validate("task-instruction-envelope", frozen)
    except ValidationError as exc:
        raise TaskClosureError("task closure instruction schema rejected") from exc
    core = {
        key: value
        for key, value in frozen.items()
        if key not in {"instruction_id", "instruction_digest", "signature"}
    }
    expected_digest = digest_object(core, domain="task-instruction-envelope-v1")
    expected_id = _identity(
        core,
        prefix="task-instruction:",
        domain="task-instruction-identity-v1",
    )
    if (
        frozen["instruction_digest"] != expected_digest
        or frozen["instruction_id"] != expected_id
    ):
        raise TaskClosureError("task closure instruction identity mismatch")
    if (
        frozen["signature"]["key_id"] != owner_key.key_id
        or frozen["owner_key_fingerprint"]
        != public_key_fingerprint(owner_key.public_key)
        or not verify_signature(frozen, owner_key.public_key)
    ):
        raise TaskClosureError("task closure owner signature rejected")
    return frozen


def resolve_task_instructions(
    instructions: Sequence[Mapping[str, Any]],
    *,
    current_phase: str,
    owner_key: TrustedKey,
) -> dict[str, Any]:
    """Resolve global and phase-local append constraints deterministically."""

    _require_id(current_phase, "current phase")
    if not 1 <= len(instructions) <= 256:
        raise TaskClosureError("task closure instruction chain size rejected")
    verified = [
        verify_task_instruction(item, owner_key=owner_key)
        for item in instructions
    ]
    task_id = verified[0]["task_id"]
    task_permission = "deny"
    phase_permissions: dict[str, str] = {}
    previous: dict[str, Any] | None = None
    for instruction in verified:
        if instruction["task_id"] != task_id:
            raise TaskClosureError("task closure instruction chain crossed tasks")
        if previous is None:
            if instruction["sequence"] != 1 or instruction["supersedes_digest"] is not None:
                raise TaskClosureError("task closure instruction chain origin rejected")
        elif (
            instruction["sequence"] != previous["sequence"] + 1
            or instruction["supersedes_digest"] != previous["instruction_digest"]
        ):
            raise TaskClosureError("task closure instruction chain link rejected")
        permission = instruction["constraints"]["terminal_event_append"]
        if permission != "unchanged":
            if instruction["scope"] == "task":
                task_permission = permission
            else:
                phase_permissions[str(instruction["phase_id"])] = permission
        previous = instruction

    phase_permission = phase_permissions.get(current_phase, "inherit")
    effective = (
        "allow"
        if task_permission == "allow" and phase_permission != "deny"
        else "deny"
    )
    chain_digest = digest_object(
        [item["instruction_digest"] for item in verified],
        domain="task-instruction-chain-v1",
    )
    head = verified[-1]
    return {
        "task_id": task_id,
        "current_phase": current_phase,
        "instruction_head_digest": head["instruction_digest"],
        "instruction_head_sequence": head["sequence"],
        "instruction_chain_digest": chain_digest,
        "task_terminal_event_append": task_permission,
        "phase_terminal_event_append": phase_permission,
        "effective_terminal_event_append": effective,
        "expired_phase_ids": sorted(
            phase for phase in phase_permissions if phase != current_phase
        ),
    }


def build_event_uid_reconciliation(
    *,
    event_uid: str,
    request_sha256: str,
    observed_at: str,
    match_count: int,
    event_id: int | None,
    source_namespace: str = SEED_NAMESPACE,
) -> dict[str, Any]:
    """Bind a content-free exact-UID lookup; never read or emit an event body."""

    validate_seed_namespace(source_namespace)
    _require_event_uid(event_uid)
    _require_hex_digest(request_sha256, "request SHA-256")
    if isinstance(match_count, bool) or match_count not in {0, 1}:
        raise TaskClosureError("task closure reconciliation uniqueness rejected")
    if match_count == 1:
        if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 1:
            raise TaskClosureError("task closure reconciled event id rejected")
    elif event_id is not None:
        raise TaskClosureError("task closure absent reconciliation has an event id")
    core = {
        "protocol": RECONCILIATION_PROTOCOL,
        "source_namespace": source_namespace,
        "action_log_alias": ACTION_LOG_ALIAS,
        "event_uid": event_uid,
        "request_sha256": request_sha256,
        "observed_at": observed_at,
        "match_count": match_count,
        "event_id": event_id,
        "content_read": False,
        "event_body_emitted": False,
        "unique_index_expected": True,
        "production_authority": False,
    }
    receipt = {
        **core,
        "reconciliation_id": _identity(
            core,
            prefix="event-uid-reconciliation:",
            domain="action-log-event-uid-reconciliation-v1",
        ),
    }
    try:
        validate("action-log-event-uid-reconciliation", receipt)
    except ValidationError as exc:
        raise TaskClosureError("task closure reconciliation schema rejected") from exc
    return receipt


def verify_event_uid_reconciliation(
    reconciliation: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify one content-free reconciliation receipt and its unique result."""

    frozen = _freeze(reconciliation, "reconciliation")
    try:
        validate("action-log-event-uid-reconciliation", frozen)
    except ValidationError as exc:
        raise TaskClosureError("task closure reconciliation schema rejected") from exc
    core = {
        key: value for key, value in frozen.items() if key != "reconciliation_id"
    }
    expected = _identity(
        core,
        prefix="event-uid-reconciliation:",
        domain="action-log-event-uid-reconciliation-v1",
    )
    if frozen["reconciliation_id"] != expected:
        raise TaskClosureError("task closure reconciliation identity mismatch")
    if (frozen["match_count"] == 1) != (frozen["event_id"] is not None):
        raise TaskClosureError("task closure reconciliation semantics rejected")
    return frozen


def _validated_append_receipt(
    receipt: Mapping[str, Any],
    *,
    event_uid: str,
    request_sha256: str,
) -> tuple[str, int]:
    frozen = _freeze(receipt, "server append receipt")
    required = {
        "protocol",
        "source_label",
        "observed_utc",
        "event_uid",
        "event_id",
        "request_sha256",
        "outcome",
    }
    if set(frozen) != required or frozen.get("protocol") != client_APPEND_RECEIPT_PROTOCOL:
        raise TaskClosureError("task closure server append receipt rejected")
    if (
        frozen.get("event_uid") != event_uid
        or frozen.get("request_sha256") != request_sha256
        or frozen.get("outcome") not in {"created", "duplicate"}
    ):
        raise TaskClosureError("task closure server append binding mismatch")
    event_id = frozen.get("event_id")
    if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 1:
        raise TaskClosureError("task closure server event id rejected")
    return str(frozen["outcome"]), event_id


def build_append_attempt_receipt(
    *,
    event_uid: str,
    request_sha256: str,
    request_sent: bool,
    response_received: bool,
    append_receipt: Mapping[str, Any] | None = None,
    reconciliation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify one append attempt without ever replaying an uncertain POST."""

    _require_event_uid(event_uid)
    _require_hex_digest(request_sha256, "request SHA-256")
    if not isinstance(request_sent, bool) or not isinstance(response_received, bool):
        raise TaskClosureError("task closure append transport state rejected")
    if response_received and not request_sent:
        raise TaskClosureError("task closure response cannot precede request")
    if not request_sent and (append_receipt is not None or reconciliation is not None):
        raise TaskClosureError("task closure unstarted append has evidence")
    if append_receipt is not None and reconciliation is not None:
        raise TaskClosureError("task closure append has competing outcomes")

    server_outcome: str | None = None
    event_id: int | None = None
    frozen_reconciliation: dict[str, Any] | None = None
    if append_receipt is not None:
        if not request_sent or not response_received:
            raise TaskClosureError("task closure server receipt transport state rejected")
        server_outcome, event_id = _validated_append_receipt(
            append_receipt,
            event_uid=event_uid,
            request_sha256=request_sha256,
        )
        state = f"confirmed-{server_outcome}"
        next_step = "none"
    elif reconciliation is not None:
        if not request_sent:
            raise TaskClosureError("task closure reconciliation preceded append")
        frozen_reconciliation = verify_event_uid_reconciliation(reconciliation)
        if (
            frozen_reconciliation["event_uid"] != event_uid
            or frozen_reconciliation["request_sha256"] != request_sha256
        ):
            raise TaskClosureError("task closure reconciliation binding mismatch")
        if frozen_reconciliation["match_count"] == 1:
            state = "reconciled-created"
            event_id = int(frozen_reconciliation["event_id"])
            next_step = "none"
        else:
            state = "reconciled-absent"
            next_step = "owner-decision-required"
    elif request_sent:
        state = "unknown-outcome"
        next_step = "reconcile-by-event-uid"
    else:
        state = "not-started"
        next_step = "send-once"

    core = {
        "protocol": APPEND_ATTEMPT_PROTOCOL,
        "event_uid": event_uid,
        "request_sha256": request_sha256,
        "request_sent": request_sent,
        "response_received": response_received,
        "state": state,
        "server_outcome": server_outcome,
        "event_id": event_id,
        "reconciliation": frozen_reconciliation,
        "first_request_allowed": state == "not-started",
        "automatic_retry_allowed": False,
        "permitted_next_step": next_step,
        "privacy_boundary": {
            "event_body_read": False,
            "event_body_emitted": False,
            "secrets_emitted": False,
        },
        "authority_boundary": {
            "event_create_attempted": request_sent,
            "event_update": False,
            "event_delete": False,
            "event_import": False,
            "event_overwrite": False,
            "bulk_write": False,
            "production_authority": False,
        },
    }
    receipt = {
        **core,
        "attempt_id": _identity(
            core,
            prefix="action-log-append-attempt:",
            domain="action-log-append-attempt-v1",
        ),
    }
    try:
        validate("action-log-append-attempt-receipt", receipt)
    except ValidationError as exc:
        raise TaskClosureError("task closure append attempt schema rejected") from exc
    return receipt


def verify_append_attempt_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Verify an append state receipt without performing reconciliation or retry."""

    frozen = _freeze(receipt, "append attempt")
    try:
        validate("action-log-append-attempt-receipt", frozen)
    except ValidationError as exc:
        raise TaskClosureError("task closure append attempt schema rejected") from exc
    core = {key: value for key, value in frozen.items() if key != "attempt_id"}
    expected = _identity(
        core,
        prefix="action-log-append-attempt:",
        domain="action-log-append-attempt-v1",
    )
    if frozen["attempt_id"] != expected:
        raise TaskClosureError("task closure append attempt identity mismatch")
    if frozen["automatic_retry_allowed"] is not False:
        raise TaskClosureError("task closure append retry boundary rejected")
    if frozen["state"] in _CONFIRMED_APPEND_STATES:
        if frozen["event_id"] is None or frozen["permitted_next_step"] != "none":
            raise TaskClosureError("task closure confirmed append semantics rejected")
    elif frozen["event_id"] is not None:
        raise TaskClosureError("task closure unconfirmed append has event id")
    return frozen


def _append_request_sha256(arguments: Mapping[str, Any]) -> str:
    """Match the stable request hash produced by the client append facade."""

    tags = list(
        dict.fromkeys(
            [
                *(str(tag).strip() for tag in arguments["tags"]),
                "client-workstation",
                "medor",
                "remote-append",
                "task",
            ]
        )
    )
    normalized = {
        "event_uid": arguments["event_uid"],
        "kind": "task",
        "summary": str(arguments["summary"]).strip(),
        "details": arguments["details"],
        "tags": tags,
    }
    return hashlib.sha256(canonical_bytes(normalized)).hexdigest()


def build_task_closure_event(
    *,
    instructions: Sequence[Mapping[str, Any]],
    evidence_digest: str,
    completed_at: str,
    owner_key: TrustedKey,
) -> dict[str, Any]:
    """Build the exact content-free terminal event that may be sent once."""

    _require_digest(evidence_digest, "evidence digest")
    state = resolve_task_instructions(
        instructions,
        current_phase="closure",
        owner_key=owner_key,
    )
    if state["effective_terminal_event_append"] != "allow":
        raise TaskClosureError("task closure terminal append is not authorized")
    binding = {
        "protocol": CLOSURE_EVENT_PROTOCOL,
        "task_id": state["task_id"],
        "instruction_head_digest": state["instruction_head_digest"],
        "instruction_chain_digest": state["instruction_chain_digest"],
        "evidence_digest": evidence_digest,
        "completed_at": completed_at,
        "result": "complete",
    }
    event_uid = "client:task-closure:" + digest_object(
        binding, domain="task-closure-terminal-event-v1"
    ).split(":", 1)[1]
    arguments = {
        "event_uid": event_uid,
        "kind": "task",
        "summary": "Integrity task completed with a receipt-bound terminal event.",
        "details": {
            "closure": binding,
            "event_mutation": "append-only",
            "production_authority": False,
        },
        "tags": ["task-closure", "receipt-bound", "no-prod"],
    }
    return {
        "arguments": arguments,
        "request_sha256": _append_request_sha256(arguments),
        "instruction_state": state,
    }


def build_task_closure_receipt(
    *,
    instructions: Sequence[Mapping[str, Any]],
    evidence_digest: str,
    completed_at: str,
    append_attempt: Mapping[str, Any],
    owner_key: TrustedKey,
) -> dict[str, Any]:
    """Close a task only after its exact terminal append has a numeric event ID."""

    event = build_task_closure_event(
        instructions=instructions,
        evidence_digest=evidence_digest,
        completed_at=completed_at,
        owner_key=owner_key,
    )
    state = event["instruction_state"]
    attempt = verify_append_attempt_receipt(append_attempt)
    if attempt["state"] not in _CONFIRMED_APPEND_STATES:
        raise TaskClosureError("task completion requires a confirmed terminal event")
    if (
        attempt["event_uid"] != event["arguments"]["event_uid"]
        or attempt["request_sha256"] != event["request_sha256"]
    ):
        raise TaskClosureError("task closure terminal event binding mismatch")
    core = {
        "protocol": CLOSURE_RECEIPT_PROTOCOL,
        "task_id": state["task_id"],
        "status": "complete",
        "phase_id": "closure",
        "completed_at": completed_at,
        "evidence_digest": evidence_digest,
        "instruction_state": {
            key: state[key]
            for key in (
                "instruction_head_digest",
                "instruction_head_sequence",
                "instruction_chain_digest",
                "task_terminal_event_append",
                "phase_terminal_event_append",
                "effective_terminal_event_append",
                "expired_phase_ids",
            )
        },
        "terminal_event": {
            "event_uid": attempt["event_uid"],
            "event_id": attempt["event_id"],
            "append_state": attempt["state"],
            "request_sha256": attempt["request_sha256"],
            "append_attempt_id": attempt["attempt_id"],
        },
        "mutation_boundary": dict(_MUTATION_BOUNDARY),
        "authority_boundary": {
            "execution": False,
            "network": False,
            "production_authority": False,
            "route_authority": False,
        },
    }
    receipt = {
        **core,
        "closure_id": _identity(
            core,
            prefix="task-closure:",
            domain="task-closure-receipt-v1",
        ),
    }
    try:
        validate("task-closure-receipt", receipt)
    except ValidationError as exc:
        raise TaskClosureError("task closure receipt schema rejected") from exc
    return receipt


def verify_task_closure_receipt(
    receipt: Mapping[str, Any],
    *,
    instructions: Sequence[Mapping[str, Any]],
    append_attempt: Mapping[str, Any],
    owner_key: TrustedKey,
) -> dict[str, Any]:
    """Rebuild and verify a closure receipt against its instruction and append proof."""

    frozen = _freeze(receipt, "receipt")
    try:
        validate("task-closure-receipt", frozen)
    except ValidationError as exc:
        raise TaskClosureError("task closure receipt schema rejected") from exc
    expected = build_task_closure_receipt(
        instructions=instructions,
        evidence_digest=frozen["evidence_digest"],
        completed_at=frozen["completed_at"],
        append_attempt=append_attempt,
        owner_key=owner_key,
    )
    if frozen != expected:
        raise TaskClosureError("task closure receipt mismatch")
    return frozen
