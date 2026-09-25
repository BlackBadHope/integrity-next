"""Admit a snapshot-bound Action Log Mind companion into the LTS read loop.

This is the shared verify/bind path used by the Memory & Synapse facade.
It does not scan history and does not grant append or production authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from typing import Any

from jsonschema import ValidationError

from .context_budget import ContextBudget, build_context_capsule, resolve_context_budget
from .medor_architecture import _validate_mind_inputs
from .schemas import validate
from .turn_memory import (
    NO_EVENT_REASONS,
    TurnMemoryError,
    TurnMemoryStore,
    normalize_event_references,
)

BRIDGE_PROTOCOL = "integrity-client-memory-mcp/v3"
MIND_PROJECTION_PROTOCOL = "integrity.action-log.mind-projection/v1"
CONCEPT_PROTOCOL = "integrity.action-log.concept-recovery/v1"
COORDINATION_PROTOCOL = "integrity.action-log.coordination-projection/v1"
SEGMENT_COVERAGE_PROTOCOL = "integrity.action-log.segmented-query-coverage/v1"
ADMISSION_PROTOCOL = BRIDGE_PROTOCOL + "/mind-admission-receipt"
MEMORY_SOURCE = "canonical-seed-action-log"
_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_INTENT_RE = re.compile(r"^[a-f0-9]{12}$")


class MindAdmissionError(ValueError):
    """Raised when a Mind companion cannot enter the LTS read loop."""


def canonical_mind_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def verify_mind_companion(
    response: dict[str, Any],
    *,
    snapshot_event_id: int,
    snapshot_event_count: int,
) -> dict[str, Any]:
    """Fail closed unless the companion matches the admitted Seed snapshot."""

    snapshot = response.get("snapshot")
    receipt = response.get("receipt")
    concept_recovery = response.get("concept_recovery")
    coordination = response.get("coordination")
    if (
        not response.get("ok")
        or not isinstance(snapshot, dict)
        or not isinstance(receipt, dict)
        or not isinstance(concept_recovery, dict)
        or not isinstance(coordination, dict)
    ):
        raise MindAdmissionError("Action Log returned an invalid Mind projection")
    if (
        response.get("memory_source") != MEMORY_SOURCE
        or response.get("home_record_count") != 0
        or response.get("production_authority") is not False
    ):
        raise MindAdmissionError("Mind projection escaped the Seed authority boundary")
    if (
        snapshot.get("event_cursor") != snapshot_event_id
        or snapshot.get("event_count") != snapshot_event_count
    ):
        raise MindAdmissionError("Mind projection does not match the admitted Seed snapshot")
    projection_digest = response.get("projection_digest")
    if not isinstance(projection_digest, str) or not _DIGEST_RE.fullmatch(projection_digest):
        raise MindAdmissionError("Mind projection digest is invalid")
    receipt_core = {
        "protocol": receipt.get("protocol"),
        "event_count": receipt.get("event_count"),
        "event_cursor": receipt.get("event_cursor"),
        "intent_fingerprint": receipt.get("intent_fingerprint"),
        "projection_digest": receipt.get("projection_digest"),
        "home_record_count": receipt.get("home_record_count"),
        "production_authority": receipt.get("production_authority"),
    }
    segment_coverage = response.get("segment_coverage")
    receipt_segment_count = receipt.get("segment_count")
    receipt_segment_digest = receipt.get("segment_coverage_digest")
    segmented = any(
        value is not None
        for value in (
            segment_coverage,
            receipt_segment_count,
            receipt_segment_digest,
        )
    )
    if segmented:
        if (
            not isinstance(segment_coverage, dict)
            or segment_coverage.get("protocol") != SEGMENT_COVERAGE_PROTOCOL
            or isinstance(receipt_segment_count, bool)
            or not isinstance(receipt_segment_count, int)
            or receipt_segment_count < 1
            or segment_coverage.get("segment_count") != receipt_segment_count
            or segment_coverage.get("evaluated_segment_count") != receipt_segment_count
            or not isinstance(receipt_segment_digest, str)
            or _DIGEST_RE.fullmatch(receipt_segment_digest) is None
            or segment_coverage.get("coverage_digest") != receipt_segment_digest
        ):
            raise MindAdmissionError("segmented Mind projection receipt is invalid")
        coverage_core = dict(segment_coverage)
        coverage_digest = coverage_core.pop("coverage_digest", None)
        if coverage_digest != canonical_mind_digest(coverage_core):
            raise MindAdmissionError("segmented Mind projection receipt is invalid")
        receipt_core.update(
            {
                "segment_count": receipt_segment_count,
                "segment_coverage_digest": receipt_segment_digest,
            }
        )
    if (
        receipt.get("protocol") != MIND_PROJECTION_PROTOCOL
        or receipt.get("event_cursor") != snapshot_event_id
        or receipt.get("event_count") != snapshot_event_count
        or receipt.get("projection_digest") != projection_digest
        or receipt.get("home_record_count") != 0
        or receipt.get("production_authority") is not False
        or not isinstance(receipt.get("intent_fingerprint"), str)
        or _INTENT_RE.fullmatch(receipt["intent_fingerprint"]) is None
        or not isinstance(receipt.get("receipt_id"), str)
        or not _DIGEST_RE.fullmatch(receipt["receipt_id"])
        or receipt["receipt_id"] != canonical_mind_digest(receipt_core)
    ):
        raise MindAdmissionError("Mind projection receipt is invalid")
    recovery_core = dict(concept_recovery)
    recovery_digest = recovery_core.pop("recovery_digest", None)
    if (
        concept_recovery.get("protocol") != CONCEPT_PROTOCOL
        or concept_recovery.get("memory_source") != MEMORY_SOURCE
        or concept_recovery.get("intent_fingerprint") != receipt.get("intent_fingerprint")
        or recovery_digest != canonical_mind_digest(recovery_core)
    ):
        raise MindAdmissionError("concept recovery projection is invalid")
    coordination_core = dict(coordination)
    coordination_digest = coordination_core.pop("coordination_digest", None)
    if (
        coordination.get("protocol") != COORDINATION_PROTOCOL
        or coordination_digest != canonical_mind_digest(coordination_core)
        or not isinstance(coordination.get("stop_required"), bool)
        or not isinstance(coordination.get("owner_go_required"), bool)
        or not isinstance(coordination.get("production_scope_present"), bool)
    ):
        raise MindAdmissionError("coordination projection is invalid")
    return response


def build_companion_admission(
    response: dict[str, Any],
    *,
    snapshot_event_id: int,
    snapshot_event_count: int,
) -> dict[str, Any]:
    """Build the facade admission over an already-verified companion."""

    receipt = response["receipt"]
    concept_recovery = response["concept_recovery"]
    coordination = response["coordination"]
    admission_core = {
        "protocol": ADMISSION_PROTOCOL,
        "memory_source": MEMORY_SOURCE,
        "snapshot_event_id": snapshot_event_id,
        "snapshot_event_count": snapshot_event_count,
        "intent_fingerprint": receipt["intent_fingerprint"],
        "projection_digest": response["projection_digest"],
        "mind_receipt_id": receipt["receipt_id"],
        "concept_recovery_digest": concept_recovery["recovery_digest"],
        "coordination_digest": coordination["coordination_digest"],
        "coordination_stop_required": coordination["stop_required"],
        "home_record_count": 0,
        "production_authority": False,
    }
    return {**admission_core, "receipt_id": canonical_mind_digest(admission_core)}


def admit_mind_companion(
    response: dict[str, Any],
    *,
    snapshot_event_id: int,
    snapshot_event_count: int,
) -> dict[str, Any]:
    """Verify one companion and return the same envelope the facade Mind call uses."""

    verified = verify_mind_companion(
        response,
        snapshot_event_id=snapshot_event_id,
        snapshot_event_count=snapshot_event_count,
    )
    return {
        "mind": verified,
        "admission_receipt": build_companion_admission(
            verified,
            snapshot_event_id=snapshot_event_id,
            snapshot_event_count=snapshot_event_count,
        ),
    }


def bind_seed_catalog_to_admission(
    admission: dict[str, Any],
    *,
    seed_snapshot_id: str,
    seed_source_digest: str,
    seed_catalog_digest: str,
) -> dict[str, Any]:
    """Bind the exact catalog snapshot onto the companion admission and rehash."""

    bound = {
        **admission,
        "seed_snapshot_id": seed_snapshot_id,
        "seed_source_digest": seed_source_digest,
        "seed_catalog_digest": seed_catalog_digest,
    }
    bound.pop("receipt_id", None)
    bound["receipt_id"] = canonical_mind_digest(bound)
    try:
        validate("memory-synapse-mind-admission", bound)
    except ValidationError as exc:
        raise MindAdmissionError("Mind admission receipt schema is invalid") from exc
    return bound


def present_lts_read_loop(
    companion_mind: dict[str, Any],
    *,
    snapshot_event_id: int,
    snapshot_event_count: int,
    seed_snapshot_id: str,
    seed_source_digest: str,
    seed_catalog_digest: str,
    intent: str,
    budget: dict[str, Any] | None = None,
    policy: ContextBudget | None = None,
) -> dict[str, Any]:
    """Close the LTS read loop: companion → catalog bind → adaptive capsule.

    The complete companion stays in ``source_mind`` for architecture custody.
    The model-facing object is the digest-bound context capsule only.
    """

    admitted = admit_mind_companion(
        companion_mind,
        snapshot_event_id=snapshot_event_id,
        snapshot_event_count=snapshot_event_count,
    )
    admission = bind_seed_catalog_to_admission(
        admitted["admission_receipt"],
        seed_snapshot_id=seed_snapshot_id,
        seed_source_digest=seed_source_digest,
        seed_catalog_digest=seed_catalog_digest,
    )
    _validate_mind_inputs(admission, admitted["mind"])
    resolved = policy or resolve_context_budget(intent, budget=budget)
    if resolved.mode != "adaptive":
        return {
            "mind": admitted["mind"],
            "source_mind": admitted["mind"],
            "admission_receipt": admission,
            "selection_receipt": {},
            "presentation_mode": resolved.mode,
            "production_authority": False,
        }
    capsule, selection = build_context_capsule(admitted["mind"], admission, resolved)
    return {
        "mind": capsule,
        "source_mind": admitted["mind"],
        "admission_receipt": admission,
        "selection_receipt": selection,
        "presentation_mode": "adaptive",
        "production_authority": False,
    }


def _witness_event_references(
    events: Iterable[Mapping[str, Any]],
    witness: Any,
) -> list[dict[str, Any]]:
    if witness is None or not hasattr(witness, "observe"):
        raise MindAdmissionError("canonical event witness is unavailable")
    verified: list[dict[str, Any]] = []
    for item in events:
        event_uid = item.get("event_uid")
        event_id = item.get("event_id")
        request_sha256 = item.get("request_sha256")
        if not isinstance(event_uid, str) or not isinstance(request_sha256, str):
            raise MindAdmissionError("event reference is invalid")
        observed = witness.observe(event_uid=event_uid, request_sha256=request_sha256)
        if not isinstance(observed, dict) or observed.get("status") != "exact":
            raise MindAdmissionError("terminal event reference is not canonically witnessed")
        if observed.get("event_id") != event_id:
            raise MindAdmissionError("terminal event reference is not canonically witnessed")
        verified.append(
            {
                "event_uid": event_uid,
                "event_id": event_id,
                "request_sha256": request_sha256,
            }
        )
    return normalize_event_references(verified)


def complete_lts_turn(
    store: TurnMemoryStore,
    *,
    machine_id: str,
    thread_id: str,
    turn_id: str,
    prompt_sha256: str,
    companion_mind: dict[str, Any],
    snapshot_event_id: int,
    snapshot_event_count: int,
    seed_snapshot_id: str,
    seed_source_digest: str,
    seed_catalog_digest: str,
    intent: str,
    budget: dict[str, Any] | None = None,
    events: Iterable[Mapping[str, Any]] | None = None,
    no_event_reason: str | None = None,
    witness: Any | None = None,
    opened_at: str | None = None,
    closed_at: str | None = None,
) -> dict[str, Any]:
    """Close one LTS turn: register, admit the capsule, then terminal coverage.

    Events require a canonical witness. Missing close stays unresolved and is
    never rewritten into no-event.
    """

    opened = store.open_turn(
        machine_id=machine_id,
        thread_id=thread_id,
        turn_id=turn_id,
        prompt_sha256=prompt_sha256,
        opened_at=opened_at,
    )
    presented = present_lts_read_loop(
        companion_mind,
        snapshot_event_id=snapshot_event_id,
        snapshot_event_count=snapshot_event_count,
        seed_snapshot_id=seed_snapshot_id,
        seed_source_digest=seed_source_digest,
        seed_catalog_digest=seed_catalog_digest,
        intent=intent,
        budget=budget,
    )
    registration_id = opened["receipt"]["receipt_id"]
    if events is not None:
        if no_event_reason is not None:
            raise MindAdmissionError("events outcome cannot contain a no-event reason")
        try:
            verified = _witness_event_references(events, witness)
            closed = store.close_turn(
                registration_id=registration_id,
                outcome="events",
                events=verified,
                closed_at=closed_at,
            )
        except TurnMemoryError as exc:
            raise MindAdmissionError(str(exc)) from exc
    elif no_event_reason in NO_EVENT_REASONS:
        try:
            closed = store.close_turn(
                registration_id=registration_id,
                outcome="no-event",
                no_event_reason=no_event_reason,
                closed_at=closed_at,
            )
        except TurnMemoryError as exc:
            raise MindAdmissionError(str(exc)) from exc
    else:
        raise MindAdmissionError("turn requires events or one no-event reason")
    coverage = store.coverage(machine_id=machine_id, thread_id=thread_id)
    if int(coverage["counts"]["unresolved"]) != 0:
        raise MindAdmissionError("turn coverage remains unresolved")
    return {
        "registration": opened,
        "presentation": presented,
        "terminal": closed,
        "coverage": coverage,
        "production_authority": False,
    }
