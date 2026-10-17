"""Per-user action logging utilities.

Action logs are content-free, deterministic receipts for operational events such as
imports and rebuilds. The module stores JSON lines payloads in user-scoped
directories for deterministic replay and easy inspection.
"""

from __future__ import annotations

import datetime
import base64
import json
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .candidates import validate_candidate_bundle, validate_candidate_receipt
from .review import validate_review_manifest
from .json_integrity import loads_json_strict
from .state_lock import corpus_state_lock

ACTION_LOG_SCHEMA_VERSION = "chronicle-action-log-entry/1"
ACTION_LOG_EVENT_IMPORT_DRY_RUN_COMPLETED = "import_dry_run_completed"
ACTION_LOG_EVENT_IMPORT_DRY_RUN_REJECTED = "import_dry_run_rejected"
ACTION_LOG_EVENT_IMPORT_COMPLETED = "import_completed"
ACTION_LOG_EVENT_IMPORT_FAILED = "import_failed"
ACTION_LOG_EVENT_FORGET_COMPLETED = "forget_completed"
ACTION_LOG_EVENT_FORGET_FAILED = "forget_failed"
ACTION_LOG_EVENT_CANDIDATE_PROJECTION_RECEIVED = "candidate_projection_received"
ACTION_LOG_EVENT_CANDIDATE_REVIEWED = "candidate_reviewed"
ACTION_LOG_EVENT_CORPUS_RECALL_COMPLETED = "corpus_recall_completed"
ACTION_LOG_FILENAME = "action-log.jsonl"
ACTION_LOG_REVIEWED_PROJECTION_SCHEMA_VERSION = "chronicle-reviewed-action-log/1"
_WINDOWS_RESERVED_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}
_MAX_USER_ID_UTF8_BYTES = 150
_FORGET_OPERATION_PREFIX = "integrity-home-forget-"
_FORGET_SELECTOR_SCHEMA_VERSION = "integrity-home-forget-selector-digest/1"
_FORGET_COMPLETED_EVENT_FIELDS = frozenset(
    {
        "schema_version",
        "event_id",
        "event_type",
        "event_utc",
        "command",
        "status",
        "status_reason",
        "user_id",
        "operation_id",
        "source_id_sha256",
        "source_projection_sha256_before",
        "source_projection_sha256_after",
        "canonical_projection_path",
        "removed_claim_selector_sha256s",
        "removed_conversation_selector_sha256s",
        "reason",
        "details",
        "entry_sha256",
    }
)
_REVIEWED_CANDIDATE_CONTENT_FIELDS = frozenset(
    {
        "memory_text",
        "memory_text_origin",
        "claim_type",
        "temporal_state",
        "created_at",
        "conversation_id",
        "is_user_assertion",
        "evidence_kind",
        "source_locator",
    }
)


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def _coerce_user_id(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("user_id must be a string")
    if not value.strip():
        raise ValueError("user_id must be a non-empty string")
    try:
        raw = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as err:
        raise ValueError("user_id must be valid UTF-8 text") from err
    if len(raw) > _MAX_USER_ID_UTF8_BYTES:
        raise ValueError(
            f"user_id exceeds {_MAX_USER_ID_UTF8_BYTES} UTF-8 bytes"
        )

    # Preserve the common readable lowercase form. All other values enter a
    # disjoint, reversible Base32 namespace. This avoids the old a/b -> a_b
    # collision, Windows case-folding collisions, reserved device names, and
    # trailing-dot/space hazards without storing the raw id in the path.
    readable = (
        bool(value)
        and value == value.casefold()
        and value[0].isalnum()
        and all(char.isascii() and (char.isalnum() or char in {"_", "-", "."}) for char in value)
        and not value.endswith((".", " "))
        and value.casefold() not in _WINDOWS_RESERVED_NAMES
    )
    if readable:
        return value
    encoded = base64.b32encode(raw).decode("ascii").rstrip("=").lower()
    return f"~{encoded}"


def action_log_path(action_log_root: str, user_id: str) -> Path:
    safe_user_id = _coerce_user_id(user_id)
    return Path(action_log_root) / safe_user_id / ACTION_LOG_FILENAME


def _serialize_event(event: Dict[str, Any]) -> str:
    return json.dumps(event, sort_keys=True, separators=(",", ":"))


def _append_json_lines(path: Path, event: Dict[str, Any]) -> str:
    # Legacy import/forget receipts use the same strict, collision-aware,
    # atomic append path as reviewed candidates. A poisoned existing JSONL must
    # never be copied forward merely because this event type predates review.
    _append_json_lines_idempotent_transactional(path, [event])
    return str(path)


def _append_json_line_idempotent(path: Path, event: Dict[str, Any]) -> bool:
    """Append once by event_id, rejecting same-id/different-body collisions."""

    return bool(_append_json_lines_idempotent_transactional(path, [event]))


def _load_existing_action_log_locked(
    path: Path,
) -> tuple[List[str], Dict[str, str], List[Dict[str, Any]]]:
    """Read and strictly validate one Action Log while its writer lock is held."""

    existing_bytes = path.read_bytes() if path.exists() else b""
    try:
        existing_text = existing_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as err:
        raise ValueError(f"action log is not valid UTF-8: {path}") from err
    existing_lines = [line for line in existing_text.splitlines() if line.strip()]
    existing_by_id: Dict[str, str] = {}
    existing_events: List[Dict[str, Any]] = []
    for line in existing_lines:
        try:
            existing = loads_json_strict(line)
        except json.JSONDecodeError as err:
            raise ValueError(f"action log contains malformed JSON: {path}") from err
        if not isinstance(existing, dict):
            raise ValueError(f"action log contains non-object entry: {path}")
        event_id = existing.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            raise ValueError(f"action log entry is missing event_id: {path}")
        serialized = _serialize_event(existing)
        previous = existing_by_id.get(event_id)
        if previous is not None and previous != serialized:
            raise ValueError(f"action log contains event_id collision: {event_id}")
        existing_by_id[event_id] = serialized
        existing_events.append(existing)
    return existing_lines, existing_by_id, existing_events


def _append_json_lines_idempotent_transactional(
    path: Path,
    events: Sequence[Dict[str, Any]],
) -> int:
    """Serialize the complete Action Log transaction across threads/processes."""

    with corpus_state_lock(str(path)):
        return _append_json_lines_idempotent_transactional_locked(path, events)


def _append_json_lines_idempotent_transactional_locked(
    path: Path,
    events: Sequence[Dict[str, Any]],
) -> int:
    """Validate a complete event batch, then publish it with one replace.

    No event becomes visible until every same-id collision and every existing
    JSON line has been checked. A failed write/replace removes the temporary
    file and leaves the previous Action Log byte-for-byte untouched.
    """

    prepared: List[tuple[str, str]] = []
    seen_new: Dict[str, str] = {}
    for event in events:
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            raise ValueError("idempotent action log event requires event_id")
        serialized = _serialize_event(event)
        previous = seen_new.get(event_id)
        if previous is not None:
            if previous != serialized:
                raise ValueError(f"action log event_id collision in batch: {event_id}")
            continue
        seen_new[event_id] = serialized
        prepared.append((event_id, serialized))

    existing_lines, existing_by_id, _ = _load_existing_action_log_locked(path)

    additions: List[str] = []
    for event_id, serialized in prepared:
        existing = existing_by_id.get(event_id)
        if existing is not None:
            if existing != serialized:
                raise ValueError(f"action log event_id collision: {event_id}")
            continue
        additions.append(serialized)
    if not additions:
        return 0

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        prefix="chronicle-action-log-", suffix=".tmp", dir=path.parent
    )
    tmp = Path(tmp_path)
    try:
        with open(fd, "w", encoding="utf-8", newline="\n") as fp:
            fp.write("\n".join(existing_lines + additions))
            fp.write("\n")
            fp.flush()
        tmp.replace(path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return len(additions)


def _entry_digest(event: Mapping[str, Any]) -> str:
    payload = dict(event)
    payload.pop("entry_sha256", None)
    return sha256(_serialize_event(payload).encode("utf-8")).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_forget_operation_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(_FORGET_OPERATION_PREFIX)
        and len(value) == len(_FORGET_OPERATION_PREFIX) + 24
        and all(
            character in "0123456789abcdef"
            for character in value[len(_FORGET_OPERATION_PREFIX) :]
        )
    )


def _forget_source_id_sha256(source_id: str) -> str:
    material = {
        "schema_version": _FORGET_SELECTOR_SCHEMA_VERSION,
        "selector_type": "source_id",
        "value": source_id,
    }
    return sha256(_serialize_event(material).encode("utf-8")).hexdigest()


def _forget_selector_sha256(
    source_id: str,
    *,
    selector_type: str,
    identifier: str,
) -> str:
    if selector_type not in {"claim_id", "conversation_id"}:
        raise ValueError(f"unsupported forget selector type: {selector_type}")
    material = {
        "schema_version": _FORGET_SELECTOR_SCHEMA_VERSION,
        "source_id": source_id,
        "selector_type": selector_type,
        "value": identifier,
    }
    return sha256(_serialize_event(material).encode("utf-8")).hexdigest()


def _derive_forget_operation_id(
    *,
    source_id: str,
    source_projection_sha256_before: str,
    source_projection_sha256_after: str,
    claim_ids: Sequence[str],
    conversation_ids: Sequence[str],
) -> str:
    # This is intentionally byte-for-byte compatible with forget.apply_forget.
    operation_material = {
        "source_id": source_id,
        "source_projection_sha256_before": source_projection_sha256_before,
        "source_projection_sha256_after": source_projection_sha256_after,
        "forget_claim_ids": list(claim_ids),
        "forget_conversation_ids": list(conversation_ids),
    }
    return _FORGET_OPERATION_PREFIX + sha256(
        json.dumps(
            operation_material,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()[:24]


def _forget_event_id(event: Mapping[str, Any]) -> str:
    operation_id = event.get("operation_id")
    if (
        event.get("event_type") == ACTION_LOG_EVENT_FORGET_COMPLETED
        and _is_forget_operation_id(operation_id)
    ):
        stable_identity = {
            "event_type": ACTION_LOG_EVENT_FORGET_COMPLETED,
            "operation_id": operation_id,
        }
        return sha256(
            _serialize_event(stable_identity).encode("utf-8")
        ).hexdigest()[:24]
    payload = dict(event)
    payload.pop("entry_sha256", None)
    payload["event_id"] = ""
    return sha256(_serialize_event(payload).encode("utf-8")).hexdigest()[:24]


def _validate_stored_sha256_list(
    event: Mapping[str, Any],
    field_name: str,
    *,
    line_number: int,
) -> list[str]:
    value = event.get(field_name)
    if not isinstance(value, list):
        raise ValueError(
            f"successful forget has invalid {field_name} at line {line_number}"
        )
    digests: list[str] = []
    for item in value:
        if not _is_sha256(item):
            raise ValueError(
                f"successful forget has invalid {field_name} at line {line_number}"
            )
        digests.append(item)
    canonical = sorted(set(digests))
    if digests != canonical:
        raise ValueError(
            f"successful forget has non-canonical {field_name} at line {line_number}"
        )
    return canonical


def _validate_successful_forget_event(
    event: Mapping[str, Any],
    *,
    safe_user: str,
    line_number: int,
) -> tuple[str, list[str], list[str]]:
    if set(event) != _FORGET_COMPLETED_EVENT_FIELDS:
        raise ValueError(
            f"successful forget has invalid fields at line {line_number}"
        )
    if event.get("schema_version") != ACTION_LOG_SCHEMA_VERSION:
        raise ValueError(
            f"successful forget has invalid schema at line {line_number}"
        )
    if event.get("event_type") != ACTION_LOG_EVENT_FORGET_COMPLETED:
        raise ValueError(
            f"successful forget has invalid event type at line {line_number}"
        )
    if event.get("command") != "forget" or event.get("status") != "ok":
        raise ValueError(
            f"successful forget has invalid status at line {line_number}"
        )
    if event.get("status_reason") is not None:
        raise ValueError(
            f"successful forget has status reason at line {line_number}"
        )
    if event.get("user_id") != safe_user:
        raise ValueError(f"successful forget user mismatch at line {line_number}")
    event_utc = event.get("event_utc")
    if not isinstance(event_utc, str) or not event_utc:
        raise ValueError(
            f"successful forget has invalid timestamp at line {line_number}"
        )
    operation_id = event.get("operation_id")
    if not _is_forget_operation_id(operation_id):
        raise ValueError(
            f"successful forget has invalid operation_id at line {line_number}"
        )
    source_id_sha256 = event.get("source_id_sha256")
    if not _is_sha256(source_id_sha256):
        raise ValueError(
            f"successful forget missing source_id_sha256 at line {line_number}"
        )
    for field_name in (
        "source_projection_sha256_before",
        "source_projection_sha256_after",
    ):
        value = event.get(field_name)
        if not _is_sha256(value):
            raise ValueError(
                f"successful forget has invalid {field_name} at line {line_number}"
            )
    if (
        event.get("canonical_projection_path") is not None
        or event.get("reason") != ""
        or event.get("details") != {}
    ):
        raise ValueError(
            f"successful forget is not content-free at line {line_number}"
        )
    if event.get("entry_sha256") != _entry_digest(event):
        raise ValueError(f"successful forget digest mismatch at line {line_number}")
    if event.get("event_id") != _forget_event_id(event):
        raise ValueError(f"successful forget event_id mismatch at line {line_number}")

    removed_claim_selector_sha256s = _validate_stored_sha256_list(
        event, "removed_claim_selector_sha256s", line_number=line_number
    )
    removed_conversation_selector_sha256s = _validate_stored_sha256_list(
        event, "removed_conversation_selector_sha256s", line_number=line_number
    )
    if not removed_claim_selector_sha256s and not removed_conversation_selector_sha256s:
        raise ValueError(
            f"successful forget has no selectors at line {line_number}"
        )
    return (
        str(source_id_sha256),
        removed_claim_selector_sha256s,
        removed_conversation_selector_sha256s,
    )


def _successful_forget_semantic_payload(event: Mapping[str, Any]) -> Dict[str, Any]:
    payload = dict(event)
    for field_name in ("event_id", "event_utc", "entry_sha256"):
        payload.pop(field_name, None)
    return payload


def _append_successful_forget_event(
    path: Path,
    event: Dict[str, Any],
    *,
    safe_user: str,
) -> Dict[str, Any]:
    """Append once by stable operation_id and return the original on retry."""

    _validate_successful_forget_event(event, safe_user=safe_user, line_number=0)
    operation_id = str(event["operation_id"])
    with corpus_state_lock(str(path)):
        _, _, existing_events = _load_existing_action_log_locked(path)
        matches = [
            (line_number, existing)
            for line_number, existing in enumerate(existing_events, 1)
            if existing.get("event_type") == ACTION_LOG_EVENT_FORGET_COMPLETED
            and existing.get("operation_id") == operation_id
        ]
        if len(matches) > 1:
            raise ValueError(
                f"action log contains duplicate forget operation_id: {operation_id}"
            )
        if matches:
            line_number, existing = matches[0]
            _validate_successful_forget_event(
                existing,
                safe_user=safe_user,
                line_number=line_number,
            )
            if _successful_forget_semantic_payload(
                existing
            ) != _successful_forget_semantic_payload(event):
                raise ValueError(
                    f"action log forget operation_id collision: {operation_id}"
                )
            return dict(existing)
        _append_json_lines_idempotent_transactional_locked(path, [event])
    return event


def _validate_reviewed_candidate_event(
    event: Mapping[str, Any],
    *,
    safe_user: str,
    line_number: int,
) -> tuple[str, str, int]:
    if event.get("schema_version") != ACTION_LOG_SCHEMA_VERSION:
        raise ValueError(
            f"reviewed candidate has invalid schema at line {line_number}"
        )
    if event.get("entry_sha256") != _entry_digest(event):
        raise ValueError(
            f"reviewed Action Log entry digest mismatch at line {line_number}"
        )
    if event.get("user_id") != safe_user:
        raise ValueError(f"reviewed candidate user mismatch at line {line_number}")
    if event.get("command") != "chronicle-action-log-sync":
        raise ValueError(
            f"reviewed candidate has invalid command at line {line_number}"
        )
    approved = event.get("review_approved")
    if not isinstance(approved, bool) or event.get("authoritative") is not False:
        raise ValueError(
            f"invalid reviewed candidate flags at line {line_number}"
        )

    required_strings = (
        "event_id",
        "event_utc",
        "source_id",
        "corpus_id",
        "index_generation",
        "source_projection_sha256",
        "candidate_bundle_sha256",
        "candidate_id",
        "candidate_sha256",
        "claim_id",
        "review_decision_id",
        "review_decision_sha256",
        "review_action",
    )
    for field_name in required_strings:
        value = event.get(field_name)
        if not isinstance(value, str) or not value:
            raise ValueError(
                f"reviewed candidate missing {field_name} at line {line_number}"
            )
    source_id = str(event["source_id"])
    candidate_id = str(event["candidate_id"])
    if event.get("claim_id") != candidate_id:
        raise ValueError(
            f"reviewed candidate identity mismatch at line {line_number}"
        )
    if (
        event.get("corpus_id") != source_id
        or event.get("index_generation")
        != event.get("source_projection_sha256")
    ):
        raise ValueError(
            f"reviewed candidate source binding mismatch at line {line_number}"
        )
    revision = event.get("review_revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise ValueError(
            f"reviewed candidate has invalid revision at line {line_number}"
        )
    expected_event_id = f"chronicle-reviewed-{str(event['review_decision_sha256'])[:24]}"
    if event.get("event_id") != expected_event_id:
        raise ValueError(
            f"reviewed candidate event_id mismatch at line {line_number}"
        )

    if approved:
        if event.get("status") != "review_approved_candidate" or event.get(
            "review_action"
        ) not in {"accept", "edit"}:
            raise ValueError(
                f"reviewed candidate approval mismatch at line {line_number}"
            )
        memory_text = event.get("memory_text")
        conversation_id = event.get("conversation_id")
        locator = event.get("source_locator")
        if not isinstance(memory_text, str) or not memory_text.strip():
            raise ValueError(
                f"reviewed candidate missing memory text at line {line_number}"
            )
        if not isinstance(conversation_id, str) or not conversation_id:
            raise ValueError(
                f"reviewed candidate missing conversation_id at line {line_number}"
            )
        if not isinstance(locator, dict):
            raise ValueError(
                f"reviewed candidate missing source locator at line {line_number}"
            )
        if (
            locator.get("source_id") != source_id
            or locator.get("source_projection_sha256")
            != event.get("source_projection_sha256")
            or locator.get("conversation_id") != conversation_id
        ):
            raise ValueError(
                f"reviewed candidate locator binding mismatch at line {line_number}"
            )
        if not isinstance(event.get("is_user_assertion"), bool):
            raise ValueError(
                f"reviewed candidate has invalid assertion flag at line {line_number}"
            )
    else:
        if event.get("status") != "review_revoked_candidate" or event.get(
            "review_action"
        ) in {"accept", "edit"}:
            raise ValueError(
                f"reviewed candidate revocation mismatch at line {line_number}"
            )
        if any(field_name in event for field_name in _REVIEWED_CANDIDATE_CONTENT_FIELDS):
            raise ValueError(
                f"revoked reviewed candidate contains candidate content at line {line_number}"
            )
    return source_id, candidate_id, revision


def _coerce_optional_string(value: Optional[str], field_name: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string when provided")
    return value


def _coerce_event_type(event_type: str) -> str:
    allowed = {
        ACTION_LOG_EVENT_IMPORT_DRY_RUN_COMPLETED,
        ACTION_LOG_EVENT_IMPORT_DRY_RUN_REJECTED,
        ACTION_LOG_EVENT_IMPORT_COMPLETED,
        ACTION_LOG_EVENT_IMPORT_FAILED,
        ACTION_LOG_EVENT_FORGET_COMPLETED,
        ACTION_LOG_EVENT_FORGET_FAILED,
        ACTION_LOG_EVENT_CANDIDATE_PROJECTION_RECEIVED,
        ACTION_LOG_EVENT_CANDIDATE_REVIEWED,
        ACTION_LOG_EVENT_CORPUS_RECALL_COMPLETED,
    }
    if event_type not in allowed:
        raise ValueError(f"unsupported action log event type: {event_type}")
    return event_type


def _coerce_payload(value: Optional[Mapping[str, Any]], field_name: str) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a dict")
    return dict(value)


def _coerce_identifier_list(value: Optional[Sequence[str]], field_name: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise TypeError(f"{field_name} must be a list or tuple of strings")
    identifiers = []
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"{field_name} must be a list or tuple of strings")
        candidate = item.strip()
        if not candidate:
            continue
        identifiers.append(candidate)
    return sorted(set(identifiers))


def append_forget_action_event(
    action_log_root: str,
    user_id: str,
    *,
    event_type: str,
    source_id: str,
    source_projection_sha256_before: Optional[str],
    source_projection_sha256_after: Optional[str],
    canonical_projection_path: Optional[str] = None,
    status: str,
    status_reason: Optional[str] = None,
    removed_claim_ids: Optional[Sequence[str]] = None,
    removed_conversation_ids: Optional[Sequence[str]] = None,
    reason: Optional[str] = None,
    extra: Optional[Mapping[str, Any]] = None,
    operation_id: Optional[str] = None,
) -> Dict[str, Any]:
    safe_user = _coerce_user_id(user_id)
    event_type = _coerce_event_type(event_type)

    if event_type not in {
        ACTION_LOG_EVENT_FORGET_COMPLETED,
        ACTION_LOG_EVENT_FORGET_FAILED,
    }:
        raise ValueError("append_forget_action_event requires a forget event type")
    if event_type == ACTION_LOG_EVENT_FORGET_COMPLETED:
        if status != "ok":
            raise ValueError("forget_completed event requires status=ok")
    elif status != "failed":
        raise ValueError("forget_failed event requires status=failed")

    if not isinstance(source_id, str) or not source_id:
        raise ValueError("source_id must be a non-empty string")
    if status_reason is not None and not isinstance(status_reason, str):
        raise TypeError("status_reason must be a string when provided")
    if reason is not None and not isinstance(reason, str):
        raise TypeError("reason must be a string when provided")
    _coerce_optional_string(canonical_projection_path, "canonical_projection_path")
    before_sha = _coerce_optional_string(
        source_projection_sha256_before, "source_projection_sha256_before"
    )
    after_sha = _coerce_optional_string(
        source_projection_sha256_after, "source_projection_sha256_after"
    )
    for field_name, value in (
        ("source_projection_sha256_before", before_sha),
        ("source_projection_sha256_after", after_sha),
    ):
        if value is not None and not _is_sha256(value):
            raise ValueError(f"{field_name} must be a lowercase SHA-256")
        if event_type == ACTION_LOG_EVENT_FORGET_COMPLETED and value is None:
            raise ValueError(
                f"forget_completed event requires a lowercase SHA-256 {field_name}"
            )

    claim_ids = _coerce_identifier_list(removed_claim_ids, "removed_claim_ids")
    conversation_ids = _coerce_identifier_list(
        removed_conversation_ids, "removed_conversation_ids"
    )
    if (
        event_type == ACTION_LOG_EVENT_FORGET_COMPLETED
        and not claim_ids
        and not conversation_ids
    ):
        raise ValueError("forget_completed event requires at least one selector")
    payload = _coerce_payload(extra, "extra")
    payload_operation_id = payload.get("operation_id")
    if operation_id is None and payload_operation_id is not None:
        if not isinstance(payload_operation_id, str):
            raise TypeError("operation_id must be a string when provided")
        operation_id = payload_operation_id

    if event_type == ACTION_LOG_EVENT_FORGET_COMPLETED:
        assert before_sha is not None and after_sha is not None
        derived_operation_id = _derive_forget_operation_id(
            source_id=source_id,
            source_projection_sha256_before=before_sha,
            source_projection_sha256_after=after_sha,
            claim_ids=claim_ids,
            conversation_ids=conversation_ids,
        )
        if operation_id is None:
            operation_id = derived_operation_id
        elif operation_id != derived_operation_id:
            raise ValueError("operation_id does not match the forget selectors")
    elif operation_id is not None and not _is_forget_operation_id(operation_id):
        raise ValueError("operation_id must be a stable Integrity Home forget id")

    safe_details: Dict[str, Any] = {}
    if event_type == ACTION_LOG_EVENT_FORGET_FAILED:
        for field_name in ("error_sha256", "reason_sha256"):
            value = payload.get(field_name)
            if value is not None:
                if not _is_sha256(value):
                    raise ValueError(f"{field_name} must be a lowercase SHA-256")
                safe_details[field_name] = value
        if status_reason:
            safe_details["status_reason_sha256"] = sha256(
                status_reason.encode("utf-8")
            ).hexdigest()
        if reason:
            safe_details["reason_sha256"] = sha256(reason.encode("utf-8")).hexdigest()

    claim_selector_sha256s = sorted(
        {
            _forget_selector_sha256(
                source_id,
                selector_type="claim_id",
                identifier=identifier,
            )
            for identifier in claim_ids
        }
    )
    conversation_selector_sha256s = sorted(
        {
            _forget_selector_sha256(
                source_id,
                selector_type="conversation_id",
                identifier=identifier,
            )
            for identifier in conversation_ids
        }
    )
    event = {
        "schema_version": ACTION_LOG_SCHEMA_VERSION,
        "event_id": "",
        "event_type": event_type,
        "event_utc": _utc_now(),
        "command": "forget",
        "status": status,
        "status_reason": None
        if event_type == ACTION_LOG_EVENT_FORGET_COMPLETED
        else "failed",
        "user_id": safe_user,
        "operation_id": operation_id,
        "source_id_sha256": _forget_source_id_sha256(source_id),
        "source_projection_sha256_before": before_sha,
        "source_projection_sha256_after": after_sha,
        "canonical_projection_path": None,
        "removed_claim_selector_sha256s": claim_selector_sha256s,
        "removed_conversation_selector_sha256s": conversation_selector_sha256s,
        "reason": "",
        "details": safe_details,
    }
    event["event_id"] = _forget_event_id(event)
    event["entry_sha256"] = _entry_digest(event)

    target = action_log_path(action_log_root, user_id)
    if event_type == ACTION_LOG_EVENT_FORGET_COMPLETED:
        return _append_successful_forget_event(target, event, safe_user=safe_user)
    _append_json_lines(target, event)
    return event


def append_import_action_event(
    action_log_root: str,
    user_id: str,
    *,
    event_type: str,
    source_id: str,
    source_sha256: str,
    archive_name: str,
    dry_run: bool,
    provider_guess: str,
    status: str,
    status_reason: Optional[str] = None,
    provider_hint: Optional[str] = None,
    source_manifest_recorded: bool = False,
    source_manifest_path: Optional[str] = None,
    canonical_projection_path: Optional[str] = None,
    canonical_projection_sha256: Optional[str] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    safe_user = _coerce_user_id(user_id)
    event_type = _coerce_event_type(event_type)

    if not isinstance(source_id, str) or not source_id:
        raise ValueError("source_id must be a non-empty string")
    if not isinstance(source_sha256, str) or not source_sha256:
        raise ValueError("source_sha256 must be a non-empty string")
    if not isinstance(archive_name, str) or not archive_name:
        raise ValueError("archive_name must be a non-empty string")
    if not isinstance(status, str) or not status:
        raise ValueError("status must be a non-empty string")
    if not isinstance(provider_guess, str) or not provider_guess:
        raise ValueError("provider_guess must be a non-empty string")
    if not isinstance(dry_run, bool):
        raise TypeError("dry_run must be a bool")

    payload = _coerce_payload(extra, "extra")
    event = {
        "schema_version": ACTION_LOG_SCHEMA_VERSION,
        "event_id": "",
        "event_type": event_type,
        "event_utc": _utc_now(),
        "command": "import",
        "status": status,
        "status_reason": status_reason,
        "user_id": safe_user,
        "source_id": source_id,
        "source_sha256": source_sha256,
        "archive_name": archive_name,
        "dry_run": dry_run,
        "provider_guess": provider_guess,
        "provider_hint": _coerce_optional_string(provider_hint, "provider_hint"),
        "source_manifest_recorded": bool(source_manifest_recorded),
        "source_manifest_path": _coerce_optional_string(source_manifest_path, "source_manifest_path"),
        "canonical_projection_path": _coerce_optional_string(canonical_projection_path, "canonical_projection_path"),
        "canonical_projection_sha256": _coerce_optional_string(canonical_projection_sha256, "canonical_projection_sha256"),
        "details": payload,
    }
    event["event_id"] = sha256(_serialize_event(event).encode("utf-8")).hexdigest()[:24]

    _append_json_lines(action_log_path(action_log_root, user_id), event)
    return event


def publish_reviewed_candidate_bundle(
    action_log_root: str,
    user_id: str,
    *,
    candidate_bundle: Mapping[str, Any],
    candidate_receipt: Mapping[str, Any],
    review_manifest: Mapping[str, Any],
    review_signing_secret: Optional[str] = None,
) -> Dict[str, Any]:
    """Publish a reviewed bundle into a per-user Action Log.

    The projection receipt is always content-free.  Candidate content is
    exported only when the latest projection-bound decision is ``accept`` or
    ``edit``.  Published entries remain non-authoritative candidates.
    """

    safe_user = _coerce_user_id(user_id)
    bundle = validate_candidate_bundle(candidate_bundle)
    receipt = validate_candidate_receipt(candidate_receipt, bundle)
    review = validate_review_manifest(
        review_manifest,
        source_id=bundle["source_id"],
        source_projection_sha256=bundle["source_projection_sha256"],
        signing_secret=review_signing_secret,
    )
    candidates = {candidate["candidate_id"]: candidate for candidate in bundle["candidates"]}

    latest_decisions: Dict[str, Dict[str, Any]] = {}
    for decision in review["decisions"]:
        candidate = candidates.get(decision["claim_id"])
        if candidate is None:
            raise ValueError(
                f"review decision references unknown candidate: {decision['claim_id']}"
            )
        if decision["review_claim_sha256"] != candidate["review_claim_sha256"]:
            raise ValueError(
                f"review decision claim digest mismatch: {decision['claim_id']}"
            )
        previous = latest_decisions.get(decision["claim_id"])
        if previous is None or decision["review_revision"] > previous["review_revision"]:
            latest_decisions[decision["claim_id"]] = decision

    approved = {
        candidate_id: decision
        for candidate_id, decision in latest_decisions.items()
        if decision["action"] in {"accept", "edit"}
    }
    approved_candidate_ids = sorted(approved)
    target = action_log_path(action_log_root, user_id)

    review_state_sha256 = sha256(
        _serialize_event(review).encode("utf-8")
    ).hexdigest()
    projection_event: Dict[str, Any] = {
        "schema_version": ACTION_LOG_SCHEMA_VERSION,
        "event_id": (
            "chronicle-projection-"
            + sha256(
                f"{receipt['receipt_id']}:{review_state_sha256}".encode("ascii")
            ).hexdigest()[:24]
        ),
        "event_type": ACTION_LOG_EVENT_CANDIDATE_PROJECTION_RECEIVED,
        "event_utc": None,
        "command": "chronicle-action-log-sync",
        "status": "reviewed",
        "user_id": safe_user,
        "source_id": bundle["source_id"],
        "corpus_id": bundle["source_id"],
        "index_generation": bundle["source_projection_sha256"],
        "source_projection_sha256": bundle["source_projection_sha256"],
        "candidate_bundle_sha256": bundle["candidate_bundle_sha256"],
        "candidate_receipt_id": receipt["receipt_id"],
        "candidate_count": bundle["candidate_count"],
        "candidate_ids": list(receipt["candidate_ids"]),
        "approved_candidate_ids": approved_candidate_ids,
        "approved_candidate_count": len(approved_candidate_ids),
        "review_revision": review["revision"],
        "review_state_sha256": review_state_sha256,
        "contains_raw_content": False,
        "contains_candidate_content": False,
        "authoritative": False,
    }
    projection_event["entry_sha256"] = _entry_digest(projection_event)

    batch_events: List[Dict[str, Any]] = [projection_event]
    published_event_ids: List[str] = []
    for candidate_id in sorted(latest_decisions):
        candidate = candidates[candidate_id]
        decision = latest_decisions[candidate_id]
        is_approved = decision["action"] in {"accept", "edit"}
        event_id = f"chronicle-reviewed-{decision['decision_sha256'][:24]}"
        event: Dict[str, Any] = {
            "schema_version": ACTION_LOG_SCHEMA_VERSION,
            "event_id": event_id,
            "event_type": ACTION_LOG_EVENT_CANDIDATE_REVIEWED,
            "event_utc": decision["issued_at_utc"],
            "command": "chronicle-action-log-sync",
            "status": (
                "review_approved_candidate"
                if is_approved
                else "review_revoked_candidate"
            ),
            "user_id": safe_user,
            "source_id": bundle["source_id"],
            "corpus_id": bundle["source_id"],
            "index_generation": bundle["source_projection_sha256"],
            "source_projection_sha256": bundle["source_projection_sha256"],
            "candidate_bundle_sha256": bundle["candidate_bundle_sha256"],
            "candidate_id": candidate_id,
            "candidate_sha256": candidate["candidate_sha256"],
            "claim_id": candidate["claim_id"],
            "review_decision_id": decision["decision_id"],
            "review_decision_sha256": decision["decision_sha256"],
            "review_revision": decision["review_revision"],
            "review_action": decision["action"],
            "review_approved": is_approved,
            "authoritative": False,
        }
        if is_approved:
            memory_text = (
                decision["replacement_text"]
                if decision["action"] == "edit"
                else candidate["claim_text"]
            )
            if not isinstance(memory_text, str) or not memory_text.strip():
                raise ValueError(f"reviewed candidate has empty memory text: {candidate_id}")
            event.update(
                {
                    "claim_type": candidate["claim_type"],
                    "memory_text": memory_text,
                    "memory_text_origin": (
                        "review_replacement"
                        if decision["action"] == "edit"
                        else "review_accept"
                    ),
                    "temporal_state": candidate["temporal_state"],
                    "created_at": candidate["created_at"],
                    "conversation_id": candidate["conversation_id"],
                    "is_user_assertion": candidate["is_user_assertion"],
                    "evidence_kind": candidate["evidence_kind"],
                    "source_locator": dict(candidate["source_locator"]),
                }
            )
        event["entry_sha256"] = _entry_digest(event)
        batch_events.append(event)
        published_event_ids.append(event_id)

    appended_count = _append_json_lines_idempotent_transactional(target, batch_events)

    return {
        "schema_version": "chronicle-action-log-sync-result/1",
        "source_id": bundle["source_id"],
        "corpus_id": bundle["source_id"],
        "index_generation": bundle["source_projection_sha256"],
        "candidate_receipt_id": receipt["receipt_id"],
        "candidate_ids": list(receipt["candidate_ids"]),
        "approved_candidate_ids": approved_candidate_ids,
        "projection_event_id": projection_event["event_id"],
        "published_event_ids": published_event_ids,
        "appended_event_count": appended_count,
        "action_log_path": str(target),
        "contains_raw_content": False,
        "authoritative": False,
    }


def load_reviewed_candidate_projection(
    action_log_root: str,
    user_id: str,
    *,
    corpus_index_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a fresh projection from reviewed Action Log candidates.

    Reviewed text is never returned without checking the current lossless
    corpus. A missing/replaced source fails closed; a matching conversation
    tombstone suppresses the candidate. This prevents Action Log history from
    resurrecting memory that the corpus forget path has invalidated.
    """

    safe_user = _coerce_user_id(user_id)
    path = action_log_path(action_log_root, user_id)
    if not path.exists():
        raise ValueError(f"action log does not exist: {path}")
    latest: Dict[tuple[str, str], Dict[str, Any]] = {}
    last_reviewed: Dict[tuple[str, str], Dict[str, Any]] = {}
    seen_review_event_ids: set[str] = set()
    seen_forget_operation_ids: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = loads_json_strict(line)
        except json.JSONDecodeError as err:
            raise ValueError(f"malformed action log JSON at line {line_number}") from err
        if not isinstance(event, dict):
            raise ValueError(f"non-object action log entry at line {line_number}")
        event_type = event.get("event_type")
        if event_type == ACTION_LOG_EVENT_FORGET_COMPLETED:
            (
                source_id_sha256,
                removed_claim_selector_sha256s,
                removed_conversation_selector_sha256s,
            ) = (
                _validate_successful_forget_event(
                    event,
                    safe_user=safe_user,
                    line_number=line_number,
                )
            )
            operation_id = str(event["operation_id"])
            if operation_id in seen_forget_operation_ids:
                raise ValueError(
                    f"duplicate successful forget operation_id at line {line_number}"
                )
            seen_forget_operation_ids.add(operation_id)
            removed_claim_set = set(removed_claim_selector_sha256s)
            removed_conversation_set = set(
                removed_conversation_selector_sha256s
            )
            for key, reviewed_event in list(latest.items()):
                source_id = key[0]
                if _forget_source_id_sha256(source_id) != source_id_sha256:
                    continue
                if (
                    _forget_selector_sha256(
                        source_id,
                        selector_type="claim_id",
                        identifier=str(reviewed_event["claim_id"]),
                    )
                    in removed_claim_set
                    or _forget_selector_sha256(
                        source_id,
                        selector_type="conversation_id",
                        identifier=str(reviewed_event.get("conversation_id", "")),
                    )
                    in removed_conversation_set
                ):
                    del latest[key]
            continue
        if event_type != ACTION_LOG_EVENT_CANDIDATE_REVIEWED:
            continue
        source_id, candidate_id, revision = _validate_reviewed_candidate_event(
            event,
            safe_user=safe_user,
            line_number=line_number,
        )
        event_id = str(event["event_id"])
        if event_id in seen_review_event_ids:
            raise ValueError(
                f"duplicate reviewed candidate event_id at line {line_number}"
            )
        seen_review_event_ids.add(event_id)
        key = (source_id, candidate_id)
        previous = last_reviewed.get(key)
        if previous is not None:
            same_generation = (
                previous.get("source_projection_sha256")
                == event.get("source_projection_sha256")
            )
            if same_generation and revision < previous["review_revision"]:
                raise ValueError(f"reviewed candidate revision regressed: {candidate_id}")
            if (
                same_generation
                and revision == previous["review_revision"]
                and event.get("review_decision_id")
                != previous.get("review_decision_id")
            ):
                raise ValueError(f"conflicting reviewed candidate revision: {candidate_id}")
        # Keep revision validation across a forget barrier, while allowing a
        # later explicit candidate_reviewed event to become effective again.
        # Final corpus-generation freshness below rejects stale re-acceptance.
        last_reviewed[key] = event
        latest[key] = event

    approved_events = [event for event in latest.values() if event["review_approved"]]
    corpus_summary: Dict[str, Any] = {}
    source_states: Dict[str, Dict[str, Any]] = {}
    tombstoned_conversations: set[tuple[str, str]] = set()
    if approved_events:
        if not isinstance(corpus_index_path, str) or not corpus_index_path:
            raise ValueError(
                "current corpus index is required for reviewed candidate freshness"
            )
        try:
            from .corpus_index import (
                CorpusIndexError,
                inspect_corpus_index,
                list_corpus_source_states,
                list_corpus_tombstones,
            )

            corpus_summary = inspect_corpus_index(corpus_index_path)
            source_states = {
                state["source_id"]: state
                for state in list_corpus_source_states(corpus_index_path)
            }
            tombstones = list_corpus_tombstones(corpus_index_path)
            for entry in tombstones:
                if entry.get("selector_type") != "conversation":
                    raise ValueError(
                        f"unsupported corpus tombstone selector: {entry.get('selector_type')}"
                    )
                if not isinstance(entry.get("source_id"), str) or not entry["source_id"]:
                    raise ValueError("corpus tombstone missing source_id")
                if (
                    not isinstance(entry.get("conversation_id"), str)
                    or not entry["conversation_id"]
                ):
                    raise ValueError("corpus tombstone missing conversation_id")
                tombstoned_conversations.add(
                    (entry["source_id"], entry["conversation_id"])
                )
        except (OSError, CorpusIndexError, KeyError, TypeError, ValueError) as err:
            raise ValueError(f"current corpus index is unavailable: {err}") from err

    claims: List[Dict[str, Any]] = []
    corpus_ids: set[str] = set()
    index_generations: set[str] = set()
    for key in sorted(latest):
        event = latest[key]
        if event["review_approved"] is False:
            if "memory_text" in event or "source_locator" in event:
                raise ValueError(
                    f"revoked reviewed candidate contains candidate content: {key[1]}"
                )
            continue
        source_id = event["source_id"]
        source_state = source_states.get(source_id)
        if source_state is None:
            raise ValueError(f"reviewed candidate source is absent from corpus: {source_id}")
        if source_state.get("projection_sha256") != event.get(
            "source_projection_sha256"
        ):
            raise ValueError(
                f"reviewed candidate source projection is stale: {source_id}"
            )
        if (source_id, str(event.get("conversation_id", ""))) in tombstoned_conversations:
            continue
        locator = event.get("source_locator")
        if not isinstance(locator, dict):
            raise ValueError(f"reviewed candidate missing source locator: {key[1]}")
        if locator.get("source_projection_sha256") != source_state["projection_sha256"]:
            raise ValueError(f"reviewed candidate locator projection is stale: {key[1]}")
        memory_text = event.get("memory_text")
        if not isinstance(memory_text, str) or not memory_text.strip():
            raise ValueError(f"reviewed candidate missing memory text: {key[1]}")
        corpus_ids.add(str(event.get("corpus_id", event["source_id"])))
        index_generations.add(str(event.get("index_generation", "")))
        claims.append(
            {
                "claim_id": event["claim_id"],
                "claim_type": event["claim_type"],
                "claim_text": memory_text,
                "temporal_state": event["temporal_state"],
                "created_at": event.get("created_at"),
                "conversation_id": event["conversation_id"],
                "is_user_assertion": event["is_user_assertion"],
                "provenance": dict(locator),
                "candidate_id": event["candidate_id"],
                "review_decision_id": event["review_decision_id"],
                "review_revision": event["review_revision"],
                "authoritative": False,
            }
        )
    claims.sort(
        key=lambda claim: (
            str(claim.get("created_at") or "9999-12-31T23:59:59Z"),
            claim["claim_id"],
        )
    )
    projection: Dict[str, Any] = {
        "schema_version": ACTION_LOG_REVIEWED_PROJECTION_SCHEMA_VERSION,
        "source_id": f"chronicle-action-log:{safe_user}",
        "corpus_ids": sorted(corpus_ids),
        "index_generations": sorted(value for value in index_generations if value),
        "corpus_id": corpus_summary.get("corpus_id"),
        "corpus_index_generation": corpus_summary.get("index_generation"),
        "corpus_tombstone_digest": corpus_summary.get("tombstone_digest"),
        "claim_count": len(claims),
        "claims": claims,
    }
    projection["projection_sha256"] = sha256(
        _serialize_event(projection).encode("utf-8")
    ).hexdigest()
    return projection


def append_corpus_recall_action_receipt(
    action_log_root: str,
    user_id: str,
    *,
    recall_result: Mapping[str, Any],
    query: str,
    filters: Optional[Mapping[str, Any]] = None,
    expected_index_generation: Optional[str] = None,
) -> Dict[str, Any]:
    """Record a content-free receipt for one bounded global-corpus recall."""

    safe_user = _coerce_user_id(user_id)
    if not isinstance(recall_result, Mapping):
        raise TypeError("recall_result must be an object")
    if not isinstance(query, str) or not query.strip():
        raise ValueError("query must be a non-empty string")
    corpus_id = recall_result.get("corpus_id")
    index_generation = recall_result.get("index_generation")
    if not isinstance(corpus_id, str) or not corpus_id.strip():
        raise ValueError("recall result missing corpus_id")
    if not isinstance(index_generation, str) or not index_generation.strip():
        raise ValueError("recall result missing index_generation")
    if expected_index_generation is not None:
        if not isinstance(expected_index_generation, str) or not expected_index_generation:
            raise ValueError("expected_index_generation must be a non-empty string")
        if index_generation != expected_index_generation:
            raise ValueError(
                "stale corpus index generation: "
                f"expected {expected_index_generation}, got {index_generation}"
            )
    results = recall_result.get("results")
    if not isinstance(results, list):
        raise ValueError("recall result results must be a list")

    candidate_ids: List[str] = []
    locator_digests: List[str] = []
    seen: set[str] = set()
    for index, result in enumerate(results):
        if not isinstance(result, Mapping):
            raise ValueError(f"recall result at index {index} must be an object")
        record_id = result.get("record_id")
        locator = result.get("locator")
        if not isinstance(record_id, str) or not record_id:
            raise ValueError(f"recall result at index {index} missing record_id")
        if record_id in seen:
            raise ValueError(f"duplicate recall record_id: {record_id}")
        seen.add(record_id)
        if not isinstance(locator, Mapping):
            raise ValueError(f"recall result at index {index} missing locator")
        if locator.get("record_id") != record_id:
            raise ValueError(f"recall locator record_id mismatch at index {index}")
        for field_name in (
            "source_id",
            "projection_sha256",
            "conversation_id",
            "message_id",
            "canonical_pointer",
        ):
            value = locator.get(field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"recall locator at index {index} missing {field_name}"
                )
        candidate_ids.append(record_id)
        locator_digests.append(
            sha256(_serialize_event(dict(locator)).encode("utf-8")).hexdigest()
        )

    normalized_filters = _coerce_payload(filters, "filters")
    query_sha256 = sha256(query.encode("utf-8")).hexdigest()
    filters_sha256 = sha256(
        _serialize_event(normalized_filters).encode("utf-8")
    ).hexdigest()
    core = {
        "user_id": safe_user,
        "corpus_id": corpus_id,
        "index_generation": index_generation,
        "query_sha256": query_sha256,
        "filters_sha256": filters_sha256,
        "candidate_ids": sorted(candidate_ids),
        "locator_sha256s": sorted(locator_digests),
    }
    event: Dict[str, Any] = {
        "schema_version": ACTION_LOG_SCHEMA_VERSION,
        "event_id": f"chronicle-recall-{sha256(_serialize_event(core).encode('utf-8')).hexdigest()[:24]}",
        "event_type": ACTION_LOG_EVENT_CORPUS_RECALL_COMPLETED,
        "event_utc": None,
        "command": "chronicle-action-log-recall",
        "status": "ok",
        **core,
        "result_count": len(candidate_ids),
        "contains_query_text": False,
        "contains_raw_content": False,
        "authoritative": False,
    }
    event["entry_sha256"] = _entry_digest(event)
    appended = _append_json_line_idempotent(
        action_log_path(action_log_root, user_id), event
    )
    result = dict(event)
    result["appended"] = appended
    return result
