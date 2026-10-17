"""Strict content-free Action Log for work projects."""

from __future__ import annotations

import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Dict, Mapping, Optional, Sequence

from .json_integrity import loads_json_strict
from .state_lock import corpus_state_lock

PROJECT_ACTION_LOG_SCHEMA = "integrity-home-project-action/1"
PROJECT_ACTION_LOG_VERIFY_SCHEMA = "integrity-home-project-action-verify/1"
GENESIS_SHA256 = "0" * 64
_ALLOWED_STATUSES = frozenset({"started", "ok", "failed", "cancelled"})


class ProjectActionLogError(ValueError):
    pass


def _identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProjectActionLogError(f"{field} must be a non-empty string")
    if len(value.encode("utf-8")) > 256 or any(ord(char) < 32 for char in value):
        raise ProjectActionLogError(f"{field} is invalid")
    return value


def _sha(value: str, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ProjectActionLogError(f"{field} must be a lowercase SHA-256")
    try:
        int(value, 16)
    except ValueError as err:
        raise ProjectActionLogError(f"{field} must be a lowercase SHA-256") from err
    if value != value.lower():
        raise ProjectActionLogError(f"{field} must be a lowercase SHA-256")
    return value


def _canonical(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _entry_sha(event: Mapping[str, Any]) -> str:
    payload = dict(event)
    payload.pop("entry_sha256", None)
    return sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _event_id(project_id: str, root_thread_id: str, operation_id: str) -> str:
    return "project-action-" + sha256(
        _canonical({
            "operation_id": operation_id,
            "project_id": project_id,
            "root_thread_id": root_thread_id,
        }).encode("utf-8")
    ).hexdigest()[:24]


def _project_path(root: str, project_id: str) -> Path:
    token = sha256(project_id.encode("utf-8")).hexdigest()[:32]
    return Path(root) / "projects" / token / "action-log.jsonl"


def _read_and_verify(path: Path, project_id: str) -> list[Dict[str, Any]]:
    if not path.exists():
        return []
    events: list[Dict[str, Any]] = []
    previous = GENESIS_SHA256
    operation_ids: set[str] = set()
    with path.open("r", encoding="utf-8", newline="") as stream:
        for line_number, raw in enumerate(stream, 1):
            if not raw.endswith("\n"):
                raise ProjectActionLogError(f"unterminated entry at line {line_number}")
            try:
                event = loads_json_strict(raw)
            except (TypeError, ValueError, json.JSONDecodeError) as err:
                raise ProjectActionLogError(f"invalid JSON at line {line_number}") from err
            if not isinstance(event, dict) or set(event) != {
                "schema_version", "event_id", "event_utc", "project_id",
                "root_thread_id", "session_id", "actor_id", "operation_id",
                "action", "status", "artifact_sha256s", "previous_entry_sha256",
                "entry_sha256",
            }:
                raise ProjectActionLogError(f"invalid fields at line {line_number}")
            if event["schema_version"] != PROJECT_ACTION_LOG_SCHEMA:
                raise ProjectActionLogError(f"invalid schema at line {line_number}")
            if event["project_id"] != project_id:
                raise ProjectActionLogError(f"project mismatch at line {line_number}")
            for field in ("event_id", "root_thread_id", "session_id", "actor_id", "operation_id", "action"):
                _identifier(event[field], field)
            if event["operation_id"] in operation_ids:
                raise ProjectActionLogError(f"duplicate operation_id at line {line_number}")
            operation_ids.add(event["operation_id"])
            if event["event_id"] != _event_id(project_id, event["root_thread_id"], event["operation_id"]):
                raise ProjectActionLogError(f"event_id mismatch at line {line_number}")
            if not isinstance(event["event_utc"], str) or not event["event_utc"]:
                raise ProjectActionLogError(f"invalid timestamp at line {line_number}")
            if event["status"] not in _ALLOWED_STATUSES:
                raise ProjectActionLogError(f"invalid status at line {line_number}")
            artifacts = event["artifact_sha256s"]
            if not isinstance(artifacts, list) or artifacts != sorted(set(artifacts)):
                raise ProjectActionLogError(f"invalid artifacts at line {line_number}")
            for digest in artifacts:
                _sha(digest, "artifact_sha256s")
            if event["previous_entry_sha256"] != previous:
                raise ProjectActionLogError(f"broken chain at line {line_number}")
            if event["entry_sha256"] != _entry_sha(event):
                raise ProjectActionLogError(f"digest mismatch at line {line_number}")
            previous = event["entry_sha256"]
            events.append(event)
    return events


def append_project_action(
    root: str,
    *,
    project_id: str,
    root_thread_id: str,
    session_id: str,
    actor_id: str,
    operation_id: str,
    action: str,
    status: str,
    artifact_sha256s: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    for field, value in (("project_id", project_id), ("root_thread_id", root_thread_id),
                         ("session_id", session_id), ("actor_id", actor_id),
                         ("operation_id", operation_id), ("action", action)):
        _identifier(value, field)
    if status not in _ALLOWED_STATUSES:
        raise ProjectActionLogError("unsupported status")
    if artifact_sha256s is None:
        artifacts: list[str] = []
    elif isinstance(artifact_sha256s, str) or not isinstance(artifact_sha256s, Sequence):
        raise ProjectActionLogError("artifact_sha256s must be a sequence")
    else:
        artifacts = sorted(set(_sha(value, "artifact_sha256s") for value in artifact_sha256s))

    path = _project_path(root, project_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with corpus_state_lock(str(path)):
        events = _read_and_verify(path, project_id)
        matching = [event for event in events if event["operation_id"] == operation_id]
        if matching:
            existing = matching[0]
            semantic = {key: existing[key] for key in (
                "project_id", "root_thread_id", "session_id", "actor_id",
                "operation_id", "action", "status", "artifact_sha256s",
            )}
            requested = {
                "project_id": project_id, "root_thread_id": root_thread_id,
                "session_id": session_id, "actor_id": actor_id,
                "operation_id": operation_id, "action": action,
                "status": status, "artifact_sha256s": artifacts,
            }
            if semantic != requested:
                raise ProjectActionLogError("operation_id collision")
            result = dict(existing)
            result["appended"] = False
            return result
        event: Dict[str, Any] = {
            "schema_version": PROJECT_ACTION_LOG_SCHEMA,
            "event_id": "",
            "event_utc": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
            "project_id": project_id,
            "root_thread_id": root_thread_id,
            "session_id": session_id,
            "actor_id": actor_id,
            "operation_id": operation_id,
            "action": action,
            "status": status,
            "artifact_sha256s": artifacts,
            "previous_entry_sha256": events[-1]["entry_sha256"] if events else GENESIS_SHA256,
            "entry_sha256": "",
        }
        event["event_id"] = _event_id(project_id, root_thread_id, operation_id)
        event["entry_sha256"] = _entry_sha(event)
        fd, temporary = tempfile.mkstemp(prefix="project-action-", suffix=".jsonl", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as output:
                if path.exists():
                    output.write(path.read_bytes())
                output.write((_canonical(event) + "\n").encode("utf-8"))
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)
    result = dict(event)
    result["appended"] = True
    return result


def verify_project_action_log(root: str, project_id: str) -> Dict[str, Any]:
    _identifier(project_id, "project_id")
    events = _read_and_verify(_project_path(root, project_id), project_id)
    return {
        "schema_version": PROJECT_ACTION_LOG_VERIFY_SCHEMA,
        "project_id": project_id,
        "entry_count": len(events),
        "last_entry_sha256": events[-1]["entry_sha256"] if events else GENESIS_SHA256,
        "valid": True,
    }
