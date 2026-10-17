"""Persistent source registry operations for dry-run intake results."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
import hashlib
import json
import tempfile
import datetime

from .validator import ArchiveValidationReport
from .json_integrity import load_json_strict


SOURCE_MANIFEST_SCHEMA_VERSION = 2
STATE_DRY_RUN_VALIDATED = "dry_run_validated"
STATE_CANONICAL_PARSED = "canonical_parsed"
STATE_CANONICAL_FORGOT = "canonical_forget_rebuilt"
SOURCE_REBUILD_EVENT_SCHEMA_VERSION = "chronicle-source-rebuild-event/1"

LEGACY_ROOT_METADATA_FIELDS = (
    "product",
    "registered_utc",
    "moved_to_vault_utc",
    "custody_state",
    "custody_replicas",
    "processing_state",
    "content_inspected",
    "content_extracted",
    "model_egress",
    "privacy_class",
)


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _entry_from_legacy_archive_item(
    item: Dict[str, Any],
    legacy_manifest: Dict[str, Any],
    now: str,
) -> Optional[Dict[str, Any]]:
    source_sha = str(item.get("source_sha256") or item.get("sha256") or "").lower()
    if not source_sha:
        return None
    source_id = item.get("source_id")
    if not source_id:
        source_id = source_sha[:24]
    provider = item.get("provider") or item.get("provider_label") or "unknown"
    return {
        "source_id": source_id,
        "source_sha256": source_sha,
        "source_size_bytes": item.get("size_bytes", item.get("source_size_bytes", 0)) or 0,
        "provider": provider,
        "original_filename": item.get("original_filename", ""),
        "stored_path": item.get("stored_path", item.get("original_filename", "")),
        "processing_state": item.get(
            "processing_state",
            item.get("state", legacy_manifest.get("processing_state", "raw_unopened")),
        ),
        "content_inspected": item.get(
            "content_inspected",
            legacy_manifest.get("content_inspected", False),
        ),
        "content_extracted": item.get(
            "content_extracted",
            legacy_manifest.get("content_extracted", False),
        ),
        "model_egress": item.get(
            "model_egress",
            legacy_manifest.get("model_egress", False),
        ),
        "privacy_class": item.get(
            "privacy_class",
            legacy_manifest.get("privacy_class", "highly_sensitive_personal_archive"),
        ),
        "validation": {
            **(
                item.get("zip_validation", {})
                if isinstance(item.get("zip_validation"), dict)
                else {}
            ),
        },
        "first_seen_utc": item.get(
            "registered_utc",
            legacy_manifest.get("registered_utc", now),
        ),
        "last_seen_utc": item.get(
            "moved_to_vault_utc",
            legacy_manifest.get("moved_to_vault_utc", now),
        ),
        "canonical_projection_path": item.get("canonical_projection_path"),
        "canonical_projection_sha256": item.get("canonical_projection_sha256"),
        "archive_entry_count": item.get("entry_count", item.get("zip_entry_count")),
        "identity_method": item.get("identity_method"),
    }


def _coerce_manifest(payload: Dict[str, Any], now: str) -> List[Dict[str, Any]]:
    entries = payload.get("entries")
    if isinstance(entries, list):
        return [entry for entry in entries if isinstance(entry, dict)]

    legacy_archives = payload.get("archives")
    if isinstance(legacy_archives, list):
        converted: List[Dict[str, Any]] = []
        for item in legacy_archives:
            if not isinstance(item, dict):
                continue
            converted_item = _entry_from_legacy_archive_item(item, payload, now)
            if converted_item is not None:
                converted.append(converted_item)
        return converted

    return []


def _load_manifest(path: str) -> Dict[str, Any]:
    manifest_path = Path(path)
    if not manifest_path.exists():
        return {
            "schema_version": SOURCE_MANIFEST_SCHEMA_VERSION,
            "generated_utc": _utc_now(),
            "entries": [],
        }

    with open(manifest_path, "r", encoding="utf-8") as fp:
        payload = load_json_strict(fp)

    if not isinstance(payload, dict):
        raise RuntimeError(f"invalid source manifest payload type: {type(payload).__name__}")

    now = _utc_now()
    normalized = {
        "schema_version": SOURCE_MANIFEST_SCHEMA_VERSION,
        "generated_utc": now,
        "entries": _coerce_manifest(payload, now),
    }
    for key in LEGACY_ROOT_METADATA_FIELDS:
        if key in payload:
            normalized[key] = payload[key]
    return normalized


def _coerce_rebuild_events(raw_events: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw_events, list):
        return []
    return [event for event in raw_events if isinstance(event, dict)]


def _find_entry_index(entries: List[Dict[str, Any]], source_id: str) -> Optional[int]:
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        if str(entry.get("source_id", "")) == source_id:
            return index
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        if str(entry.get("source_sha256", "")).startswith(source_id):
            return index
    return None


def _build_entry(
    report: ArchiveValidationReport,
    archive_path: str,
    now: str,
    *,
    processing_state: str = STATE_DRY_RUN_VALIDATED,
    content_inspected: bool = False,
    content_extracted: bool = False,
    canonical_projection_path: Optional[str] = None,
    canonical_projection_sha256: Optional[str] = None,
    user_id: Optional[str] = None,
) -> Dict[str, Any]:
    digest = _sha256_file(archive_path)
    entry = {
        "source_id": digest[:24],
        "source_sha256": digest,
        "source_size_bytes": Path(archive_path).stat().st_size,
        "provider": report.provider_guess,
        "original_filename": str(archive_path),
        "stored_path": str(archive_path),
        "processing_state": processing_state,
        "content_inspected": content_inspected,
        "content_extracted": content_extracted,
        "model_egress": False,
        "privacy_class": "highly_sensitive_personal_archive",
        "validation": report.to_dict(),
        "first_seen_utc": now,
        "last_seen_utc": now,
        "canonical_projection_path": canonical_projection_path,
        "canonical_projection_sha256": canonical_projection_sha256,
        "canonical_projection_rebuild_count": 0,
        "rebuild_events": [],
    }
    if user_id is not None:
        entry["user_id"] = user_id
    return entry


def _upsert_entry(entries: List[Dict[str, Any]], entry: Dict[str, Any]) -> None:
    existing_index = None
    for index, existing in enumerate(entries):
        if existing.get("source_sha256") == entry["source_sha256"]:
            existing_index = index
            break

    if existing_index is None:
        entries.append(entry)
        return

    first_seen = entries[existing_index].get("first_seen_utc", entry["first_seen_utc"])
    entry["first_seen_utc"] = first_seen
    entries[existing_index] = entry


def _write_manifest(path: str, payload: Dict[str, Any]) -> str:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload["entries"] = sorted(
        payload["entries"],
        key=lambda item: (str(item.get("source_id", "")), str(item.get("source_sha256", ""))),
    )
    data = json.dumps(payload, sort_keys=True, indent=2) + "\n"
    fd, tmp = tempfile.mkstemp(prefix="chronicle-manifest-", suffix=".tmp", dir=target.parent)
    with open(fd, "w", encoding="utf-8") as fp:
        fp.write(data)
    Path(tmp).replace(target)
    return str(target)


def record_source_manifest(
    report: ArchiveValidationReport,
    archive_path: str,
    source_manifest_path: str,
    *,
    processing_state: str = STATE_DRY_RUN_VALIDATED,
    content_inspected: bool = False,
    content_extracted: bool = False,
    canonical_projection_path: Optional[str] = None,
    canonical_projection_sha256: Optional[str] = None,
    user_id: Optional[str] = None,
) -> str:
    now = _utc_now()
    payload = _load_manifest(source_manifest_path)
    entry = _build_entry(
        report,
        archive_path,
        now,
        processing_state=processing_state,
        content_inspected=content_inspected,
        content_extracted=content_extracted,
        canonical_projection_path=canonical_projection_path,
        canonical_projection_sha256=canonical_projection_sha256,
        user_id=user_id,
    )
    _upsert_entry(payload["entries"], entry)
    payload["generated_utc"] = now
    return _write_manifest(source_manifest_path, payload)


def record_projection_rebuild(
    source_manifest_path: str,
    source_id: str,
    *,
    processing_state: str,
    canonical_projection_path: Optional[str],
    canonical_projection_sha256: str,
    before_projection_sha256: Optional[str],
    event_type: str,
    action_schema_version: str,
    receipt_id: str,
    reason: str,
    removed_claim_ids: Sequence[str],
    removed_conversation_ids: Sequence[str],
    removed_claim_id_count_from_selector: int,
) -> str:
    now = _utc_now()
    if not isinstance(source_id, str) or not source_id:
        raise ValueError("source_id must be a non-empty string")
    payload = _load_manifest(source_manifest_path)

    entry_index = _find_entry_index(payload["entries"], source_id)
    if entry_index is None:
        raise ValueError(f"source manifest missing source entry for source_id={source_id}")

    entry = payload["entries"][entry_index]
    if not isinstance(entry, dict):
        raise ValueError(f"source manifest entry for source_id={source_id} is malformed")

    rebuilt_events = _coerce_rebuild_events(entry.get("rebuild_events"))
    normalized_claim_ids = sorted(set(removed_claim_ids))
    normalized_conversation_ids = sorted(set(removed_conversation_ids))
    event = {
        "schema_version": SOURCE_REBUILD_EVENT_SCHEMA_VERSION,
        "event_type": event_type,
        "event_at_utc": now,
        "action_schema_version": action_schema_version,
        "receipt_id": receipt_id,
        "source_projection_sha256_before": before_projection_sha256,
        "source_projection_sha256_after": canonical_projection_sha256,
        "removed_claim_ids": normalized_claim_ids,
        "removed_claim_count": len(normalized_claim_ids),
        "removed_claim_id_count_from_selector": removed_claim_id_count_from_selector,
        "removed_conversation_ids": normalized_conversation_ids,
        "reason": reason or None,
    }
    rebuilt_events.append(event)

    rebuild_count = entry.get("canonical_projection_rebuild_count", 0)
    if not isinstance(rebuild_count, int):
        rebuild_count = 0

    entry.update(
        {
            "processing_state": processing_state,
            "canonical_projection_path": canonical_projection_path,
            "canonical_projection_sha256": canonical_projection_sha256,
            "canonical_projection_rebuild_count": rebuild_count + 1,
            "rebuild_events": rebuilt_events,
            "last_seen_utc": now,
        }
    )

    payload["entries"][entry_index] = entry
    payload["generated_utc"] = now
    return _write_manifest(source_manifest_path, payload)
