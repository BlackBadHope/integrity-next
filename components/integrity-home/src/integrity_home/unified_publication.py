"""Build the logical-scope sidecar for one shared corpus successor."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Any

from .history.sidecar import (
    PERSONAL_SCOPE_ID, REVIEWED_SCOPE_REASON_CODE,
    MAX_LOGICAL_SCOPES, MAX_RECORDS, MAX_SCOPE_DECISIONS,
    HistorySidecarReader, LogicalScope,
    ScopeDecision, _build_history_sidecar, build_history_sidecar,
    build_history_sidecar_successor,
)


@dataclass(frozen=True)
class _UnifiedSidecarSnapshot:
    """Validated content-free ownership state captured before corpus mutation."""

    scopes: tuple[LogicalScope, ...]
    decisions: tuple[ScopeDecision, ...]
    record_identities: tuple[tuple[str, tuple[str, ...]], ...]


def _snapshot_payload(
    snapshot: _UnifiedSidecarSnapshot, *, source_sidecar_sha256: str,
) -> dict[str, object]:
    if len(source_sidecar_sha256) != 64 or any(
        char not in "0123456789abcdef" for char in source_sidecar_sha256
    ):
        raise ValueError("source_sidecar_sha256 must be lowercase SHA-256")
    return {
        "schema_version": "integrity-home-history-forget-recovery/1",
        "source_sidecar_sha256": source_sidecar_sha256,
        "scopes": [item.to_dict() for item in snapshot.scopes],
        "decisions": [
            {"record_id": item.record_id, **item.to_dict()}
            for item in snapshot.decisions
        ],
        "record_identities": [
            {"record_id": record_id, "identity": list(identity)}
            for record_id, identity in snapshot.record_identities
        ],
    }


def _snapshot_from_payload(
    payload: object, *, actual_sidecar_sha256: str,
) -> _UnifiedSidecarSnapshot:
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version", "source_sidecar_sha256", "scopes", "decisions",
        "record_identities",
    }:
        raise ValueError("History recovery journal has an invalid shape")
    if payload["schema_version"] != "integrity-home-history-forget-recovery/1":
        raise ValueError("History recovery journal has an unsupported schema")
    if payload["source_sidecar_sha256"] != actual_sidecar_sha256:
        raise ValueError("History recovery journal does not bind the stale sidecar")
    raw_scopes = payload["scopes"]
    raw_decisions = payload["decisions"]
    raw_identities = payload["record_identities"]
    if (
        not isinstance(raw_scopes, list)
        or not isinstance(raw_decisions, list)
        or not isinstance(raw_identities, list)
        or len(raw_scopes) > MAX_LOGICAL_SCOPES
        or len(raw_decisions) > MAX_SCOPE_DECISIONS
        or len(raw_identities) > MAX_RECORDS
    ):
        raise ValueError("History recovery journal collections are invalid")
    scopes = tuple(LogicalScope(**item) for item in raw_scopes)
    decisions = tuple(ScopeDecision(**item) for item in raw_decisions)
    identities: list[tuple[str, tuple[str, ...]]] = []
    for item in raw_identities:
        if not isinstance(item, dict) or set(item) != {"record_id", "identity"}:
            raise ValueError("History recovery record identity is invalid")
        identity = item["identity"]
        if (
            not isinstance(item["record_id"], str)
            or not isinstance(identity, list)
            or len(identity) != 7
            or any(not isinstance(value, str) for value in identity)
        ):
            raise ValueError("History recovery record identity is invalid")
        identities.append((item["record_id"], tuple(identity)))
    if len({item.scope_id for item in scopes}) != len(scopes):
        raise ValueError("History recovery scopes are duplicated")
    if len({(item.record_id, item.scope_id) for item in decisions}) != len(decisions):
        raise ValueError("History recovery decisions are duplicated")
    if len({record_id for record_id, _identity in identities}) != len(identities):
        raise ValueError("History recovery records are duplicated")
    return _UnifiedSidecarSnapshot(scopes, decisions, tuple(identities))


def _scopes(project_ids: Iterable[str]) -> tuple[LogicalScope, ...]:
    values = [LogicalScope(PERSONAL_SCOPE_ID, "Personal", "personal", "personal")]
    projects = sorted(set(project_ids))
    values.extend(LogicalScope(
        f"project:{project}", project,
        "project", "work", project,
    ) for project in projects)
    return tuple(sorted(values, key=lambda item: item.scope_id))


def _record_ids(sidecar: str) -> tuple[str, ...]:
    uri = Path(sidecar).resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        return tuple(row[0] for row in conn.execute(
            "SELECT record_id FROM catalog_records ORDER BY record_id"
        ))
    finally:
        conn.close()


def _record_identities(sidecar: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    uri = Path(sidecar).resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        rows = conn.execute(
            """SELECT record_id, source_id, provider, conversation_id,
                      COALESCE(message_id, ''), role, content_type, content_sha256
                 FROM catalog_records ORDER BY record_id"""
        )
        return tuple((row[0], tuple(str(value) for value in row[1:])) for row in rows)
    finally:
        conn.close()


def build_unified_sidecar_successor(
    corpus_path: str, sidecar_path: str, *, target_scope_id: str,
    project_ids: Iterable[str], authority_sha256: str,
    previous_corpus_path: str | None = None,
    previous_sidecar_path: str | None = None,
) -> dict[str, object]:
    """Build one complete logical projection without copying message rows."""
    scopes = _scopes(project_ids)
    scope_ids = {item.scope_id for item in scopes}
    if target_scope_id not in scope_ids:
        raise ValueError("target scope is absent from successor inventory")
    baseline = str(Path(sidecar_path).with_suffix(".baseline.sqlite"))
    try:
        build_history_sidecar(corpus_path, baseline, scopes=scopes)
        records = _record_ids(baseline)
    finally:
        Path(baseline).unlink(missing_ok=True)
        Path(baseline + ".state.lock").unlink(missing_ok=True)
    record_set = set(records)
    prior_records = set(_record_ids(previous_sidecar_path)) if previous_sidecar_path else set()
    prior: dict[tuple[str, str], ScopeDecision] = {}
    if previous_sidecar_path and previous_corpus_path:
        with HistorySidecarReader(previous_corpus_path, previous_sidecar_path) as reader:
            after_record = after_scope = None
            while True:
                page = reader.scan_scope_decisions(
                    after_record_id=after_record, after_scope_id=after_scope, limit=1000
                )
                for raw in page["decisions"]:
                    item = ScopeDecision(**raw)  # type: ignore[arg-type]
                    if item.record_id in record_set and item.scope_id in scope_ids:
                        prior[(item.record_id, item.scope_id)] = item
                if not page["has_more"]:
                    break
                after_record = page["next_cursor"]["record_id"]
                after_scope = page["next_cursor"]["scope_id"]
    decisions: list[ScopeDecision] = []
    for record_id in records:
        for scope_id in sorted(scope_ids):
            existing = prior.get((record_id, scope_id))
            if existing is not None:
                decisions.append(existing)
            else:
                membership = (
                    "include" if record_id not in prior_records and scope_id == target_scope_id
                    else "unknown"
                )
                decisions.append(ScopeDecision(
                    record_id, scope_id, membership, "reviewed",
                    authority_sha256, REVIEWED_SCOPE_REASON_CODE,
                ))
    return build_history_sidecar_successor(
        corpus_path, sidecar_path, scopes=scopes, decisions=decisions,
        authority_sha256=authority_sha256,
    )


def _capture_unified_sidecar_snapshot(
    corpus_path: str, sidecar_path: str,
) -> _UnifiedSidecarSnapshot:
    """Capture only validated scope metadata and decisions, never corpus text."""
    decisions: list[ScopeDecision] = []
    with HistorySidecarReader(corpus_path, sidecar_path) as reader:
        scopes = tuple(LogicalScope(**raw) for raw in reader.list_scopes())
        after_record = after_scope = None
        while True:
            page = reader.scan_scope_decisions(
                after_record_id=after_record, after_scope_id=after_scope, limit=1000
            )
            decisions.extend(ScopeDecision(**raw) for raw in page["decisions"])
            if not page["has_more"]:
                break
            after_record = page["next_cursor"]["record_id"]
            after_scope = page["next_cursor"]["scope_id"]
    return _UnifiedSidecarSnapshot(
        scopes, tuple(decisions), _record_identities(sidecar_path)
    )


def _rebuild_unified_sidecar_from_snapshot(
    corpus_path: str, sidecar_path: str, snapshot: _UnifiedSidecarSnapshot,
) -> dict[str, object]:
    """Reseal a derived sidecar after deletion, retaining surviving decisions."""
    if not isinstance(snapshot, _UnifiedSidecarSnapshot):
        raise TypeError("snapshot must be a validated sidecar snapshot")
    baseline = str(Path(sidecar_path).with_suffix(".maintenance.sqlite"))
    try:
        build_history_sidecar(corpus_path, baseline, scopes=snapshot.scopes)
        current_identities = _record_identities(baseline)
    finally:
        Path(baseline).unlink(missing_ok=True)
        Path(baseline + ".state.lock").unlink(missing_ok=True)
    old_by_id = dict(snapshot.record_identities)
    new_by_identity: dict[tuple[str, ...], str] = {}
    for record_id, identity in current_identities:
        if identity in new_by_identity:
            raise ValueError("successor catalog contains an ambiguous record identity")
        new_by_identity[identity] = record_id
    decisions: list[ScopeDecision] = []
    for item in snapshot.decisions:
        identity = old_by_id.get(item.record_id)
        new_record_id = new_by_identity.get(identity) if identity is not None else None
        if new_record_id is not None:
            decisions.append(ScopeDecision(
                new_record_id, item.scope_id, item.membership, item.review_state,
                item.artifact_sha256, item.reason_code,
            ))
    return _build_history_sidecar(
        corpus_path, sidecar_path, scopes=snapshot.scopes,
        decisions=decisions, allow_reviewed=True,
    )
