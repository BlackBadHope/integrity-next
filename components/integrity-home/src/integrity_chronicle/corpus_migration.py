"""Verified rebuild gate for legacy Chronicle corpus indexes.

Schema v2 indexed conversation titles in every message FTS row.  The current
schema uses a separate conversation-title projection and applies stricter
indexing policy while rebuilding canonical records.  Updating the SQLite
schema in place would therefore bless stale derived rows without reapplying
that policy.  This module provides the safe upgrade boundary instead:

1. validate a consistent, read-only v2 snapshot;
2. atomically retain that private snapshot as a mode-0600 backup;
3. export and merge its conversation tombstones into the current external
   deletion ledger before the caller rebuilds from canonical projections.

The legacy index is never modified.  Callers must separately invoke
``build_corpus_index(..., deletion_ledger_path=<exported ledger>)``.
"""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from .corpus_index import CORPUS_INDEX_SCHEMA_VERSION
from .deletion_ledger import (
    DeletionLedgerError,
    conversation_selector,
    deletion_ledger_path,
    load_deletion_ledger,
    write_deletion_ledger,
)
from .state_lock import CorpusStateLockError, corpus_state_lock


LEGACY_CORPUS_INDEX_SCHEMA_VERSION = "chronicle-corpus-index/2"
CORPUS_V2_REBUILD_GATE_SCHEMA_VERSION = "integrity-home-corpus-v2-rebuild-gate/1"


class CorpusMigrationError(RuntimeError):
    """Raised when a legacy corpus cannot cross the rebuild gate safely."""


_REQUIRED_COLUMNS = {
    "corpus_meta": {"key", "value"},
    "source_records": {
        "source_id",
        "provider",
        "provider_schema_version",
        "projection_sha256",
        "source_json",
        "conversation_count",
        "message_count",
        "synthetic_fixture",
    },
    "conversation_records": {
        "conversation_pk",
        "source_id",
        "provider",
        "provider_schema_version",
        "conversation_id",
        "provider_conversation_id",
        "title_utf8",
        "title_norm",
        "created_at",
        "has_unknown_timestamp",
        "source_ordinal",
        "canonical_json",
    },
    "message_records": {
        "message_pk",
        "record_id",
        "source_id",
        "provider",
        "provider_schema_version",
        "projection_sha256",
        "conversation_id",
        "provider_conversation_id",
        "conversation_ordinal",
        "message_id",
        "message_ordinal",
        "parent_message_id",
        "role",
        "model",
        "content_type",
        "created_at",
        "branch_path",
        "branch_depth",
        "has_unknown_parent",
        "has_unknown_timestamp",
        "content_utf8",
        "content_norm",
        "content_sha256",
        "canonical_json",
        "provenance_json",
    },
    "message_fts": {
        "content_norm",
        "attachment_text_norm",
        "conversation_title_norm",
        "record_id",
    },
    "message_text_leaf_records": {
        "leaf_pk",
        "message_pk",
        "record_id",
        "canonical_pointer",
        "field_scope",
        "value_utf8",
        "value_norm",
        "value_sha256",
        "source_ordinal",
    },
    "message_text_leaf_fts": {"value_norm", "record_id", "canonical_pointer"},
    "corpus_tombstones": {
        "tombstone_id",
        "source_id",
        "conversation_id",
        "selector_type",
    },
}


def _stable_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError, UnicodeEncodeError) as err:
        raise CorpusMigrationError(f"legacy corpus state is not stable JSON: {err}") from err


def _readonly_uri(path: Path) -> str:
    return f"{path.resolve().as_uri()}?mode=ro"


def _path_identity(path: Path) -> str:
    return os.path.normcase(str(path.resolve()))


def _private_mode(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        os.chmod(path, 0o600)
    except OSError as err:
        raise CorpusMigrationError(f"cannot make private migration artifact: {err}") from err


def _sync_parent_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(str(path), flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _file_sha256(path: Path) -> str:
    digest = sha256()
    try:
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    return digest.hexdigest()
                digest.update(chunk)
    except OSError as err:
        raise CorpusMigrationError(f"cannot hash private migration snapshot: {err}") from err


def _text(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise CorpusMigrationError(f"{field} must be a non-empty string")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as err:
        raise CorpusMigrationError(f"{field} must be valid UTF-8") from err
    return value


def _integer(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CorpusMigrationError(f"{field} must be a non-negative integer")
    return value


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {str(row[1]) for row in conn.execute(f'PRAGMA table_info("{table}")')}
    except sqlite3.DatabaseError as err:
        raise CorpusMigrationError(f"cannot inspect legacy table {table}: {err}") from err


def _validate_required_schema(conn: sqlite3.Connection) -> None:
    for table, required in _REQUIRED_COLUMNS.items():
        actual = _table_columns(conn, table)
        if not required.issubset(actual):
            missing = ", ".join(sorted(required - actual))
            raise CorpusMigrationError(
                f"legacy corpus table {table} is missing required columns: {missing}"
            )


def _read_meta(conn: sqlite3.Connection) -> Dict[str, str]:
    try:
        rows = conn.execute("SELECT key, value FROM corpus_meta").fetchall()
    except sqlite3.DatabaseError as err:
        raise CorpusMigrationError(f"cannot read legacy corpus metadata: {err}") from err
    result: Dict[str, str] = {}
    for key, value in rows:
        key = _text(key, field="legacy corpus metadata key")
        value = _text(value, field=f"legacy corpus metadata {key}")
        if key in result:
            raise CorpusMigrationError("duplicate legacy corpus metadata key")
        result[key] = value
    if result.get("schema_version") != LEGACY_CORPUS_INDEX_SCHEMA_VERSION:
        raise CorpusMigrationError(
            "source is not an exact chronicle-corpus-index/2 index"
        )
    for key in ("corpus_id", "index_generation"):
        if key not in result:
            raise CorpusMigrationError(f"legacy corpus metadata is missing {key}")
    return result


def _read_tombstones(
    conn: sqlite3.Connection,
) -> Tuple[List[Dict[str, str]], List[Tuple[str, str]]]:
    try:
        rows = conn.execute(
            """SELECT tombstone_id, source_id, conversation_id, selector_type
                 FROM corpus_tombstones
                 ORDER BY source_id, conversation_id"""
        ).fetchall()
    except sqlite3.DatabaseError as err:
        raise CorpusMigrationError(f"cannot read legacy corpus tombstones: {err}") from err
    selectors: List[Dict[str, str]] = []
    keys: List[Tuple[str, str]] = []
    seen: set[Tuple[str, str]] = set()
    for ordinal, (tombstone_id, source_id, conversation_id, selector_type) in enumerate(rows):
        tombstone_id = _text(tombstone_id, field=f"tombstone[{ordinal}].tombstone_id")
        source_id = _text(source_id, field=f"tombstone[{ordinal}].source_id")
        conversation_id = _text(
            conversation_id, field=f"tombstone[{ordinal}].conversation_id"
        )
        if selector_type != "conversation":
            raise CorpusMigrationError("legacy corpus has unsupported tombstone selector")
        selector = conversation_selector(
            source_id=source_id, conversation_id=conversation_id
        )
        if tombstone_id != selector["selector_id"]:
            raise CorpusMigrationError("legacy corpus tombstone digest mismatch")
        key = (source_id, conversation_id)
        if key in seen:
            raise CorpusMigrationError("duplicate legacy corpus tombstone selector")
        seen.add(key)
        keys.append(key)
        selectors.append(selector)
    return selectors, keys


def _validate_fts_rowids(
    conn: sqlite3.Connection,
    *,
    records_table: str,
    record_pk: str,
    fts_table: str,
) -> None:
    missing = conn.execute(
        f"""SELECT COUNT(*) FROM {records_table} r
              LEFT JOIN {fts_table} f ON f.rowid = r.{record_pk}
             WHERE f.rowid IS NULL"""
    ).fetchone()[0]
    extra = conn.execute(
        f"""SELECT COUNT(*) FROM {fts_table} f
              LEFT JOIN {records_table} r ON r.{record_pk} = f.rowid
             WHERE r.{record_pk} IS NULL"""
    ).fetchone()[0]
    if missing or extra:
        raise CorpusMigrationError(f"legacy {fts_table} rowids do not match source records")


def _validate_v2_snapshot(conn: sqlite3.Connection) -> Dict[str, Any]:
    try:
        conn.execute("PRAGMA query_only = ON")
        integrity = conn.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or integrity[0] != "ok":
            detail = "unknown" if integrity is None else str(integrity[0])
            raise CorpusMigrationError(
                f"legacy SQLite integrity check failed: {detail}"
            )
        _validate_required_schema(conn)
        meta = _read_meta(conn)
        foreign_key_errors = conn.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_key_errors:
            raise CorpusMigrationError("legacy corpus has foreign-key violations")

        selectors, tombstone_keys = _read_tombstones(conn)
        source_rows = conn.execute(
            """SELECT source_id, projection_sha256, conversation_count, message_count
                 FROM source_records ORDER BY source_id"""
        ).fetchall()
        source_states: List[Dict[str, Any]] = []
        for ordinal, row in enumerate(source_rows):
            source_id = _text(row[0], field=f"source[{ordinal}].source_id")
            projection_sha256 = _text(
                row[1], field=f"source[{ordinal}].projection_sha256"
            )
            conversation_count = _integer(
                row[2], field=f"source[{ordinal}].conversation_count"
            )
            message_count = _integer(row[3], field=f"source[{ordinal}].message_count")
            actual_conversations = conn.execute(
                "SELECT COUNT(*) FROM conversation_records WHERE source_id = ?",
                (source_id,),
            ).fetchone()[0]
            actual_messages = conn.execute(
                "SELECT COUNT(*) FROM message_records WHERE source_id = ?",
                (source_id,),
            ).fetchone()[0]
            if (conversation_count, message_count) != (
                actual_conversations,
                actual_messages,
            ):
                raise CorpusMigrationError("legacy source counts do not match corpus rows")
            source_states.append(
                {
                    "source_id": source_id,
                    "projection_sha256": projection_sha256,
                    "conversation_count": conversation_count,
                    "message_count": message_count,
                }
            )

        for source_id, conversation_id in tombstone_keys:
            if conn.execute(
                """SELECT 1 FROM conversation_records
                     WHERE source_id = ? AND conversation_id = ?""",
                (source_id, conversation_id),
            ).fetchone() is not None:
                raise CorpusMigrationError("legacy tombstoned conversation remains indexed")
            if conn.execute(
                """SELECT 1 FROM message_records
                     WHERE source_id = ? AND conversation_id = ?""",
                (source_id, conversation_id),
            ).fetchone() is not None:
                raise CorpusMigrationError("legacy tombstoned messages remain indexed")

        _validate_fts_rowids(
            conn,
            records_table="message_records",
            record_pk="message_pk",
            fts_table="message_fts",
        )
        _validate_fts_rowids(
            conn,
            records_table="message_text_leaf_records",
            record_pk="leaf_pk",
            fts_table="message_text_leaf_fts",
        )

        tombstone_rows = [
            {
                "tombstone_id": selector["selector_id"],
                "source_id": selector["source_id"],
                "conversation_id": selector["conversation_id"],
                "selector_type": selector["selector_type"],
            }
            for selector in selectors
        ]
        corpus_id = sha256(
            _stable_json(
                {"sources": source_states, "tombstones": tombstone_rows}
            ).encode("utf-8")
        ).hexdigest()
        if meta["corpus_id"] != corpus_id or meta["index_generation"] != corpus_id:
            raise CorpusMigrationError("legacy corpus identity metadata mismatch")

        return {
            "corpus_id": corpus_id,
            "index_generation": corpus_id,
            "source_count": len(source_states),
            "conversation_count": conn.execute(
                "SELECT COUNT(*) FROM conversation_records"
            ).fetchone()[0],
            "message_count": conn.execute(
                "SELECT COUNT(*) FROM message_records"
            ).fetchone()[0],
            "selectors": selectors,
        }
    except sqlite3.DatabaseError as err:
        raise CorpusMigrationError(f"cannot validate legacy corpus: {err}") from err
    except DeletionLedgerError as err:
        raise CorpusMigrationError(str(err)) from err


def _merge_selectors(
    *groups: Iterable[Mapping[str, Any]],
) -> List[Dict[str, str]]:
    merged: Dict[Tuple[str, str], Dict[str, str]] = {}
    for group in groups:
        for value in group:
            try:
                selector = conversation_selector(
                    source_id=value.get("source_id"),
                    conversation_id=value.get("conversation_id"),
                )
            except DeletionLedgerError as err:
                raise CorpusMigrationError(str(err)) from err
            if value.get("selector_type") != "conversation":
                raise CorpusMigrationError("unsupported deletion ledger selector")
            if value.get("selector_id") != selector["selector_id"]:
                raise CorpusMigrationError("deletion ledger selector digest mismatch")
            merged[(selector["source_id"], selector["conversation_id"])] = selector
    return [merged[key] for key in sorted(merged)]


def _publish_backup(staged_path: Path, target_path: Path) -> None:
    os.replace(staged_path, target_path)


def prepare_corpus_v2_rebuild(
    index_path: str,
    *,
    backup_path: str,
    ledger_path: Optional[str] = None,
    replace_backup: bool = False,
) -> Dict[str, Any]:
    """Seal a verified v2 snapshot and export its durable forget selectors.

    This is deliberately a pre-upgrade gate, not an in-place schema migration.
    The returned receipt is safe to use only after ``backup_published`` is true.
    The backup contains the private corpus and must be protected like the
    original index.  ``ledger_path`` defaults to ``<index>.deletions.json``.
    """

    if not isinstance(index_path, str) or not index_path:
        raise CorpusMigrationError("index_path must be a non-empty string")
    if not isinstance(backup_path, str) or not backup_path:
        raise CorpusMigrationError("backup_path must be a non-empty string")
    source = Path(index_path)
    backup = Path(backup_path)
    try:
        ledger = deletion_ledger_path(index_path, ledger_path)
    except DeletionLedgerError as err:
        raise CorpusMigrationError(str(err)) from err
    resolved = [_path_identity(path) for path in (source, backup, ledger)]
    if len(set(resolved)) != len(resolved):
        raise CorpusMigrationError("source, backup, and deletion ledger paths must differ")
    if source.is_symlink() or not source.is_file():
        raise CorpusMigrationError("legacy corpus index must be a regular non-symlink file")
    if backup.is_symlink() or ledger.is_symlink():
        raise CorpusMigrationError("migration artifacts must not be symlinks")
    if backup.exists() and not replace_backup:
        raise CorpusMigrationError("backup already exists; explicit replacement is required")

    backup.parent.mkdir(parents=True, exist_ok=True)
    descriptor, staged_name = tempfile.mkstemp(
        prefix="integrity-home-v2-backup-", suffix=".sqlite", dir=backup.parent
    )
    os.close(descriptor)
    staged = Path(staged_name)
    try:
        _private_mode(staged)
        try:
            with corpus_state_lock(index_path):
                source_conn = sqlite3.connect(_readonly_uri(source), uri=True)
                destination_conn: Optional[sqlite3.Connection] = None
                try:
                    destination_conn = sqlite3.connect(str(staged))
                    source_conn.backup(destination_conn)
                    destination_conn.commit()
                except sqlite3.DatabaseError as err:
                    raise CorpusMigrationError(
                        f"cannot create consistent legacy corpus snapshot: {err}"
                    ) from err
                finally:
                    source_conn.close()
                    if destination_conn is not None:
                        destination_conn.close()

                snapshot_conn = sqlite3.connect(_readonly_uri(staged), uri=True)
                try:
                    summary = _validate_v2_snapshot(snapshot_conn)
                finally:
                    snapshot_conn.close()

                try:
                    existing = load_deletion_ledger(
                        index_path, ledger_path=ledger_path, missing_ok=True
                    )
                except DeletionLedgerError as err:
                    raise CorpusMigrationError(str(err)) from err
                existing_selectors = [] if existing is None else existing["selectors"]
                selectors = _merge_selectors(
                    existing_selectors, summary["selectors"]
                )
                try:
                    ledger_payload = write_deletion_ledger(
                        index_path, selectors, ledger_path=ledger_path
                    )
                except DeletionLedgerError as err:
                    raise CorpusMigrationError(str(err)) from err
                _private_mode(ledger)

                snapshot_sha256 = _file_sha256(staged)
                _publish_backup(staged, backup)
                _private_mode(backup)
                _sync_parent_directory(backup.parent)
        except CorpusStateLockError as err:
            raise CorpusMigrationError(str(err)) from err

        return {
            "schema_version": CORPUS_V2_REBUILD_GATE_SCHEMA_VERSION,
            "source_schema_version": LEGACY_CORPUS_INDEX_SCHEMA_VERSION,
            "target_schema_version": CORPUS_INDEX_SCHEMA_VERSION,
            "corpus_id": summary["corpus_id"],
            "index_generation": summary["index_generation"],
            "source_count": summary["source_count"],
            "conversation_count": summary["conversation_count"],
            "message_count": summary["message_count"],
            "exported_tombstone_count": len(summary["selectors"]),
            "durable_tombstone_count": ledger_payload["selector_count"],
            "deletion_ledger_sha256": ledger_payload["ledger_sha256"],
            "snapshot_sha256": snapshot_sha256,
            "backup_private_content": True,
            "backup_published": True,
            "rebuild_required": True,
        }
    finally:
        staged.unlink(missing_ok=True)


__all__ = [
    "CORPUS_V2_REBUILD_GATE_SCHEMA_VERSION",
    "LEGACY_CORPUS_INDEX_SCHEMA_VERSION",
    "CorpusMigrationError",
    "prepare_corpus_v2_rebuild",
]
