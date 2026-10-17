"""Lossless message corpus and global lexical search for Chronicle.

The claim index is intentionally not used here: every canonical message is
stored verbatim (as UTF-8 bytes) and remains addressable even when no semantic
claim was derived from it.  One SQLite database may contain many source
projections.  Re-importing a source replaces only that source atomically.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import shlex
import sqlite3
import stat as stat_module
import tempfile
import threading
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeVar,
)
import unicodedata

from .deletion_ledger import (
    DeletionLedgerError,
    conversation_selector,
    deletion_ledger_path as resolve_deletion_ledger_path,
    load_deletion_ledger,
    write_deletion_ledger,
)
from .json_integrity import loads_json_strict
from .state_lock import corpus_state_lock


CORPUS_INDEX_SCHEMA_VERSION = "integrity-home-corpus-index/3"
CORPUS_SEARCH_SCHEMA_VERSION = "integrity-home-corpus-search/3"
CORPUS_INTEGRITY_SCHEMA_VERSION = "integrity-home-corpus-integrity/1"
CORPUS_HISTORY_SCAN_SCHEMA_VERSION = "integrity-home-corpus-history-scan/1"
DELETION_LEDGER_BINDING_META_KEY = "deletion_ledger_binding"
LOGICAL_INDEX_SEAL_META_KEY = "logical_index_sha256"
_ADJACENT_LEDGER_BINDING = "adjacent"
MAX_RESULTS = 500
MAX_CONTEXT_RADIUS = 10
MAX_CHILDREN = 20
MAX_MATCHED_TEXT_LEAVES = 100
MAX_INDEXED_TEXT_LEAF_CHARS = 1_000_000
MAX_SUBSTRING_SCAN_ROWS = 50_000
MAX_SYNTHETIC_ATTACHMENT_TEXT_CHARS = 1_000_000
_SEARCHABLE_SYNTHETIC_MEDIA_TYPES = {"text/plain", "text/markdown"}
_FTS_TABLES = (
    "conversation_title_fts",
    "message_text_leaf_fts",
    "message_fts",
)
_LOGICAL_INDEX_TABLES = {
    "attachment_records",
    "conversation_records",
    "corpus_meta",
    "corpus_tombstones",
    "message_records",
    "message_text_leaf_exclusions",
    "message_text_leaf_records",
    "source_records",
    "sqlite_sequence",
    *(
        f"{table}{suffix}"
        for table in _FTS_TABLES
        for suffix in ("", "_config", "_content", "_data", "_docsize", "_idx")
    ),
}
_ATTACHMENT_SEARCHABLE_METADATA_KEYS = {
    "attachment_id",
    "byte_length",
    "checksum",
    "content_type",
    "digest",
    "extension",
    "file_id",
    "file_name",
    "filename",
    "hash",
    "id",
    "json_pointer",
    "media_type",
    "mime_type",
    "name",
    "path",
    "pointer",
    "provider_attachment_id",
    "sha256",
    "size",
    "source_locator",
    "source_path",
    "type",
}


class CorpusIndexError(RuntimeError):
    """Raised when a canonical corpus cannot be stored or queried safely."""


_ResultT = TypeVar("_ResultT")
_FileIdentity = Tuple[int, int, int, int, int]


def _file_identity(path: Path, *, label: str) -> _FileIdentity:
    """Return the path identity used to invalidate long-lived readers."""

    try:
        state = path.stat()
    except OSError as err:
        raise CorpusIndexError(f"cannot stat {label}: {err}") from err
    if not stat_module.S_ISREG(state.st_mode):
        raise CorpusIndexError(f"{label} is not a regular file")
    return (
        int(state.st_dev),
        int(state.st_ino),
        int(state.st_size),
        int(state.st_mtime_ns),
        int(state.st_ctime_ns),
    )


def _enable_secure_delete(conn: sqlite3.Connection) -> None:
    """Enable and verify SQLite page scrubbing before staged deletions."""

    conn.execute("PRAGMA secure_delete = ON")
    row = conn.execute("PRAGMA secure_delete").fetchone()
    if row is None or row[0] != 1:
        raise CorpusIndexError("SQLite secure_delete could not be enabled")


def _enable_fts_secure_delete(conn: sqlite3.Connection) -> None:
    """Enable and verify FTS5 segment scrubbing before indexed deletions."""

    for table in _FTS_TABLES:
        conn.execute(
            f"INSERT INTO {table}({table}, rank) VALUES('secure-delete', 1)"
        )
        row = conn.execute(
            f"SELECT v FROM {table}_config WHERE k = 'secure-delete'"
        ).fetchone()
        if row is None or row[0] != 1:
            raise CorpusIndexError(
                f"SQLite FTS5 secure-delete could not be enabled for {table}"
            )


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
        raise CorpusIndexError(f"canonical value is not stable JSON: {err}") from err


def _utf8(value: str, *, field: str) -> bytes:
    try:
        return value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as err:
        raise CorpusIndexError(f"{field} is not valid UTF-8 text") from err


def _text(value: Any, *, field: str, optional: bool = False) -> Optional[str]:
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise CorpusIndexError(f"{field} must be a string")
    if not optional and not value:
        raise CorpusIndexError(f"{field} must not be empty")
    _utf8(value, field=field)
    return value


def _utc_filter_timestamp(value: Any, *, field: str) -> str:
    raw = _text(value, field=field)
    assert raw is not None
    candidate = raw.strip()
    if not candidate:
        raise CorpusIndexError(f"{field} must not be empty")
    try:
        parsed = datetime.fromisoformat(
            candidate[:-1] + "+00:00" if candidate.endswith("Z") else candidate
        )
    except (OverflowError, ValueError) as err:
        raise CorpusIndexError(
            f"{field} must be a timezone-aware ISO-8601 timestamp"
        ) from err
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CorpusIndexError(
            f"{field} must be a timezone-aware ISO-8601 timestamp"
        )
    return parsed.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _bool(value: Any, *, field: str, default: bool = False) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise CorpusIndexError(f"{field} must be a boolean")
    return value


def _integer(value: Any, *, field: str, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CorpusIndexError(f"{field} must be a non-negative integer")
    return value


def _normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    decomposed = unicodedata.normalize("NFD", normalized)
    normalized = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    # Keep exact text in the record; make control characters harmless token
    # boundaries only in the rebuildable FTS projection.
    normalized = "".join(
        " " if unicodedata.category(ch).startswith("C") else ch for ch in normalized
    )
    return " ".join(normalized.split())


def _projection_signature(projection: Dict[str, Any]) -> str:
    explicit = projection.get("projection_sha256")
    unsigned = dict(projection)
    unsigned.pop("projection_sha256", None)
    computed = sha256(_utf8(_stable_json(unsigned), field="projection")).hexdigest()
    if explicit is not None:
        if not isinstance(explicit, str) or not explicit:
            raise CorpusIndexError("projection_sha256 must be a non-empty string")
        if explicit != computed:
            raise CorpusIndexError("projection_sha256 does not match canonical projection")
    return computed


def _coerce_projections(
    projections: Dict[str, Any] | Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    if isinstance(projections, dict):
        values = [projections]
    elif isinstance(projections, Sequence) and not isinstance(projections, (str, bytes)):
        values = list(projections)
    else:
        raise CorpusIndexError("projections must be an object or a sequence of objects")
    if not values:
        raise CorpusIndexError("at least one projection is required")
    if any(not isinstance(item, dict) for item in values):
        raise CorpusIndexError("every projection must be an object")
    source_ids: set[str] = set()
    for index, projection in enumerate(values):
        source_id = _text(projection.get("source_id"), field=f"projection[{index}].source_id")
        assert source_id is not None
        if source_id in source_ids:
            raise CorpusIndexError(f"duplicate source_id in batch: {source_id}")
        source_ids.add(source_id)
    return sorted(values, key=lambda item: (str(item.get("provider", "")), str(item["source_id"])))


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS corpus_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS source_records (
            source_id TEXT PRIMARY KEY,
            provider TEXT NOT NULL,
            provider_schema_version TEXT NOT NULL,
            projection_sha256 TEXT NOT NULL,
            source_json BLOB NOT NULL,
            conversation_count INTEGER NOT NULL,
            message_count INTEGER NOT NULL,
            synthetic_fixture INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS conversation_records (
            conversation_pk INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id TEXT NOT NULL REFERENCES source_records(source_id) ON DELETE CASCADE,
            provider TEXT NOT NULL,
            provider_schema_version TEXT NOT NULL,
            conversation_id TEXT NOT NULL,
            provider_conversation_id TEXT NOT NULL,
            title_utf8 BLOB NOT NULL,
            title_norm TEXT NOT NULL,
            created_at TEXT,
            has_unknown_timestamp INTEGER NOT NULL,
            source_ordinal INTEGER NOT NULL,
            canonical_json BLOB NOT NULL,
            UNIQUE(source_id, conversation_id)
        );
        CREATE INDEX IF NOT EXISTS conversation_provider_idx
            ON conversation_records(provider, conversation_id);
        CREATE VIRTUAL TABLE IF NOT EXISTS conversation_title_fts USING fts5(
            title_norm,
            source_id UNINDEXED,
            conversation_id UNINDEXED
        );
        CREATE TABLE IF NOT EXISTS message_records (
            message_pk INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id TEXT NOT NULL UNIQUE,
            source_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            provider_schema_version TEXT NOT NULL,
            projection_sha256 TEXT NOT NULL,
            conversation_id TEXT NOT NULL,
            provider_conversation_id TEXT NOT NULL,
            conversation_ordinal INTEGER NOT NULL,
            message_id TEXT NOT NULL,
            message_ordinal INTEGER NOT NULL,
            parent_message_id TEXT,
            role TEXT NOT NULL,
            model TEXT,
            content_type TEXT NOT NULL,
            created_at TEXT,
            branch_path TEXT NOT NULL,
            branch_depth INTEGER NOT NULL,
            has_unknown_parent INTEGER NOT NULL,
            has_unknown_timestamp INTEGER NOT NULL,
            content_utf8 BLOB NOT NULL,
            content_norm TEXT NOT NULL,
            content_sha256 TEXT NOT NULL,
            canonical_json BLOB NOT NULL,
            provenance_json BLOB NOT NULL,
            FOREIGN KEY(source_id, conversation_id)
                REFERENCES conversation_records(source_id, conversation_id) ON DELETE CASCADE,
            UNIQUE(source_id, conversation_id, message_id)
        );
        CREATE INDEX IF NOT EXISTS message_filter_idx
            ON message_records(provider, source_id, conversation_id, role, model, content_type, created_at);
        CREATE INDEX IF NOT EXISTS message_parent_idx
            ON message_records(source_id, conversation_id, parent_message_id);
        CREATE TABLE IF NOT EXISTS attachment_records (
            attachment_pk INTEGER PRIMARY KEY AUTOINCREMENT,
            message_pk INTEGER NOT NULL REFERENCES message_records(message_pk) ON DELETE CASCADE,
            attachment_id TEXT NOT NULL,
            media_type TEXT NOT NULL,
            name TEXT NOT NULL,
            source_locator TEXT NOT NULL,
            searchable INTEGER NOT NULL,
            text_utf8 BLOB,
            text_sha256 TEXT,
            canonical_json BLOB NOT NULL,
            source_ordinal INTEGER NOT NULL,
            UNIQUE(message_pk, attachment_id)
        );
        CREATE TABLE IF NOT EXISTS message_text_leaf_records (
            leaf_pk INTEGER PRIMARY KEY AUTOINCREMENT,
            message_pk INTEGER NOT NULL REFERENCES message_records(message_pk) ON DELETE CASCADE,
            record_id TEXT NOT NULL,
            canonical_pointer TEXT NOT NULL,
            field_scope TEXT NOT NULL,
            value_utf8 BLOB NOT NULL,
            value_norm TEXT NOT NULL,
            value_sha256 TEXT NOT NULL,
            source_ordinal INTEGER NOT NULL,
            UNIQUE(message_pk, canonical_pointer)
        );
        CREATE INDEX IF NOT EXISTS message_text_leaf_record_idx
            ON message_text_leaf_records(record_id, source_ordinal);
        CREATE TABLE IF NOT EXISTS message_text_leaf_exclusions (
            exclusion_pk INTEGER PRIMARY KEY AUTOINCREMENT,
            message_pk INTEGER NOT NULL REFERENCES message_records(message_pk) ON DELETE CASCADE,
            canonical_pointer TEXT NOT NULL,
            reason TEXT NOT NULL,
            value_sha256 TEXT NOT NULL,
            byte_length INTEGER NOT NULL,
            UNIQUE(message_pk, canonical_pointer)
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS message_text_leaf_fts USING fts5(
            value_norm,
            record_id UNINDEXED,
            canonical_pointer UNINDEXED
        );
        CREATE TABLE IF NOT EXISTS corpus_tombstones (
            tombstone_id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            conversation_id TEXT NOT NULL,
            selector_type TEXT NOT NULL,
            UNIQUE(source_id, conversation_id)
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS message_fts USING fts5(
            content_norm,
            attachment_text_norm,
            conversation_title_norm,
            record_id UNINDEXED
        );
        """
    )


def _require_schema(conn: sqlite3.Connection) -> None:
    try:
        row = conn.execute(
            "SELECT value FROM corpus_meta WHERE key = 'schema_version'"
        ).fetchone()
    except sqlite3.DatabaseError as err:
        raise CorpusIndexError(f"cannot read corpus metadata: {err}") from err
    if row is None or row[0] != CORPUS_INDEX_SCHEMA_VERSION:
        raise CorpusIndexError("corpus index schema mismatch")


def _tombstone_id(*, source_id: str, conversation_id: str) -> str:
    payload = {
        "selector_type": "conversation",
        "source_id": source_id,
        "conversation_id": conversation_id,
    }
    return sha256(
        _utf8(_stable_json(payload), field="corpus tombstone")
    ).hexdigest()


def _validate_tombstone_state(conn: sqlite3.Connection) -> None:
    """Reject missing, malformed, or forged durable forget selectors."""

    try:
        rows = conn.execute(
            """SELECT tombstone_id, source_id, conversation_id, selector_type
                 FROM corpus_tombstones
                 ORDER BY source_id, conversation_id"""
        ).fetchall()
    except sqlite3.DatabaseError as err:
        raise CorpusIndexError(f"cannot read corpus tombstones: {err}") from err
    seen: set[tuple[str, str]] = set()
    for ordinal, row in enumerate(rows):
        tombstone_id, source_id, conversation_id, selector_type = row
        values = {
            "tombstone_id": tombstone_id,
            "source_id": source_id,
            "conversation_id": conversation_id,
            "selector_type": selector_type,
        }
        for field, value in values.items():
            if not isinstance(value, str) or not value:
                raise CorpusIndexError(
                    f"corpus tombstone {ordinal} has invalid {field}"
                )
        if selector_type != "conversation":
            raise CorpusIndexError(
                f"corpus tombstone {ordinal} has unsupported selector_type"
            )
        selector = (source_id, conversation_id)
        if selector in seen:
            raise CorpusIndexError("duplicate corpus tombstone selector")
        seen.add(selector)
        if tombstone_id != _tombstone_id(
            source_id=source_id, conversation_id=conversation_id
        ):
            raise CorpusIndexError("corpus tombstone digest mismatch")


def _validate_existing_index(conn: sqlite3.Connection) -> List[Tuple[str, str, str, str]]:
    """Validate an existing index and return identifier-only tombstone rows."""

    _require_schema(conn)
    _validate_tombstone_state(conn)
    integrity = conn.execute("PRAGMA integrity_check").fetchone()
    if integrity is None or integrity[0] != "ok":
        detail = "unknown" if integrity is None else str(integrity[0])
        raise CorpusIndexError(f"existing SQLite integrity check failed: {detail}")
    before = _summary(conn)
    for key in ("corpus_id", "index_generation"):
        row = conn.execute(
            "SELECT value FROM corpus_meta WHERE key = ?", (key,)
        ).fetchone()
        if row is None or row[0] != before[key]:
            raise CorpusIndexError(f"existing corpus metadata mismatch: {key}")
    return [
        (row[0], row[1], row[2], row[3])
        for row in conn.execute(
            """SELECT tombstone_id, source_id, conversation_id, selector_type
                 FROM corpus_tombstones
                 ORDER BY source_id, conversation_id"""
        ).fetchall()
    ]


def _canonical_path(path: Path) -> Path:
    """Return one stable absolute spelling for a local state path."""

    return path.expanduser().resolve(strict=False)


def _ledger_binding_value(index_path: str, ledger_path: Path) -> str:
    adjacent = _canonical_path(resolve_deletion_ledger_path(index_path))
    canonical = _canonical_path(ledger_path)
    if canonical == _canonical_path(Path(index_path)):
        raise CorpusIndexError("deletion ledger path must differ from corpus index")
    return _ADJACENT_LEDGER_BINDING if canonical == adjacent else str(canonical)


def _ledger_path_from_binding(index_path: str, binding: str) -> Path:
    if binding == _ADJACENT_LEDGER_BINDING:
        return _canonical_path(resolve_deletion_ledger_path(index_path))
    if not isinstance(binding, str) or not binding:
        raise CorpusIndexError("corpus deletion-ledger binding is invalid")
    candidate = Path(binding)
    if not candidate.is_absolute():
        raise CorpusIndexError("external deletion-ledger binding must be absolute")
    canonical = _canonical_path(candidate)
    if canonical == _canonical_path(Path(index_path)):
        raise CorpusIndexError("deletion ledger path must differ from corpus index")
    return canonical


def _bound_deletion_ledger_path(
    index_path: str,
    *,
    conn: Optional[sqlite3.Connection] = None,
) -> Path:
    """Resolve the authoritative ledger named by an index generation.

    The missing metadata fallback is retained only for already-created v3
    development indexes; every newly published generation writes the binding.
    """

    owns_connection = conn is None
    if conn is None:
        target = Path(index_path)
        if not target.is_file():
            return _canonical_path(resolve_deletion_ledger_path(index_path))
        try:
            conn = sqlite3.connect(_readonly_uri(target), uri=True)
        except sqlite3.DatabaseError as err:
            raise CorpusIndexError(f"cannot read corpus ledger binding: {err}") from err
    try:
        try:
            row = conn.execute(
                "SELECT value FROM corpus_meta WHERE key = ?",
                (DELETION_LEDGER_BINDING_META_KEY,),
            ).fetchone()
        except sqlite3.DatabaseError as err:
            raise CorpusIndexError(f"cannot read corpus ledger binding: {err}") from err
        binding = _ADJACENT_LEDGER_BINDING if row is None else row[0]
        return _ledger_path_from_binding(index_path, binding)
    finally:
        if owns_connection:
            assert conn is not None
            conn.close()


def _select_deletion_ledger_path(
    index_path: str,
    *,
    explicit_ledger_path: Optional[str],
) -> Path:
    """Select an immutable authoritative ledger for one corpus index."""

    target = Path(index_path)
    requested = (
        _canonical_path(resolve_deletion_ledger_path(index_path, explicit_ledger_path))
        if explicit_ledger_path is not None
        else None
    )
    if target.is_file():
        bound = _bound_deletion_ledger_path(index_path)
        if requested is not None and requested != bound:
            raise CorpusIndexError(
                "existing corpus is bound to a different deletion ledger"
            )
        return bound
    selected = (
        requested
        if requested is not None
        else _canonical_path(resolve_deletion_ledger_path(index_path))
    )
    _ledger_binding_value(index_path, selected)
    return selected


def _ledger_rows(
    index_path: str,
    *,
    missing_ok: bool,
    ledger_path: Optional[str] = None,
) -> Optional[List[Tuple[str, str, str, str]]]:
    try:
        ledger = load_deletion_ledger(
            index_path, ledger_path=ledger_path, missing_ok=missing_ok
        )
    except DeletionLedgerError as err:
        raise CorpusIndexError(str(err)) from err
    if ledger is None:
        return None
    return [
        (
            selector["selector_id"],
            selector["source_id"],
            selector["conversation_id"],
            selector["selector_type"],
        )
        for selector in ledger["selectors"]
    ]


def _ledger_snapshot(
    index_path: str, ledger_path: Path
) -> Tuple[_FileIdentity, List[Tuple[str, str, str, str]]]:
    """Read one validated, stable view of the authoritative ledger."""

    before = _file_identity(ledger_path, label="corpus deletion ledger")
    rows = _ledger_rows(
        index_path, missing_ok=False, ledger_path=str(ledger_path)
    )
    assert rows is not None
    after = _file_identity(ledger_path, label="corpus deletion ledger")
    if before != after:
        raise CorpusIndexError("corpus deletion ledger changed while being read")
    return after, rows


def _database_tombstone_rows(
    conn: sqlite3.Connection,
) -> List[Tuple[str, str, str, str]]:
    _validate_tombstone_state(conn)
    return [
        (row[0], row[1], row[2], row[3])
        for row in conn.execute(
            """SELECT tombstone_id, source_id, conversation_id, selector_type
                 FROM corpus_tombstones
                 ORDER BY source_id, conversation_id"""
        ).fetchall()
    ]


def _merge_tombstone_rows(
    *row_sets: Iterable[Tuple[str, str, str, str]],
) -> List[Tuple[str, str, str, str]]:
    merged: Dict[Tuple[str, str], Tuple[str, str, str, str]] = {}
    for rows in row_sets:
        for tombstone_id, source_id, conversation_id, selector_type in rows:
            if selector_type != "conversation":
                raise CorpusIndexError("unsupported durable deletion selector")
            expected = _tombstone_id(
                source_id=source_id, conversation_id=conversation_id
            )
            if tombstone_id != expected:
                raise CorpusIndexError("durable deletion selector digest mismatch")
            merged[(source_id, conversation_id)] = (
                tombstone_id,
                source_id,
                conversation_id,
                selector_type,
            )
    return [merged[key] for key in sorted(merged)]


def _write_ledger_rows(
    index_path: str,
    rows: Iterable[Tuple[str, str, str, str]],
    *,
    ledger_path: Optional[str] = None,
) -> Dict[str, Any]:
    selectors = [
        conversation_selector(source_id=row[1], conversation_id=row[2])
        for row in rows
    ]
    try:
        return write_deletion_ledger(
            index_path, selectors, ledger_path=ledger_path
        )
    except DeletionLedgerError as err:
        raise CorpusIndexError(str(err)) from err


def _readonly_uri(path: Path) -> str:
    return f"{path.resolve().as_uri()}?mode=ro"


def _publish_index_file(staged_path: Path, target_path: Path) -> None:
    """Single injectable publication point for the disposable SQLite file."""

    os.replace(staged_path, target_path)


def _open_readonly_index(
    index_path: str, *, row_factory: bool = False
) -> sqlite3.Connection:
    target = Path(index_path)
    if not target.is_file():
        raise CorpusIndexError("corpus index does not exist")
    try:
        conn = sqlite3.connect(_readonly_uri(target), uri=True)
        if row_factory:
            conn.row_factory = sqlite3.Row
        database_rows = _validate_existing_index(conn)
        ledger_path = _bound_deletion_ledger_path(index_path, conn=conn)
        ledger_rows = _ledger_rows(
            index_path, missing_ok=False, ledger_path=str(ledger_path)
        )
        assert ledger_rows is not None
        if database_rows != ledger_rows:
            raise CorpusIndexError(
                "deletion ledger and corpus index disagree; recovery is required"
            )
        return conn
    except (sqlite3.DatabaseError, CorpusIndexError):
        if "conn" in locals():
            conn.close()
        raise


def _json_pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _text_leaf_rows(
    value: Any,
    *,
    base_pointer: str,
    searchable_attachment_text_segments: Set[Tuple[str, ...]],
    attachment_alias_sha256s: Set[str],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Return every string leaf with its exact RFC 6901 JSON pointer.

    Imported strings are indexed as inert evidence only.  They are never
    executed, interpreted as instructions, or promoted into authoritative
    memory by this layer.
    """

    rows: List[Dict[str, Any]] = []
    exclusions: List[Dict[str, Any]] = []
    attachment_payload_keys = {
        "base64", "blob", "body", "bytes", "content", "data",
        "encoded", "encoded_data", "payload", "text", "transcript",
    }
    binary_payload_keys = {"base64", "blob", "bytes", "data", "encoded", "encoded_data"}

    def visit(
        node: Any,
        pointer: str,
        top_scope: str,
        segments: List[str],
        attachment_alias_depth: Optional[int] = None,
    ) -> None:
        if isinstance(node, str):
            encoded = _utf8(node, field=f"text leaf {pointer}")
            leaf_key = segments[-1].casefold() if segments else ""
            attachment_index = None
            if top_scope == "attachments" and len(segments) >= 2:
                try:
                    attachment_index = int(segments[1])
                except ValueError:
                    attachment_index = None
            alias_segments = (
                segments[attachment_alias_depth:]
                if attachment_alias_depth is not None
                else []
            )
            reason = None
            if len(node) > MAX_INDEXED_TEXT_LEAF_CHARS:
                reason = "oversized_text_leaf"
            elif leaf_key in binary_payload_keys:
                reason = "encoded_or_binary_payload"
            elif attachment_index is not None:
                attachment_path = tuple(segments)
                direct_metadata_leaf = len(segments) == 3
                wrapped_metadata_leaf = (
                    len(segments) == 4 and segments[2] == "metadata"
                )
                if attachment_path in searchable_attachment_text_segments:
                    pass
                elif leaf_key in attachment_payload_keys:
                    reason = "attachment_payload_requires_explicit_gate"
                elif not (direct_metadata_leaf or wrapped_metadata_leaf):
                    reason = "attachment_non_allowlisted_text"
                elif leaf_key not in _ATTACHMENT_SEARCHABLE_METADATA_KEYS:
                    reason = "attachment_non_allowlisted_text"
            elif attachment_alias_depth is not None:
                direct_metadata_leaf = len(alias_segments) == 1
                wrapped_metadata_leaf = (
                    len(alias_segments) == 2 and alias_segments[0] == "metadata"
                )
                if leaf_key in attachment_payload_keys:
                    reason = "attachment_payload_requires_explicit_gate"
                elif not (direct_metadata_leaf or wrapped_metadata_leaf):
                    reason = "attachment_non_allowlisted_text"
                elif leaf_key not in _ATTACHMENT_SEARCHABLE_METADATA_KEYS:
                    reason = "attachment_non_allowlisted_text"
            if reason is not None:
                exclusions.append(
                    {
                        "canonical_pointer": pointer,
                        "reason": reason,
                        "value_sha256": sha256(encoded).hexdigest(),
                        "byte_length": len(encoded),
                    }
                )
                return
            rows.append(
                {
                    "canonical_pointer": pointer,
                    "field_scope": top_scope,
                    "value_utf8": encoded,
                    "value_norm": _normalize_text(node),
                    "value_sha256": sha256(encoded).hexdigest(),
                    "source_ordinal": len(rows),
                }
            )
            return
        if isinstance(node, list):
            for index, item in enumerate(node):
                visit(
                    item,
                    f"{pointer}/{index}",
                    top_scope,
                    [*segments, str(index)],
                    attachment_alias_depth,
                )
            return
        if isinstance(node, dict):
            for key in node:
                if not isinstance(key, str):
                    raise CorpusIndexError(f"non-string canonical key at {pointer}")
            if attachment_alias_depth is None:
                alias_digest = sha256(
                    _utf8(_stable_json(node), field=f"attachment alias {pointer}")
                ).hexdigest()
                if alias_digest in attachment_alias_sha256s:
                    attachment_alias_depth = len(segments)
            for key in sorted(node):
                scope = top_scope or key
                visit(
                    node[key],
                    f"{pointer}/{_json_pointer_token(key)}",
                    scope,
                    [*segments, key],
                    attachment_alias_depth,
                )

    if not isinstance(value, dict):
        raise CorpusIndexError("canonical message must be an object")
    for key in sorted(value):
        if not isinstance(key, str):
            raise CorpusIndexError(f"non-string canonical message key: {key!r}")
        visit(
            value[key],
            f"{base_pointer}/{_json_pointer_token(key)}",
            key,
            [key],
            None,
        )
    return rows, exclusions


def _attachment_rows(
    message: Dict[str, Any],
    *,
    synthetic_source: bool,
    allow_synthetic_attachment_text: bool,
    field_prefix: str,
) -> Tuple[List[Dict[str, Any]], str]:
    raw = message.get("attachments", [])
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise CorpusIndexError(f"{field_prefix}.attachments must be a list")
    rows: List[Dict[str, Any]] = []
    seen: set[str] = set()
    searchable_parts: List[str] = []
    for index, attachment in enumerate(raw):
        prefix = f"{field_prefix}.attachments[{index}]"
        if not isinstance(attachment, dict):
            raise CorpusIndexError(f"{prefix} must be an object")
        canonical = _stable_json(attachment)
        metadata = attachment.get("metadata")
        if metadata is None:
            metadata = attachment
            text_segments = ("attachments", str(index), "text")
        else:
            text_segments = ("attachments", str(index), "metadata", "text")
        if not isinstance(metadata, dict):
            raise CorpusIndexError(f"{prefix}.metadata must be an object")
        alias_object_sha256s = sorted(
            {
                sha256(_utf8(canonical, field=prefix)).hexdigest(),
                sha256(
                    _utf8(_stable_json(metadata), field=f"{prefix}.metadata")
                ).hexdigest(),
            }
        )
        base_id = (
            attachment.get("attachment_id")
            or attachment.get("id")
            or metadata.get("attachment_id")
            or metadata.get("id")
            or metadata.get("file_id")
        )
        if base_id is None:
            base_id = f"attachment-{sha256(_utf8(canonical, field=prefix)).hexdigest()[:16]}"
        attachment_id = _text(base_id, field=f"{prefix}.attachment_id")
        assert attachment_id is not None
        if attachment_id in seen:
            raise CorpusIndexError(f"duplicate attachment_id in message: {attachment_id}")
        seen.add(attachment_id)
        media_type = attachment.get(
            "media_type",
            attachment.get(
                "content_type",
                metadata.get("media_type", metadata.get("content_type", metadata.get("mime_type", ""))),
            ),
        )
        media_type = _text(media_type, field=f"{prefix}.media_type", optional=True) or ""
        name = _text(
            attachment.get("name", metadata.get("name", metadata.get("filename", ""))),
            field=f"{prefix}.name",
            optional=True,
        ) or ""
        locator = _text(
            attachment.get(
                "source_locator",
                attachment.get("source_path", metadata.get("path", "")),
            ),
            field=f"{prefix}.source_locator",
            optional=True,
        ) or ""
        text_value = metadata.get("text")
        fixture_marked = metadata.get("synthetic_text_fixture") is True
        searchable = bool(
            allow_synthetic_attachment_text
            and synthetic_source
            and fixture_marked
            and media_type.casefold() in _SEARCHABLE_SYNTHETIC_MEDIA_TYPES
        )
        if searchable:
            if not isinstance(text_value, str):
                raise CorpusIndexError(f"{prefix}.text must be a string")
            if len(text_value) > MAX_SYNTHETIC_ATTACHMENT_TEXT_CHARS:
                raise CorpusIndexError(f"{prefix}.text exceeds synthetic fixture limit")
            text_bytes = _utf8(text_value, field=f"{prefix}.text")
            searchable_parts.append(text_value)
        else:
            text_bytes = None
        rows.append(
            {
                "attachment_id": attachment_id,
                "media_type": media_type,
                "name": name,
                "source_locator": locator,
                "searchable": searchable,
                "text_utf8": text_bytes,
                "text_sha256": sha256(text_bytes).hexdigest() if text_bytes is not None else None,
                "searchable_text_segments": text_segments if searchable else None,
                "alias_object_sha256s": alias_object_sha256s,
                "canonical_json": _utf8(canonical, field=prefix),
                "source_ordinal": index,
            }
        )
    return rows, "\n\n".join(searchable_parts)


def _delete_source(conn: sqlite3.Connection, source_id: str) -> None:
    conversation_pks = [
        row[0]
        for row in conn.execute(
            "SELECT conversation_pk FROM conversation_records WHERE source_id = ?",
            (source_id,),
        ).fetchall()
    ]
    if conversation_pks:
        conn.executemany(
            "DELETE FROM conversation_title_fts WHERE rowid = ?",
            ((pk,) for pk in conversation_pks),
        )
    pks = [
        row[0]
        for row in conn.execute(
            "SELECT message_pk FROM message_records WHERE source_id = ?", (source_id,)
        ).fetchall()
    ]
    if pks:
        conn.executemany("DELETE FROM message_fts WHERE rowid = ?", ((pk,) for pk in pks))
        leaf_pks = [
            row[0]
            for row in conn.execute(
                """SELECT l.leaf_pk
                     FROM message_text_leaf_records l
                     JOIN message_records m ON m.message_pk = l.message_pk
                     WHERE m.source_id = ?""",
                (source_id,),
            ).fetchall()
        ]
        if leaf_pks:
            conn.executemany(
                "DELETE FROM message_text_leaf_fts WHERE rowid = ?",
                ((pk,) for pk in leaf_pks),
            )
    conn.execute("DELETE FROM source_records WHERE source_id = ?", (source_id,))


def _insert_projection(
    conn: sqlite3.Connection,
    projection: Dict[str, Any],
    *,
    allow_synthetic_attachment_text: bool,
) -> None:
    source_id = _text(projection.get("source_id"), field="projection.source_id")
    provider = _text(projection.get("provider"), field="projection.provider")
    provider_schema = _text(
        projection.get("provider_schema_version", ""),
        field="projection.provider_schema_version",
        optional=True,
    ) or ""
    assert source_id is not None and provider is not None
    signature = _projection_signature(projection)
    conversations = projection.get("conversations")
    if not isinstance(conversations, list):
        raise CorpusIndexError("projection.conversations must be a list")
    synthetic_source = projection.get("synthetic_fixture") is True
    tombstoned_conversations = {
        row[0]
        for row in conn.execute(
            "SELECT conversation_id FROM corpus_tombstones WHERE source_id = ?",
            (source_id,),
        ).fetchall()
    }

    _delete_source(conn, source_id)
    source_summary = {
        key: value
        for key, value in projection.items()
        if key not in {"conversations", "claims", "message_duplicate_candidates"}
    }
    conn.execute(
        """
        INSERT INTO source_records(
            source_id, provider, provider_schema_version, projection_sha256,
            source_json, conversation_count, message_count, synthetic_fixture
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            source_id,
            provider,
            provider_schema,
            signature,
            _utf8(_stable_json(source_summary), field="projection source metadata"),
            0,
            0,
            1 if synthetic_source else 0,
        ),
    )

    seen_conversations: set[str] = set()
    actual_message_count = 0
    source_payload_message_count = 0
    inserted_conversation_count = 0
    for conversation_index, conversation in enumerate(conversations):
        cp = f"projection.conversations[{conversation_index}]"
        if not isinstance(conversation, dict):
            raise CorpusIndexError(f"{cp} must be an object")
        conversation_id = _text(conversation.get("conversation_id"), field=f"{cp}.conversation_id")
        assert conversation_id is not None
        if conversation_id in seen_conversations:
            raise CorpusIndexError(f"duplicate conversation_id in source: {conversation_id}")
        seen_conversations.add(conversation_id)
        provider_conversation_id = _text(
            conversation.get("provider_conversation_id", conversation_id),
            field=f"{cp}.provider_conversation_id",
        )
        title = _text(conversation.get("title", ""), field=f"{cp}.title", optional=True) or ""
        created_at = _text(
            conversation.get("created_at"), field=f"{cp}.created_at", optional=True
        )
        unknown_timestamp = _bool(
            conversation.get("has_unknown_timestamp"),
            field=f"{cp}.has_unknown_timestamp",
            default=created_at is None,
        )
        messages = conversation.get("messages")
        if not isinstance(messages, list):
            raise CorpusIndexError(f"{cp}.messages must be a list")
        declared_count = conversation.get("message_count")
        if declared_count is not None and _integer(
            declared_count, field=f"{cp}.message_count"
        ) != len(messages):
            raise CorpusIndexError(f"{cp}.message_count does not match messages")
        source_payload_message_count += len(messages)
        if conversation_id in tombstoned_conversations:
            continue
        conn.execute(
            """
            INSERT INTO conversation_records(
                source_id, provider, provider_schema_version, conversation_id,
                provider_conversation_id, title_utf8, title_norm, created_at,
                has_unknown_timestamp, source_ordinal, canonical_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                provider,
                provider_schema,
                conversation_id,
                provider_conversation_id,
                _utf8(title, field=f"{cp}.title"),
                _normalize_text(title),
                created_at,
                1 if unknown_timestamp else 0,
                conversation_index,
                _utf8(_stable_json(conversation), field=cp),
            ),
        )
        conversation_pk = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            """INSERT INTO conversation_title_fts(
                   rowid, title_norm, source_id, conversation_id
               ) VALUES (?, ?, ?, ?)""",
            (conversation_pk, _normalize_text(title), source_id, conversation_id),
        )
        inserted_conversation_count += 1
        seen_messages: set[str] = set()
        for message_index, message in enumerate(messages):
            mp = f"{cp}.messages[{message_index}]"
            if not isinstance(message, dict):
                raise CorpusIndexError(f"{mp} must be an object")
            message_id = _text(message.get("message_id"), field=f"{mp}.message_id")
            assert message_id is not None
            if message_id in seen_messages:
                raise CorpusIndexError(
                    f"duplicate message_id in conversation {conversation_id}: {message_id}"
                )
            seen_messages.add(message_id)
            parent_id = _text(
                message.get("parent_message_id"), field=f"{mp}.parent_message_id", optional=True
            )
            role = _text(message.get("role"), field=f"{mp}.role")
            content_value = message.get("content")
            if not isinstance(content_value, str):
                raise CorpusIndexError(f"{mp}.content must be a string")
            content = _text(content_value, field=f"{mp}.content", optional=True)
            content_type = _text(message.get("content_type"), field=f"{mp}.content_type")
            model = _text(message.get("model"), field=f"{mp}.model", optional=True)
            message_created_at = _text(
                message.get("created_at"), field=f"{mp}.created_at", optional=True
            )
            branch_path = _text(
                message.get("branch_path", message_id), field=f"{mp}.branch_path"
            )
            branch_depth = _integer(
                message.get("branch_depth"), field=f"{mp}.branch_depth", default=0
            )
            unknown_parent = _bool(
                message.get("has_unknown_parent"), field=f"{mp}.has_unknown_parent"
            )
            message_unknown_timestamp = _bool(
                message.get("has_unknown_timestamp"),
                field=f"{mp}.has_unknown_timestamp",
                default=message_created_at is None,
            )
            assert role is not None and content is not None and content_type is not None
            assert branch_path is not None and provider_conversation_id is not None
            content_bytes = _utf8(content, field=f"{mp}.content")
            canonical = _stable_json(message)
            pointer = f"/conversations/{conversation_index}/messages/{message_index}"
            locator = {
                "source_id": source_id,
                "provider": provider,
                "provider_schema_version": provider_schema,
                "projection_sha256": signature,
                "conversation_id": conversation_id,
                "provider_conversation_id": provider_conversation_id,
                "conversation_index": conversation_index,
                "message_id": message_id,
                "message_index": message_index,
                "canonical_pointer": pointer,
            }
            record_id = sha256(_utf8(_stable_json(locator), field="message locator")).hexdigest()
            locator["record_id"] = record_id
            attachment_rows, attachment_text = _attachment_rows(
                message,
                synthetic_source=synthetic_source,
                allow_synthetic_attachment_text=allow_synthetic_attachment_text,
                field_prefix=mp,
            )
            conn.execute(
                """
                INSERT INTO message_records(
                    record_id, source_id, provider, provider_schema_version,
                    projection_sha256, conversation_id, provider_conversation_id,
                    conversation_ordinal, message_id, message_ordinal,
                    parent_message_id, role, model, content_type, created_at,
                    branch_path, branch_depth, has_unknown_parent,
                    has_unknown_timestamp, content_utf8, content_norm,
                    content_sha256, canonical_json, provenance_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record_id,
                    source_id,
                    provider,
                    provider_schema,
                    signature,
                    conversation_id,
                    provider_conversation_id,
                    conversation_index,
                    message_id,
                    message_index,
                    parent_id,
                    role,
                    model,
                    content_type,
                    message_created_at,
                    branch_path,
                    branch_depth,
                    1 if unknown_parent else 0,
                    1 if message_unknown_timestamp else 0,
                    content_bytes,
                    _normalize_text(content),
                    sha256(content_bytes).hexdigest(),
                    _utf8(canonical, field=mp),
                    _utf8(_stable_json(locator), field="message locator"),
                ),
            )
            message_pk = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            text_leaves, excluded_leaves = _text_leaf_rows(
                message,
                base_pointer=pointer,
                searchable_attachment_text_segments={
                    attachment["searchable_text_segments"]
                    for attachment in attachment_rows
                    if attachment["searchable_text_segments"] is not None
                },
                attachment_alias_sha256s={
                    alias_sha256
                    for attachment in attachment_rows
                    for alias_sha256 in attachment["alias_object_sha256s"]
                },
            )
            for leaf in text_leaves:
                conn.execute(
                    """INSERT INTO message_text_leaf_records(
                           message_pk, record_id, canonical_pointer, field_scope,
                           value_utf8, value_norm, value_sha256, source_ordinal
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        message_pk,
                        record_id,
                        leaf["canonical_pointer"],
                        leaf["field_scope"],
                        leaf["value_utf8"],
                        leaf["value_norm"],
                        leaf["value_sha256"],
                        leaf["source_ordinal"],
                    ),
                )
                leaf_pk = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                conn.execute(
                    """INSERT INTO message_text_leaf_fts(
                           rowid, value_norm, record_id, canonical_pointer
                       ) VALUES (?, ?, ?, ?)""",
                    (
                        leaf_pk,
                        leaf["value_norm"],
                        record_id,
                        leaf["canonical_pointer"],
                    ),
                )
            for exclusion in excluded_leaves:
                conn.execute(
                    """INSERT INTO message_text_leaf_exclusions(
                           message_pk, canonical_pointer, reason,
                           value_sha256, byte_length
                       ) VALUES (?, ?, ?, ?, ?)""",
                    (
                        message_pk,
                        exclusion["canonical_pointer"],
                        exclusion["reason"],
                        exclusion["value_sha256"],
                        exclusion["byte_length"],
                    ),
                )
            conn.execute(
                """INSERT INTO message_fts(
                    rowid, content_norm, attachment_text_norm,
                    conversation_title_norm, record_id
                ) VALUES (?, ?, ?, ?, ?)""",
                (
                    message_pk,
                    _normalize_text(content),
                    _normalize_text(attachment_text),
                    "",
                    record_id,
                ),
            )
            for attachment in attachment_rows:
                conn.execute(
                    """
                    INSERT INTO attachment_records(
                        message_pk, attachment_id, media_type, name,
                        source_locator, searchable, text_utf8, text_sha256,
                        canonical_json, source_ordinal
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        message_pk,
                        attachment["attachment_id"],
                        attachment["media_type"],
                        attachment["name"],
                        attachment["source_locator"],
                        1 if attachment["searchable"] else 0,
                        attachment["text_utf8"],
                        attachment["text_sha256"],
                        attachment["canonical_json"],
                        attachment["source_ordinal"],
                    ),
                )
            actual_message_count += 1

    declared_source_count = projection.get("conversation_count")
    if declared_source_count is not None and _integer(
        declared_source_count, field="projection.conversation_count"
    ) != len(conversations):
        raise CorpusIndexError("projection.conversation_count does not match conversations")
    declared_messages = projection.get("message_count")
    if declared_messages is not None and _integer(
        declared_messages, field="projection.message_count"
    ) != source_payload_message_count:
        raise CorpusIndexError("projection.message_count does not match conversations")
    conn.execute(
        """UPDATE source_records
             SET conversation_count = ?, message_count = ?
             WHERE source_id = ?""",
        (inserted_conversation_count, actual_message_count, source_id),
    )


def _summary(conn: sqlite3.Connection) -> Dict[str, Any]:
    source_rows = conn.execute(
        """SELECT source_id, projection_sha256, conversation_count, message_count
             FROM source_records ORDER BY source_id"""
    ).fetchall()
    source_states = [
        {
            "source_id": row[0],
            "projection_sha256": row[1],
            "conversation_count": row[2],
            "message_count": row[3],
        }
        for row in source_rows
    ]
    tombstones = [
        {
            "tombstone_id": row[0],
            "source_id": row[1],
            "conversation_id": row[2],
            "selector_type": row[3],
        }
        for row in conn.execute(
            """SELECT tombstone_id, source_id, conversation_id, selector_type
                 FROM corpus_tombstones
                 ORDER BY source_id, conversation_id"""
        ).fetchall()
    ]
    tombstone_digest = sha256(
        _utf8(_stable_json(tombstones), field="corpus tombstones")
    ).hexdigest()
    digest_payload = {"sources": source_states, "tombstones": tombstones}
    corpus_id = sha256(
        _utf8(_stable_json(digest_payload), field="corpus identity")
    ).hexdigest()
    source_count = len(source_rows)
    conversation_count = conn.execute("SELECT COUNT(*) FROM conversation_records").fetchone()[0]
    message_count = conn.execute("SELECT COUNT(*) FROM message_records").fetchone()[0]
    return {
        "schema_version": CORPUS_INDEX_SCHEMA_VERSION,
        "corpus_id": corpus_id,
        "index_generation": corpus_id,
        "source_count": source_count,
        "conversation_count": conversation_count,
        "message_count": message_count,
        "tombstone_count": len(tombstones),
        "tombstone_digest": tombstone_digest,
        "deletion_ledger_digest": tombstone_digest,
    }


def _quoted_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _logical_index_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {
            "type": "bytes",
            "size": len(value),
            "sha256": sha256(value).hexdigest(),
        }
    if value is None or isinstance(value, (int, float, str)):
        return value
    raise CorpusIndexError(
        f"unsupported SQLite value in logical index seal: {type(value).__name__}"
    )


def _logical_index_sha256(conn: sqlite3.Connection) -> str:
    """Hash all query-bearing rows and physical FTS state without loading it all."""

    digest = sha256(b"integrity-home-logical-index/1\n")
    schema_rows = conn.execute(
        """SELECT type, name, tbl_name, sql
             FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_autoindex_%'
            ORDER BY type, name"""
    ).fetchall()
    table_names = {row[1] for row in schema_rows if row[0] == "table"}
    if table_names != _LOGICAL_INDEX_TABLES:
        raise CorpusIndexError("logical index schema table set mismatch")
    for row in schema_rows:
        digest.update(
            _utf8(
                _stable_json([_logical_index_value(value) for value in row]),
                field="logical index schema",
            )
        )
        digest.update(b"\n")

    for table in sorted(_LOGICAL_INDEX_TABLES):
        quoted_table = _quoted_identifier(table)
        columns = conn.execute(f"PRAGMA table_info({quoted_table})").fetchall()
        if not columns:
            raise CorpusIndexError(f"logical index table has no columns: {table}")
        column_names = [str(row[1]) for row in columns]
        quoted_columns = ", ".join(
            _quoted_identifier(column) for column in column_names
        )
        primary_key_columns = [
            str(row[1])
            for row in sorted(columns, key=lambda item: int(item[5]) or 1 << 30)
            if int(row[5]) > 0
        ]
        order_columns = primary_key_columns or ["rowid"]
        order_by = ", ".join(_quoted_identifier(column) for column in order_columns)
        where = (
            f" WHERE {_quoted_identifier('key')} != ?"
            if table == "corpus_meta"
            else ""
        )
        parameters: Tuple[Any, ...] = (
            (LOGICAL_INDEX_SEAL_META_KEY,) if table == "corpus_meta" else ()
        )
        digest.update(_utf8(table, field="logical index table"))
        digest.update(b"\n")
        cursor = conn.execute(
            f"SELECT {quoted_columns} FROM {quoted_table}{where} ORDER BY {order_by}",
            parameters,
        )
        for row in cursor:
            digest.update(
                _utf8(
                    _stable_json([_logical_index_value(value) for value in row]),
                    field="logical index row",
                )
            )
            digest.update(b"\n")
    return digest.hexdigest()


def _store_logical_index_seal(conn: sqlite3.Connection) -> str:
    value = _logical_index_sha256(conn)
    conn.execute(
        "INSERT OR REPLACE INTO corpus_meta(key, value) VALUES (?, ?)",
        (LOGICAL_INDEX_SEAL_META_KEY, value),
    )
    return value


def _logical_index_seal_matches(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT value FROM corpus_meta WHERE key = ?",
        (LOGICAL_INDEX_SEAL_META_KEY,),
    ).fetchone()
    return bool(
        row is not None
        and isinstance(row[0], str)
        and row[0]
        and row[0] == _logical_index_sha256(conn)
    )


def _apply_tombstone_rows(
    conn: sqlite3.Connection,
    rows: Iterable[Tuple[str, str, str, str]],
) -> None:
    affected_sources: set[str] = set()
    for tombstone_id, source_id, conversation_id, selector_type in rows:
        conn.execute(
            """INSERT OR IGNORE INTO corpus_tombstones(
                   tombstone_id, source_id, conversation_id, selector_type
               ) VALUES (?, ?, ?, ?)""",
            (tombstone_id, source_id, conversation_id, selector_type),
        )
        if conn.execute(
            "SELECT 1 FROM source_records WHERE source_id = ?", (source_id,)
        ).fetchone() is not None:
            _delete_indexed_conversation(
                conn, source_id=source_id, conversation_id=conversation_id
            )
            affected_sources.add(source_id)
    for source_id in affected_sources:
        conversation_count = conn.execute(
            "SELECT COUNT(*) FROM conversation_records WHERE source_id = ?",
            (source_id,),
        ).fetchone()[0]
        message_count = conn.execute(
            "SELECT COUNT(*) FROM message_records WHERE source_id = ?",
            (source_id,),
        ).fetchone()[0]
        conn.execute(
            """UPDATE source_records
                 SET conversation_count = ?, message_count = ?
                 WHERE source_id = ?""",
            (conversation_count, message_count, source_id),
        )


def _attachment_gate_cannot_change_projection(projection: Dict[str, Any]) -> bool:
    """Return whether the attachment-text flag is provably irrelevant.

    Non-synthetic sources can never opt into fixture attachment text. For a
    synthetic source, a malformed structure or any attachment is handled by
    the normal replacement path because the prior flag is not persisted in
    schema v3 and therefore cannot be inferred safely.
    """

    if projection.get("synthetic_fixture") is not True:
        return True
    conversations = projection.get("conversations")
    if not isinstance(conversations, list):
        return False
    for conversation in conversations:
        if not isinstance(conversation, dict):
            return False
        messages = conversation.get("messages")
        if not isinstance(messages, list):
            return False
        for message in messages:
            if not isinstance(message, dict):
                return False
            attachments = message.get("attachments", [])
            if attachments not in (None, []):
                return False
    return True


def _identical_upsert_summary(
    conn: sqlite3.Connection,
    values: Sequence[Dict[str, Any]],
    *,
    database_tombstones: List[Tuple[str, str, str, str]],
    ledger_tombstones: List[Tuple[str, str, str, str]],
) -> Optional[Dict[str, Any]]:
    """Return the unchanged summary only for a fully proven no-op upsert."""

    if database_tombstones != ledger_tombstones:
        return None
    if not _logical_index_seal_matches(conn):
        return None
    stored = {
        row[0]: (row[1], bool(row[2]))
        for row in conn.execute(
            """SELECT source_id, projection_sha256, synthetic_fixture
                 FROM source_records"""
        ).fetchall()
    }
    for projection in values:
        source_id = _text(projection.get("source_id"), field="projection.source_id")
        assert source_id is not None
        expected = stored.get(source_id)
        if expected is None:
            return None
        signature = _projection_signature(projection)
        if expected != (signature, projection.get("synthetic_fixture") is True):
            return None
        if not _attachment_gate_cannot_change_projection(projection):
            return None
    return _summary(conn)


def _atomic_update_locked(
    projections: Dict[str, Any] | Sequence[Dict[str, Any]],
    index_path: str,
    *,
    preserve_existing: bool,
    allow_synthetic_attachment_text: bool,
    authoritative_ledger_path: Path,
    require_existing_ledger: bool,
) -> Dict[str, Any]:
    values = _coerce_projections(projections)
    if not index_path:
        raise CorpusIndexError("index_path is required")
    target = Path(index_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix="chronicle-corpus-", suffix=".sqlite", dir=target.parent
    )
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        existing_target = target.is_file()
        ledger_identity: Optional[_FileIdentity] = None
        if require_existing_ledger:
            ledger_identity, ledger_tombstones = _ledger_snapshot(
                index_path, authoritative_ledger_path
            )
        else:
            ledger_tombstones = _ledger_rows(
                index_path,
                missing_ok=True,
                ledger_path=str(authoritative_ledger_path),
            ) or []
        database_tombstones: List[Tuple[str, str, str, str]] = []
        if existing_target:
            index_identity = _file_identity(target, label="corpus index")
            source = sqlite3.connect(_readonly_uri(target), uri=True)
            destination: Optional[sqlite3.Connection] = None
            try:
                initial_data_version = source.execute("PRAGMA data_version").fetchone()
                if initial_data_version is None or not isinstance(
                    initial_data_version[0], int
                ):
                    raise CorpusIndexError("cannot read existing SQLite data_version")
                database_tombstones = _validate_existing_index(source)
                bound_ledger_path = _bound_deletion_ledger_path(
                    index_path, conn=source
                )
                if bound_ledger_path != authoritative_ledger_path:
                    raise CorpusIndexError(
                        "existing corpus is bound to a different deletion ledger"
                    )
                if preserve_existing:
                    unchanged = _identical_upsert_summary(
                        source,
                        values,
                        database_tombstones=database_tombstones,
                        ledger_tombstones=ledger_tombstones,
                    )
                    if unchanged is not None:
                        after_ledger_identity, after_ledger_tombstones = (
                            _ledger_snapshot(index_path, authoritative_ledger_path)
                        )
                        final_data_version = source.execute(
                            "PRAGMA data_version"
                        ).fetchone()
                        if (
                            after_ledger_identity != ledger_identity
                            or after_ledger_tombstones != ledger_tombstones
                            or final_data_version is None
                            or final_data_version[0] != initial_data_version[0]
                            or _file_identity(target, label="corpus index")
                            != index_identity
                        ):
                            raise CorpusIndexError(
                                "corpus state changed during identical upsert validation"
                            )
                        return unchanged
                    destination = sqlite3.connect(str(tmp_path))
                    source.backup(destination)
            except sqlite3.DatabaseError as err:
                raise CorpusIndexError(
                    f"cannot preserve existing corpus state: {err}"
                ) from err
            finally:
                source.close()
                if destination is not None:
                    destination.close()
        durable_tombstones = _merge_tombstone_rows(
            database_tombstones, ledger_tombstones
        )
        # The identifier-only negative history is authoritative and is published
        # before the disposable SQLite projection.  If a later replace fails,
        # readers fail closed until this operation is retried.
        _write_ledger_rows(
            index_path,
            durable_tombstones,
            ledger_path=str(authoritative_ledger_path),
        )
        conn = sqlite3.connect(str(tmp_path))
        try:
            _enable_secure_delete(conn)
            conn.execute("PRAGMA journal_mode = OFF")
            conn.execute("PRAGMA synchronous = OFF")
            if existing_target and preserve_existing:
                _validate_existing_index(conn)
                _init_schema(conn)
            else:
                _init_schema(conn)
            _enable_fts_secure_delete(conn)

            if not preserve_existing:
                conn.execute("DELETE FROM corpus_meta")
                conn.execute("DELETE FROM message_fts")
                conn.execute("DELETE FROM message_text_leaf_fts")
                conn.execute("DELETE FROM conversation_title_fts")
                conn.execute("DELETE FROM source_records")
                conn.execute("DELETE FROM corpus_tombstones")
            _apply_tombstone_rows(conn, durable_tombstones)
            conn.execute(
                "INSERT OR REPLACE INTO corpus_meta(key, value) VALUES ('schema_version', ?)",
                (CORPUS_INDEX_SCHEMA_VERSION,),
            )
            conn.execute(
                "INSERT OR REPLACE INTO corpus_meta(key, value) VALUES (?, ?)",
                (
                    DELETION_LEDGER_BINDING_META_KEY,
                    _ledger_binding_value(index_path, authoritative_ledger_path),
                ),
            )
            for projection in values:
                _insert_projection(
                    conn,
                    projection,
                    allow_synthetic_attachment_text=allow_synthetic_attachment_text,
                )
            summary = _summary(conn)
            for key in ("corpus_id", "index_generation"):
                conn.execute(
                    "INSERT OR REPLACE INTO corpus_meta(key, value) VALUES (?, ?)",
                    (key, summary[key]),
                )
            if conn.execute("SELECT COUNT(*) FROM message_fts").fetchone()[0] != summary["message_count"]:
                raise CorpusIndexError("FTS row count does not match message corpus")
            leaf_count = conn.execute(
                "SELECT COUNT(*) FROM message_text_leaf_records"
            ).fetchone()[0]
            if conn.execute("SELECT COUNT(*) FROM message_text_leaf_fts").fetchone()[0] != leaf_count:
                raise CorpusIndexError("text-leaf FTS row count does not match leaf corpus")
            if conn.execute("SELECT COUNT(*) FROM conversation_title_fts").fetchone()[0] != summary["conversation_count"]:
                raise CorpusIndexError("title FTS row count does not match conversation corpus")
            conn.commit()
            _store_logical_index_seal(conn)
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise CorpusIndexError(f"SQLite integrity check failed: {integrity}")
            conn.commit()
        except sqlite3.DatabaseError as err:
            raise CorpusIndexError(f"failed to update corpus index: {err}") from err
        finally:
            conn.close()
        _publish_index_file(tmp_path, target)
        return summary
    finally:
        tmp_path.unlink(missing_ok=True)


def _atomic_update(
    projections: Dict[str, Any] | Sequence[Dict[str, Any]],
    index_path: str,
    *,
    preserve_existing: bool,
    allow_synthetic_attachment_text: bool,
    deletion_ledger_path: Optional[str] = None,
) -> Dict[str, Any]:
    with corpus_state_lock(index_path):
        existing_target = Path(index_path).is_file()
        authoritative_ledger_path = _select_deletion_ledger_path(
            index_path, explicit_ledger_path=deletion_ledger_path
        )
        with corpus_state_lock(str(authoritative_ledger_path)):
            return _atomic_update_locked(
                projections,
                index_path,
                preserve_existing=preserve_existing,
                allow_synthetic_attachment_text=allow_synthetic_attachment_text,
                authoritative_ledger_path=authoritative_ledger_path,
                require_existing_ledger=(
                    existing_target or deletion_ledger_path is not None
                ),
            )


def build_corpus_index(
    projections: Dict[str, Any] | Sequence[Dict[str, Any]],
    index_path: str,
    *,
    allow_synthetic_attachment_text: bool = False,
    deletion_ledger_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Atomically replace sources while preserving durable forget tombstones.

    If ``index_path`` already exists, its current schema, tombstones, and generation
    metadata are validated before any replacement is published. Tombstones for
    sources absent from this build remain durable so a later upsert cannot
    resurrect a forgotten conversation.
    """

    return _atomic_update(
        projections,
        index_path,
        preserve_existing=False,
        allow_synthetic_attachment_text=allow_synthetic_attachment_text,
        deletion_ledger_path=deletion_ledger_path,
    )


def upsert_corpus_sources(
    projections: Dict[str, Any] | Sequence[Dict[str, Any]],
    index_path: str,
    *,
    allow_synthetic_attachment_text: bool = False,
    deletion_ledger_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Atomically add or replace source projections in one global corpus."""

    return _atomic_update(
        projections,
        index_path,
        preserve_existing=True,
        allow_synthetic_attachment_text=allow_synthetic_attachment_text,
        deletion_ledger_path=deletion_ledger_path,
    )


def _query_terms(query: str) -> List[Tuple[str, str]]:
    try:
        raw_terms = shlex.split(query)
    except ValueError:
        raw_terms = [query]
    terms: List[Tuple[str, str]] = []
    for raw in raw_terms:
        normalized = _normalize_text(raw)
        if not normalized:
            continue
        if normalized.endswith("*") and len(normalized) > 1:
            terms.append((normalized[:-1], "prefix"))
        elif " " in normalized:
            terms.append((normalized, "phrase"))
        else:
            terms.append((normalized, "term"))
    return terms


def _fts_expressions(query: str) -> List[str]:
    expressions: List[str] = []
    for value, kind in _query_terms(query):
        escaped = value.replace('"', '""')
        expression = f'"{escaped}"'
        if kind == "prefix":
            expression += "*"
        expressions.append(expression)
    return expressions


def _fts_query(query: str, *, include_attachment_text: bool) -> str:
    columns = ["content_norm"]
    if include_attachment_text:
        columns.append("attachment_text_norm")
    column_filter = "{" + " ".join(columns) + "}"
    expressions = [
        f"{column_filter} : {expression}" for expression in _fts_expressions(query)
    ]
    return " AND ".join(expressions)


def _leaf_fts_query(query: str) -> str:
    return " AND ".join(_fts_expressions(query))


def _filter_values(values: Optional[Iterable[str]], *, name: str) -> Optional[List[str]]:
    if values is None:
        return None
    result = sorted(set(values))
    if any(not isinstance(value, str) or not value for value in result):
        raise CorpusIndexError(f"{name} must contain non-empty strings")
    return result


def _add_in_filter(
    clauses: List[str], parameters: List[Any], column: str, values: Optional[List[str]]
) -> None:
    if values is None:
        return
    if not values:
        clauses.append("0")
        return
    clauses.append(f"{column} IN ({','.join('?' for _ in values)})")
    parameters.extend(values)


def _reviewed_scope_ids(
    values: Optional[Iterable[str]],
) -> Optional[Tuple[str, ...]]:
    """Validate the fixed internal selector used by an attached History view."""

    if values is None:
        return None
    if isinstance(values, (str, bytes)):
        raise CorpusIndexError("logical_scope_ids must be a collection")
    result: List[str] = []
    seen: Set[str] = set()
    for value in values:
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 128
            or "\x00" in value
        ):
            raise CorpusIndexError("logical_scope_ids contain an invalid value")
        if value in seen:
            raise CorpusIndexError("logical_scope_ids must not contain duplicates")
        seen.add(value)
        result.append(value)
        if len(result) > 64:
            raise CorpusIndexError("logical_scope_ids exceed the supported limit")
    if not result:
        raise CorpusIndexError("logical_scope_ids must not be empty")
    return tuple(sorted(result))


def _history_record_predicate(record_column: str, scope_ids: Sequence[str]) -> str:
    placeholders = ",".join("?" for _ in scope_ids)
    return (
        "EXISTS (SELECT 1 FROM history_view.scope_decisions hd "
        f"WHERE hd.record_id = {record_column} "
        f"AND hd.scope_id IN ({placeholders}) "
        "AND hd.membership = 'include' AND hd.review_state = 'reviewed')"
    )


def _history_title_predicate(scope_ids: Sequence[str]) -> str:
    placeholders = ",".join("?" for _ in scope_ids)
    return (
        "EXISTS (SELECT 1 FROM message_records hm "
        "JOIN history_view.scope_decisions hd ON hd.record_id = hm.record_id "
        "WHERE hm.source_id = c.source_id "
        "AND hm.conversation_id = c.conversation_id "
        f"AND hd.scope_id IN ({placeholders}) "
        "AND hd.membership = 'include' AND hd.review_state = 'reviewed')"
    )


def _decode_json(value: bytes, *, field: str) -> Dict[str, Any]:
    try:
        payload = loads_json_strict(bytes(value).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as err:
        raise CorpusIndexError(f"stored {field} is corrupt") from err
    if not isinstance(payload, dict):
        raise CorpusIndexError(f"stored {field} is not an object")
    return payload


def _compact_row(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "record_id": row["record_id"],
        "source_id": row["source_id"],
        "provider": row["provider"],
        "conversation_id": row["conversation_id"],
        "message_id": row["message_id"],
        "parent_message_id": row["parent_message_id"],
        "role": row["role"],
        "model": row["model"],
        "content_type": row["content_type"],
        "created_at": row["created_at"],
        "branch_path": row["branch_path"],
        "content": bytes(row["content_utf8"]).decode("utf-8"),
        "locator": _decode_json(row["provenance_json"], field="provenance"),
    }


def _attachments(conn: sqlite3.Connection, message_pk: int) -> List[Dict[str, Any]]:
    rows = conn.execute(
        """SELECT attachment_id, media_type, name, source_locator, searchable,
                  text_utf8, text_sha256, canonical_json
             FROM attachment_records WHERE message_pk = ? ORDER BY source_ordinal""",
        (message_pk,),
    ).fetchall()
    result = []
    for row in rows:
        result.append(
            {
                "attachment_id": row["attachment_id"],
                "media_type": row["media_type"],
                "name": row["name"],
                "source_locator": row["source_locator"],
                "searchable": bool(row["searchable"]),
                "text": bytes(row["text_utf8"]).decode("utf-8") if row["text_utf8"] is not None else None,
                "text_sha256": row["text_sha256"],
                "canonical_attachment": _decode_json(row["canonical_json"], field="attachment"),
            }
        )
    return result


def _matched_text_leaves(
    conn: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    query: Optional[str],
    match_mode: str,
) -> Tuple[List[Dict[str, Any]], bool]:
    if not query or not _normalize_text(query):
        return [], False
    if match_mode == "fts":
        leaf_query = _leaf_fts_query(query)
        if not leaf_query:
            return [], False
        leaves = conn.execute(
            """SELECT l.*
                 FROM message_text_leaf_records l
                 JOIN message_text_leaf_fts f ON f.rowid = l.leaf_pk
                 WHERE l.message_pk = ? AND message_text_leaf_fts MATCH ?
                 ORDER BY l.source_ordinal
                 LIMIT ?""",
            (row["message_pk"], leaf_query, MAX_MATCHED_TEXT_LEAVES + 1),
        ).fetchall()
    else:
        normalized = _normalize_text(query)
        leaves = conn.execute(
            """SELECT * FROM message_text_leaf_records
                 WHERE message_pk = ? AND instr(value_norm, ?) > 0
                 ORDER BY source_ordinal
                 LIMIT ?""",
            (row["message_pk"], normalized, MAX_MATCHED_TEXT_LEAVES + 1),
        ).fetchall()
    truncated = len(leaves) > MAX_MATCHED_TEXT_LEAVES
    base_locator = _decode_json(row["provenance_json"], field="provenance")
    results: List[Dict[str, Any]] = []
    for leaf in leaves[:MAX_MATCHED_TEXT_LEAVES]:
        locator = dict(base_locator)
        locator["canonical_pointer"] = leaf["canonical_pointer"]
        results.append(
            {
                "field_scope": leaf["field_scope"],
                "text": bytes(leaf["value_utf8"]).decode("utf-8"),
                "text_sha256": leaf["value_sha256"],
                "locator": locator,
                "authoritative": False,
                "evidence_only": True,
            }
        )
    return results, truncated


def _text_leaf_exclusions(conn: sqlite3.Connection, message_pk: int) -> List[Dict[str, Any]]:
    return [
        {
            "canonical_pointer": row[0],
            "reason": row[1],
            "value_sha256": row[2],
            "byte_length": row[3],
        }
        for row in conn.execute(
            """SELECT canonical_pointer, reason, value_sha256, byte_length
                 FROM message_text_leaf_exclusions
                 WHERE message_pk = ? ORDER BY canonical_pointer""",
            (message_pk,),
        ).fetchall()
    ]


def _bounded_context(
    conn: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    radius: int,
    logical_scope_ids: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    if radius == 0:
        return {"previous": [], "next": [], "parent": None, "children": [], "children_truncated": False}
    scope_ids = _reviewed_scope_ids(logical_scope_ids)
    scope_predicate = (
        " AND " + _history_record_predicate("m.record_id", scope_ids)
        if scope_ids is not None
        else ""
    )
    scope_parameters: Tuple[str, ...] = scope_ids or ()
    base = (row["source_id"], row["conversation_id"])
    previous = conn.execute(
        f"""SELECT m.* FROM message_records m
              WHERE m.source_id = ? AND m.conversation_id = ?
                AND m.message_ordinal < ?{scope_predicate}
              ORDER BY m.message_ordinal DESC LIMIT ?""",
        (*base, row["message_ordinal"], *scope_parameters, radius),
    ).fetchall()[::-1]
    following = conn.execute(
        f"""SELECT m.* FROM message_records m
              WHERE m.source_id = ? AND m.conversation_id = ?
                AND m.message_ordinal > ?{scope_predicate}
              ORDER BY m.message_ordinal LIMIT ?""",
        (*base, row["message_ordinal"], *scope_parameters, radius),
    ).fetchall()
    parent = None
    if row["parent_message_id"]:
        parent = conn.execute(
            f"""SELECT m.* FROM message_records m
                  WHERE m.source_id = ? AND m.conversation_id = ?
                    AND m.message_id = ?{scope_predicate}""",
            (*base, row["parent_message_id"], *scope_parameters),
        ).fetchone()
    children = conn.execute(
        f"""SELECT m.* FROM message_records m
              WHERE m.source_id = ? AND m.conversation_id = ?
                AND m.parent_message_id = ?{scope_predicate}
              ORDER BY m.message_ordinal LIMIT ?""",
        (*base, row["message_id"], *scope_parameters, MAX_CHILDREN + 1),
    ).fetchall()
    return {
        "previous": [_compact_row(item) for item in previous],
        "next": [_compact_row(item) for item in following],
        "parent": _compact_row(parent) if parent is not None else None,
        "children": [_compact_row(item) for item in children[:MAX_CHILDREN]],
        "children_truncated": len(children) > MAX_CHILDREN,
    }


def _result(
    conn: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    context_radius: int,
    query: Optional[str] = None,
    match_mode: str = "fts",
    logical_scope_ids: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    result = _compact_row(row)
    matched_leaves, leaves_truncated = _matched_text_leaves(
        conn, row, query=query, match_mode=match_mode
    )
    result.update(
        {
            "record_type": "message",
            "provider_schema_version": row["provider_schema_version"],
            "projection_sha256": row["projection_sha256"],
            "provider_conversation_id": row["provider_conversation_id"],
            "conversation_index": row["conversation_ordinal"],
            "message_index": row["message_ordinal"],
            "branch_depth": row["branch_depth"],
            "has_unknown_parent": bool(row["has_unknown_parent"]),
            "has_unknown_timestamp": bool(row["has_unknown_timestamp"]),
            "content_sha256": row["content_sha256"],
            "canonical_message": _decode_json(row["canonical_json"], field="message"),
            "attachments": _attachments(conn, row["message_pk"]),
            "matched_text_leaves": matched_leaves,
            "matched_text_leaves_truncated": leaves_truncated,
            "excluded_text_leaves": _text_leaf_exclusions(conn, row["message_pk"]),
            "authoritative": False,
            "evidence_only": True,
            "context": _bounded_context(
                conn,
                row,
                radius=context_radius,
                logical_scope_ids=logical_scope_ids,
            ),
        }
    )
    return result


def _title_result(row: sqlite3.Row) -> Dict[str, Any]:
    title = bytes(row["title_utf8"]).decode("utf-8")
    title_bytes = _utf8(title, field="stored conversation title")
    locator = {
        "source_id": row["source_id"],
        "provider": row["provider"],
        "provider_schema_version": row["provider_schema_version"],
        "projection_sha256": row["projection_sha256"],
        "conversation_id": row["conversation_id"],
        "provider_conversation_id": row["provider_conversation_id"],
        "conversation_index": row["source_ordinal"],
        "canonical_pointer": f"/conversations/{row['source_ordinal']}/title",
    }
    record_id = sha256(
        _utf8(_stable_json(locator), field="conversation title locator")
    ).hexdigest()
    locator["record_id"] = record_id
    leaf = {
        "field_scope": "conversation_metadata",
        "text": title,
        "text_sha256": sha256(title_bytes).hexdigest(),
        "locator": dict(locator),
        "authoritative": False,
        "evidence_only": True,
    }
    return {
        "record_type": "conversation_metadata",
        "metadata_field": "title",
        "record_id": record_id,
        "source_id": row["source_id"],
        "provider": row["provider"],
        "provider_schema_version": row["provider_schema_version"],
        "projection_sha256": row["projection_sha256"],
        "conversation_id": row["conversation_id"],
        "provider_conversation_id": row["provider_conversation_id"],
        "conversation_index": row["source_ordinal"],
        "message_id": None,
        "message_index": None,
        "role": None,
        "model": None,
        "content_type": "conversation_title",
        "created_at": row["created_at"],
        "content": title,
        "content_sha256": sha256(title_bytes).hexdigest(),
        "locator": locator,
        "canonical_conversation": _decode_json(
            row["canonical_json"], field="conversation"
        ),
        "matched_text_leaves": [leaf],
        "matched_text_leaves_truncated": False,
        "authoritative": False,
        "evidence_only": True,
        "context": {
            "previous": [],
            "next": [],
            "parent": None,
            "children": [],
            "children_truncated": False,
        },
    }


def inspect_corpus_index(index_path: str) -> Dict[str, Any]:
    with ValidatedCorpusReader(index_path) as reader:
        return reader.inspect()


def resolve_corpus_deletion_ledger_path(index_path: str) -> str:
    """Resolve the authoritative private ledger bound to one corpus index."""

    if not isinstance(index_path, str) or not index_path:
        raise CorpusIndexError("index_path is required")
    target = _canonical_path(Path(index_path))
    if not target.is_file():
        raise CorpusIndexError("corpus index does not exist")
    with corpus_state_lock(str(target)):
        return str(_bound_deletion_ledger_path(str(target)))


def inspect_corpus_integrity(index_path: str) -> Dict[str, Any]:
    """Return a freshly recomputed integrity binding for one corpus snapshot.

    Ordinary warm reads deliberately avoid the O(index-size) logical-seal
    calculation.  Projection builders that bind a second file to the corpus
    need the stronger check, so this operation holds the corpus state lock,
    validates the ordinary index/deletion-ledger contract, recomputes the full
    logical seal, and rejects replacement or mutation before returning.
    """

    if not isinstance(index_path, str) or not index_path:
        raise CorpusIndexError("index_path is required")
    target = _canonical_path(Path(index_path))
    if not target.is_file():
        raise CorpusIndexError("corpus index does not exist")
    with corpus_state_lock(str(target)):
        before = _file_identity(target, label="corpus index")
        with ValidatedCorpusReader(str(target)) as reader:
            summary = reader.inspect()
        conn: Optional[sqlite3.Connection] = None
        try:
            conn = sqlite3.connect(_readonly_uri(target), uri=True)
            conn.execute("PRAGMA query_only = ON")
            query_only = conn.execute("PRAGMA query_only").fetchone()
            if query_only is None or query_only[0] != 1:
                raise CorpusIndexError("SQLite query_only could not be enabled")
            initial_data_version = conn.execute("PRAGMA data_version").fetchone()
            if initial_data_version is None or not isinstance(
                initial_data_version[0], int
            ):
                raise CorpusIndexError("cannot read SQLite data_version")
            _validate_existing_index(conn)
            ledger_path = _bound_deletion_ledger_path(str(target), conn=conn)
            ledger_identity, ledger_rows = _ledger_snapshot(
                str(target), ledger_path
            )
            database_rows = _database_tombstone_rows(conn)
            if database_rows != ledger_rows:
                raise CorpusIndexError(
                    "deletion ledger and corpus index disagree; recovery is required"
                )
            seal_row = conn.execute(
                "SELECT value FROM corpus_meta WHERE key = ?",
                (LOGICAL_INDEX_SEAL_META_KEY,),
            ).fetchone()
            if (
                seal_row is None
                or not isinstance(seal_row[0], str)
                or len(seal_row[0]) != 64
                or any(character not in "0123456789abcdef" for character in seal_row[0])
                or not _logical_index_seal_matches(conn)
            ):
                raise CorpusIndexError("corpus logical-index seal mismatch")
            final_data_version = conn.execute("PRAGMA data_version").fetchone()
            if (
                final_data_version is None
                or final_data_version[0] != initial_data_version[0]
            ):
                raise CorpusIndexError("corpus index changed during integrity check")
            final_ledger_identity, final_ledger_rows = _ledger_snapshot(
                str(target), ledger_path
            )
            if (
                final_ledger_identity != ledger_identity
                or final_ledger_rows != ledger_rows
                or _database_tombstone_rows(conn) != ledger_rows
            ):
                raise CorpusIndexError(
                    "corpus deletion ledger changed during integrity check"
                )
            after = _file_identity(target, label="corpus index")
            if before != after:
                raise CorpusIndexError("corpus index changed during integrity check")
            return {
                **summary,
                "index_schema_version": summary["schema_version"],
                "schema_version": CORPUS_INTEGRITY_SCHEMA_VERSION,
                "logical_index_sha256": seal_row[0],
                "verified": True,
            }
        except sqlite3.DatabaseError as err:
            raise CorpusIndexError(f"corpus integrity check failed: {err}") from err
        finally:
            if conn is not None:
                conn.close()


def list_corpus_tombstones(index_path: str) -> List[Dict[str, str]]:
    """Return sorted private identifier selectors for bridge freshness checks."""

    with ValidatedCorpusReader(index_path) as reader:
        return reader.list_tombstones()


def list_corpus_source_states(index_path: str) -> List[Dict[str, Any]]:
    """Return content-free current per-source projection identities."""

    with ValidatedCorpusReader(index_path) as reader:
        return reader.list_source_states()


def _delete_indexed_conversation(
    conn: sqlite3.Connection, *, source_id: str, conversation_id: str
) -> int:
    conversation = conn.execute(
        """SELECT conversation_pk FROM conversation_records
             WHERE source_id = ? AND conversation_id = ?""",
        (source_id, conversation_id),
    ).fetchone()
    if conversation is not None:
        conn.execute(
            "DELETE FROM conversation_title_fts WHERE rowid = ?",
            (conversation[0],),
        )
    rows = conn.execute(
        """SELECT message_pk FROM message_records
             WHERE source_id = ? AND conversation_id = ?""",
        (source_id, conversation_id),
    ).fetchall()
    message_pks = [row[0] for row in rows]
    if message_pks:
        leaf_pks = [
            row[0]
            for row in conn.execute(
                """SELECT l.leaf_pk
                     FROM message_text_leaf_records l
                     JOIN message_records m ON m.message_pk = l.message_pk
                     WHERE m.source_id = ? AND m.conversation_id = ?""",
                (source_id, conversation_id),
            ).fetchall()
        ]
        conn.executemany(
            "DELETE FROM message_fts WHERE rowid = ?",
            ((message_pk,) for message_pk in message_pks),
        )
        if leaf_pks:
            conn.executemany(
                "DELETE FROM message_text_leaf_fts WHERE rowid = ?",
                ((leaf_pk,) for leaf_pk in leaf_pks),
            )
    conn.execute(
        "DELETE FROM conversation_records WHERE source_id = ? AND conversation_id = ?",
        (source_id, conversation_id),
    )
    return len(message_pks)


def _forget_corpus_conversations_locked(
    index_path: str,
    *,
    source_id: str,
    conversation_ids: Iterable[str],
    authoritative_ledger_path: Path,
) -> Dict[str, Any]:
    """Durably revoke conversations and rebuild the disposable SQLite index.

    The bound private deletion ledger is written first. A crash or replace
    failure can therefore leave the ledger ahead of SQLite, never the reverse.
    Read APIs detect that state and fail closed; retrying this call
    deterministically completes recovery. Multiple indexes rebuilt from the
    same ledger continue to share that authoritative negative history.
    """

    source_id = _text(source_id, field="source_id")
    assert source_id is not None
    selectors = _filter_values(conversation_ids, name="conversation_ids")
    if not selectors:
        raise CorpusIndexError("at least one conversation_id is required")
    target = Path(index_path)
    if not target.is_file():
        raise CorpusIndexError("corpus index does not exist")
    fd, tmp_name = tempfile.mkstemp(
        prefix="chronicle-corpus-forget-", suffix=".sqlite", dir=target.parent
    )
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        source = sqlite3.connect(_readonly_uri(target), uri=True)
        destination: Optional[sqlite3.Connection] = None
        try:
            database_tombstones = _validate_existing_index(source)
            before = _summary(source)
            if source.execute(
                "SELECT 1 FROM source_records WHERE source_id = ?", (source_id,)
            ).fetchone() is None:
                raise CorpusIndexError(f"source_id is not indexed: {source_id}")
            ledger_tombstones = _ledger_rows(
                index_path,
                missing_ok=False,
                ledger_path=str(authoritative_ledger_path),
            ) or []
            requested = [
                (
                    _tombstone_id(
                        source_id=source_id, conversation_id=conversation_id
                    ),
                    source_id,
                    conversation_id,
                    "conversation",
                )
                for conversation_id in selectors
            ]
            durable_tombstones = _merge_tombstone_rows(
                database_tombstones, ledger_tombstones, requested
            )
            _write_ledger_rows(
                index_path,
                durable_tombstones,
                ledger_path=str(authoritative_ledger_path),
            )
            destination = sqlite3.connect(str(tmp_path))
            source.backup(destination)
        finally:
            source.close()
            if destination is not None:
                destination.close()
        conn = sqlite3.connect(str(tmp_path))
        try:
            _enable_secure_delete(conn)
            conn.execute("PRAGMA foreign_keys = ON")
            _require_schema(conn)
            _enable_fts_secure_delete(conn)
            database_keys = {(row[1], row[2]) for row in database_tombstones}
            inserted_tombstones = sum(
                (row[1], row[2]) not in database_keys
                for row in durable_tombstones
            )
            _apply_tombstone_rows(conn, durable_tombstones)
            conn.execute(
                "INSERT OR REPLACE INTO corpus_meta(key, value) VALUES (?, ?)",
                (
                    DELETION_LEDGER_BINDING_META_KEY,
                    _ledger_binding_value(index_path, authoritative_ledger_path),
                ),
            )
            after = _summary(conn)
            removed_messages = before["message_count"] - after["message_count"]
            for key in ("corpus_id", "index_generation"):
                conn.execute(
                    "INSERT OR REPLACE INTO corpus_meta(key, value) VALUES (?, ?)",
                    (key, after[key]),
                )
            if (
                inserted_tombstones > 0 or removed_messages > 0
            ) and before["index_generation"] == after["index_generation"]:
                raise CorpusIndexError("forget did not advance index_generation")
            if conn.execute("SELECT COUNT(*) FROM message_fts").fetchone()[0] != after["message_count"]:
                raise CorpusIndexError("FTS row count does not match forgotten corpus")
            leaf_count = conn.execute(
                "SELECT COUNT(*) FROM message_text_leaf_records"
            ).fetchone()[0]
            if conn.execute("SELECT COUNT(*) FROM message_text_leaf_fts").fetchone()[0] != leaf_count:
                raise CorpusIndexError("text-leaf FTS row count does not match forgotten corpus")
            if conn.execute("SELECT COUNT(*) FROM conversation_title_fts").fetchone()[0] != after["conversation_count"]:
                raise CorpusIndexError("title FTS row count does not match forgotten corpus")
            conn.commit()
            _store_logical_index_seal(conn)
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise CorpusIndexError(f"SQLite integrity check failed: {integrity}")
            conn.commit()
        except sqlite3.DatabaseError as err:
            raise CorpusIndexError(f"failed to forget corpus conversation: {err}") from err
        finally:
            conn.close()
        _publish_index_file(tmp_path, target)
        return {
            **after,
            "source_id": source_id,
            "forgotten_conversation_ids": selectors,
            "removed_message_count": removed_messages,
            "inserted_tombstone_count": inserted_tombstones,
            "idempotent_replay": inserted_tombstones == 0 and removed_messages == 0,
            "deletion_ledger_committed": True,
            "index_generation_before": before["index_generation"],
            "index_generation_after": after["index_generation"],
        }
    finally:
        tmp_path.unlink(missing_ok=True)


def forget_corpus_conversations(
    index_path: str,
    *,
    source_id: str,
    conversation_ids: Iterable[str],
) -> Dict[str, Any]:
    with corpus_state_lock(index_path):
        authoritative_ledger_path = _select_deletion_ledger_path(
            index_path, explicit_ledger_path=None
        )
        with corpus_state_lock(str(authoritative_ledger_path)):
            return _forget_corpus_conversations_locked(
                index_path,
                source_id=source_id,
                conversation_ids=conversation_ids,
                authoritative_ledger_path=authoritative_ledger_path,
            )


def _search_corpus_with_connection(
    conn: sqlite3.Connection,
    summary: Dict[str, Any],
    *,
    query: Optional[str] = None,
    providers: Optional[Iterable[str]] = None,
    source_ids: Optional[Iterable[str]] = None,
    conversation_ids: Optional[Iterable[str]] = None,
    roles: Optional[Iterable[str]] = None,
    models: Optional[Iterable[str]] = None,
    content_types: Optional[Iterable[str]] = None,
    created_from: Optional[str] = None,
    created_to: Optional[str] = None,
    include_attachment_text: bool = False,
    match_mode: str = "fts",
    context_radius: int = 1,
    limit: int = 50,
    offset: int = 0,
    max_substring_scan_rows: int = 10_000,
    logical_scope_ids: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Search every indexed source without requiring a source file or ID.

    ``fts`` supports Unicode terms, quoted phrases, and trailing-``*`` token
    prefixes.  It intentionally does not implement arbitrary mid-token
    substring matching.  ``substring`` provides a bounded normalized scan and
    reports ``scan_truncated`` when its cap may have hidden later matches.
    """

    if match_mode not in {"fts", "substring"}:
        raise CorpusIndexError("match_mode must be 'fts' or 'substring'")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_RESULTS:
        raise CorpusIndexError(f"limit must be between 1 and {MAX_RESULTS}")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise CorpusIndexError("offset must be a non-negative integer")
    if (
        isinstance(context_radius, bool)
        or not isinstance(context_radius, int)
        or not 0 <= context_radius <= MAX_CONTEXT_RADIUS
    ):
        raise CorpusIndexError(f"context_radius must be between 0 and {MAX_CONTEXT_RADIUS}")
    if (
        isinstance(max_substring_scan_rows, bool)
        or not isinstance(max_substring_scan_rows, int)
        or not 1 <= max_substring_scan_rows <= MAX_SUBSTRING_SCAN_ROWS
    ):
        raise CorpusIndexError(
            f"max_substring_scan_rows must be between 1 and {MAX_SUBSTRING_SCAN_ROWS}"
        )
    if query is not None and not isinstance(query, str):
        raise CorpusIndexError("query must be a string")

    reviewed_scope_ids = _reviewed_scope_ids(logical_scope_ids)
    filters = {
        "providers": _filter_values(providers, name="providers"),
        "source_ids": _filter_values(source_ids, name="source_ids"),
        "conversation_ids": _filter_values(conversation_ids, name="conversation_ids"),
        "roles": _filter_values(roles, name="roles"),
        "models": _filter_values(models, name="models"),
        "content_types": _filter_values(content_types, name="content_types"),
    }
    clauses: List[str] = []
    parameters: List[Any] = []
    title_clauses: List[str] = []
    title_parameters: List[Any] = []
    _add_in_filter(clauses, parameters, "m.provider", filters["providers"])
    _add_in_filter(clauses, parameters, "m.source_id", filters["source_ids"])
    _add_in_filter(clauses, parameters, "m.conversation_id", filters["conversation_ids"])
    _add_in_filter(clauses, parameters, "m.role", filters["roles"])
    _add_in_filter(clauses, parameters, "m.model", filters["models"])
    _add_in_filter(clauses, parameters, "m.content_type", filters["content_types"])
    _add_in_filter(title_clauses, title_parameters, "c.provider", filters["providers"])
    _add_in_filter(title_clauses, title_parameters, "c.source_id", filters["source_ids"])
    _add_in_filter(
        title_clauses,
        title_parameters,
        "c.conversation_id",
        filters["conversation_ids"],
    )
    if reviewed_scope_ids is not None:
        clauses.append(_history_record_predicate("m.record_id", reviewed_scope_ids))
        parameters.extend(reviewed_scope_ids)
        title_clauses.append(_history_title_predicate(reviewed_scope_ids))
        title_parameters.extend(reviewed_scope_ids)
    if filters["roles"] is not None or filters["models"] is not None:
        title_clauses.append("0")
    if (
        filters["content_types"] is not None
        and "conversation_title" not in filters["content_types"]
    ):
        title_clauses.append("0")
    if created_from is not None:
        created_from = _utc_filter_timestamp(created_from, field="created_from")
        clauses.append("m.created_at >= ?")
        parameters.append(created_from)
        title_clauses.append("c.created_at >= ?")
        title_parameters.append(created_from)
    if created_to is not None:
        created_to = _utc_filter_timestamp(created_to, field="created_to")
        clauses.append("m.created_at <= ?")
        parameters.append(created_to)
        title_clauses.append("c.created_at <= ?")
        title_parameters.append(created_to)
    where = " AND ".join(clauses) if clauses else "1"
    title_where = " AND ".join(title_clauses) if title_clauses else "1"

    try:
        scan_truncated = False
        normalized_query = _normalize_text(query or "")
        tagged_rows: List[Tuple[str, sqlite3.Row]] = []
        fetch_limit = offset + limit

        def order_key(item: Tuple[str, sqlite3.Row]) -> Tuple[Any, ...]:
            kind, row = item
            keys = set(row.keys())
            rank = row["search_rank"] if "search_rank" in keys else 0.0
            created_at = row["created_at"]
            source_ordinal = (
                row["conversation_ordinal"]
                if "conversation_ordinal" in keys
                else row["source_ordinal"]
            )
            message_ordinal = row["message_ordinal"] if "message_ordinal" in keys else -1
            return (
                float(rank),
                1 if not created_at else 0,
                str(created_at or ""),
                str(row["source_id"]),
                int(source_ordinal),
                0 if kind == "conversation_metadata" else 1,
                int(message_ordinal),
            )

        if query and normalized_query and match_mode == "fts":
            fts = _fts_query(query, include_attachment_text=include_attachment_text)
            leaf_fts = _leaf_fts_query(query)
            if not fts and not leaf_fts:
                tagged_rows = []
            else:
                message_rows = conn.execute(
                    f"""WITH matches AS (
                           SELECT m.message_pk AS message_pk,
                                  bm25(message_fts) AS rank
                             FROM message_records m
                             JOIN message_fts ON message_fts.rowid = m.message_pk
                            WHERE message_fts MATCH ? AND {where}
                           UNION ALL
                           SELECT m.message_pk AS message_pk,
                                  bm25(message_text_leaf_fts) AS rank
                             FROM message_records m
                             JOIN message_text_leaf_records l
                               ON l.message_pk = m.message_pk
                             JOIN message_text_leaf_fts
                               ON message_text_leaf_fts.rowid = l.leaf_pk
                            WHERE message_text_leaf_fts MATCH ? AND {where}
                         ), ranked AS (
                           SELECT message_pk, MIN(rank) AS rank
                             FROM matches GROUP BY message_pk
                         )
                         SELECT m.*, ranked.rank AS search_rank
                           FROM message_records m
                          JOIN ranked ON ranked.message_pk = m.message_pk
                         ORDER BY ranked.rank,
                                  CASE WHEN NULLIF(m.created_at, '') IS NULL
                                       THEN 1 ELSE 0 END,
                                  m.created_at, m.source_id,
                                  m.conversation_ordinal, m.message_ordinal
                         LIMIT ?""",
                    (
                        fts,
                        *parameters,
                        leaf_fts,
                        *parameters,
                        fetch_limit,
                    ),
                ).fetchall()
                title_rows = conn.execute(
                    f"""SELECT c.*, s.projection_sha256,
                                bm25(conversation_title_fts) AS search_rank
                           FROM conversation_records c
                           JOIN source_records s ON s.source_id = c.source_id
                           JOIN conversation_title_fts
                             ON conversation_title_fts.rowid = c.conversation_pk
                          WHERE conversation_title_fts MATCH ? AND {title_where}
                          ORDER BY search_rank,
                                   CASE WHEN NULLIF(c.created_at, '') IS NULL
                                        THEN 1 ELSE 0 END,
                                   c.created_at, c.source_id,
                                   c.source_ordinal
                          LIMIT ?""",
                    (leaf_fts, *title_parameters, fetch_limit),
                ).fetchall()
                tagged_rows = [
                    *(('message', row) for row in message_rows),
                    *(('conversation_metadata', row) for row in title_rows),
                ]
                tagged_rows.sort(key=order_key)
                tagged_rows = tagged_rows[offset : offset + limit]
        elif query and normalized_query and match_mode == "substring":
            candidates = conn.execute(
                f"""SELECT m.*, f.attachment_text_norm,
                            EXISTS(
                              SELECT 1 FROM message_text_leaf_records l
                               WHERE l.message_pk = m.message_pk
                                 AND instr(l.value_norm, ?) > 0
                            ) AS leaf_match
                     FROM message_records m
                     JOIN message_fts f ON f.rowid = m.message_pk
                     WHERE {where}
                     ORDER BY m.source_id, m.conversation_ordinal, m.message_ordinal
                     LIMIT ?""",
                (normalized_query, *parameters, max_substring_scan_rows + 1),
            ).fetchall()
            scan_truncated = len(candidates) > max_substring_scan_rows
            candidates = candidates[:max_substring_scan_rows]
            matched = []
            for row in candidates:
                fields = [row["content_norm"]]
                if include_attachment_text:
                    fields.append(row["attachment_text_norm"])
                if row["leaf_match"] or any(
                    normalized_query in (value or "") for value in fields
                ):
                    matched.append(row)
            title_candidates = conn.execute(
                f"""SELECT c.*, s.projection_sha256, 0.0 AS search_rank
                       FROM conversation_records c
                       JOIN source_records s ON s.source_id = c.source_id
                      WHERE instr(c.title_norm, ?) > 0 AND {title_where}
                      ORDER BY c.source_id, c.source_ordinal
                      LIMIT ?""",
                (
                    normalized_query,
                    *title_parameters,
                    max_substring_scan_rows + 1,
                ),
            ).fetchall()
            scan_truncated = scan_truncated or (
                len(title_candidates) > max_substring_scan_rows
            )
            title_candidates = title_candidates[:max_substring_scan_rows]
            tagged_rows = [
                *(('message', row) for row in matched),
                *(('conversation_metadata', row) for row in title_candidates),
            ]
            tagged_rows.sort(key=order_key)
            tagged_rows = tagged_rows[offset : offset + limit]
        else:
            rows = conn.execute(
                f"""SELECT m.* FROM message_records m WHERE {where}
                     ORDER BY CASE WHEN NULLIF(m.created_at, '') IS NULL
                                        THEN 1 ELSE 0 END,
                              m.created_at, m.source_id,
                              m.conversation_ordinal, m.message_ordinal
                     LIMIT ? OFFSET ?""",
                (*parameters, limit, offset),
            ).fetchall()
            tagged_rows = [("message", row) for row in rows]
        results = [
            _title_result(row)
            if kind == "conversation_metadata"
            else _result(
                conn,
                row,
                context_radius=context_radius,
                query=query,
                match_mode=match_mode,
                logical_scope_ids=reviewed_scope_ids,
            )
            for kind, row in tagged_rows
        ]
        return {
            **summary,
            "index_schema_version": summary["schema_version"],
            "schema_version": CORPUS_SEARCH_SCHEMA_VERSION,
            "query": query,
            "match_mode": match_mode,
            "scan_truncated": scan_truncated,
            "authority": "evidence_only",
            "result_count": len(results),
            "results": results,
        }
    except sqlite3.DatabaseError as err:
        raise CorpusIndexError(f"corpus query failed: {err}") from err


def _scan_history_records_with_connection(
    conn: sqlite3.Connection,
    summary: Dict[str, Any],
    *,
    after_message_pk: int = 0,
    limit: int = MAX_RESULTS,
) -> Dict[str, Any]:
    """Read the minimal message projection with bounded keyset pagination."""

    if (
        type(after_message_pk) is not int
        or after_message_pk < 0
    ):
        raise CorpusIndexError("after_message_pk must be a non-negative integer")
    if type(limit) is not int or not 1 <= limit <= MAX_RESULTS:
        raise CorpusIndexError(f"limit must be between 1 and {MAX_RESULTS}")
    try:
        rows = conn.execute(
            """SELECT message_pk, record_id, source_id, provider,
                      conversation_id, message_id, role, content_type,
                      content_utf8, content_sha256
                 FROM message_records
                WHERE message_pk > ?
                ORDER BY message_pk
                LIMIT ?""",
            (after_message_pk, limit + 1),
        ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        results = []
        for row in rows:
            try:
                content = bytes(row["content_utf8"]).decode("utf-8")
            except (TypeError, UnicodeDecodeError) as err:
                raise CorpusIndexError("stored message content is corrupt") from err
            results.append(
                {
                    "record_id": row["record_id"],
                    "source_id": row["source_id"],
                    "provider": row["provider"],
                    "conversation_id": row["conversation_id"],
                    "message_id": row["message_id"],
                    "role": row["role"],
                    "content_type": row["content_type"],
                    "content": content,
                    "content_sha256": row["content_sha256"],
                }
            )
        return {
            **summary,
            "index_schema_version": summary["schema_version"],
            "schema_version": CORPUS_HISTORY_SCAN_SCHEMA_VERSION,
            "after_message_pk": after_message_pk,
            "next_after_message_pk": rows[-1]["message_pk"] if has_more else None,
            "result_count": len(results),
            "complete": not has_more,
            "results": results,
        }
    except sqlite3.DatabaseError as err:
        raise CorpusIndexError(f"history record scan failed: {err}") from err


def _get_message_with_connection(
    conn: sqlite3.Connection,
    *,
    source_id: str,
    conversation_id: str,
    message_id: str,
    context_radius: int = 1,
    logical_scope_ids: Optional[Iterable[str]] = None,
) -> Optional[Dict[str, Any]]:
    if not 0 <= context_radius <= MAX_CONTEXT_RADIUS:
        raise CorpusIndexError(f"context_radius must be between 0 and {MAX_CONTEXT_RADIUS}")
    reviewed_scope_ids = _reviewed_scope_ids(logical_scope_ids)
    scope_clause = ""
    parameters: List[Any] = [source_id, conversation_id, message_id]
    if reviewed_scope_ids is not None:
        scope_clause = " AND " + _history_record_predicate(
            "message_records.record_id", reviewed_scope_ids
        )
        parameters.extend(reviewed_scope_ids)
    try:
        row = conn.execute(
            f"""SELECT * FROM message_records
                 WHERE source_id = ? AND conversation_id = ? AND message_id = ?
                 {scope_clause}""",
            parameters,
        ).fetchone()
        return (
            _result(
                conn,
                row,
                context_radius=context_radius,
                logical_scope_ids=reviewed_scope_ids,
            )
            if row is not None
            else None
        )
    except sqlite3.DatabaseError as err:
        raise CorpusIndexError(f"message lookup failed: {err}") from err


def _get_conversation_with_connection(
    conn: sqlite3.Connection, *, source_id: str, conversation_id: str,
) -> Optional[Dict[str, Any]]:
    try:
        conversation = conn.execute(
            """SELECT * FROM conversation_records
                 WHERE source_id = ? AND conversation_id = ?""",
            (source_id, conversation_id),
        ).fetchone()
        if conversation is None:
            return None
        messages = conn.execute(
            """SELECT * FROM message_records
                 WHERE source_id = ? AND conversation_id = ?
                 ORDER BY message_ordinal""",
            (source_id, conversation_id),
        ).fetchall()
        return {
            "source_id": source_id,
            "provider": conversation["provider"],
            "provider_schema_version": conversation["provider_schema_version"],
            "conversation_id": conversation_id,
            "provider_conversation_id": conversation["provider_conversation_id"],
            "title": bytes(conversation["title_utf8"]).decode("utf-8"),
            "created_at": conversation["created_at"],
            "canonical_conversation": _decode_json(
                conversation["canonical_json"], field="conversation"
            ),
            "messages": [_result(conn, row, context_radius=0) for row in messages],
        }
    except sqlite3.DatabaseError as err:
        raise CorpusIndexError(f"conversation lookup failed: {err}") from err


def _get_conversation_page_with_connection(
    conn: sqlite3.Connection,
    *,
    source_id: str,
    conversation_id: str,
    limit: int,
    offset: int = 0,
    logical_scope_ids: Optional[Iterable[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Read one exact conversation boundary in deterministic bounded pages."""

    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_RESULTS:
        raise CorpusIndexError(f"limit must be between 1 and {MAX_RESULTS}")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise CorpusIndexError("offset must be a non-negative integer")
    reviewed_scope_ids = _reviewed_scope_ids(logical_scope_ids)
    scope_clause = ""
    scope_parameters: list[Any] = []
    if reviewed_scope_ids is not None:
        scope_clause = " AND " + _history_record_predicate(
            "message_records.record_id", reviewed_scope_ids
        )
        scope_parameters.extend(reviewed_scope_ids)
    try:
        conversation = conn.execute(
            """SELECT * FROM conversation_records
                 WHERE source_id = ? AND conversation_id = ?""",
            (source_id, conversation_id),
        ).fetchone()
        if conversation is None:
            return None
        base_parameters: list[Any] = [
            source_id,
            conversation_id,
            *scope_parameters,
        ]
        total = int(
            conn.execute(
                f"""SELECT COUNT(*) FROM message_records
                      WHERE source_id = ? AND conversation_id = ?
                      {scope_clause}""",
                base_parameters,
            ).fetchone()[0]
        )
        if total == 0:
            return None
        rows = conn.execute(
            f"""SELECT * FROM message_records
                  WHERE source_id = ? AND conversation_id = ?
                  {scope_clause}
                  ORDER BY message_ordinal
                  LIMIT ? OFFSET ?""",
            [*base_parameters, limit, offset],
        ).fetchall()
        messages = [
            _result(
                conn,
                row,
                context_radius=0,
                logical_scope_ids=reviewed_scope_ids,
            )
            for row in rows
        ]
        return {
            "source_id": source_id,
            "provider": conversation["provider"],
            "provider_schema_version": conversation["provider_schema_version"],
            "conversation_id": conversation_id,
            "provider_conversation_id": conversation["provider_conversation_id"],
            "title": bytes(conversation["title_utf8"]).decode("utf-8"),
            "created_at": conversation["created_at"],
            "message_count": total,
            "page_offset": offset,
            "page_count": len(messages),
            "page_start_ordinal": offset if messages else None,
            "page_end_ordinal": offset + len(messages) - 1 if messages else None,
            "has_more": offset + len(messages) < total,
            "messages": messages,
        }
    except sqlite3.DatabaseError as err:
        raise CorpusIndexError(f"conversation page lookup failed: {err}") from err


class ValidatedCorpusReader:
    """Fail-closed read session for an immutable corpus generation.

    Opening performs the same full SQLite, schema, summary, tombstone, and
    authoritative-ledger validation as every one-shot read. Subsequent
    operations reuse the validation result and cached summary, but open a
    short-lived read-only connection under the corpus state lock. Cheap
    pre/post checks reject replacement or mutation without leaving a SQLite
    handle open between operations, so Windows writers can publish atomically.
    A stale reader closes permanently; callers must open a new reader to
    validate the new generation in full. Each reader is deliberately owned by
    the thread that opened it; open one reader per worker thread.
    """

    def __init__(self, index_path: str):
        if not isinstance(index_path, str) or not index_path:
            raise CorpusIndexError("index_path is required")
        self._target = _canonical_path(Path(index_path))
        self._index_path = str(self._target)
        if not self._target.is_file():
            raise CorpusIndexError("corpus index does not exist")
        self._owner_thread_id = threading.get_ident()
        self._conn: Optional[sqlite3.Connection] = None
        self._closed = True
        with corpus_state_lock(self._index_path):
            before = _file_identity(self._target, label="corpus index")
            try:
                conn = sqlite3.connect(_readonly_uri(self._target), uri=True)
                self._conn = conn
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA query_only = ON")
                query_only = conn.execute("PRAGMA query_only").fetchone()
                if query_only is None or query_only[0] != 1:
                    raise CorpusIndexError("SQLite query_only could not be enabled")
                initial_data_version = conn.execute("PRAGMA data_version").fetchone()
                if initial_data_version is None or not isinstance(
                    initial_data_version[0], int
                ):
                    raise CorpusIndexError("cannot read SQLite data_version")
                database_rows = _validate_existing_index(conn)
                ledger_path = _bound_deletion_ledger_path(
                    self._index_path, conn=conn
                )
                ledger_identity, ledger_rows = _ledger_snapshot(
                    self._index_path, ledger_path
                )
                if database_rows != ledger_rows:
                    raise CorpusIndexError(
                        "deletion ledger and corpus index disagree; recovery is required"
                    )
                summary = _summary(conn)
                data_version = conn.execute("PRAGMA data_version").fetchone()
                if data_version is None or not isinstance(data_version[0], int):
                    raise CorpusIndexError("cannot read SQLite data_version")
                if data_version[0] != initial_data_version[0]:
                    raise CorpusIndexError("corpus index changed while being validated")
                after = _file_identity(self._target, label="corpus index")
                if before != after:
                    raise CorpusIndexError("corpus index changed while being validated")
                self._index_identity = after
                self._ledger_path = ledger_path
                self._ledger_identity = ledger_identity
                self._ledger_rows = tuple(ledger_rows)
                self._summary = dict(summary)
                self._data_version = int(data_version[0])
                self._closed = False
            except (OSError, sqlite3.DatabaseError, CorpusIndexError):
                self._closed = True
                raise
            finally:
                conn = self._conn
                self._conn = None
                if conn is not None:
                    conn.close()

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        conn = self._conn
        if not self._closed and threading.get_ident() != self._owner_thread_id:
            raise CorpusIndexError(
                "validated corpus reader is owned by a different thread"
            )
        self._conn = None
        self._closed = True
        if conn is not None:
            conn.close()

    def __enter__(self) -> "ValidatedCorpusReader":
        if self._closed:
            raise CorpusIndexError("validated corpus reader is closed")
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def _connection(self) -> sqlite3.Connection:
        if self._closed or self._conn is None:
            raise CorpusIndexError("validated corpus reader is closed")
        if threading.get_ident() != self._owner_thread_id:
            raise CorpusIndexError(
                "validated corpus reader is owned by a different thread"
            )
        return self._conn

    def _assert_fresh(self) -> None:
        conn = self._connection()
        try:
            if _file_identity(self._target, label="corpus index") != self._index_identity:
                raise CorpusIndexError("corpus index identity changed")
            query_only = conn.execute("PRAGMA query_only").fetchone()
            if query_only is None or query_only[0] != 1:
                raise CorpusIndexError("SQLite query_only is no longer enabled")
            data_version = conn.execute("PRAGMA data_version").fetchone()
            if data_version is None or data_version[0] != self._data_version:
                raise CorpusIndexError("SQLite data_version changed")
            _require_schema(conn)
            for key in ("corpus_id", "index_generation"):
                row = conn.execute(
                    "SELECT value FROM corpus_meta WHERE key = ?", (key,)
                ).fetchone()
                if row is None or row[0] != self._summary[key]:
                    raise CorpusIndexError(f"corpus metadata changed: {key}")
            if _bound_deletion_ledger_path(
                self._index_path, conn=conn
            ) != self._ledger_path:
                raise CorpusIndexError("corpus deletion-ledger binding changed")
            database_rows = _database_tombstone_rows(conn)
            ledger_identity, ledger_rows = _ledger_snapshot(
                self._index_path, self._ledger_path
            )
            if ledger_identity != self._ledger_identity:
                raise CorpusIndexError("corpus deletion ledger identity changed")
            if tuple(ledger_rows) != self._ledger_rows:
                raise CorpusIndexError("corpus deletion ledger content changed")
            if tuple(database_rows) != self._ledger_rows:
                raise CorpusIndexError(
                    "deletion ledger and corpus index disagree; recovery is required"
                )
            if _file_identity(self._target, label="corpus index") != self._index_identity:
                raise CorpusIndexError("corpus index identity changed")
            final_data_version = conn.execute("PRAGMA data_version").fetchone()
            if final_data_version is None or final_data_version[0] != self._data_version:
                raise CorpusIndexError("SQLite data_version changed")
        except (sqlite3.DatabaseError, CorpusIndexError) as err:
            self.close()
            raise CorpusIndexError(
                f"validated corpus reader freshness check failed: {err}"
            ) from err

    def _operate(self, operation: Callable[[], _ResultT]) -> _ResultT:
        if self._closed:
            raise CorpusIndexError("validated corpus reader is closed")
        if threading.get_ident() != self._owner_thread_id:
            raise CorpusIndexError(
                "validated corpus reader is owned by a different thread"
            )
        with corpus_state_lock(self._index_path):
            conn: Optional[sqlite3.Connection] = None
            try:
                conn = sqlite3.connect(_readonly_uri(self._target), uri=True)
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA query_only = ON")
                query_only = conn.execute("PRAGMA query_only").fetchone()
                if query_only is None or query_only[0] != 1:
                    raise CorpusIndexError("SQLite query_only could not be enabled")
                data_version = conn.execute("PRAGMA data_version").fetchone()
                if data_version is None or not isinstance(data_version[0], int):
                    raise CorpusIndexError("cannot read SQLite data_version")
                self._data_version = int(data_version[0])
                self._conn = conn
                self._assert_fresh()
                result = operation()
                self._assert_fresh()
                return result
            except sqlite3.DatabaseError as err:
                self.close()
                raise CorpusIndexError(
                    f"validated corpus reader operation failed: {err}"
                ) from err
            finally:
                if self._conn is not None:
                    self._conn.close()
                self._conn = None

    def inspect(self) -> Dict[str, Any]:
        return self._operate(lambda: dict(self._summary))

    def list_tombstones(self) -> List[Dict[str, str]]:
        def operation() -> List[Dict[str, str]]:
            return [
                {
                    "tombstone_id": row[0],
                    "source_id": row[1],
                    "conversation_id": row[2],
                    "selector_type": row[3],
                }
                for row in self._ledger_rows
            ]

        return self._operate(operation)

    def list_source_states(self) -> List[Dict[str, Any]]:
        def operation() -> List[Dict[str, Any]]:
            try:
                return [
                    {
                        "source_id": row[0],
                        "projection_sha256": row[1],
                        "conversation_count": row[2],
                        "message_count": row[3],
                    }
                    for row in self._connection().execute(
                        """SELECT source_id, projection_sha256,
                                  conversation_count, message_count
                             FROM source_records ORDER BY source_id"""
                    ).fetchall()
                ]
            except sqlite3.DatabaseError as err:
                raise CorpusIndexError(f"cannot list corpus sources: {err}") from err

        return self._operate(operation)

    def scan_history_records(
        self, *, after_message_pk: int = 0, limit: int = MAX_RESULTS
    ) -> Dict[str, Any]:
        """Return a compact, keyset-paged projection for offline sidecars."""

        return self._operate(
            lambda: _scan_history_records_with_connection(
                self._connection(),
                dict(self._summary),
                after_message_pk=after_message_pk,
                limit=limit,
            )
        )

    def search(
        self,
        *,
        query: Optional[str] = None,
        providers: Optional[Iterable[str]] = None,
        source_ids: Optional[Iterable[str]] = None,
        conversation_ids: Optional[Iterable[str]] = None,
        roles: Optional[Iterable[str]] = None,
        models: Optional[Iterable[str]] = None,
        content_types: Optional[Iterable[str]] = None,
        created_from: Optional[str] = None,
        created_to: Optional[str] = None,
        include_attachment_text: bool = False,
        match_mode: str = "fts",
        context_radius: int = 1,
        limit: int = 50,
        offset: int = 0,
        max_substring_scan_rows: int = 10_000,
    ) -> Dict[str, Any]:
        return self._operate(
            lambda: _search_corpus_with_connection(
                self._connection(),
                dict(self._summary),
                query=query,
                providers=providers,
                source_ids=source_ids,
                conversation_ids=conversation_ids,
                roles=roles,
                models=models,
                content_types=content_types,
                created_from=created_from,
                created_to=created_to,
                include_attachment_text=include_attachment_text,
                match_mode=match_mode,
                context_radius=context_radius,
                limit=limit,
                offset=offset,
                max_substring_scan_rows=max_substring_scan_rows,
            )
        )

    def get_message(
        self,
        *,
        source_id: str,
        conversation_id: str,
        message_id: str,
        context_radius: int = 1,
    ) -> Optional[Dict[str, Any]]:
        return self._operate(
            lambda: _get_message_with_connection(
                self._connection(),
                source_id=source_id,
                conversation_id=conversation_id,
                message_id=message_id,
                context_radius=context_radius,
            )
        )

    def get_conversation(
        self, *, source_id: str, conversation_id: str
    ) -> Optional[Dict[str, Any]]:
        return self._operate(
            lambda: _get_conversation_with_connection(
                self._connection(),
                source_id=source_id,
                conversation_id=conversation_id,
            )
        )

    def get_conversation_page(
        self,
        *,
        source_id: str,
        conversation_id: str,
        limit: int,
        offset: int = 0,
    ) -> Optional[Dict[str, Any]]:
        return self._operate(
            lambda: _get_conversation_page_with_connection(
                self._connection(),
                source_id=source_id,
                conversation_id=conversation_id,
                limit=limit,
                offset=offset,
            )
        )


CorpusReader = ValidatedCorpusReader


def search_corpus(
    index_path: str,
    *,
    query: Optional[str] = None,
    providers: Optional[Iterable[str]] = None,
    source_ids: Optional[Iterable[str]] = None,
    conversation_ids: Optional[Iterable[str]] = None,
    roles: Optional[Iterable[str]] = None,
    models: Optional[Iterable[str]] = None,
    content_types: Optional[Iterable[str]] = None,
    created_from: Optional[str] = None,
    created_to: Optional[str] = None,
    include_attachment_text: bool = False,
    match_mode: str = "fts",
    context_radius: int = 1,
    limit: int = 50,
    offset: int = 0,
    max_substring_scan_rows: int = 10_000,
) -> Dict[str, Any]:
    """Run one fully validated read-only corpus search."""

    with ValidatedCorpusReader(index_path) as reader:
        return reader.search(
            query=query,
            providers=providers,
            source_ids=source_ids,
            conversation_ids=conversation_ids,
            roles=roles,
            models=models,
            content_types=content_types,
            created_from=created_from,
            created_to=created_to,
            include_attachment_text=include_attachment_text,
            match_mode=match_mode,
            context_radius=context_radius,
            limit=limit,
            offset=offset,
            max_substring_scan_rows=max_substring_scan_rows,
        )


def get_message(
    index_path: str,
    *,
    source_id: str,
    conversation_id: str,
    message_id: str,
    context_radius: int = 1,
) -> Optional[Dict[str, Any]]:
    with ValidatedCorpusReader(index_path) as reader:
        return reader.get_message(
            source_id=source_id,
            conversation_id=conversation_id,
            message_id=message_id,
            context_radius=context_radius,
        )


def get_conversation(
    index_path: str, *, source_id: str, conversation_id: str,
) -> Optional[Dict[str, Any]]:
    with ValidatedCorpusReader(index_path) as reader:
        return reader.get_conversation(
            source_id=source_id, conversation_id=conversation_id
        )


__all__ = [
    "CORPUS_HISTORY_SCAN_SCHEMA_VERSION",
    "CORPUS_INTEGRITY_SCHEMA_VERSION",
    "CORPUS_INDEX_SCHEMA_VERSION",
    "CORPUS_SEARCH_SCHEMA_VERSION",
    "CorpusReader",
    "CorpusIndexError",
    "ValidatedCorpusReader",
    "build_corpus_index",
    "upsert_corpus_sources",
    "inspect_corpus_index",
    "inspect_corpus_integrity",
    "resolve_corpus_deletion_ledger_path",
    "list_corpus_tombstones",
    "list_corpus_source_states",
    "forget_corpus_conversations",
    "search_corpus",
    "get_message",
    "get_conversation",
]
