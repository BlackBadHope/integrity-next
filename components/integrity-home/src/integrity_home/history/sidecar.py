"""Versioned record-level catalog and logical-scope sidecar for History.

The sidecar is a rebuildable projection bound to one exact corpus logical
generation.  It never stores message text, titles, excerpts, canonical JSON,
or classifier evidence strings.  Automatic catalog labels remain routing
hints; only an explicit reviewed include decision selects a named scope.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import stat as stat_module
import tempfile
import threading
from typing import Any, Final, Literal, TypeAlias, TypeVar, cast
from urllib.parse import quote

from integrity_chronicle.corpus_index import (
    CorpusIndexError,
    ValidatedCorpusReader,
    _get_conversation_page_with_connection,
    _get_message_with_connection,
    _search_corpus_with_connection,
    inspect_corpus_integrity,
    resolve_corpus_deletion_ledger_path,
)
from integrity_chronicle.json_integrity import loads_json_strict
from integrity_chronicle.state_lock import corpus_state_lock

from .catalog import (
    CLASSIFIER_ID,
    CLASSIFIER_VERSION,
    CatalogBudgetError,
    CatalogInput,
    CatalogLabels,
    CatalogMetadata,
    WorkSummary,
    classify_record,
)


HISTORY_SIDECAR_SCHEMA_VERSION: Final = "integrity-home-history-sidecar/2"
HISTORY_VIEW_SCHEMA_VERSION: Final = "integrity-home-history-view/1"
PERSONAL_SCOPE_ID: Final = "personal:core"
INFERRED_SCOPE_REASON_CODE: Final = "classifier.scope-hint"
REVIEWED_SCOPE_REASON_CODE: Final = "owner.review"

MAX_LOGICAL_SCOPES: Final = 64
MAX_RECORDS: Final = 1_000_000
MAX_SCOPE_DECISIONS: Final = 4_000_000
MAX_DECISIONS_PER_RECORD: Final = 64
MAX_IDENTIFIER_CHARS: Final = 1_024
MAX_DISPLAY_NAME_CHARS: Final = 128
MAX_REASON_CODE_CHARS: Final = 128
MAX_PAGE_SIZE: Final = 100
MAX_PAGE_OFFSET: Final = 1_000_000
MAX_DECISION_PAGE_SIZE: Final = 1_000
SCAN_BATCH_SIZE: Final = 500

Membership: TypeAlias = Literal["exclude", "include", "unknown"]
ReviewState: TypeAlias = Literal["inferred", "reviewed"]
ScopeKind: TypeAlias = Literal["personal", "project", "public"]
Realm: TypeAlias = Literal["personal", "work", "public"]

_MEMBERSHIPS = frozenset(("exclude", "include", "unknown"))
_REVIEW_STATES = frozenset(("inferred", "reviewed"))
_SCOPE_KINDS = frozenset(("personal", "project", "public"))
_REALMS = frozenset(("personal", "work", "public"))
_CLASSIFICATION_STATES = frozenset(("classified", "unclassified_budget"))
_STABLE_ID = re.compile(
    r"^[a-z0-9](?:[a-z0-9._-]{0,63})(?::[a-z0-9][a-z0-9._-]{0,63})*$"
)
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")

_TABLE_COLUMNS: Final = {
    "history_meta": (
        ("key", "TEXT", 0, 1),
        ("value", "TEXT", 1, 0),
    ),
    "logical_scopes": (
        ("scope_id", "TEXT", 0, 1),
        ("display_name", "TEXT", 1, 0),
        ("scope_kind", "TEXT", 1, 0),
        ("realm", "TEXT", 1, 0),
        ("project_id", "TEXT", 0, 0),
    ),
    "catalog_records": (
        ("record_id", "TEXT", 0, 1),
        ("source_id", "TEXT", 1, 0),
        ("provider", "TEXT", 1, 0),
        ("conversation_id", "TEXT", 1, 0),
        ("message_id", "TEXT", 1, 0),
        ("role", "TEXT", 1, 0),
        ("content_type", "TEXT", 1, 0),
        ("content_sha256", "TEXT", 1, 0),
        ("classification_state", "TEXT", 1, 0),
        ("catalog_json", "BLOB", 1, 0),
    ),
    "scope_decisions": (
        ("record_id", "TEXT", 1, 1),
        ("scope_id", "TEXT", 1, 2),
        ("membership", "TEXT", 1, 0),
        ("review_state", "TEXT", 1, 0),
        ("artifact_sha256", "TEXT", 1, 0),
        ("reason_code", "TEXT", 1, 0),
    ),
}
_OBJECTS: Final = {
    ("index", "scope_decision_view_idx"),
    *(("table", name) for name in _TABLE_COLUMNS),
}
_META_KEYS: Final = frozenset(
    (
        "base_record_count",
        "base_record_digest",
        "classifier_id",
        "classifier_version",
        "corpus_id",
        "corpus_deletion_ledger_digest",
        "corpus_logical_index_sha256",
        "decision_count",
        "index_generation",
        "schema_version",
        "scope_count",
        "sidecar_generation",
    )
)


class HistorySidecarError(RuntimeError):
    """A sidecar could not be built or read without weakening its contract."""


class HistorySidecarSchemaError(HistorySidecarError):
    """A sidecar input or stored schema is malformed or ambiguous."""


class HistorySidecarStaleError(HistorySidecarError):
    """The sidecar and corpus no longer describe one exact snapshot."""


def _stable_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _hex_digest(value: object, *, field: str) -> str:
    if type(value) is not str or _HEX_256.fullmatch(value) is None:
        raise HistorySidecarSchemaError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _bounded_text(value: object, *, field: str, maximum: int) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    ):
        raise HistorySidecarSchemaError(f"{field} must be bounded printable text")
    return value


def _stable_id(value: object, *, field: str) -> str:
    text = _bounded_text(value, field=field, maximum=128)
    if _STABLE_ID.fullmatch(text) is None:
        raise HistorySidecarSchemaError(f"{field} must be a stable lowercase identifier")
    return text


@dataclass(frozen=True, slots=True)
class LogicalScope:
    scope_id: str
    display_name: str
    scope_kind: ScopeKind
    realm: Realm
    project_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope_id", _stable_id(self.scope_id, field="scope_id"))
        object.__setattr__(
            self,
            "display_name",
            _bounded_text(
                self.display_name,
                field="display_name",
                maximum=MAX_DISPLAY_NAME_CHARS,
            ),
        )
        if self.scope_kind not in _SCOPE_KINDS:
            raise HistorySidecarSchemaError("scope_kind is invalid")
        if self.realm not in _REALMS:
            raise HistorySidecarSchemaError("realm is invalid")
        project_id = self.project_id
        if project_id is not None:
            project_id = _stable_id(project_id, field="project_id")
            object.__setattr__(self, "project_id", project_id)
        if self.scope_kind == "project" and project_id is None:
            raise HistorySidecarSchemaError("project scopes require project_id")
        if self.scope_kind != "project" and project_id is not None:
            raise HistorySidecarSchemaError("only project scopes may define project_id")
        if self.scope_kind == "personal" and self.realm != "personal":
            raise HistorySidecarSchemaError("personal scopes require realm=personal")
        if self.scope_kind == "public" and self.realm != "public":
            raise HistorySidecarSchemaError("public scopes require realm=public")

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "display_name": self.display_name,
            "realm": self.realm,
            "scope_id": self.scope_id,
            "scope_kind": self.scope_kind,
        }
        if self.project_id is not None:
            payload["project_id"] = self.project_id
        return payload


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    record_id: str
    scope_id: str
    membership: Membership
    review_state: ReviewState
    artifact_sha256: str
    reason_code: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "record_id", _hex_digest(self.record_id, field="record_id")
        )
        object.__setattr__(self, "scope_id", _stable_id(self.scope_id, field="scope_id"))
        if self.membership not in _MEMBERSHIPS:
            raise HistorySidecarSchemaError("membership is invalid")
        if self.review_state not in _REVIEW_STATES:
            raise HistorySidecarSchemaError("review_state is invalid")
        object.__setattr__(
            self,
            "artifact_sha256",
            _hex_digest(self.artifact_sha256, field="artifact_sha256"),
        )
        reason_code = _stable_id(self.reason_code, field="reason_code")
        expected_reason = (
            REVIEWED_SCOPE_REASON_CODE
            if self.review_state == "reviewed"
            else INFERRED_SCOPE_REASON_CODE
        )
        if reason_code != expected_reason:
            raise HistorySidecarSchemaError(
                "reason_code does not match the scope-decision review state"
            )
        object.__setattr__(self, "reason_code", reason_code)

    def to_dict(self) -> dict[str, str]:
        return {
            "artifact_sha256": self.artifact_sha256,
            "membership": self.membership,
            "reason_code": self.reason_code,
            "review_state": self.review_state,
            "scope_id": self.scope_id,
        }


DEFAULT_LOGICAL_SCOPES: Final = (
    LogicalScope(
        scope_id=PERSONAL_SCOPE_ID,
        display_name="Personal",
        scope_kind="personal",
        realm="personal",
    ),
)


def _canonical_existing_file(value: str, *, label: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise HistorySidecarSchemaError(f"{label} path is required")
    raw = Path(value).expanduser()
    if not raw.is_absolute():
        raise HistorySidecarSchemaError(f"{label} path must be absolute")
    if raw.is_symlink():
        raise HistorySidecarSchemaError(f"{label} path must not be a symlink")
    target = raw.resolve(strict=False)
    if not target.is_file():
        raise HistorySidecarSchemaError(f"{label} does not exist")
    return target


def _canonical_sidecar_target(value: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise HistorySidecarSchemaError("sidecar path is required")
    raw = Path(value).expanduser()
    if not raw.is_absolute():
        raise HistorySidecarSchemaError("sidecar path must be absolute")
    if raw.is_symlink():
        raise HistorySidecarSchemaError("sidecar path must not be a symlink")
    target = raw.resolve(strict=False)
    if target.exists() and not target.is_file():
        raise HistorySidecarSchemaError("sidecar path must be a regular file")
    return target


def _path_key(path: Path) -> str:
    value = os.path.normpath(str(path))
    return os.path.normcase(value) if os.name == "nt" else value


def _authoritative_ledger(corpus: Path) -> Path:
    ledger = Path(resolve_corpus_deletion_ledger_path(str(corpus))).resolve(
        strict=False
    )
    if not ledger.is_file():
        raise HistorySidecarSchemaError("authoritative deletion ledger does not exist")
    return ledger


def _reject_path_aliases(corpus: Path, sidecar: Path, ledger: Path) -> None:
    protected = {_path_key(corpus), _path_key(ledger)}
    if _path_key(sidecar) in protected:
        raise HistorySidecarSchemaError(
            "sidecar path must differ from the corpus and deletion ledger"
        )


def _assert_ledger_binding(corpus: Path, ledger: Path) -> None:
    current = Path(resolve_corpus_deletion_ledger_path(str(corpus))).resolve(
        strict=False
    )
    if _path_key(current) != _path_key(ledger):
        raise HistorySidecarStaleError("corpus deletion-ledger binding changed")


def _file_identity(path: Path, *, label: str) -> tuple[int, int, int, int, int]:
    try:
        state = path.stat()
    except OSError as err:
        raise HistorySidecarStaleError(f"cannot stat {label}: {err}") from err
    if not stat_module.S_ISREG(state.st_mode):
        raise HistorySidecarStaleError(f"{label} is not a regular file")
    return (
        int(state.st_dev),
        int(state.st_ino),
        int(state.st_size),
        int(state.st_mtime_ns),
        int(state.st_ctime_ns),
    )


def _readonly_uri(path: Path) -> str:
    return f"file:{quote(str(path).replace(os.sep, '/'), safe='/:')}?mode=ro"


@contextmanager
def _snapshot_locks(sidecar: Path, corpus: Path, ledger: Path):
    """Use one order: sidecar lock, corpus lock, then bound-ledger lock."""

    with corpus_state_lock(str(sidecar)):
        with corpus_state_lock(str(corpus)):
            with corpus_state_lock(str(ledger)):
                yield


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA secure_delete = ON")
    conn.executescript(
        """
        CREATE TABLE history_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE logical_scopes (
            scope_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            scope_kind TEXT NOT NULL,
            realm TEXT NOT NULL,
            project_id TEXT
        );
        CREATE TABLE catalog_records (
            record_id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            conversation_id TEXT NOT NULL,
            message_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content_type TEXT NOT NULL,
            content_sha256 TEXT NOT NULL,
            classification_state TEXT NOT NULL,
            catalog_json BLOB NOT NULL,
            UNIQUE(source_id, conversation_id, message_id)
        );
        CREATE TABLE scope_decisions (
            record_id TEXT NOT NULL REFERENCES catalog_records(record_id),
            scope_id TEXT NOT NULL REFERENCES logical_scopes(scope_id),
            membership TEXT NOT NULL,
            review_state TEXT NOT NULL,
            artifact_sha256 TEXT NOT NULL,
            reason_code TEXT NOT NULL,
            PRIMARY KEY(record_id, scope_id)
        );
        CREATE INDEX scope_decision_view_idx
            ON scope_decisions(scope_id, review_state, membership, record_id);
        """
    )


def _role_authority(role: str) -> tuple[str, ...]:
    if role == "user":
        return ("user_assertion",)
    if role == "assistant":
        return ("assistant_output",)
    if role == "system":
        return ("system_metadata",)
    return ("unknown",)


def _catalog_projection(content: str, role: str) -> tuple[str, bytes]:
    metadata = CatalogMetadata(
        record_kind="message",
        authority=cast(Any, _role_authority(role)),
        sensitivity=("unknown",),
    )
    try:
        result = classify_record(CatalogInput(text=content, metadata=metadata))
    except CatalogBudgetError:
        state = "unclassified_budget"
        labels = {
            "authority": list(metadata.authority),
            "domain": ["unknown"],
            "record_kind": ["message"],
            "sensitivity": ["unknown"],
            "subject": ["unknown"],
        }
        work: dict[str, int] | None = None
    else:
        state = "classified"
        labels = result.labels.to_dict()
        work = result.work.to_dict()
    payload = {
        "classification_state": state,
        "classifier": {"id": CLASSIFIER_ID, "version": CLASSIFIER_VERSION},
        "labels": labels,
        "work": work,
    }
    return state, _stable_json(payload).encode("utf-8")


def _corpus_base_row(value: Mapping[str, object]) -> tuple[str, ...]:
    fields = (
        "record_id",
        "source_id",
        "provider",
        "conversation_id",
        "message_id",
        "role",
        "content_type",
        "content_sha256",
    )
    row = tuple(
        _bounded_text(value.get(field), field=field, maximum=MAX_IDENTIFIER_CHARS)
        for field in fields
    )
    _hex_digest(row[0], field="record_id")
    _hex_digest(row[7], field="content_sha256")
    content = value.get("content")
    if type(content) is not str:
        raise HistorySidecarSchemaError("corpus content must be text")
    try:
        actual_content_sha256 = sha256(content.encode("utf-8")).hexdigest()
    except UnicodeEncodeError as err:
        raise HistorySidecarSchemaError("corpus content is not valid UTF-8") from err
    if actual_content_sha256 != row[7]:
        raise HistorySidecarStaleError("corpus content digest mismatch")
    return row


def _scan_into_sidecar(
    reader: ValidatedCorpusReader,
    conn: sqlite3.Connection,
    *,
    expected: Mapping[str, object],
    verify_existing: bool,
) -> int:
    expected_count = expected.get("message_count")
    if type(expected_count) is not int or not 0 <= expected_count <= MAX_RECORDS:
        raise HistorySidecarSchemaError("corpus message count exceeds sidecar budget")
    if verify_existing:
        conn.execute("CREATE TEMP TABLE scan_seen(record_id TEXT PRIMARY KEY)")
    offset = 0
    cursor = 0
    try:
        while offset < expected_count:
            page = reader.scan_history_records(
                after_message_pk=cursor,
                limit=min(SCAN_BATCH_SIZE, expected_count - offset),
            )
            for key in ("corpus_id", "index_generation", "message_count"):
                if page.get(key) != expected.get(key):
                    raise HistorySidecarStaleError(
                        f"corpus changed while sidecar was scanning: {key}"
                    )
            results = page.get("results")
            if type(results) is not list or not results:
                raise HistorySidecarStaleError("corpus scan ended before message_count")
            for value in results:
                if not isinstance(value, Mapping):
                    raise HistorySidecarSchemaError("corpus scan returned an invalid row")
                row = _corpus_base_row(value)
                if verify_existing:
                    stored = conn.execute(
                        """SELECT record_id, source_id, provider, conversation_id,
                                  message_id, role, content_type, content_sha256
                             FROM catalog_records WHERE record_id = ?""",
                        (row[0],),
                    ).fetchone()
                    if stored is None or tuple(stored) != row:
                        raise HistorySidecarStaleError(
                            "corpus record set differs from staged sidecar"
                        )
                    try:
                        conn.execute("INSERT INTO scan_seen(record_id) VALUES (?)", (row[0],))
                    except sqlite3.IntegrityError as err:
                        raise HistorySidecarStaleError(
                            "corpus scan returned a duplicate record_id"
                        ) from err
                else:
                    content = cast(str, value["content"])
                    classification_state, catalog_json = _catalog_projection(
                        content, row[5]
                    )
                    try:
                        conn.execute(
                            """INSERT INTO catalog_records(
                                   record_id, source_id, provider, conversation_id,
                                   message_id, role, content_type, content_sha256,
                                   classification_state, catalog_json
                               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (*row, classification_state, catalog_json),
                        )
                    except sqlite3.IntegrityError as err:
                        raise HistorySidecarSchemaError(
                            "corpus scan contains duplicate record identity"
                        ) from err
                offset += 1
                if offset > expected_count:
                    raise HistorySidecarStaleError(
                        "corpus scan exceeded declared message_count"
                    )
            next_cursor = page.get("next_after_message_pk")
            if offset < expected_count:
                if type(next_cursor) is not int or next_cursor <= cursor:
                    raise HistorySidecarStaleError(
                        "corpus scan cursor ended before message_count"
                    )
                cursor = next_cursor
            elif page.get("complete") is not True:
                raise HistorySidecarStaleError(
                    "corpus scan contains more rows than declared"
                )
        if offset != expected_count:
            raise HistorySidecarStaleError("corpus scan count mismatch")
        if verify_existing:
            seen_count = conn.execute("SELECT COUNT(*) FROM scan_seen").fetchone()[0]
            stored_count = conn.execute("SELECT COUNT(*) FROM catalog_records").fetchone()[0]
            if seen_count != expected_count or stored_count != expected_count:
                raise HistorySidecarStaleError("sidecar does not exactly cover corpus records")
        return offset
    finally:
        if verify_existing:
            conn.execute("DROP TABLE IF EXISTS scan_seen")


def _hash_rows(
    conn: sqlite3.Connection,
    query: str,
    *,
    domain: str,
) -> str:
    digest = sha256()
    digest.update(domain.encode("ascii") + b"\x00")
    for row in conn.execute(query):
        encoded = _stable_json(list(row)).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _base_record_digest(conn: sqlite3.Connection) -> str:
    return _hash_rows(
        conn,
        """SELECT record_id, source_id, provider, conversation_id, message_id,
                  role, content_type, content_sha256
             FROM catalog_records ORDER BY record_id""",
        domain="integrity-home-history-base-records/1",
    )


def _sidecar_generation(conn: sqlite3.Connection) -> str:
    digest = sha256()
    digest.update(b"integrity-home-history-sidecar-generation/1\x00")
    meta = [
        list(row)
        for row in conn.execute(
            """SELECT key, value FROM history_meta
                 WHERE key <> 'sidecar_generation' ORDER BY key"""
        )
    ]
    sections = (
        ("meta", meta),
        (
            "scopes",
            conn.execute(
                """SELECT scope_id, display_name, scope_kind, realm, project_id
                     FROM logical_scopes ORDER BY scope_id"""
            ),
        ),
        (
            "records",
            conn.execute(
                """SELECT record_id, source_id, provider, conversation_id,
                          message_id, role, content_type, content_sha256,
                          classification_state, hex(catalog_json)
                     FROM catalog_records ORDER BY record_id"""
            ),
        ),
        (
            "decisions",
            conn.execute(
                """SELECT record_id, scope_id, membership, review_state,
                          artifact_sha256, reason_code
                     FROM scope_decisions ORDER BY record_id, scope_id"""
            ),
        ),
    )
    for name, rows in sections:
        digest.update(name.encode("ascii") + b"\x00")
        for row in rows:
            encoded = _stable_json(list(row)).encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
    return digest.hexdigest()


def _parse_nonnegative_int(value: object, *, field: str, maximum: int) -> int:
    if type(value) is not str or not value or (value != "0" and value.startswith("0")):
        raise HistorySidecarSchemaError(f"stored {field} is not canonical")
    try:
        number = int(value)
    except ValueError as err:
        raise HistorySidecarSchemaError(f"stored {field} is invalid") from err
    if not 0 <= number <= maximum or str(number) != value:
        raise HistorySidecarSchemaError(f"stored {field} is outside its budget")
    return number


def _validate_catalog_json(value: object, *, state: str) -> dict[str, object]:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise HistorySidecarSchemaError("catalog_json must be bytes")
    try:
        payload = loads_json_strict(bytes(value).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as err:
        raise HistorySidecarSchemaError("catalog_json is corrupt") from err
    if not isinstance(payload, Mapping) or set(payload) != {
        "classification_state",
        "classifier",
        "labels",
        "work",
    }:
        raise HistorySidecarSchemaError("catalog_json fields do not match schema v1")
    if payload.get("classification_state") != state:
        raise HistorySidecarSchemaError("catalog classification state mismatch")
    classifier = payload.get("classifier")
    if not isinstance(classifier, Mapping) or dict(classifier) != {
        "id": CLASSIFIER_ID,
        "version": CLASSIFIER_VERSION,
    }:
        raise HistorySidecarSchemaError("catalog classifier mismatch")
    labels = payload.get("labels")
    if not isinstance(labels, Mapping) or set(labels) != {
        "authority",
        "domain",
        "record_kind",
        "sensitivity",
        "subject",
    }:
        raise HistorySidecarSchemaError("catalog labels do not match schema v1")
    try:
        validated_labels = CatalogLabels(
            authority=tuple(labels["authority"]),
            domain=tuple(labels["domain"]),
            record_kind=tuple(labels["record_kind"]),
            sensitivity=tuple(labels["sensitivity"]),
            subject=tuple(labels["subject"]),
        )
    except (KeyError, TypeError, ValueError) as err:
        raise HistorySidecarSchemaError("catalog labels are invalid") from err
    if validated_labels.record_kind != ("message",):
        raise HistorySidecarSchemaError("sidecar v2 supports message records only")
    work = payload.get("work")
    if state == "classified":
        if not isinstance(work, Mapping) or set(work) != {
            "normalized_chars",
            "token_count",
            "token_work",
        }:
            raise HistorySidecarSchemaError("catalog work summary is invalid")
        try:
            WorkSummary(
                normalized_chars=work["normalized_chars"],
                token_count=work["token_count"],
                token_work=work["token_work"],
            )
        except (KeyError, TypeError, ValueError) as err:
            raise HistorySidecarSchemaError("catalog work summary is invalid") from err
    elif work is not None:
        raise HistorySidecarSchemaError("unclassified records cannot claim work output")
    return dict(payload)


def _stored_scope(row: Sequence[object]) -> LogicalScope:
    return LogicalScope(
        scope_id=cast(str, row[0]),
        display_name=cast(str, row[1]),
        scope_kind=cast(ScopeKind, row[2]),
        realm=cast(Realm, row[3]),
        project_id=cast(str | None, row[4]),
    )


def _stored_decision(row: Sequence[object]) -> ScopeDecision:
    return ScopeDecision(
        record_id=cast(str, row[0]),
        scope_id=cast(str, row[1]),
        membership=cast(Membership, row[2]),
        review_state=cast(ReviewState, row[3]),
        artifact_sha256=cast(str, row[4]),
        reason_code=cast(str, row[5]),
    )


def _validate_schema_objects(conn: sqlite3.Connection) -> None:
    objects = {
        (row[0], row[1])
        for row in conn.execute(
            """SELECT type, name FROM sqlite_master
                 WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"""
        )
    }
    if objects != _OBJECTS:
        raise HistorySidecarSchemaError("sidecar SQLite objects do not match schema v1")
    for table, expected in _TABLE_COLUMNS.items():
        actual = tuple(
            (row[1], row[2], row[3], row[5])
            for row in conn.execute(f'PRAGMA table_info("{table}")')
        )
        if actual != expected:
            raise HistorySidecarSchemaError(f"sidecar table contract mismatch: {table}")
    expected_indexes = {
        "history_meta": {(1, "pk", ("key",), 0)},
        "logical_scopes": {(1, "pk", ("scope_id",), 0)},
        "catalog_records": {
            (1, "pk", ("record_id",), 0),
            (1, "u", ("source_id", "conversation_id", "message_id"), 0),
        },
        "scope_decisions": {
            (1, "pk", ("record_id", "scope_id"), 0),
            (
                0,
                "c",
                ("scope_id", "review_state", "membership", "record_id"),
                0,
            ),
        },
    }
    for table, expected in expected_indexes.items():
        actual = set()
        for row in conn.execute(f'PRAGMA index_list("{table}")'):
            columns = tuple(
                item[2]
                for item in conn.execute(f'PRAGMA index_info("{row[1]}")')
            )
            actual.add((row[2], row[3], columns, row[4]))
        if actual != expected:
            raise HistorySidecarSchemaError(
                f"sidecar index contract mismatch: {table}"
            )
    expected_foreign_keys = {
        (
            "scope_decisions",
            "record_id",
            "catalog_records",
            "record_id",
            "NO ACTION",
            "NO ACTION",
        ),
        (
            "scope_decisions",
            "scope_id",
            "logical_scopes",
            "scope_id",
            "NO ACTION",
            "NO ACTION",
        ),
    }
    actual_foreign_keys = set()
    for table in _TABLE_COLUMNS:
        for row in conn.execute(f'PRAGMA foreign_key_list("{table}")'):
            actual_foreign_keys.add(
                (table, row[3], row[2], row[4], row[5], row[6])
            )
    if actual_foreign_keys != expected_foreign_keys:
        raise HistorySidecarSchemaError("sidecar foreign-key contract mismatch")


def _validate_sidecar_connection(
    conn: sqlite3.Connection,
    *,
    corpus_integrity: Mapping[str, object] | None,
) -> dict[str, object]:
    conn.row_factory = sqlite3.Row
    integrity_rows = [row[0] for row in conn.execute("PRAGMA integrity_check")]
    if integrity_rows != ["ok"]:
        raise HistorySidecarSchemaError("sidecar SQLite integrity check failed")
    if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise HistorySidecarSchemaError("sidecar foreign-key check failed")
    _validate_schema_objects(conn)
    meta_rows = conn.execute("SELECT key, value FROM history_meta ORDER BY key").fetchall()
    meta = {row[0]: row[1] for row in meta_rows}
    if len(meta) != len(meta_rows) or frozenset(meta) != _META_KEYS:
        raise HistorySidecarSchemaError("sidecar metadata fields do not match schema v1")
    if meta["schema_version"] != HISTORY_SIDECAR_SCHEMA_VERSION:
        raise HistorySidecarSchemaError("sidecar schema version mismatch")
    if meta["classifier_id"] != CLASSIFIER_ID or meta["classifier_version"] != CLASSIFIER_VERSION:
        raise HistorySidecarSchemaError("sidecar classifier version mismatch")
    for field in (
        "corpus_id",
        "index_generation",
        "corpus_deletion_ledger_digest",
        "corpus_logical_index_sha256",
        "base_record_digest",
        "sidecar_generation",
    ):
        _hex_digest(meta[field], field=field)
    record_count = _parse_nonnegative_int(
        meta["base_record_count"], field="base_record_count", maximum=MAX_RECORDS
    )
    scope_count = _parse_nonnegative_int(
        meta["scope_count"], field="scope_count", maximum=MAX_LOGICAL_SCOPES
    )
    decision_count = _parse_nonnegative_int(
        meta["decision_count"], field="decision_count", maximum=MAX_SCOPE_DECISIONS
    )
    scopes = conn.execute(
        """SELECT scope_id, display_name, scope_kind, realm, project_id
             FROM logical_scopes ORDER BY scope_id"""
    )
    actual_scope_count = 0
    for row in scopes:
        _stored_scope(tuple(row))
        actual_scope_count += 1
    actual_record_count = 0
    for row in conn.execute(
        """SELECT record_id, source_id, provider, conversation_id, message_id,
                  role, content_type, content_sha256, classification_state,
                  catalog_json FROM catalog_records ORDER BY record_id"""
    ):
        _hex_digest(row[0], field="record_id")
        for index, field in enumerate(
            ("source_id", "provider", "conversation_id", "message_id", "role", "content_type"),
            start=1,
        ):
            _bounded_text(row[index], field=field, maximum=MAX_IDENTIFIER_CHARS)
        _hex_digest(row[7], field="content_sha256")
        if row[8] not in _CLASSIFICATION_STATES:
            raise HistorySidecarSchemaError("classification_state is invalid")
        _validate_catalog_json(row[9], state=row[8])
        actual_record_count += 1
    actual_decision_count = 0
    for row in conn.execute(
        """SELECT record_id, scope_id, membership, review_state,
                  artifact_sha256, reason_code
             FROM scope_decisions ORDER BY record_id, scope_id"""
    ):
        _stored_decision(tuple(row))
        actual_decision_count += 1
    if (actual_scope_count, actual_record_count, actual_decision_count) != (
        scope_count,
        record_count,
        decision_count,
    ):
        raise HistorySidecarSchemaError("sidecar stored counts do not match metadata")
    if _base_record_digest(conn) != meta["base_record_digest"]:
        raise HistorySidecarSchemaError("sidecar base-record digest mismatch")
    if _sidecar_generation(conn) != meta["sidecar_generation"]:
        raise HistorySidecarSchemaError("sidecar generation seal mismatch")
    if corpus_integrity is not None:
        bindings = {
            "corpus_id": "corpus_id",
            "index_generation": "index_generation",
            "corpus_deletion_ledger_digest": "deletion_ledger_digest",
            "corpus_logical_index_sha256": "logical_index_sha256",
            "base_record_count": "message_count",
        }
        for sidecar_key, corpus_key in bindings.items():
            expected = str(corpus_integrity.get(corpus_key))
            if meta[sidecar_key] != expected:
                raise HistorySidecarStaleError(
                    f"sidecar corpus binding mismatch: {sidecar_key}"
                )
    return {
        "schema_version": HISTORY_SIDECAR_SCHEMA_VERSION,
        "sidecar_generation": meta["sidecar_generation"],
        "corpus_id": meta["corpus_id"],
        "index_generation": meta["index_generation"],
        "corpus_deletion_ledger_digest": meta[
            "corpus_deletion_ledger_digest"
        ],
        "corpus_logical_index_sha256": meta["corpus_logical_index_sha256"],
        "base_record_digest": meta["base_record_digest"],
        "record_count": record_count,
        "scope_count": scope_count,
        "decision_count": decision_count,
        "classified_count": conn.execute(
            "SELECT COUNT(*) FROM catalog_records WHERE classification_state = 'classified'"
        ).fetchone()[0],
        "unclassified_budget_count": conn.execute(
            """SELECT COUNT(*) FROM catalog_records
                 WHERE classification_state = 'unclassified_budget'"""
        ).fetchone()[0],
        "decisionless_count": conn.execute(
            """SELECT COUNT(*) FROM catalog_records r
                 WHERE NOT EXISTS (
                    SELECT 1 FROM scope_decisions d WHERE d.record_id = r.record_id
                 )"""
        ).fetchone()[0],
        "unassigned_count": conn.execute(
            """SELECT COUNT(*) FROM catalog_records r
                 WHERE NOT EXISTS (
                    SELECT 1 FROM scope_decisions d
                     WHERE d.record_id = r.record_id
                       AND d.membership = 'include'
                       AND d.review_state = 'reviewed'
                 )"""
        ).fetchone()[0],
        "reviewed_include_count": conn.execute(
            """SELECT COUNT(*) FROM scope_decisions
                 WHERE membership = 'include' AND review_state = 'reviewed'"""
        ).fetchone()[0],
        "inferred_candidate_count": conn.execute(
            "SELECT COUNT(*) FROM scope_decisions WHERE review_state = 'inferred'"
        ).fetchone()[0],
    }


def _private_mode(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        if os.name != "nt":
            raise


def _fsync_file(path: Path) -> None:
    # Windows rejects fsync on a descriptor opened read-only.
    descriptor = os.open(path, os.O_RDWR)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _coerce_scopes(scopes: Iterable[LogicalScope]) -> tuple[LogicalScope, ...]:
    values: list[LogicalScope] = []
    seen: set[str] = set()
    for scope in scopes:
        if type(scope) is not LogicalScope:
            raise HistorySidecarSchemaError("scopes must contain LogicalScope values")
        if scope.scope_id in seen:
            raise HistorySidecarSchemaError("logical scope IDs must be unique")
        seen.add(scope.scope_id)
        values.append(scope)
        if len(values) > MAX_LOGICAL_SCOPES:
            raise HistorySidecarSchemaError("logical scope budget exceeded")
    if not values:
        raise HistorySidecarSchemaError("at least one logical scope is required")
    return tuple(sorted(values, key=lambda item: item.scope_id))


def _insert_decisions(
    conn: sqlite3.Connection,
    decisions: Iterable[ScopeDecision],
    *,
    scope_ids: frozenset[str],
    allow_reviewed: bool,
) -> int:
    count = 0
    for decision in decisions:
        if type(decision) is not ScopeDecision:
            raise HistorySidecarSchemaError(
                "decisions must contain ScopeDecision values"
            )
        if decision.review_state == "reviewed" and not allow_reviewed:
            raise HistorySidecarSchemaError(
                "reviewed decisions require validated History review apply"
            )
        if decision.scope_id not in scope_ids:
            raise HistorySidecarSchemaError("decision references an unknown scope")
        count += 1
        if count > MAX_SCOPE_DECISIONS:
            raise HistorySidecarSchemaError("scope decision budget exceeded")
        try:
            conn.execute(
                """INSERT INTO scope_decisions(
                       record_id, scope_id, membership, review_state,
                       artifact_sha256, reason_code
                   ) VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    decision.record_id,
                    decision.scope_id,
                    decision.membership,
                    decision.review_state,
                    decision.artifact_sha256,
                    decision.reason_code,
                ),
            )
        except sqlite3.IntegrityError as err:
            raise HistorySidecarSchemaError(
                "decision is duplicate or references an unknown record"
            ) from err
    return count


def _build_history_sidecar(
    corpus_index_path: str,
    sidecar_path: str,
    *,
    scopes: Iterable[LogicalScope] = DEFAULT_LOGICAL_SCOPES,
    decisions: Iterable[ScopeDecision] = (),
    allow_reviewed: bool,
    expected_corpus_binding: Mapping[str, object] | None = None,
    prepublish_check: Callable[[], None] | None = None,
) -> dict[str, object]:
    """Build and atomically publish one content-free History sidecar.

    This is an offline projection operation.  It fully verifies the corpus
    logical seal, scans every message exactly, repeats the exact record scan
    before publication, and leaves an existing target untouched on any
    pre-publication failure.
    """

    corpus = _canonical_existing_file(corpus_index_path, label="corpus index")
    sidecar = _canonical_sidecar_target(sidecar_path)
    ledger = _authoritative_ledger(corpus)
    _reject_path_aliases(corpus, sidecar, ledger)
    scope_values = _coerce_scopes(scopes)
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    with _snapshot_locks(sidecar, corpus, ledger):
        _assert_ledger_binding(corpus, ledger)
        prior_identity = _file_identity(sidecar, label="sidecar") if sidecar.exists() else None
        try:
            initial_integrity = inspect_corpus_integrity(str(corpus))
            if expected_corpus_binding is not None:
                expected_fields = {
                    "base_record_count",
                    "base_record_digest",
                    "corpus_deletion_ledger_digest",
                    "corpus_id",
                    "corpus_logical_index_sha256",
                    "index_generation",
                }
                if set(expected_corpus_binding) != expected_fields:
                    raise HistorySidecarSchemaError(
                        "expected corpus binding fields do not match review schema"
                    )
                corpus_fields = {
                    "base_record_count": "message_count",
                    "corpus_deletion_ledger_digest": "deletion_ledger_digest",
                    "corpus_id": "corpus_id",
                    "corpus_logical_index_sha256": "logical_index_sha256",
                    "index_generation": "index_generation",
                }
                for expected_key, corpus_key in corpus_fields.items():
                    if expected_corpus_binding.get(expected_key) != initial_integrity.get(
                        corpus_key
                    ):
                        raise HistorySidecarStaleError(
                            f"review corpus binding mismatch: {expected_key}"
                        )
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{sidecar.name}.history-",
                suffix=".tmp",
                dir=sidecar.parent,
            )
            os.close(descriptor)
            temporary = Path(temporary_name)
            _private_mode(temporary)
            conn = sqlite3.connect(str(temporary))
            try:
                conn.execute("PRAGMA journal_mode = DELETE")
                conn.execute("PRAGMA synchronous = FULL")
                _init_schema(conn)
                for scope in scope_values:
                    conn.execute(
                        """INSERT INTO logical_scopes(
                               scope_id, display_name, scope_kind, realm, project_id
                           ) VALUES (?, ?, ?, ?, ?)""",
                        (
                            scope.scope_id,
                            scope.display_name,
                            scope.scope_kind,
                            scope.realm,
                            scope.project_id,
                        ),
                    )
                with ValidatedCorpusReader(str(corpus)) as reader:
                    inserted_count = _scan_into_sidecar(
                        reader,
                        conn,
                        expected=initial_integrity,
                        verify_existing=False,
                    )
                    base_digest = _base_record_digest(conn)
                    decision_count = _insert_decisions(
                        conn,
                        decisions,
                        scope_ids=frozenset(scope.scope_id for scope in scope_values),
                        allow_reviewed=allow_reviewed,
                    )
                    final_integrity = inspect_corpus_integrity(str(corpus))
                    for key in (
                        "corpus_id",
                        "index_generation",
                        "deletion_ledger_digest",
                        "logical_index_sha256",
                        "message_count",
                    ):
                        if initial_integrity.get(key) != final_integrity.get(key):
                            raise HistorySidecarStaleError(
                                f"corpus changed during sidecar build: {key}"
                            )
                    _scan_into_sidecar(
                        reader,
                        conn,
                        expected=final_integrity,
                        verify_existing=True,
                    )
                if (
                    expected_corpus_binding is not None
                    and expected_corpus_binding["base_record_digest"] != base_digest
                ):
                    raise HistorySidecarStaleError(
                        "review corpus binding mismatch: base_record_digest"
                    )
                meta = {
                    "base_record_count": str(inserted_count),
                    "base_record_digest": base_digest,
                    "classifier_id": CLASSIFIER_ID,
                    "classifier_version": CLASSIFIER_VERSION,
                    "corpus_id": cast(str, final_integrity["corpus_id"]),
                    "corpus_deletion_ledger_digest": cast(
                        str, final_integrity["deletion_ledger_digest"]
                    ),
                    "corpus_logical_index_sha256": cast(
                        str, final_integrity["logical_index_sha256"]
                    ),
                    "decision_count": str(decision_count),
                    "index_generation": cast(str, final_integrity["index_generation"]),
                    "schema_version": HISTORY_SIDECAR_SCHEMA_VERSION,
                    "scope_count": str(len(scope_values)),
                    "sidecar_generation": "0" * 64,
                }
                conn.executemany(
                    "INSERT INTO history_meta(key, value) VALUES (?, ?)",
                    sorted(meta.items()),
                )
                generation = _sidecar_generation(conn)
                conn.execute(
                    "UPDATE history_meta SET value = ? WHERE key = 'sidecar_generation'",
                    (generation,),
                )
                conn.commit()
                validated = _validate_sidecar_connection(
                    conn, corpus_integrity=final_integrity
                )
            finally:
                conn.close()
            _fsync_file(temporary)
            if prepublish_check is not None:
                prepublish_check()
            current_identity = (
                _file_identity(sidecar, label="sidecar") if sidecar.exists() else None
            )
            if current_identity != prior_identity:
                raise HistorySidecarStaleError(
                    "sidecar target changed during projection build"
                )
            os.replace(temporary, sidecar)
            temporary = None
            _private_mode(sidecar)
            _fsync_file(sidecar)
            _fsync_directory(sidecar.parent)
            published = sqlite3.connect(_readonly_uri(sidecar), uri=True)
            try:
                published.execute("PRAGMA query_only = ON")
                if published.execute("PRAGMA query_only").fetchone()[0] != 1:
                    raise HistorySidecarSchemaError(
                        "published sidecar is not query-only"
                    )
                reopened = _validate_sidecar_connection(
                    published, corpus_integrity=final_integrity
                )
            finally:
                published.close()
            if reopened != validated:
                raise HistorySidecarSchemaError(
                    "published sidecar differs from validated staging file"
                )
            return reopened
        except (CorpusIndexError, sqlite3.DatabaseError, OSError) as err:
            if isinstance(err, HistorySidecarError):
                raise
            raise HistorySidecarError(f"history sidecar build failed: {err}") from err
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass


def build_history_sidecar(
    corpus_index_path: str,
    sidecar_path: str,
    *,
    scopes: Iterable[LogicalScope] = DEFAULT_LOGICAL_SCOPES,
    decisions: Iterable[ScopeDecision] = (),
) -> dict[str, object]:
    """Build a v2 sidecar from catalog output and inferred decisions only.

    Reviewed membership is an authority boundary.  It can enter a v2 sidecar
    only through the strict request/result workflow in ``history.decisions``.
    """

    return _build_history_sidecar(
        corpus_index_path,
        sidecar_path,
        scopes=scopes,
        decisions=decisions,
        allow_reviewed=False,
    )


def build_history_sidecar_successor(
    corpus_index_path: str,
    sidecar_path: str,
    *,
    scopes: Iterable[LogicalScope],
    decisions: Iterable[ScopeDecision],
    authority_sha256: str,
) -> dict[str, object]:
    """Publish one scalable reviewed successor after an explicit import.

    The caller supplies the complete preserved/new decision stream. At least
    one reviewed decision must be bound to the current operation authority;
    older reviewed decisions retain their original artifact digests.
    """
    authority = _hex_digest(authority_sha256, field="authority_sha256")
    values = tuple(decisions)
    if not values or not any(
        item.review_state == "reviewed" and item.artifact_sha256 == authority
        for item in values
    ):
        raise HistorySidecarSchemaError(
            "successor requires a reviewed decision bound to current authority"
        )
    return _build_history_sidecar(
        corpus_index_path,
        sidecar_path,
        scopes=scopes,
        decisions=values,
        allow_reviewed=True,
    )


def _build_history_sidecar_from_validated_review(
    corpus_index_path: str,
    sidecar_path: str,
    *,
    scopes: Iterable[LogicalScope],
    decisions: Iterable[ScopeDecision],
    expected_corpus_binding: Mapping[str, object],
    prepublish_check: Callable[[], None],
) -> dict[str, object]:
    """Package-private reviewed build entry used only after artifact validation."""

    return _build_history_sidecar(
        corpus_index_path,
        sidecar_path,
        scopes=scopes,
        decisions=decisions,
        allow_reviewed=True,
        expected_corpus_binding=expected_corpus_binding,
        prepublish_check=prepublish_check,
    )


_ResultT = TypeVar("_ResultT")


class HistorySidecarReader:
    """Fail-closed, single-thread reader for one corpus/sidecar snapshot."""

    def __init__(self, corpus_index_path: str, sidecar_path: str):
        self._corpus = _canonical_existing_file(corpus_index_path, label="corpus index")
        self._sidecar = _canonical_existing_file(sidecar_path, label="sidecar")
        self._ledger = _authoritative_ledger(self._corpus)
        _reject_path_aliases(self._corpus, self._sidecar, self._ledger)
        self._owner_thread_id = threading.get_ident()
        self._closed = True
        self._corpus_reader: ValidatedCorpusReader | None = None
        with _snapshot_locks(self._sidecar, self._corpus, self._ledger):
            _assert_ledger_binding(self._corpus, self._ledger)
            corpus_before = _file_identity(self._corpus, label="corpus index")
            sidecar_before = _file_identity(self._sidecar, label="sidecar")
            integrity = inspect_corpus_integrity(str(self._corpus))
            corpus_reader = ValidatedCorpusReader(str(self._corpus))
            conn = sqlite3.connect(_readonly_uri(self._sidecar), uri=True)
            try:
                conn.execute("PRAGMA query_only = ON")
                if conn.execute("PRAGMA query_only").fetchone()[0] != 1:
                    raise HistorySidecarSchemaError("sidecar query_only could not be enabled")
                summary = _validate_sidecar_connection(
                    conn, corpus_integrity=integrity
                )
                corpus_summary = corpus_reader.inspect()
            except Exception:
                corpus_reader.close()
                raise
            finally:
                conn.close()
            corpus_after = _file_identity(self._corpus, label="corpus index")
            sidecar_after = _file_identity(self._sidecar, label="sidecar")
            if corpus_before != corpus_after or sidecar_before != sidecar_after:
                corpus_reader.close()
                raise HistorySidecarStaleError(
                    "corpus or sidecar changed while reader opened"
                )
            self._corpus_identity = corpus_after
            self._sidecar_identity = sidecar_after
            self._corpus_reader = corpus_reader
            self._corpus_summary = corpus_summary
            self._summary = summary
            self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        if not self._closed and threading.get_ident() != self._owner_thread_id:
            raise HistorySidecarError("history sidecar reader belongs to another thread")
        corpus_reader = self._corpus_reader
        self._corpus_reader = None
        if corpus_reader is not None and not corpus_reader.closed:
            corpus_reader.close()
        self._closed = True

    def __enter__(self) -> "HistorySidecarReader":
        if self._closed:
            raise HistorySidecarError("history sidecar reader is closed")
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def _operate(self, operation: Callable[[sqlite3.Connection], _ResultT]) -> _ResultT:
        if self._closed:
            raise HistorySidecarError("history sidecar reader is closed")
        if threading.get_ident() != self._owner_thread_id:
            raise HistorySidecarError("history sidecar reader belongs to another thread")
        with _snapshot_locks(self._sidecar, self._corpus, self._ledger):
            corpus_reader = self._corpus_reader
            if corpus_reader is None:
                self.close()
                raise HistorySidecarError("history sidecar reader is closed")
            try:
                corpus_reader.inspect()
            except CorpusIndexError as err:
                self.close()
                raise HistorySidecarStaleError(
                    f"corpus freshness check failed: {err}"
                ) from err
            if (
                _file_identity(self._corpus, label="corpus index")
                != self._corpus_identity
                or _file_identity(self._sidecar, label="sidecar")
                != self._sidecar_identity
            ):
                self.close()
                raise HistorySidecarStaleError("corpus or sidecar identity changed")
            conn = sqlite3.connect(_readonly_uri(self._sidecar), uri=True)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA query_only = ON")
                if conn.execute("PRAGMA query_only").fetchone()[0] != 1:
                    raise HistorySidecarSchemaError("sidecar query_only could not be enabled")
                initial_data_version = conn.execute("PRAGMA data_version").fetchone()
                if initial_data_version is None or type(initial_data_version[0]) is not int:
                    raise HistorySidecarSchemaError("cannot read sidecar data_version")
                result = operation(conn)
                final_data_version = conn.execute("PRAGMA data_version").fetchone()
                if final_data_version != initial_data_version:
                    self.close()
                    raise HistorySidecarStaleError(
                        "sidecar changed during read operation"
                    )
                try:
                    corpus_reader.inspect()
                except CorpusIndexError as err:
                    self.close()
                    raise HistorySidecarStaleError(
                        f"corpus freshness check failed: {err}"
                    ) from err
                if (
                    _file_identity(self._corpus, label="corpus index")
                    != self._corpus_identity
                    or _file_identity(self._sidecar, label="sidecar")
                    != self._sidecar_identity
                ):
                    self.close()
                    raise HistorySidecarStaleError("corpus or sidecar identity changed")
                return result
            except sqlite3.DatabaseError as err:
                self.close()
                raise HistorySidecarError(f"history sidecar read failed: {err}") from err
            finally:
                conn.close()

    def inspect(self) -> dict[str, object]:
        return self._operate(lambda _conn: dict(self._summary))

    def _joined_read(
        self,
        operation: Callable[[sqlite3.Connection], _ResultT],
    ) -> _ResultT:
        """Read corpus content with the validated sidecar attached read-only."""

        conn = sqlite3.connect(_readonly_uri(self._corpus), uri=True)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute(
                "ATTACH DATABASE ? AS history_view",
                (_readonly_uri(self._sidecar),),
            )
            conn.execute("PRAGMA query_only = ON")
            if conn.execute("PRAGMA query_only").fetchone()[0] != 1:
                raise HistorySidecarSchemaError("joined query_only could not be enabled")
            corpus_version = conn.execute("PRAGMA main.data_version").fetchone()
            sidecar_version = conn.execute("PRAGMA history_view.data_version").fetchone()
            generation = conn.execute(
                "SELECT value FROM history_view.history_meta WHERE key = 'sidecar_generation'"
            ).fetchone()
            if generation is None or generation[0] != self._summary["sidecar_generation"]:
                raise HistorySidecarStaleError("attached sidecar generation changed")
            result = operation(conn)
            if (
                conn.execute("PRAGMA main.data_version").fetchone() != corpus_version
                or conn.execute("PRAGMA history_view.data_version").fetchone()
                != sidecar_version
            ):
                raise HistorySidecarStaleError(
                    "corpus or sidecar changed during joined read"
                )
            return result
        except sqlite3.DatabaseError as err:
            raise HistorySidecarError(f"joined history read failed: {err}") from err
        finally:
            conn.close()

    def search(
        self,
        *,
        query: str | None = None,
        scope_ids: Iterable[str] | None = None,
        everywhere: bool = False,
        context_radius: int = 1,
        limit: int = 50,
        offset: int = 0,
        match_mode: str = "fts",
    ) -> dict[str, object]:
        """Search a reviewed logical view before ranking and pagination."""

        if type(everywhere) is not bool:
            raise HistorySidecarSchemaError("everywhere must be a boolean")
        if everywhere == (scope_ids is not None):
            raise HistorySidecarSchemaError(
                "choose exactly explicit scope_ids or everywhere=true"
            )

        def operation(sidecar_conn: sqlite3.Connection) -> dict[str, object]:
            selected = None if everywhere else self._scope_selection(
                sidecar_conn, cast(Iterable[str], scope_ids)
            )
            payload = self._joined_read(
                lambda corpus_conn: _search_corpus_with_connection(
                    corpus_conn,
                    dict(self._corpus_summary),
                    query=query,
                    match_mode=match_mode,
                    context_radius=context_radius,
                    limit=limit,
                    offset=offset,
                    logical_scope_ids=selected,
                )
            )
            payload["history_view"] = {
                "sidecar_generation": self._summary["sidecar_generation"],
                "mode": "everywhere" if everywhere else "reviewed_scopes",
                "scope_ids": list(selected or ()),
            }
            return cast(dict[str, object], payload)

        return self._operate(operation)

    def get_message(
        self,
        *,
        source_id: str,
        conversation_id: str,
        message_id: str,
        scope_ids: Iterable[str] | None = None,
        everywhere: bool = False,
        context_radius: int = 1,
    ) -> dict[str, object] | None:
        """Open one message while reapplying the same logical-view boundary."""

        if type(everywhere) is not bool:
            raise HistorySidecarSchemaError("everywhere must be a boolean")
        if everywhere == (scope_ids is not None):
            raise HistorySidecarSchemaError(
                "choose exactly explicit scope_ids or everywhere=true"
            )

        def operation(sidecar_conn: sqlite3.Connection) -> dict[str, object] | None:
            selected = None if everywhere else self._scope_selection(
                sidecar_conn, cast(Iterable[str], scope_ids)
            )
            result = self._joined_read(
                lambda corpus_conn: _get_message_with_connection(
                    corpus_conn,
                    source_id=source_id,
                    conversation_id=conversation_id,
                    message_id=message_id,
                    context_radius=context_radius,
                    logical_scope_ids=selected,
                )
            )
            if result is not None:
                result["history_view"] = {
                    "sidecar_generation": self._summary["sidecar_generation"],
                    "mode": "everywhere" if everywhere else "reviewed_scopes",
                    "scope_ids": list(selected or ()),
                }
            return cast(dict[str, object] | None, result)

        return self._operate(operation)

    def get_conversation_page(
        self,
        *,
        source_id: str,
        conversation_id: str,
        scope_ids: Iterable[str] | None = None,
        everywhere: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, object] | None:
        """Read one reviewed conversation boundary in bounded pages."""

        if type(everywhere) is not bool:
            raise HistorySidecarSchemaError("everywhere must be a boolean")
        if everywhere == (scope_ids is not None):
            raise HistorySidecarSchemaError(
                "choose exactly explicit scope_ids or everywhere=true"
            )

        def operation(sidecar_conn: sqlite3.Connection) -> dict[str, object] | None:
            selected = None if everywhere else self._scope_selection(
                sidecar_conn, cast(Iterable[str], scope_ids)
            )
            result = self._joined_read(
                lambda corpus_conn: _get_conversation_page_with_connection(
                    corpus_conn,
                    source_id=source_id,
                    conversation_id=conversation_id,
                    limit=limit,
                    offset=offset,
                    logical_scope_ids=selected,
                )
            )
            if result is not None:
                result["history_view"] = {
                    "sidecar_generation": self._summary["sidecar_generation"],
                    "mode": "everywhere" if everywhere else "reviewed_scopes",
                    "scope_ids": list(selected or ()),
                }
            return cast(dict[str, object] | None, result)

        return self._operate(operation)

    def list_scopes(self) -> list[dict[str, object]]:
        def operation(conn: sqlite3.Connection) -> list[dict[str, object]]:
            return [
                _stored_scope(tuple(row)).to_dict()
                for row in conn.execute(
                    """SELECT scope_id, display_name, scope_kind, realm, project_id
                         FROM logical_scopes ORDER BY scope_id"""
                )
            ]

        return self._operate(operation)

    @staticmethod
    def _record_payload(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, object]:
        catalog = _validate_catalog_json(
            row["catalog_json"], state=row["classification_state"]
        )
        decisions = [
            _stored_decision(tuple(item)).to_dict()
            for item in conn.execute(
                """SELECT record_id, scope_id, membership, review_state,
                          artifact_sha256, reason_code
                     FROM scope_decisions WHERE record_id = ? ORDER BY scope_id""",
                (row["record_id"],),
            )
        ]
        reviewed_scopes = [
            item["scope_id"]
            for item in decisions
            if item["membership"] == "include" and item["review_state"] == "reviewed"
        ]
        inferred_scopes = [
            item["scope_id"]
            for item in decisions
            if item["membership"] == "include" and item["review_state"] == "inferred"
        ]
        return {
            "record_id": row["record_id"],
            "source_id": row["source_id"],
            "provider": row["provider"],
            "conversation_id": row["conversation_id"],
            "message_id": row["message_id"],
            "role": row["role"],
            "content_type": row["content_type"],
            "content_sha256": row["content_sha256"],
            "classification_state": row["classification_state"],
            "catalog": catalog,
            "decisions": decisions,
            "reviewed_scope_ids": reviewed_scopes,
            "inferred_scope_ids": inferred_scopes,
            "decisionless": not decisions,
            "unassigned": not reviewed_scopes,
            "authoritative": False,
            "evidence_only": True,
        }

    def get_record(self, record_id: str) -> dict[str, object] | None:
        record_id = _hex_digest(record_id, field="record_id")

        def operation(conn: sqlite3.Connection) -> dict[str, object] | None:
            row = conn.execute(
                """SELECT record_id, source_id, provider, conversation_id,
                          message_id, role, content_type, content_sha256,
                          classification_state, catalog_json
                     FROM catalog_records WHERE record_id = ?""",
                (record_id,),
            ).fetchone()
            return self._record_payload(conn, row) if row is not None else None

        return self._operate(operation)

    def get_records(self, record_ids: Iterable[str]) -> list[dict[str, object]]:
        """Resolve one bounded, duplicate-free record batch in one snapshot read."""

        values: list[str] = []
        seen: set[str] = set()
        for value in record_ids:
            record_id = _hex_digest(value, field="record_id")
            if record_id in seen:
                raise HistorySidecarSchemaError(
                    "record_ids must not contain duplicates"
                )
            seen.add(record_id)
            values.append(record_id)
            if len(values) > MAX_PAGE_SIZE:
                raise HistorySidecarSchemaError(
                    f"record_ids must contain at most {MAX_PAGE_SIZE} values"
                )
        if not values:
            raise HistorySidecarSchemaError("record_ids must not be empty")
        values.sort()

        def operation(conn: sqlite3.Connection) -> list[dict[str, object]]:
            placeholders = ",".join("?" for _ in values)
            rows = conn.execute(
                f"""SELECT record_id, source_id, provider, conversation_id,
                            message_id, role, content_type, content_sha256,
                            classification_state, catalog_json
                       FROM catalog_records
                      WHERE record_id IN ({placeholders})
                      ORDER BY record_id""",
                values,
            ).fetchall()
            if len(rows) != len(values):
                raise HistorySidecarSchemaError(
                    "record_ids contain an unknown record"
                )
            return [self._record_payload(conn, row) for row in rows]

        return self._operate(operation)

    def scan_scope_decisions(
        self,
        *,
        after_record_id: str | None = None,
        after_scope_id: str | None = None,
        limit: int = MAX_DECISION_PAGE_SIZE,
    ) -> dict[str, object]:
        """Read a compact keyset page of content-free scope decisions."""

        if type(limit) is not int or not 1 <= limit <= MAX_DECISION_PAGE_SIZE:
            raise HistorySidecarSchemaError(
                f"limit must be between 1 and {MAX_DECISION_PAGE_SIZE}"
            )
        if (after_record_id is None) != (after_scope_id is None):
            raise HistorySidecarSchemaError(
                "decision cursor requires both record_id and scope_id"
            )
        cursor: tuple[str, str] | None = None
        if after_record_id is not None and after_scope_id is not None:
            cursor = (
                _hex_digest(after_record_id, field="after_record_id"),
                _stable_id(after_scope_id, field="after_scope_id"),
            )

        def operation(conn: sqlite3.Connection) -> dict[str, object]:
            if cursor is None:
                rows = conn.execute(
                    """SELECT record_id, scope_id, membership, review_state,
                              artifact_sha256, reason_code
                         FROM scope_decisions
                        ORDER BY record_id, scope_id LIMIT ?""",
                    (limit + 1,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT record_id, scope_id, membership, review_state,
                              artifact_sha256, reason_code
                         FROM scope_decisions
                        WHERE record_id > ?
                           OR (record_id = ? AND scope_id > ?)
                        ORDER BY record_id, scope_id LIMIT ?""",
                    (cursor[0], cursor[0], cursor[1], limit + 1),
                ).fetchall()
            has_more = len(rows) > limit
            page = rows[:limit]
            decisions: list[dict[str, str]] = []
            for row in page:
                decision = _stored_decision(tuple(row))
                decisions.append(
                    {"record_id": decision.record_id, **decision.to_dict()}
                )
            next_cursor = None
            if has_more and page:
                next_cursor = {
                    "record_id": page[-1][0],
                    "scope_id": page[-1][1],
                }
            return {
                "schema_version": HISTORY_VIEW_SCHEMA_VERSION,
                "sidecar_generation": self._summary["sidecar_generation"],
                "result_count": len(decisions),
                "has_more": has_more,
                "next_cursor": next_cursor,
                "decisions": decisions,
            }

        return self._operate(operation)

    @staticmethod
    def _page(limit: int, offset: int) -> tuple[int, int]:
        if type(limit) is not int or not 1 <= limit <= MAX_PAGE_SIZE:
            raise HistorySidecarSchemaError(
                f"limit must be between 1 and {MAX_PAGE_SIZE}"
            )
        if type(offset) is not int or not 0 <= offset <= MAX_PAGE_OFFSET:
            raise HistorySidecarSchemaError(
                f"offset must be between 0 and {MAX_PAGE_OFFSET}"
            )
        return limit, offset

    @staticmethod
    def _scope_selection(
        conn: sqlite3.Connection, scope_ids: Iterable[str]
    ) -> tuple[str, ...]:
        values: list[str] = []
        seen: set[str] = set()
        for value in scope_ids:
            scope_id = _stable_id(value, field="scope_id")
            if scope_id in seen:
                raise HistorySidecarSchemaError("scope_ids must not contain duplicates")
            seen.add(scope_id)
            values.append(scope_id)
            if len(values) > MAX_LOGICAL_SCOPES:
                raise HistorySidecarSchemaError("scope selection budget exceeded")
        if not values:
            raise HistorySidecarSchemaError("explicit logical view requires scope_ids")
        values.sort()
        placeholders = ",".join("?" for _ in values)
        existing = {
            row[0]
            for row in conn.execute(
                f"SELECT scope_id FROM logical_scopes WHERE scope_id IN ({placeholders})",
                values,
            )
        }
        if existing != set(values):
            raise HistorySidecarSchemaError("logical view references an unknown scope")
        return tuple(values)

    def resolve_view(
        self,
        *,
        scope_ids: Iterable[str] | None = None,
        everywhere: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, object]:
        """Resolve reviewed logical membership or all base records exactly once."""

        limit, offset = self._page(limit, offset)
        if type(everywhere) is not bool:
            raise HistorySidecarSchemaError("everywhere must be a boolean")
        if everywhere == (scope_ids is not None):
            raise HistorySidecarSchemaError(
                "choose exactly explicit scope_ids or everywhere=true"
            )

        def operation(conn: sqlite3.Connection) -> dict[str, object]:
            if everywhere:
                selected = tuple(
                    row[0]
                    for row in conn.execute(
                        "SELECT scope_id FROM logical_scopes ORDER BY scope_id"
                    )
                )
                rows = conn.execute(
                    """SELECT record_id, source_id, provider, conversation_id,
                              message_id, role, content_type, content_sha256,
                              classification_state, catalog_json
                         FROM catalog_records ORDER BY record_id LIMIT ? OFFSET ?""",
                    (limit + 1, offset),
                ).fetchall()
                mode = "everywhere"
            else:
                assert scope_ids is not None
                selected = self._scope_selection(conn, scope_ids)
                placeholders = ",".join("?" for _ in selected)
                rows = conn.execute(
                    f"""SELECT r.record_id, r.source_id, r.provider,
                                r.conversation_id, r.message_id, r.role,
                                r.content_type, r.content_sha256,
                                r.classification_state, r.catalog_json
                           FROM catalog_records r
                          WHERE EXISTS (
                              SELECT 1 FROM scope_decisions d
                               WHERE d.record_id = r.record_id
                                 AND d.scope_id IN ({placeholders})
                                 AND d.membership = 'include'
                                 AND d.review_state = 'reviewed'
                          )
                          ORDER BY r.record_id LIMIT ? OFFSET ?""",
                    (*selected, limit + 1, offset),
                ).fetchall()
                mode = "explicit"
            has_more = len(rows) > limit
            rows = rows[:limit]
            records = [self._record_payload(conn, row) for row in rows]
            return {
                "schema_version": HISTORY_VIEW_SCHEMA_VERSION,
                "sidecar_generation": self._summary["sidecar_generation"],
                "corpus_id": self._summary["corpus_id"],
                "index_generation": self._summary["index_generation"],
                "mode": mode,
                "selected_scope_ids": list(selected),
                "selection_policy": (
                    "all_base_records_once"
                    if everywhere
                    else "reviewed_include_only"
                ),
                "offset": offset,
                "limit": limit,
                "result_count": len(records),
                "has_more": has_more,
                "complete_scope_coverage": True,
                "records": records,
            }

        return self._operate(operation)

    def list_migration_candidates(
        self,
        *,
        scope_ids: Iterable[str] | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, object]:
        """List inferred decisions without promoting them into named views."""

        limit, offset = self._page(limit, offset)

        def operation(conn: sqlite3.Connection) -> dict[str, object]:
            parameters: tuple[object, ...]
            if scope_ids is None:
                selected = tuple(
                    row[0]
                    for row in conn.execute(
                        "SELECT scope_id FROM logical_scopes ORDER BY scope_id"
                    )
                )
                predicate = "d.review_state = 'inferred'"
                parameters = ()
            else:
                selected = self._scope_selection(conn, scope_ids)
                placeholders = ",".join("?" for _ in selected)
                predicate = (
                    "d.review_state = 'inferred' "
                    f"AND d.scope_id IN ({placeholders})"
                )
                parameters = cast(tuple[object, ...], selected)
            rows = conn.execute(
                f"""SELECT r.record_id, r.source_id, r.provider,
                            r.conversation_id, r.message_id, r.role,
                            r.content_type, r.content_sha256,
                            r.classification_state, r.catalog_json
                       FROM catalog_records r
                      WHERE EXISTS (
                          SELECT 1 FROM scope_decisions d
                           WHERE d.record_id = r.record_id AND {predicate}
                      )
                      ORDER BY r.record_id LIMIT ? OFFSET ?""",
                (*parameters, limit + 1, offset),
            ).fetchall()
            has_more = len(rows) > limit
            records = [self._record_payload(conn, row) for row in rows[:limit]]
            return {
                "schema_version": HISTORY_VIEW_SCHEMA_VERSION,
                "sidecar_generation": self._summary["sidecar_generation"],
                "mode": "migration_candidates",
                "selected_scope_ids": list(selected),
                "selection_policy": "inferred_only_non_authoritative",
                "offset": offset,
                "limit": limit,
                "result_count": len(records),
                "has_more": has_more,
                "records": records,
            }

        return self._operate(operation)


def inspect_history_sidecar(
    corpus_index_path: str, sidecar_path: str
) -> dict[str, object]:
    with HistorySidecarReader(corpus_index_path, sidecar_path) as reader:
        return reader.inspect()


__all__ = [
    "DEFAULT_LOGICAL_SCOPES",
    "HISTORY_SIDECAR_SCHEMA_VERSION",
    "HISTORY_VIEW_SCHEMA_VERSION",
    "INFERRED_SCOPE_REASON_CODE",
    "MAX_DECISION_PAGE_SIZE",
    "MAX_DECISIONS_PER_RECORD",
    "MAX_LOGICAL_SCOPES",
    "MAX_PAGE_OFFSET",
    "MAX_PAGE_SIZE",
    "MAX_RECORDS",
    "MAX_SCOPE_DECISIONS",
    "PERSONAL_SCOPE_ID",
    "REVIEWED_SCOPE_REASON_CODE",
    "HistorySidecarError",
    "HistorySidecarReader",
    "HistorySidecarSchemaError",
    "HistorySidecarStaleError",
    "LogicalScope",
    "ScopeDecision",
    "build_history_sidecar",
    "build_history_sidecar_successor",
    "inspect_history_sidecar",
]
