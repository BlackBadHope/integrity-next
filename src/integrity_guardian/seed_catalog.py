"""Canonical Integrity Seed memory and deterministic operational catalog.

The Seed catalog keeps the imported Action Log event bytes lossless and builds
reproducible entities, relations, task state, locks, topics and a bounded
startup doctrine capsule.  Derived tables may always be rebuilt from the raw
Seed events.  They are never authority to mutate an external system.

Integrity Home is deliberately outside this module. Each catalogue binds one
explicit immutable project namespace; the neutral local default is not a tenant identity.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import closing, contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .hashing import digest_object

SEED_NAMESPACE = "seed://project/default"
ACTION_LOG_ALIAS = "actionlog://global"
HOME_NAMESPACE = "home://owner"
SEED_NAMESPACE_PATTERN = re.compile(
    r"^seed://project/[a-z0-9][a-z0-9._-]{0,127}$"
)
CATALOG_PROTOCOL = "integrity-guardian/seed-catalog/v1"
CATALOG_SCHEMA_VERSION = 1
DOCTRINE_ACTIONS = frozenset({"seed_monument_decision", "product_rc_recorded", "seed_doctrine_declared"})
MAX_EVENTS = 1_000_000
MAX_TEXT_LENGTH = 1_000_000
READ_SEAL_PROTOCOL = "integrity-guardian/seed-catalog-read-seal/v1"
READ_SEAL_BUSY_TIMEOUT_MS = 5_000
_SQLITE_TRANSIENT_SUFFIXES = ("-wal", "-shm")


class SeedCatalogError(ValueError):
    """Raised when canonical memory cannot be imported without ambiguity."""


class SeedCatalogReadSealError(SeedCatalogError):
    """A durable catalog generation exists but is not safe for immutable reads."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str,
        catalog_state: str,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.catalog_state = catalog_state


def seal_catalog_for_immutable_read(
    connection: sqlite3.Connection,
    catalog: Path,
    *,
    generation_reader: Callable[[sqlite3.Connection], dict[str, Any]],
    expected_generation: dict[str, Any] | None = None,
    busy_timeout_ms: int | None = None,
    durable_commit: bool = False,
) -> dict[str, Any]:
    """Produce a point-in-time WAL seal for immutable Seed readers."""

    catalog_state = "COMMITTED_UNSEALED" if durable_commit else "UNSEALED"

    def reject(message: str, reason_code: str) -> SeedCatalogReadSealError:
        return SeedCatalogReadSealError(
            message,
            reason_code=reason_code,
            catalog_state=catalog_state,
        )

    if connection.in_transaction:
        raise reject(
            "Seed catalog checkpoint requires a committed transaction",
            "seed_catalog_transaction_active",
        )
    timeout = READ_SEAL_BUSY_TIMEOUT_MS if busy_timeout_ms is None else busy_timeout_ms
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 0 <= timeout <= 30_000:
        raise reject(
            "Seed catalog checkpoint timeout is invalid",
            "seed_catalog_checkpoint_timeout_invalid",
        )
    catalog = catalog.absolute()
    try:
        catalog_before = catalog.lstat()
        main_rows = [
            row for row in connection.execute("PRAGMA database_list") if str(row[1]) == "main"
        ]
        if len(main_rows) != 1:
            raise OSError("main database identity is ambiguous")
        connected_path = Path(str(main_rows[0][2])).absolute()
        bound = os.path.samefile(connected_path, catalog)
    except (OSError, sqlite3.Error) as exc:
        raise reject(
            "Seed catalog checkpoint connection is not bound to the requested catalog",
            "seed_catalog_connection_mismatch",
        ) from exc
    if (
        not bound
        or stat.S_ISLNK(catalog_before.st_mode)
        or not stat.S_ISREG(catalog_before.st_mode)
    ):
        raise reject(
            "Seed catalog checkpoint connection is not bound to the requested catalog",
            "seed_catalog_connection_mismatch",
        )
    try:
        mode_row = connection.execute("PRAGMA main.journal_mode").fetchone()
    except sqlite3.Error as exc:
        raise reject(
            "Seed catalog journal mode could not be inspected",
            "seed_catalog_journal_mode_inspection_failed",
        ) from exc
    if mode_row is None or str(mode_row[0]).lower() != "wal":
        raise reject(
            "Seed catalog checkpoint requires WAL journal mode",
            "seed_catalog_journal_mode_invalid",
        )
    try:
        previous_timeout_row = connection.execute("PRAGMA busy_timeout").fetchone()
        previous_timeout = int(previous_timeout_row[0]) if previous_timeout_row else 0
    except (sqlite3.Error, TypeError, ValueError) as exc:
        raise reject(
            "Seed catalog checkpoint timeout could not be inspected",
            "seed_catalog_checkpoint_timeout_inspection_failed",
        ) from exc
    checkpoint_error: sqlite3.Error | None = None
    try:
        connection.execute(f"PRAGMA busy_timeout={timeout}")
        checkpoint = connection.execute("PRAGMA main.wal_checkpoint(TRUNCATE)").fetchone()
    except sqlite3.Error as exc:
        checkpoint = None
        checkpoint_error = exc
    try:
        connection.execute(f"PRAGMA busy_timeout={previous_timeout}")
    except sqlite3.Error as exc:
        raise reject(
            "Seed catalog checkpoint timeout could not be restored",
            "seed_catalog_checkpoint_timeout_restore_failed",
        ) from exc
    if checkpoint_error is not None:
        raise reject(
            "Seed catalog checkpoint could not produce an immutable read seal",
            "seed_catalog_checkpoint_failed",
        ) from checkpoint_error
    if checkpoint is None or len(checkpoint) != 3:
        raise reject(
            "Seed catalog checkpoint returned an invalid receipt",
            "seed_catalog_checkpoint_receipt_invalid",
        )
    try:
        busy, log_frames, checkpointed_frames = (int(value) for value in checkpoint)
    except (TypeError, ValueError) as exc:
        raise reject(
            "Seed catalog checkpoint returned an invalid receipt",
            "seed_catalog_checkpoint_receipt_invalid",
        ) from exc
    frames = (log_frames, checkpointed_frames)
    if busy != 0 or frames not in ((0, 0), (-1, -1)):
        raise reject(
            "Seed catalog checkpoint is busy; committed catalog is not sealed for immutable reads",
            "seed_catalog_checkpoint_busy",
        )
    try:
        connection.execute("BEGIN IMMEDIATE")
    except sqlite3.Error as exc:
        raise reject(
            "Seed catalog writer barrier is busy; immutable read seal was not produced",
            "seed_catalog_writer_busy",
        ) from exc
    try:
        wal = catalog.with_name(catalog.name + "-wal")
        try:
            wal_details = wal.lstat()
        except FileNotFoundError:
            wal_state = "ABSENT"
            wal_bytes = 0
        else:
            if stat.S_ISLNK(wal_details.st_mode) or not stat.S_ISREG(wal_details.st_mode):
                raise reject(
                    "Seed catalog WAL custody is unsafe",
                    "seed_catalog_wal_custody_invalid",
                )
            wal_state = "PRESENT_EMPTY" if wal_details.st_size == 0 else "PRESENT_DATA"
            wal_bytes = wal_details.st_size
        if wal_bytes != 0:
            raise reject(
                "Seed catalog checkpoint left pending WAL data",
                "seed_catalog_checkpoint_busy",
            )
        logical_generation = generation_reader(connection)
        if not isinstance(logical_generation, dict):
            raise reject(
                "Seed catalog generation reader returned an invalid identity",
                "seed_catalog_generation_invalid",
            )
        if expected_generation is not None and logical_generation != expected_generation:
            raise reject(
                "Seed catalog generation changed before immutable read seal",
                "seed_catalog_generation_changed",
            )
        catalog_details = catalog.lstat()
        if (
            stat.S_ISLNK(catalog_details.st_mode)
            or not stat.S_ISREG(catalog_details.st_mode)
            or (catalog_details.st_dev, catalog_details.st_ino)
            != (catalog_before.st_dev, catalog_before.st_ino)
        ):
            raise reject(
                "Seed catalog custody changed during immutable read seal",
                "seed_catalog_custody_changed",
            )
        generation_digest = digest_object(
            logical_generation,
            domain="seed-catalog-read-seal-generation-v1",
        )
        observed_utc = datetime.now(UTC).isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        )
    except SeedCatalogReadSealError:
        raise
    except Exception as exc:
        raise reject(
            "Seed catalog generation could not be verified for immutable reads",
            "seed_catalog_generation_verification_failed",
        ) from exc
    finally:
        if connection.in_transaction:
            try:
                connection.rollback()
            except sqlite3.Error as exc:
                raise reject(
                    "Seed catalog writer barrier could not be released",
                    "seed_catalog_writer_barrier_release_failed",
                ) from exc

    return {
        "protocol": READ_SEAL_PROTOCOL,
        "status": "SEALED",
        "scope": "point-in-time-not-a-lease",
        "catalog_state": "COMMITTED_SEALED" if durable_commit else "SEALED",
        "checkpoint_mode": "TRUNCATE",
        "checkpoint_outcome": "TRUNCATED" if frames == (0, 0) else "NO_WAL",
        "busy": busy,
        "log_frames": log_frames,
        "checkpointed_frames": checkpointed_frames,
        "wal_state": wal_state,
        "wal_bytes": wal_bytes,
        "logical_generation": logical_generation,
        "generation_digest": generation_digest,
        "observed_utc": observed_utc,
        "catalog_identity": {
            "device": catalog_details.st_dev,
            "inode": catalog_details.st_ino,
            "bytes": catalog_details.st_size,
            "mtime_ns": catalog_details.st_mtime_ns,
        },
        "production_authority": False,
    }


def _seed_catalog_generation(
    connection: sqlite3.Connection,
    *,
    focus_run_id: str | None = None,
) -> dict[str, Any]:
    event_count, event_cursor = connection.execute(
        "SELECT COUNT(*), COALESCE(MAX(event_id),0) FROM seed_events"
    ).fetchone()
    runs = [
        {
            "run_id": str(row[0]),
            "source_digest": str(row[1]),
            "catalog_digest": str(row[2]),
            "event_count": int(row[3]),
        }
        for row in connection.execute(
            """
            SELECT run_id,source_digest,catalog_digest,event_count
            FROM seed_catalog_runs ORDER BY run_id
            """
        )
    ]
    focus = connection.execute(
        """
        SELECT run_id,source_digest,catalog_digest,event_count
        FROM seed_catalog_runs WHERE run_id=?
        """,
        (focus_run_id,),
    ).fetchone() if focus_run_id is not None else None
    return {
        "event_count": int(event_count),
        "event_cursor": int(event_cursor),
        "run_count": len(runs),
        "run_set_digest": digest_object(
            runs,
            domain="seed-catalog-read-seal-run-set-v1",
        ),
        "focus_run": (
            None
            if focus is None
            else {
                "run_id": str(focus[0]),
                "source_digest": str(focus[1]),
                "catalog_digest": str(focus[2]),
                "event_count": int(focus[3]),
            }
        ),
    }


def _path_lexists(path: Path) -> bool:
    return os.path.lexists(os.fspath(path))


def _assert_no_closed_sqlite_sidecars(path: Path) -> None:
    if any(_path_lexists(path.with_name(path.name + suffix)) for suffix in _SQLITE_TRANSIENT_SUFFIXES):
        raise SeedCatalogError("closed fresh Seed catalog retained WAL/SHM state")


def _prepare_catalog_path(path: Path) -> bool:
    fresh = not _path_lexists(path)
    if os.name != "nt":
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        return fresh

    from ._windows_files import (
        WindowsFileBoundaryError,
        assert_private_directory_acl,
        create_private_directory_tree,
    )
    from .windows_private_state import (
        WindowsPrivateStateError,
        write_private_once,
    )

    try:
        create_private_directory_tree(path.parent)
        if fresh:
            write_private_once(path, b"")
        else:
            assert_private_directory_acl(path)
    except (OSError, WindowsFileBoundaryError, WindowsPrivateStateError) as exc:
        raise SeedCatalogError("private Windows Seed catalog custody rejected") from exc
    return fresh


def _assert_catalog_path_custody(path: Path) -> None:
    if os.name != "nt":
        path.chmod(0o600)
        return
    from ._windows_files import WindowsFileBoundaryError, assert_private_directory_acl

    try:
        assert_private_directory_acl(path.parent)
        assert_private_directory_acl(path)
    except (OSError, WindowsFileBoundaryError) as exc:
        raise SeedCatalogError("private Windows Seed catalog custody rejected") from exc


@dataclass(frozen=True)
class SeedCatalogReport:
    """One complete import and verification decision."""

    run_id: str
    profile: str
    source_namespace: str
    source_digest: str
    catalog_digest: str
    event_count: int
    minimum_event_id: int
    maximum_event_id: int
    missing_event_id_count: int
    entity_count: int
    relation_count: int
    task_count: int
    active_task_count: int
    lock_count: int
    active_lock_count: int
    topic_count: int
    inserted_event_count: int
    existing_event_count: int
    home_record_count: int
    result: str
    started_at: str
    finished_at: str
    catalog_read_seal: dict[str, Any]

    def to_document(self) -> dict[str, Any]:
        return {
            "protocol": "integrity-guardian/seed-catalog-report/v1",
            "run_id": self.run_id,
            "profile": self.profile,
            "source_namespace": self.source_namespace,
            "source_digest": self.source_digest,
            "catalog_digest": self.catalog_digest,
            "event_count": self.event_count,
            "minimum_event_id": self.minimum_event_id,
            "maximum_event_id": self.maximum_event_id,
            "missing_event_id_count": self.missing_event_id_count,
            "entity_count": self.entity_count,
            "relation_count": self.relation_count,
            "task_count": self.task_count,
            "active_task_count": self.active_task_count,
            "lock_count": self.lock_count,
            "active_lock_count": self.active_lock_count,
            "topic_count": self.topic_count,
            "inserted_event_count": self.inserted_event_count,
            "existing_event_count": self.existing_event_count,
            "home_record_count": self.home_record_count,
            "result": self.result,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "catalog_read_seal": self.catalog_read_seal,
            "production_authority": False,
        }


_TOPIC_PATTERNS: dict[str, re.Pattern[str]] = {
    "identity-continuity": re.compile(
        r"(?i)action log|mind graph|memory|seed|recall|resume|handoff|"
        r"continuity|amnesia|identity|памят|продолж"
    ),
    "coordination-ownership": re.compile(
        r"(?i)task|owner|ownership|lock|thread|worker|agent|conflict|"
        r"blast[\s_-]*radius|задач|владел|блокиров|конфликт"
    ),
    "observation-senses": re.compile(
        r"(?i)read[\s_-]*only|observation|observer|sensor|telemetry|"
        r"discovery|freshness|unknown|monitor|наблюд|сенсор|неизвест"
    ),
    "guardian-evidence": re.compile(
        r"(?i)guardian|evidence|proof|receipt|signature|checkpoint|"
        r"ledger|attestation|доказ|подпис|чекпоинт"
    ),
    "atlas-fog": re.compile(
        r"(?i)\batlas\b|fog[\s_-]*of[\s_-]*war|\bfog\b|topology|"
        r"projection|world[\s_-]*model|тополог|карт[аыу]"
    ),
    "synapse-routes": re.compile(
        r"(?i)synapse|connectome|affordance|capability[\s_-]*graph|"
        r"route|синап|маршрут|нейро"
    ),
    "uroboros-procedural-memory": re.compile(
        r"(?i)uroboros|toolz|procedural|reusable|replay|reflex|"
        r"optimizer|процедур|рефлекс|повтор"
    ),
    "authority-action": re.compile(
        r"(?i)authority|owner[\s_-]*go|authorization|execute|execution|"
        r"mutation|rollback|apply|полномоч|авторизац|откат|выполн"
    ),
    "result-outcome": re.compile(
        r"(?i)result|outcome|success|failure|failed|verified|post[\s_-]*check|"
        r"done[\s_-]*when|результат|успех|ошиб|провер"
    ),
    "infrastructure-operations": re.compile(
        r"(?i)infrastructure|routing|VLAN|billing|switch|DHCP|"
        r"\bNAT\b|\bDNS\b|subscriber|абонент|платеж|outage|network"
    ),
    "concept-roadmap": re.compile(
        r"(?i)\bconcept|\bdesign|\bphilosoph|\broadmap|release[\s_-]*candidate|"
        r"(?<![A-Za-z0-9_])rc\d*(?![A-Za-z0-9_])|концеп|дизайн|философ"
    ),
}

_COMPLETE_ACTION_MARKERS = (
    "complete",
    "commit",
    "done",
    "resolved",
    "validated",
    "verified",
)
_FAILED_ACTION_MARKERS = ("failed", "rejected")
_BLOCKED_ACTION_MARKERS = ("blocked",)
_PENDING_ACTION_MARKERS = ("pending", "paused", "wait")
_ACTIVE_ACTION_MARKERS = (
    "start",
    "progress",
    "resumed",
    "checkpoint",
    "update",
)
_RESULT_COMPLETE = {
    "complete",
    "completed",
    "done",
    "ok",
    "pass",
    "passed",
    "success",
    "succeeded",
    "verified",
}
_RESULT_ACTIVE = {"active", "in-progress", "partial", "started", "running"}
_RESULT_FAILED = {"error", "fail", "failed", "rejected"}
_RESULT_BLOCKED = {"blocked"}
_RESULT_PENDING = {"paused", "pending", "waiting"}

_SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS seed_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS seed_events (
    event_id INTEGER PRIMARY KEY,
    event_uid TEXT NOT NULL,
    ts_utc TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    level TEXT NOT NULL,
    summary TEXT NOT NULL,
    details_json TEXT NOT NULL,
    tags_json TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    event_digest TEXT NOT NULL UNIQUE,
    source_namespace TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_seed_event_uid_nonempty
ON seed_events(event_uid)
WHERE event_uid <> '';
CREATE INDEX IF NOT EXISTS idx_seed_events_ts ON seed_events(ts_utc, event_id);
CREATE INDEX IF NOT EXISTS idx_seed_events_actor ON seed_events(actor, event_id);
CREATE INDEX IF NOT EXISTS idx_seed_events_action ON seed_events(action, event_id);

CREATE TABLE IF NOT EXISTS seed_entities (
    entity_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    natural_key TEXT NOT NULL,
    label TEXT NOT NULL,
    attributes_json TEXT NOT NULL,
    first_event_id INTEGER NOT NULL,
    last_event_id INTEGER NOT NULL,
    UNIQUE(kind, natural_key),
    FOREIGN KEY(first_event_id) REFERENCES seed_events(event_id),
    FOREIGN KEY(last_event_id) REFERENCES seed_events(event_id)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_seed_entities_kind
ON seed_entities(kind, natural_key);

CREATE TABLE IF NOT EXISTS seed_event_entities (
    event_id INTEGER NOT NULL,
    entity_id TEXT NOT NULL,
    role TEXT NOT NULL,
    PRIMARY KEY(event_id, entity_id, role),
    FOREIGN KEY(event_id) REFERENCES seed_events(event_id) ON DELETE CASCADE,
    FOREIGN KEY(entity_id) REFERENCES seed_entities(entity_id) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_seed_event_entities_entity
ON seed_event_entities(entity_id, role, event_id);

CREATE TABLE IF NOT EXISTS seed_relations (
    relation_id TEXT PRIMARY KEY,
    from_entity_id TEXT NOT NULL,
    to_entity_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    event_id INTEGER NOT NULL,
    attributes_json TEXT NOT NULL,
    FOREIGN KEY(from_entity_id) REFERENCES seed_entities(entity_id),
    FOREIGN KEY(to_entity_id) REFERENCES seed_entities(entity_id),
    FOREIGN KEY(event_id) REFERENCES seed_events(event_id)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_seed_relations_from
ON seed_relations(from_entity_id, relation, event_id);
CREATE INDEX IF NOT EXISTS idx_seed_relations_to
ON seed_relations(to_entity_id, relation, event_id);
CREATE INDEX IF NOT EXISTS idx_seed_relations_event
ON seed_relations(event_id, relation);

CREATE TABLE IF NOT EXISTS seed_tasks (
    task_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    owner TEXT NOT NULL,
    priority TEXT NOT NULL,
    summary TEXT NOT NULL,
    scope TEXT NOT NULL,
    subsystems_json TEXT NOT NULL,
    touched_hosts_json TEXT NOT NULL,
    files_json TEXT NOT NULL,
    first_event_id INTEGER NOT NULL,
    last_event_id INTEGER NOT NULL,
    FOREIGN KEY(first_event_id) REFERENCES seed_events(event_id),
    FOREIGN KEY(last_event_id) REFERENCES seed_events(event_id)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_seed_tasks_status
ON seed_tasks(status, priority, last_event_id);

CREATE TABLE IF NOT EXISTS seed_locks (
    lock_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    status TEXT NOT NULL,
    priority TEXT NOT NULL,
    subsystems_json TEXT NOT NULL,
    target_hosts_json TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_utc TEXT NOT NULL,
    acquired_event_id INTEGER NOT NULL,
    released_event_id INTEGER,
    FOREIGN KEY(acquired_event_id) REFERENCES seed_events(event_id),
    FOREIGN KEY(released_event_id) REFERENCES seed_events(event_id)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_seed_locks_status
ON seed_locks(status, acquired_event_id);

CREATE TABLE IF NOT EXISTS seed_topics (
    topic_id TEXT PRIMARY KEY,
    label TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS seed_event_topics (
    event_id INTEGER NOT NULL,
    topic_id TEXT NOT NULL,
    PRIMARY KEY(event_id, topic_id),
    FOREIGN KEY(event_id) REFERENCES seed_events(event_id) ON DELETE CASCADE,
    FOREIGN KEY(topic_id) REFERENCES seed_topics(topic_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS seed_doctrine (
    doctrine_id TEXT PRIMARY KEY,
    event_id INTEGER NOT NULL UNIQUE,
    rank INTEGER NOT NULL,
    summary TEXT NOT NULL,
    digest TEXT NOT NULL,
    FOREIGN KEY(event_id) REFERENCES seed_events(event_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS seed_catalog_runs (
    run_id TEXT PRIMARY KEY,
    profile TEXT NOT NULL,
    source_namespace TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    catalog_digest TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    inserted_event_count INTEGER NOT NULL,
    existing_event_count INTEGER NOT NULL,
    entity_count INTEGER NOT NULL,
    relation_count INTEGER NOT NULL,
    task_count INTEGER NOT NULL,
    active_task_count INTEGER NOT NULL,
    lock_count INTEGER NOT NULL,
    active_lock_count INTEGER NOT NULL,
    topic_count INTEGER NOT NULL,
    home_record_count INTEGER NOT NULL,
    result TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL
) WITHOUT ROWID;
"""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _reject_seed_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SeedCatalogError(f"duplicate Seed JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_seed_nonfinite(value: str) -> None:
    raise SeedCatalogError(f"non-finite Seed JSON number is prohibited: {value}")


def _parse_seed_json(document: str | bytes | bytearray) -> Any:
    """Parse lossless Action Log JSON, including finite measurement floats."""

    try:
        return json.loads(
            document,
            object_pairs_hook=_reject_seed_duplicate_keys,
            parse_constant=_reject_seed_nonfinite,
        )
    except SeedCatalogError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SeedCatalogError(f"invalid Seed JSON: {exc}") from exc


def _seed_canonical_bytes(value: Any) -> bytes:
    """Deterministic Seed JSON profile preserving finite historical numbers.

    Guardian protocol receipts retain their stricter integer-only canonical
    profile.  Seed imports must instead preserve already-recorded operational
    measurements such as load averages and free-space values.
    """

    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise SeedCatalogError(f"value is outside the Seed JSON profile: {exc}") from exc
    return rendered.encode("utf-8")


def _canonical_text(value: Any) -> str:
    return _seed_canonical_bytes(value).decode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _event_digest(event: dict[str, Any]) -> str:
    return _sha256_bytes(_seed_canonical_bytes(event))


def _source_digest(events: Sequence[dict[str, Any]]) -> str:
    payload = b"\n".join(_seed_canonical_bytes(event) for event in events) + b"\n"
    return _sha256_bytes(payload)


def _string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        values: Iterable[Any] = re.split(r"[,;\r\n]+", value)
    elif isinstance(value, (list, tuple, set)):
        values = value
    else:
        values = (value,)
    result: list[str] = []
    for item in values:
        text = _string(item).strip()
        if text and text not in result:
            result.append(text)
    return sorted(result)


def _validate_text(value: Any, *, field: str, allow_empty: bool = True) -> str:
    if not isinstance(value, str):
        raise SeedCatalogError(f"{field} must be a string")
    if len(value) > MAX_TEXT_LENGTH:
        raise SeedCatalogError(f"{field} is too large")
    if not allow_empty and not value:
        raise SeedCatalogError(f"{field} cannot be empty")
    return value


def validate_seed_events(
    events: Sequence[dict[str, Any]],
    *,
    source_namespace: str,
) -> list[dict[str, Any]]:
    """Validate and canonically order one complete Seed event snapshot."""

    validate_seed_namespace(source_namespace)
    if not events:
        raise SeedCatalogError("canonical Seed snapshot is empty")
    if len(events) > MAX_EVENTS:
        raise SeedCatalogError("canonical Seed snapshot exceeds the event limit")

    normalized: list[dict[str, Any]] = []
    event_ids: set[int] = set()
    event_uids: set[str] = set()
    for index, original in enumerate(events):
        if not isinstance(original, dict):
            raise SeedCatalogError(f"event at position {index} is not an object")
        event = deepcopy(original)
        event_id = event.get("id")
        if not isinstance(event_id, int) or isinstance(event_id, bool) or event_id < 1:
            raise SeedCatalogError("Seed event id must be a positive integer")
        if event_id in event_ids:
            raise SeedCatalogError(f"duplicate Seed event id: {event_id}")
        event_ids.add(event_id)
        uid = _validate_text(event.get("event_uid", ""), field="event_uid")
        if uid:
            if uid in event_uids:
                raise SeedCatalogError(f"duplicate nonempty Seed event_uid: {uid}")
            event_uids.add(uid)
        _validate_text(event.get("ts_utc", ""), field="ts_utc", allow_empty=False)
        _validate_text(event.get("actor", ""), field="actor")
        _validate_text(event.get("action", ""), field="action", allow_empty=False)
        _validate_text(event.get("level", ""), field="level")
        _validate_text(event.get("summary", ""), field="summary")
        details = event.get("details", {})
        if details is None:
            details = {}
            event["details"] = details
        if not isinstance(details, dict):
            raise SeedCatalogError("Seed event details must be an object")
        tags = event.get("tags", [])
        if not isinstance(tags, (str, list, tuple, set)):
            raise SeedCatalogError("Seed event tags must be a string or list")
        normalized.append(event)

    normalized.sort(key=lambda item: item["id"])
    return normalized


def validate_seed_namespace(source_namespace: str) -> str:
    """Admit one explicit project Seed namespace and always reject Home."""

    if source_namespace == HOME_NAMESPACE:
        raise SeedCatalogError("Integrity Home is forbidden as a Seed source")
    if (
        not isinstance(source_namespace, str)
        or SEED_NAMESPACE_PATTERN.fullmatch(source_namespace) is None
    ):
        raise SeedCatalogError(
            "Seed source namespace must match seed://project/<lowercase-slug>"
        )
    return source_namespace


def read_events_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read a JSONL event export without accepting arrays or comments."""

    events: list[dict[str, Any]] = []
    with path.open("rb") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = _parse_seed_json(line)
            except Exception as exc:
                raise SeedCatalogError(
                    f"invalid Seed JSONL at line {line_number}"
                ) from exc
            if not isinstance(value, dict):
                raise SeedCatalogError(
                    f"Seed JSONL line {line_number} is not an object"
                )
            events.append(value)
    return events


def write_events_jsonl(path: Path, events: Sequence[dict[str, Any]]) -> None:
    """Write one canonical JSON object per line with crash-safe replacement."""

    path = path.absolute()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    payload = b"\n".join(_seed_canonical_bytes(event) for event in events) + b"\n"
    with temporary.open("xb") as handle:
        handle.write(payload)
        handle.flush()
    temporary.chmod(0o600)
    temporary.replace(path)


def _entity_id(kind: str, natural_key: str) -> str:
    identity = digest_object(
        {"kind": kind, "natural_key": natural_key},
        domain="seed-entity-identity-v1",
    ).split(":", 1)[1]
    return f"seed-entity:{identity}"


def _relation_id(
    *,
    from_entity_id: str,
    to_entity_id: str,
    relation: str,
    event_id: int,
    attributes: dict[str, Any],
) -> str:
    identity = digest_object(
        {
            "from_entity_id": from_entity_id,
            "to_entity_id": to_entity_id,
            "relation": relation,
            "event_id": event_id,
            "attributes": attributes,
        },
        domain="seed-relation-identity-v1",
    ).split(":", 1)[1]
    return f"seed-relation:{identity}"


def _upsert_entity(
    connection: sqlite3.Connection,
    *,
    kind: str,
    natural_key: str,
    label: str,
    attributes: dict[str, Any],
    event_id: int,
) -> str:
    natural_key = natural_key.strip()
    if not natural_key:
        raise SeedCatalogError("entity natural key cannot be empty")
    entity_id = _entity_id(kind, natural_key)
    attributes_json = _canonical_text(attributes)
    existing = connection.execute(
        """
        SELECT label, attributes_json, first_event_id, last_event_id
        FROM seed_entities WHERE entity_id = ?
        """,
        (entity_id,),
    ).fetchone()
    if existing is None:
        connection.execute(
            """
            INSERT INTO seed_entities(
                entity_id, kind, natural_key, label, attributes_json,
                first_event_id, last_event_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entity_id,
                kind,
                natural_key,
                label or natural_key,
                attributes_json,
                event_id,
                event_id,
            ),
        )
    else:
        first_event_id = min(existing[2], event_id)
        last_event_id = max(existing[3], event_id)
        selected_label = existing[0] if existing[0] else (label or natural_key)
        selected_attributes = existing[1]
        if event_id >= existing[3]:
            selected_label = label or natural_key
            selected_attributes = attributes_json
        connection.execute(
            """
            UPDATE seed_entities
            SET label = ?, attributes_json = ?, first_event_id = ?,
                last_event_id = ?
            WHERE entity_id = ?
            """,
            (
                selected_label,
                selected_attributes,
                first_event_id,
                last_event_id,
                entity_id,
            ),
        )
    return entity_id


def _link_event_entity(
    connection: sqlite3.Connection,
    *,
    event_id: int,
    entity_id: str,
    role: str,
) -> None:
    connection.execute(
        """
        INSERT OR IGNORE INTO seed_event_entities(event_id, entity_id, role)
        VALUES (?, ?, ?)
        """,
        (event_id, entity_id, role),
    )


def _add_relation(
    connection: sqlite3.Connection,
    *,
    from_entity_id: str,
    to_entity_id: str,
    relation: str,
    event_id: int,
    attributes: dict[str, Any] | None = None,
) -> None:
    relation_attributes = attributes or {}
    relation_id = _relation_id(
        from_entity_id=from_entity_id,
        to_entity_id=to_entity_id,
        relation=relation,
        event_id=event_id,
        attributes=relation_attributes,
    )
    connection.execute(
        """
        INSERT OR IGNORE INTO seed_relations(
            relation_id, from_entity_id, to_entity_id, relation,
            event_id, attributes_json
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            relation_id,
            from_entity_id,
            to_entity_id,
            relation,
            event_id,
            _canonical_text(relation_attributes),
        ),
    )


def _task_status(action: str, result: str, current: str | None) -> str:
    action_lower = action.lower()
    result_lower = result.lower().strip()
    if any(marker in action_lower for marker in _BLOCKED_ACTION_MARKERS):
        return "blocked"
    if any(marker in action_lower for marker in _FAILED_ACTION_MARKERS):
        return "failed"
    if any(marker in action_lower for marker in _PENDING_ACTION_MARKERS):
        return "pending"
    if any(marker in action_lower for marker in _COMPLETE_ACTION_MARKERS):
        return "complete"
    if result_lower in _RESULT_BLOCKED:
        return "blocked"
    if result_lower in _RESULT_FAILED:
        return "failed"
    if result_lower in _RESULT_PENDING:
        return "pending"
    if result_lower in _RESULT_COMPLETE:
        return "complete"
    if result_lower in _RESULT_ACTIVE:
        return "active"
    if any(marker in action_lower for marker in _ACTIVE_ACTION_MARKERS):
        return "active"
    return current or "unknown"


def _event_narrative(event: dict[str, Any]) -> str:
    details = event.get("details") or {}
    fields = [
        event.get("summary", ""),
        details.get("scope", ""),
        details.get("risk", ""),
        details.get("verification", ""),
        details.get("next_action", ""),
        details.get("done_when", ""),
        details.get("note", ""),
        details.get("rollback", ""),
    ]
    return "\n".join(_string(value) for value in fields if value)


def _derive_event(
    connection: sqlite3.Connection,
    event: dict[str, Any],
) -> None:
    event_id = event["id"]
    details = event.get("details") or {}
    event_entity = _upsert_entity(
        connection,
        kind="event",
        natural_key=str(event_id),
        label=event.get("summary", "") or event["action"],
        attributes={
            "action": event["action"],
            "level": event.get("level", ""),
            "ts_utc": event["ts_utc"],
            "truth_status": _string(details.get("truth_status", "reported")),
        },
        event_id=event_id,
    )
    _link_event_entity(
        connection,
        event_id=event_id,
        entity_id=event_entity,
        role="event",
    )

    def connect(
        *,
        kind: str,
        key: str,
        label: str,
        role: str,
        relation: str,
        attributes: dict[str, Any] | None = None,
    ) -> str | None:
        key = key.strip()
        if not key:
            return None
        target = _upsert_entity(
            connection,
            kind=kind,
            natural_key=key,
            label=label or key,
            attributes=attributes or {},
            event_id=event_id,
        )
        _link_event_entity(
            connection,
            event_id=event_id,
            entity_id=target,
            role=role,
        )
        _add_relation(
            connection,
            from_entity_id=event_entity,
            to_entity_id=target,
            relation=relation,
            event_id=event_id,
        )
        return target

    actor = _string(event.get("actor", "")).strip()
    connect(
        kind="agent-or-actor",
        key=actor,
        label=actor,
        role="actor",
        relation="recorded_by",
    )
    session_id = _string(event.get("session_id", "")).strip()
    connect(
        kind="session",
        key=session_id,
        label=session_id,
        role="session",
        relation="recorded_in",
    )
    action = _string(event.get("action", "")).strip()
    connect(
        kind="action-class",
        key=action,
        label=action,
        role="action",
        relation="classified_as",
    )

    task_id = _string(details.get("task_id", "")).strip()
    task_entity = connect(
        kind="task",
        key=task_id,
        label=_string(event.get("summary", "")) or task_id,
        role="task",
        relation="belongs_to_task",
        attributes={"priority": _string(details.get("priority", ""))},
    )
    owner = _string(details.get("owner", "")).strip()
    owner_entity = connect(
        kind="agent-or-actor",
        key=owner,
        label=owner,
        role="owner",
        relation="declares_owner",
    )
    if task_entity is not None and owner_entity is not None:
        _add_relation(
            connection,
            from_entity_id=task_entity,
            to_entity_id=owner_entity,
            relation="owned_by",
            event_id=event_id,
        )

    for subsystem in _string_list(details.get("subsystem")):
        connect(
            kind="subsystem",
            key=subsystem,
            label=subsystem,
            role="subsystem",
            relation="concerns_subsystem",
        )
    for host in _string_list(details.get("touched_hosts")):
        connect(
            kind="host",
            key=host,
            label=host,
            role="touched-host",
            relation="touches_host",
        )
    for file_path in _string_list(details.get("files")):
        connect(
            kind="file",
            key=file_path,
            label=file_path,
            role="touched-file",
            relation="touches_file",
        )
    for evidence_path in _string_list(details.get("evidence_files")):
        connect(
            kind="evidence-artifact",
            key=evidence_path,
            label=evidence_path,
            role="evidence",
            relation="cites_evidence",
        )
    for tag in _string_list(event.get("tags")):
        connect(
            kind="tag",
            key=tag,
            label=tag,
            role="tag",
            relation="tagged_with",
        )

    task_relations = {
        "parent_task_id": "child_of",
        "depends_on_task_ids": "depends_on",
        "related_task_ids": "related_to",
        "supersedes_task_ids": "supersedes",
        "blocks_task_ids": "blocks",
        "preempts_task_ids": "preempts",
    }
    if task_entity is not None:
        for field, relation in task_relations.items():
            for other_task_id in _string_list(details.get(field)):
                other_task_entity = _upsert_entity(
                    connection,
                    kind="task",
                    natural_key=other_task_id,
                    label=other_task_id,
                    attributes={},
                    event_id=event_id,
                )
                _add_relation(
                    connection,
                    from_entity_id=task_entity,
                    to_entity_id=other_task_entity,
                    relation=relation,
                    event_id=event_id,
                )

    narrative = _event_narrative(event)
    for topic, pattern in _TOPIC_PATTERNS.items():
        if not pattern.search(narrative):
            continue
        connection.execute(
            "INSERT OR IGNORE INTO seed_topics(topic_id, label) VALUES (?, ?)",
            (topic, topic.replace("-", " ")),
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO seed_event_topics(event_id, topic_id)
            VALUES (?, ?)
            """,
            (event_id, topic),
        )
        topic_entity = _upsert_entity(
            connection,
            kind="topic",
            natural_key=topic,
            label=topic.replace("-", " "),
            attributes={},
            event_id=event_id,
        )
        _add_relation(
            connection,
            from_entity_id=event_entity,
            to_entity_id=topic_entity,
            relation="concerns_topic",
            event_id=event_id,
        )

    if task_id:
        existing = connection.execute(
            """
            SELECT status, owner, priority, summary, scope, subsystems_json,
                   touched_hosts_json, files_json, first_event_id, last_event_id
            FROM seed_tasks WHERE task_id = ?
            """,
            (task_id,),
        ).fetchone()
        current_status = existing[0] if existing else None
        status = _task_status(
            event["action"],
            _string(details.get("result", "")),
            current_status,
        )
        preserve_existing_summary = (
            existing is not None
            and (
                event["action"].startswith("agent_lock_")
                or _string(event.get("summary", "")).startswith("LOCK ")
            )
        )
        values = {
            "owner": owner or (existing[1] if existing else ""),
            "priority": _string(details.get("priority", ""))
            or (existing[2] if existing else ""),
            "summary": (
                existing[3]
                if preserve_existing_summary
                else (
                    _string(event.get("summary", ""))
                    or (existing[3] if existing else "")
                )
            ),
            "scope": _string(details.get("scope", ""))
            or (existing[4] if existing else ""),
            "subsystems_json": _canonical_text(_string_list(details.get("subsystem")))
            if details.get("subsystem") is not None
            else (existing[5] if existing else "[]"),
            "touched_hosts_json": _canonical_text(
                _string_list(details.get("touched_hosts"))
            )
            if details.get("touched_hosts") is not None
            else (existing[6] if existing else "[]"),
            "files_json": _canonical_text(_string_list(details.get("files")))
            if details.get("files") is not None
            else (existing[7] if existing else "[]"),
        }
        first_event_id = min(event_id, existing[8]) if existing else event_id
        last_event_id = max(event_id, existing[9]) if existing else event_id
        connection.execute(
            """
            INSERT INTO seed_tasks(
                task_id, status, owner, priority, summary, scope,
                subsystems_json, touched_hosts_json, files_json,
                first_event_id, last_event_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(task_id) DO UPDATE SET
                status = excluded.status,
                owner = excluded.owner,
                priority = excluded.priority,
                summary = excluded.summary,
                scope = excluded.scope,
                subsystems_json = excluded.subsystems_json,
                touched_hosts_json = excluded.touched_hosts_json,
                files_json = excluded.files_json,
                first_event_id = excluded.first_event_id,
                last_event_id = excluded.last_event_id
            """,
            (
                task_id,
                status,
                values["owner"],
                values["priority"],
                values["summary"],
                values["scope"],
                values["subsystems_json"],
                values["touched_hosts_json"],
                values["files_json"],
                first_event_id,
                last_event_id,
            ),
        )

    lock_id = _string(details.get("lock_id", "")).strip()
    if event["action"] == "agent_lock_acquire" and lock_id:
        connection.execute(
            """
            INSERT INTO seed_locks(
                lock_id, task_id, status, priority, subsystems_json,
                target_hosts_json, reason, expires_utc,
                acquired_event_id, released_event_id
            ) VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, NULL)
            ON CONFLICT(lock_id) DO UPDATE SET
                task_id = excluded.task_id,
                status = 'active',
                priority = excluded.priority,
                subsystems_json = excluded.subsystems_json,
                target_hosts_json = excluded.target_hosts_json,
                reason = excluded.reason,
                expires_utc = excluded.expires_utc,
                acquired_event_id = excluded.acquired_event_id,
                released_event_id = NULL
            """,
            (
                lock_id,
                task_id,
                _string(details.get("priority", "")),
                _canonical_text(_string_list(details.get("subsystem"))),
                _canonical_text(_string_list(details.get("target_hosts"))),
                _string(details.get("reason", "")),
                _string(details.get("expires_utc", "")),
                event_id,
            ),
        )
    elif event["action"] == "agent_lock_release" and lock_id:
        connection.execute(
            """
            UPDATE seed_locks
            SET status = 'released', released_event_id = ?
            WHERE lock_id = ?
            """,
            (event_id, lock_id),
        )

    if event["action"] in DOCTRINE_ACTIONS:
        doctrine_id = f"seed-doctrine:event-{event_id}"
        connection.execute(
            """
            INSERT OR REPLACE INTO seed_doctrine(
                doctrine_id, event_id, rank, summary, digest
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                doctrine_id,
                event_id,
                0,
                _string(event.get("summary", "")),
                _event_digest(event),
            ),
        )


def _catalog_digest(connection: sqlite3.Connection) -> str:
    hasher = hashlib.sha256()
    tables = (
        ("seed_events", "event_id"),
        ("seed_entities", "entity_id"),
        ("seed_event_entities", "event_id, entity_id, role"),
        ("seed_relations", "relation_id"),
        ("seed_tasks", "task_id"),
        ("seed_locks", "lock_id"),
        ("seed_topics", "topic_id"),
        ("seed_event_topics", "event_id, topic_id"),
        ("seed_doctrine", "rank, event_id"),
    )
    for table, order in tables:
        columns = [
            row[1]
            for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        ]
        query = f"SELECT {', '.join(columns)} FROM {table} ORDER BY {order}"
        hasher.update(table.encode("utf-8") + b"\0")
        for row in connection.execute(query):
            hasher.update(
                _seed_canonical_bytes(dict(zip(columns, row, strict=True))) + b"\n"
            )
    return "sha256:" + hasher.hexdigest()


def _counts(connection: sqlite3.Connection) -> dict[str, int]:
    def count(query: str, parameters: tuple[Any, ...] = ()) -> int:
        return int(connection.execute(query, parameters).fetchone()[0])

    now = _utc_now()
    return {
        "event_count": count("SELECT COUNT(*) FROM seed_events"),
        "entity_count": count("SELECT COUNT(*) FROM seed_entities"),
        "relation_count": count("SELECT COUNT(*) FROM seed_relations"),
        "task_count": count("SELECT COUNT(*) FROM seed_tasks"),
        "active_task_count": count(
            "SELECT COUNT(*) FROM seed_tasks WHERE status IN ('active', 'pending', 'blocked')"
        ),
        "lock_count": count("SELECT COUNT(*) FROM seed_locks"),
        "active_lock_count": count(
            """
            SELECT COUNT(*) FROM seed_locks
            WHERE status = 'active' AND (expires_utc = '' OR expires_utc > ?)
            """,
            (now,),
        ),
        "topic_count": count("SELECT COUNT(*) FROM seed_topics"),
        "home_record_count": count(
            "SELECT COUNT(*) FROM seed_events WHERE source_namespace = ?",
            (HOME_NAMESPACE,),
        ),
    }


def _verify_connection(
    connection: sqlite3.Connection,
    *,
    expected_source_digest: str | None = None,
    expected_event_count: int | None = None,
) -> dict[str, Any]:
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity != "ok":
        raise SeedCatalogError(f"SQLite integrity check failed: {integrity}")
    metadata = dict(
        connection.execute("SELECT key, value FROM seed_metadata")
    )
    metadata_namespace = metadata.get("source_namespace")
    if not isinstance(metadata_namespace, str):
        raise SeedCatalogError("catalog source namespace metadata is absent")
    validate_seed_namespace(metadata_namespace)
    source_namespaces = {
        row[0]
        for row in connection.execute(
            "SELECT DISTINCT source_namespace FROM seed_events"
        )
    }
    if source_namespaces != {metadata_namespace}:
        raise SeedCatalogError("catalog contains a noncanonical or Home namespace")
    event_count = int(connection.execute("SELECT COUNT(*) FROM seed_events").fetchone()[0])
    if expected_event_count is not None and event_count != expected_event_count:
        raise SeedCatalogError("catalog event count differs from expected snapshot")
    raw_events = [
        _parse_seed_json(row[0].encode("utf-8"))
        for row in connection.execute(
            "SELECT canonical_json FROM seed_events ORDER BY event_id"
        )
    ]
    actual_source_digest = _source_digest(raw_events)
    if (
        expected_source_digest is not None
        and actual_source_digest != expected_source_digest
    ):
        raise SeedCatalogError("catalog source digest differs from expected snapshot")
    dangling = int(
        connection.execute(
            """
            SELECT COUNT(*) FROM seed_relations r
            LEFT JOIN seed_entities f ON f.entity_id = r.from_entity_id
            LEFT JOIN seed_entities t ON t.entity_id = r.to_entity_id
            LEFT JOIN seed_events e ON e.event_id = r.event_id
            WHERE f.entity_id IS NULL OR t.entity_id IS NULL OR e.event_id IS NULL
            """
        ).fetchone()[0]
    )
    if dangling:
        raise SeedCatalogError("catalog contains dangling graph relations")
    raw_mismatch = int(
        connection.execute(
            """
            SELECT COUNT(*) FROM seed_events
            WHERE event_digest = '' OR canonical_json = ''
            """
        ).fetchone()[0]
    )
    if raw_mismatch:
        raise SeedCatalogError("catalog contains an incomplete raw event")
    maximum_event_id = int(
        connection.execute("SELECT COALESCE(MAX(event_id), 0) FROM seed_events").fetchone()[0]
    )
    present_ids = {
        row[0]
        for row in connection.execute(
            "SELECT event_id FROM seed_events WHERE event_id IN (4711, 5042)"
        )
    }
    required_ids = {
        event_id for event_id in (4711, 5042) if maximum_event_id >= event_id
    }
    if present_ids != required_ids:
        raise SeedCatalogError("catalog is missing a mandatory owner doctrine anchor")
    counts = _counts(connection)
    if counts["home_record_count"] != 0:
        raise SeedCatalogError("Integrity Home leaked into the Seed catalog")
    return {
        "ok": True,
        "protocol": CATALOG_PROTOCOL,
        "schema_version": CATALOG_SCHEMA_VERSION,
        "source_namespace": metadata_namespace,
        "source_digest": actual_source_digest,
        "catalog_digest": _catalog_digest(connection),
        **counts,
        "production_authority": False,
    }


class SeedCatalog:
    """Crash-safe local catalog whose derived data is rebuildable from Seed."""

    def __init__(
        self,
        path: Path,
        *,
        immutable: bool = False,
        readonly_connection: sqlite3.Connection | None = None,
    ):
        self.path = path.absolute()
        self.immutable = immutable
        if readonly_connection is not None and not immutable:
            raise SeedCatalogError(
                "a retained Seed connection requires immutable catalog mode"
            )
        self._retained_readonly_connection = readonly_connection

    def _readonly_uri(self) -> str:
        suffix = "&immutable=1" if self.immutable else ""
        return f"file:{self.path}?mode=ro{suffix}"

    @contextmanager
    def _read_connection(self) -> Iterator[sqlite3.Connection]:
        retained = self._retained_readonly_connection
        if retained is None:
            with closing(
                sqlite3.connect(self._readonly_uri(), uri=True)
            ) as connection:
                yield connection
            return
        try:
            yield retained
        finally:
            if retained.in_transaction:
                retained.rollback()

    def initialize(self, *, source_namespace: str = SEED_NAMESPACE) -> dict[str, Any]:
        validate_seed_namespace(source_namespace)
        fresh = _prepare_catalog_path(self.path)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(_SCHEMA)
            connection.execute(
                """
                INSERT OR IGNORE INTO seed_metadata(key, value)
                VALUES ('protocol', ?)
                """,
                (CATALOG_PROTOCOL,),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO seed_metadata(key, value)
                VALUES ('schema_version', ?)
                """,
                (str(CATALOG_SCHEMA_VERSION),),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO seed_metadata(key, value)
                VALUES ('source_namespace', ?)
                """,
                (source_namespace,),
            )
            expected_generation = _seed_catalog_generation(connection)
            connection.commit()
            catalog_read_seal = seal_catalog_for_immutable_read(
                connection,
                self.path,
                generation_reader=_seed_catalog_generation,
                expected_generation=expected_generation,
                durable_commit=True,
            )
        _assert_catalog_path_custody(self.path)
        if fresh:
            _assert_no_closed_sqlite_sidecars(self.path)
        return catalog_read_seal

    def import_events(
        self,
        events: Sequence[dict[str, Any]],
        *,
        source_namespace: str = SEED_NAMESPACE,
        profile: str = "full",
        started_at: str | None = None,
        finished_at: str | None = None,
    ) -> SeedCatalogReport:
        normalized = validate_seed_events(
            events,
            source_namespace=source_namespace,
        )
        started = started_at or _utc_now()
        fresh = not _path_lexists(self.path)
        self.initialize(source_namespace=source_namespace)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = FULL")
            inserted = 0
            existing = 0
            connection.execute("BEGIN IMMEDIATE")
            try:
                metadata_namespace = connection.execute(
                    "SELECT value FROM seed_metadata WHERE key = 'source_namespace'"
                ).fetchone()[0]
                if metadata_namespace != source_namespace:
                    raise SeedCatalogError("catalog source namespace is immutable")
                for event in normalized:
                    canonical_json = _canonical_text(event)
                    event_digest = _event_digest(event)
                    row = connection.execute(
                        """
                        SELECT canonical_json, event_digest
                        FROM seed_events WHERE event_id = ?
                        """,
                        (event["id"],),
                    ).fetchone()
                    if row is not None:
                        if (
                            row["canonical_json"] != canonical_json
                            or row["event_digest"] != event_digest
                        ):
                            raise SeedCatalogError(
                                f"immutable Seed event conflict at id {event['id']}"
                            )
                        existing += 1
                        continue
                    details = event.get("details") or {}
                    connection.execute(
                        """
                        INSERT INTO seed_events(
                            event_id, event_uid, ts_utc, actor, action, level,
                            summary, details_json, tags_json, canonical_json,
                            event_digest, source_namespace
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            event["id"],
                            _string(event.get("event_uid", "")),
                            event["ts_utc"],
                            _string(event.get("actor", "")),
                            event["action"],
                            _string(event.get("level", "")),
                            _string(event.get("summary", "")),
                            _canonical_text(details),
                            _canonical_text(_string_list(event.get("tags"))),
                            canonical_json,
                            event_digest,
                            source_namespace,
                        ),
                    )
                    _derive_event(connection, event)
                    inserted += 1

                full_verification = _verify_connection(connection)
                catalog_digest = full_verification["catalog_digest"]
                finished = finished_at or _utc_now()
                ids = [
                    int(row[0])
                    for row in connection.execute(
                        "SELECT event_id FROM seed_events ORDER BY event_id"
                    )
                ]
                missing_count = (
                    (ids[-1] - ids[0] + 1) - len(ids) if ids else 0
                )
                run_core = {
                    "profile": profile,
                    "source_namespace": source_namespace,
                    "source_digest": full_verification["source_digest"],
                    "catalog_digest": catalog_digest,
                    "event_count": full_verification["event_count"],
                    "inserted_event_count": inserted,
                    "existing_event_count": existing,
                    "started_at": started,
                    "finished_at": finished,
                }
                run_id = "seed-run:" + digest_object(
                    run_core,
                    domain="seed-catalog-run-identity-v1",
                ).split(":", 1)[1]
                connection.execute(
                    """
                    INSERT INTO seed_catalog_runs(
                        run_id, profile, source_namespace, source_digest,
                        catalog_digest, event_count, inserted_event_count,
                        existing_event_count, entity_count, relation_count,
                        task_count, active_task_count, lock_count,
                        active_lock_count, topic_count, home_record_count,
                        result, started_at, finished_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        profile,
                        source_namespace,
                        full_verification["source_digest"],
                        catalog_digest,
                        full_verification["event_count"],
                        inserted,
                        existing,
                        full_verification["entity_count"],
                        full_verification["relation_count"],
                        full_verification["task_count"],
                        full_verification["active_task_count"],
                        full_verification["lock_count"],
                        full_verification["active_lock_count"],
                        full_verification["topic_count"],
                        full_verification["home_record_count"],
                        "PASS",
                        started,
                        finished,
                    ),
                )
                def generation_reader(current: sqlite3.Connection) -> dict[str, Any]:
                    return _seed_catalog_generation(
                        current,
                        focus_run_id=run_id,
                    )

                expected_generation = generation_reader(connection)
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            catalog_read_seal = seal_catalog_for_immutable_read(
                connection,
                self.path,
                generation_reader=generation_reader,
                expected_generation=expected_generation,
                durable_commit=True,
            )
        _assert_catalog_path_custody(self.path)
        if fresh:
            _assert_no_closed_sqlite_sidecars(self.path)
        return SeedCatalogReport(
            run_id=run_id,
            profile=profile,
            source_namespace=source_namespace,
            source_digest=full_verification["source_digest"],
            catalog_digest=catalog_digest,
            event_count=full_verification["event_count"],
            minimum_event_id=ids[0],
            maximum_event_id=ids[-1],
            missing_event_id_count=missing_count,
            entity_count=full_verification["entity_count"],
            relation_count=full_verification["relation_count"],
            task_count=full_verification["task_count"],
            active_task_count=full_verification["active_task_count"],
            lock_count=full_verification["lock_count"],
            active_lock_count=full_verification["active_lock_count"],
            topic_count=full_verification["topic_count"],
            inserted_event_count=inserted,
            existing_event_count=existing,
            home_record_count=full_verification["home_record_count"],
            result="PASS",
            started_at=started,
            finished_at=finished,
            catalog_read_seal=catalog_read_seal,
        )

    def verify(
        self,
        *,
        expected_source_digest: str | None = None,
        expected_event_count: int | None = None,
    ) -> dict[str, Any]:
        if not self.path.is_file():
            raise SeedCatalogError("Seed catalog does not exist")
        with self._read_connection() as connection:
            return _verify_connection(
                connection,
                expected_source_digest=expected_source_digest,
                expected_event_count=expected_event_count,
            )

    def canonical_projection_snapshot(self) -> dict[str, Any]:
        """Read verified canonical rows through one SQLite snapshot.

        Derived projections must not combine verification digests from one
        catalog generation with events or task cards from another.  Keeping
        the read transaction open across verification and row collection
        gives callers one WAL-consistent generation without blocking writers.
        """

        if not self.path.is_file():
            raise SeedCatalogError("Seed catalog does not exist")
        with self._read_connection() as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN")
            verification = _verify_connection(connection)
            run = connection.execute(
                """
                SELECT run_id FROM seed_catalog_runs
                ORDER BY finished_at DESC, run_id DESC LIMIT 1
                """
            ).fetchone()
            if run is None:
                raise SeedCatalogError("Seed catalog has no committed catalog run")
            events: list[dict[str, Any]] = []
            for row in connection.execute(
                "SELECT canonical_json FROM seed_events ORDER BY event_id"
            ):
                value = _parse_seed_json(row["canonical_json"].encode("utf-8"))
                if not isinstance(value, dict):
                    raise SeedCatalogError("catalog raw event is not an object")
                events.append(value)
            task_records = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT task_id, status, owner, priority, summary, scope,
                           first_event_id, last_event_id
                    FROM seed_tasks ORDER BY task_id
                    """
                )
            ]
        return {
            "run_id": str(run["run_id"]),
            "verification": verification,
            "events": events,
            "task_records": task_records,
        }

    def bound_source_namespace(self) -> str | None:
        """Read immutable catalogue identity, including an initialized empty store.

        This is an identity read, not a claim that an empty store has verified
        event provenance. All event admission still uses full verification.
        """
        if not self.path.is_file():
            return None
        with self._read_connection() as connection:
            row = connection.execute(
                "SELECT value FROM seed_metadata WHERE key = 'source_namespace'"
            ).fetchone()
        if row is None:
            raise SeedCatalogError("catalog source namespace metadata is absent")
        return validate_seed_namespace(row[0])

    def event_cursor(self) -> tuple[int, int]:
        """Return the current raw event count and maximum id without projection work."""

        if not self.path.is_file():
            return (0, 0)
        with self._read_connection() as connection:
            count, maximum = connection.execute(
                "SELECT COUNT(*), COALESCE(MAX(event_id), 0) FROM seed_events"
            ).fetchone()
        return (int(count), int(maximum))

    def event_at(self, event_id: int) -> dict[str, Any]:
        """Read one exact canonical event for a bounded idempotent no-op sync."""

        if not self.path.is_file():
            raise SeedCatalogError("Seed catalog does not exist")
        with self._read_connection() as connection:
            row = connection.execute(
                "SELECT canonical_json FROM seed_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
        if row is None:
            raise SeedCatalogError(f"Seed catalog has no event {event_id}")
        value = _parse_seed_json(row[0].encode("utf-8"))
        if not isinstance(value, dict):
            raise SeedCatalogError("catalog raw event is not an object")
        return value

    def latest_run_id(self) -> str:
        """Return the latest committed catalog run identity without rehashing."""

        if not self.path.is_file():
            raise SeedCatalogError("Seed catalog does not exist")
        with self._read_connection() as connection:
            row = connection.execute(
                """
                SELECT run_id FROM seed_catalog_runs
                ORDER BY finished_at DESC, run_id DESC LIMIT 1
                """
            ).fetchone()
        if row is None:
            raise SeedCatalogError("Seed catalog has no committed catalog run")
        return str(row[0])

    def runtime_snapshot(self, *, active_limit: int = 12) -> dict[str, Any]:
        """Verify once and compose the two bounded read-only runtime views."""

        if not 1 <= active_limit <= 50:
            raise SeedCatalogError("capsule active task limit is outside 1..50")
        if not self.path.is_file():
            raise SeedCatalogError("Seed catalog does not exist")
        with self._read_connection() as connection:
            connection.row_factory = sqlite3.Row
            verification = _verify_connection(connection)
            status = self._status_from_connection(connection, verification)
            capsule = self._capsule_from_connection(
                connection,
                verification,
                active_limit=active_limit,
            )
        latest_run = status.get("latest_run") or {}
        return {
            "run_id": str(latest_run.get("run_id") or ""),
            "status": status,
            "capsule": capsule,
        }

    def status(self) -> dict[str, Any]:
        if not self.path.is_file():
            raise SeedCatalogError("Seed catalog does not exist")
        with self._read_connection() as connection:
            connection.row_factory = sqlite3.Row
            verification = _verify_connection(connection)
            return self._status_from_connection(connection, verification)

    @staticmethod
    def _status_from_connection(
        connection: sqlite3.Connection,
        verification: dict[str, Any],
    ) -> dict[str, Any]:
        latest_run = connection.execute(
            """
            SELECT * FROM seed_catalog_runs
            ORDER BY finished_at DESC, run_id DESC LIMIT 1
            """
        ).fetchone()
        minimum_id, maximum_id = connection.execute(
            "SELECT MIN(event_id), MAX(event_id) FROM seed_events"
        ).fetchone()
        topic_counts = {
            row[0]: row[1]
            for row in connection.execute(
                """
                SELECT topic_id, COUNT(*) FROM seed_event_topics
                GROUP BY topic_id ORDER BY topic_id
                """
            )
        }
        return {
            **verification,
            "status": "READY",
            "minimum_event_id": minimum_id,
            "maximum_event_id": maximum_id,
            "latest_run": dict(latest_run) if latest_run else None,
            "topic_event_counts": topic_counts,
        }

    def search(self, query: str, *, limit: int = 20) -> list[dict[str, Any]]:
        """Rank events by free-text term counts.

        This scans every event and matches substrings of actor, action,
        summary, details and tags; it uses no index. Use ``find_events`` for
        exact, index-backed filters.
        """
        terms = [term.casefold() for term in re.findall(r"[\w./:-]+", query)]
        if not terms:
            raise SeedCatalogError("Seed search requires at least one term")
        if not 1 <= limit <= 200:
            raise SeedCatalogError("Seed search limit is outside 1..200")
        with self._read_connection() as connection:
            connection.row_factory = sqlite3.Row
            candidates = connection.execute(
                """
                SELECT event_id, ts_utc, actor, action, summary, details_json,
                       tags_json, event_digest
                FROM seed_events ORDER BY event_id DESC
                """
            )
            results: list[tuple[int, dict[str, Any]]] = []
            for row in candidates:
                searchable = " ".join(
                    (
                        row["actor"],
                        row["action"],
                        row["summary"],
                        row["details_json"],
                        row["tags_json"],
                    )
                ).casefold()
                score = sum(searchable.count(term) for term in terms)
                if not score:
                    continue
                results.append(
                    (
                        score,
                        {
                            "event_id": row["event_id"],
                            "ts_utc": row["ts_utc"],
                            "actor": row["actor"],
                            "action": row["action"],
                            "summary": row["summary"],
                            "event_digest": row["event_digest"],
                            "score": score,
                        },
                    )
                )
            results.sort(key=lambda item: (item[0], item[1]["event_id"]), reverse=True)
            return [item[1] for item in results[:limit]]

    def find_events(
        self,
        *,
        actor: str | None = None,
        action: str | None = None,
        task_id: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Return events matching every given exact filter, newest first.

        ``actor``, ``action`` and the ``since``/``until`` bounds on ``ts_utc``
        use the event indexes; ``task_id`` resolves through the task entity
        projection. At least one filter is required.
        """

        if not 1 <= limit <= 500:
            raise SeedCatalogError("Seed event query limit is outside 1..500")
        filters = {
            "actor": actor,
            "action": action,
            "task_id": task_id,
            "since": since,
            "until": until,
        }
        for field, value in filters.items():
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise SeedCatalogError(f"Seed event query {field} must be a non-empty string")
        if all(value is None for value in filters.values()):
            raise SeedCatalogError("Seed event query requires at least one filter")
        clauses: list[str] = []
        parameters: list[Any] = []
        if actor is not None:
            clauses.append("actor = ?")
            parameters.append(actor.strip())
        if action is not None:
            clauses.append("action = ?")
            parameters.append(action.strip())
        if since is not None:
            clauses.append("ts_utc >= ?")
            parameters.append(since)
        if until is not None:
            clauses.append("ts_utc <= ?")
            parameters.append(until)
        if task_id is not None:
            clauses.append(
                """
                event_id IN (
                    SELECT link.event_id
                    FROM seed_entities AS entity
                    JOIN seed_event_entities AS link
                      ON link.entity_id = entity.entity_id AND link.role = 'task'
                    WHERE entity.kind = 'task' AND entity.natural_key = ?
                )
                """
            )
            parameters.append(task_id.strip())
        if not self.path.is_file():
            raise SeedCatalogError("Seed catalog does not exist")
        with self._read_connection() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                f"""
                SELECT event_id, ts_utc, actor, action, summary, event_digest
                FROM seed_events
                WHERE {" AND ".join(clauses)}
                ORDER BY event_id DESC
                LIMIT ?
                """,
                (*parameters, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def capsule(self, *, active_limit: int = 12) -> dict[str, Any]:
        if not 1 <= active_limit <= 50:
            raise SeedCatalogError("capsule active task limit is outside 1..50")
        if not self.path.is_file():
            raise SeedCatalogError("Seed catalog does not exist")
        with self._read_connection() as connection:
            connection.row_factory = sqlite3.Row
            verification = _verify_connection(connection)
            return self._capsule_from_connection(
                connection,
                verification,
                active_limit=active_limit,
            )

    @staticmethod
    def _capsule_from_connection(
        connection: sqlite3.Connection,
        verification: dict[str, Any],
        *,
        active_limit: int,
    ) -> dict[str, Any]:
        doctrine = [
            dict(row)
            for row in connection.execute(
                """
                SELECT event_id, rank, summary, digest
                FROM seed_doctrine ORDER BY rank, event_id
                """
            )
        ]
        active_tasks = [
            dict(row)
            for row in connection.execute(
                """
                SELECT task_id, status, owner, priority, summary, scope,
                       last_event_id, subsystems_json, touched_hosts_json,
                       files_json
                FROM seed_tasks
                WHERE status IN ('active', 'pending', 'blocked')
                ORDER BY
                    CASE priority
                        WHEN 'P0' THEN 0 WHEN 'P1' THEN 1
                        WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 ELSE 4
                    END,
                    last_event_id DESC
                LIMIT ?
                """,
                (active_limit,),
            )
        ]
        active_locks = [
            dict(row)
            for row in connection.execute(
                """
                SELECT lock_id, task_id, priority, reason, expires_utc,
                       acquired_event_id, subsystems_json, target_hosts_json
                FROM seed_locks
                WHERE status = 'active' AND (expires_utc = '' OR expires_utc > ?)
                ORDER BY acquired_event_id DESC
                """,
                (_utc_now(),),
            )
        ]
        latest_event_row = connection.execute(
            """
            SELECT event_id, ts_utc, action, summary, event_digest
            FROM seed_events ORDER BY event_id DESC LIMIT 1
            """
        ).fetchone()
        if latest_event_row is None:
            raise SeedCatalogError("Seed mission capsule requires at least one event")
        latest_event = dict(latest_event_row)
        for task in active_tasks:
            for field in ("subsystems_json", "touched_hosts_json", "files_json"):
                task[field.removesuffix("_json")] = json.loads(task.pop(field))
        for lock in active_locks:
            for field in ("subsystems_json", "target_hosts_json"):
                lock[field.removesuffix("_json")] = json.loads(lock.pop(field))
        capsule_core = {
            "protocol": "integrity-guardian/seed-mission-capsule/v1",
            "source_namespace": verification["source_namespace"],
            "source_digest": verification["source_digest"],
            "catalog_digest": verification["catalog_digest"],
            "event_cursor": latest_event["event_id"],
            "home_record_count": verification["home_record_count"],
            "north_star": (
                "Preserve cross-machine agent identity and coordinate work over the "
                "external target; observe the world, select a typed route, use scoped "
                "authority, prove the external result independently, and retain only "
                "verified reusable procedure memory."
            ),
            "forbidden_reductions": [
                "Guardian is a truth and evidence layer, not the whole Integrity product.",
                "A synthetic PASS is not proof of an external result.",
                "Memory and a remembered route never grant authority.",
                "Unknown or missing evidence never becomes green.",
                "Integrity Home is not part of canonical project Seed.",
            ],
            "doctrine": doctrine,
            "active_tasks": active_tasks,
            "active_locks": active_locks,
            "latest_event": latest_event,
            "production_authority": False,
        }
        capsule_digest = digest_object(
            capsule_core,
            domain="seed-mission-capsule-v1",
        )
        lines = [
            "INTEGRITY SEED MISSION CAPSULE",
            f"namespace={verification['source_namespace']}",
            f"cursor={latest_event['event_id']}",
            f"source_digest={verification['source_digest']}",
            f"catalog_digest={verification['catalog_digest']}",
            "",
            "NORTH STAR",
            capsule_core["north_star"],
            "",
            "FORBIDDEN REDUCTIONS",
            *[
                f"- {statement}"
                for statement in capsule_core["forbidden_reductions"]
            ],
            "",
            "DOCTRINE ANCHORS",
            *[
                f"- #{item['event_id']}: {item['summary']}"
                for item in doctrine
            ],
            "",
            "ACTIVE WORK",
            *[
                (
                    f"- {item['priority'] or 'P?'} {item['status']} "
                    f"{item['task_id']} owner={item['owner'] or 'unknown'}: "
                    f"{item['summary']}"
                )
                for item in active_tasks
            ],
            "",
            "ACTIVE LOCKS",
            *[
                f"- {item['lock_id']} task={item['task_id']}: {item['reason']}"
                for item in active_locks
            ],
        ]
        return {
            **capsule_core,
            "capsule_digest": capsule_digest,
            "context_text": "\n".join(lines).rstrip() + "\n",
        }

    def perspective(self, profile: str) -> dict[str, Any]:
        """Return one full-corpus verification lens used by acceptance runs."""

        profile_queries = {
            "full": ("integrity", "seed"),
            "chronology": ("timeline", "event"),
            "identity": ("identity", "memory"),
            "coordination": ("task", "lock"),
            "systems": ("host", "service"),
            "files": ("file", "repository"),
            "evidence": ("evidence", "verified"),
            "authority": ("authority", "owner go"),
            "outcomes": ("result", "postcheck"),
            "memory": ("action log", "continuity"),
            "atlas-fog": ("atlas", "fog"),
            "synapse-routes": ("synapse", "route"),
            "uroboros": ("uroboros", "toolz"),
            "infrastructure-operations": ("host", "service"),
            "doctrine": ("OWNER RC", "SEED MONUMENT"),
        }
        if profile not in profile_queries:
            raise SeedCatalogError(f"unknown Seed catalog perspective: {profile}")
        if not self.path.is_file():
            raise SeedCatalogError("Seed catalog does not exist")
        with self._read_connection() as connection:
            connection.row_factory = sqlite3.Row
            verification = _verify_connection(connection)
            status = self._status_from_connection(connection, verification)
            capsule = self._capsule_from_connection(
                connection,
                verification,
                active_limit=12,
            )
        queries = {
            query: self.search(query, limit=10)
            for query in profile_queries[profile]
        }
        if not all(queries.values()):
            raise SeedCatalogError(
                f"Seed perspective {profile} did not retrieve all required concepts"
            )
        topic_counter = Counter(status["topic_event_counts"])
        return {
            "protocol": "integrity-guardian/seed-perspective/v1",
            "profile": profile,
            "source_digest": status["source_digest"],
            "catalog_digest": status["catalog_digest"],
            "event_count": status["event_count"],
            "entity_count": status["entity_count"],
            "relation_count": status["relation_count"],
            "task_count": status["task_count"],
            "active_task_count": status["active_task_count"],
            "topic_count": status["topic_count"],
            "top_topics": topic_counter.most_common(5),
            "queries": queries,
            "capsule_digest": capsule["capsule_digest"],
            "home_record_count": status["home_record_count"],
            "result": "PASS",
            "production_authority": False,
        }


def catalog_from_jsonl(
    *,
    events_path: Path,
    catalog_path: Path,
    profile: str,
    source_namespace: str = SEED_NAMESPACE,
) -> SeedCatalogReport:
    events = read_events_jsonl(events_path)
    catalog = SeedCatalog(catalog_path)
    return catalog.import_events(
        events,
        source_namespace=source_namespace,
        profile=profile,
    )


def iter_catalog_events(path: Path) -> Iterator[dict[str, Any]]:
    """Yield exact canonical events from an existing catalog."""

    with closing(sqlite3.connect(f"file:{path.absolute()}?mode=ro", uri=True)) as connection:
        for row in connection.execute(
            "SELECT canonical_json FROM seed_events ORDER BY event_id"
        ):
            value = _parse_seed_json(row[0].encode("utf-8"))
            if not isinstance(value, dict):
                raise SeedCatalogError("catalog raw event is not an object")
            yield value
