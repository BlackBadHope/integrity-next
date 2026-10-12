#!/usr/bin/env python3
"""Small local action log for Codex/agent operational notes."""

from __future__ import annotations

import atexit
import base64
import datetime as dt
import hashlib
import hmac
import html
import json
import math
import os
import re
import socket
import sqlite3
import stat
import sys
import tempfile
import threading
from contextlib import contextmanager
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

SOURCE_PATH = Path(__file__).resolve()
APP_DIR = SOURCE_PATH.parent
DATA_DIR = Path(os.environ.get("CODEX_LOG_DATA_DIR", APP_DIR / "data"))
DB_PATH = Path(os.environ.get("CODEX_LOG_DB", DATA_DIR / "codex-action-log.sqlite3"))
SEED_DIRTY_MARKER = Path(
    os.environ.get(
        "CODEX_LOG_SEED_DIRTY_MARKER", DB_PATH.parent / "integrity-seed-dirty"
    )
)
HOST = os.environ.get("CODEX_LOG_HOST", "127.0.0.1")
PORT = int(os.environ.get("CODEX_LOG_PORT", "8765"))
TOKEN = os.environ.get("CODEX_LOG_TOKEN", "")
PID_FILE = os.environ.get("CODEX_LOG_PID_FILE", "")
MIN_TOKEN_BYTES = 32
MAX_TOKEN_BYTES = 4096
MAX_LIMIT = 1000
RECOVERY_WITNESS_TASK_ID_CHARS = 200
SERVICE_VERSION = "2.9.0"
TASK_LEASE_STALE_AFTER_HOURS = 12.0
LOCK_TTL_DEFAULT_MINUTES = 120.0
LOCK_TTL_MIN_MINUTES = 1.0
LOCK_TTL_MAX_MINUTES = 1440.0
MEMORY_CONTRACT_VERSION = 3
BOOTSTRAP_SNAPSHOT_PROTOCOL = "exampleproject.action-log.bootstrap-snapshot/v1"
MIND_PROJECTION_PROTOCOL = "exampleproject.action-log.mind-projection/v1"
MIND_CAPSULE_PROTOCOL = "integrity-guardian/mind-capsule/v1"
MIND_SEGMENT_COVERAGE_PROTOCOL = "integrity.action-log.segmented-query-coverage/v1"
# A 256 KiB UTF-8 prompt can require one extra segment when a multi-byte
# code point straddles a 4096-byte boundary. The total-byte cap remains the
# authoritative payload bound; 65 is the exact worst-case segment count.
MIND_QUERY_MAX_SEGMENTS = 65
MIND_QUERY_MAX_SEGMENT_BYTES = 4096
MIND_QUERY_MAX_UTF8_BYTES = 256 * 1024
# JSON escaping can expand a valid 256 KiB text prompt by up to 6x. Keep the
# authenticated Mind route independently bounded while preserving its full
# advertised prompt contract even when the generic POST cap is configured low.
MIND_QUERY_MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024
MIND_SEGMENT_CANDIDATE_FLOOR = 32
ADMISSION_TTL_HOURS = 5
LEVELS = {"debug", "info", "warning", "error"}
OPEN_ACTIONS = {"agent_change_start", "agent_change_progress", "agent_change_resumed"}
PENDING_ACTIONS = {"agent_change_pending"}
PAUSE_ACTIONS = {"agent_change_paused"}
CLOSE_ACTIONS = {"agent_change_complete", "agent_change_blocked", "agent_change_failed"}
RELATION_CORRECTION_ACTIONS = {"agent_relation_correction"}
STATUS_BY_CLOSE_ACTION = {
    "agent_change_complete": "complete",
    "agent_change_blocked": "blocked",
    "agent_change_failed": "failed",
}
LOCK_ACQUIRE_ACTIONS = {"agent_lock_acquire", "agent_lock_heartbeat"}
LOCK_RELEASE_ACTIONS = {"agent_lock_release"}
SESSION_ADMISSION_ACTIONS = {"agent_session_admission"}
TASK_LIFECYCLE_ACTIONS = (
    OPEN_ACTIONS
    | PENDING_ACTIONS
    | PAUSE_ACTIONS
    | CLOSE_ACTIONS
    | RELATION_CORRECTION_ACTIONS
    | SESSION_ADMISSION_ACTIONS
)
TASK_OPERATIONAL_ACTIONS = (
    OPEN_ACTIONS | PENDING_ACTIONS | PAUSE_ACTIONS | CLOSE_ACTIONS
) | {
    "agent_owner_go",
    "agent_verification",
    "agent_memory_checkpoint",
}
SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|passphrase|secret|token|api[_-]?key|authorization|cookie|credential|session)",
    re.IGNORECASE,
)
SENSITIVE_PAIR_RE = re.compile(
    r"(?i)\b(password|passwd|passphrase|secret|token|api[_-]?key|authorization|cookie|credential|session)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)


def bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


MAX_REQUEST_BODY_BYTES = bounded_env_int(
    "CODEX_LOG_MAX_REQUEST_BODY_BYTES",
    1024 * 1024,
    64 * 1024,
    2 * 1024 * 1024,
)
MAX_CONCURRENT_REQUESTS = bounded_env_int(
    "CODEX_LOG_MAX_CONCURRENT_REQUESTS",
    32,
    4,
    64,
)
REQUEST_TIMEOUT_SECONDS = bounded_env_int(
    "CODEX_LOG_REQUEST_TIMEOUT_SECONDS",
    15,
    2,
    60,
)
MAX_RUNTIME_SOURCE_BYTES = 8 * 1024 * 1024


class RequestBodyError(ValueError):
    def __init__(self, status: HTTPStatus, message: str, close_connection: bool = True):
        super().__init__(message)
        self.status = status
        self.close_connection = close_connection


def header_values(headers: Any, name: str) -> list[str]:
    getter = getattr(headers, "get_all", None)
    if callable(getter):
        values = getter(name) or []
        return [str(value).strip() for value in values]
    value = headers.get(name)
    return [] if value is None else [str(value).strip()]


def parse_request_body_length(headers: Any, maximum: int | None = None) -> int:
    limit = MAX_REQUEST_BODY_BYTES if maximum is None else maximum
    transfer_encoding = header_values(headers, "Transfer-Encoding")
    if transfer_encoding:
        raise RequestBodyError(HTTPStatus.NOT_IMPLEMENTED, "Transfer-Encoding is not supported")
    values = header_values(headers, "Content-Length")
    if not values:
        raise RequestBodyError(HTTPStatus.LENGTH_REQUIRED, "Content-Length is required")
    if len(values) != 1 or not re.fullmatch(r"[0-9]+", values[0]):
        raise RequestBodyError(HTTPStatus.BAD_REQUEST, "Content-Length is invalid")
    try:
        length = int(values[0])
    except ValueError as exc:
        raise RequestBodyError(HTTPStatus.BAD_REQUEST, "Content-Length is invalid") from exc
    if length > limit:
        raise RequestBodyError(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            f"request body exceeds {limit} bytes",
        )
    return length


def validate_mind_query_segments(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise TypeError("q_segments must be a JSON array of nonempty strings")
    if not value:
        raise ValueError("q_segments must contain at least one segment")
    if len(value) > MIND_QUERY_MAX_SEGMENTS:
        raise ValueError(
            f"q_segments exceeds the {MIND_QUERY_MAX_SEGMENTS}-segment limit"
        )
    segments: list[str] = []
    total_utf8_bytes = 0
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise TypeError(f"q_segments[{index}] must be a string")
        if item == "":
            raise ValueError(f"q_segments[{index}] must be nonempty")
        item_utf8_bytes = len(item.encode("utf-8"))
        if item_utf8_bytes > MIND_QUERY_MAX_SEGMENT_BYTES:
            raise ValueError(
                f"q_segments[{index}] exceeds the "
                f"{MIND_QUERY_MAX_SEGMENT_BYTES}-byte UTF-8 limit"
            )
        total_utf8_bytes += item_utf8_bytes
        if total_utf8_bytes > MIND_QUERY_MAX_UTF8_BYTES:
            raise ValueError(
                f"q_segments exceeds the {MIND_QUERY_MAX_UTF8_BYTES}-byte UTF-8 limit"
            )
        segments.append(item)
    if not "".join(segments).strip():
        raise ValueError("q_segments must contain a non-whitespace query")
    return segments


def mind_query_segments_digest(segments: list[str]) -> str:
    digest = hashlib.sha256()
    digest.update(b"integrity.action-log.q-segments/v1\0")
    for segment in segments:
        encoded = segment.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return "sha256:" + digest.hexdigest()


def json_query_params(payload: dict[str, Any], *, path: str) -> dict[str, list[str]]:
    if not isinstance(payload, dict):
        raise TypeError("payload must be an object")
    if "q_segments" in payload and path != "/api/mind":
        raise ValueError("q_segments is only supported by POST /api/mind")
    if "q_segments" in payload and "q" in payload:
        raise ValueError("q and q_segments are mutually exclusive")
    params: dict[str, list[str]] = {}
    for raw_key, value in payload.items():
        key = str(raw_key)
        if key == "q_segments":
            params[key] = validate_mind_query_segments(value)
            continue
        if isinstance(value, (dict, list)):
            raise TypeError(f"query parameter '{key}' must be scalar")
        if isinstance(value, bool):
            rendered = "true" if value else "false"
        else:
            rendered = "" if value is None else str(value)
        params[key] = [rendered]
    return params


@contextmanager
def open_db(*, allow_schema: bool = False):
    connection = sqlite3.connect(DB_PATH)
    if not allow_schema:
        protect_event_schema(connection)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


# BEGIN GENERATED EVENT RECOVERY POLICY
RECOVERY_PROTOCOL = "integrity.event-recovery/v1"


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")).hexdigest()


def validate_recovery(event_uid: str, details: Any) -> None:
    if not isinstance(details, dict):
        if event_uid.startswith("client:recovery-v1-"):
            raise ValueError("recovery requires object provenance")
        return
    recovery = details.get("recovery")
    if recovery is None:
        if event_uid.startswith("client:recovery-v1-"):
            raise ValueError("recovery identity requires provenance")
        return
    if not isinstance(recovery, dict) or set(recovery) != {
        "protocol", "fact_key", "occurred_at", "sources", "created_at_policy"
    }:
        raise ValueError("invalid recovery annotation")
    if recovery["protocol"] != RECOVERY_PROTOCOL or recovery["created_at_policy"] != "server-now":
        raise ValueError("recovery cannot supply or backdate creation time")
    fact_key = recovery["fact_key"]
    if not isinstance(fact_key, str) or not 1 <= len(fact_key) <= 200:
        raise ValueError("bounded recovery fact_key is required")
    occurred_at = recovery["occurred_at"]
    if not isinstance(occurred_at, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", occurred_at
    ):
        raise ValueError("recovery occurred_at must be explicit UTC")
    try:
        dt.datetime.fromisoformat(occurred_at)
    except ValueError as exc:
        raise ValueError("invalid recovery occurred_at") from exc
    sources = recovery["sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= 20:
        raise ValueError("bounded recovery provenance is required")
    for source in sources:
        if not isinstance(source, dict) or set(source) != {
            "chat_id", "turn_id", "artifact", "artifact_sha256"
        }:
            raise ValueError("recovery requires chat, turn, artifact and hash")
        if not all(isinstance(source[k], str) and 1 <= len(source[k]) <= 1024 for k in source):
            raise ValueError("recovery provenance contains missing or oversized values")
        if not re.fullmatch(r"[a-f0-9]{64}", source["artifact_sha256"]):
            raise ValueError("recovery artifact SHA256 is required")
    identities = [json.dumps(s, sort_keys=True, ensure_ascii=False) for s in sources]
    if identities != sorted(set(identities)):
        raise ValueError("recovery provenance must be sorted and unique")
    identity = {"protocol": RECOVERY_PROTOCOL, "fact_key": fact_key}
    if event_uid != "client:recovery-v1-" + _digest(identity):
        raise ValueError("recovery identity does not match provenance")
    correction = details.get("correction")
    if correction is None:
        if fact_key.startswith("correction:"):
            raise ValueError("correction requires an immutable original event link")
        return
    if not isinstance(correction, dict) or set(correction) != {
        "mode", "target_event_uid", "target_event_digest", "correction_key"
    }:
        raise ValueError("invalid linked correction")
    target = correction["target_event_uid"]
    key = correction["correction_key"]
    digest = correction["target_event_digest"]
    if (correction["mode"] != "superseding" or not isinstance(target, str)
            or not 1 <= len(target) <= 160 or target == event_uid
            or not isinstance(key, str) or not 1 <= len(key) <= 200
            or not isinstance(digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest)):
        raise ValueError("correction must link an immutable original; in-place mutation forbidden")
    if fact_key != "correction:" + _digest(correction):
        raise ValueError("correction identity does not match original link")


def build_recovery_event(*, fact_key: str, summary: str, occurred_at: str,
                         sources: list[dict[str, str]]) -> dict[str, Any]:
    sources = sorted(sources, key=lambda s: json.dumps(s, sort_keys=True, ensure_ascii=False))
    event_uid = "client:recovery-v1-" + _digest({"protocol": RECOVERY_PROTOCOL, "fact_key": fact_key})
    details = {"recovery": {"protocol": RECOVERY_PROTOCOL, "fact_key": fact_key,
               "occurred_at": occurred_at, "sources": sources, "created_at_policy": "server-now"}}
    validate_recovery(event_uid, details)
    return {"event_uid": event_uid, "kind": "thought", "summary": summary,
            "details": details, "tags": ["recovery", "provenance"]}


def protect_event_schema(connection: sqlite3.Connection) -> None:
    """Protect the application's connection, not a disk/root security boundary."""
    def authorize(operation, first, second, database, trigger):
        first = str(first).casefold()
        second = str(second).casefold()
        if operation in (sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE,
                         sqlite3.SQLITE_DROP_TABLE) and first == "events":
            return sqlite3.SQLITE_DENY
        if operation == sqlite3.SQLITE_ALTER_TABLE and second == "events":
            return sqlite3.SQLITE_DENY
        if operation == sqlite3.SQLITE_DROP_TRIGGER and str(first).startswith("events_append_only_"):
            return sqlite3.SQLITE_DENY
        if operation == sqlite3.SQLITE_PRAGMA and first == "writable_schema":
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    connection.set_authorizer(authorize)


def build_correction_event(*, target_event_uid: str, target_event_digest: str,
                           correction_key: str, summary: str, occurred_at: str,
                           sources: list[dict[str, str]]) -> dict[str, Any]:
    correction = {"mode": "superseding", "target_event_uid": target_event_uid,
                  "target_event_digest": target_event_digest, "correction_key": correction_key}
    fact_key = "correction:" + _digest(correction)
    # Link before validation; this remains a new event and never opens the original store.
    sources = sorted(sources, key=lambda s: json.dumps(s, sort_keys=True, ensure_ascii=False))
    event_uid = "client:recovery-v1-" + _digest({"protocol": RECOVERY_PROTOCOL, "fact_key": fact_key})
    details = {"correction": correction, "recovery": {"protocol": RECOVERY_PROTOCOL,
        "fact_key": fact_key, "occurred_at": occurred_at, "sources": sources,
        "created_at_policy": "server-now"}}
    validate_recovery(event_uid, details)
    return {"event_uid": event_uid, "kind": "thought", "summary": summary,
            "details": details, "tags": ["recovery", "correction", "provenance"]}
# END GENERATED EVENT RECOVERY POLICY


GENERIC_TASK_TAGS = {
    "agent-log",
    "commit",
    "handoff",
    "progress",
    "done",
    "partial",
    "blocked",
    "failed",
    "complete",
    "in-progress",
}
RECALL_STOP_WORDS = {
    "a",
    "an",
    "after",
    "again",
    "and",
    "are",
    "as",
    "at",
    "be",
    "before",
    "by",
    "can",
    "could",
    "do",
    "does",
    "for",
    "from",
    "in",
    "into",
    "is",
    "it",
    "of",
    "on",
    "or",
    "please",
    "should",
    "that",
    "the",
    "then",
    "this",
    "to",
    "was",
    "were",
    "whether",
    "with",
    "would",
    "без",
    "был",
    "была",
    "были",
    "для",
    "его",
    "если",
    "ещё",
    "как",
    "меня",
    "надо",
    "наш",
    "она",
    "они",
    "оно",
    "потом",
    "при",
    "сейчас",
    "так",
    "там",
    "теперь",
    "того",
    "тоже",
    "уже",
    "что",
    "чтобы",
    "это",
}
INTENT_ALIAS_PREFIXES = {
    "матриц": ["matrix", "inventory", "status", "category"],
    "иерарх": ["hierarchy", "parent", "roadmap", "dependency"],
    "разум": ["mind", "memory", "context", "roadmap"],
    "памят": ["memory", "context", "action-log"],
    "подсознан": ["hook", "reflex", "compact", "resume", "memory"],
    "логик": ["decision", "dependency", "verification", "reasoning"],
    "биллинг": ["billing", "nodeny", "payment"],
    "платеж": ["payment", "billing", "pays"],
    "свитч": ["switch", "stat", "snmp"],
    "коммутатор": ["switch", "stat", "snmp"],
    "оптик": ["bdcom", "onu", "pmon", "losi"],
    "резерв": ["backup", "nas2"],
}
GENERIC_RECALL_TERMS = {"action", "agent", "codex", "log"}
DOMAIN_RULES = [
    ("side-project", ("orbit",)),
    ("codex-memory", ("action-log", "codex", "hook", "skill", "typed-tool", "operator-tool", "ops-memory")),
    ("billing", ("billing", "nodeny", "payment", "pays", "privat", "tariff", "subscriber")),
    ("network", ("vm-bras", "bras", "dhcp", "kea", "nat", "public-ip", "bgp", "border", "dns", "wireguard", "vlan")),
    ("monitoring", ("monitoring", "vm-stat", "stat", "noc", "switch", "snmp", "bdcom", "onu", "pmon", "optical", "telegram")),
    ("backup", ("nas2", "backup", "restore", "archive")),
    ("access", ("access", "ssh", "rdp", "desktop", "ceber", "windows", "superadmin", "tunnel")),
    ("platform", ("hypervisor", "vm-web", "vm-sip", "sip", "web", "database", "db", "linux")),
    ("governance", ("ownership", "security", "audit", "migration", "cutover", "legacy")),
]
_EVENT_CACHE_LOCK = threading.Lock()
_EVENT_CACHE_SIGNATURE: tuple[int, int] | None = None
_EVENT_CACHE: list[dict[str, Any]] = []
_PROJECTION_CACHE_LOCK = threading.Lock()
_PROJECTION_CACHE_SIGNATURE: tuple[int, int, int] | None = None
_PROJECTION_CACHE: dict[str, Any] = {}


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def runtime_source_sha256() -> str:
    """Attest the exact regular source file serving the health response."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(SOURCE_PATH, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("runtime source is not a regular file")
        if metadata.st_size < 1 or metadata.st_size > MAX_RUNTIME_SOURCE_BYTES:
            raise RuntimeError("runtime source size is outside the release boundary")
        digest = hashlib.sha256()
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise RuntimeError("runtime source changed while hashing")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RuntimeError("runtime source grew while hashing")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def invalidate_event_cache() -> None:
    global _EVENT_CACHE_SIGNATURE, _EVENT_CACHE, _PROJECTION_CACHE_SIGNATURE, _PROJECTION_CACHE
    with _EVENT_CACHE_LOCK:
        _EVENT_CACHE_SIGNATURE = None
        _EVENT_CACHE = []
    with _PROJECTION_CACHE_LOCK:
        _PROJECTION_CACHE_SIGNATURE = None
        _PROJECTION_CACHE = {}


def write_seed_dirty_marker(event_id: int) -> None:
    """Atomically signal a new canonical event without watching SQLite/WAL."""

    if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 0:
        raise ValueError("seed dirty marker cursor rejected")
    SEED_DIRTY_MARKER.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=".integrity-seed-dirty.", dir=SEED_DIRTY_MARKER.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(f"{event_id}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, SEED_DIRTY_MARKER)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def ensure_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open_db(allow_schema=True) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc TEXT NOT NULL,
                actor TEXT NOT NULL,
                session_id TEXT NOT NULL DEFAULT '',
                level TEXT NOT NULL,
                action TEXT NOT NULL,
                summary TEXT NOT NULL,
                details TEXT NOT NULL,
                tags TEXT NOT NULL,
                created_utc TEXT NOT NULL
            )
            """
        )
        columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(events)")}
        if "event_uid" not in columns:
            conn.execute("ALTER TABLE events ADD COLUMN event_uid TEXT NOT NULL DEFAULT ''")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_utc)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_actor ON events(actor)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_action ON events(action)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id)")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_event_uid "
            "ON events(event_uid) WHERE event_uid <> ''"
        )
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS events_append_only_no_update
            BEFORE UPDATE ON events
            BEGIN
                SELECT RAISE(ABORT, 'append-only Action Log: UPDATE forbidden');
            END
            """
        )
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS events_append_only_no_delete
            BEFORE DELETE ON events
            BEGIN
                SELECT RAISE(ABORT, 'append-only Action Log: DELETE forbidden');
            END
            """
        )
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS events_append_only_no_replace
            BEFORE INSERT ON events
            WHEN EXISTS (SELECT 1 FROM events WHERE id = NEW.id
                OR (NEW.event_uid <> '' AND event_uid = NEW.event_uid))
            BEGIN
                SELECT RAISE(ABORT, 'append-only Action Log: REPLACE forbidden');
            END
            """
        )
    invalidate_event_cache()
    with open_db() as conn:
        maximum = int(
            conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
        )
    write_seed_dirty_marker(maximum)


def redact_text(value: str) -> str:
    return SENSITIVE_PAIR_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", value)


def redact_value(value: Any, key_hint: str = "") -> Any:
    if SENSITIVE_KEY_RE.search(key_hint):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v, key_hint) for v in value]
    if isinstance(value, tuple):
        return [redact_value(v, key_hint) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def parse_window(spec: str | None, default: str = "24h") -> str:
    raw = (spec or default).strip()
    if raw.lower() in {"all", "beginning", "start", "0", "*"}:
        return "0001-01-01T00:00:00Z"
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    match = re.fullmatch(r"(\d+)\s*([mhd])", raw, re.IGNORECASE)
    if match:
        amount = int(match.group(1))
        unit = match.group(2).lower()
        if unit == "m":
            start = now - dt.timedelta(minutes=amount)
        elif unit == "h":
            start = now - dt.timedelta(hours=amount)
        else:
            start = now - dt.timedelta(days=amount)
        return start.isoformat().replace("+00:00", "Z")
    try:
        parsed = dt.datetime.fromisoformat(raw)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.UTC)
        return parsed.astimezone(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except ValueError:
        return parse_window(default, "24h")


def parse_limit(value: str | None, default: int = 100) -> int:
    try:
        limit = int(value or default)
    except ValueError:
        return default
    return max(1, min(limit, MAX_LIMIT))


def parse_int_param(value: str | None, default: int = 0, minimum: int = 0) -> int:
    try:
        parsed = int(value or default)
    except ValueError:
        return default
    return max(minimum, parsed)


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_float(value: str | None, default: float) -> float:
    try:
        return float(value or default)
    except ValueError:
        return default


def parse_event_time(value: Any) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(value))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.UTC)
        return parsed.astimezone(dt.UTC)
    except ValueError:
        return None


def normalize_tags(tags: Any) -> list[str]:
    if tags is None:
        return []
    if isinstance(tags, str):
        raw_items = re.split(r"[,;\s]+", tags)
    elif isinstance(tags, list):
        raw_items = tags
    else:
        raw_items = [str(tags)]
    result: list[str] = []
    for item in raw_items:
        tag = str(item).strip()
        if tag and tag not in result:
            result.append(redact_text(tag))
    return result


def normalize_details(details: Any) -> Any:
    if details in (None, ""):
        return {}
    if isinstance(details, str):
        stripped = details.strip()
        if not stripped:
            return {}
        try:
            return redact_value(json.loads(stripped))
        except json.JSONDecodeError:
            return {"text": redact_text(stripped)}
    return redact_value(details)


def normalize_event(raw: dict[str, Any]) -> dict[str, str]:
    if any(field in raw for field in ("created_at", "created_utc", "id")):
        raise ValueError("event identity and creation time are server-owned")
    level = str(raw.get("level") or "info").lower()
    if level not in LEVELS:
        level = "info"
    details = normalize_details(raw.get("details"))
    validate_recovery(str(raw.get("event_uid") or ""), details)
    tags = normalize_tags(raw.get("tags"))
    event = {
        "ts_utc": str(raw.get("ts_utc") or utc_now()),
        "actor": redact_text(str(raw.get("actor") or "codex"))[:120],
        "session_id": redact_text(str(raw.get("session_id") or ""))[:200],
        "level": level,
        "action": redact_text(str(raw.get("action") or "note"))[:160],
        "summary": redact_text(str(raw.get("summary") or ""))[:2000],
        "details": json.dumps(details, ensure_ascii=False, separators=(",", ":")),
        "tags": json.dumps(tags, ensure_ascii=False, separators=(",", ":")),
        "event_uid": redact_text(str(raw.get("event_uid") or ""))[:160],
        "created_utc": utc_now(),
    }
    if not event["summary"]:
        event["summary"] = "(no summary)"
    return event


def insert_event(raw: dict[str, Any]) -> dict[str, Any]:
    event = normalize_event(raw)

    def existing_reply(existing: sqlite3.Row) -> dict[str, Any]:
        for field in ("actor", "session_id", "level", "action", "summary", "tags"):
            if str(existing[field]) != event[field]:
                raise ValueError("event_uid collides with different immutable content")
        if json.dumps(json.loads(existing["details"]), sort_keys=True) != json.dumps(
            json.loads(event["details"]), sort_keys=True
        ):
            raise ValueError("event_uid collides with different immutable content")
        if raw.get("ts_utc") and str(existing["ts_utc"]) != event["ts_utc"]:
            raise ValueError("event_uid collides with different immutable fact time")
        return {"ok": True, "duplicate": True, **rows_to_events([existing])[0]}

    with open_db() as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        if event["event_uid"]:
            existing = conn.execute(
                "SELECT * FROM events WHERE event_uid = ?",
                [event["event_uid"]],
            ).fetchone()
            if existing is not None:
                return existing_reply(existing)
        try:
            cur = conn.execute(
                """
                INSERT INTO events
                  (ts_utc, actor, session_id, level, action, summary, details, tags, event_uid, created_utc)
                VALUES
                  (:ts_utc, :actor, :session_id, :level, :action, :summary, :details, :tags, :event_uid, :created_utc)
                """,
                event,
            )
            event_id = int(cur.lastrowid)
        except sqlite3.IntegrityError:
            if not event["event_uid"]:
                raise
            existing = conn.execute(
                "SELECT * FROM events WHERE event_uid = ?",
                [event["event_uid"]],
            ).fetchone()
            if existing is None:
                raise
            return existing_reply(existing)
    invalidate_event_cache()
    try:
        write_seed_dirty_marker(event_id)
        projection_signal = "updated"
    except OSError as exc:
        projection_signal = "failed"
        print(
            "content-free Integrity Seed dirty-marker failed for "
            f"event {event_id}: {type(exc).__name__}",
            file=sys.stderr,
        )
    stored = {"id": event_id, **event}
    stored["details"] = json.loads(event["details"] or "{}")
    stored["tags"] = json.loads(event["tags"] or "[]")
    return {
        "ok": True,
        "duplicate": False,
        "projection_signal": projection_signal,
        **stored,
    }


def accept_task(raw: dict[str, Any]) -> dict[str, Any]:
    """Atomically accept one normal ticket as an idempotent lifecycle start."""
    summary = str(raw.get("summary") or "").strip()
    if not summary:
        raise ValueError("summary is required")
    session_id = str(raw.get("session_id") or "").strip()[:200]
    requested_task_id = str(raw.get("task_id") or "").strip()
    if requested_task_id:
        task_id = re.sub(r"[^A-Za-z0-9._:-]+", "-", requested_task_id).strip("-")[:160]
    else:
        slug = re.sub(r"[^a-z0-9]+", "-", summary.lower()).strip("-")[:48] or "task"
        digest = hashlib.sha256(f"{session_id}\n{summary}".encode()).hexdigest()[:10]
        task_id = f"{slug}-{dt.datetime.now(dt.UTC):%Y%m%d}-{digest}"
    if not task_id:
        raise ValueError("task_id is empty after normalization")

    details = {
        "schema_version": 2,
        "kind": "task-start",
        "task_id": task_id,
        "result": "in-progress",
        "truth_status": "reported",
        "verification": str(raw.get("verification") or "pending")[:500],
        "subsystem": string_list(raw.get("subsystem")) or ["unscoped"],
    }
    scalar_fields = (
        "scope",
        "risk_level",
        "risk",
        "rollback",
        "priority",
        "owner",
        "next_action",
        "done_when",
        "goal_id",
        "roadmap_item_id",
        "parent_task_id",
        "attention_class",
    )
    list_fields = (
        "touched_hosts",
        "files",
        "commands",
        "evidence_files",
        "depends_on_task_ids",
        "related_task_ids",
        "supersedes_task_ids",
        "blocks_task_ids",
    )
    for field in scalar_fields:
        value = str(raw.get(field) or "").strip()
        if value:
            details[field] = value[:2000]
    for field in list_fields:
        values = string_list(raw.get(field))
        if values:
            details[field] = values[:100]

    event_uid = str(raw.get("event_uid") or "").strip()
    if not event_uid:
        event_uid = "task-accept:" + hashlib.sha256(
            f"{session_id}\n{task_id}".encode()
        ).hexdigest()
    stored = insert_event(
        {
            "event_uid": event_uid,
            "actor": str(raw.get("actor") or "codex-fast-start"),
            "session_id": session_id,
            "level": "info",
            "action": "agent_change_start",
            "summary": summary,
            "details": details,
            "tags": [*string_list(raw.get("tags")), *details["subsystem"], "agent-log", "fast-start"],
        }
    )
    return {
        "ok": True,
        "task_id": task_id,
        "event_id": int(stored.get("id") or 0),
        "duplicate": bool(stored.get("duplicate")),
        "event_cursor": event_store_signature()[1],
    }


def rows_to_events(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        for key in ("details", "tags"):
            try:
                item[key] = json.loads(item[key] or "{}")
            except json.JSONDecodeError:
                item[key] = item[key]
        events.append(item)
    return events


def query_events(params: dict[str, list[str]]) -> list[dict[str, Any]]:
    since = parse_window(first(params, "since"), "24h")
    limit = parse_limit(first(params, "limit"), 100)
    q = (first(params, "q") or "").strip()
    event_id = parse_int_param(first(params, "id"), 0, 0)
    event_uid = (first(params, "event_uid") or "").strip()
    before_id = parse_int_param(first(params, "before_id"), 0, 0)
    after_id = parse_int_param(first(params, "after_id"), 0, 0)
    snapshot_event_id = parse_int_param(first(params, "snapshot_event_id"), 0, 0)
    offset = parse_int_param(first(params, "offset"), 0, 0)
    order = (first(params, "order") or "desc").strip().lower()
    sort_field = (first(params, "sort") or "time").strip().lower()
    actor = (first(params, "actor") or "").strip()
    session_id = (first(params, "session_id") or "").strip()
    action = (first(params, "action") or "").strip()
    level = (first(params, "level") or "").strip().lower()
    order_sql = "ASC" if order == "asc" else "DESC"
    query = "SELECT * FROM events WHERE 1=1"
    values: list[Any] = []
    if event_id > 0:
        query += " AND id = ?"
        values.append(event_id)
    elif event_uid:
        # Exact immutable-identity reconciliation is deliberately independent
        # of the default time window.  The unique partial index on event_uid
        # makes this a bounded single-row lookup.
        query += " AND event_uid = ?"
        values.append(event_uid[:160])
    else:
        query += " AND ts_utc >= ?"
        values.append(since)
        if before_id > 0:
            query += " AND id < ?"
            values.append(before_id)
        if after_id > 0:
            query += " AND id > ?"
            values.append(after_id)
        if snapshot_event_id > 0:
            query += " AND id <= ?"
            values.append(snapshot_event_id)
    if q:
        like = f"%{q}%"
        query += (
            " AND (actor LIKE ? OR session_id LIKE ? OR level LIKE ? OR action LIKE ? "
            "OR summary LIKE ? OR details LIKE ? OR tags LIKE ?)"
        )
        values.extend([like] * 7)
    if actor:
        query += " AND actor = ?"
        values.append(actor)
    if session_id:
        query += " AND session_id = ?"
        values.append(session_id)
    if action:
        query += " AND action = ?"
        values.append(action)
    if level:
        query += " AND level = ?"
        values.append(level)
    if sort_field == "id":
        query += f" ORDER BY id {order_sql} LIMIT ? OFFSET ?"
    else:
        query += f" ORDER BY ts_utc {order_sql}, id {order_sql} LIMIT ? OFFSET ?"
    values.extend([limit, offset])
    with open_db() as conn:
        conn.row_factory = sqlite3.Row
        rows = list(conn.execute(query, values))
    return rows_to_events(rows)


def event_store_signature() -> tuple[int, int]:
    with open_db() as conn:
        count, maximum = conn.execute("SELECT COUNT(*), COALESCE(MAX(id), 0) FROM events").fetchone()
    return int(count), int(maximum)


def encode_cursor(*parts: Any) -> str:
    raw = json.dumps(list(parts), ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(value: str, expected_parts: int) -> list[Any] | None:
    if not value:
        return None
    try:
        padded = value + ("=" * (-len(value) % 4))
        decoded = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(decoded, list) or len(decoded) != expected_parts:
        return None
    return decoded


def query_events_page(params: dict[str, list[str]]) -> dict[str, Any]:
    page_size = min(200, parse_limit(first(params, "page_size") or first(params, "limit"), 50))
    snapshot_event_id = parse_int_param(first(params, "snapshot_event_id"), 0, 0)
    if snapshot_event_id <= 0:
        snapshot_event_id = event_store_signature()[1]
    page_params = {key: list(values) for key, values in params.items()}
    page_params["snapshot_event_id"] = [str(snapshot_event_id)]
    page_params["sort"] = ["id"]
    page_params["limit"] = [str(min(MAX_LIMIT, page_size + 1))]
    rows = query_events(page_params)
    has_more = len(rows) > page_size
    rows = rows[:page_size]
    order = (first(params, "order") or "desc").strip().lower()
    last_id = int(rows[-1].get("id") or 0) if rows else 0
    next_before_id = last_id if rows and order != "asc" and has_more else None
    next_after_id = last_id if rows and order == "asc" and has_more else None
    return {
        "ok": True,
        "events": rows,
        "pagination": {
            "snapshot_event_id": snapshot_event_id,
            "page_size": page_size,
            "returned_count": len(rows),
            "has_more": has_more,
            "next_before_id": next_before_id,
            "next_after_id": next_after_id,
        },
    }


def query_all_events_snapshot() -> tuple[list[dict[str, Any]], tuple[int, int]]:
    """Read rows and their signature from one SQLite snapshot."""

    global _EVENT_CACHE_SIGNATURE, _EVENT_CACHE
    with _EVENT_CACHE_LOCK:
        with open_db() as conn:
            conn.execute("BEGIN")
            count, maximum = conn.execute("SELECT COUNT(*), COALESCE(MAX(id), 0) FROM events").fetchone()
            signature = (int(count), int(maximum))
            if signature == _EVENT_CACHE_SIGNATURE:
                return _EVENT_CACHE, signature
            conn.row_factory = sqlite3.Row
            rows = list(conn.execute("SELECT * FROM events ORDER BY id ASC"))
        _EVENT_CACHE = rows_to_events(rows)
        _EVENT_CACHE_SIGNATURE = signature
        return _EVENT_CACHE, signature


def query_all_events() -> list[dict[str, Any]]:
    return query_all_events_snapshot()[0]


def string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw_items = re.split(r"[,;\s]+", value)
    elif isinstance(value, list):
        raw_items = value
    else:
        raw_items = [value]
    result: list[str] = []
    for item in raw_items:
        text = str(item).strip()
        if text and text not in result:
            result.append(text)
    return result


def subsystem_domain(subsystem: str) -> str:
    value = subsystem.strip().lower()
    for domain, markers in DOMAIN_RULES:
        if any(marker in value for marker in markers):
            return domain
    return "other"


def scope_category(value: Any) -> str:
    """Project legacy free-form scope text onto a stable reasoning category."""
    text = re.sub(r"[\s_]+", "-", str(value or "").strip().lower())
    if not text:
        return "unspecified"
    if "read-only" in text or "readonly" in text or text.startswith(("audit", "inventory", "verification")):
        return "read-only"
    if any(marker in text for marker in ("production-impact", "prod-change", "production-write")):
        return "production-impact"
    if text in {"production", "production-web", "prod", "production-change"}:
        return "production-impact"
    if any(
        marker in text
        for marker in (
            "config-change",
            "safe-local",
            "tooling",
            "documentation",
            "docs",
            "codex-maintenance",
            "action-log",
            "hygiene",
            "historical",
            "project-staging",
            "local-",
        )
    ):
        return "local-change"
    return "legacy-freeform"


def risk_category(value: Any) -> str:
    """Normalize historical risk labels without pretending free text is exact."""
    text = re.sub(r"[\s_]+", "-", str(value or "").strip().lower())
    if not text:
        return "unspecified"
    if text in {"critical", "p0"}:
        return "critical"
    if text in {"high", "p1"} or "production-write" in text:
        return "high"
    if text in {"medium", "yellow", "p2", "low-medium"}:
        return "medium"
    if text in {"low", "green", "none", "safe-local", "read-only", "low-readonly", "p3", "p4"}:
        return "low"
    return "legacy-freeform"


def event_result(event: dict[str, Any]) -> str:
    return str(event_details(event).get("result") or "")


def event_details(event: dict[str, Any]) -> dict[str, Any]:
    details = event.get("details")
    return details if isinstance(details, dict) else {}


def event_task_id(event: dict[str, Any]) -> str:
    return str(event_details(event).get("task_id") or "").strip()


def event_agent_identity(event: dict[str, Any], details: dict[str, Any] | None = None) -> dict[str, Any] | None:
    payload = details if details is not None else event_details(event)
    agent = payload.get("agent") if isinstance(payload.get("agent"), dict) else {}
    agent_id = str(agent.get("agent_id") or payload.get("agent_id") or "").strip()
    if not agent_id:
        return None
    classes = payload.get("capability_class")
    return {
        "agent_id": agent_id[:200],
        "kind": str(agent.get("kind") or "")[:32],
        "vendor": str(agent.get("vendor") or "")[:64],
        "product": str(agent.get("product") or "")[:64],
        "runtime": str(agent.get("runtime") or "")[:64],
        "instance_id": str(agent.get("instance_id") or event.get("session_id") or "")[:200],
        "admission_id": str(payload.get("admission_id") or "")[:200],
        "declared_at": str(payload.get("declared_at") or event.get("ts_utc") or "")[:40],
        "expires_at": str(payload.get("expires_at") or "")[:40],
        "capability_class": [str(item)[:64] for item in classes if str(item or "").strip()]
        if isinstance(classes, list)
        else [],
    }


def bind_task_agent(task: dict[str, Any], event: dict[str, Any], details: dict[str, Any]) -> None:
    identity = event_agent_identity(event, details)
    if identity is None:
        return
    task["agent_id"] = identity["agent_id"]
    task["agent_kind"] = identity["kind"]
    task["agent_vendor"] = identity["vendor"]
    task["agent_product"] = identity["product"]
    task["agent_runtime"] = identity["runtime"]
    task["admission_id"] = identity["admission_id"]
    task["admission_declared_at"] = identity.get("declared_at") or ""
    task["admission_expires_at"] = identity.get("expires_at") or ""
    task["capability_class"] = list(identity.get("capability_class") or [])
    if not task.get("first_agent_id"):
        task["first_agent_id"] = identity["agent_id"]
    admitted = list(task.get("admitted_agents") or [])
    if identity["agent_id"] not in {str(item.get("agent_id") or "") for item in admitted}:
        admitted.append(identity)
    task["admitted_agents"] = admitted


def session_speaker_projection(events: list[dict[str, Any]], session_id: str) -> dict[str, Any]:
    speakers: list[dict[str, Any]] = []
    seen: set[str] = set()
    latest: dict[str, Any] | None = None
    empty = {
        "agent_id": "",
        "agent_vendor": "",
        "agent_product": "",
        "admission_id": "",
        "admission_declared_at": "",
        "admission_expires_at": "",
        "capability_class": [],
        "admitted_agents": [],
    }
    if not session_id:
        return empty
    for event in events:
        if str(event.get("session_id") or "") != session_id:
            continue
        if str(event.get("action") or "") not in SESSION_ADMISSION_ACTIONS:
            continue
        identity = event_agent_identity(event)
        if identity is None:
            continue
        latest = identity
        if identity["agent_id"] not in seen:
            seen.add(identity["agent_id"])
            speakers.append(identity)
    return {
        "agent_id": (latest or {}).get("agent_id") or "",
        "agent_vendor": (latest or {}).get("vendor") or "",
        "agent_product": (latest or {}).get("product") or "",
        "admission_id": (latest or {}).get("admission_id") or "",
        "admission_declared_at": (latest or {}).get("declared_at") or "",
        "admission_expires_at": (latest or {}).get("expires_at") or "",
        "capability_class": list((latest or {}).get("capability_class") or []),
        "admitted_agents": speakers,
    }


def _parse_rfc3339(value: str) -> dt.datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def admission_is_live(*, now: str, declared_at: str = "", expires_at: str = "") -> bool:
    current = _parse_rfc3339(now)
    if current is None:
        return False
    until = _parse_rfc3339(expires_at)
    if until is None:
        start = _parse_rfc3339(declared_at)
        if start is None:
            return False
        until = start + dt.timedelta(hours=ADMISSION_TTL_HOURS)
    return current < until


def classify_capsule_link(relation_type: str) -> str:
    token = str(relation_type or "").strip()
    if token in {"depends_on", "child_of", "blocks", "supersedes", "verifies", "contradicts", "caused_by"}:
        return "direct"
    if token in {"related_to", "preempts"}:
        return "supported"
    return "contextual"


def render_synaptic_capsule(capsule: dict[str, Any]) -> str:
    here = capsule.get("here") if isinstance(capsule.get("here"), dict) else {}
    lines = [
        "INTEGRITY CAPSULE v1",
        (
            f"door={capsule.get('door')} here={here.get('task_id') or '-'} "
            f"status={here.get('status') or '-'} speaker={here.get('agent_product') or 'undeclared'} "
            f"links={capsule.get('links_status')} budget={capsule.get('budget')} "
            f"projection={capsule.get('projection')}"
        ),
    ]
    door = str(capsule.get("door") or "")
    if door == "session-missing":
        lines.append("No durable session. No links. No moves.")
        return "\n".join(lines)
    if door == "undeclared":
        lines.append("No live admission. Do not treat memory as a speaker.")
    elif door == "session-expired":
        lines.append("Admission expired. Memory is not a door.")
    if door in {"session-missing", "undeclared", "session-expired"}:
        for move in capsule.get("moves") or []:
            if not lines[-1].startswith("MOVES"):
                lines.append("MOVES:")
            lines.append(f"- {move.get('kind')} [{move.get('provenance')}] {move.get('reason')}")
        return "\n".join(lines)
    if capsule.get("links"):
        lines.append("LINKS:")
        for link in capsule.get("links") or []:
            lines.append(f"- {link.get('class')} {link.get('type')} {link.get('target')}")
    elif capsule.get("links_status") == "isolated":
        lines.append("LINKS: ISOLATED")
    if capsule.get("budget") == "truncated":
        lines.append(f"TRUNCATED omitted_links={capsule.get('omitted_link_count')}")
    if capsule.get("moves"):
        lines.append("MOVES:")
        for move in capsule.get("moves") or []:
            lines.append(f"- {move.get('kind')} [{move.get('provenance')}] {move.get('reason')}")
    if capsule.get("learned_hints"):
        lines.append("HINTS (learned, not authority):")
        for hint in capsule.get("learned_hints") or []:
            lines.append(f"- {hint}")
    return "\n".join(lines)


def build_synaptic_capsule(
    *,
    session_id: str,
    reflex: dict[str, Any],
    relations: list[dict[str, Any]],
    projection: str = "current",
) -> dict[str, Any]:
    thread = reflex.get("thread") if isinstance(reflex.get("thread"), dict) else {}
    owned = list(thread.get("owned_open_tasks") or []) + list(thread.get("owned_paused_tasks") or [])
    now = str(reflex.get("generated_utc") or "")
    speaker_id = str(thread.get("agent_id") or "")
    speaker_product = str(thread.get("agent_product") or "")
    declared_at = str(thread.get("admission_declared_at") or "")
    expires_at = str(thread.get("admission_expires_at") or "")
    classes = [str(item) for item in (thread.get("capability_class") or [])]
    primary = owned[0] if owned else {}
    here_id = str(primary.get("task_id") or "")
    session = str(session_id or "").strip()
    if not session:
        door = "session-missing"
    elif not speaker_id and not speaker_product or not declared_at and not expires_at:
        door = "undeclared"
    elif not admission_is_live(now=now, declared_at=declared_at, expires_at=expires_at):
        door = "session-expired"
    else:
        door = "admitted"
    closed = door in {"session-missing", "undeclared", "session-expired"}
    links: list[dict[str, Any]] = []
    omitted = 0
    if here_id and not closed:
        class_order = {"direct": 0, "supported": 1, "contextual": 2}
        neighborhood = []
        for relation in relations:
            source = str(relation.get("source") or "")
            target = str(relation.get("target") or "")
            rel_type = str(relation.get("type") or "")
            if here_id not in {source, target} or not rel_type:
                continue
            other = target if source == here_id else source
            if not other or other == here_id:
                continue
            neighborhood.append(
                {
                    "class": classify_capsule_link(rel_type),
                    "type": rel_type[:64],
                    "target": other[:200],
                    "provenance": "declared",
                }
            )
        neighborhood.sort(key=lambda item: (class_order[item["class"]], item["type"], item["target"]))
        unique: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for item in neighborhood:
            key = (item["class"], item["type"], item["target"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        omitted = max(0, len(unique) - 8)
        links = unique[:8]
    links_status = "linked" if links else "isolated"
    budget = "truncated" if omitted else "complete"
    moves: list[dict[str, str]] = []
    if door == "undeclared":
        moves = [
            {
                "kind": "refuse-undeclared",
                "provenance": "declared",
                "reason": "No live admission. Do not treat memory as a speaker.",
            }
        ]
    elif door == "session-expired":
        moves = [
            {
                "kind": "renew-admission",
                "provenance": "declared",
                "reason": "Admission TTL elapsed. Memory is not a door.",
            }
        ]
    elif door == "admitted":
        status = str(primary.get("status") or "")
        can_append = (not classes) or ("append-memory" in classes)
        depends = [link["target"] for link in links if link["class"] == "direct" and link["type"] == "depends_on"]
        if not can_append:
            moves.append(
                {
                    "kind": "wait-or-resume-after",
                    "provenance": "declared",
                    "reason": "Read-only admission. Do not resume writes.",
                }
            )
        elif status == "paused":
            moves.append(
                {
                    "kind": "wait-or-resume-after",
                    "provenance": "declared",
                    "reason": f"Owned task {here_id} is paused.",
                }
            )
        elif here_id and status in {"open", "pending"}:
            moves.append(
                {
                    "kind": "resume",
                    "provenance": "declared",
                    "reason": f"Owned task {here_id} is {status}.",
                }
            )
        if depends:
            moves.append(
                {
                    "kind": "follow-dependency",
                    "provenance": "declared",
                    "reason": f"Direct depends_on {depends[0]}.",
                }
            )
        elif here_id and status == "open" and can_append and len(moves) < 3:
            moves.append(
                {
                    "kind": "close-or-reconcile",
                    "provenance": "declared",
                    "reason": "No blocking direct dependency in the neighborhood.",
                }
            )
    hints: list[str] = []
    next_action = str(primary.get("next_action") or "").strip()
    if next_action and door == "admitted":
        hints.append(next_action[:280])
    return {
        "protocol": MIND_CAPSULE_PROTOCOL,
        "door": door,
        "links_status": links_status,
        "budget": budget,
        "projection": "stale" if projection == "stale" else "current",
        "here": {
            "task_id": here_id[:160],
            "status": str(primary.get("status") or "")[:32],
            "agent_id": speaker_id[:200],
            "agent_product": speaker_product[:64],
        },
        "links": links,
        "moves": moves[:3],
        "learned_hints": hints[:3],
        "omitted_link_count": omitted,
        "production_authority": False,
    }


def event_subsystems(event: dict[str, Any]) -> list[str]:
    subsystems = string_list(event_details(event).get("subsystem"))
    if subsystems:
        return subsystems
    return [tag for tag in string_list(event.get("tags")) if tag.lower() not in GENERIC_TASK_TAGS]


def task_event_cursor(event: dict[str, Any]) -> dict[str, Any]:
    details = event_details(event)
    return {
        "event_id": event.get("id"),
        "ts_utc": event.get("ts_utc") or "",
        "observed_utc": event.get("created_utc") or "",
        "action": event.get("action") or "",
        "kind": classify_event_kind(event),
        "result": event_result(event),
        "summary": str(event.get("summary") or "")[:500],
        "next_action": str(details.get("next_action") or "")[:500],
        "verification": useful_verification(details)[:500],
        "scope": str(details.get("scope") or "")[:96],
        "evidence_files": string_list(details.get("evidence_files"))[:8],
    }


def task_key_for_event(event: dict[str, Any]) -> str:
    task_id = event_task_id(event)
    if task_id:
        return f"task:{task_id}"
    session_id = str(event.get("session_id") or "unknown-session")
    subsystems = event_subsystems(event)
    first_subsystem = subsystems[0] if subsystems else "untagged"
    return f"legacy:{session_id}|subsystem:{first_subsystem}"


def task_coordination_active(task: dict[str, Any]) -> bool:
    """Return whether this semantic task has a current executor lease."""

    if "coordination_active" in task:
        return bool(task.get("coordination_active"))
    return bool(
        task.get("status") in {"open", "pending", "paused"}
        and not task.get("stale")
    )


def age_fields(
    ts_utc: str,
    stale_after_hours: float,
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    parsed = parse_event_time(ts_utc)
    if not parsed:
        return {"age": "", "age_hours": None, "stale": False}
    reference = now or dt.datetime.now(dt.UTC)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=dt.UTC)
    else:
        reference = reference.astimezone(dt.UTC)
    delta = reference - parsed
    hours = round(delta.total_seconds() / 3600, 3)
    if hours >= 24:
        age = f"{hours / 24:.1f}d"
    elif hours >= 1:
        age = f"{hours:.1f}h"
    else:
        age = f"{max(0, hours * 60):.0f}m"
    return {"age": age, "age_hours": hours, "stale": hours >= stale_after_hours}


def add_minutes(ts_utc: str, minutes: float) -> str:
    parsed = parse_event_time(ts_utc)
    if not parsed:
        parsed = dt.datetime.now(dt.UTC)
    return (parsed + dt.timedelta(minutes=minutes)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def is_expired(
    expires_utc: str,
    *,
    now: dt.datetime | None = None,
) -> bool:
    parsed = parse_event_time(expires_utc)
    if not parsed:
        return True
    reference = now or dt.datetime.now(dt.UTC)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=dt.UTC)
    else:
        reference = reference.astimezone(dt.UTC)
    return reference >= parsed


def bounded_lock_ttl_minutes(value: Any) -> float:
    try:
        ttl = float(value)
    except (TypeError, ValueError):
        return LOCK_TTL_DEFAULT_MINUTES
    if not math.isfinite(ttl) or ttl < LOCK_TTL_MIN_MINUTES:
        return LOCK_TTL_DEFAULT_MINUTES
    return min(ttl, LOCK_TTL_MAX_MINUTES)


def build_tasks(
    params: dict[str, list[str]],
    *,
    events: list[dict[str, Any]] | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    observed_at = now or dt.datetime.now(dt.UTC)
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=dt.UTC)
    else:
        observed_at = observed_at.astimezone(dt.UTC)
    include_legacy = parse_bool(first(params, "include_legacy"), True)
    # This threshold participates in the coordination authority boundary.
    # Callers may not weaken or recreate a stop by supplying their own clock
    # policy through a read request.
    stale_after_hours = TASK_LEASE_STALE_AFTER_HOURS
    status_filter = (first(params, "status") or "").strip().lower()
    subsystem_filter = (first(params, "subsystem") or "").strip()
    task_id_filter = (first(params, "task_id") or "").strip()
    session_id_filter = (first(params, "session_id") or "").strip()
    stale_only = parse_bool(first(params, "stale_only"), False)
    attention_only = parse_bool(first(params, "attention_only"), False)
    limit = parse_limit(first(params, "limit"), MAX_LIMIT)

    event_rows = events if events is not None else query_all_events()
    latest_related: dict[str, dict[str, Any]] = {}
    latest_operational: dict[str, dict[str, Any]] = {}
    related_counts: dict[str, int] = {}
    operational_counts: dict[str, int] = {}
    for event in event_rows:
        task_id = event_task_id(event)
        if not task_id:
            continue
        latest_related[task_id] = task_event_cursor(event)
        related_counts[task_id] = related_counts.get(task_id, 0) + 1
        if str(event.get("action") or "") in TASK_OPERATIONAL_ACTIONS:
            latest_operational[task_id] = task_event_cursor(event)
            operational_counts[task_id] = operational_counts.get(task_id, 0) + 1

    tasks: dict[str, dict[str, Any]] = {}
    for event in event_rows:
        action = str(event.get("action") or "")
        if action not in TASK_LIFECYCLE_ACTIONS:
            continue
        task_id = event_task_id(event)
        if not task_id and not include_legacy:
            continue
        key = task_key_for_event(event)
        details = event_details(event)
        explicit_subsystems = string_list(details.get("subsystem"))
        subsystems = explicit_subsystems or event_subsystems(event)
        existing = tasks.get(key)
        if existing is None and action in RELATION_CORRECTION_ACTIONS:
            continue
        if existing is None:
            existing = {
                "task_key": key,
                "task_id": task_id,
                "legacy": not bool(task_id),
                "status": "open",
                "first_id": event.get("id"),
                "first_ts_utc": event.get("ts_utc"),
                "first_observed_utc": event.get("created_utc") or "",
                "last_id": event.get("id"),
                "last_ts_utc": event.get("ts_utc"),
                "last_observed_utc": event.get("created_utc") or "",
                "last_action": action,
                "result": event_result(event),
                "subsystem": subsystems or ["untagged"],
                "subsystem_history": subsystems or ["untagged"],
                "subsystem_mode": (
                    "replace"
                    if str(details.get("subsystem_mode") or "").strip().lower() == "replace"
                    else "merge"
                ),
                "subsystem_source": "explicit" if explicit_subsystems else "tags",
                "actor": event.get("actor") or "",
                "session_id": event.get("session_id") or "",
                "first_session_id": event.get("session_id") or "",
                "agent_id": "",
                "first_agent_id": "",
                "agent_kind": "",
                "agent_vendor": "",
                "agent_product": "",
                "agent_runtime": "",
                "admission_id": "",
                "admission_declared_at": "",
                "admission_expires_at": "",
                "capability_class": [],
                "admitted_agents": [],
                "summary": event.get("summary") or "",
                "history_count": 0,
                "scope": str(details.get("scope") or ""),
                "risk_level": str(details.get("risk_level") or ""),
                "touched_hosts": string_list(details.get("touched_hosts")),
                "rollback": str(details.get("rollback") or ""),
                "verification": str(details.get("verification") or ""),
                "evidence_files": string_list(details.get("evidence_files")),
                "next_action": str(details.get("next_action") or ""),
                "done_when": str(details.get("done_when") or ""),
                "rollback_explicit": bool(str(details.get("rollback") or "").strip()),
                "verification_explicit": bool(useful_verification(details)),
                "next_action_explicit": bool(str(details.get("next_action") or "").strip()),
                "done_when_explicit": bool(str(details.get("done_when") or "").strip()),
                "priority": str(details.get("priority") or ""),
                "owner": str(details.get("owner") or ""),
                "attention_class": str(details.get("attention_class") or ""),
                "goal_id": str(details.get("goal_id") or ""),
                "roadmap_item_id": str(details.get("roadmap_item_id") or ""),
                "parent_task_id": str(details.get("parent_task_id") or ""),
                "depends_on_task_ids": string_list(details.get("depends_on_task_ids")),
                "related_task_ids": string_list(details.get("related_task_ids")),
                "supersedes_task_ids": string_list(details.get("supersedes_task_ids")),
                "blocks_task_ids": string_list(details.get("blocks_task_ids")),
                "preempts_task_ids": string_list(details.get("preempts_task_ids")),
                "resume_after_task_ids": string_list(details.get("resume_after_task_ids")),
                "target_thread_ids": string_list(details.get("target_thread_ids")),
                "coordination_reason": str(details.get("coordination_reason") or ""),
                "requested_pause_by_utc": str(details.get("requested_pause_by_utc") or ""),
                "pause_for_task_id": str(details.get("pause_for_task_id") or ""),
                "report_required": bool(details.get("report_required", False)),
                "has_start": action == "agent_change_start",
                "has_close": action in CLOSE_ACTIONS,
            }
            tasks[key] = existing

        projection_before_correction = (
            dict(existing) if action in RELATION_CORRECTION_ACTIONS else None
        )

        existing["history_count"] = int(existing.get("history_count") or 0) + 1
        existing["last_id"] = event.get("id")
        existing["last_ts_utc"] = event.get("ts_utc")
        existing["last_observed_utc"] = event.get("created_utc") or ""
        existing["last_action"] = action
        existing["result"] = event_result(event)
        existing["actor"] = event.get("actor") or ""
        existing["session_id"] = event.get("session_id") or ""
        existing["summary"] = event.get("summary") or ""
        if action in SESSION_ADMISSION_ACTIONS:
            bind_task_agent(existing, event, details)
        for field in (
            "scope",
            "risk_level",
            "rollback",
            "verification",
            "next_action",
            "done_when",
            "priority",
            "owner",
            "attention_class",
            "goal_id",
            "roadmap_item_id",
            "parent_task_id",
            "coordination_reason",
            "requested_pause_by_utc",
            "pause_for_task_id",
        ):
            value = str(details.get(field) or "").strip()
            if value:
                existing[field] = value
        if str(details.get("rollback") or "").strip():
            existing["rollback_explicit"] = True
        if useful_verification(details):
            existing["verification_explicit"] = True
        if str(details.get("next_action") or "").strip():
            existing["next_action_explicit"] = True
        if str(details.get("done_when") or "").strip():
            existing["done_when_explicit"] = True
        for field in (
            "touched_hosts",
            "evidence_files",
            "depends_on_task_ids",
            "related_task_ids",
            "supersedes_task_ids",
            "blocks_task_ids",
            "preempts_task_ids",
            "resume_after_task_ids",
            "target_thread_ids",
        ):
            values_to_merge = string_list(details.get(field))
            relation_mode = str(details.get(f"{field}_mode") or "merge").strip().lower()
            if relation_mode == "replace":
                existing[field] = list(values_to_merge)
                continue
            merged_values = list(existing.get(field) or [])
            for value in values_to_merge:
                if value not in merged_values:
                    merged_values.append(value)
            existing[field] = merged_values
        if action == "agent_change_start":
            existing["has_start"] = True
        if "report_required" in details:
            existing["report_required"] = bool(details.get("report_required"))
        if action in CLOSE_ACTIONS:
            existing["has_close"] = True
        subsystem_history = list(existing.get("subsystem_history") or [])
        for subsystem in subsystems:
            if subsystem not in subsystem_history:
                subsystem_history.append(subsystem)
        existing["subsystem_history"] = subsystem_history
        if explicit_subsystems:
            subsystem_mode = str(details.get("subsystem_mode") or "merge").strip().lower()
            if subsystem_mode == "replace":
                existing["subsystem"] = list(explicit_subsystems)
                existing["subsystem_source"] = "explicit-replace"
                existing["subsystem_mode"] = "replace"
            else:
                merged_subsystems = (
                    []
                    if existing.get("subsystem_source") not in {"explicit", "explicit-replace"}
                    else list(existing.get("subsystem") or [])
                )
                for subsystem in explicit_subsystems:
                    if subsystem not in merged_subsystems:
                        merged_subsystems.append(subsystem)
                existing["subsystem"] = merged_subsystems
                existing["subsystem_source"] = "explicit"
                existing["subsystem_mode"] = "merge"
        elif existing.get("subsystem_source") not in {"explicit", "explicit-replace"}:
            merged_subsystems = list(existing.get("subsystem") or [])
            if merged_subsystems == ["untagged"] and subsystems:
                merged_subsystems = []
            for subsystem in subsystems:
                if subsystem not in merged_subsystems:
                    merged_subsystems.append(subsystem)
            existing["subsystem"] = merged_subsystems
        if task_id:
            existing["task_id"] = task_id
            existing["legacy"] = False

        if projection_before_correction is not None:
            corrected_relations = {
                field: list(existing.get(field) or [])
                for field in (
                    "touched_hosts",
                    "evidence_files",
                    "depends_on_task_ids",
                    "related_task_ids",
                    "supersedes_task_ids",
                    "blocks_task_ids",
                    "preempts_task_ids",
                    "resume_after_task_ids",
                    "target_thread_ids",
                )
            }
            bookkeeping = {
                "last_id": existing.get("last_id"),
                "last_ts_utc": existing.get("last_ts_utc"),
                "last_observed_utc": existing.get("last_observed_utc"),
                "history_count": existing.get("history_count"),
            }
            existing.clear()
            existing.update(projection_before_correction)
            existing.update(corrected_relations)
            existing.update(bookkeeping)

        if action in CLOSE_ACTIONS:
            existing["status"] = STATUS_BY_CLOSE_ACTION[action]
        elif action in PENDING_ACTIONS:
            existing["status"] = "pending"
        elif action in PAUSE_ACTIONS:
            existing["status"] = "paused"
        elif action in OPEN_ACTIONS:
            existing["status"] = "open"

    task_rows = []
    for task in tasks.values():
        task_id = str(task.get("task_id") or "")
        related_cursor = latest_related.get(task_id, {}) if task_id else {}
        operational_cursor = latest_operational.get(task_id, {}) if task_id else {}
        task["last_related_event"] = related_cursor
        task["operational_cursor"] = operational_cursor
        task["related_event_count"] = related_counts.get(task_id, int(task.get("history_count") or 0))
        task["operational_event_count"] = operational_counts.get(task_id, int(task.get("history_count") or 0))
        task["activity_event_id"] = operational_cursor.get("event_id") or task.get("last_id")
        task["activity_ts_utc"] = operational_cursor.get("ts_utc") or task.get("last_ts_utc") or ""
        task["activity_observed_utc"] = (
            str(operational_cursor.get("observed_utc") or "")
            if operational_cursor
            else str(task.get("last_observed_utc") or "")
        )
        activity_observed = parse_event_time(task["activity_observed_utc"])
        task["activity_observed_trusted"] = bool(
            activity_observed is not None and activity_observed <= observed_at
        )
        activity_age = age_fields(
            str(task["activity_observed_utc"]),
            stale_after_hours,
            now=observed_at,
        )
        task.update(activity_age)
        task["stale"] = bool(
            task.get("status") in {"open", "pending", "paused"}
            and (
                not task.get("activity_observed_trusted")
                or activity_age.get("stale")
            )
        )
        task["semantic_status"] = task.get("status") or ""
        task["observation_quarantined"] = not task["activity_observed_trusted"]
        if task["observation_quarantined"]:
            task["lease_state"] = "expired"
            task["queue_state"] = "recovery"
        elif task.get("status") == "complete":
            task["lease_state"] = "detached"
            task["queue_state"] = "archive"
        elif task.get("status") in {"blocked", "failed"} or (
            task.get("status") in {"open", "pending", "paused"}
            and not task.get("has_start")
        ):
            task["lease_state"] = "detached"
            task["queue_state"] = "recovery"
        elif task.get("status") in {"open", "pending", "paused"}:
            task["lease_state"] = "expired" if task.get("stale") else "live"
            task["queue_state"] = "recovery" if task.get("stale") else "current"
        else:
            task["lease_state"] = "detached"
            task["queue_state"] = "archive"
        task["coordination_active"] = bool(
            task.get("lease_state") == "live"
            and task.get("queue_state") == "current"
        )
        task["attention"] = bool(
            task.get("queue_state") == "recovery"
            or task.get("status") in {"open", "pending", "paused", "blocked", "failed"}
        )
        if task["observation_quarantined"]:
            task["attention_reason"] = "untrusted-operational-observation"
            if not task.get("next_action"):
                task["next_action"] = (
                    "Reconcile the latest operational event from a trusted "
                    "server observation before archive or continuation."
                )
        elif task.get("status") == "open":
            task["attention_reason"] = "stale-open" if task.get("stale") else "open"
            if not task.get("next_action"):
                task["next_action"] = "Reconcile current live state and continue or close this task."
        elif task.get("status") == "pending":
            task["attention_reason"] = "pending-preemption" if task.get("preempts_task_ids") else "pending"
            if not task.get("next_action"):
                task["next_action"] = "Wait for the named task owner to checkpoint, release its lock, and hand over execution."
        elif task.get("status") == "paused":
            task["attention_reason"] = "paused-for-priority-work"
            if not task.get("next_action"):
                task["next_action"] = "Resume only after the dependency report is complete and live state is reconciled."
        elif task.get("status") == "blocked":
            task["attention_reason"] = "blocked"
            if not task.get("next_action"):
                task["next_action"] = "Resolve the blocker or explicitly supersede the task after live verification."
        elif task.get("status") == "failed":
            task["attention_reason"] = "failed"
            if not task.get("next_action"):
                task["next_action"] = "Inspect failure evidence and verify rollback/current live state."
        else:
            task["attention_reason"] = ""
        task["subsystem_text"] = ",".join(task.get("subsystem") or [])
        if status_filter and str(task.get("status") or "").lower() != status_filter:
            continue
        if task_id_filter and str(task.get("task_id") or "") != task_id_filter:
            continue
        if session_id_filter and session_id_filter not in {
            str(task.get("session_id") or ""),
            str(task.get("first_session_id") or ""),
        }:
            continue
        if subsystem_filter and subsystem_filter not in (task.get("subsystem") or []):
            continue
        if stale_only and not task.get("stale"):
            continue
        if attention_only and not task.get("attention"):
            continue
        task_rows.append(task)

    task_rows.sort(key=lambda item: int(item.get("activity_event_id") or 0), reverse=True)
    task_rows = task_rows[:limit]

    open_tasks = [task for task in task_rows if task.get("status") == "open"]
    pending_tasks = [task for task in task_rows if task.get("status") == "pending"]
    paused_tasks = [task for task in task_rows if task.get("status") == "paused"]
    blocked_tasks = [task for task in task_rows if task.get("status") == "blocked"]
    failed_tasks = [task for task in task_rows if task.get("status") == "failed"]
    stale_tasks = [task for task in task_rows if task.get("stale")]
    complete_tasks = [task for task in task_rows if task.get("status") == "complete"]
    current_tasks = [task for task in task_rows if task.get("queue_state") == "current"]
    recovery_tasks = [task for task in task_rows if task.get("queue_state") == "recovery"]
    archived_tasks = [task for task in task_rows if task.get("queue_state") == "archive"]
    live_tasks = [task for task in task_rows if task.get("lease_state") == "live"]
    expired_tasks = [task for task in task_rows if task.get("lease_state") == "expired"]
    detached_tasks = [task for task in task_rows if task.get("lease_state") == "detached"]
    orphan_tasks = [task for task in task_rows if task.get("task_id") and not task.get("has_start")]

    conflict_map: dict[str, list[dict[str, Any]]] = {}
    for task in open_tasks:
        if not task_coordination_active(task):
            continue
        for subsystem in task.get("subsystem") or []:
            conflict_map.setdefault(str(subsystem), []).append(task)
    conflicts = []
    for subsystem, items in sorted(conflict_map.items()):
        if len(items) <= 1:
            continue
        conflicting_items: list[dict[str, Any]] = []
        for item in items:
            item_id = str(item.get("task_id") or "")
            item_parent = str(item.get("parent_task_id") or "")
            has_independent_peer = any(
                other is not item
                and item_id != str(other.get("parent_task_id") or "")
                and str(other.get("task_id") or "") != item_parent
                for other in items
            )
            if has_independent_peer:
                conflicting_items.append(item)
        if len(conflicting_items) <= 1:
            continue
        conflicts.append(
            {
                "subsystem": subsystem,
                "count": len(conflicting_items),
                "task_ids": [
                    str(item.get("task_id") or item.get("task_key"))
                    for item in conflicting_items
                ],
            }
        )

    return {
        "ok": True,
        "stale_after_hours": stale_after_hours,
        "lease_observed_utc": observed_at.replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        ),
        "filters": {
            "status": status_filter,
            "subsystem": subsystem_filter,
            "task_id": task_id_filter,
            "session_id": session_id_filter,
            "stale_only": stale_only,
            "attention_only": attention_only,
            "include_legacy": include_legacy,
            "limit": limit,
        },
        "task_count": len(task_rows),
        "open_count": len(open_tasks),
        "pending_count": len(pending_tasks),
        "paused_count": len(paused_tasks),
        "blocked_count": len(blocked_tasks),
        "failed_count": len(failed_tasks),
        "complete_count": len(complete_tasks),
        "stale_count": len(stale_tasks),
        "current_count": len(current_tasks),
        "recovery_count": len(recovery_tasks),
        "archive_count": len(archived_tasks),
        "live_count": len(live_tasks),
        "expired_count": len(expired_tasks),
        "detached_count": len(detached_tasks),
        "orphan_count": len(orphan_tasks),
        "conflict_count": len(conflicts),
        "tasks": task_rows,
        "conflicts": conflicts,
    }


def build_locks(
    params: dict[str, list[str]],
    *,
    events: list[dict[str, Any]] | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    observed_at = now or dt.datetime.now(dt.UTC)
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=dt.UTC)
    else:
        observed_at = observed_at.astimezone(dt.UTC)
    include_released = parse_bool(first(params, "include_released"), False)
    status_filter = (first(params, "status") or "").strip().lower()
    subsystem_filter = (first(params, "subsystem") or "").strip()
    lock_id_filter = (first(params, "lock_id") or "").strip()
    limit = parse_limit(first(params, "limit"), MAX_LIMIT)

    locks: dict[str, dict[str, Any]] = {}
    for event in (events if events is not None else query_all_events()):
        action = str(event.get("action") or "")
        if action not in LOCK_ACQUIRE_ACTIONS and action not in LOCK_RELEASE_ACTIONS:
            continue
        details = event.get("details")
        if not isinstance(details, dict):
            details = {}
        lock_id = str(details.get("lock_id") or "").strip()
        if not lock_id:
            continue
        subsystems = string_list(details.get("subsystem")) or event_subsystems(event)
        target_hosts = string_list(details.get("target_hosts") or details.get("touched_hosts"))
        existing = locks.get(lock_id)

        if action in LOCK_ACQUIRE_ACTIONS:
            acquire_observed = parse_event_time(str(event.get("created_utc") or ""))
            if (
                existing is not None
                and (acquire_observed is None or acquire_observed > observed_at)
            ):
                existing["history_count"] = int(
                    existing.get("history_count") or 0
                ) + 1
                existing["quarantined_acquire_count"] = int(
                    existing.get("quarantined_acquire_count") or 0
                ) + 1
                continue
            ttl_minutes = bounded_lock_ttl_minutes(details.get("ttl_minutes"))
            observed_utc = str(event.get("created_utc") or "")
            observed_time = acquire_observed
            expires_utc = (
                add_minutes(observed_utc, ttl_minutes)
                if observed_time is not None and observed_time <= observed_at
                else "1970-01-01T00:00:00Z"
            )
            if existing is None:
                existing = {
                    "lock_id": lock_id,
                    "status": "active",
                    "subsystem": subsystems,
                    "target_hosts": target_hosts,
                    "owner_actor": event.get("actor") or "",
                    "owner_session_id": event.get("session_id") or "",
                    "reason": str(details.get("reason") or event.get("summary") or ""),
                    "task_id": str(details.get("task_id") or ""),
                    "acquired_id": event.get("id"),
                    "acquired_ts_utc": event.get("ts_utc"),
                    "acquired_observed_utc": observed_utc,
                    "last_id": event.get("id"),
                    "last_ts_utc": event.get("ts_utc"),
                    "last_observed_utc": observed_utc,
                    "ttl_minutes": ttl_minutes,
                    "expires_utc": expires_utc,
                    "summary": event.get("summary") or "",
                    "history_count": 0,
                }
                locks[lock_id] = existing
            existing["status"] = "active"
            existing["owner_actor"] = event.get("actor") or existing.get("owner_actor") or ""
            existing["owner_session_id"] = event.get("session_id") or existing.get("owner_session_id") or ""
            existing["reason"] = str(details.get("reason") or existing.get("reason") or event.get("summary") or "")
            existing["task_id"] = str(details.get("task_id") or existing.get("task_id") or "")
            existing["last_id"] = event.get("id")
            existing["last_ts_utc"] = event.get("ts_utc")
            existing["last_observed_utc"] = observed_utc
            existing["ttl_minutes"] = ttl_minutes
            existing["expires_utc"] = expires_utc
            existing["summary"] = event.get("summary") or ""
            merged_subsystems = list(existing.get("subsystem") or [])
            for subsystem in subsystems:
                if subsystem not in merged_subsystems:
                    merged_subsystems.append(subsystem)
            existing["subsystem"] = merged_subsystems
            merged_hosts = list(existing.get("target_hosts") or [])
            for host in target_hosts:
                if host not in merged_hosts:
                    merged_hosts.append(host)
            existing["target_hosts"] = merged_hosts

        if action in LOCK_RELEASE_ACTIONS:
            release_observed = parse_event_time(str(event.get("created_utc") or ""))
            if release_observed is None or release_observed > observed_at:
                if existing is not None:
                    existing["history_count"] = int(
                        existing.get("history_count") or 0
                    ) + 1
                    existing["quarantined_release_count"] = int(
                        existing.get("quarantined_release_count") or 0
                    ) + 1
                continue
            if existing is None:
                existing = {
                    "lock_id": lock_id,
                    "status": "released",
                    "subsystem": subsystems,
                    "target_hosts": target_hosts,
                    "owner_actor": event.get("actor") or "",
                    "owner_session_id": event.get("session_id") or "",
                    "reason": str(details.get("reason") or event.get("summary") or ""),
                    "task_id": str(details.get("task_id") or ""),
                    "acquired_id": None,
                    "acquired_ts_utc": "",
                    "acquired_observed_utc": "",
                    "last_observed_utc": str(event.get("created_utc") or ""),
                    "ttl_minutes": None,
                    "expires_utc": "",
                    "history_count": 0,
                }
                locks[lock_id] = existing
            existing["status"] = "released"
            existing["released_id"] = event.get("id")
            existing["released_ts_utc"] = event.get("ts_utc")
            existing["last_id"] = event.get("id")
            existing["last_ts_utc"] = event.get("ts_utc")
            existing["last_observed_utc"] = str(event.get("created_utc") or "")
            existing["summary"] = event.get("summary") or ""

        if existing is not None:
            existing["history_count"] = int(existing.get("history_count") or 0) + 1

    rows = []
    for lock in locks.values():
        if lock.get("status") == "active" and is_expired(
            str(lock.get("expires_utc") or ""), now=observed_at
        ):
            lock["status"] = "expired"
        lock.update(
            age_fields(
                str(lock.get("last_observed_utc") or ""),
                24.0,
                now=observed_at,
            )
        )
        lock["subsystem_text"] = ",".join(lock.get("subsystem") or [])
        lock["target_hosts_text"] = ",".join(lock.get("target_hosts") or [])
        if not include_released and lock.get("status") == "released":
            continue
        if status_filter and str(lock.get("status") or "").lower() != status_filter:
            continue
        if lock_id_filter and str(lock.get("lock_id") or "") != lock_id_filter:
            continue
        if subsystem_filter and subsystem_filter not in (lock.get("subsystem") or []):
            continue
        rows.append(lock)

    rows.sort(key=lambda item: int(item.get("last_id") or 0), reverse=True)
    rows = rows[:limit]
    active_locks = [lock for lock in rows if lock.get("status") == "active"]
    expired_locks = [lock for lock in rows if lock.get("status") == "expired"]
    released_locks = [lock for lock in rows if lock.get("status") == "released"]

    conflict_map: dict[str, list[dict[str, Any]]] = {}
    for lock in active_locks:
        for subsystem in lock.get("subsystem") or []:
            conflict_map.setdefault(str(subsystem), []).append(lock)
    conflicts = []
    for subsystem, items in sorted(conflict_map.items()):
        if len(items) <= 1:
            continue
        conflicts.append(
            {
                "subsystem": subsystem,
                "count": len(items),
                "lock_ids": [str(item.get("lock_id")) for item in items],
            }
        )

    return {
        "ok": True,
        "filters": {
            "status": status_filter,
            "subsystem": subsystem_filter,
            "lock_id": lock_id_filter,
            "include_released": include_released,
            "limit": limit,
        },
        "lock_count": len(rows),
        "active_count": len(active_locks),
        "expired_count": len(expired_locks),
        "released_count": len(released_locks),
        "conflict_count": len(conflicts),
        "locks": rows,
        "conflicts": conflicts,
    }


def projection_snapshot() -> dict[str, Any]:
    """Return one rebuildable projection snapshot shared by Mind/bootstrap callers."""
    global _PROJECTION_CACHE_SIGNATURE, _PROJECTION_CACHE
    events, (count, maximum) = query_all_events_snapshot()
    observed_at = dt.datetime.now(dt.UTC)
    minute_bucket = int(observed_at.timestamp() // 60)
    signature = (count, maximum, minute_bucket)
    with _PROJECTION_CACHE_LOCK:
        if signature == _PROJECTION_CACHE_SIGNATURE:
            return _PROJECTION_CACHE
        tasks = build_tasks(
            {
                "include_legacy": ["false"],
                "limit": [str(MAX_LIMIT)],
                "stale_after_hours": [str(TASK_LEASE_STALE_AFTER_HOURS)],
            },
            events=events,
            now=observed_at,
        )
        locks = build_locks(
            {"include_released": ["false"], "limit": [str(MAX_LIMIT)]},
            events=events,
            now=observed_at,
        )
        _PROJECTION_CACHE = {
            "event_count": count,
            "event_cursor": maximum,
            "generated_utc": observed_at.replace(microsecond=0).isoformat().replace(
                "+00:00", "Z"
            ),
            "events": events,
            "tasks": tasks,
            "locks": locks,
        }
        _PROJECTION_CACHE_SIGNATURE = signature
        return _PROJECTION_CACHE


def compact_task_row(task: dict[str, Any]) -> dict[str, Any]:
    cursor = task.get("operational_cursor") if isinstance(task.get("operational_cursor"), dict) else {}
    return {
        "task_id": task.get("task_id") or "",
        "status": task.get("status") or "",
        "semantic_status": task.get("semantic_status") or task.get("status") or "",
        "lease_state": task.get("lease_state") or "",
        "queue_state": task.get("queue_state") or "",
        "priority": task.get("priority") or "",
        "owner": task.get("owner") or "",
        "attention_class": task.get("attention_class") or "",
        "subsystem": list(task.get("subsystem") or []),
        "session_id": task.get("session_id") or "",
        "activity_event_id": int(task.get("activity_event_id") or 0),
        "activity_ts_utc": task.get("activity_ts_utc") or "",
        "activity_observed_utc": task.get("activity_observed_utc") or "",
        "stale": bool(task.get("stale")),
        "summary": str(cursor.get("summary") or task.get("summary") or "")[:500],
        "next_action": str(cursor.get("next_action") or task.get("next_action") or "")[:500],
        "verification": str(cursor.get("verification") or task.get("verification") or "")[:300],
        "parent_task_id": task.get("parent_task_id") or "",
        "depends_on_task_ids": list(task.get("depends_on_task_ids") or []),
        "preempts_task_ids": list(task.get("preempts_task_ids") or []),
        "resume_after_task_ids": list(task.get("resume_after_task_ids") or []),
        "target_thread_ids": list(task.get("target_thread_ids") or []),
        "coordination_reason": task.get("coordination_reason") or "",
        "requested_pause_by_utc": task.get("requested_pause_by_utc") or "",
        "pause_for_task_id": task.get("pause_for_task_id") or "",
        "report_required": bool(task.get("report_required")),
    }


def recovery_witness_row(task: dict[str, Any]) -> dict[str, Any]:
    """Return a constant-size recovery witness for release acceptance."""
    task_id = str(task.get("task_id") or "")
    return {
        "task_id": task_id[:RECOVERY_WITNESS_TASK_ID_CHARS],
        "task_id_sha256": hashlib.sha256(task_id.encode("utf-8")).hexdigest(),
        "task_id_truncated": len(task_id) > RECOVERY_WITNESS_TASK_ID_CHARS,
        "semantic_status": str(
            task.get("semantic_status") or task.get("status") or ""
        )[:32],
        "lease_state": str(task.get("lease_state") or "")[:32],
        "queue_state": str(task.get("queue_state") or "")[:32],
    }


def compact_lock_row(lock: dict[str, Any]) -> dict[str, Any]:
    return {
        "lock_id": lock.get("lock_id") or "",
        "status": lock.get("status") or "",
        "task_id": lock.get("task_id") or "",
        "subsystem": list(lock.get("subsystem") or []),
        "target_hosts": list(lock.get("target_hosts") or []),
        "owner_session_id": lock.get("owner_session_id") or "",
        "last_id": int(lock.get("last_id") or 0),
        "last_ts_utc": lock.get("last_ts_utc") or "",
        "expires_utc": lock.get("expires_utc") or "",
        "reason": str(lock.get("reason") or "")[:500],
    }


def build_tasks_page(params: dict[str, list[str]]) -> dict[str, Any]:
    page_size = min(200, parse_limit(first(params, "page_size") or first(params, "limit"), 20))
    snapshot_event_id = parse_int_param(first(params, "snapshot_event_id"), 0, 0)
    if snapshot_event_id <= 0:
        snapshot_event_id = event_store_signature()[1]
    current = projection_snapshot()
    projection_epoch = int(
        (parse_event_time(current["generated_utc"]) or dt.datetime.now(dt.UTC)).timestamp()
        // 60
    )
    cursor_value = first(params, "cursor") or ""
    cursor = decode_cursor(cursor_value, 3)
    if cursor_value and cursor is None:
        return {
            "ok": False,
            "error": "task pagination cursor is invalid or from an older lease contract; restart",
            "pagination": {
                "snapshot_event_id": snapshot_event_id,
                "lease_projection_epoch": projection_epoch,
                "restart_required": True,
            },
        }
    if cursor and parse_int_param(str(cursor[2]), -1, -1) != projection_epoch:
        return {
            "ok": False,
            "error": "task pagination lease epoch expired; restart",
            "pagination": {
                "snapshot_event_id": snapshot_event_id,
                "lease_projection_epoch": projection_epoch,
                "restart_required": True,
            },
        }
    events = current["events"] if snapshot_event_id == current["event_cursor"] else [
        event for event in current["events"] if int(event.get("id") or 0) <= snapshot_event_id
    ]
    queue_state_filter = (first(params, "queue_state") or "").strip().lower()
    if queue_state_filter not in {"", "current", "recovery", "archive"}:
        return {
            "ok": False,
            "error": "task queue_state filter is invalid",
            "pagination": {
                "snapshot_event_id": snapshot_event_id,
                "lease_projection_epoch": projection_epoch,
                "restart_required": True,
            },
        }
    response_view = (first(params, "view") or "").strip().lower()
    if response_view not in {"", "recovery_witness"}:
        return {
            "ok": False,
            "error": "task response view is invalid",
            "pagination": {
                "snapshot_event_id": snapshot_event_id,
                "lease_projection_epoch": projection_epoch,
                "restart_required": True,
            },
        }
    if response_view == "recovery_witness" and (
        queue_state_filter != "recovery" or cursor_value or page_size != 1
    ):
        return {
            "ok": False,
            "error": "recovery witness requires queue_state=recovery and page_size=1 without cursor",
            "pagination": {
                "snapshot_event_id": snapshot_event_id,
                "lease_projection_epoch": projection_epoch,
                "restart_required": True,
            },
        }
    state_params = {key: list(values) for key, values in params.items()}
    state_params.pop("queue_state", None)
    state_params.pop("view", None)
    state_params["limit"] = [str(MAX_LIMIT)]
    cached_projection_compatible = (
        snapshot_event_id == current["event_cursor"]
        and not parse_bool(first(state_params, "include_legacy"), True)
        and not any(
            first(state_params, key)
            for key in ("status", "subsystem", "task_id", "session_id")
        )
        and not parse_bool(first(state_params, "stale_only"), False)
        and not parse_bool(first(state_params, "attention_only"), False)
        and first(state_params, "stale_after_hours") in (None, "")
    )
    state = current["tasks"] if cached_projection_compatible else build_tasks(
        state_params,
        events=events,
        now=parse_event_time(current["generated_utc"]),
    )
    rows = list(state.get("tasks") or [])
    if queue_state_filter:
        rows = [
            row
            for row in rows
            if str(row.get("queue_state") or "").lower() == queue_state_filter
        ]
    if cursor:
        cursor_key = (parse_int_param(str(cursor[0]), 0, 0), str(cursor[1] or ""))
        rows = [
            row for row in rows
            if (int(row.get("activity_event_id") or 0), str(row.get("task_id") or "")) < cursor_key
        ]
    page_rows = rows[:page_size]
    has_more = len(rows) > page_size
    next_cursor = None
    if has_more and page_rows:
        last = page_rows[-1]
        next_cursor = encode_cursor(
            int(last.get("activity_event_id") or 0),
            str(last.get("task_id") or ""),
            projection_epoch,
        )
    if response_view == "recovery_witness":
        return {
            "ok": state.get("ok") is True,
            "open_count": int(state.get("open_count") or 0),
            "current_count": int(state.get("current_count") or 0),
            "recovery_count": int(state.get("recovery_count") or 0),
            "conflict_count": int(state.get("conflict_count") or 0),
            "tasks": [recovery_witness_row(row) for row in page_rows],
            "pagination": {
                "snapshot_event_id": snapshot_event_id,
                "page_size": 1,
                "returned_count": len(page_rows),
                "has_more": has_more,
                "next_cursor": None,
                "filter_queue_state": "recovery",
                "view": "recovery_witness",
                "continuation_supported": False,
                "lease_projection_epoch": projection_epoch,
                "restart_required": False,
            },
        }
    result = dict(state)
    result["tasks"] = [compact_task_row(row) for row in page_rows]
    raw_conflicts = list(state.get("conflicts") or [])
    result["conflicts"] = [
        {
            "subsystem": str(conflict.get("subsystem") or "")[:200],
            "count": int(conflict.get("count") or 0),
            "task_ids": [
                str(task_id)[:200]
                for task_id in list(conflict.get("task_ids") or [])[:5]
            ],
        }
        for conflict in raw_conflicts[:20]
        if isinstance(conflict, dict)
    ]
    result["conflicts_truncated"] = len(raw_conflicts) > len(result["conflicts"])
    result["pagination"] = {
        "snapshot_event_id": snapshot_event_id,
        "page_size": page_size,
        "returned_count": len(page_rows),
        "has_more": has_more,
        "next_cursor": next_cursor,
        "filter_queue_state": queue_state_filter or None,
        "lease_projection_epoch": projection_epoch,
        "restart_required": False,
    }
    return result


def build_locks_page(params: dict[str, list[str]]) -> dict[str, Any]:
    page_size = min(200, parse_limit(first(params, "page_size") or first(params, "limit"), 20))
    snapshot_event_id = parse_int_param(first(params, "snapshot_event_id"), 0, 0)
    if snapshot_event_id <= 0:
        snapshot_event_id = event_store_signature()[1]
    current = projection_snapshot()
    projection_epoch = int(
        (parse_event_time(current["generated_utc"]) or dt.datetime.now(dt.UTC)).timestamp()
        // 60
    )
    cursor_value = first(params, "cursor") or ""
    cursor = decode_cursor(cursor_value, 3)
    if cursor_value and cursor is None:
        return {
            "ok": False,
            "error": "lock pagination cursor is invalid or from an older lease contract; restart",
            "pagination": {
                "snapshot_event_id": snapshot_event_id,
                "lease_projection_epoch": projection_epoch,
                "restart_required": True,
            },
        }
    if cursor and parse_int_param(str(cursor[2]), -1, -1) != projection_epoch:
        return {
            "ok": False,
            "error": "lock pagination lease epoch expired; restart",
            "pagination": {
                "snapshot_event_id": snapshot_event_id,
                "lease_projection_epoch": projection_epoch,
                "restart_required": True,
            },
        }
    events = current["events"] if snapshot_event_id == current["event_cursor"] else [
        event for event in current["events"] if int(event.get("id") or 0) <= snapshot_event_id
    ]
    state_params = {key: list(values) for key, values in params.items()}
    state_params["limit"] = [str(MAX_LIMIT)]
    state = build_locks(
        state_params,
        events=events,
        now=parse_event_time(current["generated_utc"]),
    )
    rows = list(state.get("locks") or [])
    if cursor:
        cursor_key = (parse_int_param(str(cursor[0]), 0, 0), str(cursor[1] or ""))
        rows = [
            row for row in rows
            if (int(row.get("last_id") or 0), str(row.get("lock_id") or "")) < cursor_key
        ]
    page_rows = rows[:page_size]
    has_more = len(rows) > page_size
    next_cursor = None
    if has_more and page_rows:
        last = page_rows[-1]
        next_cursor = encode_cursor(
            int(last.get("last_id") or 0),
            str(last.get("lock_id") or ""),
            projection_epoch,
        )
    result = dict(state)
    result["locks"] = [compact_lock_row(row) for row in page_rows]
    result["pagination"] = {
        "snapshot_event_id": snapshot_event_id,
        "page_size": page_size,
        "returned_count": len(page_rows),
        "has_more": has_more,
        "next_cursor": next_cursor,
        "lease_projection_epoch": projection_epoch,
        "restart_required": False,
    }
    return result


def event_age_hours(event: dict[str, Any]) -> float | None:
    parsed = parse_event_time(event.get("ts_utc"))
    if not parsed:
        return None
    return max(0.0, (dt.datetime.now(dt.UTC) - parsed).total_seconds() / 3600)


def useful_verification(details: dict[str, Any]) -> str:
    verification = str(details.get("verification") or "").strip()
    if verification.lower() in {"", "pending", "none", "n/a", "unknown"}:
        return ""
    return verification


def classify_event_kind(event: dict[str, Any]) -> str:
    details = event_details(event)
    explicit = str(details.get("kind") or "").strip().lower()
    if explicit:
        return explicit
    action = str(event.get("action") or "").lower()
    tags = {tag.lower() for tag in string_list(event.get("tags"))}
    scope = str(details.get("scope") or "").lower()
    if action == "agent_change_start":
        return "task-start"
    if action == "agent_change_progress":
        return "task-progress"
    if action == "agent_change_pending":
        return "task-pending"
    if action == "agent_change_paused":
        return "task-paused"
    if action == "agent_change_resumed":
        return "task-resumed"
    if action == "agent_change_complete":
        return "task-complete"
    if action == "agent_change_blocked":
        return "blocker"
    if action == "agent_change_failed":
        return "failure"
    if "decision" in action or "decision" in tags:
        return "decision"
    if useful_verification(details):
        return "verification"
    if scope in {"production-impact", "config-change"} or details.get("files"):
        return "change"
    if any(term in action for term in ("audit", "inspect", "check", "read", "observe", "context")):
        return "observation"
    return "note"


def event_truth_status(event: dict[str, Any]) -> str:
    details = event_details(event)
    explicit = str(details.get("truth_status") or "").strip().lower()
    if explicit in {"reported", "observed", "verified", "inferred", "superseded"}:
        return explicit
    if useful_verification(details):
        return "verified"
    kind = classify_event_kind(event)
    if kind in {"observation", "verification"}:
        return "observed"
    return "reported"


def event_confidence(event: dict[str, Any]) -> str:
    details = event_details(event)
    explicit = str(details.get("confidence") or "").strip().lower()
    if explicit in {"high", "medium", "low", "unknown"}:
        return explicit
    truth = event_truth_status(event)
    if truth == "verified":
        return "high"
    if truth == "observed":
        return "medium"
    return "unknown"


def event_fact_freshness(event: dict[str, Any]) -> dict[str, Any]:
    details = event_details(event)
    now = dt.datetime.now(dt.UTC)
    valid_until = parse_event_time(details.get("valid_until"))
    if valid_until is None and details.get("valid_for_hours") not in (None, ""):
        observed_at = parse_event_time(details.get("observed_at") or event.get("ts_utc"))
        if observed_at is not None:
            valid_until = observed_at + dt.timedelta(
                hours=parse_float(str(details.get("valid_for_hours")), 0.0)
            )
    if valid_until is None:
        kind = classify_event_kind(event)
        age = event_age_hours(event)
        if age is not None and kind in {"observation", "verification"}:
            default_hours = 72.0 if kind == "verification" else 24.0
            return {
                "fresh": age < default_hours,
                "stale": age >= default_hours,
                "valid_until": "",
                "basis": f"default-{int(default_hours)}h",
            }
        return {"fresh": None, "stale": False, "valid_until": "", "basis": "durable-history"}
    valid_until_utc = valid_until.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "fresh": now < valid_until,
        "stale": now >= valid_until,
        "valid_until": valid_until_utc,
        "basis": "explicit-validity",
    }


def intent_terms(query: str) -> list[str]:
    tokens = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}|[A-Za-zА-Яа-яЁё0-9][A-Za-zА-Яа-яЁё0-9_.:@/-]*", query.lower())
    result: list[str] = []
    for token in tokens:
        cleaned = token.strip("._-/:@")
        if not cleaned or cleaned in RECALL_STOP_WORDS:
            continue
        if len(cleaned) < 3 and not cleaned.isdigit():
            continue
        if cleaned not in result:
            result.append(cleaned)
        if len(result) >= 16:
            break
    return result


def expanded_intent_terms(terms: list[str]) -> list[str]:
    expanded = list(terms)
    for term in terms:
        for prefix, aliases in INTENT_ALIAS_PREFIXES.items():
            if not term.startswith(prefix):
                continue
            for alias in aliases:
                if alias not in expanded:
                    expanded.append(alias)
    return expanded[:32]


def recall_event_shape(
    event: dict[str, Any],
    score: float,
    matched: list[str],
    superseded_by_event_ids: list[int] | None = None,
) -> dict[str, Any]:
    details = event_details(event)
    age = age_fields(str(event.get("ts_utc") or ""), 24.0)
    freshness = event_fact_freshness(event)
    verification = useful_verification(details)
    superseded_by = sorted(set(superseded_by_event_ids or []), reverse=True)
    return {
        "id": event.get("id"),
        "ts_utc": event.get("ts_utc") or "",
        "age": age.get("age") or "",
        "action": event.get("action") or "",
        "kind": classify_event_kind(event),
        "truth_status": event_truth_status(event),
        "confidence": event_confidence(event),
        "freshness": freshness,
        "task_id": event_task_id(event),
        "result": event_result(event),
        "subsystem": event_subsystems(event),
        "scope": str(details.get("scope") or ""),
        "risk_level": str(details.get("risk_level") or ""),
        "summary": str(event.get("summary") or ""),
        "verification": verification[:500],
        "evidence_count": len(string_list(details.get("evidence_files"))),
        "memory_status": "superseded" if superseded_by else "current_or_unclassified",
        "superseded": bool(superseded_by),
        "superseded_by_event_ids": superseded_by,
        "score": round(score, 3),
        "matched_terms": matched,
    }


def recall_events(
    query: str,
    limit: int = 12,
    *,
    events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    terms = intent_terms(query)
    search_terms = expanded_intent_terms(terms)
    candidates: list[tuple[float, dict[str, Any], list[str]]] = []
    now = dt.datetime.now(dt.UTC)
    event_rows = events if events is not None else query_all_events()
    terminal_event_by_task: dict[str, int] = {}
    superseded_by_event_ids: dict[int, list[int]] = {}
    for event in event_rows:
        task_id = event_task_id(event)
        if task_id and str(event.get("action") or "") in CLOSE_ACTIONS:
            terminal_event_by_task[task_id] = int(event.get("id") or 0)
        superseder_id = int(event.get("id") or 0)
        for raw_target_id in string_list(event_details(event).get("supersedes_event_ids")):
            try:
                target_id = int(raw_target_id)
            except ValueError:
                continue
            if target_id > 0 and superseder_id > 0 and target_id != superseder_id:
                superseded_by_event_ids.setdefault(target_id, []).append(superseder_id)
    for event in event_rows:
        details = event_details(event)
        summary = str(event.get("summary") or "").lower()
        action = str(event.get("action") or "").lower()
        tags = " ".join(string_list(event.get("tags"))).lower()
        subsystem = " ".join(event_subsystems(event)).lower()
        compact_details = json.dumps(details, ensure_ascii=False, separators=(",", ":")).lower()
        matched: list[str] = []
        score = 0.0
        if search_terms:
            for term in search_terms:
                term_score = 0.0
                if term in summary:
                    term_score = max(term_score, 7.0)
                if term in subsystem:
                    term_score = max(term_score, 6.0)
                if term in action or term in tags:
                    term_score = max(term_score, 4.0)
                if term in compact_details:
                    term_score = max(term_score, 2.0)
                if term_score:
                    matched.append(term)
                    score += term_score
            if not matched:
                continue
            score += 2.0 * (len(matched) / max(1, len(search_terms)))
            generic_matches = set(matched) & GENERIC_RECALL_TERMS
            if generic_matches and not any(term in subsystem or term in tags for term in generic_matches):
                score -= 5.0
        else:
            kind = classify_event_kind(event)
            if kind not in {"decision", "blocker", "failure", "task-complete", "verification", "change"}:
                continue
            score = 2.0

        parsed = parse_event_time(event.get("ts_utc"))
        if parsed:
            age_days = max(0.0, (now - parsed).total_seconds() / 86400)
            score += max(0.0, 5.0 - math.log2(1.0 + age_days))
        kind = classify_event_kind(event)
        if kind in {"blocker", "failure", "decision"}:
            score += 2.0
        if kind == "task-complete":
            score += 5.0
        if event_truth_status(event) == "verified":
            score += 1.5
        task_id = event_task_id(event)
        if task_id:
            score += 0.5
            terminal_id = terminal_event_by_task.get(task_id, 0)
            if (
                str(event.get("action") or "") in OPEN_ACTIONS
                and terminal_id > int(event.get("id") or 0)
            ):
                score -= 8.0
        if int(event.get("id") or 0) in superseded_by_event_ids:
            # Preserve historical recall, but never present an explicitly
            # superseded event as equally current memory.
            score -= 12.0
        candidates.append((score, event, matched))

    candidates.sort(key=lambda item: (item[0], int(item[1].get("id") or 0)), reverse=True)
    hits = [
        recall_event_shape(
            event,
            score,
            matched,
            superseded_by_event_ids.get(int(event.get("id") or 0), []),
        )
        for score, event, matched in candidates[:limit]
    ]
    return {
        "query_fingerprint": hashlib.sha256(query.encode("utf-8")).hexdigest()[:12] if query else "",
        "terms": terms,
        "expanded_terms": search_terms,
        "candidate_count": len(candidates),
        "hit_count": len(hits),
        "hits": hits,
    }


def bounded_segment_terms(segment: str) -> list[str]:
    tokens = re.findall(
        r"(?:\d{1,3}\.){3}\d{1,3}|[A-Za-zА-Яа-яЁё0-9][A-Za-zА-Яа-яЁё0-9_.:@/-]*",
        segment.lower(),
    )
    all_terms: list[str] = []
    for token in tokens:
        cleaned = token.strip("._-/:@")
        if not cleaned or cleaned in RECALL_STOP_WORDS:
            continue
        if len(cleaned) < 3 and not cleaned.isdigit():
            continue
        if cleaned not in all_terms:
            all_terms.append(cleaned)
    selected = [*all_terms[:16], *all_terms[-8:]]
    return list(dict.fromkeys(selected))


def bounded_segment_phrases(segment: str) -> list[str]:
    terms = bounded_segment_terms(segment)
    phrases = [f"{terms[index]} {terms[index + 1]}" for index in range(len(terms) - 1)]
    selected = [*phrases[:4], *phrases[-4:]]
    return list(dict.fromkeys(selected))[:8]


def _extend_balanced(target: list[str], values: list[str], per_segment: int = 8) -> None:
    head = max(1, per_segment // 2)
    selected = [*values[:head], *values[-(per_segment - head) :]]
    for value in selected:
        if value and value not in target:
            target.append(value)


def recall_events_segments(
    raw_segments: Any,
    limit: int = 12,
    *,
    events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    segments = validate_mind_query_segments(raw_segments)
    event_rows = events if events is not None else query_all_events()
    candidate_limit = min(MAX_LIMIT, max(MIND_SEGMENT_CANDIDATE_FLOOR, limit * 4))
    merged: dict[int, dict[str, Any]] = {}
    aggregate_terms: list[str] = []
    aggregate_expanded_terms: list[str] = []
    aggregate_phrases: list[str] = []
    matched_segment_indexes: list[int] = []
    candidate_pool_truncated = False

    for segment_index, segment in enumerate(segments):
        segment_terms = bounded_segment_terms(segment)
        recalled = (
            recall_events(" ".join(segment_terms), candidate_limit, events=event_rows)
            if segment_terms
            else {
                "query_fingerprint": "",
                "terms": [],
                "expanded_terms": [],
                "candidate_count": 0,
                "hit_count": 0,
                "hits": [],
            }
        )
        _extend_balanced(aggregate_terms, list(recalled.get("terms") or []))
        _extend_balanced(
            aggregate_expanded_terms,
            list(recalled.get("expanded_terms") or []),
        )
        _extend_balanced(aggregate_phrases, bounded_segment_phrases(segment))
        if recalled.get("hits"):
            matched_segment_indexes.append(segment_index)
        if int(recalled.get("candidate_count") or 0) > candidate_limit:
            candidate_pool_truncated = True
        for rank, raw_hit in enumerate(recalled.get("hits") or []):
            event_id = int(raw_hit.get("id") or 0)
            if event_id <= 0:
                continue
            entry = merged.get(event_id)
            if entry is None:
                entry = {
                    "hit": dict(raw_hit),
                    "score": 0.0,
                    "best_score": float("-inf"),
                    "best_rank": rank,
                    "matched_terms": [],
                    "segment_indexes": [],
                }
                merged[event_id] = entry
            score = float(raw_hit.get("score") or 0.0)
            entry["score"] += score
            entry["best_score"] = max(float(entry["best_score"]), score)
            entry["best_rank"] = min(int(entry["best_rank"]), rank)
            if segment_index not in entry["segment_indexes"]:
                entry["segment_indexes"].append(segment_index)
            for term in raw_hit.get("matched_terms") or []:
                if term not in entry["matched_terms"]:
                    entry["matched_terms"].append(term)

    ranked_hits: list[dict[str, Any]] = []
    for event_id, entry in merged.items():
        segment_indexes = list(entry["segment_indexes"])
        aggregate_score = float(entry["score"]) + 2.0 * max(
            0, len(segment_indexes) - 1
        )
        hit = dict(entry["hit"])
        hit["score"] = round(aggregate_score, 3)
        hit["matched_terms"] = list(entry["matched_terms"])[:64]
        hit["matched_segment_indexes"] = segment_indexes
        hit["matched_segment_count"] = len(segment_indexes)
        ranked_hits.append(
            {
                **hit,
                "_rank_key": (
                    aggregate_score,
                    len(segment_indexes),
                    float(entry["best_score"]),
                    -int(entry["best_rank"]),
                    event_id,
                ),
            }
        )
    ranked_hits.sort(key=lambda hit: hit["_rank_key"], reverse=True)
    hits = []
    for ranked in ranked_hits[:limit]:
        ranked.pop("_rank_key", None)
        hits.append(ranked)

    query_digest = mind_query_segments_digest(segments)
    coverage_core = {
        "protocol": MIND_SEGMENT_COVERAGE_PROTOCOL,
        "query_digest": query_digest,
        "segment_count": len(segments),
        "evaluated_segment_count": len(segments),
        "total_utf8_bytes": sum(len(segment.encode("utf-8")) for segment in segments),
        "matched_segment_count": len(matched_segment_indexes),
        "matched_segment_indexes": matched_segment_indexes,
        "unmatched_segment_count": len(segments) - len(matched_segment_indexes),
        "candidate_event_count": len(merged),
        "returned_event_count": len(hits),
        "candidate_pool_truncated": candidate_pool_truncated,
        "semantic_complete": False,
    }
    segment_coverage = {
        **coverage_core,
        "coverage_digest": "sha256:"
        + hashlib.sha256(
            json.dumps(
                coverage_core,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
    }
    return {
        "query_fingerprint": query_digest.removeprefix("sha256:")[:12],
        "terms": aggregate_terms,
        "expanded_terms": aggregate_expanded_terms,
        "phrases": aggregate_phrases,
        "candidate_count": len(merged),
        "hit_count": len(hits),
        "hits": hits,
        "coverage": {
            "status": (
                "all-segments-matched"
                if len(matched_segment_indexes) == len(segments)
                else "partial"
                if matched_segment_indexes
                else "no-match"
            ),
            "semantic_complete": False,
            "segment_coverage_digest": segment_coverage["coverage_digest"],
            "note": "Every segment was evaluated; bounded retrieval is not semantic completeness.",
        },
        "segment_coverage": segment_coverage,
    }


def looks_like_codex_thread_id(value: str) -> bool:
    candidate = value.split(":")[-1]
    return bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}", candidate))


def build_memory_quality(events: list[dict[str, Any]]) -> dict[str, Any]:
    lifecycle = [event for event in events if str(event.get("action") or "") in TASK_LIFECYCLE_ACTIONS]
    closes = [event for event in lifecycle if str(event.get("action") or "") in CLOSE_ACTIONS]
    production_starts = [
        event
        for event in lifecycle
        if str(event.get("action") or "") == "agent_change_start"
        and str(event_details(event).get("scope") or "") == "production-impact"
    ]
    codex_events = [event for event in events if str(event.get("actor") or "").lower() == "codex"]

    def ratio(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 4) if denominator else None

    task_id_count = sum(bool(event_task_id(event)) for event in lifecycle)
    verified_close_count = sum(bool(useful_verification(event_details(event))) for event in closes)
    rollback_count = sum(bool(str(event_details(event).get("rollback") or "").strip()) for event in production_starts)
    thread_identity_count = sum(looks_like_codex_thread_id(str(event.get("session_id") or "")) for event in codex_events)
    evidence_close_count = sum(bool(string_list(event_details(event).get("evidence_files"))) for event in closes)

    metrics = {
        "lifecycle_task_id": ratio(task_id_count, len(lifecycle)),
        "close_verification": ratio(verified_close_count, len(closes)),
        "production_start_rollback": ratio(rollback_count, len(production_starts)),
        "codex_thread_identity": ratio(thread_identity_count, len(codex_events)),
        "close_evidence": ratio(evidence_close_count, len(closes)),
    }
    weighted = [
        (metrics["lifecycle_task_id"], 30),
        (metrics["close_verification"], 25),
        (metrics["production_start_rollback"], 20),
        (metrics["codex_thread_identity"], 15),
        (metrics["close_evidence"], 10),
    ]
    available = [(value, weight) for value, weight in weighted if value is not None]
    score = round(sum(float(value) * weight for value, weight in available) / sum(weight for _, weight in available) * 100, 1) if available else 100.0
    warnings: list[str] = []
    if metrics["lifecycle_task_id"] is not None and metrics["lifecycle_task_id"] < 1:
        warnings.append("Some lifecycle events lack task_id and cannot be coordinated precisely.")
    if metrics["close_verification"] is not None and metrics["close_verification"] < 0.9:
        warnings.append("Some closed tasks lack usable verification evidence.")
    if metrics["production_start_rollback"] is not None and metrics["production_start_rollback"] < 1:
        warnings.append("Some production-impact starts lack rollback text.")
    if metrics["codex_thread_identity"] is not None and metrics["codex_thread_identity"] < 0.8:
        warnings.append("Codex events are not consistently bound to durable thread identity.")
    return {
        "score": score,
        "window_event_count": len(events),
        "lifecycle_count": len(lifecycle),
        "close_count": len(closes),
        "production_start_count": len(production_starts),
        "metrics": metrics,
        "warnings": warnings,
    }


def task_attention_item(task: dict[str, Any], priority: int, reason: str) -> dict[str, Any]:
    cursor = task.get("operational_cursor")
    if not isinstance(cursor, dict):
        cursor = {}
    return {
        "priority": priority,
        "kind": "task",
        "reason": reason,
        "task_id": task.get("task_id") or task.get("task_key"),
        "status": task.get("status") or "",
        "age": task.get("age") or "",
        "subsystem": task.get("subsystem") or [],
        "summary": cursor.get("summary") or task.get("summary") or "",
        "next_action": cursor.get("next_action") or task.get("next_action") or "",
        "owner_session_id": task.get("session_id") or "",
        "preempts_task_ids": list(task.get("preempts_task_ids") or []),
        "resume_after_task_ids": list(task.get("resume_after_task_ids") or []),
        "target_thread_ids": list(task.get("target_thread_ids") or []),
        "operational_cursor": cursor,
    }


def build_reflex_context(reflex: dict[str, Any]) -> str:
    state = reflex["global_state"]
    thread = reflex["thread"]
    quality = reflex["memory_quality"]
    lines = [
        f"exampleproject SECOND MIND v{MEMORY_CONTRACT_VERSION}",
        (
            f"attention={reflex['attention']['level']} open={state['open_tasks']} "
            f"pending={state.get('pending_tasks', 0)} "
            f"paused={state.get('paused_tasks', 0)} "
            f"stale_open={state['stale_open_tasks']} "
            f"locks={state['active_locks']} conflicts={state['conflicts']} "
            f"quality={quality['score']}"
        ),
        f"thread={thread['session_id'] or '-'} owned_open={thread['owned_open_count']} dirty={str(thread.get('dirty', False)).lower()}",
    ]
    if reflex["attention"]["items"]:
        lines.append("ATTENTION:")
        for item in reflex["attention"]["items"][:6]:
            identity = item.get("task_id") or item.get("lock_id") or item.get("kind")
            lines.append(
                f"- P{item['priority']} {item['reason']} {identity}: {str(item.get('summary') or item.get('next_action') or '')[:280]}"
            )
    hits = reflex["recall"]["hits"]
    if hits:
        lines.append("RELEVANT MEMORY (memory, not live proof):")
        for hit in hits[:8]:
            stale = " stale" if hit["freshness"].get("stale") else ""
            lines.append(
                f"- #{hit['id']} [{hit['kind']}/{hit['truth_status']}/{hit['confidence']}{stale}] "
                f"{hit['summary'][:360]}"
            )
    if quality["warnings"]:
        lines.append("MEMORY QUALITY:")
        for warning in quality["warnings"][:4]:
            lines.append(f"- {warning}")
    lines.append("REASONING ORDER:")
    for index, instruction in enumerate(reflex["reasoning_order"], start=1):
        lines.append(f"{index}. {instruction}")
    return "\n".join(lines)


def build_reflex(
    params: dict[str, list[str]],
    *,
    task_state: dict[str, Any] | None = None,
    lock_state: dict[str, Any] | None = None,
    events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    query = first(params, "q") or ""
    query_segments = params.get("q_segments")
    if query_segments is not None and "q" in params:
        raise ValueError("q and q_segments are mutually exclusive")
    session_id = (first(params, "session_id") or "").strip()
    recall_limit = parse_limit(first(params, "limit"), 12)
    recent_hours = parse_float(first(params, "recent_hours"), 168.0)
    stale_after_hours = TASK_LEASE_STALE_AFTER_HOURS

    event_rows = events if events is not None else query_all_events()
    if task_state is None:
        task_state = build_tasks(
            {
                "include_legacy": ["false"],
                "limit": [str(MAX_LIMIT)],
                "stale_after_hours": [str(stale_after_hours)],
            },
            events=event_rows,
        )
    if lock_state is None:
        lock_state = build_locks(
            {"include_released": ["false"], "limit": [str(MAX_LIMIT)]},
            events=event_rows,
        )
    recall = (
        recall_events_segments(query_segments, recall_limit, events=event_rows)
        if query_segments is not None
        else recall_events(query, recall_limit, events=event_rows)
    )
    recent_since = dt.datetime.now(dt.UTC) - dt.timedelta(hours=recent_hours)
    recent_events = [
        event
        for event in event_rows
        if (parse_event_time(event.get("ts_utc")) or dt.datetime.min.replace(tzinfo=dt.UTC)) >= recent_since
    ][-MAX_LIMIT:]
    memory_quality = build_memory_quality(recent_events)

    tasks = list(task_state.get("tasks") or [])
    semantic_open_tasks = [task for task in tasks if task.get("status") == "open"]
    semantic_pending_tasks = [task for task in tasks if task.get("status") == "pending"]
    semantic_paused_tasks = [task for task in tasks if task.get("status") == "paused"]
    open_tasks = [task for task in semantic_open_tasks if task_coordination_active(task)]
    pending_tasks = [task for task in semantic_pending_tasks if task_coordination_active(task)]
    paused_tasks = [task for task in semantic_paused_tasks if task_coordination_active(task)]
    recovery_tasks = [task for task in tasks if task.get("queue_state") == "recovery"]
    owned_open = [
        task
        for task in open_tasks
        if session_id and session_id == str(task.get("session_id") or "")
    ]
    owned_paused = [
        task
        for task in paused_tasks
        if session_id and session_id == str(task.get("session_id") or "")
    ]
    targeted_open = [
        task
        for task in open_tasks
        if session_id
        and session_id in set(string_list(task.get("target_thread_ids")))
        and task not in owned_open
    ]
    recent_terminal = [
        task
        for task in tasks
        if task.get("status") in {"blocked", "failed"}
        and task.get("age_hours") is not None
        and float(task["age_hours"]) <= recent_hours
    ]
    recall_task_ids = {str(hit.get("task_id") or "") for hit in recall["hits"] if hit.get("task_id")}
    recall_terms = set(recall.get("terms") or [])
    def task_matches_recall(task: dict[str, Any]) -> bool:
        cursor = task.get("operational_cursor")
        if not isinstance(cursor, dict):
            cursor = {}
        task_words = " ".join(
            [
                str(cursor.get("summary") or task.get("summary") or ""),
                " ".join(task.get("subsystem") or []),
                str(task.get("task_id") or ""),
            ]
        ).lower()
        return bool(
            str(task.get("task_id") or "") in recall_task_ids
            or any(term in task_words for term in recall_terms)
        )

    related_open = [task for task in open_tasks if task_matches_recall(task)]
    related_recovery = [task for task in recovery_tasks if task_matches_recall(task)]

    attention_items: list[dict[str, Any]] = []
    for task in pending_tasks:
        requested_priority = priority_value(task.get("priority"))
        reason = "pending-preemption" if task.get("preempts_task_ids") else "pending-queued-work"
        attention_items.append(
            task_attention_item(task, max(90, requested_priority), reason)
        )
    for conflict in task_state.get("conflicts") or []:
        attention_items.append(
            {
                "priority": 100,
                "kind": "task-conflict",
                "reason": "overlapping-open-tasks",
                "summary": f"Subsystem {conflict['subsystem']} has {conflict['count']} open tasks.",
                "task_ids": conflict.get("task_ids") or [],
                "next_action": "Reconcile ownership and exact scope before any write.",
            }
        )
    for conflict in lock_state.get("conflicts") or []:
        attention_items.append(
            {
                "priority": 100,
                "kind": "lock-conflict",
                "reason": "overlapping-active-locks",
                "summary": f"Subsystem {conflict['subsystem']} has {conflict['count']} active locks.",
                "lock_ids": conflict.get("lock_ids") or [],
                "next_action": "Resolve lock ownership before any overlapping write.",
            }
        )
    for task in owned_open:
        attention_items.append(task_attention_item(task, 92 if task.get("stale") else 86, "owned-stale-task" if task.get("stale") else "owned-open-task"))
    for task in related_open:
        if task in owned_open:
            continue
        attention_items.append(task_attention_item(task, 84 if task.get("stale") else 78, "related-stale-task" if task.get("stale") else "related-open-task"))
    for task in owned_paused:
        attention_items.append(task_attention_item(task, 88, "owned-paused-task"))
    for task in related_recovery:
        attention_items.append(
            task_attention_item(task, 58, "recovery-task-nonblocking")
        )
    for task in recent_terminal:
        priority = 76 if task.get("status") == "failed" else 72
        attention_items.append(task_attention_item(task, priority, f"recent-{task.get('status')}"))
    for lock in lock_state.get("locks") or []:
        if lock.get("status") != "active":
            continue
        attention_items.append(
            {
                "priority": 82,
                "kind": "lock",
                "reason": "active-lock",
                "lock_id": lock.get("lock_id") or "",
                "task_id": lock.get("task_id") or "",
                "subsystem": lock.get("subsystem") or [],
                "summary": lock.get("reason") or lock.get("summary") or "",
                "next_action": "Respect the lock or reconcile with its owner before overlapping work.",
            }
        )
    if memory_quality["score"] < 80:
        attention_items.append(
            {
                "priority": 60,
                "kind": "memory-quality",
                "reason": "memory-quality-debt",
                "summary": "; ".join(memory_quality["warnings"]),
                "next_action": "Treat uncertain memory as a lead and obtain fresh evidence.",
            }
        )

    deduped_attention: list[dict[str, Any]] = []
    seen_attention: set[tuple[str, str]] = set()
    for item in sorted(attention_items, key=lambda value: int(value.get("priority") or 0), reverse=True):
        identity = str(item.get("task_id") or item.get("lock_id") or item.get("summary") or "")
        key = (str(item.get("reason") or item.get("kind") or ""), identity)
        if key in seen_attention:
            continue
        seen_attention.add(key)
        deduped_attention.append(item)
    top_priority = int(deduped_attention[0]["priority"]) if deduped_attention else 0
    attention_level = "critical" if top_priority >= 95 else "warning" if top_priority >= 80 else "notice" if top_priority >= 60 else "clear"

    reasoning_order: list[str] = []
    if pending_tasks:
        reasoning_order.append("Honor the highest-priority pending request: reach a safe checkpoint, publish evidence, release the conflicting lock, and resume only after the hotfix report.")
    if owned_open:
        reasoning_order.append("Resume, reconcile, or explicitly close the current thread's existing task before starting another overlapping lifecycle.")
    if task_state.get("conflict_count") or lock_state.get("conflict_count"):
        reasoning_order.append("Resolve task or lock conflicts before any overlapping change.")
    reasoning_order.extend(
        [
            "Separate verified observations from reported, inferred, stale, or superseded memory.",
            "Use relevant history to form hypotheses, then verify current state with bounded read-only checks.",
            "Before production impact, confirm scoped owner GO, TaskId, rollback, and pre-check evidence.",
            "After action, perform post-check and record outcome, evidence, remaining uncertainty, and next action.",
        ]
    )

    speaker = session_speaker_projection(event_rows, session_id)
    result: dict[str, Any] = {
        "ok": True,
        "service_version": SERVICE_VERSION,
        "memory_contract_version": MEMORY_CONTRACT_VERSION,
        "generated_utc": utc_now(),
        "thread": {
            "session_id": session_id,
            "agent_id": speaker["agent_id"],
            "agent_vendor": speaker["agent_vendor"],
            "agent_product": speaker["agent_product"],
            "admission_id": speaker.get("admission_id") or "",
            "admission_declared_at": speaker.get("admission_declared_at") or "",
            "admission_expires_at": speaker.get("admission_expires_at") or "",
            "capability_class": list(speaker.get("capability_class") or []),
            "admitted_agents": speaker["admitted_agents"],
            "owned_open_count": len(owned_open),
            "owned_open_tasks": owned_open[:10],
            "targeted_open_count": len(targeted_open),
            "targeted_open_tasks": targeted_open[:10],
            "related_open_count": len(related_open),
            "related_open_tasks": related_open[:10],
            "owned_paused_count": len(owned_paused),
            "owned_paused_tasks": owned_paused[:10],
            "related_recovery_count": len(related_recovery),
            "related_recovery_tasks": related_recovery[:10],
        },
        "scheduler": {
            "pending_count": len(pending_tasks),
            "paused_count": len(paused_tasks),
            "semantic_pending_count": len(semantic_pending_tasks),
            "semantic_paused_count": len(semantic_paused_tasks),
            "recovery_count": len(recovery_tasks),
            "pending_tasks": pending_tasks[:20],
            "recovery_tasks": recovery_tasks[:20],
        },
        "attention": {
            "level": attention_level,
            "top_priority": top_priority,
            "count": len(deduped_attention),
            "items": deduped_attention[:20],
        },
        "global_state": {
            "task_count": task_state.get("task_count", 0),
            "open_tasks": len(semantic_open_tasks),
            "pending_tasks": len(semantic_pending_tasks),
            "paused_tasks": len(semantic_paused_tasks),
            "current_tasks": task_state.get("current_count", 0),
            "recovery_tasks": task_state.get("recovery_count", 0),
            "archived_tasks": task_state.get("archive_count", 0),
            "stale_open_tasks": sum(bool(task.get("stale")) for task in semantic_open_tasks),
            "recent_blocked_tasks": sum(task.get("status") == "blocked" for task in recent_terminal),
            "recent_failed_tasks": sum(task.get("status") == "failed" for task in recent_terminal),
            "active_locks": lock_state.get("active_count", 0),
            "expired_locks": lock_state.get("expired_count", 0),
            "task_conflicts": task_state.get("conflict_count", 0),
            "lock_conflicts": lock_state.get("conflict_count", 0),
            "conflicts": int(task_state.get("conflict_count", 0)) + int(lock_state.get("conflict_count", 0)),
        },
        "memory_quality": memory_quality,
        "recall": recall,
        "invariants": [
            "Action Log is durable memory and coordination, not current-state proof.",
            "Semantic task status is history; only a live current lease enters hard coordination.",
            "Fresh bounded read-only evidence is required before a production conclusion or write.",
            "Production impact requires scoped owner GO, TaskId, rollback, pre-check, and post-check.",
            "Never store or emit secrets, tokens, cookies, private keys, or raw credential contents.",
            "Preserve access paths and respect active tasks and locks until explicitly reconciled.",
            "A pending task never steals a lock: the active owner checkpoints, reports, and releases before handoff.",
        ],
        "reasoning_order": reasoning_order,
    }
    result["context_text"] = build_reflex_context(result)
    return result


def priority_value(value: Any) -> int:
    text = str(value or "").strip().upper()
    named = {"P0": 100, "P1": 80, "P2": 60, "P3": 40, "P4": 20, "CRITICAL": 100, "HIGH": 80, "MEDIUM": 50, "LOW": 20}
    if text in named:
        return named[text]
    try:
        return max(0, min(100, int(float(text))))
    except ValueError:
        return 0


def task_plan_score(task: dict[str, Any], *, owned: bool, related: bool, dependency_blocked: bool) -> tuple[int, list[str]]:
    score = priority_value(task.get("priority"))
    reasons: list[str] = []
    if score:
        reasons.append(f"explicit-priority:{task.get('priority')}")
    status = str(task.get("status") or "")
    if status == "open":
        score += 45
        reasons.append("open")
    elif status == "pending":
        score += 55
        reasons.append("pending")
        if task.get("preempts_task_ids"):
            score += 20
            reasons.append("preemption-request")
    elif status == "paused":
        score += 15
        reasons.append("paused")
    elif status == "failed":
        score += 35
        reasons.append("failed")
    elif status == "blocked":
        score += 30
        reasons.append("blocked")
    if task.get("stale"):
        score += 12
        reasons.append("stale")
    if owned:
        score += 25
        reasons.append("owned-by-current-thread")
    if related:
        score += 18
        reasons.append("matches-current-intent")
    if str(task.get("risk_level") or "").lower() in {"high", "critical"}:
        score += 8
        reasons.append("high-risk")
    if str(task.get("scope") or "").lower() == "production-impact":
        score += 6
        reasons.append("production-impact")
    if dependency_blocked:
        score -= 15
        reasons.append("dependency-blocked")
    return max(0, score), reasons


def dependency_cycles(tasks: dict[str, dict[str, Any]], limit: int = 20) -> list[list[str]]:
    graph = {
        task_id: [dependency for dependency in task.get("depends_on_task_ids") or [] if dependency in tasks]
        for task_id, task in tasks.items()
    }
    state: dict[str, int] = {}
    stack: list[str] = []
    cycles: list[list[str]] = []

    def visit(node: str) -> None:
        if len(cycles) >= limit:
            return
        marker = state.get(node, 0)
        if marker == 2:
            return
        if marker == 1:
            if node in stack:
                start = stack.index(node)
                cycle = stack[start:] + [node]
                if cycle not in cycles:
                    cycles.append(cycle)
            return
        state[node] = 1
        stack.append(node)
        for child in graph.get(node, []):
            visit(child)
        stack.pop()
        state[node] = 2

    for task_id in graph:
        visit(task_id)
    return cycles


def task_logic_chain(task: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    timeline: list[dict[str, Any]] = []
    for event in events:
        details = event_details(event)
        timeline.append(
            {
                "event_id": event.get("id"),
                "ts_utc": event.get("ts_utc") or "",
                "action": event.get("action") or "",
                "kind": classify_event_kind(event),
                "truth_status": event_truth_status(event),
                "confidence": event_confidence(event),
                "summary": event.get("summary") or "",
                "verified": bool(useful_verification(details)),
                "evidence_count": len(string_list(details.get("evidence_files"))),
                "next_action": str(details.get("next_action") or ""),
            }
        )
    gaps: list[str] = []
    if task.get("task_id") and not task.get("has_start"):
        gaps.append("missing-start")
    if task.get("status") in {"open", "pending", "paused"} and not task.get("next_action_explicit"):
        gaps.append("missing-next-action")
    if task.get("status") in {"open", "pending", "paused"} and not task.get("done_when_explicit"):
        gaps.append("missing-done-when")
    if task.get("status") in {"complete", "blocked", "failed"} and not task.get("verification_explicit"):
        gaps.append("missing-close-verification")
    if str(task.get("scope") or "") == "production-impact" and not task.get("rollback_explicit"):
        gaps.append("missing-production-rollback")
    cursor = task.get("operational_cursor")
    if not isinstance(cursor, dict):
        cursor = {}
    return {
        "task_id": task.get("task_id") or task.get("task_key"),
        "status": task.get("status") or "",
        "summary": cursor.get("summary") or task.get("summary") or "",
        "event_count": len(timeline),
        "events": timeline,
        "chain_gaps": gaps,
        "next_action": cursor.get("next_action") or task.get("next_action") or "",
        "done_when": task.get("done_when") or "",
    }


def normalize_assertion(event: dict[str, Any], raw: Any, index: int) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    subject = str(raw.get("subject") or "").strip()
    predicate = str(raw.get("predicate") or raw.get("key") or "").strip()
    if not subject or not predicate or "value" not in raw:
        return None
    assertion_id = str(raw.get("id") or f"event:{event.get('id')}:{index}")
    observed_at = str(raw.get("observed_at") or event.get("ts_utc") or "")
    valid_until = str(raw.get("valid_until") or "")
    if not valid_until and raw.get("valid_for_hours") not in (None, ""):
        parsed = parse_event_time(observed_at)
        if parsed:
            valid_until = (
                parsed + dt.timedelta(hours=parse_float(str(raw.get("valid_for_hours")), 0.0))
            ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    expires = parse_event_time(valid_until)
    stale = bool(expires and dt.datetime.now(dt.UTC) >= expires)
    return {
        "assertion_id": assertion_id,
        "subject": subject,
        "predicate": predicate,
        "value": raw.get("value"),
        "truth_status": str(raw.get("truth_status") or event_truth_status(event)),
        "confidence": str(raw.get("confidence") or event_confidence(event)),
        "observed_at": observed_at,
        "valid_until": valid_until,
        "stale": stale,
        "source_event_id": event.get("id"),
        "task_id": event_task_id(event),
        "evidence": string_list(raw.get("evidence")),
        "supersedes_assertion_ids": string_list(raw.get("supersedes_assertion_ids")),
    }


def build_epistemic_state(events: list[dict[str, Any]], terms: list[str], limit: int) -> dict[str, Any]:
    assertions: list[dict[str, Any]] = []
    superseded_event_ids: set[int] = set()
    for event in events:
        details = event_details(event)
        for event_id in string_list(details.get("supersedes_event_ids")):
            try:
                superseded_event_ids.add(int(event_id))
            except ValueError:
                continue
        raw_assertions = details.get("assertions")
        if raw_assertions is None:
            raw_assertions = details.get("facts")
        if isinstance(raw_assertions, dict):
            raw_assertions = [raw_assertions]
        if not isinstance(raw_assertions, list):
            continue
        for index, raw in enumerate(raw_assertions):
            assertion = normalize_assertion(event, raw, index)
            if assertion:
                assertions.append(assertion)

    superseded_assertion_ids = {
        superseded
        for assertion in assertions
        for superseded in assertion.get("supersedes_assertion_ids") or []
    }
    active = [
        assertion
        for assertion in assertions
        if assertion["assertion_id"] not in superseded_assertion_ids
        and int(assertion.get("source_event_id") or 0) not in superseded_event_ids
    ]
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for assertion in active:
        groups.setdefault((assertion["subject"].lower(), assertion["predicate"].lower()), []).append(assertion)

    contradictions: list[dict[str, Any]] = []
    current: list[dict[str, Any]] = []
    for key, group in groups.items():
        ordered = sorted(group, key=lambda item: int(item.get("source_event_id") or 0), reverse=True)
        current.append(ordered[0])
        live_values: dict[str, list[str]] = {}
        for assertion in ordered:
            if assertion.get("stale") or assertion.get("truth_status") == "superseded":
                continue
            encoded = json.dumps(assertion.get("value"), ensure_ascii=False, sort_keys=True)
            live_values.setdefault(encoded, []).append(assertion["assertion_id"])
        if len(live_values) > 1:
            contradictions.append(
                {
                    "subject": key[0],
                    "predicate": key[1],
                    "values": [json.loads(value) for value in live_values],
                    "assertion_ids": [item for ids in live_values.values() for item in ids],
                    "next_action": "Obtain fresh evidence and explicitly supersede the losing assertion.",
                }
            )

    def matches(assertion: dict[str, Any]) -> bool:
        if not terms:
            return True
        blob = f"{assertion['subject']} {assertion['predicate']} {json.dumps(assertion['value'], ensure_ascii=False)}".lower()
        return any(term in blob for term in terms)

    current.sort(key=lambda item: int(item.get("source_event_id") or 0), reverse=True)
    matching_current = [assertion for assertion in current if matches(assertion)]
    return {
        "assertion_count": len(assertions),
        "active_assertion_count": len(active),
        "current_fact_count": len(current),
        "stale_assertion_count": sum(bool(assertion.get("stale")) for assertion in active),
        "contradiction_count": len(contradictions),
        "contradictions": contradictions[:limit],
        "current_facts": matching_current[:limit],
        "coverage_note": "Only explicit structured assertions are treated as facts; free-text summaries remain memory leads.",
    }


def build_task_matrix(tasks: list[dict[str, Any]], limit: int) -> dict[str, Any]:
    rows: dict[str, dict[str, Any]] = {}
    domain_status: dict[str, dict[str, int]] = {}
    scope_status: dict[str, dict[str, int]] = {}
    risk_status: dict[str, dict[str, int]] = {}
    for task in tasks:
        status = str(task.get("status") or "unknown")
        subsystems = task.get("subsystem") or ["untagged"]
        task_domains: set[str] = set()
        for subsystem in subsystems:
            row = rows.setdefault(
                str(subsystem),
                {
                    "subsystem": str(subsystem),
                    "domain": subsystem_domain(str(subsystem)),
                    "open": 0,
                    "blocked": 0,
                    "failed": 0,
                    "complete": 0,
                    "total": 0,
                },
            )
            row[status] = int(row.get(status) or 0) + 1
            row["total"] += 1
            task_domains.add(str(row["domain"]))
        for domain in task_domains:
            domain_status.setdefault(domain, {})[status] = domain_status.setdefault(domain, {}).get(status, 0) + 1
        scope = scope_category(task.get("scope"))
        scope_status.setdefault(scope, {})[status] = scope_status.setdefault(scope, {}).get(status, 0) + 1
        risk = risk_category(task.get("risk_level"))
        risk_status.setdefault(risk, {})[status] = risk_status.setdefault(risk, {}).get(status, 0) + 1
    ordered = sorted(
        rows.values(),
        key=lambda row: (int(row.get("open") or 0) + int(row.get("blocked") or 0) + int(row.get("failed") or 0), int(row["total"])),
        reverse=True,
    )
    return {
        "subsystem_count": len(ordered),
        "subsystem_status": ordered[:limit],
        "domain_status": domain_status,
        "scope_status": scope_status,
        "risk_status": risk_status,
    }


def build_mind_context(mind: dict[str, Any]) -> str:
    capsule = mind.get("capsule") if isinstance(mind.get("capsule"), dict) else None
    lead = render_synaptic_capsule(capsule) if capsule else ""
    if capsule and str(capsule.get("door") or "") != "admitted":
        return lead
    lead = f"{lead}\n\n" if lead else ""
    lines = [
        f"exampleproject MIND GRAPH v{MEMORY_CONTRACT_VERSION}",
        "Role: episodic memory + working state + semantic relations + executive plan + subconscious reflexes.",
    ]
    plan = mind["plan"]
    if plan["items"]:
        lines.append("EXECUTIVE PLAN:")
        for index, item in enumerate(plan["items"][:8], start=1):
            readiness = "ready" if item["ready"] else "blocked-by-dependency"
            lines.append(
                f"{index}. score={item['score']} {readiness} {item['task_id']} [{item['status']}] "
                f"{item['next_action'] or item['summary'][:260]}"
            )
    hierarchy = mind["hierarchy"]
    if hierarchy["dependency_cycles"] or hierarchy["orphan_parent_count"]:
        lines.append(
            f"STRUCTURE WARNINGS: dependency_cycles={len(hierarchy['dependency_cycles'])} "
            f"orphan_parents={hierarchy['orphan_parent_count']}"
        )
    epistemic = mind["epistemic"]
    lines.append(
        f"EPISTEMIC STATE: structured_facts={epistemic['current_fact_count']} "
        f"stale={epistemic['stale_assertion_count']} contradictions={epistemic['contradiction_count']}"
    )
    if epistemic["contradictions"]:
        for conflict in epistemic["contradictions"][:4]:
            lines.append(f"- CONTRADICTION {conflict['subject']}.{conflict['predicate']}: {conflict['values']}")
    chain_gaps = [
        (chain["task_id"], gap)
        for chain in mind["logical_chains"]
        for gap in chain.get("chain_gaps") or []
    ]
    if chain_gaps:
        lines.append("LOGICAL CHAIN GAPS:")
        for task_id, gap in chain_gaps[:8]:
            lines.append(f"- {task_id}: {gap}")
    lines.append("")
    lines.append(mind["reflex_context"])
    return lead + "\n".join(lines)


def build_mind(params: dict[str, list[str]]) -> dict[str, Any]:
    session_id = (first(params, "session_id") or "").strip()
    limit = parse_limit(first(params, "limit"), 12)
    stale_after_hours = TASK_LEASE_STALE_AFTER_HOURS
    current = projection_snapshot()
    requested_snapshot_event_id = parse_int_param(
        first(params, "snapshot_event_id"), 0, 0
    )
    current_cursor = int(current["event_cursor"])
    if requested_snapshot_event_id > current_cursor:
        raise ValueError("Mind snapshot cursor is newer than the canonical Action Log")
    snapshot_event_id = requested_snapshot_event_id or current_cursor
    events = (
        current["events"]
        if snapshot_event_id == current_cursor
        else [
            event
            for event in current["events"]
            if int(event.get("id") or 0) <= snapshot_event_id
        ]
    )
    if snapshot_event_id == current_cursor:
        task_state = current["tasks"]
        lock_state = current["locks"]
    else:
        task_state = build_tasks(
            {
                "include_legacy": ["false"],
                "limit": [str(MAX_LIMIT)],
                "stale_after_hours": [str(stale_after_hours)],
            },
            events=events,
        )
        lock_state = build_locks(
            {"include_released": ["false"], "limit": [str(MAX_LIMIT)]},
            events=events,
        )
    reflex = build_reflex(
        params,
        task_state=task_state,
        lock_state=lock_state,
        events=events,
    )
    tasks = list(task_state.get("tasks") or [])
    task_by_id = {str(task.get("task_id")): task for task in tasks if task.get("task_id")}
    events_by_task: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        task_id = event_task_id(event)
        if task_id:
            events_by_task.setdefault(task_id, []).append(event)

    recall_task_ids = [str(hit.get("task_id")) for hit in reflex["recall"]["hits"] if hit.get("task_id")]
    focus_task_ids: list[str] = []
    for task in reflex["thread"]["owned_open_tasks"]:
        task_id = str(task.get("task_id") or "")
        if task_id and task_id not in focus_task_ids:
            focus_task_ids.append(task_id)
    for item in reflex["attention"]["items"]:
        task_id = str(item.get("task_id") or "")
        if task_id and task_id in task_by_id and task_id not in focus_task_ids:
            focus_task_ids.append(task_id)
    for task_id in recall_task_ids:
        if task_id in task_by_id and task_id not in focus_task_ids:
            focus_task_ids.append(task_id)
    for task in tasks:
        task_id = str(task.get("task_id") or "")
        if (
            task.get("status") == "open"
            and task_coordination_active(task)
            and task_id
            and task_id not in focus_task_ids
        ):
            focus_task_ids.append(task_id)
    focus_task_ids = focus_task_ids[:limit]

    parent_children: dict[str, list[str]] = {}
    orphan_parents: list[dict[str, str]] = []
    for task_id, task in task_by_id.items():
        parent = str(task.get("parent_task_id") or "")
        if not parent:
            continue
        parent_children.setdefault(parent, []).append(task_id)
        if parent not in task_by_id:
            orphan_parents.append({"task_id": task_id, "missing_parent_task_id": parent})

    relations: list[dict[str, str]] = []
    relation_fields = {
        "depends_on_task_ids": "depends_on",
        "related_task_ids": "related_to",
        "supersedes_task_ids": "supersedes",
        "blocks_task_ids": "blocks",
    }
    for task_id in focus_task_ids:
        task = task_by_id[task_id]
        parent = str(task.get("parent_task_id") or "")
        roadmap_item = str(task.get("roadmap_item_id") or "")
        goal = str(task.get("goal_id") or "")
        if parent:
            relations.append({"source": task_id, "type": "child_of", "target": parent})
        elif roadmap_item:
            relations.append({"source": task_id, "type": "child_of", "target": f"roadmap:{roadmap_item}"})
        elif goal:
            relations.append({"source": task_id, "type": "child_of", "target": f"goal:{goal}"})
        elif task.get("subsystem"):
            relations.append(
                {
                    "source": task_id,
                    "type": "inferred_child_of",
                    "target": f"subsystem:{task['subsystem'][0]}",
                }
            )
        if roadmap_item and goal:
            relations.append(
                {"source": f"roadmap:{roadmap_item}", "type": "child_of", "target": f"goal:{goal}"}
            )
        if goal:
            relations.append({"source": f"goal:{goal}", "type": "child_of", "target": "project:exampleproject"})
        for field, relation_type in relation_fields.items():
            for target in task.get(field) or []:
                relations.append({"source": task_id, "type": relation_type, "target": str(target)})
        for subsystem in task.get("subsystem") or []:
            relations.append({"source": task_id, "type": "belongs_to", "target": f"subsystem:{subsystem}"})
            relations.append(
                {
                    "source": f"subsystem:{subsystem}",
                    "type": "child_of",
                    "target": f"domain:{subsystem_domain(str(subsystem))}",
                }
            )

    focus_event_ids = {int(hit["id"]) for hit in reflex["recall"]["hits"] if hit.get("id") is not None}
    event_relation_fields = {
        "related_event_ids": "related_to",
        "contradicts_event_ids": "contradicts",
        "verifies_event_ids": "verifies",
        "caused_by_event_ids": "caused_by",
        "supersedes_event_ids": "supersedes",
    }
    for event in events:
        event_id = int(event.get("id") or 0)
        details = event_details(event)
        targets_by_type = {
            relation_type: string_list(details.get(field))
            for field, relation_type in event_relation_fields.items()
        }
        target_ids = {
            int(target)
            for targets in targets_by_type.values()
            for target in targets
            if str(target).isdigit()
        }
        if event_id not in focus_event_ids and not target_ids.intersection(focus_event_ids):
            continue
        for relation_type, targets in targets_by_type.items():
            for target in targets:
                relations.append(
                    {
                        "source": f"event:{event_id}",
                        "type": relation_type,
                        "target": f"event:{target}",
                    }
                )
        task_id = event_task_id(event)
        if task_id:
            relations.append(
                {
                    "source": f"event:{event_id}",
                    "type": "advances",
                    "target": task_id,
                }
            )
    unique_relations: list[dict[str, str]] = []
    seen_relations: set[tuple[str, str, str]] = set()
    for relation in relations:
        key = (relation["source"], relation["type"], relation["target"])
        if key in seen_relations:
            continue
        seen_relations.add(key)
        unique_relations.append(relation)
    relations = unique_relations

    logical_chains = [
        task_logic_chain(task_by_id[task_id], events_by_task.get(task_id, []))
        for task_id in focus_task_ids
    ]
    epistemic = build_epistemic_state(events, reflex["recall"].get("expanded_terms") or [], limit)

    plan_items: list[dict[str, Any]] = []
    related_set = set(recall_task_ids)
    owned_set = {
        str(task.get("task_id") or "")
        for task in reflex["thread"]["owned_open_tasks"]
        if task.get("task_id")
    }
    recent_attention_ids = {
        str(item.get("task_id") or "")
        for item in reflex["attention"]["items"]
        if item.get("task_id")
    }
    for task_id, task in task_by_id.items():
        if task.get("status") == "complete":
            continue
        if (
            task.get("queue_state") == "recovery"
            and task_id not in related_set
            and task_id not in recent_attention_ids
        ):
            continue
        if task.get("status") in {"blocked", "failed"} and task_id not in related_set and task_id not in recent_attention_ids:
            continue
        dependency_states = [
            {
                "task_id": dependency,
                "status": (task_by_id.get(dependency) or {}).get("status", "missing"),
            }
            for dependency in task.get("depends_on_task_ids") or []
        ]
        dependency_blocked = any(item["status"] != "complete" for item in dependency_states)
        score, reasons = task_plan_score(
            task,
            owned=task_id in owned_set,
            related=task_id in related_set,
            dependency_blocked=dependency_blocked,
        )
        cursor = task.get("operational_cursor")
        if not isinstance(cursor, dict):
            cursor = {}
        plan_items.append(
            {
                "task_id": task_id,
                "status": task.get("status") or "",
                "score": score,
                "score_reasons": reasons,
                "ready": not dependency_blocked,
                "dependencies": dependency_states,
                "scope": task.get("scope") or "",
                "risk_level": task.get("risk_level") or "",
                "requires_owner_go": task.get("scope") == "production-impact",
                "requires_fresh_evidence": True,
                "summary": cursor.get("summary") or task.get("summary") or "",
                "next_action": cursor.get("next_action")
                or task.get("next_action")
                or "Reconcile live state, then continue or close the task.",
                "done_when": task.get("done_when") or "Post-check is recorded and no required work remains.",
                "operational_cursor": cursor,
            }
        )
    plan_items.sort(key=lambda item: (int(item["score"]), item["task_id"]), reverse=True)

    matrix = build_task_matrix(tasks, max(limit, 20))
    goal_ids = {str(task.get("goal_id")) for task in task_by_id.values() if task.get("goal_id")}
    roadmap_item_ids = {
        str(task.get("roadmap_item_id")) for task in task_by_id.values() if task.get("roadmap_item_id")
    }
    hierarchy = {
        "mission_root": "project:exampleproject",
        "task_count": len(task_by_id),
        "goal_count": len(goal_ids),
        "roadmap_item_count": len(roadmap_item_ids),
        "domain_count": len(matrix["domain_status"]),
        "subsystem_count": matrix["subsystem_count"],
        "explicit_parent_task_count": sum(bool(str(task.get("parent_task_id") or "")) for task in task_by_id.values()),
        "inferred_parent_task_count": sum(not str(task.get("parent_task_id") or "") for task in task_by_id.values()),
        "root_task_count": sum(not str(task.get("parent_task_id") or "") for task in task_by_id.values()),
        "linked_task_count": sum(bool(str(task.get("parent_task_id") or "")) for task in task_by_id.values()),
        "orphan_parent_count": len(orphan_parents),
        "orphan_parents": orphan_parents[:limit],
        "dependency_cycles": dependency_cycles(task_by_id, limit),
        "focus": [
            {
                "task_id": task_id,
                "goal_id": task_by_id[task_id].get("goal_id") or "",
                "roadmap_item_id": task_by_id[task_id].get("roadmap_item_id") or "",
                "parent_task_id": task_by_id[task_id].get("parent_task_id") or "",
                "effective_parent": task_by_id[task_id].get("parent_task_id")
                or (
                    f"roadmap:{task_by_id[task_id].get('roadmap_item_id')}"
                    if task_by_id[task_id].get("roadmap_item_id")
                    else ""
                )
                or (
                    f"goal:{task_by_id[task_id].get('goal_id')}"
                    if task_by_id[task_id].get("goal_id")
                    else ""
                )
                or f"subsystem:{(task_by_id[task_id].get('subsystem') or ['untagged'])[0]}",
                "children": parent_children.get(task_id, []),
                "depends_on": task_by_id[task_id].get("depends_on_task_ids") or [],
                "status": task_by_id[task_id].get("status") or "",
                "summary": task_by_id[task_id].get("summary") or "",
            }
            for task_id in focus_task_ids
        ],
    }
    node_counts = {
        "task": len(task_by_id),
        "event": len(events),
        "goal": len(goal_ids),
        "roadmap_item": len(roadmap_item_ids),
        "domain": len(matrix["domain_status"]),
        "subsystem": matrix["subsystem_count"],
        "assertion": epistemic["assertion_count"],
        "evidence": sum(
            len(string_list(event_details(event).get("evidence_files")))
            for event in events
        ),
    }
    recovered_tasks = [
        {
            "task_id": task_id,
            "status": task_by_id[task_id].get("status") or "",
            "summary": task_by_id[task_id].get("summary") or "",
            "goal_id": task_by_id[task_id].get("goal_id") or "",
            "roadmap_item_id": task_by_id[task_id].get("roadmap_item_id") or "",
            "parent_task_id": task_by_id[task_id].get("parent_task_id") or "",
            "next_action": task_by_id[task_id].get("next_action") or "",
            "done_when": task_by_id[task_id].get("done_when") or "",
        }
        for task_id in focus_task_ids
    ]
    recovery_core = {
        "protocol": "exampleproject.action-log.concept-recovery/v1",
        "memory_source": "canonical-seed-action-log",
        "mission_root": hierarchy["mission_root"],
        "intent_fingerprint": reflex["recall"].get("query_fingerprint") or "",
        "focus_terms": reflex["recall"].get("terms") or [],
        "relevant_event_ids": sorted(focus_event_ids),
        "relevant_tasks": recovered_tasks,
        "relation_count": len(relations),
        "logical_chain_count": len(logical_chains),
        "known_unknowns": {
            "contradiction_count": epistemic["contradiction_count"],
            "stale_assertion_count": epistemic["stale_assertion_count"],
            "chain_gap_count": sum(len(chain["chain_gaps"]) for chain in logical_chains),
            "orphan_parent_count": hierarchy["orphan_parent_count"],
            "dependency_cycle_count": len(hierarchy["dependency_cycles"]),
        },
        "invariants": reflex["invariants"],
    }
    concept_recovery = {
        **recovery_core,
        "recovery_digest": "sha256:"
        + hashlib.sha256(
            json.dumps(
                recovery_core,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
    }
    # The deep Mind graph deliberately carries fuzzy global recall so the
    # agent can recover the wider project. Coordination is an action boundary:
    # only session ownership or an exact task ID may enter its blast radius.
    # Semantic words such as "access", "Integrity" or "bundle" are context,
    # never ambient evidence that a production task is being acted on.
    query_text = str(first(params, "q") or "").lower()
    task_id_boundary = r"[A-Za-z0-9._:@/-]"
    explicit_task_ids = [
        task_id
        for task_id in task_by_id
        if re.search(
            rf"(?<!{task_id_boundary}){re.escape(task_id.lower())}(?!{task_id_boundary})",
            query_text,
        )
    ]

    def task_neighbors(task_ids: list[str]) -> list[str]:
        relation_fields = (
            "depends_on_task_ids",
            "related_task_ids",
            "supersedes_task_ids",
            "blocks_task_ids",
        )
        selected = set(task_ids)
        for task_id in list(task_ids):
            task = task_by_id.get(task_id) or {}
            parent = str(task.get("parent_task_id") or "")
            if parent in task_by_id:
                selected.add(parent)
            for field in relation_fields:
                selected.update(
                    related
                    for related in task.get(field) or []
                    if str(related) in task_by_id
                )
        for candidate_id, task in task_by_id.items():
            if str(task.get("parent_task_id") or "") in selected:
                selected.add(candidate_id)
                continue
            if any(
                selected.intersection(str(item) for item in task.get(field) or [])
                for field in relation_fields
            ):
                selected.add(candidate_id)
        return sorted(selected)

    coordination_recall_task_ids = (
        task_neighbors(explicit_task_ids) if explicit_task_ids else []
    )

    coordination_focus_task_ids: list[str] = []
    for task in reflex["thread"]["owned_open_tasks"]:
        task_id = str(task.get("task_id") or "")
        if task_id and task_id not in coordination_focus_task_ids:
            coordination_focus_task_ids.append(task_id)
    for task_id in coordination_recall_task_ids:
        if (
            task_id in task_by_id
            and task_coordination_active(task_by_id[task_id])
            and task_id not in coordination_focus_task_ids
        ):
            coordination_focus_task_ids.append(task_id)
    coordination_tasks = [
        task_by_id[task_id]
        for task_id in coordination_focus_task_ids
        if task_id in task_by_id and task_coordination_active(task_by_id[task_id])
    ]
    coordination_task_ids = {
        str(task.get("task_id") or "")
        for task in coordination_tasks
        if task.get("task_id")
    }
    recovery_task_ids = {
        task_id
        for task_id in coordination_recall_task_ids
        if task_id in task_by_id
        and not task_coordination_active(task_by_id[task_id])
    }
    def coordination_values(value: object) -> list[str]:
        raw_items = value if isinstance(value, list) else [value]
        normalized: list[str] = []
        for item in raw_items:
            for part in re.split(r"[,;]+", str(item or "")):
                text = part.strip().strip("[]'\"").strip()
                if text and text not in normalized:
                    normalized.append(text)
        return normalized

    affected_subsystems = {
        subsystem
        for task in coordination_tasks
        for subsystem in coordination_values(task.get("subsystem"))
    }
    affected_hosts = {
        host
        for task in coordination_tasks
        for host in coordination_values(task.get("touched_hosts"))
    }
    lock_scope_task_ids = coordination_task_ids.union(explicit_task_ids)
    relevant_task_conflicts = [
        conflict
        for conflict in task_state.get("conflicts") or []
        if coordination_task_ids.intersection(
            str(task_id) for task_id in conflict.get("task_ids") or []
        )
    ]
    relevant_active_locks = [
        lock
        for lock in lock_state.get("locks") or []
        if lock.get("status") == "active"
        and (
            str(lock.get("task_id") or "") in lock_scope_task_ids
            or affected_subsystems.intersection(
                str(subsystem) for subsystem in lock.get("subsystem") or []
            )
            or affected_hosts.intersection(
                str(host) for host in lock.get("target_hosts") or []
            )
        )
    ]
    relevant_active_lock_ids = {
        str(lock.get("lock_id") or "")
        for lock in relevant_active_locks
        if lock.get("lock_id")
    }
    relevant_lock_conflicts = [
        conflict
        for conflict in lock_state.get("conflicts") or []
        if (
            str(conflict.get("subsystem") or "") in affected_subsystems
            or relevant_active_lock_ids.intersection(
                str(lock_id) for lock_id in conflict.get("lock_ids") or []
            )
        )
    ]
    relevant_dependency_cycles = [
        cycle
        for cycle in hierarchy["dependency_cycles"]
        if coordination_task_ids.intersection(str(task_id) for task_id in cycle)
    ]
    coordination_core = {
        "protocol": "exampleproject.action-log.coordination-projection/v1",
        "session_id": session_id,
        "lease_observed_utc": task_state.get("lease_observed_utc") or "",
        "lease_stale_after_hours": task_state.get("stale_after_hours"),
        "owned_task_ids": sorted(
            str(task.get("task_id") or "")
            for task in reflex["thread"]["owned_open_tasks"]
            if task.get("task_id")
        ),
        "related_task_ids": sorted(
            coordination_task_ids
            - {
                str(task.get("task_id") or "")
                for task in reflex["thread"]["owned_open_tasks"]
                if task.get("task_id")
            }
        ),
        "recovery_task_ids": sorted(recovery_task_ids),
        "recovery_tasks": [
            {
                "task_id": task_id,
                "semantic_status": task_by_id[task_id].get("semantic_status")
                or task_by_id[task_id].get("status")
                or "",
                "lease_state": task_by_id[task_id].get("lease_state") or "",
                "queue_state": task_by_id[task_id].get("queue_state") or "",
                "last_observed_utc": task_by_id[task_id].get("activity_observed_utc")
                or "",
            }
            for task_id in sorted(recovery_task_ids)
        ],
        "affected_subsystems": sorted(affected_subsystems),
        "affected_hosts": sorted(affected_hosts),
        "scope_classes": sorted(
            {scope_category(task.get("scope")) for task in coordination_tasks}
        ),
        "risk_classes": sorted(
            {risk_category(task.get("risk_level")) for task in coordination_tasks}
        ),
        "task_conflicts": relevant_task_conflicts,
        "lock_conflicts": relevant_lock_conflicts,
        "dependency_cycles": relevant_dependency_cycles,
        "active_locks": [
            {
                "lock_id": lock.get("lock_id") or "",
                "task_id": lock.get("task_id") or "",
                "subsystem": lock.get("subsystem") or [],
                "target_hosts": lock.get("target_hosts") or [],
                "session_id": lock.get("owner_session_id") or "",
            }
            for lock in relevant_active_locks
        ],
        "production_scope_present": any(
            str(task.get("scope") or "") == "production-impact"
            for task in coordination_tasks
        ),
        "owner_go_required": any(
            str(task.get("scope") or "") == "production-impact"
            for task in coordination_tasks
        ),
        "stop_required": bool(
            relevant_task_conflicts
            or relevant_lock_conflicts
            or relevant_dependency_cycles
        ),
    }
    coordination = {
        **coordination_core,
        "coordination_digest": "sha256:"
        + hashlib.sha256(
            json.dumps(
                coordination_core,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
    }
    result: dict[str, Any] = {
        "ok": True,
        "service_version": SERVICE_VERSION,
        "memory_contract_version": MEMORY_CONTRACT_VERSION,
        "generated_utc": utc_now(),
        "memory_source": "canonical-seed-action-log",
        "snapshot": {
            "event_count": len(events),
            "event_cursor": snapshot_event_id,
        },
        "home_record_count": 0,
        "production_authority": False,
        "session_id": session_id,
        "focus_terms": reflex["recall"].get("terms") or [],
        "node_counts": node_counts,
        "concept_recovery": concept_recovery,
        "coordination": coordination,
        "matrix": matrix,
        "hierarchy": hierarchy,
        "relations": relations,
        "logical_chains": logical_chains,
        "epistemic": epistemic,
        "plan": {
            "item_count": len(plan_items),
            "ready_count": sum(bool(item["ready"]) for item in plan_items),
            "blocked_by_dependency_count": sum(not bool(item["ready"]) for item in plan_items),
            "items": plan_items[: max(limit, 20)],
        },
        "attention": reflex["attention"],
        "global_state": reflex["global_state"],
        "memory_quality": reflex["memory_quality"],
        "recall": reflex["recall"],
        "invariants": reflex["invariants"],
        "reasoning_order": reflex["reasoning_order"],
        "reflex_context": reflex["context_text"],
    }
    segment_coverage = reflex["recall"].get("segment_coverage")
    if isinstance(segment_coverage, dict):
        result["segment_coverage"] = segment_coverage
    result["capsule"] = build_synaptic_capsule(
        session_id=session_id,
        reflex=reflex,
        relations=relations,
        projection="current",
    )
    result["context_text"] = build_mind_context(result)
    projection_core = {
        key: result[key]
        for key in (
            "service_version",
            "memory_contract_version",
            "memory_source",
            "snapshot",
            "home_record_count",
            "production_authority",
            "focus_terms",
            "node_counts",
            "concept_recovery",
            "coordination",
            "matrix",
            "hierarchy",
            "relations",
            "logical_chains",
            "epistemic",
            "plan",
            "attention",
            "global_state",
            "memory_quality",
            "recall",
            "invariants",
            "reasoning_order",
            "capsule",
        )
    }
    if "segment_coverage" in result:
        projection_core["segment_coverage"] = result["segment_coverage"]
    projection_digest = "sha256:" + hashlib.sha256(
        json.dumps(
            projection_core,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    receipt_core = {
        "protocol": MIND_PROJECTION_PROTOCOL,
        "event_count": len(events),
        "event_cursor": snapshot_event_id,
        "intent_fingerprint": reflex["recall"].get("query_fingerprint") or "",
        "projection_digest": projection_digest,
        "home_record_count": 0,
        "production_authority": False,
    }
    if "segment_coverage" in result:
        receipt_core["segment_count"] = result["segment_coverage"]["segment_count"]
        receipt_core["segment_coverage_digest"] = result["segment_coverage"][
            "coverage_digest"
        ]
    result["projection_digest"] = projection_digest
    result["receipt"] = {
        **receipt_core,
        "receipt_id": "sha256:"
        + hashlib.sha256(
            json.dumps(
                receipt_core,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
    }
    return result


def compact_mind(mind: dict[str, Any]) -> dict[str, Any]:
    """Return the working-memory projection used by hooks and CLI reflexes."""
    hierarchy = mind["hierarchy"]
    epistemic = mind["epistemic"]
    compact = {
        "ok": mind["ok"],
        "compact": True,
        "service_version": mind["service_version"],
        "memory_contract_version": mind["memory_contract_version"],
        "generated_utc": mind["generated_utc"],
        "memory_source": mind["memory_source"],
        "snapshot": mind["snapshot"],
        "home_record_count": mind["home_record_count"],
        "production_authority": mind["production_authority"],
        "projection_digest": mind["projection_digest"],
        "receipt": mind["receipt"],
        "capsule": mind.get("capsule") or {},
        "session_id": mind["session_id"],
        "focus_terms": mind["focus_terms"],
        "node_counts": mind["node_counts"],
        "concept_recovery": mind["concept_recovery"],
        "coordination": mind["coordination"],
        "matrix": {
            "domain_status": mind["matrix"]["domain_status"],
            "scope_status": mind["matrix"]["scope_status"],
            "risk_status": mind["matrix"]["risk_status"],
        },
        "hierarchy": {
            key: hierarchy[key]
            for key in (
                "mission_root",
                "task_count",
                "goal_count",
                "roadmap_item_count",
                "domain_count",
                "subsystem_count",
                "orphan_parent_count",
                "orphan_parents",
                "dependency_cycles",
            )
        },
        "logical_chains": [
            {
                "task_id": chain["task_id"],
                "status": chain["status"],
                "event_count": chain["event_count"],
                "last_event": chain["events"][-1] if chain["events"] else None,
                "chain_gaps": chain["chain_gaps"],
                "next_action": chain["next_action"],
                "done_when": chain["done_when"],
            }
            for chain in mind["logical_chains"]
        ],
        "plan": mind["plan"],
        "attention": mind["attention"],
        "global_state": mind["global_state"],
        "memory_quality": mind["memory_quality"],
        "recall": mind["recall"],
        "epistemic": {
            key: epistemic[key]
            for key in (
                "assertion_count",
                "active_assertion_count",
                "current_fact_count",
                "stale_assertion_count",
                "contradiction_count",
                "contradictions",
                "current_facts",
                "coverage_note",
            )
        },
        "invariants": mind["invariants"],
        "reasoning_order": mind["reasoning_order"],
        "context_text": mind["context_text"],
    }
    if "segment_coverage" in mind:
        compact["segment_coverage"] = mind["segment_coverage"]
    return compact


MUTATION_INTENT_RE = re.compile(
    r"(?i)(?:\b(?:apply|deploy|restart|reload|write|edit|delete|remove|create|install|upgrade|fix)\b"
    r"|(?:выполняй|примен|разверн|перезапуст|измени|исправ|удали|создай|установ|обнови|почини))"
)
PRODUCTION_INTENT_RE = re.compile(
    r"(?i)(?:\b(?:production|prod|live|switch|router|firewall|billing|payment|database|service)\b"
    r"|(?:прод|боев|свитч|коммутатор|маршрутизатор|фаервол|биллинг|платеж|баз[ауеы]|сервис))"
)


def bootstrap_safety_mode(query: str) -> dict[str, Any]:
    mutation = bool(MUTATION_INTENT_RE.search(query or ""))
    production = bool(PRODUCTION_INTENT_RE.search(query or ""))
    if mutation and production:
        mode = "production"
    elif mutation:
        mode = "elevated"
    else:
        mode = "normal"
    return {
        "mode": mode,
        "mutation_intent": mutation,
        "production_area_intent": production,
        "authoritative": False,
        "production_requirements": ["owner_go", "task_id", "rollback", "precheck", "postcheck"]
        if mode == "production"
        else [],
    }


def compact_memory_hit(hit: dict[str, Any]) -> dict[str, Any]:
    freshness = hit.get("freshness") if isinstance(hit.get("freshness"), dict) else {}
    return {
        "event_id": int(hit.get("id") or 0),
        "task_id": hit.get("task_id") or "",
        "summary": str(hit.get("summary") or "")[:300],
        "truth_status": hit.get("truth_status") or "unknown",
        "confidence": hit.get("confidence") or "unknown",
        "stale": bool(freshness.get("stale")),
        "score": int(hit.get("score") or 0),
        "matched_terms": list(hit.get("matched_terms") or [])[:6],
    }


def compact_attention_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "priority": int(item.get("priority") or 0),
        "kind": item.get("kind") or "",
        "reason": item.get("reason") or "",
        "status": item.get("status") or "",
        "task_id": item.get("task_id") or "",
        "task_ids": list(item.get("task_ids") or [])[:5],
        "owner_session_id": item.get("owner_session_id") or "",
        "preempts_task_ids": list(item.get("preempts_task_ids") or [])[:5],
        "resume_after_task_ids": list(item.get("resume_after_task_ids") or [])[:5],
        "target_thread_ids": list(item.get("target_thread_ids") or [])[:5],
        "summary": str(item.get("summary") or "")[:280],
        "next_action": str(item.get("next_action") or "")[:280],
    }


def compact_bootstrap_task(task: dict[str, Any]) -> dict[str, Any]:
    """Return only the task fields needed on the per-turn hot path."""
    cursor = task.get("operational_cursor") if isinstance(task.get("operational_cursor"), dict) else {}
    return {
        "task_id": task.get("task_id") or "",
        "status": task.get("status") or "",
        "semantic_status": task.get("semantic_status") or task.get("status") or "",
        "lease_state": task.get("lease_state") or "",
        "queue_state": task.get("queue_state") or "",
        "attention_class": task.get("attention_class") or "",
        "session_id": task.get("session_id") or "",
        "activity_event_id": int(task.get("activity_event_id") or 0),
        "stale": bool(task.get("stale")),
        "summary": str(cursor.get("summary") or task.get("summary") or "")[:250],
        "next_action": str(cursor.get("next_action") or task.get("next_action") or "")[:250],
    }


def select_bootstrap_tasks(reflex: dict[str, Any], query: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    thread = reflex.get("thread") if isinstance(reflex.get("thread"), dict) else {}
    owned = list(thread.get("owned_open_tasks") or [])
    targeted = list(thread.get("targeted_open_tasks") or [])
    owned_paused = list(thread.get("owned_paused_tasks") or [])
    related = list(thread.get("related_open_tasks") or [])
    related_ids = [str(hit.get("task_id") or "") for hit in (reflex.get("recall") or {}).get("hits") or []]

    def ranked(tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_id: dict[str, dict[str, Any]] = {}
        for task in tasks:
            task_id = str(task.get("task_id") or "")
            if task_id:
                by_id[task_id] = task
        return sorted(
            by_id.values(),
            key=lambda task: (
                str(task.get("task_id") or "") in related_ids,
                str(task.get("attention_class") or "") == "primary",
                int(task.get("activity_event_id") or 0),
            ),
            reverse=True,
        )

    # Thread ownership is the routing boundary. Free-text recall may rank
    # tasks inside one tier, but it must never promote an unrelated foreign
    # task over the current thread's own work. An explicit target-thread
    # handoff is the only foreign open-task tier above paused owned work.
    tiers = [ranked(owned), ranked(targeted), ranked(owned_paused), ranked(related)]
    primary_pool = next((tier for tier in tiers if tier), [])
    primary = primary_pool[0] if primary_pool else None

    related_tasks: list[dict[str, Any]] = []
    seen = {str(primary.get("task_id") or "")} if primary else set()
    for tier in [tiers[0], tiers[1], tiers[3], tiers[2]]:
        for task in tier:
            task_id = str(task.get("task_id") or "")
            if not task_id or task_id in seen:
                continue
            seen.add(task_id)
            related_tasks.append(task)
            if len(related_tasks) >= 3:
                return primary, related_tasks
    return primary, related_tasks


def build_bootstrap_context(
    *,
    cursor: int,
    primary: dict[str, Any] | None,
    attention: list[dict[str, Any]],
    memory: list[dict[str, Any]],
    safety: dict[str, Any],
    max_chars: int = 1200,
) -> str:
    lines = [f"exampleproject BOOTSTRAP v1 cursor={cursor}"]
    if primary:
        lines.append(
            "PRIMARY: {task_id} [{status}] — {next_action}".format(
                task_id=primary.get("task_id") or "unknown",
                status=primary.get("status") or "unknown",
                next_action=str(primary.get("next_action") or primary.get("summary") or "")[:280],
            )
        )
    else:
        lines.append("PRIMARY: no matching open task; use bounded discovery before creating lifecycle state.")
    if attention:
        lines.append("ATTENTION:")
        for item in attention[:3]:
            if item.get("reason") == "pending-preemption":
                targets = ",".join(item.get("preempts_task_ids") or []) or "active-owner"
                lines.append(
                    f"- PREEMPT P{item.get('priority')}: {item.get('task_id')} waits for {targets}; "
                    f"checkpoint, report, release lock, then hand off."
                )
            else:
                lines.append(f"- {item.get('kind')}: {str(item.get('summary') or '')[:240]}")
    if memory:
        lines.append("RELEVANT MEMORY (lead, not live proof):")
        for item in memory[:3]:
            lines.append(f"- #{item.get('event_id')} {str(item.get('summary') or '')[:240]}")
    lines.append(
        f"SAFETY: {safety.get('mode')}; production memory never replaces scoped GO, rollback and live pre/post checks."
    )
    return "\n".join(lines)[:max_chars]


def build_bootstrap_snapshot(event_count_value: int, event_cursor_value: int) -> dict[str, Any]:
    """Return a content-free, digest-bound identity for the canonical log head."""

    core = {
        "protocol": BOOTSTRAP_SNAPSHOT_PROTOCOL,
        "service": "codex-action-log",
        "service_version": SERVICE_VERSION,
        "memory_contract_version": MEMORY_CONTRACT_VERSION,
        "event_count": int(event_count_value),
        "event_cursor": int(event_cursor_value),
        "append_only": True,
        "update_enabled": False,
        "delete_enabled": False,
        "home_record_count": 0,
        "production_authority": False,
    }
    digest = hashlib.sha256(
        json.dumps(
            core,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {**core, "snapshot_digest": f"sha256:{digest}"}


def build_bootstrap(params: dict[str, list[str]]) -> dict[str, Any]:
    query = first(params, "q") or ""
    session_id = (first(params, "session_id") or "").strip()
    stale_after_hours = TASK_LEASE_STALE_AFTER_HOURS
    event_count_now, event_cursor_now = event_store_signature()
    projection_epoch = int(dt.datetime.now(dt.UTC).timestamp() // 60)
    context_limit = min(1500, max(400, parse_int_param(first(params, "context_limit"), 1200, 1)))
    intent_fingerprint = hashlib.sha256(
        json.dumps(intent_terms(query), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]
    previous_hash = (first(params, "previous_hash") or "").strip().lower()
    previous_event_cursor = parse_int_param(first(params, "previous_event_cursor"), 0, 0)
    previous_intent_fingerprint = (first(params, "previous_intent_fingerprint") or "").strip().lower()
    previous_projection_epoch = parse_int_param(
        first(params, "previous_projection_epoch"), 0, 0
    )
    head_snapshot = build_bootstrap_snapshot(event_count_now, event_cursor_now)
    if (
        previous_hash
        and previous_event_cursor == event_cursor_now
        and previous_intent_fingerprint == intent_fingerprint
        and previous_projection_epoch == projection_epoch
    ):
        return {
            "ok": True,
            "schema": "exampleproject.bootstrap.v1",
            "service_version": SERVICE_VERSION,
            "generated_utc": utc_now(),
            "event_cursor": event_cursor_now,
            "event_count": event_count_now,
            "snapshot": head_snapshot,
            "projection_epoch": projection_epoch,
            "capsule_hash": previous_hash,
            "intent_fingerprint": intent_fingerprint,
            "changed": False,
            "delta": "unchanged",
            "session_id": session_id,
            "context_text": "",
        }

    snapshot = projection_snapshot()
    reflex_params = {
        "q": [query],
        "session_id": [session_id],
        "limit": ["6"],
        "stale_after_hours": [str(stale_after_hours)],
    }
    reflex = build_reflex(
        reflex_params,
        task_state=snapshot["tasks"],
        lock_state=snapshot["locks"],
        events=snapshot["events"],
    )
    primary_raw, related_raw = select_bootstrap_tasks(reflex, query)
    primary = compact_bootstrap_task(primary_raw) if primary_raw else None
    related = [compact_bootstrap_task(task) for task in related_raw[:1]]
    attention = [compact_attention_item(item) for item in list((reflex.get("attention") or {}).get("items") or [])[:3]]
    memory = [compact_memory_hit(hit) for hit in list((reflex.get("recall") or {}).get("hits") or [])[:5]]
    safety = bootstrap_safety_mode(query)
    capsule_core = {
        "cursor": snapshot["event_cursor"],
        "intent": intent_fingerprint,
        "primary": primary,
        "related": related,
        "attention": attention,
        "memory": memory,
        "safety": safety,
    }
    capsule_hash = hashlib.sha256(
        json.dumps(capsule_core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    changed = capsule_hash != previous_hash
    context_text = build_bootstrap_context(
        cursor=snapshot["event_cursor"],
        primary=primary,
        attention=attention,
        memory=memory,
        safety=safety,
        max_chars=context_limit,
    ) if changed else ""
    return {
        "ok": True,
        "schema": "exampleproject.bootstrap.v1",
        "service_version": SERVICE_VERSION,
        "generated_utc": snapshot["generated_utc"],
        "event_cursor": snapshot["event_cursor"],
        "event_count": snapshot["event_count"],
        "snapshot": build_bootstrap_snapshot(
            snapshot["event_count"], snapshot["event_cursor"]
        ),
        "projection_epoch": projection_epoch,
        "capsule_hash": capsule_hash,
        "intent_fingerprint": intent_fingerprint,
        "changed": changed,
        "delta": "full" if changed else "unchanged",
        "session_id": session_id,
        "primary_task": primary,
        "related_tasks": related,
        "attention": attention,
        "memory": memory,
        "safety": safety,
        "counts": {
            "open_tasks": int(snapshot["tasks"].get("open_count") or 0),
            "pending_tasks": int(snapshot["tasks"].get("pending_count") or 0),
            "paused_tasks": int(snapshot["tasks"].get("paused_count") or 0),
            "current_tasks": int(snapshot["tasks"].get("current_count") or 0),
            "recovery_tasks": int(snapshot["tasks"].get("recovery_count") or 0),
            "task_conflicts": int(snapshot["tasks"].get("conflict_count") or 0),
            "active_locks": int(snapshot["locks"].get("active_count") or 0),
            "lock_conflicts": int(snapshot["locks"].get("conflict_count") or 0),
        },
        "pagination": {
            "events": {"snapshot_event_id": snapshot["event_cursor"], "default_page_size": 50},
            "tasks": {"snapshot_event_id": snapshot["event_cursor"], "default_page_size": 20},
            "locks": {"snapshot_event_id": snapshot["event_cursor"], "default_page_size": 20},
        },
        "context_text": context_text,
    }


def build_context(params: dict[str, list[str]]) -> str:
    since_spec = first(params, "since") or "24h"
    limit = parse_limit(first(params, "limit"), 100)
    events = query_events({"since": [since_spec], "limit": [str(limit)], "q": params.get("q", [""])} )
    lines = [
        "Codex Action Log context",
        f"window: since={since_spec}, limit={limit}",
        f"events: {len(events)}",
        "",
    ]
    if not events:
        lines.append("No events found for this window.")
        return "\n".join(lines)
    for event in reversed(events):
        tags = event.get("tags") or []
        tag_text = f" tags={','.join(tags)}" if isinstance(tags, list) and tags else ""
        session = f" session={event['session_id']}" if event.get("session_id") else ""
        lines.append(
            f"- [{event['ts_utc']}] {event['level']} actor={event['actor']}{session} "
            f"action={event['action']}: {event['summary']}{tag_text}"
        )
        details = event.get("details")
        if details not in ({}, [], "", None):
            compact = json.dumps(details, ensure_ascii=False, separators=(",", ":"))
            if len(compact) > 700:
                compact = compact[:697] + "..."
            lines.append(f"  details={compact}")
    return "\n".join(lines)


def first(params: dict[str, list[str]], name: str) -> str | None:
    values = params.get(name)
    return values[0] if values else None


def event_count() -> int:
    with open_db() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])


def html_event(event: dict[str, Any]) -> str:
    tags = event.get("tags") or []
    if isinstance(tags, list):
        tag_text = ", ".join(tags)
    else:
        tag_text = str(tags)
    details = event.get("details")
    details_text = ""
    if details not in ({}, [], "", None):
        details_text = json.dumps(details, ensure_ascii=False, indent=2)
    return f"""
    <article class="event level-{html.escape(str(event['level']))}">
      <header>
        <span class="ts">{html.escape(str(event['ts_utc']))}</span>
        <span class="level">{html.escape(str(event['level']))}</span>
        <span class="actor">{html.escape(str(event['actor']))}</span>
        <span class="action">{html.escape(str(event['action']))}</span>
      </header>
      <p>{html.escape(str(event['summary']))}</p>
      <div class="meta">session: {html.escape(str(event.get('session_id') or '-'))} | tags: {html.escape(tag_text or '-')}</div>
      {f"<pre>{html.escape(details_text)}</pre>" if details_text else ""}
    </article>
    """


def render_ui(params: dict[str, list[str]]) -> bytes:
    since = first(params, "since") or "24h"
    limit = first(params, "limit") or "100"
    q = first(params, "q") or ""
    events = query_events({"since": [since], "limit": [limit], "q": [q]})
    context = build_context({"since": [since], "limit": [limit], "q": [q]})
    query_string = urlencode({"since": since, "limit": limit, "q": q})
    saved = "saved" in params
    body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Codex Action Log</title>
  <style>
    :root {{ color-scheme: light; --bg:#f5f7fa; --panel:#fff; --line:#d8e0ea; --text:#1c2733; --muted:#607080; --accent:#1768ac; }}
    body {{ margin:0; font:14px/1.45 system-ui, -apple-system, Segoe UI, Arial, sans-serif; background:var(--bg); color:var(--text); }}
    main {{ max-width:1120px; margin:0 auto; padding:24px; }}
    h1 {{ margin:0 0 4px; font-size:24px; }}
    h2 {{ margin:0 0 12px; font-size:18px; }}
    .sub {{ color:var(--muted); margin:0 0 20px; }}
    section {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; margin:0 0 16px; box-shadow:0 1px 2px rgba(20,30,40,.04); }}
    label {{ display:block; font-weight:600; margin:0 0 4px; }}
    input, select, textarea {{ width:100%; box-sizing:border-box; border:1px solid #bcc8d4; border-radius:6px; padding:8px; font:inherit; background:#fff; }}
    textarea {{ min-height:88px; resize:vertical; }}
    .grid {{ display:grid; grid-template-columns:repeat(4, 1fr); gap:10px; }}
    .wide {{ grid-column:1 / -1; }}
    button, .button {{ display:inline-block; border:0; border-radius:6px; background:var(--accent); color:#fff; padding:9px 14px; font-weight:700; cursor:pointer; text-decoration:none; }}
    .filters {{ display:grid; grid-template-columns:120px 120px 1fr auto auto; gap:10px; align-items:end; }}
    .ok {{ padding:8px 10px; border:1px solid #8bd1a4; background:#ebfff2; border-radius:6px; margin-bottom:12px; color:#17632f; }}
    .event {{ border:1px solid var(--line); border-radius:8px; padding:10px 12px; margin:10px 0; background:#fff; }}
    .event header {{ display:flex; gap:8px; flex-wrap:wrap; color:var(--muted); font-size:12px; }}
    .level {{ color:#fff; background:#44566c; border-radius:999px; padding:1px 8px; }}
    .level-warning .level {{ background:#a86a00; }}
    .level-error .level {{ background:#b3261e; }}
    .level-debug .level {{ background:#56616c; }}
    .action {{ color:#0b5798; font-weight:700; }}
    .meta {{ color:var(--muted); font-size:12px; }}
    pre {{ overflow:auto; background:#f4f6f8; border:1px solid #e1e7ee; border-radius:6px; padding:10px; }}
    .context {{ min-height:260px; font-family:Consolas, Monaco, monospace; font-size:12px; }}
    @media (max-width:760px) {{ .grid,.filters {{ grid-template-columns:1fr; }} }}
  </style>
</head>
<body>
<main>
  <h1>Codex Action Log</h1>
  <p class="sub">Local SQLite journal for factual Codex/agent operational context. Do not log secrets.</p>
  {'<div class="ok">Event saved.</div>' if saved else ''}
  <section>
    <h2>Add Event</h2>
    <form method="post" action="/events">
      <div class="grid">
        <div><label>Actor</label><input name="actor" value="codex"></div>
        <div><label>Session</label><input name="session_id" placeholder="task/session id"></div>
        <div><label>Level</label><select name="level"><option>info</option><option>warning</option><option>error</option><option>debug</option></select></div>
        <div><label>Action</label><input name="action" value="note"></div>
        <div class="wide"><label>Summary</label><input name="summary" required placeholder="short factual note"></div>
        <div class="wide"><label>Details JSON or text</label><textarea name="details" placeholder='{{"command":"...", "result":"..."}}'></textarea></div>
        <div class="wide"><label>Tags</label><input name="tags" placeholder="setup, smoke-test"></div>
      </div>
      <p><button type="submit">Save event</button></p>
    </form>
  </section>
  <section>
    <h2>Recent Events</h2>
    <form class="filters" method="get" action="/">
      <div><label>Since</label><input name="since" value="{html.escape(since)}"></div>
      <div><label>Limit</label><input name="limit" value="{html.escape(limit)}"></div>
      <div><label>Search</label><input name="q" value="{html.escape(q)}"></div>
      <button type="submit">Apply</button>
      <a class="button" href="/api/context?{html.escape(query_string)}">Agent context</a>
    </form>
    {''.join(html_event(e) for e in events) if events else '<p>No events found.</p>'}
  </section>
  <section>
    <h2>Agent-Friendly Context</h2>
    <textarea class="context" readonly>{html.escape(context)}</textarea>
  </section>
</main>
</body>
</html>"""
    return body.encode("utf-8")


def validate_runtime_auth_boundary(
    host: str = HOST,
    token: str = TOKEN,
) -> None:
    """Reject an unauthenticated or non-loopback listener before side effects."""

    if host != "127.0.0.1":
        raise RuntimeError("Action Log requires exact IPv4 loopback binding")
    encoded = token.encode("utf-8")
    if not MIN_TOKEN_BYTES <= len(encoded) <= MAX_TOKEN_BYTES:
        raise RuntimeError("Action Log requires a strong local authentication token")
    if any(byte < 0x21 or byte > 0x7E for byte in encoded):
        raise RuntimeError("Action Log authentication token is invalid")


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler_class: type[BaseHTTPRequestHandler],
        bind_and_activate: bool = True,
        max_concurrent_requests: int = MAX_CONCURRENT_REQUESTS,
        request_timeout_seconds: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        self.max_concurrent_requests = max(1, min(int(max_concurrent_requests), 64))
        self.request_timeout_seconds = max(0.1, min(float(request_timeout_seconds), 60.0))
        self._request_slots = threading.BoundedSemaphore(self.max_concurrent_requests)
        self._request_lease_lock = threading.Lock()
        self._leased_requests: set[socket.socket] = set()
        super().__init__(server_address, request_handler_class, bind_and_activate)

    def acquire_request_slot(self, request: socket.socket) -> bool:
        if not self._request_slots.acquire(blocking=False):
            return False
        with self._request_lease_lock:
            self._leased_requests.add(request)
        return True

    def release_request_slot(self, request: socket.socket) -> bool:
        with self._request_lease_lock:
            if request not in self._leased_requests:
                return False
            self._leased_requests.remove(request)
        self._request_slots.release()
        return True

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        request, client_address = super().get_request()
        request.settimeout(self.request_timeout_seconds)
        return request, client_address

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if not self.acquire_request_slot(request):
            body = b'{"ok":false,"error":"server is busy"}\n'
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\n"
                    b"Content-Type: application/json; charset=utf-8\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                    + body
                )
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.release_request_slot(request)
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.release_request_slot(request)


class Handler(BaseHTTPRequestHandler):
    server_version = f"CodexActionLog/{SERVICE_VERSION}"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Mind/bootstrap queries may contain owner text.  Keep access evidence
        # structural and never persist a query string or JSON request body.
        safe_path = urlparse(getattr(self, "path", "")).path or "/"
        status = str(args[1]) if len(args) > 1 else "-"
        method = str(getattr(self, "command", "-") or "-")
        sys.stderr.write(
            f"{self.client_address[0]} - - "
            f"[{self.log_date_time_string()}] \"{method} {safe_path}\" {status}\n"
        )

    def auth_ok(self) -> bool:
        if not TOKEN:
            return True
        token = self.headers.get("X-Codex-Log-Token", "")
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth.removeprefix("Bearer ").strip()
        return hmac.compare_digest(token, TOKEN)

    def require_auth(self) -> bool:
        if self.auth_ok():
            return True
        self.close_connection = True
        self.send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "token required"})
        return False

    def send_json(self, status: HTTPStatus | int, payload: dict[str, Any]) -> None:
        # API clients consume structure, not pretty-printing. Compact encoding is
        # part of the v2.2 hot-path budget and preserves the exact JSON shape.
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, status: HTTPStatus | int, payload: str) -> None:
        body = payload.encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def request_body(self, maximum: int | None = None) -> bytes | None:
        try:
            length = parse_request_body_length(self.headers, maximum)
        except RequestBodyError as exc:
            self.close_connection = exc.close_connection
            self.send_json(exc.status, {"ok": False, "error": str(exc)})
            return None
        try:
            raw_body = self.rfile.read(length)
        except OSError:
            self.close_connection = True
            release_slot = getattr(self.server, "release_request_slot", None)
            if callable(release_slot):
                release_slot(self.request)
            self.send_json(HTTPStatus.REQUEST_TIMEOUT, {"ok": False, "error": "request body timed out"})
            return None
        if len(raw_body) != length:
            self.close_connection = True
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "request body is incomplete"})
            return None
        return raw_body

    def handle_expect_100(self) -> bool:
        try:
            maximum = (
                MIND_QUERY_MAX_REQUEST_BODY_BYTES
                if urlparse(self.path).path == "/api/mind"
                else None
            )
            parse_request_body_length(self.headers, maximum)
        except RequestBodyError as exc:
            self.close_connection = exc.close_connection
            self.send_json(exc.status, {"ok": False, "error": str(exc)})
            return False
        return super().handle_expect_100()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == "/api/health":
            self.send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "service": "codex-action-log",
                    "service_version": SERVICE_VERSION,
                    "source_path": str(SOURCE_PATH),
                    "source_sha256": runtime_source_sha256(),
                    "memory_contract_version": MEMORY_CONTRACT_VERSION,
                    "time_utc": utc_now(),
                    "db_path": str(DB_PATH),
                    "events": event_count(),
                    "token_auth": bool(TOKEN),
                    "append_only": True,
                    "delete_enabled": False,
                    "update_enabled": False,
                    "tasks_endpoint": True,
                    "locks_endpoint": True,
                    "reflex_endpoint": True,
                    "mind_endpoint": True,
                    "mind_post_endpoint": True,
                    "mind_query_segments": {
                        "protocol": MIND_SEGMENT_COVERAGE_PROTOCOL,
                        "max_segments": MIND_QUERY_MAX_SEGMENTS,
                        "max_segment_bytes": MIND_QUERY_MAX_SEGMENT_BYTES,
                        "max_utf8_bytes": MIND_QUERY_MAX_UTF8_BYTES,
                        "max_request_body_bytes": MIND_QUERY_MAX_REQUEST_BODY_BYTES,
                    },
                    "bootstrap_endpoint": True,
                    "task_accept_endpoint": True,
                    "cursor_pagination": True,
                    "event_uid_filter": True,
                    "max_request_body_bytes": MAX_REQUEST_BODY_BYTES,
                    "max_concurrent_requests": MAX_CONCURRENT_REQUESTS,
                    "request_timeout_seconds": REQUEST_TIMEOUT_SECONDS,
                },
            )
            return
        if parsed.path == "/api/events":
            if not self.require_auth():
                return
            if any(key in params for key in ("page_size", "snapshot_event_id")):
                self.send_json(HTTPStatus.OK, query_events_page(params))
            else:
                self.send_json(HTTPStatus.OK, {"ok": True, "events": query_events(params)})
            return
        if parsed.path == "/api/tasks":
            if not self.require_auth():
                return
            if any(key in params for key in ("page_size", "cursor", "snapshot_event_id")):
                self.send_json(HTTPStatus.OK, build_tasks_page(params))
            else:
                self.send_json(HTTPStatus.OK, build_tasks(params))
            return
        if parsed.path == "/api/locks":
            if not self.require_auth():
                return
            if any(key in params for key in ("page_size", "cursor", "snapshot_event_id")):
                self.send_json(HTTPStatus.OK, build_locks_page(params))
            else:
                self.send_json(HTTPStatus.OK, build_locks(params))
            return
        if parsed.path == "/api/bootstrap":
            if not self.require_auth():
                return
            self.send_json(HTTPStatus.OK, build_bootstrap(params))
            return
        if parsed.path == "/api/reflex":
            if not self.require_auth():
                return
            reflex = build_reflex(params)
            if (first(params, "format") or "").lower() in {"text", "context"}:
                self.send_text(HTTPStatus.OK, reflex["context_text"])
            else:
                self.send_json(HTTPStatus.OK, reflex)
            return
        if parsed.path == "/api/mind":
            if not self.require_auth():
                return
            if "q_segments" in params:
                self.send_json(
                    HTTPStatus.BAD_REQUEST,
                    {
                        "ok": False,
                        "error": "q_segments is only supported by JSON POST /api/mind",
                    },
                )
                return
            try:
                mind = build_mind(params)
            except ValueError as exc:
                self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
                return
            if (first(params, "format") or "").lower() in {"text", "context"}:
                self.send_text(HTTPStatus.OK, mind["context_text"])
            else:
                self.send_json(HTTPStatus.OK, compact_mind(mind) if parse_bool(first(params, "compact"), False) else mind)
            return
        if parsed.path == "/api/context":
            if not self.require_auth():
                return
            self.send_text(HTTPStatus.OK, build_context(params))
            return
        if parsed.path == "/":
            if not self.require_auth():
                return
            body = render_ui(params)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        json_query_paths = {"/api/mind"}
        if parsed.path not in {
            "/api/events",
            "/api/tasks/accept",
            "/events",
            "/ui/events",
            *json_query_paths,
        }:
            self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})
            return
        if not self.require_auth():
            return
        content_type = self.headers.get("Content-Type", "")
        media_type = content_type.partition(";")[0].strip().lower()
        if (
            parsed.path in {"/api/events", "/api/tasks/accept", *json_query_paths}
            and media_type != "application/json"
        ):
            self.close_connection = True
            self.send_json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"ok": False, "error": "use application/json"})
            return
        raw_body = self.request_body(
            MIND_QUERY_MAX_REQUEST_BODY_BYTES
            if parsed.path == "/api/mind"
            else None
        )
        if raw_body is None:
            return
        try:
            if parsed.path in {"/api/events", "/api/tasks/accept", *json_query_paths}:
                payload = json.loads(raw_body.decode("utf-8") or "{}")
            else:
                form = parse_qs(raw_body.decode("utf-8"), keep_blank_values=True)
                payload = {key: values[0] if values else "" for key, values in form.items()}
            if not isinstance(payload, dict):
                raise TypeError("payload must be an object")
            if parsed.path in json_query_paths:
                params = json_query_params(payload, path=parsed.path)
                result = build_mind(params)
                if parse_bool(first(params, "compact"), False):
                    result = compact_mind(result)
                self.send_json(HTTPStatus.OK, result)
                return
            event = accept_task(payload) if parsed.path == "/api/tasks/accept" else insert_event(payload)
        except Exception as exc:  # noqa: BLE001 - keep API self-contained and explicit.
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        if parsed.path in {"/api/events", "/api/tasks/accept"}:
            self.send_json(HTTPStatus.CREATED, event)
        else:
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/?saved=1")
            self.end_headers()

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/api/events":
            self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})
            return
        self.send_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {
                "ok": False,
                "error": "append-only Action Log: DELETE is not supported",
            },
        )


def main() -> None:
    validate_runtime_auth_boundary(HOST, TOKEN)
    ensure_db()
    if PID_FILE:
        pid_path = Path(PID_FILE)
        pid_path.parent.mkdir(parents=True, exist_ok=True)
        pid_path.write_text(str(os.getpid()), encoding="ascii")

        def cleanup_pid() -> None:
            try:
                if pid_path.read_text(encoding="ascii").strip() == str(os.getpid()):
                    pid_path.unlink(missing_ok=True)
            except OSError:
                pass

        atexit.register(cleanup_pid)

    server = BoundedThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Codex Action Log listening on http://{HOST}:{PORT}")
    print(f"Database: {DB_PATH}")
    print(f"Token auth: {'enabled' if TOKEN else 'disabled'}")
    server.serve_forever()


if __name__ == "__main__":
    main()
