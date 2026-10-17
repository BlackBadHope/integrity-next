#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Shared, dependency-free primitives for the Integrity memory-plane P0."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import contextlib
import fcntl
import ipaddress
import hashlib
import json
import os
import sqlite3
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterator, Mapping


REQUIRED_APPEND_ONLY_TRIGGERS = {
    "events_append_only_no_delete",
    "events_append_only_no_update",
}
ACTION_LOG_READER_HEADER = "X-Codex-Log-Token"
ACTION_LOG_READER_TOKEN_ENV = "CODEX_LOG_TOKEN"
MAX_ACTION_LOG_READER_TOKEN_BYTES = 4_096


def require_action_log_reader_token(value: object) -> str:
    """Require one exact visible-ASCII Action Log credential."""

    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_ACTION_LOG_READER_TOKEN_BYTES
        or any(not 0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise RuntimeError(
            "Action Log reader authentication token is required before network I/O"
        )
    return value


def action_log_reader_headers(
    environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build the sole admitted reader header without normalizing its value."""

    source = os.environ if environment is None else environment
    return {
        ACTION_LOG_READER_HEADER: require_action_log_reader_token(
            source.get(ACTION_LOG_READER_TOKEN_ENV)
        )
    }


def validate_action_log_reader_url(value: object) -> str:
    """Accept only plain HTTP to an exact loopback endpoint."""

    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(not 0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise RuntimeError("Action Log reader URL is invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port or 80
    except ValueError as exc:
        raise RuntimeError("Action Log reader URL is invalid") from exc
    if (
        parsed.scheme != "http"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or not 1 <= port <= 65_535
    ):
        raise RuntimeError("Action Log reader URL must be plain loopback HTTP")
    hostname = parsed.hostname
    if hostname is None or "%" in hostname:
        raise RuntimeError("Action Log reader URL must be plain loopback HTTP")
    if hostname.casefold() == "localhost":
        rendered_host = "localhost"
    else:
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError as exc:
            raise RuntimeError("Action Log reader URL forbids DNS resolution") from exc
        if not address.is_loopback:
            raise RuntimeError("Action Log reader URL must be loopback-only")
        rendered_host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return f"http://{rendered_host}:{port}"


class DirectHttpTransportError(RuntimeError):
    pass


class _DenyDirectRedirects(urllib.request.HTTPRedirectHandler):
    """Deny every redirect before protected headers can be copied."""

    def _deny(self, _request, response, _code, _message, _headers):
        response.close()
        raise DirectHttpTransportError(
            "authenticated direct HTTP redirect is forbidden"
        )

    http_error_301 = _deny
    http_error_302 = _deny
    http_error_303 = _deny
    http_error_307 = _deny
    http_error_308 = _deny


def open_direct_http_request(request, *, timeout: float):
    """Open one direct request with no ambient proxy or redirect authority."""

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _DenyDirectRedirects(),
    )
    return opener.open(request, timeout=timeout)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_json(path: Path, value: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonical_json(value))
            handle.write(b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


@contextlib.contextmanager
def exclusive_lock(path: Path, wait_seconds: float = 0) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="ascii") as handle:
        deadline = time.monotonic() + max(0, wait_seconds)
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"another memory-plane operation holds {path}") from exc
                time.sleep(min(0.1, max(0.01, deadline - time.monotonic())))
        yield


def readonly_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True, timeout=30)
    connection.execute("PRAGMA busy_timeout=30000")
    return connection


def snapshot_connection(path: Path) -> sqlite3.Connection:
    """Open a live WAL database for a read transaction without allowing SQL writes.

    SQLite may need write access to its WAL shared-memory coordination files even
    when every application statement is read-only.  A URI ``mode=ro`` connection
    therefore is not sufficient inside a hardened systemd sandbox.  ``query_only``
    lets SQLite coordinate WAL state while rejecting INSERT/UPDATE/DELETE.
    """
    connection = sqlite3.connect(path, timeout=30)
    connection.execute("PRAGMA busy_timeout=30000")
    connection.execute("PRAGMA query_only=ON")
    enabled = int(connection.execute("PRAGMA query_only").fetchone()[0])
    if enabled != 1:
        connection.close()
        raise RuntimeError("SQLite query_only guard did not activate")
    return connection


def schema_digest(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        "SELECT type, name, tbl_name, COALESCE(sql, '') "
        "FROM sqlite_master ORDER BY type, name, tbl_name"
    )
    return sha256_bytes(canonical_json([list(row) for row in rows]))


def row_digest(connection: sqlite3.Connection, first_id: int = 0, last_id: int | None = None) -> str:
    columns = [str(row[1]) for row in connection.execute("PRAGMA table_info(events)")]
    if not columns:
        raise RuntimeError("events table is missing")
    quoted = ",".join('"' + item.replace('"', '""') + '"' for item in columns)
    query = f"SELECT {quoted} FROM events WHERE id > ?"
    params: list[Any] = [first_id]
    if last_id is not None:
        query += " AND id <= ?"
        params.append(last_id)
    query += " ORDER BY id"
    digest = hashlib.sha256()
    digest.update(canonical_json({"columns": columns}))
    digest.update(b"\n")
    for row in connection.execute(query, params):
        encoded = canonical_json(list(row))
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def database_facts(connection: sqlite3.Connection) -> dict[str, Any]:
    event_count = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
    event_cursor = int(connection.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0])
    sequence_row = connection.execute(
        "SELECT seq FROM sqlite_sequence WHERE name = 'events'"
    ).fetchone()
    triggers = sorted(
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='events'"
        )
    )
    quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
    return {
        "event_count": event_count,
        "event_cursor": event_cursor,
        "sqlite_sequence": int(sequence_row[0]) if sequence_row else 0,
        "quick_check": quick_check,
        "schema_sha256": schema_digest(connection),
        "row_sha256": row_digest(connection, last_id=event_cursor),
        "append_only_triggers": triggers,
        "append_only_ok": REQUIRED_APPEND_ONLY_TRIGGERS.issubset(triggers),
    }


def safe_copy(source: Path, destination: Path, mode: int = 0o400) -> str:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with source.open("rb") as src, os.fdopen(fd, "wb") as dst:
            for block in iter(lambda: src.read(1024 * 1024), b""):
                dst.write(block)
            dst.flush()
            os.fsync(dst.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, destination)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    source_digest = sha256_file(source)
    destination_digest = sha256_file(destination)
    if destination_digest != source_digest:
        raise RuntimeError(f"copy readback digest mismatch: {destination}")
    return destination_digest
