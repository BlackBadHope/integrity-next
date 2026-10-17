#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build disposable incremental P1 FTS, graph, vector, and current-state projections."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import gzip
import hashlib
import json
import math
import os
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Iterable

from memory_plane_common import atomic_json, canonical_json, exclusive_lock, sha256_bytes
from p1_segment_verify import _object
from p1_segment_witness import PROTOCOL


PROJECTION_PROTOCOL = "integrity-memory-plane.p1-projection.v1"
VECTOR_DIMENSIONS = 256
TOKEN_RE = re.compile(r"[0-9A-Za-zА-Яа-яЁё_./:-]{2,}", re.UNICODE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("sync", "rebuild", "status"))
    parser.add_argument("--store-root", type=Path, default=Path(_integrity_value('path_5350cd670b63')))
    parser.add_argument("--projection-db", type=Path, default=Path(_integrity_value('path_1ba0c7fb8a53')))
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_1a518d87181f')))
    parser.add_argument("--lock", type=Path, default=Path("/run/integrity-memory-p1-projection/projector.lock"))
    return parser.parse_args()


def tokens(text: str) -> list[str]:
    return [match.group(0).casefold() for match in TOKEN_RE.finditer(text)]


def sparse_vector(text: str) -> tuple[list[list[float | int]], float]:
    values: dict[int, float] = {}
    for token in tokens(text):
        raw = hashlib.sha256(token.encode("utf-8")).digest()
        index = int.from_bytes(raw[:4], "big") % VECTOR_DIMENSIONS
        sign = 1.0 if raw[4] & 1 else -1.0
        values[index] = values.get(index, 0.0) + sign
    norm = math.sqrt(sum(value * value for value in values.values()))
    vector = [[index, value] for index, value in sorted(values.items()) if value]
    return vector, norm


def _json(value: Any, fallback: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(str(value or ""))
    except json.JSONDecodeError:
        return fallback


def _initialize(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        -- Projection readers run in a read-only systemd sandbox. WAL would
        -- require a writable -shm sidecar even for mode=ro readers and can
        -- therefore produce SQLITE_CANTOPEN immediately after incremental
        -- sync. This database is disposable and rebuilt from immutable
        -- segments, so a fully committed DELETE journal is the safer contract.
        PRAGMA journal_mode=DELETE;
        PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS projection_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS events(
          id INTEGER PRIMARY KEY, ts_utc TEXT NOT NULL, actor TEXT NOT NULL,
          session_id TEXT NOT NULL, level TEXT NOT NULL, action TEXT NOT NULL,
          summary TEXT NOT NULL, details TEXT NOT NULL, tags TEXT NOT NULL,
          created_utc TEXT NOT NULL, event_uid TEXT NOT NULL,
          body_text TEXT NOT NULL, source_manifest_sha256 TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_projection_event_uid ON events(event_uid) WHERE event_uid <> '';
        CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
          event_id UNINDEXED, summary, details, tags, actor, action,
          tokenize='unicode61 remove_diacritics 2'
        );
        CREATE TABLE IF NOT EXISTS graph_nodes(
          node_key TEXT PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL
        ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS graph_edges(
          event_id INTEGER NOT NULL, node_key TEXT NOT NULL, relation TEXT NOT NULL,
          PRIMARY KEY(event_id,node_key,relation),
          FOREIGN KEY(event_id) REFERENCES events(id),
          FOREIGN KEY(node_key) REFERENCES graph_nodes(node_key)
        ) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS idx_graph_edges_node ON graph_edges(node_key,event_id);
        CREATE TABLE IF NOT EXISTS event_vectors(
          event_id INTEGER PRIMARY KEY, dimensions INTEGER NOT NULL,
          sparse_json TEXT NOT NULL, norm REAL NOT NULL,
          FOREIGN KEY(event_id) REFERENCES events(id)
        );
        CREATE TABLE IF NOT EXISTS task_state(
          task_id TEXT PRIMARY KEY, last_event_id INTEGER NOT NULL,
          result TEXT NOT NULL, summary TEXT NOT NULL, details TEXT NOT NULL
        ) WITHOUT ROWID;
        """
    )


def _meta(connection: sqlite3.Connection, key: str, default: str = "") -> str:
    row = connection.execute("SELECT value FROM projection_meta WHERE key=?", (key,)).fetchone()
    return str(row[0]) if row else default


def _set_meta(connection: sqlite3.Connection, key: str, value: Any) -> None:
    connection.execute(
        "INSERT INTO projection_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )


def _node(connection: sqlite3.Connection, event_id: int, kind: str, value: str, relation: str) -> None:
    normalized = value.strip()
    if not normalized:
        return
    node_key = f"{kind}:{normalized.casefold()}"
    connection.execute("INSERT OR IGNORE INTO graph_nodes(node_key,kind,value) VALUES(?,?,?)", (node_key, kind, normalized))
    connection.execute("INSERT OR IGNORE INTO graph_edges(event_id,node_key,relation) VALUES(?,?,?)", (event_id, node_key, relation))


def _event_nodes(details: Any, tags: Any, actor: str, action: str) -> Iterable[tuple[str, str, str]]:
    yield "actor", actor, "ACTED_BY"
    yield "action", action, "HAS_ACTION"
    for tag in tags if isinstance(tags, list) else []:
        yield "tag", str(tag), "TAGGED"
    if isinstance(details, dict):
        for key in ("task_id", "goal_id", "roadmap_item_id", "parent_task_id"):
            if details.get(key):
                yield key, str(details[key]), "REFERENCES"
        for key in ("subsystem", "touched_hosts", "related_task_ids", "depends_on_task_ids"):
            values = details.get(key) or []
            if not isinstance(values, list):
                values = [values]
            for value in values:
                yield key, str(value), "REFERENCES"


def _ingest_event(connection: sqlite3.Connection, columns: list[str], row: list[Any], manifest_sha256: str) -> None:
    event = dict(zip(columns, row))
    event_id = int(event["id"])
    details_raw = str(event.get("details") or "{}")
    tags_raw = str(event.get("tags") or "[]")
    details = _json(details_raw, {})
    tags = _json(tags_raw, [])
    body = "\n".join(
        str(event.get(key) or "") for key in ("summary", "details", "tags", "actor", "action", "session_id")
    )
    connection.execute(
        "INSERT INTO events(id,ts_utc,actor,session_id,level,action,summary,details,tags,created_utc,event_uid,body_text,source_manifest_sha256) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            event_id,
            str(event.get("ts_utc") or ""),
            str(event.get("actor") or ""),
            str(event.get("session_id") or ""),
            str(event.get("level") or ""),
            str(event.get("action") or ""),
            str(event.get("summary") or ""),
            details_raw,
            tags_raw,
            str(event.get("created_utc") or ""),
            str(event.get("event_uid") or ""),
            body,
            manifest_sha256,
        ),
    )
    connection.execute(
        "INSERT INTO events_fts(event_id,summary,details,tags,actor,action) VALUES(?,?,?,?,?,?)",
        (event_id, event.get("summary") or "", details_raw, tags_raw, event.get("actor") or "", event.get("action") or ""),
    )
    vector, norm = sparse_vector(body)
    connection.execute(
        "INSERT INTO event_vectors(event_id,dimensions,sparse_json,norm) VALUES(?,?,?,?)",
        (event_id, VECTOR_DIMENSIONS, canonical_json(vector).decode("utf-8"), norm),
    )
    for kind, value, relation in _event_nodes(details, tags, str(event.get("actor") or ""), str(event.get("action") or "")):
        _node(connection, event_id, kind, value, relation)
    if isinstance(details, dict) and details.get("task_id"):
        connection.execute(
            "INSERT INTO task_state(task_id,last_event_id,result,summary,details) VALUES(?,?,?,?,?) "
            "ON CONFLICT(task_id) DO UPDATE SET last_event_id=excluded.last_event_id,result=excluded.result,summary=excluded.summary,details=excluded.details "
            "WHERE excluded.last_event_id > task_state.last_event_id",
            (str(details["task_id"]), event_id, str(details.get("result") or "unknown"), str(event.get("summary") or ""), details_raw),
        )


def sync_projection(store_root: Path, database: Path) -> dict[str, Any]:
    database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    connection = sqlite3.connect(database, timeout=30)
    connection.execute("PRAGMA busy_timeout=30000")
    try:
        _initialize(connection)
        last_cursor = int(_meta(connection, "last_cursor", "0"))
        previous = _meta(connection, "manifest_head_sha256", "")
        inserted = 0
        processed = 0
        for reference in sorted((store_root / "segments").glob("*.json")):
            manifest_bytes = reference.read_bytes()
            manifest_sha256 = sha256_bytes(manifest_bytes)
            manifest = json.loads(manifest_bytes)
            if int(manifest.get("last_cursor") or 0) <= last_cursor:
                continue
            if manifest.get("protocol") != PROTOCOL + ".manifest" or manifest.get("previous_manifest_sha256") != previous:
                raise RuntimeError("projection input manifest chain diverged")
            payload = _object(store_root, manifest.get("payload") or {})
            lines = gzip.decompress(payload).splitlines()
            header = json.loads(lines[0])
            columns = [str(value) for value in header.get("columns") or []]
            rows = [json.loads(line) for line in lines[1:]]
            digest = hashlib.sha256()
            for row in rows:
                encoded = canonical_json(row)
                digest.update(len(encoded).to_bytes(8, "big"))
                digest.update(encoded)
            if digest.hexdigest() != manifest.get("rows_sha256") or len(rows) != int(manifest.get("event_count") or -1):
                raise RuntimeError("projection input payload failed verification")
            for row in rows:
                if int(row[columns.index("id")]) <= last_cursor:
                    raise RuntimeError("projection input overlaps committed cursor")
                _ingest_event(connection, columns, row, manifest_sha256)
                inserted += 1
            last_cursor = int(manifest["last_cursor"])
            previous = manifest_sha256
            processed += 1
            _set_meta(connection, "last_cursor", last_cursor)
            _set_meta(connection, "manifest_head_sha256", previous)
            _set_meta(connection, "protocol", PROJECTION_PROTOCOL)
        connection.commit()
        quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        counts = {
            "events": int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]),
            "fts": int(connection.execute("SELECT COUNT(*) FROM events_fts").fetchone()[0]),
            "vectors": int(connection.execute("SELECT COUNT(*) FROM event_vectors").fetchone()[0]),
            "graph_nodes": int(connection.execute("SELECT COUNT(*) FROM graph_nodes").fetchone()[0]),
            "graph_edges": int(connection.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0]),
            "task_state": int(connection.execute("SELECT COUNT(*) FROM task_state").fetchone()[0]),
        }
        status = "pass" if inserted else "noop"
        return {
            "protocol": PROJECTION_PROTOCOL + ".receipt",
            "status": status,
            "inserted_event_count": inserted,
            "processed_segment_count": processed,
            "event_cursor": last_cursor,
            "manifest_head_sha256": previous,
            "quick_check": quick_check,
            "counts": counts,
            "production_authority": False,
            "rebuildable_from_raw_segments": True,
        }
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def rebuild_projection(store_root: Path, database: Path) -> dict[str, Any]:
    database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{database.name}.rebuild.", dir=database.parent)
    os.close(descriptor)
    Path(temporary).unlink()
    try:
        result = sync_projection(store_root, Path(temporary))
        result["mode"] = "rebuild"
        os.chmod(temporary, 0o600)
        os.replace(temporary, database)
        return result
    finally:
        try:
            Path(temporary).unlink()
        except FileNotFoundError:
            pass


def projection_status(database: Path) -> dict[str, Any]:
    connection = sqlite3.connect(f"file:{database.resolve()}?mode=ro", uri=True)
    try:
        counts = {
            table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in ("events", "events_fts", "event_vectors", "graph_nodes", "graph_edges", "task_state")
        }
        return {
            "protocol": PROJECTION_PROTOCOL + ".status",
            "status": "READY",
            "event_cursor": int(_meta(connection, "last_cursor", "0")),
            "manifest_head_sha256": _meta(connection, "manifest_head_sha256", ""),
            "counts": counts,
            "quick_check": str(connection.execute("PRAGMA quick_check").fetchone()[0]),
            "production_authority": False,
        }
    finally:
        connection.close()


def main() -> int:
    args = parse_args()
    if args.command == "status":
        result = projection_status(args.projection_db)
    else:
        with exclusive_lock(args.lock):
            result = rebuild_projection(args.store_root, args.projection_db) if args.command == "rebuild" else sync_projection(args.store_root, args.projection_db)
            args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            atomic_json(args.receipt_root / f"projection-{args.command}-cursor-{result['event_cursor']}.json", result, mode=0o440)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get("quick_check") == "ok" else 1


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
