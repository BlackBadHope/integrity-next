#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write exact canonical Action Log rows into immutable P1 witness segments."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Iterable

from memory_plane_common import atomic_json, canonical_json, exclusive_lock, schema_digest, sha256_bytes, sha256_file, snapshot_connection


PROTOCOL = "integrity-memory-plane.p1-segment.v1"
STATE_PROTOCOL = PROTOCOL + ".state"
RECEIPT_PROTOCOL = PROTOCOL + ".receipt"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-db", type=Path, default=Path(_integrity_value('path_97373521e3ad')))
    parser.add_argument("--store-root", type=Path, default=Path(_integrity_value('path_5350cd670b63')))
    parser.add_argument("--lock", type=Path, default=Path("/run/integrity-memory-plane-p1-witness/writer.lock"))
    parser.add_argument("--namespace", default=_integrity_value('seed_namespace'))
    parser.add_argument("--segment-events", type=int, default=512)
    parser.add_argument("--max-events", type=int, default=0)
    return parser.parse_args()


def immutable_write(path: Path, content: bytes, mode: int = 0o440) -> str:
    """Create an immutable object or prove that an exact retry already exists."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    digest = sha256_bytes(content)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError:
        if sha256_file(path) != digest or path.read_bytes() != content:
            raise RuntimeError(f"immutable object collision: {path}")
        return digest
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, mode)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise
    return digest


def deterministic_gzip(content: bytes) -> bytes:
    with tempfile.TemporaryFile() as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=6) as compressed:
            compressed.write(content)
        raw.seek(0)
        return raw.read()


def _load_state(path: Path, namespace: str, source_schema_sha256: str) -> dict[str, Any]:
    if not path.is_file():
        return {
            "protocol": STATE_PROTOCOL,
            "namespace": namespace,
            "source_schema_sha256": source_schema_sha256,
            "last_cursor": 0,
            "event_count": 0,
            "segment_count": 0,
            "previous_manifest_sha256": "",
        }
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("protocol") != STATE_PROTOCOL or value.get("namespace") != namespace:
        raise RuntimeError("P1 witness state identity mismatch")
    if value.get("source_schema_sha256") != source_schema_sha256:
        raise RuntimeError("canonical Action Log schema changed; an explicit witness migration is required")
    return value


def _schema_capsule(connection: sqlite3.Connection, namespace: str, source_schema_sha256: str) -> bytes:
    rank = {"table": 0, "index": 1, "trigger": 2}
    rows = [
        {"type": str(row[0]), "name": str(row[1]), "table": str(row[2]), "sql": str(row[3])}
        for row in connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master "
            "WHERE tbl_name='events' AND sql IS NOT NULL AND name NOT LIKE 'sqlite_%'"
        )
    ]
    rows.sort(key=lambda row: (rank.get(row["type"], 99), row["name"]))
    if not rows or rows[0]["type"] != "table" or rows[0]["name"] != "events":
        raise RuntimeError("canonical events schema capsule is incomplete")
    return canonical_json(
        {
            "protocol": PROTOCOL + ".schema",
            "namespace": namespace,
            "source_schema_sha256": source_schema_sha256,
            "objects": rows,
        }
    ) + b"\n"


def _segment_content(columns: list[str], rows: list[list[Any]], namespace: str) -> tuple[bytes, str, list[str]]:
    header = {"protocol": PROTOCOL, "namespace": namespace, "columns": columns}
    lines = [canonical_json(header)]
    row_digest = hashlib.sha256()
    event_uids: list[str] = []
    uid_index = columns.index("event_uid") if "event_uid" in columns else -1
    for row in rows:
        encoded = canonical_json(row)
        lines.append(encoded)
        row_digest.update(len(encoded).to_bytes(8, "big"))
        row_digest.update(encoded)
        if uid_index >= 0:
            uid = str(row[uid_index] or "")
            if uid:
                event_uids.append(uid)
    if len(event_uids) != len(set(event_uids)):
        raise RuntimeError("duplicate non-empty event_uid inside witness segment")
    return deterministic_gzip(b"\n".join(lines) + b"\n"), row_digest.hexdigest(), event_uids


def _chunks(rows: Iterable[sqlite3.Row], size: int) -> Iterable[list[sqlite3.Row]]:
    chunk: list[sqlite3.Row] = []
    for row in rows:
        chunk.append(row)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def write_witness(args: argparse.Namespace) -> dict[str, Any]:
    if args.segment_events < 1 or args.segment_events > 100_000:
        raise ValueError("--segment-events must be between 1 and 100000")
    if args.max_events < 0:
        raise ValueError("--max-events cannot be negative")
    root = args.store_root
    state_path = root / "state.json"
    receipts = root / "receipts"
    root.mkdir(parents=True, exist_ok=True, mode=0o750)
    receipts.mkdir(parents=True, exist_ok=True, mode=0o750)
    with exclusive_lock(args.lock):
        connection = snapshot_connection(args.source_db)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN")
            columns = [str(row[1]) for row in connection.execute("PRAGMA table_info(events)")]
            if not columns or "id" not in columns or "event_uid" not in columns:
                raise RuntimeError("canonical events schema lacks required identity columns")
            source_schema_sha256 = schema_digest(connection)
            state = _load_state(state_path, args.namespace, source_schema_sha256)
            schema_bytes = _schema_capsule(connection, args.namespace, source_schema_sha256)
            schema_sha256 = sha256_bytes(schema_bytes)
            schema_key = f"objects/sha256/{schema_sha256[:2]}/{schema_sha256}"
            immutable_write(root / schema_key, schema_bytes)
            if state.get("schema_object_sha256") not in (None, "", schema_sha256):
                raise RuntimeError("P1 witness schema object changed without migration")
            last_cursor = int(state.get("last_cursor") or 0)
            source_count, snapshot_cursor = connection.execute(
                "SELECT COUNT(*), COALESCE(MAX(id),0) FROM events"
            ).fetchone()
            query = "SELECT * FROM events WHERE id > ? AND id <= ? ORDER BY id"
            parameters: list[Any] = [last_cursor, int(snapshot_cursor)]
            if args.max_events:
                query += " LIMIT ?"
                parameters.append(args.max_events)
            cursor = connection.execute(query, parameters)
            created: list[dict[str, Any]] = []
            previous_manifest = str(state.get("previous_manifest_sha256") or "")
            total_count = int(state.get("event_count") or 0)
            segment_count = int(state.get("segment_count") or 0)
            for sqlite_rows in _chunks(cursor, args.segment_events):
                rows = [list(row) for row in sqlite_rows]
                ids = [int(row[columns.index("id")]) for row in rows]
                if ids != sorted(ids) or ids[0] <= last_cursor or len(ids) != len(set(ids)):
                    raise RuntimeError("witness source rows are not strictly ordered")
                payload, rows_sha256, event_uids = _segment_content(columns, rows, args.namespace)
                payload_sha256 = sha256_bytes(payload)
                payload_key = f"objects/sha256/{payload_sha256[:2]}/{payload_sha256}"
                immutable_write(root / payload_key, payload)
                manifest = {
                    "protocol": PROTOCOL + ".manifest",
                    "namespace": args.namespace,
                    "source_schema_sha256": source_schema_sha256,
                    "schema_object": {"key": schema_key, "bytes": len(schema_bytes), "sha256": schema_sha256},
                    "first_cursor": ids[0],
                    "last_cursor": ids[-1],
                    "event_count": len(rows),
                    "event_uid_count": len(event_uids),
                    "blank_event_uid_count": len(rows) - len(event_uids),
                    "rows_sha256": rows_sha256,
                    "event_uid_set_sha256": sha256_bytes(canonical_json(sorted(event_uids))),
                    "payload": {"key": payload_key, "bytes": len(payload), "sha256": payload_sha256},
                    "previous_manifest_sha256": previous_manifest,
                }
                manifest_bytes = canonical_json(manifest) + b"\n"
                manifest_sha256 = sha256_bytes(manifest_bytes)
                manifest_key = f"objects/sha256/{manifest_sha256[:2]}/{manifest_sha256}"
                immutable_write(root / manifest_key, manifest_bytes)
                reference = root / "segments" / f"{ids[0]:020d}-{ids[-1]:020d}-{manifest_sha256}.json"
                immutable_write(reference, manifest_bytes)
                last_cursor = ids[-1]
                total_count += len(rows)
                segment_count += 1
                previous_manifest = manifest_sha256
                next_state = {
                    "protocol": STATE_PROTOCOL,
                    "namespace": args.namespace,
                    "source_schema_sha256": source_schema_sha256,
                    "schema_object_sha256": schema_sha256,
                    "schema_object_key": schema_key,
                    "last_cursor": last_cursor,
                    "event_count": total_count,
                    "segment_count": segment_count,
                    "previous_manifest_sha256": previous_manifest,
                    "source_snapshot_cursor": int(snapshot_cursor),
                    "source_snapshot_count": int(source_count),
                    "updated_utc": dt.datetime.now(dt.UTC).isoformat(),
                }
                atomic_json(state_path, next_state, mode=0o640)
                state = next_state
                created.append({"first_cursor": ids[0], "last_cursor": ids[-1], "event_count": len(rows), "manifest_sha256": manifest_sha256, "payload_sha256": payload_sha256})
        finally:
            connection.rollback()
            connection.close()
    status = "pass" if created else "noop"
    receipt = {
        "protocol": RECEIPT_PROTOCOL,
        "status": status,
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "namespace": args.namespace,
        "source_authority": "sqlite-action-log",
        "witness_authority": False,
        "source_snapshot_cursor": int(state.get("source_snapshot_cursor") or snapshot_cursor),
        "source_snapshot_count": int(state.get("source_snapshot_count") or source_count),
        "witness_cursor": int(state.get("last_cursor") or 0),
        "witness_event_count": int(state.get("event_count") or 0),
        "segment_count": int(state.get("segment_count") or 0),
        "created_segments": created,
        "previous_manifest_sha256": str(state.get("previous_manifest_sha256") or ""),
        "production_authority": False,
    }
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    atomic_json(receipts / f"witness-{stamp}-cursor-{receipt['witness_cursor']}.json", receipt, mode=0o440)
    return receipt


def main() -> int:
    args = parse_args()
    receipt = write_witness(args)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
