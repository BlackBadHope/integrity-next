#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Seal Action Log deltas into immutable, hash-chained cold segments."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import gzip
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, exclusive_lock, safe_copy, schema_digest, sha256_bytes, sha256_file, snapshot_connection


PROTOCOL = "integrity-memory-plane.tail-segment.v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-db", type=Path, default=Path(_integrity_value('path_97373521e3ad')))
    parser.add_argument("--local-root", type=Path, default=Path("/var/backups/integrity-memory-plane/action-log/tail"))
    parser.add_argument("--vdb-root", type=Path, default=Path(_integrity_value('path_f99c29cce43c')))
    parser.add_argument("--full-root", type=Path, default=Path(_integrity_value('path_4e44c119019c')))
    parser.add_argument("--evidence-root", type=Path, default=Path(_integrity_value('path_29857010143f')))
    parser.add_argument("--lock", type=Path, default=Path("/run/lock/integrity-memory-plane-tail.lock"))
    parser.add_argument("--max-events", type=int, default=10000)
    return parser.parse_args()


def latest_full_cursor(full_root: Path) -> int:
    receipts = sorted(full_root.glob("full-backup-*.json"), reverse=True)
    for path in receipts:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            cursor = int((value.get("snapshot") or {}).get("event_cursor") or 0)
            if cursor:
                return cursor
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            continue
    raise RuntimeError("no verified full-backup receipt is available as tail anchor")


def load_state(path: Path, full_root: Path) -> dict[str, Any]:
    if path.is_file():
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("protocol") != PROTOCOL + ".state":
            raise RuntimeError("tail state protocol mismatch")
        return value
    cursor = latest_full_cursor(full_root)
    return {"protocol": PROTOCOL + ".state", "archived_cursor": cursor, "previous_manifest_sha256": "", "segment_count": 0}


def stable_rows(connection: sqlite3.Connection, after: int, maximum: int) -> tuple[list[str], list[list[Any]]]:
    columns = [str(row[1]) for row in connection.execute("PRAGMA table_info(events)")]
    quoted = ",".join('"' + item.replace('"', '""') + '"' for item in columns)
    rows = [list(row) for row in connection.execute(f"SELECT {quoted} FROM events WHERE id > ? AND id <= ? ORDER BY id", [after, maximum])]
    return columns, rows


def main() -> int:
    args = parse_args()
    args.vdb_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.local_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.evidence_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    state_path = args.vdb_root / "state.json"
    with exclusive_lock(args.lock):
        state = load_state(state_path, args.full_root)
        after = int(state["archived_cursor"])
        with snapshot_connection(args.source_db) as connection:
            connection.execute("BEGIN")
            live_cursor = int(connection.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0])
            maximum = min(live_cursor, after + max(1, args.max_events))
            if maximum <= after:
                receipt = {"protocol": PROTOCOL + ".receipt", "status": "noop", "archived_cursor": after, "live_cursor": live_cursor}
                print(json.dumps(receipt, sort_keys=True))
                return 0
            columns, rows = stable_rows(connection, after, maximum)
            current_schema = schema_digest(connection)
            connection.rollback()
        first_id = int(rows[0][columns.index("id")])
        last_id = int(rows[-1][columns.index("id")])
        if first_id <= after or last_id != maximum:
            raise RuntimeError("tail range is not contiguous with the selected cursor boundary")
        stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        stem = f"events-{first_id:020d}-{last_id:020d}"
        with tempfile.TemporaryDirectory(prefix="memory-tail-", dir=args.vdb_root) as temporary:
            payload = Path(temporary) / f"{stem}.jsonl.gz"
            row_hash = __import__("hashlib").sha256()
            with payload.open("wb") as raw:
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=6) as compressed:
                    header = canonical_json({"protocol": PROTOCOL, "columns": columns}) + b"\n"
                    compressed.write(header)
                    for row in rows:
                        encoded = canonical_json(row)
                        row_hash.update(len(encoded).to_bytes(8, "big"))
                        row_hash.update(encoded)
                        compressed.write(encoded + b"\n")
            manifest = {
                "protocol": PROTOCOL,
                "created_utc": dt.datetime.now(dt.UTC).isoformat(),
                "first_cursor": first_id,
                "last_cursor": last_id,
                "event_count": len(rows),
                "columns": columns,
                "schema_sha256": current_schema,
                "row_sha256": row_hash.hexdigest(),
                "payload": {"name": payload.name, "bytes": payload.stat().st_size, "sha256": sha256_file(payload)},
                "previous_manifest_sha256": str(state.get("previous_manifest_sha256") or ""),
            }
            manifest_path = Path(temporary) / f"{stem}.manifest.json"
            atomic_json(manifest_path, manifest)
            manifest_digest = sha256_file(manifest_path)
            destinations = {}
            for label, root in (("local", args.local_root), ("vdb", args.vdb_root)):
                payload_target = root / payload.name
                manifest_target = root / manifest_path.name
                destinations[label] = {
                    "payload": str(payload_target),
                    "payload_sha256": safe_copy(payload, payload_target),
                    "manifest": str(manifest_target),
                    "manifest_sha256": safe_copy(manifest_path, manifest_target),
                }
            checks = {
                "local_payload_readback": destinations["local"]["payload_sha256"] == manifest["payload"]["sha256"],
                "vdb_payload_readback": destinations["vdb"]["payload_sha256"] == manifest["payload"]["sha256"],
                "manifest_readback": destinations["local"]["manifest_sha256"] == destinations["vdb"]["manifest_sha256"] == manifest_digest,
            }
            if not all(checks.values()):
                raise RuntimeError("tail segment independent readback failed")
            next_state = {
                "protocol": PROTOCOL + ".state",
                "archived_cursor": last_id,
                "previous_manifest_sha256": manifest_digest,
                "segment_count": int(state.get("segment_count") or 0) + 1,
                "updated_utc": dt.datetime.now(dt.UTC).isoformat(),
                "offhost_ack_cursor": int(state.get("offhost_ack_cursor") or 0),
            }
            atomic_json(state_path, next_state)
            safe_copy(state_path, args.local_root / "state.json", mode=0o400)
            receipt = {
                "protocol": PROTOCOL + ".receipt",
                "status": "pass-local-vdb-offhost-pending",
                "checks": checks,
                "segment": manifest,
                "manifest_sha256": manifest_digest,
                "state": next_state,
                "destinations": destinations,
                "offhost_ack": False,
            }
            receipt_path = args.evidence_root / f"tail-{stamp}-{first_id}-{last_id}.json"
            atomic_json(receipt_path, receipt)
            print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
            return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
