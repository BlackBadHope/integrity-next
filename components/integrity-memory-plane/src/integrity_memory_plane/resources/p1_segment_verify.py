#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify P1 immutable segments, exact source parity, and segment-only restore."""

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
from typing import Any

from memory_plane_common import atomic_json, canonical_json, database_facts, row_digest, sha256_bytes, sha256_file, snapshot_connection
from p1_segment_witness import PROTOCOL, STATE_PROTOCOL


VERIFY_PROTOCOL = "integrity-memory-plane.p1-segment-verify.v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--store-root", type=Path, default=Path(_integrity_value('path_5350cd670b63')))
    parser.add_argument("--source-db", type=Path, default=Path(_integrity_value('path_97373521e3ad')))
    parser.add_argument("--skip-source-parity", action="store_true")
    parser.add_argument("--restore-db", type=Path, default=None)
    parser.add_argument("--receipt-root", type=Path, default=None)
    return parser.parse_args()


def _object(root: Path, descriptor: dict[str, Any]) -> bytes:
    path = root / str(descriptor.get("key") or "")
    if not path.is_file():
        raise RuntimeError(f"missing witness object: {path}")
    content = path.read_bytes()
    if len(content) != int(descriptor.get("bytes") or -1) or sha256_bytes(content) != descriptor.get("sha256"):
        raise RuntimeError(f"witness object readback mismatch: {path}")
    return content


def _restore(schema: dict[str, Any], columns: list[str], rows: list[list[Any]], destination: Path) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(descriptor)
    Path(temporary).unlink()
    connection = sqlite3.connect(temporary)
    try:
        for item in schema.get("objects") or []:
            if item.get("type") == "table":
                connection.execute(str(item["sql"]))
        quoted = ",".join('"' + column.replace('"', '""') + '"' for column in columns)
        placeholders = ",".join("?" for _ in columns)
        connection.executemany(f"INSERT INTO events({quoted}) VALUES({placeholders})", rows)
        for item in schema.get("objects") or []:
            if item.get("type") != "table":
                connection.execute(str(item["sql"]))
        connection.commit()
        facts = database_facts(connection)
    finally:
        connection.close()
    os.chmod(temporary, 0o400)
    os.replace(temporary, destination)
    return facts


def verify_store(store_root: Path, source_db: Path | None = None, restore_db: Path | None = None) -> dict[str, Any]:
    state_path = store_root / "state.json"
    if not state_path.is_file():
        raise RuntimeError("P1 witness state is missing")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("protocol") != STATE_PROTOCOL:
        raise RuntimeError("P1 witness state protocol mismatch")
    references = sorted((store_root / "segments").glob("*.json"))
    if not references:
        raise RuntimeError("P1 witness has no segment manifests")
    previous = ""
    columns: list[str] | None = None
    all_rows: list[list[Any]] = []
    ids: list[int] = []
    nonempty_uids: list[str] = []
    manifest_digests: list[str] = []
    aggregate = hashlib.sha256()
    for reference in references:
        manifest_bytes = reference.read_bytes()
        manifest_sha256 = sha256_bytes(manifest_bytes)
        manifest = json.loads(manifest_bytes)
        if manifest.get("protocol") != PROTOCOL + ".manifest":
            raise RuntimeError("P1 witness manifest protocol mismatch")
        if manifest.get("previous_manifest_sha256") != previous:
            raise RuntimeError("P1 witness manifest hash-chain mismatch")
        if not reference.name.endswith(f"-{manifest_sha256}.json"):
            raise RuntimeError("P1 witness manifest reference digest mismatch")
        payload = _object(store_root, manifest.get("payload") or {})
        lines = gzip.decompress(payload).splitlines()
        if not lines:
            raise RuntimeError("empty P1 witness payload")
        header = json.loads(lines[0])
        if header.get("protocol") != PROTOCOL or header.get("namespace") != state.get("namespace"):
            raise RuntimeError("P1 witness payload identity mismatch")
        segment_columns = [str(value) for value in header.get("columns") or []]
        if columns is None:
            columns = segment_columns
            aggregate.update(canonical_json({"columns": columns}))
            aggregate.update(b"\n")
        elif columns != segment_columns:
            raise RuntimeError("P1 witness columns changed inside chain")
        rows = [json.loads(line) for line in lines[1:]]
        if len(rows) != int(manifest.get("event_count") or -1):
            raise RuntimeError("P1 witness segment count mismatch")
        row_hash = hashlib.sha256()
        for row in rows:
            encoded = canonical_json(row)
            row_hash.update(len(encoded).to_bytes(8, "big"))
            row_hash.update(encoded)
            aggregate.update(len(encoded).to_bytes(8, "big"))
            aggregate.update(encoded)
        if row_hash.hexdigest() != manifest.get("rows_sha256"):
            raise RuntimeError("P1 witness row digest mismatch")
        id_index = columns.index("id")
        uid_index = columns.index("event_uid")
        segment_ids = [int(row[id_index]) for row in rows]
        segment_uids = [str(row[uid_index] or "") for row in rows if str(row[uid_index] or "")]
        if not segment_ids or segment_ids[0] != int(manifest["first_cursor"]) or segment_ids[-1] != int(manifest["last_cursor"]):
            raise RuntimeError("P1 witness segment cursor boundary mismatch")
        if sha256_bytes(canonical_json(sorted(segment_uids))) != manifest.get("event_uid_set_sha256"):
            raise RuntimeError("P1 witness event_uid digest mismatch")
        ids.extend(segment_ids)
        nonempty_uids.extend(segment_uids)
        all_rows.extend(rows)
        manifest_digests.append(manifest_sha256)
        previous = manifest_sha256
    if ids != sorted(ids) or len(ids) != len(set(ids)):
        raise RuntimeError("duplicate or out-of-order event id in P1 witness")
    duplicate_uids = len(nonempty_uids) - len(set(nonempty_uids))
    checks: dict[str, bool] = {
        "manifest_chain": previous == state.get("previous_manifest_sha256"),
        "state_cursor_match": ids[-1] == int(state.get("last_cursor") or -1),
        "state_count_match": len(ids) == int(state.get("event_count") or -1),
        "segment_count_match": len(references) == int(state.get("segment_count") or -1),
        "duplicate_event_id_zero": len(ids) == len(set(ids)),
        "duplicate_event_uid_zero": duplicate_uids == 0,
    }
    source: dict[str, Any] | None = None
    if source_db is not None:
        connection = snapshot_connection(source_db)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN")
            source_columns = [str(row[1]) for row in connection.execute("PRAGMA table_info(events)")]
            source_rows = [list(row) for row in connection.execute("SELECT * FROM events WHERE id <= ? ORDER BY id", (ids[-1],))]
            source_ids = [int(row[source_columns.index("id")]) for row in source_rows]
            source_uids = [str(row[source_columns.index("event_uid")] or "") for row in source_rows if str(row[source_columns.index("event_uid")] or "")]
            source_row_sha256 = row_digest(connection, last_id=ids[-1])
            source = {"cursor": source_ids[-1] if source_ids else 0, "event_count": len(source_ids), "row_sha256": source_row_sha256}
            checks.update(
                {
                    "source_columns_match": source_columns == columns,
                    "source_cursor_parity": source_ids == ids,
                    "source_event_uid_parity": source_uids == nonempty_uids,
                    "source_row_digest_parity": source_row_sha256 == aggregate.hexdigest(),
                    "missing_event_zero": set(source_ids) - set(ids) == set(),
                    "extra_event_zero": set(ids) - set(source_ids) == set(),
                }
            )
        finally:
            connection.rollback()
            connection.close()
    schema_descriptor = json.loads(references[0].read_text(encoding="utf-8")).get("schema_object") or {}
    schema_bytes = _object(store_root, schema_descriptor)
    schema = json.loads(schema_bytes)
    if schema.get("protocol") != PROTOCOL + ".schema" or schema.get("source_schema_sha256") != state.get("source_schema_sha256"):
        raise RuntimeError("P1 witness schema object mismatch")
    restored: dict[str, Any] | None = None
    if restore_db is not None:
        restored = _restore(schema, columns or [], all_rows, restore_db)
        checks.update(
            {
                "restore_quick_check": restored.get("quick_check") == "ok",
                "restore_append_only": restored.get("append_only_ok") is True,
                "restore_cursor_match": int(restored.get("event_cursor") or -1) == ids[-1],
                "restore_count_match": int(restored.get("event_count") or -1) == len(ids),
                "restore_row_digest_match": restored.get("row_sha256") == aggregate.hexdigest(),
            }
        )
    return {
        "protocol": VERIFY_PROTOCOL,
        "status": "pass" if all(checks.values()) else "failed",
        "checks": checks,
        "namespace": state.get("namespace"),
        "witness_cursor": ids[-1],
        "witness_event_count": len(ids),
        "segment_count": len(references),
        "row_sha256": aggregate.hexdigest(),
        "duplicate_event_uid_count": duplicate_uids,
        "manifest_head_sha256": previous,
        "source": source,
        "restored": restored,
        "production_authority": False,
    }


def main() -> int:
    args = parse_args()
    result = verify_store(args.store_root, None if args.skip_source_parity else args.source_db, args.restore_db)
    if args.receipt_root is not None:
        stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        atomic_json(args.receipt_root / f"segment-verify-{stamp}-cursor-{result['witness_cursor']}.json", result, mode=0o440)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
