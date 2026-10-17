#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Archive routine Seed build runs and keep the live derived telemetry bounded."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import gzip
import hashlib
import json
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, exclusive_lock, safe_copy, sha256_file
from seed_catalog_read_seal import seal_catalog_for_immutable_read

PROTOCOL = "integrity-memory-plane.seed-run-retention.v1"
PERMANENT_PROFILE_MARKERS = ("release", "acceptance", "checkpoint", "cutover", "freeze", "seal")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", type=Path, default=Path(_integrity_value('path_dbe216bb3340')))
    parser.add_argument("--local-root", type=Path, default=Path("/var/backups/integrity-memory-plane/seed/runs"))
    parser.add_argument("--vdb-root", type=Path, default=Path(_integrity_value('path_0307d9cac2d9')))
    parser.add_argument("--evidence-root", type=Path, default=Path(_integrity_value('path_29857010143f')))
    parser.add_argument("--lock", type=Path, default=Path("/run/lock/integrity-memory-plane-seed-retention.lock"))
    parser.add_argument("--keep-recent", type=int, default=256)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def _day(value: str) -> str:
    return value[:10] if len(value) >= 10 else "unknown"


def choose_runs(rows: list[dict[str, Any]], keep_recent: int) -> tuple[set[str], list[dict[str, Any]]]:
    """Keep policy anchors and daily edges; return run ids plus rows to archive."""
    ordered = sorted(rows, key=lambda row: (str(row["finished_at"]), str(row["run_id"])))
    keep: set[str] = set()
    for row in ordered[-max(1, keep_recent) :]:
        keep.add(str(row["run_id"]))
    passes = [row for row in ordered if str(row["result"]).upper() == "PASS"]
    failures = [row for row in ordered if str(row["result"]).upper() != "PASS"]
    if passes:
        keep.add(str(passes[-1]["run_id"]))
    if failures:
        keep.add(str(failures[-1]["run_id"]))
    buckets: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in ordered:
        profile = str(row["profile"])
        if any(marker in profile.lower() for marker in PERMANENT_PROFILE_MARKERS):
            keep.add(str(row["run_id"]))
            continue
        key = (_day(str(row["finished_at"])), profile, str(row["result"]).upper())
        buckets.setdefault(key, []).append(row)
    for bucket in buckets.values():
        keep.add(str(bucket[0]["run_id"]))
        keep.add(str(bucket[-1]["run_id"]))
    archived = [row for row in ordered if str(row["run_id"]) not in keep]
    return keep, archived


def choose_delta_runs(rows: list[dict[str, Any]], keep_recent: int) -> tuple[set[str], list[dict[str, Any]]]:
    """Bound delta checkpoint telemetry while preserving recent and policy-anchor runs."""
    ordered = sorted(rows, key=lambda row: (str(row["finished_at"]), str(row["checkpoint_digest"])))
    keep: set[str] = {str(row["checkpoint_digest"]) for row in ordered[-max(1, keep_recent) :]}
    buckets: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in ordered:
        profile = str(row["profile"])
        checkpoint = str(row["checkpoint_digest"])
        if any(marker in profile.lower() for marker in PERMANENT_PROFILE_MARKERS):
            keep.add(checkpoint)
            continue
        key = (_day(str(row["finished_at"])), profile, str(row["verification_mode"]))
        buckets.setdefault(key, []).append(row)
    for bucket in buckets.values():
        keep.add(str(bucket[0]["checkpoint_digest"]))
        keep.add(str(bucket[-1]["checkpoint_digest"]))
    archived = [row for row in ordered if str(row["checkpoint_digest"]) not in keep]
    return keep, archived


def _load_state(path: Path, protocol: str = PROTOCOL) -> dict[str, Any]:
    if not path.is_file():
        return {"protocol": protocol + ".state", "previous_manifest_sha256": "", "archive_count": 0}
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("protocol") != protocol + ".state":
        raise RuntimeError("Seed retention state protocol mismatch")
    return value


def _retention_generation(connection: sqlite3.Connection) -> dict[str, Any]:
    has_delta_runs = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='seed_delta_runs'"
    ).fetchone() is not None
    has_delta_state = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='seed_delta_state'"
    ).fetchone() is not None
    checkpoint_digest = None
    if has_delta_state:
        row = connection.execute(
            "SELECT checkpoint_digest FROM seed_delta_state WHERE singleton=1"
        ).fetchone()
        checkpoint_digest = str(row[0]) if row is not None else None
    catalog_runs = [
        dict(row)
        for row in connection.execute(
            "SELECT * FROM seed_catalog_runs ORDER BY run_id"
        )
    ]
    delta_runs = (
        [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM seed_delta_runs ORDER BY checkpoint_digest"
            )
        ]
        if has_delta_runs
        else []
    )

    def rows_digest(rows: list[dict[str, Any]], stream: str) -> str:
        payload = (
            b"integrity-seed-retention-generation-v1\0"
            + stream.encode("ascii")
            + b"\0"
            + canonical_json(rows)
        )
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    return {
        "seed_catalog_run_count": len(catalog_runs),
        "seed_catalog_runs_digest": rows_digest(catalog_runs, "catalog-runs"),
        "seed_delta_run_count": len(delta_runs),
        "seed_delta_runs_digest": rows_digest(delta_runs, "delta-runs"),
        "delta_checkpoint_digest": checkpoint_digest,
    }


def _archive_rows(args: argparse.Namespace, rows: list[dict[str, Any]], before_count: int, *, stream: str = "catalog") -> dict[str, Any]:
    protocol = PROTOCOL if stream == "catalog" else PROTOCOL + ".delta"
    prefix = "seed-runs" if stream == "catalog" else "seed-delta-runs"
    local_root = args.local_root if stream == "catalog" else args.local_root / "delta"
    vdb_root = args.vdb_root if stream == "catalog" else args.vdb_root / "delta"
    for root in (local_root, vdb_root):
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
    state_path = vdb_root / "state.json"
    state = _load_state(state_path, protocol)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    with tempfile.TemporaryDirectory(prefix=prefix + "-", dir=vdb_root) as temporary:
        payload = Path(temporary) / f"{prefix}-{stamp}.jsonl.gz"
        with (
            payload.open("wb") as raw,
            gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=6) as compressed,
        ):
            compressed.write(canonical_json({"protocol": protocol, "stream": stream, "columns": list(rows[0])}) + b"\n")
            for row in rows:
                compressed.write(canonical_json(row) + b"\n")
        manifest = {
            "protocol": protocol,
            "stream": stream,
            "created_utc": dt.datetime.now(dt.UTC).isoformat(),
            "source_count_before": before_count,
            "archived_run_count": len(rows),
            "first_finished_at": rows[0]["finished_at"],
            "last_finished_at": rows[-1]["finished_at"],
            "payload": {"name": payload.name, "bytes": payload.stat().st_size, "sha256": sha256_file(payload)},
            "previous_manifest_sha256": str(state.get("previous_manifest_sha256") or ""),
        }
        manifest_path = Path(temporary) / f"{prefix}-{stamp}.manifest.json"
        atomic_json(manifest_path, manifest)
        manifest_sha = sha256_file(manifest_path)
        destinations: dict[str, Any] = {}
        for label, root in (("local", local_root), ("vdb", vdb_root)):
            destinations[label] = {
                "payload_sha256": safe_copy(payload, root / payload.name),
                "manifest_sha256": safe_copy(manifest_path, root / manifest_path.name),
            }
        if any(destination["payload_sha256"] != manifest["payload"]["sha256"] for destination in destinations.values()):
            raise RuntimeError("Seed run archive readback mismatch")
        if any(destination["manifest_sha256"] != manifest_sha for destination in destinations.values()):
            raise RuntimeError("Seed run manifest readback mismatch")
        next_state = {
            "protocol": protocol + ".state",
            "previous_manifest_sha256": manifest_sha,
            "archive_count": int(state.get("archive_count") or 0) + 1,
            "last_finished_at": rows[-1]["finished_at"],
            "updated_utc": dt.datetime.now(dt.UTC).isoformat(),
        }
        atomic_json(state_path, next_state)
        safe_copy(state_path, local_root / "state.json", mode=0o400)
        return {"manifest": manifest, "manifest_sha256": manifest_sha, "destinations": destinations, "state": next_state}


def main() -> int:
    args = parse_args()
    for root in (args.local_root, args.vdb_root, args.evidence_root):
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with exclusive_lock(args.lock):
        connection = sqlite3.connect(args.catalog, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("BEGIN IMMEDIATE")
        try:
            rows = [dict(row) for row in connection.execute("SELECT * FROM seed_catalog_runs ORDER BY finished_at, run_id")]
            keep, archived = choose_runs(rows, args.keep_recent)
            has_delta = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='seed_delta_runs'").fetchone() is not None
            delta_rows = [dict(row) for row in connection.execute("SELECT * FROM seed_delta_runs ORDER BY finished_at, checkpoint_digest")] if has_delta else []
            delta_keep, delta_archived = choose_delta_runs(delta_rows, args.keep_recent)
            archives: dict[str, Any] = {}
            if archived:
                archives["catalog"] = _archive_rows(args, archived, len(rows), stream="catalog")
            if delta_archived:
                archives["delta"] = _archive_rows(args, delta_archived, len(delta_rows), stream="delta")
            if not archived and not delta_archived:
                expected_generation = _retention_generation(connection)
                connection.rollback()
                catalog_read_seal = seal_catalog_for_immutable_read(
                    connection,
                    args.catalog,
                    generation_reader=_retention_generation,
                    expected_generation=expected_generation,
                    durable_commit=True,
                )
                receipt = {"protocol": PROTOCOL + ".receipt", "status": "noop", "source_count": len(rows), "kept_count": len(keep), "delta_source_count": len(delta_rows), "delta_kept_count": len(delta_keep), "catalog_read_seal": catalog_read_seal, "catalog_rebuildable": True, "production_authority": False}
                receipt_path = args.evidence_root / f"seed-run-retention-{dt.datetime.now(dt.UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
                atomic_json(receipt_path, receipt)
                print(json.dumps(receipt, sort_keys=True))
                return 0
            if args.dry_run:
                connection.rollback()
                status = "dry-run"
                catalog_read_seal = None
            else:
                connection.executemany("DELETE FROM seed_catalog_runs WHERE run_id = ?", [(row["run_id"],) for row in archived])
                if delta_archived:
                    connection.executemany("DELETE FROM seed_delta_runs WHERE checkpoint_digest = ?", [(row["checkpoint_digest"],) for row in delta_archived])
                remaining = int(connection.execute("SELECT COUNT(*) FROM seed_catalog_runs").fetchone()[0])
                if remaining != len(keep):
                    raise RuntimeError("Seed retention row-count gate failed")
                delta_remaining = int(connection.execute("SELECT COUNT(*) FROM seed_delta_runs").fetchone()[0]) if has_delta else 0
                if delta_remaining != len(delta_keep):
                    raise RuntimeError("Seed delta retention row-count gate failed")
                if str(connection.execute("PRAGMA quick_check").fetchone()[0]) != "ok":
                    raise RuntimeError("Seed catalog quick_check failed after retention")
                expected_generation = _retention_generation(connection)
                connection.commit()
                catalog_read_seal = seal_catalog_for_immutable_read(
                    connection,
                    args.catalog,
                    generation_reader=_retention_generation,
                    expected_generation=expected_generation,
                    durable_commit=True,
                )
                status = "pass"
            receipt = {
                "protocol": PROTOCOL + ".receipt",
                "status": status,
                "source_count": len(rows),
                "archived_count": len(archived),
                "kept_count": len(keep),
                "delta_source_count": len(delta_rows),
                "delta_archived_count": len(delta_archived),
                "delta_kept_count": len(delta_keep),
                "archives": archives,
                "catalog_read_seal": catalog_read_seal,
                "catalog_rebuildable": True,
                "production_authority": False,
            }
            receipt_path = args.evidence_root / f"seed-run-retention-{dt.datetime.now(dt.UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
            atomic_json(receipt_path, receipt)
            print(json.dumps(receipt, sort_keys=True))
            return 0
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
