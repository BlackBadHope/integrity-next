#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed P1 transition gate over immutable witness receipts."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import json
import sqlite3
from pathlib import Path

from memory_plane_common import atomic_json, sha256_file


PROTOCOL = "integrity-memory-plane.p1-transition.v1"


def latest(root: Path, pattern: str) -> Path:
    values = list(root.glob(pattern))
    if not values:
        raise RuntimeError(f"no receipt matching {pattern} in {root}")
    return max(values, key=lambda value: value.stat().st_mtime_ns)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate(store_root: Path, projection_db: Path, verify_root: Path, eval_root: Path) -> dict:
    state_path = store_root / "state.json"
    verify_path = latest(verify_root, "segment-verify-*.json")
    golden_path = latest(eval_root, "golden-eval-*.json")
    state, verify, golden = load(state_path), load(verify_path), load(golden_path)
    with sqlite3.connect(f"file:{projection_db.resolve()}?mode=ro", uri=True) as connection:
        meta = dict(connection.execute("SELECT key,value FROM projection_meta"))
        projection_cursor = int(meta.get("last_cursor", "0"))
        projection_head = str(meta.get("manifest_head_sha256", ""))
        projection_count = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        projection_quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
    cursor = int(state.get("last_cursor") or 0)
    count = int(state.get("event_count") or 0)
    head = str(state.get("previous_manifest_sha256") or "")
    checks = {
        "witness_state_self_consistent": cursor == int(state.get("source_snapshot_cursor") or -1) and count == int(state.get("source_snapshot_count") or -1),
        "verifier_pass": verify.get("status") == "pass" and all((verify.get("checks") or {}).values()),
        "source_cursor_parity": int((verify.get("source") or {}).get("cursor") or -1) == cursor,
        "source_count_parity": int((verify.get("source") or {}).get("event_count") or -1) == count,
        "restore_cursor_parity": int((verify.get("restored") or {}).get("event_cursor") or -1) == cursor,
        "restore_count_parity": int((verify.get("restored") or {}).get("event_count") or -1) == count,
        "restore_row_digest_parity": (verify.get("restored") or {}).get("row_sha256") == (verify.get("source") or {}).get("row_sha256"),
        "projection_cursor_parity": projection_cursor == cursor,
        "projection_count_parity": projection_count == count,
        "projection_head_parity": projection_head == head,
        "projection_quick_check": projection_quick_check == "ok",
        "golden_pass": golden.get("status") == "pass" and all((golden.get("checks") or {}).values()),
        "golden_after_projection": golden_path.stat().st_mtime_ns >= projection_db.stat().st_mtime_ns,
        "unsupported_green_zero": int((golden.get("metrics") or {}).get("unsupported_green_count") or 0) == 0,
        "authority_boundary_recall_100": float((golden.get("metrics") or {}).get("authority_boundary_recall") or 0.0) == 1.0,
        "causal_path_recall_at_least_95": float((golden.get("metrics") or {}).get("causal_path_recall") or 0.0) >= 0.95,
        "retrieval_p95_under_2s": float((golden.get("metrics") or {}).get("retrieval_p95_ms") or 999999.0) <= 2000.0,
        "capsule_budget_8_to_32k": 8192 <= int((golden.get("metrics") or {}).get("capsule_budget_bytes") or 0) <= 32768,
    }
    status = "pass" if all(checks.values()) else "failed"
    return {
        "protocol": PROTOCOL,
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "status": status,
        "transition_state": "P1_WITNESS_READY" if status == "pass" else "P1_BLOCKED",
        "checks": checks,
        "cursor": cursor,
        "event_count": count,
        "manifest_head_sha256": head,
        "source_row_sha256": (verify.get("source") or {}).get("row_sha256"),
        "receipts": {
            "state": {"path": str(state_path), "sha256": sha256_file(state_path)},
            "verify": {"path": str(verify_path), "sha256": sha256_file(verify_path)},
            "golden": {"path": str(golden_path), "sha256": sha256_file(golden_path)},
            "projection": {"path": str(projection_db), "sha256": sha256_file(projection_db)},
        },
        "sqlite_authority": True,
        "witness_authority": False,
        "authority_migration_allowed": False,
        "production_authority": False,
        "memory_grants_authority": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--store-root", type=Path, default=Path(_integrity_value('path_5350cd670b63')))
    parser.add_argument("--projection-db", type=Path, default=Path(_integrity_value('path_1ba0c7fb8a53')))
    parser.add_argument("--verify-root", type=Path, default=Path(_integrity_value('path_4f0ff2fe92a7')))
    parser.add_argument("--eval-root", type=Path, default=Path(_integrity_value('path_efaf193b4c54')))
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_34cb67a175d2')))
    args = parser.parse_args()
    result = evaluate(args.store_root, args.projection_db, args.verify_root, args.eval_root)
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    atomic_json(args.receipt_root / f"p1-transition-{stamp}-cursor-{result['cursor']}.json", result, mode=0o440)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
