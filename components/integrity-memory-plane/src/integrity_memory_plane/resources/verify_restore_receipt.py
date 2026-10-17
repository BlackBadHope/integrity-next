#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Re-evaluate a durable restore receipt without repeating the restore drill."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import json
from pathlib import Path

from memory_plane_common import atomic_json, sha256_file


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source = json.loads(args.receipt.read_text(encoding="utf-8"))
    seed = source.get("seed") or {}
    sync = seed.get("sync") or {}
    verify = seed.get("verify") or {}
    connection = seed.get("early_event_connections") or {}
    queries = seed.get("queries") or {}
    outer = source.get("checks") or {}
    checks = {
        "full_archive_digest": outer.get("full_archive_digest") is True,
        "full_manifest": outer.get("full_manifest") is True,
        "restored_cursor_match": outer.get("restored_cursor_match") is True,
        "restored_row_digest_match": outer.get("restored_row_digest_match") is True,
        "append_only": outer.get("append_only") is True,
        "action_log_service_smoke": outer.get("action_log_service_smoke") is True,
        "seed_sync_pass": sync.get("result") == "PASS",
        "seed_verify_ok": verify.get("ok") is True,
        "seed_event_count_match": int(sync.get("event_count") or -1) == int(verify.get("event_count") or -2),
        "seed_cursor_match": int(sync.get("event_cursor") or -1) == int((source.get("tail") or {}).get("target_cursor") or -2),
        "home_excluded": int(verify.get("home_record_count", -1)) == 0,
        "production_authority_false": verify.get("production_authority") is False,
        "known_queries_nonempty": bool(queries) and all(int(value) > 0 for value in queries.values()),
        "early_event_path_found": int(connection.get("event_id") or 0) == 1803 and connection.get("result") in {"CONNECTED", "CONTEXT_ONLY"},
    }
    correction = {
        "protocol": "integrity-memory-plane.restore-drill-correction.v1",
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "source_receipt": str(args.receipt),
        "source_receipt_sha256": sha256_file(args.receipt),
        "source_status": source.get("status"),
        "correction": "home_record_count=0 is a successful privacy boundary; the original verifier used int(0 or -1)",
        "checks": checks,
        "status": "pass" if all(checks.values()) else "failed",
    }
    atomic_json(args.output, correction)
    print(json.dumps(correction, ensure_ascii=False, sort_keys=True))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
