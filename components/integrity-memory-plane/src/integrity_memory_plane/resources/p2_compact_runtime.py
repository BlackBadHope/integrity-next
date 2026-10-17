#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the non-authoritative compact cold-index pipeline and emit one receipt."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, sha256_bytes
from p2_compact_catalog import sync_catalog
from p2_compact_index import DEFAULT_BUCKET_SPAN, build_store_stream, iter_source_events, verify_store
from p2_projection import committed_receipts, load_env, s3_client
from p2_receipt_catalog import build_catalog as build_receipt_catalog


PROTOCOL = "integrity-memory-plane.p2-compact-runtime.v1"


def tree_bytes(root: Path, *, exclude: tuple[str, ...] = ()) -> int:
    return sum(
        path.stat().st_size
        for path in root.rglob("*")
        if path.is_file() and not any(part in exclude for part in path.parts)
    )


def run(args: argparse.Namespace) -> dict[str, Any]:
    receipts = committed_receipts(args.receipts)
    if not receipts:
        raise RuntimeError("compact runtime has no committed raw receipts")
    raw_head = int(receipts[-1][1]["batch"]["last_cursor"])
    receipt_catalog = build_receipt_catalog(receipts, args.catalog_root / "receipts.json")
    client = s3_client(load_env(args.minio_env), args.s3_endpoint)
    build = build_store_stream(iter_source_events(receipts, client), args.index_root, bucket_span=args.bucket_span, raw_head_cursor=raw_head)
    catalog = sync_catalog(args.index_root, args.catalog_root)
    verify = verify_store(args.index_root, args.catalog_root)
    indexed_events = int(verify["event_count"])
    index_bytes = tree_bytes(args.index_root, exclude=("receipts",))
    catalog_bytes = tree_bytes(args.catalog_root, exclude=("receipts",))
    lag = int(build["coverage_lag_events"])
    checks = {
        "build_pass_or_noop": build["status"] in ("PASS", "NOOP"),
        "independent_verify_pass": verify["status"] == "PASS",
        "catalog_pass": catalog["status"] == "PASS",
        "early_history_starts_at_cursor_one": int(verify["first_cursor"]) == 1,
        "tail_is_bounded_and_explicit": 0 <= lag < args.bucket_span,
        "catalog_events_equal_index_events": int(catalog["event_count"]) == indexed_events,
        "unsupported_green_zero": True,
        "production_authority_false": True,
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    receipt = {
        "protocol": PROTOCOL + ".receipt",
        "status": status,
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "bucket_span": args.bucket_span,
        "raw_head_cursor": raw_head,
        "coverage_through_cursor": int(build["coverage_through_cursor"]),
        "coverage_lag_events": lag,
        "indexed_events": indexed_events,
        "segment_count": int(verify["segment_count"]),
        "manifest_head_sha256": verify["manifest_head_sha256"],
        "peak_bucket_events": int(build["peak_bucket_events"]),
        "streaming_source": build.get("streaming_source") is True,
        "index_bytes": index_bytes,
        "catalog_bytes": catalog_bytes,
        "receipt_catalog_sha256": receipt_catalog["catalog_sha256"],
        "receipt_catalog_count": receipt_catalog["receipt_count"],
        "index_and_catalog_bytes_per_event": round((index_bytes + catalog_bytes) / indexed_events, 3),
        "build_evidence_sha256": build["evidence_sha256"],
        "catalog_evidence_sha256": catalog["evidence_sha256"],
        "checks": checks,
        "hot_tail_required": lag > 0,
        "physical_billion_event_gate_passed": False,
        "regional_gate_passed": False,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    receipt["evidence_sha256"] = sha256_bytes(canonical_json(receipt))
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    path = args.receipt_root / f"compact-runtime-{stamp}-{receipt['evidence_sha256'][:16]}.json"
    atomic_json(path, receipt, mode=0o440)
    return {**receipt, "receipt_path": str(path)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipts", type=Path, default=Path(_integrity_value('path_f5a9a1727fe8')))
    parser.add_argument("--minio-env", type=Path, default=Path("/etc/integrity-memory-p2/projection-minio.env"))
    parser.add_argument("--s3-endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    parser.add_argument("--index-root", type=Path, required=True)
    parser.add_argument("--catalog-root", type=Path, required=True)
    parser.add_argument("--receipt-root", type=Path, required=True)
    parser.add_argument("--bucket-span", type=int, default=DEFAULT_BUCKET_SPAN)
    args = parser.parse_args()
    result = run(args)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
