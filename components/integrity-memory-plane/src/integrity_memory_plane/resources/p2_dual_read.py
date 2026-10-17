#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare canonical P1 and shadow P2 retrieval without creating two authorities."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, sha256_bytes
from p1_retrieval import retrieve as p1_retrieve
from p2_retrieval import connect, load_env, retrieve as p2_retrieve, s3_client


PROTOCOL = "integrity-memory-plane.p2-dual-read.v1"


def compare(query: str, p1: dict[str, Any], p2: dict[str, Any]) -> dict[str, Any]:
    if p1.get("query_sha256") != p2.get("query_sha256"):
        raise RuntimeError("dual-read query digest mismatch")
    common_cursor = min(int(p1.get("projection_cursor") or 0), int(p2.get("projection_cursor") or 0))
    p1_ids = [int(value) for value in p1.get("included_event_ids") or [] if int(value) <= common_cursor]
    p2_ids = [int(value) for value in p2.get("included_event_ids") or [] if int(value) <= common_cursor]
    p1_set = set(p1_ids)
    p2_set = set(p2_ids)
    double_proof = sorted(p1_set & p2_set)
    exact = bool(__import__("re").fullmatch(r"#?\d+", query.strip()) or query.strip().startswith("event_uid:"))
    causal = query.strip().startswith("task_path:")
    p1_supported = p1.get("decision") == "SUPPORTED"
    p2_supported = p2.get("decision") == "SUPPORTED"
    if p2.get("decision") == "UNPROVEN" or not p2.get("offsets_equal"):
        disposition = "UNPROVEN"
    elif exact:
        disposition = "EQUIVALENT" if p1_supported == p2_supported and p1_ids == p2_ids else "DIVERGED"
    elif causal:
        p1_path = [int(value) for value in ((p1.get("causal_path") or {}).get("event_ids") or []) if int(value) <= common_cursor]
        p2_path = [int(value) for value in ((p2.get("causal_path") or {}).get("event_ids") or []) if int(value) <= common_cursor]
        disposition = "EQUIVALENT" if p1_supported == p2_supported and p1_path == p2_path else "DIVERGED"
    elif not p1_supported and not p2_supported:
        disposition = "EQUIVALENT"
    elif p1_supported and p2_supported and p1_set == p2_set:
        disposition = "EQUIVALENT"
    else:
        disposition = "DIVERGED"
    double_proof_ok = all(
        any(int(event["event_id"]) == event_id and (event.get("manifest_proof") or {}).get("ok") is True for event in (p1.get("capsule") or {}).get("events") or [])
        and any(int(event["event_id"]) == event_id and (event.get("worm_proof") or {}).get("ok") is True for event in (p2.get("capsule") or {}).get("events") or [])
        for event_id in double_proof
    )
    receipt = {
        "protocol": PROTOCOL + ".receipt",
        "query": query.strip(),
        "query_sha256": p1["query_sha256"],
        "common_cursor": common_cursor,
        "disposition": disposition,
        "served_plane": "P1_CANONICAL_WITNESS",
        "served_capsule_sha256": p1.get("capsule_sha256"),
        "p2_served_to_agent": False,
        "p1": {"decision": p1.get("decision"), "cursor": p1.get("projection_cursor"), "included_event_ids": p1_ids, "receipt_sha256": sha256_bytes(canonical_json(p1)), "capsule_sha256": p1.get("capsule_sha256")},
        "p2": {"decision": p2.get("decision"), "cursor": p2.get("projection_cursor"), "raw_head_cursor": p2.get("raw_head_cursor"), "coverage_complete_to_raw_head": p2.get("coverage_complete_to_raw_head"), "included_event_ids": p2_ids, "receipt_sha256": sha256_bytes(canonical_json(p2)), "capsule_sha256": p2.get("capsule_sha256")},
        "double_proof_event_ids": double_proof,
        "double_proof_ok": double_proof_ok,
        "unsupported_green_count": int(p1.get("unsupported_green_count") or 0) + int(p2.get("unsupported_green_count") or 0),
        "production_authority": False,
        "memory_grants_authority": False,
    }
    receipt["receipt_sha256"] = sha256_bytes(canonical_json(receipt))
    return receipt


def run_dual(
    query: str,
    *,
    p1_projection_db: Path,
    p1_store_root: Path,
    pg_env: Path,
    minio_env: Path,
    receipts_root: Path,
    postgres_host: str = "127.0.0.1",
    s3_endpoint: str = _integrity_value('endpoint_1940bdd68a0a'),
    limit: int = 20,
    capsule_budget: int = 32768,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    p1 = p1_retrieve(query, p1_projection_db, p1_store_root, limit=limit, capsule_budget=capsule_budget)
    with connect(load_env(pg_env), postgres_host) as connection:
        p2 = p2_retrieve(query, connection, s3_client(load_env(minio_env), s3_endpoint), receipts_root, limit=limit, capsule_budget=capsule_budget)
    return p1, p2, compare(query, p1, p2)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("query")
    parser.add_argument("--p1-projection-db", type=Path, default=Path(_integrity_value('path_1ba0c7fb8a53')))
    parser.add_argument("--p1-store-root", type=Path, default=Path(_integrity_value('path_5350cd670b63')))
    parser.add_argument("--pg-env", type=Path, default=Path("/etc/integrity-memory-p2/dual-reader.env"))
    parser.add_argument("--minio-env", type=Path, default=Path("/etc/integrity-memory-p2/dual-reader-minio.env"))
    parser.add_argument("--receipts", type=Path, default=Path(_integrity_value('path_f5a9a1727fe8')))
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_77511ec53d36')))
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--capsule-bytes", type=int, default=32768)
    args = parser.parse_args()
    p1, p2, receipt = run_dual(args.query, p1_projection_db=args.p1_projection_db, p1_store_root=args.p1_store_root, pg_env=args.pg_env, minio_env=args.minio_env, receipts_root=args.receipts, limit=args.limit, capsule_budget=args.capsule_bytes)
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = args.receipt_root / f"dual-{stamp}-{receipt['query_sha256'][:16]}-{receipt['receipt_sha256'][:16]}.json"
    atomic_json(path, receipt, mode=0o440)
    print(json.dumps({**receipt, "receipt_path": str(path)}, ensure_ascii=False, sort_keys=True))
    return 0 if receipt["disposition"] == "EQUIVALENT" and receipt["unsupported_green_count"] == 0 else 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
