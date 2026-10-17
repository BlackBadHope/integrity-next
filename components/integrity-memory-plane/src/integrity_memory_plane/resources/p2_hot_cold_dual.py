#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Merge compact cold and PostgreSQL hot-tail evidence without a new authority."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import concurrent.futures
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, sha256_bytes
from p1_retrieval import retrieve as p1_retrieve
from p2_compact_retrieval import retrieve as cold_retrieve
from p2_dual_read import compare
from p2_retrieval import connect, load_env, retrieve as hot_retrieve, s3_client


PROTOCOL = "integrity-memory-plane.p2-hot-cold-dual.v1"


def _proven(event: dict[str, Any]) -> bool:
    return (event.get("worm_proof") or {}).get("ok") is True


def _rrf(cold: list[dict[str, Any]], hot: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked: list[tuple[float, int, int, dict[str, Any]]] = []
    for plane_priority, values in ((1, cold), (0, hot)):
        for rank, event in enumerate(values, 1):
            ranked.append((1.0 / rank, plane_priority, int(event["event_id"]), event))
    ranked.sort(key=lambda value: (-value[0], value[1], -value[2]))
    result: list[dict[str, Any]] = []
    seen: set[int] = set()
    for _score, _plane, cursor, event in ranked:
        if cursor not in seen:
            seen.add(cursor)
            result.append(event)
    return result


def combine(query: str, cold: dict[str, Any], hot: dict[str, Any], *, limit: int = 20, capsule_budget: int = 32768) -> dict[str, Any]:
    if cold.get("query_sha256") != hot.get("query_sha256"):
        raise RuntimeError("hot/cold query digest mismatch")
    cold_cursor = int(cold.get("projection_cursor") or 0)
    cold_events = list((cold.get("capsule") or {}).get("events") or [])
    hot_events = [event for event in (hot.get("capsule") or {}).get("events") or [] if int(event["event_id"]) > cold_cursor]
    normalized = query.strip()
    exact = bool(re.fullmatch(r"#?\d+", normalized) or normalized.startswith("event_uid:"))
    causal = normalized.startswith("task_path:")
    if exact:
        ordered = cold_events if cold_events else hot_events
    elif causal:
        cold_path = [int(value) for value in ((cold.get("causal_path") or {}).get("event_ids") or [])]
        hot_path = [int(value) for value in ((hot.get("causal_path") or {}).get("event_ids") or []) if int(value) > cold_cursor]
        path = sorted(set([*cold_path, *hot_path]))
        by_cursor = {int(event["event_id"]): event for event in [*cold_events, *hot_events]}
        ordered = [by_cursor[cursor] for cursor in path if cursor in by_cursor]
    else:
        path = []
        ordered = _rrf(cold_events, hot_events)
    included: list[dict[str, Any]] = []
    rejected_budget = 0
    query_sha = str(cold["query_sha256"])
    for event in ordered:
        trial = {
            "protocol": PROTOCOL + ".capsule",
            "query_sha256": query_sha,
            "cold_cursor": cold_cursor,
            "events": [*included, event],
            "production_authority": False,
        }
        if len(canonical_json(trial)) > capsule_budget:
            rejected_budget += 1
            continue
        included.append(event)
        if len(included) >= limit:
            break
    any_unproven = cold.get("decision") == "UNPROVEN" or hot.get("decision") == "UNPROVEN"
    proofs_ok = all(_proven(event) for event in included)
    if any_unproven or (included and not proofs_ok):
        decision = "UNPROVEN"
    elif included:
        decision = "SUPPORTED"
    else:
        decision = "NO_EVIDENCE"
    capsule = {
        "protocol": PROTOCOL + ".capsule",
        "query_sha256": query_sha,
        "cold_cursor": cold_cursor,
        "events": included,
        "production_authority": False,
    }
    causal_path = None
    if causal:
        causal_path = {
            "kind": "TASK_SEQUENCE",
            "task_id": normalized.removeprefix("task_path:").strip(),
            "event_ids": path,
            "complete": bool(path),
        }
    return {
        "protocol": PROTOCOL + ".receipt",
        "decision": decision,
        "truth_status": "shadow-supported-hot-cold" if decision == "SUPPORTED" else "unknown",
        "query": normalized,
        "query_sha256": query_sha,
        "projection_cursor": int(hot.get("projection_cursor") or 0),
        "cold_cursor": cold_cursor,
        "raw_head_cursor": int(hot.get("raw_head_cursor") or 0),
        "projection_lag_events": int(hot.get("projection_lag_events") or 0),
        "coverage_complete_to_raw_head": hot.get("coverage_complete_to_raw_head") is True,
        "offsets_equal": hot.get("offsets_equal") is True,
        "cold_decision": cold.get("decision"),
        "hot_decision": hot.get("decision"),
        "cold_event_ids": [int(event["event_id"]) for event in cold_events],
        "hot_tail_event_ids": [int(event["event_id"]) for event in hot_events],
        "included_event_ids": [int(event["event_id"]) for event in included],
        "causal_path": causal_path,
        "all_included_proven": proofs_ok,
        "rejected_capsule_budget_count": rejected_budget,
        "unsupported_green_count": int(cold.get("unsupported_green_count") or 0) + int(hot.get("unsupported_green_count") or 0),
        "support_gate": {
            "cold_cursor_boundary_enforced": True,
            "hot_events_must_be_after_cold_cursor": True,
            "exact_worm_version_required": True,
            "p1_remains_served": True,
        },
        "capsule_bytes": len(canonical_json(capsule)),
        "capsule_budget_bytes": capsule_budget,
        "capsule_sha256": sha256_bytes(canonical_json(capsule)),
        "capsule": capsule,
        "elapsed_ms": round(float(cold.get("elapsed_ms") or 0) + float(hot.get("elapsed_ms") or 0), 3),
        "production_authority": False,
        "memory_grants_authority": False,
    }


def run_dual(
    query: str,
    *,
    p1_projection_db: Path,
    p1_store_root: Path,
    index_root: Path,
    catalog_root: Path,
    pg_env: Path,
    minio_env: Path,
    receipts_root: Path,
    postgres_host: str = "127.0.0.1",
    s3_endpoint: str = _integrity_value('endpoint_1940bdd68a0a'),
    limit: int = 20,
    capsule_budget: int = 32768,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    pg_values = load_env(pg_env)
    minio_values = load_env(minio_env)

    def read_p1() -> dict[str, Any]:
        return p1_retrieve(query, p1_projection_db, p1_store_root, limit=limit, capsule_budget=capsule_budget)

    def read_cold() -> dict[str, Any]:
        client = s3_client(minio_values, s3_endpoint)
        return cold_retrieve(
            query,
            index_root,
            receipts_root,
            client,
            limit=limit,
            capsule_budget=capsule_budget,
            catalog_root=catalog_root,
            receipt_catalog_path=catalog_root / "receipts.json",
        )

    def read_hot() -> dict[str, Any]:
        client = s3_client(minio_values, s3_endpoint)
        with connect(pg_values, postgres_host) as connection:
            return hot_retrieve(
                query,
                connection,
                client,
                receipts_root,
                limit=limit,
                capsule_budget=capsule_budget,
                receipt_catalog_path=catalog_root / "receipts.json",
            )

    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=3, thread_name_prefix="integrity-p2-read") as executor:
        p1_future = executor.submit(read_p1)
        cold_future = executor.submit(read_cold)
        hot_future = executor.submit(read_hot)
        cold = cold_future.result()
        hot = hot_future.result()
        p2_elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        p1 = p1_future.result()
    end_to_end_elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    merged = combine(query, cold, hot, limit=limit, capsule_budget=capsule_budget)
    merged["elapsed_ms"] = p2_elapsed_ms
    merged["end_to_end_elapsed_ms"] = end_to_end_elapsed_ms
    merged["component_elapsed_ms"] = {
        "cold": float(cold.get("elapsed_ms") or 0.0),
        "hot": float(hot.get("elapsed_ms") or 0.0),
        "p1_parallel": float(p1.get("elapsed_ms") or 0.0),
    }
    merged["execution"] = "parallel-independent-read-domains"
    return p1, merged, compare(query, p1, merged)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("query")
    parser.add_argument("--p1-projection-db", type=Path, default=Path(_integrity_value('path_1ba0c7fb8a53')))
    parser.add_argument("--p1-store-root", type=Path, default=Path(_integrity_value('path_5350cd670b63')))
    parser.add_argument("--index-root", type=Path, default=Path(_integrity_value('path_2bc0a1dc9ccf')))
    parser.add_argument("--catalog-root", type=Path, default=Path(_integrity_value('path_545661f97ab7')))
    parser.add_argument("--pg-env", type=Path, default=Path("/etc/integrity-memory-p2/dual-reader.env"))
    parser.add_argument("--minio-env", type=Path, default=Path("/etc/integrity-memory-p2/dual-reader-minio.env"))
    parser.add_argument("--receipts", type=Path, default=Path(_integrity_value('path_f5a9a1727fe8')))
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_77511ec53d36')))
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--capsule-bytes", type=int, default=32768)
    args = parser.parse_args()
    p1, merged, receipt = run_dual(
        args.query,
        p1_projection_db=args.p1_projection_db,
        p1_store_root=args.p1_store_root,
        index_root=args.index_root,
        catalog_root=args.catalog_root,
        pg_env=args.pg_env,
        minio_env=args.minio_env,
        receipts_root=args.receipts,
        limit=args.limit,
        capsule_budget=args.capsule_bytes,
    )
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = args.receipt_root / f"hot-cold-dual-{stamp}-{receipt['query_sha256'][:16]}-{receipt['receipt_sha256'][:16]}.json"
    atomic_json(path, receipt, mode=0o440)
    print(json.dumps({**receipt, "receipt_path": str(path)}, ensure_ascii=False, sort_keys=True))
    return 0 if receipt["disposition"] == "EQUIVALENT" and receipt["unsupported_green_count"] == 0 else 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
