#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Golden recall and authority-boundary gate for hot+cold compact retrieval."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, sha256_bytes
from p2_dual_golden_eval import case_outcome
from p2_hot_cold_dual import run_dual


PROTOCOL = "integrity-memory-plane.p2-compact-dual-golden.v1"


def run_eval(args: argparse.Namespace) -> dict[str, Any]:
    fixture = json.loads(args.fixture.read_text(encoding="utf-8"))
    if fixture.get("protocol") != "integrity-memory-plane.p1-golden-eval.v1":
        raise RuntimeError("compact golden fixture protocol mismatch")
    outcomes: list[dict[str, Any]] = []
    for case in fixture.get("cases") or []:
        p1, p2, dual = run_dual(
            str(case["query"]),
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
        outcome = case_outcome(case, p1, p2, dual, args.limit, args.capsule_bytes)
        outcome["end_to_end_elapsed_ms"] = float(p2.get("end_to_end_elapsed_ms") or p2.get("elapsed_ms") or 0.0)
        outcomes.append(outcome)
    expected_total = sum(len(value["expected_event_ids"]) for value in outcomes)
    found = sum(len(set(value["expected_event_ids"]) & set(value["p2_event_ids"])) for value in outcomes)
    authority = [value for value in outcomes if value["category"] == "authority"]
    authority_expected = sum(len(value["expected_event_ids"]) for value in authority)
    authority_found = sum(len(set(value["expected_event_ids"]) & set(value["p2_event_ids"])) for value in authority)
    causal = next((value for value in outcomes if value["category"] == "causal-path"), None)
    causal_expected = len(causal["expected_event_ids"]) if causal else 0
    causal_found = len(set(causal["expected_event_ids"]) & set(causal["p2_sequence"])) if causal else 0
    latencies = sorted(float(value["p2_elapsed_ms"] or 0.0) for value in outcomes)
    p95 = latencies[max(0, math.ceil(0.95 * len(latencies)) - 1)] if latencies else 0.0
    end_to_end_latencies = sorted(float(value["end_to_end_elapsed_ms"] or 0.0) for value in outcomes)
    end_to_end_p95 = end_to_end_latencies[max(0, math.ceil(0.95 * len(end_to_end_latencies)) - 1)] if end_to_end_latencies else 0.0
    metrics = {
        "case_count": len(outcomes),
        "case_pass_count": sum(1 for value in outcomes if value["ok"]),
        "expected_recall_at_20": found / expected_total if expected_total else 1.0,
        "authority_boundary_recall": authority_found / authority_expected if authority_expected else 1.0,
        "causal_path_recall_at_20": causal_found / causal_expected if causal_expected else 1.0,
        "early_event_1_found": any(value["id"] == "early-event-1" and 1 in value["p2_event_ids"] for value in outcomes),
        "negative_stays_unknown": all(value["checks"]["negative_stays_unknown"] for value in outcomes if value["category"] == "negative"),
        "p2_recall_not_worse_all_cases": all(value["checks"]["p2_recall_not_worse"] for value in outcomes),
        "unsupported_green_count": sum(0 if value["checks"]["unsupported_green_zero"] else 1 for value in outcomes),
        "retrieval_p95_ms": round(p95, 3),
        "end_to_end_p95_ms": round(end_to_end_p95, 3),
        "capsule_budget_bytes": args.capsule_bytes,
    }
    gates = {
        "all_cases_pass": metrics["case_pass_count"] == metrics["case_count"],
        "authority_boundary_recall_100": metrics["authority_boundary_recall"] == 1.0,
        "causal_path_recall_at_20_gte_95": metrics["causal_path_recall_at_20"] >= 0.95,
        "early_event_1": metrics["early_event_1_found"],
        "negative_unknown": metrics["negative_stays_unknown"],
        "p2_not_worse": metrics["p2_recall_not_worse_all_cases"],
        "unsupported_green_zero": metrics["unsupported_green_count"] == 0,
        "retrieval_p95_lte_2000ms": metrics["retrieval_p95_ms"] <= 2000,
        "end_to_end_p95_lte_2500ms": metrics["end_to_end_p95_ms"] <= 2500,
        "capsule_budget_8_to_32k": 8192 <= args.capsule_bytes <= 32768,
    }
    result = {
        "protocol": PROTOCOL + ".receipt",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "PASS" if all(gates.values()) else "FAIL",
        "fixture_sha256": sha256_bytes(canonical_json(fixture)),
        "metrics": metrics,
        "gates": gates,
        "outcomes": outcomes,
        "served_plane": "P1_CANONICAL_WITNESS",
        "p2_served_to_agent": False,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    result["receipt_sha256"] = sha256_bytes(canonical_json(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, default=Path(_integrity_value('path_4eca12dbe6bf')))
    parser.add_argument("--p1-projection-db", type=Path, default=Path(_integrity_value('path_1ba0c7fb8a53')))
    parser.add_argument("--p1-store-root", type=Path, default=Path(_integrity_value('path_5350cd670b63')))
    parser.add_argument("--index-root", type=Path, default=Path(_integrity_value('path_2bc0a1dc9ccf')))
    parser.add_argument("--catalog-root", type=Path, default=Path(_integrity_value('path_545661f97ab7')))
    parser.add_argument("--pg-env", type=Path, default=Path("/etc/integrity-memory-p2/dual-reader.env"))
    parser.add_argument("--minio-env", type=Path, default=Path("/etc/integrity-memory-p2/dual-reader-minio.env"))
    parser.add_argument("--receipts", type=Path, default=Path(_integrity_value('path_f5a9a1727fe8')))
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_921dd9207d14')))
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--capsule-bytes", type=int, default=32768)
    args = parser.parse_args()
    result = run_eval(args)
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = args.receipt_root / f"compact-dual-golden-{stamp}-{result['receipt_sha256'][:16]}.json"
    atomic_json(path, result, mode=0o440)
    print(json.dumps({**result, "receipt_path": str(path)}, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
