#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Evaluate P2 shadow retrieval against canonical P1 on fixed golden evidence."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, sha256_bytes
from p2_dual_read import run_dual


PROTOCOL = "integrity-memory-plane.p2-dual-golden-eval.v1"


def recall(expected: list[int], observed: list[int]) -> float:
    return 1.0 if not expected else len(set(expected) & set(observed)) / len(set(expected))


def case_outcome(case: dict[str, Any], p1: dict[str, Any], p2: dict[str, Any], dual: dict[str, Any], limit: int, capsule_budget: int) -> dict[str, Any]:
    expected = [int(value) for value in case.get("expected_event_ids") or []]
    p1_ids = [int(value) for value in p1.get("included_event_ids") or []]
    p2_ids = [int(value) for value in p2.get("included_event_ids") or []]
    ranks = {event_id: index + 1 for index, event_id in enumerate(p2_ids)}
    p1_recall = recall(expected, p1_ids)
    p2_recall = recall(expected, p2_ids)
    expected_decision = str(case.get("expected_decision"))
    rank_ok = all(event_id in ranks and ranks[event_id] <= int(case.get("max_rank") or limit) for event_id in expected)
    expected_sequence = [int(value) for value in case.get("expected_sequence") or []]
    p2_sequence = [int(value) for value in ((p2.get("causal_path") or {}).get("event_ids") or [])]
    sequence_ok = not expected_sequence or p2_sequence == expected_sequence
    proof_ok = p2.get("all_included_proven") is True
    decision_ok = p2.get("decision") == expected_decision
    negative_ok = expected_decision != "NO_EVIDENCE" or not p2_ids
    checks = {
        "decision": decision_ok,
        "expected_rank": rank_ok,
        "causal_sequence": sequence_ok,
        "exact_worm_proof": proof_ok,
        "capsule_budget": int(p2.get("capsule_bytes") or 0) <= capsule_budget,
        "p2_recall_not_worse": p2_recall >= p1_recall,
        "unsupported_green_zero": int(p2.get("unsupported_green_count") or 0) == 0,
        "negative_stays_unknown": negative_ok,
        "p1_remains_served_plane": dual.get("served_plane") == "P1_CANONICAL_WITNESS" and dual.get("p2_served_to_agent") is False,
    }
    return {
        "id": case["id"],
        "category": case.get("category"),
        "query": case["query"],
        "ok": all(checks.values()),
        "checks": checks,
        "expected_event_ids": expected,
        "p1_event_ids": p1_ids,
        "p2_event_ids": p2_ids,
        "p1_recall": p1_recall,
        "p2_recall": p2_recall,
        "p2_sequence": p2_sequence,
        "dual_disposition": dual.get("disposition"),
        "double_proof_event_ids": dual.get("double_proof_event_ids"),
        "p1_elapsed_ms": p1.get("elapsed_ms"),
        "p2_elapsed_ms": p2.get("elapsed_ms"),
        "p1_receipt_sha256": dual["p1"]["receipt_sha256"],
        "p2_receipt_sha256": dual["p2"]["receipt_sha256"],
    }


def run_eval(args: argparse.Namespace) -> dict[str, Any]:
    fixture = json.loads(args.fixture.read_text(encoding="utf-8"))
    if fixture.get("protocol") != "integrity-memory-plane.p1-golden-eval.v1":
        raise RuntimeError("dual golden fixture protocol mismatch")
    outcomes: list[dict[str, Any]] = []
    for case in fixture.get("cases") or []:
        p1, p2, dual = run_dual(
            str(case["query"]),
            p1_projection_db=args.p1_projection_db,
            p1_store_root=args.p1_store_root,
            pg_env=args.pg_env,
            minio_env=args.minio_env,
            receipts_root=args.receipts,
            limit=args.limit,
            capsule_budget=args.capsule_bytes,
        )
        outcomes.append(case_outcome(case, p1, p2, dual, args.limit, args.capsule_bytes))
    expected_total = sum(len(value["expected_event_ids"]) for value in outcomes)
    p2_found = sum(len(set(value["expected_event_ids"]) & set(value["p2_event_ids"])) for value in outcomes)
    authority = [value for value in outcomes if value["category"] == "authority"]
    authority_expected = sum(len(value["expected_event_ids"]) for value in authority)
    authority_found = sum(len(set(value["expected_event_ids"]) & set(value["p2_event_ids"])) for value in authority)
    causal = next((value for value in outcomes if value["category"] == "causal-path"), None)
    causal_expected = len(causal["expected_event_ids"]) if causal else 0
    causal_found = len(set(causal["expected_event_ids"]) & set(causal["p2_sequence"])) if causal else 0
    latencies = sorted(float(value["p2_elapsed_ms"] or 0.0) for value in outcomes)
    p95 = latencies[max(0, math.ceil(0.95 * len(latencies)) - 1)] if latencies else 0.0
    metrics = {
        "case_count": len(outcomes),
        "case_pass_count": sum(1 for value in outcomes if value["ok"]),
        "expected_recall_at_20": p2_found / expected_total if expected_total else 1.0,
        "authority_boundary_recall": authority_found / authority_expected if authority_expected else 1.0,
        "causal_path_recall_at_20": causal_found / causal_expected if causal_expected else 1.0,
        "early_event_1_found": any(value["id"] == "early-event-1" and 1 in value["p2_event_ids"] for value in outcomes),
        "negative_stays_unknown": all(value["checks"]["negative_stays_unknown"] for value in outcomes if value["category"] == "negative"),
        "p2_recall_not_worse_all_cases": all(value["checks"]["p2_recall_not_worse"] for value in outcomes),
        "unsupported_green_count": sum(0 if value["checks"]["unsupported_green_zero"] else 1 for value in outcomes),
        "p2_retrieval_p95_ms": round(p95, 3),
        "capsule_budget_bytes": args.capsule_bytes,
    }
    gates = {
        "all_cases_pass": metrics["case_pass_count"] == metrics["case_count"],
        "authority_boundary_recall_100": metrics["authority_boundary_recall"] == 1.0,
        "causal_path_recall_at_20_gte_95": metrics["causal_path_recall_at_20"] >= 0.95,
        "early_event_1": metrics["early_event_1_found"] is True,
        "negative_unknown": metrics["negative_stays_unknown"] is True,
        "p2_not_worse": metrics["p2_recall_not_worse_all_cases"] is True,
        "unsupported_green_zero": metrics["unsupported_green_count"] == 0,
        "retrieval_p95_lte_2000ms": metrics["p2_retrieval_p95_ms"] <= 2000,
        "capsule_budget_8_to_32k": 8192 <= args.capsule_bytes <= 32768,
    }
    result = {
        "protocol": PROTOCOL + ".receipt",
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
    parser.add_argument("--fixture", type=Path, default=Path(_integrity_value('path_def59ca62c26')))
    parser.add_argument("--p1-projection-db", type=Path, default=Path(_integrity_value('path_1ba0c7fb8a53')))
    parser.add_argument("--p1-store-root", type=Path, default=Path(_integrity_value('path_5350cd670b63')))
    parser.add_argument("--pg-env", type=Path, default=Path("/etc/integrity-memory-p2/dual-reader.env"))
    parser.add_argument("--minio-env", type=Path, default=Path("/etc/integrity-memory-p2/dual-reader-minio.env"))
    parser.add_argument("--receipts", type=Path, default=Path(_integrity_value('path_f5a9a1727fe8')))
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_77511ec53d36')))
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--capsule-bytes", type=int, default=32768)
    args = parser.parse_args()
    result = run_eval(args)
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = args.receipt_root / f"dual-golden-{stamp}-{result['receipt_sha256'][:16]}.json"
    atomic_json(path, result, mode=0o440)
    print(json.dumps({**result, "receipt_path": str(path)}, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
