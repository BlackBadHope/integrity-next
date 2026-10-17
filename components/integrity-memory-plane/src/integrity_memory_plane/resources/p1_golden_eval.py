#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run reproducible P1 early/authority/causal retrieval evaluation."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import json
import math
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, sha256_bytes
from p1_retrieval import retrieve


EVAL_PROTOCOL = "integrity-memory-plane.p1-golden-eval.v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, default=Path(_integrity_value('path_def59ca62c26')))
    parser.add_argument("--projection-db", type=Path, default=Path(_integrity_value('path_1ba0c7fb8a53')))
    parser.add_argument("--store-root", type=Path, default=Path(_integrity_value('path_5350cd670b63')))
    parser.add_argument("--baseline-url", default=_integrity_value('endpoint_4fc20356fbf3'))
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_efaf193b4c54')))
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--capsule-bytes", type=int, default=32768)
    return parser.parse_args()


def _baseline_ids(base_url: str, query: str, limit: int) -> list[int] | None:
    if not base_url:
        return None
    encoded = urllib.parse.urlencode({"q": query, "limit": str(limit)})
    with urllib.request.urlopen(f"{base_url.rstrip('/')}/v1/seed/search?{encoded}", timeout=5) as response:
        value = json.load(response)
    return [int(event.get("id") or event.get("event_id") or 0) for event in value.get("events") or [] if int(event.get("id") or event.get("event_id") or 0) > 0]


def _recall(expected: list[int], observed: list[int]) -> float:
    if not expected:
        return 1.0
    return len(set(expected) & set(observed)) / len(set(expected))


def run_eval(
    fixture: Path,
    projection_db: Path,
    store_root: Path,
    *,
    baseline_url: str = "",
    limit: int = 20,
    capsule_bytes: int = 32768,
) -> dict[str, Any]:
    specification = json.loads(fixture.read_text(encoding="utf-8"))
    if specification.get("protocol") != EVAL_PROTOCOL:
        raise RuntimeError("P1 golden fixture protocol mismatch")
    outcomes: list[dict[str, Any]] = []
    total_expected = 0
    total_found = 0
    authority_expected = 0
    authority_found = 0
    causal_expected = 0
    causal_found = 0
    latencies: list[float] = []
    unsupported_green = 0
    baseline_comparisons: list[bool] = []
    projection_cursors: set[int] = set()
    for case in specification.get("cases") or []:
        result = retrieve(str(case["query"]), projection_db, store_root, limit=limit, capsule_budget=capsule_bytes)
        observed = [int(value) for value in result.get("included_event_ids") or []]
        expected = [int(value) for value in case.get("expected_event_ids") or []]
        ranks = {event_id: index + 1 for index, event_id in enumerate(observed)}
        found = [event_id for event_id in expected if event_id in ranks]
        rank_ok = all(ranks[event_id] <= int(case.get("max_rank") or limit) for event_id in found) and len(found) == len(expected)
        decision_ok = result.get("decision") == case.get("expected_decision")
        sequence = [int(value) for value in ((result.get("causal_path") or {}).get("event_ids") or [])]
        expected_sequence = [int(value) for value in case.get("expected_sequence") or []]
        sequence_ok = not expected_sequence or sequence == expected_sequence
        proof_ok = result.get("all_included_proven") is True
        capsule_ok = int(result.get("capsule_bytes") or 0) <= capsule_bytes
        unsupported_green += int(result.get("unsupported_green_count") or 0)
        projection_cursors.add(int(result.get("projection_cursor") or 0))
        latency = float(result.get("elapsed_ms") or 0.0)
        latencies.append(latency)
        baseline_ids = _baseline_ids(baseline_url, str(case["query"]), limit) if baseline_url else None
        baseline_recall = _recall(expected, baseline_ids or []) if baseline_ids is not None else None
        p1_recall = _recall(expected, observed)
        if baseline_recall is not None:
            baseline_comparisons.append(p1_recall >= baseline_recall)
        total_expected += len(expected)
        total_found += len(found)
        if case.get("category") == "authority":
            authority_expected += len(expected)
            authority_found += len(found)
        if case.get("category") == "causal-path":
            causal_expected += len(expected_sequence)
            causal_found += len(set(expected_sequence) & set(sequence))
        case_ok = decision_ok and rank_ok and sequence_ok and proof_ok and capsule_ok and int(result.get("unsupported_green_count") or 0) == 0
        outcomes.append(
            {
                "id": case["id"],
                "category": case.get("category"),
                "ok": case_ok,
                "decision": result.get("decision"),
                "expected_event_ids": expected,
                "observed_event_ids": observed,
                "found_event_ids": found,
                "rank_ok": rank_ok,
                "sequence_ok": sequence_ok,
                "proof_ok": proof_ok,
                "capsule_bytes": result.get("capsule_bytes"),
                "elapsed_ms": latency,
                "p1_recall": p1_recall,
                "baseline_recall": baseline_recall,
            }
        )
    ordered_latency = sorted(latencies)
    p95_index = max(0, math.ceil(len(ordered_latency) * 0.95) - 1)
    recall_at_20 = total_found / total_expected if total_expected else 1.0
    authority_recall = authority_found / authority_expected if authority_expected else 1.0
    causal_recall = causal_found / causal_expected if causal_expected else 1.0
    checks = {
        "all_cases_pass": all(case["ok"] for case in outcomes),
        "golden_recall_at_20": recall_at_20 >= 0.95,
        "authority_boundary_recall": authority_recall == 1.0,
        "causal_path_recall": causal_recall >= 0.95,
        "retrieval_p95_under_2s": ordered_latency[p95_index] <= 2000.0,
        "capsule_budget_respected": all(int(case["capsule_bytes"] or 0) <= capsule_bytes for case in outcomes),
        "unsupported_green_zero": unsupported_green == 0,
        "projection_cursor_stable": len(projection_cursors) == 1,
        "baseline_equivalent_or_better": all(baseline_comparisons) if baseline_comparisons else True,
    }
    return {
        "protocol": EVAL_PROTOCOL + ".receipt",
        "status": "pass" if all(checks.values()) else "failed",
        "fixture_sha256": sha256_bytes(canonical_json(specification)),
        "checks": checks,
        "case_count": len(outcomes),
        "cases": outcomes,
        "metrics": {
            "golden_recall_at_20": recall_at_20,
            "authority_boundary_recall": authority_recall,
            "causal_path_recall": causal_recall,
            "retrieval_p95_ms": ordered_latency[p95_index],
            "retrieval_max_ms": max(ordered_latency, default=0.0),
            "unsupported_green_count": unsupported_green,
            "capsule_budget_bytes": capsule_bytes,
        },
        "production_authority": False,
    }


def main() -> int:
    args = parse_args()
    result = run_eval(args.fixture, args.projection_db, args.store_root, baseline_url=args.baseline_url, limit=args.limit, capsule_bytes=args.capsule_bytes)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    atomic_json(args.receipt_root / f"golden-eval-{stamp}.json", result, mode=0o440)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
