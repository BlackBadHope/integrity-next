from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from p2_dual_golden_eval import case_outcome  # noqa: E402


def plane(ids: list[int], decision: str = "SUPPORTED") -> dict:
    return {"decision": decision, "included_event_ids": ids, "all_included_proven": True, "capsule_bytes": 1000, "unsupported_green_count": 0, "elapsed_ms": 10, "causal_path": {"event_ids": ids}}


def test_case_requires_p2_not_worse_and_p1_only_serving() -> None:
    case = {"id": "authority", "category": "authority", "query": "authority", "expected_decision": "SUPPORTED", "expected_event_ids": [1], "max_rank": 1}
    dual = {"served_plane": "P1_CANONICAL_WITNESS", "p2_served_to_agent": False, "disposition": "EQUIVALENT", "double_proof_event_ids": [1], "p1": {"receipt_sha256": "1"}, "p2": {"receipt_sha256": "2"}}
    assert case_outcome(case, plane([1]), plane([1]), dual, 20, 32768)["ok"] is True
    assert case_outcome(case, plane([1]), plane([]), dual, 20, 32768)["ok"] is False


def test_negative_case_must_remain_empty() -> None:
    case = {"id": "negative", "category": "negative", "query": "none", "expected_decision": "NO_EVIDENCE", "expected_event_ids": [], "max_rank": 0}
    dual = {"served_plane": "P1_CANONICAL_WITNESS", "p2_served_to_agent": False, "disposition": "EQUIVALENT", "double_proof_event_ids": [], "p1": {"receipt_sha256": "1"}, "p2": {"receipt_sha256": "2"}}
    assert case_outcome(case, plane([], "NO_EVIDENCE"), plane([], "NO_EVIDENCE"), dual, 20, 32768)["ok"] is True
    assert case_outcome(case, plane([], "NO_EVIDENCE"), plane([2], "SUPPORTED"), dual, 20, 32768)["ok"] is False
