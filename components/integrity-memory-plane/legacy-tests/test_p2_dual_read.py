from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from p2_dual_read import compare  # noqa: E402


def receipt(plane: str, ids: list[int], decision: str = "SUPPORTED", cursor: int = 10) -> dict:
    proof_name = "manifest_proof" if plane == "p1" else "worm_proof"
    return {
        "query_sha256": "a" * 64,
        "decision": decision,
        "projection_cursor": cursor,
        "raw_head_cursor": cursor,
        "offsets_equal": True,
        "coverage_complete_to_raw_head": True,
        "included_event_ids": ids,
        "capsule_sha256": plane * 32,
        "capsule": {"events": [{"event_id": value, proof_name: {"ok": True}} for value in ids]},
        "unsupported_green_count": 0,
    }


def test_exact_equivalence_has_double_proof_and_serves_only_p1() -> None:
    result = compare("#1", receipt("p1", [1]), receipt("p2", [1]))
    assert result["disposition"] == "EQUIVALENT"
    assert result["double_proof_event_ids"] == [1]
    assert result["double_proof_ok"] is True
    assert result["served_plane"] == "P1_CANONICAL_WITNESS"
    assert result["p2_served_to_agent"] is False


def test_arbitrary_extra_p2_hits_are_divergence_not_unproven_better() -> None:
    result = compare("memory", receipt("p1", [1]), receipt("p2", [1, 2]))
    assert result["disposition"] == "DIVERGED"


def test_unproven_p2_cannot_be_equivalent() -> None:
    p2 = receipt("p2", [1], decision="UNPROVEN")
    result = compare("#1", receipt("p1", [1]), p2)
    assert result["disposition"] == "UNPROVEN"
