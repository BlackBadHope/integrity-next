from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import p2_billion_capacity as capacity  # noqa: E402


def observation() -> dict:
    relation = lambda rows, size: {"rows": rows, "heap_bytes": size // 2, "index_bytes": size // 2, "total_bytes": size}
    return {
        "postgres": {
            "events": 10_000,
            "raw_partition_distribution": [
                {"relation": "p0", "rows": 2500},
                {"relation": "p1", "rows": 2500},
                {"relation": "p2", "rows": 2500},
                {"relation": "p3", "rows": 2500},
            ],
            "raw_partition_total_bytes": 1_000_000,
            "guard_tables": {
                "ingest_batches": relation(50, 100_000),
                "dead_letters": relation(0, 0),
                "gap_guard_runs": relation(1, 1),
            },
            "projections": {
                "projection_fts_events": relation(10_000, 2_000_000),
                "projection_vector_events": relation(10_000, 1_000_000),
                "projection_graph_nodes": relation(100, 100_000),
                "projection_graph_edges": relation(20_000, 1_000_000),
                "current_task_state": relation(100, 100_000),
            },
        },
        "s3": {"latest_logical_bytes": 1_000_000},
        "linux_free_bytes": 10**15,
        "client": {
            "volumes": [{"drive": "D", "free_bytes": 10**15}],
            "capsules": 1,
            "capsule_total_bytes": 1_000_000,
            "capsule_max_bytes": 1_000_000,
        },
    }


class P2BillionCapacityTests(unittest.TestCase):
    def test_capacity_alone_cannot_claim_completed_billion_run(self) -> None:
        result = capacity.evaluate(observation())
        self.assertEqual("FAIL", result["status"])
        self.assertEqual(["physical_billion_run_already_completed"], result["blockers"])
        self.assertFalse(result["production_authority"])

    def test_skew_cumulative_capsules_and_low_capacity_all_fail(self) -> None:
        value = copy.deepcopy(observation())
        value["postgres"]["raw_partition_distribution"] = [{"relation": "p0", "rows": 10_000}]
        value["client"]["capsules"] = 10
        value["client"]["capsule_total_bytes"] = 10_000_000
        value["linux_free_bytes"] = 1
        value["client"]["volumes"][0]["free_bytes"] = 1
        result = capacity.evaluate(value)
        self.assertIn("raw_partition_max_share_at_most_25_percent", result["blockers"])
        self.assertIn("offhost_is_incremental_not_cumulative_snapshots", result["blockers"])
        self.assertIn("combined_proven_free_capacity_has_2x_headroom", result["blockers"])


if __name__ == "__main__":
    unittest.main()
