from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from p1_golden_eval import EVAL_PROTOCOL, run_eval  # noqa: E402
from p1_projection import rebuild_projection  # noqa: E402
from p1_segment_witness import write_witness  # noqa: E402
from tests.test_p1_segment_witness import make_db  # noqa: E402


class P1GoldenEvalTests(unittest.TestCase):
    def test_early_positive_and_unknown_negative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.sqlite3"
            make_db(source)
            args = type("Args", (), {"source_db": source, "store_root": root / "store", "lock": root / "writer.lock", "namespace": "seed://project/test", "segment_events": 2, "max_events": 0})()
            write_witness(args)
            projection = root / "projection.sqlite3"
            rebuild_projection(args.store_root, projection)
            fixture = root / "fixture.json"
            fixture.write_text(
                json.dumps(
                    {
                        "protocol": EVAL_PROTOCOL,
                        "cases": [
                            {"id": "early", "category": "early", "query": "#1", "expected_decision": "SUPPORTED", "expected_event_ids": [1], "max_rank": 1},
                            {"id": "semantic", "category": "authority", "query": "first", "expected_decision": "SUPPORTED", "expected_event_ids": [1], "max_rank": 3},
                            {"id": "negative", "category": "negative", "query": "qzxwvutnomemory987654321", "expected_decision": "NO_EVIDENCE", "expected_event_ids": [], "max_rank": 0},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = run_eval(fixture, projection, args.store_root, baseline_url="", limit=20, capsule_bytes=8192)
            self.assertEqual("pass", result["status"])
            self.assertTrue(all(result["checks"].values()), result["checks"])
            self.assertEqual(1.0, result["metrics"]["authority_boundary_recall"])
            self.assertEqual(0, result["metrics"]["unsupported_green_count"])


if __name__ == "__main__":
    unittest.main()
