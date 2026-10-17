from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import p2_fault_lab as lab  # noqa: E402


class P2FaultLabTests(unittest.TestCase):
    def test_synthetic_source_is_deterministic_and_collision_is_cross_batch(self) -> None:
        source = lab.SyntheticActionLog(10_000)
        self.assertEqual(source.event(42), source.event(42))
        source.set_collision_tail(10_001)
        self.assertEqual(source.event(10_000)["event_uid"], source.event(10_001)["event_uid"])
        self.assertNotEqual(source.event(10_000)["summary"], source.event(10_001)["summary"])

    def test_lab_endpoints_use_separate_loopback_identity(self) -> None:
        self.assertEqual("127.0.0.2", lab.LAB_HOST)
        self.assertNotEqual(8765, lab.SOURCE_PORT)
        self.assertNotEqual(19000, lab.SOURCE_PORT)

    def test_last_json_parser_ignores_diagnostics(self) -> None:
        self.assertEqual({"status": "PASS"}, lab.parse_last_json("note\n{\"status\":\"PASS\"}\n"))


if __name__ == "__main__":
    unittest.main()
