from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import p2_fault_lab_verify as verifier  # noqa: E402


def valid_receipt(root: Path) -> dict:
    command_log = root / "logs" / "commands.jsonl"
    command_log.parent.mkdir(parents=True)
    command_log.write_text("{\"status\":\"PASS\"}\n", encoding="utf-8")
    projection = {
        "last_cursor": 10_000,
        "projection_sha256": "a" * 64,
        "row_count": 10_000,
        "source_batch_sha256": "b" * 64,
    }
    value = {
        "protocol": verifier.PROTOCOL,
        "status": "PASS",
        "production_authority": False,
        "memory_grants_authority": False,
        "ack_boundary": {
            "production_authority": False,
            "rpo_zero_claimed": False,
            "shadow_receipts_not_production_ack": True,
        },
        "isolation": {
            "canonical_action_log_touched": False,
            "p1_touched": False,
            "production_endpoints_touched": False,
            "host": "127.0.0.2",
        },
        "production_baseline": {"required_10x_events_per_minute": 930.0},
        "load": {
            "events": 10_000,
            "batch_count": 50,
            "clean_measured_events": 9_600,
            "events_per_minute": 7_000.0,
            "production_peak_multiplier": 75.0,
            "postgres": {"events": 10_000, "batches": 50},
        },
        "faults": {key: True for key in verifier.BOOLEAN_FAULTS},
        "guard": {
            "baseline_status": "PASS",
            "red_status": "FAIL",
            "final_status": "PASS",
            "final_hard_failures": {"missing_event_rows": 0},
            "final_projection_lag": {name: 0 for name in verifier.PROJECTIONS},
        },
        "projection_rebuild": {
            "parity": True,
            "sync": {name: dict(projection) for name in verifier.PROJECTIONS},
            "rebuild": {name: dict(projection) for name in verifier.PROJECTIONS},
        },
        "lab_root": str(root),
        "command_log_sha256": verifier.sha256_file(command_log),
    }
    value["faults"]["postgres_mid_transaction_exit_code"] = 97
    value["receipt_sha256"] = verifier.semantic_sha256(value)
    return value


class P2FaultLabVerifyTests(unittest.TestCase):
    def test_valid_receipt_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual([], verifier.verify(valid_receipt(Path(temporary))))

    def test_mutation_breaks_semantic_digest_and_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt = valid_receipt(Path(temporary))
            receipt["faults"]["object_outage_fail_closed"] = False
            errors = verifier.verify(receipt)
            self.assertIn("semantic receipt SHA-256 mismatch", errors)
            self.assertIn("fault gate is not proven: object_outage_fail_closed", errors)

    def test_rehashed_projection_mutation_still_fails_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt = copy.deepcopy(valid_receipt(Path(temporary)))
            receipt["projection_rebuild"]["rebuild"]["fts"]["row_count"] = 9_999
            receipt["receipt_sha256"] = verifier.semantic_sha256(receipt)
            self.assertIn("projection rebuild differs: fts", verifier.verify(receipt))

    def test_legacy_receipt_allows_only_cleanup_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt = valid_receipt(Path(temporary))
            command_log = Path(temporary) / "logs" / "commands.jsonl"
            with command_log.open("a", encoding="utf-8") as handle:
                handle.write('{"label":"docker-logs-test","returncode":0}\n')
            self.assertEqual([], verifier.verify(receipt))
            with command_log.open("a", encoding="utf-8") as handle:
                handle.write('{"label":"relay-unbound-work","returncode":0}\n')
            self.assertIn("command log SHA-256/prefix mismatch", verifier.verify(receipt))


if __name__ == "__main__":
    unittest.main()
