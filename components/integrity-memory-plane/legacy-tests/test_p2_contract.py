from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from p2_contract import Envelope, ack_decision, build_batch  # noqa: E402


MANIFEST = "a" * 64


def event(cursor: int, previous: str = "", uid: str | None = None, payload: dict | None = None) -> Envelope:
    return Envelope(
        tenant_id="workspace",
        namespace="seed://project/default",
        edge_id="source-linux",
        cursor=cursor,
        event_uid=uid or f"uid-{cursor}",
        ts_utc=f"2026-08-08T19:{cursor:02d}:00Z",
        payload=payload or {"id": cursor, "summary": f"event {cursor}"},
        source_manifest_sha256=MANIFEST,
        previous_envelope_sha256=previous,
    )


class P2ContractTests(unittest.TestCase):
    def test_ordered_batch_is_hash_chained_and_partitioned(self) -> None:
        first = event(1).value()
        batch = build_batch([event(1), event(2, first["envelope_sha256"])])
        self.assertEqual((1, 2, 2), (batch["first_cursor"], batch["last_cursor"], batch["event_count"]))
        self.assertIn("tenant=workspace", batch["object_key"])
        self.assertIn("cursor_bucket=000000000000", batch["object_key"])
        self.assertFalse(batch["production_authority"])

    def test_out_of_order_and_broken_chain_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "ascending"):
            build_batch([event(2), event(1)])
        with self.assertRaisesRegex(ValueError, "hash chain"):
            build_batch([event(1), event(2, "b" * 64)])

    def test_event_uid_payload_collision_is_quarantined(self) -> None:
        first = event(1, uid="same", payload={"v": 1}).value()
        with self.assertRaisesRegex(ValueError, "collision"):
            build_batch([event(1, uid="same", payload={"v": 1}), event(2, first["envelope_sha256"], uid="same", payload={"v": 2})])

    def test_shadow_never_claims_rpo_zero_or_authority(self) -> None:
        result = ack_decision(chain_contiguous=True, worm_primary_readback=True, bus_replicas=3, bus_fault_domains=2, offhost_readback=True, uid_collision_count=0, shadow_mode=True)
        self.assertEqual("SHADOW_DURABLE", result["status"])
        self.assertFalse(result["rpo_zero_after_this_ack"])
        self.assertFalse(result["production_authority"])

    def test_production_ack_requires_every_durability_proof(self) -> None:
        denied = ack_decision(chain_contiguous=True, worm_primary_readback=True, bus_replicas=1, bus_fault_domains=1, offhost_readback=True, uid_collision_count=0, shadow_mode=False)
        self.assertEqual("NOT_ACKED", denied["status"])
        self.assertFalse(denied["rpo_zero_after_this_ack"])
        accepted = ack_decision(chain_contiguous=True, worm_primary_readback=True, bus_replicas=3, bus_fault_domains=2, offhost_readback=True, uid_collision_count=0, shadow_mode=False)
        self.assertEqual("PRODUCTION_ACK", accepted["status"])
        self.assertTrue(accepted["rpo_zero_after_this_ack"])


if __name__ == "__main__":
    unittest.main()
