from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from p2_dlq import replay_eligibility  # noqa: E402


def test_uncertain_or_already_delivered_dead_letter_is_not_replayable() -> None:
    eligible, reasons = replay_eligibility(
        "preflight_nondeterministic_source_manifest",
        {"sequence": 2, "postgres_ingest_committed": False, "raw_object": {"key": "k", "version_id": "v", "content_sha256": "0" * 64}},
        False,
    )
    assert not eligible
    assert "reason_not_replay_allowlisted" in reasons
    assert "bus_sequence_already_assigned" in reasons


def test_only_exact_unpublished_allowlisted_worm_source_can_be_eligible() -> None:
    eligible, reasons = replay_eligibility(
        "delivery_failed_before_bus_publish_after_worm_commit",
        {"postgres_ingest_committed": False, "raw_object": {"key": "k", "version_id": "v", "content_sha256": "0" * 64}},
        False,
    )
    assert eligible
    assert reasons == []
    assert replay_eligibility("delivery_failed_before_bus_publish_after_worm_commit", {}, False)[0] is False
    assert replay_eligibility("delivery_failed_before_bus_publish_after_worm_commit", {"raw_object": {"key": "k", "version_id": "v", "content_sha256": "0" * 64}}, True)[0] is False
