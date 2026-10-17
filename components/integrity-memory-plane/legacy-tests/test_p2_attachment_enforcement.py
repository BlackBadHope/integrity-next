from __future__ import annotations

import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from p2_attachment_capacity import ENFORCEMENT_CHECKS  # noqa: E402
from p2_attachment_enforcement import (  # noqa: E402
    _http_events,
    _reference_policy_sha256,
    build_intent,
    deterministic_body,
    negative_checks,
)


def policy() -> dict:
    return {
        "max_object_bytes": 8,
        "max_objects_per_event": 4,
        "max_payload_bytes_per_event": 31,
        "max_manifest_bytes_per_event": 4096,
    }


def test_action_log_reader_auth_denies_before_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import p2_attachment_enforcement as enforcement

    attempted: list[object] = []
    monkeypatch.delenv("CODEX_LOG_TOKEN", raising=False)
    monkeypatch.setattr(
        enforcement,
        "open_direct_http_request",
        lambda *args, **kwargs: attempted.append((args, kwargs)),
    )
    with pytest.raises(RuntimeError, match="required before network I/O"):
        _http_events("http://127.0.0.1:8765", "synthetic-event")
    assert attempted == []



def test_action_log_reader_url_cannot_forward_token_off_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import p2_attachment_enforcement as enforcement

    attempted: list[object] = []
    monkeypatch.setenv("CODEX_LOG_TOKEN", "synthetic-reader-token")
    monkeypatch.setattr(
        enforcement,
        "open_direct_http_request",
        lambda *args, **kwargs: attempted.append((args, kwargs)),
    )
    with pytest.raises(RuntimeError, match="Action Log reader URL"):
        _http_events("http://attacker.example:8765", "synthetic-event")
    assert attempted == []


def test_intent_is_deterministic_and_binds_every_body_digest() -> None:
    first = build_intent("a" * 64, "b" * 64, 32)
    second = build_intent("a" * 64, "b" * 64, 32)
    assert first == second
    assert first["sample_events"] == 4
    assert first["objects_per_event"] == 4
    assert first["total_payload_bytes"] == 512
    for event in first["events"]:
        for item in event["objects"]:
            body = deterministic_body(item["seed"], item["size_bytes"])
            from memory_plane_common import sha256_bytes

            assert sha256_bytes(body) == item["content_sha256"]


def test_negative_enforcement_paths_are_all_reached_without_s3() -> None:
    checks = negative_checks(policy(), "a" * 64)
    assert checks == {
        "oversized_object_rejected": True,
        "fifth_object_rejected": True,
        "payload_budget_overflow_rejected": True,
        "digest_mismatch_rejected": True,
    }
    assert set(checks) < ENFORCEMENT_CHECKS


def test_enforcement_schema_requires_canonical_reference() -> None:
    assert "canonical_event_reference_bound" in ENFORCEMENT_CHECKS
    assert "all_canonical_attachment_references_validated" in ENFORCEMENT_CHECKS


def test_historical_reference_keeps_its_policy_generation() -> None:
    current = "a" * 64
    historical = "b" * 64
    reference = {"policy_file_sha256": historical}
    assert _reference_policy_sha256(reference, "old-event", current, {"new-event"}) == historical
    with pytest.raises(RuntimeError, match="current attachment reference policy mismatch"):
        _reference_policy_sha256(reference, "new-event", current, {"new-event"})
