from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from p2_capacity_supplement import (  # noqa: E402
    ATTACHMENT_BUCKET,
    RAW_BUCKET,
    TARGET_EVENTS,
    evaluate,
)


def observation(*, events: int = 100, bus_stream_bytes: int = 400, bus_allocated_bytes: int = 800) -> dict:
    value = {
        "postgres": {
            "raw_events": events,
            "ingest_batches": 4,
            "batch_event_sum": events,
            "first_cursor": 1,
            "last_cursor": events + 3,
            "max_bus_sequence": 11,
            "raw_object_identities": 4,
            "raw_object_identity_sha256": "d" * 64,
            "dead_letter_raw_objects": 0,
        },
        "nats_before": {
            "server": {"max_storage": 25_000_000_000, "storage_used": 1000, "store_dir": "/data", "sync_always": True},
            "stream": {"state": {"last_seq": 10}},
        },
        "nats_after": {
            "server": {"max_storage": 25_000_000_000, "storage_used": 1000, "store_dir": "/data", "sync_always": True},
            "stream": {
                "config": {
                    "retention": "limits",
                    "max_msgs": -1,
                    "max_bytes": 20_000_000_000,
                    "max_age": 0,
                    "max_msgs_per_subject": -1,
                    "discard": "new",
                    "storage": "file",
                    "num_replicas": 1,
                    "deny_delete": True,
                    "deny_purge": True,
                },
                "state": {"messages": 5, "bytes": bus_stream_bytes, "first_seq": 1, "last_seq": 11},
            },
        },
        "s3_after": {
            RAW_BUCKET: {
                "versions": 5,
                "latest_objects": 5,
                "noncurrent_versions": 0,
                "all_version_bytes": 1000,
                "latest_bytes": 1000,
                "version_overhang_bytes": 0,
                "delete_markers": 0,
                "incomplete_multipart_uploads": 0,
                "prefix_version_counts": {"_bootstrap": 1, "raw": 4},
                "max_versions_per_key": 1,
                "inventory_records": 5,
                "inventory_sha256": "a" * 64,
                "raw_object_identities": 4,
                "raw_object_identity_sha256": "d" * 64,
                "versioning": "Enabled",
                "object_lock": "Enabled",
                "retention_mode": "COMPLIANCE",
                "retention_days": 30,
            },
            ATTACHMENT_BUCKET: {
                "versions": 1,
                "latest_objects": 1,
                "noncurrent_versions": 0,
                "all_version_bytes": 132,
                "latest_bytes": 132,
                "version_overhang_bytes": 0,
                "delete_markers": 0,
                "incomplete_multipart_uploads": 0,
                "prefix_version_counts": {"_bootstrap": 1},
                "max_versions_per_key": 1,
                "inventory_records": 1,
                "inventory_sha256": "b" * 64,
                "raw_object_identities": 0,
                "raw_object_identity_sha256": "e" * 64,
                "versioning": "Enabled",
                "object_lock": "Enabled",
                "retention_mode": "COMPLIANCE",
                "retention_days": 30,
            },
        },
        "filesystem": {
            "nats": {
                "logical_bytes": bus_stream_bytes,
                "allocated_bytes": bus_allocated_bytes,
                "files": 2,
                "filesystem_total_bytes": 100_000_000_000,
                "filesystem_available_bytes": 80_000_000_000,
                "filesystem_used_bytes": 20_000_000_000,
                "filesystem_device_id": 123,
            },
            "minio": {"logical_bytes": 2000, "allocated_bytes": 3000, "files": 10},
            "minio_raw": {"logical_bytes": 1200, "allocated_bytes": 2000, "files": 8},
            "minio_attachments": {"logical_bytes": 200, "allocated_bytes": 4096, "files": 1},
            "minio_system": {"logical_bytes": 600, "allocated_bytes": 800, "files": 1},
        },
        "bindings": {
            "physical_stage_admission_file_sha256": "a" * 64,
            "fault_domain_topology_sha256": "b" * 64,
        },
        "configuration_files": [],
        "artifact_sha256": {},
        "gap_guard": {
            "receipt": {
                "committed_events": events,
                "committed_batches": 4,
                "early_cursor_present": True,
                "s3": {"keys": 4, "committed_keys": 4, "known_dlq_keys": 0},
            }
        },
    }
    value["s3_before"] = copy.deepcopy(value["s3_after"])
    return value


def test_bus_and_object_measurements_are_admitted_but_attachment_zero_is_not() -> None:
    result = evaluate(observation())
    assert result["status"] == "INCOMPLETE"
    assert result["measurement_checks"] == {"bus": True, "object_store": True, "attachments": False}
    assert result["bus"]["target_capacity_admitted"] is True
    assert result["object_store"]["all_versions_used_not_latest_only"] is True
    assert result["attachments"]["required_bytes_per_region"] is None
    assert result["attachments"]["zero_is_not_used_as_capacity_evidence"] is True
    assert result["blockers"] == [
        "attachment_capacity_policy_bound",
        "attachment_nonbootstrap_workload_observed",
    ]


def test_target_capacity_cannot_be_admitted_from_an_invalid_bus_measurement() -> None:
    value = observation()
    value["postgres"]["batch_event_sum"] -= 1

    result = evaluate(value)

    assert result["checks"]["bus_stream_max_bytes_has_2x_target_headroom"] is True
    assert result["checks"]["source_event_and_batch_counts_consistent"] is False
    assert result["measurement_checks"]["bus"] is False
    assert result["bus"]["target_capacity_admitted"] is False


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    (
        ("discard_new_per_subject", True),
        ("allow_rollup_hdrs", True),
        ("allow_msg_ttl", True),
        ("allow_msg_schedules", True),
        ("allow_atomic", True),
        ("allow_batched", True),
        ("subject_transform", {"src": "a", "dest": "b"}),
        ("republish", {"src": ">", "dest": "copy.>"}),
        ("subject_delete_marker_ttl", 60),
        ("compression", "s2"),
        ("persist_mode", "async"),
    ),
)
def test_full_history_sizing_rejects_retention_or_representation_drift(
    field: str,
    unsafe_value: object,
) -> None:
    value = observation()
    value["nats_after"]["stream"]["config"][field] = unsafe_value

    result = evaluate(value)

    assert result["checks"]["bus_stream_contract_classified"] is False
    assert result["measurement_checks"]["bus"] is False
    assert result["bus"]["target_capacity_admitted"] is False


def test_full_history_bus_limit_one_byte_short_is_a_blocker() -> None:
    value = observation(events=4001, bus_stream_bytes=1, bus_allocated_bytes=1)
    exact = (TARGET_EVENTS + 4000) // 4001
    value["nats_after"]["stream"]["config"]["max_bytes"] = exact - 1
    value["nats_after"]["server"]["max_storage"] = exact
    result = evaluate(value)
    assert result["bus"]["projected_stream_logical_bytes_at_target"] == exact
    assert result["checks"]["bus_stream_max_bytes_covers_target"] is False
    assert "bus_stream_max_bytes_covers_target" in result["blockers"]


def test_bus_admission_requires_2x_target_and_not_only_1x() -> None:
    value = observation()
    projected = (400 * TARGET_EVENTS + 99) // 100
    value["nats_after"]["stream"]["config"]["max_bytes"] = projected * 2 - 1
    result = evaluate(value)
    assert result["checks"]["bus_stream_max_bytes_covers_target"] is True
    assert result["checks"]["bus_stream_max_bytes_has_2x_target_headroom"] is False
    assert result["bus"]["required_stream_logical_bytes_with_2x_headroom"] == projected * 2
    assert result["bus"]["target_capacity_admitted"] is False


def test_stream_2x_target_exactly_at_high_watermark_is_blocked() -> None:
    value = observation()
    projected = (400 * TARGET_EVENTS + 99) // 100
    required_2x = projected * 2
    value["nats_after"]["stream"]["config"]["max_bytes"] = required_2x * 100 // 80
    result = evaluate(value)
    assert result["checks"]["bus_stream_max_bytes_has_2x_target_headroom"] is True
    assert result["checks"]["bus_stream_2x_target_below_high_watermark"] is False
    assert required_2x * 100 == result["bus"]["config"]["max_bytes"] * 80
    assert result["bus"]["target_capacity_admitted"] is False


def test_server_2x_target_includes_other_store_and_blocks_exact_high_watermark() -> None:
    value = observation()
    projected_physical = (800 * TARGET_EVENTS + 99) // 100
    required_physical_2x = projected_physical * 2
    other_store = 1000 - 400
    projected_server_usage = required_physical_2x + other_store
    exact_high_watermark_capacity = projected_server_usage * 100 // 80
    value["nats_after"]["server"]["max_storage"] = exact_high_watermark_capacity
    result = evaluate(value)
    assert result["bus"]["server_other_store_bytes"] == other_store
    assert result["bus"]["projected_server_storage_bytes_at_2x_target"] == projected_server_usage
    assert result["checks"]["bus_server_max_storage_has_2x_target_headroom"] is True
    assert result["checks"]["bus_server_2x_target_below_high_watermark"] is False
    assert projected_server_usage * 100 == exact_high_watermark_capacity * 80
    assert result["bus"]["target_capacity_admitted"] is False


def test_filesystem_2x_growth_plus_reserve_exactly_at_high_watermark_is_blocked() -> None:
    value = observation()
    # 2x projected physical usage is 16,000,000,000 bytes.  Subtract the
    # current 800-byte allocation to obtain the incremental filesystem growth.
    growth = 15_999_999_200
    projected_used = 20_000_000_000 + growth
    total = projected_used * 100 // 80
    available = total - 20_000_000_000
    value["filesystem"]["nats"].update(
        {
            "filesystem_total_bytes": total,
            "filesystem_available_bytes": available,
            "filesystem_used_bytes": 20_000_000_000,
        }
    )
    result = evaluate(value)
    assert result["bus"]["physical_growth_bytes_to_2x_target"] == growth
    assert result["bus"]["projected_filesystem_used_bytes_at_2x_target"] == projected_used
    assert available == growth + result["bus"]["filesystem_reserve_bytes"]
    assert result["checks"]["bus_filesystem_can_grow_to_2x_target_with_reserve"] is False
    assert result["checks"]["bus_filesystem_2x_target_below_high_watermark"] is False
    assert projected_used * 100 == total * 80
    assert result["checks"]["bus_filesystem_below_high_watermark"] is True
    assert result["bus"]["target_capacity_admitted"] is False


def test_bus_filesystem_exactly_high_watermark_is_blocked() -> None:
    value = observation()
    value["filesystem"]["nats"]["filesystem_available_bytes"] = 20_000_000_000
    value["filesystem"]["nats"]["filesystem_used_bytes"] = 80_000_000_000
    result = evaluate(value)
    assert result["checks"]["bus_filesystem_below_high_watermark"] is False
    assert result["bus"]["target_capacity_admitted"] is False


def test_projection_uses_exact_integer_ceil_above_float_range() -> None:
    events = 4001
    allocated = (1 << 54) + 1
    value = observation(events=events, bus_stream_bytes=1, bus_allocated_bytes=allocated)
    value["nats_after"]["server"]["max_storage"] = allocated * TARGET_EVENTS
    result = evaluate(value)
    expected = (allocated * TARGET_EVENTS + events - 1) // events
    assert result["bus"]["projected_physical_bytes_at_target"] == expected
    assert result["bus"]["allocated_bytes_per_event"]["numerator_bytes"] == allocated
    assert result["bus"]["allocated_bytes_per_event"]["denominator_events"] == events


def test_latest_only_cannot_hide_version_overhang() -> None:
    value = observation()
    value["s3_after"][RAW_BUCKET]["all_version_bytes"] = 1500
    value["s3_after"][RAW_BUCKET]["latest_bytes"] = 900
    value["s3_after"][RAW_BUCKET]["version_overhang_bytes"] = 600
    value["s3_after"][RAW_BUCKET]["versions"] = 6
    value["s3_after"][RAW_BUCKET]["noncurrent_versions"] = 1
    value["s3_after"][RAW_BUCKET]["prefix_version_counts"]["legacy"] = 1
    value["s3_after"][RAW_BUCKET]["inventory_records"] = 6
    value["s3_before"] = copy.deepcopy(value["s3_after"])
    result = evaluate(value)
    ratio = result["object_store"]["raw_all_versions_bytes_per_event"]
    assert ratio["numerator_bytes"] == 15
    assert ratio["denominator_events"] == 1
    assert result["object_store"]["buckets"][RAW_BUCKET]["version_overhang_bytes"] == 600


def test_unmeasured_multipart_or_duplicate_version_fails_object_measurement() -> None:
    value = observation()
    value["s3_after"][RAW_BUCKET]["incomplete_multipart_uploads"] = 1
    value["s3_after"][RAW_BUCKET]["max_versions_per_key"] = 2
    value["s3_before"] = copy.deepcopy(value["s3_after"])
    result = evaluate(value)
    assert result["measurement_checks"]["object_store"] is False
    assert result["checks"]["object_store_no_unmeasured_multipart_uploads"] is False
    assert result["checks"]["raw_content_addressed_version_multiplicity_one"] is False


def test_truthy_non_boolean_worm_state_does_not_pass() -> None:
    value = observation()
    value["s3_after"][RAW_BUCKET]["object_lock"] = "true"
    value["s3_before"] = copy.deepcopy(value["s3_after"])
    result = evaluate(value)
    assert result["checks"]["object_store_worm_contract_verified"] is False


def test_source_count_or_bus_order_mismatch_is_fail_closed() -> None:
    value = observation()
    value["postgres"]["batch_event_sum"] -= 1
    value["postgres"]["max_bus_sequence"] = 12
    result = evaluate(value)
    assert result["measurement_checks"]["bus"] is False
    assert result["checks"]["source_event_and_batch_counts_consistent"] is False
    assert result["checks"]["bus_stream_snapshot_ordered_around_postgres"] is False


def test_inventory_race_delete_marker_and_gap_drift_are_fail_closed() -> None:
    value = observation()
    value["s3_before"][RAW_BUCKET]["inventory_sha256"] = "c" * 64
    value["s3_after"][RAW_BUCKET]["delete_markers"] = 1
    value["s3_after"][RAW_BUCKET]["inventory_records"] = 6
    value["gap_guard"]["receipt"]["committed_events"] += 1
    result = evaluate(value)
    assert result["checks"]["object_store_inventory_stable_during_physical_measurement"] is False
    assert result["checks"]["object_store_delete_markers_absent"] is False
    assert result["checks"]["gap_guard_exact_raw_object_parity_bound"] is False
    assert result["measurement_checks"]["object_store"] is False
