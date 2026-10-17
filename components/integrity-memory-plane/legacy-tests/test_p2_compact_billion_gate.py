from __future__ import annotations

import copy
import datetime as dt
import json
import os
import sys
from fractions import Fraction
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file  # noqa: E402
from p2_compact_billion_gate import (  # noqa: E402
    ATTACHMENT_CAPACITY_PROTOCOL,
    ATTACHMENT_ENFORCEMENT_CHECKS,
    ATTACHMENT_ENFORCEMENT_PROTOCOL,
    BUS_TARGET_CAPACITY_ADMISSION_CHECKS,
    PHYSICAL_PROTOCOL,
    PROTOCOL,
    REQUIRED_ADMISSION_CHECKS,
    REQUIRED_PHYSICAL_CHECKS,
    REQUIRED_RETRIEVAL_CHECKS,
    REQUIRED_ATTACHMENT_CAPACITY_CHECKS,
    REQUIRED_VERIFY_CHECKS,
    RETRIEVAL_PROTOCOL,
    STAGE_ADMISSION_PROTOCOL,
    TARGET_EVENTS,
    VERIFY_PROTOCOL,
    _independently_validate_bus_target_watermarks,
    _artifact_path,
    evaluate,
    latest_golden_recall,
    latest_physical_offhost,
    load_stage_admissions,
    validate_attachment_capacity,
    validate_stage_admission,
)


def _write_signed(path: Path, value: dict) -> tuple[dict, str]:
    value = json.loads(json.dumps(value))
    value.pop("evidence_sha256", None)
    value["evidence_sha256"] = sha256_bytes(canonical_json(value))
    atomic_json(path, value)
    return value, sha256_file(path)


def _artifact_digests() -> tuple[dict[str, str], dict[str, str]]:
    verify = {
        "compact_index": sha256_file(ROOT / "p2_compact_index.py"),
        "compact_catalog": sha256_file(ROOT / "p2_compact_catalog.py"),
        "physical_verify_replay": sha256_file(ROOT / "p2_physical_verify_replay.py"),
    }
    retrieval = {
        "compact_index": verify["compact_index"],
        "compact_catalog": verify["compact_catalog"],
        "compact_retrieval": sha256_file(ROOT / "p2_compact_retrieval.py"),
        "physical_retrieval_replay": sha256_file(ROOT / "p2_physical_retrieval_replay.py"),
    }
    return verify, retrieval


def _stage_fixture(
    base: Path,
    *,
    count: int = 1_000_000,
    state_count: int | None = None,
    component_bytes: int | None = None,
    previous: Path | None = None,
) -> Path:
    root = (base / f"physical-{count}").resolve()
    index_state_path = root / "compact-index" / "state.json"
    catalog_state_path = root / "compact-catalog" / "state.json"
    actual_state_count = count if state_count is None else state_count
    atomic_json(index_state_path, {"event_count": actual_state_count})
    atomic_json(catalog_state_path, {"uid_records": actual_state_count})
    index_sha = sha256_file(index_state_path)
    catalog_sha = sha256_file(catalog_state_path)
    total = component_bytes if component_bytes is not None else count * 200

    physical_checks = {name: True for name in REQUIRED_PHYSICAL_CHECKS}
    physical, physical_file_sha = _write_signed(
        root / "receipts" / "physical.json",
        {
            "protocol": PHYSICAL_PROTOCOL,
            "status": "PASS",
            "stage": f"physical-{count}",
            "physical_event_count": count,
            "storage": {
                name: {"logical_bytes": total, "allocated_bytes": total, "files": 1}
                for name in ("raw", "index", "catalog", "receipts")
            },
            "checks": physical_checks,
            "blockers": [],
            "sparse_or_extrapolated_run": False,
            "production_authority": False,
            "memory_grants_authority": False,
        },
    )
    verify_artifacts, retrieval_artifacts = _artifact_digests()
    manifest_head = "a" * 64
    verify, verify_file_sha = _write_signed(
        root / "verify-receipts" / "verify.json",
        {
            "protocol": VERIFY_PROTOCOL,
            "status": "PASS",
            "physical_event_count": count,
            "source_root": str(root),
            "physical_receipt_evidence_sha256": physical["evidence_sha256"],
            "physical_receipt_file_sha256": physical_file_sha,
            "index_state_sha256": index_sha,
            "catalog_state_sha256": catalog_sha,
            "artifact_sha256": verify_artifacts,
            "checks": {name: True for name in REQUIRED_VERIFY_CHECKS},
            "verify": {"manifest_head_sha256": manifest_head},
            "blockers": [],
            "production_authority": False,
            "memory_grants_authority": False,
        },
    )
    retrieval, retrieval_file_sha = _write_signed(
        root / "retrieval-receipts" / "retrieval.json",
        {
            "protocol": RETRIEVAL_PROTOCOL,
            "status": "PASS",
            "physical_event_count": count,
            "source_root": str(root),
            "physical_receipt_evidence_sha256": physical["evidence_sha256"],
            "physical_receipt_file_sha256": physical_file_sha,
            "verify_receipt_evidence_sha256": verify["evidence_sha256"],
            "verify_receipt_file_sha256": verify_file_sha,
            "reader_attestation": {"snapshot_sha256": catalog_sha},
            "artifact_sha256": retrieval_artifacts,
            "checks": {name: True for name in REQUIRED_RETRIEVAL_CHECKS},
            "blockers": [],
            "production_authority": False,
            "memory_grants_authority": False,
        },
    )
    billion = count >= TARGET_EVENTS
    if count == 1_000_000:
        previous_evidence_sha = ""
        previous_file_sha = ""
    elif previous is not None:
        previous_value = json.loads(previous.read_text(encoding="utf-8"))
        previous_evidence_sha = previous_value["evidence_sha256"]
        previous_file_sha = sha256_file(previous)
    else:
        # A direct validator fixture may carry syntactically valid linkage;
        # load_stage_admissions still rejects it when the predecessor is absent.
        previous_evidence_sha = "b" * 64
        previous_file_sha = "c" * 64
    admission_path = root / "admissions" / f"admission-{count}.json"
    admission, _ = _write_signed(
        admission_path,
        {
            "protocol": STAGE_ADMISSION_PROTOCOL,
            "created_utc": dt.datetime.now(dt.UTC).isoformat(),
            "status": "PASS",
            "source_root": str(root),
            "stage_lineage_root": str(base.resolve()),
            "physical_event_count": count,
            "stage": f"physical-{count}",
            "source_receipts": {
                "physical": {
                    "path": str(root / "receipts" / "physical.json"),
                    "file_sha256": physical_file_sha,
                    "evidence_sha256": physical["evidence_sha256"],
                },
                "verify": {
                    "path": str(root / "verify-receipts" / "verify.json"),
                    "file_sha256": verify_file_sha,
                    "evidence_sha256": verify["evidence_sha256"],
                },
                "retrieval": {
                    "path": str(root / "retrieval-receipts" / "retrieval.json"),
                    "file_sha256": retrieval_file_sha,
                    "evidence_sha256": retrieval["evidence_sha256"],
                },
            },
            "index_state_sha256": index_sha,
            "catalog_state_sha256": catalog_sha,
            "compact_manifest_head_sha256": manifest_head,
            "checks": {**{name: True for name in REQUIRED_ADMISSION_CHECKS}, "stage_predecessor_exact": True},
            "milestone_checks": {
                "physical_100k_completed": count >= 100_000,
                "physical_1m_completed": count >= 1_000_000,
                "physical_10m_completed": count >= 10_000_000,
                "physical_100m_completed": count >= 100_000_000,
            },
            "release_checks": {
                "physical_billion_event_run_completed": billion,
                "combined_proven_free_capacity_has_2x_headroom": False,
                "regional_failover_rpo_rto_verified": False,
                "full_semantic_projection_raw_equivalence_verified": False,
            },
            "physical_billion_event_run_completed": billion,
            "previous_stage_admission_sha256": previous_evidence_sha,
            "previous_stage_admission_file_sha256": previous_file_sha,
            "blockers": [],
            "production_authority": False,
            "memory_grants_authority": False,
        },
    )
    assert admission["physical_event_count"] == count
    return admission_path


def _domains(free: int) -> list[dict]:
    return [
        {
            "name": "A",
            "host_id": "host-a",
            "storage_domain_id": "storage-a",
            "power_domain_id": "power-a",
            "region_id": "region-a",
            "free_bytes": free,
            "live_observation": True,
            "topology_attested": True,
        },
        {
            "name": "B",
            "host_id": "host-b",
            "storage_domain_id": "storage-b",
            "power_domain_id": "power-b",
            "region_id": "region-b",
            "free_bytes": free,
            "live_observation": True,
            "topology_attested": True,
        },
    ]


def _valid_bus_target_claim() -> tuple[dict, dict, int, int]:
    projected_logical = 4_000_000_000
    projected_physical = 8_000_000_000
    required_physical_2x = 16_000_000_000
    allocated = 800
    stream_bytes = 400
    server_store_used = 1000
    other_store = server_store_used - stream_bytes
    filesystem_used = 20_000_000_000
    filesystem_total = 100_000_000_000
    physical_growth = required_physical_2x - allocated
    bus = {
        "state_after": {"bytes": stream_bytes},
        "config": {"max_bytes": 20_000_000_000},
        "server": {"max_storage": 25_000_000_000, "storage_used": server_store_used},
        "filesystem": {
            "allocated_bytes": allocated,
            "filesystem_total_bytes": filesystem_total,
            "filesystem_available_bytes": filesystem_total - filesystem_used,
            "filesystem_used_bytes": filesystem_used,
        },
        "projected_server_storage_bytes_at_2x_target": other_store + required_physical_2x,
        "projected_filesystem_used_bytes_at_2x_target": filesystem_used + physical_growth,
        "target_capacity_admitted": True,
    }
    return bus, {name: True for name in BUS_TARGET_CAPACITY_ADMISSION_CHECKS}, projected_logical, projected_physical


def test_compact_validator_rejects_forged_target_watermark_fields_and_booleans() -> None:
    bus, checks, projected_logical, projected_physical = _valid_bus_target_claim()
    assert _independently_validate_bus_target_watermarks(
        bus,
        checks,
        projected_logical=projected_logical,
        projected_physical=projected_physical,
    ) is True

    forged_field = copy.deepcopy(bus)
    forged_field["projected_server_storage_bytes_at_2x_target"] += 1
    with pytest.raises(RuntimeError, match="fields are not measurement-derived"):
        _independently_validate_bus_target_watermarks(
            forged_field,
            checks,
            projected_logical=projected_logical,
            projected_physical=projected_physical,
        )

    forged_check = dict(checks)
    forged_check["bus_filesystem_2x_target_below_high_watermark"] = False
    with pytest.raises(RuntimeError, match="checks are not measurement-derived"):
        _independently_validate_bus_target_watermarks(
            bus,
            forged_check,
            projected_logical=projected_logical,
            projected_physical=projected_physical,
        )

    forged_admission = copy.deepcopy(bus)
    forged_admission["target_capacity_admitted"] = False
    with pytest.raises(RuntimeError, match="admission is forged"):
        _independently_validate_bus_target_watermarks(
            forged_admission,
            checks,
            projected_logical=projected_logical,
            projected_physical=projected_physical,
        )


def test_compact_validator_rederives_strict_stream_target_high_watermark() -> None:
    bus, checks, projected_logical, projected_physical = _valid_bus_target_claim()
    required_stream_2x = projected_logical * 2
    bus["config"]["max_bytes"] = required_stream_2x * 100 // 80
    # The forged receipt keeps the old green boolean at exact 80%; independent
    # integer arithmetic must reject it before trusting target_capacity_admitted.
    with pytest.raises(RuntimeError, match="checks are not measurement-derived"):
        _independently_validate_bus_target_watermarks(
            bus,
            checks,
            projected_logical=projected_logical,
            projected_physical=projected_physical,
        )


def _observation(stage_scan: dict | None = None, *, events: int = 10_000, bytes_each: int | None = None) -> dict:
    total = bytes_each if bytes_each is not None else events * 10
    return {
        "postgres": {"events": events, "guard_tables": {"ingest_batches": {"total_bytes": total}}},
        "s3": {"latest_logical_bytes": total},
        "compact": {"events": events, "logical_bytes": total, "allocated_bytes": total, "files": 1},
        "catalog": {"events": events, "logical_bytes": total, "allocated_bytes": total, "files": 1},
        "capacity_domains": _domains(10**15),
        "stage_admissions": stage_scan,
        "regional_failover_evidence": {"valid": True},
        "physical_offhost_evidence": {"valid": True},
        "golden_recall_evidence": {"valid": True},
    }


def test_naked_green_booleans_never_admit() -> None:
    observed = _observation(None)
    observed.update(
        {
            "catalog_verified": True,
            "retrieval_verified": True,
            "physical_incremental_offhost_verified": True,
            "golden_recall_verified": True,
            "physical_billion_completed": True,
            "regional_failover_verified": True,
        }
    )
    result = evaluate(observed)
    assert result["status"] == "FAIL"
    assert result["checks"]["physical_billion_event_run_completed"] is False
    assert result["checks"]["latest_physical_stage_admission_digest_chain_valid"] is False
    assert result["legacy_boolean_claims_ignored"] is True


def test_one_million_is_only_a_milestone_and_physical_catalog_wins(tmp_path: Path) -> None:
    admission = _stage_fixture(tmp_path, count=1_000_000)
    scan = load_stage_admissions(tmp_path)
    assert scan["latest"]["path"] == str(admission)
    result = evaluate(_observation(scan))
    assert result["checks"]["latest_physical_stage_admission_digest_chain_valid"] is True
    assert result["checks"]["physical_billion_event_run_completed"] is False
    assert result["stage_admission_evidence"]["latest_physical_event_count"] == 1_000_000
    assert result["selected_component_bytes_per_event"]["catalog"]["selected_source"].startswith("physical:1000000:")
    assert result["status"] == "FAIL"


def test_required_check_schema_cannot_be_replaced_by_dummy_true(tmp_path: Path) -> None:
    path = _stage_fixture(tmp_path)
    value = json.loads(path.read_text(encoding="utf-8"))
    value["checks"] = {"dummy": True}
    _write_signed(path, value)
    checked = validate_stage_admission(path)
    assert checked["valid"] is False
    assert "all-green admitted milestone" in checked["error"]


def test_coordinated_rehashed_billion_claim_fails_live_state_count_binding(tmp_path: Path) -> None:
    path = _stage_fixture(tmp_path, count=TARGET_EVENTS, state_count=1_000_000)
    checked = validate_stage_admission(path)
    assert checked["valid"] is False
    assert "state count mismatch" in checked["error"]


def test_latest_corrupt_receipt_poison_does_not_fallback(tmp_path: Path) -> None:
    admission = _stage_fixture(tmp_path)
    corrupt = tmp_path / "admission-corrupt.json"
    corrupt.write_text('{"protocol":', encoding="utf-8")
    future = dt.datetime.now().timestamp() + 60
    os.utime(corrupt, (future, future))
    scan = load_stage_admissions(tmp_path)
    assert scan["selection_authority"] == "physical_event_count_and_predecessor_digests"
    assert scan["latest"]["path"] == str(admission)
    assert scan["latest"]["valid"] is True
    assert scan["all_valid"] is False
    assert scan["digest_chain_valid"] is False
    assert scan["invalid"][0]["path"] == str(corrupt)
    result = evaluate(_observation(scan))
    assert result["checks"]["physical_billion_event_run_completed"] is False


def test_stage_tip_is_selected_by_exact_digest_chain_not_mtime(tmp_path: Path) -> None:
    genesis = _stage_fixture(tmp_path, count=1_000_000)
    ten_million = _stage_fixture(tmp_path, count=10_000_000, previous=genesis)
    future = dt.datetime.now().timestamp() + 600
    os.utime(genesis, (future, future))

    scan = load_stage_admissions(tmp_path)

    assert scan["digest_chain_valid"] is True
    assert scan["latest"]["path"] == str(ten_million)
    assert [entry["receipt"]["physical_event_count"] for entry in scan["ordered_chain"]] == [
        1_000_000,
        10_000_000,
    ]


def test_forged_predecessor_digest_poison_fails_closed(tmp_path: Path) -> None:
    genesis = _stage_fixture(tmp_path, count=1_000_000)
    ten_million = _stage_fixture(tmp_path, count=10_000_000, previous=genesis)
    value = json.loads(ten_million.read_text(encoding="utf-8"))
    value["previous_stage_admission_sha256"] = "f" * 64
    _write_signed(ten_million, value)

    scan = load_stage_admissions(tmp_path)

    assert scan["all_valid"] is True
    assert scan["digest_chain_valid"] is False
    assert any("predecessor evidence digest mismatch" in error for error in scan["chain_errors"])


def test_same_storage_domain_cannot_be_counted_twice(tmp_path: Path) -> None:
    _stage_fixture(tmp_path)
    observed = _observation(load_stage_admissions(tmp_path))
    observed["capacity_domains"][1]["storage_domain_id"] = "storage-a"
    result = evaluate(observed)
    assert result["checks"]["at_least_two_independent_live_capacity_domains"] is False
    assert result["checks"]["combined_proven_free_capacity_has_2x_headroom"] is False


def test_capacity_uses_componentwise_max_exact_fraction_and_ceil(tmp_path: Path) -> None:
    events = 1_000_000
    _stage_fixture(tmp_path, count=events, component_bytes=1)
    result = evaluate(_observation(load_stage_admissions(tmp_path), events=events, bytes_each=1))
    expected_one_region = (Fraction(5, events) * TARGET_EVENTS).__ceil__()
    projection = result["capacity_projection"]
    assert projection["known_one_region_bytes"] == expected_one_region
    assert projection["known_required_per_domain_with_2x_headroom_bytes"] == expected_one_region * 2
    assert projection["known_required_total_with_2x_headroom_bytes"] == expected_one_region * 4
    assert result["protocol"] == PROTOCOL + ".evidence"


def test_capacity_lower_bound_never_greens_missing_bus_object_and_attachment_storage(tmp_path: Path) -> None:
    _stage_fixture(tmp_path)
    result = evaluate(_observation(load_stage_admissions(tmp_path)))
    assert result["capacity_projection"]["known_lower_bound_capacity_pass"] is True
    assert result["capacity_projection"]["measurements_complete"] is False
    assert result["checks"]["combined_proven_free_capacity_has_2x_headroom"] is False
    assert "event_bus_retention_physical_bytes_measured" in result["blockers"]
    assert "object_store_versioning_and_erasure_overhead_measured" in result["blockers"]
    assert "attachment_storage_operationally_admitted" in result["blockers"]


def test_attachment_capacity_receipt_is_rederived_and_artifact_bound(tmp_path: Path) -> None:
    policy_path = tmp_path / "attachment-policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "protocol": "integrity-memory-plane.p2-attachment-operational-policy.v2",
                "max_payload_bytes_per_event": 32,
                "max_manifest_bytes_per_event": 16,
                "capacity_model": "current-retained-bytes-and-filesystem-watermarks",
                "filesystem_high_watermark_percent": 80,
                "filesystem_reserve_percent": 20,
            }
        ),
        encoding="utf-8",
    )
    source_path = ROOT / "p2_attachment_ingress.py"

    supplement_path = tmp_path / "supplement.json"
    supplement_path.write_text('{"measured":true}\n', encoding="utf-8")
    supplement_evidence_sha = "a" * 64
    supplement_receipt = {
        "evidence_sha256": supplement_evidence_sha,
        "attachments": {"nonbootstrap_versions": 2, "retained_payload_bytes": 64},
        "object_store": {
            "filesystem": {
                "attachments": {
                    "allocated_bytes": 128,
                    "filesystem_total_bytes": 1_000,
                    "filesystem_used_bytes": 100,
                    "filesystem_available_bytes": 900,
                }
            }
        },
    }
    supplement_evidence = {
        "valid": True,
        "path": str(supplement_path),
        "file_sha256": sha256_file(supplement_path),
        "receipt": supplement_receipt,
    }

    enforcement, enforcement_file_sha = _write_signed(
        tmp_path / "enforcement.json",
        {
            "protocol": ATTACHMENT_ENFORCEMENT_PROTOCOL,
            "status": "PASS",
            "policy_file_sha256": sha256_file(policy_path),
            "checks": {name: True for name in ATTACHMENT_ENFORCEMENT_CHECKS},
            "production_authority": False,
            "memory_grants_authority": False,
        },
    )
    assert enforcement["status"] == "PASS"
    artifact_names = {
        "attachment_capacity",
        "attachment_enforcement",
        "attachment_ingress",
        "capacity_supplement",
    }
    receipt_path = tmp_path / "attachment-capacity.json"
    receipt, _ = _write_signed(
        receipt_path,
        {
            "protocol": ATTACHMENT_CAPACITY_PROTOCOL,
            "created_utc": dt.datetime.now(dt.UTC).isoformat(),
            "status": "PASS",
            "capacity_scope": "current-live-attachment-storage",
            "billion_event_projection_excluded": True,
            "capacity_admitted": True,
            "policy": {
                "path": str(policy_path.resolve()),
                "file_sha256": sha256_file(policy_path),
                "max_payload_bytes_per_event": 32,
                "max_manifest_bytes_per_event": 16,
                "max_stored_bytes_per_event": 48,
                "capacity_model": "current-retained-bytes-and-filesystem-watermarks",
                "filesystem_high_watermark_percent": 80,
                "filesystem_reserve_percent": 20,
                "source_constraints": [
                    {
                        "path": str(source_path.resolve()),
                        "expected_sha256": sha256_file(source_path),
                        "actual_sha256": sha256_file(source_path),
                    }
                ],
            },
            "capacity_supplement": {
                "path": str(supplement_path.resolve()),
                "file_sha256": sha256_file(supplement_path),
                "evidence_sha256": supplement_evidence_sha,
            },
            "enforcement_receipt": {
                "path": str((tmp_path / "enforcement.json").resolve()),
                "file_sha256": enforcement_file_sha,
            },
            "artifact_sha256": {name: sha256_file(_artifact_path(name)) for name in artifact_names},
            "physical_sample": {
                "nonbootstrap_versions": 2,
                "retained_payload_bytes": 64,
                "allocated_bytes": 128,
                "minimum_objects": 2,
                "minimum_payload_bytes": 64,
            },
            "physical_allocation_ratio": {
                "allocated_bytes": 128,
                "retained_bytes": 64,
                "decimal_ratio": 2.0,
            },
            "filesystem_capacity": {
                "total_bytes": 1_000,
                "used_bytes": 100,
                "available_bytes": 900,
                "high_watermark_bytes": 800,
                "reserve_bytes": 200,
                "headroom_to_high_watermark_bytes": 700,
                "headroom_after_reserve_bytes": 700,
                "operational_headroom_bytes": 700,
                "max_additional_full_ingress_events": 14,
            },
            "checks": {name: True for name in REQUIRED_ATTACHMENT_CAPACITY_CHECKS},
            "blockers": [],
            "per_event_limit_is_not_population_projection": True,
            "production_authority": False,
            "memory_grants_authority": False,
        },
    )
    assert receipt["capacity_admitted"] is True
    validated = validate_attachment_capacity(
        receipt_path,
        capacity_supplement=supplement_evidence,
        policy_path=policy_path,
    )
    assert validated["valid"] is True
    assert validated["operational_headroom_bytes"] == 700

    forged = copy.deepcopy(receipt)
    forged["filesystem_capacity"]["operational_headroom_bytes"] += 1
    _write_signed(receipt_path, forged)
    assert validate_attachment_capacity(
        receipt_path,
        capacity_supplement=supplement_evidence,
        policy_path=policy_path,
    )["valid"] is False


def test_admitted_attachment_storage_is_excluded_from_event_capacity_projection(tmp_path: Path) -> None:
    _stage_fixture(tmp_path)
    observed = _observation(load_stage_admissions(tmp_path))
    baseline = evaluate(observed)
    observed["attachment_capacity_evidence"] = {
        "valid": True,
        "path": "/receipt.json",
        "file_sha256": "d" * 64,
        "operational_headroom_bytes": 700,
        "receipt": {"filesystem_capacity": {"operational_headroom_bytes": 700}},
    }
    result = evaluate(observed)
    assert result["checks"]["attachment_storage_operationally_admitted"] is True
    assert result["attachments_in_event_capacity_projection"] is False
    assert result["attachment_storage_accounted_separately"] is True
    assert "attachments" not in result["selected_component_bytes_per_event"]
    assert result["capacity_projection"]["known_one_region_bytes"] == baseline["capacity_projection"]["known_one_region_bytes"]


def test_physical_offhost_receipt_requires_bound_digest_host_and_freshness(tmp_path: Path) -> None:
    value = {
        "status": "PASS",
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "incremental_physical_offhost": True,
        "remote_host": "client",
        "event_count": 4092,
        "checks": {"all_objects_readback": True, "transfer_accounting": True},
        "production_authority": False,
    }
    value["evidence_sha256"] = sha256_bytes(canonical_json(value))
    path = tmp_path / "client-compact-proof.json"
    atomic_json(path, value)
    assert latest_physical_offhost(tmp_path)["valid"] is True
    corrupt = json.loads(path.read_text())
    corrupt["remote_host"] = "UNKNOWN"
    atomic_json(path, corrupt)
    assert latest_physical_offhost(tmp_path)["valid"] is False


def test_golden_receipt_requires_fresh_bound_all_green_non_authoritative_proof(tmp_path: Path) -> None:
    value = {
        "protocol": "integrity-memory-plane.p2-compact-dual-golden.v1.receipt",
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "status": "PASS",
        "served_plane": "P1_CANONICAL_WITNESS",
        "p2_served_to_agent": False,
        "production_authority": False,
        "memory_grants_authority": False,
        "gates": {"all_cases_pass": True, "retrieval_p95_lte_2000ms": True},
        "metrics": {
            "authority_boundary_recall": 1.0,
            "causal_path_recall_at_20": 1.0,
            "early_event_1_found": True,
            "unsupported_green_count": 0,
        },
    }
    value["receipt_sha256"] = sha256_bytes(canonical_json(value))
    path = tmp_path / "compact-dual-golden-proof.json"
    atomic_json(path, value)
    assert latest_golden_recall(tmp_path)["valid"] is True
    corrupt = json.loads(path.read_text())
    corrupt["gates"]["all_cases_pass"] = False
    atomic_json(path, corrupt)
    assert latest_golden_recall(tmp_path)["valid"] is False
