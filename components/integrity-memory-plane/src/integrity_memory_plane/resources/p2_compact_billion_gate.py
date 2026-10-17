#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed admission and capacity gate for a physical billion-event history.

The gate deliberately does not accept caller supplied ``*_verified`` booleans.
Release facts are derived from immutable, digest-bound receipts and current
fault-domain observations.  Capacity arithmetic uses exact rational values and
rounds every byte requirement upwards.
"""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import json
import os
import re
from fractions import Fraction
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file
from p2_billion_capacity import (
    TARGET_EVENTS,
    client_observation,
    filesystem_free,
    postgres_observation,
    s3_observation,
)


PROTOCOL = "integrity-memory-plane.p2-compact-billion-gate.v2"
STAGE_ADMISSION_PROTOCOL = "integrity-memory-plane.p2-physical-stage-admission.v1.receipt"
PHYSICAL_PROTOCOL = "integrity-memory-plane.p2-physical-history-lab.v1.receipt"
VERIFY_PROTOCOL = "integrity-memory-plane.p2-physical-verify-replay.v1.receipt"
RETRIEVAL_PROTOCOL = "integrity-memory-plane.p2-physical-retrieval-replay.v1.receipt"
REGIONAL_FAILOVER_PROTOCOL = "integrity-memory-plane.p2-regional-failover.v1.receipt"
CAPACITY_SUPPLEMENT_PROTOCOL = "integrity-memory-plane.p2-capacity-supplement.v1.receipt"
ATTACHMENT_CAPACITY_PROTOCOL = "integrity-memory-plane.p2-attachment-operational-capacity.v2.receipt"
ATTACHMENT_ENFORCEMENT_PROTOCOL = "integrity-memory-plane.p2-attachment-ingress-enforcement.v1.receipt"
HEADROOM_NUMERATOR = 2
HIGH_WATERMARK_PERCENT = 80
CRITICAL_WATERMARK_PERCENT = 90
FILESYSTEM_RESERVE_PERCENT = 20
REGIONAL_COPIES = 2
PHYSICAL_STAGE_SEQUENCE = (1_000_000, 10_000_000, 100_000_000, 1_000_000_000)
PHYSICAL_STAGE_PREDECESSOR = {
    count: (PHYSICAL_STAGE_SEQUENCE[index - 1] if index else 0)
    for index, count in enumerate(PHYSICAL_STAGE_SEQUENCE)
}
SHA256 = re.compile(r"[0-9a-f]{64}")
PHYSICAL_COMPONENTS = ("raw", "index", "catalog", "receipts")
KNOWN_COMPONENTS = (
    "raw",
    "index",
    "catalog",
    "receipts",
    "ingest_metadata",
    "event_bus",
    "object_store_overhead",
)
READER_ONLY_FAILURES = {"exact_lookup_p95_lte_1000ms", "semantic_retrieval_lte_2000ms"}
REQUIRED_ADMISSION_CHECKS = {
    "source_receipt_digests_valid",
    "source_root_and_count_bound",
    "physical_non_sparse",
    "physical_checks_present",
    "physical_declared_blockers_exact",
    "physical_structural_failures_zero",
    "physical_reader_failures_only_allowlisted",
    "bounded_verify_pass",
    "retrieval_replay_pass",
    "verify_artifacts_bound",
    "retrieval_artifacts_bound",
    "uid_catalog_matches_payload",
    "reader_generation_bound",
    "stage_monotonic",
    "production_authority_false",
}
REQUIRED_PHYSICAL_CHECKS = {
    "physical_raw_rows_equal_target",
    "compact_rows_equal_target",
    "cursor_parity_100_percent",
    "event_uid_duplicate_zero",
    "manifest_chain_verified",
    "receipt_chain_terminates_at_target",
    "streaming_peak_bounded_to_bucket",
    "exact_samples_all_worm_proven",
    "exact_lookup_p95_lte_1000ms",
    "semantic_anchor_recall",
    "semantic_retrieval_lte_2000ms",
    "causal_path_recall_at_20_gte_95",
    "negative_stays_unknown",
    "capsule_budget_8_to_32k",
    "unsupported_green_zero",
    "production_authority_false",
}
REQUIRED_VERIFY_CHECKS = {
    "physical_receipt_digest_valid",
    "physical_receipt_non_sparse",
    "bounded_verifier_pass",
    "event_count_matches_physical",
    "cursor_parity_100_percent",
    "uid_proof_payload_derived",
    "uid_catalog_matches_payload",
    "semantic_claim_not_misrepresented_as_raw_equivalence",
    "production_authority_false",
}
REQUIRED_RETRIEVAL_CHECKS = {
    "physical_receipt_bound",
    "bounded_verify_receipt_bound",
    "index_generation_matches_verify",
    "catalog_generation_matches_verify",
    "reader_attestation_pass",
    "reader_bootstrap_sample_lte_1000ms",
    "exact_samples_all_worm_proven",
    "exact_lookup_p95_lte_1000ms",
    "semantic_anchor_recall",
    "semantic_retrieval_lte_2000ms",
    "causal_path_recall_at_20_gte_95",
    "negative_stays_unknown",
    "all_included_worm_proven",
    "production_authority_false",
}
ARTIFACT_FILES = {
    "compact_index": ("p2_compact_index.py",),
    "compact_catalog": ("p2_compact_catalog.py",),
    "compact_retrieval": ("p2_compact_retrieval.py",),
    "physical_verify_replay": ("p2_physical_verify_replay.py", "physical-verify-replay"),
    "physical_retrieval_replay": ("p2_physical_retrieval_replay.py", "physical-retrieval-replay"),
    "capacity_supplement": ("p2_capacity_supplement.py", "capacity-supplement"),
    "billion_capacity": ("p2_billion_capacity.py", "billion-capacity"),
    "compact_billion_gate": ("p2_compact_billion_gate.py", "compact-billion-capacity"),
    "attachment_capacity": ("p2_attachment_capacity.py", "attachment-capacity"),
    "attachment_enforcement": ("p2_attachment_enforcement.py", "attachment-enforcement"),
    "attachment_ingress": ("p2_attachment_ingress.py", "attachment-ingress"),
}
REQUIRED_ATTACHMENT_CAPACITY_CHECKS = {
    "policy_source_constraints_current",
    "capacity_supplement_integrity_valid",
    "capacity_supplement_object_store_measurement_valid",
    "attachment_worm_contract_bound",
    "attachment_inventory_stable",
    "attachment_delete_markers_absent",
    "attachment_unmeasured_multipart_absent",
    "representative_nonbootstrap_workload_observed",
    "attachment_physical_allocation_ratio_valid",
    "attachment_filesystem_arithmetic_valid",
    "attachment_filesystem_below_high_watermark",
    "attachment_reserve_preserved",
    "attachment_max_event_fits_remaining_headroom",
    "canonical_ingress_enforcement_receipt_valid",
}
ATTACHMENT_ENFORCEMENT_CHECKS = {
    "oversized_object_rejected",
    "fifth_object_rejected",
    "payload_budget_overflow_rejected",
    "digest_mismatch_rejected",
    "content_addressed_duplicate_idempotent",
    "exact_version_readback_verified",
    "canonical_event_reference_bound",
    "all_canonical_attachment_references_validated",
}
REQUIRED_CAPACITY_SUPPLEMENT_CHECKS = {
    "source_event_and_batch_counts_consistent",
    "bus_stream_snapshot_ordered_around_postgres",
    "bus_stream_contract_classified",
    "bus_physical_measurement_valid",
    "bus_stream_max_bytes_covers_target",
    "bus_server_max_storage_covers_target",
    "bus_stream_max_bytes_has_2x_target_headroom",
    "bus_server_max_storage_has_2x_target_headroom",
    "bus_filesystem_can_grow_to_2x_target_with_reserve",
    "bus_stream_2x_target_below_high_watermark",
    "bus_server_2x_target_below_high_watermark",
    "bus_filesystem_2x_target_below_high_watermark",
    "bus_stream_below_high_watermark",
    "bus_server_below_high_watermark",
    "bus_filesystem_below_high_watermark",
    "object_store_all_versions_enumerated",
    "object_store_inventory_arithmetic_consistent",
    "object_store_inventory_stable_during_physical_measurement",
    "object_store_delete_markers_absent",
    "object_store_worm_contract_verified",
    "object_store_no_unmeasured_multipart_uploads",
    "object_store_physical_measurement_valid",
    "raw_object_versions_cover_committed_batches",
    "raw_content_addressed_version_multiplicity_one",
    "gap_guard_exact_raw_object_parity_bound",
    "attachment_nonbootstrap_workload_observed",
    "attachment_capacity_policy_bound",
}
BUS_TARGET_CAPACITY_ADMISSION_CHECKS = (
    "source_event_and_batch_counts_consistent",
    "bus_stream_snapshot_ordered_around_postgres",
    "bus_stream_contract_classified",
    "bus_physical_measurement_valid",
    "bus_stream_max_bytes_has_2x_target_headroom",
    "bus_server_max_storage_has_2x_target_headroom",
    "bus_filesystem_can_grow_to_2x_target_with_reserve",
    "bus_stream_2x_target_below_high_watermark",
    "bus_server_2x_target_below_high_watermark",
    "bus_filesystem_2x_target_below_high_watermark",
    "bus_stream_below_high_watermark",
    "bus_server_below_high_watermark",
    "bus_filesystem_below_high_watermark",
)


def tree_stats(root: Path, exclude: tuple[str, ...] = ("receipts",)) -> dict[str, int]:
    logical = allocated = files = 0
    for path in root.rglob("*"):
        if not path.is_file() or any(part in exclude for part in path.parts):
            continue
        value = path.stat()
        logical += int(value.st_size)
        allocated += int(value.st_blocks * 512)
        files += 1
    return {"logical_bytes": logical, "allocated_bytes": allocated, "files": files}


def _ceil(value: Fraction) -> int:
    return (value.numerator + value.denominator - 1) // value.denominator


def _ratio(total: int, events: int) -> Fraction:
    if total < 0 or events <= 0:
        raise ValueError("capacity measurement must have non-negative bytes and positive events")
    return Fraction(total, events)


def _ratio_json(value: Fraction) -> dict[str, Any]:
    return {
        "numerator_bytes": value.numerator,
        "denominator_events": value.denominator,
        "decimal_bytes_per_event": round(float(value), 6),
    }


def _signed_receipt(path: Path, protocol: str) -> tuple[dict[str, Any], str]:
    value = json.loads(path.read_text(encoding="utf-8"))
    claimed = str(value.get("evidence_sha256") or "")
    unsigned = dict(value)
    unsigned.pop("evidence_sha256", None)
    if value.get("protocol") != protocol:
        raise RuntimeError(f"receipt protocol mismatch: {path}")
    if not SHA256.fullmatch(claimed) or claimed != sha256_bytes(canonical_json(unsigned)):
        raise RuntimeError(f"receipt canonical digest mismatch: {path}")
    if value.get("production_authority") is not False or value.get("memory_grants_authority") is not False:
        raise RuntimeError(f"receipt authority boundary mismatch: {path}")
    return value, sha256_file(path)


def _all_true(value: Any) -> bool:
    return isinstance(value, dict) and bool(value) and all(item is True for item in value.values())


def _required_all_true(value: Any, required: set[str]) -> bool:
    return _all_true(value) and required.issubset(value) and all(value[name] is True for name in required)


def _strict_positive_int(value: Any, name: str) -> int:
    if type(value) is not int or value <= 0:  # bool is deliberately rejected
        raise RuntimeError(f"{name} must be a positive integer")
    return value


def _strict_nonnegative_int(value: Any, name: str) -> int:
    if type(value) is not int or value < 0:
        raise RuntimeError(f"{name} must be a non-negative integer")
    return value


def _independently_validate_bus_target_watermarks(
    bus: dict[str, Any],
    checks: dict[str, Any],
    *,
    projected_logical: int,
    projected_physical: int,
) -> bool:
    """Re-derive target watermarks from raw counters, never claimed booleans."""

    stream_bytes = _strict_positive_int((bus.get("state_after") or {}).get("bytes"), "bus stream bytes")
    stream_max_bytes = _strict_positive_int((bus.get("config") or {}).get("max_bytes"), "stream max bytes")
    server = bus.get("server") or {}
    server_max_storage = _strict_positive_int(server.get("max_storage"), "server max storage")
    server_store_used = _strict_nonnegative_int(server.get("storage_used"), "server store used")
    filesystem = bus.get("filesystem") or {}
    bus_allocated = _strict_positive_int(filesystem.get("allocated_bytes"), "bus allocated bytes")
    filesystem_total = _strict_positive_int(filesystem.get("filesystem_total_bytes"), "bus filesystem total bytes")
    filesystem_available = _strict_nonnegative_int(
        filesystem.get("filesystem_available_bytes"), "bus filesystem available bytes"
    )
    filesystem_used = _strict_nonnegative_int(
        filesystem.get("filesystem_used_bytes"), "bus filesystem used bytes"
    )
    if filesystem_available + filesystem_used != filesystem_total:
        raise RuntimeError("bus filesystem arithmetic mismatch")

    required_stream_2x = projected_logical * HEADROOM_NUMERATOR
    required_physical_2x = projected_physical * HEADROOM_NUMERATOR
    physical_growth_2x = max(0, required_physical_2x - bus_allocated)
    server_other_store = max(0, server_store_used - stream_bytes)
    projected_server_store_used_2x = server_other_store + required_physical_2x
    projected_filesystem_used_2x = filesystem_used + physical_growth_2x
    filesystem_reserve = (filesystem_total * FILESYSTEM_RESERVE_PERCENT + 99) // 100

    expected_fields = {
        "projected_server_storage_bytes_at_2x_target": projected_server_store_used_2x,
        "projected_filesystem_used_bytes_at_2x_target": projected_filesystem_used_2x,
    }
    if any(bus.get(name) != expected for name, expected in expected_fields.items()):
        raise RuntimeError("bus target watermark fields are not measurement-derived")

    expected_checks = {
        "bus_filesystem_can_grow_to_2x_target_with_reserve": (
            filesystem_available > physical_growth_2x + filesystem_reserve
        ),
        "bus_stream_2x_target_below_high_watermark": (
            required_stream_2x * 100 < stream_max_bytes * HIGH_WATERMARK_PERCENT
        ),
        "bus_server_2x_target_below_high_watermark": (
            projected_server_store_used_2x * 100 < server_max_storage * HIGH_WATERMARK_PERCENT
        ),
        "bus_filesystem_2x_target_below_high_watermark": (
            projected_filesystem_used_2x * 100 < filesystem_total * HIGH_WATERMARK_PERCENT
        ),
    }
    if any(checks.get(name) is not expected for name, expected in expected_checks.items()):
        raise RuntimeError("bus target watermark checks are not measurement-derived")

    expected_admitted = all(checks.get(name) is True for name in BUS_TARGET_CAPACITY_ADMISSION_CHECKS)
    if bus.get("target_capacity_admitted") is not expected_admitted:
        raise RuntimeError("bus target watermark admission is forged")
    return expected_admitted


def _artifact_path(name: str) -> Path:
    base = Path(__file__).resolve().parent
    for candidate in ARTIFACT_FILES.get(name, ()):
        path = base / candidate
        if path.is_file() and not path.is_symlink():
            return path
    raise RuntimeError(f"bound artifact is unavailable: {name}")


def validate_stage_admission(path: Path) -> dict[str, Any]:
    """Revalidate one staged admission and every immutable source receipt.

    A valid 1M admission remains a valid milestone but can never be interpreted
    as a physical billion-event proof.
    """

    result: dict[str, Any] = {"valid": False, "path": str(path)}
    try:
        admission, admission_file_sha = _signed_receipt(path, STAGE_ADMISSION_PROTOCOL)
        count = _strict_positive_int(admission.get("physical_event_count"), "admission physical_event_count")
        source_root = str(admission.get("source_root") or "")
        if count <= 0 or admission.get("stage") != f"physical-{count}":
            raise RuntimeError("stage admission count/stage mismatch")
        if count not in PHYSICAL_STAGE_PREDECESSOR:
            raise RuntimeError("stage admission count is outside the admitted physical ladder")
        predecessor_count = PHYSICAL_STAGE_PREDECESSOR[count]
        predecessor_evidence_sha = str(admission.get("previous_stage_admission_sha256") or "")
        predecessor_file_sha = str(admission.get("previous_stage_admission_file_sha256") or "")
        if predecessor_count == 0:
            if predecessor_evidence_sha or predecessor_file_sha:
                raise RuntimeError("genesis stage admission cannot claim a predecessor")
        elif not SHA256.fullmatch(predecessor_evidence_sha) or not SHA256.fullmatch(predecessor_file_sha):
            raise RuntimeError("stage admission predecessor digest binding is incomplete")
        if admission.get("status") != "PASS" or not _required_all_true(admission.get("checks"), REQUIRED_ADMISSION_CHECKS):
            raise RuntimeError("stage admission is not an all-green admitted milestone")
        if admission.get("blockers") not in ([], None):
            raise RuntimeError("stage admission has local blockers")

        canonical_root = Path(source_root)
        if not canonical_root.is_absolute() or canonical_root.resolve() != canonical_root or not canonical_root.is_dir():
            raise RuntimeError("stage admission source root is not an available canonical directory")
        derived_lineage_root = str(canonical_root.parent)
        claimed_lineage_root = str(admission.get("stage_lineage_root") or "")
        if claimed_lineage_root:
            lineage_path = Path(claimed_lineage_root)
            if (
                not lineage_path.is_absolute()
                or lineage_path.resolve() != lineage_path
                or claimed_lineage_root != derived_lineage_root
            ):
                raise RuntimeError("stage admission lineage root mismatch")
        elif predecessor_count != 0:
            raise RuntimeError("non-genesis stage admission lineage root is absent")
        source_specs = {
            "physical": PHYSICAL_PROTOCOL,
            "verify": VERIFY_PROTOCOL,
            "retrieval": RETRIEVAL_PROTOCOL,
        }
        sources: dict[str, dict[str, Any]] = {}
        for name, protocol in source_specs.items():
            binding = (admission.get("source_receipts") or {}).get(name) or {}
            source_path = Path(str(binding.get("path") or ""))
            if not source_path.is_absolute() or source_path.is_symlink() or not source_path.is_file():
                raise RuntimeError(f"{name} source receipt path is unavailable")
            try:
                source_path.resolve().relative_to(canonical_root)
            except ValueError as exc:
                raise RuntimeError(f"{name} source receipt escapes the canonical root") from exc
            receipt, file_sha = _signed_receipt(source_path, protocol)
            if file_sha != str(binding.get("file_sha256") or ""):
                raise RuntimeError(f"{name} source file digest mismatch")
            if receipt.get("evidence_sha256") != str(binding.get("evidence_sha256") or ""):
                raise RuntimeError(f"{name} source evidence binding mismatch")
            sources[name] = receipt

        physical = sources["physical"]
        verify = sources["verify"]
        retrieval = sources["retrieval"]
        physical_sha = str(physical["evidence_sha256"])
        verify_sha = str(verify["evidence_sha256"])
        if _strict_positive_int(physical.get("physical_event_count"), "physical event_count") != count or physical.get("stage") != f"physical-{count}":
            raise RuntimeError("physical receipt count/stage mismatch")
        if physical.get("sparse_or_extrapolated_run") is not False:
            raise RuntimeError("physical receipt is sparse or extrapolated")
        if not isinstance(physical.get("storage"), dict):
            raise RuntimeError("physical storage measurements are absent")
        for component in PHYSICAL_COMPONENTS:
            measurement = physical["storage"].get(component) or {}
            if max(int(measurement.get("logical_bytes") or -1), int(measurement.get("allocated_bytes") or -1)) < 0:
                raise RuntimeError(f"physical {component} storage measurement is absent")

        physical_checks = physical.get("checks") or {}
        if not REQUIRED_PHYSICAL_CHECKS.issubset(physical_checks) or any(type(value) is not bool for value in physical_checks.values()):
            raise RuntimeError("physical receipt required check schema is incomplete")
        false_physical = {name for name, passed in physical_checks.items() if passed is not True}
        if {str(value) for value in (physical.get("blockers") or [])} != false_physical:
            raise RuntimeError("physical blockers do not exactly match false checks")
        if false_physical - READER_ONLY_FAILURES:
            raise RuntimeError("physical receipt has structural failures")
        expected_physical_status = "PASS" if not false_physical else "FAIL"
        if physical.get("status") != expected_physical_status:
            raise RuntimeError("physical status/check consistency mismatch")

        for name, receipt, required in (
            ("verify", verify, REQUIRED_VERIFY_CHECKS),
            ("retrieval", retrieval, REQUIRED_RETRIEVAL_CHECKS),
        ):
            if receipt.get("status") != "PASS" or not _required_all_true(receipt.get("checks"), required):
                raise RuntimeError(f"{name} receipt is not all-green")
            if _strict_positive_int(receipt.get("physical_event_count"), f"{name} event_count") != count or receipt.get("source_root") != source_root:
                raise RuntimeError(f"{name} count/root binding mismatch")
            if receipt.get("physical_receipt_evidence_sha256") != physical_sha:
                raise RuntimeError(f"{name} physical evidence binding mismatch")
        if retrieval.get("verify_receipt_evidence_sha256") != verify_sha:
            raise RuntimeError("retrieval verifier evidence binding mismatch")
        physical_binding = (admission.get("source_receipts") or {}).get("physical") or {}
        verify_binding = (admission.get("source_receipts") or {}).get("verify") or {}
        if verify.get("physical_receipt_file_sha256") != physical_binding.get("file_sha256"):
            raise RuntimeError("verify physical file binding mismatch")
        if retrieval.get("physical_receipt_file_sha256") != physical_binding.get("file_sha256"):
            raise RuntimeError("retrieval physical file binding mismatch")
        if retrieval.get("verify_receipt_file_sha256") != verify_binding.get("file_sha256"):
            raise RuntimeError("retrieval verify file binding mismatch")
        if (retrieval.get("reader_attestation") or {}).get("snapshot_sha256") != verify.get("catalog_state_sha256"):
            raise RuntimeError("retrieval catalog generation binding mismatch")
        if admission.get("index_state_sha256") != verify.get("index_state_sha256"):
            raise RuntimeError("admission index state binding mismatch")
        if admission.get("catalog_state_sha256") != verify.get("catalog_state_sha256"):
            raise RuntimeError("admission catalog state binding mismatch")
        if admission.get("compact_manifest_head_sha256") != (verify.get("verify") or {}).get("manifest_head_sha256"):
            raise RuntimeError("admission manifest head binding mismatch")
        if (verify.get("checks") or {}).get("uid_catalog_matches_payload") is not True:
            raise RuntimeError("payload-derived UID catalog proof is absent")

        index_state = canonical_root / "compact-index" / "state.json"
        catalog_state = canonical_root / "compact-catalog" / "state.json"
        if index_state.is_symlink() or catalog_state.is_symlink() or not index_state.is_file() or not catalog_state.is_file():
            raise RuntimeError("current physical index/catalog state is unavailable")
        if sha256_file(index_state) != verify.get("index_state_sha256"):
            raise RuntimeError("current physical index state digest changed")
        if sha256_file(catalog_state) != verify.get("catalog_state_sha256"):
            raise RuntimeError("current physical catalog state digest changed")
        index_value = json.loads(index_state.read_text(encoding="utf-8"))
        catalog_value = json.loads(catalog_state.read_text(encoding="utf-8"))
        if _strict_positive_int(index_value.get("event_count"), "index state event_count") != count:
            raise RuntimeError("current index state count mismatch")
        if _strict_positive_int(catalog_value.get("uid_records"), "catalog state uid_records") != count:
            raise RuntimeError("current catalog state count mismatch")

        verify_artifacts = verify.get("artifact_sha256") or {}
        retrieval_artifacts = retrieval.get("artifact_sha256") or {}
        for name, digest in {**verify_artifacts, **retrieval_artifacts}.items():
            if name not in ARTIFACT_FILES or not SHA256.fullmatch(str(digest)):
                raise RuntimeError(f"unknown or malformed artifact binding: {name}")
            if sha256_file(_artifact_path(name)) != digest:
                raise RuntimeError(f"current artifact digest changed: {name}")
        for shared in set(verify_artifacts) & set(retrieval_artifacts):
            if verify_artifacts[shared] != retrieval_artifacts[shared]:
                raise RuntimeError(f"verify/retrieval artifact disagreement: {shared}")

        computed_billion = count >= TARGET_EVENTS
        release = admission.get("release_checks") or {}
        if admission.get("physical_billion_event_run_completed") is not computed_billion:
            raise RuntimeError("admission physical-billion claim is not count-derived")
        if release.get("physical_billion_event_run_completed") is not computed_billion:
            raise RuntimeError("admission release physical-billion claim is not count-derived")
        expected_milestones = {
            "physical_100k_completed": count >= 100_000,
            "physical_1m_completed": count >= 1_000_000,
            "physical_10m_completed": count >= 10_000_000,
            "physical_100m_completed": count >= 100_000_000,
        }
        if admission.get("milestone_checks") != expected_milestones:
            raise RuntimeError("admission milestone claims are not count-derived")

        result.update(
            {
                "valid": True,
                "file_sha256": admission_file_sha,
                "receipt": admission,
                "physical_receipt": physical,
                "verify_receipt": verify,
                "retrieval_receipt": retrieval,
                "physical_billion_event_run_completed": computed_billion,
                "expected_predecessor_count": predecessor_count,
                "predecessor_evidence_sha256": predecessor_evidence_sha,
                "predecessor_file_sha256": predecessor_file_sha,
                "stage_lineage_root": derived_lineage_root,
                "full_semantic_projection_raw_equivalence_verified": release.get(
                    "full_semantic_projection_raw_equivalence_verified"
                )
                is True,
            }
        )
    except Exception as exc:  # fail closed and preserve a compact diagnostic
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def load_stage_admissions(root: Path) -> dict[str, Any]:
    """Load the unique digest-linked stage chain without using file time as authority."""

    paths = sorted(root.rglob("admission-*.json"), key=lambda value: str(value))
    entries = [validate_stage_admission(path) for path in paths]
    valid = sorted(
        (entry for entry in entries if entry.get("valid")),
        key=lambda entry: (int(entry["receipt"]["physical_event_count"]), str(entry["path"])),
    )
    by_count: dict[int, list[dict[str, Any]]] = {}
    for entry in valid:
        by_count.setdefault(int(entry["receipt"]["physical_event_count"]), []).append(entry)

    chain_errors: list[str] = []
    if not valid:
        chain_errors.append("no valid stage admission exists")
    duplicate_counts = sorted(count for count, values in by_count.items() if len(values) != 1)
    if duplicate_counts:
        chain_errors.append(f"ambiguous duplicate stage admissions: {duplicate_counts}")

    ordered: list[dict[str, Any]] = []
    if valid and not duplicate_counts:
        highest_count = max(by_count)
        highest_index = PHYSICAL_STAGE_SEQUENCE.index(highest_count)
        required_counts = PHYSICAL_STAGE_SEQUENCE[: highest_index + 1]
        missing = [count for count in required_counts if count not in by_count]
        extra = [count for count in by_count if count not in required_counts]
        if missing:
            chain_errors.append(f"missing physical stage admissions: {missing}")
        if extra:
            chain_errors.append(f"unexpected physical stage admissions: {sorted(extra)}")
        if not missing and not extra:
            ordered = [by_count[count][0] for count in required_counts]
            if len({entry.get("stage_lineage_root") for entry in ordered}) != 1:
                chain_errors.append("physical stage admissions disagree on lineage root")
            for index, entry in enumerate(ordered):
                if index == 0:
                    continue
                predecessor = ordered[index - 1]
                if entry.get("predecessor_evidence_sha256") != predecessor["receipt"].get("evidence_sha256"):
                    chain_errors.append(
                        f"stage {entry['receipt']['physical_event_count']} predecessor evidence digest mismatch"
                    )
                if entry.get("predecessor_file_sha256") != predecessor.get("file_sha256"):
                    chain_errors.append(
                        f"stage {entry['receipt']['physical_event_count']} predecessor file digest mismatch"
                    )

    all_valid = bool(entries) and len(valid) == len(entries)
    chain_valid = all_valid and not chain_errors and bool(ordered)
    latest = ordered[-1] if ordered else (valid[-1] if valid else None)
    return {
        "root": str(root),
        "discovered": len(entries),
        "all_valid": all_valid,
        "monotonic": chain_valid,
        "digest_chain_valid": chain_valid,
        "selection_authority": "physical_event_count_and_predecessor_digests",
        "latest": latest,
        "valid_entries": valid,
        "ordered_chain": ordered,
        "chain_errors": chain_errors,
        "invalid": [{"path": item.get("path"), "error": item.get("error")} for item in entries if not item.get("valid")],
    }


def validate_regional_failover(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"valid": False, "path": None, "error": "regional failover receipt not supplied"}
    result: dict[str, Any] = {"valid": False, "path": str(path)}
    try:
        receipt, file_sha = _signed_receipt(path, REGIONAL_FAILOVER_PROTOCOL)
        domains = receipt.get("fault_domains") or []
        names = {str(item.get("name") or "") for item in domains if isinstance(item, dict)}
        valid = (
            receipt.get("status") == "PASS"
            and _all_true(receipt.get("checks"))
            and len(domains) >= REGIONAL_COPIES
            and len(names - {""}) >= REGIONAL_COPIES
            and float(receipt.get("observed_rpo_seconds")) <= float(receipt.get("required_rpo_seconds"))
            and float(receipt.get("observed_rto_seconds")) <= float(receipt.get("required_rto_seconds"))
        )
        result.update({"valid": valid, "file_sha256": file_sha, "receipt": receipt})
        if not valid:
            result["error"] = "regional failover gates are incomplete"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def _ratio_matches(value: Any, expected: Fraction) -> bool:
    return bool(
        isinstance(value, dict)
        and type(value.get("numerator_bytes")) is int
        and type(value.get("denominator_events")) is int
        and value["numerator_bytes"] == expected.numerator
        and value["denominator_events"] == expected.denominator
    )


def validate_capacity_supplement(
    path: Path | None,
    *,
    stage_scan: dict[str, Any],
    topology_path: Path,
    max_age_seconds: int = 3600,
) -> dict[str, Any]:
    """Validate a fresh, explicitly supplied capacity measurement receipt."""

    if path is None:
        return {"valid": False, "path": None, "error": "capacity supplement receipt not supplied"}
    result: dict[str, Any] = {"valid": False, "path": str(path)}
    try:
        receipt, file_sha = _signed_receipt(path, CAPACITY_SUPPLEMENT_PROTOCOL)
        created = dt.datetime.fromisoformat(str(receipt.get("created_utc") or "").replace("Z", "+00:00"))
        age = (dt.datetime.now(dt.UTC) - created.astimezone(dt.UTC)).total_seconds()
        if not 0 <= age <= max_age_seconds:
            raise RuntimeError("capacity supplement is stale or future-dated")
        if receipt.get("target_events") != TARGET_EVENTS:
            raise RuntimeError("capacity supplement target mismatch")
        checks = receipt.get("checks") or {}
        if set(checks) != REQUIRED_CAPACITY_SUPPLEMENT_CHECKS or any(type(value) is not bool for value in checks.values()):
            raise RuntimeError("capacity supplement check schema mismatch")
        false_checks = {name for name, passed in checks.items() if passed is not True}
        if set(receipt.get("blockers") or []) != false_checks:
            raise RuntimeError("capacity supplement blockers/checks mismatch")
        expected_status = "PASS" if not false_checks else "INCOMPLETE"
        if receipt.get("status") != expected_status:
            raise RuntimeError("capacity supplement status/checks mismatch")

        latest = stage_scan.get("latest") or {}
        if not latest.get("valid") or not stage_scan.get("all_valid") or not stage_scan.get("monotonic"):
            raise RuntimeError("capacity supplement has no valid current stage binding")
        bindings = receipt.get("bindings") or {}
        if bindings.get("physical_stage_admission_file_sha256") != latest.get("file_sha256"):
            raise RuntimeError("capacity supplement stage admission binding mismatch")
        canonical_topology = topology_path.resolve()
        if topology_path.is_symlink() or not topology_path.is_file():
            raise RuntimeError("capacity supplement topology is unavailable")
        topology_sha = sha256_file(canonical_topology)
        if bindings.get("fault_domain_topology_path") != str(canonical_topology):
            raise RuntimeError("capacity supplement topology path mismatch")
        if bindings.get("fault_domain_topology_sha256") != topology_sha:
            raise RuntimeError("capacity supplement topology digest mismatch")

        configuration_files = receipt.get("configuration_files") or []
        if not isinstance(configuration_files, list) or len(configuration_files) < 3:
            raise RuntimeError("capacity supplement configuration bindings are incomplete")
        bound_configuration: dict[str, str] = {}
        for item in configuration_files:
            config_path = Path(str((item or {}).get("path") or ""))
            claimed = str((item or {}).get("sha256") or "")
            if not config_path.is_absolute() or config_path.is_symlink() or not config_path.is_file():
                raise RuntimeError("capacity supplement configuration path is unavailable")
            if not SHA256.fullmatch(claimed) or sha256_file(config_path) != claimed:
                raise RuntimeError("capacity supplement configuration digest changed")
            bound_configuration[str(config_path.resolve())] = claimed
        if bound_configuration.get(str(canonical_topology)) != topology_sha:
            raise RuntimeError("capacity supplement configuration set omits topology")

        artifacts = receipt.get("artifact_sha256") or {}
        if set(artifacts) != {"capacity_supplement", "billion_capacity", "compact_billion_gate"}:
            raise RuntimeError("capacity supplement artifact set mismatch")
        for name, digest in artifacts.items():
            if not SHA256.fullmatch(str(digest)) or sha256_file(_artifact_path(name)) != digest:
                raise RuntimeError(f"capacity supplement artifact digest changed: {name}")

        source = receipt.get("source_snapshot") or {}
        events = _strict_positive_int(source.get("raw_events"), "capacity sample raw_events")
        batches = _strict_positive_int(source.get("ingest_batches"), "capacity sample ingest_batches")

        gap_path = Path(str(bindings.get("gap_guard_receipt_path") or ""))
        if not gap_path.is_absolute() or gap_path.is_symlink() or not gap_path.is_file():
            raise RuntimeError("capacity supplement gap guard path is unavailable")
        if sha256_file(gap_path) != bindings.get("gap_guard_receipt_file_sha256"):
            raise RuntimeError("capacity supplement gap guard file binding mismatch")
        gap = json.loads(gap_path.read_text(encoding="utf-8"))
        gap_evidence = dict(gap)
        for name in ("evidence_sha256", "run_uid", "created_utc"):
            gap_evidence.pop(name, None)
        if (
            gap.get("protocol") != "integrity-memory-plane.p2-gap-guard.v1.evidence"
            or gap.get("status") not in {"PASS", "DEGRADED"}
            or gap.get("production_authority") is not False
            or gap.get("memory_grants_authority") is not False
            or gap.get("evidence_sha256") != bindings.get("gap_guard_evidence_sha256")
            or gap.get("evidence_sha256") != sha256_bytes(canonical_json(gap_evidence))
            or any(value != 0 or type(value) is not int for value in (gap.get("hard_failures") or {}).values())
            or any(type(value) is not int or value < 0 for value in (gap.get("projection_lag") or {}).values())
            or not 0 < int(gap.get("committed_events") or -1) <= events
            or not 0 < int(gap.get("committed_batches") or -1) <= batches
        ):
            raise RuntimeError("capacity supplement gap guard evidence mismatch")
        embedded_gap = receipt.get("gap_guard") or {}
        if (
            embedded_gap.get("file_sha256") != bindings.get("gap_guard_receipt_file_sha256")
            or embedded_gap.get("evidence_sha256") != gap.get("evidence_sha256")
            or (embedded_gap.get("receipt") or {}).get("evidence_sha256") != gap.get("evidence_sha256")
        ):
            raise RuntimeError("capacity supplement embedded gap guard binding mismatch")

        bus = receipt.get("bus") or {}
        object_store = receipt.get("object_store") or {}
        attachments = receipt.get("attachments") or {}
        bus_allocated = _strict_positive_int((bus.get("filesystem") or {}).get("allocated_bytes"), "bus allocated bytes")
        stream_bytes = _strict_positive_int((bus.get("state_after") or {}).get("bytes"), "bus stream bytes")
        raw_bucket = ((object_store.get("buckets") or {}).get("integrity-p2-raw") or {})
        attachment_bucket = ((object_store.get("buckets") or {}).get("integrity-p2-attachments") or {})
        raw_workload_versions = int((raw_bucket.get("prefix_version_counts") or {}).get("raw") or 0)
        source_identity_count = _strict_positive_int(
            source.get("raw_object_identities"), "capacity sample raw object identities"
        )
        source_identity_sha = str(source.get("raw_object_identity_sha256") or "")
        if (
            not SHA256.fullmatch(source_identity_sha)
            or source_identity_count != raw_workload_versions
            or source_identity_sha != raw_bucket.get("raw_object_identity_sha256")
            or raw_workload_versions - int((gap.get("s3") or {}).get("keys") or -1)
            != batches - int(gap.get("committed_batches") or -1)
            or int(source.get("dead_letter_raw_objects", -1))
            != int((gap.get("s3") or {}).get("known_dlq_keys", -1))
        ):
            raise RuntimeError("capacity supplement live raw identity parity mismatch")
        before_buckets = object_store.get("inventory_snapshot_before") or {}
        for bucket_name, bucket in (
            ("integrity-p2-raw", raw_bucket),
            ("integrity-p2-attachments", attachment_bucket),
        ):
            before_bucket = before_buckets.get(bucket_name) or {}
            if (
                bucket.get("inventory_sha256") != before_bucket.get("inventory_sha256")
                or bucket.get("inventory_records") != before_bucket.get("inventory_records")
                or bucket.get("all_version_bytes") != before_bucket.get("all_version_bytes")
                or int(bucket.get("versions", -1))
                != int(bucket.get("latest_objects", -1)) + int(bucket.get("noncurrent_versions", -1))
                or int(bucket.get("inventory_records", -1))
                != int(bucket.get("versions", -1)) + int(bucket.get("delete_markers", -1))
                or sum(int(count) for count in (bucket.get("prefix_version_counts") or {}).values())
                != int(bucket.get("versions", -1))
                or int(bucket.get("version_overhang_bytes", -1))
                != int(bucket.get("all_version_bytes", -1)) - int(bucket.get("latest_bytes", -1))
            ):
                raise RuntimeError(f"capacity supplement object inventory mismatch: {bucket_name}")
        raw_all_versions = _strict_positive_int(raw_bucket.get("all_version_bytes"), "raw all-version bytes")
        attachment_all_versions = int(attachment_bucket.get("all_version_bytes") or 0)
        if attachment_all_versions < 0:
            raise RuntimeError("attachment all-version bytes is negative")
        root_allocated = _strict_positive_int(
            ((object_store.get("filesystem") or {}).get("root") or {}).get("allocated_bytes"),
            "object store allocated bytes",
        )
        expected_overhead = max(0, root_allocated - raw_all_versions - attachment_all_versions)
        if object_store.get("physical_overhead_bytes") != expected_overhead:
            raise RuntimeError("object store physical overhead derivation mismatch")
        bus_ratio = Fraction(bus_allocated, events)
        raw_ratio = Fraction(raw_all_versions, events)
        overhead_ratio = Fraction(expected_overhead, events)
        if not _ratio_matches(bus.get("allocated_bytes_per_event"), bus_ratio):
            raise RuntimeError("bus exact ratio mismatch")
        if not _ratio_matches(object_store.get("raw_all_versions_bytes_per_event"), raw_ratio):
            raise RuntimeError("raw all-version exact ratio mismatch")
        if not _ratio_matches(object_store.get("physical_overhead_bytes_per_event"), overhead_ratio):
            raise RuntimeError("object store overhead exact ratio mismatch")
        projected_logical = _ceil(Fraction(stream_bytes, events) * TARGET_EVENTS)
        projected_physical = _ceil(bus_ratio * TARGET_EVENTS)
        if bus.get("projected_stream_logical_bytes_at_target") != projected_logical:
            raise RuntimeError("bus logical target projection mismatch")
        if bus.get("projected_physical_bytes_at_target") != projected_physical:
            raise RuntimeError("bus physical target projection mismatch")
        bus_filesystem = bus.get("filesystem") or {}
        filesystem_total = _strict_positive_int(
            bus_filesystem.get("filesystem_total_bytes"), "bus filesystem total bytes"
        )
        filesystem_available = _strict_nonnegative_int(
            bus_filesystem.get("filesystem_available_bytes"), "bus filesystem available bytes"
        )
        filesystem_used = _strict_nonnegative_int(
            bus_filesystem.get("filesystem_used_bytes"), "bus filesystem used bytes"
        )
        if filesystem_available + filesystem_used != filesystem_total:
            raise RuntimeError("bus filesystem arithmetic mismatch")
        if type(bus_filesystem.get("filesystem_device_id")) is not int:
            raise RuntimeError("bus filesystem device identity is absent")
        server = bus.get("server") or {}
        stream_max_bytes = _strict_positive_int((bus.get("config") or {}).get("max_bytes"), "stream max bytes")
        server_max_storage = _strict_positive_int(server.get("max_storage"), "server max storage")
        server_store_used = _strict_nonnegative_int(server.get("storage_used"), "server store used")
        required_stream_2x = projected_logical * HEADROOM_NUMERATOR
        required_physical_2x = projected_physical * HEADROOM_NUMERATOR
        physical_growth_2x = max(0, required_physical_2x - bus_allocated)
        server_other_store = max(0, server_store_used - stream_bytes)
        server_capacity_for_stream = max(0, server_max_storage - server_other_store)
        filesystem_reserve = (filesystem_total * FILESYSTEM_RESERVE_PERCENT + 99) // 100
        projected_server_store_used_2x = server_other_store + required_physical_2x
        projected_filesystem_used_2x = filesystem_used + physical_growth_2x
        expected_bus_fields = {
            "required_stream_logical_bytes_with_2x_headroom": required_stream_2x,
            "required_physical_bytes_with_2x_headroom": required_physical_2x,
            "physical_growth_bytes_to_2x_target": physical_growth_2x,
            "server_other_store_bytes": server_other_store,
            "server_capacity_for_stream_bytes": server_capacity_for_stream,
            "filesystem_reserve_bytes": filesystem_reserve,
            "projected_server_storage_bytes_at_2x_target": projected_server_store_used_2x,
            "projected_filesystem_used_bytes_at_2x_target": projected_filesystem_used_2x,
        }
        if any(bus.get(name) != expected for name, expected in expected_bus_fields.items()):
            raise RuntimeError("bus 2x capacity derivation mismatch")
        if bus.get("headroom") != {"numerator": HEADROOM_NUMERATOR, "denominator": 1}:
            raise RuntimeError("bus headroom contract mismatch")
        if bus.get("watermark_policy") != {
            "high_percent": HIGH_WATERMARK_PERCENT,
            "critical_percent": CRITICAL_WATERMARK_PERCENT,
            "filesystem_reserve_percent": FILESYSTEM_RESERVE_PERCENT,
        }:
            raise RuntimeError("bus watermark policy mismatch")
        if object_store.get("projected_physical_overhead_bytes_at_target") != _ceil(overhead_ratio * TARGET_EVENTS):
            raise RuntimeError("object store overhead target projection mismatch")

        expected_measurements = {
            "bus": all(
                checks[name]
                for name in (
                    "source_event_and_batch_counts_consistent",
                    "bus_stream_snapshot_ordered_around_postgres",
                    "bus_stream_contract_classified",
                    "bus_physical_measurement_valid",
                )
            ),
            "object_store": all(
                checks[name]
                for name in (
                    "object_store_all_versions_enumerated",
                    "object_store_inventory_arithmetic_consistent",
                    "object_store_inventory_stable_during_physical_measurement",
                    "object_store_delete_markers_absent",
                    "object_store_worm_contract_verified",
                    "object_store_no_unmeasured_multipart_uploads",
                    "object_store_physical_measurement_valid",
                    "raw_object_versions_cover_committed_batches",
                    "raw_content_addressed_version_multiplicity_one",
                    "gap_guard_exact_raw_object_parity_bound",
                )
            ),
            "attachments": checks["attachment_nonbootstrap_workload_observed"]
            and checks["attachment_capacity_policy_bound"],
        }
        if receipt.get("measurement_checks") != expected_measurements:
            raise RuntimeError("capacity supplement measurement derivation mismatch")
        derived_bus_checks = {
            "bus_stream_max_bytes_covers_target": stream_max_bytes >= projected_logical,
            "bus_server_max_storage_covers_target": server_max_storage >= projected_physical,
            "bus_stream_max_bytes_has_2x_target_headroom": stream_max_bytes >= required_stream_2x,
            "bus_server_max_storage_has_2x_target_headroom": server_capacity_for_stream >= required_physical_2x,
            "bus_filesystem_can_grow_to_2x_target_with_reserve": (
                filesystem_available > physical_growth_2x + filesystem_reserve
            ),
            "bus_stream_2x_target_below_high_watermark": (
                required_stream_2x * 100 < stream_max_bytes * HIGH_WATERMARK_PERCENT
            ),
            "bus_server_2x_target_below_high_watermark": (
                projected_server_store_used_2x * 100 < server_max_storage * HIGH_WATERMARK_PERCENT
            ),
            "bus_filesystem_2x_target_below_high_watermark": (
                projected_filesystem_used_2x * 100 < filesystem_total * HIGH_WATERMARK_PERCENT
            ),
            "bus_stream_below_high_watermark": (
                stream_bytes * 100 < stream_max_bytes * HIGH_WATERMARK_PERCENT
            ),
            "bus_server_below_high_watermark": (
                server_store_used * 100 < server_max_storage * HIGH_WATERMARK_PERCENT
            ),
            "bus_filesystem_below_high_watermark": (
                filesystem_used * 100 < filesystem_total * HIGH_WATERMARK_PERCENT
            ),
        }
        if any(checks[name] is not expected for name, expected in derived_bus_checks.items()):
            raise RuntimeError("capacity supplement bus checks are not measurement-derived")
        expected_bus_capacity = all(checks[name] for name in BUS_TARGET_CAPACITY_ADMISSION_CHECKS)
        if bus.get("target_capacity_admitted") is not expected_bus_capacity:
            raise RuntimeError("capacity supplement bus admission derivation mismatch")
        independently_validated_capacity = _independently_validate_bus_target_watermarks(
            bus,
            checks,
            projected_logical=projected_logical,
            projected_physical=projected_physical,
        )
        if independently_validated_capacity is not expected_bus_capacity:
            raise RuntimeError("capacity supplement independent bus admission derivation mismatch")
        # v1 records the absence of an attachment workload/policy.  A future
        # positive attachment admission requires its own policy receipt rather
        # than a self-asserted boolean in this measurement file.
        if (
            attachments.get("capacity_admitted") is not False
            or attachments.get("required_bytes_per_region") is not None
            or checks["attachment_capacity_policy_bound"] is not False
        ):
            raise RuntimeError("capacity supplement v1 cannot self-admit attachment capacity")

        result.update(
            {
                "valid": True,
                "file_sha256": file_sha,
                "age_seconds": round(age, 3),
                "receipt": receipt,
                "bus_measurement_valid": expected_measurements["bus"],
                "object_store_measurement_valid": expected_measurements["object_store"],
                "attachment_capacity_admitted": False,
                "bus_target_capacity_admitted": expected_bus_capacity,
                "bus_bytes_per_event": bus_ratio,
                "raw_all_versions_bytes_per_event": raw_ratio,
                "object_store_overhead_bytes_per_event": overhead_ratio,
                "attachment_required_bytes_per_region": 0,
            }
        )
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def validate_attachment_capacity(
    path: Path | None,
    *,
    capacity_supplement: dict[str, Any],
    policy_path: Path,
    max_age_seconds: int = 3600,
) -> dict[str, Any]:
    """Re-derive separately admitted operational attachment storage.

    The maximum payload accepted by one event is an ingress safety limit.  It
    is intentionally not converted into a billion-event population forecast.
    """

    if path is None:
        return {"valid": False, "path": None, "error": "attachment capacity receipt not supplied"}
    result: dict[str, Any] = {"valid": False, "path": str(path)}
    try:
        receipt, file_sha = _signed_receipt(path, ATTACHMENT_CAPACITY_PROTOCOL)
        created = dt.datetime.fromisoformat(str(receipt.get("created_utc") or "").replace("Z", "+00:00"))
        age = (dt.datetime.now(dt.UTC) - created.astimezone(dt.UTC)).total_seconds()
        if not 0 <= age <= max_age_seconds:
            raise RuntimeError("attachment capacity receipt is stale or future-dated")
        checks = receipt.get("checks") or {}
        if set(checks) != REQUIRED_ATTACHMENT_CAPACITY_CHECKS or any(value is not True for value in checks.values()):
            raise RuntimeError("attachment capacity checks are incomplete")
        if (
            receipt.get("status") != "PASS"
            or receipt.get("capacity_admitted") is not True
            or receipt.get("blockers") not in ([], None)
            or receipt.get("capacity_scope") != "current-live-attachment-storage"
            or receipt.get("billion_event_projection_excluded") is not True
            or receipt.get("per_event_limit_is_not_population_projection") is not True
            or receipt.get("production_authority") is not False
            or receipt.get("memory_grants_authority") is not False
        ):
            raise RuntimeError("attachment capacity admission contract mismatch")

        artifacts = receipt.get("artifact_sha256") or {}
        expected_artifacts = {
            "attachment_capacity",
            "attachment_enforcement",
            "attachment_ingress",
            "capacity_supplement",
        }
        if set(artifacts) != expected_artifacts:
            raise RuntimeError("attachment capacity artifact set mismatch")
        for name, digest in artifacts.items():
            if not SHA256.fullmatch(str(digest)) or sha256_file(_artifact_path(name)) != digest:
                raise RuntimeError(f"attachment capacity artifact digest changed: {name}")

        canonical_policy = policy_path.resolve()
        if policy_path.is_symlink() or not policy_path.is_file():
            raise RuntimeError("attachment capacity policy is unavailable")
        policy_file_sha = sha256_file(canonical_policy)
        policy_source = json.loads(canonical_policy.read_text(encoding="utf-8"))
        policy = receipt.get("policy") or {}
        if policy.get("path") != str(canonical_policy) or policy.get("file_sha256") != policy_file_sha:
            raise RuntimeError("attachment capacity policy binding mismatch")
        if policy_source.get("protocol") != "integrity-memory-plane.p2-attachment-operational-policy.v2":
            raise RuntimeError("attachment operational policy protocol mismatch")
        max_payload = _strict_positive_int(policy.get("max_payload_bytes_per_event"), "attachment payload bytes")
        max_manifest = _strict_positive_int(policy.get("max_manifest_bytes_per_event"), "attachment manifest bytes")
        max_stored = _strict_positive_int(policy.get("max_stored_bytes_per_event"), "attachment stored bytes")
        high_percent = _strict_positive_int(
            policy.get("filesystem_high_watermark_percent"), "attachment filesystem high watermark"
        )
        reserve_percent = _strict_positive_int(
            policy.get("filesystem_reserve_percent"), "attachment filesystem reserve"
        )
        if (
            max_stored != max_payload + max_manifest
            or policy.get("capacity_model") != "current-retained-bytes-and-filesystem-watermarks"
            or high_percent >= 100
            or reserve_percent >= 100
            or high_percent + reserve_percent > 100
        ):
            raise RuntimeError("attachment operational policy derivation mismatch")
        policy_exact = {
            "max_payload_bytes_per_event": max_payload,
            "max_manifest_bytes_per_event": max_manifest,
            "capacity_model": policy.get("capacity_model"),
            "filesystem_high_watermark_percent": high_percent,
            "filesystem_reserve_percent": reserve_percent,
        }
        if any(policy_source.get(name) != value for name, value in policy_exact.items()):
            raise RuntimeError("attachment receipt policy values differ from the bound policy")
        constraints = policy.get("source_constraints") or []
        if not constraints:
            raise RuntimeError("attachment source constraints are absent")
        for item in constraints:
            source_path = Path(str((item or {}).get("path") or ""))
            expected = str((item or {}).get("expected_sha256") or "")
            actual = str((item or {}).get("actual_sha256") or "")
            if (
                not source_path.is_absolute()
                or source_path.is_symlink()
                or not source_path.is_file()
                or not SHA256.fullmatch(expected)
                or expected != actual
                or sha256_file(source_path) != expected
            ):
                raise RuntimeError("attachment source constraint changed")

        supplement = capacity_supplement.get("receipt") or {}
        supplement_binding = receipt.get("capacity_supplement") or {}
        if (
            capacity_supplement.get("valid") is not True
            or supplement_binding.get("path") != str(Path(str(capacity_supplement.get("path"))).resolve())
            or supplement_binding.get("file_sha256") != capacity_supplement.get("file_sha256")
            or supplement_binding.get("evidence_sha256") != supplement.get("evidence_sha256")
        ):
            raise RuntimeError("attachment capacity supplement binding mismatch")

        enforcement_binding = receipt.get("enforcement_receipt") or {}
        enforcement_path = Path(str(enforcement_binding.get("path") or ""))
        if not enforcement_path.is_absolute() or enforcement_path.is_symlink() or not enforcement_path.is_file():
            raise RuntimeError("attachment enforcement receipt is unavailable")
        if sha256_file(enforcement_path) != enforcement_binding.get("file_sha256"):
            raise RuntimeError("attachment enforcement receipt file binding mismatch")
        enforcement, _ = _signed_receipt(enforcement_path, ATTACHMENT_ENFORCEMENT_PROTOCOL)
        enforcement_checks = enforcement.get("checks") or {}
        if (
            enforcement.get("status") != "PASS"
            or enforcement.get("policy_file_sha256") != policy_file_sha
            or enforcement.get("production_authority") is not False
            or enforcement.get("memory_grants_authority") is not False
            or set(enforcement_checks) != ATTACHMENT_ENFORCEMENT_CHECKS
            or any(value is not True for value in enforcement_checks.values())
        ):
            raise RuntimeError("attachment enforcement receipt is incomplete")

        sample = receipt.get("physical_sample") or {}
        versions = _strict_positive_int(sample.get("nonbootstrap_versions"), "attachment sample versions")
        retained = _strict_positive_int(sample.get("retained_payload_bytes"), "attachment retained bytes")
        allocated = _strict_positive_int(sample.get("allocated_bytes"), "attachment allocated bytes")
        minimum_objects = _strict_positive_int(sample.get("minimum_objects"), "attachment minimum objects")
        minimum_payload = _strict_positive_int(sample.get("minimum_payload_bytes"), "attachment minimum payload")
        if versions < minimum_objects or retained < minimum_payload or allocated < retained:
            raise RuntimeError("attachment physical sample is insufficient")
        supplement_receipt = capacity_supplement.get("receipt") or {}
        supplement_sample = supplement_receipt.get("attachments") or {}
        supplement_fs = ((supplement_receipt.get("object_store") or {}).get("filesystem") or {}).get("attachments") or {}
        if (
            versions != supplement_sample.get("nonbootstrap_versions")
            or retained != supplement_sample.get("retained_payload_bytes")
            or allocated != supplement_fs.get("allocated_bytes")
        ):
            raise RuntimeError("attachment physical sample differs from the bound supplement")
        allocation_ratio = receipt.get("physical_allocation_ratio") or {}
        if (
            allocation_ratio.get("allocated_bytes") != allocated
            or allocation_ratio.get("retained_bytes") != retained
            or allocation_ratio.get("decimal_ratio") != round(allocated / retained, 9)
        ):
            raise RuntimeError("attachment physical allocation ratio mismatch")

        filesystem = receipt.get("filesystem_capacity") or {}
        total = _strict_positive_int(filesystem.get("total_bytes"), "attachment filesystem total bytes")
        used = _strict_positive_int(filesystem.get("used_bytes"), "attachment filesystem used bytes")
        available = _strict_positive_int(filesystem.get("available_bytes"), "attachment filesystem available bytes")
        if (
            total != supplement_fs.get("filesystem_total_bytes")
            or used != supplement_fs.get("filesystem_used_bytes")
            or available != supplement_fs.get("filesystem_available_bytes")
            or used + available != total
        ):
            raise RuntimeError("attachment filesystem counters mismatch")
        high_watermark = total * high_percent // 100
        reserve = (total * reserve_percent + 99) // 100
        headroom_to_high = max(0, high_watermark - used)
        headroom_after_reserve = max(0, available - reserve)
        operational_headroom = min(headroom_to_high, headroom_after_reserve)
        expected_filesystem = {
            "total_bytes": total,
            "used_bytes": used,
            "available_bytes": available,
            "high_watermark_bytes": high_watermark,
            "reserve_bytes": reserve,
            "headroom_to_high_watermark_bytes": headroom_to_high,
            "headroom_after_reserve_bytes": headroom_after_reserve,
            "operational_headroom_bytes": operational_headroom,
            "max_additional_full_ingress_events": operational_headroom // max_stored,
        }
        if filesystem != expected_filesystem:
            raise RuntimeError("attachment operational filesystem derivation mismatch")

        result.update(
            {
                "valid": True,
                "file_sha256": file_sha,
                "age_seconds": round(age, 3),
                "receipt": receipt,
                "operational_headroom_bytes": operational_headroom,
            }
        )
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def latest_physical_offhost(root: Path, *, max_age_seconds: int = 3600) -> dict[str, Any] | None:
    paths = sorted(root.glob("client-compact-*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
    for path in paths:
        value = json.loads(path.read_text(encoding="utf-8"))
        claimed = str(value.get("evidence_sha256") or "")
        unsigned = dict(value)
        unsigned.pop("evidence_sha256", None)
        created = dt.datetime.fromisoformat(str(value.get("created_utc") or "1970-01-01T00:00:00+00:00").replace("Z", "+00:00"))
        age = (dt.datetime.now(dt.UTC) - created.astimezone(dt.UTC)).total_seconds()
        checks = value.get("checks") or {}
        valid = (
            value.get("status") == "PASS"
            and value.get("incremental_physical_offhost") is True
            and value.get("remote_host") == "client"
            and value.get("production_authority") is False
            and all(checks.values())
            and int(value.get("event_count") or 0) >= 4000
            and claimed == sha256_bytes(canonical_json(unsigned))
            and 0 <= age <= max_age_seconds
        )
        return {"valid": valid, "path": str(path), "age_seconds": round(age, 3), "receipt": value}
    return None


def latest_golden_recall(root: Path, *, max_age_seconds: int = 3600) -> dict[str, Any] | None:
    paths = sorted(root.glob("compact-dual-golden-*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
    for path in paths:
        value = json.loads(path.read_text(encoding="utf-8"))
        claimed = str(value.get("receipt_sha256") or "")
        unsigned = dict(value)
        unsigned.pop("receipt_sha256", None)
        created = dt.datetime.fromisoformat(str(value.get("created_utc") or "1970-01-01T00:00:00+00:00").replace("Z", "+00:00"))
        age = (dt.datetime.now(dt.UTC) - created.astimezone(dt.UTC)).total_seconds()
        gates = value.get("gates") or {}
        metrics = value.get("metrics") or {}
        valid = (
            value.get("status") == "PASS"
            and value.get("served_plane") == "P1_CANONICAL_WITNESS"
            and value.get("p2_served_to_agent") is False
            and value.get("production_authority") is False
            and value.get("memory_grants_authority") is False
            and bool(gates)
            and all(gates.values())
            and float(metrics.get("authority_boundary_recall") or 0.0) == 1.0
            and float(metrics.get("causal_path_recall_at_20") or 0.0) >= 0.95
            and bool(metrics.get("early_event_1_found"))
            and int(metrics.get("unsupported_green_count") or 0) == 0
            and claimed == sha256_bytes(canonical_json(unsigned))
            and 0 <= age <= max_age_seconds
        )
        return {"valid": valid, "path": str(path), "age_seconds": round(age, 3), "receipt": value}
    return None


def _physical_component_samples(stage_scan: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    samples: dict[str, list[dict[str, Any]]] = {name: [] for name in PHYSICAL_COMPONENTS}
    for entry in stage_scan.get("valid_entries") or []:
        physical = entry["physical_receipt"]
        count = int(physical["physical_event_count"])
        for component in PHYSICAL_COMPONENTS:
            value = physical["storage"][component]
            total = max(int(value.get("logical_bytes") or 0), int(value.get("allocated_bytes") or 0))
            samples[component].append(
                {
                    "source": f"physical:{count}:{entry['file_sha256']}",
                    "bytes": total,
                    "events": count,
                    "ratio": _ratio(total, count),
                }
            )
    return samples


def evaluate(observed: dict[str, Any]) -> dict[str, Any]:
    postgres = observed["postgres"]
    raw = observed["s3"]
    compact = observed["compact"]
    catalog = observed["catalog"]
    raw_events = int(postgres["events"])
    indexed_events = int(compact["events"])
    if raw_events <= 0 or indexed_events <= 0:
        raise ValueError("live capacity samples must contain events")

    stage_scan = observed.get("stage_admissions") or {
        "discovered": 0,
        "all_valid": False,
        "monotonic": False,
        "latest": None,
        "valid_entries": [],
        "invalid": [],
    }
    latest = stage_scan.get("latest") or {}
    stage_catalog_safe = bool(stage_scan.get("all_valid")) and bool(stage_scan.get("monotonic")) and bool(latest.get("valid"))

    samples = _physical_component_samples(stage_scan)
    samples["raw"].append(
        {"source": "live:s3-latest-logical", "bytes": int(raw["latest_logical_bytes"]), "events": raw_events,
         "ratio": _ratio(int(raw["latest_logical_bytes"]), raw_events)}
    )
    index_bytes = max(int(compact["logical_bytes"]), int(compact["allocated_bytes"]))
    catalog_bytes = max(int(catalog["logical_bytes"]), int(catalog["allocated_bytes"]))
    ingest_bytes = int(postgres["guard_tables"]["ingest_batches"]["total_bytes"])
    samples["index"].append(
        {"source": "live:compact-index", "bytes": index_bytes, "events": indexed_events, "ratio": _ratio(index_bytes, indexed_events)}
    )
    samples["catalog"].append(
        {"source": "live:compact-catalog", "bytes": catalog_bytes, "events": indexed_events, "ratio": _ratio(catalog_bytes, indexed_events)}
    )
    samples["ingest_metadata"] = [
        {"source": "live:postgres-ingest", "bytes": ingest_bytes, "events": raw_events, "ratio": _ratio(ingest_bytes, raw_events)}
    ]
    supplement = observed.get("capacity_supplement_evidence") or {"valid": False}
    if supplement.get("valid") is True:
        supplement_receipt = supplement["receipt"]
        supplement_events = int(supplement_receipt["source_snapshot"]["raw_events"])
        supplement_source = f"capacity-supplement:{supplement['file_sha256']}"
        samples["raw"].append(
            {
                "source": supplement_source + ":raw-all-versions",
                "bytes": _ceil(supplement["raw_all_versions_bytes_per_event"] * supplement_events),
                "events": supplement_events,
                "ratio": supplement["raw_all_versions_bytes_per_event"],
            }
        )
        samples["event_bus"] = [
            {
                "source": supplement_source + ":event-bus-physical",
                "bytes": _ceil(supplement["bus_bytes_per_event"] * supplement_events),
                "events": supplement_events,
                "ratio": supplement["bus_bytes_per_event"],
            }
        ]
        samples["object_store_overhead"] = [
            {
                "source": supplement_source + ":object-store-overhead",
                "bytes": _ceil(supplement["object_store_overhead_bytes_per_event"] * supplement_events),
                "events": supplement_events,
                "ratio": supplement["object_store_overhead_bytes_per_event"],
            }
        ]
    attachment = observed.get("attachment_capacity_evidence") or {"valid": False}

    selected: dict[str, Fraction] = {}
    selected_sources: dict[str, str] = {}
    for component in KNOWN_COMPONENTS:
        candidates = samples.get(component) or []
        if candidates:
            item = max(candidates, key=lambda value: value["ratio"])
            selected[component] = item["ratio"]
            selected_sources[component] = str(item["source"])

    known_components_bound = all(component in selected for component in KNOWN_COMPONENTS) and stage_catalog_safe
    known_one_region_bpe = sum(selected.values(), Fraction(0, 1))
    known_one_region_bytes = _ceil(known_one_region_bpe * TARGET_EVENTS)
    known_required_per_domain = known_one_region_bytes * HEADROOM_NUMERATOR
    known_steady_total = known_one_region_bytes * REGIONAL_COPIES
    known_required_total = known_required_per_domain * REGIONAL_COPIES

    completeness = {
        "event_bus_retention_physical_bytes_measured": supplement.get("bus_measurement_valid") is True,
        "object_store_versioning_and_erasure_overhead_measured": supplement.get("object_store_measurement_valid") is True,
        "attachment_storage_operationally_admitted": attachment.get("valid") is True,
    }
    capacity_measurements_complete = known_components_bound and all(completeness.values())

    raw_domains = observed.get("capacity_domains") or []
    domains: list[dict[str, Any]] = []
    for item in raw_domains:
        name = str(item.get("name") or "")
        host_id = str(item.get("host_id") or "")
        storage_domain_id = str(item.get("storage_domain_id") or "")
        power_domain_id = str(item.get("power_domain_id") or "")
        region_id = str(item.get("region_id") or "")
        free = int(item.get("free_bytes") or -1)
        attested = item.get("live_observation") is True and item.get("topology_attested") is True and all(
            (name, host_id, storage_domain_id, power_domain_id, region_id)
        ) and power_domain_id != "unknown" and region_id != "unknown"
        domains.append(
            {
                "name": name,
                "host_id": host_id,
                "storage_domain_id": storage_domain_id,
                "power_domain_id": power_domain_id,
                "region_id": region_id,
                "free_bytes": free,
                "live_observation": attested,
                "topology_attested": item.get("topology_attested") is True,
                "can_host_one_known_copy": attested and free >= known_one_region_bytes,
                "has_known_2x_local_headroom": attested and free >= known_required_per_domain,
            }
        )
    attested_domains = [item for item in domains if item["live_observation"]]
    independent_dimensions = ("name", "host_id", "storage_domain_id", "power_domain_id")
    independent_domains = (
        len(attested_domains) >= REGIONAL_COPIES
        and all(len({item[field] for item in attested_domains}) == len(attested_domains) for field in independent_dimensions)
        and len({item["region_id"] for item in attested_domains}) >= REGIONAL_COPIES
    )
    domains_with_known_headroom = sum(item["has_known_2x_local_headroom"] for item in domains)
    combined_free = sum(max(0, int(item["free_bytes"])) for item in domains if item["live_observation"])
    known_capacity_lower_bound_pass = (
        independent_domains
        and domains_with_known_headroom >= REGIONAL_COPIES
        and combined_free >= known_required_total
    )
    capacity_release_pass = capacity_measurements_complete and known_capacity_lower_bound_pass

    regional = observed.get("regional_failover_evidence") or {"valid": False}
    physical_offhost = observed.get("physical_offhost_evidence") or {"valid": False}
    golden = observed.get("golden_recall_evidence") or {"valid": False}
    physical_billion = stage_catalog_safe and latest.get("physical_billion_event_run_completed") is True
    semantic_equivalence = stage_catalog_safe and latest.get("full_semantic_projection_raw_equivalence_verified") is True
    checks = {
        "compact_sample_events_at_least_4000": indexed_events >= 4000,
        "latest_physical_stage_admission_digest_chain_valid": stage_catalog_safe,
        "physical_stage_admission_catalog_monotonic": bool(stage_scan.get("monotonic")),
        "physical_component_measurements_bound": known_components_bound,
        "physical_incremental_offhost_domain_verified": physical_offhost.get("valid") is True,
        "golden_recall_and_authority_boundaries_verified": golden.get("valid") is True,
        "event_bus_retention_physical_bytes_measured": completeness["event_bus_retention_physical_bytes_measured"],
        "event_bus_target_capacity_admitted": supplement.get("bus_target_capacity_admitted") is True,
        "object_store_versioning_and_erasure_overhead_measured": completeness[
            "object_store_versioning_and_erasure_overhead_measured"
        ],
        "attachment_storage_operationally_admitted": completeness["attachment_storage_operationally_admitted"],
        "at_least_two_independent_live_capacity_domains": independent_domains,
        "each_capacity_domain_has_2x_headroom": domains_with_known_headroom >= REGIONAL_COPIES,
        "combined_proven_free_capacity_has_2x_headroom": capacity_release_pass,
        "physical_billion_event_run_completed": physical_billion,
        "regional_failover_rpo_rto_verified": regional.get("valid") is True,
        "full_semantic_projection_raw_equivalence_verified": semantic_equivalence,
    }
    blockers = sorted(name for name, value in checks.items() if not value)
    result = {
        "protocol": PROTOCOL + ".evidence",
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "status": "PASS" if not blockers else "FAIL",
        "target_events": TARGET_EVENTS,
        "headroom_factor": HEADROOM_NUMERATOR,
        "regional_copies": REGIONAL_COPIES,
        "sample_events": {"raw": raw_events, "compact": indexed_events},
        "selected_component_bytes_per_event": {
            name: {**_ratio_json(value), "selected_source": selected_sources[name]}
            for name, value in selected.items()
        },
        "capacity_projection": {
            "known_lower_bound_only": not capacity_measurements_complete,
            "known_one_region_bytes": known_one_region_bytes,
            "known_steady_state_bytes": known_steady_total,
            "known_required_per_domain_with_2x_headroom_bytes": known_required_per_domain,
            "known_required_total_with_2x_headroom_bytes": known_required_total,
            "combined_proven_free_bytes": combined_free,
            "known_lower_bound_available_fraction": round(combined_free / known_required_total, 9)
            if known_required_total
            else 0,
            "fault_domains": domains,
            "measurements_complete": capacity_measurements_complete,
            "known_lower_bound_capacity_pass": known_capacity_lower_bound_pass,
        },
        "stage_admission_evidence": {
            "root": stage_scan.get("root"),
            "discovered": int(stage_scan.get("discovered") or 0),
            "all_valid": bool(stage_scan.get("all_valid")),
            "monotonic": bool(stage_scan.get("monotonic")),
            "latest_path": latest.get("path"),
            "latest_file_sha256": latest.get("file_sha256"),
            "latest_physical_event_count": int((latest.get("receipt") or {}).get("physical_event_count") or 0),
            "invalid": stage_scan.get("invalid") or [],
        },
        "regional_failover_evidence": regional,
        "capacity_supplement_evidence": {
            "valid": supplement.get("valid") is True,
            "path": supplement.get("path"),
            "file_sha256": supplement.get("file_sha256"),
            "age_seconds": supplement.get("age_seconds"),
            "error": supplement.get("error"),
        },
        "attachment_capacity_evidence": {
            "valid": attachment.get("valid") is True,
            "path": attachment.get("path"),
            "file_sha256": attachment.get("file_sha256"),
            "age_seconds": attachment.get("age_seconds"),
            "operational_headroom_bytes": attachment.get("operational_headroom_bytes"),
            "error": attachment.get("error"),
        },
        "capacity_measurement_completeness": completeness,
        "compact_storage": {"index": compact, "catalog": catalog},
        "attachments_in_event_capacity_projection": False,
        "attachment_storage_accounted_separately": True,
        "checks": checks,
        "blockers": blockers,
        "legacy_boolean_claims_ignored": True,
        "projection_is_not_physical_run_proof": True,
        "sparse_or_extrapolated_pass": False,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    result["evidence_sha256"] = sha256_bytes(canonical_json(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--guard-env", type=Path, default=Path("/etc/integrity-memory-p2/guard.env"))
    parser.add_argument("--dual-env", type=Path, default=Path("/etc/integrity-memory-p2/dual-reader.env"))
    parser.add_argument("--minio-env", type=Path, default=Path("/etc/integrity-memory-p2/guard-minio.env"))
    parser.add_argument("--s3-endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    parser.add_argument("--client-endpoint", default=_integrity_value('endpoint_f5891d8ae959'))
    parser.add_argument(
        "--client-token",
        type=Path,
        default=Path("~workspace/.workspace/personal-pc-exec-token").expanduser(),
    )
    parser.add_argument("--index-root", type=Path, default=Path(_integrity_value('path_815eab4c81f8')))
    parser.add_argument("--catalog-root", type=Path, default=Path(_integrity_value('path_ad1bcafc7441')))
    parser.add_argument("--stage-admissions-root", type=Path, default=Path(_integrity_value('path_f18d26ced31b')))
    parser.add_argument("--capacity-supplement-receipt", type=Path)
    parser.add_argument("--attachment-capacity-receipt", type=Path)
    parser.add_argument(
        "--attachment-policy",
        type=Path,
        default=Path("/etc/integrity-memory-p2/p2-attachment-capacity-policy.json"),
    )
    parser.add_argument("--topology", type=Path, default=Path("/etc/integrity-memory-p2/p2-fault-domains.json"))
    parser.add_argument("--regional-failover-receipt", type=Path)
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_a7db3f473263')))
    parser.add_argument("--physical-offhost-receipts", type=Path, default=Path(_integrity_value('path_02ebb2142aa5')))
    parser.add_argument("--golden-receipts", type=Path, default=Path(_integrity_value('path_921dd9207d14')))
    args = parser.parse_args()
    index_state = json.loads((args.index_root / "state.json").read_text(encoding="utf-8"))
    catalog_state = json.loads((args.catalog_root / "state.json").read_text(encoding="utf-8"))
    physical_offhost = latest_physical_offhost(args.physical_offhost_receipts)
    golden_recall = latest_golden_recall(args.golden_receipts)
    client = client_observation(args.client_endpoint, args.client_token)
    client_free = sum(int(value["free_bytes"]) for value in client.get("volumes", []) if value.get("drive") == "D")
    stage_scan = load_stage_admissions(args.stage_admissions_root)
    topology = json.loads(args.topology.read_text(encoding="utf-8"))
    if (
        topology.get("protocol") != "integrity-memory-plane.p2-fault-domains.v1"
        or topology.get("production_authority") is not False
        or topology.get("memory_grants_authority") is not False
    ):
        raise RuntimeError("fault-domain topology contract mismatch")
    topology_nodes = {str(item.get("node_id")): item for item in (topology.get("nodes") or [])}

    def capacity_domain(node_id: str, free_bytes: int, live: bool) -> dict[str, Any]:
        node = topology_nodes.get(node_id) or {}
        return {
            "name": node_id,
            "host_id": str(node.get("host_domain") or ""),
            "storage_domain_id": str(node.get("storage_domain") or ""),
            "power_domain_id": str(node.get("power_domain") or ""),
            "region_id": str(node.get("region") or ""),
            "free_bytes": free_bytes,
            "live_observation": live,
            "topology_attested": node.get("regional_attested") is True,
        }

    capacity_supplement = validate_capacity_supplement(
        args.capacity_supplement_receipt,
        stage_scan=stage_scan,
        topology_path=args.topology,
    )
    attachment_capacity = validate_attachment_capacity(
        args.attachment_capacity_receipt,
        capacity_supplement=capacity_supplement,
        policy_path=args.attachment_policy,
    )
    observed = {
        "postgres": postgres_observation(args.guard_env, args.dual_env),
        "s3": s3_observation(args.minio_env, args.s3_endpoint),
        "compact": {"events": int(index_state["event_count"]), **tree_stats(args.index_root)},
        "catalog": {"events": int(catalog_state["uid_records"]), **tree_stats(args.catalog_root)},
        "capacity_domains": [
            capacity_domain("source-linux", filesystem_free(Path(_integrity_value('path_0dcb1df88675'))), True),
            capacity_domain("client", client_free, bool(client.get("volumes"))),
        ],
        "stage_admissions": stage_scan,
        "capacity_supplement_evidence": capacity_supplement,
        "attachment_capacity_evidence": attachment_capacity,
        "regional_failover_evidence": validate_regional_failover(args.regional_failover_receipt),
        "physical_offhost_evidence": physical_offhost,
        "golden_recall_evidence": golden_recall,
    }
    result = evaluate(observed)
    result["physical_offhost_evidence"] = physical_offhost
    result["golden_recall_evidence"] = golden_recall
    result["evidence_sha256"] = sha256_bytes(canonical_json({key: value for key, value in result.items() if key != "evidence_sha256"}))
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    path = args.receipt_root / f"compact-billion-{stamp}-{result['evidence_sha256'][:16]}.json"
    atomic_json(path, result, mode=0o440)
    print(json.dumps({**result, "receipt_path": str(path)}, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
