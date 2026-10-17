from __future__ import annotations

import copy
import datetime as dt
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_plane_common import canonical_json, sha256_bytes, sha256_file  # noqa: E402
from p2_attachment_capacity import (  # noqa: E402
    ENFORCEMENT_CHECKS,
    ENFORCEMENT_PROTOCOL,
    POLICY_PROTOCOL,
    evaluate,
)
from p2_capacity_supplement import ATTACHMENT_BUCKET, PROTOCOL as SUPPLEMENT_PROTOCOL  # noqa: E402


def _source(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "guard.py"
    path.write_text("MAX = 8\n", encoding="utf-8")
    return path, sha256_file(path)


def policy(tmp_path: Path) -> dict:
    source, digest = _source(tmp_path)
    return {
        "protocol": POLICY_PROTOCOL,
        "tenant_id": "workspace",
        "namespace": "seed://project/default",
        "bucket": ATTACHMENT_BUCKET,
        "max_object_bytes": 8,
        "max_objects_per_event": 4,
        "max_payload_bytes_per_event": 32,
        "max_manifest_bytes_per_event": 16,
        "minimum_physical_sample_objects": 2,
        "minimum_physical_sample_payload_bytes": 64,
        "capacity_model": "current-retained-bytes-and-filesystem-watermarks",
        "filesystem_high_watermark_percent": 80,
        "filesystem_reserve_percent": 20,
        "payload_key_contract": "attachments/v1/sha256/<first2>/<sha256>",
        "manifest_key_contract": "attachment-manifests/v1/sha256/<first2>/<sha256>.json",
        "retention_contract": {
            "versioning": "Enabled",
            "object_lock": "Enabled",
            "retention_mode": "COMPLIANCE",
            "minimum_retention_days": 30,
            "delete_markers_forbidden": True,
            "unmeasured_multipart_forbidden": True,
        },
        "source_constraints": [{"path": source.name, "sha256": digest}],
        "production_authority": False,
        "memory_grants_authority": False,
    }


def supplement(
    *,
    nonbootstrap: int = 2,
    retained: int = 64,
    allocated: int = 128,
    filesystem_total: int = 1_000,
    filesystem_used: int = 100,
) -> dict:
    value = {
        "protocol": SUPPLEMENT_PROTOCOL,
        "production_authority": False,
        "memory_grants_authority": False,
        "measurement_checks": {"bus": True, "object_store": True, "attachments": False},
        "checks": {
            "object_store_worm_contract_verified": True,
            "object_store_inventory_stable_during_physical_measurement": True,
        },
        "attachments": {"nonbootstrap_versions": nonbootstrap, "retained_payload_bytes": retained},
        "object_store": {
            "buckets": {ATTACHMENT_BUCKET: {"delete_markers": 0, "incomplete_multipart_uploads": 0}},
            "filesystem": {
                "attachments": {
                    "allocated_bytes": allocated,
                    "filesystem_total_bytes": filesystem_total,
                    "filesystem_used_bytes": filesystem_used,
                    "filesystem_available_bytes": filesystem_total - filesystem_used,
                }
            },
        },
    }
    value["evidence_sha256"] = sha256_bytes(canonical_json(value))
    return value


def enforcement(policy_sha256: str) -> dict:
    value = {
        "protocol": ENFORCEMENT_PROTOCOL,
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "status": "PASS",
        "policy_file_sha256": policy_sha256,
        "bucket": ATTACHMENT_BUCKET,
        "checks": {name: True for name in ENFORCEMENT_CHECKS},
        "production_authority": False,
        "memory_grants_authority": False,
    }
    value["evidence_sha256"] = sha256_bytes(canonical_json(value))
    return value


def run(tmp_path: Path, value: dict, sample: dict, proof: dict | None = None) -> dict:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(value), encoding="utf-8")
    return evaluate(
        value,
        sample,
        project_root=tmp_path,
        policy_file_sha256=sha256_file(policy_path),
        supplement_path=tmp_path / "supplement.json",
        supplement_file_sha256="a" * 64,
        enforcement=proof,
    )


def test_missing_sample_and_enforcement_never_use_zero_as_capacity(tmp_path: Path) -> None:
    value = policy(tmp_path)
    result = run(tmp_path, value, supplement(nonbootstrap=0, retained=132, allocated=4096))
    assert result["status"] == "INCOMPLETE"
    assert result["capacity_admitted"] is False
    assert result["physical_allocation_ratio"] is None
    assert result["billion_event_projection_excluded"] is True
    assert result["per_event_limit_is_not_population_projection"] is True
    assert "projected_physical_bytes_at_target" not in result
    assert "representative_nonbootstrap_workload_observed" in result["blockers"]
    assert "canonical_ingress_enforcement_receipt_valid" in result["blockers"]


def test_exact_policy_sample_and_bound_enforcement_admit_operational_storage(tmp_path: Path) -> None:
    value = policy(tmp_path)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(value), encoding="utf-8")
    policy_sha = sha256_file(policy_path)
    result = evaluate(
        value,
        supplement(),
        project_root=tmp_path,
        policy_file_sha256=policy_sha,
        supplement_path=tmp_path / "supplement.json",
        supplement_file_sha256="a" * 64,
        enforcement=enforcement(policy_sha),
    )
    assert result["status"] == "PASS"
    assert result["physical_allocation_ratio"] == {
        "allocated_bytes": 128,
        "retained_bytes": 64,
        "decimal_ratio": 2.0,
    }
    assert result["filesystem_capacity"]["high_watermark_bytes"] == 800
    assert result["filesystem_capacity"]["reserve_bytes"] == 200
    assert result["filesystem_capacity"]["operational_headroom_bytes"] == 700
    assert result["filesystem_capacity"]["max_additional_full_ingress_events"] == 14
    assert "required_bytes_per_region_with_2x_headroom" not in result


def test_operational_storage_fails_closed_at_watermark_or_reserve(tmp_path: Path) -> None:
    value = policy(tmp_path)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(value), encoding="utf-8")
    result = evaluate(
        value,
        supplement(filesystem_total=1_000, filesystem_used=800),
        project_root=tmp_path,
        policy_file_sha256=sha256_file(policy_path),
        supplement_path=tmp_path / "supplement.json",
        supplement_file_sha256="a" * 64,
        enforcement=enforcement(sha256_file(policy_path)),
    )
    assert result["status"] == "INCOMPLETE"
    assert result["checks"]["attachment_filesystem_below_high_watermark"] is False
    assert result["checks"]["attachment_reserve_preserved"] is False
    assert result["checks"]["attachment_max_event_fits_remaining_headroom"] is False


def test_enforcement_bound_to_another_policy_is_rejected(tmp_path: Path) -> None:
    value = policy(tmp_path)
    result = run(tmp_path, value, supplement(), enforcement("f" * 64))
    assert result["capacity_admitted"] is False
    assert result["checks"]["canonical_ingress_enforcement_receipt_valid"] is False


def test_source_constraint_drift_fails_closed(tmp_path: Path) -> None:
    value = policy(tmp_path)
    (tmp_path / "guard.py").write_text("MAX = 9\n", encoding="utf-8")
    result = run(tmp_path, value, supplement())
    assert result["checks"]["policy_source_constraints_current"] is False
    assert result["capacity_admitted"] is False


def test_policy_budget_cannot_exceed_object_count_bound(tmp_path: Path) -> None:
    value = policy(tmp_path)
    value["max_payload_bytes_per_event"] += 1
    with pytest.raises(RuntimeError, match="budget exceeds"):
        run(tmp_path, value, supplement())


def test_tampered_capacity_supplement_is_rejected(tmp_path: Path) -> None:
    value = policy(tmp_path)
    sample = supplement()
    sample["attachments"]["retained_payload_bytes"] += 1
    result = run(tmp_path, value, sample)
    assert result["checks"]["capacity_supplement_integrity_valid"] is False
    assert result["capacity_admitted"] is False
