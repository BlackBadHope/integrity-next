#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed operational attachment-storage admission.

Per-event ingress limits are safety bounds, never a claim that every Action Log
event carries a maximum-sized attachment.  Capacity is admitted from current
retained/allocated bytes, filesystem watermarks and an independently produced
ingress-enforcement receipt.  No billion-event attachment extrapolation is
performed.
"""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file
from p2_capacity_supplement import ATTACHMENT_BUCKET, PROTOCOL as SUPPLEMENT_PROTOCOL


POLICY_PROTOCOL = "integrity-memory-plane.p2-attachment-operational-policy.v2"
RECEIPT_PROTOCOL = "integrity-memory-plane.p2-attachment-operational-capacity.v2.receipt"
ENFORCEMENT_PROTOCOL = "integrity-memory-plane.p2-attachment-ingress-enforcement.v1.receipt"
MAX_EVIDENCE_AGE_SECONDS = 3600
POLICY_KEYS = {
    "protocol",
    "tenant_id",
    "namespace",
    "bucket",
    "max_object_bytes",
    "max_objects_per_event",
    "max_payload_bytes_per_event",
    "max_manifest_bytes_per_event",
    "minimum_physical_sample_objects",
    "minimum_physical_sample_payload_bytes",
    "capacity_model",
    "filesystem_high_watermark_percent",
    "filesystem_reserve_percent",
    "payload_key_contract",
    "manifest_key_contract",
    "retention_contract",
    "source_constraints",
    "production_authority",
    "memory_grants_authority",
}
RETENTION_KEYS = {
    "versioning",
    "object_lock",
    "retention_mode",
    "minimum_retention_days",
    "delete_markers_forbidden",
    "unmeasured_multipart_forbidden",
}
ENFORCEMENT_CHECKS = {
    "oversized_object_rejected",
    "fifth_object_rejected",
    "payload_budget_overflow_rejected",
    "digest_mismatch_rejected",
    "content_addressed_duplicate_idempotent",
    "exact_version_readback_verified",
    "canonical_event_reference_bound",
    "all_canonical_attachment_references_validated",
}
REQUIRED_CHECKS = {
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
ARTIFACT_FILES = {
    "attachment_capacity": ("p2_attachment_capacity.py", "attachment-capacity"),
    "attachment_enforcement": ("p2_attachment_enforcement.py", "attachment-enforcement"),
    "attachment_ingress": ("p2_attachment_ingress.py", "attachment-ingress"),
    "capacity_supplement": ("p2_capacity_supplement.py", "capacity-supplement"),
}


def _artifact_path(name: str) -> Path:
    base = Path(__file__).resolve().parent
    for candidate in ARTIFACT_FILES.get(name, ()):
        path = base / candidate
        if path.is_file() and not path.is_symlink():
            return path
    raise RuntimeError(f"bound artifact is unavailable: {name}")


def _strict_int(value: Any, name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise RuntimeError(f"{name} must be an integer >= {minimum}")
    return value


def _load_signed(path: Path, protocol: str) -> tuple[dict[str, Any], str]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("protocol") != protocol:
        raise RuntimeError(f"protocol mismatch: {path}")
    claimed = str(value.get("evidence_sha256") or "")
    unsigned = dict(value)
    unsigned.pop("evidence_sha256", None)
    if claimed != sha256_bytes(canonical_json(unsigned)):
        raise RuntimeError(f"evidence digest mismatch: {path}")
    return value, sha256_file(path)


def validate_policy(policy: dict[str, Any], project_root: Path) -> dict[str, Any]:
    if set(policy) != POLICY_KEYS or policy.get("protocol") != POLICY_PROTOCOL:
        raise RuntimeError("attachment policy schema mismatch")
    if policy.get("tenant_id") != "workspace" or policy.get("namespace") != _integrity_value('seed_namespace'):
        raise RuntimeError("attachment policy identity mismatch")
    if policy.get("bucket") != ATTACHMENT_BUCKET:
        raise RuntimeError("attachment policy bucket mismatch")
    max_object = _strict_int(policy.get("max_object_bytes"), "max object bytes", minimum=1)
    max_objects = _strict_int(policy.get("max_objects_per_event"), "max objects per event", minimum=1)
    max_payload = _strict_int(policy.get("max_payload_bytes_per_event"), "max payload bytes per event", minimum=1)
    _strict_int(policy.get("max_manifest_bytes_per_event"), "max manifest bytes per event", minimum=1)
    if max_payload > max_object * max_objects:
        raise RuntimeError("attachment policy per-event budget exceeds the object/count bound")
    _strict_int(policy.get("minimum_physical_sample_objects"), "minimum sample objects", minimum=1)
    _strict_int(policy.get("minimum_physical_sample_payload_bytes"), "minimum sample bytes", minimum=1)
    if policy.get("capacity_model") != "current-retained-bytes-and-filesystem-watermarks":
        raise RuntimeError("attachment operational capacity model mismatch")
    high_watermark = _strict_int(
        policy.get("filesystem_high_watermark_percent"), "filesystem high watermark", minimum=1
    )
    reserve = _strict_int(policy.get("filesystem_reserve_percent"), "filesystem reserve", minimum=1)
    if high_watermark >= 100 or reserve >= 100 or high_watermark + reserve > 100:
        raise RuntimeError("attachment filesystem watermark policy is invalid")
    if policy.get("payload_key_contract") != "attachments/v1/sha256/<first2>/<sha256>":
        raise RuntimeError("attachment payload key contract mismatch")
    if policy.get("manifest_key_contract") != "attachment-manifests/v1/sha256/<first2>/<sha256>.json":
        raise RuntimeError("attachment manifest key contract mismatch")
    retention = policy.get("retention_contract") or {}
    if set(retention) != RETENTION_KEYS:
        raise RuntimeError("attachment retention policy schema mismatch")
    if not (
        retention.get("versioning") == "Enabled"
        and retention.get("object_lock") == "Enabled"
        and retention.get("retention_mode") == "COMPLIANCE"
        and _strict_int(retention.get("minimum_retention_days"), "minimum retention days", minimum=30) >= 30
        and retention.get("delete_markers_forbidden") is True
        and retention.get("unmeasured_multipart_forbidden") is True
    ):
        raise RuntimeError("attachment WORM policy mismatch")
    constraints = policy.get("source_constraints")
    if not isinstance(constraints, list) or not constraints:
        raise RuntimeError("attachment policy has no source constraints")
    current = True
    normalized = []
    for item in constraints:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise RuntimeError("attachment source constraint schema mismatch")
        relative = Path(str(item["path"]))
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError("attachment source constraint path escapes project")
        path = (project_root / relative).resolve()
        expected = str(item["sha256"])
        actual = sha256_file(path) if path.is_file() else ""
        current = current and len(expected) == 64 and actual == expected
        normalized.append({"path": str(path), "expected_sha256": expected, "actual_sha256": actual})
    if policy.get("production_authority") is not False or policy.get("memory_grants_authority") is not False:
        raise RuntimeError("attachment policy attempted to grant authority")
    return {"source_constraints_current": current, "source_constraints": normalized}


def validate_enforcement(value: dict[str, Any] | None, policy_sha256: str) -> bool:
    if not value or value.get("protocol") != ENFORCEMENT_PROTOCOL:
        return False
    claimed = str(value.get("evidence_sha256") or "")
    unsigned = dict(value)
    unsigned.pop("evidence_sha256", None)
    checks = value.get("checks") or {}
    created = dt.datetime.fromisoformat(str(value.get("created_utc") or "1970-01-01T00:00:00+00:00").replace("Z", "+00:00"))
    age = (dt.datetime.now(dt.UTC) - created.astimezone(dt.UTC)).total_seconds()
    return (
        claimed == sha256_bytes(canonical_json(unsigned))
        and value.get("status") == "PASS"
        and value.get("policy_file_sha256") == policy_sha256
        and value.get("bucket") == ATTACHMENT_BUCKET
        and value.get("production_authority") is False
        and value.get("memory_grants_authority") is False
        and set(checks) == ENFORCEMENT_CHECKS
        and all(item is True for item in checks.values())
        and 0 <= age <= MAX_EVIDENCE_AGE_SECONDS
    )


def evaluate(
    policy: dict[str, Any],
    supplement: dict[str, Any],
    *,
    project_root: Path,
    policy_file_sha256: str,
    supplement_path: Path,
    supplement_file_sha256: str,
    enforcement: dict[str, Any] | None = None,
    enforcement_path: Path | None = None,
    enforcement_file_sha256: str | None = None,
    artifact_sha256: dict[str, str] | None = None,
) -> dict[str, Any]:
    policy_validation = validate_policy(policy, project_root)
    unsigned_supplement = dict(supplement)
    claimed_supplement = str(unsigned_supplement.pop("evidence_sha256", ""))
    supplement_integrity = (
        supplement.get("protocol") == SUPPLEMENT_PROTOCOL
        and claimed_supplement == sha256_bytes(canonical_json(unsigned_supplement))
        and supplement.get("production_authority") is False
        and supplement.get("memory_grants_authority") is False
    )
    checks_in = supplement.get("checks") or {}
    measurements = supplement.get("measurement_checks") or {}
    attachments = supplement.get("attachments") or {}
    object_store = supplement.get("object_store") or {}
    bucket = (object_store.get("buckets") or {}).get(ATTACHMENT_BUCKET) or {}
    attachment_fs = (object_store.get("filesystem") or {}).get("attachments") or {}
    nonbootstrap = _strict_int(attachments.get("nonbootstrap_versions"), "nonbootstrap attachment versions")
    retained = _strict_int(attachments.get("retained_payload_bytes"), "retained attachment bytes")
    allocated = _strict_int(attachment_fs.get("allocated_bytes"), "allocated attachment bytes")
    sample_valid = (
        nonbootstrap >= int(policy["minimum_physical_sample_objects"])
        and retained >= int(policy["minimum_physical_sample_payload_bytes"])
    )
    ratio_valid = sample_valid and allocated >= retained > 0
    enforcement_valid = validate_enforcement(enforcement, policy_file_sha256)
    max_stored_bytes_per_event = int(policy["max_payload_bytes_per_event"]) + int(
        policy["max_manifest_bytes_per_event"]
    )
    filesystem_total = _strict_int(
        attachment_fs.get("filesystem_total_bytes"), "attachment filesystem total bytes", minimum=1
    )
    filesystem_used = _strict_int(
        attachment_fs.get("filesystem_used_bytes"), "attachment filesystem used bytes"
    )
    filesystem_available = _strict_int(
        attachment_fs.get("filesystem_available_bytes"), "attachment filesystem available bytes"
    )
    filesystem_arithmetic_valid = filesystem_used + filesystem_available == filesystem_total
    high_percent = int(policy["filesystem_high_watermark_percent"])
    reserve_percent = int(policy["filesystem_reserve_percent"])
    high_watermark_bytes = filesystem_total * high_percent // 100
    reserve_bytes = (filesystem_total * reserve_percent + 99) // 100
    headroom_to_high_watermark = max(0, high_watermark_bytes - filesystem_used)
    headroom_after_reserve = max(0, filesystem_available - reserve_bytes)
    operational_headroom = min(headroom_to_high_watermark, headroom_after_reserve)
    checks = {
        "policy_source_constraints_current": policy_validation["source_constraints_current"],
        "capacity_supplement_integrity_valid": supplement_integrity,
        "capacity_supplement_object_store_measurement_valid": measurements.get("object_store") is True,
        "attachment_worm_contract_bound": checks_in.get("object_store_worm_contract_verified") is True,
        "attachment_inventory_stable": checks_in.get("object_store_inventory_stable_during_physical_measurement") is True,
        "attachment_delete_markers_absent": int(bucket.get("delete_markers") or 0) == 0,
        "attachment_unmeasured_multipart_absent": int(bucket.get("incomplete_multipart_uploads") or 0) == 0,
        "representative_nonbootstrap_workload_observed": sample_valid,
        "attachment_physical_allocation_ratio_valid": ratio_valid,
        "attachment_filesystem_arithmetic_valid": filesystem_arithmetic_valid,
        "attachment_filesystem_below_high_watermark": filesystem_used < high_watermark_bytes,
        "attachment_reserve_preserved": filesystem_available > reserve_bytes,
        "attachment_max_event_fits_remaining_headroom": operational_headroom >= max_stored_bytes_per_event,
        "canonical_ingress_enforcement_receipt_valid": enforcement_valid,
    }
    if set(checks) != REQUIRED_CHECKS or any(type(value) is not bool for value in checks.values()):
        raise RuntimeError("attachment capacity check schema mismatch")
    admitted = all(checks.values())
    result = {
        "protocol": RECEIPT_PROTOCOL,
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "status": "PASS" if admitted else "INCOMPLETE",
        "capacity_scope": "current-live-attachment-storage",
        "billion_event_projection_excluded": True,
        "policy": {
            "path": None,
            "file_sha256": policy_file_sha256,
            "max_object_bytes": policy["max_object_bytes"],
            "max_objects_per_event": policy["max_objects_per_event"],
            "max_payload_bytes_per_event": policy["max_payload_bytes_per_event"],
            "max_manifest_bytes_per_event": policy["max_manifest_bytes_per_event"],
            "max_stored_bytes_per_event": max_stored_bytes_per_event,
            "capacity_model": policy["capacity_model"],
            "filesystem_high_watermark_percent": high_percent,
            "filesystem_reserve_percent": reserve_percent,
            "source_constraints": policy_validation["source_constraints"],
        },
        "capacity_supplement": {
            "path": str(supplement_path.resolve()),
            "file_sha256": supplement_file_sha256,
            "evidence_sha256": supplement.get("evidence_sha256"),
        },
        "enforcement_receipt": {
            "path": str(enforcement_path.resolve()) if enforcement_path else None,
            "file_sha256": enforcement_file_sha256,
        },
        "artifact_sha256": dict(artifact_sha256 or {}),
        "physical_sample": {
            "nonbootstrap_versions": nonbootstrap,
            "retained_payload_bytes": retained,
            "allocated_bytes": allocated,
            "minimum_objects": policy["minimum_physical_sample_objects"],
            "minimum_payload_bytes": policy["minimum_physical_sample_payload_bytes"],
        },
        "physical_allocation_ratio": (
            {
                "allocated_bytes": allocated,
                "retained_bytes": retained,
                "decimal_ratio": round(allocated / retained, 9),
            }
            if ratio_valid
            else None
        ),
        "filesystem_capacity": {
            "total_bytes": filesystem_total,
            "used_bytes": filesystem_used,
            "available_bytes": filesystem_available,
            "high_watermark_bytes": high_watermark_bytes,
            "reserve_bytes": reserve_bytes,
            "headroom_to_high_watermark_bytes": headroom_to_high_watermark,
            "headroom_after_reserve_bytes": headroom_after_reserve,
            "operational_headroom_bytes": operational_headroom,
            "max_additional_full_ingress_events": operational_headroom // max_stored_bytes_per_event,
        },
        "capacity_admitted": admitted,
        "checks": checks,
        "blockers": sorted(name for name, passed in checks.items() if not passed),
        "per_event_limit_is_not_population_projection": True,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    result["evidence_sha256"] = sha256_bytes(canonical_json(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, default=Path("/etc/integrity-memory-p2/p2-attachment-capacity-policy.json"))
    parser.add_argument("--capacity-supplement-receipt", type=Path, required=True)
    parser.add_argument("--enforcement-receipt", type=Path)
    parser.add_argument("--project-root", type=Path, default=Path(_integrity_value('path_6c566dbbf48b')))
    parser.add_argument(
        "--receipt-root",
        type=Path,
        default=Path(_integrity_value('path_edfc7d2638fe')),
    )
    args = parser.parse_args()
    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    supplement, supplement_file_sha256 = _load_signed(args.capacity_supplement_receipt, SUPPLEMENT_PROTOCOL)
    enforcement = None
    enforcement_file_sha256 = None
    if args.enforcement_receipt:
        enforcement, enforcement_file_sha256 = _load_signed(args.enforcement_receipt, ENFORCEMENT_PROTOCOL)
    result = evaluate(
        policy,
        supplement,
        project_root=args.project_root,
        policy_file_sha256=sha256_file(args.policy),
        supplement_path=args.capacity_supplement_receipt,
        supplement_file_sha256=supplement_file_sha256,
        enforcement=enforcement,
        enforcement_path=args.enforcement_receipt,
        enforcement_file_sha256=enforcement_file_sha256,
        artifact_sha256={name: sha256_file(_artifact_path(name)) for name in ARTIFACT_FILES},
    )
    result["policy"]["path"] = str(args.policy.resolve())
    result["evidence_sha256"] = sha256_bytes(canonical_json({k: v for k, v in result.items() if k != "evidence_sha256"}))
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    path = args.receipt_root / f"attachment-capacity-{stamp}-{result['evidence_sha256'][:16]}.json"
    atomic_json(path, result, mode=0o440)
    print(json.dumps({**result, "receipt_path": str(path)}, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
