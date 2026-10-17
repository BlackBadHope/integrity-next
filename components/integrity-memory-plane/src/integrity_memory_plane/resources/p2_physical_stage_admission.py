#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Combine immutable physical, verifier, and retrieval receipts into one staged admission."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import json
import re
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file


PROTOCOL = "integrity-memory-plane.p2-physical-stage-admission.v1"
PHYSICAL_PROTOCOL = "integrity-memory-plane.p2-physical-history-lab.v1.receipt"
VERIFY_PROTOCOL = "integrity-memory-plane.p2-physical-verify-replay.v1.receipt"
RETRIEVAL_PROTOCOL = "integrity-memory-plane.p2-physical-retrieval-replay.v1.receipt"
READER_ONLY_FAILURES = {"exact_lookup_p95_lte_1000ms", "semantic_retrieval_lte_2000ms"}
SHA256 = re.compile(r"[0-9a-f]{64}")
STAGE_LADDER = (1_000_000, 10_000_000, 100_000_000, 1_000_000_000)
IMMEDIATE_PREDECESSOR = {
    count: (STAGE_LADDER[index - 1] if index else None)
    for index, count in enumerate(STAGE_LADDER)
}


def load_receipt(path: Path, protocol: str) -> tuple[dict[str, Any], str]:
    value = json.loads(path.read_text(encoding="utf-8"))
    claimed = str(value.get("evidence_sha256") or "")
    unsigned = dict(value)
    unsigned.pop("evidence_sha256", None)
    if value.get("protocol") != protocol or not SHA256.fullmatch(claimed):
        raise RuntimeError(f"{protocol} protocol/evidence field mismatch")
    if claimed != sha256_bytes(canonical_json(unsigned)):
        raise RuntimeError(f"{protocol} canonical evidence digest mismatch")
    if value.get("production_authority") is not False or value.get("memory_grants_authority") is not False:
        raise RuntimeError(f"{protocol} authority boundary mismatch")
    return value, sha256_file(path)


def artifact_digests_valid(value: dict[str, Any]) -> bool:
    artifacts = value.get("artifact_sha256") or {}
    return bool(artifacts) and all(SHA256.fullmatch(str(digest)) for digest in artifacts.values())


def validate_predecessor(
    *,
    count: int,
    canonical_root: str,
    previous_admission: Path | None,
) -> tuple[str, str, int]:
    """Validate one exact predecessor edge in the immutable stage ladder.

    The already deployed one-million admission predates the explicit chain
    check.  It is safe to accept that receipt as genesis only when both legacy
    predecessor fields are empty.  Every non-genesis predecessor must carry
    the new, all-green chain check and both predecessor digests so transitive
    trust fails closed.
    """

    if count not in IMMEDIATE_PREDECESSOR:
        raise RuntimeError(f"unsupported physical stage count: {count}")
    expected_previous_count = IMMEDIATE_PREDECESSOR[count]
    if expected_previous_count is None:
        if previous_admission is not None:
            raise RuntimeError("physical-1000000 is genesis and rejects a predecessor")
        return "", "", 0
    if previous_admission is None:
        raise RuntimeError(f"physical-{count} requires physical-{expected_previous_count} predecessor")

    previous, previous_file_sha = load_receipt(previous_admission, PROTOCOL + ".receipt")
    previous_count = int(previous.get("physical_event_count") or 0)
    previous_checks = previous.get("checks") or {}
    if (
        previous.get("status") != "PASS"
        or previous.get("blockers") not in ([], None)
        or not previous_checks
        or any(type(value) is not bool or value is not True for value in previous_checks.values())
    ):
        raise RuntimeError("physical stage predecessor is not an all-green admission")
    if previous_count != expected_previous_count or previous.get("stage") != f"physical-{expected_previous_count}":
        raise RuntimeError(
            f"physical-{count} requires immediate physical-{expected_previous_count} predecessor"
        )
    current_root = Path(canonical_root)
    previous_root = Path(str(previous.get("source_root") or ""))
    if (
        not previous_root.is_absolute()
        or previous_root.resolve() != previous_root
        or previous_root.parent != current_root.parent
    ):
        raise RuntimeError("physical stage predecessor lineage root mismatch")

    predecessor_evidence_sha = str(previous.get("previous_stage_admission_sha256") or "")
    predecessor_file_sha = str(previous.get("previous_stage_admission_file_sha256") or "")
    if expected_previous_count == STAGE_LADDER[0]:
        # Backward-compatible, locally derivable genesis read.  The old 1M
        # receipt did not have the file-SHA field or explicit chain check.
        if predecessor_evidence_sha or predecessor_file_sha:
            raise RuntimeError("physical-1000000 predecessor has invalid genesis linkage")
    elif (
        previous_checks.get("stage_predecessor_exact") is not True
        or not SHA256.fullmatch(predecessor_evidence_sha)
        or not SHA256.fullmatch(predecessor_file_sha)
    ):
        raise RuntimeError("physical stage predecessor chain proof is missing")
    if not SHA256.fullmatch(previous_file_sha):
        raise RuntimeError("previous admission file digest mismatch")
    return str(previous["evidence_sha256"]), previous_file_sha, previous_count


def run(args: argparse.Namespace) -> dict[str, Any]:
    physical, physical_file_sha = load_receipt(args.physical_receipt, PHYSICAL_PROTOCOL)
    verify, verify_file_sha = load_receipt(args.verify_receipt, VERIFY_PROTOCOL)
    retrieval, retrieval_file_sha = load_receipt(args.retrieval_receipt, RETRIEVAL_PROTOCOL)
    count = int(physical.get("physical_event_count") or 0)
    canonical_root = str(args.root.resolve())
    if count < 1 or str(physical.get("stage") or "") != f"physical-{count}":
        raise RuntimeError("physical stage/count mismatch")
    if count not in IMMEDIATE_PREDECESSOR:
        raise RuntimeError(f"unsupported physical stage count: {count}")
    for name, value in (("verify", verify), ("retrieval", retrieval)):
        if int(value.get("physical_event_count") or 0) != count or str(value.get("source_root") or "") != canonical_root:
            raise RuntimeError(f"{name} count/root mismatch")
    if str(verify.get("physical_receipt_evidence_sha256") or "") != str(physical["evidence_sha256"]):
        raise RuntimeError("verify-to-physical evidence binding mismatch")
    if str(retrieval.get("physical_receipt_evidence_sha256") or "") != str(physical["evidence_sha256"]):
        raise RuntimeError("retrieval-to-physical evidence binding mismatch")
    if str(retrieval.get("verify_receipt_evidence_sha256") or "") != str(verify["evidence_sha256"]):
        raise RuntimeError("retrieval-to-verify evidence binding mismatch")
    if str((retrieval.get("reader_attestation") or {}).get("snapshot_sha256") or "") != str(verify.get("catalog_state_sha256") or ""):
        raise RuntimeError("retrieval catalog generation binding mismatch")

    physical_checks = {str(key): bool(value) for key, value in (physical.get("checks") or {}).items()}
    false_physical = {name for name, passed in physical_checks.items() if not passed}
    declared_blockers = {str(value) for value in (physical.get("blockers") or [])}
    structural_failures = false_physical - READER_ONLY_FAILURES
    reader_failures = false_physical & READER_ONLY_FAILURES
    verify_pass = verify.get("status") == "PASS" and bool(verify.get("checks")) and all(bool(v) for v in verify["checks"].values())
    retrieval_pass = retrieval.get("status") == "PASS" and bool(retrieval.get("checks")) and all(
        bool(v) for v in retrieval["checks"].values()
    )
    previous_sha, previous_file_sha, previous_count = validate_predecessor(
        count=count,
        canonical_root=canonical_root,
        previous_admission=args.previous_admission,
    )
    checks = {
        "source_receipt_digests_valid": True,
        "source_root_and_count_bound": True,
        "physical_non_sparse": physical.get("sparse_or_extrapolated_run") is False,
        "physical_checks_present": bool(physical_checks),
        "physical_declared_blockers_exact": declared_blockers == false_physical,
        "physical_structural_failures_zero": not structural_failures,
        "physical_reader_failures_only_allowlisted": reader_failures == false_physical,
        "bounded_verify_pass": verify_pass,
        "retrieval_replay_pass": retrieval_pass,
        "verify_artifacts_bound": artifact_digests_valid(verify),
        "retrieval_artifacts_bound": artifact_digests_valid(retrieval),
        "uid_catalog_matches_payload": bool((verify.get("checks") or {}).get("uid_catalog_matches_payload")),
        "reader_generation_bound": True,
        "stage_predecessor_exact": (
            previous_count == 0
            if count == STAGE_LADDER[0]
            else previous_count == IMMEDIATE_PREDECESSOR[count]
        ),
        "stage_monotonic": count > previous_count,
        "production_authority_false": True,
    }
    effective_stage_pass = all(checks.values())
    physical_billion = effective_stage_pass and count >= 1_000_000_000
    milestones = {
        "physical_100k_completed": effective_stage_pass and count >= 100_000,
        "physical_1m_completed": effective_stage_pass and count >= 1_000_000,
        "physical_10m_completed": effective_stage_pass and count >= 10_000_000,
        "physical_100m_completed": effective_stage_pass and count >= 100_000_000,
    }
    result = {
        "protocol": PROTOCOL + ".receipt",
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "status": "PASS" if effective_stage_pass else "FAIL",
        "source_root": canonical_root,
        "stage_lineage_root": str(Path(canonical_root).parent),
        "physical_event_count": count,
        "stage": f"physical-{count}",
        "source_receipts": {
            "physical": {"path": str(args.physical_receipt.resolve()), "file_sha256": physical_file_sha, "evidence_sha256": physical["evidence_sha256"]},
            "verify": {"path": str(args.verify_receipt.resolve()), "file_sha256": verify_file_sha, "evidence_sha256": verify["evidence_sha256"]},
            "retrieval": {"path": str(args.retrieval_receipt.resolve()), "file_sha256": retrieval_file_sha, "evidence_sha256": retrieval["evidence_sha256"]},
        },
        "index_state_sha256": verify["index_state_sha256"],
        "catalog_state_sha256": verify["catalog_state_sha256"],
        "compact_manifest_head_sha256": verify["verify"]["manifest_head_sha256"],
        "reader_artifact_sha256": {"verify": verify["artifact_sha256"], "retrieval": retrieval["artifact_sha256"]},
        "physical_original_status": physical["status"],
        "physical_original_reader_failures": sorted(reader_failures),
        "checks": checks,
        "milestone_checks": milestones,
        "release_checks": {
            "physical_billion_event_run_completed": physical_billion,
            "combined_proven_free_capacity_has_2x_headroom": False,
            "regional_failover_rpo_rto_verified": False,
            "full_semantic_projection_raw_equivalence_verified": False,
        },
        "physical_billion_event_run_completed": physical_billion,
        "previous_stage_admission_sha256": previous_sha,
        "previous_stage_admission_file_sha256": previous_file_sha,
        "blockers": sorted(name for name, passed in checks.items() if not passed),
        "global_release_blockers": [
            name
            for name, passed in {
                "physical_billion_event_run_completed": physical_billion,
                "combined_proven_free_capacity_has_2x_headroom": False,
                "regional_failover_rpo_rto_verified": False,
                "full_semantic_projection_raw_equivalence_verified": False,
            }.items()
            if not passed
        ],
        "production_authority": False,
        "memory_grants_authority": False,
    }
    result["evidence_sha256"] = sha256_bytes(canonical_json(result))
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    path = args.receipt_root / f"admission-{count}-{stamp}-{result['evidence_sha256'][:16]}.json"
    atomic_json(path, result, mode=0o440)
    return {**result, "receipt_path": str(path)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--physical-receipt", type=Path, required=True)
    parser.add_argument("--verify-receipt", type=Path, required=True)
    parser.add_argument("--retrieval-receipt", type=Path, required=True)
    parser.add_argument("--previous-admission", type=Path)
    parser.add_argument("--receipt-root", type=Path, required=True)
    args = parser.parse_args()
    result = run(args)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
