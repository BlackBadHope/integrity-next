#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only retrieval SLO replay over an existing physical history stage."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import json
import math
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file
import p2_compact_catalog
import p2_compact_index
import p2_compact_retrieval
from p2_compact_catalog import attest_catalog
from p2_compact_retrieval import retrieve
from p2_physical_history_lab import LocalWormClient


PROTOCOL = "integrity-memory-plane.p2-physical-retrieval-replay.v1"


def percentile95(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)] if ordered else 0.0


def validated_receipt(path: Path, protocol: str) -> tuple[dict[str, Any], str]:
    value = json.loads(path.read_text(encoding="utf-8"))
    claimed = str(value.get("evidence_sha256") or "")
    unsigned = dict(value)
    unsigned.pop("evidence_sha256", None)
    if value.get("protocol") != protocol or claimed != sha256_bytes(canonical_json(unsigned)):
        raise RuntimeError(f"{protocol} digest/protocol mismatch")
    if value.get("production_authority") is not False or value.get("memory_grants_authority") is not False:
        raise RuntimeError(f"{protocol} authority boundary mismatch")
    return value, sha256_file(path)


def run(args: argparse.Namespace) -> dict[str, Any]:
    root, event_count, exact_samples = args.root, args.event_count, args.exact_samples
    physical, physical_file_sha = validated_receipt(
        args.physical_receipt, "integrity-memory-plane.p2-physical-history-lab.v1.receipt"
    )
    verify_receipt, verify_file_sha = validated_receipt(
        args.verify_receipt, "integrity-memory-plane.p2-physical-verify-replay.v1.receipt"
    )
    canonical_root = str(root.resolve())
    if int(physical.get("physical_event_count") or 0) != event_count or physical.get("sparse_or_extrapolated_run") is not False:
        raise RuntimeError("physical receipt count/sparse mismatch")
    if int(verify_receipt.get("physical_event_count") or 0) != event_count:
        raise RuntimeError("verify receipt count mismatch")
    if str(verify_receipt.get("source_root") or "") != canonical_root:
        raise RuntimeError("verify receipt source root mismatch")
    if str(verify_receipt.get("physical_receipt_evidence_sha256") or "") != str(physical["evidence_sha256"]):
        raise RuntimeError("verify receipt physical binding mismatch")
    index_root = root / "compact-index"
    catalog_root = args.catalog_root_override or (root / "compact-catalog")
    receipts_root = root / "relay-receipts"
    client = LocalWormClient(root / "raw")
    attestation = attest_catalog(catalog_root)
    catalog_state_sha256 = sha256_file(catalog_root / "state.json")
    catalog_migration = None
    catalog_migration_file_sha256 = None
    if args.catalog_migration_receipt is not None:
        catalog_migration, catalog_migration_file_sha256 = validated_receipt(
            args.catalog_migration_receipt,
            "integrity-memory-plane.p2-compact-catalog.v1.block-integrity-hydration-receipt",
        )
    catalog_state = json.loads((catalog_root / "state.json").read_text(encoding="utf-8"))
    migration_binding_valid = bool(catalog_migration) and all(catalog_migration["checks"].values()) and all(
        (
            catalog_migration["status"] == "PASS",
            str(catalog_migration["origin_state_sha256"]) == str(verify_receipt["catalog_state_sha256"]),
            str(catalog_migration["hydrated_state_sha256"]) == catalog_state_sha256,
            str(catalog_migration["semantic_run_binding_sha256"])
            == p2_compact_catalog.catalog_run_binding_sha256(catalog_state),
        )
    )
    exact_latencies: list[float] = []
    exact_proven = True
    for index in range(exact_samples):
        cursor = 1 + ((index * 104_729) % event_count)
        value = retrieve(
            f"#{cursor}", index_root, receipts_root, client,
            limit=20, capsule_budget=32768, catalog_root=catalog_root,
            receipt_catalog_path=catalog_root / "receipts.json",
        )
        exact_latencies.append(float(value["elapsed_ms"]))
        exact_proven = exact_proven and value["decision"] == "SUPPORTED" and bool(value["all_included_proven"])
    semantic = retrieve(
        "early-anchor-one", index_root, receipts_root, client,
        limit=20, capsule_budget=32768, catalog_root=catalog_root,
        receipt_catalog_path=catalog_root / "receipts.json",
    )
    causal = retrieve(
        "task_path:physical-causal-anchor", index_root, receipts_root, client,
        limit=20, capsule_budget=32768, catalog_root=catalog_root,
        receipt_catalog_path=catalog_root / "receipts.json",
    )
    negative = retrieve(
        "qzxwvut-physical-no-evidence-987654321", index_root, receipts_root, client,
        limit=20, capsule_budget=32768, catalog_root=catalog_root,
        receipt_catalog_path=catalog_root / "receipts.json",
    )
    exact_p95 = percentile95(exact_latencies)
    expected = {317, 318, 319}
    causal_ids = set((causal.get("causal_path") or {}).get("event_ids") or [])
    checks = {
        "physical_receipt_bound": True,
        "bounded_verify_receipt_bound": verify_receipt["status"] == "PASS" and all(verify_receipt["checks"].values()),
        "index_generation_matches_verify": sha256_file(index_root / "state.json") == str(verify_receipt["index_state_sha256"]),
        "catalog_generation_matches_verify": catalog_state_sha256 == str(verify_receipt["catalog_state_sha256"])
        or migration_binding_valid,
        "catalog_migration_binding_valid": catalog_state_sha256 == str(verify_receipt["catalog_state_sha256"])
        or migration_binding_valid,
        "reader_attestation_pass": attestation["status"] == "PASS" and all(attestation["checks"].values()),
        "reader_bootstrap_sample_lte_1000ms": float(attestation["elapsed_ms"]) <= 1000.0,
        "exact_samples_all_worm_proven": exact_proven and len(exact_latencies) == exact_samples,
        "exact_lookup_p95_lte_1000ms": exact_p95 <= 1000.0,
        "semantic_anchor_recall": semantic["decision"] == "SUPPORTED" and 1 in semantic["included_event_ids"],
        "semantic_retrieval_lte_2000ms": float(semantic["elapsed_ms"]) <= 2000.0,
        "causal_path_recall_at_20_gte_95": len(expected & causal_ids) / len(expected) >= 0.95,
        "negative_stays_unknown": negative["decision"] == "NO_EVIDENCE" and not negative["included_event_ids"],
        "all_included_worm_proven": all(bool(value["all_included_proven"]) for value in (semantic, causal)),
        "production_authority_false": True,
    }
    result = {
        "protocol": PROTOCOL + ".receipt",
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "status": "PASS" if all(checks.values()) else "FAIL",
        "physical_event_count": event_count,
        "source_root": canonical_root,
        "catalog_root": str(catalog_root.resolve()),
        "catalog_migration_receipt_path": str(args.catalog_migration_receipt.resolve())
        if args.catalog_migration_receipt is not None
        else None,
        "catalog_migration_receipt_file_sha256": catalog_migration_file_sha256,
        "physical_receipt_path": str(args.physical_receipt.resolve()),
        "physical_receipt_file_sha256": physical_file_sha,
        "physical_receipt_evidence_sha256": physical["evidence_sha256"],
        "verify_receipt_path": str(args.verify_receipt.resolve()),
        "verify_receipt_file_sha256": verify_file_sha,
        "verify_receipt_evidence_sha256": verify_receipt["evidence_sha256"],
        "artifact_sha256": {
            "physical_retrieval_replay": sha256_file(Path(__file__)),
            "compact_index": sha256_file(Path(p2_compact_index.__file__)),
            "compact_catalog": sha256_file(Path(p2_compact_catalog.__file__)),
            "compact_retrieval": sha256_file(Path(p2_compact_retrieval.__file__)),
        },
        "reader_attestation": attestation,
        "retrieval": {
            "exact_samples": exact_samples,
            "exact_p95_ms": round(exact_p95, 3),
            "semantic_ms": float(semantic["elapsed_ms"]),
            "causal_ms": float(causal["elapsed_ms"]),
            "negative_ms": float(negative["elapsed_ms"]),
            "semantic_event_ids": semantic["included_event_ids"],
            "causal_event_ids": sorted(causal_ids),
        },
        "checks": checks,
        "blockers": sorted(name for name, passed in checks.items() if not passed),
        "production_authority": False,
        "memory_grants_authority": False,
    }
    result["evidence_sha256"] = sha256_bytes(canonical_json(result))
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    path = args.receipt_root / f"retrieval-{event_count}-{stamp}-{result['evidence_sha256'][:16]}.json"
    atomic_json(path, result, mode=0o440)
    return {**result, "receipt_path": str(path)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--physical-receipt", type=Path, required=True)
    parser.add_argument("--verify-receipt", type=Path, required=True)
    parser.add_argument("--receipt-root", type=Path, required=True)
    parser.add_argument("--catalog-root-override", type=Path)
    parser.add_argument("--catalog-migration-receipt", type=Path)
    parser.add_argument("--event-count", type=int, required=True)
    parser.add_argument("--exact-samples", type=int, default=20)
    args = parser.parse_args()
    if args.event_count < 319 or args.exact_samples < 3:
        raise ValueError("physical replay parameters rejected")
    result = run(args)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
