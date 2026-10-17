#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Issue an immutable bounded-verifier receipt for an existing physical stage."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import json
import resource
import time
from pathlib import Path
from typing import Any

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file
import p2_compact_catalog
import p2_compact_index
from p2_compact_index import verify_store


PROTOCOL = "integrity-memory-plane.p2-physical-verify-replay.v1"


def validated_physical_receipt(path: Path, expected_events: int) -> tuple[dict[str, Any], str]:
    value = json.loads(path.read_text(encoding="utf-8"))
    claimed = str(value.get("evidence_sha256") or "")
    unsigned = dict(value)
    unsigned.pop("evidence_sha256", None)
    if claimed != sha256_bytes(canonical_json(unsigned)):
        raise RuntimeError("physical source receipt evidence digest mismatch")
    if int(value.get("physical_event_count") or 0) != expected_events or value.get("sparse_or_extrapolated_run") is not False:
        raise RuntimeError("physical source receipt count/sparse contract mismatch")
    if value.get("production_authority") is not False or value.get("memory_grants_authority") is not False:
        raise RuntimeError("physical source receipt authority boundary mismatch")
    return value, sha256_file(path)


def run(args: argparse.Namespace) -> dict[str, Any]:
    physical, physical_file_sha = validated_physical_receipt(args.physical_receipt, args.event_count)
    index_root = args.root / "compact-index"
    catalog_root = args.root / "compact-catalog"
    index_state_sha = sha256_file(index_root / "state.json")
    catalog_state_sha = sha256_file(catalog_root / "state.json")
    started = time.perf_counter()
    verify = verify_store(index_root, catalog_root)
    elapsed = time.perf_counter() - started
    checks = {
        "physical_receipt_digest_valid": True,
        "physical_receipt_non_sparse": physical["sparse_or_extrapolated_run"] is False,
        "bounded_verifier_pass": verify["status"] == "PASS" and all(verify["checks"].values()),
        "event_count_matches_physical": int(verify["event_count"]) == args.event_count,
        "cursor_parity_100_percent": int(verify["first_cursor"]) == 1 and int(verify["last_cursor"]) == args.event_count,
        "uid_proof_payload_derived": verify["uid_verification"]["method"] == "transient-external-sort-from-compact-payloads",
        "uid_catalog_matches_payload": bool(verify["checks"]["persistent_uid_catalog_matches_payload"]),
        "semantic_claim_not_misrepresented_as_raw_equivalence": verify["semantic_claims_only_not_raw_equivalence"] is True,
        "production_authority_false": True,
    }
    result = {
        "protocol": PROTOCOL + ".receipt",
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "status": "PASS" if all(checks.values()) else "FAIL",
        "source_root": str(args.root.resolve()),
        "physical_event_count": args.event_count,
        "physical_receipt_path": str(args.physical_receipt.resolve()),
        "physical_receipt_file_sha256": physical_file_sha,
        "physical_receipt_evidence_sha256": physical["evidence_sha256"],
        "index_state_sha256": index_state_sha,
        "catalog_state_sha256": catalog_state_sha,
        "artifact_sha256": {
            "physical_verify_replay": sha256_file(Path(__file__)),
            "compact_index": sha256_file(Path(p2_compact_index.__file__)),
            "compact_catalog": sha256_file(Path(p2_compact_catalog.__file__)),
        },
        "verify": verify,
        "elapsed_seconds": round(elapsed, 3),
        "peak_rss_bytes": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024,
        "checks": checks,
        "blockers": sorted(name for name, passed in checks.items() if not passed),
        "production_authority": False,
        "memory_grants_authority": False,
    }
    result["evidence_sha256"] = sha256_bytes(canonical_json(result))
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    path = args.receipt_root / f"verify-{args.event_count}-{stamp}-{result['evidence_sha256'][:16]}.json"
    atomic_json(path, result, mode=0o440)
    return {**result, "receipt_path": str(path)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--physical-receipt", type=Path, required=True)
    parser.add_argument("--receipt-root", type=Path, required=True)
    parser.add_argument("--event-count", type=int, required=True)
    args = parser.parse_args()
    result = run(args)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
