#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify an isolated P2 fault/load receipt without rerunning the lab."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from memory_plane_common import canonical_json, sha256_bytes, sha256_file


PROTOCOL = "integrity-memory-plane.p2-fault-lab.v1.receipt"
PROJECTIONS = ("fts", "vector", "graph", "task-state")
BOOLEAN_FAULTS = (
    "object_outage_fail_closed",
    "object_outage_recovered_same_intent",
    "postgres_mid_transaction_rolled_back",
    "duplicate_bus_ack_on_recovery",
    "cross_batch_uid_collision_rejected",
    "future_gap_made_guard_red",
    "explicit_dlq_restored_explained_pass",
)


def semantic_sha256(receipt: dict[str, Any]) -> str:
    value = dict(receipt)
    value.pop("receipt_sha256", None)
    return sha256_bytes(canonical_json(value))


def command_log_matches(path: Path, expected_sha256: str, *, allow_cleanup_suffix: bool) -> bool:
    """Accept an exact journal or a legacy receipt-bound prefix plus cleanup only."""
    if sha256_file(path) == expected_sha256:
        return True
    if not allow_cleanup_suffix:
        return False
    digest = hashlib.sha256()
    matched_prefix = False
    suffix: list[bytes] = []
    with path.open("rb") as handle:
        for line in handle:
            if matched_prefix:
                suffix.append(line)
                continue
            digest.update(line)
            if digest.hexdigest() == expected_sha256:
                matched_prefix = True
    if not matched_prefix or not suffix:
        return False
    try:
        records = [json.loads(line) for line in suffix]
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    return all(str(record.get("label", "")).startswith("docker-logs-") for record in records)


def verify(receipt: dict[str, Any], *, check_artifacts: bool = True) -> list[str]:
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    require(receipt.get("protocol") == PROTOCOL, "unexpected protocol")
    require(receipt.get("status") == "PASS", "receipt status is not PASS")
    require(receipt.get("receipt_sha256") == semantic_sha256(receipt), "semantic receipt SHA-256 mismatch")
    require(receipt.get("production_authority") is False, "fault lab must not claim production authority")
    require(receipt.get("memory_grants_authority") is False, "memory must not grant authority")

    boundary = receipt.get("ack_boundary", {})
    require(boundary.get("production_authority") is False, "ACK boundary claims production authority")
    require(boundary.get("rpo_zero_claimed") is False, "shadow lab must not claim RPO=0")
    require(boundary.get("shadow_receipts_not_production_ack") is True, "shadow receipt boundary is missing")

    isolation = receipt.get("isolation", {})
    for key in ("canonical_action_log_touched", "p1_touched", "production_endpoints_touched"):
        require(isolation.get(key) is False, f"isolation violation: {key}")
    require(isolation.get("host") == "127.0.0.2", "lab did not use the isolated loopback identity")

    load = receipt.get("load", {})
    baseline = receipt.get("production_baseline", {})
    events = int(load.get("events", -1))
    batch_count = int(load.get("batch_count", -1))
    required_rate = float(baseline.get("required_10x_events_per_minute", float("inf")))
    observed_rate = float(load.get("events_per_minute", -1))
    require(events >= 10_000, "load gate used fewer than 10,000 events")
    require(int(load.get("clean_measured_events", -1)) > 0, "clean measured load is missing")
    require(observed_rate >= required_rate, "load rate is below the 10x gate")
    require(float(load.get("production_peak_multiplier", -1)) >= 10.0, "production peak multiplier is below 10x")
    postgres = load.get("postgres", {})
    require(int(postgres.get("events", -1)) == events, "PostgreSQL event count differs from generated load")
    require(int(postgres.get("batches", -1)) == batch_count, "PostgreSQL batch count differs from generated load")

    faults = receipt.get("faults", {})
    for key in BOOLEAN_FAULTS:
        require(faults.get(key) is True, f"fault gate is not proven: {key}")
    require(faults.get("postgres_mid_transaction_exit_code") == 97, "mid-transaction crash exit code is not 97")

    guard = receipt.get("guard", {})
    require(guard.get("baseline_status") == "PASS", "baseline guard is not PASS")
    require(guard.get("red_status") == "FAIL", "injected future gap did not make guard FAIL")
    require(guard.get("final_status") == "PASS", "final explained guard is not PASS")
    failures = guard.get("final_hard_failures", {})
    require(bool(failures) and all(value == 0 for value in failures.values()), "final guard has hard failures")
    lag = guard.get("final_projection_lag", {})
    require(set(lag) == set(PROJECTIONS), "final guard projection set is incomplete")
    require(bool(lag) and all(value == 0 for value in lag.values()), "final projection lag is non-zero")

    rebuild = receipt.get("projection_rebuild", {})
    require(rebuild.get("parity") is True, "projection rebuild parity is false")
    sync = rebuild.get("sync", {})
    restored = rebuild.get("rebuild", {})
    require(set(sync) == set(PROJECTIONS), "sync projection set is incomplete")
    require(set(restored) == set(PROJECTIONS), "rebuilt projection set is incomplete")
    for projection in PROJECTIONS:
        require(sync.get(projection) == restored.get(projection), f"projection rebuild differs: {projection}")
        require(restored.get(projection, {}).get("last_cursor") == events, f"projection cursor differs: {projection}")

    if check_artifacts:
        try:
            lab_root = Path(str(receipt["lab_root"]))
            relative_log = receipt.get("command_log_path")
            command_log = lab_root / (str(relative_log) if relative_log else "logs/commands.jsonl")
            require(lab_root.is_dir(), "lab root is missing")
            require(command_log.is_file(), "command log is missing")
            if command_log.is_file():
                require(
                    command_log_matches(
                        command_log,
                        str(receipt.get("command_log_sha256", "")),
                        allow_cleanup_suffix=relative_log is None,
                    ),
                    "command log SHA-256/prefix mismatch",
                )
        except (KeyError, TypeError, OSError) as exc:
            errors.append(f"artifact verification failed: {exc}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--skip-artifact-check", action="store_true")
    args = parser.parse_args()
    try:
        receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
        errors = verify(receipt, check_artifacts=not args.skip_artifact_check)
    except Exception as exc:  # fail closed on unreadable or malformed evidence
        errors = [f"unable to verify receipt: {exc}"]
        receipt = {}
    result = {
        "protocol": "integrity-memory-plane.p2-fault-lab.verify.v1",
        "receipt": str(args.receipt),
        "receipt_sha256": receipt.get("receipt_sha256"),
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if not errors else 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    sys.exit(main())
