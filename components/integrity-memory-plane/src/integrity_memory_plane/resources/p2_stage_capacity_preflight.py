#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed local capacity preflight for the next physical P2 stage.

The preflight never treats a projection as a completed physical run.  It
scales the exact allocated-byte total from an admitted predecessor, rounds the
target requirement upwards, requires two complete target copies plus a 20%
filesystem reserve, and binds the decision to immutable input and code/config
identities.
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
from typing import Any, Iterable

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file


PROTOCOL = "integrity-memory-plane.p2-stage-capacity-preflight.v1.receipt"
STAGE_ADMISSION_PROTOCOL = "integrity-memory-plane.p2-physical-stage-admission.v1.receipt"
PHYSICAL_PROTOCOL = "integrity-memory-plane.p2-physical-history-lab.v1.receipt"
TOPOLOGY_PROTOCOL = "integrity-memory-plane.p2-fault-domains.v1"
STAGE_PROFILE_PROTOCOL = "integrity-memory-plane.p2-physical-stage-profile.v1"
TARGET_PREDECESSOR = {10_000_000: 1_000_000, 100_000_000: 10_000_000}
PHYSICAL_COMPONENTS = ("raw", "receipts", "index", "catalog")
HEADROOM_COPIES = 2
FILESYSTEM_RESERVE_PERCENT = 20
SHA256 = re.compile(r"[0-9a-f]{64}")
IDENTITY_NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}")

DEFAULT_ARTIFACTS = {
    "stage_capacity_preflight": ("p2_stage_capacity_preflight.py", "physical-stage-capacity-preflight"),
    "physical_history_lab": ("p2_physical_history_lab.py", "physical-history-lab"),
    "physical_stage_admission": ("p2_physical_stage_admission.py", "physical-stage-admission"),
    "physical_verify_replay": ("p2_physical_verify_replay.py", "physical-verify-replay"),
    "physical_retrieval_replay": ("p2_physical_retrieval_replay.py", "physical-retrieval-replay"),
    "compact_index": ("p2_compact_index.py", "compact-index"),
    "compact_catalog": ("p2_compact_catalog.py", "compact-catalog"),
    "compact_retrieval": ("p2_compact_retrieval.py", "compact-retrieval"),
    "memory_plane_common": ("memory_plane_common.py",),
}


def _strict_positive_int(value: Any, name: str) -> int:
    if type(value) is not int or value <= 0:  # bool is deliberately rejected
        raise RuntimeError(f"{name} must be a positive integer")
    return value


def _strict_nonnegative_int(value: Any, name: str) -> int:
    if type(value) is not int or value < 0:
        raise RuntimeError(f"{name} must be a non-negative integer")
    return value


def _ceil(value: Fraction) -> int:
    return (value.numerator + value.denominator - 1) // value.denominator


def _ratio_json(value: Fraction) -> dict[str, int]:
    return {
        "numerator_bytes": value.numerator,
        "denominator_events": value.denominator,
    }


def _signed_receipt(path: Path, protocol: str) -> tuple[dict[str, Any], str]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"receipt is unavailable or symlinked: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"receipt root must be an object: {path}")
    claimed = str(value.get("evidence_sha256") or "")
    unsigned = dict(value)
    unsigned.pop("evidence_sha256", None)
    if value.get("protocol") != protocol:
        raise RuntimeError(f"receipt protocol mismatch: {path}")
    if not SHA256.fullmatch(claimed) or claimed != sha256_bytes(canonical_json(unsigned)):
        raise RuntimeError(f"receipt canonical evidence mismatch: {path}")
    if value.get("production_authority") is not False or value.get("memory_grants_authority") is not False:
        raise RuntimeError(f"receipt authority boundary mismatch: {path}")
    return value, sha256_file(path)


def _file_identity(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"bound file is unavailable or symlinked: {path}")
    canonical = path.resolve()
    size = canonical.stat().st_size
    if size <= 0:
        raise RuntimeError(f"bound file is empty: {canonical}")
    return {"path": str(canonical), "sha256": sha256_file(canonical), "bytes": int(size)}


def _parse_named_paths(specs: Iterable[str], kind: str) -> dict[str, Path]:
    values: dict[str, Path] = {}
    for raw in specs:
        name, separator, path = str(raw).partition("=")
        if not separator or not IDENTITY_NAME.fullmatch(name) or not path:
            raise RuntimeError(f"{kind} must use name=/absolute/or/relative/path syntax")
        if name in values:
            raise RuntimeError(f"duplicate {kind} identity: {name}")
        values[name] = Path(path)
    return values


def artifact_identities(extra_specs: Iterable[str]) -> dict[str, dict[str, Any]]:
    base = Path(__file__).resolve().parent
    paths: dict[str, Path] = {}
    for name, candidates in DEFAULT_ARTIFACTS.items():
        selected = next(
            (base / filename for filename in candidates if (base / filename).is_file() and not (base / filename).is_symlink()),
            None,
        )
        if selected is None:
            raise RuntimeError(f"required artifact is unavailable: {name}")
        paths[name] = selected
    for name, path in _parse_named_paths(extra_specs, "artifact").items():
        if name in paths:
            raise RuntimeError(f"artifact identity shadows a required artifact: {name}")
        paths[name] = path
    return {name: _file_identity(path) for name, path in sorted(paths.items())}


def configuration_identities(specs: Iterable[str]) -> dict[str, dict[str, Any]]:
    paths = _parse_named_paths(specs, "config")
    if "stage_profile" not in paths:
        raise RuntimeError("stage_profile named configuration file is required")
    identities = {name: _file_identity(path) for name, path in sorted(paths.items())}
    profile = json.loads(Path(identities["stage_profile"]["path"]).read_text(encoding="utf-8"))
    expected = {
        "protocol": STAGE_PROFILE_PROTOCOL,
        "stage_ladder_events": [1_000_000, 10_000_000, 100_000_000, 1_000_000_000],
        "capacity_headroom_copies": HEADROOM_COPIES,
        "filesystem_reserve_percent": FILESYSTEM_RESERVE_PERCENT,
        "projection_only_does_not_complete_stage": True,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    if not isinstance(profile, dict) or any(profile.get(key) != value for key, value in expected.items()):
        raise RuntimeError("physical stage profile contract mismatch")
    for key in ("batch_size", "bucket_span", "capsule_bytes", "exact_samples", "progress_every"):
        _strict_positive_int(profile.get(key), f"stage profile {key}")
    route_id = str(profile.get("route_id") or "")
    if not re.fullmatch(r"[0-9a-f]{8}", route_id):
        raise RuntimeError("physical stage profile route_id must be eight lowercase hex characters")
    if profile["batch_size"] > profile["bucket_span"] or not 8192 <= profile["capsule_bytes"] <= 32768:
        raise RuntimeError("physical stage profile operational bounds mismatch")
    identities["stage_profile"].update(
        {
            "protocol": STAGE_PROFILE_PROTOCOL,
            "canonical_json_sha256": sha256_bytes(canonical_json(profile)),
            "route_id": route_id,
            "run_parameters": {
                key: profile[key]
                for key in ("batch_size", "bucket_span", "capsule_bytes", "exact_samples", "progress_every")
            },
        }
    )
    return identities


def topology_identity(path: Path) -> dict[str, Any]:
    identity = _file_identity(path)
    value = json.loads(Path(identity["path"]).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("fault-domain topology root must be an object")
    if (
        value.get("protocol") != TOPOLOGY_PROTOCOL
        or value.get("production_authority") is not False
        or value.get("memory_grants_authority") is not False
        or not isinstance(value.get("nodes"), list)
        or not value["nodes"]
    ):
        raise RuntimeError("fault-domain topology contract mismatch")
    identity["canonical_json_sha256"] = sha256_bytes(canonical_json(value))
    identity["protocol"] = TOPOLOGY_PROTOCOL
    return identity


def filesystem_identity(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError(f"filesystem path is unavailable or symlinked: {path}")
    canonical = path.resolve()
    stat = canonical.stat()
    fs = os.statvfs(canonical)
    fragment_size = _strict_positive_int(int(fs.f_frsize), "filesystem fragment size")
    block_size = _strict_positive_int(int(fs.f_bsize), "filesystem block size")
    blocks = _strict_positive_int(int(fs.f_blocks), "filesystem blocks")
    blocks_available = _strict_nonnegative_int(int(fs.f_bavail), "filesystem available blocks")
    blocks_free = _strict_nonnegative_int(int(fs.f_bfree), "filesystem free blocks")
    if blocks_available > blocks_free or blocks_free > blocks:
        raise RuntimeError("filesystem block counters are inconsistent")
    total = blocks * fragment_size
    available = blocks_available * fragment_size
    free = blocks_free * fragment_size
    return {
        "path": str(canonical),
        "device_id": int(stat.st_dev),
        "fragment_size_bytes": fragment_size,
        "block_size_bytes": block_size,
        "blocks": blocks,
        "blocks_available_to_unprivileged": blocks_available,
        "blocks_free": blocks_free,
        "total_bytes": total,
        "available_bytes": available,
        "free_bytes": free,
        "used_bytes": total - free,
    }


def planned_target_filesystem_identity(
    target_root: Path,
    *,
    target_events: int,
    expected_lineage_root: str,
    route_id: str,
) -> dict[str, Any]:
    if target_root.is_symlink():
        raise RuntimeError("planned physical target root cannot be a symlink")
    canonical_target = target_root.resolve()
    expected_name = f"physical-{target_events}-route{route_id}"
    if canonical_target.name != expected_name:
        raise RuntimeError(f"planned target root must be named {expected_name}")
    if str(canonical_target.parent) != expected_lineage_root:
        raise RuntimeError("planned target root is outside the admitted stage lineage")
    target_exists = target_root.exists()
    if target_exists:
        if not target_root.is_dir() or any(target_root.iterdir()):
            raise RuntimeError("planned physical target root must be absent or empty")
        observation_path = target_root
    else:
        observation_path = target_root.parent
    identity = filesystem_identity(observation_path)
    identity.update(
        {
            "target_root": str(canonical_target),
            "target_root_exists": target_exists,
            "target_root_empty": True,
            "observation_path": identity.pop("path"),
        }
    )
    return identity


def admitted_sample(admission_path: Path, physical_override: Path | None, target_events: int) -> dict[str, Any]:
    if target_events not in TARGET_PREDECESSOR:
        raise RuntimeError("target events must be exactly 10000000 or 100000000")
    admission, admission_file_sha = _signed_receipt(admission_path, STAGE_ADMISSION_PROTOCOL)
    sample_events = _strict_positive_int(admission.get("physical_event_count"), "admission event count")
    expected_sample_events = TARGET_PREDECESSOR[target_events]
    if sample_events != expected_sample_events or admission.get("stage") != f"physical-{sample_events}":
        raise RuntimeError(
            f"target {target_events} requires admitted physical-{expected_sample_events} predecessor"
        )
    checks = admission.get("checks")
    if (
        admission.get("status") != "PASS"
        or not isinstance(checks, dict)
        or not checks
        or any(value is not True for value in checks.values())
        or admission.get("blockers") not in ([], None)
    ):
        raise RuntimeError("stage admission is not an all-green predecessor")

    source_root = Path(str(admission.get("source_root") or ""))
    if not source_root.is_absolute() or source_root.resolve() != source_root or not source_root.is_dir():
        raise RuntimeError("stage admission source root is unavailable or non-canonical")
    lineage_root = str(source_root.parent)
    claimed_lineage = str(admission.get("stage_lineage_root") or "")
    predecessor_evidence_sha = str(admission.get("previous_stage_admission_sha256") or "")
    predecessor_file_sha = str(admission.get("previous_stage_admission_file_sha256") or "")
    if sample_events == 1_000_000:
        if predecessor_evidence_sha or predecessor_file_sha:
            raise RuntimeError("physical-1000000 sample has invalid genesis linkage")
        if claimed_lineage and claimed_lineage != lineage_root:
            raise RuntimeError("physical-1000000 sample lineage root mismatch")
    elif (
        checks.get("stage_predecessor_exact") is not True
        or not SHA256.fullmatch(predecessor_evidence_sha)
        or not SHA256.fullmatch(predecessor_file_sha)
        or claimed_lineage != lineage_root
    ):
        raise RuntimeError("non-genesis stage admission chain binding is incomplete")

    binding = (admission.get("source_receipts") or {}).get("physical") or {}
    bound_path_text = str(binding.get("path") or "")
    if not bound_path_text:
        raise RuntimeError("stage admission has no physical receipt path binding")
    bound_path = Path(bound_path_text)
    if not bound_path.is_absolute() or bound_path.resolve() != bound_path:
        raise RuntimeError("stage admission physical receipt path is non-canonical")
    try:
        bound_path.relative_to(source_root)
    except ValueError as exc:
        raise RuntimeError("stage admission physical receipt escapes source root") from exc
    physical_path = physical_override if physical_override is not None else bound_path
    physical, physical_file_sha = _signed_receipt(physical_path, PHYSICAL_PROTOCOL)
    if physical_file_sha != str(binding.get("file_sha256") or ""):
        raise RuntimeError("physical receipt file digest does not match stage admission")
    if physical.get("evidence_sha256") != str(binding.get("evidence_sha256") or ""):
        raise RuntimeError("physical receipt evidence does not match stage admission")
    physical_events = _strict_positive_int(physical.get("physical_event_count"), "physical sample event count")
    if (
        physical_events != sample_events
        or physical.get("stage") != f"physical-{sample_events}"
        or physical.get("sparse_or_extrapolated_run") is not False
    ):
        raise RuntimeError("physical predecessor count/stage/non-sparse contract mismatch")

    storage = physical.get("storage")
    if not isinstance(storage, dict):
        raise RuntimeError("physical sample storage measurements are absent")
    measurements: dict[str, dict[str, int]] = {}
    for component in PHYSICAL_COMPONENTS:
        value = storage.get(component)
        if not isinstance(value, dict):
            raise RuntimeError(f"physical sample storage component is absent: {component}")
        logical = _strict_nonnegative_int(value.get("logical_bytes"), f"{component} logical bytes")
        allocated = _strict_nonnegative_int(value.get("allocated_bytes"), f"{component} allocated bytes")
        files = _strict_positive_int(value.get("files"), f"{component} files")
        measurements[component] = {"logical_bytes": logical, "allocated_bytes": allocated, "files": files}
    allocated_total = sum(value["allocated_bytes"] for value in measurements.values())
    logical_total = sum(value["logical_bytes"] for value in measurements.values())
    if allocated_total <= 0:
        raise RuntimeError("physical sample allocated-byte total must be positive")

    return {
        "event_count": sample_events,
        "stage": f"physical-{sample_events}",
        "stage_lineage_root": lineage_root,
        "stage_admission": {
            "path": str(admission_path.resolve()),
            "file_sha256": admission_file_sha,
            "evidence_sha256": admission["evidence_sha256"],
        },
        "physical_receipt": {
            "bound_path": bound_path_text,
            "observed_path": str(physical_path.resolve()),
            "file_sha256": physical_file_sha,
            "evidence_sha256": physical["evidence_sha256"],
        },
        "storage": measurements,
        "logical_bytes": logical_total,
        "allocated_bytes": allocated_total,
    }


def evaluate(
    *,
    sample: dict[str, Any],
    target_events: int,
    filesystem: dict[str, Any],
    topology: dict[str, Any],
    configurations: dict[str, dict[str, Any]],
    artifacts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    sample_events = _strict_positive_int(sample.get("event_count"), "sample event count")
    sample_allocated = _strict_positive_int(sample.get("allocated_bytes"), "sample allocated bytes")
    if TARGET_PREDECESSOR.get(target_events) != sample_events:
        raise RuntimeError("sample is not the exact predecessor for the target stage")
    ratio = Fraction(sample_allocated, sample_events)
    projected = _ceil(ratio * target_events)
    required_2x = projected * HEADROOM_COPIES
    filesystem_total = _strict_positive_int(filesystem.get("total_bytes"), "filesystem total bytes")
    filesystem_available = _strict_nonnegative_int(filesystem.get("available_bytes"), "filesystem available bytes")
    if filesystem_available > filesystem_total:
        raise RuntimeError("filesystem available bytes exceed total bytes")
    reserve = _ceil(Fraction(filesystem_total * FILESYSTEM_RESERVE_PERCENT, 100))
    total_requirement = required_2x + reserve
    capacity_pass = filesystem_available >= total_requirement
    checks = {
        "admitted_predecessor_is_exact_stage": True,
        "physical_sample_is_non_sparse_and_digest_bound": True,
        "physical_allocated_measurement_is_exact_integer_sum": True,
        "target_is_supported_next_stage": True,
        "artifact_identities_digest_bound": bool(artifacts),
        "topology_identity_digest_bound": bool(topology),
        "configuration_identities_digest_bound": bool(configurations),
        "filesystem_device_and_statvfs_bound": _strict_nonnegative_int(
            filesystem.get("device_id"), "filesystem device id"
        )
        >= 0,
        "two_target_copies_plus_20_percent_filesystem_reserve_fit": capacity_pass,
        "projection_does_not_claim_physical_target_completion": True,
        "production_authority_false": True,
        "memory_grants_authority_false": True,
    }
    blockers = sorted(name for name, passed in checks.items() if passed is not True)
    result: dict[str, Any] = {
        "protocol": PROTOCOL,
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "status": "PASS" if not blockers else "FAIL",
        "target": {
            "event_count": target_events,
            "stage": f"physical-{target_events}",
            "expected_predecessor_event_count": TARGET_PREDECESSOR[target_events],
        },
        "source_sample": sample,
        "bindings": {
            "artifacts": artifacts,
            "topology": topology,
            "configurations": configurations,
        },
        "filesystem": filesystem,
        "capacity_projection": {
            "allocated_bytes_per_event": _ratio_json(ratio),
            "rounding": "ceil_exact_fraction",
            "projected_target_allocated_bytes": projected,
            "headroom_copies": HEADROOM_COPIES,
            "required_two_copy_allocated_bytes": required_2x,
            "filesystem_reserve_percent": FILESYSTEM_RESERVE_PERCENT,
            "filesystem_reserve_bytes": reserve,
            "required_two_copy_plus_reserve_bytes": total_requirement,
            "filesystem_available_bytes": filesystem_available,
            "available_minus_requirement_bytes": filesystem_available - total_requirement,
        },
        "checks": checks,
        "blockers": blockers,
        "projection_only": True,
        "physical_target_completed": False,
        "sparse_or_extrapolated_pass": False,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    result["evidence_sha256"] = sha256_bytes(canonical_json(result))
    return result


def run(args: argparse.Namespace) -> dict[str, Any]:
    target_events = _strict_positive_int(args.target_events, "target events")
    sample = admitted_sample(args.stage_admission, args.physical_receipt, target_events)
    artifacts = artifact_identities(args.artifact)
    topology = topology_identity(args.topology)
    configurations = configuration_identities(args.config)
    filesystem = planned_target_filesystem_identity(
        args.target_root,
        target_events=target_events,
        expected_lineage_root=str(sample["stage_lineage_root"]),
        route_id=str(configurations["stage_profile"]["route_id"]),
    )
    try:
        args.receipt_root.resolve().relative_to(args.target_root.resolve())
    except ValueError:
        pass
    else:
        raise RuntimeError("preflight receipt root must remain outside the planned target root")
    result = evaluate(
        sample=sample,
        target_events=target_events,
        filesystem=filesystem,
        topology=topology,
        configurations=configurations,
        artifacts=artifacts,
    )
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    path = args.receipt_root / f"stage-preflight-{target_events}-{stamp}-{result['evidence_sha256'][:16]}.json"
    atomic_json(path, result, mode=0o440)
    return {**result, "receipt_path": str(path)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage-admission", type=Path, required=True)
    parser.add_argument(
        "--physical-receipt",
        type=Path,
        help="optional relocated byte-identical physical receipt; digest must match the admission binding",
    )
    parser.add_argument("--target-events", type=int, choices=sorted(TARGET_PREDECESSOR), required=True)
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--topology", type=Path, required=True)
    parser.add_argument("--config", action="append", default=[], metavar="NAME=PATH", required=True)
    parser.add_argument("--artifact", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument("--receipt-root", type=Path, required=True)
    args = parser.parse_args()
    result = run(args)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
