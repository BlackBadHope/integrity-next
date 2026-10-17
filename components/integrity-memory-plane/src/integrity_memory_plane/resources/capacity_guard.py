#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Content-free capacity firewall for Integrity storage tiers."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import stat
import subprocess
import time
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Callable

from memory_plane_common import atomic_json, exclusive_lock


CAPACITY_PROTOCOL = "integrity-memory-plane.capacity.v2"
STATE_PROTOCOL = "integrity-memory-plane.capacity-monitor-state.v1"
LEVELS = ((95, "emergency"), (90, "critical"), (85, "block-large-artifacts"), (80, "warning"))
BLOCKING_LEVELS = {"block-large-artifacts", "critical", "emergency", "exhausted", "unavailable"}
DEFAULT_MIN_GROWTH_BYTES = 64 * 1024**2
DEFAULT_WARNING_ETA_SECONDS = 24 * 3600
DEFAULT_CRITICAL_ETA_SECONDS = 2 * 3600
DEFAULT_STALE_SECONDS = 15 * 60
DEFAULT_PERSISTENT_INTERVALS = 3
MAX_HEALTH_BODY_BYTES = 64 * 1024
MAX_PSEUDOFILE_BYTES = 16 * 1024
MAX_CODEX_SESSIONS_PATHS = 32
PSI_WARNING_PERCENT = 20.0
PSI_CRITICAL_PERCENT = 50.0
RUNTIME_MONITORING_PROTOCOL = "integrity-memory-plane.runtime-monitoring.v1"
MCP_PROCESS_MARKERS = (
    b"guardian-memory-synapse-mcp",
    b"integrity_guardian.memory_synapse_mcp",
    b"/run-mcp",
)
BROKER_PROCESS_MARKERS = (
    b"integrity-client-turn-broker.py",
    b"integrity-client-turn-broker",
)


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def absolute_config_path(value: str, label: str) -> Path:
    if not value:
        raise ValueError(f"{label} must not be empty")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    return Path(os.path.normpath(path))


def validate_codex_sessions_paths(values: Sequence[str], label: str) -> list[Path]:
    if not values:
        raise ValueError(f"{label} must define at least one path")
    if len(values) > MAX_CODEX_SESSIONS_PATHS:
        raise ValueError(f"{label} exceeds the {MAX_CODEX_SESSIONS_PATHS}-path limit")
    paths: list[Path] = []
    seen: set[Path] = set()
    for index, value in enumerate(values, start=1):
        path = absolute_config_path(value, f"{label}[{index}]")
        if path not in seen:
            seen.add(path)
            paths.append(path)
    return paths


def resolve_codex_sessions_paths(
    cli_values: Sequence[str] | None,
    environ: Mapping[str, str] | None = None,
) -> list[Path]:
    if cli_values is not None:
        return validate_codex_sessions_paths(cli_values, "--codex-sessions-path")

    environment = os.environ if environ is None else environ
    plural = environment.get("INTEGRITY_CODEX_SESSIONS_PATHS")
    singular = environment.get("INTEGRITY_CODEX_SESSIONS_PATH")
    if plural is not None and singular is not None:
        raise ValueError(
            "INTEGRITY_CODEX_SESSIONS_PATHS and INTEGRITY_CODEX_SESSIONS_PATH "
            "must not both be set"
        )
    if plural is not None:
        return validate_codex_sessions_paths(
            plural.split(os.pathsep), "INTEGRITY_CODEX_SESSIONS_PATHS"
        )
    if singular is not None:
        return validate_codex_sessions_paths(
            [singular], "INTEGRITY_CODEX_SESSIONS_PATH"
        )
    raise ValueError(
        "Codex sessions paths are required via --codex-sessions-path, "
        "INTEGRITY_CODEX_SESSIONS_PATHS, or INTEGRITY_CODEX_SESSIONS_PATH"
    )


def codex_sessions_sample_key(path: Path, total_paths: int) -> str:
    if total_paths == 1:
        return "codex-sessions"
    path_digest = hashlib.sha256(os.fsencode(path)).hexdigest()[:16]
    return f"codex-sessions:{path_digest}"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", action="append", default=["/", _integrity_value('path_0dcb1df88675')])
    parser.add_argument("--min-free-gib", type=float, default=10.0)
    parser.add_argument("--status", type=Path, default=Path(_integrity_value('path_e93e1c8def2a')))
    parser.add_argument("--marker", type=Path, default=Path("/run/integrity-memory-plane/capacity-block-large-artifacts"))
    parser.add_argument("--growth-state", type=Path, default=Path(_integrity_value('path_aaa8eeb896a5')))
    parser.add_argument("--state-lock", type=Path, default=Path("/run/integrity-memory-plane/capacity-monitor.lock"))
    parser.add_argument(
        "--codex-sessions-path",
        action="append",
        dest="codex_sessions_paths",
        default=None,
        help=(
            "absolute Codex sessions root; repeat for each profile (overrides the "
            "environment)"
        ),
    )
    parser.add_argument("--docker-volumes-path", type=Path, default=Path(_integrity_value('path_fde3788c3a5e')))
    parser.add_argument("--architecture-replay-path", type=Path, default=Path(_integrity_value('path_6ded83bac4a7')))
    parser.add_argument("--psi-io-path", type=Path, default=Path("/proc/pressure/io"))
    parser.add_argument("--shm-path", type=Path, default=Path("/dev/shm"))
    parser.add_argument("--proc-path", type=Path, default=Path("/proc"))
    parser.add_argument("--runtime-max-processes", type=int, default=32_768)
    parser.add_argument("--runtime-timeout-seconds", type=float, default=3.0)
    parser.add_argument("--growth-min-delta-mib", type=float, default=64.0)
    parser.add_argument("--growth-stale-seconds", type=float, default=DEFAULT_STALE_SECONDS)
    parser.add_argument("--growth-warning-hours", type=float, default=24.0)
    parser.add_argument("--growth-critical-hours", type=float, default=2.0)
    parser.add_argument("--growth-persistent-intervals", type=int, default=DEFAULT_PERSISTENT_INTERVALS)
    parser.add_argument("--directory-max-entries", type=int, default=200_000)
    parser.add_argument("--directory-timeout-seconds", type=float, default=10.0)
    parser.add_argument("--action-log-health-url", default=_integrity_value('endpoint_d70a81d63709'))
    parser.add_argument("--action-log-health-timeout", type=float, default=3.0)
    parser.add_argument("--hypervisor-host", default="")
    parser.add_argument("--ssh-config", type=Path, default=Path(_integrity_value('path_efcbe20e087d')))
    parser.add_argument("--ssh-identity", type=Path, default=None)
    parser.add_argument("--ssh-known-hosts", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        args.codex_sessions_paths = resolve_codex_sessions_paths(
            args.codex_sessions_paths
        )
    except ValueError as exc:
        parser.error(str(exc))
    return args


def classify_usage(label: str, total: int, free: int, min_free_gib: float, *, device_id: int | None = None) -> dict[str, Any]:
    if total <= 0 or free < 0 or free > total:
        return {"path": label, "total_bytes": total, "free_bytes": free, "available_percent": None, "used_percent": None, "level": "unavailable", "device_id": device_id}
    used_percent = 100.0 * (total - free) / total
    if free == 0:
        level = "exhausted"
    else:
        level = "ok"
        for threshold, candidate in LEVELS:
            if used_percent >= threshold:
                level = candidate
                break
        if free < min_free_gib * 1024**3 and level in {"ok", "warning"}:
            level = "block-large-artifacts"
    return {"path": label, "total_bytes": total, "free_bytes": free, "available_percent": round(100.0 * free / total, 3), "used_percent": round(used_percent, 3), "level": level, "device_id": device_id}


def usage(path: str, min_free_gib: float) -> dict[str, Any]:
    stats = os.statvfs(path)
    return classify_usage(path, stats.f_blocks * stats.f_frsize, stats.f_bavail * stats.f_frsize, min_free_gib, device_id=os.stat(path).st_dev)


def classify_inode_usage(label: str, total: int, free: int, *, device_id: int | None = None) -> dict[str, Any]:
    if total <= 0 or free < 0 or free > total:
        return {
            "path": label,
            "total_inodes": total,
            "free_inodes": free,
            "used_percent": None,
            "level": "unavailable",
            "device_id": device_id,
        }
    used_percent = 100.0 * (total - free) / total
    if free == 0:
        level = "exhausted"
    else:
        level = "ok"
        for threshold, candidate in LEVELS:
            if used_percent >= threshold:
                level = candidate
                break
    return {
        "path": label,
        "total_inodes": total,
        "free_inodes": free,
        "used_percent": round(used_percent, 3),
        "level": level,
        "device_id": device_id,
    }


def inode_usage(path: str) -> dict[str, Any]:
    stats = os.statvfs(path)
    return classify_inode_usage(path, stats.f_files, stats.f_favail, device_id=os.stat(path).st_dev)


def read_bounded_bytes(path: Path, maximum_bytes: int = MAX_PSEUDOFILE_BYTES) -> bytes:
    with path.open("rb") as handle:
        payload = handle.read(maximum_bytes + 1)
    if len(payload) > maximum_bytes:
        raise RuntimeError("bounded read limit exceeded")
    return payload


def parse_psi_io(payload: bytes) -> dict[str, Any]:
    rows: dict[str, dict[str, Any]] = {}
    try:
        text = payload.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("PSI payload is not ASCII") from exc
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0] not in {"some", "full"}:
            continue
        label = fields[0]
        if label in rows:
            raise ValueError("duplicate PSI row")
        values: dict[str, str] = {}
        for field in fields[1:]:
            key, separator, value = field.partition("=")
            if not separator or key in values:
                raise ValueError("invalid PSI field")
            values[key] = value
        if set(values) != {"avg10", "avg60", "avg300", "total"}:
            raise ValueError("incomplete PSI row")
        averages = [float(values[name]) for name in ("avg10", "avg60", "avg300")]
        total = int(values["total"])
        if total < 0 or any(not math.isfinite(value) or value < 0 or value > 100 for value in averages):
            raise ValueError("invalid PSI value")
        rows[label] = {
            "avg10_percent": round(averages[0], 3),
            "avg60_percent": round(averages[1], 3),
            "avg300_percent": round(averages[2], 3),
            "total_stall_microseconds": total,
        }
    if set(rows) != {"some", "full"}:
        raise ValueError("required PSI rows are missing")
    peak = max(float(rows["some"]["avg10_percent"]), float(rows["full"]["avg10_percent"]))
    level = "critical" if peak >= PSI_CRITICAL_PERCENT else "warning" if peak >= PSI_WARNING_PERCENT else "ok"
    return {
        "sample_status": "ok",
        "level": level,
        "peak_avg10_percent": round(peak, 3),
        "warning_percent": PSI_WARNING_PERCENT,
        "critical_percent": PSI_CRITICAL_PERCENT,
        "some": rows["some"],
        "full": rows["full"],
    }


def collect_psi_io(path: Path) -> dict[str, Any]:
    return {"path": str(path), **parse_psi_io(read_bounded_bytes(path))}


def collect_inode_usage(paths: list[str]) -> dict[str, Any]:
    rows = []
    for path in paths:
        try:
            rows.append(inode_usage(path))
        except OSError as exc:
            rows.append({
                "path": path,
                "total_inodes": None,
                "free_inodes": None,
                "used_percent": None,
                "level": "unavailable",
                "error_class": type(exc).__name__,
            })
    unavailable = sum(row["level"] == "unavailable" for row in rows)
    sample_status = "ok" if unavailable == 0 else "unavailable" if unavailable == len(rows) else "partial"
    return {"sample_status": sample_status, "filesystems": rows}


def collect_shm_usage(path: Path) -> dict[str, Any]:
    return {"sample_status": "ok", **usage(str(path), 0)}


def classify_remote(label: str, total: int, free: int, min_free_gib: float) -> dict[str, Any]:
    row = classify_usage(label, total, free, min_free_gib)
    row.pop("device_id", None)
    return row


def remote_usage(args: argparse.Namespace) -> tuple[list[dict[str, Any]], str]:
    if not args.hypervisor_host:
        return [], "not-configured"
    command = [_integrity_value('command_7f5a55cf3f88'), "-F", str(args.ssh_config), "-n", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"]
    if args.ssh_identity is not None:
        command.extend(["-i", str(args.ssh_identity)])
    if args.ssh_known_hosts is not None:
        command.extend(["-o", f"UserKnownHostsFile={args.ssh_known_hosts}", "-o", "StrictHostKeyChecking=yes"])
    command.extend([args.hypervisor_host, "df -B1 --output=size,avail,target / /data | tail -n +2"])
    try:
        completed = subprocess.run(command, check=True, timeout=15, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        rows = []
        for line in completed.stdout.splitlines():
            fields = line.split()
            if len(fields) != 3:
                continue
            total, free, target = int(fields[0]), int(fields[1]), fields[2]
            rows.append(classify_remote(f"hypervisor:{target}", total, free, args.min_free_gib))
        if len(rows) != 2:
            raise RuntimeError("expected Hypervisor / and /data capacity rows")
        return rows, "ok"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        return [{"path": "hypervisor:unknown", "total_bytes": None, "free_bytes": None, "available_percent": None, "used_percent": None, "level": "block-large-artifacts", "error_class": type(exc).__name__}], "unavailable"


def filesystem_growth_sample(row: dict[str, Any]) -> dict[str, Any]:
    if row.get("level") == "unavailable":
        return {
            "kind": "filesystem", "path": str(row["path"]), "metric": "used_bytes",
            "sample_status": "unavailable", "error_class": "InvalidCapacitySample",
        }
    return {
        "kind": "filesystem", "path": str(row["path"]), "metric": "used_bytes", "sample_status": "ok",
        "observed_bytes": int(row["total_bytes"]) - int(row["free_bytes"]),
        "available_bytes": int(row["free_bytes"]), "filesystem_total_bytes": int(row["total_bytes"]),
        "device_id": int(row["device_id"]),
    }


def measure_directory(name: str, path: Path, *, max_entries: int, timeout_seconds: float, monotonic: Callable[[], float] = time.monotonic) -> dict[str, Any]:
    base = {"kind": "directory", "name": name, "path": str(path), "metric": "allocated_bytes"}
    try:
        root = path.stat()
        if not stat.S_ISDIR(root.st_mode):
            raise NotADirectoryError(path)
        filesystem = os.statvfs(path)
        deadline = monotonic() + timeout_seconds
        stack, seen = [path], set()
        allocated = apparent = files = entries_seen = largest = 0
        while stack:
            if monotonic() > deadline:
                raise TimeoutError("directory scan deadline exceeded")
            with os.scandir(stack.pop()) as entries:
                for entry in entries:
                    if monotonic() > deadline:
                        raise TimeoutError("directory scan deadline exceeded")
                    entries_seen += 1
                    if entries_seen > max_entries:
                        raise RuntimeError("directory scan entry limit exceeded")
                    metadata = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(metadata.st_mode):
                        if metadata.st_dev == root.st_dev:
                            stack.append(Path(entry.path))
                    elif stat.S_ISREG(metadata.st_mode) and metadata.st_dev == root.st_dev:
                        inode = (metadata.st_dev, metadata.st_ino)
                        if inode in seen:
                            continue
                        seen.add(inode)
                        files += 1
                        apparent += metadata.st_size
                        allocated += metadata.st_blocks * 512
                        largest = max(largest, metadata.st_size)
        return {
            **base, "sample_status": "ok", "observed_bytes": allocated, "apparent_bytes": apparent,
            "file_count": files, "entry_count": entries_seen, "largest_file_bytes": largest,
            "available_bytes": filesystem.f_bavail * filesystem.f_frsize,
            "filesystem_total_bytes": filesystem.f_blocks * filesystem.f_frsize, "device_id": root.st_dev,
        }
    except (OSError, RuntimeError, TimeoutError) as exc:
        return {**base, "sample_status": "unavailable", "error_class": type(exc).__name__}


def measure_replay_store(
    path: Path,
    *,
    max_entries: int,
    timeout_seconds: float,
    observed_epoch: float,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    base = {"path": str(path), "metric": "allocated_bytes"}
    try:
        root = path.stat()
        if not stat.S_ISDIR(root.st_mode):
            raise NotADirectoryError(path)
        deadline = monotonic() + timeout_seconds
        stack = [path]
        entries_seen = record_count = allocated = apparent = 0
        oldest_modified_epoch: float | None = None
        while stack:
            if monotonic() > deadline:
                raise TimeoutError("architecture replay scan deadline exceeded")
            with os.scandir(stack.pop()) as entries:
                for entry in entries:
                    entries_seen += 1
                    if entries_seen > max_entries:
                        raise RuntimeError("architecture replay entry limit exceeded")
                    if monotonic() > deadline:
                        raise TimeoutError("architecture replay scan deadline exceeded")
                    metadata = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(metadata.st_mode):
                        if metadata.st_dev == root.st_dev:
                            stack.append(Path(entry.path))
                    elif stat.S_ISREG(metadata.st_mode) and metadata.st_dev == root.st_dev:
                        record_count += 1
                        apparent += metadata.st_size
                        allocated += metadata.st_blocks * 512
                        oldest_modified_epoch = (
                            metadata.st_mtime
                            if oldest_modified_epoch is None
                            else min(oldest_modified_epoch, metadata.st_mtime)
                        )
        oldest_age = None if oldest_modified_epoch is None else round(max(0.0, observed_epoch - oldest_modified_epoch), 3)
        return {
            **base,
            "sample_status": "ok",
            "observed_bytes": allocated,
            "apparent_bytes": apparent,
            "record_count": record_count,
            "entry_count": entries_seen,
            "oldest_age_seconds": oldest_age,
        }
    except (OSError, RuntimeError, TimeoutError) as exc:
        return {**base, "sample_status": "unavailable", "error_class": type(exc).__name__}


def parse_process_stat(payload: bytes) -> tuple[str, int]:
    try:
        text = payload.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("process stat is not ASCII") from exc
    command_end = text.rfind(")")
    if command_end < 2:
        raise ValueError("invalid process stat")
    fields = text[command_end + 1 :].split()
    if len(fields) < 20 or len(fields[0]) != 1:
        raise ValueError("incomplete process stat")
    start_ticks = int(fields[19])
    if start_ticks < 0:
        raise ValueError("negative process start time")
    return fields[0], start_ticks


def _age_summary(count: int, oldest_age: float | None) -> dict[str, Any]:
    return {
        "count": count,
        "oldest_age_seconds": None if oldest_age is None else round(max(0.0, oldest_age), 3),
    }


def collect_process_health(
    proc_root: Path,
    *,
    max_processes: int,
    timeout_seconds: float,
    monotonic: Callable[[], float] = time.monotonic,
    clock_ticks: int | None = None,
) -> dict[str, Any]:
    uptime_payload = read_bounded_bytes(proc_root / "uptime")
    try:
        uptime_seconds = float(uptime_payload.decode("ascii", errors="strict").split()[0])
    except (UnicodeDecodeError, ValueError, IndexError) as exc:
        raise ValueError("invalid proc uptime") from exc
    ticks_per_second = clock_ticks if clock_ticks is not None else int(os.sysconf("SC_CLK_TCK"))
    if not math.isfinite(uptime_seconds) or uptime_seconds < 0 or ticks_per_second <= 0:
        raise ValueError("invalid process clock")

    deadline = monotonic() + timeout_seconds
    scanned = disappeared = unreadable = 0
    mcp_count = broker_count = d_task_count = 0
    oldest_mcp: float | None = None
    oldest_broker: float | None = None
    oldest_d_task: float | None = None
    with os.scandir(proc_root) as entries:
        for entry in entries:
            if not entry.name.isdecimal():
                continue
            if scanned >= max_processes:
                raise RuntimeError("process scan entry limit exceeded")
            if monotonic() > deadline:
                raise TimeoutError("process scan deadline exceeded")
            scanned += 1
            process_path = proc_root / entry.name
            try:
                state, start_ticks = parse_process_stat(read_bounded_bytes(process_path / "stat"))
            except FileNotFoundError:
                disappeared += 1
                continue
            except (OSError, ValueError, RuntimeError):
                unreadable += 1
                continue
            age = max(0.0, uptime_seconds - start_ticks / ticks_per_second)
            if state == "D":
                d_task_count += 1
                oldest_d_task = age if oldest_d_task is None else max(oldest_d_task, age)
            try:
                command = read_bounded_bytes(process_path / "cmdline").lower()
            except FileNotFoundError:
                disappeared += 1
                continue
            except (OSError, RuntimeError):
                unreadable += 1
                continue
            if any(marker in command for marker in MCP_PROCESS_MARKERS):
                mcp_count += 1
                oldest_mcp = age if oldest_mcp is None else max(oldest_mcp, age)
            if any(marker in command for marker in BROKER_PROCESS_MARKERS):
                broker_count += 1
                oldest_broker = age if oldest_broker is None else max(oldest_broker, age)
    sample_status = "partial" if unreadable else "ok"
    return {
        "sample_status": sample_status,
        "scanned_processes": scanned,
        "disappeared_processes": disappeared,
        "unreadable_processes": unreadable,
        "mcp": _age_summary(mcp_count, oldest_mcp),
        "broker": _age_summary(broker_count, oldest_broker),
        "d_tasks": _age_summary(d_task_count, oldest_d_task),
    }


def observe_collector(
    operation: Callable[[], dict[str, Any]],
    *,
    monotonic: Callable[[], float] = time.monotonic,
) -> tuple[dict[str, Any], dict[str, Any]]:
    started = monotonic()
    try:
        observation = operation()
        if not isinstance(observation, dict):
            raise TypeError("collector result is not an object")
    except Exception as exc:
        observation = {
            "sample_status": "unavailable",
            "reason": "collector-error",
            "error_class": type(exc).__name__,
        }
    duration_ms = round(max(0.0, monotonic() - started) * 1000, 3)
    sample_status = str(observation.get("sample_status", "unavailable"))
    ready = sample_status == "ok"
    health = {
        "status": "ready" if ready else "degraded",
        "sample_status": sample_status,
        "duration_ms": duration_ms,
    }
    if not ready:
        health["reason"] = str(observation.get("reason", "incomplete-sample"))
        if "error_class" in observation:
            health["error_class"] = str(observation["error_class"])
    return observation, health


def collect_runtime_monitoring(
    args: argparse.Namespace,
    paths: list[str],
    observed: dt.datetime,
    *,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    started = monotonic()
    operations: dict[str, Callable[[], dict[str, Any]]] = {
        "psi_io": lambda: collect_psi_io(args.psi_io_path),
        "inodes": lambda: collect_inode_usage(paths),
        "dev_shm": lambda: collect_shm_usage(args.shm_path),
        "architecture_replay": lambda: measure_replay_store(
            args.architecture_replay_path,
            max_entries=args.directory_max_entries,
            timeout_seconds=args.directory_timeout_seconds,
            observed_epoch=observed.timestamp(),
            monotonic=monotonic,
        ),
        "processes": lambda: collect_process_health(
            args.proc_path,
            max_processes=args.runtime_max_processes,
            timeout_seconds=args.runtime_timeout_seconds,
            monotonic=monotonic,
        ),
    }
    observations: dict[str, dict[str, Any]] = {}
    collector_health: dict[str, dict[str, Any]] = {}
    reasons: list[str] = []
    for name, operation in operations.items():
        observation, health = observe_collector(operation, monotonic=monotonic)
        observations[name] = observation
        collector_health[name] = health
        if health["status"] != "ready":
            reasons.append(f"monitoring:collector:{name}:{health['sample_status']}")

    psi_level = observations["psi_io"].get("level")
    if psi_level in {"warning", "critical"}:
        reasons.append(f"monitoring:psi-io:{psi_level}")
    for row in observations["inodes"].get("filesystems", []):
        if row.get("level") in {"warning", "block-large-artifacts", "critical", "emergency", "exhausted"}:
            reasons.append(f"monitoring:inodes:{row.get('path')}:{row.get('level')}")
    shm_level = observations["dev_shm"].get("level")
    if shm_level in {"warning", "block-large-artifacts", "critical", "emergency", "exhausted"}:
        reasons.append(f"monitoring:dev-shm:{shm_level}")
    d_task_count = observations["processes"].get("d_tasks", {}).get("count")
    if isinstance(d_task_count, int) and d_task_count > 0:
        reasons.append("monitoring:d-tasks:present")

    reasons = sorted(set(reasons))
    return {
        "protocol": RUNTIME_MONITORING_PROTOCOL,
        "status": "degraded" if reasons else "ready",
        "timer_overlap": False,
        "duration_ms": round(max(0.0, monotonic() - started) * 1000, 3),
        "collector_health": collector_health,
        "observations": observations,
        "reasons": reasons,
    }


def parse_utc(value: Any) -> dt.datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp is not a string")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp is naive")
    return parsed.astimezone(dt.UTC)


def load_monitor_state(path: Path) -> tuple[dict[str, Any], str]:
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, "first-sample"
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}, "invalid-state"
    if not isinstance(state, dict) or state.get("protocol") != STATE_PROTOCOL or not isinstance(state.get("sources"), dict):
        return {}, "invalid-state"
    if not all(isinstance(name, str) and isinstance(source, dict) for name, source in state["sources"].items()):
        return {}, "invalid-state"
    return state, "ok"


def clock_context(previous_state: dict[str, Any], state_reason: str, observed: dt.datetime, stale_seconds: float) -> tuple[float | None, str]:
    if state_reason != "ok":
        return None, state_reason
    try:
        previous = parse_utc(previous_state.get("observed_utc"))
    except (TypeError, ValueError):
        return None, "invalid-state"
    elapsed = (observed - previous).total_seconds()
    if elapsed <= 0:
        return None, "non-monotonic-clock"
    if elapsed > stale_seconds:
        return None, "stale-history"
    return elapsed, "ok"


def classify_growth(current: dict[str, Any], previous: dict[str, Any] | None, *, elapsed_seconds: float | None, reset_reason: str, minimum_delta_bytes: int = DEFAULT_MIN_GROWTH_BYTES, warning_eta_seconds: int = DEFAULT_WARNING_ETA_SECONDS, critical_eta_seconds: int = DEFAULT_CRITICAL_ETA_SECONDS, persistent_intervals: int = DEFAULT_PERSISTENT_INTERVALS) -> dict[str, Any]:
    result = {
        **current, "trend": "insufficient-history", "severity": "none", "delta_bytes": None,
        "elapsed_seconds": elapsed_seconds, "rate_bytes_per_second": None, "eta_seconds": None,
        "qualifying_growth": False, "consecutive_growth_intervals": 0, "persistent_growth": False,
        "history_reason": reset_reason,
    }
    if current.get("sample_status") != "ok":
        result.update(trend="unavailable", severity="unknown", history_reason="current-unavailable")
        return result
    available, total = int(current["available_bytes"]), int(current["filesystem_total_bytes"])
    if total > 0 and available == 0:
        result.update(trend="exhausted", severity="exhausted", history_reason="current-exhausted")
        return result
    if reset_reason != "ok" or elapsed_seconds is None or previous is None:
        return result
    if previous.get("sample_status") != "ok":
        result["history_reason"] = "previous-unavailable"
        return result
    if previous.get("path") != current.get("path"):
        result["history_reason"] = "source-changed"
        return result
    if previous.get("device_id") != current.get("device_id"):
        result["history_reason"] = "device-changed"
        return result
    if previous.get("filesystem_total_bytes") != current.get("filesystem_total_bytes"):
        result["history_reason"] = "filesystem-resized"
        return result
    try:
        delta = int(current["observed_bytes"]) - int(previous["observed_bytes"])
    except (KeyError, TypeError, ValueError):
        result["history_reason"] = "invalid-previous-sample"
        return result
    result.update(delta_bytes=delta, history_reason="comparable", rate_bytes_per_second=round(delta / elapsed_seconds, 3))
    if delta < minimum_delta_bytes:
        result["trend"] = "stable"
        return result
    previous_streak = 0
    if previous.get("qualifying_growth") is True:
        try:
            previous_streak = max(0, int(previous.get("consecutive_growth_intervals", 0)))
        except (TypeError, ValueError):
            previous_streak = 0
    streak = previous_streak + 1
    eta_seconds = math.ceil(available * elapsed_seconds / delta)
    severity = "critical" if eta_seconds <= critical_eta_seconds else "warning" if eta_seconds <= warning_eta_seconds else "notice"
    persistent = streak >= persistent_intervals
    result.update(trend="persistent-growth" if persistent else "growing", severity=severity, eta_seconds=eta_seconds, qualifying_growth=True, consecutive_growth_intervals=streak, persistent_growth=persistent)
    return result


def summarize_growth(sources: dict[str, dict[str, Any]], reset_reason: str, *, minimum_delta_bytes: int, warning_eta_seconds: int, critical_eta_seconds: int, persistent_intervals: int) -> dict[str, Any]:
    order = {"unknown": -1, "none": 0, "notice": 1, "warning": 2, "critical": 3, "exhausted": 4}
    severities = [str(source.get("severity", "unknown")) for source in sources.values()]
    maximum = max(severities, key=lambda item: order.get(item, -1), default="unknown")
    persistent = sorted(name for name, source in sources.items() if source.get("persistent_growth") is True)
    unavailable = sorted(name for name, source in sources.items() if source.get("trend") == "unavailable")
    return {
        "state_protocol": STATE_PROTOCOL, "state_reset_reason": reset_reason,
        "minimum_delta_bytes": minimum_delta_bytes, "warning_eta_seconds": warning_eta_seconds,
        "critical_eta_seconds": critical_eta_seconds, "persistent_intervals": persistent_intervals,
        "sources": sources, "maximum_severity": maximum, "suspected_leak": bool(persistent),
        "persistent_sources": persistent, "unavailable_sources": unavailable,
    }


def validate_action_log_health(payload: Any, previous_events: int | None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {"status": "invalid", "reason": "payload-not-object"}
    valid = payload.get("ok") is True and payload.get("service") == "codex-action-log" and payload.get("append_only") is True and payload.get("update_enabled") is False and payload.get("delete_enabled") is False
    events = payload.get("events")
    if not valid or isinstance(events, bool) or not isinstance(events, int) or events < 0:
        return {"status": "invalid", "reason": "contract-mismatch"}
    if previous_events is not None and events < previous_events:
        return {"status": "invalid", "reason": "event-count-regression", "events": events, "previous_events": previous_events}
    return {"status": "ready", "reason": "contract-ok", "events": events}


def is_loopback_health_url(url: str) -> bool:
    parsed = urllib.parse.urlsplit(url)
    return (
        parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
        and parsed.username is None
        and parsed.password is None
        and parsed.path == "/api/health"
        and not parsed.query
        and not parsed.fragment
    )


def probe_action_log(url: str, timeout_seconds: float, previous_events: int | None, *, opener: Callable[..., Any] | None = None, monotonic: Callable[[], float] = time.monotonic) -> dict[str, Any]:
    if not is_loopback_health_url(url):
        return {"status": "invalid", "reason": "non-loopback-health-target"}
    started = monotonic()
    try:
        request = urllib.request.Request(url, headers={"Accept": "application/json"})
        open_url = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), RejectRedirects()
        ).open
        with open_url(request, timeout=timeout_seconds) as response:
            if not is_loopback_health_url(response.geturl()):
                return {"status": "invalid", "reason": "redirect-target-rejected"}
            if int(response.status) != 200:
                return {"status": "unavailable", "reason": "http-status", "http_status": int(response.status)}
            body = response.read(MAX_HEALTH_BODY_BYTES + 1)
        if len(body) > MAX_HEALTH_BODY_BYTES:
            return {"status": "invalid", "reason": "response-too-large"}
        checked = validate_action_log_health(json.loads(body), previous_events)
        checked["latency_ms"] = round((monotonic() - started) * 1000, 3)
        return checked
    except (OSError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return {"status": "unavailable", "reason": "probe-failed", "error_class": type(exc).__name__, "latency_ms": round((monotonic() - started) * 1000, 3)}


def persist_monitor_result(args: argparse.Namespace, status: dict[str, Any], next_state: dict[str, Any], blocked: bool) -> None:
    args.marker.parent.mkdir(parents=True, exist_ok=True)
    if blocked:
        atomic_json(args.marker, status)
    atomic_json(args.growth_state, next_state)
    atomic_json(args.status, status)
    if not blocked:
        args.marker.unlink(missing_ok=True)


def run_guard(args: argparse.Namespace) -> int:
    observed = dt.datetime.now(dt.UTC)
    paths = list(dict.fromkeys(args.path))
    with exclusive_lock(args.state_lock):
        previous_state, state_reason = load_monitor_state(args.growth_state)
        elapsed, reset_reason = clock_context(previous_state, state_reason, observed, args.growth_stale_seconds)

        local_rows = [usage(path, args.min_free_gib) for path in paths]
        remote_rows, remote_status = remote_usage(args)
        rows = [*local_rows, *remote_rows]
        samples: dict[str, dict[str, Any]] = {
            f"filesystem:{row['path']}": filesystem_growth_sample(row) for row in local_rows
        }
        for path in args.codex_sessions_paths:
            sample_key = codex_sessions_sample_key(
                path,
                len(args.codex_sessions_paths),
            )
            samples[sample_key] = measure_directory(
                sample_key,
                path,
                max_entries=args.directory_max_entries,
                timeout_seconds=args.directory_timeout_seconds,
            )
        samples["docker-volumes"] = measure_directory(
            "docker-volumes", args.docker_volumes_path,
            max_entries=args.directory_max_entries, timeout_seconds=args.directory_timeout_seconds,
        )
        previous_sources = previous_state.get("sources", {}) if state_reason == "ok" else {}
        minimum_delta = int(args.growth_min_delta_mib * 1024**2)
        warning_eta = int(args.growth_warning_hours * 3600)
        critical_eta = int(args.growth_critical_hours * 3600)
        growth_sources = {
            name: classify_growth(
                sample,
                previous_sources.get(name) if isinstance(previous_sources, dict) else None,
                elapsed_seconds=elapsed,
                reset_reason=reset_reason if name in previous_sources else "first-sample",
                minimum_delta_bytes=minimum_delta,
                warning_eta_seconds=warning_eta,
                critical_eta_seconds=critical_eta,
                persistent_intervals=args.growth_persistent_intervals,
            )
            for name, sample in samples.items()
        }
        growth = summarize_growth(
            growth_sources, reset_reason,
            minimum_delta_bytes=minimum_delta, warning_eta_seconds=warning_eta,
            critical_eta_seconds=critical_eta, persistent_intervals=args.growth_persistent_intervals,
        )

        previous_events = previous_state.get("last_good_action_log_events")
        if isinstance(previous_events, bool) or not isinstance(previous_events, int) or previous_events < 0:
            previous_events = None
        action_health = probe_action_log(args.action_log_health_url, args.action_log_health_timeout, previous_events)
        last_good_events = action_health.get("events") if action_health.get("status") == "ready" else previous_events
        runtime_monitoring = collect_runtime_monitoring(args, paths, observed)

        capacity_blocking = [row for row in rows if row["level"] in BLOCKING_LEVELS]
        growth_blocking = [name for name, source in growth_sources.items() if source.get("severity") in {"critical", "exhausted"}]
        reasons = [f"capacity:{row['path']}:{row['level']}" for row in capacity_blocking]
        reasons.extend(f"growth:{name}:{growth_sources[name]['severity']}" for name in growth_blocking)
        reasons.extend(runtime_monitoring["reasons"])
        if action_health.get("status") != "ready":
            reasons.append(f"action-log:{action_health.get('status')}:{action_health.get('reason')}")
        for name, source in growth_sources.items():
            if source.get("persistent_growth") is True:
                reasons.append(f"growth:{name}:persistent")
            elif source.get("severity") == "warning":
                reasons.append(f"growth:{name}:warning")
            elif source.get("trend") == "unavailable":
                reasons.append(f"growth:{name}:unavailable")
        blocked = bool(capacity_blocking or growth_blocking)
        degraded = bool(reasons) and not blocked
        overall_status = "blocked" if blocked else "degraded" if degraded else "pass"
        status = {
            "protocol": CAPACITY_PROTOCOL,
            "observed_utc": observed.isoformat(),
            "thresholds_percent": {"warning": 80, "block_large_artifacts": 85, "critical": 90, "emergency": 95, "exhausted_available_bytes": 0},
            "minimum_free_gib": args.min_free_gib,
            "filesystems": rows,
            "hypervisor_probe": remote_status,
            "growth": growth,
            "action_log_health": action_health,
            "runtime_monitoring": runtime_monitoring,
            "reasons": sorted(set(reasons)),
            "block_large_artifacts": blocked,
            "status": overall_status,
        }
        next_state = {
            "protocol": STATE_PROTOCOL,
            "observed_utc": observed.isoformat(),
            "sources": growth_sources,
            "last_good_action_log_events": last_good_events,
        }
        persist_monitor_result(args, status, next_state, blocked)
    print(json.dumps(status, sort_keys=True))
    if blocked:
        return 20
    if degraded:
        return 10
    return 0


def timer_overlap_status(observed: dt.datetime) -> dict[str, Any]:
    reason = "monitoring:timer-overlap"
    return {
        "protocol": CAPACITY_PROTOCOL,
        "observed_utc": observed.isoformat(),
        "filesystems": [],
        "hypervisor_probe": "not-run",
        "growth": {"status": "not-run", "reason": "timer-overlap"},
        "action_log_health": {"status": "not-run", "reason": "timer-overlap"},
        "runtime_monitoring": {
            "protocol": RUNTIME_MONITORING_PROTOCOL,
            "status": "degraded",
            "timer_overlap": True,
            "duration_ms": 0.0,
            "collector_health": {},
            "observations": {},
            "reasons": [reason],
        },
        "reasons": [reason],
        "block_large_artifacts": False,
        "status": "degraded",
    }


def main() -> int:
    args = parse_args()
    if args.growth_min_delta_mib <= 0 or args.growth_stale_seconds <= 0:
        raise SystemExit("growth thresholds must be positive")
    if args.growth_critical_hours <= 0 or args.growth_warning_hours < args.growth_critical_hours:
        raise SystemExit("growth ETA thresholds are invalid")
    if args.growth_persistent_intervals < 1:
        raise SystemExit("growth persistence must be at least one interval")
    if args.directory_max_entries < 1 or args.directory_timeout_seconds <= 0:
        raise SystemExit("directory scan bounds are invalid")
    if args.runtime_max_processes < 1 or args.runtime_timeout_seconds <= 0:
        raise SystemExit("runtime scan bounds are invalid")
    try:
        return run_guard(args)
    except RuntimeError as exc:
        if not str(exc).startswith("another memory-plane operation holds "):
            raise
        status = timer_overlap_status(dt.datetime.now(dt.UTC))
        print(json.dumps(status, sort_keys=True))
        return 10


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
