#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Safely reconcile the non-authoritative P2 JetStream capacity limit.

The capacity supplement is evidence, not authority.  This tool validates its
canonical encoding and digest, independently re-derives the bus projections,
and permits exactly one change: increasing the existing stream ``max_bytes``
to the value declared by :mod:`p2_nats_bootstrap`.  The server-wide file-store
limit must already have been reconciled out of band and is never changed here.
"""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import asyncio
import copy
import datetime as dt
import fcntl
import json
import os
import re
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import nats

from memory_plane_common import canonical_json, sha256_bytes, sha256_file
import p2_nats_bootstrap as bootstrap
from p2_billion_capacity import TARGET_EVENTS
from p2_capacity_supplement import (
    BUS_TARGET_CAPACITY_ADMISSION_CHECKS,
    CRITICAL_WATERMARK_PERCENT,
    FILESYSTEM_RESERVE_PERCENT,
    HEADROOM_NUMERATOR,
    HIGH_WATERMARK_PERCENT,
    PROTOCOL as CAPACITY_SUPPLEMENT_PROTOCOL,
    REQUIRED_CHECKS as CAPACITY_SUPPLEMENT_CHECKS,
    full_history_bus_contract,
)


PROTOCOL = "integrity-memory-plane.p2-nats-capacity-reconcile.v1.receipt"
INTENT_PROTOCOL = "integrity-memory-plane.p2-nats-capacity-reconcile.v1.intent"
SHA256 = re.compile(r"[0-9a-f]{64}")
CAPACITY_CHECK_NAMES = {
    "stream_2x_target_strictly_below_high_watermark",
    "server_2x_target_strictly_below_high_watermark",
    "filesystem_growth_plus_reserve_strictly_fits",
    "filesystem_2x_target_strictly_below_high_watermark",
}
RECEIPT_CHECK_NAMES = {
    "capacity_supplement_canonical_and_bus_measurement_valid",
    "bootstrap_targets_admit_2x_below_high_watermark",
    "filesystem_growth_plus_reserve_strictly_fits",
    "live_server_max_storage_exact_target",
    "monitor_and_connected_server_identity_match",
    "live_filesystem_capacity_rechecked",
    "stream_contract_valid_except_previous_max_bytes",
    "fsynced_intent_bound_before_update",
    "stream_target_exact_after_update",
    "stream_sequence_message_and_byte_regression_absent",
    "production_authority_false",
    "memory_grants_authority_false",
}
MAX_SUPPLEMENT_AGE_SECONDS = 3600


@dataclass(frozen=True)
class CapacityPlan:
    supplement_path: Path
    supplement_file_sha256: str
    supplement_evidence_sha256: str
    target_events: int
    required_stream_bytes: int
    required_physical_bytes: int
    physical_growth_bytes: int
    server_other_store_bytes: int
    projected_server_storage_bytes: int
    filesystem_total_bytes: int
    filesystem_available_bytes: int
    filesystem_used_bytes: int
    filesystem_reserve_bytes: int
    projected_filesystem_used_bytes: int
    measured_filesystem_device_id: int
    measured_store_dir: str
    target_stream_max_bytes: int
    target_server_max_storage_bytes: int
    capacity_checks: dict[str, bool]
    operation_uid: str


class RollbackError(RuntimeError):
    """The stream update failed and its max-bytes rollback was not proven."""


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")


def _strict_int(value: Any, name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise RuntimeError(f"{name} must be an integer >= {minimum}")
    return value


def _ceil_ratio(total: int, units: int, target: int) -> int:
    if total < 0 or units <= 0 or target <= 0:
        raise RuntimeError("capacity projection ratio is invalid")
    return (total * target + units - 1) // units


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError(f"duplicate JSON key in canonical receipt: {key}")
        result[key] = value
    return result


def _validate_signed_value(value: Any, protocol: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError("canonical evidence value is not an object")
    encoded = canonical_json(value)
    decoded = json.loads(encoded, object_pairs_hook=_pairs_without_duplicates)
    if decoded != value:
        raise RuntimeError("canonical evidence does not round-trip exactly")
    if value.get("protocol") != protocol:
        raise RuntimeError("canonical evidence protocol mismatch")
    unsigned = dict(value)
    claimed = str(unsigned.pop("evidence_sha256", ""))
    if not SHA256.fullmatch(claimed) or claimed != sha256_bytes(canonical_json(unsigned)):
        raise RuntimeError("canonical evidence digest mismatch")
    return value


def _load_canonical_signed(path: Path, protocol: str) -> tuple[dict[str, Any], str]:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise RuntimeError(f"canonical receipt is unavailable: {path}")
    raw = path.read_bytes()
    try:
        value = json.loads(raw, object_pairs_hook=_pairs_without_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"canonical receipt JSON is invalid: {path}") from exc
    if not isinstance(value, dict) or raw != canonical_json(value) + b"\n":
        raise RuntimeError(f"receipt is not canonically encoded: {path}")
    try:
        _validate_signed_value(value, protocol)
    except RuntimeError as exc:
        raise RuntimeError(f"receipt canonical validation failed: {path}: {exc}") from exc
    return value, sha256_file(path)


def _write_immutable_json(path: Path, value: dict[str, Any]) -> None:
    """Create one canonical file and fsync both its bytes and directory entry."""

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    body = canonical_json(value) + b"\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    linked = False
    committed = False
    try:
        os.fchmod(descriptor, 0o400)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
            linked = True
        except FileExistsError as exc:
            raise RuntimeError(f"immutable evidence path already exists: {path}") from exc
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
            committed = True
        finally:
            os.close(directory)
    finally:
        if linked and not committed:
            try:
                path.unlink()
                directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            except FileNotFoundError:
                pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _derive_supplement_bus(receipt: dict[str, Any]) -> dict[str, Any]:
    if receipt.get("production_authority") is not False or receipt.get("memory_grants_authority") is not False:
        raise RuntimeError("capacity supplement authority boundary mismatch")
    if receipt.get("sparse_or_extrapolated_pass") is not False:
        raise RuntimeError("sparse or extrapolated capacity evidence is forbidden")
    target_events = _strict_int(receipt.get("target_events"), "capacity target events", minimum=1)
    if target_events != TARGET_EVENTS:
        raise RuntimeError("capacity supplement target event count mismatch")

    checks = receipt.get("checks")
    if not isinstance(checks, dict) or set(checks) != CAPACITY_SUPPLEMENT_CHECKS:
        raise RuntimeError("capacity supplement check schema mismatch")
    if any(type(value) is not bool for value in checks.values()):
        raise RuntimeError("capacity supplement checks are not boolean")
    false_checks = sorted(name for name, passed in checks.items() if not passed)
    if receipt.get("blockers") != false_checks:
        raise RuntimeError("capacity supplement blockers/checks mismatch")
    if receipt.get("status") != ("PASS" if not false_checks else "INCOMPLETE"):
        raise RuntimeError("capacity supplement status/checks mismatch")

    source = receipt.get("source_snapshot") or {}
    bus = receipt.get("bus") or {}
    config = bus.get("config") or {}
    before = bus.get("state_before") or {}
    after = bus.get("state_after") or {}
    server = bus.get("server") or {}
    filesystem = bus.get("filesystem") or {}

    events = _strict_int(source.get("raw_events"), "capacity sample raw events", minimum=1)
    batches = _strict_int(source.get("ingest_batches"), "capacity sample ingest batches", minimum=1)
    batch_events = _strict_int(source.get("batch_event_sum"), "capacity sample batch event sum", minimum=1)
    first_cursor = _strict_int(source.get("first_cursor"), "capacity sample first cursor", minimum=1)
    last_cursor = _strict_int(source.get("last_cursor"), "capacity sample last cursor", minimum=1)
    maximum_bus_sequence = _strict_int(source.get("max_bus_sequence"), "capacity sample bus sequence")
    before_last = _strict_int(before.get("last_seq"), "capacity NATS before last sequence")
    after_last = _strict_int(after.get("last_seq"), "capacity NATS after last sequence")
    stream_messages = _strict_int(after.get("messages"), "capacity NATS stream messages", minimum=1)
    stream_bytes = _strict_int(after.get("bytes"), "capacity NATS stream bytes", minimum=1)
    allocated_bytes = _strict_int(filesystem.get("allocated_bytes"), "capacity NATS allocated bytes", minimum=1)
    allocated_files = _strict_int(filesystem.get("files"), "capacity NATS allocated files", minimum=1)

    full_history_contract = full_history_bus_contract(config)

    stream_max_bytes = _strict_int(config.get("max_bytes"), "capacity stream max bytes", minimum=1)
    server_max_storage = _strict_int(server.get("max_storage"), "capacity server max storage", minimum=1)
    server_store_used = _strict_int(server.get("storage_used"), "capacity server storage used")
    filesystem_total = _strict_int(filesystem.get("filesystem_total_bytes"), "capacity filesystem total", minimum=1)
    filesystem_available = _strict_int(filesystem.get("filesystem_available_bytes"), "capacity filesystem available")
    filesystem_used = _strict_int(filesystem.get("filesystem_used_bytes"), "capacity filesystem used")
    if filesystem_available + filesystem_used != filesystem_total:
        raise RuntimeError("capacity supplement filesystem arithmetic mismatch")
    if type(filesystem.get("filesystem_device_id")) is not int:
        raise RuntimeError("capacity supplement filesystem device identity is absent")
    measured_store_dir = server.get("store_dir")
    if not isinstance(measured_store_dir, str) or not measured_store_dir.startswith("/"):
        raise RuntimeError("capacity supplement NATS store_dir is absent or not absolute")

    projected_logical = _ceil_ratio(stream_bytes, events, target_events)
    projected_physical = _ceil_ratio(allocated_bytes, events, target_events)
    required_stream = projected_logical * HEADROOM_NUMERATOR
    required_physical = projected_physical * HEADROOM_NUMERATOR
    physical_growth = max(0, required_physical - allocated_bytes)
    server_other_store = max(0, server_store_used - stream_bytes)
    server_capacity_for_stream = max(0, server_max_storage - server_other_store)
    filesystem_reserve = (filesystem_total * FILESYSTEM_RESERVE_PERCENT + 99) // 100
    projected_server = server_other_store + required_physical
    projected_filesystem = filesystem_used + physical_growth

    expected_fields = {
        "projected_stream_logical_bytes_at_target": projected_logical,
        "projected_physical_bytes_at_target": projected_physical,
        "required_stream_logical_bytes_with_2x_headroom": required_stream,
        "required_physical_bytes_with_2x_headroom": required_physical,
        "physical_growth_bytes_to_2x_target": physical_growth,
        "server_other_store_bytes": server_other_store,
        "server_capacity_for_stream_bytes": server_capacity_for_stream,
        "filesystem_reserve_bytes": filesystem_reserve,
        "projected_server_storage_bytes_at_2x_target": projected_server,
        "projected_filesystem_used_bytes_at_2x_target": projected_filesystem,
    }
    if any(bus.get(name) != expected for name, expected in expected_fields.items()):
        raise RuntimeError("capacity supplement bus projection derivation mismatch")
    if bus.get("headroom") != {"numerator": HEADROOM_NUMERATOR, "denominator": 1}:
        raise RuntimeError("capacity supplement headroom contract mismatch")
    if bus.get("watermark_policy") != {
        "high_percent": HIGH_WATERMARK_PERCENT,
        "critical_percent": CRITICAL_WATERMARK_PERCENT,
        "filesystem_reserve_percent": FILESYSTEM_RESERVE_PERCENT,
    }:
        raise RuntimeError("capacity supplement watermark policy mismatch")

    derived_checks = {
        "source_event_and_batch_counts_consistent": (
            batch_events == events and first_cursor >= 1 and last_cursor >= events
        ),
        "bus_stream_snapshot_ordered_around_postgres": (
            before_last <= maximum_bus_sequence <= after_last and stream_messages >= batches
        ),
        "bus_stream_contract_classified": full_history_contract,
        "bus_physical_measurement_valid": allocated_bytes >= stream_bytes and allocated_files >= 1,
        "bus_stream_max_bytes_covers_target": stream_max_bytes >= projected_logical,
        "bus_server_max_storage_covers_target": server_max_storage >= projected_physical,
        "bus_stream_max_bytes_has_2x_target_headroom": stream_max_bytes >= required_stream,
        "bus_server_max_storage_has_2x_target_headroom": server_capacity_for_stream >= required_physical,
        "bus_filesystem_can_grow_to_2x_target_with_reserve": (
            filesystem_available > physical_growth + filesystem_reserve
        ),
        "bus_stream_2x_target_below_high_watermark": (
            required_stream * 100 < stream_max_bytes * HIGH_WATERMARK_PERCENT
        ),
        "bus_server_2x_target_below_high_watermark": (
            projected_server * 100 < server_max_storage * HIGH_WATERMARK_PERCENT
        ),
        "bus_filesystem_2x_target_below_high_watermark": (
            projected_filesystem * 100 < filesystem_total * HIGH_WATERMARK_PERCENT
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
    if any(checks[name] is not expected for name, expected in derived_checks.items()):
        raise RuntimeError("capacity supplement bus checks are not independently derived")
    expected_measurement = all(
        derived_checks[name]
        for name in (
            "source_event_and_batch_counts_consistent",
            "bus_stream_snapshot_ordered_around_postgres",
            "bus_stream_contract_classified",
            "bus_physical_measurement_valid",
        )
    )
    if (receipt.get("measurement_checks") or {}).get("bus") is not expected_measurement:
        raise RuntimeError("capacity supplement bus measurement summary mismatch")
    if not expected_measurement:
        raise RuntimeError("capacity supplement bus measurement is not valid")
    expected_admission = all(
        derived_checks[name] for name in BUS_TARGET_CAPACITY_ADMISSION_CHECKS
    )
    if bus.get("target_capacity_admitted") is not expected_admission:
        raise RuntimeError("capacity supplement target admission summary mismatch")
    return {
        "target_events": target_events,
        "required_stream": required_stream,
        "required_physical": required_physical,
        "physical_growth": physical_growth,
        "server_other_store": server_other_store,
        "projected_server": projected_server,
        "filesystem_total": filesystem_total,
        "filesystem_available": filesystem_available,
        "filesystem_used": filesystem_used,
        "filesystem_reserve": filesystem_reserve,
        "projected_filesystem": projected_filesystem,
        "filesystem_device_id": int(filesystem["filesystem_device_id"]),
        "store_dir": measured_store_dir,
    }


def load_capacity_plan(path: Path, *, now: dt.datetime | None = None) -> CapacityPlan:
    receipt, file_sha = _load_canonical_signed(path, CAPACITY_SUPPLEMENT_PROTOCOL)
    try:
        created = dt.datetime.fromisoformat(str(receipt.get("created_utc") or "").replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError("capacity supplement creation time is invalid") from exc
    if created.tzinfo is None:
        raise RuntimeError("capacity supplement creation time has no timezone")
    observed_now = now or dt.datetime.now(dt.UTC)
    age = (observed_now.astimezone(dt.UTC) - created.astimezone(dt.UTC)).total_seconds()
    if not 0 <= age <= MAX_SUPPLEMENT_AGE_SECONDS:
        raise RuntimeError("capacity supplement is stale or future-dated")
    derived = _derive_supplement_bus(receipt)
    target_stream = _strict_int(bootstrap.MAX_BYTES, "bootstrap stream max bytes", minimum=1)
    target_server = _strict_int(
        bootstrap.SERVER_MAX_FILE_STORE_BYTES,
        "bootstrap server max file-store bytes",
        minimum=1,
    )
    capacity_checks = {
        "stream_2x_target_strictly_below_high_watermark": (
            int(derived["required_stream"]) * 100 < target_stream * HIGH_WATERMARK_PERCENT
        ),
        "server_2x_target_strictly_below_high_watermark": (
            int(derived["projected_server"]) * 100 < target_server * HIGH_WATERMARK_PERCENT
        ),
        "filesystem_growth_plus_reserve_strictly_fits": (
            int(derived["filesystem_available"])
            > int(derived["physical_growth"]) + int(derived["filesystem_reserve"])
        ),
        "filesystem_2x_target_strictly_below_high_watermark": (
            int(derived["projected_filesystem"]) * 100
            < int(derived["filesystem_total"]) * HIGH_WATERMARK_PERCENT
        ),
    }
    if set(capacity_checks) != CAPACITY_CHECK_NAMES or not all(capacity_checks.values()):
        failed = sorted(name for name, passed in capacity_checks.items() if not passed)
        raise RuntimeError("bootstrap capacity target is not admissible: " + ",".join(failed))
    operation = {
        "capacity_supplement_evidence_sha256": receipt["evidence_sha256"],
        "stream": bootstrap.STREAM,
        "target_stream_max_bytes": target_stream,
        "target_server_max_storage_bytes": target_server,
    }
    operation_uid = sha256_bytes(canonical_json(operation))
    return CapacityPlan(
        supplement_path=path.resolve(),
        supplement_file_sha256=file_sha,
        supplement_evidence_sha256=str(receipt["evidence_sha256"]),
        target_events=int(derived["target_events"]),
        required_stream_bytes=int(derived["required_stream"]),
        required_physical_bytes=int(derived["required_physical"]),
        physical_growth_bytes=int(derived["physical_growth"]),
        server_other_store_bytes=int(derived["server_other_store"]),
        projected_server_storage_bytes=int(derived["projected_server"]),
        filesystem_total_bytes=int(derived["filesystem_total"]),
        filesystem_available_bytes=int(derived["filesystem_available"]),
        filesystem_used_bytes=int(derived["filesystem_used"]),
        filesystem_reserve_bytes=int(derived["filesystem_reserve"]),
        projected_filesystem_used_bytes=int(derived["projected_filesystem"]),
        measured_filesystem_device_id=int(derived["filesystem_device_id"]),
        measured_store_dir=str(derived["store_dir"]),
        target_stream_max_bytes=target_stream,
        target_server_max_storage_bytes=target_server,
        capacity_checks=capacity_checks,
        operation_uid=operation_uid,
    )


def _get_field(value: Any, name: str) -> Any:
    if isinstance(value, dict):
        return value.get(name)
    return getattr(value, name, None)


def live_server_capacity(monitor_endpoint: str) -> dict[str, Any]:
    """Read the server JetStream limit, never the unrelated account quota."""

    uri = monitor_endpoint.rstrip("/") + "/jsz?config=true"
    with urllib.request.urlopen(uri, timeout=5) as response:  # noqa: S310 - explicit operator endpoint
        raw = response.read()
    try:
        payload = json.loads(raw, object_pairs_hook=_pairs_without_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError("NATS monitor /jsz response is not valid JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("config"), dict):
        raise RuntimeError("NATS monitor /jsz response has no single server config")
    server_id = payload.get("server_id")
    if not isinstance(server_id, str) or not server_id:
        raise RuntimeError("NATS monitor /jsz response has no server identity")
    max_storage = _strict_int(
        payload["config"].get("max_storage"),
        "live NATS server max_storage",
        minimum=1,
    )
    store_dir = payload["config"].get("store_dir")
    if not isinstance(store_dir, str) or not store_dir.startswith("/"):
        raise RuntimeError("NATS monitor /jsz response has no absolute store_dir")
    return {
        "server_id": server_id,
        "max_storage": max_storage,
        "store_dir": store_dir,
        "monitor_uri": uri,
    }


def connected_server_id(client: Any) -> str:
    """Return the ID from the NATS INFO frame for the active connection.

    nats-py currently exposes the connected URL/version but no public server-ID
    accessor.  Prefer a future public accessor and otherwise use the parsed
    INFO mapping maintained by the client; absence is a hard failure.
    """

    candidate = getattr(client, "connected_server_id", None)
    if callable(candidate):
        candidate = candidate()
    if not isinstance(candidate, str) or not candidate:
        info = getattr(client, "_server_info", None)
        candidate = info.get("server_id") if isinstance(info, dict) else None
    if not isinstance(candidate, str) or not candidate:
        raise RuntimeError("connected NATS server identity is unavailable")
    return candidate


def live_filesystem_capacity(
    plan: CapacityPlan,
    live_server: dict[str, Any],
    nats_data_root: Path,
) -> dict[str, Any]:
    """Recheck the measured JetStream filesystem immediately before intent."""

    store_dir = live_server.get("store_dir")
    if store_dir != plan.measured_store_dir:
        raise RuntimeError("live NATS store_dir differs from capacity measurement")
    container_store = Path(str(store_dir))
    if container_store == Path("/data"):
        host_store = nats_data_root
    elif Path("/data") in container_store.parents:
        host_store = nats_data_root / container_store.relative_to("/data")
    else:
        host_store = container_store
    if host_store.is_symlink() or not host_store.is_dir():
        raise RuntimeError(f"live NATS host store root is unavailable: {host_store}")
    host_store = host_store.resolve()
    device_id = int(host_store.stat().st_dev)
    if device_id != plan.measured_filesystem_device_id:
        raise RuntimeError("live NATS store filesystem device differs from capacity measurement")
    filesystem = os.statvfs(host_store)
    total = int(filesystem.f_frsize * filesystem.f_blocks)
    available = int(filesystem.f_frsize * filesystem.f_bavail)
    if not 0 <= available <= total:
        raise RuntimeError("live NATS filesystem counters are invalid")
    used = total - available
    reserve = (total * FILESYSTEM_RESERVE_PERCENT + 99) // 100
    projected_used = used + plan.physical_growth_bytes
    checks = {
        "growth_plus_reserve_strictly_fits": available > plan.physical_growth_bytes + reserve,
        "projected_2x_target_strictly_below_high_watermark": (
            projected_used * 100 < total * HIGH_WATERMARK_PERCENT
        ),
    }
    if not all(checks.values()):
        failed = sorted(name for name, passed in checks.items() if not passed)
        raise RuntimeError("live NATS filesystem capacity is not admissible: " + ",".join(failed))
    return {
        "monitor_store_dir": store_dir,
        "host_store_root": str(host_store),
        "filesystem_device_id": device_id,
        "filesystem_total_bytes": total,
        "filesystem_available_bytes": available,
        "filesystem_used_bytes": used,
        "filesystem_reserve_bytes": reserve,
        "physical_growth_bytes_to_2x_target": plan.physical_growth_bytes,
        "projected_filesystem_used_bytes_at_2x_target": projected_used,
        "checks": checks,
    }


def _optional_int_list(value: Any, name: str) -> list[int] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise RuntimeError(f"{name} must be an integer list or null")
    return [_strict_int(item, name) for item in value]


def stream_state(value: Any) -> dict[str, Any]:
    state = _get_field(value, "state")
    if state is None:
        state = value
    lost = _get_field(state, "lost")
    lost_value = None
    if lost is not None:
        lost_value = {
            "msgs": _optional_int_list(_get_field(lost, "msgs"), "lost stream messages"),
            "bytes": (
                None
                if _get_field(lost, "bytes") is None
                else _strict_int(_get_field(lost, "bytes"), "lost stream bytes")
            ),
        }
    num_deleted = _get_field(state, "num_deleted")
    return {
        "messages": _strict_int(_get_field(state, "messages"), "live stream messages"),
        "bytes": _strict_int(_get_field(state, "bytes"), "live stream bytes"),
        "first_seq": _strict_int(_get_field(state, "first_seq"), "live stream first sequence"),
        "last_seq": _strict_int(_get_field(state, "last_seq"), "live stream last sequence"),
        "num_deleted": None if num_deleted is None else _strict_int(num_deleted, "deleted stream messages"),
        "deleted": _optional_int_list(_get_field(state, "deleted"), "deleted stream sequences"),
        "lost": lost_value,
    }


def assert_no_stream_regression(before: dict[str, Any], after: dict[str, Any]) -> None:
    for name in ("messages", "bytes", "last_seq"):
        if _strict_int(after.get(name), f"after {name}") < _strict_int(before.get(name), f"before {name}"):
            raise RuntimeError(f"stream state regressed after capacity update: {name}")
    before_messages = _strict_int(before.get("messages"), "before messages")
    before_first = _strict_int(before.get("first_seq"), "before first sequence")
    after_first = _strict_int(after.get("first_seq"), "after first sequence")
    if before_messages > 0 and after_first != before_first:
        raise RuntimeError("stream state regressed after capacity update: first_seq")
    if after.get("num_deleted") != before.get("num_deleted"):
        raise RuntimeError("stream deletion evidence changed after capacity update: num_deleted")
    if after.get("deleted") != before.get("deleted"):
        raise RuntimeError("stream deletion evidence changed after capacity update: deleted")
    if after.get("lost") != before.get("lost"):
        raise RuntimeError("stream loss evidence changed after capacity update: lost")


def stream_config_digest(config: Any) -> str:
    if not hasattr(config, "as_dict"):
        raise RuntimeError("live StreamConfig has no canonical API representation")
    value = config.as_dict()
    if not isinstance(value, dict):
        raise RuntimeError("live StreamConfig canonical representation is invalid")
    return sha256_bytes(canonical_json(value))


def validate_stream_contract_allowing_old_max_bytes(config: Any) -> int:
    current_max = _strict_int(_get_field(config, "max_bytes"), "live stream max bytes", minimum=1)
    expected = bootstrap.expected_config()
    for name in ("name", "description", "mirror", "sources"):
        if _get_field(config, name) != _get_field(expected, name):
            raise RuntimeError(f"JetStream contract drift: {name}")
    normalized = copy.deepcopy(config)
    setattr(normalized, "max_bytes", bootstrap.MAX_BYTES)
    bootstrap.verify_config(normalized)
    return current_max


def _capacity_summary(plan: CapacityPlan) -> dict[str, Any]:
    return {
        "target_events": plan.target_events,
        "required_stream_logical_bytes_with_2x_headroom": plan.required_stream_bytes,
        "required_physical_bytes_with_2x_headroom": plan.required_physical_bytes,
        "physical_growth_bytes_to_2x_target": plan.physical_growth_bytes,
        "server_other_store_bytes": plan.server_other_store_bytes,
        "projected_server_storage_bytes_at_2x_target": plan.projected_server_storage_bytes,
        "filesystem_total_bytes": plan.filesystem_total_bytes,
        "filesystem_available_bytes": plan.filesystem_available_bytes,
        "filesystem_used_bytes": plan.filesystem_used_bytes,
        "filesystem_reserve_bytes": plan.filesystem_reserve_bytes,
        "projected_filesystem_used_bytes_at_2x_target": plan.projected_filesystem_used_bytes,
        "measured_filesystem_device_id": plan.measured_filesystem_device_id,
        "measured_store_dir": plan.measured_store_dir,
        "headroom": {"numerator": HEADROOM_NUMERATOR, "denominator": 1},
        "high_watermark_percent": HIGH_WATERMARK_PERCENT,
        "filesystem_reserve_percent": FILESYSTEM_RESERVE_PERCENT,
        "checks": plan.capacity_checks,
    }


def _validate_live_filesystem_snapshot(value: Any, plan: CapacityPlan) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError("live filesystem preflight is absent")
    total = _strict_int(value.get("filesystem_total_bytes"), "live filesystem total", minimum=1)
    available = _strict_int(value.get("filesystem_available_bytes"), "live filesystem available")
    used = _strict_int(value.get("filesystem_used_bytes"), "live filesystem used")
    reserve = (total * FILESYSTEM_RESERVE_PERCENT + 99) // 100
    projected = used + plan.physical_growth_bytes
    expected_checks = {
        "growth_plus_reserve_strictly_fits": available > plan.physical_growth_bytes + reserve,
        "projected_2x_target_strictly_below_high_watermark": (
            projected * 100 < total * HIGH_WATERMARK_PERCENT
        ),
    }
    if (
        available + used != total
        or value.get("monitor_store_dir") != plan.measured_store_dir
        or value.get("filesystem_device_id") != plan.measured_filesystem_device_id
        or value.get("filesystem_reserve_bytes") != reserve
        or value.get("physical_growth_bytes_to_2x_target") != plan.physical_growth_bytes
        or value.get("projected_filesystem_used_bytes_at_2x_target") != projected
        or value.get("checks") != expected_checks
        or not all(expected_checks.values())
        or not isinstance(value.get("host_store_root"), str)
        or not value.get("host_store_root")
    ):
        raise RuntimeError("live filesystem preflight derivation mismatch")
    return value


def _intent_value(
    plan: CapacityPlan,
    current_max: int,
    state: dict[str, Any],
    live_filesystem: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "protocol": INTENT_PROTOCOL,
        "created_utc": utc_now(),
        "status": "PREPARED",
        "operation_uid": plan.operation_uid,
        "capacity_supplement": {
            "path": str(plan.supplement_path),
            "file_sha256": plan.supplement_file_sha256,
            "evidence_sha256": plan.supplement_evidence_sha256,
        },
        "stream": {
            "name": bootstrap.STREAM,
            "previous_max_bytes": current_max,
            "target_max_bytes": plan.target_stream_max_bytes,
            "state_before": state,
        },
        "server": {"target_max_storage_bytes": plan.target_server_max_storage_bytes},
        "live_filesystem_preflight": live_filesystem,
        "capacity": _capacity_summary(plan),
        "production_authority": False,
        "memory_grants_authority": False,
    }
    value["evidence_sha256"] = sha256_bytes(canonical_json(value))
    return value


def _validate_intent(path: Path, plan: CapacityPlan) -> tuple[dict[str, Any], str]:
    value, file_sha = _load_canonical_signed(path, INTENT_PROTOCOL)
    supplement = value.get("capacity_supplement") or {}
    stream = value.get("stream") or {}
    server = value.get("server") or {}
    if (
        value.get("status") != "PREPARED"
        or value.get("operation_uid") != plan.operation_uid
        or supplement.get("path") != str(plan.supplement_path)
        or supplement.get("file_sha256") != plan.supplement_file_sha256
        or supplement.get("evidence_sha256") != plan.supplement_evidence_sha256
        or stream.get("name") != bootstrap.STREAM
        or stream.get("target_max_bytes") != plan.target_stream_max_bytes
        or server.get("target_max_storage_bytes") != plan.target_server_max_storage_bytes
        or value.get("capacity") != _capacity_summary(plan)
        or value.get("production_authority") is not False
        or value.get("memory_grants_authority") is not False
    ):
        raise RuntimeError("existing capacity reconcile intent binding mismatch")
    previous = _strict_int(stream.get("previous_max_bytes"), "intent previous stream max bytes", minimum=1)
    if previous > plan.target_stream_max_bytes:
        raise RuntimeError("existing capacity reconcile intent would decrease stream capacity")
    state = stream.get("state_before") or {}
    stream_state(state)
    _validate_live_filesystem_snapshot(value.get("live_filesystem_preflight"), plan)
    return value, file_sha


def _receipt_value(
    plan: CapacityPlan,
    intent: dict[str, Any],
    intent_path: Path,
    intent_file_sha: str,
    state_after: dict[str, Any],
    *,
    live_server: dict[str, Any],
    live_filesystem: dict[str, Any],
    update_performed_this_run: bool,
    recovered_pending_intent: bool,
) -> dict[str, Any]:
    value = {
        "protocol": PROTOCOL,
        "created_utc": utc_now(),
        "status": "PASS",
        "operation_uid": plan.operation_uid,
        "capacity_supplement": {
            "path": str(plan.supplement_path),
            "file_sha256": plan.supplement_file_sha256,
            "evidence_sha256": plan.supplement_evidence_sha256,
        },
        "intent": {
            "path": str(intent_path),
            "file_sha256": intent_file_sha,
            "evidence_sha256": intent["evidence_sha256"],
        },
        "live_filesystem_preflight": live_filesystem,
        "stream": {
            "name": bootstrap.STREAM,
            "previous_max_bytes": (intent.get("stream") or {})["previous_max_bytes"],
            "target_max_bytes": plan.target_stream_max_bytes,
            "state_before": (intent.get("stream") or {})["state_before"],
            "state_after": state_after,
            "update_performed_this_run": update_performed_this_run,
            "recovered_pending_intent": recovered_pending_intent,
        },
        "server": {
            "server_id": live_server["server_id"],
            "connected_server_id": live_server["connected_server_id"],
            "monitor_uri": live_server["monitor_uri"],
            "live_max_storage_bytes": live_server["max_storage"],
            "target_max_storage_bytes": plan.target_server_max_storage_bytes,
        },
        "capacity": _capacity_summary(plan),
        "checks": {
            "capacity_supplement_canonical_and_bus_measurement_valid": True,
            "bootstrap_targets_admit_2x_below_high_watermark": True,
            "filesystem_growth_plus_reserve_strictly_fits": True,
            "live_server_max_storage_exact_target": True,
            "monitor_and_connected_server_identity_match": True,
            "live_filesystem_capacity_rechecked": True,
            "stream_contract_valid_except_previous_max_bytes": True,
            "fsynced_intent_bound_before_update": True,
            "stream_target_exact_after_update": True,
            "stream_sequence_message_and_byte_regression_absent": True,
            "production_authority_false": True,
            "memory_grants_authority_false": True,
        },
        "production_authority": False,
        "memory_grants_authority": False,
    }
    value["evidence_sha256"] = sha256_bytes(canonical_json(value))
    return value


def _validate_receipt_value(
    value: dict[str, Any],
    plan: CapacityPlan,
    intent_path: Path,
    intent: dict[str, Any],
    intent_file_sha: str,
    live_server: dict[str, Any],
) -> dict[str, Any]:
    _validate_signed_value(value, PROTOCOL)
    supplement = value.get("capacity_supplement") or {}
    stream = value.get("stream") or {}
    server = value.get("server") or {}
    intent_binding = value.get("intent") or {}
    if (
        value.get("status") != "PASS"
        or value.get("operation_uid") != plan.operation_uid
        or supplement.get("path") != str(plan.supplement_path)
        or supplement.get("file_sha256") != plan.supplement_file_sha256
        or supplement.get("evidence_sha256") != plan.supplement_evidence_sha256
        or intent_binding.get("path") != str(intent_path)
        or intent_binding.get("file_sha256") != intent_file_sha
        or intent_binding.get("evidence_sha256") != intent.get("evidence_sha256")
        or stream.get("name") != bootstrap.STREAM
        or stream.get("target_max_bytes") != plan.target_stream_max_bytes
        or stream.get("state_before") != (intent.get("stream") or {}).get("state_before")
        or type(stream.get("update_performed_this_run")) is not bool
        or type(stream.get("recovered_pending_intent")) is not bool
        or (
            stream.get("update_performed_this_run") is True
            and stream.get("recovered_pending_intent") is True
        )
        or not isinstance(server.get("server_id"), str)
        or not server.get("server_id")
        or not isinstance(server.get("connected_server_id"), str)
        or server.get("connected_server_id") != server.get("server_id")
        or not isinstance(live_server.get("server_id"), str)
        or not live_server.get("server_id")
        or live_server.get("connected_server_id") != live_server.get("server_id")
        or server.get("monitor_uri") != live_server.get("monitor_uri")
        or server.get("live_max_storage_bytes") != live_server.get("max_storage")
        or server.get("target_max_storage_bytes") != plan.target_server_max_storage_bytes
        or value.get("capacity") != _capacity_summary(plan)
        or not isinstance(value.get("checks"), dict)
        or set(value["checks"]) != RECEIPT_CHECK_NAMES
        or any(check is not True for check in value["checks"].values())
        or value.get("production_authority") is not False
        or value.get("memory_grants_authority") is not False
    ):
        raise RuntimeError("existing capacity reconcile receipt binding mismatch")
    if stream.get("previous_max_bytes") != (intent.get("stream") or {}).get("previous_max_bytes"):
        raise RuntimeError("existing receipt previous capacity does not match intent")
    before = stream.get("state_before") or {}
    after = stream.get("state_after") or {}
    stream_state(before)
    stream_state(after)
    assert_no_stream_regression(before, after)
    _validate_live_filesystem_snapshot(value.get("live_filesystem_preflight"), plan)
    return value


def _validate_receipt(
    path: Path,
    plan: CapacityPlan,
    intent_path: Path,
    live_server: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    value, file_sha = _load_canonical_signed(path, PROTOCOL)
    intent, intent_file_sha = _validate_intent(intent_path, plan)
    _validate_receipt_value(value, plan, intent_path, intent, intent_file_sha, live_server)
    return value, file_sha


async def _rollback_stream_max_bytes(jetstream: Any, previous_max: int) -> None:
    current = await jetstream.stream_info(bootstrap.STREAM)
    rollback_baseline = stream_state(current)
    if rollback_baseline["bytes"] > previous_max:
        raise RuntimeError("rollback would set max_bytes below the current retained stream bytes")
    rollback_config = copy.deepcopy(current.config)
    rollback_config.max_bytes = previous_max
    update_error: Exception | None = None
    try:
        await jetstream.update_stream(config=rollback_config)
    except Exception as exc:
        # A request timeout is not proof that the server rejected the update.
        # Reconcile the immutable target from live state before escalating.
        update_error = exc
    try:
        restored = await jetstream.stream_info(bootstrap.STREAM)
    except Exception as observation_error:
        if update_error is not None:
            raise RuntimeError("rollback response and live reconciliation are both unavailable") from update_error
        raise RuntimeError("rollback live reconciliation is unavailable") from observation_error
    restored_max = _strict_int(
        _get_field(restored.config, "max_bytes"),
        "restored stream max bytes",
        minimum=1,
    )
    if restored_max != previous_max:
        if update_error is not None:
            raise RuntimeError("unknown rollback response did not reach the previous max_bytes") from update_error
        raise RuntimeError("stream max-bytes rollback did not reach the previous value")
    assert_no_stream_regression(rollback_baseline, stream_state(restored))


async def reconcile(args: argparse.Namespace, *, connector: Callable[..., Any] | None = None) -> dict[str, Any]:
    if getattr(args, "apply", False) is not True:
        raise RuntimeError("capacity reconciliation requires explicit --apply")
    plan = load_capacity_plan(args.capacity_supplement)
    root = args.receipt_root.resolve()
    if args.receipt_root.is_symlink():
        raise RuntimeError("capacity reconcile receipt root must not be a symlink")
    root.mkdir(parents=True, exist_ok=True, mode=0o750)
    intent_path = root / f"nats-capacity-intent-{plan.operation_uid}.json"
    receipt_path = root / f"nats-capacity-reconcile-{plan.operation_uid}.json"

    environment = bootstrap.load_env(args.admin_env)
    connect = connector or nats.connect
    client = await connect(
        servers=[args.server],
        user=environment["NATS_USER"],
        password=environment["NATS_PASSWORD"],
        name="integrity-p2-nats-capacity-reconcile",
        connect_timeout=3,
        max_reconnect_attempts=0,
        allow_reconnect=False,
    )
    try:
        jetstream = client.jetstream(timeout=5)
        live_server = live_server_capacity(args.monitor_endpoint)
        connected_id = connected_server_id(client)
        if live_server["server_id"] != connected_id:
            raise RuntimeError(
                "NATS monitor and connected server identities differ: "
                f"{live_server['server_id']} != {connected_id}"
            )
        live_server = {**live_server, "connected_server_id": connected_id}
        if live_server["max_storage"] != plan.target_server_max_storage_bytes:
            raise RuntimeError(
                "live NATS server max_storage does not equal bootstrap target: "
                f"{live_server['max_storage']} != {plan.target_server_max_storage_bytes}"
            )

        current_info = await jetstream.stream_info(bootstrap.STREAM)
        current_max = _strict_int(
            _get_field(current_info.config, "max_bytes"),
            "live stream max bytes",
            minimum=1,
        )
        current_state = stream_state(current_info)
        current_config_digest = stream_config_digest(current_info.config)
        if current_max > plan.target_stream_max_bytes:
            raise RuntimeError("capacity reconcile refuses to decrease stream max_bytes")

        if receipt_path.exists():
            validate_stream_contract_allowing_old_max_bytes(current_info.config)
            receipt, receipt_file_sha = _validate_receipt(
                receipt_path,
                plan,
                intent_path,
                live_server,
            )
            if current_max != plan.target_stream_max_bytes:
                raise RuntimeError("live stream capacity drifted below an existing reconcile receipt")
            bootstrap.verify_config(current_info.config)
            assert_no_stream_regression((receipt.get("stream") or {})["state_after"], current_state)
            return {
                "status": "PASS",
                "reused": True,
                "receipt_path": str(receipt_path),
                "receipt_file_sha256": receipt_file_sha,
                "receipt": receipt,
            }

        live_filesystem = live_filesystem_capacity(
            plan,
            live_server,
            args.nats_data_root,
        )
        _validate_live_filesystem_snapshot(live_filesystem, plan)
        if intent_path.exists():
            intent, intent_file_sha = _validate_intent(intent_path, plan)
        else:
            validate_stream_contract_allowing_old_max_bytes(current_info.config)
            intent = _intent_value(plan, current_max, current_state, live_filesystem)
            _write_immutable_json(intent_path, intent)
            intent, intent_file_sha = _validate_intent(intent_path, plan)

        intent_stream = intent.get("stream") or {}
        previous_max = _strict_int(intent_stream.get("previous_max_bytes"), "intent previous max bytes", minimum=1)
        baseline = stream_state(intent_stream.get("state_before") or {})
        if current_max not in {previous_max, plan.target_stream_max_bytes}:
            raise RuntimeError("live stream max_bytes does not match the prepared intent")
        if current_max < plan.target_stream_max_bytes and current_max != previous_max:
            raise RuntimeError("live stream capacity changed after intent preparation")

        pre_update_info = await jetstream.stream_info(bootstrap.STREAM)
        validate_stream_contract_allowing_old_max_bytes(pre_update_info.config)
        pre_update_state = stream_state(pre_update_info)
        if (
            stream_config_digest(pre_update_info.config) != current_config_digest
            or pre_update_state != current_state
        ):
            raise RuntimeError("concurrent stream config or state drift before capacity update")

        update_performed = False
        recovered_pending = previous_max < plan.target_stream_max_bytes and current_max == plan.target_stream_max_bytes
        rollback_required = recovered_pending
        receipt_committed = False
        try:
            assert_no_stream_regression(baseline, pre_update_state)
            if current_max < plan.target_stream_max_bytes:
                rollback_required = True
                update_performed = True
                update_config = copy.deepcopy(pre_update_info.config)
                update_config.max_bytes = plan.target_stream_max_bytes
                bootstrap.verify_config(update_config)
                await jetstream.update_stream(config=update_config)
            updated_info = await jetstream.stream_info(bootstrap.STREAM)
            bootstrap.verify_config(updated_info.config)
            updated_state = stream_state(updated_info)
            assert_no_stream_regression(baseline, updated_state)
            receipt = _receipt_value(
                plan,
                intent,
                intent_path,
                intent_file_sha,
                updated_state,
                live_server=live_server,
                live_filesystem=live_filesystem,
                update_performed_this_run=update_performed,
                recovered_pending_intent=recovered_pending,
            )
            _validate_receipt_value(
                receipt,
                plan,
                intent_path,
                intent,
                intent_file_sha,
                live_server,
            )
            receipt_file_sha = sha256_bytes(canonical_json(receipt) + b"\n")
            _write_immutable_json(receipt_path, receipt)
            receipt_committed = True
        except Exception as failure:
            if rollback_required and not receipt_committed:
                try:
                    await _rollback_stream_max_bytes(jetstream, previous_max)
                except Exception as rollback_failure:
                    raise RollbackError(
                        "capacity update failed and stream max_bytes rollback could not be proven"
                    ) from rollback_failure
                raise RuntimeError(
                    "capacity update failed after mutation; previous stream max_bytes was restored"
                ) from failure
            raise
        return {
            "status": "PASS",
            "reused": False,
            "receipt_path": str(receipt_path),
            "receipt_file_sha256": receipt_file_sha,
            "receipt": receipt,
        }
    finally:
        await client.drain()


def run(args: argparse.Namespace, *, connector: Callable[..., Any] | None = None) -> dict[str, Any]:
    root = args.receipt_root.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o750)
    lock_path = root / ".nats-capacity-reconcile.lock"
    with lock_path.open("a+", encoding="ascii") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("another NATS capacity reconciliation is active") from exc
        return asyncio.run(reconcile(args, connector=connector))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--admin-env",
        type=Path,
        default=Path("/etc/integrity-memory-p2/shadow.env"),
        help="NATS administrative credential environment",
    )
    parser.add_argument("--server", default="nats://127.0.0.1:4222")
    parser.add_argument("--monitor-endpoint", default=_integrity_value('endpoint_37a28bd31428'))
    parser.add_argument(
        "--nats-data-root",
        type=Path,
        default=Path(_integrity_value('path_a2a38cd4c8c1')),
    )
    parser.add_argument("--capacity-supplement", type=Path, required=True)
    parser.add_argument("--receipt-root", type=Path, required=True)
    parser.add_argument("--apply", action="store_true", required=True)
    args = parser.parse_args()
    result = run(args)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
