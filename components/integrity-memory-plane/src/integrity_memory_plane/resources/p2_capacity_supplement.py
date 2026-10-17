#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Measure capacity dimensions absent from the physical history lab.

This collector is read-only with respect to NATS, PostgreSQL and MinIO.  Its
only write is one immutable evidence receipt.  Missing attachment policy or an
undersized bus is represented as an explicit blocker, never as a zero-sized
component.
"""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import hashlib
import json
import os
import urllib.request
from fractions import Fraction
from pathlib import Path
from typing import Any

import boto3
from botocore.client import Config

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file
from p2_billion_capacity import TARGET_EVENTS, connect, load_env


PROTOCOL = "integrity-memory-plane.p2-capacity-supplement.v1.receipt"
GAP_GUARD_PROTOCOL = "integrity-memory-plane.p2-gap-guard.v1.evidence"
STREAM = "INTEGRITY_P2_RAW"
RAW_BUCKET = "integrity-p2-raw"
ATTACHMENT_BUCKET = "integrity-p2-attachments"
HEADROOM_NUMERATOR = 2
HIGH_WATERMARK_PERCENT = 80
CRITICAL_WATERMARK_PERCENT = 90
FILESYSTEM_RESERVE_PERCENT = 20
REQUIRED_CHECKS = {
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
BUS_MEASUREMENT_CHECKS = (
    "source_event_and_batch_counts_consistent",
    "bus_stream_snapshot_ordered_around_postgres",
    "bus_stream_contract_classified",
    "bus_physical_measurement_valid",
)
BUS_TARGET_CAPACITY_ADMISSION_CHECKS = BUS_MEASUREMENT_CHECKS + (
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


def _strict_int(value: Any, name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise RuntimeError(f"{name} must be an integer >= {minimum}")
    return value


def _ceil_ratio(total: int, units: int, target: int = TARGET_EVENTS) -> int:
    if total < 0 or units <= 0 or target < 0:
        raise RuntimeError("invalid projection ratio")
    return (total * target + units - 1) // units


def _ratio_json(total: int, units: int) -> dict[str, Any]:
    value = Fraction(total, units)
    return {
        "numerator_bytes": value.numerator,
        "denominator_events": value.denominator,
        "decimal_bytes_per_event": round(float(value), 9),
    }


def tree_stats(root: Path) -> dict[str, int]:
    logical = allocated = files = 0
    for base, _directories, names in os.walk(root):
        for name in names:
            path = Path(base) / name
            value = path.stat()
            logical += int(value.st_size)
            allocated += int(value.st_blocks * 512)
            files += 1
    filesystem = os.statvfs(root)
    total = int(filesystem.f_frsize * filesystem.f_blocks)
    available = int(filesystem.f_frsize * filesystem.f_bavail)
    if not 0 <= available <= total:
        raise RuntimeError(f"filesystem counters are invalid: {root}")
    return {
        "logical_bytes": logical,
        "allocated_bytes": allocated,
        "files": files,
        "filesystem_total_bytes": total,
        "filesystem_available_bytes": available,
        "filesystem_used_bytes": total - available,
        "filesystem_device_id": int(root.stat().st_dev),
    }


def nats_snapshot(endpoint: str) -> dict[str, Any]:
    uri = endpoint.rstrip("/") + "/jsz?streams=true&config=true"
    with urllib.request.urlopen(uri, timeout=5) as response:  # noqa: S310 - loopback endpoint is explicit
        payload = json.load(response)
    details = []
    for account in payload.get("account_details") or []:
        details.extend(account.get("stream_detail") or [])
    matches = [value for value in details if value.get("name") == STREAM]
    if len(matches) != 1:
        raise RuntimeError("expected exactly one Integrity P2 stream")
    stream = matches[0]
    return {
        "observed_utc": str(payload.get("now") or ""),
        "server": {
            "server_id": str(payload.get("server_id") or ""),
            "storage_used": _strict_int(payload.get("storage"), "NATS storage used"),
            "max_storage": _strict_int((payload.get("config") or {}).get("max_storage"), "NATS max_storage", minimum=1),
            "store_dir": str((payload.get("config") or {}).get("store_dir") or ""),
            "sync_always": (payload.get("config") or {}).get("sync_always") is True,
        },
        "stream": {"name": STREAM, "config": stream.get("config") or {}, "state": stream.get("state") or {}},
    }


def postgres_snapshot(env_path: Path) -> dict[str, Any]:
    with connect(load_env(env_path), "GUARD") as connection:
        events = int(connection.execute("SELECT count(*) FROM integrity_p2.raw_events").fetchone()[0])
        row = connection.execute(
            "SELECT count(*),COALESCE(sum(event_count),0),COALESCE(min(first_cursor),0),"
            "COALESCE(max(last_cursor),0),COALESCE(max(bus_sequence),0) FROM integrity_p2.ingest_batches"
        ).fetchone()
        identities = hashlib.sha256()
        identity_count = 0
        dead_letter_raw_objects = 0
        for key, version_id, source in connection.execute(
            "SELECT raw_object_key,raw_object_version,'ingest' FROM integrity_p2.ingest_batches "
            "UNION ALL SELECT raw_object_key,evidence #>> '{raw_object,version_id}','dead-letter' "
            "FROM integrity_p2.dead_letters WHERE raw_object_key IS NOT NULL "
            "ORDER BY 1,2,3"
        ):
            if not key or not version_id:
                raise RuntimeError("committed raw object identity is incomplete")
            identities.update(canonical_json({"key": str(key), "version_id": str(version_id)}))
            identities.update(b"\n")
            identity_count += 1
            dead_letter_raw_objects += int(source == "dead-letter")
    return {
        "raw_events": events,
        "ingest_batches": int(row[0]),
        "batch_event_sum": int(row[1]),
        "first_cursor": int(row[2]),
        "last_cursor": int(row[3]),
        "max_bus_sequence": int(row[4]),
        "raw_object_identities": identity_count,
        "raw_object_identity_sha256": identities.hexdigest(),
        "dead_letter_raw_objects": dead_letter_raw_objects,
    }


def s3_client(env_path: Path, endpoint: str) -> Any:
    env = load_env(env_path)
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=env["MINIO_ROOT_USER"],
        aws_secret_access_key=env["MINIO_ROOT_PASSWORD"],
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 2}),
    )


def bucket_snapshot(client: Any, bucket: str) -> dict[str, Any]:
    version_count = latest_count = all_bytes = latest_bytes = delete_markers = 0
    prefix_versions: dict[str, int] = {}
    versions_per_key: dict[str, int] = {}
    inventory = hashlib.sha256()
    raw_identities = hashlib.sha256()
    raw_identity_count = 0

    def bind(kind: str, item: dict[str, Any]) -> None:
        record = {
            "kind": kind,
            "key": str(item.get("Key") or ""),
            "version_id": str(item.get("VersionId") or ""),
            "is_latest": item.get("IsLatest") is True,
            "size": int(item.get("Size") or 0) if kind == "version" else 0,
            "etag": str(item.get("ETag") or "") if kind == "version" else "",
            "last_modified": item.get("LastModified"),
        }
        inventory.update(canonical_json(record))
        inventory.update(b"\n")

    for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for item in page.get("Versions", []):
            bind("version", item)
            key = str(item.get("Key") or "")
            if bucket == RAW_BUCKET and key.startswith("raw/v1/"):
                raw_identities.update(
                    canonical_json({"key": key, "version_id": str(item.get("VersionId") or "")})
                )
                raw_identities.update(b"\n")
                raw_identity_count += 1
            size = int(item.get("Size") or 0)
            version_count += 1
            all_bytes += size
            versions_per_key[key] = versions_per_key.get(key, 0) + 1
            prefix = key.split("/", 1)[0]
            prefix_versions[prefix] = prefix_versions.get(prefix, 0) + 1
            if item.get("IsLatest") is True:
                latest_count += 1
                latest_bytes += size
        for item in page.get("DeleteMarkers", []):
            bind("delete-marker", item)
            delete_markers += 1
    multipart = 0
    for page in client.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
        multipart += len(page.get("Uploads", []))
    lock = client.get_object_lock_configuration(Bucket=bucket).get("ObjectLockConfiguration") or {}
    retention = ((lock.get("Rule") or {}).get("DefaultRetention") or {})
    return {
        "bucket": bucket,
        "versions": version_count,
        "latest_objects": latest_count,
        "noncurrent_versions": version_count - latest_count,
        "all_version_bytes": all_bytes,
        "latest_bytes": latest_bytes,
        "version_overhang_bytes": all_bytes - latest_bytes,
        "delete_markers": delete_markers,
        "incomplete_multipart_uploads": multipart,
        "prefix_version_counts": prefix_versions,
        "max_versions_per_key": max(versions_per_key.values(), default=0),
        "inventory_records": version_count + delete_markers,
        "inventory_sha256": inventory.hexdigest(),
        "raw_object_identities": raw_identity_count,
        "raw_object_identity_sha256": raw_identities.hexdigest(),
        "versioning": client.get_bucket_versioning(Bucket=bucket).get("Status"),
        "object_lock": lock.get("ObjectLockEnabled"),
        "retention_mode": retention.get("Mode"),
        "retention_days": int(retention.get("Days") or 0),
    }


def gap_guard_snapshot(path: Path, *, max_age_seconds: int = 3600) -> dict[str, Any]:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise RuntimeError("gap guard receipt is unavailable or non-canonical")
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("protocol") != GAP_GUARD_PROTOCOL or value.get("status") not in {"PASS", "DEGRADED"}:
        raise RuntimeError("gap guard receipt has hard-failure status")
    if value.get("production_authority") is not False or value.get("memory_grants_authority") is not False:
        raise RuntimeError("gap guard authority boundary mismatch")
    claimed = str(value.get("evidence_sha256") or "")
    evidence = dict(value)
    for name in ("evidence_sha256", "run_uid", "created_utc"):
        evidence.pop(name, None)
    if claimed != sha256_bytes(canonical_json(evidence)):
        raise RuntimeError("gap guard canonical digest mismatch")
    created = dt.datetime.fromisoformat(str(value.get("created_utc") or "").replace("Z", "+00:00"))
    age = (dt.datetime.now(dt.UTC) - created.astimezone(dt.UTC)).total_seconds()
    if not 0 <= age <= max_age_seconds:
        raise RuntimeError("gap guard receipt is stale or future-dated")
    hard = value.get("hard_failures") or {}
    if not hard or any(type(item) is not int or item != 0 for item in hard.values()):
        raise RuntimeError("gap guard has hard failures or malformed counters")
    lag = value.get("projection_lag") or {}
    if not lag or any(type(item) is not int or item < 0 for item in lag.values()):
        raise RuntimeError("gap guard projection lag counters are malformed")
    return {
        "path": str(path.resolve()),
        "file_sha256": sha256_file(path),
        "evidence_sha256": claimed,
        "age_seconds": round(age, 3),
        "receipt": value,
    }


def full_history_bus_contract(config: dict[str, Any]) -> bool:
    """Classify a lossless full-history JetStream sizing sample.

    A hard-stop stream is not enough if per-message TTL, rollups, transforms,
    compression, or newer scheduling/atomic modes could make retained bytes an
    incomplete or non-comparable sample.  Absent keys are accepted only where
    the pinned NATS default is the disabled value.
    """

    disabled = lambda name: config.get(name) in (None, False)  # noqa: E731
    return (
        config.get("retention") == "limits"
        and _strict_int(config.get("max_age"), "stream max_age") == 0
        and int(config.get("max_msgs")) == -1
        and int(config.get("max_msgs_per_subject")) == -1
        and config.get("discard") == "new"
        and disabled("discard_new_per_subject")
        and config.get("deny_delete") is True
        and config.get("deny_purge") is True
        and disabled("allow_rollup_hdrs")
        and disabled("allow_msg_ttl")
        and disabled("allow_msg_schedules")
        and disabled("allow_atomic")
        and disabled("allow_batched")
        and config.get("subject_transform") is None
        and config.get("republish") is None
        and config.get("subject_delete_marker_ttl") in (None, 0)
        and config.get("compression") in (None, "none")
        and config.get("persist_mode") in (None, "default")
        and not config.get("mirror")
        and not config.get("sources")
    )


def evaluate(observed: dict[str, Any]) -> dict[str, Any]:
    postgres = observed["postgres"]
    event_count = _strict_int(postgres.get("raw_events"), "raw event count", minimum=1)
    batches = _strict_int(postgres.get("ingest_batches"), "ingest batch count", minimum=1)
    before = observed["nats_before"]
    after = observed["nats_after"]
    config = after["stream"]["config"]
    state = after["stream"]["state"]
    bus_fs = observed["filesystem"]["nats"]
    minio_fs = observed["filesystem"]["minio"]
    raw_fs = observed["filesystem"]["minio_raw"]
    attachment_fs = observed["filesystem"]["minio_attachments"]
    minio_system_fs = observed["filesystem"]["minio_system"]
    s3_before = observed["s3_before"]
    s3_after = observed["s3_after"]
    raw = s3_after[RAW_BUCKET]
    attachments = s3_after[ATTACHMENT_BUCKET]
    gap = observed["gap_guard"]["receipt"]

    before_last = _strict_int(before["stream"]["state"].get("last_seq"), "NATS before last_seq")
    after_last = _strict_int(state.get("last_seq"), "NATS after last_seq")
    max_bus_sequence = _strict_int(postgres.get("max_bus_sequence"), "Postgres max bus sequence")
    stream_bytes = _strict_int(state.get("bytes"), "NATS stream bytes")
    stream_messages = _strict_int(state.get("messages"), "NATS stream messages")
    bus_allocated = _strict_int(bus_fs.get("allocated_bytes"), "NATS allocated bytes", minimum=1)
    bus_projected_logical = _ceil_ratio(stream_bytes, event_count)
    bus_projected_physical = _ceil_ratio(bus_allocated, event_count)
    stream_max_bytes = _strict_int(config.get("max_bytes"), "stream max_bytes", minimum=1)
    server_max_storage = _strict_int(after["server"].get("max_storage"), "server max_storage", minimum=1)
    server_store_used = _strict_int(after["server"].get("storage_used"), "server storage used")
    required_stream_2x = bus_projected_logical * HEADROOM_NUMERATOR
    required_physical_2x = bus_projected_physical * HEADROOM_NUMERATOR
    physical_growth_2x = max(0, required_physical_2x - bus_allocated)
    server_other_store = max(0, server_store_used - stream_bytes)
    server_capacity_for_stream = max(0, server_max_storage - server_other_store)
    filesystem_total = _strict_int(bus_fs.get("filesystem_total_bytes"), "NATS filesystem total", minimum=1)
    filesystem_available = _strict_int(bus_fs.get("filesystem_available_bytes"), "NATS filesystem available")
    filesystem_used = _strict_int(bus_fs.get("filesystem_used_bytes"), "NATS filesystem used")
    if filesystem_available + filesystem_used != filesystem_total:
        raise RuntimeError("NATS filesystem total/available/used arithmetic mismatch")
    filesystem_reserve = (filesystem_total * FILESYSTEM_RESERVE_PERCENT + 99) // 100
    projected_server_store_used_2x = server_other_store + required_physical_2x
    projected_filesystem_used_2x = filesystem_used + physical_growth_2x
    bus_classified_full_history = full_history_bus_contract(config)

    raw_all_bytes = _strict_int(raw.get("all_version_bytes"), "raw all-version bytes", minimum=1)
    attachment_all_bytes = _strict_int(attachments.get("all_version_bytes"), "attachment all-version bytes")
    total_payload = raw_all_bytes + attachment_all_bytes
    minio_allocated = _strict_int(minio_fs.get("allocated_bytes"), "MinIO allocated bytes", minimum=1)
    object_overhead = max(0, minio_allocated - total_payload)
    raw_workload_versions = int((raw.get("prefix_version_counts") or {}).get("raw") or 0)
    attachment_workload_versions = sum(
        int(count) for prefix, count in (attachments.get("prefix_version_counts") or {}).items() if prefix != "_bootstrap"
    )
    inventories_stable = all(
        s3_before[bucket].get("inventory_sha256") == s3_after[bucket].get("inventory_sha256")
        and s3_before[bucket].get("inventory_records") == s3_after[bucket].get("inventory_records")
        and s3_before[bucket].get("all_version_bytes") == s3_after[bucket].get("all_version_bytes")
        for bucket in (RAW_BUCKET, ATTACHMENT_BUCKET)
    )
    inventory_arithmetic = all(
        int(value.get("versions", -1))
        == int(value.get("latest_objects", -1)) + int(value.get("noncurrent_versions", -1))
        and int(value.get("version_overhang_bytes", -1))
        == int(value.get("all_version_bytes", -1)) - int(value.get("latest_bytes", -1))
        and sum(int(count) for count in (value.get("prefix_version_counts") or {}).values())
        == int(value.get("versions", -1))
        and int(value.get("inventory_records", -1))
        == int(value.get("versions", -1)) + int(value.get("delete_markers", -1))
        for value in (raw, attachments)
    )
    gap_exact = (
        0 < int(gap.get("committed_events") or -1) <= event_count
        and 0 < int(gap.get("committed_batches") or -1) <= batches
        and int((gap.get("s3") or {}).get("committed_keys") or -1) == int(gap.get("committed_batches") or -1)
        and int(postgres.get("raw_object_identities") or -1) == raw_workload_versions
        and str(postgres.get("raw_object_identity_sha256") or "")
        == str(raw.get("raw_object_identity_sha256") or "")
        and raw_workload_versions - int((gap.get("s3") or {}).get("keys") or -1)
        == batches - int(gap.get("committed_batches") or -1)
        and int(postgres.get("dead_letter_raw_objects") or -1)
        == int((gap.get("s3") or {}).get("known_dlq_keys") or -1)
        and gap.get("early_cursor_present") is True
    )

    checks = {
        "source_event_and_batch_counts_consistent": (
            int(postgres.get("batch_event_sum") or -1) == event_count
            and int(postgres.get("first_cursor") or 0) >= 1
            and int(postgres.get("last_cursor") or 0) >= event_count
        ),
        "bus_stream_snapshot_ordered_around_postgres": (
            before_last <= max_bus_sequence <= after_last and stream_messages >= batches
        ),
        "bus_stream_contract_classified": bus_classified_full_history,
        "bus_physical_measurement_valid": bus_allocated >= stream_bytes and int(bus_fs.get("files") or 0) >= 1,
        "bus_stream_max_bytes_covers_target": stream_max_bytes >= bus_projected_logical,
        "bus_server_max_storage_covers_target": server_max_storage >= bus_projected_physical,
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
        "bus_stream_below_high_watermark": stream_bytes * 100 < stream_max_bytes * HIGH_WATERMARK_PERCENT,
        "bus_server_below_high_watermark": server_store_used * 100 < server_max_storage * HIGH_WATERMARK_PERCENT,
        "bus_filesystem_below_high_watermark": filesystem_used * 100 < filesystem_total * HIGH_WATERMARK_PERCENT,
        "object_store_all_versions_enumerated": (
            int(raw.get("versions") or -1) >= raw_workload_versions
            and int(attachments.get("versions") or -1) >= attachment_workload_versions
            and int(raw.get("all_version_bytes") or -1) >= int(raw.get("latest_bytes") or -1)
            and int(attachments.get("all_version_bytes") or -1) >= int(attachments.get("latest_bytes") or -1)
        ),
        "object_store_inventory_arithmetic_consistent": inventory_arithmetic,
        "object_store_inventory_stable_during_physical_measurement": inventories_stable,
        "object_store_delete_markers_absent": all(
            int(value.get("delete_markers") or 0) == 0 for value in (raw, attachments)
        ),
        "object_store_worm_contract_verified": all(
            value.get("versioning") == "Enabled"
            and value.get("object_lock") == "Enabled"
            and value.get("retention_mode") == "COMPLIANCE"
            and int(value.get("retention_days") or 0) >= 30
            for value in (raw, attachments)
        ),
        "object_store_no_unmeasured_multipart_uploads": all(
            int(value.get("incomplete_multipart_uploads") or 0) == 0 for value in (raw, attachments)
        ),
        "object_store_physical_measurement_valid": (
            minio_allocated >= total_payload
            and int(raw_fs.get("allocated_bytes") or 0) >= raw_all_bytes
            and int(attachment_fs.get("allocated_bytes") or 0) >= attachment_all_bytes
            and int(minio_system_fs.get("allocated_bytes") or 0) >= 0
        ),
        "raw_object_versions_cover_committed_batches": raw_workload_versions >= batches,
        "raw_content_addressed_version_multiplicity_one": int(raw.get("max_versions_per_key") or 0) <= 1,
        "gap_guard_exact_raw_object_parity_bound": gap_exact,
        "attachment_nonbootstrap_workload_observed": attachment_workload_versions > 0,
        "attachment_capacity_policy_bound": False,
    }
    if set(checks) != REQUIRED_CHECKS or any(type(value) is not bool for value in checks.values()):
        raise RuntimeError("capacity supplement check schema mismatch")
    blockers = sorted(name for name, passed in checks.items() if not passed)
    measurement_checks = {
        "bus": all(checks[name] for name in BUS_MEASUREMENT_CHECKS),
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
    result = {
        "protocol": PROTOCOL,
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "status": "PASS" if not blockers else "INCOMPLETE",
        "target_events": TARGET_EVENTS,
        "source_snapshot": postgres,
        "bus": {
            "policy_class": "full-history-hard-stop" if bus_classified_full_history else "unclassified",
            "config": config,
            "state_before": before["stream"]["state"],
            "state_after": state,
            "server": after["server"],
            "filesystem": bus_fs,
            "allocated_bytes_per_event": _ratio_json(bus_allocated, event_count),
            "projected_stream_logical_bytes_at_target": bus_projected_logical,
            "projected_physical_bytes_at_target": bus_projected_physical,
            "required_stream_logical_bytes_with_2x_headroom": required_stream_2x,
            "required_physical_bytes_with_2x_headroom": required_physical_2x,
            "physical_growth_bytes_to_2x_target": physical_growth_2x,
            "server_other_store_bytes": server_other_store,
            "server_capacity_for_stream_bytes": server_capacity_for_stream,
            "filesystem_reserve_bytes": filesystem_reserve,
            "projected_server_storage_bytes_at_2x_target": projected_server_store_used_2x,
            "projected_filesystem_used_bytes_at_2x_target": projected_filesystem_used_2x,
            "headroom": {"numerator": HEADROOM_NUMERATOR, "denominator": 1},
            "watermark_policy": {
                "high_percent": HIGH_WATERMARK_PERCENT,
                "critical_percent": CRITICAL_WATERMARK_PERCENT,
                "filesystem_reserve_percent": FILESYSTEM_RESERVE_PERCENT,
            },
            "target_capacity_admitted": all(
                checks[name] for name in BUS_TARGET_CAPACITY_ADMISSION_CHECKS
            ),
        },
        "object_store": {
            "buckets": s3_after,
            "inventory_snapshot_before": s3_before,
            "filesystem": {
                "root": minio_fs,
                "raw": raw_fs,
                "attachments": attachment_fs,
                "system": minio_system_fs,
            },
            "raw_all_versions_bytes_per_event": _ratio_json(raw_all_bytes, event_count),
            "physical_overhead_bytes": object_overhead,
            "physical_overhead_bytes_per_event": _ratio_json(object_overhead, event_count),
            "projected_physical_overhead_bytes_at_target": _ceil_ratio(object_overhead, event_count),
            "all_versions_used_not_latest_only": True,
        },
        "attachments": {
            "nonbootstrap_versions": attachment_workload_versions,
            "retained_payload_bytes": attachment_all_bytes,
            "representative_workload_observed": checks["attachment_nonbootstrap_workload_observed"],
            "capacity_policy_bound": False,
            "required_bytes_per_region": None,
            "capacity_admitted": False,
            "zero_is_not_used_as_capacity_evidence": True,
        },
        "measurement_checks": measurement_checks,
        "checks": checks,
        "blockers": blockers,
        "bindings": observed.get("bindings") or {},
        "gap_guard": observed.get("gap_guard") or {},
        "configuration_files": observed.get("configuration_files") or [],
        "artifact_sha256": observed.get("artifact_sha256") or {},
        "sparse_or_extrapolated_pass": False,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    result["evidence_sha256"] = sha256_bytes(canonical_json(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--guard-env", type=Path, default=Path("/etc/integrity-memory-p2/guard.env"))
    parser.add_argument("--minio-env", type=Path, default=Path("/etc/integrity-memory-p2/minio.env"))
    parser.add_argument("--s3-endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    parser.add_argument("--nats-monitor-endpoint", default=_integrity_value('endpoint_37a28bd31428'))
    parser.add_argument("--minio-root", type=Path, default=Path(_integrity_value('path_731bbb2bf224')))
    parser.add_argument("--nats-root", type=Path, default=Path(_integrity_value('path_a2a38cd4c8c1')))
    parser.add_argument("--nats-config", type=Path, default=Path("/etc/integrity-memory-p2/p2-nats.conf"))
    parser.add_argument("--shadow-compose", type=Path, default=Path("/etc/integrity-memory-p2/p2-shadow-compose.yaml"))
    parser.add_argument("--topology", type=Path, default=Path("/etc/integrity-memory-p2/p2-fault-domains.json"))
    parser.add_argument("--stage-admission", type=Path, required=True)
    parser.add_argument("--gap-guard-receipt", type=Path, required=True)
    parser.add_argument(
        "--receipt-root",
        type=Path,
        default=Path(_integrity_value('path_93cad4be9012')),
    )
    args = parser.parse_args()
    before = nats_snapshot(args.nats_monitor_endpoint)
    postgres = postgres_snapshot(args.guard_env)
    client = s3_client(args.minio_env, args.s3_endpoint)
    s3_before = {bucket: bucket_snapshot(client, bucket) for bucket in (RAW_BUCKET, ATTACHMENT_BUCKET)}
    filesystem = {
        "nats": tree_stats(args.nats_root),
        "minio": tree_stats(args.minio_root),
        "minio_raw": tree_stats(args.minio_root / RAW_BUCKET),
        "minio_attachments": tree_stats(args.minio_root / ATTACHMENT_BUCKET),
        "minio_system": tree_stats(args.minio_root / ".minio.sys"),
    }
    s3_after = {bucket: bucket_snapshot(client, bucket) for bucket in (RAW_BUCKET, ATTACHMENT_BUCKET)}
    after = nats_snapshot(args.nats_monitor_endpoint)
    gap_guard = gap_guard_snapshot(args.gap_guard_receipt)
    configuration_files = [
        {"path": str(path.resolve()), "sha256": sha256_file(path)}
        for path in (args.nats_config, args.shadow_compose, args.topology)
    ]
    observed = {
        "postgres": postgres,
        "nats_before": before,
        "nats_after": after,
        "s3_before": s3_before,
        "s3_after": s3_after,
        "filesystem": filesystem,
        "gap_guard": gap_guard,
        "configuration_files": configuration_files,
        "bindings": {
            "physical_stage_admission_path": str(args.stage_admission.resolve()),
            "physical_stage_admission_file_sha256": sha256_file(args.stage_admission),
            "fault_domain_topology_path": str(args.topology.resolve()),
            "fault_domain_topology_sha256": sha256_file(args.topology),
            "gap_guard_receipt_path": gap_guard["path"],
            "gap_guard_receipt_file_sha256": gap_guard["file_sha256"],
            "gap_guard_evidence_sha256": gap_guard["evidence_sha256"],
        },
        "artifact_sha256": {
            "capacity_supplement": sha256_file(Path(__file__).resolve()),
            "billion_capacity": sha256_file(Path(__file__).resolve().parent / "p2_billion_capacity.py"),
            "compact_billion_gate": sha256_file(Path(__file__).resolve().parent / "p2_compact_billion_gate.py"),
        },
    }
    result = evaluate(observed)
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    path = args.receipt_root / f"capacity-supplement-{stamp}-{result['evidence_sha256'][:16]}.json"
    atomic_json(path, result, mode=0o440)
    print(json.dumps({**result, "receipt_path": str(path)}, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
