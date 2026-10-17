#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Relay one canonical Action Log page into the non-authoritative P2 shadow."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import asyncio
import gzip
import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request

import boto3
import nats
import psycopg
from botocore.client import Config
from botocore.exceptions import ClientError
from nats.js.errors import APIError, NotFoundError
from psycopg.types.json import Jsonb

from memory_plane_common import (
    action_log_reader_headers,
    atomic_json,
    canonical_json,
    exclusive_lock,
    open_direct_http_request,
    sha256_bytes,
    sha256_file,
    validate_action_log_reader_url,
)

RAW_PLANE_LOCK = Path(_integrity_value('path_13faba5553a5'))
from p2_contract import Envelope, ack_decision, build_batch


STATE_PROTOCOL = "integrity-memory-plane.p2-edge-state.v1"
SOURCE_PROTOCOL = "integrity-memory-plane.p2-source-snapshot.v1"
OBJECT_PROTOCOL = "integrity-memory-plane.p2-raw-object.v1"
RECEIPT_PROTOCOL = "integrity-memory-plane.p2-relay-receipt.v1"
INTENT_PROTOCOL = "integrity-memory-plane.p2-edge-intent.v1"
BUS_PROTOCOL = "integrity-memory-plane.p2-bus-manifest.v1"
TENANT_ID = "workspace"
NAMESPACE = _integrity_value('seed_namespace')
EDGE_ID = "source-linux-action-log"
STREAM = "INTEGRITY_P2_RAW"
RAW_BUCKET = "integrity-p2-raw"
BUS_HIGH_WATERMARK_PERCENT = 80
BUS_CRITICAL_WATERMARK_PERCENT = 90
BUS_RECOVERY_WATERMARK_PERCENT = 70


class BusBackpressureError(RuntimeError):
    def __init__(self, reason_code: str, evidence: dict[str, Any]):
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.evidence = evidence


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def bus_pressure_observation(config: Any, state: Any, *, next_message_bytes: int = 0) -> dict[str, Any]:
    max_bytes = int(config.max_bytes or 0)
    used_bytes = int(state.bytes or 0)
    if type(next_message_bytes) is not int or next_message_bytes < 0:
        raise RuntimeError("next bus message reserve must be a non-negative integer")
    projected_used_bytes = used_bytes + next_message_bytes
    contract = {
        "retention_limits": _enum_value(config.retention) == "limits",
        "discard_new": _enum_value(config.discard) == "new",
        "max_msgs_unbounded": int(config.max_msgs) == -1,
        "max_age_unbounded": int(config.max_age or 0) == 0,
        "max_msgs_per_subject_unbounded": int(config.max_msgs_per_subject) == -1,
        "max_bytes_positive": max_bytes > 0,
        "deny_delete": config.deny_delete is True,
        "deny_purge": config.deny_purge is True,
        "no_ack_false": config.no_ack is False,
        "sealed_false": config.sealed is False,
    }
    failed = sorted(name for name, passed in contract.items() if passed is not True)
    if failed:
        raise RuntimeError("JetStream full-history contract drift: " + ",".join(failed))
    if used_bytes < 0 or used_bytes > max_bytes:
        raise RuntimeError("JetStream byte counters are outside the configured capacity")
    if projected_used_bytes * 100 >= max_bytes * BUS_CRITICAL_WATERMARK_PERCENT:
        pressure = "critical"
    elif projected_used_bytes * 100 >= max_bytes * BUS_HIGH_WATERMARK_PERCENT:
        pressure = "high"
    elif used_bytes * 100 < max_bytes * BUS_RECOVERY_WATERMARK_PERCENT:
        pressure = "normal"
    else:
        pressure = "hysteresis"
    return {
        "stream": STREAM,
        "used_bytes": used_bytes,
        "next_message_reserve_bytes": next_message_bytes,
        "projected_used_bytes": projected_used_bytes,
        "max_bytes": max_bytes,
        "messages": int(state.messages or 0),
        "pressure": pressure,
        "high_watermark_percent": BUS_HIGH_WATERMARK_PERCENT,
        "critical_watermark_percent": BUS_CRITICAL_WATERMARK_PERCENT,
        "recovery_watermark_percent": BUS_RECOVERY_WATERMARK_PERCENT,
        "full_history_contract": contract,
    }


async def preflight_bus(env: dict[str, str], server: str, batch: dict[str, Any], intent: dict[str, Any]) -> dict[str, Any]:
    client = await nats.connect(
        servers=[server],
        user=env["NATS_RELAY_USER"],
        password=env["NATS_RELAY_PASSWORD"],
        name="integrity-p2-edge-relay-preflight",
        connect_timeout=3,
        max_reconnect_attempts=0,
        allow_reconnect=False,
    )
    try:
        jetstream = client.jetstream(timeout=5)
        try:
            info = await jetstream.stream_info(STREAM)
        except NotFoundError as error:
            raise RuntimeError("required JetStream shadow stream is missing") from error
        if info.config.num_replicas != 1:
            raise RuntimeError("shadow relay expected the explicit R1 stream")
        observation = bus_pressure_observation(info.config, info.state, next_message_bytes=int(info.config.max_msg_size or 0))
        if observation["pressure"] in {"high", "critical"}:
            raise BusBackpressureError(
                "STREAM_CRITICAL_WATERMARK" if observation["pressure"] == "critical" else "STREAM_HIGH_WATERMARK",
                {
                    "batch_sha256": batch["batch_sha256"],
                    "first_cursor": batch["first_cursor"],
                    "last_cursor": batch["last_cursor"],
                    "intent_path": intent["intent_path"],
                    "intent_sha256": intent["intent_sha256"],
                    "bus": observation,
                },
            )
        return observation
    finally:
        await client.drain()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key:
            raise RuntimeError(f"invalid environment line in {path}")
        result[key] = value
    return result


def http_json(base_url: str, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    resolved_base_url = validate_action_log_reader_url(base_url)
    query = "?" + urlencode(params or {}) if params else ""
    request = Request(
        resolved_base_url + path + query,
        headers={"Accept": "application/json", **action_log_reader_headers()},
        method="GET",
    )
    with open_direct_http_request(request, timeout=8) as response:
        if response.status != 200:
            raise RuntimeError(f"Action Log read API returned HTTP {response.status}")
        value = json.load(response)
    if not isinstance(value, dict):
        raise RuntimeError("Action Log read API returned a non-object")
    return value


def initial_state() -> dict[str, Any]:
    return {
        "protocol": STATE_PROTOCOL,
        "tenant_id": TENANT_ID,
        "namespace": NAMESPACE,
        "edge_id": EDGE_ID,
        "last_cursor": 0,
        "processed_event_count": 0,
        "last_source_payload_sha256": "",
        "last_envelope_sha256": "",
        "last_batch_sha256": "",
        "batch_count": 0,
        "production_authority": False,
    }


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return initial_state()
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("protocol") != STATE_PROTOCOL:
        raise RuntimeError("edge state protocol mismatch")
    if (value.get("tenant_id"), value.get("namespace"), value.get("edge_id")) != (
        TENANT_ID,
        NAMESPACE,
        EDGE_ID,
    ):
        raise RuntimeError("edge state identity mismatch")
    if value.get("production_authority") is not False:
        raise RuntimeError("edge state attempted to claim production authority")
    return value


def payload_digest(event: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(event))


def transport_event_uid(event: dict[str, Any], digest: str) -> tuple[str, str]:
    canonical_uid = str(event.get("event_uid") or "").strip()
    if canonical_uid:
        return canonical_uid, "canonical"
    cursor = int(event["id"])
    return f"legacy-action-log-{cursor}-{digest[:32]}", "derived_legacy_empty"


def verify_previous_source_event(base_url: str, state: dict[str, Any]) -> None:
    cursor = int(state["last_cursor"])
    if cursor == 0:
        return
    value = http_json(base_url, "/api/events", {"id": cursor})
    events = value.get("events") or []
    if len(events) != 1 or int(events[0].get("id") or 0) != cursor:
        raise RuntimeError("previously relayed Action Log cursor disappeared")
    if payload_digest(events[0]) != state["last_source_payload_sha256"]:
        raise RuntimeError("previously relayed Action Log payload changed")


def fetch_source_page(
    base_url: str, state: dict[str, Any], page_size: int
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    health = http_json(base_url, "/api/health")
    if health.get("service") != "codex-action-log" or health.get("append_only") is not True:
        raise RuntimeError("Action Log append-only health contract is unavailable")
    if health.get("cursor_pagination") is not True:
        raise RuntimeError("Action Log cursor pagination is unavailable")
    verify_previous_source_event(base_url, state)
    page = http_json(
        base_url,
        "/api/events",
        {
            "page_size": page_size,
            "after_id": int(state["last_cursor"]),
            "order": "asc",
            "since": "1970-01-01T00:00:00Z",
        },
    )
    pagination = page.get("pagination") or {}
    events = page.get("events") or []
    if not isinstance(events, list):
        raise RuntimeError("Action Log events page has invalid shape")
    cursors = [int(event.get("id") or 0) for event in events]
    if cursors != sorted(cursors) or len(cursors) != len(set(cursors)) or any(cursor <= int(state["last_cursor"]) for cursor in cursors):
        raise RuntimeError("Action Log page ordering contract failed")
    source_manifest = {
        "protocol": SOURCE_PROTOCOL,
        "source_service": "codex-action-log",
        "source_append_only": True,
        "source_update_enabled": bool(health.get("update_enabled", False)),
        "source_delete_enabled": bool(health.get("delete_enabled", False)),
        "selection_after_cursor": int(state["last_cursor"]),
        "selected_first_cursor": cursors[0] if cursors else 0,
        "selected_last_cursor": cursors[-1] if cursors else int(state["last_cursor"]),
        "selected_event_count": len(events),
        "normalized_api_payload_sha256": sha256_bytes(canonical_json(events)),
        "natural_cursor_gaps": [
            missing
            for previous, current in zip([int(state["last_cursor"]), *cursors[:-1]], cursors)
            for missing in range(previous + 1, current)
        ],
    }
    source_observation = {
        "captured_utc": utc_now(),
        "source_service_version": str(health.get("service_version") or ""),
        "snapshot_event_id": int(pagination.get("snapshot_event_id") or 0),
        "source_event_count_observed": int(health.get("events") or 0),
        "has_more": bool(pagination.get("has_more")),
    }
    return source_manifest, source_observation, events


def build_raw_object(source_manifest: dict[str, Any], batch: dict[str, Any]) -> tuple[bytes, str]:
    header = {
        "protocol": OBJECT_PROTOCOL,
        "source_manifest": source_manifest,
        "batch_manifest": {key: value for key, value in batch.items() if key not in {"envelopes"}},
    }
    plaintext = b"\n".join([canonical_json(header), *(canonical_json(value) for value in batch["envelopes"])]) + b"\n"
    compressed = gzip.compress(plaintext, compresslevel=6, mtime=0)
    return compressed, sha256_bytes(compressed)


def load_or_create_intent(args: argparse.Namespace, state: dict[str, Any]) -> dict[str, Any] | None:
    prefix = f"intent-after-{int(state['last_cursor']):020d}-"
    candidates = sorted(args.intents.glob(prefix + "*.json"))
    if len(candidates) > 1:
        raise RuntimeError("multiple edge intents exist for one state cursor")
    if candidates:
        intent = json.loads(candidates[0].read_text(encoding="utf-8"))
        if intent.get("protocol") != INTENT_PROTOCOL:
            raise RuntimeError("edge intent protocol mismatch")
        binding = intent.get("state_before") or {}
        if (
            int(binding.get("last_cursor") or 0) != int(state["last_cursor"])
            or str(binding.get("last_envelope_sha256") or "") != str(state.get("last_envelope_sha256") or "")
            or str(binding.get("last_batch_sha256") or "") != str(state.get("last_batch_sha256") or "")
        ):
            raise RuntimeError("edge intent state binding mismatch")
        source_manifest = intent["source_manifest"]
        batch = intent["batch"]
        if sha256_bytes(canonical_json(source_manifest)) != intent["source_manifest_sha256"]:
            raise RuntimeError("edge intent source manifest digest mismatch")
        raw_body, raw_content_sha = build_raw_object(source_manifest, batch)
        if raw_content_sha != intent["raw_content_sha256"]:
            raise RuntimeError("edge intent raw object digest mismatch")
        if batch["batch_sha256"] not in candidates[0].name:
            raise RuntimeError("edge intent filename digest mismatch")
        intent["intent_path"] = str(candidates[0])
        intent["intent_sha256"] = sha256_file(candidates[0])
        intent["raw_body"] = raw_body
        return intent

    source_manifest, source_observation, events = fetch_source_page(args.action_log_url, state, args.batch_size)
    if not events:
        return None
    source_sha = sha256_bytes(canonical_json(source_manifest))
    previous_envelope = str(state.get("last_envelope_sha256") or "")
    envelopes: list[Envelope] = []
    for event in events:
        digest = payload_digest(event)
        event_uid, _origin = transport_event_uid(event, digest)
        envelope = Envelope(
            tenant_id=TENANT_ID,
            namespace=NAMESPACE,
            edge_id=EDGE_ID,
            cursor=int(event["id"]),
            event_uid=event_uid,
            ts_utc=str(event["ts_utc"]),
            payload=event,
            source_manifest_sha256=source_sha,
            previous_envelope_sha256=previous_envelope,
        )
        previous_envelope = envelope.value()["envelope_sha256"]
        envelopes.append(envelope)
    batch = build_batch(envelopes, previous_batch_sha256=str(state.get("last_batch_sha256") or ""))
    raw_body, raw_content_sha = build_raw_object(source_manifest, batch)
    intent_path = args.intents / (
        f"intent-after-{int(state['last_cursor']):020d}-batch-{batch['batch_sha256']}.json"
    )
    intent = {
        "protocol": INTENT_PROTOCOL,
        "created_utc": utc_now(),
        "state_before": {
            "last_cursor": int(state["last_cursor"]),
            "last_envelope_sha256": str(state.get("last_envelope_sha256") or ""),
            "last_batch_sha256": str(state.get("last_batch_sha256") or ""),
        },
        "source_manifest": source_manifest,
        "source_manifest_sha256": source_sha,
        "source_observation": source_observation,
        "batch": batch,
        "last_envelope_sha256": previous_envelope,
        "raw_content_sha256": raw_content_sha,
        "production_authority": False,
    }
    atomic_json(intent_path, intent, mode=0o400)
    intent["intent_path"] = str(intent_path)
    intent["intent_sha256"] = sha256_file(intent_path)
    intent["raw_body"] = raw_body
    return intent


def s3_client(env: dict[str, str], endpoint: str) -> Any:
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=env["MINIO_ACCESS_KEY"],
        aws_secret_access_key=env["MINIO_SECRET_KEY"],
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 2}),
    )


def exact_versions(client: Any, key: str) -> list[dict[str, Any]]:
    response = client.list_object_versions(Bucket=RAW_BUCKET, Prefix=key)
    return [version for version in response.get("Versions", []) if version.get("Key") == key]


def verify_raw_version(client: Any, key: str, version_id: str, content_sha256: str, batch_sha256: str) -> dict[str, Any]:
    head = client.head_object(Bucket=RAW_BUCKET, Key=key, VersionId=version_id)
    if (head.get("Metadata") or {}).get("sha256") != content_sha256:
        raise RuntimeError("raw object metadata digest mismatch")
    if (head.get("Metadata") or {}).get("batch-sha256") != batch_sha256:
        raise RuntimeError("raw object batch digest mismatch")
    retention = client.get_object_retention(Bucket=RAW_BUCKET, Key=key, VersionId=version_id).get("Retention") or {}
    if retention.get("Mode") != "COMPLIANCE" or not retention.get("RetainUntilDate"):
        raise RuntimeError("raw object COMPLIANCE retention is missing")
    body = client.get_object(Bucket=RAW_BUCKET, Key=key, VersionId=version_id)["Body"].read()
    if sha256_bytes(body) != content_sha256:
        raise RuntimeError("raw object exact-version readback mismatch")
    return {
        "bucket": RAW_BUCKET,
        "key": key,
        "version_id": version_id,
        "content_sha256": content_sha256,
        "readback_sha256": content_sha256,
        "retention_mode": "COMPLIANCE",
        "retain_until_utc": retention["RetainUntilDate"].astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def put_raw_once(client: Any, key: str, body: bytes, content_sha256: str, batch: dict[str, Any]) -> dict[str, Any]:
    versions = exact_versions(client, key)
    if len(versions) > 1:
        raise RuntimeError("multiple raw object versions violate content-addressed idempotency")
    if versions:
        return verify_raw_version(client, key, str(versions[0]["VersionId"]), content_sha256, batch["batch_sha256"])
    try:
        response = client.put_object(
            Bucket=RAW_BUCKET,
            Key=key,
            Body=body,
            ContentType="application/x-ndjson",
            ContentEncoding="gzip",
            IfNoneMatch="*",
            Metadata={
                "sha256": content_sha256,
                "batch-sha256": batch["batch_sha256"],
                "first-cursor": str(batch["first_cursor"]),
                "last-cursor": str(batch["last_cursor"]),
            },
        )
        version_id = str(response.get("VersionId") or "")
    except ClientError as error:
        status = int(error.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0))
        if status not in {409, 412}:
            raise
        versions = exact_versions(client, key)
        if len(versions) != 1:
            raise RuntimeError("conditional raw PUT raced without one reusable version") from error
        version_id = str(versions[0]["VersionId"])
    if not version_id or version_id == "null":
        raise RuntimeError("raw PUT did not return a version ID")
    return verify_raw_version(client, key, version_id, content_sha256, batch["batch_sha256"])


def subject_token(value: str) -> str:
    token = re.sub(r"[^A-Za-z0-9_-]+", "_", value).strip("_")
    return token[:80] if token else "sha256_" + sha256_bytes(value.encode("utf-8"))[:32]


async def publish_bus(env: dict[str, str], server: str, batch: dict[str, Any], raw: dict[str, Any]) -> dict[str, Any]:
    subject = ".".join(
        ["integrity", "p2", "raw", subject_token(TENANT_ID), subject_token(NAMESPACE), subject_token(EDGE_ID)]
    )
    manifest = {
        "protocol": BUS_PROTOCOL,
        "tenant_id": TENANT_ID,
        "namespace": NAMESPACE,
        "edge_id": EDGE_ID,
        "first_cursor": batch["first_cursor"],
        "last_cursor": batch["last_cursor"],
        "event_count": batch["event_count"],
        "batch_sha256": batch["batch_sha256"],
        "previous_batch_sha256": batch["previous_batch_sha256"],
        "raw_object": raw,
        "production_authority": False,
    }
    body = canonical_json(manifest)
    body_sha256 = sha256_bytes(body)
    client = await nats.connect(
        servers=[server],
        user=env["NATS_RELAY_USER"],
        password=env["NATS_RELAY_PASSWORD"],
        name="integrity-p2-edge-relay",
        connect_timeout=3,
        max_reconnect_attempts=0,
        allow_reconnect=False,
    )
    try:
        jetstream = client.jetstream(timeout=5)
        try:
            info = await jetstream.stream_info(STREAM)
        except NotFoundError as error:
            raise RuntimeError("required JetStream shadow stream is missing") from error
        if info.config.num_replicas != 1:
            raise RuntimeError("shadow relay expected the explicit R1 stream")
        observation = bus_pressure_observation(info.config, info.state, next_message_bytes=len(body))
        if observation["pressure"] in {"high", "critical"}:
            raise BusBackpressureError(
                "STREAM_CRITICAL_WATERMARK" if observation["pressure"] == "critical" else "STREAM_HIGH_WATERMARK",
                {"batch_sha256": batch["batch_sha256"], "raw_object": raw, "bus": observation},
            )
        try:
            ack = await jetstream.publish(
                subject,
                body,
                headers={"Nats-Msg-Id": batch["batch_sha256"], "Integrity-Payload-SHA256": body_sha256},
                timeout=5,
                stream=STREAM,
            )
        except APIError as error:
            description = str(error.description or "").lower()
            if "maximum" in description and ("byte" in description or "message" in description):
                raise BusBackpressureError(
                    "STREAM_PUBLISH_CAPACITY_REJECTED",
                    {
                        "batch_sha256": batch["batch_sha256"],
                        "raw_object": raw,
                        "bus": observation,
                        "nats_error_code": error.err_code,
                        "nats_description": str(error.description or "")[:300],
                    },
                ) from error
            raise
        message = await jetstream.get_msg(STREAM, seq=ack.seq, direct=True)
        if sha256_bytes(message.data) != body_sha256:
            raise RuntimeError("bus direct readback digest mismatch")
        return {
            "stream": ack.stream,
            "sequence": ack.seq,
            "duplicate": bool(ack.duplicate),
            "subject": subject,
            "payload_sha256": body_sha256,
            "readback_sha256": body_sha256,
            "replicas": 1,
            "fault_domains": 1,
            "pre_publish_capacity": observation,
        }
    finally:
        await client.drain()


def event_metadata(event: dict[str, Any], uid_origin: str) -> dict[str, Any]:
    return {
        "source": "codex-action-log-api",
        "source_event_id": int(event["id"]),
        "event_uid_origin": uid_origin,
        "actor": str(event.get("actor") or ""),
        "session_id": str(event.get("session_id") or ""),
        "level": str(event.get("level") or ""),
        "action": str(event.get("action") or ""),
        "tags": event.get("tags") if isinstance(event.get("tags"), list) else [],
        "production_authority": False,
    }


def postgres_crash_after(event_count: int, enabled: bool) -> int:
    """Return the explicit lab-only crash boundary inside one transaction."""

    return max(1, int(event_count) // 2) if enabled else 0


def commit_postgres(
    env: dict[str, str],
    host: str,
    batch: dict[str, Any],
    raw: dict[str, Any],
    bus: dict[str, Any],
    source_sha: str,
    *,
    crash_after_events: int = 0,
) -> dict[str, Any]:
    inserted_events = 0
    with psycopg.connect(
        host=host,
        port=55432,
        user=env["POSTGRES_RELAY_USER"],
        password=env["POSTGRES_RELAY_PASSWORD"],
        dbname=env["POSTGRES_RELAY_DB"],
        connect_timeout=5,
    ) as connection:
        with connection.transaction():
            for envelope in batch["envelopes"]:
                event = envelope["payload"]
                origin = "canonical" if str(event.get("event_uid") or "").strip() else "derived_legacy_empty"
                cursor_bucket = int(envelope["cursor"]) // 1_000_000
                time_bucket = datetime.fromisoformat(str(envelope["ts_utc"]).replace("Z", "+00:00")).date()
                result = connection.execute(
                    """
                    INSERT INTO integrity_p2.raw_events(
                      tenant_id,namespace,edge_id,cursor,event_uid,ts_utc,time_bucket,cursor_bucket,
                      payload_sha256,envelope_sha256,previous_envelope_sha256,source_manifest_sha256,
                      batch_sha256,raw_object_key,raw_object_version,metadata
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT DO NOTHING
                    """,
                    (
                        TENANT_ID,
                        NAMESPACE,
                        EDGE_ID,
                        int(envelope["cursor"]),
                        envelope["event_uid"],
                        envelope["ts_utc"],
                        time_bucket,
                        cursor_bucket,
                        envelope["payload_sha256"],
                        envelope["envelope_sha256"],
                        envelope["previous_envelope_sha256"],
                        source_sha,
                        batch["batch_sha256"],
                        raw["key"],
                        raw["version_id"],
                        Jsonb(event_metadata(event, origin)),
                    ),
                )
                inserted_events += max(0, result.rowcount)
                if crash_after_events and inserted_events >= crash_after_events:
                    # Deliberately bypass Python cleanup: the server must see a
                    # broken client while the transaction is still open.  This
                    # path is reachable only through the explicit lab flag.
                    os._exit(97)
                stored = connection.execute(
                    """
                    SELECT cursor,event_uid,payload_sha256,envelope_sha256,previous_envelope_sha256,
                           source_manifest_sha256,batch_sha256,raw_object_key,raw_object_version
                    FROM integrity_p2.raw_events
                    WHERE tenant_id=%s AND namespace=%s AND edge_id=%s AND cursor=%s
                    """,
                    (TENANT_ID, NAMESPACE, EDGE_ID, int(envelope["cursor"])),
                ).fetchone()
                expected = (
                    int(envelope["cursor"]),
                    envelope["event_uid"],
                    envelope["payload_sha256"],
                    envelope["envelope_sha256"],
                    envelope["previous_envelope_sha256"],
                    source_sha,
                    batch["batch_sha256"],
                    raw["key"],
                    raw["version_id"],
                )
                normalized_stored = tuple(stored) if stored is not None else None
                if normalized_stored is not None and not envelope["previous_envelope_sha256"]:
                    normalized_stored = (*normalized_stored[:4], str(normalized_stored[4]).rstrip(), *normalized_stored[5:])
                if normalized_stored != expected:
                    raise RuntimeError(f"PostgreSQL raw event collision at cursor {envelope['cursor']}")

            result = connection.execute(
                """
                INSERT INTO integrity_p2.ingest_batches(
                  tenant_id,namespace,edge_id,first_cursor,last_cursor,event_count,batch_sha256,
                  previous_batch_sha256,raw_object_key,raw_object_version,bus_stream,bus_sequence,
                  bus_replicas,fault_domains
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT DO NOTHING
                """,
                (
                    TENANT_ID,
                    NAMESPACE,
                    EDGE_ID,
                    batch["first_cursor"],
                    batch["last_cursor"],
                    batch["event_count"],
                    batch["batch_sha256"],
                    batch["previous_batch_sha256"],
                    raw["key"],
                    raw["version_id"],
                    bus["stream"],
                    bus["sequence"],
                    bus["replicas"],
                    bus["fault_domains"],
                ),
            )
            inserted_batch = max(0, result.rowcount)
            stored_batch = connection.execute(
                """
                SELECT last_cursor,event_count,batch_sha256,previous_batch_sha256,raw_object_key,
                       raw_object_version,bus_stream,bus_sequence,bus_replicas,fault_domains
                FROM integrity_p2.ingest_batches
                WHERE tenant_id=%s AND namespace=%s AND edge_id=%s AND first_cursor=%s
                """,
                (TENANT_ID, NAMESPACE, EDGE_ID, batch["first_cursor"]),
            ).fetchone()
            expected_batch = (
                batch["last_cursor"],
                batch["event_count"],
                batch["batch_sha256"],
                batch["previous_batch_sha256"],
                raw["key"],
                raw["version_id"],
                bus["stream"],
                bus["sequence"],
                bus["replicas"],
                bus["fault_domains"],
            )
            normalized_batch = tuple(stored_batch) if stored_batch is not None else None
            if normalized_batch is not None and not batch["previous_batch_sha256"]:
                normalized_batch = (*normalized_batch[:3], str(normalized_batch[3]).rstrip(), *normalized_batch[4:])
            if normalized_batch != expected_batch:
                raise RuntimeError("PostgreSQL batch collision")
    return {
        "transaction_committed": True,
        "events_inserted": inserted_events,
        "events_verified": batch["event_count"],
        "batch_inserted": inserted_batch,
        "batch_verified": True,
        "production_authority": False,
    }


def quarantine(root: Path, reason: str, evidence: dict[str, Any]) -> Path:
    path = root / f"quarantine-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4()}.json"
    atomic_json(
        path,
        {
            "protocol": "integrity-memory-plane.p2-quarantine.v1",
            "created_utc": utc_now(),
            "reason": reason,
            "evidence": evidence,
            "production_authority": False,
        },
        mode=0o400,
    )
    return path


def record_backpressure_once(root: Path, error: BusBackpressureError) -> tuple[Path, bool]:
    batch_sha = str(error.evidence.get("batch_sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", batch_sha):
        raise RuntimeError("backpressure evidence has no bound batch digest")
    reason = re.sub(r"[^A-Z0-9_]+", "_", error.reason_code).strip("_")
    path = root / f"blocked-{reason}-{batch_sha}.json"
    value = {
        "protocol": "integrity-memory-plane.p2-backpressure.v1.receipt",
        "created_utc": utc_now(),
        "status": "BLOCKED_BACKPRESSURE",
        "reason_code": error.reason_code,
        "batch_sha256": batch_sha,
        "evidence": error.evidence,
        "source_cursor_advanced": False,
        "postgres_committed": False,
        "intent_preserved": True,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    value["evidence_sha256"] = sha256_bytes(canonical_json(value))
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8"))
        unsigned = dict(existing)
        claimed = str(unsigned.pop("evidence_sha256", ""))
        if (
            claimed != sha256_bytes(canonical_json(unsigned))
            or existing.get("protocol") != value["protocol"]
            or existing.get("status") != value["status"]
            or existing.get("reason_code") != value["reason_code"]
            or existing.get("batch_sha256") != batch_sha
            or (existing.get("evidence") or {}).get("intent_sha256")
            != (value.get("evidence") or {}).get("intent_sha256")
            or existing.get("source_cursor_advanced") is not False
            or existing.get("postgres_committed") is not False
            or existing.get("intent_preserved") is not True
            or existing.get("production_authority") is not False
            or existing.get("memory_grants_authority") is not False
        ):
            raise RuntimeError("existing backpressure receipt conflicts with current blocked batch")
        return path, True
    atomic_json(path, value, mode=0o400)
    return path, False


def process_one(args: argparse.Namespace) -> dict[str, Any]:
    state = load_state(args.state)
    intent = load_or_create_intent(args, state)
    if intent is None:
        _, source_observation, _ = fetch_source_page(args.action_log_url, state, args.batch_size)
        return {
            "protocol": RECEIPT_PROTOCOL,
            "status": "noop",
            "last_cursor": int(state["last_cursor"]),
            "snapshot_event_id": source_observation["snapshot_event_id"],
            "production_authority": False,
        }
    source_manifest = intent["source_manifest"]
    source_sha = intent["source_manifest_sha256"]
    batch = intent["batch"]
    events = [envelope["payload"] for envelope in batch["envelopes"]]
    previous_envelope = intent["last_envelope_sha256"]
    raw_body = intent.pop("raw_body")
    raw_content_sha = intent["raw_content_sha256"]
    if args.fail_after == "intent":
        raise RuntimeError("injected failpoint after intent")
    minio_env = load_env(args.minio_env)
    shadow_env = load_env(args.shadow_env)
    asyncio.run(preflight_bus(shadow_env, args.nats_server, batch, intent))
    raw = put_raw_once(s3_client(minio_env, args.s3_endpoint), batch["object_key"], raw_body, raw_content_sha, batch)
    if args.fail_after == "s3":
        raise RuntimeError("injected failpoint after s3")
    bus = asyncio.run(publish_bus(shadow_env, args.nats_server, batch, raw))
    if args.fail_after == "bus":
        raise RuntimeError("injected failpoint after bus")
    postgres = commit_postgres(
        shadow_env,
        args.postgres_host,
        batch,
        raw,
        bus,
        source_sha,
        crash_after_events=postgres_crash_after(batch["event_count"], args.fail_after == "postgres-mid-crash"),
    )
    if args.fail_after == "postgres":
        raise RuntimeError("injected failpoint after postgres")
    decision = ack_decision(
        chain_contiguous=True,
        worm_primary_readback=True,
        bus_replicas=bus["replicas"],
        bus_fault_domains=bus["fault_domains"],
        offhost_readback=False,
        uid_collision_count=0,
        shadow_mode=True,
    )
    receipt = {
        "protocol": RECEIPT_PROTOCOL,
        "created_utc": utc_now(),
        "status": "shadow_pipeline_committed",
        "tenant_id": TENANT_ID,
        "namespace": NAMESPACE,
        "edge_id": EDGE_ID,
        "source_manifest": source_manifest,
        "source_observation": intent["source_observation"],
        "source_manifest_sha256": source_sha,
        "edge_intent": {
            "path": intent["intent_path"],
            "sha256": intent["intent_sha256"],
        },
        "batch": {key: value for key, value in batch.items() if key != "envelopes"},
        "last_envelope_sha256": previous_envelope,
        "raw": raw,
        "bus": bus,
        "postgres": postgres,
        "ack_decision": decision,
        "edge_ack_unchanged": True,
        "action_log_authority_mutation_count": 0,
        "production_authority": False,
    }
    receipt_path = args.receipts / f"batch-{batch['batch_sha256']}.json"
    if receipt_path.exists():
        existing = json.loads(receipt_path.read_text(encoding="utf-8"))
        immutable_paths = (
            existing.get("batch", {}).get("batch_sha256") == batch["batch_sha256"],
            existing.get("raw", {}).get("version_id") == raw["version_id"],
            existing.get("bus", {}).get("sequence") == bus["sequence"],
            existing.get("postgres", {}).get("transaction_committed") is True,
        )
        if not all(immutable_paths):
            raise RuntimeError("existing relay receipt conflicts with recovered stages")
    else:
        # The setgid receipt directory is shared read-only with independent
        # projection workers.  Intents/state remain private to the relay.
        atomic_json(receipt_path, receipt, mode=0o440)
    if args.fail_after == "receipt":
        raise RuntimeError("injected failpoint after receipt")
    next_state = {
        **initial_state(),
        "last_cursor": batch["last_cursor"],
        "processed_event_count": int(state.get("processed_event_count") or 0) + batch["event_count"],
        "last_source_payload_sha256": payload_digest(events[-1]),
        "last_envelope_sha256": previous_envelope,
        "last_batch_sha256": batch["batch_sha256"],
        "batch_count": int(state.get("batch_count") or 0) + 1,
        "last_receipt": str(receipt_path),
        "last_receipt_sha256": sha256_file(receipt_path),
        "updated_utc": utc_now(),
    }
    atomic_json(args.state, next_state, mode=0o600)
    receipt["receipt_path"] = str(receipt_path)
    receipt["receipt_sha256"] = next_state["last_receipt_sha256"]
    receipt["next_state"] = next_state
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--action-log-url", default=_integrity_value('endpoint_72b0e86b156f'))
    parser.add_argument("--batch-size", type=int, default=200)
    parser.add_argument("--state", type=Path, default=Path(_integrity_value('path_9b0a73c6e071')))
    parser.add_argument("--receipts", type=Path, default=Path(_integrity_value('path_f5a9a1727fe8')))
    parser.add_argument("--intents", type=Path, default=Path(_integrity_value('path_fbea448fef79')))
    parser.add_argument("--quarantine", type=Path, default=Path(_integrity_value('path_6e77c79d3982')))
    parser.add_argument("--backpressure", type=Path, default=Path(_integrity_value('path_9f38c0c82693')))
    parser.add_argument(
        "--lock",
        type=Path,
        default=RAW_PLANE_LOCK,
    )
    parser.add_argument("--minio-env", type=Path, default=Path("/etc/integrity-memory-p2/relay-minio.env"))
    parser.add_argument("--shadow-env", type=Path, default=Path("/etc/integrity-memory-p2/relay-shadow.env"))
    parser.add_argument("--s3-endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    parser.add_argument("--nats-server", default="nats://127.0.0.1:4222")
    parser.add_argument("--postgres-host", default="127.0.0.1")
    parser.add_argument("--fail-after", choices=("", "intent", "s3", "bus", "postgres-mid-crash", "postgres", "receipt"), default="")
    args = parser.parse_args()
    if not 1 <= args.batch_size <= 200:
        raise SystemExit("batch-size must be between 1 and the Action Log API cap 200")
    args.receipts.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.intents.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.quarantine.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.backpressure.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        with exclusive_lock(args.lock, wait_seconds=120):
            result = process_one(args)
    except BusBackpressureError as error:
        path, reused = record_backpressure_once(args.backpressure, error)
        print(
            json.dumps(
                {
                    "ok": False,
                    "status": "BLOCKED_BACKPRESSURE",
                    "reason_code": error.reason_code,
                    "receipt": str(path),
                    "reused": reused,
                    "source_cursor_advanced": False,
                    "postgres_committed": False,
                    "intent_preserved": True,
                },
                sort_keys=True,
            )
        )
        return 0
    except Exception as error:
        path = quarantine(
            args.quarantine,
            type(error).__name__,
            {"message": str(error)[:1000], "state_path": str(args.state), "batch_size": args.batch_size},
        )
        print(json.dumps({"ok": False, "quarantine": str(path), "error": type(error).__name__}, sort_keys=True))
        raise
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
