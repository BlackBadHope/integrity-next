#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Create and verify the non-authoritative Integrity P2 JetStream contract."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import asyncio
import hashlib
import json
import os
import tempfile
from dataclasses import fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import nats
from nats.js.api import (
    DiscardPolicy,
    PersistMode,
    RetentionPolicy,
    StorageType,
    StoreCompression,
    StreamConfig,
)
from nats.js.errors import NotFoundError


STREAM = "INTEGRITY_P2_RAW"
SUBJECT_PATTERN = "integrity.p2.raw.*.*.*"
SMOKE_SUBJECT = "integrity.p2.raw.bootstrap.seed.shadow"
# Capacity-admission contract.  Keep these as exact byte counts so neither
# NATS configuration suffix parsing nor decimal/binary unit ambiguity can
# silently reduce the measured 2x headroom.
MAX_BYTES = 111_669_149_696  # 104 GiB
SERVER_MAX_FILE_STORE_BYTES = 120_259_084_288  # 112 GiB
DUPLICATE_WINDOW_SECONDS = 24 * 60 * 60
STREAM_CONFIG_FIELD_ALLOWLIST = frozenset(
    {
        "name",
        "description",
        "subjects",
        "retention",
        "max_consumers",
        "max_msgs",
        "max_bytes",
        "discard",
        "discard_new_per_subject",
        "max_age",
        "max_msgs_per_subject",
        "max_msg_size",
        "storage",
        "num_replicas",
        "no_ack",
        "template_owner",
        "duplicate_window",
        "placement",
        "mirror",
        "sources",
        "sealed",
        "deny_delete",
        "deny_purge",
        "allow_rollup_hdrs",
        "first_seq",
        "republish",
        "subject_transform",
        "allow_direct",
        "mirror_direct",
        "compression",
        "allow_msg_ttl",
        "allow_msg_schedules",
        "allow_atomic",
        "allow_batched",
        "persist_mode",
        "metadata",
        "consumer_limits",
        "subject_delete_marker_ttl",
    }
)


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


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o640)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def expected_config() -> StreamConfig:
    return StreamConfig(
        name=STREAM,
        description="Integrity P2 raw ordered-ingestion shadow; never canonical authority",
        subjects=[SUBJECT_PATTERN],
        retention=RetentionPolicy.LIMITS,
        max_consumers=-1,
        max_msgs=-1,
        max_bytes=MAX_BYTES,
        discard=DiscardPolicy.NEW,
        discard_new_per_subject=False,
        max_age=0,
        max_msgs_per_subject=-1,
        max_msg_size=8 * 1024 * 1024,
        storage=StorageType.FILE,
        num_replicas=1,
        no_ack=False,
        template_owner=None,
        duplicate_window=DUPLICATE_WINDOW_SECONDS,
        placement=None,
        mirror=None,
        sources=None,
        sealed=False,
        deny_delete=True,
        deny_purge=True,
        allow_rollup_hdrs=False,
        first_seq=None,
        republish=None,
        subject_transform=None,
        allow_direct=True,
        mirror_direct=False,
        compression=StoreCompression.NONE,
        allow_msg_ttl=False,
        allow_msg_schedules=False,
        allow_atomic=False,
        allow_batched=False,
        persist_mode=None,
        metadata={
            "integrity.contract": "p2-raw-v1",
            "integrity.mode": "shadow",
            "integrity.production_authority": "false",
        },
        consumer_limits=None,
        subject_delete_marker_ttl=None,
    )


def verify_config(config: StreamConfig) -> None:
    actual_schema = frozenset(field.name for field in fields(StreamConfig))
    if actual_schema != STREAM_CONFIG_FIELD_ALLOWLIST:
        added = sorted(actual_schema - STREAM_CONFIG_FIELD_ALLOWLIST)
        removed = sorted(STREAM_CONFIG_FIELD_ALLOWLIST - actual_schema)
        raise RuntimeError(
            "JetStream StreamConfig schema is not reviewed: "
            f"added={added},removed={removed}"
        )
    expected = expected_config()
    consumer_limits = config.consumer_limits
    consumer_limits_disabled = consumer_limits is None or (
        consumer_limits.inactive_threshold is None and consumer_limits.max_ack_pending is None
    )
    checks = {
        "name": config.name == expected.name,
        "description": config.description == expected.description,
        "subjects": config.subjects == expected.subjects,
        "retention": config.retention == expected.retention,
        "max_consumers": config.max_consumers == expected.max_consumers,
        "max_msgs": config.max_msgs == expected.max_msgs,
        "max_bytes": config.max_bytes == expected.max_bytes,
        "discard": config.discard == expected.discard,
        "discard_new_per_subject": config.discard_new_per_subject is False,
        "max_age": int(config.max_age or 0) == 0,
        "max_msgs_per_subject": config.max_msgs_per_subject == expected.max_msgs_per_subject,
        "max_msg_size": config.max_msg_size == expected.max_msg_size,
        "storage": config.storage == expected.storage,
        "num_replicas": config.num_replicas == 1,
        "no_ack": config.no_ack is False,
        "template_owner": config.template_owner is None,
        "duplicate_window": int(config.duplicate_window or 0) == DUPLICATE_WINDOW_SECONDS,
        "placement": config.placement is None,
        "mirror": config.mirror is None,
        "sources": not config.sources,
        "deny_delete": config.deny_delete is True,
        "deny_purge": config.deny_purge is True,
        "allow_direct": config.allow_direct is True,
        "sealed": config.sealed is False,
        "allow_rollup_hdrs": config.allow_rollup_hdrs is False,
        "first_seq": config.first_seq in (None, 0),
        "republish": config.republish is None,
        "subject_transform": config.subject_transform is None,
        "mirror_direct": config.mirror_direct is False,
        "compression_disabled": config.compression in (None, StoreCompression.NONE, "none"),
        "allow_msg_ttl": config.allow_msg_ttl in (None, False),
        "allow_msg_schedules": config.allow_msg_schedules in (None, False),
        "allow_atomic": config.allow_atomic in (None, False),
        "allow_batched": config.allow_batched in (None, False),
        "persist_mode": config.persist_mode in (None, PersistMode.DEFAULT, "default"),
        "consumer_limits": consumer_limits_disabled,
        "subject_delete_marker_ttl": config.subject_delete_marker_ttl in (None, 0),
        "contract_metadata": (config.metadata or {}).get("integrity.contract") == "p2-raw-v1",
        "production_authority_metadata": (config.metadata or {}).get("integrity.production_authority") == "false",
        "shadow_metadata": (config.metadata or {}).get("integrity.mode") == "shadow",
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise RuntimeError("JetStream contract drift: " + ",".join(failed))


async def run(args: argparse.Namespace) -> dict[str, Any]:
    env = load_env(args.env_file)
    client = await nats.connect(
        servers=[args.server],
        user=env["NATS_USER"],
        password=env["NATS_PASSWORD"],
        name="integrity-p2-bootstrap",
        connect_timeout=3,
        max_reconnect_attempts=0,
        allow_reconnect=False,
    )
    try:
        jetstream = client.jetstream(timeout=5)
        created = False
        try:
            info = await jetstream.stream_info(STREAM)
        except NotFoundError:
            info = await jetstream.add_stream(config=expected_config())
            created = True
        verify_config(info.config)

        if args.receipt.exists():
            receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
            sequence = int(receipt["smoke"]["sequence"])
            message = await jetstream.get_msg(STREAM, seq=sequence, direct=True)
            digest = hashlib.sha256(message.data).hexdigest()
            if digest != receipt["smoke"]["payload_sha256"]:
                raise RuntimeError("existing JetStream smoke readback mismatch")
            receipt["reused"] = True
            receipt["reused_verified_utc"] = utc_now()
            receipt["stream_state"] = {
                "messages": info.state.messages,
                "bytes": info.state.bytes,
                "first_seq": info.state.first_seq,
                "last_seq": info.state.last_seq,
            }
            return receipt

        body = json.dumps(
            {
                "protocol": "integrity.p2.jetstream-smoke.v1",
                "stream": STREAM,
                "subject": SMOKE_SUBJECT,
                "payload_uid": "integrity-p2-bootstrap-v1",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.sha256(body).hexdigest()
        message_id = f"integrity-p2-bootstrap-{digest}"
        headers = {"Nats-Msg-Id": message_id, "Integrity-Payload-SHA256": digest}
        first_ack = await jetstream.publish(SMOKE_SUBJECT, body, headers=headers, timeout=5, stream=STREAM)
        duplicate_ack = await jetstream.publish(SMOKE_SUBJECT, body, headers=headers, timeout=5, stream=STREAM)
        if first_ack.seq != duplicate_ack.seq or duplicate_ack.duplicate is not True:
            raise RuntimeError("JetStream Nats-Msg-Id deduplication was not proven")
        message = await jetstream.get_msg(STREAM, seq=first_ack.seq, direct=True)
        if hashlib.sha256(message.data).hexdigest() != digest:
            raise RuntimeError("JetStream direct readback digest mismatch")
        info = await jetstream.stream_info(STREAM)
        verify_config(info.config)
        return {
            "protocol": "integrity.p2.nats-bootstrap-receipt.v1",
            "created_utc": utc_now(),
            "stream_created": created,
            "stream": STREAM,
            "subject_pattern": SUBJECT_PATTERN,
            "storage": "file",
            "replicas": 1,
            "fault_domains": 1,
            "production_authority": False,
            "production_ack_allowed": False,
            "rpo_zero_after_ack": False,
            "reused": False,
            "smoke": {
                "subject": SMOKE_SUBJECT,
                "message_id": message_id,
                "sequence": first_ack.seq,
                "payload_sha256": digest,
                "readback_sha256": digest,
                "duplicate_sequence": duplicate_ack.seq,
                "duplicate_ack": True,
            },
            "stream_state": {
                "messages": info.state.messages,
                "bytes": info.state.bytes,
                "first_seq": info.state.first_seq,
                "last_seq": info.state.last_seq,
            },
        }
    finally:
        await client.drain()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", type=Path, default=Path("/etc/integrity-memory-p2/shadow.env"))
    parser.add_argument("--server", default="nats://127.0.0.1:4222")
    parser.add_argument(
        "--receipt",
        type=Path,
        default=Path(_integrity_value('path_038fa4ee2256')),
    )
    args = parser.parse_args()
    receipt = asyncio.run(run(args))
    if not args.receipt.exists():
        atomic_json(args.receipt, receipt)
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
