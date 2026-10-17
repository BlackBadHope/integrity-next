#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prove a two-host P2 JetStream canary without calling it a regional quorum."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import asyncio
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import nats
from nats.js.api import DiscardPolicy, RetentionPolicy, StorageType, StreamConfig
from nats.js.errors import NotFoundError


PROTOCOL = "integrity-memory-plane.p2-regional-canary.v1"
STREAM = "INTEGRITY_P2_REGIONAL_CANARY"
SUBJECT = "integrity.p2.regional.canary"
EXPECTED_NODES = {"integrity-p2-canary-linux-1", "integrity-p2-client-1"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="ascii").splitlines():
        key, separator, value = raw.strip().partition("=")
        if separator and key and value:
            values[key] = value
    required = {"NATS_CANARY_USER", "NATS_CANARY_PASSWORD", "NATS_CLUSTER_USER", "NATS_CLUSTER_PASSWORD"}
    if set(values) != required:
        raise RuntimeError("regional canary environment differs from contract")
    return values


def expected_config() -> StreamConfig:
    return StreamConfig(
        name=STREAM,
        description="Integrity P2 two-host regional canary; never production authority",
        subjects=[SUBJECT],
        retention=RetentionPolicy.LIMITS,
        max_bytes=1024 * 1024 * 1024,
        max_msg_size=1024 * 1024,
        discard=DiscardPolicy.NEW,
        storage=StorageType.FILE,
        num_replicas=2,
        duplicate_window=24 * 60 * 60,
        deny_delete=True,
        deny_purge=True,
        allow_direct=True,
        metadata={
            "integrity.contract": "p2-regional-canary-v1",
            "integrity.mode": "canary",
            "integrity.production_authority": "false",
        },
    )


def cluster_nodes(info: Any) -> tuple[set[str], list[dict[str, Any]]]:
    cluster = info.cluster
    if cluster is None:
        return set(), []
    nodes = {str(cluster.leader)} if cluster.leader else set()
    replicas: list[dict[str, Any]] = []
    for replica in cluster.replicas or []:
        value = {
            "name": str(replica.name),
            "current": bool(replica.current),
            "offline": bool(replica.offline),
            "lag": int(replica.lag or 0),
        }
        replicas.append(value)
        if value["current"] and not value["offline"] and value["lag"] == 0:
            nodes.add(value["name"])
    return nodes, replicas


def verify_config(config: StreamConfig) -> None:
    expected = expected_config()
    checks = {
        "subjects": config.subjects == expected.subjects,
        "retention": config.retention == expected.retention,
        "max_bytes": config.max_bytes == expected.max_bytes,
        "max_msg_size": config.max_msg_size == expected.max_msg_size,
        "discard": config.discard == expected.discard,
        "storage": config.storage == expected.storage,
        "replicas": config.num_replicas == 2,
        "deny_delete": config.deny_delete is True,
        "deny_purge": config.deny_purge is True,
        "allow_direct": config.allow_direct is True,
        "mode": (config.metadata or {}).get("integrity.mode") == "canary",
        "authority": (config.metadata or {}).get("integrity.production_authority") == "false",
    }
    failed = sorted(key for key, value in checks.items() if not value)
    if failed:
        raise RuntimeError("regional canary stream drift: " + ",".join(failed))


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o440)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


async def run(args: argparse.Namespace) -> dict[str, Any]:
    env = load_env(args.env)
    client = await nats.connect(
        servers=[args.server],
        user=env["NATS_CANARY_USER"],
        password=env["NATS_CANARY_PASSWORD"],
        name="integrity-p2-regional-canary-verify",
        connect_timeout=5,
        allow_reconnect=False,
        max_reconnect_attempts=0,
    )
    try:
        jetstream = client.jetstream(timeout=10)
        created = False
        try:
            info = await jetstream.stream_info(STREAM)
        except NotFoundError:
            info = await jetstream.add_stream(config=expected_config())
            created = True
        verify_config(info.config)
        nodes, replicas = cluster_nodes(info)
        if nodes != EXPECTED_NODES:
            raise RuntimeError(f"regional canary peers differ: observed={sorted(nodes)}")
        body = json.dumps(
            {"protocol": PROTOCOL + ".smoke", "nodes": sorted(EXPECTED_NODES), "payload_uid": "p2-regional-canary-v1"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        digest = hashlib.sha256(body).hexdigest()
        message_id = "p2-regional-canary-" + digest
        headers = {"Nats-Msg-Id": message_id, "Integrity-Payload-SHA256": digest}
        first = await jetstream.publish(SUBJECT, body, headers=headers, timeout=10, stream=STREAM)
        duplicate = await jetstream.publish(SUBJECT, body, headers=headers, timeout=10, stream=STREAM)
        if first.seq != duplicate.seq or duplicate.duplicate is not True:
            raise RuntimeError("regional canary idempotent ACK failed")
        message = await jetstream.get_msg(STREAM, seq=first.seq, direct=True)
        if hashlib.sha256(message.data).hexdigest() != digest:
            raise RuntimeError("regional canary direct readback digest mismatch")
        info = await jetstream.stream_info(STREAM)
        nodes, replicas = cluster_nodes(info)
        if nodes != EXPECTED_NODES:
            raise RuntimeError("regional canary lost a current replica after publish")
        return {
            "protocol": PROTOCOL + ".receipt",
            "created_utc": utc_now(),
            "status": "PASS",
            "stream_created": created,
            "stream": STREAM,
            "storage": "file",
            "replicas": 2,
            "live_nodes": sorted(nodes),
            "replica_state": replicas,
            "host_domains_proven": 2,
            "regions_proven": 1,
            "smoke": {
                "sequence": first.seq,
                "duplicate_sequence": duplicate.seq,
                "duplicate_ack": True,
                "payload_sha256": digest,
                "readback_sha256": digest,
            },
            "regional_gate_passed": False,
            "production_ack_allowed": False,
            "rpo_zero_claimed": False,
            "production_authority": False,
            "memory_grants_authority": False,
        }
    finally:
        await client.drain()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path, default=Path("/etc/integrity-memory-p2/regional-canary.env"))
    parser.add_argument("--server", default="nats://127.0.0.1:14222")
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_1cc8a565c593')))
    args = parser.parse_args()
    receipt = asyncio.run(run(args))
    receipt["evidence_sha256"] = hashlib.sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = args.receipt_root / f"regional-canary-{stamp}-{receipt['evidence_sha256'][:16]}.json"
    atomic_json(path, receipt)
    print(json.dumps({**receipt, "receipt_path": str(path)}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
