#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prove the P2 relay's positive and negative backend permissions."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any, Callable

import boto3
import nats
import psycopg
from botocore.client import Config
from botocore.exceptions import ClientError


STREAM = "INTEGRITY_P2_RAW"
RAW_BUCKET = "integrity-p2-raw"


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


def postgres_gate(env: dict[str, str], host: str) -> dict[str, Any]:
    denied: list[str] = []
    with psycopg.connect(
        host=host,
        port=55432,
        user=env["POSTGRES_RELAY_USER"],
        password=env["POSTGRES_RELAY_PASSWORD"],
        dbname=env["POSTGRES_RELAY_DB"],
        connect_timeout=5,
    ) as connection:
        counts = connection.execute(
            "SELECT (SELECT count(*) FROM integrity_p2.raw_events), "
            "(SELECT count(*) FROM integrity_p2.ingest_batches)"
        ).fetchone()
        probes = {
            "update_raw": "UPDATE integrity_p2.raw_events SET metadata=metadata WHERE cursor=1",
            "delete_raw": "DELETE FROM integrity_p2.raw_events WHERE cursor=1",
            "read_projection": "SELECT count(*) FROM integrity_p2.current_task_state",
        }
        for name, statement in probes.items():
            try:
                with connection.transaction():
                    connection.execute(statement)
            except psycopg.errors.InsufficientPrivilege:
                denied.append(name)
            else:
                raise RuntimeError(f"PostgreSQL negative permission probe unexpectedly succeeded: {name}")
    if sorted(denied) != sorted(probes):
        raise RuntimeError("PostgreSQL deny proof incomplete")
    return {"raw_events": int(counts[0]), "batches": int(counts[1]), "denied": sorted(denied)}


def s3_gate(env: dict[str, str], endpoint: str, receipt: Path) -> dict[str, Any]:
    last = json.loads(receipt.read_text(encoding="utf-8"))
    raw = last["raw"]
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=env["MINIO_ACCESS_KEY"],
        aws_secret_access_key=env["MINIO_SECRET_KEY"],
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 1}),
    )
    body = client.get_object(Bucket=RAW_BUCKET, Key=raw["key"], VersionId=raw["version_id"])["Body"].read()
    if not body:
        raise RuntimeError("scoped S3 exact-version readback returned an empty body")
    denied: list[str] = []
    probes: dict[str, Callable[[], Any]] = {
        "attachments_bucket": lambda: client.list_object_versions(Bucket="integrity-p2-attachments", MaxKeys=1),
        "outside_raw_prefix": lambda: client.put_object(
            Bucket=RAW_BUCKET,
            Key="raw/v2/least-privilege-deny-probe",
            Body=b"must-not-be-written",
            IfNoneMatch="*",
        ),
    }
    for name, probe in probes.items():
        try:
            probe()
        except ClientError as error:
            status = int(error.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0))
            if status != 403:
                raise
            denied.append(name)
        else:
            raise RuntimeError(f"S3 negative permission probe unexpectedly succeeded: {name}")
    return {"exact_version_read_bytes": len(body), "denied": sorted(denied)}


async def nats_gate(env: dict[str, str], server: str) -> dict[str, Any]:
    permission_errors: list[str] = []

    async def error_callback(error: Exception) -> None:
        text = str(error)
        if "Permissions Violation" in text:
            permission_errors.append(text)

    client = await nats.connect(
        servers=[server],
        user=env["NATS_RELAY_USER"],
        password=env["NATS_RELAY_PASSWORD"],
        name="integrity-p2-least-privilege-verifier",
        error_cb=error_callback,
        connect_timeout=3,
        max_reconnect_attempts=0,
        allow_reconnect=False,
    )
    try:
        jetstream = client.jetstream(timeout=2)
        info = await jetstream.stream_info(STREAM)
        message = await jetstream.get_msg(STREAM, seq=info.state.first_seq, direct=True)
        if not message.data:
            raise RuntimeError("NATS direct readback returned an empty message")
        try:
            await client.request("$JS.API.STREAM.LIST", b"{}", timeout=0.5)
        except nats.errors.TimeoutError:
            await asyncio.sleep(0.1)
        else:
            raise RuntimeError("NATS administrative STREAM.LIST unexpectedly succeeded")
        after = await jetstream.stream_info(STREAM)
        if after.state.messages != info.state.messages:
            raise RuntimeError("NATS stream changed during the safe deny probe")
        return {
            "stream": STREAM,
            "messages": info.state.messages,
            "direct_read_sequence": info.state.first_seq,
            "denied": ["$JS.API.STREAM.LIST"],
            "deny_observation": "bounded_timeout_between_two_allowed_stream_info_roundtrips",
            "client_permission_callbacks": len(permission_errors),
        }
    finally:
        await client.drain()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shadow-env", type=Path, default=Path("/etc/integrity-memory-p2/relay-shadow.env"))
    parser.add_argument("--minio-env", type=Path, default=Path("/etc/integrity-memory-p2/relay-minio.env"))
    parser.add_argument("--state", type=Path, default=Path(_integrity_value('path_9b0a73c6e071')))
    parser.add_argument("--postgres-host", default="127.0.0.1")
    parser.add_argument("--minio-endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    parser.add_argument("--nats-server", default="nats://127.0.0.1:4222")
    args = parser.parse_args()
    shadow = load_env(args.shadow_env)
    minio = load_env(args.minio_env)
    state = json.loads(args.state.read_text(encoding="utf-8"))
    result = {
        "protocol": "integrity-memory-plane.p2-least-privilege-proof.v1",
        "postgres": postgres_gate(shadow, args.postgres_host),
        "s3": s3_gate(minio, args.minio_endpoint, Path(state["last_receipt"])),
        "nats": asyncio.run(nats_gate(shadow, args.nats_server)),
        "production_authority": False,
        "secret_values_exposed": False,
    }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
