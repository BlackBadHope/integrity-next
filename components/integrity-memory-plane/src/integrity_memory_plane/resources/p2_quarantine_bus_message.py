#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Quarantine one explicitly selected P2 bus message with immutable evidence."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import asyncio
import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Any

import nats
import psycopg
from psycopg.types.json import Jsonb

from memory_plane_common import atomic_json, canonical_json


STREAM = "INTEGRITY_P2_RAW"
TENANT_ID = "workspace"
NAMESPACE = _integrity_value('seed_namespace')
EDGE_ID = "source-linux-action-log"


def load_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            key, separator, value = line.partition("=")
            if not separator:
                raise RuntimeError("invalid environment line")
            result[key] = value
    return result


async def read_bus(env: dict[str, str], server: str, sequence: int) -> tuple[dict[str, Any], str]:
    client = await nats.connect(
        servers=[server],
        user=env["NATS_USER"],
        password=env["NATS_PASSWORD"],
        name="integrity-p2-explicit-quarantine",
        connect_timeout=3,
        max_reconnect_attempts=0,
        allow_reconnect=False,
    )
    try:
        message = await client.jetstream(timeout=5).get_msg(STREAM, seq=sequence, direct=True)
        digest = hashlib.sha256(message.data).hexdigest()
        value = json.loads(message.data)
        if value.get("protocol") != "integrity-memory-plane.p2-bus-manifest.v1":
            raise RuntimeError("selected message is not a P2 bus manifest")
        if value.get("production_authority") is not False:
            raise RuntimeError("selected message claims production authority")
        return value, digest
    finally:
        await client.drain()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sequence", required=True, type=int)
    parser.add_argument("--reason-code", required=True)
    parser.add_argument("--shadow-env", type=Path, default=Path("/etc/integrity-memory-p2/shadow.env"))
    parser.add_argument("--nats-server", default="nats://127.0.0.1:4222")
    parser.add_argument("--postgres-host", default="127.0.0.1")
    parser.add_argument(
        "--quarantine-root",
        type=Path,
        default=Path(_integrity_value('path_6e77c79d3982')),
    )
    args = parser.parse_args()
    if args.sequence < 1 or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{2,80}", args.reason_code):
        raise SystemExit("invalid explicit quarantine selector")
    env = load_env(args.shadow_env)
    manifest, payload_sha256 = asyncio.run(read_bus(env, args.nats_server, args.sequence))
    batch_sha256 = str(manifest["batch_sha256"])
    dlq_id = uuid.uuid5(uuid.NAMESPACE_URL, f"integrity-p2:{STREAM}:{args.sequence}:{batch_sha256}")
    evidence = {
        "protocol": "integrity-memory-plane.p2-explicit-quarantine.v1",
        "dlq_id": str(dlq_id),
        "reason_code": args.reason_code,
        "stream": STREAM,
        "sequence": args.sequence,
        "bus_payload_sha256": payload_sha256,
        "batch_sha256": batch_sha256,
        "first_cursor": int(manifest["first_cursor"]),
        "last_cursor": int(manifest["last_cursor"]),
        "raw_object": manifest["raw_object"],
        "postgres_ingest_committed": False,
        "production_authority": False,
    }
    path = args.quarantine_root / f"dlq-{dlq_id}.json"
    if path.exists():
        if json.loads(path.read_text(encoding="utf-8")) != evidence:
            raise RuntimeError("immutable local DLQ record collision")
    else:
        atomic_json(path, evidence, mode=0o400)
    with psycopg.connect(
        host=args.postgres_host,
        port=55432,
        user=env["POSTGRES_USER"],
        password=env["POSTGRES_PASSWORD"],
        dbname=env["POSTGRES_DB"],
        connect_timeout=5,
    ) as connection:
        connection.execute(
            """
            INSERT INTO integrity_p2.dead_letters(
              dlq_id,tenant_id,namespace,edge_id,observed_cursor,event_uid,reason_code,evidence,raw_object_key
            ) VALUES (%s,%s,%s,%s,%s,NULL,%s,%s,%s)
            ON CONFLICT DO NOTHING
            """,
            (
                dlq_id,
                TENANT_ID,
                NAMESPACE,
                EDGE_ID,
                int(manifest["first_cursor"]),
                args.reason_code,
                Jsonb(evidence),
                str(manifest["raw_object"]["key"]),
            ),
        )
        stored = connection.execute(
            "SELECT reason_code,evidence,raw_object_key FROM integrity_p2.dead_letters WHERE dlq_id=%s",
            (dlq_id,),
        ).fetchone()
        if stored is None or stored[0] != args.reason_code or stored[1] != evidence or stored[2] != manifest["raw_object"]["key"]:
            raise RuntimeError("PostgreSQL DLQ readback mismatch")
    print(json.dumps({**evidence, "local_record": str(path)}, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
