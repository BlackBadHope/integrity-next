#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build independent disposable P2 projections from committed raw WORM batches."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import gzip
import hashlib
import json
import math
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import boto3
import psycopg
from botocore.client import Config
from psycopg.types.json import Jsonb

from memory_plane_common import atomic_json, canonical_json, exclusive_lock, sha256_bytes
from p2_contract import Envelope, build_batch


PROTOCOL = "integrity-memory-plane.p2-projection.v1"
TENANT_ID = "workspace"
NAMESPACE = _integrity_value('seed_namespace')
EDGE_ID = "source-linux-action-log"
RAW_BUCKET = "integrity-p2-raw"
PROJECTIONS = ("fts", "graph", "vector", "task-state")
VECTOR_DIMENSIONS = 256
TOKEN_RE = re.compile(r"[0-9A-Za-zА-Яа-яЁё_./:-]{2,}", re.UNICODE)


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


def tokens(text: str) -> list[str]:
    return [match.group(0).casefold() for match in TOKEN_RE.finditer(text)]


def sparse_vector(text: str) -> tuple[list[list[float | int]], float]:
    values: dict[int, float] = {}
    for token in tokens(text):
        raw = hashlib.sha256(token.encode("utf-8")).digest()
        index = int.from_bytes(raw[:4], "big") % VECTOR_DIMENSIONS
        sign = 1.0 if raw[4] & 1 else -1.0
        values[index] = values.get(index, 0.0) + sign
    norm = math.sqrt(sum(value * value for value in values.values()))
    return [[index, value] for index, value in sorted(values.items()) if value], norm


def object_text(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return canonical_json(value).decode("utf-8")
    return str(value or "")


def event_body(event: dict[str, Any]) -> str:
    return "\n".join(
        object_text(event.get(key))
        for key in ("summary", "details", "tags", "actor", "action", "session_id", "task_id")
    )


def event_nodes(event: dict[str, Any]) -> Iterable[tuple[str, str, str]]:
    for key, relation in (("actor", "ACTED_BY"), ("action", "HAS_ACTION")):
        if event.get(key):
            yield key, str(event[key]), relation
    tags = event.get("tags") or []
    if not isinstance(tags, list):
        tags = [tags]
    for tag in tags:
        if str(tag).strip():
            yield "tag", str(tag), "TAGGED"
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    for key in ("task_id", "goal_id", "roadmap_item_id", "parent_task_id"):
        value = event.get(key) or details.get(key)
        if value:
            yield key, str(value), "REFERENCES"
    for key in ("subsystem", "touched_hosts", "related_task_ids", "depends_on_task_ids"):
        values = event.get(key) or details.get(key) or []
        if not isinstance(values, list):
            values = [values]
        for value in values:
            if str(value).strip():
                yield key, str(value), "REFERENCES"


def committed_receipts(root: Path) -> list[tuple[Path, dict[str, Any]]]:
    result: list[tuple[Path, dict[str, Any]]] = []
    for path in root.glob("batch-*.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("status") != "shadow_pipeline_committed" or value.get("production_authority") is not False:
            raise RuntimeError(f"uncommitted or authority-claiming relay receipt: {path.name}")
        if (value.get("ack_decision") or {}).get("status") != "NOT_ACKED":
            raise RuntimeError(f"unexpected shadow ACK state: {path.name}")
        result.append((path, value))
    result.sort(key=lambda item: int(item[1]["batch"]["first_cursor"]))
    previous_batch = ""
    previous_cursor = 0
    seen_batches: set[str] = set()
    for path, value in result:
        batch = value["batch"]
        digest = str(batch["batch_sha256"])
        if digest in seen_batches or str(batch["previous_batch_sha256"]).rstrip() != previous_batch:
            raise RuntimeError(f"committed receipt batch chain diverged at {path.name}")
        if int(batch["first_cursor"]) <= previous_cursor:
            raise RuntimeError(f"committed receipt cursor order diverged at {path.name}")
        seen_batches.add(digest)
        previous_batch = digest
        previous_cursor = int(batch["last_cursor"])
    return result


def s3_client(env: dict[str, str], endpoint: str) -> Any:
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=env["MINIO_PROJECTION_ACCESS_KEY"],
        aws_secret_access_key=env["MINIO_PROJECTION_SECRET_KEY"],
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 2}),
    )


def raw_envelopes(client: Any, receipt: dict[str, Any]) -> list[dict[str, Any]]:
    raw = receipt["raw"]
    body = client.get_object(Bucket=RAW_BUCKET, Key=raw["key"], VersionId=raw["version_id"])["Body"].read()
    if sha256_bytes(body) != raw["content_sha256"]:
        raise RuntimeError("raw object digest mismatch")
    lines = gzip.decompress(body).splitlines()
    if len(lines) < 2:
        raise RuntimeError("raw object has no envelopes")
    header = json.loads(lines[0])
    if header.get("batch_manifest") != receipt["batch"]:
        raise RuntimeError("raw header and committed receipt batch mismatch")
    values = [json.loads(line) for line in lines[1:]]
    reconstructed: list[Envelope] = []
    for value in values:
        envelope = Envelope(
            tenant_id=value["tenant_id"],
            namespace=value["namespace"],
            edge_id=value["edge_id"],
            cursor=int(value["cursor"]),
            event_uid=value["event_uid"],
            ts_utc=value["ts_utc"],
            payload=value["payload"],
            source_manifest_sha256=value["source_manifest_sha256"],
            previous_envelope_sha256=value["previous_envelope_sha256"],
        )
        if envelope.value() != value:
            raise RuntimeError("raw envelope digest mismatch")
        reconstructed.append(envelope)
    rebuilt = build_batch(reconstructed, previous_batch_sha256=str(receipt["batch"]["previous_batch_sha256"]).rstrip())
    if {key: value for key, value in rebuilt.items() if key != "envelopes"} != receipt["batch"]:
        raise RuntimeError("raw batch digest reconstruction mismatch")
    return values


def connect(env: dict[str, str], host: str) -> psycopg.Connection[Any]:
    return psycopg.connect(
        host=host,
        port=55432,
        user=env["POSTGRES_PROJECTION_USER"],
        password=env["POSTGRES_PROJECTION_PASSWORD"],
        dbname=env["POSTGRES_PROJECTION_DB"],
        connect_timeout=5,
    )


def offset(connection: psycopg.Connection[Any], projection: str) -> tuple[int, str]:
    row = connection.execute(
        "SELECT last_cursor,last_batch_sha256 FROM integrity_p2.projection_offsets "
        "WHERE projection_name=%s AND tenant_id=%s AND namespace=%s AND edge_id=%s",
        (projection, TENANT_ID, NAMESPACE, EDGE_ID),
    ).fetchone()
    return (int(row[0]), str(row[1]).rstrip()) if row else (0, "")


def set_offset(connection: psycopg.Connection[Any], projection: str, cursor: int, batch_sha256: str) -> None:
    connection.execute(
        "INSERT INTO integrity_p2.projection_offsets(projection_name,tenant_id,namespace,edge_id,last_cursor,last_batch_sha256) "
        "VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT(projection_name,tenant_id,namespace,edge_id) DO UPDATE "
        "SET last_cursor=excluded.last_cursor,last_batch_sha256=excluded.last_batch_sha256,updated_utc=clock_timestamp()",
        (projection, TENANT_ID, NAMESPACE, EDGE_ID, cursor, batch_sha256),
    )


def ingest(connection: psycopg.Connection[Any], projection: str, envelope: dict[str, Any]) -> None:
    event = envelope["payload"]
    cursor = int(envelope["cursor"])
    event_uid = str(envelope["event_uid"])
    payload_sha = str(envelope["payload_sha256"])
    body = event_body(event)
    if projection == "fts":
        connection.execute(
            "INSERT INTO integrity_p2.projection_fts_events(tenant_id,namespace,edge_id,cursor,event_uid,ts_utc,payload_sha256,summary,body_text) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            (TENANT_ID, NAMESPACE, EDGE_ID, cursor, event_uid, envelope["ts_utc"], payload_sha, str(event.get("summary") or ""), body),
        )
    elif projection == "vector":
        vector, norm = sparse_vector(body)
        connection.execute(
            "INSERT INTO integrity_p2.projection_vector_events(tenant_id,namespace,edge_id,cursor,event_uid,payload_sha256,dimensions,sparse_vector,norm) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            (TENANT_ID, NAMESPACE, EDGE_ID, cursor, event_uid, payload_sha, VECTOR_DIMENSIONS, Jsonb(vector), norm),
        )
    elif projection == "graph":
        for kind, value, relation in event_nodes(event):
            normalized = value.strip()
            node_key = f"{kind}:{normalized.casefold()}"
            connection.execute(
                "INSERT INTO integrity_p2.projection_graph_nodes(tenant_id,namespace,node_key,kind,value) VALUES(%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (TENANT_ID, NAMESPACE, node_key, kind, normalized),
            )
            connection.execute(
                "INSERT INTO integrity_p2.projection_graph_edges(tenant_id,namespace,edge_id,cursor,node_key,relation) VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (TENANT_ID, NAMESPACE, EDGE_ID, cursor, node_key, relation),
            )
    elif projection == "task-state":
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        task_id = str(event.get("task_id") or details.get("task_id") or "").strip()
        if task_id:
            result = str(event.get("result") or details.get("result") or "unknown")
            connection.execute(
                "INSERT INTO integrity_p2.current_task_state(tenant_id,namespace,task_id,last_cursor,result,summary,details,updated_utc) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(tenant_id,namespace,task_id) DO UPDATE "
                "SET last_cursor=excluded.last_cursor,result=excluded.result,summary=excluded.summary,details=excluded.details,updated_utc=excluded.updated_utc "
                "WHERE excluded.last_cursor > integrity_p2.current_task_state.last_cursor",
                (TENANT_ID, NAMESPACE, task_id, cursor, result, str(event.get("summary") or ""), Jsonb(event), envelope["ts_utc"]),
            )
    else:
        raise ValueError(f"unknown projection: {projection}")


def truncate_projection(connection: psycopg.Connection[Any], projection: str) -> None:
    tables = {
        "fts": "integrity_p2.projection_fts_events",
        "vector": "integrity_p2.projection_vector_events",
        "graph": "integrity_p2.projection_graph_edges,integrity_p2.projection_graph_nodes",
        "task-state": "integrity_p2.current_task_state",
    }
    connection.execute("TRUNCATE " + tables[projection])
    connection.execute(
        "DELETE FROM integrity_p2.projection_offsets WHERE projection_name=%s AND tenant_id=%s AND namespace=%s AND edge_id=%s",
        (projection, TENANT_ID, NAMESPACE, EDGE_ID),
    )


def projection_digest(connection: psycopg.Connection[Any], projection: str) -> tuple[int, str]:
    queries = {
        "fts": "SELECT cursor,event_uid,payload_sha256,summary,body_text FROM integrity_p2.projection_fts_events WHERE tenant_id=%s AND namespace=%s AND edge_id=%s ORDER BY cursor",
        "vector": "SELECT cursor,event_uid,payload_sha256,dimensions,sparse_vector,norm FROM integrity_p2.projection_vector_events WHERE tenant_id=%s AND namespace=%s AND edge_id=%s ORDER BY cursor",
        "graph": "SELECT cursor,node_key,relation FROM integrity_p2.projection_graph_edges WHERE tenant_id=%s AND namespace=%s AND edge_id=%s ORDER BY cursor,node_key,relation",
        "task-state": "SELECT task_id,last_cursor,result,summary,details FROM integrity_p2.current_task_state WHERE tenant_id=%s AND namespace=%s ORDER BY task_id",
    }
    parameters = (TENANT_ID, NAMESPACE) if projection == "task-state" else (TENANT_ID, NAMESPACE, EDGE_ID)
    rows = connection.execute(queries[projection], parameters).fetchall()
    digest = hashlib.sha256()
    for row in rows:
        value = canonical_json([str(item) if not isinstance(item, (int, float, dict, list)) else item for item in row])
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return len(rows), digest.hexdigest()


def run_projection(
    connection: psycopg.Connection[Any],
    projection: str,
    receipts: list[tuple[Path, dict[str, Any]]],
    client: Any,
    cache: dict[str, list[dict[str, Any]]],
    mode: str,
) -> dict[str, Any]:
    if mode == "rebuild":
        with connection.transaction():
            truncate_projection(connection, projection)
    last_cursor, last_batch = offset(connection, projection)
    processed = 0
    first_cursor: int | None = None
    for _, receipt in receipts:
        batch = receipt["batch"]
        if int(batch["last_cursor"]) <= last_cursor:
            continue
        if str(batch["previous_batch_sha256"]).rstrip() != last_batch:
            raise RuntimeError(f"{projection} offset batch chain diverged")
        digest = str(batch["batch_sha256"])
        if digest not in cache:
            cache[digest] = raw_envelopes(client, receipt)
        envelopes = cache[digest]
        with connection.transaction():
            for envelope in envelopes:
                ingest(connection, projection, envelope)
                processed += 1
                if first_cursor is None:
                    first_cursor = int(envelope["cursor"])
            set_offset(connection, projection, int(batch["last_cursor"]), digest)
        last_cursor = int(batch["last_cursor"])
        last_batch = digest
    count, digest = projection_digest(connection, projection)
    run_uid = uuid.uuid4()
    with connection.transaction():
        connection.execute(
            "INSERT INTO integrity_p2.projection_runs(run_uid,projection_name,tenant_id,namespace,edge_id,mode,first_cursor,last_cursor,processed_events,projection_sha256,source_batch_sha256) "
            "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (run_uid, projection, TENANT_ID, NAMESPACE, EDGE_ID, mode, first_cursor, last_cursor, processed, digest, last_batch),
        )
    return {
        "projection": projection,
        "mode": mode,
        "status": "pass" if processed or mode == "rebuild" else "noop",
        "first_cursor": first_cursor,
        "last_cursor": last_cursor,
        "processed_events": processed,
        "row_count": count,
        "projection_sha256": digest,
        "source_batch_sha256": last_batch,
        "run_uid": str(run_uid),
        "production_authority": False,
        "rebuildable_from_committed_raw": True,
    }


def status_projection(connection: psycopg.Connection[Any], projection: str) -> dict[str, Any]:
    last_cursor, last_batch = offset(connection, projection)
    count, digest = projection_digest(connection, projection)
    return {
        "projection": projection,
        "status": "ready" if last_cursor else "empty",
        "last_cursor": last_cursor,
        "row_count": count,
        "projection_sha256": digest,
        "source_batch_sha256": last_batch,
        "production_authority": False,
        "rebuildable_from_committed_raw": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("sync", "rebuild", "status"))
    parser.add_argument("--projection", choices=(*PROJECTIONS, "all"), default="all")
    parser.add_argument("--receipts", type=Path, default=Path(_integrity_value('path_f5a9a1727fe8')))
    parser.add_argument("--shadow-env", type=Path, default=Path("/etc/integrity-memory-p2/projection.env"))
    parser.add_argument("--minio-env", type=Path, default=Path("/etc/integrity-memory-p2/projection-minio.env"))
    parser.add_argument("--postgres-host", default="127.0.0.1")
    parser.add_argument("--s3-endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_723c1b74bd25')))
    parser.add_argument("--lock", type=Path, default=Path("/run/integrity-memory-p2/projection.lock"))
    args = parser.parse_args()
    selected = list(PROJECTIONS) if args.projection == "all" else [args.projection]
    pg_env = load_env(args.shadow_env)
    if args.command == "status":
        with connect(pg_env, args.postgres_host) as connection:
            result = {
                "protocol": PROTOCOL + ".status",
                "command": "status",
                "results": [status_projection(connection, projection) for projection in selected],
                "production_authority": False,
                "memory_grants_authority": False,
            }
        print(json.dumps(result, sort_keys=True))
        return 0
    minio_env = load_env(args.minio_env)
    receipts = committed_receipts(args.receipts)
    client = s3_client(minio_env, args.s3_endpoint)
    cache: dict[str, list[dict[str, Any]]] = {}
    with exclusive_lock(args.lock):
        with connect(pg_env, args.postgres_host) as connection:
            results = [
                run_projection(connection, projection, receipts, client, cache, args.command)
                for projection in selected
            ]
    result = {
        "protocol": PROTOCOL + ".receipt",
        "command": args.command,
        "created_utc": utc_now(),
        "committed_batch_count": len(receipts),
        "results": results,
        "production_authority": False,
        "memory_grants_authority": False,
        "source": "committed-relay-receipts-plus-exact-version-WORM-raw",
    }
    args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    atomic_json(args.receipt_root / f"projection-{args.command}-{args.projection}-{stamp}.json", result, mode=0o440)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
