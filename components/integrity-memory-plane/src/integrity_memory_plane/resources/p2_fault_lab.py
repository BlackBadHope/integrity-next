#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run destructive P2 fault/load evidence only in a disposable isolated lab."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import asyncio
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import nats
import psycopg

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file


PROTOCOL = "integrity-memory-plane.p2-fault-lab.v1"
LAB_HOST = "127.0.0.2"
POSTGRES_PORT = 55432
NATS_PORT = 4222
NATS_MONITOR_PORT = 18222
MINIO_PORT = 19000
SOURCE_PORT = 18765
STREAM = "INTEGRITY_P2_RAW"
SUBJECT = "integrity.p2.raw.workspace.seed_project_workspace.source-linux-action-log"
NATS_IMAGE = "nats@sha256:9e5633ac7584fc4e80d34be3ff7e15aa3fabec79a5573c2d9abefcf1f7761d9a"
POSTGRES_IMAGE = "integrity-p2-postgres:18.4-uid62002"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            key, separator, value = line.partition("=")
            if not separator:
                raise RuntimeError(f"invalid environment line: {path}")
            result[key] = value
    return result


def write_env(path: Path, values: dict[str, str]) -> None:
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="ascii")
    path.chmod(0o600)


def port_open(host: str, port: int, timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_port(host: str, port: int, *, timeout: float = 45.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if port_open(host, port):
            return
        time.sleep(0.2)
    raise RuntimeError(f"timeout waiting for {host}:{port}")


def parse_last_json(stdout: str) -> dict[str, Any]:
    for line in reversed(stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise RuntimeError("command did not emit a JSON object")


class CommandLog:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.sequence = 0

    def run(
        self,
        label: str,
        command: list[str],
        *,
        check: bool = True,
        expected_codes: set[int] | None = None,
        timeout: float = 300.0,
    ) -> subprocess.CompletedProcess[str]:
        self.sequence += 1
        started = time.perf_counter()
        result = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
        elapsed = time.perf_counter() - started
        stem = f"{self.sequence:04d}-{label}"
        (self.root / f"{stem}.stdout.log").write_text(result.stdout, encoding="utf-8")
        (self.root / f"{stem}.stderr.log").write_text(result.stderr, encoding="utf-8")
        record = {
            "label": label,
            "returncode": result.returncode,
            "elapsed_seconds": round(elapsed, 6),
            "stdout_sha256": sha256_bytes(result.stdout.encode()),
            "stderr_sha256": sha256_bytes(result.stderr.encode()),
        }
        with (self.root / "commands.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        allowed = expected_codes if expected_codes is not None else ({0} if check else set(range(256)))
        if result.returncode not in allowed:
            raise RuntimeError(f"{label} returned {result.returncode}")
        return result


class SyntheticActionLog:
    def __init__(self, event_count: int):
        self.event_count = event_count
        self.collision_cursor = 0
        self.lock = threading.Lock()

    def set_collision_tail(self, cursor: int) -> None:
        with self.lock:
            self.event_count = cursor
            self.collision_cursor = cursor

    def event(self, cursor: int) -> dict[str, Any]:
        when = datetime(2026, 8, 8, tzinfo=timezone.utc) + timedelta(milliseconds=cursor)
        collision = cursor == self.collision_cursor
        uid_cursor = cursor - 1 if collision else cursor
        return {
            "id": cursor,
            "ts_utc": when.isoformat().replace("+00:00", "Z"),
            "actor": "integrity-p2-fault-lab",
            "session_id": "isolated-fault-lab",
            "level": "info",
            "action": "fault_lab_event",
            "summary": ("collision payload" if collision else "fault lab canonical memory") + f" event {cursor}",
            "details": {"task_id": f"fault-task-{cursor // 10:08d}", "result": "complete", "cursor": cursor},
            "tags": ["p2-fault-lab", "isolated", f"bucket-{cursor // 1000}"],
            "created_utc": when.isoformat().replace("+00:00", "Z"),
            "event_uid": f"fault-event-{uid_cursor:020d}",
        }

    def handler(self) -> type[BaseHTTPRequestHandler]:
        source = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: object) -> None:
                return

            def send_value(self, value: dict[str, Any]) -> None:
                body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                query = parse_qs(parsed.query)
                with source.lock:
                    count = source.event_count
                if parsed.path == "/api/health":
                    self.send_value(
                        {
                            "service": "codex-action-log",
                            "service_version": "fault-lab-1",
                            "events": count,
                            "append_only": True,
                            "update_enabled": False,
                            "delete_enabled": False,
                            "cursor_pagination": True,
                        }
                    )
                    return
                if parsed.path != "/api/events":
                    self.send_error(404)
                    return
                if "id" in query:
                    cursor = int(query["id"][0])
                    events = [source.event(cursor)] if 1 <= cursor <= count else []
                    self.send_value({"events": events, "pagination": {"snapshot_event_id": count, "has_more": False}})
                    return
                after = int(query.get("after_id", ["0"])[0])
                page_size = min(200, int(query.get("page_size", ["200"])[0]))
                last = min(count, after + page_size)
                events = [source.event(cursor) for cursor in range(after + 1, last + 1)]
                self.send_value(
                    {
                        "events": events,
                        "pagination": {"snapshot_event_id": count, "has_more": last < count},
                    }
                )

        return Handler


def postgres_counts(env: dict[str, str]) -> dict[str, int]:
    with psycopg.connect(
        host=LAB_HOST,
        port=POSTGRES_PORT,
        user=env["POSTGRES_USER"],
        password=env["POSTGRES_PASSWORD"],
        dbname=env["POSTGRES_DB"],
        connect_timeout=5,
    ) as connection:
        return {
            "events": int(connection.execute("SELECT count(*) FROM integrity_p2.raw_events").fetchone()[0]),
            "batches": int(connection.execute("SELECT count(*) FROM integrity_p2.ingest_batches").fetchone()[0]),
            "dead_letters": int(connection.execute("SELECT count(*) FROM integrity_p2.dead_letters").fetchone()[0]),
        }


def wait_postgres(env: dict[str, str], timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            postgres_counts(env)
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("isolated PostgreSQL did not become ready")


async def nats_state(env: dict[str, str]) -> dict[str, int]:
    client = await nats.connect(
        servers=[f"nats://{LAB_HOST}:{NATS_PORT}"],
        user=env["NATS_USER"],
        password=env["NATS_PASSWORD"],
        connect_timeout=3,
        max_reconnect_attempts=0,
        allow_reconnect=False,
    )
    try:
        info = await client.jetstream(timeout=5).stream_info(STREAM)
        return {"messages": int(info.state.messages), "first_seq": int(info.state.first_seq), "last_seq": int(info.state.last_seq)}
    finally:
        await client.drain()


async def publish_future_gap(env: dict[str, str], cursor: int, previous_batch: str) -> int:
    batch_sha = sha256_bytes(f"fault-lab-future-gap:{cursor}:{previous_batch}".encode())
    raw = {
        "bucket": "integrity-p2-raw",
        "key": f"raw/v1/fault-lab/future-gap-{cursor}-{batch_sha}.ndjson.gz",
        "version_id": "not-committed",
        "content_sha256": sha256_bytes(b"future-gap"),
        "readback_sha256": sha256_bytes(b"future-gap"),
        "retention_mode": "COMPLIANCE",
        "retain_until_utc": "2099-01-01T00:00:00Z",
    }
    manifest = {
        "protocol": "integrity-memory-plane.p2-bus-manifest.v1",
        "tenant_id": "workspace",
        "namespace": _integrity_value('seed_namespace'),
        "edge_id": "source-linux-action-log",
        "first_cursor": cursor,
        "last_cursor": cursor,
        "event_count": 1,
        "batch_sha256": batch_sha,
        "previous_batch_sha256": previous_batch,
        "raw_object": raw,
        "production_authority": False,
    }
    body = canonical_json(manifest)
    client = await nats.connect(
        servers=[f"nats://{LAB_HOST}:{NATS_PORT}"],
        user=env["NATS_RELAY_USER"],
        password=env["NATS_RELAY_PASSWORD"],
        connect_timeout=3,
        max_reconnect_attempts=0,
        allow_reconnect=False,
    )
    try:
        ack = await client.jetstream(timeout=5).publish(
            SUBJECT,
            body,
            headers={"Nats-Msg-Id": batch_sha, "Integrity-Payload-SHA256": sha256_bytes(body)},
            timeout=5,
            stream=STREAM,
        )
        return int(ack.seq)
    finally:
        await client.drain()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=10_000)
    parser.add_argument("--production-peak-events-per-minute", type=float, default=93.0)
    parser.add_argument("--lab-root", type=Path, default=Path(_integrity_value('path_06873fbc0d01')))
    parser.add_argument("--receipt-root", type=Path, default=Path(_integrity_value('path_d114ac7a68e9')))
    args = parser.parse_args()
    if args.events < 2_000 or args.events % 200:
        raise SystemExit("--events must be >=2000 and divisible by 200")
    if os.geteuid() != 0:
        raise SystemExit("P2 isolated fault lab must run as root")
    for port in (POSTGRES_PORT, NATS_PORT, NATS_MONITOR_PORT, MINIO_PORT, SOURCE_PORT):
        if port_open(LAB_HOST, port):
            raise RuntimeError(f"isolated endpoint already in use: {LAB_HOST}:{port}")

    module_root = Path(__file__).resolve().parent
    python = Path(_integrity_value('path_f4763e7ac785'))
    minio_binary = Path(_integrity_value('path_0bec209d2ff3'))
    run_uid = str(uuid.uuid4())
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    root = args.lab_root / f"run-{stamp}-{run_uid}"
    root.mkdir(parents=True, mode=0o700)
    logs = CommandLog(root / "logs")
    config = root / "config"
    config.mkdir(mode=0o700)
    edge = root / "edge"
    for path in (edge / "receipts", edge / "intents", edge / "quarantine", root / "coordination", root / "projection-receipts", root / "gap-receipts"):
        path.mkdir(parents=True, mode=0o700)

    password = secrets.token_urlsafe(36)
    nats_password = secrets.token_urlsafe(36)
    relay_password = secrets.token_urlsafe(36)
    minio_password = secrets.token_urlsafe(42)
    shadow_values = {
        "POSTGRES_USER": "integrity_p2_lab",
        "POSTGRES_PASSWORD": password,
        "POSTGRES_DB": "integrity_p2_lab",
        "NATS_USER": "integrity_p2_lab",
        "NATS_PASSWORD": nats_password,
        "NATS_RELAY_USER": "integrity_p2_lab_relay",
        "NATS_RELAY_PASSWORD": relay_password,
    }
    shadow_env = config / "shadow.env"
    write_env(shadow_env, shadow_values)
    relay_shadow = config / "relay-shadow.env"
    write_env(
        relay_shadow,
        {
            "NATS_RELAY_USER": shadow_values["NATS_RELAY_USER"],
            "NATS_RELAY_PASSWORD": shadow_values["NATS_RELAY_PASSWORD"],
            "POSTGRES_RELAY_USER": shadow_values["POSTGRES_USER"],
            "POSTGRES_RELAY_PASSWORD": shadow_values["POSTGRES_PASSWORD"],
            "POSTGRES_RELAY_DB": shadow_values["POSTGRES_DB"],
        },
    )
    projection_env = config / "projection.env"
    write_env(
        projection_env,
        {
            "POSTGRES_PROJECTION_USER": shadow_values["POSTGRES_USER"],
            "POSTGRES_PROJECTION_PASSWORD": shadow_values["POSTGRES_PASSWORD"],
            "POSTGRES_PROJECTION_DB": shadow_values["POSTGRES_DB"],
        },
    )
    guard_env = config / "guard.env"
    write_env(
        guard_env,
        {
            "POSTGRES_GUARD_USER": shadow_values["POSTGRES_USER"],
            "POSTGRES_GUARD_PASSWORD": shadow_values["POSTGRES_PASSWORD"],
            "POSTGRES_GUARD_DB": shadow_values["POSTGRES_DB"],
        },
    )
    minio_env = config / "minio.env"
    write_env(minio_env, {"MINIO_ROOT_USER": "integrityp2labroot", "MINIO_ROOT_PASSWORD": minio_password})
    relay_minio = config / "relay-minio.env"
    write_env(relay_minio, {"MINIO_ACCESS_KEY": "integrityp2labroot", "MINIO_SECRET_KEY": minio_password})
    projection_minio = config / "projection-minio.env"
    write_env(projection_minio, {"MINIO_PROJECTION_ACCESS_KEY": "integrityp2labroot", "MINIO_PROJECTION_SECRET_KEY": minio_password})
    guard_minio = config / "guard-minio.env"
    write_env(guard_minio, {"MINIO_GUARD_ACCESS_KEY": "integrityp2labroot", "MINIO_GUARD_SECRET_KEY": minio_password})
    nats_conf = config / "p2-nats.conf"
    shutil.copyfile(module_root / "p2-nats.conf", nats_conf)
    nats_conf.chmod(0o644)
    postgres_init = config / "p2-postgres-init.sql"
    projections_init = config / "p2-projections.sql"
    for source, target in (
        (module_root / "p2-postgres-init.sql", postgres_init),
        (module_root / "p2-projections.sql", projections_init),
    ):
        shutil.copyfile(source, target)
        target.chmod(0o444)

    suffix = run_uid.split("-")[0]
    pg_name = f"integrity-p2-fault-pg-{suffix}"
    nats_name = f"integrity-p2-fault-nats-{suffix}"
    containers: list[str] = []
    minio_process: subprocess.Popen[bytes] | None = None
    minio_log_handle: Any = None
    source_server: ThreadingHTTPServer | None = None
    source_thread: threading.Thread | None = None
    final: dict[str, Any] = {}

    def start_minio(label: str) -> None:
        nonlocal minio_process, minio_log_handle
        minio_log_handle = (root / "logs" / f"minio-{label}.log").open("wb")
        environment = {**os.environ, "MINIO_ROOT_USER": "integrityp2labroot", "MINIO_ROOT_PASSWORD": minio_password, "MINIO_BROWSER": "off"}
        minio_process = subprocess.Popen(
            [str(minio_binary), "server", "--address", f"{LAB_HOST}:{MINIO_PORT}", "--console-address", f"{LAB_HOST}:19001", str(root / "minio")],
            stdout=minio_log_handle,
            stderr=subprocess.STDOUT,
            env=environment,
        )
        wait_port(LAB_HOST, MINIO_PORT)

    def stop_minio() -> None:
        nonlocal minio_process, minio_log_handle
        if minio_process is not None and minio_process.poll() is None:
            minio_process.terminate()
            try:
                minio_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                minio_process.kill()
                minio_process.wait(timeout=5)
        minio_process = None
        if minio_log_handle is not None:
            minio_log_handle.close()
            minio_log_handle = None
        deadline = time.monotonic() + 10
        while port_open(LAB_HOST, MINIO_PORT) and time.monotonic() < deadline:
            time.sleep(0.1)

    def relay_command(fail_after: str = "") -> list[str]:
        command = [
            str(python),
            str(module_root / "p2_edge_relay.py"),
            "--action-log-url", f"http://{LAB_HOST}:{SOURCE_PORT}",
            "--batch-size", "200",
            "--state", str(edge / "state.json"),
            "--receipts", str(edge / "receipts"),
            "--intents", str(edge / "intents"),
            "--quarantine", str(edge / "quarantine"),
            "--lock", str(root / "coordination" / "raw-plane.lock"),
            "--minio-env", str(relay_minio),
            "--shadow-env", str(relay_shadow),
            "--s3-endpoint", f"http://{LAB_HOST}:{MINIO_PORT}",
            "--nats-server", f"nats://{LAB_HOST}:{NATS_PORT}",
            "--postgres-host", LAB_HOST,
        ]
        if fail_after:
            command += ["--fail-after", fail_after]
        return command

    def projector(command: str) -> dict[str, Any]:
        result = logs.run(
            f"projection-{command}",
            [
                str(python), str(module_root / "p2_projection.py"), command,
                "--projection", "all",
                "--receipts", str(edge / "receipts"),
                "--shadow-env", str(projection_env),
                "--minio-env", str(projection_minio),
                "--postgres-host", LAB_HOST,
                "--s3-endpoint", f"http://{LAB_HOST}:{MINIO_PORT}",
                "--receipt-root", str(root / "projection-receipts"),
                "--lock", str(root / "coordination" / "projection.lock"),
            ],
            timeout=600,
        )
        return parse_last_json(result.stdout)

    def run_guard(label: str, expected_codes: set[int]) -> dict[str, Any]:
        result = logs.run(
            label,
            [
                str(python), str(module_root / "p2_gap_guard.py"),
                "--guard-env", str(guard_env),
                "--minio-env", str(guard_minio),
                "--receipts", str(edge / "receipts"),
                "--postgres-host", LAB_HOST,
                "--s3-endpoint", f"http://{LAB_HOST}:{MINIO_PORT}",
                "--nats-monitor", f"http://{LAB_HOST}:{NATS_MONITOR_PORT}",
                "--receipt-root", str(root / "gap-receipts"),
                "--lock", str(root / "coordination" / "raw-plane.lock"),
            ],
            expected_codes=expected_codes,
            timeout=600,
        )
        return parse_last_json(result.stdout)

    try:
        for directory, uid in ((root / "postgres", 62002), (root / "nats", 65532)):
            directory.mkdir(mode=0o700)
            os.chown(directory, uid, uid)
        (root / "minio").mkdir(mode=0o700)

        logs.run(
            "docker-postgres-start",
            [
                "docker", "run", "-d", "--name", pg_name,
                "--label", f"integrity.p2.fault-lab={run_uid}",
                "--restart", "no", "--env-file", str(shadow_env),
                "-p", f"{LAB_HOST}:{POSTGRES_PORT}:5432",
                # PostgreSQL 18+ stores versioned clusters below this parent;
                # mounting /data directly is rejected by its entrypoint.
                "-v", f"{root / 'postgres'}:/var/lib/postgresql",
                "-v", f"{postgres_init}:/docker-entrypoint-initdb.d/10-integrity-p2.sql:ro",
                "-v", f"{projections_init}:/docker-entrypoint-initdb.d/20-integrity-p2-projections.sql:ro",
                "--tmpfs", "/tmp:size=64m,mode=1777",
                "--tmpfs", "/var/run/postgresql:size=16m,mode=3775,uid=62002,gid=62002",
                "--security-opt", "no-new-privileges:true", "--memory", "2g", "--cpus", "2", "--pids-limit", "512",
                POSTGRES_IMAGE, "postgres", "-c", "fsync=on", "-c", "synchronous_commit=on", "-c", "full_page_writes=on", "-c", "listen_addresses=*",
            ],
        )
        containers.append(pg_name)
        logs.run(
            "docker-nats-start",
            [
                "docker", "run", "-d", "--name", nats_name,
                "--label", f"integrity.p2.fault-lab={run_uid}",
                "--restart", "no", "--env-file", str(shadow_env),
                "--user", "65532:65532",
                "-p", f"{LAB_HOST}:{NATS_PORT}:4222", "-p", f"{LAB_HOST}:{NATS_MONITOR_PORT}:8222",
                "-v", f"{root / 'nats'}:/data", "-v", f"{nats_conf}:/etc/nats/nats-server.conf:ro",
                "--read-only", "--tmpfs", "/tmp:size=32m,mode=1777", "--security-opt", "no-new-privileges:true",
                "--cap-drop", "ALL", "--memory", "1g", "--cpus", "1", "--pids-limit", "256",
                NATS_IMAGE, "-c", "/etc/nats/nats-server.conf",
            ],
        )
        containers.append(nats_name)
        wait_port(LAB_HOST, NATS_PORT)
        wait_postgres(shadow_values)
        start_minio("initial")

        logs.run(
            "s3-bootstrap",
            [str(python), str(module_root / "p2_s3_bootstrap.py"), "--env-file", str(minio_env), "--endpoint", f"http://{LAB_HOST}:{MINIO_PORT}", "--receipt", str(root / "s3-bootstrap.json")],
        )
        logs.run(
            "nats-bootstrap",
            [str(python), str(module_root / "p2_nats_bootstrap.py"), "--env-file", str(shadow_env), "--server", f"nats://{LAB_HOST}:{NATS_PORT}", "--receipt", str(root / "nats-bootstrap.json")],
        )

        source = SyntheticActionLog(args.events)
        source_server = ThreadingHTTPServer((LAB_HOST, SOURCE_PORT), source.handler())
        source_thread = threading.Thread(target=source_server.serve_forever, name="p2-fault-lab-source", daemon=True)
        source_thread.start()
        wait_port(LAB_HOST, SOURCE_PORT)

        # Object-store outage: an intent may persist, but no state/PG advance is allowed.
        stop_minio()
        outage = logs.run("relay-object-outage", relay_command(), expected_codes={1}, timeout=60)
        outage_counts = postgres_counts(shadow_values)
        outage_state_absent = not (edge / "state.json").exists()
        if outage_counts["events"] != 0 or not outage_state_absent:
            raise RuntimeError("object outage advanced edge or metadata state")
        start_minio("recovery")
        first = parse_last_json(logs.run("relay-object-recovery", relay_command(), timeout=120).stdout)
        if int(first["next_state"]["last_cursor"]) != 200:
            raise RuntimeError("object outage recovery did not commit first batch")

        # Real client disconnect while a PostgreSQL transaction is open.
        crash = logs.run("relay-postgres-mid-crash", relay_command("postgres-mid-crash"), expected_codes={97}, timeout=120)
        crash_counts = postgres_counts(shadow_values)
        crash_state = json.loads((edge / "state.json").read_text(encoding="utf-8"))
        if crash_counts != {"events": 200, "batches": 1, "dead_letters": 0} or int(crash_state["last_cursor"]) != 200:
            raise RuntimeError("mid-transaction crash was not fully rolled back")
        recovered = parse_last_json(logs.run("relay-postgres-crash-recovery", relay_command(), timeout=120).stdout)
        if recovered["bus"]["duplicate"] is not True or postgres_counts(shadow_values)["events"] != 400:
            raise RuntimeError("crash recovery did not prove idempotent bus/object reuse")

        # Sustained clean load through the exact production relay code path.
        clean_events = args.events - 400
        load_started = time.perf_counter()
        batch_calls = 0
        while True:
            state = json.loads((edge / "state.json").read_text(encoding="utf-8"))
            if int(state["last_cursor"]) >= args.events:
                break
            logs.run(f"relay-load-{batch_calls + 1:04d}", relay_command(), timeout=120)
            batch_calls += 1
        load_elapsed = time.perf_counter() - load_started
        events_per_minute = clean_events / load_elapsed * 60.0
        load_multiplier = events_per_minute / args.production_peak_events_per_minute
        counts_after_load = postgres_counts(shadow_values)
        expected_batches = args.events // 200
        if counts_after_load["events"] != args.events or counts_after_load["batches"] != expected_batches or load_multiplier < 10.0:
            raise RuntimeError("10x isolated load gate failed")

        sync = projector("sync")
        rebuild = projector("rebuild")
        sync_map = {value["projection"]: value for value in sync["results"]}
        rebuild_map = {value["projection"]: value for value in rebuild["results"]}
        projection_parity = all(
            (sync_map[name]["last_cursor"], sync_map[name]["row_count"], sync_map[name]["projection_sha256"], sync_map[name]["source_batch_sha256"])
            == (rebuild_map[name]["last_cursor"], rebuild_map[name]["row_count"], rebuild_map[name]["projection_sha256"], rebuild_map[name]["source_batch_sha256"])
            for name in sync_map
        )
        if not projection_parity or any(int(value["last_cursor"]) != args.events for value in rebuild_map.values()):
            raise RuntimeError("projection loss/rebuild parity failed")
        baseline_guard = run_guard("guard-baseline", {0})
        if baseline_guard["status"] != "PASS":
            raise RuntimeError("baseline gap guard did not pass")

        # Cross-batch event_uid collision: raw+bus stage, PostgreSQL refuses it.
        source.set_collision_tail(args.events + 1)
        before_collision_nats = asyncio.run(nats_state(shadow_values))
        collision = logs.run("relay-cross-batch-uid-collision", relay_command(), expected_codes={1}, timeout=120)
        after_collision_nats = asyncio.run(nats_state(shadow_values))
        collision_sequence = after_collision_nats["last_seq"]
        if collision_sequence != before_collision_nats["last_seq"] + 1 or postgres_counts(shadow_values)["events"] != args.events:
            raise RuntimeError("collision was not fail-closed after one bus stage")

        state = json.loads((edge / "state.json").read_text(encoding="utf-8"))
        future_sequence = asyncio.run(publish_future_gap(shadow_values, args.events + 401, str(state["last_batch_sha256"])))
        red_guard = run_guard("guard-before-explicit-quarantine", {1})
        if red_guard["status"] != "FAIL" or red_guard["hard_failures"]["nats_count_mismatch"] != 1:
            raise RuntimeError("out-of-order/collision delivery did not make guard red")

        for sequence, reason in ((collision_sequence, "event_uid_payload_collision"), (future_sequence, "future_gap_out_of_order")):
            logs.run(
                f"quarantine-{reason}",
                [
                    str(python), str(module_root / "p2_quarantine_bus_message.py"),
                    "--sequence", str(sequence), "--reason-code", reason,
                    "--shadow-env", str(shadow_env),
                    "--nats-server", f"nats://{LAB_HOST}:{NATS_PORT}",
                    "--postgres-host", LAB_HOST,
                    "--quarantine-root", str(edge / "quarantine"),
                ],
            )
        final_guard = run_guard("guard-after-explicit-quarantine", {0})
        if final_guard["status"] != "PASS":
            raise RuntimeError("explicit DLQ did not restore explained PASS")

        nats_final = asyncio.run(nats_state(shadow_values))
        # Freeze the evidence prefix before ``finally`` appends container log
        # collection records.  The receipt binds this immutable snapshot, while
        # the complete command journal remains available for cleanup audit.
        command_log = root / "logs" / "commands.jsonl"
        command_log_snapshot = root / "logs" / "commands-receipt-prefix.jsonl"
        shutil.copyfile(command_log, command_log_snapshot)
        command_log_snapshot.chmod(0o440)
        final = {
            "protocol": PROTOCOL + ".receipt",
            "status": "PASS",
            "created_utc": utc_now(),
            "run_uid": run_uid,
            "lab_root": str(root),
            "isolation": {
                "host": LAB_HOST,
                "production_endpoints_touched": False,
                "canonical_action_log_touched": False,
                "p1_touched": False,
                "containers": [pg_name, nats_name],
            },
            "production_baseline": {
                "observed_peak_events_per_minute": args.production_peak_events_per_minute,
                "required_10x_events_per_minute": args.production_peak_events_per_minute * 10.0,
            },
            "load": {
                "events": args.events,
                "clean_measured_events": clean_events,
                "elapsed_seconds": round(load_elapsed, 6),
                "events_per_minute": round(events_per_minute, 3),
                "production_peak_multiplier": round(load_multiplier, 3),
                "batch_count": expected_batches,
                "postgres": counts_after_load,
            },
            "faults": {
                "object_outage_fail_closed": outage.returncode == 1 and outage_counts["events"] == 0 and outage_state_absent,
                "object_outage_recovered_same_intent": int(first["next_state"]["last_cursor"]) == 200,
                "postgres_mid_transaction_exit_code": crash.returncode,
                "postgres_mid_transaction_rolled_back": crash_counts["events"] == 200 and int(crash_state["last_cursor"]) == 200,
                "duplicate_bus_ack_on_recovery": recovered["bus"]["duplicate"] is True,
                "cross_batch_uid_collision_rejected": postgres_counts(shadow_values)["events"] == args.events,
                "future_gap_made_guard_red": red_guard["status"] == "FAIL",
                "explicit_dlq_restored_explained_pass": final_guard["status"] == "PASS",
            },
            "projection_rebuild": {
                "parity": projection_parity,
                "sync": {name: {key: value[key] for key in ("last_cursor", "row_count", "projection_sha256", "source_batch_sha256")} for name, value in sync_map.items()},
                "rebuild": {name: {key: value[key] for key in ("last_cursor", "row_count", "projection_sha256", "source_batch_sha256")} for name, value in rebuild_map.items()},
            },
            "guard": {
                "baseline_status": baseline_guard["status"],
                "red_status": red_guard["status"],
                "final_status": final_guard["status"],
                "final_evidence_sha256": final_guard["evidence_sha256"],
                "final_hard_failures": final_guard["hard_failures"],
                "final_projection_lag": final_guard["projection_lag"],
            },
            "nats": nats_final,
            "ack_boundary": {
                "shadow_receipts_not_production_ack": all(
                    (json.loads(path.read_text(encoding="utf-8")).get("ack_decision") or {}).get("status") == "NOT_ACKED"
                    for path in (edge / "receipts").glob("batch-*.json")
                ),
                "production_authority": False,
                "rpo_zero_claimed": False,
            },
            "command_log_path": "logs/commands-receipt-prefix.jsonl",
            "command_log_sha256": sha256_file(command_log_snapshot),
            "production_authority": False,
            "memory_grants_authority": False,
        }
        required = [
            load_multiplier >= 10.0,
            projection_parity,
            all(final["faults"].values()),
            final_guard["status"] == "PASS",
            final["ack_boundary"]["shadow_receipts_not_production_ack"] is True,
        ]
        if not all(required):
            raise RuntimeError("fault lab final gate aggregation failed")
        final["receipt_sha256"] = sha256_bytes(canonical_json(final))
        receipt = root / f"fault-lab-{final['receipt_sha256'][:16]}.json"
        atomic_json(receipt, final, mode=0o440)
        args.receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
        published = args.receipt_root / receipt.name
        shutil.copyfile(receipt, published)
        published.chmod(0o440)
        print(json.dumps({**final, "receipt_path": str(published)}, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as error:
        failure = {
            "protocol": PROTOCOL + ".failure",
            "status": "FAIL",
            "created_utc": utc_now(),
            "run_uid": run_uid,
            "lab_root": str(root),
            "error_type": type(error).__name__,
            "error": str(error)[:1000],
            "production_endpoints_touched": False,
            "production_authority": False,
        }
        failure["receipt_sha256"] = sha256_bytes(canonical_json(failure))
        atomic_json(root / f"fault-lab-failure-{failure['receipt_sha256'][:16]}.json", failure, mode=0o440)
        print(json.dumps(failure, sort_keys=True, separators=(",", ":")))
        return 1
    finally:
        if source_server is not None:
            source_server.shutdown()
            source_server.server_close()
        if source_thread is not None:
            source_thread.join(timeout=5)
        stop_minio()
        for name in reversed(containers):
            try:
                logs.run(f"docker-logs-{name}", ["docker", "logs", name], check=False, timeout=30)
            except Exception:
                pass
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
