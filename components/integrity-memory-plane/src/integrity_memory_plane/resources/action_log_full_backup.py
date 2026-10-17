#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Create, independently read back, and restore-test a canonical Action Log backup."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import json
import os
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from memory_plane_common import (
    REQUIRED_APPEND_ONLY_TRIGGERS,
    atomic_json,
    canonical_json,
    database_facts,
    exclusive_lock,
    open_direct_http_request,
    readonly_connection,
    safe_copy,
    sha256_bytes,
    sha256_file,
    snapshot_connection,
)


PROTOCOL = "integrity-memory-plane.full-backup.v1"
ACTION_LOG_READER_HEADER = "X-Codex-Log-Token"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-db", type=Path, default=Path(_integrity_value('path_97373521e3ad')))
    parser.add_argument("--service-source", type=Path, default=Path(_integrity_value('path_c59340f58c1d')))
    parser.add_argument("--local-root", type=Path, default=Path("/var/backups/integrity-memory-plane/action-log/full"))
    parser.add_argument("--vdb-root", type=Path, default=Path(_integrity_value('path_4e44c119019c')))
    parser.add_argument("--evidence-root", type=Path, default=Path(_integrity_value('path_29857010143f')))
    parser.add_argument("--lock", type=Path, default=Path("/run/lock/integrity-memory-plane-full-backup.lock"))
    parser.add_argument("--keep", type=int, default=7)
    parser.add_argument("--skip-service-smoke", action="store_true")
    parser.add_argument("--allow-missing-offhost", action="store_true")
    parser.add_argument("--offhost-host", default="")
    parser.add_argument("--offhost-root", default="")
    parser.add_argument("--ssh-config", type=Path, default=Path(_integrity_value('path_efcbe20e087d')))
    parser.add_argument("--ssh-identity", type=Path, default=None)
    parser.add_argument("--ssh-known-hosts", type=Path, default=None)
    return parser.parse_args()


def online_backup(source: Path, target: Path) -> dict[str, Any]:
    source_connection = snapshot_connection(source)
    target_connection = sqlite3.connect(target, timeout=30)
    try:
        source_connection.backup(target_connection, pages=256, sleep=0.02)
        target_connection.commit()
    finally:
        target_connection.close()
        source_connection.close()
    with readonly_connection(target) as restored:
        facts = database_facts(restored)
    if facts["quick_check"] != "ok" or not facts["append_only_ok"]:
        raise RuntimeError("online backup failed quick_check or append-only trigger gate")
    return facts


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def get_json(url: str, token: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={ACTION_LOG_READER_HEADER: token})
    with open_direct_http_request(request, timeout=5) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise RuntimeError("restore service returned non-object JSON")
    return value


def anonymous_status(url: str) -> int:
    try:
        open_direct_http_request(urllib.request.Request(url), timeout=5)
    except urllib.error.HTTPError as exc:
        try:
            return int(exc.code)
        finally:
            exc.close()
    raise RuntimeError("restore service accepted an anonymous protected read")


def test_sqlite_guards(path: Path) -> dict[str, bool]:
    result: dict[str, bool] = {}
    connection = sqlite3.connect(path)
    try:
        for label, statement in (
            ("update_rejected", "UPDATE events SET summary=summary WHERE id=(SELECT MIN(id) FROM events)"),
            ("delete_rejected", "DELETE FROM events WHERE id=(SELECT MIN(id) FROM events)"),
        ):
            try:
                connection.execute(statement)
                connection.commit()
                result[label] = False
            except sqlite3.DatabaseError:
                connection.rollback()
                result[label] = True
    finally:
        connection.close()
    return result


def restore_smoke(service_source: Path, backup_db: Path, expected: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="action-log-restore-") as temporary:
        root = Path(temporary)
        restored_db = root / "restore.sqlite3"
        shutil.copy2(backup_db, restored_db)
        guards = test_sqlite_guards(restored_db)
        port = free_port()
        reader_token = secrets.token_hex(32)
        env = os.environ.copy()
        env.update(
            {
                "CODEX_LOG_DB": str(restored_db),
                "CODEX_LOG_HOST": "127.0.0.1",
                "CODEX_LOG_PORT": str(port),
                "CODEX_LOG_TOKEN": reader_token,
                "CODEX_LOG_SEED_DIRTY_MARKER": str(root / "seed-dirty"),
                "CODEX_LOG_PID_FILE": str(root / "service.pid"),
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        process = subprocess.Popen(
            [sys.executable, str(service_source)],
            cwd=root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 10
            health: dict[str, Any] | None = None
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                try:
                    health = get_json(f"http://127.0.0.1:{port}/api/health", reader_token)
                    break
                except Exception:
                    time.sleep(0.1)
            if health is None:
                stdout, stderr = process.communicate(timeout=2)
                raise RuntimeError(f"isolated restore service did not start: {stdout[-500:]} {stderr[-1000:]}")
            bootstrap = get_json(f"http://127.0.0.1:{port}/api/bootstrap", reader_token)
            events = get_json(
                f"http://127.0.0.1:{port}/api/events?limit=1&order=desc",
                reader_token,
            )
            tasks = get_json(f"http://127.0.0.1:{port}/api/tasks?limit=1", reader_token)
            anonymous_protected_read_rejected = (
                anonymous_status(
                    f"http://127.0.0.1:{port}/api/events?limit=1&order=desc"
                )
                == 401
            )
            with readonly_connection(restored_db) as connection:
                restored = database_facts(connection)
            checks = {
                "anonymous_protected_read_rejected": anonymous_protected_read_rejected,
                "health_ok": health.get("ok") is True,
                "event_count_match": int(health.get("events") or -1) == int(expected["event_count"]),
                "cursor_match": int(bootstrap.get("event_cursor") or -1) == int(expected["event_cursor"]),
                "row_digest_match": restored["row_sha256"] == expected["row_sha256"],
                "schema_digest_match": restored["schema_sha256"] == expected["schema_sha256"],
                "event_lookup_ok": bool(events.get("events")),
                "task_projection_ok": isinstance(tasks.get("tasks"), list),
                **guards,
            }
            return {"ok": all(checks.values()), "checks": checks, "service_version": health.get("service_version")}
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)


def build_archive(stage: Path, destination: Path) -> str:
    with tarfile.open(destination, "w:gz", compresslevel=6) as archive:
        for path in sorted(stage.rglob("*")):
            archive.add(path, arcname=path.relative_to(stage), recursive=False)
    return sha256_file(destination)


def offhost_copy(args: argparse.Namespace, source: Path, expected_digest: str) -> dict[str, Any]:
    if not args.offhost_host or not args.offhost_root:
        return {"configured": False, "ok": False, "error": "off-host destination is not configured"}
    if not args.offhost_root.startswith("/") or ".." in Path(args.offhost_root).parts:
        raise RuntimeError("unsafe off-host root")
    remote_path = f"{args.offhost_root.rstrip('/')}/{source.name}"
    common = ["-F", str(args.ssh_config), "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"]
    if args.ssh_identity is not None:
        common.extend(["-i", str(args.ssh_identity)])
    if args.ssh_known_hosts is not None:
        common.extend(["-o", f"UserKnownHostsFile={args.ssh_known_hosts}", "-o", "StrictHostKeyChecking=yes"])
    try:
        subprocess.run([_integrity_value('command_7f5a55cf3f88'), *common, args.offhost_host, "mkdir", "-p", "--", args.offhost_root], check=True, timeout=15, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["scp", "-q", *common, str(source), f"{args.offhost_host}:{remote_path}"], check=True, timeout=120, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        readback = subprocess.run([_integrity_value('command_7f5a55cf3f88'), *common, args.offhost_host, "sha256sum", "--", remote_path], check=True, timeout=20, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        digest = readback.stdout.split()[0].strip()
        return {"configured": True, "ok": digest == expected_digest, "path": remote_path, "sha256": digest}
    except (subprocess.SubprocessError, OSError) as exc:
        return {"configured": True, "ok": False, "path": remote_path, "error": f"{type(exc).__name__}: {exc}"}


def prune(root: Path, keep: int) -> None:
    if keep < 1:
        return
    archives = sorted(root.glob("action-log-full-*.tar.gz"), reverse=True)
    for path in archives[keep:]:
        path.unlink()


def main() -> int:
    args = parse_args()
    for required in (args.source_db, args.service_source):
        if not required.is_file():
            raise RuntimeError(f"required source is missing: {required}")
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    args.local_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.vdb_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.evidence_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with exclusive_lock(args.lock), tempfile.TemporaryDirectory(prefix="memory-full-", dir=args.vdb_root) as temporary:
        stage = Path(temporary) / "capsule"
        stage.mkdir(mode=0o700)
        backup_db = stage / "codex-action-log.sqlite3"
        facts = online_backup(args.source_db, backup_db)
        service_copy = stage / "codex_action_log.py"
        shutil.copy2(args.service_source, service_copy)
        inventory = {
            "protocol": PROTOCOL,
            "created_utc": dt.datetime.now(dt.UTC).isoformat(),
            "source_host": socket.gethostname(),
            "source_db": str(args.source_db),
            "facts": facts,
            "service_source_sha256": sha256_file(service_copy),
        }
        atomic_json(stage / "inventory.json", inventory)
        file_manifest = []
        for path in sorted(stage.iterdir()):
            file_manifest.append({"name": path.name, "bytes": path.stat().st_size, "sha256": sha256_file(path)})
        manifest = {"protocol": PROTOCOL, "inventory_sha256": sha256_bytes(canonical_json(inventory)), "files": file_manifest}
        atomic_json(stage / "manifest.json", manifest)
        archive_stage = Path(temporary) / f"action-log-full-{stamp}-cursor-{facts['event_cursor']}.tar.gz"
        archive_digest = build_archive(stage, archive_stage)
        local_path = args.local_root / archive_stage.name
        vdb_path = args.vdb_root / archive_stage.name
        local_digest = safe_copy(archive_stage, local_path)
        vdb_digest = safe_copy(archive_stage, vdb_path)
        restore = {"ok": True, "checks": {"skipped": True}}
        if not args.skip_service_smoke:
            restore = restore_smoke(service_copy, backup_db, facts)
        offhost = offhost_copy(args, archive_stage, archive_digest)
        with readonly_connection(args.source_db) as live:
            live_after = database_facts(live)
        checks = {
            "quick_check": facts["quick_check"] == "ok",
            "append_only": REQUIRED_APPEND_ONLY_TRIGGERS.issubset(facts["append_only_triggers"]),
            "local_readback": local_digest == archive_digest,
            "vdb_readback": vdb_digest == archive_digest,
            "restore_smoke": bool(restore.get("ok")),
            "live_cursor_captured": int(live_after["event_cursor"]) == int(facts["event_cursor"]),
            "offhost_readback": bool(offhost.get("ok")),
        }
        core_ok = all(value for key, value in checks.items() if key != "offhost_readback")
        accepted = core_ok and (checks["offhost_readback"] or args.allow_missing_offhost)
        receipt = {
            "protocol": PROTOCOL + ".receipt",
            "created_utc": dt.datetime.now(dt.UTC).isoformat(),
            "status": "pass" if accepted else "failed",
            "offhost_required": not args.allow_missing_offhost,
            "checks": checks,
            "snapshot": facts,
            "live_after": live_after,
            "archive": {"name": archive_stage.name, "bytes": archive_stage.stat().st_size, "sha256": archive_digest},
            "copies": {"local": str(local_path), "vdb": str(vdb_path), "offhost": offhost},
            "restore": restore,
        }
        receipt_path = args.evidence_root / f"full-backup-{stamp}.json"
        atomic_json(receipt_path, receipt)
        safe_copy(receipt_path, args.local_root / (receipt_path.name), mode=0o400)
        safe_copy(receipt_path, args.vdb_root / (receipt_path.name), mode=0o400)
        prune(args.local_root, args.keep)
        prune(args.vdb_root, args.keep)
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
        if not checks["offhost_readback"] and not args.allow_missing_offhost:
            return 75
        return 0 if core_ok else 1


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
