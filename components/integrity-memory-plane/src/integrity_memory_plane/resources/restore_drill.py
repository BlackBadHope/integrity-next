#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reconstruct Action Log from full+tail and rebuild Seed in isolated scratch."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
import pwd
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from action_log_full_backup import free_port, restore_smoke
from memory_plane_common import (
    atomic_json,
    canonical_json,
    database_facts,
    open_direct_http_request,
    readonly_connection,
    row_digest,
    sha256_file,
    snapshot_connection,
)


PROTOCOL = "integrity-memory-plane.restore-drill.v1"
ACTION_LOG_READER_HEADER = "X-Codex-Log-Token"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-root", type=Path, default=Path(_integrity_value('path_4e44c119019c')))
    parser.add_argument("--tail-root", type=Path, default=Path(_integrity_value('path_f99c29cce43c')))
    parser.add_argument("--live-db", type=Path, default=Path(_integrity_value('path_97373521e3ad')))
    parser.add_argument("--scratch-root", type=Path, default=Path(_integrity_value('path_bbd715b15233')))
    parser.add_argument("--evidence-root", type=Path, default=Path(_integrity_value('path_29857010143f')))
    parser.add_argument("--guardian", type=Path, default=Path(_integrity_value('path_3a1c616db98a')))
    parser.add_argument("--delta-sync", type=Path, default=Path(_integrity_value('path_fa0fad3a672c')))
    parser.add_argument("--delta-runtime", type=Path, default=Path(_integrity_value('path_a08e852b28cf')))
    parser.add_argument("--seed-user", default="integrity-seed")
    parser.add_argument("--keep-scratch", action="store_true")
    return parser.parse_args()


def load_latest_full(root: Path) -> tuple[Path, dict[str, Any]]:
    for receipt_path in sorted(root.glob("full-backup-*.json"), reverse=True):
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        archive = root / str((receipt.get("archive") or {}).get("name") or "")
        if archive.is_file() and sha256_file(archive) == (receipt.get("archive") or {}).get("sha256"):
            return archive, receipt
    raise RuntimeError("no digest-valid full backup and receipt pair found")


def verify_extracted(root: Path) -> dict[str, Any]:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    for item in manifest.get("files") or []:
        path = root / item["name"]
        if not path.is_file() or path.stat().st_size != int(item["bytes"]) or sha256_file(path) != item["sha256"]:
            raise RuntimeError(f"full backup manifest mismatch: {path}")
    return json.loads((root / "inventory.json").read_text(encoding="utf-8"))


def read_tail_segment(payload: Path, manifest: dict[str, Any]) -> tuple[list[str], list[list[Any]]]:
    if sha256_file(payload) != (manifest.get("payload") or {}).get("sha256"):
        raise RuntimeError(f"tail payload digest mismatch: {payload}")
    with gzip.open(payload, "rb") as handle:
        lines = handle.read().splitlines()
    if not lines:
        raise RuntimeError("empty tail segment")
    header = json.loads(lines[0])
    if header.get("protocol") != "integrity-memory-plane.tail-segment.v1":
        raise RuntimeError("tail protocol mismatch")
    columns = list(header.get("columns") or [])
    rows = [json.loads(line) for line in lines[1:]]
    digest = hashlib.sha256()
    for row in rows:
        encoded = canonical_json(row)
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    if digest.hexdigest() != manifest.get("row_sha256"):
        raise RuntimeError("tail row digest mismatch")
    if len(rows) != int(manifest.get("event_count") or -1):
        raise RuntimeError("tail event count mismatch")
    return columns, rows


def apply_tail(database: Path, tail_root: Path, full_cursor: int) -> dict[str, Any]:
    previous_manifest = ""
    cursor = full_cursor
    applied = 0
    segments = 0
    connection = sqlite3.connect(database)
    try:
        for manifest_path in sorted(tail_root.glob("events-*.manifest.json")):
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            first = int(manifest.get("first_cursor") or 0)
            last = int(manifest.get("last_cursor") or 0)
            if str(manifest.get("previous_manifest_sha256") or "") != previous_manifest:
                raise RuntimeError("tail manifest hash-chain mismatch")
            manifest_digest = sha256_file(manifest_path)
            if last <= full_cursor:
                previous_manifest = manifest_digest
                continue
            if first <= cursor:
                raise RuntimeError("overlapping or out-of-order tail segment")
            payload = tail_root / str((manifest.get("payload") or {}).get("name") or "")
            columns, rows = read_tail_segment(payload, manifest)
            quoted = ",".join('"' + item.replace('"', '""') + '"' for item in columns)
            placeholders = ",".join("?" for _ in columns)
            connection.executemany(f"INSERT INTO events({quoted}) VALUES({placeholders})", rows)
            connection.commit()
            cursor = last
            applied += len(rows)
            segments += 1
            previous_manifest = manifest_digest
    finally:
        connection.close()
    return {"target_cursor": cursor, "applied_event_count": applied, "segment_count": segments, "last_manifest_sha256": previous_manifest}


def parse_json_output(output: str) -> dict[str, Any]:
    for line in reversed(output.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise RuntimeError("command returned no JSON object")


def process_identity(username: str) -> dict[str, Any]:
    """Return a direct, non-escalating subprocess identity for a local account."""
    account = pwd.getpwnam(username)
    return {
        "user": account.pw_uid,
        "group": account.pw_gid,
        "extra_groups": os.getgrouplist(username, account.pw_gid),
    }


def run_guardian(
    command: list[str],
    timeout: int,
    *,
    run_as: str | None = None,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    identity = process_identity(run_as) if run_as else {}
    completed = subprocess.run(
        command,
        check=False,
        timeout=timeout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
        **identity,
    )
    if completed.returncode:
        raise RuntimeError(
            "Guardian command failed rc={} command={} stdout_tail={} stderr_tail={}".format(
                completed.returncode,
                command[-4:],
                completed.stdout[-1000:],
                completed.stderr[-2000:],
            )
        )
    return parse_json_output(completed.stdout)


def action_log_json(url: str, token: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={ACTION_LOG_READER_HEADER: token})
    with open_direct_http_request(request, timeout=5) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise RuntimeError("Action Log returned a non-object response")
    return value


def action_log_status(url: str) -> int:
    try:
        open_direct_http_request(urllib.request.Request(url), timeout=5)
    except urllib.error.HTTPError as exc:
        try:
            return int(exc.code)
        finally:
            exc.close()
    raise RuntimeError("Action Log accepted an anonymous protected read")


def runtime_json(url: str) -> dict[str, Any]:
    with open_direct_http_request(url, timeout=5) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise RuntimeError("Seed runtime returned a non-object response")
    return value


def runtime_post_rejected(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
    try:
        open_direct_http_request(request, timeout=5)
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(1024 * 1024)
        finally:
            exc.close()
        value = json.loads(raw)
        return {"status": exc.code, "body": value}
    raise RuntimeError("Seed runtime unexpectedly accepted POST")


def delta_runtime_rebuild(args: argparse.Namespace, catalog: Path, target_cursor: int, expected_count: int, scratch: Path) -> dict[str, Any]:
    initialize_json = run_guardian(
        [str(args.delta_sync), "initialize", "--catalog", str(catalog), "--profile", "total-loss-restore-initialize"],
        180,
        run_as=args.seed_user,
    )
    full_verify_json = run_guardian(
        [str(args.delta_sync), "full-verify", "--catalog", str(catalog), "--profile", "total-loss-restore-full-verify"],
        180,
        run_as=args.seed_user,
    )
    status_json = run_guardian(
        [str(args.delta_sync), "status", "--catalog", str(catalog)],
        60,
        run_as=args.seed_user,
    )
    port = free_port()
    process = subprocess.Popen(
        [str(args.delta_runtime), "--catalog", str(catalog), "--host", "127.0.0.1", "--port", str(port)],
        cwd=scratch,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **process_identity(args.seed_user),
    )
    try:
        deadline = time.monotonic() + 15
        health: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                health = runtime_json(f"http://127.0.0.1:{port}/healthz")
                break
            except Exception:
                time.sleep(0.1)
        if health is None:
            stdout, stderr = process.communicate(timeout=2)
            raise RuntimeError(f"delta Seed runtime did not start: {stdout[-500:]} {stderr[-1500:]}")
        capsule = runtime_json(f"http://127.0.0.1:{port}/v1/seed/capsule")
        queries = {}
        for query in ("Action Log canonical memory", "Guardian", "Seed Synapse", "power outage"):
            encoded = urllib.parse.urlencode({"q": query, "limit": "10"})
            result = runtime_json(f"http://127.0.0.1:{port}/v1/seed/search?{encoded}")
            queries[query] = int(result.get("count") or 0)
        connections = runtime_json(f"http://127.0.0.1:{port}/v1/seed/connections?event_id=1803&limit=20")
        rejected = runtime_post_rejected(f"http://127.0.0.1:{port}/v1/seed/capsule")

        def read_seal_matches(value: dict[str, Any]) -> bool:
            seal = value.get("catalog_read_seal")
            generation = seal.get("logical_generation") if isinstance(seal, dict) else None
            return bool(
                isinstance(seal, dict)
                and seal.get("protocol") == "integrity-guardian/seed-catalog-read-seal/v1"
                and seal.get("status") == "SEALED"
                and seal.get("wal_bytes") == 0
                and isinstance(generation, dict)
                and generation.get("checkpoint_digest") == value.get("checkpoint_digest")
            )

        checks = {
            "initialize_cursor_match": int(initialize_json.get("event_cursor") or -1) == target_cursor,
            "initialize_count_match": int(initialize_json.get("event_count") or -1) == expected_count,
            "full_verify_pass": full_verify_json.get("result") == "PASS",
            "full_verify_cursor_match": int(full_verify_json.get("event_cursor") or -1) == target_cursor,
            "full_verify_count_match": int(full_verify_json.get("event_count") or -1) == expected_count,
            "initialize_read_seal": read_seal_matches(initialize_json),
            "full_verify_read_seal": read_seal_matches(full_verify_json),
            "mmr_root_match": full_verify_json.get("mmr_root") == status_json.get("mmr_root") == health.get("source_digest"),
            "checkpoint_match": full_verify_json.get("checkpoint_digest") == status_json.get("checkpoint_digest") == health.get("catalog_digest"),
            "delta_since_full_zero": int(status_json.get("delta_since_full", -1)) == 0,
            "runtime_version": health.get("version") == "5.5.2rc2",
            "runtime_ready": health.get("ok") is True and health.get("status") == "READY",
            "runtime_cursor_match": int(health.get("event_cursor") or -1) == target_cursor,
            "runtime_count_match": int(health.get("event_count") or -1) == expected_count,
            "home_excluded": int(health.get("home_record_count", -1)) == 0 and int(capsule.get("home_record_count", -1)) == 0,
            "production_authority_false": health.get("production_authority") is False and capsule.get("production_authority") is False,
            "known_queries_nonempty": all(value > 0 for value in queries.values()),
            "early_event_path_found": connections.get("result") in {"CONNECTED", "CONTEXT_ONLY"} and int((connections.get("event") or {}).get("event_id") or 0) == 1803,
            "runtime_mutation_rejected": rejected.get("status") == 405 and (rejected.get("body") or {}).get("production_authority") is False,
        }
        return {
            "ok": all(checks.values()),
            "checks": checks,
            "initialize": {key: initialize_json.get(key) for key in ("protocol", "event_count", "event_cursor", "mmr_root", "checkpoint_digest", "last_full_source_digest", "last_full_catalog_digest")},
            "full_verify": full_verify_json,
            "status": status_json,
            "runtime_health": health,
            "runtime_capsule": {key: capsule.get(key) for key in ("protocol", "event_count", "maximum_event_id", "home_record_count", "production_authority", "source_digest", "catalog_digest")},
            "queries": queries,
            "early_event_connections": {"result": connections.get("result"), "event_id": int((connections.get("event") or {}).get("event_id") or 0), "link_count": len(connections.get("links") or []), "explanation_digest": connections.get("explanation_digest")},
            "post_rejection": rejected,
        }
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def seed_rebuild(args: argparse.Namespace, service_source: Path, restored_db: Path, scratch: Path, expected_count: int, target_cursor: int) -> dict[str, Any]:
    seed_account = pwd.getpwnam(args.seed_user)
    os.chown(scratch, seed_account.pw_uid, seed_account.pw_gid)
    os.chmod(scratch, 0o700)
    seed_root = scratch / "seed"
    seed_root.mkdir(mode=0o700)
    os.chown(seed_root, seed_account.pw_uid, seed_account.pw_gid)
    catalog = seed_root / "catalog.sqlite3"
    port = free_port()
    reader_token = secrets.token_hex(32)
    env = os.environ.copy()
    env.update({"CODEX_LOG_DB": str(restored_db), "CODEX_LOG_HOST": "127.0.0.1", "CODEX_LOG_PORT": str(port), "CODEX_LOG_TOKEN": reader_token, "CODEX_LOG_SEED_DIRTY_MARKER": str(scratch / "scratch-seed-dirty"), "PYTHONDONTWRITEBYTECODE": "1"})
    action_log = subprocess.Popen([sys.executable, str(service_source)], cwd=scratch, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                health = action_log_json(
                    f"http://127.0.0.1:{port}/api/health",
                    reader_token,
                )
                if health.get("ok"):
                    break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("reconstructed Action Log did not start for Seed rebuild")
        anonymous_protected_read_rejected = (
            action_log_status(
                f"http://127.0.0.1:{port}/api/events?limit=1&order=desc"
            )
            == 401
        )
        prefix = [str(args.guardian)]
        seed_sync_environment = {**os.environ, "CODEX_LOG_TOKEN": reader_token}
        sync_json = run_guardian(
            [
                *prefix,
                "seed-sync",
                "--catalog",
                str(catalog),
                "--source-url",
                f"http://127.0.0.1:{port}",
                "--profile",
                "total-loss-restore-drill",
                "--page-size",
                "1000",
            ],
            180,
            run_as=args.seed_user,
            environment=seed_sync_environment,
        )
        verify_json = run_guardian([*prefix, "seed-catalog-verify", "--catalog", str(catalog), "--expected-event-count", str(expected_count)], 180, run_as=args.seed_user)
        queries = {}
        for query in ("Action Log canonical memory", "Guardian", "Seed Synapse", "power outage"):
            result = run_guardian([*prefix, "seed-search", "--catalog", str(catalog), "--query", query, "--limit", "10"], 60, run_as=args.seed_user)
            queries[query] = int(result.get("count") or 0)
        connection_json = run_guardian([*prefix, "seed-connections", "--catalog", str(catalog), "--event-id", "1803", "--limit", "20"], 60, run_as=args.seed_user)
        connection_event_id = int((connection_json.get("event") or {}).get("event_id") or 0)
        connection_summary = {
            "protocol": connection_json.get("protocol"),
            "result": connection_json.get("result"),
            "event_id": connection_event_id,
            "link_count": len(connection_json.get("links") or []),
            "home_record_count": connection_json.get("home_record_count"),
            "production_authority": connection_json.get("production_authority"),
            "explanation_digest": connection_json.get("explanation_digest"),
        }
        checks = {
            "anonymous_protected_read_rejected": anonymous_protected_read_rejected,
            "sync_pass": sync_json.get("result") == "PASS",
            "seed_cursor_match": int(sync_json.get("event_cursor") or -1) == target_cursor,
            "verify_ok": verify_json.get("ok") is True,
            "event_count_match": int(verify_json.get("event_count") or -1) == expected_count,
            "home_excluded": int(verify_json.get("home_record_count", -1)) == 0,
            "production_authority_false": verify_json.get("production_authority") is False,
            "known_queries_nonempty": all(value > 0 for value in queries.values()),
            "early_event_path_found": connection_json.get("result") in {"CONNECTED", "CONTEXT_ONLY"} and connection_event_id == 1803,
        }
        delta = delta_runtime_rebuild(args, catalog, target_cursor, expected_count, scratch)
        checks["delta_mmr_runtime"] = bool(delta.get("ok"))
        return {"ok": all(checks.values()), "checks": checks, "sync": sync_json, "verify": verify_json, "queries": queries, "early_event_connections": connection_summary, "delta": delta}
    finally:
        if action_log.poll() is None:
            action_log.terminate()
            try:
                action_log.wait(timeout=3)
            except subprocess.TimeoutExpired:
                action_log.kill()
                action_log.wait(timeout=3)


def main() -> int:
    args = parse_args()
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    args.scratch_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    seed_account = pwd.getpwnam(args.seed_user)
    os.chown(args.scratch_root, 0, seed_account.pw_gid)
    os.chmod(args.scratch_root, 0o710)
    args.evidence_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    scratch = Path(tempfile.mkdtemp(prefix=f"restore-{stamp}-", dir=args.scratch_root))
    receipt_path = args.evidence_root / f"restore-drill-{stamp}.json"
    stage = "preflight"
    try:
        stage = "validate-executables"
        for required in (args.guardian, args.delta_sync, args.delta_runtime):
            if not required.is_file():
                raise RuntimeError(f"required restore executable is missing: {required}")
        stage = "load-full"
        archive, full_receipt = load_latest_full(args.full_root)
        extracted = scratch / "full"
        extracted.mkdir(mode=0o700)
        stage = "extract-full"
        with tarfile.open(archive, "r:gz") as bundle:
            bundle.extractall(extracted, filter="data")
        stage = "verify-full"
        inventory = verify_extracted(extracted)
        full_facts = inventory["facts"]
        restored_db = scratch / "restored.sqlite3"
        shutil.copy2(extracted / "codex-action-log.sqlite3", restored_db)
        stage = "apply-tail"
        tail = apply_tail(restored_db, args.tail_root, int(full_facts["event_cursor"]))
        stage = "restored-readback"
        with readonly_connection(restored_db) as restored:
            restored_facts = database_facts(restored)
        stage = "live-readback"
        with snapshot_connection(args.live_db) as live:
            live_cursor_at_reconstruction = int(live.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0])
            live_digest_at_target = row_digest(live, last_id=int(tail["target_cursor"]))
        stage = "action-log-smoke"
        service = restore_smoke(extracted / "codex_action_log.py", restored_db, restored_facts)
        atomic_json(
            receipt_path,
            {
                "protocol": PROTOCOL,
                "created_utc": dt.datetime.now(dt.UTC).isoformat(),
                "status": "in-progress",
                "stage": "action-log-reconstructed",
                "full_archive": str(archive),
                "tail": tail,
                "restored": restored_facts,
                "action_log_service": service,
            },
        )
        stage = "seed-rebuild"
        seed = seed_rebuild(args, extracted / "codex_action_log.py", restored_db, scratch, int(restored_facts["event_count"]), int(tail["target_cursor"]))
        stage = "final-verification"
        checks = {
            "full_archive_digest": sha256_file(archive) == (full_receipt.get("archive") or {}).get("sha256"),
            "full_manifest": True,
            "restored_cursor_match": int(restored_facts["event_cursor"]) == int(tail["target_cursor"]),
            "recovery_boundary_not_ahead_of_live": int(tail["target_cursor"]) <= live_cursor_at_reconstruction,
            "restored_row_digest_match": restored_facts["row_sha256"] == live_digest_at_target,
            "append_only": bool(restored_facts["append_only_ok"]),
            "action_log_service_smoke": bool(service.get("ok")),
            "seed_rebuild": bool(seed.get("ok")),
        }
        receipt = {"protocol": PROTOCOL, "created_utc": dt.datetime.now(dt.UTC).isoformat(), "status": "pass" if all(checks.values()) else "failed", "checks": checks, "full_archive": {"path": str(archive), "sha256": sha256_file(archive), "cursor": full_facts["event_cursor"]}, "tail": tail, "live_cursor_at_reconstruction": live_cursor_at_reconstruction, "recovery_point_lag_events": live_cursor_at_reconstruction - int(tail["target_cursor"]), "restored": restored_facts, "action_log_service": service, "seed": seed, "delta_artifacts": {"sync": {"path": str(args.delta_sync), "sha256": sha256_file(args.delta_sync)}, "runtime": {"path": str(args.delta_runtime), "sha256": sha256_file(args.delta_runtime)}}, "scratch_retained": args.keep_scratch}
        atomic_json(receipt_path, receipt)
        print(json.dumps({"protocol": PROTOCOL + ".result", "status": receipt["status"], "checks": checks, "receipt_path": str(receipt_path)}, ensure_ascii=False, sort_keys=True))
        return 0 if all(checks.values()) else 1
    except Exception as exc:
        failure = {
            "protocol": PROTOCOL,
            "created_utc": dt.datetime.now(dt.UTC).isoformat(),
            "status": "failed",
            "stage": stage,
            "error_type": type(exc).__name__,
            "error": str(exc)[-4000:],
        }
        atomic_json(receipt_path, failure)
        print(json.dumps({"protocol": PROTOCOL + ".result", "status": "failed", "receipt_path": str(receipt_path), "error_type": type(exc).__name__, "error": str(exc)[-1000:]}, ensure_ascii=False, sort_keys=True))
        return 1
    finally:
        if not args.keep_scratch:
            shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
