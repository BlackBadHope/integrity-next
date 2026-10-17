#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a digest-bound 5.5.2rc2 Seed delta cutover/rollback bundle."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

SCHEMA = "integrity-seed-delta-release.v2"
DIGEST_DOMAIN = b"integrity-seed-delta-release-v2\0"
OLD_VERSION = "5.5.2rc1"
NEW_VERSION = "5.5.2rc2"
CONSUMERS = (
    "tools/codex-seed-context.ps1",
    "tools/integrity_task_close.py",
    "tools/verify-zero-session-integrity-behavior.py",
    "tools/check-action-log-startup-contract.ps1",
    "tools/tests/test_integrity_memory_startup_lts.py",
    "tools/tests/test_integrity_task_close.py",
    ".codex/hooks/workspace_action_log_mind.py",
)
RELEASE_FILES = (
    "tools/integrity-memory-plane/build_seed_delta_release.py",
    "tools/integrity-memory-plane/verify_seed_delta_release.py",
    "tools/integrity-memory-plane/seed_catalog_read_seal.py",
    "tools/integrity-memory-plane/seed_delta_sync.py",
    "tools/integrity-memory-plane/seed_delta_runtime.py",
    "tools/integrity-memory-plane/seed_run_retention.py",
    "tools/integrity-memory-plane/restore_drill.py",
    "tools/integrity-memory-plane/P0_5_DELTA_RELEASE_CANDIDATE_RU.md",
    "tools/integrity-memory-plane/systemd/90-integrity-seed-sync-delta.conf",
    "tools/integrity-memory-plane/systemd/90-integrity-seed-runtime-delta.conf",
    "tools/integrity-memory-plane/systemd/integrity-seed-delta-full-verify.service",
    "tools/integrity-memory-plane/systemd/integrity-seed-delta-full-verify.timer",
    "tools/integrity-memory-plane/systemd/integrity-memory-seed-run-retention.service",
    "tools/integrity-memory-plane/systemd/integrity-memory-seed-run-retention.timer",
    "tools/integrity-memory-plane/systemd/integrity-memory-restore-drill.service",
    "tools/integrity-memory-plane/systemd/integrity-memory-restore-drill.timer",
)
SEMANTIC_CONTRACT = {
    "profile": "seed-delta-read-seal-v2-universal-rc1",
    "read_seal": {
        "protocol": "integrity-guardian/seed-catalog-read-seal/v1",
        "scope": "point-in-time-not-a-lease",
        "checkpoint_pragma": "PRAGMA main.wal_checkpoint(TRUNCATE)",
        "accepted_checkpoint_rows": [[0, 0, 0], [0, -1, -1]],
        "wal_bytes": 0,
        "pass_requires_seal": True,
        "behavioral_probe": "pinned-reader-busy-then-generation-bound-recovery-v1",
        "required_writer_paths": [
            "seed_delta_sync.initialize-existing",
            "seed_delta_sync.initialize-new",
            "seed_delta_sync.import-delta",
            "seed_delta_sync.full-verify",
            "seed_delta_sync.delta-noop-reseal",
            "seed_run_retention.pass",
            "seed_run_retention.noop-recovery",
        ],
    },
    "self_verifier_included": True,
    "reviewed_writer_digests_pinned": True,
    "atomic_installer_included": False,
}


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def copy_file(source: Path, target: Path, mode: int | None = None) -> dict[str, Any]:
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copy2(source, target)
    if mode is not None:
        target.chmod(mode)
    return {"path": str(target), "sha256": sha256(target), "bytes": target.stat().st_size}


def build(project: Path, output: Path, created_utc: str) -> dict[str, Any]:
    if output.exists():
        raise RuntimeError(f"release output already exists: {output}")
    output.mkdir(parents=True, mode=0o700)
    consumers: list[dict[str, Any]] = []
    for relative in CONSUMERS:
        source = project / relative
        raw = source.read_text(encoding="utf-8")
        if raw.count(OLD_VERSION) != 1 or NEW_VERSION in raw:
            raise RuntimeError(f"consumer version preimage mismatch: {relative}")
        preimage = output / "rollback" / relative
        overlay = output / "overlay" / relative
        pre = copy_file(source, preimage)
        overlay.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        overlay.write_text(raw.replace(OLD_VERSION, NEW_VERSION), encoding="utf-8")
        overlay.chmod(source.stat().st_mode & 0o777)
        consumers.append(
            {
                "relative_path": relative,
                "replacement_count": 1,
                "preimage_sha256": pre["sha256"],
                "overlay_sha256": sha256(overlay),
            }
        )
    release_files: list[dict[str, Any]] = []
    for relative in RELEASE_FILES:
        source = project / relative
        mode = 0o755 if source.suffix == ".py" else 0o644
        target = output / "release" / relative
        copied = copy_file(source, target, mode=mode)
        release_files.append({"relative_path": relative, "sha256": copied["sha256"], "bytes": copied["bytes"], "mode": f"{mode:04o}"})
    inventory = {
        "schema": SCHEMA,
        "created_utc": created_utc,
        "old_version": OLD_VERSION,
        "new_version": NEW_VERSION,
        "semantic_contract": SEMANTIC_CONTRACT,
        "consumers": consumers,
        "release_files": release_files,
        "live_mutations_performed": False,
        "production_authority": False,
    }
    inventory["bundle_digest"] = "sha256:" + hashlib.sha256(
        DIGEST_DOMAIN + canonical(inventory)
    ).hexdigest()
    manifest = output / "MANIFEST.json"
    manifest.write_bytes(canonical(inventory) + b"\n")
    manifest.chmod(0o400)
    return inventory


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", type=Path, default=Path(_integrity_value('path_6c566dbbf48b')))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--created-utc", required=True)
    args = parser.parse_args()
    manifest = build(args.project.resolve(), args.output.resolve(), args.created_utc)
    print(json.dumps(manifest, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
