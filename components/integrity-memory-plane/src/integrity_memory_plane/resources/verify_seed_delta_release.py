#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independently verify a self-contained 5.5.2rc2 Seed delta bundle."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import ast
import hashlib
import importlib.util
import json
import re
import sqlite3
import tempfile
from contextlib import closing
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
# Universal RC source review: neutral protocol/path substitutions only.
# These are pinned expected bytes, not values derived from a supplied bundle.
# The delta runtime version remains independent of the Guardian package version.
REVIEWED_SOURCE_SHA256 = {
    "tools/integrity-memory-plane/seed_catalog_read_seal.py": (
        _integrity_value('pin_613e383a917d')
    ),
    "tools/integrity-memory-plane/seed_delta_sync.py": (
        _integrity_value('pin_87943255e51f')
    ),
    "tools/integrity-memory-plane/seed_run_retention.py": (
        _integrity_value('pin_5361b8daf0cb')
    ),
    "tools/integrity-memory-plane/restore_drill.py": (
        _integrity_value('pin_1309109372e4')
    ),
}
MANIFEST_KEYS = {
    "schema",
    "created_utc",
    "old_version",
    "new_version",
    "semantic_contract",
    "consumers",
    "release_files",
    "live_mutations_performed",
    "production_authority",
    "bundle_digest",
}


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"release file custody mismatch: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _function(tree: ast.AST, name: str) -> ast.FunctionDef:
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(matches) != 1:
        raise RuntimeError(f"release semantic function mismatch: {name}")
    return matches[0]


def _call_count(node: ast.AST, name: str) -> int:
    return sum(
        1
        for item in ast.walk(node)
        if isinstance(item, ast.Call)
        and isinstance(item.func, ast.Name)
        and item.func.id == name
    )


def _string_constants(node: ast.AST) -> set[str]:
    return {
        item.value
        for item in ast.walk(node)
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    }


def _verify_python_semantics(root: Path) -> None:
    plane = root / "release/tools/integrity-memory-plane"
    helper_tree = ast.parse(
        (plane / "seed_catalog_read_seal.py").read_text(encoding="utf-8")
    )
    helper = _function(helper_tree, "seal_catalog_for_immutable_read")
    if "PRAGMA main.wal_checkpoint(TRUNCATE)" not in _string_constants(helper):
        raise RuntimeError("Seed immutable read-seal checkpoint contract mismatch")
    if "point-in-time-not-a-lease" not in _string_constants(helper):
        raise RuntimeError("Seed immutable read-seal scope contract mismatch")

    sync_tree = ast.parse((plane / "seed_delta_sync.py").read_text(encoding="utf-8"))
    if _call_count(_function(sync_tree, "initialize"), "seal_catalog_for_immutable_read") != 2:
        raise RuntimeError("Seed initialize read-seal path mismatch")
    if _call_count(_function(sync_tree, "import_delta"), "seal_catalog_for_immutable_read") != 1:
        raise RuntimeError("Seed delta import read-seal path mismatch")
    if _call_count(_function(sync_tree, "full_verify"), "seal_catalog_for_immutable_read") != 1:
        raise RuntimeError("Seed full verify read-seal path mismatch")
    if _call_count(_function(sync_tree, "read_seal"), "seal_catalog_for_immutable_read") != 1:
        raise RuntimeError("Seed checkpoint-only recovery path mismatch")
    sync_main = _function(sync_tree, "main")
    if (
        _call_count(sync_main, "initialize") < 2
        or _call_count(sync_main, "read_seal") != 1
        or "catalog_read_seal" not in _string_constants(sync_main)
    ):
        raise RuntimeError("Seed delta noop reseal path mismatch")

    retention_tree = ast.parse(
        (plane / "seed_run_retention.py").read_text(encoding="utf-8")
    )
    retention_main = _function(retention_tree, "main")
    if _call_count(retention_main, "seal_catalog_for_immutable_read") != 2:
        raise RuntimeError("Seed retention read-seal path mismatch")
    if "catalog_read_seal" not in _string_constants(retention_main):
        raise RuntimeError("Seed retention read-seal receipt mismatch")


def _verify_read_seal_behavior(root: Path) -> None:
    helper_path = (
        root
        / "release/tools/integrity-memory-plane/seed_catalog_read_seal.py"
    )
    spec = importlib.util.spec_from_file_location(
        "_bundled_seed_catalog_read_seal",
        helper_path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Seed immutable read-seal behavioral probe import failed")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)

    with tempfile.TemporaryDirectory(prefix="seed-read-seal-probe-") as temporary:
        catalog = Path(temporary) / "catalog.sqlite3"
        writer = sqlite3.connect(catalog)
        reader: sqlite3.Connection | None = sqlite3.connect(catalog)
        try:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("PRAGMA wal_autocheckpoint=0")
            writer.execute("CREATE TABLE probe(value INTEGER NOT NULL)")
            writer.execute("INSERT INTO probe VALUES(1)")
            writer.commit()
            assert reader is not None
            reader.execute("BEGIN")
            reader.execute("SELECT COUNT(*) FROM probe").fetchone()
            writer.execute("INSERT INTO probe VALUES(2)")
            writer.commit()

            with closing(sqlite3.connect(catalog)) as sealing:
                try:
                    helper.seal_catalog_for_immutable_read(
                        sealing,
                        catalog,
                        generation_reader=lambda current: {
                            "row_count": int(
                                current.execute("SELECT COUNT(*) FROM probe").fetchone()[0]
                            )
                        },
                        busy_timeout_ms=10,
                    )
                except helper.SeedCatalogReadSealError as exc:
                    if (
                        exc.reason_code != "seed_catalog_checkpoint_busy"
                        or exc.catalog_state != "COMMITTED_UNSEALED"
                    ):
                        raise RuntimeError(
                            "Seed immutable read-seal pinned-reader classification mismatch"
                        ) from exc
                else:
                    raise RuntimeError(
                        "Seed immutable read-seal accepted a pinned reader"
                    )
            reader.rollback()
            reader.close()
            reader = None

            expected_generation = {"row_count": 2, "maximum_value": 2}
            try:
                with closing(sqlite3.connect(catalog)) as sealing:
                    receipt = helper.seal_catalog_for_immutable_read(
                        sealing,
                        catalog,
                        generation_reader=lambda current: {
                            "row_count": int(
                                current.execute("SELECT COUNT(*) FROM probe").fetchone()[0]
                            ),
                            "maximum_value": int(
                                current.execute("SELECT MAX(value) FROM probe").fetchone()[0]
                            ),
                        },
                        expected_generation=expected_generation,
                        busy_timeout_ms=1_000,
                    )
            except Exception as exc:
                raise RuntimeError(
                    "Seed immutable read-seal behavioral recovery failed"
                ) from exc
            wal = catalog.with_name(catalog.name + "-wal")
            if (
                receipt.get("status") != "SEALED"
                or receipt.get("scope") != "point-in-time-not-a-lease"
                or receipt.get("catalog_state") != "COMMITTED_SEALED"
                or receipt.get("logical_generation") != expected_generation
                or receipt.get("wal_bytes") != 0
                or (wal.stat().st_size if wal.exists() else 0) != 0
            ):
                raise RuntimeError("Seed immutable read-seal behavioral receipt mismatch")
        finally:
            if reader is not None:
                reader.rollback()
                reader.close()
            writer.close()


def _verify_reviewed_sources(root: Path) -> None:
    for relative, expected in REVIEWED_SOURCE_SHA256.items():
        actual = sha256(root / "release" / relative)
        if actual != expected:
            raise RuntimeError(f"reviewed source digest mismatch: {relative}")


def verify(root: Path, project: Path | None = None) -> dict[str, Any]:
    manifest_path = root / "MANIFEST.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise RuntimeError("release manifest custody mismatch")
    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != MANIFEST_KEYS:
        raise RuntimeError("release manifest key set mismatch")
    if value.get("schema") != SCHEMA:
        raise RuntimeError("release manifest schema mismatch")
    if value.get("old_version") != OLD_VERSION or value.get("new_version") != NEW_VERSION:
        raise RuntimeError("release version contract mismatch")
    if value.get("semantic_contract") != SEMANTIC_CONTRACT:
        raise RuntimeError("release semantic contract mismatch")
    if value.get("live_mutations_performed") is not False:
        raise RuntimeError("release live-mutation boundary mismatch")
    if value.get("production_authority") is not False:
        raise RuntimeError("release authority boundary mismatch")
    claimed = str(value.get("bundle_digest") or "")
    core = dict(value)
    core.pop("bundle_digest")
    actual = "sha256:" + hashlib.sha256(DIGEST_DOMAIN + canonical(core)).hexdigest()
    if claimed != actual:
        raise RuntimeError("release bundle digest mismatch")

    consumer_items = value.get("consumers")
    if not isinstance(consumer_items, list) or len(consumer_items) != len(CONSUMERS):
        raise RuntimeError("release consumer inventory mismatch")
    consumers = {item["relative_path"]: item for item in consumer_items}
    if set(consumers) != set(CONSUMERS):
        raise RuntimeError("release consumer inventory mismatch")
    for relative in CONSUMERS:
        item = consumers[relative]
        if set(item) != {
            "relative_path",
            "replacement_count",
            "preimage_sha256",
            "overlay_sha256",
        } or item["replacement_count"] != 1:
            raise RuntimeError(f"consumer manifest contract mismatch: {relative}")
        preimage = root / "rollback" / relative
        overlay = root / "overlay" / relative
        if sha256(preimage) != item["preimage_sha256"] or sha256(overlay) != item[
            "overlay_sha256"
        ]:
            raise RuntimeError(f"consumer digest mismatch: {relative}")
        text = overlay.read_text(encoding="utf-8")
        if text.count(NEW_VERSION) != 1 or OLD_VERSION in text:
            raise RuntimeError(f"consumer version replacement mismatch: {relative}")
        if project is not None and sha256(project / relative) != item["preimage_sha256"]:
            raise RuntimeError(f"live consumer moved since bundle build: {relative}")

    release_items = value.get("release_files")
    if not isinstance(release_items, list) or len(release_items) != len(RELEASE_FILES):
        raise RuntimeError("release file inventory mismatch")
    files = {item["relative_path"]: item for item in release_items}
    if set(files) != set(RELEASE_FILES):
        raise RuntimeError("release file inventory mismatch")
    for relative in RELEASE_FILES:
        item = files[relative]
        expected_mode = "0755" if Path(relative).suffix == ".py" else "0644"
        if set(item) != {"relative_path", "sha256", "bytes", "mode"}:
            raise RuntimeError(f"release file manifest contract mismatch: {relative}")
        if item["mode"] != expected_mode:
            raise RuntimeError(f"release file mode contract mismatch: {relative}")
        path = root / "release" / relative
        if sha256(path) != item["sha256"] or path.stat().st_size != int(item["bytes"]):
            raise RuntimeError(f"release file digest mismatch: {relative}")

    runtime = (
        root / "release/tools/integrity-memory-plane/seed_delta_runtime.py"
    ).read_text(encoding="utf-8")
    if f'DELTA_RUNTIME_VERSION = "{NEW_VERSION}"' not in runtime:
        raise RuntimeError("delta runtime version mismatch")
    _verify_python_semantics(root)
    _verify_read_seal_behavior(root)
    _verify_reviewed_sources(root)

    systemd_root = root / "release/tools/integrity-memory-plane/systemd"
    sync_dropin = (systemd_root / "90-integrity-seed-sync-delta.conf").read_text(
        encoding="utf-8"
    )
    runtime_dropin = (systemd_root / "90-integrity-seed-runtime-delta.conf").read_text(
        encoding="utf-8"
    )
    retention_unit = (
        systemd_root / "integrity-memory-seed-run-retention.service"
    ).read_text(encoding="utf-8")
    restore_unit = (
        systemd_root / "integrity-memory-restore-drill.service"
    ).read_text(encoding="utf-8")
    if not re.search(r"^ExecStart=$", sync_dropin, re.MULTILINE) or "seed_delta_sync.py sync" not in sync_dropin:
        raise RuntimeError("sync drop-in reset/command mismatch")
    if not re.search(r"^ExecStart=$", runtime_dropin, re.MULTILINE) or "seed_delta_runtime.py" not in runtime_dropin or "full-verify" not in runtime_dropin:
        raise RuntimeError("runtime drop-in startup seal mismatch")
    if "seed_run_retention.py" not in retention_unit:
        raise RuntimeError("retention unit command mismatch")
    if "restore_drill.py" not in restore_unit:
        raise RuntimeError("restore drill unit command mismatch")
    return {
        "schema": SCHEMA + ".verification",
        "ok": True,
        "bundle_digest": claimed,
        "consumer_count": len(consumers),
        "release_file_count": len(files),
        "live_preimages_match": project is not None,
        "production_authority": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--project", type=Path)
    args = parser.parse_args()
    print(
        json.dumps(
            verify(
                args.root.resolve(),
                args.project.resolve() if args.project else None,
            ),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
