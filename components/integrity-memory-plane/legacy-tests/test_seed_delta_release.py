from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from build_seed_delta_release import (
    CONSUMERS,
    RELEASE_FILES,
    build,
    canonical,
)
from verify_seed_delta_release import verify


def make_project(root: Path) -> None:
    for relative in CONSUMERS:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("before 5.5.2rc1 after\n", encoding="utf-8")
    source_root = Path(__file__).resolve().parents[1]
    for relative in RELEASE_FILES:
        source = source_root / Path(relative).relative_to("tools/integrity-memory-plane")
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())


def test_release_bundle_has_exact_overlay_and_rollback(tmp_path: Path) -> None:
    project = tmp_path / "project"
    bundle = tmp_path / "bundle"
    make_project(project)
    manifest = build(project, bundle, "2026-08-08T17:00:00Z")
    result = verify(bundle, project)
    assert result["ok"] is True
    assert result["bundle_digest"] == manifest["bundle_digest"]
    assert result["consumer_count"] == len(CONSUMERS)
    assert result["release_file_count"] == len(RELEASE_FILES)


def test_bundled_verifier_runs_without_checkout_pythonpath(tmp_path: Path) -> None:
    project = tmp_path / "project"
    bundle = tmp_path / "bundle"
    make_project(project)
    build(project, bundle, "2026-08-08T17:00:00Z")
    verifier = (
        bundle
        / "release/tools/integrity-memory-plane/verify_seed_delta_release.py"
    )
    environment = {
        key: value for key, value in os.environ.items() if key.upper() != "PYTHONPATH"
    }
    completed = subprocess.run(
        [
            sys.executable,
            str(verifier),
            "--root",
            str(bundle),
            "--project",
            str(project),
        ],
        cwd=tmp_path,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(completed.stdout)["ok"] is True


def test_verifier_rejects_overlay_tamper(tmp_path: Path) -> None:
    project = tmp_path / "project"
    bundle = tmp_path / "bundle"
    make_project(project)
    build(project, bundle, "2026-08-08T17:00:00Z")
    target = bundle / "overlay" / CONSUMERS[0]
    target.write_text(target.read_text(encoding="utf-8") + "tamper\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="consumer digest mismatch"):
        verify(bundle, project)


def test_verifier_rejects_release_without_immutable_read_seal(tmp_path: Path) -> None:
    project = tmp_path / "project"
    bundle = tmp_path / "bundle"
    make_project(project)
    helper = project / "tools/integrity-memory-plane/seed_catalog_read_seal.py"
    helper.write_text(
        helper.read_text(encoding="utf-8").replace(
            "PRAGMA main.wal_checkpoint(TRUNCATE)",
            "PRAGMA main.wal_checkpoint(PASSIVE)",
        ),
        encoding="utf-8",
    )
    build(project, bundle, "2026-08-08T17:00:00Z")
    with pytest.raises(RuntimeError, match="checkpoint contract mismatch"):
        verify(bundle, project)


def test_verifier_behaviorally_rejects_dead_checkpoint_with_contract_string(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    bundle = tmp_path / "bundle"
    make_project(project)
    helper = project / "tools/integrity-memory-plane/seed_catalog_read_seal.py"
    helper.write_text(
        helper.read_text(encoding="utf-8").replace(
            'checkpoint = connection.execute("PRAGMA main.wal_checkpoint(TRUNCATE)").fetchone()',
            '"PRAGMA main.wal_checkpoint(TRUNCATE)"\n        checkpoint = (0, 0, 0)',
        ),
        encoding="utf-8",
    )
    build(project, bundle, "2026-08-08T17:00:00Z")
    with pytest.raises(RuntimeError, match="behavioral recovery failed"):
        verify(bundle, project)


def test_verifier_rejects_sync_with_one_seal_path_removed(tmp_path: Path) -> None:
    project = tmp_path / "project"
    bundle = tmp_path / "bundle"
    make_project(project)
    sync = project / "tools/integrity-memory-plane/seed_delta_sync.py"
    sync.write_text(
        sync.read_text(encoding="utf-8").replace(
            "seal_catalog_for_immutable_read(",
            "removed_read_seal_for_test(",
            1,
        ),
        encoding="utf-8",
    )
    build(project, bundle, "2026-08-08T17:00:00Z")
    with pytest.raises(RuntimeError, match="initialize read-seal path mismatch"):
        verify(bundle, project)


def test_verifier_rejects_unreachable_writer_seal_with_same_ast_call_count(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    bundle = tmp_path / "bundle"
    make_project(project)
    sync = project / "tools/integrity-memory-plane/seed_delta_sync.py"
    source = sync.read_text(encoding="utf-8").replace(
        "seal_catalog_for_immutable_read(",
        "removed_read_seal_for_test(",
        1,
    )
    source = source.replace(
        "    started = utc_now()",
        (
            "    if False:\n"
            "        seal_catalog_for_immutable_read(\n"
            "            None, None, generation_reader=lambda current: {}\n"
            "        )\n"
            "    started = utc_now()"
        ),
        1,
    )
    sync.write_text(source, encoding="utf-8")
    build(project, bundle, "2026-08-08T17:00:00Z")
    with pytest.raises(RuntimeError, match="reviewed source digest mismatch"):
        verify(bundle, project)


def test_verifier_rejects_retention_without_both_seal_paths(tmp_path: Path) -> None:
    project = tmp_path / "project"
    bundle = tmp_path / "bundle"
    make_project(project)
    retention = project / "tools/integrity-memory-plane/seed_run_retention.py"
    retention.write_text(
        retention.read_text(encoding="utf-8").replace(
            "seal_catalog_for_immutable_read(",
            "removed_read_seal_for_test(",
            1,
        ),
        encoding="utf-8",
    )
    build(project, bundle, "2026-08-08T17:00:00Z")
    with pytest.raises(RuntimeError, match="retention read-seal path mismatch"):
        verify(bundle, project)


def test_verifier_rejects_redigested_v1_manifest(tmp_path: Path) -> None:
    project = tmp_path / "project"
    bundle = tmp_path / "bundle"
    make_project(project)
    build(project, bundle, "2026-08-08T17:00:00Z")
    manifest = bundle / "MANIFEST.json"
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["schema"] = "integrity-seed-delta-release.v1"
    core = dict(value)
    core.pop("bundle_digest")
    value["bundle_digest"] = "sha256:" + hashlib.sha256(
        b"integrity-seed-delta-release-v1\0" + canonical(core)
    ).hexdigest()
    manifest.chmod(0o600)
    manifest.write_bytes(canonical(value) + b"\n")
    with pytest.raises(RuntimeError, match="schema mismatch"):
        verify(bundle, project)


def test_universal_writer_review_pins_all_actual_sources() -> None:
    from build_seed_delta_release import SEMANTIC_CONTRACT as build_contract
    from verify_seed_delta_release import REVIEWED_SOURCE_SHA256, SEMANTIC_CONTRACT

    assert build_contract == SEMANTIC_CONTRACT
    assert SEMANTIC_CONTRACT["profile"] == "seed-delta-read-seal-v2-universal-rc1"
    assert len(REVIEWED_SOURCE_SHA256) == 4
    repository = ROOT.parents[1]
    for relative, expected in REVIEWED_SOURCE_SHA256.items():
        assert hashlib.sha256((repository / relative).read_bytes()).hexdigest() == expected


def test_previous_source_profile_cannot_be_redigested_as_current(tmp_path: Path) -> None:
    from verify_seed_delta_release import DIGEST_DOMAIN

    project, bundle = tmp_path / "project", tmp_path / "bundle"
    make_project(project)
    build(project, bundle, "2026-09-17T00:00:00Z")
    manifest = bundle / "MANIFEST.json"
    value = json.loads(manifest.read_bytes())
    value["semantic_contract"]["profile"] = "seed-delta-read-seal-v2"
    core = dict(value)
    core.pop("bundle_digest")
    value["bundle_digest"] = "sha256:" + hashlib.sha256(DIGEST_DOMAIN + canonical(core)).hexdigest()
    manifest.chmod(0o600)
    manifest.write_bytes(canonical(value) + b"\n")
    with pytest.raises(RuntimeError, match="semantic contract mismatch"):
        verify(bundle, project)
