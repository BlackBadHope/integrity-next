from __future__ import annotations

import argparse
import copy
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file  # noqa: E402
from p2_physical_stage_admission import run  # noqa: E402


def write_receipt(path: Path, value: dict) -> Path:
    payload = copy.deepcopy(value)
    payload["evidence_sha256"] = sha256_bytes(canonical_json(payload))
    atomic_json(path, payload, mode=0o440)
    return path


def fixtures(tmp_path: Path) -> argparse.Namespace:
    root = tmp_path / "physical"
    root.mkdir()
    physical = {
        "protocol": "integrity-memory-plane.p2-physical-history-lab.v1.receipt",
        "status": "FAIL",
        "stage": "physical-1000000",
        "physical_event_count": 1_000_000,
        "sparse_or_extrapolated_run": False,
        "physical_billion_event_run_completed": True,
        "checks": {
            "physical_raw_rows_equal_target": True,
            "compact_rows_equal_target": True,
            "cursor_parity_100_percent": True,
            "event_uid_duplicate_zero": True,
            "manifest_chain_verified": True,
            "exact_lookup_p95_lte_1000ms": False,
            "semantic_retrieval_lte_2000ms": False,
        },
        "blockers": ["exact_lookup_p95_lte_1000ms", "semantic_retrieval_lte_2000ms"],
        "production_authority": False,
        "memory_grants_authority": False,
    }
    physical_path = write_receipt(tmp_path / "physical.json", physical)
    physical_value = __import__("json").loads(physical_path.read_text())
    verify = {
        "protocol": "integrity-memory-plane.p2-physical-verify-replay.v1.receipt",
        "status": "PASS",
        "source_root": str(root.resolve()),
        "physical_event_count": 1_000_000,
        "physical_receipt_evidence_sha256": physical_value["evidence_sha256"],
        "index_state_sha256": "1" * 64,
        "catalog_state_sha256": "2" * 64,
        "artifact_sha256": {"wrapper": "3" * 64, "index": "4" * 64},
        "verify": {"manifest_head_sha256": "5" * 64},
        "checks": {"bounded_verifier_pass": True, "uid_catalog_matches_payload": True},
        "production_authority": False,
        "memory_grants_authority": False,
    }
    verify_path = write_receipt(tmp_path / "verify.json", verify)
    verify_value = __import__("json").loads(verify_path.read_text())
    retrieval = {
        "protocol": "integrity-memory-plane.p2-physical-retrieval-replay.v1.receipt",
        "status": "PASS",
        "source_root": str(root.resolve()),
        "physical_event_count": 1_000_000,
        "physical_receipt_evidence_sha256": physical_value["evidence_sha256"],
        "verify_receipt_evidence_sha256": verify_value["evidence_sha256"],
        "reader_attestation": {"snapshot_sha256": "2" * 64},
        "artifact_sha256": {"wrapper": "6" * 64, "retrieval": "7" * 64},
        "checks": {"exact": True, "semantic": True, "negative": True},
        "production_authority": False,
        "memory_grants_authority": False,
    }
    retrieval_path = write_receipt(tmp_path / "retrieval.json", retrieval)
    return argparse.Namespace(
        root=root,
        physical_receipt=physical_path,
        verify_receipt=verify_path,
        retrieval_receipt=retrieval_path,
        previous_admission=None,
        receipt_root=tmp_path / "admissions",
    )


def bind_count(args: argparse.Namespace, tmp_path: Path, count: int) -> None:
    root = tmp_path / f"physical-{count}"
    root.mkdir(exist_ok=True)
    args.root = root
    physical = __import__("json").loads(args.physical_receipt.read_text())
    physical.pop("evidence_sha256")
    physical["physical_event_count"] = count
    physical["stage"] = f"physical-{count}"
    args.physical_receipt = write_receipt(tmp_path / f"physical-{count}.json", physical)
    physical_value = __import__("json").loads(args.physical_receipt.read_text())

    verify = __import__("json").loads(args.verify_receipt.read_text())
    verify.pop("evidence_sha256")
    verify["source_root"] = str(root.resolve())
    verify["physical_event_count"] = count
    verify["physical_receipt_evidence_sha256"] = physical_value["evidence_sha256"]
    args.verify_receipt = write_receipt(tmp_path / f"verify-{count}.json", verify)
    verify_value = __import__("json").loads(args.verify_receipt.read_text())

    retrieval = __import__("json").loads(args.retrieval_receipt.read_text())
    retrieval.pop("evidence_sha256")
    retrieval["source_root"] = str(root.resolve())
    retrieval["physical_event_count"] = count
    retrieval["physical_receipt_evidence_sha256"] = physical_value["evidence_sha256"]
    retrieval["verify_receipt_evidence_sha256"] = verify_value["evidence_sha256"]
    args.retrieval_receipt = write_receipt(tmp_path / f"retrieval-{count}.json", retrieval)


def write_legacy_genesis(path: Path, result: dict) -> Path:
    legacy = copy.deepcopy(result)
    legacy.pop("receipt_path", None)
    legacy.pop("evidence_sha256")
    legacy["checks"].pop("stage_predecessor_exact")
    legacy.pop("previous_stage_admission_file_sha256")
    return write_receipt(path, legacy)


def test_one_million_admission_passes_but_cannot_green_billion(tmp_path: Path) -> None:
    args = fixtures(tmp_path)
    result = run(args)
    assert result["status"] == "PASS"
    assert result["milestone_checks"]["physical_1m_completed"] is True
    assert result["physical_billion_event_run_completed"] is False
    assert result["release_checks"]["physical_billion_event_run_completed"] is False
    assert "physical_billion_event_run_completed" in result["global_release_blockers"]
    assert result["checks"]["stage_predecessor_exact"] is True
    assert result["previous_stage_admission_sha256"] == ""
    assert result["previous_stage_admission_file_sha256"] == ""


def test_ten_million_links_exact_immediate_predecessor_digests(tmp_path: Path) -> None:
    args = fixtures(tmp_path)
    genesis = run(args)
    previous_path = Path(genesis["receipt_path"])
    bind_count(args, tmp_path, 10_000_000)
    args.previous_admission = previous_path

    result = run(args)

    assert result["status"] == "PASS"
    assert result["checks"]["stage_predecessor_exact"] is True
    assert result["previous_stage_admission_sha256"] == genesis["evidence_sha256"]
    assert result["previous_stage_admission_file_sha256"] == sha256_file(previous_path)


def test_ten_million_accepts_only_safe_legacy_genesis_read(tmp_path: Path) -> None:
    args = fixtures(tmp_path)
    genesis = run(args)
    legacy_path = write_legacy_genesis(tmp_path / "legacy-genesis.json", genesis)
    bind_count(args, tmp_path, 10_000_000)
    args.previous_admission = legacy_path

    result = run(args)

    assert result["status"] == "PASS"
    assert result["previous_stage_admission_sha256"] == __import__("json").loads(
        legacy_path.read_text()
    )["evidence_sha256"]
    assert result["previous_stage_admission_file_sha256"] == sha256_file(legacy_path)


def test_full_ladder_links_every_immediate_predecessor(tmp_path: Path) -> None:
    args = fixtures(tmp_path)
    previous = run(args)
    for count in (10_000_000, 100_000_000, 1_000_000_000):
        previous_path = Path(previous["receipt_path"])
        bind_count(args, tmp_path, count)
        args.previous_admission = previous_path

        current = run(args)

        assert current["status"] == "PASS"
        assert current["checks"]["stage_predecessor_exact"] is True
        assert current["previous_stage_admission_sha256"] == previous["evidence_sha256"]
        assert current["previous_stage_admission_file_sha256"] == sha256_file(previous_path)
        previous = current
    assert previous["physical_billion_event_run_completed"] is True


def test_legacy_non_genesis_without_exact_chain_proof_is_rejected(tmp_path: Path) -> None:
    args = fixtures(tmp_path)
    genesis = run(args)
    bind_count(args, tmp_path, 10_000_000)
    args.previous_admission = Path(genesis["receipt_path"])
    ten_million = run(args)
    legacy = copy.deepcopy(ten_million)
    legacy.pop("receipt_path")
    legacy.pop("evidence_sha256")
    legacy["checks"].pop("stage_predecessor_exact")
    legacy.pop("previous_stage_admission_file_sha256")
    legacy_path = write_receipt(tmp_path / "legacy-ten-million.json", legacy)
    bind_count(args, tmp_path, 100_000_000)
    args.previous_admission = legacy_path

    with pytest.raises(RuntimeError, match="predecessor chain proof is missing"):
        run(args)


def test_non_genesis_stage_requires_predecessor(tmp_path: Path) -> None:
    args = fixtures(tmp_path)
    bind_count(args, tmp_path, 10_000_000)
    with pytest.raises(RuntimeError, match="requires physical-1000000 predecessor"):
        run(args)


def test_genesis_rejects_predecessor(tmp_path: Path) -> None:
    args = fixtures(tmp_path)
    genesis = run(args)
    args.previous_admission = Path(genesis["receipt_path"])
    with pytest.raises(RuntimeError, match="genesis and rejects a predecessor"):
        run(args)


def test_stage_rejects_non_immediate_predecessor(tmp_path: Path) -> None:
    args = fixtures(tmp_path)
    genesis = run(args)
    bind_count(args, tmp_path, 100_000_000)
    args.previous_admission = Path(genesis["receipt_path"])
    with pytest.raises(RuntimeError, match="requires immediate physical-10000000 predecessor"):
        run(args)


def test_non_ladder_stage_is_rejected(tmp_path: Path) -> None:
    args = fixtures(tmp_path)
    bind_count(args, tmp_path, 2_000_000)
    with pytest.raises(RuntimeError, match="unsupported physical stage count"):
        run(args)


def test_retrieval_cannot_repair_structural_physical_failure(tmp_path: Path) -> None:
    args = fixtures(tmp_path)
    physical = __import__("json").loads(args.physical_receipt.read_text())
    physical.pop("evidence_sha256")
    physical["checks"]["manifest_chain_verified"] = False
    physical["blockers"].append("manifest_chain_verified")
    args.physical_receipt = write_receipt(tmp_path / "physical-structural-fail.json", physical)
    verify = __import__("json").loads(args.verify_receipt.read_text())
    verify.pop("evidence_sha256")
    verify["physical_receipt_evidence_sha256"] = __import__("json").loads(args.physical_receipt.read_text())["evidence_sha256"]
    args.verify_receipt = write_receipt(tmp_path / "verify-rebound.json", verify)
    retrieval = __import__("json").loads(args.retrieval_receipt.read_text())
    retrieval.pop("evidence_sha256")
    retrieval["physical_receipt_evidence_sha256"] = __import__("json").loads(args.physical_receipt.read_text())["evidence_sha256"]
    retrieval["verify_receipt_evidence_sha256"] = __import__("json").loads(args.verify_receipt.read_text())["evidence_sha256"]
    args.retrieval_receipt = write_receipt(tmp_path / "retrieval-rebound.json", retrieval)
    assert run(args)["status"] == "FAIL"


def test_foreign_verify_binding_is_rejected(tmp_path: Path) -> None:
    args = fixtures(tmp_path)
    retrieval = __import__("json").loads(args.retrieval_receipt.read_text())
    retrieval.pop("evidence_sha256")
    retrieval["verify_receipt_evidence_sha256"] = "f" * 64
    args.retrieval_receipt = write_receipt(tmp_path / "retrieval-foreign.json", retrieval)
    with pytest.raises(RuntimeError, match="retrieval-to-verify"):
        run(args)


def test_fake_billion_count_cannot_override_bound_one_million_receipts(tmp_path: Path) -> None:
    args = fixtures(tmp_path)
    physical = __import__("json").loads(args.physical_receipt.read_text())
    physical.pop("evidence_sha256")
    physical["physical_event_count"] = 1_000_000_000
    physical["stage"] = "physical-1000000000"
    args.physical_receipt = write_receipt(tmp_path / "physical-fake-billion.json", physical)
    with pytest.raises(RuntimeError, match="count/root mismatch"):
        run(args)
