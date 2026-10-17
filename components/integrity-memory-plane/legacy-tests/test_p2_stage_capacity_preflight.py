from __future__ import annotations

import argparse
import copy
import json
import sys
from fractions import Fraction
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_plane_common import atomic_json, canonical_json, sha256_bytes, sha256_file  # noqa: E402
import p2_stage_capacity_preflight as preflight  # noqa: E402


def write_signed(path: Path, value: dict) -> Path:
    payload = copy.deepcopy(value)
    payload.pop("evidence_sha256", None)
    payload["evidence_sha256"] = sha256_bytes(canonical_json(payload))
    atomic_json(path, payload, mode=0o440)
    return path


def fake_filesystem(*, total: int, available: int, device_id: int = 77) -> dict:
    assert 0 <= available <= total
    return {
        "path": "/capacity-test",
        "device_id": device_id,
        "fragment_size_bytes": 4096,
        "block_size_bytes": 4096,
        "blocks": total // 4096,
        "blocks_available_to_unprivileged": available // 4096,
        "blocks_free": available // 4096,
        "total_bytes": total,
        "available_bytes": available,
        "free_bytes": available,
        "used_bytes": total - available,
    }


def fixture_args(
    tmp_path: Path,
    *,
    sample_events: int = 1_000_000,
    target_events: int = 10_000_000,
    allocated_total: int = 1_000_001,
) -> argparse.Namespace:
    physical_root = tmp_path / f"physical-{sample_events}"
    physical_root.mkdir()
    component_allocated = {
        "raw": allocated_total - 6,
        "receipts": 1,
        "index": 2,
        "catalog": 3,
    }
    assert component_allocated["raw"] >= 0
    physical = {
        "protocol": preflight.PHYSICAL_PROTOCOL,
        "created_utc": "2026-08-09T00:00:00+00:00",
        "status": "PASS",
        "stage": f"physical-{sample_events}",
        "physical_event_count": sample_events,
        "sparse_or_extrapolated_run": False,
        "storage": {
            name: {"logical_bytes": allocated, "allocated_bytes": allocated, "files": 1}
            for name, allocated in component_allocated.items()
        },
        "checks": {"physical_rows_exact": True},
        "blockers": [],
        "production_authority": False,
        "memory_grants_authority": False,
    }
    physical_path = write_signed(physical_root / "physical.json", physical)
    physical_value = json.loads(physical_path.read_text(encoding="utf-8"))
    admission = {
        "protocol": preflight.STAGE_ADMISSION_PROTOCOL,
        "created_utc": "2026-08-09T00:01:00+00:00",
        "status": "PASS",
        "source_root": str(physical_root.resolve()),
        "physical_event_count": sample_events,
        "stage": f"physical-{sample_events}",
        "source_receipts": {
            "physical": {
                "path": str(physical_path.resolve()),
                "file_sha256": sha256_file(physical_path),
                "evidence_sha256": physical_value["evidence_sha256"],
            }
        },
        "checks": {"admitted": True, "production_authority_false": True},
        "blockers": [],
        "production_authority": False,
        "memory_grants_authority": False,
    }
    admission_path = write_signed(tmp_path / "admission.json", admission)
    topology_path = tmp_path / "topology.json"
    topology_path.write_text(
        json.dumps(
            {
                "protocol": preflight.TOPOLOGY_PROTOCOL,
                "nodes": [{"node_id": "local-capacity-domain"}],
                "production_authority": False,
                "memory_grants_authority": False,
            }
        ),
        encoding="utf-8",
    )
    config_path = tmp_path / "stage.conf"
    config_path.write_text(
        json.dumps(
            {
                "protocol": preflight.STAGE_PROFILE_PROTOCOL,
                "stage_ladder_events": [1_000_000, 10_000_000, 100_000_000, 1_000_000_000],
                "batch_size": 4096,
                "bucket_span": 4096,
                "capsule_bytes": 32768,
                "exact_samples": 20,
                "progress_every": 100000,
                "route_id": "2576f731",
                "capacity_headroom_copies": 2,
                "filesystem_reserve_percent": 20,
                "projection_only_does_not_complete_stage": True,
                "production_authority": False,
                "memory_grants_authority": False,
            }
        ),
        encoding="utf-8",
    )
    return argparse.Namespace(
        stage_admission=admission_path,
        physical_receipt=None,
        target_events=target_events,
        target_root=tmp_path / f"physical-{target_events}-route2576f731",
        topology=topology_path,
        config=[f"stage_profile={config_path}"],
        artifact=[],
        receipt_root=tmp_path / "preflight-receipts",
    )


def test_run_emits_canonical_authority_false_projection_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args = fixture_args(tmp_path)
    monkeypatch.setattr(
        preflight,
        "filesystem_identity",
        lambda _path: fake_filesystem(total=10_000_000_000, available=8_000_000_000),
    )
    result = preflight.run(args)
    assert result["status"] == "PASS"
    assert result["projection_only"] is True
    assert result["physical_target_completed"] is False
    assert result["sparse_or_extrapolated_pass"] is False
    assert result["production_authority"] is False
    assert result["memory_grants_authority"] is False
    unsigned = dict(result)
    unsigned.pop("receipt_path")
    claimed = unsigned.pop("evidence_sha256")
    assert claimed == sha256_bytes(canonical_json(unsigned))
    persisted = json.loads(Path(result["receipt_path"]).read_text(encoding="utf-8"))
    assert persisted == {**unsigned, "evidence_sha256": claimed}


def test_projection_uses_exact_fraction_and_never_float_rounding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    allocated = (1 << 54) + 1
    args = fixture_args(tmp_path, allocated_total=allocated)
    projected = allocated * 10
    monkeypatch.setattr(
        preflight,
        "filesystem_identity",
        lambda _path: fake_filesystem(total=1 << 62, available=1 << 61),
    )
    result = preflight.run(args)
    ratio = Fraction(allocated, 1_000_000)
    assert result["capacity_projection"]["allocated_bytes_per_event"] == {
        "numerator_bytes": ratio.numerator,
        "denominator_events": ratio.denominator,
    }
    assert result["capacity_projection"]["projected_target_allocated_bytes"] == projected
    assert result["capacity_projection"]["required_two_copy_allocated_bytes"] == projected * 2


def test_exact_two_copy_plus_reserve_boundary_passes_and_one_byte_less_fails() -> None:
    sample = {"event_count": 1_000_000, "allocated_bytes": 20, "stage": "physical-1000000"}
    bindings = {"bound": {"sha256": "a" * 64}}
    total = 1_000
    projected = 200
    required = projected * 2 + 200
    passed = preflight.evaluate(
        sample=sample,
        target_events=10_000_000,
        filesystem=fake_filesystem(total=total, available=required),
        topology={"sha256": "b" * 64},
        configurations=bindings,
        artifacts=bindings,
    )
    failed = preflight.evaluate(
        sample=sample,
        target_events=10_000_000,
        filesystem=fake_filesystem(total=total, available=required - 1),
        topology={"sha256": "b" * 64},
        configurations=bindings,
        artifacts=bindings,
    )
    check = "two_target_copies_plus_20_percent_filesystem_reserve_fit"
    assert passed["status"] == "PASS" and passed["checks"][check] is True
    assert failed["status"] == "FAIL" and failed["checks"][check] is False
    assert failed["blockers"] == [check]


def test_100m_requires_exact_admitted_10m_predecessor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    args = fixture_args(tmp_path, sample_events=10_000_000, target_events=100_000_000)
    admission = json.loads(args.stage_admission.read_text(encoding="utf-8"))
    admission.pop("evidence_sha256")
    admission["stage_lineage_root"] = str(tmp_path.resolve())
    admission["previous_stage_admission_sha256"] = "a" * 64
    admission["previous_stage_admission_file_sha256"] = "b" * 64
    admission["checks"]["stage_predecessor_exact"] = True
    args.stage_admission = write_signed(args.stage_admission, admission)
    monkeypatch.setattr(
        preflight,
        "filesystem_identity",
        lambda _path: fake_filesystem(total=10_000_000_000, available=8_000_000_000),
    )
    assert preflight.run(args)["status"] == "PASS"


def test_10m_rejects_non_predecessor_stage_even_when_admission_is_green(tmp_path: Path) -> None:
    args = fixture_args(tmp_path, sample_events=10_000_000, target_events=10_000_000)
    with pytest.raises(RuntimeError, match="requires admitted physical-1000000 predecessor"):
        preflight.run(args)


def test_tampered_admission_is_rejected_before_capacity_evaluation(tmp_path: Path) -> None:
    args = fixture_args(tmp_path)
    value = json.loads(args.stage_admission.read_text(encoding="utf-8"))
    value["status"] = "FAIL"
    args.stage_admission.chmod(0o640)
    args.stage_admission.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(RuntimeError, match="canonical evidence mismatch"):
        preflight.run(args)


def test_relocated_physical_receipt_must_be_byte_identical_to_admission_binding(tmp_path: Path) -> None:
    args = fixture_args(tmp_path)
    original = Path(json.loads(args.stage_admission.read_text())["source_receipts"]["physical"]["path"])
    relocated = tmp_path / "relocated-physical.json"
    relocated.write_bytes(original.read_bytes())
    args.physical_receipt = relocated
    sample = preflight.admitted_sample(args.stage_admission, args.physical_receipt, args.target_events)
    assert sample["physical_receipt"]["bound_path"] == str(original)
    assert sample["physical_receipt"]["observed_path"] == str(relocated.resolve())
    value = json.loads(relocated.read_text(encoding="utf-8"))
    value["storage"]["raw"]["allocated_bytes"] += 1
    relocated.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(RuntimeError, match="canonical evidence mismatch"):
        preflight.admitted_sample(args.stage_admission, args.physical_receipt, args.target_events)


def test_config_and_topology_are_mandatory_digest_bound_identities(tmp_path: Path) -> None:
    args = fixture_args(tmp_path)
    with pytest.raises(RuntimeError, match="stage_profile named configuration"):
        preflight.configuration_identities([])
    topology = preflight.topology_identity(args.topology)
    configs = preflight.configuration_identities(args.config)
    artifacts = preflight.artifact_identities([])
    assert topology["sha256"] == sha256_file(args.topology)
    assert topology["canonical_json_sha256"] != ""
    assert configs["stage_profile"]["sha256"] == sha256_file(Path(args.config[0].split("=", 1)[1]))
    assert set(preflight.DEFAULT_ARTIFACTS).issubset(artifacts)
    assert all(len(value["sha256"]) == 64 for value in artifacts.values())


def test_duplicate_or_shadowed_named_identities_are_rejected(tmp_path: Path) -> None:
    config = tmp_path / "x.conf"
    config.write_text("x=1\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="duplicate config identity"):
        preflight.configuration_identities([f"stage={config}", f"stage={config}"])
    with pytest.raises(RuntimeError, match="shadows a required artifact"):
        preflight.artifact_identities([f"compact_index={config}"])
