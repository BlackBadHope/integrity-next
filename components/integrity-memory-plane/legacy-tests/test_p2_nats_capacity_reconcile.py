from __future__ import annotations

import argparse
import asyncio
import copy
import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from memory_plane_common import canonical_json, sha256_bytes
import p2_nats_bootstrap as bootstrap
import p2_nats_capacity_reconcile as reconcile
from p2_billion_capacity import TARGET_EVENTS
from p2_capacity_supplement import (
    BUS_TARGET_CAPACITY_ADMISSION_CHECKS,
    CRITICAL_WATERMARK_PERCENT,
    FILESYSTEM_RESERVE_PERCENT,
    HEADROOM_NUMERATOR,
    HIGH_WATERMARK_PERCENT,
    PROTOCOL as CAPACITY_PROTOCOL,
    REQUIRED_CHECKS,
)


OLD_STREAM_MAX = 16 * 1024**3
OLD_SERVER_MAX = 20 * 1024**3
EVENTS = 100
STREAM_BYTES = 1_000
ALLOCATED_BYTES = 2_000
FILESYSTEM_TOTAL = 200 * 1024**3
FILESYSTEM_USED = 20 * 1024**3
FILESYSTEM_AVAILABLE = FILESYSTEM_TOTAL - FILESYSTEM_USED


def _write_capacity_supplement(path: Path) -> dict[str, object]:
    projected_logical = (STREAM_BYTES * TARGET_EVENTS + EVENTS - 1) // EVENTS
    projected_physical = (ALLOCATED_BYTES * TARGET_EVENTS + EVENTS - 1) // EVENTS
    required_stream = projected_logical * HEADROOM_NUMERATOR
    required_physical = projected_physical * HEADROOM_NUMERATOR
    growth = required_physical - ALLOCATED_BYTES
    reserve = (FILESYSTEM_TOTAL * FILESYSTEM_RESERVE_PERCENT + 99) // 100
    server_store_used = STREAM_BYTES + 1_100
    server_other = server_store_used - STREAM_BYTES
    projected_server = server_other + required_physical
    projected_filesystem = FILESYSTEM_USED + growth
    config = {
        "retention": "limits",
        "max_age": 0,
        "max_msgs": -1,
        "max_msgs_per_subject": -1,
        "discard": "new",
        "deny_delete": True,
        "deny_purge": True,
        "max_bytes": OLD_STREAM_MAX,
    }
    bus_checks = {
        "source_event_and_batch_counts_consistent": True,
        "bus_stream_snapshot_ordered_around_postgres": True,
        "bus_stream_contract_classified": True,
        "bus_physical_measurement_valid": True,
        "bus_stream_max_bytes_covers_target": OLD_STREAM_MAX >= projected_logical,
        "bus_server_max_storage_covers_target": OLD_SERVER_MAX >= projected_physical,
        "bus_stream_max_bytes_has_2x_target_headroom": OLD_STREAM_MAX >= required_stream,
        "bus_server_max_storage_has_2x_target_headroom": OLD_SERVER_MAX - server_other >= required_physical,
        "bus_filesystem_can_grow_to_2x_target_with_reserve": FILESYSTEM_AVAILABLE > growth + reserve,
        "bus_stream_2x_target_below_high_watermark": (
            required_stream * 100 < OLD_STREAM_MAX * HIGH_WATERMARK_PERCENT
        ),
        "bus_server_2x_target_below_high_watermark": (
            projected_server * 100 < OLD_SERVER_MAX * HIGH_WATERMARK_PERCENT
        ),
        "bus_filesystem_2x_target_below_high_watermark": (
            projected_filesystem * 100 < FILESYSTEM_TOTAL * HIGH_WATERMARK_PERCENT
        ),
        "bus_stream_below_high_watermark": (
            STREAM_BYTES * 100 < OLD_STREAM_MAX * HIGH_WATERMARK_PERCENT
        ),
        "bus_server_below_high_watermark": (
            server_store_used * 100 < OLD_SERVER_MAX * HIGH_WATERMARK_PERCENT
        ),
        "bus_filesystem_below_high_watermark": (
            FILESYSTEM_USED * 100 < FILESYSTEM_TOTAL * HIGH_WATERMARK_PERCENT
        ),
    }
    checks = {name: False for name in REQUIRED_CHECKS}
    checks.update(bus_checks)
    value: dict[str, object] = {
        "protocol": CAPACITY_PROTOCOL,
        "created_utc": reconcile.utc_now(),
        "status": "PASS" if all(checks.values()) else "INCOMPLETE",
        "target_events": TARGET_EVENTS,
        "source_snapshot": {
            "raw_events": EVENTS,
            "ingest_batches": 10,
            "batch_event_sum": EVENTS,
            "first_cursor": 1,
            "last_cursor": EVENTS,
            "max_bus_sequence": 10,
        },
        "bus": {
            "policy_class": "full-history-hard-stop",
            "config": config,
            "state_before": {"last_seq": 10},
            "state_after": {"messages": 10, "bytes": STREAM_BYTES, "last_seq": 10},
            "server": {
                "max_storage": OLD_SERVER_MAX,
                "storage_used": server_store_used,
                "store_dir": "/data/jetstream",
            },
            "filesystem": {
                "allocated_bytes": ALLOCATED_BYTES,
                "files": 3,
                "filesystem_total_bytes": FILESYSTEM_TOTAL,
                "filesystem_available_bytes": FILESYSTEM_AVAILABLE,
                "filesystem_used_bytes": FILESYSTEM_USED,
                "filesystem_device_id": 9,
            },
            "projected_stream_logical_bytes_at_target": projected_logical,
            "projected_physical_bytes_at_target": projected_physical,
            "required_stream_logical_bytes_with_2x_headroom": required_stream,
            "required_physical_bytes_with_2x_headroom": required_physical,
            "physical_growth_bytes_to_2x_target": growth,
            "server_other_store_bytes": server_other,
            "server_capacity_for_stream_bytes": OLD_SERVER_MAX - server_other,
            "filesystem_reserve_bytes": reserve,
            "projected_server_storage_bytes_at_2x_target": projected_server,
            "projected_filesystem_used_bytes_at_2x_target": projected_filesystem,
            "headroom": {"numerator": HEADROOM_NUMERATOR, "denominator": 1},
            "watermark_policy": {
                "high_percent": HIGH_WATERMARK_PERCENT,
                "critical_percent": CRITICAL_WATERMARK_PERCENT,
                "filesystem_reserve_percent": FILESYSTEM_RESERVE_PERCENT,
            },
            "target_capacity_admitted": all(
                bus_checks[name] for name in BUS_TARGET_CAPACITY_ADMISSION_CHECKS
            ),
        },
        "measurement_checks": {"bus": True, "object_store": False, "attachments": False},
        "checks": checks,
        "blockers": sorted(name for name, passed in checks.items() if not passed),
        "sparse_or_extrapolated_pass": False,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    value["evidence_sha256"] = sha256_bytes(canonical_json(value))
    path.write_bytes(canonical_json(value) + b"\n")
    return value


def _arguments(tmp_path: Path, supplement: Path) -> argparse.Namespace:
    environment = tmp_path / "admin.env"
    environment.write_text("NATS_USER=admin\nNATS_PASSWORD=secret\n", encoding="utf-8")
    return argparse.Namespace(
        admin_env=environment,
        server="nats://127.0.0.1:4222",
        monitor_endpoint="http://127.0.0.1:18222",
        nats_data_root=tmp_path / "nats",
        capacity_supplement=supplement,
        receipt_root=tmp_path / "receipts",
        apply=True,
    )


class FakeJetStream:
    def __init__(
        self,
        max_bytes: int = OLD_STREAM_MAX,
        *,
        regress_after_update: bool = False,
        unknown_rollback_response: bool = False,
        drift_before_update: bool = False,
    ) -> None:
        self.config = bootstrap.expected_config()
        self.config.max_bytes = max_bytes
        self.config.metadata = {**(self.config.metadata or {}), "future.server.field": "preserve-me"}
        self.state = {"messages": 10, "bytes": 1_000, "first_seq": 1, "last_seq": 10}
        self.original_state = dict(self.state)
        self.regress_after_update = regress_after_update
        self.unknown_rollback_response = unknown_rollback_response
        self.drift_before_update = drift_before_update
        self.updated_configs: list[object] = []
        self.intent_assertion = None
        self.account_info_calls = 0
        self.stream_info_calls = 0

    async def account_info(self) -> object:
        self.account_info_calls += 1
        raise AssertionError("account max_storage=-1 is not the server file-store limit")

    async def stream_info(self, _stream: str) -> object:
        self.stream_info_calls += 1
        if self.drift_before_update and self.stream_info_calls == 2:
            self.state.update({"messages": 11, "bytes": 1_001, "last_seq": 11})
        return SimpleNamespace(
            config=copy.deepcopy(self.config),
            state=SimpleNamespace(**self.state),
        )

    async def update_stream(self, *, config: object) -> object:
        if self.intent_assertion is not None:
            self.intent_assertion()
        self.updated_configs.append(copy.deepcopy(config))
        self.config = copy.deepcopy(config)
        if self.config.max_bytes == bootstrap.MAX_BYTES:
            if self.regress_after_update:
                self.state["bytes"] = self.original_state["bytes"] - 1
            else:
                self.state.update({"messages": 11, "bytes": 1_100, "last_seq": 11})
        else:
            self.state = dict(self.original_state)
            if self.unknown_rollback_response:
                raise TimeoutError("simulated lost rollback response")
        return await self.stream_info(bootstrap.STREAM)


class FakeClient:
    def __init__(self, jetstream: FakeJetStream, *, server_id: str = "SERVER-A") -> None:
        self._jetstream = jetstream
        self.connected_server_id = server_id
        self.drains = 0

    def jetstream(self, *, timeout: int) -> FakeJetStream:
        assert timeout == 5
        return self._jetstream

    async def drain(self) -> None:
        self.drains += 1


def _connector(client: FakeClient):
    async def connect(**kwargs: object) -> FakeClient:
        assert kwargs["servers"] == ["nats://127.0.0.1:4222"]
        assert kwargs["user"] == "admin"
        assert kwargs["password"] == "secret"
        return client

    return connect


def _mock_server_monitor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        reconcile,
        "live_server_capacity",
        lambda endpoint: {
            "server_id": "SERVER-A",
            "max_storage": bootstrap.SERVER_MAX_FILE_STORE_BYTES,
            "store_dir": "/data/jetstream",
            "monitor_uri": endpoint.rstrip("/") + "/jsz?config=true",
        },
    )
    monkeypatch.setattr(
        reconcile,
        "live_filesystem_capacity",
        lambda plan, live_server, nats_data_root: {
            "monitor_store_dir": live_server["store_dir"],
            "host_store_root": str(nats_data_root),
            "filesystem_device_id": plan.measured_filesystem_device_id,
            "filesystem_total_bytes": plan.filesystem_total_bytes,
            "filesystem_available_bytes": plan.filesystem_available_bytes,
            "filesystem_used_bytes": plan.filesystem_used_bytes,
            "filesystem_reserve_bytes": plan.filesystem_reserve_bytes,
            "physical_growth_bytes_to_2x_target": plan.physical_growth_bytes,
            "projected_filesystem_used_bytes_at_2x_target": (
                plan.filesystem_used_bytes + plan.physical_growth_bytes
            ),
            "checks": {
                "growth_plus_reserve_strictly_fits": True,
                "projected_2x_target_strictly_below_high_watermark": True,
            },
        },
    )


def test_live_server_capacity_reads_server_jsz_not_account_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int]] = []

    class Response:
        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {
                    "server_id": "SERVER-A",
                    "config": {
                        "max_storage": bootstrap.SERVER_MAX_FILE_STORE_BYTES,
                        "store_dir": "/data/jetstream",
                    },
                    "account_details": [{"limits": {"max_storage": -1}}],
                }
            ).encode("utf-8")

    def urlopen(uri: str, *, timeout: int) -> Response:
        calls.append((uri, timeout))
        return Response()

    monkeypatch.setattr(reconcile.urllib.request, "urlopen", urlopen)
    result = reconcile.live_server_capacity("http://127.0.0.1:18222")

    assert result["max_storage"] == bootstrap.SERVER_MAX_FILE_STORE_BYTES
    assert result["store_dir"] == "/data/jetstream"
    assert calls == [("http://127.0.0.1:18222/jsz?config=true", 5)]


def test_capacity_plan_rederives_strict_bootstrap_headroom(tmp_path: Path) -> None:
    supplement = tmp_path / "capacity.json"
    _write_capacity_supplement(supplement)

    plan = reconcile.load_capacity_plan(supplement)

    assert plan.required_stream_bytes == 20_000_000_000
    assert plan.required_physical_bytes == 40_000_000_000
    assert plan.target_stream_max_bytes == 104 * 1024**3
    assert plan.target_server_max_storage_bytes == 112 * 1024**3
    assert all(plan.capacity_checks.values())


def test_capacity_plan_rejects_exact_80_percent_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supplement = tmp_path / "capacity.json"
    _write_capacity_supplement(supplement)
    monkeypatch.setattr(bootstrap, "MAX_BYTES", 25_000_000_000)

    with pytest.raises(RuntimeError, match="strictly_below_high_watermark"):
        reconcile.load_capacity_plan(supplement)


def test_capacity_supplement_must_be_canonically_encoded(tmp_path: Path) -> None:
    supplement = tmp_path / "capacity.json"
    value = _write_capacity_supplement(supplement)
    supplement.write_text(json.dumps(value, indent=2), encoding="utf-8")

    with pytest.raises(RuntimeError, match="not canonically encoded"):
        reconcile.load_capacity_plan(supplement)


def test_capacity_supplement_must_be_fresh(tmp_path: Path) -> None:
    supplement = tmp_path / "capacity.json"
    value = _write_capacity_supplement(supplement)
    value["created_utc"] = "2000-01-01T00:00:00Z"
    value.pop("evidence_sha256")
    value["evidence_sha256"] = sha256_bytes(canonical_json(value))
    supplement.write_bytes(canonical_json(value) + b"\n")

    with pytest.raises(RuntimeError, match="stale or future-dated"):
        reconcile.load_capacity_plan(supplement)


def test_capacity_plan_rejects_ttl_enabled_sample_even_if_receipt_claims_full_history(
    tmp_path: Path,
) -> None:
    supplement = tmp_path / "capacity.json"
    value = _write_capacity_supplement(supplement)
    value["bus"]["config"]["allow_msg_ttl"] = True
    value.pop("evidence_sha256")
    value["evidence_sha256"] = sha256_bytes(canonical_json(value))
    supplement.write_bytes(canonical_json(value) + b"\n")

    with pytest.raises(RuntimeError, match="checks are not independently derived"):
        reconcile.load_capacity_plan(supplement)


def test_stream_contract_allows_only_old_max_bytes() -> None:
    config = bootstrap.expected_config()
    config.max_bytes = OLD_STREAM_MAX
    assert reconcile.validate_stream_contract_allowing_old_max_bytes(config) == OLD_STREAM_MAX

    config.description = "drifted"
    with pytest.raises(RuntimeError, match="description"):
        reconcile.validate_stream_contract_allowing_old_max_bytes(config)


def test_reconcile_uses_monitor_not_account_quota_and_reuses_stable_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supplement = tmp_path / "capacity.json"
    _write_capacity_supplement(supplement)
    args = _arguments(tmp_path, supplement)
    _mock_server_monitor(monkeypatch)
    jetstream = FakeJetStream()
    client = FakeClient(jetstream)

    def intent_exists_before_update() -> None:
        assert len(list(args.receipt_root.glob("nats-capacity-intent-*.json"))) == 1

    jetstream.intent_assertion = intent_exists_before_update
    first = asyncio.run(reconcile.reconcile(args, connector=_connector(client)))

    assert first["status"] == "PASS"
    assert first["reused"] is False
    assert jetstream.account_info_calls == 0
    assert [item.max_bytes for item in jetstream.updated_configs] == [bootstrap.MAX_BYTES]
    assert jetstream.updated_configs[0].metadata["future.server.field"] == "preserve-me"
    intent_path = next(args.receipt_root.glob("nats-capacity-intent-*.json"))
    receipt_path = Path(first["receipt_path"])
    assert stat.S_IMODE(intent_path.stat().st_mode) == 0o400
    assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o400
    assert first["receipt"]["production_authority"] is False
    assert first["receipt"]["memory_grants_authority"] is False

    client.connected_server_id = "SERVER-B-AFTER-SAFE-RECREATE"
    monkeypatch.setattr(
        reconcile,
        "live_server_capacity",
        lambda endpoint: {
            "server_id": "SERVER-B-AFTER-SAFE-RECREATE",
            "max_storage": bootstrap.SERVER_MAX_FILE_STORE_BYTES,
            "store_dir": "/data/jetstream",
            "monitor_uri": endpoint.rstrip("/") + "/jsz?config=true",
        },
    )
    second = asyncio.run(reconcile.reconcile(args, connector=_connector(client)))
    assert second["reused"] is True
    assert second["receipt"]["evidence_sha256"] == first["receipt"]["evidence_sha256"]
    assert len(jetstream.updated_configs) == 1
    assert jetstream.account_info_calls == 0


def test_post_update_state_regression_rolls_back_only_max_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supplement = tmp_path / "capacity.json"
    _write_capacity_supplement(supplement)
    args = _arguments(tmp_path, supplement)
    _mock_server_monitor(monkeypatch)
    jetstream = FakeJetStream(regress_after_update=True)
    client = FakeClient(jetstream)

    with pytest.raises(RuntimeError, match="previous stream max_bytes was restored"):
        asyncio.run(reconcile.reconcile(args, connector=_connector(client)))

    assert [item.max_bytes for item in jetstream.updated_configs] == [bootstrap.MAX_BYTES, OLD_STREAM_MAX]
    assert all(item.metadata["future.server.field"] == "preserve-me" for item in jetstream.updated_configs)
    assert jetstream.config.max_bytes == OLD_STREAM_MAX
    assert jetstream.state == jetstream.original_state
    assert len(list(args.receipt_root.glob("nats-capacity-intent-*.json"))) == 1
    assert not list(args.receipt_root.glob("nats-capacity-reconcile-*.json"))


def test_unknown_rollback_response_is_reconciled_from_live_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supplement = tmp_path / "capacity.json"
    _write_capacity_supplement(supplement)
    args = _arguments(tmp_path, supplement)
    _mock_server_monitor(monkeypatch)
    jetstream = FakeJetStream(regress_after_update=True, unknown_rollback_response=True)

    with pytest.raises(RuntimeError, match="previous stream max_bytes was restored"):
        asyncio.run(reconcile.reconcile(args, connector=_connector(FakeClient(jetstream))))

    assert [item.max_bytes for item in jetstream.updated_configs] == [bootstrap.MAX_BYTES, OLD_STREAM_MAX]
    assert jetstream.config.max_bytes == OLD_STREAM_MAX
    assert jetstream.state == jetstream.original_state


def test_live_server_limit_must_be_exact_before_intent_or_update(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supplement = tmp_path / "capacity.json"
    _write_capacity_supplement(supplement)
    args = _arguments(tmp_path, supplement)
    monkeypatch.setattr(
        reconcile,
        "live_server_capacity",
        lambda endpoint: {
            "server_id": "SERVER-A",
            "max_storage": bootstrap.SERVER_MAX_FILE_STORE_BYTES - 1,
            "monitor_uri": endpoint.rstrip("/") + "/jsz?config=true",
        },
    )
    jetstream = FakeJetStream()

    with pytest.raises(RuntimeError, match="does not equal bootstrap target"):
        asyncio.run(reconcile.reconcile(args, connector=_connector(FakeClient(jetstream))))

    assert not args.receipt_root.exists() or not list(args.receipt_root.glob("*.json"))
    assert not jetstream.updated_configs


def test_reconcile_refuses_capacity_decrease_before_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supplement = tmp_path / "capacity.json"
    _write_capacity_supplement(supplement)
    args = _arguments(tmp_path, supplement)
    _mock_server_monitor(monkeypatch)
    jetstream = FakeJetStream(max_bytes=bootstrap.MAX_BYTES + 1)

    with pytest.raises(RuntimeError, match="refuses to decrease"):
        asyncio.run(reconcile.reconcile(args, connector=_connector(FakeClient(jetstream))))

    assert not list(args.receipt_root.glob("*.json"))
    assert not jetstream.updated_configs


def test_monitor_identity_must_match_connected_server_before_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supplement = tmp_path / "capacity.json"
    _write_capacity_supplement(supplement)
    args = _arguments(tmp_path, supplement)
    _mock_server_monitor(monkeypatch)
    jetstream = FakeJetStream()
    client = FakeClient(jetstream, server_id="SERVER-B")

    with pytest.raises(RuntimeError, match="identities differ"):
        asyncio.run(reconcile.reconcile(args, connector=_connector(client)))

    assert not list(args.receipt_root.glob("*.json"))
    assert not jetstream.updated_configs


def test_concurrent_stream_drift_fails_before_update(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supplement = tmp_path / "capacity.json"
    _write_capacity_supplement(supplement)
    args = _arguments(tmp_path, supplement)
    _mock_server_monitor(monkeypatch)
    jetstream = FakeJetStream(drift_before_update=True)

    with pytest.raises(RuntimeError, match="concurrent stream config or state drift"):
        asyncio.run(reconcile.reconcile(args, connector=_connector(FakeClient(jetstream))))

    assert len(list(args.receipt_root.glob("nats-capacity-intent-*.json"))) == 1
    assert not list(args.receipt_root.glob("nats-capacity-reconcile-*.json"))
    assert not jetstream.updated_configs


def test_new_receipt_is_validated_before_commit_without_post_commit_reread(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supplement = tmp_path / "capacity.json"
    _write_capacity_supplement(supplement)
    args = _arguments(tmp_path, supplement)
    _mock_server_monitor(monkeypatch)
    monkeypatch.setattr(
        reconcile,
        "_validate_receipt",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected reread")),
    )

    result = asyncio.run(
        reconcile.reconcile(args, connector=_connector(FakeClient(FakeJetStream())))
    )

    assert result["status"] == "PASS"
    assert Path(result["receipt_path"]).is_file()
