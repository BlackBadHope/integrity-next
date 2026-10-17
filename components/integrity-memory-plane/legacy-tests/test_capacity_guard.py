from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import urllib.request

import pytest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import capacity_guard as guard  # noqa: E402


MIB = 1024**2
GIB = 1024**3


def test_codex_sessions_paths_use_plural_env_and_deduplicate(tmp_path: Path) -> None:
    first = tmp_path / "profile-a" / "sessions"
    second = tmp_path / "profile-b" / "sessions"
    environment = {
        "INTEGRITY_CODEX_SESSIONS_PATHS": os.pathsep.join(
            (str(first), str(second), str(first))
        )
    }
    assert guard.resolve_codex_sessions_paths(None, environment) == [first, second]
    assert guard.codex_sessions_sample_key(first, 1) == "codex-sessions"
    assert guard.codex_sessions_sample_key(first, 2) != (
        guard.codex_sessions_sample_key(second, 2)
    )


def test_codex_sessions_paths_support_legacy_singular_without_home_fallback(
    tmp_path: Path,
) -> None:
    explicit = tmp_path / "sessions"
    assert guard.resolve_codex_sessions_paths(
        None, {"INTEGRITY_CODEX_SESSIONS_PATH": str(explicit)}
    ) == [explicit]
    with pytest.raises(ValueError, match="Codex sessions paths are required"):
        guard.resolve_codex_sessions_paths(None, {})
    with pytest.raises(ValueError, match="must not both be set"):
        guard.resolve_codex_sessions_paths(
            None,
            {
                "INTEGRITY_CODEX_SESSIONS_PATHS": str(explicit),
                "INTEGRITY_CODEX_SESSIONS_PATH": str(explicit),
            },
        )


def test_codex_sessions_paths_reject_empty_relative_and_unbounded_lists(
    tmp_path: Path,
) -> None:
    absolute = tmp_path / "sessions"
    with pytest.raises(ValueError, match="must not be empty"):
        guard.resolve_codex_sessions_paths(
            None,
            {"INTEGRITY_CODEX_SESSIONS_PATHS": f"{absolute}{os.pathsep}"},
        )
    with pytest.raises(ValueError, match="must be absolute"):
        guard.resolve_codex_sessions_paths(["relative/sessions"], {})
    unbounded = [f"/profiles/{index}/sessions" for index in range(33)]
    with pytest.raises(ValueError, match="exceeds the 32-path limit"):
        guard.resolve_codex_sessions_paths(unbounded, {})


def test_repeatable_cli_codex_sessions_paths_override_environment(
    tmp_path: Path,
    monkeypatch,
) -> None:
    first = tmp_path / "profile-a" / "sessions"
    second = tmp_path / "profile-b" / "sessions"
    monkeypatch.setenv("INTEGRITY_CODEX_SESSIONS_PATHS", "/ignored/sessions")
    args = guard.parse_args(
        [
            "--codex-sessions-path",
            str(first),
            "--codex-sessions-path",
            str(second),
            "--codex-sessions-path",
            str(first),
        ]
    )
    assert args.codex_sessions_paths == [first, second]


def test_capacity_service_requires_explicit_sessions_environment_file() -> None:
    service = (
        ROOT / "systemd" / "integrity-memory-capacity-guard.service"
    ).read_text(encoding="utf-8")
    assert "EnvironmentFile=/etc/integrity-memory-plane/capacity-guard.env" in service
    assert "EnvironmentFile=-/etc/integrity-memory-plane/capacity-guard.env" not in service


def sample(observed: int, available: int = 20 * GIB, *, device: int = 7, total: int = 80 * GIB) -> dict[str, object]:
    return {
        "kind": "filesystem",
        "path": "/",
        "metric": "used_bytes",
        "sample_status": "ok",
        "observed_bytes": observed,
        "available_bytes": available,
        "filesystem_total_bytes": total,
        "device_id": device,
    }


def test_zero_available_is_exhausted_but_zero_total_is_not() -> None:
    exhausted = guard.classify_usage("/", 100, 0, 10)
    assert exhausted["level"] == "exhausted"
    assert exhausted["used_percent"] == 100.0
    assert exhausted["available_percent"] == 0.0
    invalid = guard.classify_usage("invalid", 0, 0, 10)
    assert invalid["level"] == "unavailable"
    assert guard.classify_usage("invalid", 100, 101, 10)["level"] == "unavailable"
    assert "unavailable" in guard.BLOCKING_LEVELS
    assert guard.filesystem_growth_sample(invalid)["sample_status"] == "unavailable"


def test_existing_percent_and_absolute_free_boundaries() -> None:
    total = 100 * GIB
    assert guard.classify_usage("x", total, 21 * GIB, 10)["level"] == "ok"
    assert guard.classify_usage("x", total, 20 * GIB, 10)["level"] == "warning"
    assert guard.classify_usage("x", total, 15 * GIB, 10)["level"] == "block-large-artifacts"
    assert guard.classify_usage("x", total, 10 * GIB, 10)["level"] == "critical"
    assert guard.classify_usage("x", total, 5 * GIB, 10)["level"] == "emergency"
    assert guard.classify_usage("small", 20 * GIB, 9 * GIB, 10)["level"] == "block-large-artifacts"


def test_growth_eta_boundaries_are_inclusive() -> None:
    delta = 64 * MIB
    previous = sample(10 * GIB)
    exact_critical = sample(10 * GIB + delta, available=delta * 24)
    result = guard.classify_growth(exact_critical, previous, elapsed_seconds=300, reset_reason="ok")
    assert result["eta_seconds"] == 2 * 3600
    assert result["severity"] == "critical"

    exact_warning = sample(10 * GIB + delta, available=delta * 288)
    result = guard.classify_growth(exact_warning, previous, elapsed_seconds=300, reset_reason="ok")
    assert result["eta_seconds"] == 24 * 3600
    assert result["severity"] == "warning"

    below_threshold = sample(10 * GIB + delta - 1)
    result = guard.classify_growth(below_threshold, previous, elapsed_seconds=300, reset_reason="ok")
    assert result["trend"] == "stable"
    assert result["consecutive_growth_intervals"] == 0


def test_profile_path_change_resets_growth_on_same_device() -> None:
    previous = {**sample(10 * GIB), "path": "/var/lib/profile-a/sessions"}
    current = {**sample(12 * GIB), "path": "/var/lib/profile-b/sessions"}
    result = guard.classify_growth(current, previous, elapsed_seconds=300, reset_reason="ok")
    assert result["history_reason"] == "source-changed"
    assert result["delta_bytes"] is None
    assert result["persistent_growth"] is False


def test_three_qualifying_intervals_become_persistent() -> None:
    previous: dict[str, object] = guard.classify_growth(
        sample(10 * GIB), None, elapsed_seconds=None, reset_reason="first-sample"
    )
    for interval in range(1, 4):
        current = sample(10 * GIB + interval * 64 * MIB)
        previous = guard.classify_growth(current, previous, elapsed_seconds=300, reset_reason="ok")
        assert previous["consecutive_growth_intervals"] == interval
    assert previous["trend"] == "persistent-growth"
    assert previous["persistent_growth"] is True

    reset = guard.classify_growth(sample(int(previous["observed_bytes"])), previous, elapsed_seconds=300, reset_reason="ok")
    assert reset["trend"] == "stable"
    assert reset["consecutive_growth_intervals"] == 0


def test_stale_clock_and_device_change_reset_history() -> None:
    now = dt.datetime(2026, 9, 4, 12, 30, tzinfo=dt.UTC)
    state = {"observed_utc": "2026-09-04T12:00:00+00:00"}
    assert guard.clock_context(state, "ok", now, 900) == (None, "stale-history")
    future = {"observed_utc": "2026-09-04T13:00:00+00:00"}
    assert guard.clock_context(future, "ok", now, 900) == (None, "non-monotonic-clock")

    changed = guard.classify_growth(sample(2 * GIB, device=8), sample(GIB, device=7), elapsed_seconds=300, reset_reason="ok")
    assert changed["trend"] == "insufficient-history"
    assert changed["history_reason"] == "device-changed"


def test_monitor_state_rejects_non_object_sources(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"protocol": guard.STATE_PROTOCOL, "sources": {"filesystem:/": 1}}))
    assert guard.load_monitor_state(state) == ({}, "invalid-state")


def test_directory_measurement_deduplicates_hardlinks_and_ignores_symlinks(tmp_path: Path) -> None:
    payload = tmp_path / "payload"
    payload.write_bytes(b"x" * MIB)
    os.link(payload, tmp_path / "hardlink")
    (tmp_path / "symlink").symlink_to(payload)
    result = guard.measure_directory("fixture", tmp_path, max_entries=10, timeout_seconds=2)
    assert result["sample_status"] == "ok"
    assert result["file_count"] == 1
    assert result["observed_bytes"] >= MIB


def test_directory_deadline_applies_inside_one_flat_directory(tmp_path: Path) -> None:
    for index in range(3):
        (tmp_path / str(index)).write_bytes(b"payload")
    observed = iter((0.0, 0.0, 3.0))
    result = guard.measure_directory(
        "flat", tmp_path, max_entries=100, timeout_seconds=2,
        monotonic=lambda: next(observed),
    )
    assert result["sample_status"] == "unavailable"
    assert result["error_class"] == "TimeoutError"


def test_action_log_health_contract_and_monotone_event_count() -> None:
    healthy = {
        "ok": True,
        "service": "codex-action-log",
        "append_only": True,
        "update_enabled": False,
        "delete_enabled": False,
        "events": 7120,
    }
    assert guard.validate_action_log_health(healthy, 7119)["status"] == "ready"
    regression = guard.validate_action_log_health({**healthy, "events": 7118}, 7119)
    assert regression == {"status": "invalid", "reason": "event-count-regression", "events": 7118, "previous_events": 7119}
    assert guard.probe_action_log("https://example.com/api/health", 1, None)["reason"] == "non-loopback-health-target"


def test_action_log_probe_rejects_redirects_before_reading() -> None:
    request = urllib.request.Request("http://127.0.0.1:8765/api/health")
    assert guard.RejectRedirects().redirect_request(
        request, None, 302, "Found", {}, "https://example.com/api/health"
    ) is None

    class RedirectedResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def geturl(self):
            return "https://example.com/api/health"

        def read(self, size):
            raise AssertionError("redirected response body must not be read")

    result = guard.probe_action_log(
        "http://127.0.0.1:8765/api/health",
        1,
        None,
        opener=lambda *args, **kwargs: RedirectedResponse(),
    )
    assert result == {"status": "invalid", "reason": "redirect-target-rejected"}


def test_main_persists_exhausted_level_and_marker(tmp_path: Path, monkeypatch) -> None:
    status_path = tmp_path / "capacity.json"
    state_path = tmp_path / "state.json"
    marker_path = tmp_path / "blocked"
    args = argparse.Namespace(
        path=["/"], min_free_gib=10.0, status=status_path, marker=marker_path,
        growth_state=state_path, state_lock=tmp_path / "guard.lock",
        codex_sessions_paths=[tmp_path / "profile-a", tmp_path / "profile-b"],
        docker_volumes_path=tmp_path,
        architecture_replay_path=tmp_path, psi_io_path=tmp_path / "pressure-io",
        shm_path=tmp_path, proc_path=tmp_path / "proc",
        runtime_max_processes=100, runtime_timeout_seconds=2.0,
        growth_min_delta_mib=64.0, growth_stale_seconds=900.0,
        growth_warning_hours=24.0, growth_critical_hours=2.0,
        growth_persistent_intervals=3, directory_max_entries=100,
        directory_timeout_seconds=2.0, action_log_health_url="http://127.0.0.1:8765/api/health",
        action_log_health_timeout=1.0, hypervisor_host="", ssh_config=tmp_path,
        ssh_identity=None, ssh_known_hosts=None,
    )
    row = guard.classify_usage("/", 80 * GIB, 0, 10, device_id=7)
    directory = {**sample(1 * GIB, available=20 * GIB), "kind": "directory", "sample_status": "ok"}
    monkeypatch.setattr(guard, "parse_args", lambda: args)
    monkeypatch.setattr(guard, "usage", lambda path, floor: row)
    monkeypatch.setattr(guard, "remote_usage", lambda parsed: ([], "not-configured"))
    measurements: list[tuple[str, Path]] = []

    def measure(name: str, path: Path, **kwargs) -> dict[str, object]:
        measurements.append((name, path))
        return directory

    monkeypatch.setattr(guard, "measure_directory", measure)
    monkeypatch.setattr(guard, "probe_action_log", lambda *a, **kw: {"status": "ready", "reason": "contract-ok", "events": 7120})
    monkeypatch.setattr(guard, "collect_runtime_monitoring", lambda *a, **kw: {
        "protocol": guard.RUNTIME_MONITORING_PROTOCOL, "status": "ready", "timer_overlap": False,
        "duration_ms": 1.0, "collector_health": {}, "observations": {}, "reasons": [],
    })

    assert guard.main() == 20
    stored = json.loads(status_path.read_text())
    assert stored["protocol"] == guard.CAPACITY_PROTOCOL
    assert stored["filesystems"][0]["level"] == "exhausted"
    assert stored["status"] == "blocked"
    assert stored["block_large_artifacts"] is True
    assert "capacity:/:exhausted" in stored["reasons"]
    assert marker_path.exists()
    first_key = guard.codex_sessions_sample_key(tmp_path / "profile-a", 2)
    second_key = guard.codex_sessions_sample_key(tmp_path / "profile-b", 2)
    assert measurements[:2] == [
        (first_key, tmp_path / "profile-a"),
        (second_key, tmp_path / "profile-b"),
    ]
    assert first_key in stored["growth"]["sources"]
    assert second_key in stored["growth"]["sources"]


def test_block_marker_precedes_state_write_failure(tmp_path: Path, monkeypatch) -> None:
    args = argparse.Namespace(
        marker=tmp_path / "blocked",
        growth_state=tmp_path / "state.json",
        status=tmp_path / "status.json",
    )
    real_atomic_json = guard.atomic_json

    def fail_state(path: Path, value: object) -> None:
        if path == args.growth_state:
            raise OSError("simulated state filesystem exhaustion")
        real_atomic_json(path, value)

    monkeypatch.setattr(guard, "atomic_json", fail_state)
    with pytest.raises(OSError):
        guard.persist_monitor_result(args, {"status": "blocked"}, {"state": "new"}, True)
    assert json.loads(args.marker.read_text()) == {"status": "blocked"}


def test_psi_io_parser_reports_bounded_pressure_levels() -> None:
    payload = (
        b"some avg10=61.25 avg60=45.00 avg300=20.00 total=123456\n"
        b"full avg10=55.50 avg60=40.00 avg300=18.00 total=65432\n"
    )
    result = guard.parse_psi_io(payload)
    assert result["sample_status"] == "ok"
    assert result["level"] == "critical"
    assert result["peak_avg10_percent"] == 61.25
    assert result["full"]["total_stall_microseconds"] == 65432
    with pytest.raises(ValueError):
        guard.parse_psi_io(b"some avg10=1.0 avg60=1.0 avg300=1.0 total=1\n")


def test_inode_pressure_classification() -> None:
    assert guard.classify_inode_usage("/srv", 100, 10)["level"] == "critical"
    assert guard.classify_inode_usage("/srv", 100, 0)["level"] == "exhausted"
    assert guard.classify_inode_usage("/srv", 0, 0)["level"] == "unavailable"


def test_replay_store_reports_count_storage_and_oldest_age_with_entry_bound(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_bytes(b"a" * 100)
    second.write_bytes(b"b" * 200)
    os.utime(first, (900, 900))
    os.utime(second, (950, 950))
    result = guard.measure_replay_store(
        tmp_path, max_entries=10, timeout_seconds=2, observed_epoch=1000
    )
    assert result["sample_status"] == "ok"
    assert result["record_count"] == 2
    assert result["apparent_bytes"] == 300
    assert result["oldest_age_seconds"] == 100.0

    bounded = guard.measure_replay_store(
        tmp_path, max_entries=1, timeout_seconds=2, observed_epoch=1000
    )
    assert bounded["sample_status"] == "unavailable"
    assert bounded["error_class"] == "RuntimeError"


def test_process_collector_reports_only_counts_and_oldest_ages(tmp_path: Path) -> None:
    (tmp_path / "uptime").write_text("1000.0 0.0\n", encoding="ascii")

    def process(pid: int, state: str, start_ticks: int, command: bytes) -> None:
        root = tmp_path / str(pid)
        root.mkdir()
        fields = [state, *("0" for _ in range(18)), str(start_ticks)]
        (root / "stat").write_text(f"{pid} (worker) {' '.join(fields)}\n", encoding="ascii")
        (root / "cmdline").write_bytes(command)

    process(100, "D", 10_000, b"python\0/opt/integrity/run-mcp\0")
    process(101, "S", 20_000, b"python\0integrity-client-turn-broker.py\0")
    process(102, "D", 50_000, b"worker\0")
    result = guard.collect_process_health(
        tmp_path, max_processes=10, timeout_seconds=2, clock_ticks=100
    )
    assert result["sample_status"] == "ok"
    assert result["mcp"] == {"count": 1, "oldest_age_seconds": 900.0}
    assert result["broker"] == {"count": 1, "oldest_age_seconds": 800.0}
    assert result["d_tasks"] == {"count": 2, "oldest_age_seconds": 900.0}
    assert "pid" not in json.dumps(result)
    assert "cmdline" not in json.dumps(result)


def test_collector_error_is_content_free_degraded_observation() -> None:
    def fail() -> dict[str, object]:
        raise TimeoutError("secret collector detail")

    observation, health = guard.observe_collector(fail)
    assert observation == {
        "sample_status": "unavailable",
        "reason": "collector-error",
        "error_class": "TimeoutError",
    }
    assert health["status"] == "degraded"
    assert "secret" not in json.dumps({"observation": observation, "health": health})


def test_monitoring_degradation_never_creates_storage_block(tmp_path: Path, monkeypatch) -> None:
    args = argparse.Namespace(
        path=["/"], min_free_gib=10.0, status=tmp_path / "capacity.json",
        marker=tmp_path / "blocked", growth_state=tmp_path / "state.json",
        state_lock=tmp_path / "guard.lock", codex_sessions_paths=[tmp_path],
        docker_volumes_path=tmp_path, architecture_replay_path=tmp_path,
        psi_io_path=tmp_path / "pressure-io", shm_path=tmp_path,
        proc_path=tmp_path / "proc", runtime_max_processes=100,
        runtime_timeout_seconds=2.0, growth_min_delta_mib=64.0,
        growth_stale_seconds=900.0, growth_warning_hours=24.0,
        growth_critical_hours=2.0, growth_persistent_intervals=3,
        directory_max_entries=100, directory_timeout_seconds=2.0,
        action_log_health_url="http://127.0.0.1:8765/api/health",
        action_log_health_timeout=1.0, hypervisor_host="", ssh_config=tmp_path,
        ssh_identity=None, ssh_known_hosts=None,
    )
    row = guard.classify_usage("/", 100 * GIB, 50 * GIB, 10, device_id=7)
    directory = {**sample(1 * GIB, available=50 * GIB, total=100 * GIB), "kind": "directory"}
    runtime = {
        "protocol": guard.RUNTIME_MONITORING_PROTOCOL,
        "status": "degraded",
        "timer_overlap": False,
        "duration_ms": 2.0,
        "collector_health": {"processes": {"status": "degraded", "sample_status": "unavailable"}},
        "observations": {},
        "reasons": ["monitoring:collector:processes:unavailable"],
    }
    monkeypatch.setattr(guard, "parse_args", lambda: args)
    monkeypatch.setattr(guard, "usage", lambda path, floor: row)
    monkeypatch.setattr(guard, "remote_usage", lambda parsed: ([], "not-configured"))
    monkeypatch.setattr(guard, "measure_directory", lambda *a, **kw: directory)
    monkeypatch.setattr(guard, "probe_action_log", lambda *a, **kw: {"status": "ready", "reason": "contract-ok", "events": 7120})
    monkeypatch.setattr(guard, "collect_runtime_monitoring", lambda *a, **kw: runtime)

    assert guard.main() == 10
    stored = json.loads(args.status.read_text())
    assert stored["status"] == "degraded"
    assert stored["block_large_artifacts"] is False
    assert stored["runtime_monitoring"] == runtime
    assert not args.marker.exists()


def test_timer_overlap_is_reported_without_false_storage_block(monkeypatch, capsys) -> None:
    args = argparse.Namespace(
        growth_min_delta_mib=64.0, growth_stale_seconds=900.0,
        growth_warning_hours=24.0, growth_critical_hours=2.0,
        growth_persistent_intervals=3, directory_max_entries=100,
        directory_timeout_seconds=2.0, runtime_max_processes=100,
        runtime_timeout_seconds=2.0,
    )
    monkeypatch.setattr(guard, "parse_args", lambda: args)
    monkeypatch.setattr(
        guard,
        "run_guard",
        lambda parsed: (_ for _ in ()).throw(RuntimeError("another memory-plane operation holds /run/lock")),
    )
    assert guard.main() == 10
    status = json.loads(capsys.readouterr().out)
    assert status["runtime_monitoring"]["timer_overlap"] is True
    assert status["block_large_artifacts"] is False
