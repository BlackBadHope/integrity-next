"""Real stdlib Seed runtime process identity across Windows venv redirectors."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys

import pytest

LAUNCHER = (Path(__file__).resolve().parents[1] /
    "components/integrity-seed/plugins/integrity-seed/skills/integrity-seed/scripts/integrity_seed.py")


def load_launcher():
    spec = importlib.util.spec_from_file_location("seed_process_boundary_test", LAUNCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_real_runtime_start_keeps_exact_signed_process_identity(tmp_path, monkeypatch):
    seed = load_launcher()
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    monkeypatch.setenv("INTEGRITY_SEED_HOME", str(tmp_path / "seed"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    runtime_commands = []
    real_popen = seed.subprocess.Popen
    def spawn(*args, **kwargs):
        command = args[0]
        if isinstance(command, (list, tuple)) and str(seed.RUNTIME_SOURCE) in command:
            runtime_commands.append(list(command))
        return real_popen(*args, **kwargs)
    monkeypatch.setattr(seed.subprocess, "Popen", spawn)
    runtime = None
    try:
        runtime = seed.ensure_runtime(work)
        assert runtime_commands == [[seed._runtime_python_executable(), "-I", "-B", str(seed.RUNTIME_SOURCE)]]
        receipt = runtime["receipt"]
        resolved = seed.paths(work)
        assert seed._valid_signed_receipt(receipt, runtime["token"])
        assert seed._process_matches_runtime(receipt, resolved)
        assert seed._process_start_id(receipt["pid"]) == receipt["process_start_id"]
        assert os.path.normcase(seed._process_executable(receipt["pid"])) == os.path.normcase(receipt["python_executable"])
        assert os.path.normcase(receipt["python_executable"]) == os.path.normcase(seed._runtime_python_executable())
        assert receipt["source_sha256"] == seed.source_hash()
        assert receipt["workspace_id"] == resolved["workspace_id"]
        assert seed.runtime_health(receipt, runtime["token"]) is not None
        assert not seed._process_matches_runtime({**receipt, "process_start_id": "wrong-start-identity"}, resolved)
        assert not seed._process_matches_runtime({**receipt, "pid": -1}, resolved)
        assert not seed._valid_signed_receipt({**receipt, "startup_nonce": "x" * 64}, runtime["token"])
    finally:
        if runtime is not None:
            stopped = seed.stop_runtime()
            assert stopped["ok"] is True
            assert not seed._pid_exists(runtime["receipt"]["pid"])


@pytest.mark.skipif(os.name != "nt" or sys.prefix == sys.base_prefix,
                    reason="Windows virtualenv redirector boundary")
def test_windows_venv_uses_only_current_base_executable(monkeypatch):
    seed = load_launcher()
    assert Path(seed._runtime_python_executable()) == Path(sys._base_executable).resolve(strict=True)
    monkeypatch.setattr(sys, "_base_executable", "", raising=False)
    with pytest.raises(RuntimeError, match="base Python executable is unavailable"):
        seed._runtime_python_executable()


@pytest.mark.skipif(os.name != "nt" or sys.prefix == sys.base_prefix,
                    reason="Windows virtualenv redirector boundary")
def test_windows_venv_rejects_relative_base_executable(monkeypatch):
    seed = load_launcher()
    monkeypatch.setattr(sys, "_base_executable", "python.exe", raising=False)
    with pytest.raises(RuntimeError, match="not absolute"):
        seed._runtime_python_executable()
