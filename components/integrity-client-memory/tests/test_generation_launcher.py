import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import pytest


def test_immutable_generation_is_verified_before_exec(tmp_path, monkeypatch):
    source = Path(__file__).resolve().parents[1] / "src/integrity_client_memory/resources/common/generation_launcher.py"
    spec = importlib.util.spec_from_file_location("public_immutable_generation_test", source)
    launcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(launcher)
    monkeypatch.setattr(launcher, "__file__", str(tmp_path / "generation_launcher.py"))
    generations = tmp_path / launcher.GENERATIONS_DIR
    generations.mkdir(mode=0o700)
    parts = {
        "broker": (launcher.BROKER_FILE, b"# Synthetic broker only; never executed by this test.\n", 0o500),
        "tools": (launcher.TOOLS_FILE, b"[]\n", 0o400),
        "turn_envelope": (launcher.TURN_ENVELOPE_FILE, b"# Synthetic envelope only.\n", 0o400),
    }
    files = {key: {"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
             for key, (name, data, mode) in parts.items()}
    generation_id = launcher._digest(launcher._canonical({"protocol": launcher.GENERATION_PROTOCOL, "files": files}))
    directory = generations / generation_id
    directory.mkdir(mode=0o700)
    for name, data, mode in parts.values():
        path = directory / name
        path.write_bytes(data)
        path.chmod(mode)
    manifest = launcher._canonical({"protocol": launcher.GENERATION_PROTOCOL,
                                    "generation_id": generation_id, "files": files}) + b"\n"
    (directory / "manifest.json").write_bytes(manifest)
    (directory / "manifest.json").chmod(0o400)
    active = {"protocol": launcher.ACTIVE_PROTOCOL, "generation_id": generation_id,
              "manifest_sha256": hashlib.sha256(manifest).hexdigest()}
    (tmp_path / launcher.ACTIVE_FILE).write_bytes(launcher._canonical(active) + b"\n")
    (tmp_path / launcher.ACTIVE_FILE).chmod(0o600)
    directory.chmod(0o500)
    calls = []
    monkeypatch.setattr(launcher.os, "execv", lambda executable, argv: calls.append((executable, argv)))
    monkeypatch.setattr(sys, "argv", ["generation_launcher", "--config", "own-upstream.toml",
                                      "--upstream-server", "own-memory", "--tools-contract", "ignored.json"])
    try:
        assert launcher.main() == 0
        assert len(calls) == 1
        assert calls[0][1][-1] == str(directory / launcher.TOOLS_FILE)
        broker = directory / launcher.BROKER_FILE
        broker.chmod(0o700)
        broker.write_bytes(b"# Changed bytes must never reach exec.\n")
        broker.chmod(0o500)
        with pytest.raises(launcher.LaunchError, match="digest mismatch"):
            launcher.main()
        assert len(calls) == 1
    finally:
        directory.chmod(0o700)
        for path in directory.iterdir(): path.chmod(0o600)
