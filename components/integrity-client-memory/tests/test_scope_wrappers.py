import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

COMMON = Path(__file__).resolve().parents[1] / "src/integrity_client_memory/resources/common"


@pytest.mark.parametrize("harness", ["codex", "claude"])
def test_scope_cli_accepts_explicit_wrapper_arguments(tmp_path, monkeypatch, capsys, harness):
    source = COMMON / "integrity_scope_synapse.py"
    spec = importlib.util.spec_from_file_location("public_scope_wrapper_test", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b'{"session_id":"synthetic-scope-wrapper"}'), encoding="utf-8"))
    assert module.main(["--event", "PreToolUse", "--harness", harness, "--state", str(tmp_path / "state")]) == 0
    assert json.loads(capsys.readouterr().out) == {}


@pytest.mark.parametrize("harness", ["codex", "claude"])
def test_powershell_scope_wrapper_forwards_harness(tmp_path, harness):
    executable = shutil.which("pwsh")
    if executable is None:
        pytest.skip("PowerShell is not installed on this platform")
    wrapper = str(COMMON / "scope.ps1").replace("'", "''")
    command = ("function integrity-client-memory { $script:LASTEXITCODE=0; ConvertTo-Json -Compress -InputObject @($args) }; "
               f"& '{wrapper}' -Event PreToolUse -Harness {harness}")
    env = dict(os.environ, INTEGRITY_CLIENT_MEMORY_CONFIG=str(tmp_path / "own-config.json"))
    result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-Command", command],
                            capture_output=True, text=True, env=env, check=True)
    assert json.loads(result.stdout) == ["--config", env["INTEGRITY_CLIENT_MEMORY_CONFIG"],
        "common/integrity_scope_synapse", "--event", "PreToolUse", "--harness", harness]


def test_posix_wrapper_requires_and_validates_owner_selected_harness():
    script = (COMMON / "scope.sh").read_text(encoding="utf-8")
    assert 'harness=${2:?' in script
    assert 'case "$harness" in codex|claude)' in script
    assert 'common/integrity_scope_synapse --event "$event" --harness "$harness"' in script
