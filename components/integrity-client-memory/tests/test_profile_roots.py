"""Explicit profile roots are metadata-only references, never state migration."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from integrity_client_memory import broker_bundle, native_install, native_runtime, profile_roots


def bindings():
    return {"seed_namespace": "fixture-seed", "namespace_fingerprint": "sha256:" + "a" * 64,
            "architecture_checkpoint_id": "checkpoint:fixture"}


def upstream():
    return {"command": sys.executable, "args": ["-c", "raise RuntimeError('UPSTREAM FORBIDDEN')"]}


def private(path):
    if os.name == "nt":
        from integrity_guardian._windows_files import create_private_directory_tree
        create_private_directory_tree(path)
    else:
        path.mkdir(mode=0o700)
    return path


@pytest.fixture
def roots(tmp_path):
    base = private(tmp_path / "private")
    return base, private(base / "owner-state"), private(base / "owner-envelopes")


def build(roots, **kwargs):
    base, state, envelopes = roots
    return broker_bundle.build_bundle(base / "staging", bindings=bindings(), upstream=upstream(), tools=None,
        deployment_root=base / "deployed", state_root=state, envelope_root=envelopes, **kwargs)


@pytest.mark.skipif(os.name != "nt", reason="Native Codex profile compilation requires Windows")
def test_default_has_no_preserved_root_contract(tmp_path, monkeypatch):
    monkeypatch.setattr(profile_roots, "existing_root", lambda *a: pytest.fail("default inspected an external root"))
    value = native_install.build("codex", upstream(), bindings(), tmp_path / "default")
    assert "preserved_roots" not in value and "state_root" not in value
    native_runtime.verify(tmp_path / "default/profile.json")


@pytest.mark.skipif(os.name != "nt", reason="Native Codex profile compilation requires Windows")
def test_stage_binds_deployment_and_never_reads_existing_state_contents(roots, monkeypatch):
    base, state, envelopes = roots
    (state / "opaque-fixture.bin").write_bytes(b"synthetic opaque fixture")
    (envelopes / "opaque-fixture.bin").write_bytes(b"synthetic opaque fixture")
    original = Path.read_bytes
    def read(path):
        if path.is_relative_to(state) or path.is_relative_to(envelopes):
            pytest.fail("compiler read existing protected contents")
        return original(path)
    monkeypatch.setattr(Path, "read_bytes", read)
    value = build(roots)
    assert value["root"] == str(base / "deployed")
    assert value["state_root"] == str(state) and value["envelope_root"] == str(envelopes)
    component = json.loads((base / "staging/component.json").read_text())
    assert component["values"]["path_2dbd800b4e29"] == str(state)
    assert component["values"]["path_f51de7de1b1c"] == str(envelopes)
    assert not (base / "deployed").exists()
    assert not list((base / "staging").rglob("opaque-fixture.bin"))
    with pytest.raises(ValueError, match="identity/platform"):
        native_runtime.verify(base / "staging/profile.json")


@pytest.mark.skipif(os.name != "nt", reason="Native Codex ownership entrypoints are Windows-only")
def test_full_deployed_payload_verifies_and_local_wire_probes(roots):
    base, state, envelopes = roots
    value = build(roots)
    shutil.copytree(base / "staging", base / "deployed")
    profile = base / "deployed/profile.json"
    native_runtime.verify(profile)
    environment = native_runtime.environment(value, base / "deployed")
    assert environment["INTEGRITY_CLIENT_STATE_ROOT"] == str(state)
    assert environment["INTEGRITY_CLIENT_ENVELOPE_ROOT"] == str(envelopes)
    checked = subprocess.run([sys.executable, "-B", str(base / "deployed/run-native-profile.py"),
        "--profile", str(profile), "probe"], env=environment, capture_output=True, timeout=45)
    assert checked.returncode == 0, checked.stderr.decode(errors="replace")


@pytest.mark.skipif(os.name != "nt", reason="Native Codex profile compilation requires Windows")
def test_preserved_root_replacement_is_denied_at_runtime(roots):
    base, state, _ = roots
    build(roots)
    shutil.copytree(base / "staging", base / "deployed")
    state.rename(base / "original-state")
    private(state)
    with pytest.raises(ValueError, match="custody changed"):
        native_runtime.verify(base / "deployed/profile.json")


def test_reparse_root_is_rejected_before_payload_creation(roots):
    base, state, envelopes = roots
    link = base / "state-link"
    if os.name == "nt":
        environment = dict(os.environ, INTEGRITY_FIXTURE_LINK=str(link), INTEGRITY_FIXTURE_TARGET=str(state))
        checked = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-Command",
            "New-Item -ItemType Junction -Path $env:INTEGRITY_FIXTURE_LINK -Target $env:INTEGRITY_FIXTURE_TARGET | Out-Null"],
            env=environment, capture_output=True, timeout=15)
        assert checked.returncode == 0
    else:
        link.symlink_to(state, target_is_directory=True)
    with pytest.raises(ValueError, match="ancestry custody"):
        profile_roots.existing_root(link)
    assert not (base / "refused").exists()


@pytest.mark.parametrize("fault", ["relative", "missing", "overlap", "command-path"])
@pytest.mark.skipif(os.name != "nt", reason="Native Codex profile compilation requires Windows")
def test_invalid_root_bindings_refused_before_output(roots, fault):
    base, state, envelopes = roots
    if fault == "relative":
        state = Path("relative")
    elif fault == "missing":
        state = base / "missing"
    elif fault == "overlap":
        envelopes = state
    with pytest.raises(ValueError):
        native_install.build("codex", upstream(), bindings(), base / "refused",
                             state_root=state, envelope_root=envelopes,
                             deployment_root=base / "unsafe&command" if fault == "command-path" else None)
    assert not (base / "refused").exists()


@pytest.mark.skipif(os.name != "nt", reason="Native Codex profile compilation requires Windows")
def test_canonical_memory_name_keeps_same_route_guards(tmp_path):
    owner = {**bindings(), "mcp_server_name": "integrity_client_memory"}
    value = native_install.build("codex", upstream(), owner, tmp_path / "canonical")
    assert value["mcp_server_name"] == "integrity_client_memory"
    assert "[mcp_servers.integrity_client_memory]" in (tmp_path / "canonical/codex-workspace/.codex/config.toml").read_text()
    native_runtime.verify(tmp_path / "canonical/profile.json")
    assert native_runtime.memory_call(b'{"tool_name":"mcp__integrity_client_memory__integrity_append_event"}') is True
    assert native_runtime.memory_call(b'{"tool_name":"mcp__integrity_native__integrity_append_event"}') is True
    assert native_runtime.memory_call(b'{"tool_name":"mcp__integrity_guardian__apply"}') is False
    with pytest.raises(ValueError, match="supported Memory route"):
        native_install.build("codex", upstream(), {**bindings(), "mcp_server_name": "foreign"}, tmp_path / "foreign")
    assert not (tmp_path / "foreign").exists()
