import hashlib
import json
import pytest
from integrity_client_memory.profile import compile_catalog, main, native_source_pins


def tools():
    return [{"name": name, "description": name, "inputSchema": {"type": "object"},
             "annotations": {"readOnlyHint": False}}
            for name in ("integrity_context_admission_current_turn", "integrity_turn_memory_open",
                         "integrity_turn_memory_close")]


def test_digest_is_of_actual_catalogue_bytes():
    data, digest = compile_catalog(tools())
    assert digest == hashlib.sha256(data).hexdigest()
    assert json.loads(data) == tools()
    changed = tools()
    changed[0]["inputSchema"]["required"] = ["turn_ref"]
    assert compile_catalog(changed)[1] != digest


def test_duplicate_or_incomplete_surface_is_rejected():
    with pytest.raises(ValueError): compile_catalog(tools() + [tools()[0]])
    with pytest.raises(ValueError): compile_catalog(tools()[:1])


def test_profile_is_unconfigured_and_never_clobbers(tmp_path):
    source = tmp_path / "tools.json"
    source.write_text(json.dumps(tools()))
    target = tmp_path / "profile"
    assert main(["--tools-json", str(source), "--output", str(target)]) == 0
    profile = json.loads((target / "profile-source.json").read_text())
    assert profile["configured"] is False
    assert profile["native_owner_bindings"] is None
    before = (target / "integrity-client-tools.json").read_bytes()
    assert main(["--tools-json", str(source), "--output", str(target)]) == 2
    assert (target / "integrity-client-tools.json").read_bytes() == before


def test_native_pins_are_packaged_code_not_an_enrollment():
    pins = native_source_pins()
    assert len(pins) >= 12
    assert all(len(digest) == 64 for digest in pins.values())
    assert not any("config" in path or "key" in path for path in pins)
