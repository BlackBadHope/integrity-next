import hashlib
import json
from pathlib import Path
import pytest
from integrity_bridges.profile import compile_profile, REQUIRED


def test_space_hub_profile_is_complete_closed_and_digest_bound(tmp_path):
    target = tmp_path / "hub"
    manifest = compile_profile("private-memory", target)
    assert REQUIRED <= manifest["files"].keys()
    assert set(manifest["files"]) == {p.name for p in target.glob("*.py")}
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((target / name).read_bytes()).hexdigest() == digest
    assert json.loads((target / "hub.example.json").read_text())["local_host"] is None
    with pytest.raises(FileExistsError): compile_profile("private-memory", target)
