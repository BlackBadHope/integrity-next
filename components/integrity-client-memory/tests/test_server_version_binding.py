"""Metadata identity derivation cannot weaken a Native protocol contract."""
import ast
import sys

import pytest

from integrity_client_memory import native_install


def owner(**extra):
    return {"seed_namespace": "fixture-seed", "namespace_fingerprint": "sha256:" + "a" * 64,
            "architecture_checkpoint_id": "checkpoint:fixture", **extra}


def build(path, **bindings):
    return native_install.build("codex", {"command": sys.executable, "args": ["-c", "raise RuntimeError('UPSTREAM FORBIDDEN')"]},
                                owner(**bindings), path)


def test_absent_and_none_keep_default_hook_bytes(tmp_path):
    default, explicit = tmp_path / "default", tmp_path / "none"
    build(default)
    build(explicit, server_version=None)
    assert (default / "runtime/integrity-client-admission.py").read_bytes() == (explicit / "runtime/integrity-client-admission.py").read_bytes()


def test_derivation_changes_exactly_one_assignment_and_records_provenance(tmp_path):
    default, selected = tmp_path / "default", tmp_path / "selected"
    original = build(default)
    profile = build(selected, server_version="2.10.0")
    before = ast.parse((default / "runtime/integrity-client-admission.py").read_text())
    after = ast.parse((selected / "runtime/integrity-client-admission.py").read_text())
    for tree in (before, after):
        assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == "SERVER_VERSION" for target in node.targets))
        assignment.value = ast.Constant(value="NORMALIZED_EXACT_METADATA_IDENTITY")
    assert ast.dump(before, include_attributes=False) == ast.dump(after, include_attributes=False)
    assert profile["template_source_pins"] == original["template_source_pins"]
    assert any(row.get("constant") == "SERVER_VERSION" and row["value"] == "2.10.0"
               and row["binding"] == "server_version" for row in profile["derivations"])


@pytest.mark.parametrize("version", [True, "2.10", "02.10.0", "2.10.0\n", "2.10.0;unsafe"])
def test_invalid_identity_refused_before_output(tmp_path, version):
    path = tmp_path / "refused"
    with pytest.raises(ValueError, match="exact semantic version"):
        build(path, server_version=version)
    assert not path.exists()
