"""The manifest updater preserves the public mode and path boundaries."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "public_manifest_updater", ROOT / ".github/scripts/update_manifest.py")
assert spec and spec.loader
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


def test_windows_mode_comes_from_git_or_retained_manifest() -> None:
    assert updater.portable_mode(0o100666, "0o755", "100755", windows=True) == "0o755"
    assert updater.portable_mode(0o100666, "0o755", None, windows=True) == "0o755"
    assert updater.portable_mode(0o100666, "0o755", "100644", windows=True) == "0o644"
    assert updater.portable_mode(0o100666, None, None, windows=True) == "0o644"


def test_posix_mode_uses_native_executable_bit() -> None:
    assert updater.portable_mode(0o100755, "0o644", "100644", windows=False) == "0o755"
    assert updater.portable_mode(0o100644, "0o755", "100755", windows=False) == "0o644"


@pytest.mark.parametrize("relative", ["../outside", "/absolute", "a/../outside", "a\\b", "a:stream"])
def test_manifest_rejects_path_escape(tmp_path: Path, relative: str) -> None:
    with pytest.raises(SystemExit, match="invalid relative"):
        updater.entry_for(tmp_path, relative, 0)


def test_mode_rejects_symlink_and_special_claims() -> None:
    with pytest.raises(SystemExit, match="Git file mode"):
        updater.portable_mode(0o100644, "0o644", "120000", windows=True)


def test_refreshed_manifest_has_portable_lf_bytes(tmp_path: Path) -> None:
    manifest = tmp_path / "PUBLIC-EXPORT-MANIFEST.json"
    manifest.write_bytes(b'{"files": [], "generated_files": []}\r\n')
    assert updater.main(["--root", str(tmp_path)]) == 0
    data = manifest.read_bytes()
    assert b"\r\n" not in data and data.endswith(b"\n")
    assert json.loads(data)["file_count"] == 0


@pytest.mark.parametrize("unexpected", [None, "unexpected.py", ".env"])
def test_guardian_sdist_keeps_an_exact_metadata_boundary(tmp_path: Path, unexpected) -> None:
    import io
    import tarfile
    import zipfile

    verifier_spec = importlib.util.spec_from_file_location(
        "public_wheel_verifier", ROOT / ".github/scripts/verify_wheels.py")
    assert verifier_spec and verifier_spec.loader
    verifier = importlib.util.module_from_spec(verifier_spec)
    verifier_spec.loader.exec_module(verifier)
    root = tmp_path / "source"
    package = root / "src/integrity_guardian"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (root / "COMPONENTS.json").write_text(json.dumps({"components": [{
        "distribution": "integrity-guardian", "version": "6.1.1",
        "dependencies": [], "optional_dependencies": {}}]}), encoding="utf-8")
    directory = tmp_path / "dist"
    directory.mkdir()
    with zipfile.ZipFile(directory / "integrity_guardian-6.1.1-py3-none-any.whl", "w") as archive:
        archive.writestr("integrity_guardian-6.1.1.dist-info/METADATA",
                         "Name: integrity-guardian\nVersion: 6.1.1\nLicense-Expression: Apache-2.0\n\n")
        archive.writestr("integrity_guardian-6.1.1.dist-info/licenses/LICENSE", "Apache-2.0")
        archive.writestr("integrity_guardian/__init__.py", "")
    members = ["src/integrity_guardian/__init__.py", "README.md", "LICENSE", "NOTICE",
               "AUTHORS.md", "pyproject.toml", "PKG-INFO", ".gitignore"]
    if unexpected:
        members.append(unexpected)
    with tarfile.open(directory / "integrity_guardian-6.1.1.tar.gz", "w:gz") as archive:
        for relative in members:
            info = tarfile.TarInfo("integrity_guardian-6.1.1/" + relative)
            archive.addfile(info, io.BytesIO(b""))
    if unexpected:
        with pytest.raises(ValueError, match="exactly the canonical package"):
            verifier.verify(root, directory)
    else:
        assert verifier.verify(root, directory)["guardian_sdist_boundary"] == "PASS"
