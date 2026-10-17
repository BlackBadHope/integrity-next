"""Source-integrity refusals happen before loading a compiled Hub."""
import hashlib
import json

import pytest

from integrity_space import hub


@pytest.mark.parametrize("mutation", ["extra", "digest", "unsafe-name"])
def test_hub_manifest_refuses_unpinned_or_changed_source(tmp_path, monkeypatch, mutation):
    directory = tmp_path / "profile"
    directory.mkdir()
    files = {}
    for name in hub.HUB_FILES:
        data = b"# synthetic source-integrity fixture\n"
        (directory / name).write_bytes(data)
        files[name] = hashlib.sha256(data).hexdigest()
    if mutation == "extra":
        (directory / "unlisted.py").write_text("# synthetic unlisted\n")
    elif mutation == "digest":
        files["host_hub.py"] = "0" * 64
    else:
        files["../outside.py"] = "0" * 64
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"directory": str(directory), "files": files}), encoding="utf-8")
    config = tmp_path / "config.json"
    config.write_text("{}", encoding="utf-8")
    # This test admits only its own regular temp paths; it never imports code.
    def custody(path, *, directory=False):
        assert path.resolve().is_relative_to(tmp_path.resolve())
        assert path.is_dir() if directory else path.is_file()
    monkeypatch.setattr(hub, "private_path", custody)
    with pytest.raises(ValueError, match="(invalid pinned|unpinned|source changed)"):
        hub.load_hub(manifest, config)
