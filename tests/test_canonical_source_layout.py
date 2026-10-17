"""Canonical layout verification must still reject tampering and mode drift."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "canonical_source_verifier",
    ROOT / "components/integrity-installed-runtime/verify_sources.py",
)
assert spec and spec.loader
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


@pytest.fixture
def layout(tmp_path, monkeypatch):
    here = tmp_path / "components/integrity-installed-runtime"
    here.mkdir(parents=True)
    source = tmp_path / "src/synthetic_package"
    source.mkdir(parents=True)
    member = source / "__init__.py"
    data = b'"""Synthetic package."""\n'
    member.write_bytes(data)
    (here / "VARIANTS.json").write_text(json.dumps({
        "schema": "integrity.source-layout/v2", "runtime_data_included": False,
        "canonical_sources": [{"path": "src/synthetic_package"}],
    }), encoding="utf-8")
    (tmp_path / "PUBLIC-EXPORT-MANIFEST.json").write_text(json.dumps({
        "files": [{"path": "src/synthetic_package/__init__.py", "mode": "0o644",
                   "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}],
        "generated_files": [],
    }), encoding="utf-8")
    monkeypatch.setattr(verifier, "HERE", here)
    monkeypatch.setattr(verifier, "REPO", tmp_path)
    return tmp_path, source, member


def test_canonical_layout_checks_bytes_closure_and_modes(layout, monkeypatch):
    seen = []
    monkeypatch.setattr(verifier, "verify_modes", lambda modes, **kw: seen.append((modes, kw)) or ["synthetic"])
    result = verifier.verify()
    assert result["passed"] and result["source_files"] == result["python_files"] == 1
    assert seen == [({"src/synthetic_package/__init__.py": "100644"},
                     {"roots": ["src/synthetic_package"]})]


def test_canonical_layout_rejects_changed_bytes(layout):
    layout[2].write_bytes(b"tampered = True\n")
    with pytest.raises(ValueError, match="byte identity"):
        verifier.verify()


def test_canonical_layout_rejects_unmanifested_source(layout):
    (layout[1] / "extra.py").write_text("extra = True\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not closed"):
        verifier.verify()


def test_canonical_layout_rejects_escape(layout):
    path = verifier.HERE / "VARIANTS.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["canonical_sources"] = [{"path": "../outside"}]
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid canonical source root"):
        verifier.verify()


def test_git_executable_mode_drift_is_rejected(layout, monkeypatch):
    (layout[0] / ".git").mkdir()
    monkeypatch.setattr(verifier.subprocess, "run", lambda *a, **k: SimpleNamespace(
        stdout=b"100755 " + b"a" * 40 + b" 0\tsrc/synthetic_package/__init__.py\0"))
    with pytest.raises(ValueError, match="mode mismatch in Git index"):
        verifier.verify_modes({"src/synthetic_package/__init__.py": "100644"},
                              roots=["src/synthetic_package"])
