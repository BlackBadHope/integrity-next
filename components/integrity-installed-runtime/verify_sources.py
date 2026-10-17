"""Verify a code-only source reference without importing or running its code."""
from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
ALLOWED_SOURCE_GROUPS = frozenset({
    "core", "client-memory", "workstation-memory", "seed-sync",
    "server-hooks", "client-hooks", "action-log",
})


def verify_modes(expected: dict[str, str], *, roots: list[str] | None = None) -> list[str]:
    """Check portable Git metadata and native POSIX executable state separately."""
    checked = []
    prefix = "" if roots is not None else HERE.relative_to(REPO).as_posix() + "/"
    if (REPO / ".git").exists():
        raw = subprocess.run(
            ["git", "-C", str(REPO), "ls-files", "--stage", "-z", "--",
             *(roots if roots is not None else [prefix + "sources/"])],
            capture_output=True, check=True, timeout=15,
        ).stdout
        actual = {}
        for entry in raw.split(b"\0"):
            if not entry:
                continue
            metadata, name = entry.split(b"\t", 1)
            mode, _object_id, stage = metadata.split()
            if stage != b"0":
                raise ValueError("unmerged source member")
            actual[name.decode("utf-8")[len(prefix):]] = mode.decode("ascii")
        if actual != expected:
            raise ValueError("source executable mode mismatch in Git index")
        checked.append("git-index")
    if os.name != "nt":
        for relative, mode in expected.items():
            target = (REPO if roots is not None else HERE) / relative
            actual_mode = "100755" if target.stat().st_mode & 0o111 else "100644"
            if actual_mode != mode:
                raise ValueError("source executable mode mismatch on filesystem")
        checked.append("posix-filesystem")
    return checked


def verify_canonical() -> dict[str, object]:
    """Verify relocated canonical implementations without retaining kernel copies."""
    layout = json.loads((HERE / "VARIANTS.json").read_text(encoding="utf-8"))
    if layout.get("schema") != "integrity.source-layout/v2" or layout.get("runtime_data_included") is not False:
        raise ValueError("canonical source layout contract mismatch")
    roots = [row["path"] for row in layout["canonical_sources"]]
    if not roots or len(set(roots)) != len(roots):
        raise ValueError("canonical source roots are empty or duplicated")
    for relative in roots:
        candidate = Path(relative)
        target = REPO / relative
        if (candidate.is_absolute() or "\\" in relative or ":" in relative
                or ".." in candidate.parts or not target.is_dir() or target.is_symlink()
                or not target.resolve().is_relative_to(REPO.resolve())):
            raise ValueError("invalid canonical source root")
    manifest = json.loads((REPO / "PUBLIC-EXPORT-MANIFEST.json").read_text(encoding="utf-8"))
    rows = [row for group in ("files", "generated_files") for row in manifest[group]
            if any(row["path"].startswith(root.rstrip("/") + "/") for root in roots)]
    expected = set()
    modes = {}
    python_files = 0
    for row in rows:
        relative = row["path"]
        target = REPO / relative
        if (relative in expected or not target.is_file() or target.is_symlink()
                or not target.resolve().is_relative_to(REPO.resolve())
                or target.stat().st_nlink != 1):
            raise ValueError("invalid canonical source member")
        expected.add(relative)
        mode = int(row["mode"], 8)
        if mode not in {0o644, 0o755}:
            raise ValueError("invalid canonical executable mode")
        modes[relative] = "100755" if mode == 0o755 else "100644"
        data = target.read_bytes()
        if len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise ValueError("canonical source byte identity mismatch")
        if target.suffix in {".db", ".sqlite", ".sqlite3", ".key", ".pem", ".token", ".log"}:
            raise ValueError("non-source runtime member")
        if target.suffix == ".py":
            ast.parse(data.decode("utf-8"), filename=relative)
            python_files += 1
    actual = {path.relative_to(REPO).as_posix() for root in roots
              for path in (REPO / root).rglob("*") if path.is_file()}
    if not expected or actual != expected:
        raise ValueError("canonical source reference is not closed")
    checked = verify_modes(modes, roots=roots)
    return {"passed": True, "source_files": len(rows), "python_files": python_files,
            "mode_checks": checked, "layout": "canonical-v2",
            "native_executable_modes": "not-applicable-on-Windows" if os.name == "nt" else "verified"}


def verify() -> dict[str, object]:
    if (HERE / "VARIANTS.json").is_file():
        return verify_canonical()
    inventory = HERE / "SOURCE-INVENTORY.json"
    if inventory.is_file():
        value = json.loads(inventory.read_text(encoding="utf-8"))
        if (value.get("schema") != "integrity.installed-source-inventory/v1"
                or value.get("code_only") is not True
                or value.get("operational_state_included") is not False
                or value.get("source_count") != len(value["files"])):
            raise ValueError("source inventory contract mismatch")
        rows = value["files"]
    else:
        value = json.loads((REPO / "PUBLIC-EXPORT-MANIFEST.json").read_text(encoding="utf-8"))
        prefix = HERE.relative_to(REPO).as_posix() + "/"
        rows = [{**row, "path": row["path"][len(prefix):]}
                for row in value["files"] if row["path"].startswith(prefix + "sources/")]
    expected = set()
    expected_modes = {}
    python_files = 0
    for row in rows:
        relative = row["path"]
        target = HERE / relative
        if (not isinstance(relative, str) or not relative.startswith("sources/")
                or "\\" in relative or ".." in relative.split("/")
                or not target.resolve().is_relative_to(HERE.resolve())
                or target.is_symlink() or not target.is_file()):
            raise ValueError("invalid source member")
        if relative.split("/")[1] not in ALLOWED_SOURCE_GROUPS:
            raise ValueError("personal integration is outside the source boundary")
        if relative in expected:
            raise ValueError("duplicate source member")
        expected.add(relative)
        recorded_mode = row["mode"]
        mode = int(recorded_mode, 8) if isinstance(recorded_mode, str) else recorded_mode
        if mode not in {0o644, 0o755}:
            raise ValueError("invalid source executable mode")
        expected_modes[relative] = "100755" if mode == 0o755 else "100644"
        data = target.read_bytes()
        if len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise ValueError("source byte identity mismatch")
        if target.suffix in {".db", ".sqlite", ".sqlite3", ".key", ".pem", ".token", ".log"}:
            raise ValueError("non-source runtime member")
        if target.suffix == ".py":
            ast.parse(data.decode("utf-8"), filename=relative)
            python_files += 1
    actual = {p.relative_to(HERE).as_posix() for p in (HERE / "sources").rglob("*") if p.is_file()}
    if not expected or actual != expected:
        raise ValueError("source reference is not closed")
    modes_checked = verify_modes(expected_modes)
    return {"passed": True, "source_files": len(rows), "python_files": python_files,
            "mode_checks": modes_checked,
            "native_executable_modes": "not-applicable-on-Windows" if os.name == "nt" else "verified"}


if __name__ == "__main__":
    print(json.dumps(verify(), sort_keys=True))
