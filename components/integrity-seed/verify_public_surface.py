#!/usr/bin/env python3
from __future__ import annotations

import ast
import json
import sys
import tarfile
from pathlib import Path

sys.dont_write_bytecode = True

from verify_seed import validate_public_text


ROOT = Path(__file__).resolve().parent
FORBIDDEN_SUFFIXES = {".pyc", ".pyo", ".sqlite3", ".wal", ".shm"}
FORBIDDEN_NAMES = {"auth.json", "runtime.json", "server.log", "server.pid", "token"}
FORBIDDEN_IMPORT_ROOTS = frozenset({"integrity_guardian"})


def validate_dependency_boundary(label: str, value: str) -> None:
    """Reject ambient monorepo imports from Seed-owned Python source."""
    if not label.lower().endswith(".py"):
        return
    try:
        module = ast.parse(value, filename=label)
    except SyntaxError as exc:
        raise RuntimeError(f"invalid Python source in public tree: {label}:{exc.lineno}") from exc

    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            imported = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported = [node.module]
        else:
            continue
        for name in imported:
            root = name.partition(".")[0]
            if root in FORBIDDEN_IMPORT_ROOTS:
                line = getattr(node, "lineno", 0)
                raise RuntimeError(
                    f"forbidden monorepo import in public Seed source: {label}:{line}: {name}"
                )


def verify_dependency_boundary_guard() -> None:
    validate_dependency_boundary(
        "probe/local.py",
        "import json\nfrom .runtime import action_log\n",
    )
    try:
        validate_dependency_boundary(
            "probe/forbidden.py",
            "from integrity_guardian.mind_capsule import build_mind_capsule\n",
        )
    except RuntimeError as exc:
        if "forbidden monorepo import" not in str(exc):
            raise
    else:
        raise RuntimeError("dependency-boundary guard failed closed-loop probe")


def main() -> int:
    verify_dependency_boundary_guard()
    files = 0
    archive_members = 0
    python_sources = 0
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if ".git" in relative.parts or not path.is_file():
            continue
        files += 1
        label = relative.as_posix()
        validate_public_text("public path", label)
        if path.suffix.lower() in FORBIDDEN_SUFFIXES or path.name.lower() in FORBIDDEN_NAMES:
            raise RuntimeError(f"state or bytecode file in public tree: {label}")
        if path.suffix.lower() == ".tar":
            with tarfile.open(path, "r:") as archive:
                for member in archive.getmembers():
                    if not member.isfile():
                        raise RuntimeError(f"unsupported archive member: {member.name}")
                    archive_members += 1
                    validate_public_text("archive member name", member.name)
                    source = archive.extractfile(member)
                    if source is None:
                        raise RuntimeError(f"cannot read archive member: {member.name}")
                    value = source.read().decode("utf-8")
                    validate_public_text(member.name, value)
                    validate_dependency_boundary(member.name, value)
                    if member.name.lower().endswith(".py"):
                        python_sources += 1
            continue
        value = path.read_text(encoding="utf-8")
        validate_public_text(label, value)
        validate_dependency_boundary(label, value)
        if label.lower().endswith(".py"):
            python_sources += 1

    print(
        json.dumps(
            {
                "schema": "integrity-seed.public-surface-verifier.v1",
                "files": files,
                "archive_members": archive_members,
                "python_sources_checked": python_sources,
                "forbidden_monorepo_imports": 0,
                "dependency_boundary_probes": 2,
                "language_marker_matches": 0,
                "private_environment_matches": 0,
                "state_or_bytecode_files": 0,
                "passed": True,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
