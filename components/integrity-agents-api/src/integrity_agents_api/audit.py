"""Read-only first workload over an explicit immutable snapshot; no filesystem crawl."""
from __future__ import annotations

import re
import tomllib

from .contracts import MAX_BYTES, digest, encode, need, sha


def audit_snapshot(files: dict[str, bytes], expected: dict[str, str], commit: str) -> dict:
    need(type(commit) is str and bool(re.fullmatch(r"[0-9a-f]{40}", commit)), "exact_commit_required")
    need(type(files) is dict and set(files) == set(expected) and 1 <= len(files) <= 32, "snapshot_files")
    inventory, total = [], 0
    for name, raw in sorted(files.items()):
        need(type(name) is str and re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", name)
             and ".." not in name.split("/"), "snapshot_path")
        need(type(raw) is bytes and len(raw) <= 65536, "snapshot_file_size")
        total += len(raw)
        need(total <= MAX_BYTES and sha(raw) == digest(expected[name]), "snapshot_hash")
        inventory.append({"path": name, "sha256": sha(raw), "bytes": len(raw)})
    need("pyproject.toml" in files and "README.md" in files, "audit_inputs_required")
    try:
        version = tomllib.loads(files["pyproject.toml"].decode())["project"]["version"]
        readme = files["README.md"].decode()
    except (ValueError, UnicodeError, KeyError):
        raise ValueError("audit_input_rejected") from None
    need(type(version) is str and len(version) <= 64, "audit_version")
    findings = []
    if version not in readme:
        findings.append({"kind": "version_not_documented", "declared_version": version,
                         "source_path": "pyproject.toml", "documentation_path": "README.md"})
    return {"schema": "integrity-snapshot-audit/v1", "commit_ref": commit,
            "snapshot_sha256": sha(encode(inventory)), "inventory": inventory, "findings": findings,
            "git_commit_authenticated": False, "files_changed": False,
            "independent_review_performed": False, "canonical_completion_recorded": False}


def demo() -> dict:
    files = {"pyproject.toml": b'[project]\nname="fixture"\nversion="1.0.0rc1"\n',
             "README.md": b"# Synthetic fixture\nVersion: 0.9.0\n"}
    return audit_snapshot(files, {p: sha(b) for p, b in files.items()}, "a" * 40)
