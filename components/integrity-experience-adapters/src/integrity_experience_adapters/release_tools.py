"""Read exact Git objects without checking out or trusting dirty worktree bytes."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

from . import contracts as c


def git_inventory(repository: Path, revision: str, paths: list[str]) -> dict:
    c.revision(revision)
    c.require(type(paths) is list and 1 <= len(paths) <= 128, "explicit_file_allowlist_required")
    c.require(len(set(paths)) == len(paths), "duplicate_allowlist_path")
    for name in paths:
        c.path(name)
    executable = shutil.which("git")
    c.require(executable is not None, "git_not_installed")
    environment = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                   "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0",
                   "GIT_NO_LAZY_FETCH": "1"}
    if os.name == "nt":
        environment["SystemRoot"] = os.environ.get("SystemRoot", "C:\\Windows")
    def git(*args: str) -> bytes:
        try:
            return subprocess.run([executable, "--no-replace-objects", "-C", str(repository), *args],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15,
                env=environment, check=True, shell=False).stdout
        except (subprocess.SubprocessError, OSError) as exc:
            raise c.ContractError("git_object_read_failed") from exc
    c.require(git("cat-file", "-t", revision).strip() == b"commit", "commit_object_required")
    size = int(git("cat-file", "-s", revision))
    c.require(0 < size <= c.MAX_JSON_BYTES, "commit_size_limit")
    commit = git("cat-file", "commit", revision)
    c.require(hashlib.sha1(b"commit " + str(len(commit)).encode() + b"\0" + commit).hexdigest()
              == revision, "commit_identity_mismatch")
    files = {}
    for name in paths:
        line = git("ls-tree", "-z", revision, "--", name)
        c.require(line.count(b"\0") == 1 and line.endswith(b"\0"), "single_regular_file_required")
        header, found = line[:-1].split(b"\t", 1)
        mode, kind, object_id = header.split(b" ")
        c.require(mode in (b"100644", b"100755") and kind == b"blob" and
                  found.decode("utf-8") == name, "non_regular_git_member")
        c.revision(object_id.decode("ascii"))
        size = int(git("cat-file", "-s", object_id.decode("ascii")))
        c.require(0 <= size <= 8 * 1024 * 1024, "git_blob_size_limit")
        data = git("cat-file", "blob", object_id.decode("ascii"))
        c.require(len(data) == size and hashlib.sha1(b"blob " + str(size).encode() + b"\0" + data)
                  .hexdigest().encode() == object_id, "git_blob_identity_mismatch")
        files[name] = data
        c.require(sum(map(len, files.values())) <= 32 * 1024 * 1024, "source_total_limit")
    result = c.release_inventory(files, revision)["payload"]
    result.update(git_source_verified=True, source_authenticity="exact_local_git_objects",
                  worktree_bytes_used=False, commit_signature_verified=False)
    return c.candidate("release-inventory", result)


def audit_changed_paths(plan: dict, role: str, changed_paths: list[str], contract: bytes) -> dict:
    """Pre-commit scope gate. The host obtains the diff and authenticates the role."""
    c.validate_workplan(plan)
    c.require(c.sha(contract) == plan["contract_sha256"], "contract_drift")
    owned = [job for job in plan["jobs"] if job["role"] == role]
    c.require(len(owned) == 1, "unknown_role")
    c.require(type(changed_paths) is list and len(changed_paths) <= 512, "changed_path_limit")
    scopes = [c.path(p).casefold() for p in owned[0]["write_paths"]]
    for name in changed_paths:
        name = c.path(name).casefold()
        c.require(any(name == scope or name.startswith(scope + "/") for scope in scopes),
                  "write_scope_violation")
    return c.candidate("scope-audit", {"role": role, "changed_paths": sorted(changed_paths),
        "contract_sha256": c.sha(contract), "scope_matches": True,
        "authenticated_actor_verified": False, "filesystem_permissions_enforced": False})
