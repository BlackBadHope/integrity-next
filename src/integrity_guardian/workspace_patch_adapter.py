"""Target-specific Git worktree adapter over the existing ASDK lifecycle."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path, PurePosixPath
from typing import Any

from .adapter_conformance import (
    require_adapter_conformance_readiness,
    verify_adapter_conformance_receipt,
)
from .adapter_runtime import (
    AdapterDispatchPermit,
    AdapterRuntimeError,
    _verify_envelope_signature,
    build_adapter_execution_report,
)
from .adapter_sdk import (
    ADAPTER_SDK_VERSION,
    AdapterReportedOutcome,
    adapter_capability_manifest_digest,
    adapter_execution_envelope_digest,
    adapter_operation_binding_digest,
    adapter_target_operation_digest,
    verify_adapter_capability_manifest,
    verify_adapter_operation_binding,
    verify_adapter_target_operation,
)
from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object, sha256_digest
from .schemas import load_schema, validate
from .signing import Ed25519Signer, TrustedKey, verify_signature

_SAFE_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,239}$")
_OID = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
_DIFF_HEADER = re.compile(
    r"^diff --git a/([A-Za-z0-9][A-Za-z0-9._/-]{0,239}) b/([A-Za-z0-9][A-Za-z0-9._/-]{0,239})$"
)
_FORBIDDEN_PATCH_PREFIXES = (
    "GIT binary patch",
    "Binary files ",
    "new file mode ",
    "deleted file mode ",
    "old mode ",
    "new mode ",
    "rename from ",
    "rename to ",
    "copy from ",
    "copy to ",
)
_MAX_PATCH_BYTES = 4 * 1024 * 1024


class WorkspacePatchError(AdapterRuntimeError):
    """Raised before a workspace transition can be overstated or widened."""


def _freeze(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    try:
        candidate = parse_json_strict(canonical_bytes(dict(value)))
    except Exception as exc:
        raise WorkspacePatchError(f"workspace patch {field} rejected") from exc
    if not isinstance(candidate, dict):
        raise WorkspacePatchError(f"workspace patch {field} rejected")
    return candidate


def _identity(
    document: Mapping[str, Any],
    *,
    field: str,
    prefix: str,
    domain: str,
) -> str:
    core = deepcopy(dict(document))
    core.pop(field, None)
    core.pop("signature", None)
    return prefix + digest_object(core, domain=domain).split(":", 1)[1]


def _verify_signed(
    document: Mapping[str, Any],
    *,
    schema: str,
    field: str,
    prefix: str,
    domain: str,
    trusted_key: TrustedKey,
) -> dict[str, Any]:
    candidate = _freeze(document, schema)
    try:
        validate(schema, candidate)
    except Exception as exc:
        raise WorkspacePatchError(f"workspace patch {schema} schema rejected") from exc
    if candidate[field] != _identity(
        candidate,
        field=field,
        prefix=prefix,
        domain=domain,
    ):
        raise WorkspacePatchError(f"workspace patch {schema} identity mismatch")
    if (
        candidate["signer_id"] != trusted_key.key_id
        or candidate["signature"]["key_id"] != trusted_key.key_id
        or not verify_signature(candidate, trusted_key.public_key)
    ):
        raise WorkspacePatchError(f"workspace patch {schema} signature rejected")
    return candidate


def workspace_patch_schema_digest() -> str:
    return digest_object(
        load_schema("workspace-patch-manifest"),
        domain="workspace-patch-manifest-schema-v1",
    )


def workspace_patch_manifest_digest(manifest: Mapping[str, Any]) -> str:
    return digest_object(dict(manifest), domain="workspace-patch-manifest-v1")


def workspace_patch_execution_receipt_digest(receipt: Mapping[str, Any]) -> str:
    return digest_object(dict(receipt), domain="workspace-patch-execution-receipt-v1")


def workspace_patch_witness_digest(witness: Mapping[str, Any]) -> str:
    return digest_object(dict(witness), domain="workspace-patch-witness-v1")


def _workspace_patch_resource_ids(patch: Mapping[str, Any]) -> list[str]:
    return [
        "path:"
        + digest_object(path, domain="workspace-patch-path-identity-v1").split(
            ":",
            1,
        )[1]
        for path in patch["patch"]["allowed_paths"]
    ]


def _require_workspace_patch_operation_binding(
    operation: Mapping[str, Any],
    patch: Mapping[str, Any],
) -> None:
    if (
        operation["payload"]
        != {
            "schema_id": "workspace-patch-manifest/v1",
            "schema_digest": workspace_patch_schema_digest(),
            "document_digest": workspace_patch_manifest_digest(patch),
        }
        or operation["blast_radius"]["resource_kind"] != "path"
        or operation["blast_radius"]["allowed_resource_ids"]
        != _workspace_patch_resource_ids(patch)
        or patch["intent_operation_digest"] != operation["intent_operation_digest"]
        or patch["target"]["node_id"] != operation["target"]["node_id"]
        or patch["target"]["zone_id"] != operation["target"]["zone_id"]
        or patch["target"]["environment_digest"]
        != operation["target"]["environment_digest"]
    ):
        raise WorkspacePatchError("workspace patch typed operation mismatch")


def _file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            hasher.update(chunk)
    return "sha256:" + hasher.hexdigest()


def _git_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent-integrity-workspace",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    if extra:
        environment.update(extra)
    return environment


def _run(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
    pass_fds: Sequence[int] = (),
    timeout: int = 30,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            list(argv),
            cwd=None if cwd is None else str(cwd),
            env=dict(environment or _git_environment()),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            pass_fds=tuple(pass_fds),
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise WorkspacePatchError("workspace patch contained process unavailable") from exc
    if len(result.stdout) > 1024 * 1024 or len(result.stderr) > 1024 * 1024:
        raise WorkspacePatchError("workspace patch contained output exceeded bound")
    if check and result.returncode != 0:
        raise WorkspacePatchError("workspace patch git operation failed")
    return result


def _git(root: Path, git_executable: Path, *arguments: str, check: bool = True) -> bytes:
    return _run(
        [str(git_executable), "-C", str(root), *arguments],
        environment=_git_environment(),
        check=check,
    ).stdout


def _decode_token(value: bytes, field: str) -> str:
    try:
        text = value.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise WorkspacePatchError(f"workspace patch {field} rejected") from exc
    if not text:
        raise WorkspacePatchError(f"workspace patch {field} rejected")
    return text


def _normalize_path(value: str) -> str:
    if _SAFE_PATH.fullmatch(value) is None or "\\" in value:
        raise WorkspacePatchError("workspace patch path rejected")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise WorkspacePatchError("workspace patch path rejected")
    if path.parts[0] == ".git":
        raise WorkspacePatchError("workspace patch Git metadata path rejected")
    return path.as_posix()


def _normalize_paths(values: Sequence[str]) -> list[str]:
    paths = [_normalize_path(value) for value in values]
    if not paths or paths != sorted(set(paths)) or len(paths) > 64:
        raise WorkspacePatchError("workspace patch allowed path set rejected")
    return paths


def _patch_paths(payload: bytes) -> list[str]:
    if not payload or len(payload) > _MAX_PATCH_BYTES or b"\x00" in payload:
        raise WorkspacePatchError("workspace patch payload rejected")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise WorkspacePatchError("workspace patch encoding rejected") from exc
    paths: list[str] = []
    current_path: str | None = None
    old_marker_seen = False
    new_marker_seen = False
    for line in text.splitlines():
        if line.startswith(_FORBIDDEN_PATCH_PREFIXES):
            raise WorkspacePatchError("workspace patch unsupported transition rejected")
        if line.startswith(("--- /dev/null", "+++ /dev/null")):
            raise WorkspacePatchError("workspace patch create/delete rejected")
        if line.startswith("diff --git "):
            if current_path is not None and not (old_marker_seen and new_marker_seen):
                raise WorkspacePatchError("workspace patch file markers rejected")
            match = _DIFF_HEADER.fullmatch(line)
            if match is None or match.group(1) != match.group(2):
                raise WorkspacePatchError("workspace patch diff header rejected")
            current_path = _normalize_path(match.group(1))
            paths.append(current_path)
            old_marker_seen = False
            new_marker_seen = False
        elif current_path is not None and not old_marker_seen and line.startswith("--- "):
            if line != f"--- a/{current_path}":
                raise WorkspacePatchError("workspace patch old path marker rejected")
            old_marker_seen = True
        elif (
            current_path is not None
            and old_marker_seen
            and not new_marker_seen
            and line.startswith("+++ ")
        ):
            if line != f"+++ b/{current_path}":
                raise WorkspacePatchError("workspace patch new path marker rejected")
            new_marker_seen = True
    if current_path is not None and not (old_marker_seen and new_marker_seen):
        raise WorkspacePatchError("workspace patch file markers rejected")
    if not paths or paths != sorted(set(paths)):
        raise WorkspacePatchError("workspace patch diff path set rejected")
    return paths


def _changed_paths(root: Path, git_executable: Path) -> list[str]:
    tracked = _git(
        root,
        git_executable,
        "diff",
        "--name-only",
        "-z",
        "--no-ext-diff",
        "HEAD",
    )
    untracked = _git(
        root,
        git_executable,
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
    )
    values = [
        _normalize_path(item.decode("utf-8", errors="strict"))
        for item in (tracked + untracked).split(b"\x00")
        if item
    ]
    return sorted(set(values))


def _git_layout(root: Path, git_executable: Path) -> tuple[Path, Path]:
    git_dir_text = _decode_token(
        _git(root, git_executable, "rev-parse", "--absolute-git-dir"),
        "git directory",
    )
    common_text = _decode_token(
        _git(root, git_executable, "rev-parse", "--git-common-dir"),
        "git common directory",
    )
    git_dir = Path(git_dir_text).resolve(strict=True)
    common = Path(common_text)
    if not common.is_absolute():
        common = (root / common).resolve(strict=True)
    else:
        common = common.resolve(strict=True)
    return git_dir, common


def _worktree_tree_oid(
    root: Path,
    git_executable: Path,
    *,
    patch_path: Path | None = None,
) -> str:
    _, common = _git_layout(root, git_executable)
    objects = (common / "objects").resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="integrity-workspace-tree-") as temporary:
        temp = Path(temporary)
        object_directory = temp / "objects"
        object_directory.mkdir(mode=0o700)
        environment = _git_environment(
            {
                "GIT_INDEX_FILE": str(temp / "index"),
                "GIT_OBJECT_DIRECTORY": str(object_directory),
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(objects),
            }
        )
        prefix = [str(git_executable), "-C", str(root)]
        _run([*prefix, "read-tree", "HEAD"], environment=environment)
        if patch_path is None:
            _run([*prefix, "add", "-A"], environment=environment)
        else:
            _run(
                [*prefix, "apply", "--cached", "--check", str(patch_path)],
                environment=environment,
            )
            _run(
                [*prefix, "apply", "--cached", str(patch_path)],
                environment=environment,
            )
        tree = _decode_token(
            _run([*prefix, "write-tree"], environment=environment).stdout,
            "tree oid",
        )
    if _OID.fullmatch(tree) is None:
        raise WorkspacePatchError("workspace patch tree oid rejected")
    return tree


def observe_workspace(
    root: Path,
    *,
    git_executable: Path = Path("/usr/bin/git"),
) -> dict[str, Any]:
    """Return a content-free Git target fingerprint and current state."""

    resolved = root.resolve(strict=True)
    executable = git_executable.resolve(strict=True)
    if not resolved.is_dir() or not executable.is_file():
        raise WorkspacePatchError("workspace patch target unavailable")
    git_dir, common = _git_layout(resolved, executable)
    head = _decode_token(_git(resolved, executable, "rev-parse", "HEAD"), "head oid")
    base_tree = _decode_token(
        _git(resolved, executable, "rev-parse", "HEAD^{tree}"),
        "base tree oid",
    )
    object_format = _decode_token(
        _git(resolved, executable, "rev-parse", "--show-object-format"),
        "object format",
    )
    if (
        object_format not in {"sha1", "sha256"}
        or not _OID.fullmatch(head)
        or not _OID.fullmatch(base_tree)
    ):
        raise WorkspacePatchError("workspace patch repository identity rejected")
    changed = _changed_paths(resolved, executable)
    tree = base_tree if not changed else _worktree_tree_oid(resolved, executable)
    repository_id = (
        "repository:"
        + digest_object(
            {"common_git_directory": str(common)},
            domain="workspace-patch-repository-identity-v1",
        ).split(":", 1)[1]
    )
    worktree_id = (
        "worktree:"
        + digest_object(
            {"root": str(resolved), "git_directory": str(git_dir)},
            domain="workspace-patch-worktree-identity-v1",
        ).split(":", 1)[1]
    )
    git_version = _decode_token(
        _run([str(executable), "--version"], environment=_git_environment()).stdout,
        "git version",
    )
    environment_digest = digest_object(
        {
            "os": platform.system(),
            "machine": platform.machine(),
            "git_version": git_version,
            "git_executable_digest": _file_sha256(executable),
            "object_format": object_format,
        },
        domain="workspace-patch-environment-v1",
    )
    changed_digest = digest_object(changed, domain="workspace-patch-path-set-v1")
    state_digest = digest_object(
        {
            "repository_id": repository_id,
            "worktree_id": worktree_id,
            "environment_digest": environment_digest,
            "head_oid": head,
            "tree_oid": tree,
            "changed_paths_digest": changed_digest,
        },
        domain="workspace-patch-state-v1",
    )
    return {
        "repository_id": repository_id,
        "worktree_id": worktree_id,
        "environment_digest": environment_digest,
        "object_format": object_format,
        "head_oid": head,
        "base_tree_oid": base_tree,
        "tree_oid": tree,
        "state_digest": state_digest,
        "clean": not changed,
        "changed_paths": changed,
        "changed_paths_digest": changed_digest,
    }


def build_workspace_patch_manifest(
    *,
    capability_manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    intent_operation_digest: str,
    target_node_id: str,
    target_zone_id: str,
    workspace: Mapping[str, Any],
    patch_path: Path,
    allowed_paths: Sequence[str],
    created_at: str,
    signer: Ed25519Signer,
    git_executable: Path = Path("/usr/bin/git"),
    workspace_root: Path,
) -> dict[str, Any]:
    manifest = verify_adapter_capability_manifest(
        capability_manifest,
        adapter_key=adapter_key,
    )
    snapshot = _freeze(workspace, "workspace observation")
    if snapshot["clean"] is not True:
        raise WorkspacePatchError("workspace patch requires a clean target")
    paths = _normalize_paths(allowed_paths)
    patch = patch_path.resolve(strict=True)
    payload = patch.read_bytes()
    if _patch_paths(payload) != paths:
        raise WorkspacePatchError("workspace patch payload exceeds declared paths")
    root = workspace_root.resolve(strict=True)
    current = observe_workspace(root, git_executable=git_executable)
    if current != snapshot:
        raise WorkspacePatchError("workspace patch observation is stale")
    for path in paths:
        unresolved = root / path
        candidate = unresolved.resolve(strict=True)
        if unresolved.is_symlink() or not candidate.is_file() or not candidate.is_relative_to(root):
            raise WorkspacePatchError("workspace patch path type rejected")
        _git(root, git_executable, "ls-files", "--error-unmatch", "--", path)
        attribute = _decode_token(
            _git(root, git_executable, "check-attr", "filter", "--", path),
            "filter attribute",
        )
        if not attribute.endswith(": unspecified"):
            raise WorkspacePatchError("workspace patch filtered path rejected")
    expected_tree = _worktree_tree_oid(root, git_executable, patch_path=patch)
    core = {
        "protocol": "integrity-guardian/workspace-patch-manifest/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "manifest": {
            "manifest_id": manifest["manifest_id"],
            "manifest_digest": adapter_capability_manifest_digest(manifest),
            "adapter_id": manifest["adapter_id"],
            "adapter_artifact_digest": manifest["adapter_artifact_digest"],
        },
        "intent_operation_digest": intent_operation_digest,
        "target": {
            "node_id": target_node_id,
            "zone_id": target_zone_id,
            "repository_id": snapshot["repository_id"],
            "worktree_id": snapshot["worktree_id"],
            "environment_digest": snapshot["environment_digest"],
            "object_format": snapshot["object_format"],
            "base_head_oid": snapshot["head_oid"],
            "base_tree_oid": snapshot["tree_oid"],
            "expected_tree_oid": expected_tree,
        },
        "patch": {
            "digest": sha256_digest(payload),
            "byte_count": len(payload),
            "allowed_paths": paths,
            "allowed_paths_digest": digest_object(
                paths,
                domain="workspace-patch-path-set-v1",
            ),
        },
        "controls": {
            "clean_worktree_required": True,
            "tracked_paths_only": True,
            "regular_files_only": True,
            "binary_patch": False,
            "rename_copy": False,
            "mode_change": False,
            "symlink": False,
            "git_index_write": False,
            "git_remote": False,
            "network": False,
            "credentials": False,
            "production_authority": False,
            "max_invocations": 1,
            "automatic_retry_after_unknown": False,
        },
        "created_at": created_at,
        "signer_id": signer.key_id,
    }
    unsigned = {
        "patch_id": _identity(
            core,
            field="patch_id",
            prefix="workspace-patch:",
            domain="workspace-patch-manifest-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("workspace-patch-manifest", signed)
    return signed


def verify_workspace_patch_manifest(
    manifest: Mapping[str, Any],
    *,
    capability_manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    patch_key: TrustedKey,
) -> dict[str, Any]:
    candidate = _verify_signed(
        manifest,
        schema="workspace-patch-manifest",
        field="patch_id",
        prefix="workspace-patch:",
        domain="workspace-patch-manifest-identity-v1",
        trusted_key=patch_key,
    )
    capability = verify_adapter_capability_manifest(
        capability_manifest,
        adapter_key=adapter_key,
    )
    if candidate["manifest"] != {
        "manifest_id": capability["manifest_id"],
        "manifest_digest": adapter_capability_manifest_digest(capability),
        "adapter_id": capability["adapter_id"],
        "adapter_artifact_digest": capability["adapter_artifact_digest"],
    }:
        raise WorkspacePatchError("workspace patch adapter manifest mismatch")
    paths = _normalize_paths(candidate["patch"]["allowed_paths"])
    if candidate["patch"]["allowed_paths_digest"] != digest_object(
        paths,
        domain="workspace-patch-path-set-v1",
    ):
        raise WorkspacePatchError("workspace patch allowed path digest mismatch")
    return candidate


def _receipt_state(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "head_oid": snapshot["head_oid"],
        "tree_oid": snapshot["tree_oid"],
        "state_digest": snapshot["state_digest"],
        "clean": snapshot["clean"],
    }


def _build_execution_receipt(
    *,
    envelope: Mapping[str, Any],
    target_operation: Mapping[str, Any],
    patch_manifest: Mapping[str, Any],
    executor_id: str,
    executor_artifact_digest: str,
    before: Mapping[str, Any],
    after: Mapping[str, Any] | None,
    reported_outcome: AdapterReportedOutcome,
    reason_code: str,
    recorded_at: str,
    signer: Ed25519Signer,
) -> dict[str, Any]:
    observed_paths = [] if after is None else list(after["changed_paths"])
    allowed = patch_manifest["patch"]["allowed_paths"]
    outside = sorted(set(observed_paths) - set(allowed))
    if outside:
        raise WorkspacePatchError("workspace patch observed out-of-scope change")
    expected = (
        None
        if after is None
        else after["tree_oid"] == patch_manifest["target"]["expected_tree_oid"]
    )
    core = {
        "protocol": "integrity-guardian/workspace-patch-execution-receipt/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "envelope": {
            "envelope_id": envelope["envelope_id"],
            "envelope_digest": adapter_execution_envelope_digest(envelope),
        },
        "operation": {
            "target_operation_id": target_operation["operation_id"],
            "target_operation_digest": adapter_target_operation_digest(target_operation),
            "patch_id": patch_manifest["patch_id"],
            "patch_manifest_digest": workspace_patch_manifest_digest(patch_manifest),
            "patch_digest": patch_manifest["patch"]["digest"],
        },
        "executor": {
            "executor_id": executor_id,
            "executor_artifact_digest": executor_artifact_digest,
            "key_id": signer.key_id,
        },
        "before": _receipt_state(before),
        "after": None if after is None else _receipt_state(after),
        "blast_radius": {
            "allowed_paths_digest": patch_manifest["patch"]["allowed_paths_digest"],
            "allowed_path_count": len(allowed),
            "observed_paths_digest": digest_object(
                observed_paths,
                domain="workspace-patch-path-set-v1",
            ),
            "observed_path_count": len(observed_paths),
            "outside_allowed_count": 0,
        },
        "result": {
            "reported_outcome": reported_outcome.value,
            "reason_code": reason_code,
            "expected_tree_observed": expected,
            "action_replayed": False,
            "automatic_retry_allowed": False,
        },
        "controls": {
            "bwrap": True,
            "network": False,
            "credentials": False,
            "git_index_write": False,
            "git_remote": False,
            "production_authority": False,
        },
        "recorded_at": recorded_at,
        "signer_id": signer.key_id,
    }
    unsigned = {
        "receipt_id": _identity(
            core,
            field="receipt_id",
            prefix="workspace-patch-execution:",
            domain="workspace-patch-execution-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("workspace-patch-execution-receipt", signed)
    return signed


def verify_workspace_patch_execution_receipt(
    receipt: Mapping[str, Any],
    *,
    executor_key: TrustedKey,
    envelope: Mapping[str, Any],
    target_operation: Mapping[str, Any],
    patch_manifest: Mapping[str, Any],
    executor_id: str,
    executor_artifact_digest: str,
) -> dict[str, Any]:
    candidate = _verify_signed(
        receipt,
        schema="workspace-patch-execution-receipt",
        field="receipt_id",
        prefix="workspace-patch-execution:",
        domain="workspace-patch-execution-identity-v1",
        trusted_key=executor_key,
    )
    try:
        _require_workspace_patch_operation_binding(target_operation, patch_manifest)
        expected_envelope = {
            "envelope_id": envelope["envelope_id"],
            "envelope_digest": adapter_execution_envelope_digest(envelope),
        }
        expected_operation = {
            "target_operation_id": target_operation["operation_id"],
            "target_operation_digest": adapter_target_operation_digest(
                target_operation
            ),
            "patch_id": patch_manifest["patch_id"],
            "patch_manifest_digest": workspace_patch_manifest_digest(
                patch_manifest
            ),
            "patch_digest": patch_manifest["patch"]["digest"],
        }
        expected_executor = {
            "executor_id": executor_id,
            "executor_artifact_digest": executor_artifact_digest,
            "key_id": executor_key.key_id,
        }
        expected_allowed_digest = patch_manifest["patch"]["allowed_paths_digest"]
        expected_allowed_count = len(patch_manifest["patch"]["allowed_paths"])
    except WorkspacePatchError as exc:
        raise WorkspacePatchError("workspace patch receipt context mismatch") from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise WorkspacePatchError("workspace patch receipt context rejected") from exc
    if (
        candidate["envelope"] != expected_envelope
        or candidate["operation"] != expected_operation
        or candidate["executor"] != expected_executor
        or candidate["blast_radius"]["allowed_paths_digest"]
        != expected_allowed_digest
        or candidate["blast_radius"]["allowed_path_count"]
        != expected_allowed_count
    ):
        raise WorkspacePatchError("workspace patch receipt context mismatch")
    after = candidate["after"]
    expected_tree_observed = (
        None
        if after is None
        else after["tree_oid"] == patch_manifest["target"]["expected_tree_oid"]
    )
    result = candidate["result"]
    if result["expected_tree_observed"] is not expected_tree_observed:
        raise WorkspacePatchError("workspace patch receipt result mismatch")
    if result["reported_outcome"] == "reported-success" and (
        result["reason_code"] != "expected-tree-observed"
        or expected_tree_observed is not True
        or candidate["blast_radius"]["observed_paths_digest"]
        != expected_allowed_digest
        or candidate["blast_radius"]["observed_path_count"]
        != expected_allowed_count
    ):
        raise WorkspacePatchError("workspace patch receipt success mismatch")
    return candidate


def _bwrap_apply(
    *,
    root: Path,
    patch_fd: int,
    git_executable: Path,
    bwrap_executable: Path,
) -> subprocess.CompletedProcess[bytes]:
    git_dir, common = _git_layout(root, git_executable)
    relative_git_dir = git_dir.relative_to(common) if git_dir != common else Path(".")
    sandbox_git_dir = Path("/git-common") / relative_git_dir
    argv = [
        str(bwrap_executable),
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--ro-bind",
        "/usr",
        "/usr",
    ]
    for system_path in (Path("/lib"), Path("/lib64")):
        if system_path.exists():
            argv.extend(["--ro-bind", str(system_path), str(system_path)])
    argv.extend(
        [
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--bind",
            str(root),
            "/workspace",
            "--ro-bind",
            str(common),
            "/git-common",
            "--ro-bind-data",
            str(patch_fd),
            "/input.patch",
            "--setenv",
            "GIT_DIR",
            str(sandbox_git_dir),
            "--setenv",
            "GIT_COMMON_DIR",
            "/git-common",
            "--setenv",
            "GIT_WORK_TREE",
            "/workspace",
            "--setenv",
            "GIT_CONFIG_GLOBAL",
            "/dev/null",
            "--setenv",
            "GIT_CONFIG_NOSYSTEM",
            "1",
            "--setenv",
            "GIT_OPTIONAL_LOCKS",
            "0",
            "--setenv",
            "GIT_TERMINAL_PROMPT",
            "0",
            "--setenv",
            "HOME",
            "/nonexistent-integrity-workspace",
            "--setenv",
            "LANG",
            "C",
            "--setenv",
            "LC_ALL",
            "C",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--chdir",
            "/workspace",
            str(git_executable),
            "apply",
            "--check",
            "/input.patch",
        ]
    )
    os.lseek(patch_fd, 0, os.SEEK_SET)
    check = _run(
        argv,
        environment=_git_environment(),
        pass_fds=(patch_fd,),
        check=False,
    )
    if check.returncode != 0:
        return check
    argv[-4:] = [str(git_executable), "apply", "/input.patch"]
    os.lseek(patch_fd, 0, os.SEEK_SET)
    return _run(
        argv,
        environment=_git_environment(),
        pass_fds=(patch_fd,),
        check=False,
    )


def _sealed_patch_fd(payload: bytes) -> int:
    try:
        import fcntl
    except ImportError as exc:
        raise WorkspacePatchError("workspace patch immutable custody unavailable") from exc
    if not hasattr(os, "memfd_create"):
        raise WorkspacePatchError("workspace patch immutable custody unavailable")
    flags = getattr(os, "MFD_CLOEXEC", 0) | getattr(os, "MFD_ALLOW_SEALING", 0)
    try:
        descriptor = os.memfd_create("integrity-workspace-patch", flags)
    except OSError as exc:
        raise WorkspacePatchError("workspace patch immutable custody unavailable") from exc
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise WorkspacePatchError("workspace patch immutable copy failed")
            remaining = remaining[written:]
        os.fchmod(descriptor, 0o400)
        seals = (
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
        )
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & seals != seals:
            raise WorkspacePatchError("workspace patch immutable seal rejected")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except WorkspacePatchError:
        os.close(descriptor)
        raise
    except (AttributeError, OSError) as exc:
        os.close(descriptor)
        raise WorkspacePatchError("workspace patch immutable seal rejected") from exc


class WorkspacePatchAdapter:
    """One exact non-production patch under the shared ASDK crash boundary."""

    def __init__(
        self,
        *,
        capability_manifest: Mapping[str, Any],
        adapter_key: TrustedKey,
        conformance_profile: Mapping[str, Any],
        conformance_profile_key: TrustedKey,
        conformance_receipt: Mapping[str, Any],
        conformance_evidence: Sequence[Mapping[str, Any]],
        conformance_evidence_keys: Mapping[str, TrustedKey],
        conformance_receipt_key: TrustedKey,
        proposal: Mapping[str, Any],
        proposer_key: TrustedKey,
        operation_binding: Mapping[str, Any],
        target_operation: Mapping[str, Any],
        operation_key: TrustedKey,
        patch_manifest: Mapping[str, Any],
        patch_key: TrustedKey,
        coordinator_key: TrustedKey,
        executor_id: str,
        executor_artifact_digest: str,
        signer: Ed25519Signer,
        workspace_root: Path,
        patch_path: Path,
        git_executable: Path = Path("/usr/bin/git"),
        bwrap_executable: Path = Path("/usr/bin/bwrap"),
    ) -> None:
        manifest = verify_adapter_capability_manifest(
            capability_manifest,
            adapter_key=adapter_key,
        )
        conformance = verify_adapter_conformance_receipt(
            conformance_receipt,
            profile=conformance_profile,
            profile_key=conformance_profile_key,
            manifest=manifest,
            adapter_key=adapter_key,
            evidence_documents=conformance_evidence,
            evidence_keys=conformance_evidence_keys,
            receipt_key=conformance_receipt_key,
        )
        require_adapter_conformance_readiness(conformance, minimum="source-ready")
        if manifest["declared_channels"] != {
            "api": False,
            "browser_control": False,
            "computer_use": False,
            "credentials": False,
            "network": False,
            "service_control": False,
            "shell": True,
        }:
            raise WorkspacePatchError("workspace patch channel declaration rejected")
        operation = verify_adapter_target_operation(
            target_operation,
            manifest=manifest,
            adapter_key=adapter_key,
            operation_key=operation_key,
        )
        patch = verify_workspace_patch_manifest(
            patch_manifest,
            capability_manifest=manifest,
            adapter_key=adapter_key,
            patch_key=patch_key,
        )
        binding = verify_adapter_operation_binding(
            operation_binding,
            manifest=manifest,
            adapter_key=adapter_key,
            proposal=proposal,
            proposer_key=proposer_key,
            operation_manifest=operation,
            operation_key=operation_key,
            binding_key=coordinator_key,
            used_at=operation_binding["created_at"],
        )
        _require_workspace_patch_operation_binding(operation, patch)
        root = workspace_root.resolve(strict=True)
        patch_file = patch_path.resolve(strict=True)
        payload = patch_file.read_bytes()
        if (
            sha256_digest(payload) != patch["patch"]["digest"]
            or len(payload) != patch["patch"]["byte_count"]
            or _patch_paths(payload) != patch["patch"]["allowed_paths"]
        ):
            raise WorkspacePatchError("workspace patch artifact mismatch")
        for executable in (git_executable, bwrap_executable):
            if not executable.resolve(strict=True).is_file():
                raise WorkspacePatchError("workspace patch executor unavailable")
        self.manifest = manifest
        self.conformance = conformance
        self.proposal = deepcopy(dict(proposal))
        self.binding = binding
        self.operation = operation
        self.patch = patch
        self.coordinator_key = coordinator_key
        self.executor_id = executor_id
        self.executor_artifact_digest = executor_artifact_digest
        self.signer = signer
        self.root = root
        if patch_file.is_relative_to(root):
            raise WorkspacePatchError("workspace patch artifact must be outside target")
        self._patch_payload = payload
        self.git_executable = git_executable.resolve(strict=True)
        self.bwrap_executable = bwrap_executable.resolve(strict=True)
        self._used: set[str] = set()

    def execute(
        self,
        envelope: Mapping[str, Any],
        *,
        dispatch_permit: AdapterDispatchPermit,
        recorded_at: str,
    ) -> dict[str, Any]:
        candidate = _verify_envelope_signature(
            envelope,
            coordinator_key=self.coordinator_key,
        )
        if candidate["manifest"] != {
            "manifest_id": self.manifest["manifest_id"],
            "manifest_digest": adapter_capability_manifest_digest(self.manifest),
            "adapter_id": self.manifest["adapter_id"],
            "adapter_artifact_digest": self.manifest["adapter_artifact_digest"],
        } or candidate["operation_binding"] != {
            "binding_id": self.binding["binding_id"],
            "binding_digest": adapter_operation_binding_digest(self.binding),
            "conformance_receipt_id": self.binding["conformance"]["receipt_id"],
            "conformance_receipt_digest": self.binding["conformance"]["receipt_digest"],
            "conformance_readiness": self.binding["conformance"]["readiness"],
            "operation_kind": self.binding["operation"]["kind"],
            "operation_manifest_id": self.binding["operation"]["manifest_id"],
            "operation_manifest_digest": self.binding["operation"]["manifest_digest"],
            "executor_id": self.binding["executor"]["executor_id"],
            "executor_artifact_digest": self.binding["executor"]["executor_artifact_digest"],
            "executor_key_id": self.binding["executor"]["key_id"],
        }:
            raise WorkspacePatchError("workspace patch envelope mismatch")
        if candidate["envelope_id"] in self._used:
            raise WorkspacePatchError("workspace patch replay rejected")
        payload = bytes(self._patch_payload)
        if (
            sha256_digest(payload) != self.patch["patch"]["digest"]
            or len(payload) != self.patch["patch"]["byte_count"]
            or _patch_paths(payload) != self.patch["patch"]["allowed_paths"]
        ):
            raise WorkspacePatchError("workspace patch admitted payload changed")
        patch_fd = _sealed_patch_fd(payload)
        try:
            dispatch_permit.consume(envelope=candidate)
            self._used.add(candidate["envelope_id"])
            before = observe_workspace(self.root, git_executable=self.git_executable)
            target = self.patch["target"]
            if (
                before["clean"] is not True
                or before["repository_id"] != target["repository_id"]
                or before["worktree_id"] != target["worktree_id"]
                or before["environment_digest"] != target["environment_digest"]
                or before["head_oid"] != target["base_head_oid"]
                or before["tree_oid"] != target["base_tree_oid"]
            ):
                receipt = _build_execution_receipt(
                    envelope=candidate,
                    target_operation=self.operation,
                    patch_manifest=self.patch,
                    executor_id=self.executor_id,
                    executor_artifact_digest=self.executor_artifact_digest,
                    before=before,
                    after=before,
                    reported_outcome=AdapterReportedOutcome.REPORTED_FAILURE,
                    reason_code="precondition-mismatch",
                    recorded_at=recorded_at,
                    signer=self.signer,
                )
            else:
                result = _bwrap_apply(
                    root=self.root,
                    patch_fd=patch_fd,
                    git_executable=self.git_executable,
                    bwrap_executable=self.bwrap_executable,
                )
                after = observe_workspace(self.root, git_executable=self.git_executable)
                observed = after["changed_paths"]
                expected_tree = target["expected_tree_oid"]
                success = (
                    result.returncode == 0
                    and observed == self.patch["patch"]["allowed_paths"]
                    and after["tree_oid"] == expected_tree
                    and after["head_oid"] == before["head_oid"]
                )
                receipt = _build_execution_receipt(
                    envelope=candidate,
                    target_operation=self.operation,
                    patch_manifest=self.patch,
                    executor_id=self.executor_id,
                    executor_artifact_digest=self.executor_artifact_digest,
                    before=before,
                    after=after,
                    reported_outcome=(
                        AdapterReportedOutcome.REPORTED_SUCCESS
                        if success
                        else AdapterReportedOutcome.REPORTED_FAILURE
                    ),
                    reason_code=(
                        "expected-tree-observed"
                        if success
                        else "apply-failed"
                        if result.returncode != 0
                        else "postcondition-mismatch"
                    ),
                    recorded_at=recorded_at,
                    signer=self.signer,
                )
        finally:
            os.close(patch_fd)
        verified = verify_workspace_patch_execution_receipt(
            receipt,
            executor_key=TrustedKey(self.signer.key_id, self.signer.public_key),
            envelope=candidate,
            target_operation=self.operation,
            patch_manifest=self.patch,
            executor_id=self.executor_id,
            executor_artifact_digest=self.executor_artifact_digest,
        )
        return build_adapter_execution_report(
            envelope=candidate,
            coordinator_key=self.coordinator_key,
            adapter_id=self.manifest["adapter_id"],
            adapter_artifact_digest=self.manifest["adapter_artifact_digest"],
            executor_id=self.executor_id,
            executor_artifact_digest=self.executor_artifact_digest,
            operation_binding=self.binding,
            conformance_receipt=self.conformance,
            operation_evidence_reference={
                "schema_id": "workspace-patch-execution-receipt/v1",
                "receipt_id": verified["receipt_id"],
                "receipt_digest": workspace_patch_execution_receipt_digest(verified),
            },
            evidence_artifact_count=1,
            reported_outcome=verified["result"]["reported_outcome"],
            recorded_at=recorded_at,
            signer=self.signer,
        )


def build_workspace_patch_witness(
    *,
    target_operation: Mapping[str, Any],
    operation_key: TrustedKey,
    capability_manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    patch_manifest: Mapping[str, Any],
    patch_key: TrustedKey,
    workspace_root: Path,
    observer_id: str,
    observer_artifact_digest: str,
    observed_at: str,
    signer: Ed25519Signer,
    git_executable: Path = Path("/usr/bin/git"),
) -> dict[str, Any]:
    operation = verify_adapter_target_operation(
        target_operation,
        manifest=capability_manifest,
        adapter_key=adapter_key,
        operation_key=operation_key,
    )
    patch = verify_workspace_patch_manifest(
        patch_manifest,
        capability_manifest=capability_manifest,
        adapter_key=adapter_key,
        patch_key=patch_key,
    )
    _require_workspace_patch_operation_binding(operation, patch)
    observed = observe_workspace(workspace_root, git_executable=git_executable)
    allowed = patch["patch"]["allowed_paths"]
    outside = sorted(set(observed["changed_paths"]) - set(allowed))
    if outside:
        raise WorkspacePatchError("workspace patch witness observed expanded blast radius")
    core = {
        "protocol": "integrity-guardian/workspace-patch-witness/v1",
        "sdk_version": ADAPTER_SDK_VERSION,
        "operation": {
            "target_operation_id": operation["operation_id"],
            "target_operation_digest": adapter_target_operation_digest(operation),
            "patch_id": patch["patch_id"],
            "patch_manifest_digest": workspace_patch_manifest_digest(patch),
        },
        "observer": {
            "observer_id": observer_id,
            "observer_artifact_digest": observer_artifact_digest,
            "key_id": signer.key_id,
        },
        "observed": {
            "repository_id": observed["repository_id"],
            "worktree_id": observed["worktree_id"],
            "environment_digest": observed["environment_digest"],
            "head_oid": observed["head_oid"],
            "tree_oid": observed["tree_oid"],
            "state_digest": observed["state_digest"],
        },
        "blast_radius": {
            "allowed_paths_digest": patch["patch"]["allowed_paths_digest"],
            "observed_paths_digest": observed["changed_paths_digest"],
            "observed_path_count": len(observed["changed_paths"]),
            "outside_allowed_count": 0,
        },
        "result": {
            "expected_tree_observed": observed["tree_oid"] == patch["target"]["expected_tree_oid"],
            "blast_radius_clean": not outside and observed["changed_paths"] == allowed,
            "executor_claim_trusted": False,
            "external_causality_proven": False,
        },
        "observed_at": observed_at,
        "signer_id": signer.key_id,
    }
    unsigned = {
        "witness_id": _identity(
            core,
            field="witness_id",
            prefix="workspace-patch-witness:",
            domain="workspace-patch-witness-identity-v1",
        ),
        **core,
    }
    signed = signer.sign(unsigned)
    validate("workspace-patch-witness", signed)
    return signed


def verify_workspace_patch_witness(
    witness: Mapping[str, Any],
    *,
    target_operation: Mapping[str, Any],
    operation_key: TrustedKey,
    capability_manifest: Mapping[str, Any],
    adapter_key: TrustedKey,
    patch_manifest: Mapping[str, Any],
    patch_key: TrustedKey,
    observer_key: TrustedKey,
) -> dict[str, Any]:
    operation = verify_adapter_target_operation(
        target_operation,
        manifest=capability_manifest,
        adapter_key=adapter_key,
        operation_key=operation_key,
    )
    patch = verify_workspace_patch_manifest(
        patch_manifest,
        capability_manifest=capability_manifest,
        adapter_key=adapter_key,
        patch_key=patch_key,
    )
    _require_workspace_patch_operation_binding(operation, patch)
    candidate = _verify_signed(
        witness,
        schema="workspace-patch-witness",
        field="witness_id",
        prefix="workspace-patch-witness:",
        domain="workspace-patch-witness-identity-v1",
        trusted_key=observer_key,
    )
    allowed_paths_digest = patch["patch"]["allowed_paths_digest"]
    expected_state_digest = digest_object(
        {
            "repository_id": patch["target"]["repository_id"],
            "worktree_id": patch["target"]["worktree_id"],
            "environment_digest": patch["target"]["environment_digest"],
            "head_oid": patch["target"]["base_head_oid"],
            "tree_oid": patch["target"]["expected_tree_oid"],
            "changed_paths_digest": allowed_paths_digest,
        },
        domain="workspace-patch-state-v1",
    )
    if (
        candidate["operation"]
        != {
            "target_operation_id": operation["operation_id"],
            "target_operation_digest": adapter_target_operation_digest(operation),
            "patch_id": patch["patch_id"],
            "patch_manifest_digest": workspace_patch_manifest_digest(patch),
        }
        or candidate["observed"]
        != {
            "repository_id": patch["target"]["repository_id"],
            "worktree_id": patch["target"]["worktree_id"],
            "environment_digest": patch["target"]["environment_digest"],
            "head_oid": patch["target"]["base_head_oid"],
            "tree_oid": patch["target"]["expected_tree_oid"],
            "state_digest": expected_state_digest,
        }
        or candidate["blast_radius"]
        != {
            "allowed_paths_digest": allowed_paths_digest,
            "observed_paths_digest": allowed_paths_digest,
            "observed_path_count": len(patch["patch"]["allowed_paths"]),
            "outside_allowed_count": 0,
        }
    ):
        raise WorkspacePatchError("workspace patch witness context mismatch")
    if candidate["result"] != {
        "expected_tree_observed": True,
        "blast_radius_clean": True,
        "executor_claim_trusted": False,
        "external_causality_proven": False,
    }:
        raise WorkspacePatchError("workspace patch witness did not confirm transition")
    return candidate


__all__ = [
    "WorkspacePatchAdapter",
    "WorkspacePatchError",
    "build_workspace_patch_manifest",
    "build_workspace_patch_witness",
    "observe_workspace",
    "verify_workspace_patch_execution_receipt",
    "verify_workspace_patch_manifest",
    "verify_workspace_patch_witness",
    "workspace_patch_execution_receipt_digest",
    "workspace_patch_manifest_digest",
    "workspace_patch_schema_digest",
    "workspace_patch_witness_digest",
]
