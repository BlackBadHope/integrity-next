# SPDX-License-Identifier: Apache-2.0
"""Optional project labels. No authority, database, namespace or state relocation."""

from __future__ import annotations

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config

import hashlib
import json
import ntpath
import os
import posixpath
import re
import socket
import stat
import tempfile
from pathlib import Path, PureWindowsPath
from typing import Any

SCHEMA = "integrity.project-scopes.v1"
METADATA_SCHEMA = "integrity.project-scope.v1"
MAX_CONFIG_BYTES = 256 * 1024
MAX_RULES = 1000
AREAS = {"HOME", "PROD", "UNCLASSIFIED"}
_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_HASH_RE = re.compile(r"^[a-f0-9]{64}$")
_TAG_RE = re.compile(r"\[(HOME|PROD)\]", re.IGNORECASE)


class ProjectScopeError(ValueError):
    """An explicit configuration operation was invalid or ambiguous."""


def host_identity(value: str | None = None) -> str:
    host = (value or os.environ.get("INTEGRITY_SEED_HOST_ID") or socket.gethostname()).lower()
    if not _HOST_RE.fullmatch(host):
        raise ProjectScopeError("host id must be a bounded explicit host name")
    return host


def config_path() -> Path:
    explicit = os.environ.get("INTEGRITY_PROJECT_SCOPES")
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_absolute():
            raise ProjectScopeError("INTEGRITY_PROJECT_SCOPES must be absolute")
        return path
    codex = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")).expanduser()
    return codex.absolute() / "integrity-seed" / "project-scopes.json"


def normalized_path(value: str | Path, *, resolve: bool = False) -> str:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ProjectScopeError("project path must be absolute")
    if os.name == "nt":
        text = str(path)
        if text.startswith(("\\\\?\\", "\\\\.\\")):
            raise ProjectScopeError("Windows device paths are ambiguous")
        if any(part.endswith((" ", ".")) or ":" in part for part in path.parts[1:]):
            raise ProjectScopeError("Windows path component is ambiguous")
    if resolve:
        path = path.resolve(strict=True)
        if not path.is_dir():
            raise ProjectScopeError("project path must be an existing directory")
        if os.name == "nt":
            _reject_windows_case_sensitive_tree(path)
    return os.path.normcase(os.path.normpath(str(path)))


def _reject_windows_case_sensitive_tree(path: Path) -> None:
    # Case-sensitive NTFS directories cannot safely use Windows normcase rules.
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    get_info = kernel.GetFileInformationByHandleEx
    get_info.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    get_info.restype = wintypes.BOOL
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    for directory in (path, *path.parents):
        handle = create(str(directory), 0, 7, None, 3, 0x02000000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ProjectScopeError("Windows path case semantics could not be inspected")
        try:
            flags = wintypes.DWORD()
            if get_info(handle, 23, ctypes.byref(flags), ctypes.sizeof(flags)):
                if flags.value & 1:
                    raise ProjectScopeError("case-sensitive Windows project paths are unsupported")
            elif ctypes.get_last_error() not in {1, 50, 87}:  # unsupported filesystem/API
                raise ProjectScopeError("Windows path case semantics could not be inspected")
        finally:
            close(handle)


def contains(root: str, candidate: str) -> bool:
    path_module = ntpath if PureWindowsPath(root).is_absolute() else posixpath
    try:
        return path_module.commonpath((root, candidate)) == root
    except ValueError:
        return False


def project_id(host: str, root: str) -> str:
    return hashlib.sha256(f"{host}\0{root}".encode()).hexdigest()


def _stored_normalized_path(value: str) -> str:
    """Validate foreign-host entries without resolving paths on this host."""
    if not isinstance(value, str) or len(value) > 4096:
        raise ProjectScopeError("stored project path is invalid")
    if PureWindowsPath(value).is_absolute():
        parts = PureWindowsPath(value).parts[1:]
        if value.startswith(("\\\\?\\", "\\\\.\\")) or any(
            part.endswith((" ", ".")) or ":" in part for part in parts
        ):
            raise ProjectScopeError("stored Windows project path is ambiguous")
        return ntpath.normcase(ntpath.normpath(value))
    if value.startswith("/") and not value.startswith("//"):
        return posixpath.normpath(value)
    raise ProjectScopeError("stored project path must have an explicit absolute root")


def canonical_workspace_root(cwd: str | Path) -> Path:
    """The launcher's existing nearest-.git/cwd identity, also used at append."""
    candidate = Path(cwd).expanduser().resolve(strict=True)
    if not candidate.is_dir():
        candidate = candidate.parent
    for directory in (candidate, *candidate.parents):
        marker = directory / ".git"
        try:
            info = marker.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            continue
        if stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode):
            return directory
    return candidate


def _check_config_path(path: Path) -> None:
    if not path.is_absolute():
        raise ProjectScopeError("configuration path must be absolute")
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ProjectScopeError("configuration path cannot contain links or reparse points")
        if part == path and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
            raise ProjectScopeError("configuration must be a single regular file")


def load_config(path: Path) -> dict[str, Any]:
    _check_config_path(path)
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
    except FileNotFoundError:
        return {"schema": SCHEMA, "rules": []}
    if len(raw) > MAX_CONFIG_BYTES:
        raise ProjectScopeError("project configuration exceeds its byte budget")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ProjectScopeError("project configuration is not valid JSON") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "rules"}
        or value["schema"] != SCHEMA
    ):
        raise ProjectScopeError("project configuration schema is invalid")
    rules = value["rules"]
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise ProjectScopeError("project configuration rule budget is invalid")
    seen = set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {
            "host_id",
            "project_root",
            "workspace_id",
            "area",
        }:
            raise ProjectScopeError("project rule fields are invalid")
        if (
            not isinstance(rule["host_id"], str)
            or host_identity(rule["host_id"]) != rule["host_id"]
            or not isinstance(rule["project_root"], str)
            or _stored_normalized_path(rule["project_root"]) != rule["project_root"]
            or not isinstance(rule["workspace_id"], str)
            or not _HASH_RE.fullmatch(rule["workspace_id"])
            or rule["area"] not in {"HOME", "PROD"}
        ):
            raise ProjectScopeError("project rule identity or area is invalid")
        key = (rule["host_id"], rule["project_root"])
        if key in seen:
            raise ProjectScopeError("duplicate project rules are ambiguous")
        seen.add(key)
    return value


def configure(
    path: Path, *, host: str, root: str, workspace_id: str, area: str | None, replace: bool = False
) -> dict[str, Any]:
    """Set/reset one exact rule; never initialize Seed or change permissions."""
    if (
        host_identity(host) != host
        or normalized_path(root) != root
        or not _HASH_RE.fullmatch(workspace_id)
        or area not in {None, "HOME", "PROD"}
    ):
        raise ProjectScopeError("project rule identity or area is invalid")
    _check_config_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _check_config_path(path)
    lock = path.with_name(path.name + ".lock")
    try:
        lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise ProjectScopeError("configuration is busy; inspect the lock before retrying") from exc
    try:
        os.close(lock_fd)
        config = load_config(path)
        key = (host, root)
        old = next((r for r in config["rules"] if (r["host_id"], r["project_root"]) == key), None)
        rule = {"host_id": host, "project_root": root, "workspace_id": workspace_id, "area": area}
        if old and area is not None and old != rule and not replace:
            raise ProjectScopeError(
                "existing mapping differs; inspect it and use --replace explicitly"
            )
        rules = [r for r in config["rules"] if (r["host_id"], r["project_root"]) != key]
        if area is not None:
            rules.append(rule)
        if len(rules) > MAX_RULES:
            raise ProjectScopeError("project configuration rule budget exceeded")
        config["rules"] = sorted(rules, key=lambda r: (r["host_id"], r["project_root"]))
        data = (json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        if len(data) > MAX_CONFIG_BYTES:
            raise ProjectScopeError("project configuration exceeds its byte budget")
        fd, temporary = tempfile.mkstemp(prefix=".project-scopes-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            _check_config_path(path)
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return config
    finally:
        lock.unlink(missing_ok=True)


def classify(
    cwd: str | Path,
    workspace_root: str | Path,
    workspace_id: str,
    *,
    path: Path | None = None,
    host: str | None = None,
) -> dict[str, Any]:
    """Explain an optional label; malformed/absent settings never block tasks."""
    result: dict[str, Any] = {
        "schema": METADATA_SCHEMA,
        "area": "UNCLASSIFIED",
        "status": "unconfigured",
        "warnings": [],
    }
    try:
        host = host_identity(host)
        current = normalized_path(cwd or workspace_root, resolve=True)
        # Per-write cwd matters when an explicitly shared state directory serves
        # multiple projects. Its workspace_id remains the existing store identity.
        workspace = normalized_path(canonical_workspace_root(current), resolve=True)
        result.update(
            host_id=host,
            workspace_id=workspace_id,
            project_root=workspace,
            project_id=project_id(host, workspace),
        )
        hints = sorted(set(_TAG_RE.findall(str(cwd).upper())))
        result["folder_hints"] = hints
        target = path if path is not None else config_path()
        existed = target.exists()
        config = load_config(target)
        if not existed:
            if hints:
                result["warnings"].append("folder hint only; no explicit mapping")
            return result
        result["status"] = "unmatched"
        matches = [
            r
            for r in config["rules"]
            if r["host_id"] == host and contains(r["project_root"], current)
        ]
        if matches:
            rule = max(matches, key=lambda r: len(Path(r["project_root"]).parts))
            project = (
                workspace
                if contains(rule["project_root"], workspace) and (Path(workspace) / ".git").exists()
                else rule["project_root"]
            )
            result.update(
                area=rule["area"],
                status="configured",
                project_root=project,
                project_id=project_id(host, project),
                configured_root=rule["project_root"],
                configured_workspace_id=rule["workspace_id"],
            )
            if workspace_id != rule["workspace_id"]:
                result["warnings"].append(
                    "configured workspace id differs from current Seed store; no state relocation"
                )
            if hints and hints != [rule["area"]]:
                result["warnings"].append(
                    "folder hint conflicts with explicit setting; setting wins"
                )
        elif hints:
            result["warnings"].append("folder hint only; no explicit mapping")
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        result.update(
            area="UNCLASSIFIED",
            status="invalid",
            warnings=["project configuration or path is unavailable/ambiguous"],
        )
    return result


def matches(
    metadata: Any,
    *,
    area: str | None = None,
    host: str | None = None,
    project: str | None = None,
    include_legacy: bool = False,
) -> bool:
    if area is None and host is None and project is None:
        return True
    if not isinstance(metadata, dict) or metadata.get("schema") != METADATA_SCHEMA:
        return include_legacy or (area == "UNCLASSIFIED" and host is None and project is None)
    return (
        (area is None or metadata.get("area") == area)
        and (host is None or metadata.get("host_id") == host)
        and (project is None or metadata.get("project_id") == project)
    )


MAX_METADATA_BYTES = 8192


def validated_metadata(value: Any) -> dict[str, Any]:
    """Validate frozen metadata without consulting this receiver's filesystem."""
    fields = {
        "schema", "area", "status", "warnings", "host_id", "workspace_id",
        "project_root", "project_id", "folder_hints", "configured_root",
        "configured_workspace_id",
    }
    if not isinstance(value, dict) or set(value) - fields:
        raise ProjectScopeError("project metadata fields are invalid")
    if (value.get("schema") != METADATA_SCHEMA
            or not isinstance(value.get("area"), str)
            or not isinstance(value.get("status"), str)
            or value.get("area") not in {"HOME", "PROD", "UNCLASSIFIED"}
            or value.get("status") not in {"configured", "unconfigured", "unmatched", "invalid"}):
        raise ProjectScopeError("project metadata classification is invalid")
    if (value["area"] in {"HOME", "PROD"}) != (value["status"] == "configured"):
        raise ProjectScopeError("project metadata classification is inconsistent")
    for key in ("warnings", "folder_hints"):
        items = value.get(key, [])
        if (not isinstance(items, list) or len(items) > 8
                or any(not isinstance(item, str) or len(item) > 256 for item in items)):
            raise ProjectScopeError("project metadata explanation exceeds its bound")
    if any(item not in {"HOME", "PROD"} for item in value.get("folder_hints", [])):
        raise ProjectScopeError("project metadata folder hints are invalid")
    identity_fields = {"host_id", "workspace_id", "project_root", "project_id"}
    if value["status"] != "invalid" or identity_fields & set(value):
        if not identity_fields <= set(value):
            raise ProjectScopeError("project metadata identity is incomplete")
        if not isinstance(value["host_id"], str) or not value["host_id"]:
            raise ProjectScopeError("project metadata host is invalid")
        host = host_identity(value["host_id"])
        if host != value["host_id"]:
            raise ProjectScopeError("project metadata host is not canonical")
        root = _stored_normalized_path(value["project_root"])
        if root != value["project_root"] or value["project_id"] != project_id(host, root):
            raise ProjectScopeError("project metadata identity digest is invalid")
        if not isinstance(value["workspace_id"], str) or not re.fullmatch(
            r"[a-f0-9]{64}", value["workspace_id"]
        ):
            raise ProjectScopeError("project metadata workspace identity is invalid")
    if value["status"] == "configured":
        configured_root = _stored_normalized_path(value.get("configured_root"))
        if (configured_root != value["configured_root"]
                or not contains(configured_root, value["project_root"])):
            raise ProjectScopeError("project metadata configured root is inconsistent")
        if not isinstance(value.get("configured_workspace_id"), str) or not re.fullmatch(
            r"[a-f0-9]{64}", value["configured_workspace_id"]
        ):
            raise ProjectScopeError("project metadata configured workspace identity is invalid")
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_METADATA_BYTES:
        raise ProjectScopeError("project metadata exceeds its byte bound")
    return json.loads(encoded)


def owning_hook_scope(payload: Any) -> dict[str, Any] | None:
    """Optional classification from the native owning hook's cwd, never MCP input."""
    try:
        target = config_path()
        if not target.exists():
            return None
        cwd = payload.get("cwd") if isinstance(payload, dict) else None
        if not isinstance(cwd, str) or not Path(cwd).is_absolute():
            return validated_metadata({
                "schema": METADATA_SCHEMA, "area": "UNCLASSIFIED", "status": "invalid",
                "warnings": ["owning hook cwd is unavailable; project is unclassified"],
            })
        root = canonical_workspace_root(cwd)
        override = os.environ.get("INTEGRITY_SEED_HOME", "").strip()
        identity = normalized_path(override, resolve=False) if override else os.path.normcase(str(root))
        material = "override\0" + identity if override else identity
        workspace_id = hashlib.sha256(material.encode("utf-8")).hexdigest()
        return validated_metadata(classify(cwd, root, workspace_id, path=target))
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        # Optional metadata must never turn a valid LLM task into a failed hook.
        return None


def event_metadata(details: Any) -> dict[str, Any] | None:
    """Canonical records use the reserved server marker; ignore caller labels."""
    if not isinstance(details, dict):
        return None
    marker = details.get("_integrity_client")
    value = marker.get("project_scope") if isinstance(marker, dict) else details.get("project_scope")
    if "_integrity_client" in details and not isinstance(marker, dict):
        return None
    try:
        return validated_metadata(value)
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        return None
