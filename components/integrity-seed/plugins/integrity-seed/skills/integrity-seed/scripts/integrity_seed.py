#!/usr/bin/env python3
"""Cross-platform launcher and CLI for the Integrity Seed Codex plugin."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


PLUGIN_ROOT = Path(__file__).resolve().parents[3]
RUNTIME_SOURCE = PLUGIN_ROOT / "runtime" / "action_log.py"
PROVIDER_GUARD_SOURCE = PLUGIN_ROOT / "hooks" / "canonical-provider-guard.py"
VERSION = "0.1.3"
RUNTIME_SCHEMA = "integrity.seed.runtime.v1"
STATE_ROOT_SCHEMA = "integrity.seed.state-root.v1"
STATE_MARKER_NAME = ".integrity-seed-root.json"
STARTUP_TIMEOUT_SECONDS = 8.0
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{32,160}$")
_VERIFIED_CLOSURE_KINDS = {"handoff", "checkpoint", "completion", "blocked", "failure"}
_CLOSURE_VERIFICATION_STATES = {"verified", "synthetic-clean-room"}
_CLOSURE_RECEIPT_SCHEMA = "integrity.closure-receipt.v2"
_DEBT_BINDING_SCHEMA = "integrity.debt-binding.v1"
_CLOSURE_MAPPING = {
    "handoff": ("agent_memory_checkpoint", "handoff"),
    "checkpoint": ("agent_memory_checkpoint", "checkpoint"),
    "completion": ("agent_change_complete", "complete"),
    "blocked": ("agent_change_blocked", "blocked"),
    "failure": ("agent_change_failed", "failed"),
}
_HARDENED_WINDOWS_PATHS: set[str] = set()
_HOOK_EVENTS = (
    "SessionStart",
    "UserPromptSubmit",
    "PostToolUse",
    "PreCompact",
    "PostCompact",
    "SubagentStart",
    "SubagentStop",
    "Stop",
)
_CONTEXT_OUTPUT_HOOK_EVENTS = {
    "SessionStart",
    "UserPromptSubmit",
    "PostToolUse",
    "SubagentStart",
}
_COMMON_OUTPUT_HOOK_EVENTS = {"PreCompact", "PostCompact", "SubagentStop", "Stop"}


class RuntimeStateCorruptionError(RuntimeError):
    """A persisted runtime identity file exists but cannot be trusted."""


def _useful_verification(value: Any) -> bool:
    return str(value or "").strip().lower() in _CLOSURE_VERIFICATION_STATES


# Integrity Seed has no network backend: every launcher request must go directly
# to its loopback runtime even when the host exports HTTP(S)_PROXY.
class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


_DIRECT_OPENER = build_opener(ProxyHandler({}), _NoRedirectHandler())


def _absolute_path(value: str | os.PathLike[str]) -> Path:
    return Path(os.path.abspath(os.fspath(Path(value).expanduser())))


def canonical_provider_suppresses_local_runtime() -> bool:
    """Honor the same deployment marker for direct compatibility hooks."""
    codex_home = _absolute_path(
        os.environ.get("CODEX_HOME") or (Path.home() / ".codex")
    )
    marker = codex_home / "integrity-seed" / "canonical-provider.json"
    try:
        namespace = runpy.run_path(str(PROVIDER_GUARD_SOURCE))
        validator = namespace.get("marker_suppresses_local_runtime")
        return bool(callable(validator) and validator(marker))
    except Exception:
        return False


def _is_reparse_or_symlink(path: Path) -> bool:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = int(getattr(info, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & reparse_flag)


def _assert_no_reparse_chain(path: Path) -> None:
    target = _absolute_path(path)
    current = Path(target.anchor)
    for part in target.parts[1:]:
        current /= part
        try:
            if _is_reparse_or_symlink(current):
                raise RuntimeError(f"Integrity state path contains a symlink/reparse point: {current}")
        except FileNotFoundError:
            continue


def _windows_account_name() -> str:
    import ctypes  # imported lazily to preserve non-Windows startup

    size = ctypes.c_ulong(256)
    buffer = ctypes.create_unicode_buffer(size.value)
    if not ctypes.windll.advapi32.GetUserNameW(buffer, ctypes.byref(size)):
        raise OSError(ctypes.get_last_error(), "GetUserNameW failed")
    name = buffer.value
    domain = os.environ.get("USERDOMAIN", "").strip()
    return f"{domain}\\{name}" if domain else name


def _harden_windows_acl(path: Path, *, directory: bool, force: bool = False) -> None:
    """Harden exactly one plugin-owned path; never traverse descendants."""
    cache_key = f"{'d' if directory else 'f'}:{os.path.normcase(str(_absolute_path(path)))}"
    if not force and cache_key in _HARDENED_WINDOWS_PATHS:
        return
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    icacls = system_root / "System32" / "icacls.exe"
    if not icacls.is_file():
        raise RuntimeError("Windows ACL hardening tool is unavailable")
    account = _windows_account_name()
    suffix = "(OI)(CI)F" if directory else "F"
    commands = (
        [str(icacls), str(path), "/reset"],
        [
            str(icacls),
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"{account}:{suffix}",
            f"*S-1-5-18:{suffix}",
            f"*S-1-5-32-544:{suffix}",
        ],
    )
    for command in commands:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            timeout=10,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"failed to harden Windows ACL for {path}")
    _HARDENED_WINDOWS_PATHS.add(cache_key)


def _secure_directory(path: Path, *, harden_acl: bool = False) -> None:
    _assert_no_reparse_chain(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _assert_no_reparse_chain(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"Integrity state path is not a directory: {path}")
    if os.name == "nt":
        if harden_acl:
            _harden_windows_acl(path, directory=True)
    else:
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise RuntimeError(f"Integrity state directory is owned by another user: {path}")
        os.chmod(path, 0o700)
        if stat.S_IMODE(path.stat().st_mode) != 0o700:
            raise RuntimeError(f"Integrity state directory permissions are not private: {path}")


def _secure_existing_file(
    path: Path, *, harden_acl: bool = False, force_acl: bool = False
) -> None:
    _assert_no_reparse_chain(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"Integrity state file is not a regular file: {path}")
    if os.name == "nt" and harden_acl:
        _harden_windows_acl(path, directory=False, force=force_acl)
        _assert_no_reparse_chain(path)
        try:
            hardened_info = path.lstat()
        except FileNotFoundError as exc:
            raise RuntimeStateCorruptionError(
                "Integrity state file disappeared during Windows ACL hardening"
            ) from exc
        if (
            not stat.S_ISREG(hardened_info.st_mode)
            or int(getattr(hardened_info, "st_nlink", 1)) != 1
        ):
            raise RuntimeStateCorruptionError(
                "Integrity state file changed during Windows ACL hardening"
            )
    elif os.name != "nt":
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise RuntimeError(f"Integrity state file is owned by another user: {path}")
        os.chmod(path, 0o600)
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise RuntimeError(f"Integrity state file permissions are not private: {path}")


def canonical_workspace_root(cwd: str | os.PathLike[str] | None = None) -> Path:
    candidate = Path(cwd if cwd is not None else os.getcwd()).expanduser().resolve(strict=True)
    if not candidate.is_dir():
        candidate = candidate.parent
    for directory in (candidate, *candidate.parents):
        marker = directory / ".git"
        try:
            marker_info = marker.lstat()
        except FileNotFoundError:
            continue
        if _is_reparse_or_symlink(marker):
            continue
        if stat.S_ISDIR(marker_info.st_mode) or stat.S_ISREG(marker_info.st_mode):
            return directory
    return candidate


def _workspace_identity(cwd: str | os.PathLike[str] | None = None) -> tuple[Path, str]:
    override = os.environ.get("INTEGRITY_SEED_HOME", "").strip()
    if override:
        home = _absolute_path(override)
        normalized = os.path.normcase(str(home)) if os.name == "nt" else str(home)
        workspace_id = hashlib.sha256(f"override\0{normalized}".encode("utf-8")).hexdigest()
        return canonical_workspace_root(cwd), workspace_id
    root = canonical_workspace_root(cwd)
    normalized = os.path.normcase(str(root)) if os.name == "nt" else str(root)
    return root, hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def home_dir(workspace_cwd: str | os.PathLike[str] | None = None) -> Path:
    override = os.environ.get("INTEGRITY_SEED_HOME", "").strip()
    if override:
        return _absolute_path(override)
    _, workspace_id = _workspace_identity(workspace_cwd)
    codex_home = _absolute_path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    return codex_home / "integrity-seed" / "workspaces" / workspace_id


def _validate_explicit_home(home: Path, workspace_root: Path | None = None) -> None:
    """Reject broad or unrelated override directories before changing ACLs."""
    profile = _absolute_path(Path.home())
    codex_home = _absolute_path(os.environ.get("CODEX_HOME", profile / ".codex"))
    forbidden = {Path(home.anchor), profile, codex_home}
    if home in forbidden:
        raise RuntimeError("INTEGRITY_SEED_HOME must name a dedicated state directory")
    workspace = _absolute_path(workspace_root or canonical_workspace_root())
    normalized_home = os.path.normcase(str(_absolute_path(home)))
    normalized_workspace = os.path.normcase(str(workspace))
    try:
        nested_in_workspace = (
            os.path.commonpath((normalized_home, normalized_workspace))
            == normalized_workspace
        )
    except ValueError:
        nested_in_workspace = False
    if nested_in_workspace:
        raise RuntimeError(
            "INTEGRITY_SEED_HOME cannot equal or be nested under the canonical workspace"
        )
    if not home.exists():
        return
    _assert_no_reparse_chain(home)
    if not home.is_dir():
        raise RuntimeError("INTEGRITY_SEED_HOME is not a directory")
    allowed = {
        STATE_MARKER_NAME,
        "data",
        "runtime",
        "threads",
        "mind-state",
        "mind-locks",
    }
    unexpected = sorted(entry.name for entry in home.iterdir() if entry.name not in allowed)
    if unexpected:
        raise RuntimeError(
            "INTEGRITY_SEED_HOME must be empty or contain only Integrity Seed state"
        )


def _read_state_marker(path: Path) -> dict[str, Any]:
    _assert_no_reparse_chain(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {}
    if not stat.S_ISREG(info.st_mode) or int(getattr(info, "st_nlink", 1)) != 1:
        raise RuntimeStateCorruptionError("Integrity state marker is not a private regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeStateCorruptionError("Integrity state marker is unreadable") from exc
    if not isinstance(value, dict):
        raise RuntimeStateCorruptionError("Integrity state marker is invalid")
    return value


def paths(workspace_cwd: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    workspace_root, workspace_id = _workspace_identity(workspace_cwd)
    home = home_dir(workspace_cwd)
    override = bool(os.environ.get("INTEGRITY_SEED_HOME", "").strip())
    integrity_base = home if override else home.parent.parent
    workspaces_base = home if override else home.parent
    return {
        "home": home,
        "integrity_base": integrity_base,
        "workspaces_base": workspaces_base,
        "workspace_root": workspace_root,
        "workspace_id": workspace_id,
        "data": home / "data",
        "db": home / "data" / "action-log.sqlite3",
        "runtime": home / "runtime",
        "receipt": home / "runtime" / "runtime.json",
        "token": home / "runtime" / "token",
        "pid": home / "runtime" / "server.pid",
        "log": home / "runtime" / "server.log",
        "lock": home / "runtime" / "launch.lock",
        "threads": home / "threads",
        "marker": home / STATE_MARKER_NAME,
    }


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    _secure_directory(path.parent)
    _secure_existing_file(path)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _secure_existing_file(path, harden_acl=os.name == "nt")
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def load_json(path: Path) -> dict[str, Any]:
    _secure_existing_file(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise RuntimeStateCorruptionError(f"cannot read runtime state: {path.name}") from exc
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeStateCorruptionError(f"invalid runtime state: {path.name}") from exc
    if not isinstance(value, dict):
        raise RuntimeStateCorruptionError(f"runtime state is not an object: {path.name}")
    return value


def read_pid_evidence(path: Path) -> int | None:
    _secure_existing_file(path)
    try:
        raw = path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError) as exc:
        raise RuntimeStateCorruptionError("runtime PID evidence is unreadable") from exc
    try:
        pid = int(raw)
    except ValueError as exc:
        raise RuntimeStateCorruptionError("runtime PID evidence is invalid") from exc
    if pid <= 0:
        raise RuntimeStateCorruptionError("runtime PID evidence is invalid")
    return pid


@contextmanager
def launch_lock(lock_path: Path, timeout: float = 10.0) -> Iterator[None]:
    _secure_directory(lock_path.parent)
    _secure_existing_file(lock_path) if lock_path.exists() and lock_path.is_file() else None
    deadline = time.monotonic() + timeout
    while True:
        try:
            _assert_no_reparse_chain(lock_path)
            lock_path.mkdir(mode=0o700)
            break
        except FileExistsError:
            try:
                if _is_reparse_or_symlink(lock_path) or not lock_path.is_dir():
                    raise RuntimeError("Integrity lifecycle lock is not a private directory")
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("timed out waiting for the Integrity runtime lock")
            time.sleep(0.05)
    try:
        yield
    finally:
        try:
            lock_path.rmdir()
        except OSError:
            pass


def ensure_directories(workspace_cwd: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    result = paths(workspace_cwd)
    if os.environ.get("INTEGRITY_SEED_HOME", "").strip():
        _validate_explicit_home(result["home"], result["workspace_root"])
    marker = _read_state_marker(result["marker"])
    initialize_acl = not marker
    if result["integrity_base"] != result["home"]:
        _secure_directory(
            result["integrity_base"], harden_acl=os.name == "nt" and initialize_acl
        )
        _secure_directory(
            result["workspaces_base"], harden_acl=os.name == "nt" and initialize_acl
        )
    _secure_directory(result["home"], harden_acl=os.name == "nt" and initialize_acl)
    if marker:
        if marker != {
            "schema": STATE_ROOT_SCHEMA,
            "workspace_id": result["workspace_id"],
        }:
            raise RuntimeStateCorruptionError("Integrity state marker binding is invalid")
    else:
        atomic_json(
            result["marker"],
            {"schema": STATE_ROOT_SCHEMA, "workspace_id": result["workspace_id"]},
        )
    for key in ("data", "runtime", "threads"):
        _secure_directory(result[key], harden_acl=os.name == "nt" and initialize_acl)
    for name in ("mind-state", "mind-locks"):
        candidate = result["home"] / name
        if candidate.exists():
            _secure_directory(candidate, harden_acl=os.name == "nt" and initialize_acl)
    for key in ("db", "receipt", "token", "pid", "log"):
        _secure_existing_file(result[key])
    return result


def _read_existing_bearer_token(token_path: Path) -> str | None:
    """Read a bearer token only after current-file ACL hardening and validation."""
    _secure_existing_file(
        token_path,
        harden_acl=os.name == "nt",
        force_acl=os.name == "nt",
    )
    try:
        token_info = token_path.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(token_info.st_mode)
        or int(getattr(token_info, "st_nlink", 1)) != 1
        or int(token_info.st_size) > 512
    ):
        raise RuntimeStateCorruptionError("Integrity bearer token file is invalid")
    try:
        token = token_path.read_text(encoding="ascii").strip()
    except FileNotFoundError as exc:
        raise RuntimeStateCorruptionError(
            "Integrity bearer token disappeared before reading"
        ) from exc
    except (OSError, UnicodeError) as exc:
        raise RuntimeStateCorruptionError("Integrity bearer token is unreadable") from exc
    if not _NONCE_RE.fullmatch(token):
        raise RuntimeStateCorruptionError("Integrity bearer token is invalid")
    return token


def ensure_token(token_path: Path) -> str:
    existing = _read_existing_bearer_token(token_path)
    if existing is not None:
        return existing
    token = secrets.token_urlsafe(48)
    token_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(token_path, flags, 0o600)
    except FileExistsError:
        existing = _read_existing_bearer_token(token_path)
        if existing is None:
            raise RuntimeStateCorruptionError(
                "Integrity bearer token disappeared during creation"
            )
        return existing
    with os.fdopen(fd, "w", encoding="ascii", newline="\n") as handle:
        handle.write(token + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    if os.name != "nt":
        os.chmod(token_path, 0o600)
    _secure_existing_file(
        token_path,
        harden_acl=os.name == "nt",
        force_acl=os.name == "nt",
    )
    return token


def rotate_token(token_path: Path) -> str:
    token = secrets.token_urlsafe(48)
    _secure_directory(token_path.parent)
    _secure_existing_file(token_path)
    fd, temporary = tempfile.mkstemp(prefix=f".{token_path.name}.", dir=token_path.parent)
    try:
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as handle:
            handle.write(token + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, token_path)
        _secure_existing_file(
            token_path,
            harden_acl=os.name == "nt",
            force_acl=os.name == "nt",
        )
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return token


def request_json(
    base_url: str,
    token: str,
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    timeout: float = 3.0,
) -> dict[str, Any]:
    parsed_base = urlsplit(base_url)
    try:
        base_port = parsed_base.port
    except ValueError as exc:
        raise RuntimeError("Integrity runtime base URL has an invalid port") from exc
    if (
        parsed_base.scheme != "http"
        or parsed_base.hostname != "127.0.0.1"
        or parsed_base.username is not None
        or parsed_base.password is not None
        or base_port is None
        or not 1 <= base_port <= 65535
        or parsed_base.path not in {"", "/"}
        or parsed_base.query
        or parsed_base.fragment
    ):
        raise RuntimeError("Integrity runtime base URL must be strict IPv4 loopback")
    parsed_path = urlsplit(path)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "\\" in path
        or any(ord(character) < 0x20 for character in path)
        or parsed_path.scheme
        or parsed_path.netloc
        or parsed_path.fragment
    ):
        raise RuntimeError("Integrity runtime request path is invalid")
    authority = f"127.0.0.1:{base_port}"
    target_url = urlunsplit(("http", authority, parsed_path.path, parsed_path.query, ""))
    data = None
    headers = {"X-Codex-Log-Token": token}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    request = Request(target_url, data=data, headers=headers, method=method)
    with _DIRECT_OPENER.open(request, timeout=timeout) as response:
        if response.geturl() != target_url:
            raise RuntimeError("Integrity runtime redirect is forbidden")
        media_type = response.headers.get_content_type()
        if media_type != "application/json":
            raise RuntimeError("Integrity runtime returned a non-JSON content type")
        body = response.read(2 * 1024 * 1024 + 1)
        if len(body) > 2 * 1024 * 1024:
            raise RuntimeError("Integrity runtime response exceeds 2 MiB")
        value = json.loads(body.decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("Integrity runtime returned a non-object response")
    return value


def source_hash() -> str:
    return hashlib.sha256(RUNTIME_SOURCE.read_bytes()).hexdigest()


def _receipt_unsigned(receipt: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "schema",
        "version",
        "pid",
        "port",
        "host",
        "source_sha256",
        "workspace_id",
        "startup_nonce",
        "process_start_id",
        "python_executable",
        "started_unix",
    )
    return {key: receipt.get(key) for key in keys}


def _receipt_signature(receipt: dict[str, Any], token: str) -> str:
    canonical = json.dumps(
        _receipt_unsigned(receipt), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hmac.new(token.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def _valid_signed_receipt(receipt: dict[str, Any], token: str) -> bool:
    if (
        receipt.get("schema") != RUNTIME_SCHEMA
        or receipt.get("version") != VERSION
        or type(receipt.get("pid")) is not int
        or int(receipt["pid"]) <= 0
        or type(receipt.get("port")) is not int
        or not 1 <= int(receipt["port"]) <= 65535
        or receipt.get("host") != "127.0.0.1"
        or not isinstance(receipt.get("source_sha256"), str)
        or not _HASH_RE.fullmatch(str(receipt["source_sha256"]))
        or not isinstance(receipt.get("workspace_id"), str)
        or not _HASH_RE.fullmatch(str(receipt["workspace_id"]))
        or not isinstance(receipt.get("startup_nonce"), str)
        or not _NONCE_RE.fullmatch(str(receipt["startup_nonce"]))
        or not isinstance(receipt.get("process_start_id"), str)
        or not receipt["process_start_id"]
        or not isinstance(receipt.get("python_executable"), str)
        or not Path(str(receipt["python_executable"])).is_absolute()
        or type(receipt.get("started_unix")) is not int
        or not isinstance(receipt.get("signature"), str)
    ):
        return False
    return hmac.compare_digest(str(receipt["signature"]), _receipt_signature(receipt, token))


def runtime_health(receipt: dict[str, Any], token: str) -> dict[str, Any] | None:
    try:
        if not _valid_signed_receipt(receipt, token):
            return None
        health = request_json(
            f"http://127.0.0.1:{int(receipt['port'])}", token, "/api/health", timeout=0.8
        )
        exact = {
            "pid": receipt["pid"],
            "startup_nonce": receipt["startup_nonce"],
            "source_sha256": receipt["source_sha256"],
            "workspace_id": receipt["workspace_id"],
            "process_start_id": receipt["process_start_id"],
            "python_executable": receipt["python_executable"],
        }
        if (
            health.get("ok") is not True
            or health.get("service") != "integrity-seed"
            or health.get("service_version") != VERSION
            or health.get("token_auth") is not True
            or health.get("delete_enabled") is not False
            or any(health.get(key) != value for key, value in exact.items())
        ):
            return None
        return health
    except (OSError, ValueError, RuntimeError, HTTPError, URLError, json.JSONDecodeError):
        return None


def runtime_health_with_retries(
    receipt: dict[str, Any], token: str, *, attempts: int = 3
) -> dict[str, Any] | None:
    for attempt in range(max(1, attempts)):
        health = runtime_health(receipt, token)
        if health is not None:
            return health
        if attempt + 1 < attempts:
            time.sleep(0.1 * (attempt + 1))
    return None


def _process_start_id(pid: int) -> str | None:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class FILETIME(ctypes.Structure):
            _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetProcessTimes.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(FILETIME),
            ctypes.POINTER(FILETIME),
            ctypes.POINTER(FILETIME),
            ctypes.POINTER(FILETIME),
        ]
        kernel32.GetProcessTimes.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return None
        try:
            creation, exit_time, kernel, user = FILETIME(), FILETIME(), FILETIME(), FILETIME()
            if not kernel32.GetProcessTimes(
                handle,
                ctypes.byref(creation),
                ctypes.byref(exit_time),
                ctypes.byref(kernel),
                ctypes.byref(user),
            ):
                return None
            value = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)
            return f"win-filetime:{value}"
        finally:
            kernel32.CloseHandle(handle)
    stat_path = Path(f"/proc/{pid}/stat")
    try:
        raw = stat_path.read_text(encoding="ascii")
        tail = raw[raw.rfind(")") + 2 :].split()
        return f"linux-startticks:{tail[19]}"
    except (OSError, IndexError, ValueError):
        return None


def _process_executable(pid: int) -> str | None:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return None
        try:
            size = wintypes.DWORD(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            if not kernel32.QueryFullProcessImageNameW(
                handle, 0, buffer, ctypes.byref(size)
            ):
                return None
            return str(Path(buffer.value).resolve())
        finally:
            kernel32.CloseHandle(handle)
    try:
        return str(Path(f"/proc/{pid}/exe").resolve(strict=True))
    except OSError:
        return None


def _pid_exists(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.GetExitCodeProcess.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(wintypes.DWORD),
            ]
            kernel32.GetExitCodeProcess.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            handle = kernel32.OpenProcess(0x1000, False, pid)
            if not handle:
                return False
            try:
                exit_code = wintypes.DWORD()
                if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    return False
                return int(exit_code.value) == 259
            finally:
                kernel32.CloseHandle(handle)
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _process_matches_runtime(receipt: dict[str, Any], resolved: dict[str, Any]) -> bool:
    pid = receipt.get("pid")
    if type(pid) is not int or pid <= 0:
        return False
    try:
        _secure_existing_file(resolved["pid"])
        if resolved["pid"].read_text(encoding="ascii").strip() != str(pid):
            return False
    except OSError:
        return False
    if _process_start_id(pid) != receipt.get("process_start_id"):
        return False
    executable = _process_executable(pid)
    if executable is None or os.path.normcase(executable) != os.path.normcase(
        str(Path(str(receipt.get("python_executable", ""))).resolve())
    ):
        return False
    if os.name != "nt":
        try:
            argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            expected = os.fsencode(str(RUNTIME_SOURCE.resolve()))
            if expected not in argv:
                return False
        except OSError:
            return False
    return True


def recover_transient_runtime(
    resolved: dict[str, Any], token: str
) -> dict[str, Any] | None:
    recovered: list[tuple[Path, dict[str, Any], dict[str, Any]]] = []
    for candidate in sorted(resolved["runtime"].glob(".startup-*.json")):
        receipt = load_json(candidate)
        if (
            not _valid_signed_receipt(receipt, token)
            or receipt.get("source_sha256") != source_hash()
            or receipt.get("workspace_id") != resolved["workspace_id"]
            or not _process_matches_runtime(receipt, resolved)
        ):
            continue
        health = runtime_health_with_retries(receipt, token)
        if health is not None:
            recovered.append((candidate, receipt, health))
    if len(recovered) > 1:
        raise RuntimeError("multiple live transient Integrity runtimes were found")
    if not recovered:
        return None
    candidate, receipt, health = recovered[0]
    atomic_json(resolved["receipt"], receipt)
    candidate.unlink(missing_ok=True)
    return {"paths": resolved, "receipt": receipt, "health": health, "token": token}


def _native_terminate(pid: int) -> bool:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateProcess.restype = wintypes.BOOL
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        # PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE.
        handle = kernel32.OpenProcess(0x0001 | 0x1000 | 0x00100000, False, pid)
        if not handle:
            return False
        try:
            if not kernel32.TerminateProcess(handle, 0):
                return False
            return int(kernel32.WaitForSingleObject(handle, 5000)) == 0
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, signal.SIGTERM)
        return True
    except OSError:
        return False


def terminate_owned_runtime(receipt: dict[str, Any], token: str, resolved: dict[str, Any]) -> bool:
    health = runtime_health(receipt, token)
    if health is None:
        return False
    pid = receipt.get("pid")
    if type(pid) is not int or not _process_matches_runtime(receipt, resolved):
        return False
    return _native_terminate(pid)


def _terminate_spawned_process(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=2)
    except (OSError, subprocess.SubprocessError):
        try:
            process.kill()
            process.wait(timeout=2)
        except (OSError, subprocess.SubprocessError):
            pass


def start_runtime(resolved: dict[str, Any], token: str) -> dict[str, Any]:
    if not RUNTIME_SOURCE.is_file():
        raise RuntimeError(f"Integrity runtime is missing: {RUNTIME_SOURCE}")
    current_source_hash = source_hash()
    startup_nonce = secrets.token_urlsafe(48)
    startup_name = hashlib.sha256(startup_nonce.encode("ascii")).hexdigest()
    startup_receipt = resolved["runtime"] / f".startup-{startup_name}.json"
    _secure_existing_file(startup_receipt)
    startup_receipt.unlink(missing_ok=True)
    env = os.environ.copy()
    env.update(
        {
            "INTEGRITY_SEED_HOME": str(resolved["home"]),
            "CODEX_LOG_DATA_DIR": str(resolved["data"]),
            "CODEX_LOG_DB": str(resolved["db"]),
            "CODEX_LOG_HOST": "127.0.0.1",
            "CODEX_LOG_PORT": "0",
            "CODEX_LOG_TOKEN": token,
            "CODEX_LOG_MAX_CONCURRENT_REQUESTS": "16",
            "CODEX_LOG_PID_FILE": str(resolved["pid"]),
            "CODEX_LOG_STARTUP_RECEIPT": str(startup_receipt),
            "CODEX_LOG_STARTUP_NONCE": startup_nonce,
            "CODEX_LOG_SOURCE_SHA256": current_source_hash,
            "CODEX_LOG_WORKSPACE_ID": str(resolved["workspace_id"]),
        }
    )
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "PYTHONUSERBASE",
    ):
        env.pop(name, None)
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
            subprocess, "DETACHED_PROCESS", 0
        )
    _secure_existing_file(resolved["log"])
    log_flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        log_flags |= os.O_NOFOLLOW
    log_fd = os.open(resolved["log"], log_flags, 0o600)
    _secure_existing_file(resolved["log"], harden_acl=os.name == "nt")
    log_handle = os.fdopen(log_fd, "a", encoding="utf-8", buffering=1)
    process: subprocess.Popen[Any] | None = None
    try:
        try:
            process = subprocess.Popen(
                [sys.executable, "-I", str(RUNTIME_SOURCE)],
                cwd=str(resolved["home"]),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                shell=False,
                creationflags=creationflags,
                start_new_session=os.name != "nt",
            )
        finally:
            log_handle.close()
    except BaseException:
        if process is not None:
            _terminate_spawned_process(process)
        startup_receipt.unlink(missing_ok=True)
        rotate_token(resolved["token"])
        raise
    if process is None:
        rotate_token(resolved["token"])
        raise RuntimeError("Integrity runtime process was not created")
    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"Integrity runtime exited with code {process.returncode}")
            if startup_receipt.exists():
                try:
                    receipt = load_json(startup_receipt)
                except RuntimeStateCorruptionError:
                    time.sleep(0.05)
                    continue
                if (
                    not _valid_signed_receipt(receipt, token)
                    or receipt.get("pid") != process.pid
                    or receipt.get("startup_nonce") != startup_nonce
                    or receipt.get("source_sha256") != current_source_hash
                    or receipt.get("workspace_id") != resolved["workspace_id"]
                ):
                    raise RuntimeError("Integrity runtime published an invalid startup receipt")
                if not _process_matches_runtime(receipt, resolved):
                    raise RuntimeError("Integrity runtime startup identity did not verify")
                health = runtime_health(receipt, token)
                if health is None:
                    time.sleep(0.05)
                    continue
                atomic_json(resolved["receipt"], receipt)
                startup_receipt.unlink(missing_ok=True)
                return {"receipt": receipt, "health": health, "token": token}
            time.sleep(0.05)
        raise RuntimeError("Integrity runtime did not become healthy")
    except BaseException:
        _terminate_spawned_process(process)
        startup_receipt.unlink(missing_ok=True)
        try:
            if resolved["pid"].read_text(encoding="ascii").strip() == str(process.pid):
                resolved["pid"].unlink(missing_ok=True)
        except OSError:
            pass
        resolved["receipt"].unlink(missing_ok=True)
        rotate_token(resolved["token"])
        raise


def ensure_runtime(workspace_cwd: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    resolved = ensure_directories(workspace_cwd)
    with launch_lock(resolved["lock"]):
        token = ensure_token(resolved["token"])
        receipt = load_json(resolved["receipt"])
        if not receipt and resolved["pid"].exists():
            recovered = recover_transient_runtime(resolved, token)
            if recovered is not None:
                return recovered
        if receipt and not _valid_signed_receipt(receipt, token):
            raise RuntimeStateCorruptionError("persisted runtime receipt is not validly signed")
        health = runtime_health_with_retries(receipt, token) if receipt else None
        identity_matches = bool(receipt and _process_matches_runtime(receipt, resolved))
        current_identity = bool(
            identity_matches
            and receipt.get("source_sha256") == source_hash()
            and receipt.get("workspace_id") == resolved["workspace_id"]
        )
        if (
            health is not None
            and health.get("service_version") == VERSION
            and current_identity
        ):
            return {"paths": resolved, "receipt": receipt, "health": health, "token": token}
        if current_identity and type(receipt.get("pid")) is int and _pid_exists(receipt["pid"]):
            raise RuntimeError(
                "current Integrity runtime identity is valid but health is unavailable; refusing restart"
            )
        if health is not None:
            if not terminate_owned_runtime(receipt, token, resolved):
                raise RuntimeError("refusing to terminate a runtime with unverified process identity")
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and _pid_exists(int(receipt["pid"])):
                time.sleep(0.05)
            if _pid_exists(int(receipt["pid"])):
                raise RuntimeError("verified Integrity runtime did not stop")
        elif receipt:
            pid = receipt.get("pid")
            if type(pid) is int and _pid_exists(pid):
                if identity_matches:
                    if not _native_terminate(pid):
                        raise RuntimeError("failed to stop a signed stale Integrity runtime")
                    deadline = time.monotonic() + 5.0
                    while time.monotonic() < deadline and _pid_exists(pid):
                        time.sleep(0.05)
                    if _pid_exists(pid):
                        raise RuntimeError("signed stale Integrity runtime did not stop")
                else:
                    raise RuntimeError("refusing to replace an unverified live runtime receipt")
        elif resolved["pid"].exists():
            orphan_pid = read_pid_evidence(resolved["pid"])
            if orphan_pid is not None and _pid_exists(orphan_pid):
                raise RuntimeError(
                    "refusing to start beside a live runtime without a valid signed receipt"
                )
        pid_evidence = read_pid_evidence(resolved["pid"])
        receipt_pid = receipt.get("pid") if receipt else None
        if (
            pid_evidence is not None
            and _pid_exists(pid_evidence)
            and pid_evidence != receipt_pid
        ):
            raise RuntimeError("live runtime PID evidence does not match the signed receipt")
        resolved["receipt"].unlink(missing_ok=True)
        resolved["pid"].unlink(missing_ok=True)
        started = start_runtime(resolved, token)
        return {"paths": resolved, **started}


def hook_command(event: str) -> int:
    if canonical_provider_suppresses_local_runtime():
        return 0
    raw = sys.stdin.buffer.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise RuntimeError("hook payload exceeds 1 MiB")
    payload = json.loads(raw.decode("utf-8") or "{}")
    if not isinstance(payload, dict):
        raise RuntimeError("hook payload must be an object")
    payload_cwd = payload.get("cwd")
    if not isinstance(payload_cwd, str) or not payload_cwd.strip():
        raise RuntimeError("hook cwd must be a non-empty absolute directory")
    cwd_path = Path(payload_cwd.strip()).expanduser()
    if not cwd_path.is_absolute():
        raise RuntimeError("hook cwd must be a non-empty absolute directory")
    try:
        cwd_path = cwd_path.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("hook cwd is unavailable") from exc
    if not cwd_path.is_dir():
        raise RuntimeError("hook cwd is not a directory")
    runtime = ensure_runtime(cwd_path)
    sys.path.insert(0, str(PLUGIN_ROOT))
    from runtime import mind_hook  # noqa: PLC0415

    base_url = f"http://127.0.0.1:{runtime['receipt']['port']}"
    return int(
        mind_hook.run(
            event,
            payload,
            base_url=base_url,
            token=runtime["token"],
            home=runtime["paths"]["home"],
        )
    )


def hook_unavailable_payload(event: str) -> dict[str, Any]:
    """Return a schema-valid, non-blocking failure for each supported hook event."""
    context_message = (
        "MEMORY CONTINUITY: UNAVAILABLE. Integrity Seed could not initialize; "
        "do not claim shared context was restored."
    )
    if event in _CONTEXT_OUTPUT_HOOK_EVENTS:
        return {
            "hookSpecificOutput": {
                "hookEventName": event,
                "additionalContext": context_message,
            }
        }
    if event in _COMMON_OUTPUT_HOOK_EVENTS:
        return {
            "continue": True,
            "systemMessage": "Integrity Seed unavailable; memory continuity was not restored.",
        }
    return {}


def event_payload(args: argparse.Namespace) -> dict[str, Any]:
    tags = [part.strip() for part in (args.tags or "").split(",") if part.strip()]
    kind = str(args.kind).strip().lower()
    truth_status = str(args.truth_status).strip().lower()
    verification = str(args.verification).strip().lower()
    expected = _CLOSURE_MAPPING.get(kind)
    if expected is not None:
        action = str(args.action or expected[0]).strip().lower()
        result = str(args.result or expected[1]).strip().lower()
    else:
        action = str(args.action or "agent_change_progress").strip().lower()
        result = str(args.result or "partial").strip().lower()
    closure_actions = {mapping[0] for mapping in _CLOSURE_MAPPING.values()}
    if expected is not None and (action, result) != expected:
        raise RuntimeError("closure kind requires its exact action and result mapping")
    if action in closure_actions and expected is None:
        raise RuntimeError("closure action requires an exact closure kind and result mapping")
    details: dict[str, Any] = {
        "schema_version": 1,
        "kind": kind,
        "task_id": args.task_id,
        "truth_status": truth_status,
        "verification": verification,
        "result": result,
    }
    if (
        kind in _VERIFIED_CLOSURE_KINDS
        and truth_status == "observed"
        and _useful_verification(verification)
    ):
        details["closure_nonce"] = secrets.token_urlsafe(32)
    return {
        "actor": args.actor,
        "session_id": args.session_id,
        "action": action,
        "summary": args.summary,
        "details": details,
        "tags": [*tags, "integrity", "agent-memory"],
    }


def _current_debt_binding(
    resolved: dict[str, Any], session_id: str
) -> dict[str, Any] | None:
    """Read the current private hook challenge without exposing it to the event."""
    if not session_id:
        return None
    sys.path.insert(0, str(PLUGIN_ROOT))
    from runtime import mind_hook  # noqa: PLC0415

    with mind_hook._session_lock(resolved["home"], session_id):
        state = mind_hook._load_state(resolved["home"], session_id)
        if mind_hook._migrate_debt_state(state):
            mind_hook._save_state(resolved["home"], session_id, state)
        generation = mind_hook._strict_generation(
            state.get("debt_generation"), allow_zero=False
        )
        challenge = state.get("debt_challenge")
        challenge_id = state.get("debt_challenge_id")
        if (
            not bool(state.get("dirty"))
            or generation is None
            or not isinstance(challenge, str)
            or mind_hook._CHALLENGE_RE.fullmatch(challenge) is None
            or not isinstance(challenge_id, str)
            or not hmac.compare_digest(challenge_id, mind_hook._challenge_id(challenge))
        ):
            return None
        return {
            "debt_generation": generation,
            "debt_challenge_id": challenge_id,
            "challenge": challenge,
        }


def _closure_receipt_signature(
    unsigned: dict[str, Any], token: str, challenge: str
) -> str:
    canonical = json.dumps(
        unsigned, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hmac.new(
        token.encode("utf-8"), canonical + b"\0" + challenge.encode("ascii"), hashlib.sha256
    ).hexdigest()


def remember_command(args: argparse.Namespace) -> int:
    runtime = ensure_runtime()
    base_url = f"http://127.0.0.1:{runtime['receipt']['port']}"
    payload = event_payload(args)
    payload_details = payload["details"]
    closure_binding = None
    if (
        payload_details.get("kind") in _VERIFIED_CLOSURE_KINDS
        and payload_details.get("truth_status") == "observed"
        and _useful_verification(payload_details.get("verification"))
    ):
        closure_binding = _current_debt_binding(
            runtime["paths"], str(payload.get("session_id") or "")
        )
        if closure_binding is not None:
            payload_details.update(
                {
                    "closure_binding_schema": _DEBT_BINDING_SCHEMA,
                    "debt_generation": closure_binding["debt_generation"],
                    "debt_challenge_id": closure_binding["debt_challenge_id"],
                }
            )
    stored = request_json(
        base_url,
        runtime["token"],
        "/api/events",
        method="POST",
        payload=payload,
    )
    details = stored.get("details") if isinstance(stored.get("details"), dict) else {}
    kind = str(details.get("kind") or "").strip().lower()
    if (
        kind in _VERIFIED_CLOSURE_KINDS
        and str(details.get("truth_status") or "").strip().lower() == "observed"
        and _useful_verification(details.get("verification"))
        and isinstance(details.get("closure_nonce"), str)
        and details["closure_nonce"]
        and type(stored.get("id")) is int
        and isinstance(stored.get("created_utc"), str)
        and closure_binding is not None
        and details.get("closure_binding_schema") == _DEBT_BINDING_SCHEMA
        and type(details.get("debt_generation")) is int
        and details.get("debt_generation") == closure_binding["debt_generation"]
        and isinstance(details.get("debt_challenge_id"), str)
        and hmac.compare_digest(
            details["debt_challenge_id"], closure_binding["debt_challenge_id"]
        )
    ):
        unsigned = {
            "schema": _CLOSURE_RECEIPT_SCHEMA,
            "event_id": stored["id"],
            "created_utc": stored["created_utc"],
            "workspace_id": runtime["paths"]["workspace_id"],
            "session_id": str(stored.get("session_id") or ""),
            "session_hash": hashlib.sha256(
                str(stored.get("session_id") or "").encode("utf-8")
            ).hexdigest(),
            "action": str(stored.get("action") or ""),
            "kind": kind,
            "result": str(details.get("result") or ""),
            "truth_status": str(details.get("truth_status") or ""),
            "verification": str(details.get("verification") or ""),
            "nonce": details["closure_nonce"],
            "debt_generation": details["debt_generation"],
            "debt_challenge_id": details["debt_challenge_id"],
        }
        stored["closure_receipt"] = {
            **unsigned,
            "signature": _closure_receipt_signature(
                unsigned, runtime["token"], closure_binding["challenge"]
            ),
        }
    print(json.dumps(stored, ensure_ascii=False, separators=(",", ":")))
    return 0


def recall_command(args: argparse.Namespace) -> int:
    runtime = ensure_runtime()
    base_url = f"http://127.0.0.1:{runtime['receipt']['port']}"
    query = args.query.strip()
    session_value = args.session_id.strip() or "integrity-seed-cli"
    bootstrap = request_json(
        base_url,
        runtime["token"],
        "/api/bootstrap",
        method="POST",
        payload={
            "session_id": session_value,
            "q": query,
            "stale_after_hours": 12,
            "context_limit": max(512, min(int(args.context_limit), 6000)),
        },
    )
    continuity = bootstrap.get("continuity") if isinstance(bootstrap.get("continuity"), dict) else {}
    result = {
        "ok": bootstrap.get("ok") is True,
        "schema": bootstrap.get("schema"),
        "memory_contract_version": bootstrap.get("memory_contract_version"),
        "event_cursor": bootstrap.get("event_cursor"),
        "coverage_status": continuity.get("coverage_status"),
        "semantic_complete": continuity.get("semantic_complete"),
        "selected_source_event_ids": continuity.get("selected_source_event_ids", []),
        "delivered_event_ids": continuity.get("delivered_event_ids", []),
        "context_text": bootstrap.get("context_text", ""),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1


def stop_runtime() -> dict[str, Any]:
    resolved = paths()
    if not resolved["home"].exists():
        return {
            "ok": True,
            "was_running": False,
            "database_preserved": False,
            "home": str(resolved["home"]),
        }
    resolved = ensure_directories()
    with launch_lock(resolved["lock"]):
        receipt = load_json(resolved["receipt"])
        token = _read_existing_bearer_token(resolved["token"]) or ""
        if receipt and (not token or not _valid_signed_receipt(receipt, token)):
            raise RuntimeStateCorruptionError("persisted runtime receipt is not validly signed")
        was_running = False
        termination_verified = True
        receipt_pid = receipt.get("pid") if isinstance(receipt, dict) else None
        if receipt and type(receipt_pid) is int and _pid_exists(receipt_pid):
            if _process_matches_runtime(receipt, resolved):
                was_running = True
                termination_verified = _native_terminate(receipt_pid)
                if termination_verified:
                    deadline = time.monotonic() + 5.0
                    while time.monotonic() < deadline and _pid_exists(receipt_pid):
                        time.sleep(0.05)
            else:
                termination_verified = False
        elif not receipt:
            orphan_pid = read_pid_evidence(resolved["pid"])
            if orphan_pid is not None and _pid_exists(orphan_pid):
                termination_verified = False
        pid_evidence = read_pid_evidence(resolved["pid"])
        if (
            pid_evidence is not None
            and _pid_exists(pid_evidence)
            and pid_evidence != receipt_pid
        ):
            termination_verified = False
        stopped = bool(
            termination_verified
            and not (type(receipt_pid) is int and _pid_exists(receipt_pid))
        )
        if stopped and termination_verified:
            for name in ("receipt", "pid"):
                resolved[name].unlink(missing_ok=True)
    return {
        "ok": bool(stopped and termination_verified),
        "was_running": was_running,
        "database_preserved": resolved["db"].is_file(),
        "home": str(resolved["home"]),
    }


def status_payload(start: bool) -> dict[str, Any]:
    if start:
        runtime = ensure_runtime()
        health = runtime["health"]
        receipt = runtime["receipt"]
        resolved = runtime["paths"]
    else:
        resolved = paths()
        if os.environ.get("INTEGRITY_SEED_HOME", "").strip():
            _validate_explicit_home(resolved["home"], resolved["workspace_root"])
        if resolved["home"].exists():
            marker = _read_state_marker(resolved["marker"])
            if marker != {
                "schema": STATE_ROOT_SCHEMA,
                "workspace_id": resolved["workspace_id"],
            }:
                raise RuntimeStateCorruptionError("Integrity state marker binding is invalid")
        token = _read_existing_bearer_token(resolved["token"]) or ""
        receipt = load_json(resolved["receipt"])
        receipt_current = bool(
            receipt
            and token
            and _valid_signed_receipt(receipt, token)
            and receipt.get("source_sha256") == source_hash()
            and receipt.get("workspace_id") == resolved["workspace_id"]
            and _process_matches_runtime(receipt, resolved)
        )
        health = runtime_health_with_retries(receipt, token) if receipt_current else None
        health = health or {}
    return {
        "ok": bool(health.get("ok")),
        "version": health.get("service_version"),
        "memory_contract_version": health.get("memory_contract_version"),
        "events": health.get("events"),
        "loopback_only": receipt.get("host") == "127.0.0.1",
        "token_auth": bool(health.get("token_auth")),
        "delete_enabled": bool(health.get("delete_enabled")),
        "home": str(resolved["home"]),
        "database": str(resolved["db"]),
        "pid": receipt.get("pid"),
        "port": receipt.get("port"),
        "workspace_id": resolved["workspace_id"],
        "workspace_root": str(resolved["workspace_root"]),
    }


def _powershell_literal(value: str) -> str:
    if "\x00" in value or "\r" in value or "\n" in value:
        raise RuntimeError("Hook command path contains an invalid character")
    return "'" + value.replace("'", "''") + "'"


def _project_hook_payload() -> dict[str, Any]:
    python = Path(sys.executable).resolve(strict=True)
    launcher = Path(__file__).resolve(strict=True)
    if not python.is_file() or not launcher.is_file():
        raise RuntimeError("Integrity hook launcher is not a regular file")
    posix_prefix = f"{shlex.quote(str(python))} -I {shlex.quote(str(launcher))} hook --event"
    windows_prefix = (
        f"& {_powershell_literal(str(python))} -I {_powershell_literal(str(launcher))} "
        "hook --event"
    )
    groups: dict[str, list[dict[str, Any]]] = {}
    for event in _HOOK_EVENTS:
        matcher = "Bash|Edit|Write|MultiEdit|NotebookEdit|apply_patch" if event == "PostToolUse" else ""
        groups[event] = [
            {
                "matcher": matcher,
                "hooks": [
                    {
                        "type": "command",
                        "command": f"{posix_prefix} {event}",
                        "commandWindows": f"{windows_prefix} {event}",
                        "timeout": 30,
                    }
                ],
            }
        ]
    return {
        "description": (
            "Integrity Seed project hook layer generated from an installed, reviewed plugin."
        ),
        "hooks": groups,
    }


def _write_new_text(path: Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _read_project_text(path: Path) -> str | None:
    """Read one regular project file without following a link."""
    _assert_no_reparse_chain(path)
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode) or int(getattr(before, "st_nlink", 1)) != 1:
        raise RuntimeError(f"Project {path.name} is not a safe regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"Project {path.name} cannot be inspected safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError(f"Project {path.name} changed during inspection")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            value = handle.read(256 * 1024 + 1)
    except (OSError, UnicodeError) as exc:
        raise RuntimeError(f"Project {path.name} cannot be inspected safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(value) > 256 * 1024:
        raise RuntimeError(f"Project {path.name} exceeds the inspection limit")
    after = path.lstat()
    if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
        raise RuntimeError(f"Project {path.name} changed during inspection")
    return value


def _remove_exact_project_text(path: Path, expected: str) -> bool:
    existing = _read_project_text(path)
    if existing is None:
        return False
    if existing != expected:
        raise RuntimeError(f"Project {path.name} is not the exact Integrity compatibility file")
    path.unlink()
    return True


def install_project_hooks(
    workspace_cwd: str | os.PathLike[str] | None = None,
    *,
    force_compat: bool = False,
) -> dict[str, Any]:
    """Inspect bundled-first delivery or create an explicit fallback hook layer.

    The installed plugin already declares its lifecycle hooks. The compatibility
    layer is generated only after bundled output was absent in a fresh trusted
    task. Existing project hook/config files are never overwritten.
    """
    root = canonical_workspace_root(workspace_cwd)
    hooks_path = root / ".codex" / "hooks.json"
    payload_text = json.dumps(_project_hook_payload(), ensure_ascii=False, indent=2) + "\n"
    if not force_compat:
        existing_hooks = _read_project_text(hooks_path)
        exact_fallback_present = existing_hooks == payload_text
        unclassified_hooks_present = (
            existing_hooks is not None and not exact_fallback_present
        )
        return {
            "ok": not exact_fallback_present and not unclassified_hooks_present,
            "workspace_root": str(root),
            "hooks_status": (
                "exact-fallback-present"
                if exact_fallback_present
                else (
                    "foreign-or-legacy-present"
                    if unclassified_hooks_present
                    else "not-created-bundled-first"
                )
            ),
            "config_status": "not-created",
            "compatibility_mode": "fallback-only",
            "compatibility_layer_required": "not_established",
            "duplicate_risk": exact_fallback_present or unclassified_hooks_present,
            "hook_events": list(_HOOK_EVENTS),
            "trust_required": False,
            "restart_required": False,
            "delivery_claim": "not_asserted-by-installer",
            "delivery_claim_scope": "project-compatibility-layer",
            "next": (
                "Integrity Seed already ships bundled hooks. If an exact project fallback is "
                "present while bundled output is observed, run disable-compat-hooks before the "
                "next task. A foreign or legacy hook file requires manual review and is never "
                "removed automatically. Otherwise, if a fresh "
                "trusted task shows no bundled hook output, review the generated commands and rerun "
                "enable-hooks with --force-compat."
            ),
        }
    _assert_no_reparse_chain(root)
    codex_dir = root / ".codex"
    if codex_dir.exists():
        _assert_no_reparse_chain(codex_dir)
        if not codex_dir.is_dir():
            raise RuntimeError("Project .codex path is not a directory")
    else:
        codex_dir.mkdir(mode=0o700)
    hooks_path = codex_dir / "hooks.json"
    config_path = codex_dir / "config.toml"
    existing_hooks = _read_project_text(hooks_path)
    if existing_hooks is not None and existing_hooks != payload_text:
        raise RuntimeError("Project hooks.json already exists; Integrity Seed will not overwrite it")
    existing_config = _read_project_text(config_path)
    hooks_status = "already-present" if existing_hooks is not None else "created"
    config_status = "preserved" if existing_config is not None else "created"
    hooks_created = False
    config_created = False
    try:
        if existing_hooks is None:
            _write_new_text(hooks_path, payload_text)
            hooks_created = True
        if existing_config is None:
            _write_new_text(config_path, "[features]\nhooks = true\n")
            config_created = True
    except BaseException:
        if config_created:
            _remove_exact_project_text(config_path, "[features]\nhooks = true\n")
        if hooks_created:
            _remove_exact_project_text(hooks_path, payload_text)
        if codex_dir.exists() and not any(codex_dir.iterdir()):
            codex_dir.rmdir()
        raise
    return {
        "ok": True,
        "workspace_root": str(root),
        "hooks_path": str(hooks_path),
        "hooks_status": hooks_status,
        "config_path": str(config_path),
        "config_status": config_status,
        "compatibility_mode": "forced-fallback",
        "compatibility_layer_required": True,
        "hook_events": list(_HOOK_EVENTS),
        "trust_required": True,
        "restart_required": True,
        "delivery_claim": "not_observed",
        "delivery_claim_scope": "project-compatibility-layer-created-by-this-call",
        "next": (
            "Review and trust this project and its exact hooks in Codex, then start a new task. "
            "Windows command-hook delivery may be unavailable in the current Codex build; "
            "verify actual hook output before claiming continuity."
        ),
    }


def remove_project_hooks(
    workspace_cwd: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Remove only the exact generated fallback files after explicit request."""
    root = canonical_workspace_root(workspace_cwd)
    codex_dir = root / ".codex"
    hooks_path = codex_dir / "hooks.json"
    config_path = codex_dir / "config.toml"
    payload_text = json.dumps(_project_hook_payload(), ensure_ascii=False, indent=2) + "\n"
    existing_hooks = _read_project_text(hooks_path)
    if existing_hooks is not None and existing_hooks != payload_text:
        raise RuntimeError(
            "Project hooks.json is foreign or modified; Integrity Seed will not remove it"
        )
    hooks_removed = _remove_exact_project_text(hooks_path, payload_text)

    # Content equality cannot prove that this installer created config.toml.
    # Preserve it unconditionally; a redundant hooks feature flag is harmless.
    config_present = _read_project_text(config_path) is not None
    if codex_dir.exists() and not any(codex_dir.iterdir()):
        codex_dir.rmdir()
    return {
        "ok": True,
        "workspace_root": str(root),
        "hooks_status": "removed" if hooks_removed else "absent",
        "config_status": "preserved" if config_present else "absent",
        "duplicate_risk": False,
        "restart_required": hooks_removed,
        "next": (
            "Start a fresh Codex task and verify one bundled hook delivery per lifecycle event."
            if hooks_removed
            else "No exact Integrity compatibility hook layer was present."
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Integrity Seed workspace memory and event catalog"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    hook = sub.add_parser("hook", help=argparse.SUPPRESS)
    hook.add_argument("--event", required=True)
    setup = sub.add_parser("setup", help="Initialize or resume the local Integrity runtime")
    setup.add_argument("--json", action="store_true")
    status = sub.add_parser("status", help="Show runtime status without starting it")
    status.add_argument("--json", action="store_true")
    doctor = sub.add_parser("doctor", help="Start and verify the local security/runtime contract")
    doctor.add_argument("--json", action="store_true")
    enable_hooks = sub.add_parser(
        "enable-hooks",
        help="Inspect bundled-first hook setup or explicitly create a fallback project layer",
    )
    enable_hooks.add_argument("--json", action="store_true")
    enable_hooks.add_argument(
        "--force-compat",
        action="store_true",
        help="Create the fallback project hook layer only after bundled delivery was not observed",
    )
    disable_hooks = sub.add_parser(
        "disable-compat-hooks",
        help="Remove only an exact generated project fallback hook layer",
    )
    disable_hooks.add_argument("--json", action="store_true")
    remember = sub.add_parser("remember", help="Record one evidence-backed memory event")
    remember.add_argument("summary")
    remember.add_argument("--task-id", required=True)
    remember.add_argument(
        "--action",
        default=None,
        help="Action name; inferred from a recognized closure kind when omitted",
    )
    remember.add_argument("--kind", default="progress")
    remember.add_argument(
        "--result",
        default=None,
        help="Result name; inferred from a recognized closure kind when omitted",
    )
    remember.add_argument("--truth-status", default="reported")
    remember.add_argument("--verification", default="pending")
    remember.add_argument("--tags", default="")
    remember.add_argument("--actor", default="codex")
    remember.add_argument("--session-id", default=os.environ.get("CODEX_THREAD_ID", ""))
    recall = sub.add_parser("recall", help="Retrieve a bounded, evidence-linked memory capsule")
    recall.add_argument("query")
    recall.add_argument("--session-id", default=os.environ.get("CODEX_THREAD_ID", ""))
    recall.add_argument("--context-limit", type=int, default=1200)
    stop = sub.add_parser("stop", help="Stop the local runtime without deleting memory")
    stop.add_argument("--json", action="store_true")
    self_test = sub.add_parser("self-test", help="Run non-destructive runtime checks")
    self_test.add_argument("--json", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "hook":
            return hook_command(args.event)
        if args.command == "remember":
            return remember_command(args)
        if args.command == "recall":
            return recall_command(args)
        if args.command == "stop":
            result = stop_runtime()
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result.get("ok") else 1
        if args.command == "enable-hooks":
            result = install_project_hooks(force_compat=bool(args.force_compat))
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result.get("ok") else 1
        if args.command == "disable-compat-hooks":
            result = remove_project_hooks()
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result.get("ok") else 1
        if args.command == "status":
            result = status_payload(False)
        else:
            result = status_payload(True)
            result["checks"] = {
                "service_version": result["version"] == VERSION,
                "memory_contract_v3": result["memory_contract_version"] == 3,
                "loopback_only": result["loopback_only"] is True,
                "token_auth": result["token_auth"] is True,
                "delete_disabled": result["delete_enabled"] is False,
                "runtime_source_present": RUNTIME_SOURCE.is_file(),
            }
            result["ok"] = bool(result["ok"] and all(result["checks"].values()))
            if args.command == "setup":
                result["next"] = (
                    "Start a new Codex task so SessionStart can load bounded memory; "
                    "choose local workspace use or ask Codex to audit a compatible authenticated "
                    "server transport for multiple machines. The bundled runtime remains loopback-only."
                )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("ok") else 1
    except Exception as exc:  # noqa: BLE001 - CLI must return a concise, secret-free failure.
        if getattr(args, "command", "") == "hook":
            print(json.dumps(hook_unavailable_payload(getattr(args, "event", ""))))
            print(f"Integrity Seed hook unavailable: {type(exc).__name__}", file=sys.stderr)
            return 0
        print(json.dumps({"ok": False, "error": type(exc).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
