"""Exact local identities: executable, repository HEAD, argv, environment, custody paths.

Everything here is an explicit call; importing performs no I/O. These are bindings,
not authority: a matching digest never permits a launch by itself.
"""
from __future__ import annotations

import hashlib
import ntpath
import os
import re
import stat
from pathlib import Path

from .canonical import Rejected, bounded_int, need, sha256_bytes

MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_GIT_FILE_BYTES = 1024 * 1024
MAX_ARGV = 64
MAX_ARGUMENT_CHARS = 4096
MAX_ENVIRONMENT = 64
_SHELL_IMAGES = {"cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "sh.exe", "wsl.exe",
                 "wscript.exe", "cscript.exe", "mshta.exe", "conhost.exe", "rundll32.exe"}
_OBJECT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_REF = re.compile(r"refs/[A-Za-z0-9._/-]{1,240}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_()]{0,127}")
# Names that select API billing, another provider or carry credentials. Refused by name;
# the value is never read into a report.
_FORBIDDEN_ENV = {
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "ANTHROPIC_CUSTOM_HEADERS",
    "ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_VERTEX_BASE_URL", "ANTHROPIC_VERTEX_PROJECT_ID",
    "ANTHROPIC_FOUNDRY_API_KEY", "ANTHROPIC_FOUNDRY_BASE_URL", "ANTHROPIC_FOUNDRY_RESOURCE",
    "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_API_KEY_HELPER_TTL_MS", "CLOUD_ML_REGION",
    "GOOGLE_APPLICATION_CREDENTIALS", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NODE_OPTIONS",
}
_FORBIDDEN_ENV_PARTS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "COOKIE")
_FORBIDDEN_ENV_PREFIXES = ("AWS_", "AZURE_", "ANTHROPIC_", "CLAUDE_CODE_USE_")

# Defence in depth: the argv must equal the policy builder output exactly (parity); these
# tokens are refused anywhere even so. "allowedTools" appears only as the builder emits it.
_FORBIDDEN_TOKENS = {"--dangerously-skip-permissions", "--allow-dangerously-skip-permissions",
                     "--bare", "--continue", "-c", "--fork-session", "--from-pr", "--ide",
                     "--remote", "--teleport", "--api-key", "--chrome", "--plugin-dir",
                     "--add-dir", "--agents", "--settings", "--permission-prompt-tool",
                     "bypassPermissions", "acceptEdits"}


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    attributes = getattr(info, "st_file_attributes", 0)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def require_plain_path(path: Path, code: str) -> Path:
    """Absolute, no symlink/junction/reparse point in the path or any parent."""
    need(isinstance(path, Path) and path.is_absolute(), code + "_absolute")
    for part in (path, *path.parents):
        need(not _is_link_or_reparse(part), code + "_link")
    return path


def is_within(path: Path, root: Path) -> bool:
    left = os.path.normcase(os.path.abspath(path))
    right = os.path.normcase(os.path.abspath(root))
    return left == right or left.startswith(right.rstrip("\\/") + os.sep)


def executable_identity(path: Path) -> dict:
    """Read-only digest of a native Windows executable. No execution, no version probe."""
    require_plain_path(path, "executable")
    need(path.suffix.lower() == ".exe", "executable_native_exe_required")
    need(path.name.lower() not in _SHELL_IMAGES, "executable_shell_rejected")
    info = os.stat(path)
    need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_EXECUTABLE_BYTES, "executable_file")
    hasher, size = hashlib.sha256(), 0
    with open(path, "rb") as stream:
        head = stream.read(2)
        need(head == b"MZ", "executable_pe_header")
        hasher.update(head)
        size = len(head)
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            need(size <= MAX_EXECUTABLE_BYTES, "executable_file")
            hasher.update(chunk)
    return {"path": str(path), "sha256": "sha256:" + hasher.hexdigest(), "bytes": size}


def _read_small(path: Path) -> str:
    require_plain_path(path, "git_file")
    need(path.is_file() and path.stat().st_size <= MAX_GIT_FILE_BYTES, "git_file")
    try:
        return path.read_bytes().decode("ascii", errors="strict")
    except UnicodeError:
        raise Rejected("git_file_encoding") from None


def repository_identity(root: Path) -> dict:
    """Resolve HEAD from files only (no git subprocess). Worktrees and packed refs supported.

    Dirty working-tree state is NOT captured here; the independent observer owns that.
    """
    require_plain_path(root, "repository")
    dotgit = root / ".git"
    need(dotgit.exists(), "repository_root_required")
    if dotgit.is_file():
        line = _read_small(dotgit).strip()
        need(line.startswith("gitdir: "), "gitdir_file")
        gitdir = Path(line[8:])
        gitdir = gitdir if gitdir.is_absolute() else (root / gitdir)
    else:
        gitdir = dotgit
    gitdir = Path(os.path.abspath(gitdir))
    common = gitdir
    if (gitdir / "commondir").exists():
        value = Path(_read_small(gitdir / "commondir").strip())
        common = Path(os.path.abspath(value if value.is_absolute() else gitdir / value))
    head = _read_small(gitdir / "HEAD").strip()
    ref = None
    if head.startswith("ref: "):
        ref = head[5:]
        need(_REF.fullmatch(ref) is not None and ".." not in ref, "git_ref")
        head = None
        for base in (gitdir, common):
            candidate = base / ref
            if candidate.is_file():
                head = _read_small(candidate).strip()
                break
        if head is None and (common / "packed-refs").is_file():
            for line in _read_small(common / "packed-refs").splitlines():
                parts = line.split(" ")
                if len(parts) == 2 and parts[1] == ref:
                    head = parts[0]
                    break
        need(head is not None, "git_ref_unresolved")
    need(_OBJECT_ID.fullmatch(head) is not None, "git_head")
    return {"head": head, "ref": ref}


def environment_identity(environment: dict) -> dict:
    """Exact child environment. Credential/provider-selecting names are refused by name."""
    need(type(environment) is dict and 0 < len(environment) <= MAX_ENVIRONMENT, "environment_shape")
    folded = set()
    for name, value in environment.items():
        need(type(name) is str and _ENV_NAME.fullmatch(name) is not None, "environment_name")
        upper = name.upper()
        need(upper not in folded, "environment_duplicate_name")
        folded.add(upper)
        need(upper not in _FORBIDDEN_ENV
             and not upper.startswith(_FORBIDDEN_ENV_PREFIXES)
             and not any(part in upper for part in _FORBIDDEN_ENV_PARTS), "environment_forbidden_name")
        need(type(value) is str and "\x00" not in value and len(value) <= 32767, "environment_value")
    names = sorted(environment, key=str.upper)
    material = "\x00".join(f"{name}={environment[name]}" for name in names).encode("utf-8")
    return {"names": names, "sha256": sha256_bytes(material)}


def argv_identity(argv: list, *, expected_tail: list, prefix: int = 0) -> dict:
    """Bind argv by exact parity with the policy builder (prompt is stdin-only).

    ``prefix`` leading non-flag tokens exist only for the offline fixture profile
    (interpreter script + scenario); the production CLI profile requires prefix 0.
    """
    need(type(argv) is list and 0 < len(argv) <= MAX_ARGV, "argv_shape")
    bounded_int(prefix, 0, 4, "argv_prefix")
    for token in argv:
        # Empty values are legitimate only where the builder emits them ("--tools" "").
        need(type(token) is str and len(token) <= MAX_ARGUMENT_CHARS and "\x00" not in token,
             "argv_token")
    need(all(token and not token.startswith("-") for token in argv[:prefix]), "argv_prefix")
    need(argv[prefix:] == list(expected_tail), "argv_policy_parity")
    for token in argv:
        need(token.partition("=")[0] not in _FORBIDDEN_TOKENS, "argv_forbidden_flag")
    return {"count": len(argv), "prefix": prefix,
            "sha256": sha256_bytes("\x00".join(argv).encode("utf-8"))}


def prompt_identity(prompt: bytes, limit: int) -> dict:
    bounded_int(limit, 1, 1024 * 1024, "prompt_limit")
    need(type(prompt) is bytes and 0 < len(prompt) <= limit, "prompt_bytes")
    try:
        prompt.decode("utf-8", errors="strict")
    except UnicodeError:
        raise Rejected("prompt_utf8") from None
    return {"bytes": len(prompt), "sha256": sha256_bytes(prompt)}


def normalized_directory(path: Path) -> str:
    require_plain_path(path, "directory")
    need(path.is_dir(), "directory_missing")
    return ntpath.normcase(os.path.abspath(path)) if os.name == "nt" else os.path.abspath(path)
