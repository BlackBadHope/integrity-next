#!/usr/bin/env python3
"""Codex lifecycle adapter for the public-neutral Integrity Seed runtime.

The hook sends prompt text only in an authenticated POST body, never stores the
prompt, and treats recalled event text as untrusted evidence.  Local hook state
is bound to the full SHA-256 hash of one durable Codex session identifier.
"""

from __future__ import annotations

from contextlib import contextmanager
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


BOOTSTRAP_SCHEMA = "integrity.bootstrap.v1"
MEMORY_CONTRACT_VERSION = 3
TIMEOUT_SECONDS = 2.5
MAX_CONTEXT_CHARS = 6000
MAX_RESPONSE_BYTES = 64 * 1024
MAX_CONTINUATION_EVENT_IDS = 5

CONTEXT_EVENTS = {"SessionStart", "UserPromptSubmit", "SubagentStart"}
STOP_EVENTS = {"Stop", "SubagentStop"}

_BOOTSTRAP_MARKERS = (
    "INTEGRITY BOOTSTRAP v1",
    "CONTINUITY RECEIPT:",
    "CLAIM GATE ",
    "MEMORY TRUST BOUNDARY:",
)
_COVERAGE_STATES = {"unscoped", "no-match", "weak", "partial", "strong"}
_SCOPES = {"recent+strategic", "intent+recent+strategic"}
_LANE_FIELDS = (
    "recent_event_ids",
    "strategic_event_ids",
    "intent_event_ids",
    "task_event_ids",
    "attention_event_ids",
)

_PYTHON_BASENAME_RE = re.compile(
    r"^(?:python(?:3(?:\.\d+)?)?|py)(?:\.exe)?$", re.IGNORECASE
)
_CLOSURE_KINDS = {"handoff", "checkpoint", "completion", "blocked", "failure"}
_CLOSURE_MAPPING = {
    "handoff": ("agent_memory_checkpoint", "handoff"),
    "checkpoint": ("agent_memory_checkpoint", "checkpoint"),
    "completion": ("agent_change_complete", "complete"),
    "blocked": ("agent_change_blocked", "blocked"),
    "failure": ("agent_change_failed", "failed"),
}
_CLOSURE_RECEIPT_SCHEMA = "integrity.closure-receipt.v2"
_DEBT_BINDING_SCHEMA = "integrity.debt-binding.v1"
_CLOSURE_VERIFICATION_STATES = {"verified", "synthetic-clean-room"}
_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9_-]{32,160}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_NON_WORK_INTEGRITY_COMMANDS = {"setup", "status", "doctor", "recall", "stop", "self-test"}


class BootstrapValidationError(RuntimeError):
    """The service response did not satisfy the continuity receipt contract."""


class SessionStateCorruptionError(RuntimeError):
    """Existing per-session state is present but cannot be trusted."""


class _NoRedirect(HTTPRedirectHandler):
    """Do not forward the local bearer token through an HTTP redirect."""

    def redirect_request(  # type: ignore[override]
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


# Never let ambient HTTP(S)_PROXY settings intercept the bearer token or prompt.
# The only supported peer is the loopback runtime validated by
# ``_normalise_base_url`` below.
_OPENER = build_opener(ProxyHandler({}), _NoRedirect)


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _session_id(payload: dict[str, Any]) -> str:
    """Use only the event-bound identity; never guess from another session."""
    return str(payload.get("session_id") or payload.get("thread_id") or "").strip()


def _session_hash(session_value: str) -> str:
    if not session_value:
        raise ValueError("a durable session_id is required")
    return hashlib.sha256(session_value.encode("utf-8")).hexdigest()


def _state_path(home: str | os.PathLike[str], session_value: str) -> Path:
    return Path(home).expanduser() / "mind-state" / f"{_session_hash(session_value)}.json"


def _validate_posix_directory(path: Path, *, label: str) -> os.stat_result:
    """Reject a POSIX state directory unless it is private and owned by this process."""
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise SessionStateCorruptionError(f"{label} could not be inspected") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise SessionStateCorruptionError(f"{label} is not a real directory")
    if metadata.st_uid != os.geteuid():
        raise SessionStateCorruptionError(f"{label} is not owned by the current user")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SessionStateCorruptionError(f"{label} permissions are not exactly 0700")
    return metadata


def _private_subdirectory(
    home: str | os.PathLike[str],
    name: str,
    *,
    create: bool,
) -> Path | None:
    """Return a validated Seed-owned directory, creating it owner-only if requested."""
    home_path = Path(home).expanduser()
    child = home_path / name
    if os.name != "posix":
        if create:
            child.mkdir(parents=True, exist_ok=True)
        return child if child.exists() else None

    if create:
        try:
            home_path.mkdir(mode=0o700, parents=True, exist_ok=False)
        except FileExistsError:
            pass
        except OSError as exc:
            raise SessionStateCorruptionError("Integrity state home could not be created") from exc
    try:
        _validate_posix_directory(home_path, label="Integrity state home")
    except SessionStateCorruptionError as exc:
        if not create and isinstance(exc.__cause__, FileNotFoundError):
            return None
        raise

    if create:
        try:
            child.mkdir(mode=0o700, exist_ok=False)
        except FileExistsError:
            pass
        except OSError as exc:
            raise SessionStateCorruptionError(f"{name} could not be created") from exc
    try:
        _validate_posix_directory(child, label=name)
    except SessionStateCorruptionError as exc:
        if not create and isinstance(exc.__cause__, FileNotFoundError):
            return None
        raise
    return child


def _validate_posix_state_file(path: Path) -> os.stat_result:
    """Validate a state file before content is trusted or replaced."""
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise SessionStateCorruptionError("session state could not be inspected") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise SessionStateCorruptionError("session state is not a regular file")
    if metadata.st_uid != os.geteuid():
        raise SessionStateCorruptionError("session state is not owned by the current user")
    if metadata.st_nlink != 1:
        raise SessionStateCorruptionError("session state has an unexpected link count")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SessionStateCorruptionError("session state permissions are not exactly 0600")
    return metadata


def _read_private_state_file(path: Path) -> str:
    """Read one POSIX state file without following a replaced final-component link."""
    before = _validate_posix_state_file(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SessionStateCorruptionError("session state could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise SessionStateCorruptionError("session state changed during validation")
        if not stat.S_ISREG(opened.st_mode):
            raise SessionStateCorruptionError("opened session state is not a regular file")
        if opened.st_uid != os.geteuid() or opened.st_nlink != 1:
            raise SessionStateCorruptionError("opened session state identity is unsafe")
        if stat.S_IMODE(opened.st_mode) != 0o600:
            raise SessionStateCorruptionError("opened session state permissions are unsafe")
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            return handle.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@contextmanager
def _session_lock(
    home: str | os.PathLike[str],
    session_value: str,
    *,
    timeout: float = 5.0,
) -> Any:
    """Serialize only short state-file transactions for one parent session."""
    root = _private_subdirectory(home, "mind-locks", create=True)
    assert root is not None
    lock_path = root / f"{_session_hash(session_value)}.lock"
    deadline = time.monotonic() + timeout
    lock_identity: tuple[int, int] | None = None
    while True:
        try:
            lock_path.mkdir(mode=0o700)
            if os.name == "posix":
                metadata = _validate_posix_directory(lock_path, label="session lock")
                lock_identity = (metadata.st_dev, metadata.st_ino)
            break
        except FileExistsError:
            try:
                metadata = (
                    _validate_posix_directory(lock_path, label="session lock")
                    if os.name == "posix"
                    else lock_path.stat()
                )
                if time.time() - metadata.st_mtime > 30:
                    lock_path.rmdir()
                    continue
            except SessionStateCorruptionError:
                raise
            except OSError as exc:
                raise SessionStateCorruptionError("session lock could not be inspected") from exc
            if time.monotonic() >= deadline:
                raise TimeoutError("timed out waiting for Integrity session-state lock")
            time.sleep(0.01)
    try:
        yield
    finally:
        try:
            if os.name == "posix":
                metadata = _validate_posix_directory(lock_path, label="session lock")
                if lock_identity != (metadata.st_dev, metadata.st_ino):
                    raise SessionStateCorruptionError("session lock identity changed")
            lock_path.rmdir()
        except OSError:
            pass


def _load_state(home: str | os.PathLike[str], session_value: str) -> dict[str, Any]:
    expected_hash = _session_hash(session_value)
    root = _private_subdirectory(home, "mind-state", create=False)
    if root is None:
        return {}
    path = root / f"{expected_hash}.json"
    try:
        raw = (
            _read_private_state_file(path)
            if os.name == "posix"
            else path.read_text(encoding="utf-8")
        )
    except SessionStateCorruptionError as exc:
        if isinstance(exc.__cause__, FileNotFoundError):
            return {}
        raise
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise SessionStateCorruptionError("session state could not be read") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SessionStateCorruptionError("session state JSON is corrupt") from exc
    if not isinstance(payload, dict):
        raise SessionStateCorruptionError("session state must be an object")
    if payload.get("session_hash") != expected_hash:
        raise SessionStateCorruptionError("session state belongs to a different session")
    return payload


def _save_state(
    home: str | os.PathLike[str],
    session_value: str,
    state: dict[str, Any],
) -> None:
    root = _private_subdirectory(home, "mind-state", create=True)
    assert root is not None
    path = root / f"{_session_hash(session_value)}.json"
    if os.name == "posix":
        try:
            _validate_posix_state_file(path)
        except SessionStateCorruptionError as exc:
            if not isinstance(exc.__cause__, FileNotFoundError):
                raise
    state["session_hash"] = _session_hash(session_value)
    state["updated_utc"] = _utc_now()
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=root)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        if os.name == "posix":
            _validate_posix_state_file(Path(temporary))
        else:
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
        os.replace(temporary, path)
        if os.name == "posix":
            _validate_posix_state_file(path)
        else:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _strict_generation(value: Any, *, allow_zero: bool = True) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    minimum = 0 if allow_zero else 1
    return value if value >= minimum else None


def _challenge_id(challenge: str) -> str:
    return hashlib.sha256(challenge.encode("ascii")).hexdigest()


def _new_debt_challenge() -> tuple[str, str]:
    challenge = secrets.token_urlsafe(32)
    return challenge, _challenge_id(challenge)


def _migrate_debt_state(state: dict[str, Any]) -> bool:
    """Lazily add a private generation/challenge binding to legacy state."""
    changed = False
    generation = _strict_generation(state.get("debt_generation"))
    if not bool(state.get("dirty")):
        if generation is None:
            state["debt_generation"] = 0
            changed = True
        for field in ("debt_challenge", "debt_challenge_id"):
            if field in state:
                state.pop(field, None)
                changed = True
        return changed

    challenge = state.get("debt_challenge")
    challenge_id = state.get("debt_challenge_id")
    challenge_valid = bool(
        isinstance(challenge, str)
        and _CHALLENGE_RE.fullmatch(challenge)
        and isinstance(challenge_id, str)
        and hmac.compare_digest(challenge_id, _challenge_id(challenge))
    )
    if generation is None or generation < 1 or not challenge_valid:
        count = _strict_generation(state.get("meaningful_tool_count")) or 0
        state["debt_generation"] = max(1, generation or 0, count)
        challenge, challenge_id = _new_debt_challenge()
        state["debt_challenge"] = challenge
        state["debt_challenge_id"] = challenge_id
        changed = True
    return changed


def _read_migrated_state(
    home: str | os.PathLike[str], session_value: str
) -> dict[str, Any]:
    with _session_lock(home, session_value):
        state = _load_state(home, session_value)
        if _migrate_debt_state(state):
            _save_state(home, session_value, state)
        return state


def _workspace_id(home: str | os.PathLike[str]) -> str:
    marker = Path(home).expanduser() / ".integrity-seed-root.json"
    try:
        raw = (
            _read_private_state_file(marker)
            if os.name == "posix"
            else marker.read_text(encoding="utf-8")
        )
        payload = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SessionStateCorruptionError("workspace marker is unavailable") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != "integrity.seed.state-root.v1"
        or not isinstance(payload.get("workspace_id"), str)
        or _HASH_RE.fullmatch(payload["workspace_id"]) is None
    ):
        raise SessionStateCorruptionError("workspace marker binding is invalid")
    return payload["workspace_id"]


def _prompt_text(payload: dict[str, Any]) -> str:
    for key in ("prompt", "user_prompt", "userPrompt", "message", "input"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            # This value is sent only in the POST body and is never persisted.
            return value[:4000]
    return ""


def _js_ws(source: str, index: int) -> int:
    while index < len(source) and source[index] in " \t\r\n":
        index += 1
    return index


def _js_string(source: str, index: int) -> tuple[str, int]:
    if index >= len(source) or source[index] not in {"'", '"'}:
        raise ValueError("a literal JavaScript string is required")
    quote = source[index]
    index += 1
    value: list[str] = []
    escapes = {
        "\\": "\\",
        "/": "/",
        "'": "'",
        '"': '"',
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "b": "\b",
        "f": "\f",
    }
    while index < len(source):
        character = source[index]
        index += 1
        if character == quote:
            return "".join(value), index
        if character == "\\":
            if index >= len(source):
                raise ValueError("unsupported JavaScript string escape")
            escape = source[index]
            index += 1
            if escape == "u":
                digits = source[index : index + 4]
                if len(digits) != 4 or re.fullmatch(r"[0-9A-Fa-f]{4}", digits) is None:
                    raise ValueError("invalid JavaScript Unicode escape")
                code_unit = int(digits, 16)
                index += 4
                if 0xD800 <= code_unit <= 0xDBFF:
                    if not source.startswith("\\u", index):
                        raise ValueError("unpaired JavaScript Unicode surrogate")
                    low_digits = source[index + 2 : index + 6]
                    if (
                        len(low_digits) != 4
                        or re.fullmatch(r"[0-9A-Fa-f]{4}", low_digits) is None
                    ):
                        raise ValueError("invalid JavaScript Unicode escape")
                    low = int(low_digits, 16)
                    if not 0xDC00 <= low <= 0xDFFF:
                        raise ValueError("unpaired JavaScript Unicode surrogate")
                    code_unit = 0x10000 + ((code_unit - 0xD800) << 10) + (low - 0xDC00)
                    index += 6
                elif 0xDC00 <= code_unit <= 0xDFFF:
                    raise ValueError("unpaired JavaScript Unicode surrogate")
                decoded = chr(code_unit)
                if ord(decoded) < 0x20:
                    raise ValueError("control character in JavaScript string")
                value.append(decoded)
                continue
            if escape not in escapes:
                raise ValueError("unsupported JavaScript string escape")
            decoded = escapes[escape]
            if ord(decoded) < 0x20:
                raise ValueError("control character in JavaScript string")
            value.append(decoded)
            continue
        code_point = ord(character)
        if code_point < 0x20:
            raise ValueError("control character in JavaScript string")
        if 0xD800 <= code_point <= 0xDFFF:
            raise ValueError("unpaired JavaScript Unicode surrogate")
        value.append(character)
    raise ValueError("unterminated JavaScript string")


def _js_string_array(source: str, index: int) -> tuple[list[str], int]:
    """Parse one bounded array containing only literal JavaScript strings."""
    if index >= len(source) or source[index] != "[":
        raise ValueError("a literal JavaScript string array is required")
    index = _js_ws(source, index + 1)
    values: list[str] = []
    if index < len(source) and source[index] == "]":
        return values, index + 1
    while index < len(source):
        if len(values) >= 32:
            raise ValueError("JavaScript string array is too large")
        value, index = _js_string(source, index)
        values.append(value)
        index = _js_ws(source, index)
        if index < len(source) and source[index] == "]":
            return values, index + 1
        if index >= len(source) or source[index] != ",":
            raise ValueError("invalid JavaScript string array")
        index = _js_ws(source, index + 1)
        if index >= len(source) or source[index] == "]":
            raise ValueError("trailing comma in JavaScript string array")
    raise ValueError("unterminated JavaScript string array")


def _extract_code_mode_exec_command(source: str) -> str | None:
    """Parse one exact code-mode exec wrapper without evaluating JavaScript."""
    if not isinstance(source, str) or len(source) > 64 * 1024:
        return None
    index = _js_ws(source, 0)
    if not source.startswith("const", index):
        return None
    index += len("const")
    spaced = _js_ws(source, index)
    if spaced == index or not source.startswith("r", spaced):
        return None
    index = _js_ws(source, spaced + 1)
    if not source.startswith("=", index):
        return None
    index = _js_ws(source, index + 1)
    if not source.startswith("await", index):
        return None
    index += len("await")
    spaced = _js_ws(source, index)
    if spaced == index or not source.startswith("tools.exec_command", spaced):
        return None
    index = _js_ws(source, spaced + len("tools.exec_command"))
    if index >= len(source) or source[index] != "(":
        return None
    index = _js_ws(source, index + 1)
    if index >= len(source) or source[index] != "{":
        return None
    index = _js_ws(source, index + 1)

    fields: dict[str, Any] = {}
    allowed = {
        "cmd",
        "command",
        "workdir",
        "yield_time_ms",
        "max_output_tokens",
        "sandbox_permissions",
        "justification",
        "prefix_rule",
    }
    try:
        while index < len(source) and source[index] != "}":
            if source[index] in {"'", '"'}:
                key, index = _js_string(source, index)
            else:
                match = re.match(r"[A-Za-z_$][A-Za-z0-9_$-]*", source[index:])
                if match is None:
                    return None
                key = match.group(0)
                index += len(key)
            if key not in allowed or key in fields:
                return None
            index = _js_ws(source, index)
            if index >= len(source) or source[index] != ":":
                return None
            index = _js_ws(source, index + 1)
            if key == "prefix_rule":
                value, index = _js_string_array(source, index)
            elif key in {
                "cmd",
                "command",
                "workdir",
                "sandbox_permissions",
                "justification",
            }:
                value, index = _js_string(source, index)
            else:
                match = re.match(r"[0-9]+", source[index:])
                if match is None:
                    return None
                literal = match.group(0)
                index += len(literal)
                value = int(literal)
            fields[key] = value
            index = _js_ws(source, index)
            if index < len(source) and source[index] == ",":
                index = _js_ws(source, index + 1)
                if index >= len(source) or source[index] == "}":
                    return None
                continue
            break
    except ValueError:
        return None
    if index >= len(source) or source[index] != "}":
        return None
    index = _js_ws(source, index + 1)
    if index >= len(source) or source[index] != ")":
        return None
    index = _js_ws(source, index + 1)
    if index < len(source) and source[index] == ";":
        index = _js_ws(source, index + 1)
    if not source.startswith("text", index):
        return None
    index = _js_ws(source, index + len("text"))
    if index >= len(source) or source[index] != "(":
        return None
    index = _js_ws(source, index + 1)
    if not source.startswith("r.output", index):
        return None
    index = _js_ws(source, index + len("r.output"))
    if index >= len(source) or source[index] != ")":
        return None
    index = _js_ws(source, index + 1)
    if index < len(source) and source[index] == ";":
        index = _js_ws(source, index + 1)
    if index != len(source):
        return None

    command_fields = [name for name in ("cmd", "command") if name in fields]
    if len(command_fields) != 1:
        return None
    command = fields[command_fields[0]]
    if not isinstance(command, str) or not command or len(command) > 32 * 1024:
        return None
    workdir = fields.get("workdir")
    if workdir is not None and (
        not isinstance(workdir, str)
        or not workdir
        or "\x00" in workdir
        or "\r" in workdir
        or "\n" in workdir
        or not Path(workdir).is_absolute()
    ):
        return None
    if "yield_time_ms" in fields and not 0 <= fields["yield_time_ms"] <= 60_000:
        return None
    if "max_output_tokens" in fields and not 1 <= fields["max_output_tokens"] <= 1_000_000:
        return None
    permission = fields.get("sandbox_permissions")
    if permission is not None and permission not in {"use_default", "require_escalated"}:
        return None
    justification = fields.get("justification")
    if justification is not None and (
        not justification
        or len(justification) > 2000
        or any(ord(character) < 0x20 for character in justification)
        or permission != "require_escalated"
    ):
        return None
    prefix_rule = fields.get("prefix_rule")
    if prefix_rule is not None and (
        permission != "require_escalated"
        or not isinstance(prefix_rule, list)
        or not prefix_rule
        or any(
            not isinstance(part, str) or not part or len(part) > 4096
            for part in prefix_rule
        )
    ):
        return None
    return command


def _tool_command(payload: dict[str, Any]) -> str:
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, str):
        return tool_input
    if isinstance(tool_input, dict):
        candidates: list[str] = []
        for key in ("command", "cmd", "code", "patch", "input"):
            value = tool_input.get(key)
            if isinstance(value, str):
                candidates.append(value)
        if len(candidates) == 1:
            return candidates[0]
    return ""


def _direct_command_words(command: str) -> list[str] | None:
    """Tokenize one direct shell invocation without evaluating shell syntax.

    Only documented Bash backslash-newline and PowerShell backtick-newline
    continuations are folded.  Any other command separator, redirection,
    newline, or command substitution makes the command ineligible to clear
    lifecycle debt.
    """
    if not isinstance(command, str) or not command.strip():
        return None
    command = re.sub(r"(?:\\|`)\r?\n[ \t]*", " ", command)
    if "\r" in command or "\n" in command or "$(" in command or "`" in command:
        return None

    words: list[str] = []
    current: list[str] = []
    quote = ""
    for character in command:
        if quote:
            if character == quote:
                quote = ""
            else:
                current.append(character)
            continue
        if character in {"'", '"'}:
            quote = character
        elif character in " \t":
            if current:
                words.append("".join(current))
                current = []
        elif character in ";&|<>":
            if character == "&" and not words and not current:
                words.append(character)
            else:
                return None
        else:
            current.append(character)
    if quote:
        return None
    if current:
        words.append("".join(current))
    return words


def _direct_integrity_subcommand(command: str) -> str:
    """Return the subcommand for one direct Integrity launcher invocation."""
    extracted = _extract_code_mode_exec_command(command)
    if extracted is not None:
        command = extracted
    words = _direct_command_words(command)
    if not words:
        return ""
    if words[0] == "&":
        words = words[1:]
    if len(words) < 3:
        return ""

    interpreter_name = words[0].replace("\\", "/").rsplit("/", 1)[-1]
    if _PYTHON_BASENAME_RE.fullmatch(interpreter_name) is None:
        return ""
    supplied_interpreter_path = Path(words[0]).expanduser()
    if not supplied_interpreter_path.is_absolute():
        return ""
    try:
        supplied_interpreter = supplied_interpreter_path.resolve(strict=True)
        trusted_interpreter = Path(sys.executable).resolve(strict=True)
    except (OSError, RuntimeError):
        return ""
    if os.path.normcase(str(supplied_interpreter)) != os.path.normcase(
        str(trusted_interpreter)
    ):
        return ""

    index = 1
    if interpreter_name.lower().removesuffix(".exe") == "py":
        if index < len(words) and re.fullmatch(r"-3(?:\.\d+)?", words[index]):
            index += 1
    isolated = False
    while index < len(words):
        option = words[index]
        if option == "-I":
            isolated = True
            index += 1
            continue
        if option == "-B":
            index += 1
            continue
        if option in {"-Xutf8", "-Xutf8=1"}:
            index += 1
            continue
        if option == "-X" and index + 1 < len(words) and words[index + 1] in {
            "utf8",
            "utf8=1",
        }:
            index += 2
            continue
        break
    if not isolated:
        return ""
    if index + 1 >= len(words):
        return ""
    supplied_launcher_path = Path(words[index]).expanduser()
    if not supplied_launcher_path.is_absolute():
        return ""
    try:
        supplied_launcher = supplied_launcher_path.resolve(strict=True)
        trusted_launcher = (
            Path(__file__).resolve().parents[1]
            / "skills"
            / "integrity-seed"
            / "scripts"
            / "integrity_seed.py"
        ).resolve(strict=True)
    except (OSError, RuntimeError):
        return ""
    supplied_value = os.path.normcase(str(supplied_launcher))
    trusted_value = os.path.normcase(str(trusted_launcher))
    if supplied_value != trusted_value:
        return ""
    return words[index + 1]


def _is_direct_remember_command(command: str) -> bool:
    """Recognize exactly interpreter -> Integrity launcher -> ``remember``."""
    return _direct_integrity_subcommand(command) == "remember"


def _is_direct_non_work_integrity_command(command: str) -> bool:
    """Exclude only exact launcher diagnostics from workspace-side-effect debt."""
    return _direct_integrity_subcommand(command) in _NON_WORK_INTEGRITY_COMMANDS


def _useful_verification(value: Any) -> bool:
    return str(value or "").strip().lower() in _CLOSURE_VERIFICATION_STATES


def _iter_json_objects(value: Any) -> Any:
    """Yield bounded JSON objects from the structured or model-facing tool result."""
    if isinstance(value, dict):
        yield value
        for nested in value.values():
            yield from _iter_json_objects(nested)
        return
    if isinstance(value, list):
        for nested in value:
            yield from _iter_json_objects(nested)
        return
    if not isinstance(value, str) or len(value) > 128 * 1024:
        return
    candidates = [value.strip(), *(line.strip() for line in value.splitlines())]
    seen: set[str] = set()
    for candidate in candidates:
        if (
            candidate in seen
            or not candidate.startswith("{")
            or not candidate.endswith("}")
            or len(candidate) > 64 * 1024
        ):
            continue
        seen.add(candidate)
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            yield parsed


def _receipt_unsigned(receipt: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "schema",
        "event_id",
        "created_utc",
        "workspace_id",
        "session_id",
        "session_hash",
        "action",
        "kind",
        "result",
        "truth_status",
        "verification",
        "nonce",
        "debt_generation",
        "debt_challenge_id",
    )
    return {field: receipt.get(field) for field in fields}


def _receipt_signature(receipt: dict[str, Any], token: str, challenge: str) -> str:
    canonical = json.dumps(
        _receipt_unsigned(receipt),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(
        token.encode("utf-8"), canonical + b"\0" + challenge.encode("ascii"), hashlib.sha256
    ).hexdigest()


def _receipt_digest(receipt: dict[str, Any]) -> str:
    canonical = json.dumps(
        receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _parse_receipt_time(value: Any) -> dt.datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("closure receipt timestamp is missing")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("closure receipt timestamp has no timezone")
    return parsed.astimezone(dt.UTC)


def _verified_closure_receipt(
    payload: dict[str, Any],
    token: str,
    session_value: str,
    state: dict[str, Any],
    workspace_id: str,
) -> dict[str, Any] | None:
    """Accept only a fresh, HMAC-bound receipt emitted by a direct remember call.

    The receipt proves that the event was durably accepted by this local store;
    its actor, verification and outcome fields remain self-reported evidence.
    """
    if str(payload.get("tool_name") or "") != "Bash":
        return None
    command = _tool_command(payload)
    if not _is_direct_remember_command(command):
        return None
    candidates: list[dict[str, Any]] = []
    for item in _iter_json_objects(payload.get("tool_response")):
        receipt = item.get("closure_receipt")
        if isinstance(receipt, dict):
            candidates.append(receipt)
    if len(candidates) != 1:
        return None
    receipt = candidates[0]
    if set(receipt) != {*_receipt_unsigned(receipt), "signature"}:
        return None
    event_id = receipt.get("event_id")
    if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id <= 0:
        return None
    if receipt.get("schema") != _CLOSURE_RECEIPT_SCHEMA:
        return None
    if receipt.get("workspace_id") != workspace_id:
        return None
    if receipt.get("session_id") != session_value:
        return None
    if receipt.get("session_hash") != _session_hash(session_value):
        return None
    if receipt.get("kind") not in _CLOSURE_KINDS:
        return None
    if (receipt.get("action"), receipt.get("result")) != _CLOSURE_MAPPING[receipt["kind"]]:
        return None
    if receipt.get("truth_status") != "observed" or not _useful_verification(
        receipt.get("verification")
    ):
        return None
    if not isinstance(receipt.get("action"), str) or not receipt["action"]:
        return None
    if not isinstance(receipt.get("result"), str) or not receipt["result"]:
        return None
    if not isinstance(receipt.get("nonce"), str) or _CHALLENGE_RE.fullmatch(receipt["nonce"]) is None:
        return None
    signature = receipt.get("signature")
    if not isinstance(signature, str) or _HASH_RE.fullmatch(signature) is None:
        return None
    last_event_id = int(state.get("last_closure_event_id") or 0)
    if event_id <= last_event_id:
        prior_signature = str(state.get("last_closure_receipt_signature") or "")
        prior_digest = str(state.get("last_closure_receipt_sha256") or "")
        if (
            event_id == last_event_id
            and prior_signature
            and prior_digest
            and hmac.compare_digest(signature, prior_signature)
            and hmac.compare_digest(_receipt_digest(receipt), prior_digest)
        ):
            return {**receipt, "_duplicate": True}
        return None
    generation = _strict_generation(receipt.get("debt_generation"), allow_zero=False)
    current_generation = _strict_generation(state.get("debt_generation"), allow_zero=False)
    challenge = state.get("debt_challenge")
    challenge_id = state.get("debt_challenge_id")
    if (
        not bool(state.get("dirty"))
        or generation is None
        or current_generation is None
        or generation != current_generation
        or not isinstance(challenge, str)
        or _CHALLENGE_RE.fullmatch(challenge) is None
        or not isinstance(challenge_id, str)
        or _HASH_RE.fullmatch(challenge_id) is None
        or not hmac.compare_digest(challenge_id, _challenge_id(challenge))
        or not hmac.compare_digest(str(receipt.get("debt_challenge_id") or ""), challenge_id)
    ):
        return None
    if not hmac.compare_digest(signature, _receipt_signature(receipt, token, challenge)):
        return None
    try:
        created = _parse_receipt_time(receipt.get("created_utc"))
        now = dt.datetime.now(dt.UTC)
        last_meaningful = _parse_receipt_time(state.get("last_meaningful_utc"))
    except (TypeError, ValueError):
        return None
    if created <= last_meaningful or created > now + dt.timedelta(minutes=5):
        return None
    return receipt


def _is_meaningful_tool(payload: dict[str, Any]) -> bool:
    tool_name = str(payload.get("tool_name") or "").strip().lower()
    if tool_name in {"bash", "shell_command"} and _is_direct_non_work_integrity_command(
        _tool_command(payload)
    ):
        return False
    if tool_name in {
        "bash",
        "shell_command",
        "apply_patch",
        "edit",
        "write",
        "multiedit",
        "notebookedit",
    }:
        return True
    return False


def _normalise_base_url(base_url: str) -> str:
    candidate = str(base_url or "").strip().rstrip("/")
    parsed = urlsplit(candidate)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("Integrity Seed requires a loopback-only HTTP base_url")
    # Accessing port also validates its numeric range.
    _ = parsed.port
    return candidate


def _headers(token: str) -> dict[str, str]:
    value = str(token or "")
    if not value or "\r" in value or "\n" in value:
        raise ValueError("a valid local Integrity token is required")
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Codex-Log-Token": value,
    }


def _post_json(
    base_url: str,
    path: str,
    body: dict[str, Any],
    token: str,
    *,
    timeout: float,
    expected_status: set[int],
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> Any:
    request = Request(
        f"{_normalise_base_url(base_url)}{path}",
        data=json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        headers=_headers(token),
        method="POST",
    )
    with _OPENER.open(request, timeout=timeout) as response:
        status = int(response.getcode())
        if status not in expected_status:
            raise RuntimeError(f"Integrity service returned HTTP {status}")
        raw = response.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise RuntimeError("Integrity service response exceeded the bounded limit")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Integrity service returned invalid JSON") from exc


def _overload_retry_delay(session_value: str) -> float:
    bucket = hashlib.sha256(session_value.encode("utf-8")).digest()[0]
    return 0.150 + (bucket / 255.0) * 0.200


def _positive_event_ids(value: Any, name: str) -> list[int]:
    if not isinstance(value, list):
        raise BootstrapValidationError(f"{name} must be an array")
    result: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0 or item in result:
            raise BootstrapValidationError(
                f"{name} must contain unique positive integer event IDs"
            )
        result.append(item)
    return result


def _strict_nonnegative_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BootstrapValidationError(f"{name} must be a non-negative integer")
    return value


def _rendered_evidence_event_ids(context: str) -> list[int]:
    """Derive the receipt only from complete, explicitly rendered evidence lines."""
    result: list[int] = []
    for line in context.splitlines():
        match = re.match(
            r"^(?:RECENT|STRATEGIC|STRATEGIC\+|INTENT MEMORY): #(\d+)\b.*\sdata=\S",
            line,
        ) or re.match(r"^(?:PRIMARY|ATTENTION): source=#(\d+)\b\sdata=\S", line)
        if match:
            event_id = int(match.group(1))
            if event_id > 0 and event_id not in result:
                result.append(event_id)
    return result


def _stable_lane_union(lanes: dict[str, list[int]]) -> list[int]:
    result: list[int] = []
    for name in ("recent", "strategic", "intent", "task", "attention"):
        for event_id in lanes[name]:
            if event_id not in result:
                result.append(event_id)
    return result


def _validate_changed_receipt(
    payload: dict[str, Any],
    *,
    continuation_event_ids: list[int],
    continuation_intent_fingerprint: str,
    continuation_primary_task_id: str,
) -> dict[str, Any]:
    for name in ("counts", "ledger_hygiene", "attention", "primary_task", "continuity"):
        if name not in payload:
            raise BootstrapValidationError(f"bootstrap omitted {name}")

    continuity = payload["continuity"]
    if not isinstance(continuity, dict):
        raise BootstrapValidationError("continuity must be an object")
    for name in (
        "scope",
        "coverage_status",
        "semantic_complete",
        "continuation_mode",
        "continuation_intent_fingerprint",
        "selected_source_event_ids",
        "delivered_event_ids",
        "source_event_ids",
        *_LANE_FIELDS,
    ):
        if name not in continuity:
            raise BootstrapValidationError(f"continuity omitted {name}")
    if continuity["semantic_complete"] is not False:
        raise BootstrapValidationError("semantic_complete must remain false")
    if continuity["coverage_status"] not in _COVERAGE_STATES:
        raise BootstrapValidationError("coverage_status is invalid")
    if continuity["scope"] not in _SCOPES:
        raise BootstrapValidationError("continuity scope is invalid")

    selected = _positive_event_ids(
        continuity["selected_source_event_ids"], "selected_source_event_ids"
    )
    delivered = _positive_event_ids(continuity["delivered_event_ids"], "delivered_event_ids")
    source = _positive_event_ids(continuity["source_event_ids"], "source_event_ids")
    lanes = {
        "recent": _positive_event_ids(continuity["recent_event_ids"], "recent_event_ids"),
        "strategic": _positive_event_ids(
            continuity["strategic_event_ids"], "strategic_event_ids"
        ),
        "intent": _positive_event_ids(continuity["intent_event_ids"], "intent_event_ids"),
        "task": _positive_event_ids(continuity["task_event_ids"], "task_event_ids"),
        "attention": _positive_event_ids(
            continuity["attention_event_ids"], "attention_event_ids"
        ),
    }
    if selected != _stable_lane_union(lanes):
        raise BootstrapValidationError("selected IDs do not equal the stable continuity lane union")
    if any(event_id not in selected for event_id in delivered):
        raise BootstrapValidationError("delivered evidence is outside the selected set")
    if delivered != source:
        raise BootstrapValidationError("source_event_ids is not the delivered compatibility alias")

    context = payload["context_text"]
    lines = context.splitlines()
    if len(lines) < len(_BOOTSTRAP_MARKERS) or any(
        not lines[index].startswith(marker)
        for index, marker in enumerate(_BOOTSTRAP_MARKERS)
    ):
        raise BootstrapValidationError("visible continuity or trust boundary is missing")
    evidence = _rendered_evidence_event_ids("\n".join(lines[len(_BOOTSTRAP_MARKERS) :]))
    if evidence != delivered:
        raise BootstrapValidationError(
            "delivered_event_ids do not exactly equal rendered evidence event IDs"
        )

    continuation_requested = bool(continuation_event_ids)
    if continuation_requested:
        if continuity["continuation_mode"] != "exact-event-ids":
            raise BootstrapValidationError("exact continuation mode was not honored")
        if continuity["continuation_intent_fingerprint"] != continuation_intent_fingerprint:
            raise BootstrapValidationError("continuation fingerprint changed")
        if set(lanes["intent"]) != set(continuation_event_ids):
            raise BootstrapValidationError("exact continuation events were not rehydrated")
        if continuation_primary_task_id:
            primary = payload["primary_task"]
            returned_task_id = (
                str(primary.get("task_id") or "") if isinstance(primary, dict) else ""
            )
            if returned_task_id != continuation_primary_task_id:
                raise BootstrapValidationError("continuation primary task changed")
    else:
        expected_mode = "fresh-intent" if continuity["scope"].startswith("intent+") else "unscoped"
        if continuity["continuation_mode"] != expected_mode:
            raise BootstrapValidationError("fresh bootstrap continuation mode is invalid")
        if continuity["continuation_intent_fingerprint"] not in {"", None}:
            raise BootstrapValidationError("fresh bootstrap carried a continuation fingerprint")

    return {
        "coverage_status": str(continuity["coverage_status"]),
        "scope": str(continuity["scope"]),
        "selected_event_ids": selected,
        "delivered_event_ids": delivered,
        "evidence_event_ids": evidence,
        "lane_event_ids": lanes,
        "semantic_complete": False,
    }


def _validate_bootstrap(
    payload: Any,
    *,
    session_value: str,
    query: str,
    previous_hash: str,
    previous_event_cursor: int,
    previous_intent_fingerprint: str,
    continuation_event_ids: list[int],
    continuation_intent_fingerprint: str,
    continuation_primary_task_id: str,
) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise BootstrapValidationError("bootstrap response is not an ok object")
    for name in (
        "schema",
        "memory_contract_version",
        "event_cursor",
        "capsule_hash",
        "intent_fingerprint",
        "changed",
        "delta",
        "session_id",
        "context_text",
    ):
        if name not in payload:
            raise BootstrapValidationError(f"bootstrap omitted {name}")
    if payload["schema"] != BOOTSTRAP_SCHEMA:
        raise BootstrapValidationError("bootstrap schema is unsupported")
    contract_version = _strict_nonnegative_int(
        payload["memory_contract_version"], "memory_contract_version"
    )
    if contract_version < MEMORY_CONTRACT_VERSION:
        raise BootstrapValidationError("memory contract is older than v3")
    event_cursor = _strict_nonnegative_int(payload["event_cursor"], "event_cursor")
    capsule_hash = payload["capsule_hash"]
    if not isinstance(capsule_hash, str) or re.fullmatch(r"[a-f0-9]{64}", capsule_hash) is None:
        raise BootstrapValidationError("capsule_hash is invalid")
    if payload["session_id"] != session_value:
        raise BootstrapValidationError("bootstrap is bound to a different session")
    if not isinstance(payload["context_text"], str):
        raise BootstrapValidationError("context_text must be a string")
    if not isinstance(payload["changed"], bool):
        raise BootstrapValidationError("changed must be a boolean")

    expected_fingerprint = (
        continuation_intent_fingerprint
        if continuation_event_ids
        else hashlib.sha256(query.strip().encode("utf-8")).hexdigest()[:16]
    )
    if payload["intent_fingerprint"] != expected_fingerprint:
        raise BootstrapValidationError("bootstrap is bound to a different intent")

    if payload["changed"]:
        if payload["delta"] != "full":
            raise BootstrapValidationError("changed bootstrap must carry a full delta")
        receipt = _validate_changed_receipt(
            payload,
            continuation_event_ids=continuation_event_ids,
            continuation_intent_fingerprint=continuation_intent_fingerprint,
            continuation_primary_task_id=continuation_primary_task_id,
        )
    else:
        if payload["delta"] != "unchanged":
            raise BootstrapValidationError("unchanged bootstrap delta is invalid")
        if not previous_hash or previous_event_cursor < 0 or not previous_intent_fingerprint:
            raise BootstrapValidationError("unchanged bootstrap has no caller-bound prior receipt")
        if capsule_hash != previous_hash:
            raise BootstrapValidationError("unchanged capsule_hash changed")
        if event_cursor != previous_event_cursor:
            raise BootstrapValidationError("unchanged event_cursor changed")
        if payload["intent_fingerprint"] != previous_intent_fingerprint:
            raise BootstrapValidationError("unchanged intent fingerprint changed")
        if payload["context_text"]:
            raise BootstrapValidationError("unchanged bootstrap unexpectedly returned context")
        receipt = {}

    payload["_validated_receipt"] = receipt
    return payload


def _fetch_bootstrap(
    *,
    session_value: str,
    query: str,
    base_url: str,
    token: str,
    previous_hash: str = "",
    previous_event_cursor: int = 0,
    previous_intent_fingerprint: str = "",
    context_limit: int = 1200,
    continuation_event_ids: list[int] | None = None,
    continuation_intent_fingerprint: str = "",
    continuation_primary_task_id: str = "",
) -> dict[str, Any]:
    requested_ids: list[int] = []
    for raw_event_id in (continuation_event_ids or [])[:MAX_CONTINUATION_EVENT_IDS]:
        if isinstance(raw_event_id, bool):
            raise ValueError("continuation event IDs must be integers")
        event_id = int(raw_event_id)
        if event_id > 0 and event_id not in requested_ids:
            requested_ids.append(event_id)
    continuation_requested = bool(
        not query.strip()
        and requested_ids
        and re.fullmatch(r"[a-f0-9]{16}", continuation_intent_fingerprint)
    )
    if requested_ids and not continuation_requested:
        raise ValueError("invalid exact-continuation binding")

    body: dict[str, Any] = {
        "session_id": session_value,
        "q": query,
        "stale_after_hours": 12,
        "context_limit": min(1500, max(400, int(context_limit))),
    }
    if continuation_requested:
        body["continuation_event_ids"] = ",".join(str(event_id) for event_id in requested_ids)
        body["continuation_intent_fingerprint"] = continuation_intent_fingerprint
        if continuation_primary_task_id:
            body["continuation_primary_task_id"] = continuation_primary_task_id[:160]
    if previous_hash:
        body.update(
            {
                "previous_hash": previous_hash,
                "previous_event_cursor": previous_event_cursor,
                "previous_intent_fingerprint": previous_intent_fingerprint,
                "previous_session_id": session_value,
            }
        )

    deadline = time.monotonic() + TIMEOUT_SECONDS
    response_payload: Any = None
    for attempt in range(2):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("bootstrap deadline exhausted")
        try:
            response_payload = _post_json(
                base_url,
                "/api/bootstrap",
                body,
                token,
                timeout=remaining,
                expected_status={200},
            )
            break
        except HTTPError as exc:
            if exc.code != 503 or attempt > 0:
                raise
            delay = _overload_retry_delay(session_value)
            if time.monotonic() + delay >= deadline:
                raise
            time.sleep(delay)

    return _validate_bootstrap(
        response_payload,
        session_value=session_value,
        query=query,
        previous_hash=previous_hash,
        previous_event_cursor=previous_event_cursor,
        previous_intent_fingerprint=previous_intent_fingerprint,
        continuation_event_ids=requested_ids,
        continuation_intent_fingerprint=(
            continuation_intent_fingerprint if continuation_requested else ""
        ),
        continuation_primary_task_id=(
            continuation_primary_task_id if continuation_requested else ""
        ),
    )


def _continuation_from_state(state: dict[str, Any]) -> tuple[list[int], str, str]:
    lane_payload = state.get("bootstrap_continuity_lane_event_ids")
    if not isinstance(lane_payload, dict):
        return [], "", ""
    result: list[int] = []
    for lane_name in ("intent", "task", "attention"):
        lane = lane_payload.get(lane_name)
        if not isinstance(lane, list):
            continue
        for raw_event_id in lane:
            if isinstance(raw_event_id, bool) or not isinstance(raw_event_id, int):
                raise BootstrapValidationError("stored continuation lane is invalid")
            if raw_event_id > 0 and raw_event_id not in result:
                result.append(raw_event_id)
            if len(result) >= MAX_CONTINUATION_EVENT_IDS:
                break
        if len(result) >= MAX_CONTINUATION_EVENT_IDS:
            break
    if not result:
        return [], "", ""
    fingerprint = str(state.get("bootstrap_intent_fingerprint") or "")
    if re.fullmatch(r"[a-f0-9]{16}", fingerprint) is None:
        raise BootstrapValidationError("stored continuation fingerprint is invalid")
    return result, fingerprint, str(state.get("bootstrap_primary_task_id") or "")[:160]


def _apply_bootstrap_state(state: dict[str, Any], bootstrap: dict[str, Any]) -> dict[str, Any]:
    state["bootstrap_schema"] = BOOTSTRAP_SCHEMA
    state["bootstrap_memory_contract_version"] = int(bootstrap["memory_contract_version"])
    state["bootstrap_event_cursor"] = int(bootstrap["event_cursor"])
    state["bootstrap_capsule_hash"] = str(bootstrap["capsule_hash"])
    state["bootstrap_intent_fingerprint"] = str(bootstrap["intent_fingerprint"])
    receipt = bootstrap.get("_validated_receipt")
    if isinstance(receipt, dict) and receipt:
        primary = bootstrap.get("primary_task")
        state["bootstrap_primary_task_id"] = (
            str(primary.get("task_id") or "") if isinstance(primary, dict) else ""
        )
        state["bootstrap_primary_event_id"] = (
            int(primary.get("activity_event_id") or 0) if isinstance(primary, dict) else 0
        )
        state["bootstrap_continuity_status"] = receipt["coverage_status"]
        state["bootstrap_continuity_scope"] = receipt["scope"]
        state["bootstrap_continuity_selected_event_ids"] = list(receipt["selected_event_ids"])
        state["bootstrap_continuity_delivered_event_ids"] = list(receipt["delivered_event_ids"])
        state["bootstrap_continuity_evidence_event_ids"] = list(receipt["evidence_event_ids"])
        state["bootstrap_continuity_source_event_ids"] = list(receipt["delivered_event_ids"])
        state["bootstrap_continuity_lane_event_ids"] = dict(receipt["lane_event_ids"])
        state["bootstrap_semantic_complete"] = False
    return receipt if isinstance(receipt, dict) else {}


def _closure_debt_context(state: dict[str, Any]) -> str:
    if not state.get("dirty"):
        return ""
    return (
        "INTEGRITY CLOSURE DEBT:\n"
        f"- This session used a potentially write-capable tool at {state.get('last_meaningful_utc') or 'an unknown time'} "
        "after its last observed Integrity closure. Reconcile current state and record a verified "
        "handoff, checkpoint, completion, blocked result, or failure."
    )


def _context_for_event(
    event: str,
    payload: dict[str, Any],
    state: dict[str, Any],
    *,
    session_value: str,
    base_url: str,
    token: str,
) -> tuple[str, bool, dict[str, Any]]:
    query = _prompt_text(payload) if event == "UserPromptSubmit" else ""
    force_context = event in {"SessionStart", "SubagentStart"}
    continuation_ids: list[int] = []
    continuation_fingerprint = ""
    continuation_primary_task_id = ""
    if force_context:
        continuation_ids, continuation_fingerprint, continuation_primary_task_id = (
            _continuation_from_state(state)
        )
    previous_hash = "" if force_context else str(state.get("bootstrap_capsule_hash") or "")
    previous_cursor = int(state.get("bootstrap_event_cursor") or 0)
    previous_intent = str(state.get("bootstrap_intent_fingerprint") or "")

    memory_context = ""
    receipt: dict[str, Any] = {}
    memory_candidate = False
    try:
        bootstrap = _fetch_bootstrap(
            session_value=session_value,
            query=query,
            base_url=base_url,
            token=token,
            previous_hash=previous_hash,
            previous_event_cursor=previous_cursor,
            previous_intent_fingerprint=previous_intent,
            context_limit=900 if event == "UserPromptSubmit" else 1200,
            continuation_event_ids=continuation_ids,
            continuation_intent_fingerprint=continuation_fingerprint,
            continuation_primary_task_id=continuation_primary_task_id,
        )
        receipt = _apply_bootstrap_state(state, bootstrap)
        memory_context = str(bootstrap["context_text"])
        memory_candidate = bool(memory_context and receipt)
    except Exception as exc:  # Hooks degrade without turning missing evidence into success.
        memory_context = (
            "INTEGRITY MEMORY UNAVAILABLE\n"
            f"reason={type(exc).__name__}\n"
            "No continuity claim is valid. Treat recalled content as unavailable and inspect live state."
        )
        receipt = {}
        memory_candidate = False

    return memory_context, memory_candidate, receipt


def _bounded_additional_context(context: str) -> str:
    if len(context) <= MAX_CONTEXT_CHARS:
        return context
    prefix = context[:MAX_CONTEXT_CHARS]
    # A partial line cannot be counted as delivered evidence.
    return prefix.rsplit("\n", 1)[0] if "\n" in prefix else ""


def _additional_context_output(event: str, context: str) -> dict[str, Any]:
    return {
        "continue": True,
        "hookSpecificOutput": {
            "hookEventName": event,
            "additionalContext": context,
        },
    }


def _universal_message_output(message: str) -> dict[str, Any]:
    return {"continue": True, "systemMessage": message[:2000], "suppressOutput": False}


def _post_precompact_checkpoint(
    session_value: str,
    payload: dict[str, Any],
    state: dict[str, Any],
    *,
    base_url: str,
    token: str,
) -> None:
    turn_id = str(payload.get("turn_id") or payload.get("turnId") or "")
    checkpoint_material = "|".join(
        (
            _session_hash(session_value),
            turn_id,
            str(state.get("meaningful_tool_count") or 0),
            str(state.get("last_meaningful_utc") or ""),
            "PreCompact",
        )
    )
    fingerprint = hashlib.sha256(checkpoint_material.encode("utf-8")).hexdigest()[:32]
    event = {
        "event_uid": f"integrity-checkpoint-{fingerprint}",
        "actor": "integrity-seed-hook",
        "session_id": session_value,
        "level": "warning" if state.get("dirty") else "info",
        "action": "agent_memory_checkpoint",
        "summary": (
            "Codex session reached compaction with unresolved closure debt"
            if state.get("dirty")
            else "Codex session reached compaction with no local closure debt"
        ),
        "details": {
            "schema_version": 1,
            "kind": "memory-checkpoint",
            "truth_status": "observed",
            "confidence": "high",
            "result": "partial" if state.get("dirty") else "ok",
            "dirty": bool(state.get("dirty")),
            "meaningful_tool_count": int(state.get("meaningful_tool_count") or 0),
            "last_meaningful_utc": str(state.get("last_meaningful_utc") or ""),
            "source": "PreCompact hook",
        },
        "tags": ["integrity", "memory", "checkpoint", "hook"],
    }
    _post_json(
        base_url,
        "/api/events",
        event,
        token,
        timeout=TIMEOUT_SECONDS,
        expected_status={200, 201},
        max_bytes=1024 * 1024,
    )


def _read_locked_state(home: str | os.PathLike[str], session_value: str) -> dict[str, Any]:
    with _session_lock(home, session_value):
        return _load_state(home, session_value)


def _merge_locked_state(
    home: str | os.PathLike[str],
    session_value: str,
    updates: dict[str, Any],
) -> dict[str, Any]:
    with _session_lock(home, session_value):
        latest = _load_state(home, session_value)
        latest.update(updates)
        _save_state(home, session_value, latest)
        return latest


def _bootstrap_state_updates(state: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in state.items() if key.startswith("bootstrap_")}


def _state_unavailable(event: str, exc: Exception) -> None:
    if event in CONTEXT_EVENTS:
        unavailable = (
            "INTEGRITY MEMORY UNAVAILABLE\n"
            f"reason={type(exc).__name__}\n"
            "Existing local session state was not trusted and was not overwritten."
        )
        print(json.dumps(_additional_context_output(event, unavailable), ensure_ascii=False), flush=True)
    else:
        print(f"Integrity Seed state unavailable: {type(exc).__name__}", file=sys.stderr)


def run(
    event: str,
    payload: dict[str, Any],
    base_url: str,
    token: str,
    home: str | os.PathLike[str],
) -> int:
    """Handle one Codex hook event and emit only event-supported hook JSON."""
    if not isinstance(payload, dict):
        payload = {}
    session_value = _session_id(payload)
    if not session_value:
        if event in CONTEXT_EVENTS:
            unavailable = (
                "INTEGRITY MEMORY UNAVAILABLE. No durable session_id was supplied; "
                "no state was read or written and no continuity claim is valid."
            )
            print(json.dumps(_additional_context_output(event, unavailable), ensure_ascii=False), flush=True)
        else:
            print("Integrity Seed skipped: durable session_id unavailable", file=sys.stderr)
        return 0

    try:
        state = _read_migrated_state(home, session_value)
    except (OSError, TypeError, ValueError, TimeoutError, SessionStateCorruptionError) as exc:
        _state_unavailable(event, exc)
        return 0

    if event == "PostToolUse":
        try:
            with _session_lock(home, session_value):
                latest = _load_state(home, session_value)
                _migrate_debt_state(latest)
                direct_remember = _is_direct_remember_command(_tool_command(payload))
                closure_receipt = (
                    _verified_closure_receipt(
                        payload,
                        token,
                        session_value,
                        latest,
                        _workspace_id(home),
                    )
                    if direct_remember
                    else None
                )
                if closure_receipt is not None:
                    if closure_receipt.get("_duplicate") is True:
                        return 0
                    latest["dirty"] = False
                    latest["last_closure_utc"] = str(closure_receipt["created_utc"])
                    latest["last_closure_event_id"] = int(closure_receipt["event_id"])
                    latest["last_closure_receipt_signature"] = str(
                        closure_receipt["signature"]
                    )
                    latest["last_closure_receipt_sha256"] = _receipt_digest(
                        closure_receipt
                    )
                    latest["last_closed_debt_generation"] = int(
                        closure_receipt["debt_generation"]
                    )
                    latest["last_closure_receipt_status"] = "durably-recorded-self-reported"
                    latest.pop("debt_challenge", None)
                    latest.pop("debt_challenge_id", None)
                elif direct_remember:
                    # A malformed, stale, non-closure, or already persisted
                    # direct memory write must not create workspace debt or
                    # disturb the current generation/challenge.
                    return 0
                elif _is_meaningful_tool(payload):
                    latest["dirty"] = True
                    latest["last_meaningful_utc"] = _utc_now()
                    latest["last_meaningful_tool"] = str(payload.get("tool_name") or "")[:80]
                    latest["meaningful_tool_count"] = (
                        int(latest.get("meaningful_tool_count") or 0) + 1
                    )
                    generation = _strict_generation(latest.get("debt_generation")) or 0
                    challenge, challenge_id = _new_debt_challenge()
                    latest["debt_generation"] = generation + 1
                    latest["debt_challenge"] = challenge
                    latest["debt_challenge_id"] = challenge_id
                else:
                    return 0
                _save_state(home, session_value, latest)
        except (OSError, TypeError, ValueError, TimeoutError, SessionStateCorruptionError) as exc:
            _state_unavailable(event, exc)
        return 0

    if event == "PreCompact":
        try:
            _post_precompact_checkpoint(
                session_value,
                payload,
                state,
                base_url=base_url,
                token=token,
            )
            _merge_locked_state(
                home,
                session_value,
                {
                    "last_precompact_checkpoint_utc": _utc_now(),
                    "last_precompact_checkpoint_status": "observed",
                    "last_precompact_checkpoint_error": "",
                },
            )
        except Exception as exc:
            try:
                _merge_locked_state(
                    home,
                    session_value,
                    {
                        "last_precompact_checkpoint_status": "not_observed",
                        "last_precompact_checkpoint_error": type(exc).__name__,
                    },
                )
            except Exception:
                pass
            print(f"Integrity Seed checkpoint not observed: {type(exc).__name__}", file=sys.stderr)
        return 0

    if event == "PostCompact":
        # Official Codex PostCompact accepts common output only and rejects
        # hookSpecificOutput. Rehydration occurs at SessionStart(source=compact).
        try:
            _merge_locked_state(
                home,
                session_value,
                {
                    "last_postcompact_utc": _utc_now(),
                    "last_postcompact_delivery_status": "no-context-output-by-contract",
                },
            )
        except Exception as exc:
            _state_unavailable(event, exc)
        return 0

    if event in CONTEXT_EVENTS:
        try:
            memory_context, memory_candidate, receipt = _context_for_event(
                event,
                payload,
                state,
                session_value=session_value,
                base_url=base_url,
                token=token,
            )
            latest = _read_locked_state(home, session_value)
            closure = _closure_debt_context(latest)
            context = "\n\n".join(part for part in (closure, memory_context) if part)
        except Exception as exc:
            context = (
                "INTEGRITY MEMORY UNAVAILABLE\n"
                f"reason={type(exc).__name__}\n"
                "No local session state or continuity receipt was trusted."
            )
            memory_candidate = False
            receipt = {}
        if context:
            prepared_context = _bounded_additional_context(context)
            expected_delivered = list(receipt.get("delivered_event_ids") or [])
            visible_contract = all(marker in prepared_context for marker in _BOOTSTRAP_MARKERS)
            rendered_evidence = _rendered_evidence_event_ids(prepared_context)
            memory_prepared = bool(
                memory_candidate
                and visible_contract
                and rendered_evidence == expected_delivered
            )
            if memory_candidate and not memory_prepared:
                prepared_context = (
                    "INTEGRITY MEMORY UNAVAILABLE\n"
                    "reason=BoundedReceiptMismatch\n"
                    "The bounded output did not preserve the exact delivered evidence receipt."
                )
                rendered_evidence = []

            updates = _bootstrap_state_updates(state)
            updates.update(
                {
                    "last_context_output_schema": "integrity.hook-context-output.v1",
                    "last_context_output_utc": _utc_now(),
                    "last_context_output_event": event,
                    "last_context_output_sha256": hashlib.sha256(
                        prepared_context.encode("utf-8")
                    ).hexdigest(),
                    "last_context_output_delivery_status": "prepared-not-acknowledged",
                    "last_context_output_memory_prepared": memory_prepared,
                    "last_context_output_bootstrap_schema": (
                        BOOTSTRAP_SCHEMA if memory_prepared else ""
                    ),
                    "last_context_output_memory_contract_version": (
                        MEMORY_CONTRACT_VERSION if memory_prepared else 0
                    ),
                    "last_context_output_continuity_status": (
                        str(receipt.get("coverage_status") or "unscoped")
                        if memory_prepared
                        else "not-prepared"
                    ),
                    "last_context_output_continuity_selected_event_ids": (
                        list(receipt.get("selected_event_ids") or []) if memory_prepared else []
                    ),
                    "last_context_output_continuity_delivered_event_ids": (
                        rendered_evidence if memory_prepared else []
                    ),
                    "last_context_output_continuity_evidence_event_ids": (
                        rendered_evidence if memory_prepared else []
                    ),
                    "last_context_output_continuity_source_event_ids": (
                        rendered_evidence if memory_prepared else []
                    ),
                    "last_context_output_continuity_lane_event_ids": (
                        dict(receipt.get("lane_event_ids") or {}) if memory_prepared else {}
                    ),
                    "last_context_output_semantic_complete": False,
                }
            )
            try:
                _merge_locked_state(home, session_value, updates)
            except Exception as exc:
                _state_unavailable(event, exc)
                return 0
            print(
                json.dumps(_additional_context_output(event, prepared_context), ensure_ascii=False),
                flush=True,
            )
        return 0

    if event in STOP_EVENTS:
        try:
            with _session_lock(home, session_value):
                latest = _load_state(home, session_value)
                dirty = bool(latest.get("dirty"))
                if dirty:
                    latest["stopped_with_closure_debt_utc"] = _utc_now()
                    _save_state(home, session_value, latest)
        except Exception as exc:
            _state_unavailable(event, exc)
            return 0
        if dirty:
            message = (
                "Integrity Seed: this session still has unresolved observed-tool debt. "
                "Do not assume the work is complete; reconcile live state and durably record a "
                "handoff, checkpoint, completion, blocked result, or failure."
            )
        else:
            message = "Integrity Seed: no local unclosed observed-tool debt was recorded for this session."
        print(json.dumps(_universal_message_output(message), ensure_ascii=False), flush=True)
        return 0

    return 0
