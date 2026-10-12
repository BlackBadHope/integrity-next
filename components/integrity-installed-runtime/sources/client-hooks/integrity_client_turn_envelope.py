"""Private, short-lived full-prompt envelopes shared by Integrity hooks and broker.

The public model sees only an opaque ``turn_ref``.  The exact prompt remains on
the owner machine until the broker has flushed the admitted response.  Windows
payloads use DPAPI CurrentUser, or CNG LOCAL=logon when that Windows logon cannot
use CurrentUser DPAPI. POSIX payloads live below a 0700 directory in 0600 files.
Persistent hook state and receipts contain only content-free digests and sizes.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import ctypes
import datetime as dt
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

PROTOCOL = "integrity-client/turn-envelope/v1"
TURN_REF_RE = re.compile(r"^turnref:[A-Za-z0-9_-]{43}$")
MAX_PROMPT_BYTES = 256 * 1024
MAX_ENVELOPE_FILE_BYTES = 2 * 1024 * 1024
MAX_ENVELOPES = 128
MAX_COMMITTED_ENVELOPES = 64
MAX_DIRECTORY_ENTRIES = 512
TTL_SECONDS = 10 * 60
COMMITTED_TTL_SECONDS = 60 * 60
TEMP_TTL_SECONDS = TTL_SECONDS
LOCK_TIMEOUT_SECONDS = 2.0
SEGMENT_BYTES = 4096
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
ROOT_MODE = 0o700
FILE_MODE = 0o600
LOCK_FILE = ".custody.lock"
TEMP_FILE_RE = re.compile(r"^\.envelope-[a-f0-9]{32}\.tmp$")


class TurnEnvelopeError(RuntimeError):
    """One fail-closed local envelope contract violation."""


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _ref_digest(turn_ref: str) -> str:
    return "sha256:" + _sha256_text(turn_ref)


def split_prompt(prompt: str, maximum_bytes: int = SEGMENT_BYTES) -> list[str]:
    """Split exact Unicode text into bounded UTF-8 segments without normalization."""

    if not isinstance(prompt, str) or not prompt.strip():
        raise TurnEnvelopeError("prompt is empty")
    if maximum_bytes < 4:
        raise TurnEnvelopeError("segment byte limit is invalid")
    segments: list[str] = []
    current: list[str] = []
    current_bytes = 0
    for character in prompt:
        encoded = character.encode("utf-8")
        if current and current_bytes + len(encoded) > maximum_bytes:
            segments.append("".join(current))
            current = []
            current_bytes = 0
        current.append(character)
        current_bytes += len(encoded)
    if current:
        segments.append("".join(current))
    if not segments or "".join(segments) != prompt:
        raise TurnEnvelopeError("prompt segmentation failed")
    return segments


def _details_are_link_like(details: os.stat_result) -> bool:
    attributes = getattr(details, "st_file_attributes", 0)
    return stat.S_ISLNK(details.st_mode) or bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


def _absolute_path(path: Path, label: str) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        raise TurnEnvelopeError(f"{label} must be absolute")
    return Path(os.path.abspath(expanded))


def _default_root() -> Path:
    override = os.environ.get("INTEGRITY_CLIENT_ENVELOPE_ROOT")
    if override:
        return _absolute_path(Path(override), "turn envelope root")
    codex_root = _absolute_path(
        Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))),
        "CODEX_HOME",
    )
    return codex_root / "integrity-memory" / "turn-envelopes"


def _validate_root_parent(path: Path, details: os.stat_result) -> None:
    if _details_are_link_like(details) or not stat.S_ISDIR(details.st_mode):
        raise TurnEnvelopeError("turn envelope parent is unsafe")
    if os.name == "nt":
        return
    mode = stat.S_IMODE(details.st_mode)
    root_owned_sticky = details.st_uid == 0 and bool(mode & stat.S_ISVTX)
    if (
        details.st_uid not in {0, os.geteuid()}
        or ((mode & (stat.S_IWGRP | stat.S_IWOTH)) and not root_owned_sticky)
    ):
        raise TurnEnvelopeError("turn envelope parent custody is unsafe")


def _validate_root(path: Path, details: os.stat_result) -> None:
    if _details_are_link_like(details) or not stat.S_ISDIR(details.st_mode):
        raise TurnEnvelopeError("turn envelope root is unsafe")
    if os.name != "nt" and (
        details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != ROOT_MODE
    ):
        raise TurnEnvelopeError("turn envelope root custody is unsafe")


def _validate_root_ancestry(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            details = current.lstat()
        except OSError as exc:
            raise TurnEnvelopeError("turn envelope ancestry is unavailable") from exc
        if _details_are_link_like(details) or not stat.S_ISDIR(details.st_mode):
            raise TurnEnvelopeError("turn envelope ancestry is unsafe")


def _ensure_root(root: Path | None = None) -> Path:
    target = (
        _absolute_path(root, "turn envelope root")
        if root is not None
        else _default_root()
    )
    _validate_root_ancestry(target.parent)
    try:
        parent_details = target.parent.lstat()
    except OSError as exc:
        raise TurnEnvelopeError("turn envelope parent is unavailable") from exc
    _validate_root_parent(target.parent, parent_details)
    try:
        target.mkdir(mode=ROOT_MODE)
    except FileExistsError:
        pass
    except OSError as exc:
        raise TurnEnvelopeError("turn envelope root cannot be created") from exc
    try:
        before = target.lstat()
    except OSError as exc:
        raise TurnEnvelopeError("turn envelope root is unavailable") from exc
    _validate_root(target, before)
    if os.name == "nt":
        try:
            after = target.lstat()
        except OSError as exc:
            raise TurnEnvelopeError("turn envelope root is unavailable") from exc
        _validate_root(target, after)
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise TurnEnvelopeError("turn envelope root changed while verified")
        return target
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError as exc:
        raise TurnEnvelopeError("turn envelope root cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        _validate_root(target, opened)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise TurnEnvelopeError("turn envelope root changed while opened")
    finally:
        os.close(descriptor)
    return target


def _path(root: Path, turn_ref: str) -> Path:
    if not isinstance(turn_ref, str) or TURN_REF_RE.fullmatch(turn_ref) is None:
        raise TurnEnvelopeError("turn_ref is invalid")
    return root / f"{_sha256_text(turn_ref)}.json"


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        _validate_root(path, os.fstat(descriptor))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_envelope_file(
    path: Path,
    details: os.stat_result,
    *,
    allow_empty: bool = False,
) -> None:
    size_is_valid = (
        0 <= details.st_size <= MAX_ENVELOPE_FILE_BYTES
        if allow_empty
        else 0 < details.st_size <= MAX_ENVELOPE_FILE_BYTES
    )
    if (
        _details_are_link_like(details)
        or not stat.S_ISREG(details.st_mode)
        or not size_is_valid
    ):
        raise TurnEnvelopeError("turn envelope file is unsafe")
    if os.name != "nt" and (
        details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != FILE_MODE
        or details.st_nlink != 1
    ):
        raise TurnEnvelopeError("turn envelope file custody is unsafe")


def _validate_lock_file(path: Path, details: os.stat_result) -> None:
    if (
        _details_are_link_like(details)
        or not stat.S_ISREG(details.st_mode)
        or details.st_size not in {0, 1}
    ):
        raise TurnEnvelopeError("turn envelope custody lock is unsafe")
    if os.name != "nt" and (
        details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != FILE_MODE
        or details.st_nlink != 1
    ):
        raise TurnEnvelopeError("turn envelope custody lock ownership is unsafe")


def _try_lock(descriptor: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        return
    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock(descriptor: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(descriptor, fcntl.LOCK_UN)


@contextlib.contextmanager
def _exclusive_root_lock(root: Path) -> Iterator[None]:
    lock_path = root / LOCK_FILE
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    created = False
    before: os.stat_result | None = None
    try:
        descriptor = os.open(lock_path, flags | os.O_CREAT | os.O_EXCL, FILE_MODE)
        created = True
    except FileExistsError:
        try:
            before = lock_path.lstat()
        except OSError as exc:
            raise TurnEnvelopeError("turn envelope custody lock is unavailable") from exc
        _validate_lock_file(lock_path, before)
        try:
            descriptor = os.open(lock_path, flags)
        except OSError as exc:
            raise TurnEnvelopeError(
                "turn envelope custody lock cannot be opened safely"
            ) from exc
    except OSError as exc:
        raise TurnEnvelopeError("turn envelope custody lock cannot be created") from exc
    acquired = False
    try:
        if created and hasattr(os, "fchmod"):
            os.fchmod(descriptor, FILE_MODE)
        opened = os.fstat(descriptor)
        _validate_lock_file(lock_path, opened)
        if before is not None and (opened.st_dev, opened.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise TurnEnvelopeError("turn envelope custody lock changed while opened")
        if opened.st_size == 0:
            if os.write(descriptor, b"\0") != 1:
                raise TurnEnvelopeError("turn envelope custody lock initialization failed")
            os.fsync(descriptor)
            opened = os.fstat(descriptor)
            _validate_lock_file(lock_path, opened)
        deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
        while True:
            try:
                _try_lock(descriptor)
                acquired = True
                break
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise TurnEnvelopeError(
                        "turn envelope custody lock cannot be acquired"
                    ) from exc
                if time.monotonic() >= deadline:
                    raise TurnEnvelopeError("turn envelope custody lock is busy") from exc
                time.sleep(0.01)
        locked = os.fstat(descriptor)
        _validate_lock_file(lock_path, locked)
        try:
            current = lock_path.lstat()
        except OSError as exc:
            raise TurnEnvelopeError("turn envelope custody lock is unavailable") from exc
        if (current.st_dev, current.st_ino) != (locked.st_dev, locked.st_ino):
            raise TurnEnvelopeError("turn envelope custody lock changed while acquired")
        yield
    finally:
        try:
            if acquired:
                _unlock(descriptor)
        finally:
            os.close(descriptor)


def _write_atomic(path: Path, value: dict[str, Any], *, create_only: bool = False) -> None:
    payload = _canonical(value)
    if len(payload) > MAX_ENVELOPE_FILE_BYTES:
        raise TurnEnvelopeError("turn envelope file exceeds its bound")
    if create_only:
        try:
            path.lstat()
        except FileNotFoundError:
            pass
        else:
            raise TurnEnvelopeError("turn envelope collision")
    temporary = path.with_name(f".envelope-{uuid.uuid4().hex}.tmp")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, FILE_MODE)
    try:
        try:
            details = os.fstat(descriptor)
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, FILE_MODE)
                details = os.fstat(descriptor)
            _validate_envelope_file(temporary, details, allow_empty=True)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise TurnEnvelopeError("turn envelope write failed")
                view = view[written:]
            os.fsync(descriptor)
            _validate_envelope_file(temporary, os.fstat(descriptor))
        finally:
            os.close(descriptor)
        if create_only:
            try:
                path.lstat()
            except FileNotFoundError:
                pass
            else:
                raise TurnEnvelopeError("turn envelope collision")
        os.replace(temporary, path)
        _validate_envelope_file(path, path.lstat())
        _fsync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _read(path: Path) -> dict[str, Any]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise TurnEnvelopeError("turn envelope file is unavailable") from exc
    _validate_envelope_file(path, before)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise TurnEnvelopeError("turn envelope file cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        _validate_envelope_file(path, opened)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise TurnEnvelopeError("turn envelope file changed while opened")
        chunks: list[bytes] = []
        remaining = MAX_ENVELOPE_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        finished = os.fstat(descriptor)
        if (
            finished.st_size,
            finished.st_mtime_ns,
            finished.st_ctime_ns,
        ) != (
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ):
            raise TurnEnvelopeError("turn envelope file changed while read")
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if len(raw) > MAX_ENVELOPE_FILE_BYTES:
        raise TurnEnvelopeError("turn envelope file is oversized")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TurnEnvelopeError("turn envelope file is malformed") from exc
    if not isinstance(value, dict):
        raise TurnEnvelopeError("turn envelope file is malformed")
    return value


def _bounded_root_paths(target: Path) -> tuple[list[Path], list[Path]]:
    json_paths: list[Path] = []
    temporary_paths: list[Path] = []
    scanned = 0
    try:
        with os.scandir(target) as entries:
            for entry in entries:
                scanned += 1
                if scanned > MAX_DIRECTORY_ENTRIES:
                    raise TurnEnvelopeError("turn envelope directory exceeds its scan bound")
                if entry.name.endswith(".json"):
                    json_paths.append(target / entry.name)
                elif TEMP_FILE_RE.fullmatch(entry.name) is not None:
                    temporary_paths.append(target / entry.name)
    except OSError as exc:
        raise TurnEnvelopeError("turn envelope directory cannot be scanned safely") from exc
    return (
        sorted(json_paths, key=lambda item: item.name),
        sorted(temporary_paths, key=lambda item: item.name),
    )


if os.name == "nt":
    class _DataBlob(ctypes.Structure):
        _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


    def _blob(value: bytes) -> tuple[_DataBlob, Any]:
        buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value) if value else None
        pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)) if buffer is not None else None
        return _DataBlob(len(value), pointer), buffer


def _protect_dpapi(prompt: bytes, turn_ref: str) -> bytes:
    data, data_buffer = _blob(prompt)
    entropy, entropy_buffer = _blob(hashlib.sha256(turn_ref.encode("utf-8")).digest())
    output = _DataBlob()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    ok = crypt32.CryptProtectData(
        ctypes.byref(data),
        "Integrity turn envelope",
        ctypes.byref(entropy),
        None,
        None,
        0x1,
        ctypes.byref(output),
    )
    del data_buffer, entropy_buffer
    if not ok:
        raise TurnEnvelopeError("DPAPI prompt protection failed")
    try:
        protected = ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(output.pbData)
    return protected


def _unprotect_dpapi(protected: bytes, turn_ref: str) -> bytes:
    data, data_buffer = _blob(protected)
    entropy, entropy_buffer = _blob(hashlib.sha256(turn_ref.encode("utf-8")).digest())
    output = _DataBlob()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(data),
        None,
        ctypes.byref(entropy),
        None,
        None,
        0x1,
        ctypes.byref(output),
    )
    del data_buffer, entropy_buffer
    if not ok:
        raise TurnEnvelopeError("DPAPI prompt recovery failed")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(output.pbData)


def _cng_logon_transform(data: bytes, *, protect: bool) -> bytes:
    """Use only the current logon session; never machine-wide or plaintext custody."""

    from ctypes import wintypes

    descriptor = ctypes.c_void_p()
    output = ctypes.c_void_p()
    size = wintypes.ULONG()
    try:
        # Restrict DLL resolution to System32, including passwordless SSH logons.
        ncrypt = ctypes.WinDLL("ncrypt.dll", winmode=0x800)
        kernel32 = ctypes.WinDLL("kernel32.dll", winmode=0x800)
        pointer = ctypes.c_void_p
        ncrypt.NCryptCreateProtectionDescriptor.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(pointer),
        ]
        ncrypt.NCryptCreateProtectionDescriptor.restype = wintypes.LONG
        ncrypt.NCryptCloseProtectionDescriptor.argtypes = [pointer]
        ncrypt.NCryptCloseProtectionDescriptor.restype = wintypes.LONG
        arguments = [
            pointer, wintypes.DWORD, pointer, wintypes.ULONG, pointer, pointer,
            ctypes.POINTER(pointer), ctypes.POINTER(wintypes.ULONG),
        ]
        ncrypt.NCryptProtectSecret.argtypes = arguments
        ncrypt.NCryptProtectSecret.restype = wintypes.LONG
        ncrypt.NCryptUnprotectSecret.argtypes = [ctypes.POINTER(pointer), *arguments[1:]]
        ncrypt.NCryptUnprotectSecret.restype = wintypes.LONG
        kernel32.LocalFree.argtypes = [pointer]
        kernel32.LocalFree.restype = pointer
    except (OSError, AttributeError) as exc:
        raise TurnEnvelopeError("CNG logon prompt custody is unavailable") from exc
    source = ctypes.create_string_buffer(data)
    try:
        if protect:
            status = ncrypt.NCryptCreateProtectionDescriptor(
                "LOCAL=logon", 0, ctypes.byref(descriptor),
            )
            if status != 0:
                raise TurnEnvelopeError("CNG logon protection descriptor failed")
            status = ncrypt.NCryptProtectSecret(
                descriptor, 0x40, source, len(data), None, None,
                ctypes.byref(output), ctypes.byref(size),
            )
        else:
            status = ncrypt.NCryptUnprotectSecret(
                None, 0x40, source, len(data), None, None,
                ctypes.byref(output), ctypes.byref(size),
            )
        if status != 0 or not output or not 0 < size.value <= MAX_ENVELOPE_FILE_BYTES:
            operation = "protection" if protect else "recovery"
            raise TurnEnvelopeError(f"CNG logon prompt {operation} failed")
        return ctypes.string_at(output, size.value)
    finally:
        if output:
            kernel32.LocalFree(output)
        if descriptor:
            ncrypt.NCryptCloseProtectionDescriptor(descriptor)


def _logon_binding(turn_ref: str) -> bytes:
    return b"integrity-client/logon-envelope/v1\0" + hashlib.sha256(
        turn_ref.encode("utf-8"),
    ).digest()


def _protect(prompt: bytes, turn_ref: str) -> tuple[str, str]:
    if os.name != "nt":
        return "private-utf8-base64/v1", base64.b64encode(prompt).decode("ascii")
    try:
        protected = _protect_dpapi(prompt, turn_ref)
        encoding = "dpapi-current-user/v1"
    except TurnEnvelopeError:
        protected = _cng_logon_transform(_logon_binding(turn_ref) + prompt, protect=True)
        encoding = "cng-local-logon/v1"
    return encoding, base64.b64encode(protected).decode("ascii")


def _unprotect(encoding: str, payload_b64: str, turn_ref: str) -> bytes:
    try:
        protected = base64.b64decode(payload_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise TurnEnvelopeError("turn envelope payload is malformed") from exc
    if encoding == "private-utf8-base64/v1" and os.name != "nt":
        return protected
    if os.name == "nt":
        if encoding == "dpapi-current-user/v1":
            return _unprotect_dpapi(protected, turn_ref)
        if encoding == "cng-local-logon/v1":
            recovered = _cng_logon_transform(protected, protect=False)
            binding = _logon_binding(turn_ref)
            if not secrets.compare_digest(recovered[:len(binding)], binding):
                raise TurnEnvelopeError("CNG logon prompt binding failed")
            return recovered[len(binding):]
    raise TurnEnvelopeError("turn envelope protection mode is unavailable")


def _identity_hash(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise TurnEnvelopeError(f"{label} is invalid")
    return _sha256_text(value)


def _claim_digest(claim_id: str) -> str:
    if (
        not isinstance(claim_id, str)
        or re.fullmatch(r"claim:[a-f0-9]{64}", claim_id) is None
    ):
        raise TurnEnvelopeError("turn envelope claim is invalid")
    return _sha256_text(claim_id)


def _require_claim(value: dict[str, Any], claim_id: str) -> None:
    expected = value.get("claim_id_sha256")
    actual = _claim_digest(claim_id)
    if (
        not isinstance(expected, str)
        or re.fullmatch(r"[a-f0-9]{64}", expected) is None
        or not secrets.compare_digest(expected, actual)
    ):
        raise TurnEnvelopeError("turn envelope claim mismatch")


def _validate_common(value: dict[str, Any], turn_ref: str) -> None:
    if value.get("protocol") != PROTOCOL or value.get("turn_ref_digest") != _ref_digest(turn_ref):
        raise TurnEnvelopeError("turn envelope identity mismatch")
    prompt_sha256 = value.get("prompt_sha256")
    if not isinstance(prompt_sha256, str) or re.fullmatch(r"[a-f0-9]{64}", prompt_sha256) is None:
        raise TurnEnvelopeError("turn envelope prompt digest is invalid")
    prompt_bytes = value.get("prompt_bytes")
    segment_count = value.get("segment_count")
    generation = value.get("generation")
    if (
        isinstance(prompt_bytes, bool)
        or not isinstance(prompt_bytes, int)
        or prompt_bytes < 1
        or prompt_bytes > MAX_PROMPT_BYTES
        or isinstance(segment_count, bool)
        or not isinstance(segment_count, int)
        or segment_count < 1
        or segment_count > (MAX_PROMPT_BYTES // SEGMENT_BYTES + 1)
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 1
    ):
        raise TurnEnvelopeError("turn envelope bounds are invalid")
    expires_epoch = value.get("expires_epoch")
    if not isinstance(expires_epoch, (int, float)) or isinstance(expires_epoch, bool):
        raise TurnEnvelopeError("turn envelope expiry is invalid")


def _public(value: dict[str, Any], turn_ref: str) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL,
        "turn_ref": turn_ref,
        "turn_ref_digest": value["turn_ref_digest"],
        "prompt_sha256": value["prompt_sha256"],
        "prompt_bytes": value["prompt_bytes"],
        "segment_count": value["segment_count"],
        "prompt_coverage": "text-only",
        "truncation": False,
        "generation": value["generation"],
        "expires_utc": value["expires_utc"],
        "status": value["status"],
    }


def _gc_locked(
    target: Path,
    *,
    observed: float,
    protected_committed: Path | None = None,
) -> tuple[int, list[tuple[Path, dict[str, Any]]]]:
    removed = 0
    survivors: list[tuple[Path, dict[str, Any]]] = []
    committed: list[tuple[bool, float, str, Path]] = []
    json_paths, temporary_paths = _bounded_root_paths(target)
    for path in temporary_paths:
        try:
            details = path.lstat()
        except OSError as exc:
            raise TurnEnvelopeError("turn envelope temporary file is unavailable") from exc
        _validate_envelope_file(path, details, allow_empty=True)
        if details.st_mtime <= observed - TEMP_TTL_SECONDS:
            path.unlink()
            removed += 1
    for path in json_paths:
        value = _read(path)
        expires = value.get("expires_epoch")
        status = value.get("status")
        if (
            isinstance(expires, bool)
            or not isinstance(expires, (int, float))
            or status not in {"staged", "armed", "claimed", "committed"}
        ):
            raise TurnEnvelopeError("turn envelope retention metadata is invalid")
        if expires <= observed:
            path.unlink()
            removed += 1
            continue
        survivors.append((path, value))
        if status == "committed":
            committed.append(
                (
                    path == protected_committed,
                    float(expires),
                    path.name,
                    path,
                )
            )
    prune = {
        path
        for _protected, _expires, _name, path in sorted(committed)[
            : max(0, len(committed) - MAX_COMMITTED_ENVELOPES)
        ]
    }
    for path in prune:
        path.unlink()
        removed += 1
    if prune:
        survivors = [(path, value) for path, value in survivors if path not in prune]
    if removed:
        _fsync_directory(target)
    return removed, survivors


def gc(root: Path | None = None, *, now: float | None = None) -> int:
    target = _ensure_root(root)
    observed = time.time() if now is None else now
    with _exclusive_root_lock(target):
        removed, _survivors = _gc_locked(target, observed=observed)
    return removed


def stage(
    prompt: str,
    *,
    machine_id: str,
    thread_id: str,
    turn_id: str,
    generation: int,
    root: Path | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    target = _ensure_root(root)
    if not isinstance(prompt, str) or not prompt.strip():
        raise TurnEnvelopeError("prompt is empty")
    prompt_utf8 = prompt.encode("utf-8")
    if len(prompt_utf8) > MAX_PROMPT_BYTES:
        raise TurnEnvelopeError("prompt exceeds the 256 KiB envelope bound")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise TurnEnvelopeError("generation is invalid")
    segments = split_prompt(prompt)
    turn_ref = "turnref:" + secrets.token_urlsafe(32)
    encoding, payload_b64 = _protect(prompt_utf8, turn_ref)
    observed = time.time() if now is None else now
    expires = observed + TTL_SECONDS
    value = {
        "protocol": PROTOCOL,
        "turn_ref_digest": _ref_digest(turn_ref),
        "machine_id_sha256": _identity_hash(machine_id, "machine_id"),
        "thread_id_sha256": _identity_hash(thread_id, "thread_id"),
        "turn_id_sha256": _identity_hash(turn_id, "turn_id"),
        "generation": generation,
        "prompt_sha256": _sha256_bytes(prompt_utf8),
        "prompt_bytes": len(prompt_utf8),
        "segment_count": len(segments),
        "prompt_coverage": "text-only",
        "truncation": False,
        "created_utc": _utc_now(),
        "expires_utc": dt.datetime.fromtimestamp(expires, dt.UTC).isoformat().replace("+00:00", "Z"),
        "expires_epoch": expires,
        "status": "staged",
        "encoding": encoding,
        "payload_b64": payload_b64,
    }
    with _exclusive_root_lock(target):
        _removed, survivors = _gc_locked(target, observed=observed)
        active = sum(
            envelope.get("status") in {"staged", "armed", "claimed"}
            for _path_value, envelope in survivors
        )
        if active >= MAX_ENVELOPES:
            raise TurnEnvelopeError("turn envelope quota is exhausted")
        _write_atomic(_path(target, turn_ref), value, create_only=True)
    return _public(value, turn_ref)


def arm(
    turn_ref: str,
    *,
    machine_id: str,
    thread_id: str,
    turn_id: str,
    generation: int,
    prompt_sha256: str,
    root: Path | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    target = _ensure_root(root)
    path = _path(target, turn_ref)
    with _exclusive_root_lock(target):
        value = _read(path)
        _validate_common(value, turn_ref)
        observed = time.time() if now is None else now
        if value["expires_epoch"] <= observed:
            try:
                path.unlink()
            finally:
                _fsync_directory(target)
            raise TurnEnvelopeError("turn envelope expired")
        expected = {
            "machine_id_sha256": _identity_hash(machine_id, "machine_id"),
            "thread_id_sha256": _identity_hash(thread_id, "thread_id"),
            "turn_id_sha256": _identity_hash(turn_id, "turn_id"),
            "generation": generation,
            "prompt_sha256": prompt_sha256,
        }
        if any(value.get(key) != item for key, item in expected.items()):
            raise TurnEnvelopeError("turn envelope binding mismatch")
        if value.get("status") not in {"staged", "armed"}:
            raise TurnEnvelopeError("turn envelope is not armable")
        if value.get("status") == "staged":
            value["status"] = "armed"
            value["armed_utc"] = _utc_now()
            _write_atomic(path, value)
        return _public(value, turn_ref)


def resolve(
    turn_ref: str,
    *,
    root: Path | None = None,
    now: float | None = None,
) -> tuple[str, dict[str, Any], str]:
    target = _ensure_root(root)
    path = _path(target, turn_ref)
    with _exclusive_root_lock(target):
        value = _read(path)
        _validate_common(value, turn_ref)
        observed = time.time() if now is None else now
        if value["expires_epoch"] <= observed:
            raise TurnEnvelopeError("turn envelope expired")
        if value.get("status") != "armed":
            raise TurnEnvelopeError("turn envelope is not armed by its owning hook")
        payload_b64 = value.get("payload_b64")
        encoding = value.get("encoding")
        if not isinstance(payload_b64, str) or not isinstance(encoding, str):
            raise TurnEnvelopeError("turn envelope payload is unavailable")
        prompt_utf8 = _unprotect(encoding, payload_b64, turn_ref)
        if (
            len(prompt_utf8) != value["prompt_bytes"]
            or _sha256_bytes(prompt_utf8) != value["prompt_sha256"]
        ):
            raise TurnEnvelopeError("turn envelope prompt integrity failed")
        try:
            prompt = prompt_utf8.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TurnEnvelopeError("turn envelope prompt is not UTF-8") from exc
        if len(split_prompt(prompt)) != value["segment_count"]:
            raise TurnEnvelopeError("turn envelope segment binding failed")
        claim_id = "claim:" + secrets.token_hex(32)
        value["status"] = "claimed"
        value["claim_id_sha256"] = _claim_digest(claim_id)
        value["claimed_utc"] = _utc_now()
        _write_atomic(path, value)
        binding = _public(value, turn_ref)
        binding.pop("turn_ref")
        return prompt, binding, claim_id


def release_claim(
    turn_ref: str,
    claim_id: str,
    *,
    root: Path | None = None,
) -> dict[str, Any]:
    target = _ensure_root(root)
    path = _path(target, turn_ref)
    with _exclusive_root_lock(target):
        value = _read(path)
        _validate_common(value, turn_ref)
        if value.get("status") != "claimed":
            raise TurnEnvelopeError("turn envelope is not claimed")
        _require_claim(value, claim_id)
        if value.get("retire_after_claim") is True:
            # A newer owner intent superseded this in-flight admission. Never
            # re-arm the old prompt when an upstream pre-send retry releases it.
            path.unlink()
            _fsync_directory(target)
            return {"retired": True, "status": "retired"}
        value["status"] = "armed"
        value.pop("claim_id_sha256", None)
        value.pop("claimed_utc", None)
        _write_atomic(path, value)
        return _public(value, turn_ref)


def commit(
    turn_ref: str,
    claim_id: str,
    *,
    root: Path | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    target = _ensure_root(root)
    path = _path(target, turn_ref)
    with _exclusive_root_lock(target):
        value = _read(path)
        _validate_common(value, turn_ref)
        if value.get("status") == "committed":
            return _public(value, turn_ref)
        if value.get("status") != "claimed":
            raise TurnEnvelopeError("turn envelope is not commit-ready")
        _require_claim(value, claim_id)
        observed = time.time() if now is None else now
        tombstone = {
            key: value[key]
            for key in (
                "protocol",
                "turn_ref_digest",
                "machine_id_sha256",
                "thread_id_sha256",
                "turn_id_sha256",
                "generation",
                "prompt_sha256",
                "prompt_bytes",
                "segment_count",
                "prompt_coverage",
                "truncation",
                "created_utc",
            )
        }
        tombstone.update(
            {
                "status": "committed",
                "committed_utc": _utc_now(),
                "expires_epoch": observed + COMMITTED_TTL_SECONDS,
                "expires_utc": dt.datetime.fromtimestamp(
                    observed + COMMITTED_TTL_SECONDS, dt.UTC
                ).isoformat().replace("+00:00", "Z"),
            }
        )
        _write_atomic(path, tombstone)
        _gc_locked(
            target,
            observed=observed,
            protected_committed=path,
        )
        return _public(tombstone, turn_ref)


def retire(
    turn_ref: str, *, root: Path | None = None, preserve_claimed: bool = False
) -> bool:
    target = _ensure_root(root)
    path = _path(target, turn_ref)
    with _exclusive_root_lock(target):
        try:
            path.lstat()
        except FileNotFoundError:
            return False
        value = _read(path)
        if preserve_claimed and value.get("status") == "claimed":
            # Custody stays with the in-flight broker until commit/release/TTL.
            # The same root lock serializes this decision with claim acquisition.
            value["retire_after_claim"] = True
            _write_atomic(path, value)
            return False
        path.unlink()
        _fsync_directory(target)
        return True


def _machine_id() -> str:
    import socket

    value = re.sub(r"[^a-z0-9._-]", "-", socket.gethostname().lower())
    if not value:
        raise TurnEnvelopeError("machine identity is unavailable")
    return "machine:" + value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    stage_parser = subparsers.add_parser("stage")
    stage_parser.add_argument("--thread-id", required=True)
    stage_parser.add_argument("--turn-id", required=True)
    stage_parser.add_argument("--generation", required=True, type=int)
    stage_parser.add_argument("--machine-id", default="")
    arm_parser = subparsers.add_parser("arm")
    arm_parser.add_argument("--turn-ref", required=True)
    arm_parser.add_argument("--thread-id", required=True)
    arm_parser.add_argument("--turn-id", required=True)
    arm_parser.add_argument("--generation", required=True, type=int)
    arm_parser.add_argument("--prompt-sha256", required=True)
    arm_parser.add_argument("--machine-id", default="")
    commit_parser = subparsers.add_parser("commit")
    commit_parser.add_argument("--turn-ref", required=True)
    commit_parser.add_argument("--claim-id", required=True)
    retire_parser = subparsers.add_parser("retire")
    retire_parser.add_argument("--turn-ref", required=True)
    retire_parser.add_argument("--preserve-claimed", action="store_true")
    subparsers.add_parser("gc")
    args = parser.parse_args(argv)
    try:
        if args.command == "stage":
            try:
                prompt_bytes = sys.stdin.buffer.read(MAX_PROMPT_BYTES + 1)
                if len(prompt_bytes) > MAX_PROMPT_BYTES:
                    raise TurnEnvelopeError("prompt exceeds the 256 KiB envelope bound")
                prompt = prompt_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise TurnEnvelopeError("prompt stdin is not exact UTF-8") from exc
            value = stage(
                prompt,
                machine_id=args.machine_id or _machine_id(),
                thread_id=args.thread_id,
                turn_id=args.turn_id,
                generation=args.generation,
            )
        elif args.command == "arm":
            value = arm(
                args.turn_ref,
                machine_id=args.machine_id or _machine_id(),
                thread_id=args.thread_id,
                turn_id=args.turn_id,
                generation=args.generation,
                prompt_sha256=args.prompt_sha256,
            )
        elif args.command == "commit":
            value = commit(args.turn_ref, args.claim_id)
        elif args.command == "retire":
            value = {"retired": retire(args.turn_ref, preserve_claimed=args.preserve_claimed)}
        else:
            value = {"removed": gc()}
    except (OSError, TurnEnvelopeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
