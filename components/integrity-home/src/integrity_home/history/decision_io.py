"""Bounded canonical file I/O for History review artifacts."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile

from integrity_chronicle.state_lock import CorpusStateLockError, corpus_state_lock

from .decisions import (
    MAX_HISTORY_REVIEW_ARTIFACT_BYTES,
    history_review_request_json_bytes,
    history_review_result_json_bytes,
    validate_history_review_request,
    validate_history_review_result,
)
from .sidecar import (
    HistorySidecarError,
    HistorySidecarReader,
    HistorySidecarSchemaError,
    HistorySidecarStaleError,
)


FileIdentity = tuple[int, int, int, int]


def _path_key(path: Path) -> str:
    value = os.path.normpath(str(path))
    return os.path.normcase(value) if os.name == "nt" else value


def _canonical_path(value: str, *, label: str, must_exist: bool) -> Path:
    if type(value) is not str or not value or "\x00" in value:
        raise HistorySidecarSchemaError(f"{label} path is required")
    raw = Path(value)
    if not raw.is_absolute():
        raise HistorySidecarSchemaError(f"{label} path must be absolute")
    if raw.is_symlink():
        raise HistorySidecarSchemaError(f"{label} path must not be a symlink")
    try:
        parent = raw.parent.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as err:
        raise HistorySidecarSchemaError(f"{label} parent is unavailable") from err
    if not parent.is_dir() or parent.is_symlink():
        raise HistorySidecarSchemaError(f"{label} parent must be a real directory")
    if _path_key(raw.parent) != _path_key(parent):
        raise HistorySidecarSchemaError(f"{label} path must not traverse symlinks")
    candidate = parent / raw.name
    try:
        resolved = raw.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as err:
        raise HistorySidecarSchemaError(f"{label} path is invalid") from err
    if _path_key(candidate) != _path_key(resolved):
        raise HistorySidecarSchemaError(f"{label} path must not traverse symlinks")
    if must_exist:
        try:
            state = candidate.lstat()
        except OSError as err:
            raise HistorySidecarSchemaError(f"{label} does not exist") from err
        if not stat.S_ISREG(state.st_mode) or stat.S_ISLNK(state.st_mode):
            raise HistorySidecarSchemaError(f"{label} must be a regular file")
    elif candidate.exists():
        state = candidate.lstat()
        if not stat.S_ISREG(state.st_mode) or stat.S_ISLNK(state.st_mode):
            raise HistorySidecarSchemaError(f"{label} must be a regular file")
    return candidate


def _file_identity(path: Path, *, label: str) -> FileIdentity:
    try:
        state = path.lstat()
    except OSError as err:
        raise HistorySidecarStaleError(f"cannot stat {label}") from err
    if not stat.S_ISREG(state.st_mode) or stat.S_ISLNK(state.st_mode):
        raise HistorySidecarStaleError(f"{label} is no longer a regular file")
    return (
        int(state.st_dev),
        int(state.st_ino),
        int(state.st_size),
        int(state.st_mtime_ns),
    )


def _read_bounded_artifact(path: Path, *, label: str) -> tuple[bytes, FileIdentity]:
    before = _file_identity(path, label=label)
    if not 0 < before[2] <= MAX_HISTORY_REVIEW_ARTIFACT_BYTES:
        raise HistorySidecarSchemaError(f"{label} exceeds its byte budget")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as err:
        raise HistorySidecarError(f"cannot read {label}") from err
    try:
        opened = os.fstat(descriptor)
        opened_identity = (
            int(opened.st_dev),
            int(opened.st_ino),
            int(opened.st_size),
            int(opened.st_mtime_ns),
        )
        if opened_identity != before or not stat.S_ISREG(opened.st_mode):
            raise HistorySidecarStaleError(f"{label} changed before read")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(MAX_HISTORY_REVIEW_ARTIFACT_BYTES + 1)
        after = os.fstat(descriptor)
        after_identity = (
            int(after.st_dev),
            int(after.st_ino),
            int(after.st_size),
            int(after.st_mtime_ns),
        )
        if after_identity != before or len(data) != before[2]:
            raise HistorySidecarStaleError(f"{label} changed during read")
    finally:
        os.close(descriptor)
    if _file_identity(path, label=label) != before:
        raise HistorySidecarStaleError(f"{label} changed during read")
    if len(data) > MAX_HISTORY_REVIEW_ARTIFACT_BYTES:
        raise HistorySidecarSchemaError(f"{label} exceeds its byte budget")
    return data, before


def _private_mode(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        if os.name != "nt":
            raise


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _write_atomic(path: str, data: bytes, *, label: str) -> Path:
    target = _canonical_path(path, label=label, must_exist=False)
    try:
        with corpus_state_lock(str(target)):
            target = _canonical_path(path, label=label, must_exist=False)
            try:
                parent_state = target.parent.lstat()
            except OSError as err:
                raise HistorySidecarStaleError(f"{label} parent changed") from err
            parent_key = (int(parent_state.st_dev), int(parent_state.st_ino))
            prior = _file_identity(target, label=label) if target.exists() else None
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{target.name}.review-", suffix=".tmp", dir=target.parent
            )
            temporary: Path | None = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                _private_mode(temporary)
                current_parent = target.parent.lstat()
                if (
                    not stat.S_ISDIR(current_parent.st_mode)
                    or (int(current_parent.st_dev), int(current_parent.st_ino))
                    != parent_key
                ):
                    raise HistorySidecarStaleError(f"{label} parent changed")
                current = _file_identity(target, label=label) if target.exists() else None
                if current != prior:
                    raise HistorySidecarStaleError(f"{label} target changed")
                os.replace(temporary, target)
                temporary = None
                _private_mode(target)
                descriptor = os.open(target, os.O_RDWR)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                _fsync_directory(target.parent)
            finally:
                if temporary is not None:
                    try:
                        temporary.unlink(missing_ok=True)
                    except OSError:
                        pass
    except CorpusStateLockError as err:
        raise HistorySidecarError(f"could not lock {label}") from err
    except OSError as err:
        raise HistorySidecarError(f"could not write {label}") from err
    return target


def write_history_review_request(
    path: str,
    payload: object,
    *,
    reader: HistorySidecarReader | None = None,
) -> str:
    data = history_review_request_json_bytes(payload, reader=reader)
    return str(_write_atomic(path, data, label="History review request"))


def write_history_review_result(
    path: str,
    payload: object,
    *,
    request: object,
    reader: HistorySidecarReader | None = None,
) -> str:
    data = history_review_result_json_bytes(payload, request=request, reader=reader)
    return str(_write_atomic(path, data, label="History review result"))


def load_history_review_request(
    path: str,
    *,
    reader: HistorySidecarReader | None = None,
) -> dict[str, object]:
    target = _canonical_path(path, label="History review request", must_exist=True)
    data, _identity = _read_bounded_artifact(target, label="History review request")
    normalized = validate_history_review_request(data, reader=reader)
    if history_review_request_json_bytes(normalized, reader=reader) != data:
        raise HistorySidecarSchemaError("History review request bytes are not canonical")
    return normalized


def load_history_review_result(
    path: str,
    *,
    request: object,
    reader: HistorySidecarReader | None = None,
) -> dict[str, object]:
    target = _canonical_path(path, label="History review result", must_exist=True)
    data, _identity = _read_bounded_artifact(target, label="History review result")
    normalized = validate_history_review_result(payload=data, request=request, reader=reader)
    if history_review_result_json_bytes(
        normalized, request=request, reader=reader
    ) != data:
        raise HistorySidecarSchemaError("History review result bytes are not canonical")
    return normalized


__all__ = [
    "load_history_review_request",
    "load_history_review_result",
    "write_history_review_request",
    "write_history_review_result",
]
