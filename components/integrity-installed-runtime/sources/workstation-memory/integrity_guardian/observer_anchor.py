"""Crash-atomic local custody for externally retained observer anchors.

The file is deliberately separate from the SQLite stores whose heads it pins.
It provides ordinary crash recovery and stale-writer exclusion.  It cannot
prove that an attacker did not roll back the complete filesystem failure
domain; authoritative use still needs a cursor digest retained elsewhere.
"""

from __future__ import annotations

import os
import re
import secrets
import stat
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Self

from jsonschema import ValidationError

from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .local_lock import (
    LocalLockError,
    lock_exclusive,
    lock_shared,
    unlock,
)
from .schemas import validate
from .uroboros_toolzs_outcome import (
    toolz_action_outcome_digest,
    toolz_action_outcome_identity,
)
from .uroboros_toolzs_store import ToolzRouteStoreError, ToolzStoreCursor

OBSERVER_ANCHOR_FILE_NAME = "observer-anchor.json"
MAX_OBSERVER_ANCHOR_BYTES = 4 * 1024 * 1024
MAX_OBSERVER_ANCHOR_SEQUENCE = 1_000_000

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_STORAGE_BOUNDARY = {
    "availability_recovery": True,
    "crash_atomic_replace": True,
    "local_storage": True,
    "network": False,
    "production_authority": False,
    "same_failure_domain_rollback_protection": False,
    "subject_store_write": False,
    "trusted_latest_without_external_pin": False,
}


class ObserverAnchorError(RuntimeError):
    """Raised before unsafe, stale or ambiguous anchor state is accepted."""


class ObserverAnchorSubjectKind(StrEnum):
    """Closed anchor subjects admitted by the first observer store."""

    TOOLZ_ROUTE_STORE_CURSOR = "toolz-route-store-cursor"
    TOOLZ_AUTHORITY_CHECKPOINT = "toolz-authority-checkpoint"
    TOOLZ_ACTION_OUTCOME_OBSERVATION = "toolz-action-outcome-observation"


@dataclass(frozen=True)
class ObserverAnchorCursor:
    """Caller-retained exact anchor head."""

    store_id: str
    sequence: int
    anchor_id: str
    anchor_digest: str

    def __post_init__(self) -> None:
        _require_id(self.store_id, "store id", synthetic=True)
        if (
            not isinstance(self.sequence, int)
            or isinstance(self.sequence, bool)
            or not 0 <= self.sequence <= MAX_OBSERVER_ANCHOR_SEQUENCE
        ):
            raise ObserverAnchorError("observer anchor cursor sequence rejected")
        if (
            not isinstance(self.anchor_id, str)
            or re.fullmatch(r"observer-anchor:[a-f0-9]{64}", self.anchor_id) is None
        ):
            raise ObserverAnchorError("observer anchor cursor identity rejected")
        _require_digest(self.anchor_digest, "cursor digest")

    def to_document(self) -> dict[str, Any]:
        return {
            "store_id": self.store_id,
            "sequence": self.sequence,
            "anchor_id": self.anchor_id,
            "anchor_digest": self.anchor_digest,
        }

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> ObserverAnchorCursor:
        fields = {"store_id", "sequence", "anchor_id", "anchor_digest"}
        if not isinstance(document, Mapping) or set(document) != fields:
            raise ObserverAnchorError("observer anchor cursor document rejected")
        try:
            return cls(**dict(document))
        except TypeError as exc:
            raise ObserverAnchorError(
                "observer anchor cursor document rejected"
            ) from exc


@dataclass(frozen=True)
class ObserverAnchorRecovery:
    """One recovered anchor plus its explicit rollback assurance."""

    record: dict[str, Any]
    cursor: ObserverAnchorCursor
    externally_pinned: bool

    @property
    def rollback_protection(self) -> bool:
        return self.externally_pinned

    @property
    def availability_recovery(self) -> bool:
        return True


def _require_id(value: object, field: str, *, synthetic: bool = False) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ObserverAnchorError(f"observer anchor {field} rejected")
    if synthetic and "synthetic" not in value:
        raise ObserverAnchorError(f"observer anchor {field} rejected")
    return value


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ObserverAnchorError(f"observer anchor {field} rejected")
    return value


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ObserverAnchorError(f"observer anchor {field} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ObserverAnchorError(f"observer anchor {field} rejected") from exc
    if parsed.tzinfo is None:
        raise ObserverAnchorError(f"observer anchor {field} rejected")
    return parsed


def _freeze_mapping(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    try:
        candidate = parse_json_strict(canonical_bytes(dict(value)))
    except Exception as exc:
        raise ObserverAnchorError(f"observer anchor {field} rejected") from exc
    if not isinstance(candidate, dict):
        raise ObserverAnchorError(f"observer anchor {field} rejected")
    return candidate


def _subject_document(
    kind: ObserverAnchorSubjectKind,
    subject: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    candidate = _freeze_mapping(subject, "subject")
    try:
        if kind is ObserverAnchorSubjectKind.TOOLZ_ROUTE_STORE_CURSOR:
            cursor = ToolzStoreCursor.from_document(candidate)
            candidate = cursor.to_document()
            digest = digest_object(
                candidate,
                domain="observer-anchor-toolz-route-store-cursor-v1",
            )
        elif kind is ObserverAnchorSubjectKind.TOOLZ_AUTHORITY_CHECKPOINT:
            validate("checkpoint", candidate)
            digest = digest_object(
                candidate,
                domain="observer-anchor-toolz-authority-checkpoint-v1",
            )
        else:
            validate("toolz-action-outcome-observation", candidate)
            if candidate["observation_id"] != toolz_action_outcome_identity(candidate):
                raise ObserverAnchorError(
                    "observer anchor outcome identity rejected"
                )
            digest = toolz_action_outcome_digest(candidate)
    except (
        KeyError,
        ToolzRouteStoreError,
        ValidationError,
        ValueError,
    ) as exc:
        if isinstance(exc, ObserverAnchorError):
            raise
        raise ObserverAnchorError("observer anchor subject rejected") from exc
    return candidate, digest


def _record_core(record: Mapping[str, Any]) -> dict[str, Any]:
    core = deepcopy(dict(record))
    core.pop("anchor_id", None)
    return core


def observer_anchor_record_identity(record: Mapping[str, Any]) -> str:
    """Return the content identity of one unsigned local anchor record."""

    digest = digest_object(
        _record_core(record),
        domain="observer-anchor-record-identity-v1",
    )
    return f"observer-anchor:{digest.split(':', 1)[1]}"


def observer_anchor_record_digest(record: Mapping[str, Any]) -> str:
    """Return the exact canonical digest of one anchor record."""

    return digest_object(dict(record), domain="observer-anchor-record-v1")


def verify_observer_anchor_record(
    record: Mapping[str, Any],
    *,
    expected_store_id: str,
    expected_previous_digest: str | None = None,
) -> dict[str, Any]:
    """Verify one exact record and its admitted subject shape."""

    _require_id(expected_store_id, "expected store id", synthetic=True)
    try:
        candidate = _freeze_mapping(record, "record")
        validate("observer-anchor-record", candidate)
        kind = ObserverAnchorSubjectKind(candidate["subject_kind"])
    except (KeyError, ValidationError, TypeError, ValueError) as exc:
        if isinstance(exc, ObserverAnchorError):
            raise
        raise ObserverAnchorError("observer anchor record schema rejected") from exc
    if candidate["anchor_id"] != observer_anchor_record_identity(candidate):
        raise ObserverAnchorError("observer anchor record identity mismatch")
    if candidate["store_id"] != expected_store_id:
        raise ObserverAnchorError("observer anchor store mismatch")
    if candidate["storage_boundary"] != _STORAGE_BOUNDARY:
        raise ObserverAnchorError("observer anchor storage boundary mismatch")
    subject, subject_digest = _subject_document(kind, candidate["subject"])
    if candidate["subject"] != subject or candidate["subject_digest"] != subject_digest:
        raise ObserverAnchorError("observer anchor subject digest mismatch")
    if candidate["sequence"] == 0:
        if candidate["previous_anchor_digest"] is not None:
            raise ObserverAnchorError("observer anchor initial chain rejected")
    elif (
        expected_previous_digest is not None
        and candidate["previous_anchor_digest"] != expected_previous_digest
    ):
        raise ObserverAnchorError("observer anchor previous digest mismatch")
    _parse_time(candidate["created_at"], "creation time")
    return candidate


def _cursor(record: Mapping[str, Any]) -> ObserverAnchorCursor:
    return ObserverAnchorCursor(
        store_id=record["store_id"],
        sequence=record["sequence"],
        anchor_id=record["anchor_id"],
        anchor_digest=observer_anchor_record_digest(record),
    )


def _assert_root_binding(root: Path, descriptor: Any) -> None:
    if os.name == "nt":
        from ._windows_files import (
            WindowsFileBoundaryError,
            assert_private_directory_acl,
        )
        from .windows_private_state import WindowsPrivateRoot

        if (
            not isinstance(descriptor, WindowsPrivateRoot)
            or descriptor.path != Path(os.path.abspath(root))
        ):
            raise ObserverAnchorError("observer anchor root is unsafe")
        try:
            assert_private_directory_acl(descriptor.path)
        except WindowsFileBoundaryError as exc:
            raise ObserverAnchorError("observer anchor root is unsafe") from exc
        return
    try:
        linked = root.lstat()
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise ObserverAnchorError("observer anchor root rejected") from exc
    if (
        stat.S_ISLNK(linked.st_mode)
        or not stat.S_ISDIR(linked.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
        or (linked.st_dev, linked.st_ino) != (opened.st_dev, opened.st_ino)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) != 0o700
    ):
        raise ObserverAnchorError("observer anchor root is unsafe")


def _prepare_root(root: Path, *, create: bool) -> tuple[Path, Any]:
    candidate = Path(root).absolute()
    if os.name == "nt":
        from .windows_private_state import (
            WindowsPrivateRoot,
            WindowsPrivateStateError,
        )

        try:
            handle = WindowsPrivateRoot(candidate, create=create)
            return handle.path, handle
        except WindowsPrivateStateError as exc:
            raise ObserverAnchorError("observer anchor root rejected") from exc
    try:
        if create:
            candidate.mkdir(mode=0o700, parents=True, exist_ok=False)
        details = candidate.lstat()
    except (FileExistsError, FileNotFoundError, OSError) as exc:
        raise ObserverAnchorError("observer anchor root rejected") from exc
    if (
        stat.S_ISLNK(details.st_mode)
        or not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != 0o700
    ):
        raise ObserverAnchorError("observer anchor root is unsafe")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(candidate, flags)
        _assert_root_binding(candidate, descriptor)
    except OSError as exc:
        raise ObserverAnchorError("observer anchor root rejected") from exc
    except Exception:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    return candidate, descriptor


def _read_record(root: Path, root_descriptor: Any) -> dict[str, Any]:
    _assert_root_binding(root, root_descriptor)
    if os.name == "nt":
        from .windows_private_state import (
            WindowsPrivateStateError,
            read_private_bytes,
        )

        try:
            payload = read_private_bytes(
                root / OBSERVER_ANCHOR_FILE_NAME,
                maximum_bytes=MAX_OBSERVER_ANCHOR_BYTES,
            )
            record = parse_json_strict(payload)
            if not isinstance(record, dict) or canonical_bytes(record) != payload:
                raise ObserverAnchorError(
                    "observer anchor file is not canonical"
                )
            return record
        except WindowsPrivateStateError as exc:
            raise ObserverAnchorError("observer anchor file rejected") from exc
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(
            OBSERVER_ANCHOR_FILE_NAME,
            flags,
            dir_fd=root_descriptor,
        )
        details = os.fstat(descriptor)
        linked = os.stat(
            OBSERVER_ANCHOR_FILE_NAME,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(details.st_mode)
            or not stat.S_ISREG(linked.st_mode)
            or (details.st_dev, details.st_ino) != (linked.st_dev, linked.st_ino)
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_size > MAX_OBSERVER_ANCHOR_BYTES
        ):
            raise ObserverAnchorError("observer anchor file is unsafe")
        chunks: list[bytes] = []
        remaining = MAX_OBSERVER_ANCHOR_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > MAX_OBSERVER_ANCHOR_BYTES:
            raise ObserverAnchorError("observer anchor file is too large")
        record = parse_json_strict(payload)
        if not isinstance(record, dict) or canonical_bytes(record) != payload:
            raise ObserverAnchorError("observer anchor file is not canonical")
        return record
    except FileNotFoundError as exc:
        raise ObserverAnchorError("observer anchor file is missing") from exc
    except OSError as exc:
        raise ObserverAnchorError("observer anchor file rejected") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_record(
    root: Path,
    root_descriptor: Any,
    record: Mapping[str, Any],
) -> None:
    _assert_root_binding(root, root_descriptor)
    payload = canonical_bytes(dict(record))
    if len(payload) > MAX_OBSERVER_ANCHOR_BYTES:
        raise ObserverAnchorError("observer anchor record is too large")
    if os.name == "nt":
        from .windows_private_state import (
            WindowsPrivateStateError,
            replace_private_bytes,
        )

        try:
            replace_private_bytes(
                root / OBSERVER_ANCHOR_FILE_NAME,
                payload,
            )
            return
        except WindowsPrivateStateError as exc:
            raise ObserverAnchorError(
                "observer anchor atomic write rejected"
            ) from exc
    temporary = f".observer-anchor.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600, dir_fd=root_descriptor)
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ObserverAnchorError("observer anchor write failed")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.rename(
            temporary,
            OBSERVER_ANCHOR_FILE_NAME,
            src_dir_fd=root_descriptor,
            dst_dir_fd=root_descriptor,
        )
        os.fsync(root_descriptor)
        _assert_root_binding(root, root_descriptor)
    except OSError as exc:
        raise ObserverAnchorError("observer anchor atomic write rejected") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=root_descriptor)
        except FileNotFoundError:
            pass


def _root_lock_descriptor(root_descriptor: Any) -> int:
    if os.name == "nt":
        try:
            return int(root_descriptor.lock_descriptor)
        except (AttributeError, TypeError, ValueError) as exc:
            raise ObserverAnchorError("observer anchor root lock rejected") from exc
    if not isinstance(root_descriptor, int):
        raise ObserverAnchorError("observer anchor root lock rejected")
    return root_descriptor


def _close_root(root_descriptor: Any) -> None:
    if os.name == "nt":
        root_descriptor.close()
    else:
        os.close(root_descriptor)


def _lock_root(root_descriptor: Any, *, shared: bool = False) -> int:
    descriptor = _root_lock_descriptor(root_descriptor)
    try:
        if shared:
            lock_shared(descriptor)
        else:
            lock_exclusive(descriptor)
    except LocalLockError as exc:
        raise ObserverAnchorError("observer anchor local lock rejected") from exc
    return descriptor


def _new_record(
    *,
    store_id: str,
    sequence: int,
    previous_anchor_digest: str | None,
    subject_kind: ObserverAnchorSubjectKind,
    subject: Mapping[str, Any],
    created_at: str,
) -> dict[str, Any]:
    _require_id(store_id, "store id", synthetic=True)
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or not 0 <= sequence <= MAX_OBSERVER_ANCHOR_SEQUENCE
    ):
        raise ObserverAnchorError("observer anchor sequence rejected")
    if previous_anchor_digest is not None:
        _require_digest(previous_anchor_digest, "previous digest")
    _parse_time(created_at, "creation time")
    subject_document, subject_digest = _subject_document(subject_kind, subject)
    core = {
        "protocol": "integrity-guardian/observer-anchor-record/v1",
        "store_id": store_id,
        "sequence": sequence,
        "previous_anchor_digest": previous_anchor_digest,
        "subject_kind": subject_kind.value,
        "subject_digest": subject_digest,
        "subject": subject_document,
        "created_at": created_at,
        "storage_boundary": deepcopy(_STORAGE_BOUNDARY),
    }
    record = {
        "anchor_id": observer_anchor_record_identity(core),
        **core,
    }
    return verify_observer_anchor_record(
        record,
        expected_store_id=store_id,
        expected_previous_digest=previous_anchor_digest,
    )


class ObserverAnchorStore:
    """One descriptor-pinned, cursor-checked external anchor file."""

    def __init__(
        self,
        *,
        root: Path,
        root_descriptor: Any,
        store_id: str,
        record: Mapping[str, Any],
        externally_pinned: bool,
    ) -> None:
        self.root = root
        self.store_id = store_id
        self._root_descriptor = root_descriptor
        self._record = deepcopy(dict(record))
        self._externally_pinned = externally_pinned
        self._closed = False

    @classmethod
    def initialize(
        cls,
        root: Path,
        *,
        store_id: str,
        subject_kind: ObserverAnchorSubjectKind | str,
        subject: Mapping[str, Any],
        created_at: str,
    ) -> ObserverAnchorStore:
        """Create sequence zero and return its externally retainable cursor."""

        try:
            kind = ObserverAnchorSubjectKind(subject_kind)
        except ValueError as exc:
            raise ObserverAnchorError("observer anchor subject kind rejected") from exc
        prepared_root, descriptor = _prepare_root(root, create=True)
        lock_descriptor = _root_lock_descriptor(descriptor)
        try:
            _lock_root(descriptor)
            record = _new_record(
                store_id=store_id,
                sequence=0,
                previous_anchor_digest=None,
                subject_kind=kind,
                subject=subject,
                created_at=created_at,
            )
            _write_record(prepared_root, descriptor, record)
            persisted = verify_observer_anchor_record(
                _read_record(prepared_root, descriptor),
                expected_store_id=store_id,
            )
            return cls(
                root=prepared_root,
                root_descriptor=descriptor,
                store_id=store_id,
                record=persisted,
                externally_pinned=True,
            )
        except Exception:
            _close_root(descriptor)
            raise
        finally:
            try:
                unlock(lock_descriptor)
            except LocalLockError:
                pass

    @classmethod
    def open(
        cls,
        root: Path,
        *,
        store_id: str,
        expected_cursor: ObserverAnchorCursor | None = None,
        allow_unpinned_availability_recovery: bool = False,
    ) -> ObserverAnchorStore:
        """Open an exact pin, or explicitly degraded availability-only latest."""

        if expected_cursor is None and not allow_unpinned_availability_recovery:
            raise ObserverAnchorError("observer anchor external cursor required")
        if expected_cursor is not None and expected_cursor.store_id != store_id:
            raise ObserverAnchorError("observer anchor external cursor mismatch")
        prepared_root, descriptor = _prepare_root(root, create=False)
        lock_descriptor = _root_lock_descriptor(descriptor)
        try:
            _lock_root(descriptor, shared=True)
            record = verify_observer_anchor_record(
                _read_record(prepared_root, descriptor),
                expected_store_id=store_id,
            )
            cursor = _cursor(record)
            if expected_cursor is not None and cursor != expected_cursor:
                raise ObserverAnchorError("observer anchor external cursor rejected")
            return cls(
                root=prepared_root,
                root_descriptor=descriptor,
                store_id=store_id,
                record=record,
                externally_pinned=expected_cursor is not None,
            )
        except Exception:
            _close_root(descriptor)
            raise
        finally:
            try:
                unlock(lock_descriptor)
            except LocalLockError:
                pass

    def _assert_open(self) -> None:
        if self._closed:
            raise ObserverAnchorError("observer anchor store is closed")

    def close(self) -> None:
        if not self._closed:
            _close_root(self._root_descriptor)
            self._closed = True

    def __enter__(self) -> Self:
        self._assert_open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def cursor(self) -> ObserverAnchorCursor:
        self._assert_open()
        return _cursor(self._record)

    @property
    def recovery(self) -> ObserverAnchorRecovery:
        self._assert_open()
        return ObserverAnchorRecovery(
            record=deepcopy(self._record),
            cursor=self.cursor,
            externally_pinned=self._externally_pinned,
        )

    def advance(
        self,
        *,
        expected_cursor: ObserverAnchorCursor,
        subject_kind: ObserverAnchorSubjectKind | str,
        subject: Mapping[str, Any],
        created_at: str,
    ) -> ObserverAnchorCursor:
        """Replace the local anchor exactly once from one pinned current head."""

        self._assert_open()
        if not isinstance(expected_cursor, ObserverAnchorCursor):
            raise ObserverAnchorError("observer anchor expected cursor rejected")
        try:
            kind = ObserverAnchorSubjectKind(subject_kind)
        except ValueError as exc:
            raise ObserverAnchorError("observer anchor subject kind rejected") from exc
        lock_descriptor = _lock_root(self._root_descriptor)
        try:
            current = verify_observer_anchor_record(
                _read_record(self.root, self._root_descriptor),
                expected_store_id=self.store_id,
            )
            current_cursor = _cursor(current)
            if current_cursor != expected_cursor or current_cursor != self.cursor:
                raise ObserverAnchorError("observer anchor stale cursor rejected")
            if current["sequence"] >= MAX_OBSERVER_ANCHOR_SEQUENCE:
                raise ObserverAnchorError("observer anchor sequence exhausted")
            if _parse_time(created_at, "creation time") < _parse_time(
                current["created_at"],
                "current creation time",
            ):
                raise ObserverAnchorError("observer anchor clock rollback")
            next_record = _new_record(
                store_id=self.store_id,
                sequence=current["sequence"] + 1,
                previous_anchor_digest=observer_anchor_record_digest(current),
                subject_kind=kind,
                subject=subject,
                created_at=created_at,
            )
            _write_record(self.root, self._root_descriptor, next_record)
            persisted = verify_observer_anchor_record(
                _read_record(self.root, self._root_descriptor),
                expected_store_id=self.store_id,
                expected_previous_digest=observer_anchor_record_digest(current),
            )
            if persisted != next_record:
                raise ObserverAnchorError("observer anchor post-write mismatch")
            self._record = persisted
            self._externally_pinned = True
            return self.cursor
        finally:
            unlock(lock_descriptor)
