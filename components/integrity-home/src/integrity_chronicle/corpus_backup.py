"""Verified backup and restore for one Integrity Home corpus generation.

The backup contains the private SQLite corpus, its identifier-only deletion
ledger, and an unsigned hash manifest. Callers must protect the resulting
archive like the source corpus; this module never uploads or opens network
connections.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import struct
import shutil
import tempfile
from typing import Any, BinaryIO, Dict, Iterable, Tuple
import zipfile

from .deletion_ledger import (
    DeletionLedgerError,
    conversation_selector,
    deletion_ledger_path,
    load_deletion_ledger,
    validate_deletion_ledger,
    write_deletion_ledger,
)
from .json_integrity import loads_json_strict
from .state_lock import CorpusStateLockError, corpus_state_lock


CORPUS_BACKUP_SCHEMA_VERSION = "integrity-home-corpus-backup/1"
SHARED_BACKUP_SCHEMA_VERSION = "integrity-home-corpus-backup/2"
_V1_BACKUP_MEMBERS = {"corpus.sqlite", "deletion-ledger.json", "manifest.json"}
_V2_BACKUP_MEMBERS = _V1_BACKUP_MEMBERS | {"history.sqlite"}

# Restore intentionally accepts only classic archives created by this module:
# all members are stored (not compressed), have a fixed name, and are bounded
# before any archive member is copied to disk. Python starts emitting ZIP64 at
# ``ZIP64_LIMIT`` (currently 2 GiB), so create and restore share a deliberately
# lower total ceiling with room for local/central headers.
MAX_BACKUP_MANIFEST_BYTES = 1 << 20
MAX_BACKUP_LEDGER_BYTES = 64 << 20
_CLASSIC_ZIP_OVERHEAD_ALLOWANCE = 2 << 20
MAX_BACKUP_TOTAL_BYTES = zipfile.ZIP64_LIMIT - _CLASSIC_ZIP_OVERHEAD_ALLOWANCE
MAX_BACKUP_CORPUS_BYTES = MAX_BACKUP_TOTAL_BYTES
MAX_BACKUP_HISTORY_BYTES = MAX_BACKUP_TOTAL_BYTES
# ``ZipFile`` reads the complete central directory into memory while opening an
# archive.  Bound and validate that structure ourselves before handing the file
# to ``ZipFile``.  Archives created here contain only three short ASCII names,
# so one MiB leaves ample forward-compatible headroom without making hostile
# metadata an unbounded allocation.
MAX_BACKUP_CENTRAL_DIRECTORY_BYTES = 1 << 20
MAX_BACKUP_ARCHIVE_BYTES = zipfile.ZIP64_LIMIT
_PRIVATE_FILE_MODE = 0o600

_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"
_EOCD_STRUCT = struct.Struct("<4s4H2LH")
_CENTRAL_DIRECTORY_STRUCT = struct.Struct("<4s6H3L5H2L")
_MAX_ZIP_COMMENT_BYTES = (1 << 16) - 1


class CorpusBackupError(RuntimeError):
    """Raised when backup or restore cannot preserve verified corpus state."""


def _history_sidecar_path(index_path: str | Path) -> Path:
    index = Path(index_path).resolve()
    return (
        index.with_name("history.sqlite")
        if index.name == "corpus.sqlite"
        else Path(f"{index}.history.sqlite")
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stable_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _ensure_private_file(path: Path) -> None:
    """Force a private POSIX mode and fail instead of publishing loosely."""

    if os.name == "nt":
        return
    os.chmod(path, _PRIVATE_FILE_MODE)
    if path.stat().st_mode & 0o777 != _PRIVATE_FILE_MODE:
        raise CorpusBackupError(f"cannot enforce private file mode: {path}")


def _create_private_empty_file(path: Path) -> None:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, _PRIVATE_FILE_MODE)
    os.close(descriptor)
    _ensure_private_file(path)


def _write_private_bytes(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, _PRIVATE_FILE_MODE)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    _ensure_private_file(path)


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    _write_private_bytes(
        path,
        (
            json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        ).encode("utf-8"),
    )


def _sync_file(path: Path) -> None:
    # Windows requires a writable descriptor for FlushFileBuffers/fsync.
    with path.open("r+b") as stream:
        os.fsync(stream.fileno())


def _sync_parent_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_resource_sizes(sizes: Dict[str, int]) -> None:
    if set(sizes) not in (_V1_BACKUP_MEMBERS, _V2_BACKUP_MEMBERS):
        raise CorpusBackupError("backup resource accounting is incomplete")
    limits = {
        "manifest.json": MAX_BACKUP_MANIFEST_BYTES,
        "deletion-ledger.json": MAX_BACKUP_LEDGER_BYTES,
        "corpus.sqlite": MAX_BACKUP_CORPUS_BYTES,
        "history.sqlite": MAX_BACKUP_HISTORY_BYTES,
    }
    for name, size in sizes.items():
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise CorpusBackupError(f"backup member has invalid size: {name}")
        if size > limits[name]:
            raise CorpusBackupError(f"backup member exceeds resource limit: {name}")
    total_size = sum(sizes.values())
    if total_size > MAX_BACKUP_TOTAL_BYTES:
        raise CorpusBackupError("backup archive exceeds total resource limit")
    # Keep this dynamic check as defense in depth and as a regression seam:
    # even a runtime with a lower ZIP64 threshold must never create an archive
    # that the restore contract will reject.
    classic_total_limit = zipfile.ZIP64_LIMIT - _CLASSIC_ZIP_OVERHEAD_ALLOWANCE
    if classic_total_limit < 0 or total_size > classic_total_limit:
        raise CorpusBackupError("backup exceeds the classic ZIP format limit")


def _validate_source_corpus_size(index_path: str) -> None:
    """Reject an over-limit source before SQLite opens or snapshots it."""

    source = Path(index_path)
    try:
        size = source.stat().st_size
    except OSError as err:
        raise CorpusBackupError(f"cannot inspect corpus before backup: {err}") from err
    if size > MAX_BACKUP_CORPUS_BYTES:
        raise CorpusBackupError("backup member exceeds resource limit: corpus.sqlite")


def _contains_zip64_extra(extra: bytes) -> bool:
    cursor = 0
    while cursor < len(extra):
        if len(extra) - cursor < 4:
            raise CorpusBackupError("malformed backup central-directory extra field")
        field_id, field_size = struct.unpack_from("<HH", extra, cursor)
        cursor += 4
        if field_size > len(extra) - cursor:
            raise CorpusBackupError("malformed backup central-directory extra field")
        if field_id == 0x0001:
            return True
        cursor += field_size
    return False


def _find_eocd(tail: bytes, *, tail_offset: int, archive_size: int) -> Tuple[int, tuple]:
    """Return the unique end-anchored classic EOCD record from a bounded tail."""

    cursor = len(tail)
    while True:
        cursor = tail.rfind(_EOCD_SIGNATURE, 0, cursor)
        if cursor < 0:
            raise CorpusBackupError("backup archive has no valid end record")
        if len(tail) - cursor >= _EOCD_STRUCT.size:
            fields = _EOCD_STRUCT.unpack_from(tail, cursor)
            comment_size = fields[-1]
            absolute_offset = tail_offset + cursor
            if absolute_offset + _EOCD_STRUCT.size + comment_size == archive_size:
                return absolute_offset, fields


def _preflight_zip_container(stream: BinaryIO) -> Dict[str, Dict[str, int]]:
    """Bound and parse ZIP metadata before ``zipfile.ZipFile`` sees it.

    The restore format deliberately accepts classic, single-disk ZIP only.
    Rejecting ZIP64 keeps entry counts, offsets, and sizes independently
    checkable with fixed-width fields before the standard library allocates for
    the central directory.
    """

    try:
        stream.seek(0, os.SEEK_END)
        archive_size = stream.tell()
        if archive_size > MAX_BACKUP_ARCHIVE_BYTES:
            raise CorpusBackupError("backup archive exceeds container resource limit")
        if archive_size < _EOCD_STRUCT.size:
            raise CorpusBackupError("backup archive is truncated")

        tail_size = min(
            archive_size,
            _EOCD_STRUCT.size + _MAX_ZIP_COMMENT_BYTES,
        )
        tail_offset = archive_size - tail_size
        stream.seek(tail_offset)
        tail = stream.read(tail_size)
        if len(tail) != tail_size:
            raise CorpusBackupError("backup archive changed during preflight")
        eocd_offset, fields = _find_eocd(
            tail,
            tail_offset=tail_offset,
            archive_size=archive_size,
        )
        (
            _signature,
            disk_number,
            central_directory_disk,
            entries_on_disk,
            entry_count,
            central_directory_size,
            central_directory_offset,
            _comment_size,
        ) = fields

        zip64_sentinels = (
            entries_on_disk == 0xFFFF
            or entry_count == 0xFFFF
            or central_directory_size == 0xFFFFFFFF
            or central_directory_offset == 0xFFFFFFFF
        )
        if zip64_sentinels:
            raise CorpusBackupError("ZIP64 backup archives are not supported")
        if eocd_offset >= 20:
            stream.seek(eocd_offset - 20)
            if stream.read(4) == _ZIP64_LOCATOR_SIGNATURE:
                raise CorpusBackupError("ZIP64 backup archives are not supported")
        if disk_number != 0 or central_directory_disk != 0:
            raise CorpusBackupError("multi-disk backup archives are not supported")
        if entries_on_disk != entry_count:
            raise CorpusBackupError("backup archive entry count is inconsistent")
        if entry_count not in (len(_V1_BACKUP_MEMBERS), len(_V2_BACKUP_MEMBERS)):
            raise CorpusBackupError("backup archive member set mismatch")
        if central_directory_size > MAX_BACKUP_CENTRAL_DIRECTORY_BYTES:
            raise CorpusBackupError(
                "backup central directory exceeds resource limit"
            )
        if central_directory_offset + central_directory_size != eocd_offset:
            raise CorpusBackupError("backup central directory bounds are invalid")

        stream.seek(central_directory_offset)
        directory = stream.read(central_directory_size)
        if len(directory) != central_directory_size:
            raise CorpusBackupError("backup central directory is truncated")
    except CorpusBackupError:
        raise
    except (OSError, OverflowError, ValueError) as err:
        raise CorpusBackupError(f"cannot preflight backup archive: {err}") from err

    entries: Dict[str, Dict[str, int]] = {}
    cursor = 0
    for _ in range(entry_count):
        if len(directory) - cursor < _CENTRAL_DIRECTORY_STRUCT.size:
            raise CorpusBackupError("backup central directory is truncated")
        fields = _CENTRAL_DIRECTORY_STRUCT.unpack_from(directory, cursor)
        if fields[0] != _CENTRAL_DIRECTORY_SIGNATURE:
            if fields[0] in (_ZIP64_EOCD_SIGNATURE, _ZIP64_LOCATOR_SIGNATURE):
                raise CorpusBackupError("ZIP64 backup archives are not supported")
            raise CorpusBackupError("backup central directory is malformed")
        flag_bits = fields[3]
        compression = fields[4]
        compressed_size = fields[8]
        file_size = fields[9]
        filename_size = fields[10]
        extra_size = fields[11]
        comment_size = fields[12]
        disk_start = fields[13]
        local_header_offset = fields[16]
        if (
            compressed_size == 0xFFFFFFFF
            or file_size == 0xFFFFFFFF
            or disk_start == 0xFFFF
            or local_header_offset == 0xFFFFFFFF
        ):
            raise CorpusBackupError("ZIP64 backup archives are not supported")

        variable_size = filename_size + extra_size + comment_size
        entry_end = cursor + _CENTRAL_DIRECTORY_STRUCT.size + variable_size
        if entry_end > len(directory):
            raise CorpusBackupError("backup central directory is truncated")
        name_start = cursor + _CENTRAL_DIRECTORY_STRUCT.size
        name_bytes = directory[name_start : name_start + filename_size]
        extra_start = name_start + filename_size
        extra = directory[extra_start : extra_start + extra_size]
        if _contains_zip64_extra(extra):
            raise CorpusBackupError("ZIP64 backup archives are not supported")
        try:
            name = name_bytes.decode("ascii")
        except UnicodeDecodeError as err:
            raise CorpusBackupError("backup archive member name is not ASCII") from err
        if name in entries:
            raise CorpusBackupError("backup archive contains duplicate members")
        if flag_bits & 0x41:
            raise CorpusBackupError(f"encrypted backup member is not allowed: {name}")
        if compression != zipfile.ZIP_STORED:
            raise CorpusBackupError(f"compressed backup member is not allowed: {name}")
        if compressed_size != file_size:
            raise CorpusBackupError(f"stored backup member size mismatch: {name}")
        if disk_start != 0 or local_header_offset >= central_directory_offset:
            raise CorpusBackupError("backup member location is invalid")
        entries[name] = {
            "file_size": file_size,
            "compress_size": compressed_size,
            "header_offset": local_header_offset,
        }
        cursor = entry_end

    if cursor != len(directory) or set(entries) not in (
        _V1_BACKUP_MEMBERS, _V2_BACKUP_MEMBERS,
    ):
        raise CorpusBackupError("backup archive member set mismatch")
    _validate_resource_sizes(
        {name: metadata["file_size"] for name, metadata in entries.items()}
    )
    return entries


def _manifest_digest(payload: Dict[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("manifest_sha256", None)
    return sha256(_stable_json(unsigned).encode("utf-8")).hexdigest()


def _validate_manifest(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise CorpusBackupError("backup manifest must be an object")
    expected_fields = {
        "schema_version",
        "created_at_utc",
        "contains_private_corpus_content",
        "corpus_id",
        "index_generation",
        "tombstone_digest",
        "source_count",
        "conversation_count",
        "message_count",
        "files",
        "manifest_sha256",
    }
    if set(payload) != expected_fields:
        raise CorpusBackupError("backup manifest has unexpected fields")
    schema_version = payload.get("schema_version")
    if schema_version not in (
        CORPUS_BACKUP_SCHEMA_VERSION, SHARED_BACKUP_SCHEMA_VERSION,
    ):
        raise CorpusBackupError("backup manifest schema mismatch")
    if payload.get("contains_private_corpus_content") is not True:
        raise CorpusBackupError("backup privacy classification is missing")
    files = payload.get("files")
    expected_files = {"corpus.sqlite", "deletion-ledger.json"}
    if schema_version == SHARED_BACKUP_SCHEMA_VERSION:
        expected_files.add("history.sqlite")
    if not isinstance(files, dict) or set(files) != expected_files:
        raise CorpusBackupError("backup manifest file set mismatch")
    for name, metadata in files.items():
        if not isinstance(metadata, dict) or set(metadata) != {"sha256", "size_bytes"}:
            raise CorpusBackupError(f"backup manifest has invalid metadata for {name}")
        digest = metadata.get("sha256")
        size = metadata.get("size_bytes")
        if not isinstance(digest, str) or len(digest) != 64:
            raise CorpusBackupError(f"backup manifest has invalid digest for {name}")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise CorpusBackupError(f"backup manifest has invalid size for {name}")
    if payload.get("manifest_sha256") != _manifest_digest(payload):
        raise CorpusBackupError("backup manifest digest mismatch")
    return dict(payload)


def _rows_from_ledger(payload: Dict[str, Any]) -> list[Tuple[str, str, str, str]]:
    return [
        (
            selector["selector_id"],
            selector["source_id"],
            selector["conversation_id"],
            selector["selector_type"],
        )
        for selector in payload["selectors"]
    ]


def _backup_corpus_state_with_ledger_locked(
    index_path: str,
    backup_path: str,
    *,
    authoritative_ledger_path: Path,
) -> Dict[str, Any]:
    """Create one atomic, locally verified backup while corpus state is locked."""

    from .corpus_index import (
        DELETION_LEDGER_BINDING_META_KEY,
        CorpusIndexError,
        _ledger_binding_value,
        _open_readonly_index,
        _summary,
        _validate_existing_index,
    )

    target = Path(backup_path)
    if target.exists():
        raise CorpusBackupError(f"backup target already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    _validate_source_corpus_size(index_path)
    try:
        ledger = load_deletion_ledger(
            index_path,
            ledger_path=str(authoritative_ledger_path),
        )
    except DeletionLedgerError as err:
        raise CorpusBackupError(str(err)) from err
    assert ledger is not None

    with tempfile.TemporaryDirectory(
        prefix="integrity-home-backup-", dir=target.parent
    ) as temporary_root:
        staging = Path(temporary_root)
        staged_index = staging / "corpus.sqlite"
        staged_ledger = staging / "deletion-ledger.json"
        staged_sidecar = staging / "history.sqlite"
        staged_manifest = staging / "manifest.json"
        staged_archive = staging / "backup.zip"

        try:
            _create_private_empty_file(staged_index)
            source = _open_readonly_index(index_path)
            destination = sqlite3.connect(str(staged_index))
            try:
                summary = _summary(source)
                source.backup(destination)
                # The archive is portable: never preserve an absolute binding
                # to the source host's shared deletion ledger.
                destination.execute(
                    "INSERT OR REPLACE INTO corpus_meta(key, value) VALUES (?, ?)",
                    (
                        DELETION_LEDGER_BINDING_META_KEY,
                        _ledger_binding_value(
                            index_path, deletion_ledger_path(index_path)
                        ),
                    ),
                )
                destination.commit()
            finally:
                source.close()
                destination.close()
            # A large WAL can make the consistent SQLite snapshot larger than
            # the source file checked above. Reject that result before an
            # integrity scan or full-file hash, while retaining the complete
            # final accounting check below.
            if staged_index.stat().st_size > MAX_BACKUP_CORPUS_BYTES:
                raise CorpusBackupError(
                    "backup member exceeds resource limit: corpus.sqlite"
                )
            check = sqlite3.connect(staged_index)
            try:
                if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise CorpusBackupError("staged backup SQLite integrity check failed")
                if _validate_existing_index(check) != _rows_from_ledger(ledger):
                    raise CorpusBackupError("staged backup and deletion ledger disagree")
            finally:
                check.close()
        except (sqlite3.DatabaseError, CorpusIndexError) as err:
            raise CorpusBackupError(f"cannot snapshot corpus: {err}") from err

        _write_json(staged_ledger, ledger)
        source_sidecar = _history_sidecar_path(index_path)
        has_history = source_sidecar.is_file()
        if has_history:
            from integrity_home.history.sidecar import inspect_history_sidecar

            inspect_history_sidecar(index_path, str(source_sidecar))
            shutil.copyfile(source_sidecar, staged_sidecar)
            _ensure_private_file(staged_sidecar)
            portable_ledger = deletion_ledger_path(str(staged_index))
            shutil.copyfile(staged_ledger, portable_ledger)
            try:
                inspect_history_sidecar(str(staged_index), str(staged_sidecar))
            finally:
                portable_ledger.unlink(missing_ok=True)
        manifest: Dict[str, Any] = {
            "schema_version": (
                SHARED_BACKUP_SCHEMA_VERSION if has_history
                else CORPUS_BACKUP_SCHEMA_VERSION
            ),
            "created_at_utc": _utc_now(),
            "contains_private_corpus_content": True,
            "corpus_id": summary["corpus_id"],
            "index_generation": summary["index_generation"],
            "tombstone_digest": summary["tombstone_digest"],
            "source_count": summary["source_count"],
            "conversation_count": summary["conversation_count"],
            "message_count": summary["message_count"],
            "files": {
                "corpus.sqlite": {
                    "sha256": _sha256_file(staged_index),
                    "size_bytes": staged_index.stat().st_size,
                },
                "deletion-ledger.json": {
                    "sha256": _sha256_file(staged_ledger),
                    "size_bytes": staged_ledger.stat().st_size,
                },
            },
        }
        if has_history:
            manifest["files"]["history.sqlite"] = {
                "sha256": _sha256_file(staged_sidecar),
                "size_bytes": staged_sidecar.stat().st_size,
            }
        manifest["manifest_sha256"] = _manifest_digest(manifest)
        _write_json(staged_manifest, manifest)
        resource_sizes = {
            "corpus.sqlite": staged_index.stat().st_size,
            "deletion-ledger.json": staged_ledger.stat().st_size,
            "manifest.json": staged_manifest.stat().st_size,
        }
        if has_history:
            resource_sizes["history.sqlite"] = staged_sidecar.stat().st_size
        _validate_resource_sizes(resource_sizes)
        _create_private_empty_file(staged_archive)
        try:
            with zipfile.ZipFile(
                staged_archive,
                "w",
                compression=zipfile.ZIP_STORED,
                allowZip64=False,
            ) as archive:
                archive.write(staged_index, "corpus.sqlite")
                archive.write(staged_ledger, "deletion-ledger.json")
                if has_history:
                    archive.write(staged_sidecar, "history.sqlite")
                archive.write(staged_manifest, "manifest.json")
        except zipfile.LargeZipFile as err:
            raise CorpusBackupError(
                "backup exceeds the classic ZIP format limit"
            ) from err
        _ensure_private_file(staged_archive)
        _sync_file(staged_archive)
        os.replace(staged_archive, target)
        _ensure_private_file(target)
        _sync_parent_directory(target.parent)
    return {**manifest, "backup_path": str(target.resolve())}


def _backup_corpus_state_locked(index_path: str, backup_path: str) -> Dict[str, Any]:
    """Resolve and lock the immutable ledger binding under the index lock."""

    from .corpus_index import CorpusIndexError, _bound_deletion_ledger_path

    try:
        authoritative_ledger_path = _bound_deletion_ledger_path(index_path)
        with corpus_state_lock(str(authoritative_ledger_path)):
            return _backup_corpus_state_with_ledger_locked(
                index_path,
                backup_path,
                authoritative_ledger_path=authoritative_ledger_path,
            )
    except (CorpusIndexError, CorpusStateLockError) as err:
        raise CorpusBackupError(str(err)) from err


def backup_corpus_state(index_path: str, backup_path: str) -> Dict[str, Any]:
    """Create one atomic, locally verified backup archive."""

    try:
        sidecar = _history_sidecar_path(index_path)
        if sidecar.is_file():
            with corpus_state_lock(str(sidecar)):
                with corpus_state_lock(index_path):
                    return _backup_corpus_state_locked(index_path, backup_path)
        with corpus_state_lock(index_path):
            return _backup_corpus_state_locked(index_path, backup_path)
    except CorpusStateLockError as err:
        raise CorpusBackupError(str(err)) from err


def _read_member_bounded(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    maximum_bytes: int,
) -> bytes:
    chunks: list[bytes] = []
    copied = 0
    with archive.open(info, "r") as source:
        while True:
            chunk = source.read(min(1 << 20, maximum_bytes - copied + 1))
            if not chunk:
                break
            copied += len(chunk)
            if copied > maximum_bytes or copied > info.file_size:
                raise CorpusBackupError(
                    f"backup member exceeds declared size: {info.filename}"
                )
            chunks.append(chunk)
    if copied != info.file_size:
        raise CorpusBackupError(f"backup member size changed: {info.filename}")
    return b"".join(chunks)


def _preflight_archive(
    archive: zipfile.ZipFile,
    container_entries: Dict[str, Dict[str, int]],
) -> Tuple[Dict[str, zipfile.ZipInfo], Dict[str, Any], bytes]:
    entries = archive.infolist()
    names = [entry.filename for entry in entries]
    member_set = set(names)
    if len(names) != len(member_set) or member_set not in (
        _V1_BACKUP_MEMBERS, _V2_BACKUP_MEMBERS,
    ):
        raise CorpusBackupError("backup archive member set mismatch")

    infos = {entry.filename: entry for entry in entries}
    for name, info in infos.items():
        container = container_entries.get(name)
        if container is None or (
            info.file_size != container["file_size"]
            or info.compress_size != container["compress_size"]
            or info.header_offset != container["header_offset"]
        ):
            raise CorpusBackupError("backup archive metadata changed during preflight")
        if info.is_dir() or info.filename != name:
            raise CorpusBackupError(f"invalid backup member: {name}")
        if info.flag_bits & 0x41:
            raise CorpusBackupError(f"encrypted backup member is not allowed: {name}")
        if info.compress_type != zipfile.ZIP_STORED:
            raise CorpusBackupError(f"compressed backup member is not allowed: {name}")
        if info.compress_size != info.file_size:
            raise CorpusBackupError(f"stored backup member size mismatch: {name}")

    _validate_resource_sizes(
        {name: info.file_size for name, info in infos.items()}
    )
    manifest_bytes = _read_member_bounded(
        archive,
        infos["manifest.json"],
        maximum_bytes=MAX_BACKUP_MANIFEST_BYTES,
    )
    try:
        manifest = _validate_manifest(
            loads_json_strict(manifest_bytes.decode("utf-8"))
        )
    except (UnicodeDecodeError, ValueError) as err:
        raise CorpusBackupError(f"invalid backup metadata: {err}") from err

    expected_members = set(manifest["files"]) | {"manifest.json"}
    if member_set != expected_members:
        raise CorpusBackupError("backup archive and manifest member sets disagree")
    for name in manifest["files"]:
        if infos[name].file_size != manifest["files"][name]["size_bytes"]:
            raise CorpusBackupError(f"backup size mismatch: {name}")
    return infos, manifest, manifest_bytes


def _copy_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    destination: Path,
    *,
    expected_size: int,
    expected_sha256: str,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(destination, flags, _PRIVATE_FILE_MODE)
    copied = 0
    digest = sha256()
    try:
        with archive.open(info, "r") as source, os.fdopen(descriptor, "wb") as target:
            descriptor = -1
            while True:
                chunk = source.read(min(1 << 20, expected_size - copied + 1))
                if not chunk:
                    break
                copied += len(chunk)
                if copied > expected_size:
                    raise CorpusBackupError(
                        f"backup member exceeds declared size: {info.filename}"
                    )
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        if copied != expected_size:
            raise CorpusBackupError(f"backup size mismatch: {info.filename}")
        if digest.hexdigest() != expected_sha256:
            raise CorpusBackupError(f"backup digest mismatch: {info.filename}")
        _ensure_private_file(destination)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _restore_corpus_state_locked(
    backup_path: str,
    index_path: str,
    *,
    replace: bool = False,
) -> Dict[str, Any]:
    """Restore a verified backup while destination corpus state is locked."""

    from .corpus_index import (
        DELETION_LEDGER_BINDING_META_KEY,
        CorpusIndexError,
        _bound_deletion_ledger_path,
        _ledger_binding_value,
        _apply_tombstone_rows,
        _merge_tombstone_rows,
        _publish_index_file,
        _store_logical_index_seal,
        _summary,
        _validate_existing_index,
        inspect_corpus_index,
    )

    source_path = Path(backup_path)
    target = Path(index_path)
    if not source_path.is_file():
        raise CorpusBackupError(f"backup archive does not exist: {source_path}")
    if target.exists() and not replace:
        raise CorpusBackupError(f"restore target already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix="integrity-home-restore-", dir=target.parent
    ) as temporary_root:
        staging = Path(temporary_root)
        staged_index = staging / "corpus.sqlite"
        staged_ledger = staging / "deletion-ledger.json"
        staged_sidecar = staging / "history.sqlite"
        staged_manifest = staging / "manifest.json"
        try:
            with source_path.open("rb") as archive_stream:
                # Bound and validate the complete central directory before
                # ZipFile parses or allocates for attacker-controlled metadata.
                container_entries = _preflight_zip_container(archive_stream)
                archive_stream.seek(0)
                with zipfile.ZipFile(archive_stream, "r") as archive:
                    # Complete all metadata, format, and resource checks before
                    # copying even the first member to the restore staging area.
                    infos, manifest, manifest_bytes = _preflight_archive(
                        archive, container_entries
                    )
                    target_sidecar = _history_sidecar_path(target)
                    if (
                        manifest["schema_version"] == CORPUS_BACKUP_SCHEMA_VERSION
                        and target_sidecar.exists()
                    ):
                        raise CorpusBackupError(
                            "corpus-only backup cannot replace a shared History target"
                        )
                    if (
                        manifest["schema_version"] == SHARED_BACKUP_SCHEMA_VERSION
                        and target_sidecar.exists() and not replace
                    ):
                        raise CorpusBackupError("restore History target already exists")
                    _write_private_bytes(staged_manifest, manifest_bytes)
                    destinations = {
                        "corpus.sqlite": staged_index,
                        "deletion-ledger.json": staged_ledger,
                        "history.sqlite": staged_sidecar,
                    }
                    for name in manifest["files"]:
                        destination = destinations[name]
                        metadata = manifest["files"][name]
                        _copy_member(
                            archive,
                            infos[name],
                            destination,
                            expected_size=metadata["size_bytes"],
                            expected_sha256=metadata["sha256"],
                        )
        except CorpusBackupError:
            raise
        except (OSError, EOFError, RuntimeError, zipfile.BadZipFile, KeyError) as err:
            raise CorpusBackupError(f"cannot read backup archive: {err}") from err

        try:
            backup_ledger = validate_deletion_ledger(
                loads_json_strict(staged_ledger.read_text(encoding="utf-8"))
            )
        except (
            OSError,
            UnicodeDecodeError,
            ValueError,
            DeletionLedgerError,
        ) as err:
            raise CorpusBackupError(f"invalid backup metadata: {err}") from err
        verified_paths = {
            "corpus.sqlite": staged_index,
            "deletion-ledger.json": staged_ledger,
            "history.sqlite": staged_sidecar,
        }
        for name in manifest["files"]:
            path = verified_paths[name]
            metadata = manifest["files"][name]
            if path.stat().st_size != metadata["size_bytes"]:
                raise CorpusBackupError(f"backup size mismatch: {name}")
            if _sha256_file(path) != metadata["sha256"]:
                raise CorpusBackupError(f"backup digest mismatch: {name}")

        destination_ledger_rows: Iterable[Tuple[str, str, str, str]] = []
        try:
            if target.exists():
                existing_ledger_path = _bound_deletion_ledger_path(index_path)
                adjacent_ledger_path = deletion_ledger_path(index_path).resolve(
                    strict=False
                )
                if existing_ledger_path != adjacent_ledger_path:
                    raise CorpusBackupError(
                        "restore replace refuses an external-bound deletion ledger"
                    )
            current_ledger = load_deletion_ledger(index_path, missing_ok=True)
        except (DeletionLedgerError, CorpusIndexError) as err:
            raise CorpusBackupError(str(err)) from err
        if target.exists() and current_ledger is None:
            raise CorpusBackupError(
                "existing restore target has no deletion ledger; refusing resurrection risk"
            )
        if current_ledger is not None:
            destination_ledger_rows = _rows_from_ledger(current_ledger)
        backup_rows = _rows_from_ledger(backup_ledger)
        history_snapshot = None
        if manifest["schema_version"] == SHARED_BACKUP_SCHEMA_VERSION:
            from integrity_home.unified_publication import (
                _capture_unified_sidecar_snapshot,
            )

            portable_ledger = deletion_ledger_path(str(staged_index))
            shutil.copyfile(staged_ledger, portable_ledger)
            try:
                try:
                    history_snapshot = _capture_unified_sidecar_snapshot(
                        str(staged_index), str(staged_sidecar)
                    )
                except (OSError, RuntimeError, ValueError) as err:
                    raise CorpusBackupError(
                        f"cannot validate archived History sidecar: {err}"
                    ) from err
            finally:
                portable_ledger.unlink(missing_ok=True)
        try:
            conn = sqlite3.connect(staged_index)
            try:
                backup_database_rows = _validate_existing_index(conn)
                if backup_database_rows != backup_rows:
                    raise CorpusBackupError("backup database and ledger disagree")
                durable_rows = _merge_tombstone_rows(
                    backup_rows, destination_ledger_rows
                )
                _apply_tombstone_rows(conn, durable_rows)
                # Restores are self-contained regardless of the binding stored
                # in the archived source generation.
                conn.execute(
                    "INSERT OR REPLACE INTO corpus_meta(key, value) VALUES (?, ?)",
                    (
                        DELETION_LEDGER_BINDING_META_KEY,
                        _ledger_binding_value(
                            index_path, deletion_ledger_path(index_path)
                        ),
                    ),
                )
                summary = _summary(conn)
                for key in ("corpus_id", "index_generation"):
                    conn.execute(
                        "INSERT OR REPLACE INTO corpus_meta(key, value) VALUES (?, ?)",
                        (key, summary[key]),
                    )
                conn.commit()
                _store_logical_index_seal(conn)
                if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise CorpusBackupError("restored SQLite integrity check failed")
                conn.commit()
            finally:
                conn.close()
        except (sqlite3.DatabaseError, CorpusIndexError) as err:
            raise CorpusBackupError(f"cannot validate restored corpus: {err}") from err

        selectors = [
            conversation_selector(source_id=row[1], conversation_id=row[2])
            for row in durable_rows
        ]
        try:
            # Publish negative history first.  A failed SQLite replace leaves
            # reads fail-closed and a retry can finish deterministically.
            write_deletion_ledger(index_path, selectors)
            _ensure_private_file(deletion_ledger_path(index_path))
            _ensure_private_file(staged_index)
            _publish_index_file(staged_index, target)
            _ensure_private_file(target)
            if history_snapshot is not None:
                from integrity_home.unified_publication import (
                    _rebuild_unified_sidecar_from_snapshot,
                )

                try:
                    _rebuild_unified_sidecar_from_snapshot(
                        str(target), str(staged_sidecar), history_snapshot,
                    )
                except (OSError, RuntimeError, ValueError) as err:
                    raise CorpusBackupError(
                        f"cannot rebuild restored History sidecar: {err}"
                    ) from err
                restored_sidecar = _history_sidecar_path(target)
                _ensure_private_file(staged_sidecar)
                os.replace(staged_sidecar, restored_sidecar)
                _ensure_private_file(restored_sidecar)
            _sync_parent_directory(target.parent)
            restored = inspect_corpus_index(index_path)
            if history_snapshot is not None:
                from integrity_home.history.sidecar import inspect_history_sidecar

                restored["history"] = inspect_history_sidecar(
                    index_path, str(_history_sidecar_path(target))
                )
        except (DeletionLedgerError, CorpusIndexError, OSError) as err:
            raise CorpusBackupError(f"cannot publish restored corpus: {err}") from err
    return {
        **restored,
        "backup_path": str(source_path.resolve()),
        "index_path": str(target.resolve()),
        "replayed_tombstone_count": len(durable_rows) - len(backup_rows),
    }


def restore_corpus_state(
    backup_path: str,
    index_path: str,
    *,
    replace: bool = False,
) -> Dict[str, Any]:
    """Restore a verified backup and replay all locally newer tombstones."""

    from .corpus_index import CorpusIndexError, _bound_deletion_ledger_path

    try:
        sidecar_path = _history_sidecar_path(index_path)
        with corpus_state_lock(str(sidecar_path)):
            with corpus_state_lock(index_path):
                # A fresh restore and an allowed replacement both publish to
                # the target's adjacent ledger. Keep its transaction lock
                # ordered after the index lock, matching corpus writers.
                adjacent_ledger_path = deletion_ledger_path(index_path).resolve(
                    strict=False
                )
                if replace and Path(index_path).exists():
                    existing_ledger_path = _bound_deletion_ledger_path(index_path)
                    if existing_ledger_path != adjacent_ledger_path:
                        raise CorpusBackupError(
                            "restore replace refuses an external-bound deletion ledger"
                        )
                with corpus_state_lock(str(adjacent_ledger_path)):
                    return _restore_corpus_state_locked(
                        backup_path,
                        index_path,
                        replace=replace,
                    )
    except (CorpusIndexError, CorpusStateLockError) as err:
        raise CorpusBackupError(str(err)) from err


__all__ = [
    "CORPUS_BACKUP_SCHEMA_VERSION",
    "SHARED_BACKUP_SCHEMA_VERSION",
    "MAX_BACKUP_ARCHIVE_BYTES",
    "MAX_BACKUP_CENTRAL_DIRECTORY_BYTES",
    "MAX_BACKUP_CORPUS_BYTES",
    "MAX_BACKUP_HISTORY_BYTES",
    "MAX_BACKUP_LEDGER_BYTES",
    "MAX_BACKUP_MANIFEST_BYTES",
    "MAX_BACKUP_TOTAL_BYTES",
    "CorpusBackupError",
    "backup_corpus_state",
    "restore_corpus_state",
]
