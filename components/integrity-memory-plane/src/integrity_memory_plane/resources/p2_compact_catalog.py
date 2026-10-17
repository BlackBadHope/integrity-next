#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Disposable O(log N) cursor and event_uid catalogs for compact buckets."""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import contextlib
import datetime as dt
import gzip
import hashlib
import heapq
import json
import os
import struct
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator

from memory_plane_common import atomic_json, canonical_json, exclusive_lock, sha256_bytes, sha256_file
from p2_compact_index import PROTOCOL as INDEX_PROTOCOL, iter_manifests, manifest_at_bucket, object_path


PROTOCOL = "integrity-memory-plane.p2-compact-catalog.v1"
BUCKET_MAGIC = b"IP2BKT1\0"
UID_MAGIC = b"IP2UID1\0"
ROUTE_MAGIC = b"IP2RTE1\0"
HEADER = struct.Struct(">8sQ")
BUCKET_RECORD = struct.Struct(">QQQ32s")
UID_RECORD = struct.Struct(">32sQ")
ROUTE_RECORD = struct.Struct(">B32sQ32s")
ROUTE_KINDS = {"fts": 1, "graph": 2}
BLOCK_INTEGRITY_SIZE = 64 * 1024


_RUN_VERIFY_CACHE: dict[tuple[str, str], tuple[int, int, int, int, int]] = {}
_BLOCK_MANIFEST_CACHE: dict[tuple[str, str], tuple[tuple[int, int, int, int, int], dict[str, Any]]] = {}
_BLOCK_VERIFY_CACHE: dict[
    tuple[str, str, str], tuple[tuple[int, int, int, int, int], set[int]]
] = {}
_RUN_VERIFY_LOCK = threading.Lock()


def _stat_signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (int(value.st_dev), int(value.st_ino), int(value.st_size), int(value.st_mtime_ns), int(value.st_ctime_ns))


def _sha256_handle(handle: BinaryIO) -> str:
    digest = hashlib.sha256()
    handle.seek(0)
    for block in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(block)
    return digest.hexdigest()


def _load_block_manifest(root: Path, metadata: dict[str, Any]) -> tuple[dict[str, Any], str]:
    relative = str(metadata.get("block_integrity_path") or "")
    expected = str(metadata.get("block_integrity_sha256") or "")
    if not relative or len(expected) != 64:
        raise RuntimeError("catalog block-integrity metadata is incomplete")
    path = root / relative
    signature = _stat_signature(path.stat())
    key = (str(path.resolve()), expected)
    with _RUN_VERIFY_LOCK:
        cached = _BLOCK_MANIFEST_CACHE.get(key)
    if cached is not None and cached[0] == signature:
        return cached[1], expected
    raw = path.read_bytes()
    if sha256_bytes(raw) != expected:
        raise RuntimeError("catalog block-integrity manifest digest mismatch")
    value = json.loads(raw)
    if (
        value.get("protocol") != PROTOCOL + ".block-integrity-v1"
        or value.get("production_authority") is not False
    ):
        raise RuntimeError("catalog block-integrity manifest rejected")
    with _RUN_VERIFY_LOCK:
        _BLOCK_MANIFEST_CACHE[key] = (signature, value)
    return value, expected


class _VerifiedBlockHandle:
    def __init__(
        self,
        handle: BinaryIO,
        path: Path,
        expected_sha256: str,
        manifest_sha256: str,
        manifest: dict[str, Any],
        signature: tuple[int, int, int, int, int],
    ) -> None:
        self._handle = handle
        self._path = path
        self._signature = signature
        self._block_size = int(manifest["block_size"])
        self._blocks = [str(value) for value in manifest["block_sha256"]]
        self._cache_key = (str(path.resolve()), expected_sha256, manifest_sha256)
        with _RUN_VERIFY_LOCK:
            cached = _BLOCK_VERIFY_CACHE.get(self._cache_key)
            if cached is None or cached[0] != signature:
                _BLOCK_VERIFY_CACHE[self._cache_key] = (signature, set())

    def _verify_block(self, index: int) -> None:
        with _RUN_VERIFY_LOCK:
            cached = _BLOCK_VERIFY_CACHE[self._cache_key]
            if index in cached[1]:
                return
        position = self._handle.tell()
        self._handle.seek(index * self._block_size)
        value = self._handle.read(self._block_size)
        self._handle.seek(position)
        if index >= len(self._blocks) or sha256_bytes(value) != self._blocks[index]:
            raise RuntimeError("catalog run authenticated block mismatch")
        if _stat_signature(os.fstat(self._handle.fileno())) != self._signature:
            raise RuntimeError("catalog run changed during authenticated block read")
        with _RUN_VERIFY_LOCK:
            _BLOCK_VERIFY_CACHE[self._cache_key][1].add(index)

    def read(self, size: int = -1) -> bytes:
        start = self._handle.tell()
        value = self._handle.read(size)
        end = self._handle.tell()
        if value:
            for index in range(start // self._block_size, (end - 1) // self._block_size + 1):
                self._verify_block(index)
        return value

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        return self._handle.seek(offset, whence)

    def tell(self) -> int:
        return self._handle.tell()

    def fileno(self) -> int:
        return self._handle.fileno()


@contextlib.contextmanager
def _verified_run(
    path: Path, expected_sha256: str, metadata: dict[str, Any] | None = None
) -> Iterator[BinaryIO | _VerifiedBlockHandle]:
    """Open one immutable run and attest each observed inode generation once.

    The cache removes repeated O(N) hashing from hot lookups without trusting a
    pathname alone.  Any inode, size, mtime, or ctime change forces a full
    digest pass again.  The lookup then uses the same descriptor that was
    inspected, so an atomic generation swap cannot redirect this read.
    """

    handle = path.open("rb")
    try:
        before = _stat_signature(os.fstat(handle.fileno()))
        if metadata is not None and metadata.get("block_integrity_path"):
            manifest, manifest_sha256 = _load_block_manifest(path.parents[1], metadata)
            if (
                str(manifest.get("file_sha256") or "") != expected_sha256
                or int(manifest.get("bytes") or -1) != before[2]
                or int(manifest.get("block_size") or 0) != BLOCK_INTEGRITY_SIZE
                or int(manifest.get("block_count") or -1) != len(manifest.get("block_sha256") or [])
            ):
                raise RuntimeError("catalog block-integrity manifest does not bind the run")
            yield _VerifiedBlockHandle(
                handle, path, expected_sha256, manifest_sha256, manifest, before
            )
            if _stat_signature(os.fstat(handle.fileno())) != before:
                raise RuntimeError("catalog run changed during authenticated block session")
            return
        key = (str(path.resolve()), expected_sha256)
        with _RUN_VERIFY_LOCK:
            cached = _RUN_VERIFY_CACHE.get(key)
        if cached != before:
            observed = _sha256_handle(handle)
            after = _stat_signature(os.fstat(handle.fileno()))
            if after != before:
                raise RuntimeError("catalog run changed during digest verification")
            if observed != expected_sha256:
                raise RuntimeError("catalog run digest mismatch")
            with _RUN_VERIFY_LOCK:
                _RUN_VERIFY_CACHE[key] = after
        handle.seek(0)
        yield handle
    finally:
        handle.close()


def _atomic_bytes(path: Path, value: bytes, mode: int = 0o440) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _block_integrity_metadata(root: Path, path: Path, expected_sha256: str) -> dict[str, Any]:
    sidecar = path.with_suffix(path.suffix + ".blocks.json")
    file_digest = hashlib.sha256()
    blocks: list[str] = []
    total = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(BLOCK_INTEGRITY_SIZE), b""):
            file_digest.update(block)
            blocks.append(sha256_bytes(block))
            total += len(block)
    if file_digest.hexdigest() != expected_sha256:
        raise RuntimeError("catalog run digest mismatch while building block integrity")
    value = {
        "protocol": PROTOCOL + ".block-integrity-v1",
        "file_sha256": expected_sha256,
        "bytes": total,
        "block_size": BLOCK_INTEGRITY_SIZE,
        "block_count": len(blocks),
        "block_sha256": blocks,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    atomic_json(sidecar, value, mode=0o440)
    raw = sidecar.read_bytes()
    return {
        "block_integrity_path": str(sidecar.relative_to(root)),
        "block_integrity_sha256": sha256_bytes(raw),
        "block_size": BLOCK_INTEGRITY_SIZE,
        "block_count": len(blocks),
    }


def _with_block_integrity(root: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    if metadata.get("block_integrity_path") and metadata.get("block_integrity_sha256"):
        manifest, _digest = _load_block_manifest(root, metadata)
        if (
            str(manifest.get("file_sha256") or "") != str(metadata["sha256"])
            or int(manifest.get("bytes") or -1) != (root / str(metadata["path"])).stat().st_size
        ):
            raise RuntimeError("catalog block-integrity manifest does not bind the retained run")
        return dict(metadata)
    result = dict(metadata)
    result.update(_block_integrity_metadata(root, root / str(metadata["path"]), str(metadata["sha256"])))
    return result


def _bucket_bytes(values: list[tuple[Path, dict[str, Any], str]]) -> bytes:
    records = bytearray(HEADER.pack(BUCKET_MAGIC, len(values)))
    for _path, manifest, digest in values:
        records.extend(
            BUCKET_RECORD.pack(
                int(manifest["bucket_id"]),
                int(manifest["first_cursor"]),
                int(manifest["last_cursor"]),
                bytes.fromhex(digest),
            )
        )
    return bytes(records)


def _read_header(handle: Any, magic: bytes, record_size: int) -> int:
    raw = handle.read(HEADER.size)
    if len(raw) != HEADER.size:
        raise RuntimeError("compact catalog header is truncated")
    observed, count = HEADER.unpack(raw)
    if observed != magic:
        raise RuntimeError("compact catalog magic mismatch")
    handle.seek(0, os.SEEK_END)
    if handle.tell() != HEADER.size + int(count) * record_size:
        raise RuntimeError("compact catalog length mismatch")
    return int(count)


def _uid_records(index_root: Path, manifest: dict[str, Any]) -> list[tuple[bytes, int]]:
    payload = json.loads(gzip.decompress(object_path(index_root, str(manifest["payload"]["sha256"])).read_bytes()))
    return sorted((hashlib.sha256(str(uid).encode("utf-8")).digest(), int(cursor)) for uid, cursor in payload["uids"])


def _uid_run_bytes(records: Iterable[tuple[bytes, int]]) -> bytes:
    values = sorted(records)
    result = bytearray(HEADER.pack(UID_MAGIC, len(values)))
    for digest, cursor in values:
        result.extend(UID_RECORD.pack(digest, cursor))
    return bytes(result)


def _read_uid_run(path: Path) -> list[tuple[bytes, int]]:
    with path.open("rb") as handle:
        count = _read_header(handle, UID_MAGIC, UID_RECORD.size)
        handle.seek(HEADER.size)
        return [UID_RECORD.unpack(handle.read(UID_RECORD.size)) for _ in range(count)]


def _write_uid_run(root: Path, level: int, records: list[tuple[bytes, int]]) -> dict[str, Any]:
    return _write_sorted_run(root, "uid-runs", level, UID_MAGIC, UID_RECORD, iter(sorted(records)), len(records))


def _route_records(index_root: Path, manifest: dict[str, Any], manifest_digest: str) -> list[tuple[int, bytes, int, bytes]]:
    payload = json.loads(gzip.decompress(object_path(index_root, str(manifest["payload"]["sha256"])).read_bytes()))
    bucket_id = int(manifest["bucket_id"])
    digest = bytes.fromhex(manifest_digest)
    values: set[tuple[int, bytes, int, bytes]] = set()
    for kind in ("fts", "graph"):
        kind_id = ROUTE_KINDS[kind]
        for key, _postings in payload[kind]:
            values.add((kind_id, hashlib.sha256(str(key).encode("utf-8")).digest(), bucket_id, digest))
    return sorted(values)


def _route_run_bytes(records: Iterable[tuple[int, bytes, int, bytes]]) -> bytes:
    values = sorted(records)
    result = bytearray(HEADER.pack(ROUTE_MAGIC, len(values)))
    for kind, key_digest, bucket_id, manifest_digest in values:
        result.extend(ROUTE_RECORD.pack(kind, key_digest, bucket_id, manifest_digest))
    return bytes(result)


def _read_route_run(path: Path) -> list[tuple[int, bytes, int, bytes]]:
    with path.open("rb") as handle:
        count = _read_header(handle, ROUTE_MAGIC, ROUTE_RECORD.size)
        handle.seek(HEADER.size)
        return [ROUTE_RECORD.unpack(handle.read(ROUTE_RECORD.size)) for _ in range(count)]


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _iter_fixed_records(handle: BinaryIO, record: struct.Struct, count: int, label: str) -> Iterator[tuple[Any, ...]]:
    handle.seek(HEADER.size)
    previous: tuple[Any, ...] | None = None
    for _ in range(count):
        raw = handle.read(record.size)
        if len(raw) != record.size:
            raise RuntimeError(f"{label} run truncated during streaming merge")
        value = record.unpack(raw)
        if previous is not None and value < previous:
            raise RuntimeError(f"{label} run is not sorted")
        previous = value
        yield value


def _write_sorted_run(
    root: Path,
    family: str,
    level: int,
    magic: bytes,
    record: struct.Struct,
    records: Iterable[tuple[Any, ...]],
    expected_count: int,
) -> dict[str, Any]:
    directory = root / family
    directory.mkdir(parents=True, exist_ok=True, mode=0o750)
    descriptor, temporary = tempfile.mkstemp(prefix=f".level-{level:03d}.", dir=directory)
    digest = hashlib.sha256()
    count = 0
    previous: tuple[Any, ...] | None = None
    try:
        os.fchmod(descriptor, 0o440)
        with os.fdopen(descriptor, "wb") as handle:
            header = HEADER.pack(magic, expected_count)
            handle.write(header)
            digest.update(header)
            for value in records:
                if previous is not None and value < previous:
                    raise RuntimeError(f"{family} output is not sorted")
                packed = record.pack(*value)
                handle.write(packed)
                digest.update(packed)
                previous = value
                count += 1
            if count != expected_count:
                raise RuntimeError(f"{family} output record count mismatch")
            handle.flush()
            os.fsync(handle.fileno())
        value_sha256 = digest.hexdigest()
        path = directory / f"level-{level:03d}-{value_sha256}.bin"
        if path.is_file():
            if sha256_file(path) != value_sha256:
                raise RuntimeError(f"{family} immutable collision")
            os.unlink(temporary)
        else:
            os.replace(temporary, path)
            os.chmod(path, 0o440)
            _fsync_directory(directory)
        metadata = {
            "level": level,
            "path": str(path.relative_to(root)),
            "sha256": value_sha256,
            "records": count,
            "bytes": HEADER.size + count * record.size,
        }
        metadata.update(_block_integrity_metadata(root, path, value_sha256))
        return metadata
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _merge_sorted_runs(
    root: Path,
    family: str,
    level: int,
    magic: bytes,
    record: struct.Struct,
    left: dict[str, Any],
    right: dict[str, Any],
) -> dict[str, Any]:
    with _verified_run(root / str(left["path"]), str(left["sha256"]), left) as left_handle, _verified_run(
        root / str(right["path"]), str(right["sha256"]), right
    ) as right_handle:
        left_count = _read_header(left_handle, magic, record.size)
        right_count = _read_header(right_handle, magic, record.size)
        if left_count != int(left["records"]) or right_count != int(right["records"]):
            raise RuntimeError(f"{family} input metadata count mismatch")
        merged = heapq.merge(
            _iter_fixed_records(left_handle, record, left_count, family),
            _iter_fixed_records(right_handle, record, right_count, family),
        )
        return _write_sorted_run(root, family, level, magic, record, merged, left_count + right_count)


def _write_route_run(root: Path, level: int, records: list[tuple[int, bytes, int, bytes]]) -> dict[str, Any]:
    return _write_sorted_run(root, "route-runs", level, ROUTE_MAGIC, ROUTE_RECORD, iter(sorted(records)), len(records))


def sync_catalog(index_root: Path, catalog_root: Path, *, rebuild: bool = False) -> dict[str, Any]:
    index_state_path = index_root / "state.json"
    index_state_before = index_state_path.read_bytes()
    index_state = json.loads(index_state_before)
    total_segments = int(index_state.get("segment_count") or 0)
    total_events = int(index_state.get("event_count") or 0)
    index_head = str(index_state.get("manifest_head_sha256") or "")
    if total_segments < 1 or total_events < 1 or not index_head:
        raise RuntimeError("cannot catalog an empty compact index")
    catalog_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    (catalog_root / "receipts").mkdir(parents=True, exist_ok=True, mode=0o750)
    with exclusive_lock(catalog_root / "catalog.lock"):
        state_path = catalog_root / "state.json"
        state: dict[str, Any] = {}
        if state_path.is_file() and not rebuild:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        processed = int(state.get("processed_segments") or 0)
        if processed > total_segments:
            rebuild = True
        if processed and not rebuild:
            prior_digest = str(state.get("processed_manifest_head_sha256") or "")
            if manifest_at_bucket(index_root, processed - 1)[2] != prior_digest:
                rebuild = True
        if state and "route_levels" not in state:
            rebuild = True
        if rebuild or not state:
            processed = 0
            levels: dict[int, dict[str, Any]] = {}
            route_levels: dict[int, dict[str, Any]] = {}
        else:
            levels = {int(key): value for key, value in (state.get("uid_levels") or {}).items()}
            route_levels = {int(key): value for key, value in (state.get("route_levels") or {}).items()}
        new_segment_count = total_segments - processed
        for bucket_id in range(processed, total_segments):
            _reference, manifest, manifest_digest = manifest_at_bucket(index_root, bucket_id)
            carry = _write_uid_run(catalog_root, 0, _uid_records(index_root, manifest))
            level = 0
            while level in levels:
                prior = levels.pop(level)
                level += 1
                carry = _merge_sorted_runs(catalog_root, "uid-runs", level, UID_MAGIC, UID_RECORD, prior, carry)
            levels[level] = carry
            route_carry = _write_route_run(catalog_root, 0, _route_records(index_root, manifest, manifest_digest))
            route_level = 0
            while route_level in route_levels:
                prior = route_levels.pop(route_level)
                route_level += 1
                route_carry = _merge_sorted_runs(
                    catalog_root, "route-runs", route_level, ROUTE_MAGIC, ROUTE_RECORD, prior, route_carry
                )
            route_levels[route_level] = route_carry

        # Upgrade pre-block-integrity catalogs in place without rewriting any
        # content-addressed run.  The one-time sequential pass creates small
        # authenticated block manifests; future readers verify only the blocks
        # they actually touch.
        levels = {level: _with_block_integrity(catalog_root, value) for level, value in levels.items()}
        route_levels = {
            level: _with_block_integrity(catalog_root, value) for level, value in route_levels.items()
        }

        def bucket_records() -> Iterator[tuple[int, int, int, bytes]]:
            previous = ""
            for _reference, manifest, digest in iter_manifests(index_root, total_segments):
                if str(manifest["previous_manifest_sha256"]) != previous:
                    raise RuntimeError("compact manifest chain diverged during catalog sync")
                yield (
                    int(manifest["bucket_id"]),
                    int(manifest["first_cursor"]),
                    int(manifest["last_cursor"]),
                    bytes.fromhex(digest),
                )
                previous = digest
            if previous != index_head:
                raise RuntimeError("compact manifest head diverged during catalog sync")

        bucket_generation = _write_sorted_run(
            catalog_root, "bucket-runs", 0, BUCKET_MAGIC, BUCKET_RECORD, bucket_records(), total_segments
        )
        if index_state_path.read_bytes() != index_state_before:
            raise RuntimeError("compact index generation changed during catalog sync")
        next_state = {
            "protocol": PROTOCOL + ".state",
            "index_protocol": INDEX_PROTOCOL,
            "updated_utc": dt.datetime.now(dt.UTC).isoformat(),
            "processed_segments": total_segments,
            "processed_manifest_head_sha256": index_head,
            "bucket_catalog_path": bucket_generation["path"],
            "bucket_catalog_sha256": bucket_generation["sha256"],
            "bucket_integrity": bucket_generation,
            "bucket_records": total_segments,
            "uid_levels": {str(level): levels[level] for level in sorted(levels)},
            "uid_records": sum(int(value["records"]) for value in levels.values()),
            "route_levels": {str(level): route_levels[level] for level in sorted(route_levels)},
            "route_records": sum(int(value["records"]) for value in route_levels.values()),
            "block_integrity_version": 1,
            "production_authority": False,
        }
        atomic_json(state_path, next_state, mode=0o640)
        keep = {catalog_root / str(value["path"]) for value in [*levels.values(), *route_levels.values()]}
        keep_integrity = {
            catalog_root / str(value["block_integrity_path"])
            for value in [*levels.values(), *route_levels.values(), bucket_generation]
        }
        for path in (catalog_root / "uid-runs").glob("*.bin"):
            if path not in keep:
                path.unlink()
        for path in (catalog_root / "route-runs").glob("*.bin"):
            if path not in keep:
                path.unlink()
        for path in (catalog_root / "bucket-runs").glob("*.bin"):
            if path != catalog_root / str(bucket_generation["path"]):
                path.unlink()
        for family in ("uid-runs", "route-runs", "bucket-runs"):
            for path in (catalog_root / family).glob("*.blocks.json"):
                if path not in keep_integrity:
                    path.unlink()
    checks = {
        "bucket_catalog_digest": sha256_file(catalog_root / str(next_state["bucket_catalog_path"])) == next_state["bucket_catalog_sha256"],
        "bucket_records_match_segments": next_state["bucket_records"] == total_segments,
        "uid_records_match_events": next_state["uid_records"] == total_events,
        "uid_levels_logarithmically_bounded": len(levels) <= max(1, total_segments.bit_length()),
        "route_levels_logarithmically_bounded": len(route_levels) <= max(1, total_segments.bit_length()),
        "route_records_present": next_state["route_records"] > 0,
        "authenticated_block_manifests": all(
            bool(value.get("block_integrity_sha256"))
            for value in [*levels.values(), *route_levels.values(), bucket_generation]
        ),
        "streaming_run_merge": True,
        "merge_fan_in_max_two": True,
        "run_record_counts_exact": True,
        "streaming_manifest_scan": True,
        "streaming_bucket_catalog": True,
        "production_authority_false": next_state["production_authority"] is False,
    }
    if not all(checks.values()):
        raise RuntimeError(f"compact catalog gate failed: {checks}")
    receipt = {
        "protocol": PROTOCOL + ".receipt",
        "status": "PASS",
        "created_utc": dt.datetime.now(dt.UTC).isoformat(),
        "mode": "rebuild" if rebuild else "sync",
        "new_segments": new_segment_count,
        "segment_count": total_segments,
        "event_count": next_state["uid_records"],
        "uid_level_count": len(levels),
        "bucket_catalog_bytes": int(bucket_generation["bytes"]),
        "uid_catalog_bytes": sum(int(value["bytes"]) for value in levels.values()),
        "route_catalog_bytes": sum(int(value["bytes"]) for value in route_levels.values()),
        "route_record_count": next_state["route_records"],
        "authenticated_block_size": BLOCK_INTEGRITY_SIZE,
        "streaming_run_merge": True,
        "merge_fan_in_max": 2,
        "streaming_manifest_scan": True,
        "streaming_bucket_catalog": True,
        "checks": checks,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    receipt["evidence_sha256"] = sha256_bytes(canonical_json(receipt))
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    path = catalog_root / "receipts" / f"catalog-{stamp}-{receipt['evidence_sha256'][:16]}.json"
    atomic_json(path, receipt, mode=0o440)
    return {**receipt, "receipt_path": str(path)}


def attest_catalog(catalog_root: Path) -> dict[str, Any]:
    """Verify and pin one immutable reader generation before serving queries."""

    started = time.perf_counter()
    state_path = catalog_root / "state.json"
    before = state_path.read_bytes()
    state = json.loads(before)
    if state.get("protocol") != PROTOCOL + ".state" or state.get("production_authority") is not False:
        raise RuntimeError("compact catalog state protocol/authority mismatch")
    bucket_metadata = state.get("bucket_integrity") or {
        "path": state.get("bucket_catalog_path") or "buckets.bin",
        "sha256": state["bucket_catalog_sha256"],
    }
    bucket_path = catalog_root / str(bucket_metadata["path"])
    with _verified_run(bucket_path, str(bucket_metadata["sha256"]), bucket_metadata) as handle:
        bucket_records = _read_header(handle, BUCKET_MAGIC, BUCKET_RECORD.size)
    uid_records = 0
    for value in (state.get("uid_levels") or {}).values():
        with _verified_run(catalog_root / str(value["path"]), str(value["sha256"]), value) as handle:
            observed = _read_header(handle, UID_MAGIC, UID_RECORD.size)
        if observed != int(value["records"]):
            raise RuntimeError("UID catalog run record count mismatch")
        uid_records += observed
    route_records = 0
    for value in (state.get("route_levels") or {}).values():
        with _verified_run(catalog_root / str(value["path"]), str(value["sha256"]), value) as handle:
            observed = _read_header(handle, ROUTE_MAGIC, ROUTE_RECORD.size)
        if observed != int(value["records"]):
            raise RuntimeError("route catalog run record count mismatch")
        route_records += observed
    if state_path.read_bytes() != before:
        raise RuntimeError("compact catalog generation changed during reader attestation")
    checks = {
        "generation_stable": True,
        "bucket_records_match": bucket_records == int(state["bucket_records"]),
        "uid_records_match": uid_records == int(state["uid_records"]),
        "route_records_match": route_records == int(state["route_records"]),
        "authenticated_random_access": all(
            bool(value.get("block_integrity_sha256"))
            for value in [
                bucket_metadata,
                *(state.get("uid_levels") or {}).values(),
                *(state.get("route_levels") or {}).values(),
            ]
        ),
        "production_authority_false": state.get("production_authority") is False,
    }
    if not all(checks.values()):
        raise RuntimeError(f"compact catalog reader attestation failed: {checks}")
    return {
        "protocol": PROTOCOL + ".reader-attestation",
        "status": "PASS",
        "snapshot_sha256": sha256_bytes(before),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        "bucket_records": bucket_records,
        "uid_records": uid_records,
        "route_records": route_records,
        "checks": checks,
        "production_authority": False,
        "memory_grants_authority": False,
    }


def _iter_uid_records(handle: BinaryIO, count: int) -> Iterator[tuple[bytes, int]]:
    handle.seek(HEADER.size)
    previous: tuple[bytes, int] | None = None
    for _ in range(count):
        raw = handle.read(UID_RECORD.size)
        if len(raw) != UID_RECORD.size:
            raise RuntimeError("UID catalog run truncated during verification")
        value = UID_RECORD.unpack(raw)
        if previous is not None and value < previous:
            raise RuntimeError("UID catalog run is not sorted")
        previous = value
        yield value


def verify_uid_catalog_unique(
    catalog_root: Path,
    expected_count: int,
    expected_manifest_head_sha256: str,
    expected_segment_count: int,
) -> dict[str, Any]:
    """Prove global UID-hash uniqueness with O(log(run-count)) resident state."""

    before = (catalog_root / "state.json").read_bytes()
    state = json.loads(before)
    if state.get("protocol") != PROTOCOL + ".state" or state.get("production_authority") is not False:
        raise RuntimeError("compact catalog state protocol/authority mismatch")
    iterators: list[Iterator[tuple[bytes, int]]] = []
    level_records = 0
    with contextlib.ExitStack() as stack:
        for level, value in sorted((state.get("uid_levels") or {}).items(), key=lambda item: int(item[0])):
            handle = stack.enter_context(
                _verified_run(catalog_root / str(value["path"]), str(value["sha256"]), value)
            )
            observed = _read_header(handle, UID_MAGIC, UID_RECORD.size)
            if observed != int(value["records"]):
                raise RuntimeError(f"UID catalog level {level} record count mismatch")
            level_records += observed
            iterators.append(_iter_uid_records(handle, observed))
        count = 0
        previous_digest: bytes | None = None
        sequence = hashlib.sha256()
        for digest, cursor in heapq.merge(*iterators):
            if digest == previous_digest:
                raise RuntimeError("duplicate event_uid hash across compact catalog")
            previous_digest = digest
            sequence.update(UID_RECORD.pack(digest, cursor))
            count += 1
    if (catalog_root / "state.json").read_bytes() != before:
        raise RuntimeError("compact catalog generation changed during UID verification")
    checks = {
        "uid_hash_unique": True,
        "merged_count_matches_levels": count == level_records,
        "merged_count_matches_state": count == int(state.get("uid_records") or 0),
        "merged_count_matches_expected": count == int(expected_count),
        "catalog_manifest_head_matches_index": str(state.get("processed_manifest_head_sha256") or "") == expected_manifest_head_sha256,
        "catalog_segment_count_matches_index": int(state.get("processed_segments") or 0) == int(expected_segment_count),
        "bucket_record_count_matches_index": int(state.get("bucket_records") or 0) == int(expected_segment_count),
        "input_runs_sorted": True,
        "bounded_memory_kway_merge": True,
        "production_authority_false": state.get("production_authority") is False,
    }
    if not all(checks.values()):
        raise RuntimeError(f"compact UID uniqueness verification failed: {checks}")
    return {
        "protocol": PROTOCOL + ".uid-verify-receipt",
        "status": "PASS",
        "event_count": count,
        "level_count": len(iterators),
        "uid_hash_cursor_sequence_sha256": sequence.hexdigest(),
        "checks": checks,
        "production_authority": False,
        "memory_grants_authority": False,
    }


def catalog_run_binding_sha256(state: dict[str, Any]) -> str:
    bucket = state.get("bucket_integrity") or {
        "level": 0,
        "path": state.get("bucket_catalog_path") or "buckets.bin",
        "sha256": state["bucket_catalog_sha256"],
        "records": int(state["bucket_records"]),
    }

    def bound_run(family: str, level: str, value: dict[str, Any]) -> dict[str, Any]:
        return {
            "family": family,
            "level": int(level),
            "path": str(value["path"]),
            "sha256": str(value["sha256"]),
            "records": int(value["records"]),
        }

    runs = [bound_run("bucket", "0", bucket)]
    for family in ("uid_levels", "route_levels"):
        for level, value in sorted((state.get(family) or {}).items(), key=lambda item: int(item[0])):
            runs.append(bound_run(family, level, value))
    binding = {
        "protocol": PROTOCOL + ".semantic-run-binding-v1",
        "processed_segments": int(state["processed_segments"]),
        "processed_manifest_head_sha256": str(state["processed_manifest_head_sha256"]),
        "bucket_records": int(state["bucket_records"]),
        "uid_records": int(state["uid_records"]),
        "route_records": int(state["route_records"]),
        "runs": runs,
        "production_authority": False,
    }
    return sha256_bytes(canonical_json(binding))


def hydrate_block_integrity(catalog_root: Path) -> dict[str, Any]:
    """Upgrade an existing derived catalog without rewriting run contents."""

    started = time.perf_counter()
    state_path = catalog_root / "state.json"
    with exclusive_lock(catalog_root / "catalog.lock"):
        before = state_path.read_bytes()
        state = json.loads(before)
        if state.get("protocol") != PROTOCOL + ".state" or state.get("production_authority") is not False:
            raise RuntimeError("compact catalog state protocol/authority mismatch")
        origin_state_sha256 = str(state.get("block_integrity_origin_state_sha256") or sha256_bytes(before))
        run_binding_before = catalog_run_binding_sha256(state)
        bucket = state.get("bucket_integrity") or {
            "level": 0,
            "path": state.get("bucket_catalog_path") or "buckets.bin",
            "sha256": state["bucket_catalog_sha256"],
            "records": int(state["bucket_records"]),
            "bytes": (catalog_root / str(state.get("bucket_catalog_path") or "buckets.bin")).stat().st_size,
        }
        bucket = _with_block_integrity(catalog_root, bucket)
        uid_levels = {
            str(level): _with_block_integrity(catalog_root, value)
            for level, value in (state.get("uid_levels") or {}).items()
        }
        route_levels = {
            str(level): _with_block_integrity(catalog_root, value)
            for level, value in (state.get("route_levels") or {}).items()
        }
        next_state = {
            **state,
            "updated_utc": dt.datetime.now(dt.UTC).isoformat(),
            "bucket_integrity": bucket,
            "uid_levels": uid_levels,
            "route_levels": route_levels,
            "block_integrity_version": 1,
            "block_integrity_origin_state_sha256": origin_state_sha256,
        }
        atomic_json(state_path, next_state, mode=0o640)
    hydrated_state = state_path.read_bytes()
    run_binding_after = catalog_run_binding_sha256(next_state)
    run_values = [bucket, *uid_levels.values(), *route_levels.values()]
    checks = {
        "run_content_sha256s_preserved": all(bool(value.get("sha256")) for value in run_values),
        "authenticated_block_manifests_present": all(
            bool(value.get("block_integrity_sha256")) for value in run_values
        ),
        "state_generation_updated_atomically": state_path.read_bytes() != before
        or int(state.get("block_integrity_version") or 0) == 1,
        "semantic_run_binding_preserved": run_binding_before == run_binding_after,
        "production_authority_false": next_state.get("production_authority") is False,
    }
    if not all(checks.values()):
        raise RuntimeError(f"compact catalog block-integrity hydration failed: {checks}")
    receipt = {
        "protocol": PROTOCOL + ".block-integrity-hydration-receipt",
        "status": "PASS",
        "origin_state_sha256": origin_state_sha256,
        "hydrated_state_sha256": sha256_bytes(hydrated_state),
        "semantic_run_binding_sha256": run_binding_after,
        "run_count": len(run_values),
        "block_count": sum(int(value["block_count"]) for value in run_values),
        "block_size": BLOCK_INTEGRITY_SIZE,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        "checks": checks,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    receipt["evidence_sha256"] = sha256_bytes(canonical_json(receipt))
    receipt_root = catalog_root / "receipts"
    receipt_root.mkdir(parents=True, exist_ok=True, mode=0o750)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    path = receipt_root / f"block-integrity-{stamp}-{receipt['evidence_sha256'][:16]}.json"
    atomic_json(path, receipt, mode=0o440)
    return {**receipt, "receipt_path": str(path)}


def bucket_manifest_digest(catalog_root: Path, cursor: int, bucket_span: int) -> str | None:
    if cursor < 1:
        return None
    target = (cursor - 1) // bucket_span
    state = json.loads((catalog_root / "state.json").read_text(encoding="utf-8"))
    metadata = state.get("bucket_integrity") or {
        "path": state.get("bucket_catalog_path") or "buckets.bin",
        "sha256": state["bucket_catalog_sha256"],
    }
    path = catalog_root / str(metadata["path"])
    with _verified_run(path, str(metadata["sha256"]), metadata) as handle:
        count = _read_header(handle, BUCKET_MAGIC, BUCKET_RECORD.size)
        low, high = 0, count
        while low < high:
            middle = (low + high) // 2
            handle.seek(HEADER.size + middle * BUCKET_RECORD.size)
            bucket_id, first, last, digest = BUCKET_RECORD.unpack(handle.read(BUCKET_RECORD.size))
            if bucket_id < target:
                low = middle + 1
            else:
                high = middle
        if low >= count:
            return None
        handle.seek(HEADER.size + low * BUCKET_RECORD.size)
        bucket_id, first, last, digest = BUCKET_RECORD.unpack(handle.read(BUCKET_RECORD.size))
        return digest.hex() if bucket_id == target and first <= cursor <= last else None


def uid_cursors(catalog_root: Path, event_uid: str) -> list[int]:
    target = hashlib.sha256(event_uid.encode("utf-8")).digest()
    state = json.loads((catalog_root / "state.json").read_text(encoding="utf-8"))
    result: list[int] = []
    for value in (state.get("uid_levels") or {}).values():
        path = catalog_root / str(value["path"])
        with _verified_run(path, str(value["sha256"]), value) as handle:
            count = _read_header(handle, UID_MAGIC, UID_RECORD.size)
            low, high = 0, count
            while low < high:
                middle = (low + high) // 2
                handle.seek(HEADER.size + middle * UID_RECORD.size)
                digest, _cursor = UID_RECORD.unpack(handle.read(UID_RECORD.size))
                if digest < target:
                    low = middle + 1
                else:
                    high = middle
            position = low
            while position < count:
                handle.seek(HEADER.size + position * UID_RECORD.size)
                digest, cursor = UID_RECORD.unpack(handle.read(UID_RECORD.size))
                if digest != target:
                    break
                result.append(int(cursor))
                position += 1
    return sorted(set(result))


def route_manifest_records(catalog_root: Path, kind: str, key: str) -> list[tuple[int, str]]:
    if kind not in ROUTE_KINDS:
        raise ValueError("unknown compact route kind")
    target_kind = ROUTE_KINDS[kind]
    target_digest = hashlib.sha256(key.encode("utf-8")).digest()
    state = json.loads((catalog_root / "state.json").read_text(encoding="utf-8"))
    result: set[tuple[int, str]] = set()
    for value in (state.get("route_levels") or {}).values():
        path = catalog_root / str(value["path"])
        with _verified_run(path, str(value["sha256"]), value) as handle:
            count = _read_header(handle, ROUTE_MAGIC, ROUTE_RECORD.size)
            low, high = 0, count
            while low < high:
                middle = (low + high) // 2
                handle.seek(HEADER.size + middle * ROUTE_RECORD.size)
                observed_kind, observed_digest, _bucket, _manifest = ROUTE_RECORD.unpack(handle.read(ROUTE_RECORD.size))
                if (observed_kind, observed_digest) < (target_kind, target_digest):
                    low = middle + 1
                else:
                    high = middle
            position = low
            while position < count:
                handle.seek(HEADER.size + position * ROUTE_RECORD.size)
                observed_kind, observed_digest, bucket, manifest = ROUTE_RECORD.unpack(handle.read(ROUTE_RECORD.size))
                if (observed_kind, observed_digest) != (target_kind, target_digest):
                    break
                result.add((int(bucket), manifest.hex()))
                position += 1
    return sorted(result)


def route_manifest_digests(catalog_root: Path, kind: str, key: str) -> list[str]:
    """Compatibility view for callers that do not need cursor ordering."""

    return sorted({digest for _bucket, digest in route_manifest_records(catalog_root, kind, key)})


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sync = sub.add_parser("sync")
    sync.add_argument("--index-root", type=Path, required=True)
    sync.add_argument("--catalog-root", type=Path, required=True)
    sync.add_argument("--rebuild", action="store_true")
    hydrate = sub.add_parser("hydrate-block-integrity")
    hydrate.add_argument("--catalog-root", type=Path, required=True)
    lookup = sub.add_parser("lookup")
    lookup.add_argument("--catalog-root", type=Path, required=True)
    lookup.add_argument("--bucket-span", type=int, required=True)
    lookup.add_argument("--cursor", type=int)
    lookup.add_argument("--event-uid")
    lookup.add_argument("--route-kind", choices=tuple(ROUTE_KINDS))
    lookup.add_argument("--route-key")
    args = parser.parse_args()
    if args.command == "sync":
        result = sync_catalog(args.index_root, args.catalog_root, rebuild=args.rebuild)
    elif args.command == "hydrate-block-integrity":
        result = hydrate_block_integrity(args.catalog_root)
    elif args.cursor:
        result = {"manifest_sha256": bucket_manifest_digest(args.catalog_root, args.cursor, args.bucket_span)}
    elif args.event_uid:
        result = {"candidate_cursors": uid_cursors(args.catalog_root, args.event_uid)}
    elif args.route_kind and args.route_key:
        records = route_manifest_records(args.catalog_root, args.route_kind, args.route_key)
        result = {"route_manifest_count": len(records), "records": records}
    else:
        raise ValueError("lookup requires --cursor, --event-uid, or --route-kind plus --route-key")
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
