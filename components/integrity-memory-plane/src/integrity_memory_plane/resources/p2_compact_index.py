#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Disposable compact cold indexes over committed P2 WORM events.

The index is deliberately not an authority.  It contains bounded locators and
candidate-generation structures only; every supported retrieval must still
read and verify the referenced raw WORM object.
"""

from __future__ import annotations

from integrity_memory_plane.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import contextlib
import datetime as dt
import gzip
import hashlib
import heapq
import itertools
import json
import os
import struct
import tempfile
from bisect import bisect_left
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator

from memory_plane_common import atomic_json, canonical_json, exclusive_lock, sha256_bytes, sha256_file
from p2_projection import committed_receipts, event_body, event_nodes, load_env, raw_envelopes, s3_client, tokens


PROTOCOL = "integrity-memory-plane.p2-compact-index.v1"
DEFAULT_BUCKET_SPAN = 4096
UID_VERIFY_MAGIC = b"IP2UVF1\0"
UID_VERIFY_RECORD = struct.Struct(">32sQ")


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")


def deterministic_gzip(value: bytes) -> bytes:
    with tempfile.TemporaryFile() as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=6) as compressed:
            compressed.write(value)
        raw.seek(0)
        return raw.read()


def immutable_write(path: Path, value: bytes, mode: int = 0o440) -> str:
    digest = sha256_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError:
        if sha256_file(path) != digest:
            raise RuntimeError(f"immutable object collision: {path}")
        return digest
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, mode)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise
    return digest


def object_path(root: Path, digest: str) -> Path:
    return root / "objects" / "sha256" / digest[:2] / digest


def encode_deltas(cursors: Iterable[int], base: int) -> list[int]:
    result: list[int] = []
    previous = base
    for cursor in sorted(set(int(value) for value in cursors)):
        if cursor < base:
            raise ValueError("posting cursor precedes bucket base")
        result.append(cursor - previous)
        previous = cursor
    return result


def decode_deltas(values: Iterable[int], base: int) -> list[int]:
    result: list[int] = []
    cursor = base
    for delta in values:
        if int(delta) < 0:
            raise ValueError("negative posting delta")
        cursor += int(delta)
        result.append(cursor)
    return result


def simhash64(text: str) -> int:
    weights = [0] * 64
    for token in tokens(text):
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        value = int.from_bytes(digest[:8], "big")
        for bit in range(64):
            weights[bit] += 1 if value & (1 << bit) else -1
    result = 0
    for bit, weight in enumerate(weights):
        if weight >= 0:
            result |= 1 << bit
    return result


def vector_bands(value: int) -> list[str]:
    return [f"{band}:{(value >> (band * 16)) & 0xffff:04x}" for band in range(4)]


def source_ref(receipt: dict[str, Any]) -> dict[str, Any]:
    batch, raw = receipt["batch"], receipt["raw"]
    return {
        "first_cursor": int(batch["first_cursor"]),
        "last_cursor": int(batch["last_cursor"]),
        "batch_sha256": str(batch["batch_sha256"]),
        "raw_key": str(raw["key"]),
        "raw_version_id": str(raw["version_id"]),
        "raw_content_sha256": str(raw["content_sha256"]),
    }


def iter_source_events(receipts: list[tuple[Path, dict[str, Any]]], client: Any) -> Iterator[dict[str, Any]]:
    for receipt_path, receipt in receipts:
        reference = source_ref(receipt)
        reference["receipt_sha256"] = sha256_file(receipt_path)
        for envelope in raw_envelopes(client, receipt):
            yield {"envelope": envelope, "source": reference}


def source_events(receipts: list[tuple[Path, dict[str, Any]]], client: Any) -> list[dict[str, Any]]:
    """Compatibility wrapper for bounded tests and small one-shot labs."""

    return list(iter_source_events(receipts, client))


def _identity(events: list[dict[str, Any]]) -> tuple[str, str, str]:
    identities = {
        (
            str(item["envelope"]["tenant_id"]),
            str(item["envelope"]["namespace"]),
            str(item["envelope"]["edge_id"]),
        )
        for item in events
    }
    if len(identities) != 1:
        raise RuntimeError("compact bucket cannot cross an ordered edge identity")
    return next(iter(identities))


def compact_payload(events: list[dict[str, Any]], bucket_start: int) -> tuple[bytes, dict[str, int]]:
    fts: dict[str, list[int]] = defaultdict(list)
    graph: dict[str, list[int]] = defaultdict(list)
    vector: dict[str, list[int]] = defaultdict(list)
    uids: list[list[Any]] = []
    semantic = hashlib.sha256()
    for item in events:
        envelope = item["envelope"]
        event = envelope["payload"]
        cursor = int(envelope["cursor"])
        uid = str(envelope["event_uid"])
        uids.append([uid, cursor])
        semantic.update(canonical_json([cursor, uid, envelope["payload_sha256"], envelope["envelope_sha256"]]))
        body = event_body(event)
        index_terms = {
            term for term in tokens(body)
            if not (len(term) >= 32 and all(value in "0123456789abcdef" for value in term))
            and not (len(term) >= 8 and term.isdigit())
        }
        for term in index_terms:
            fts[term].append(cursor)
        for kind, value, _relation in event_nodes(event):
            graph[f"{kind}:{value.strip().casefold()}"].append(cursor)
        for band in vector_bands(simhash64(body)):
            vector[band].append(cursor)
    if len({value[0] for value in uids}) != len(uids):
        raise RuntimeError("duplicate event_uid in compact bucket")
    payload = {
        "protocol": PROTOCOL + ".payload",
        "bucket_start": bucket_start,
        "uids": sorted(uids),
        "fts": [[key, encode_deltas(values, bucket_start)] for key, values in sorted(fts.items())],
        "graph": [[key, encode_deltas(values, bucket_start)] for key, values in sorted(graph.items())],
        "vector_lsh16x4": [[key, encode_deltas(values, bucket_start)] for key, values in sorted(vector.items())],
        "semantic_events_sha256": semantic.hexdigest(),
        "production_authority": False,
    }
    raw = canonical_json(payload) + b"\n"
    compressed = deterministic_gzip(raw)
    return compressed, {
        "uid_entries": len(uids),
        "fts_terms": len(fts),
        "graph_nodes": len(graph),
        "vector_bands": len(vector),
        "uncompressed_bytes": len(raw),
        "compressed_bytes": len(compressed),
    }


def _load_state(root: Path, tenant: str, namespace: str, edge: str, span: int) -> dict[str, Any]:
    path = root / "state.json"
    if not path.is_file():
        return {
            "protocol": PROTOCOL + ".state",
            "tenant_id": tenant,
            "namespace": namespace,
            "edge_id": edge,
            "bucket_span": span,
            "last_covered_cursor": 0,
            "segment_count": 0,
            "event_count": 0,
            "manifest_head_sha256": "",
            "sealed_bucket_ids": [],
        }
    state = json.loads(path.read_text(encoding="utf-8"))
    expected = (PROTOCOL + ".state", tenant, namespace, edge, span)
    observed = (
        state.get("protocol"), state.get("tenant_id"), state.get("namespace"),
        state.get("edge_id"), int(state.get("bucket_span") or 0),
    )
    if observed != expected:
        raise RuntimeError("compact index state identity/policy mismatch")
    return state


def build_store_stream(
    events: Iterable[dict[str, Any]],
    root: Path,
    *,
    bucket_span: int = DEFAULT_BUCKET_SPAN,
    raw_head_cursor: int,
    seal_head: bool = False,
) -> dict[str, Any]:
    if bucket_span < 16 or bucket_span > 1_000_000:
        raise ValueError("bucket_span must be between 16 and 1000000")
    iterator = iter(events)
    try:
        first = next(iterator)
    except StopIteration as exc:
        raise ValueError("compact index source is empty") from exc
    tenant, namespace, edge = _identity([first])
    raw_head = int(raw_head_cursor)
    if raw_head < 1:
        raise ValueError("raw_head_cursor must be positive")
    root.mkdir(parents=True, exist_ok=True, mode=0o750)
    (root / "segments").mkdir(parents=True, exist_ok=True, mode=0o750)
    (root / "receipts").mkdir(parents=True, exist_ok=True, mode=0o750)
    with exclusive_lock(root / "writer.lock"):
        state = _load_state(root, tenant, namespace, edge, bucket_span)
        sealed = {int(value) for value in state.get("sealed_bucket_ids", [])}
        created: list[dict[str, Any]] = []
        previous = str(state.get("manifest_head_sha256") or "")
        event_count = int(state.get("event_count") or 0)
        segment_count = int(state.get("segment_count") or 0)
        last_covered = int(state.get("last_covered_cursor") or 0)
        peak_bucket_events = 0

        def seal_bucket(bucket_id: int, bucket_events: list[dict[str, Any]]) -> None:
            nonlocal previous, event_count, segment_count, last_covered, peak_bucket_events
            if bucket_id in sealed:
                return
            bucket_start = bucket_id * bucket_span + 1
            bucket_end = (bucket_id + 1) * bucket_span
            is_complete = raw_head >= bucket_end
            if not is_complete and not seal_head:
                return
            if not bucket_events:
                raise RuntimeError("unsealed compact bucket has no events")
            peak_bucket_events = max(peak_bucket_events, len(bucket_events))
            if int(bucket_events[0]["envelope"]["cursor"]) <= last_covered:
                raise RuntimeError("new compact bucket overlaps sealed coverage")
            payload, statistics = compact_payload(bucket_events, bucket_start)
            payload_sha = immutable_write(object_path(root, sha256_bytes(payload)), payload)
            sources: dict[str, dict[str, Any]] = {}
            for item in bucket_events:
                source = item["source"]
                sources[str(source["batch_sha256"])] = dict(source)
            times = [str(item["envelope"]["ts_utc"]) for item in bucket_events]
            manifest = {
                "protocol": PROTOCOL + ".manifest",
                "tenant_id": tenant,
                "namespace": namespace,
                "edge_id": edge,
                "bucket_id": bucket_id,
                "bucket_span": bucket_span,
                "bucket_start": bucket_start,
                "bucket_end": bucket_end,
                "sealed_partial_head": not is_complete,
                "first_cursor": int(bucket_events[0]["envelope"]["cursor"]),
                "last_cursor": int(bucket_events[-1]["envelope"]["cursor"]),
                "first_ts_utc": min(times),
                "last_ts_utc": max(times),
                "event_count": len(bucket_events),
                "payload": {"sha256": payload_sha, "bytes": len(payload)},
                "statistics": statistics,
                "sources": sorted(sources.values(), key=lambda value: int(value["first_cursor"])),
                "previous_manifest_sha256": previous,
                "production_authority": False,
            }
            manifest_bytes = canonical_json(manifest) + b"\n"
            manifest_sha = immutable_write(object_path(root, sha256_bytes(manifest_bytes)), manifest_bytes)
            reference = root / "segments" / f"{bucket_id:020d}-{manifest_sha}.json"
            immutable_write(reference, manifest_bytes)
            previous = manifest_sha
            last_covered = int(bucket_events[-1]["envelope"]["cursor"])
            event_count += len(bucket_events)
            segment_count += 1
            sealed.add(bucket_id)
            created.append({
                "bucket_id": bucket_id,
                "first_cursor": manifest["first_cursor"],
                "last_cursor": manifest["last_cursor"],
                "events": len(bucket_events),
                "payload_bytes": len(payload),
                "manifest_sha256": manifest_sha,
                "payload_sha256": payload_sha,
            })

        current_bucket_id: int | None = None
        current_bucket: list[dict[str, Any]] = []
        previous_cursor = 0
        last_seen_cursor = 0
        for item in itertools.chain((first,), iterator):
            envelope = item["envelope"]
            identity = (str(envelope["tenant_id"]), str(envelope["namespace"]), str(envelope["edge_id"]))
            if identity != (tenant, namespace, edge):
                raise RuntimeError("compact stream crossed an ordered edge identity")
            cursor = int(envelope["cursor"])
            if cursor <= previous_cursor or cursor > raw_head:
                raise RuntimeError("source cursors are not unique, ascending, and head-bounded")
            bucket_id = (cursor - 1) // bucket_span
            if current_bucket_id is None:
                current_bucket_id = bucket_id
            elif bucket_id != current_bucket_id:
                seal_bucket(current_bucket_id, current_bucket)
                current_bucket = []
                current_bucket_id = bucket_id
            if bucket_id not in sealed:
                current_bucket.append(item)
            previous_cursor = cursor
            last_seen_cursor = cursor
        if current_bucket_id is not None:
            seal_bucket(current_bucket_id, current_bucket)
        if last_seen_cursor != raw_head:
            raise RuntimeError("compact source does not terminate at declared raw head")
        next_state = {
            "protocol": PROTOCOL + ".state",
            "tenant_id": tenant,
            "namespace": namespace,
            "edge_id": edge,
            "bucket_span": bucket_span,
            "raw_head_cursor": raw_head,
            "last_covered_cursor": last_covered,
            "coverage_lag_events": max(0, raw_head - last_covered),
            "event_count": event_count,
            "segment_count": segment_count,
            "manifest_head_sha256": previous,
            "sealed_bucket_ids": sorted(sealed),
            "updated_utc": utc_now(),
            "production_authority": False,
        }
        atomic_json(root / "state.json", next_state, mode=0o640)
    receipt = {
        "protocol": PROTOCOL + ".build-receipt",
        "status": "PASS" if created else "NOOP",
        "created_utc": utc_now(),
        "raw_head_cursor": raw_head,
        "coverage_through_cursor": next_state["last_covered_cursor"],
        "coverage_lag_events": next_state["coverage_lag_events"],
        "total_events": next_state["event_count"],
        "segment_count": next_state["segment_count"],
        "created_segments": created,
        "created_segment_count": len(created),
        "peak_bucket_events": peak_bucket_events,
        "streaming_source": True,
        "manifest_head_sha256": next_state["manifest_head_sha256"],
        "rebuildable_from_committed_raw": True,
        "production_authority": False,
        "memory_grants_authority": False,
    }
    receipt["evidence_sha256"] = sha256_bytes(canonical_json(receipt))
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    receipt_path = root / "receipts" / f"build-{stamp}-{receipt['evidence_sha256'][:16]}.json"
    atomic_json(receipt_path, receipt, mode=0o440)
    return {**receipt, "receipt_path": str(receipt_path)}


def build_store(
    events: list[dict[str, Any]],
    root: Path,
    *,
    bucket_span: int = DEFAULT_BUCKET_SPAN,
    raw_head_cursor: int | None = None,
    seal_head: bool = False,
) -> dict[str, Any]:
    """Bounded compatibility API; production runtime uses build_store_stream."""

    if not events:
        raise ValueError("compact index source is empty")
    raw_head = int(raw_head_cursor if raw_head_cursor is not None else events[-1]["envelope"]["cursor"])
    return build_store_stream(events, root, bucket_span=bucket_span, raw_head_cursor=raw_head, seal_head=seal_head)


def manifest_at_bucket(root: Path, bucket_id: int) -> tuple[Path, dict[str, Any], str]:
    matches = list((root / "segments").glob(f"{bucket_id:020d}-*.json"))
    if len(matches) != 1:
        raise RuntimeError(f"compact bucket {bucket_id} has {len(matches)} manifest references")
    path = matches[0]
    digest = path.stem.rsplit("-", 1)[-1]
    if sha256_file(path) != digest:
        raise RuntimeError(f"segment reference digest mismatch: {path.name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("protocol") != PROTOCOL + ".manifest" or value.get("production_authority") is not False:
        raise RuntimeError(f"invalid compact manifest: {path.name}")
    if int(value.get("bucket_id", -1)) != bucket_id:
        raise RuntimeError(f"compact manifest bucket mismatch: {path.name}")
    if sha256_file(object_path(root, digest)) != digest:
        raise RuntimeError(f"content-addressed manifest mismatch: {digest}")
    payload = value["payload"]
    if sha256_file(object_path(root, str(payload["sha256"]))) != str(payload["sha256"]):
        raise RuntimeError(f"compact payload digest mismatch: {payload['sha256']}")
    return path, value, digest


def iter_manifests(root: Path, segment_count: int | None = None) -> Iterator[tuple[Path, dict[str, Any], str]]:
    if segment_count is None:
        state = json.loads((root / "state.json").read_text(encoding="utf-8"))
        segment_count = int(state.get("segment_count") or 0)
    for bucket_id in range(segment_count):
        yield manifest_at_bucket(root, bucket_id)


def manifests(root: Path) -> list[tuple[Path, dict[str, Any], str]]:
    """Compatibility materializer; scale-sensitive paths use iter_manifests."""

    return list(iter_manifests(root))


def manifest_by_digest(root: Path, digest: str) -> tuple[Path, dict[str, Any], str]:
    if not __import__("re").fullmatch(r"[0-9a-f]{64}", digest):
        raise RuntimeError("compact manifest digest rejected")
    path = object_path(root, digest)
    if sha256_file(path) != digest:
        raise RuntimeError("content-addressed compact manifest mismatch")
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("protocol") != PROTOCOL + ".manifest" or value.get("production_authority") is not False:
        raise RuntimeError("invalid content-addressed compact manifest")
    payload = value["payload"]
    if sha256_file(object_path(root, str(payload["sha256"]))) != str(payload["sha256"]):
        raise RuntimeError("compact payload digest mismatch")
    return path, value, digest


def verify_store(root: Path, catalog_root: Path | None = None) -> dict[str, Any]:
    if catalog_root is None:
        raise RuntimeError("bounded compact verification requires the UID catalog")
    state_path = root / "state.json"
    state_before = state_path.read_bytes()
    state = json.loads(state_before)
    expected_segments = int(state.get("segment_count") or 0)
    previous = ""
    event_count = 0
    segment_count = 0
    first_cursor = 0
    last_cursor = 0
    peak_bucket_events = 0
    semantic = hashlib.sha256()
    from p2_compact_catalog import (
        _iter_fixed_records,
        _merge_sorted_runs,
        _read_header,
        _verified_run,
        _write_sorted_run,
        verify_uid_catalog_unique,
    )

    transient_levels: dict[int, dict[str, Any]] = {}
    scratch_parent = catalog_root
    with tempfile.TemporaryDirectory(prefix=".uid-verify-", dir=scratch_parent) as scratch_value:
        scratch = Path(scratch_value)
        for _path, manifest, digest in iter_manifests(root, expected_segments):
            if str(manifest["previous_manifest_sha256"]) != previous:
                raise RuntimeError("compact manifest chain diverged")
            payload_path = object_path(root, str(manifest["payload"]["sha256"]))
            payload = json.loads(gzip.decompress(payload_path.read_bytes()))
            if payload.get("protocol") != PROTOCOL + ".payload" or payload.get("production_authority") is not False:
                raise RuntimeError("compact payload protocol/authority mismatch")
            bucket_uids = [str(value[0]) for value in payload["uids"]]
            bucket_cursors = sorted(int(value[1]) for value in payload["uids"])
            if len(bucket_cursors) != int(manifest["event_count"]):
                raise RuntimeError("compact event count mismatch")
            if len(set(bucket_uids)) != len(bucket_uids):
                raise RuntimeError("duplicate event_uid inside compact bucket")
            if any(right != left + 1 for left, right in zip(bucket_cursors, bucket_cursors[1:])):
                raise RuntimeError("compact cursor gap or duplicate inside bucket")
            if bucket_cursors and last_cursor and bucket_cursors[0] != last_cursor + 1:
                raise RuntimeError("compact cursor gap between buckets")
            if bucket_cursors and int(manifest["first_cursor"]) != bucket_cursors[0]:
                raise RuntimeError("compact manifest first cursor mismatch")
            if bucket_cursors and int(manifest["last_cursor"]) != bucket_cursors[-1]:
                raise RuntimeError("compact manifest last cursor mismatch")
            uid_records = sorted(
                (hashlib.sha256(str(uid).encode("utf-8")).digest(), int(cursor))
                for uid, cursor in payload["uids"]
            )
            if any(left[0] == right[0] for left, right in zip(uid_records, uid_records[1:])):
                raise RuntimeError("duplicate event_uid hash inside compact bucket")
            carry = _write_sorted_run(
                scratch, "uid-runs", 0, UID_VERIFY_MAGIC, UID_VERIFY_RECORD, iter(uid_records), len(uid_records)
            )
            level = 0
            while level in transient_levels:
                prior = transient_levels.pop(level)
                level += 1
                carry = _merge_sorted_runs(
                    scratch, "uid-runs", level, UID_VERIFY_MAGIC, UID_VERIFY_RECORD, prior, carry
                )
            transient_levels[level] = carry
            if bucket_cursors and first_cursor == 0:
                first_cursor = bucket_cursors[0]
            if bucket_cursors:
                last_cursor = bucket_cursors[-1]
            event_count += len(bucket_cursors)
            segment_count += 1
            peak_bucket_events = max(peak_bucket_events, len(bucket_cursors))
            semantic.update(canonical_json([manifest["bucket_id"], payload["semantic_events_sha256"]]))
            previous = digest
        transient_count = 0
        previous_uid_digest: bytes | None = None
        transient_uid_sequence = hashlib.sha256()
        with contextlib.ExitStack() as stack:
            iterators: list[Iterator[tuple[Any, ...]]] = []
            for level, metadata in sorted(transient_levels.items()):
                handle = stack.enter_context(_verified_run(scratch / str(metadata["path"]), str(metadata["sha256"])))
                observed = _read_header(handle, UID_VERIFY_MAGIC, UID_VERIFY_RECORD.size)
                if observed != int(metadata["records"]):
                    raise RuntimeError(f"transient UID level {level} record count mismatch")
                iterators.append(_iter_fixed_records(handle, UID_VERIFY_RECORD, observed, "transient UID"))
            for uid_digest, uid_cursor in heapq.merge(*iterators):
                if uid_digest == previous_uid_digest:
                    raise RuntimeError("duplicate event_uid hash across compact payloads")
                previous_uid_digest = uid_digest
                transient_uid_sequence.update(UID_VERIFY_RECORD.pack(uid_digest, uid_cursor))
                transient_count += 1
        if transient_count != event_count:
            raise RuntimeError("transient UID verification count mismatch")

    if state_path.read_bytes() != state_before:
        raise RuntimeError("compact index generation changed during verification")
    reference_count = sum(1 for _path in (root / "segments").glob("*.json"))
    catalog_uid_verify = verify_uid_catalog_unique(catalog_root, event_count, previous, segment_count)
    uid_projection_matches_payload = (
        str(catalog_uid_verify.get("uid_hash_cursor_sequence_sha256") or "") == transient_uid_sequence.hexdigest()
    )
    checks = {
        "manifest_chain": previous == str(state.get("manifest_head_sha256") or ""),
        "segment_count": segment_count == int(state.get("segment_count") or 0),
        "event_count": event_count == int(state.get("event_count") or 0),
        "segment_reference_count": reference_count == segment_count,
        "cursor_order_unique": True,
        "cursor_contiguous_from_one": first_cursor == 1 and last_cursor == event_count,
        "event_uid_unique": transient_count == event_count,
        "persistent_uid_catalog_consistent": catalog_uid_verify["status"] == "PASS" and all(catalog_uid_verify["checks"].values()),
        "persistent_uid_catalog_matches_payload": uid_projection_matches_payload,
        "bounded_memory_verifier": True,
        "production_authority_false": state.get("production_authority") is False,
    }
    if not all(checks.values()):
        raise RuntimeError(f"compact store verification failed: {checks}")
    return {
        "protocol": PROTOCOL + ".verify-receipt",
        "status": "PASS",
        "checks": checks,
        "event_count": event_count,
        "first_cursor": first_cursor,
        "last_cursor": last_cursor,
        "segment_count": segment_count,
        "peak_bucket_events": peak_bucket_events,
        "uid_verification": {
            "status": "PASS",
            "method": "transient-external-sort-from-compact-payloads",
            "event_count": transient_count,
            "level_count": len(transient_levels),
            "uid_hash_cursor_sequence_sha256": transient_uid_sequence.hexdigest(),
            "bounded_memory": True,
            "production_authority": False,
        },
        "persistent_uid_catalog_verification": catalog_uid_verify,
        "manifest_head_sha256": previous,
        "semantic_bucket_claim_chain_sha256": semantic.hexdigest(),
        "semantic_bucket_chain_sha256": semantic.hexdigest(),
        "semantic_claims_only_not_raw_equivalence": True,
        "production_authority": False,
    }


def _payload_map(payload: dict[str, Any], name: str, base: int) -> dict[str, list[int]]:
    return {str(key): decode_deltas(values, base) for key, values in payload[name]}


def candidate_lookup(root: Path, query: str, limit: int = 20, catalog_root: Path | None = None) -> dict[str, Any]:
    normalized = query.strip()
    if not normalized or limit < 1 or limit > 100:
        raise ValueError("invalid compact lookup bounds")
    route_heaps: dict[str, list[int]] = {"exact": [], "fts": [], "graph": [], "vector": []}
    route_populations = {name: 0 for name in route_heaps}
    ranked_heap: list[tuple[float, int]] = []
    sources: dict[int, dict[str, Any]] = {}
    vector_matches: set[int] = set()
    candidate_population = 0
    ranking_state_max = 0

    def retain_smallest_route(name: str, cursors: set[int]) -> None:
        route_populations[name] += len(cursors)
        retained = route_heaps[name]
        for cursor in cursors:
            if len(retained) < limit:
                heapq.heappush(retained, -cursor)
            elif cursor < -retained[0]:
                heapq.heapreplace(retained, -cursor)

    def source_for(manifest: dict[str, Any], cursor: int) -> dict[str, Any] | None:
        for source in manifest["sources"]:
            if int(source["first_cursor"]) <= cursor <= int(source["last_cursor"]):
                return source
        return None

    def retain_ranked(manifest: dict[str, Any], cursor: int, score: float, vector_match: bool) -> None:
        nonlocal ranking_state_max
        candidate = (score, cursor)
        if len(ranked_heap) >= limit and candidate <= ranked_heap[0]:
            return
        source = source_for(manifest, cursor)
        if len(ranked_heap) < limit:
            heapq.heappush(ranked_heap, candidate)
        else:
            evicted = heapq.heapreplace(ranked_heap, candidate)
            sources.pop(evicted[1], None)
            vector_matches.discard(evicted[1])
        if source is not None:
            sources[cursor] = source
        if vector_match:
            vector_matches.add(cursor)
        ranking_state_max = max(ranking_state_max, len(ranked_heap))

    exact_cursor = int(normalized.lstrip("#")) if normalized.lstrip("#").isdigit() else None
    exact_uid = normalized.removeprefix("event_uid:").strip() if normalized.startswith("event_uid:") else ""
    task_id = normalized.removeprefix("task_path:").strip() if normalized.startswith("task_path:") else ""
    query_terms = sorted(set(tokens(normalized)))
    query_bands = set(vector_bands(simhash64(normalized)))
    manifest_values: list[tuple[Path, dict[str, Any], str]] | None = None
    manifest_references: list[tuple[int, str]] | None = None
    routed_query_terms = set(query_terms)
    if catalog_root is not None:
        from p2_compact_catalog import bucket_manifest_digest, route_manifest_records, uid_cursors

        state = json.loads((root / "state.json").read_text(encoding="utf-8"))
        span = int(state["bucket_span"])
        selected: dict[str, int] = {}
        if exact_cursor is not None:
            digest = bucket_manifest_digest(catalog_root, exact_cursor, span)
            if digest:
                selected[digest] = (exact_cursor - 1) // span
        elif exact_uid:
            for cursor in uid_cursors(catalog_root, exact_uid):
                digest = bucket_manifest_digest(catalog_root, cursor, span)
                if digest:
                    selected[digest] = (cursor - 1) // span
        elif task_id:
            for bucket, digest in route_manifest_records(catalog_root, "graph", f"task_id:{task_id.casefold()}"):
                selected[digest] = bucket
        else:
            routed_query_terms = set()
            for term in query_terms:
                records = route_manifest_records(catalog_root, "fts", term)
                if records:
                    routed_query_terms.add(term)
                for bucket, digest in records:
                    selected[digest] = bucket
        manifest_references = sorted(((bucket, digest) for digest, bucket in selected.items()), reverse=True)
        manifest_iterator = (manifest_by_digest(root, digest) for _bucket, digest in manifest_references)
        manifest_count = len(manifest_references)
    else:
        manifest_values = sorted(manifests(root), key=lambda value: int(value[1]["last_cursor"]), reverse=True)
        manifest_iterator = iter(manifest_values)
        manifest_count = len(manifest_values)
    scanned_manifest_count = 0
    lookup_early_stopped = False
    maximum_lexical_score = 4.0 * len(routed_query_terms)
    for _path, manifest, _digest in manifest_iterator:
        scanned_manifest_count += 1
        if exact_cursor is not None and not (int(manifest["first_cursor"]) <= exact_cursor <= int(manifest["last_cursor"])):
            continue
        local_routes: dict[str, set[int]] = {name: set() for name in route_heaps}
        local_scores: dict[int, float] = defaultdict(float)
        payload = json.loads(gzip.decompress(object_path(root, str(manifest["payload"]["sha256"])).read_bytes()))
        base = int(payload["bucket_start"])
        if exact_cursor is not None:
            uid_cursors = {int(cursor) for _uid, cursor in payload["uids"]}
            if exact_cursor in uid_cursors:
                local_routes["exact"].add(exact_cursor)
                local_scores[exact_cursor] += 100.0
        elif exact_uid:
            keys = [str(value[0]) for value in payload["uids"]]
            position = bisect_left(keys, exact_uid)
            if position < len(keys) and keys[position] == exact_uid:
                cursor = int(payload["uids"][position][1])
                local_routes["exact"].add(cursor)
                local_scores[cursor] += 100.0
        elif task_id:
            graph = _payload_map(payload, "graph", base)
            for cursor in graph.get(f"task_id:{task_id.casefold()}", []):
                local_routes["graph"].add(cursor)
                local_scores[cursor] += 20.0
        else:
            postings = _payload_map(payload, "fts", base)
            for term in query_terms:
                for cursor in postings.get(term, []):
                    local_routes["fts"].add(cursor)
                    local_scores[cursor] += 4.0
            vector = _payload_map(payload, "vector_lsh16x4", base)
            for band in query_bands:
                for cursor in vector.get(band, []):
                    if cursor in local_scores:
                        local_routes["vector"].add(cursor)
        # A cursor belongs to exactly one sealed bucket.  Rank that bucket's
        # candidates immediately and retain only the exact global top-K.  This
        # preserves the score/cursor ordering while bounding ranking state by
        # ``limit`` instead of the total candidate population.
        candidate_population += len(local_scores)
        for name, cursors in local_routes.items():
            if name != "vector":
                retain_smallest_route(name, cursors)
        for cursor, score in local_scores.items():
            retain_ranked(manifest, cursor, score, cursor in local_routes["vector"])
        if (
            exact_cursor is None
            and not exact_uid
            and not task_id
            and scanned_manifest_count < manifest_count
            and len(ranked_heap) == limit
            and ranked_heap[0][0] >= maximum_lexical_score
        ):
            lookup_early_stopped = True
            break

    # Vector similarity is a bounded second-stage reranker: it may reorder the
    # retained lexical top-K, but it cannot force an unbounded history scan or
    # promote a cursor outside that proven lexical candidate set.
    ranked = [
        cursor
        for _score, cursor in sorted(
            ranked_heap,
            key=lambda item: (-(item[0] + (0.25 if item[1] in vector_matches else 0.0)), -item[1]),
        )
    ]
    retain_smallest_route("vector", vector_matches)
    bounded_routes = {name: sorted(-cursor for cursor in retained) for name, retained in route_heaps.items()}
    routes_truncated = {name: route_populations[name] > len(bounded_routes[name]) for name in route_heaps}
    if lookup_early_stopped:
        routes_truncated["fts"] = True
    causal_path = None
    if task_id:
        causal_ids = bounded_routes["graph"]
        causal_path = {
            "kind": "TASK_SEQUENCE",
            "task_id": task_id,
            "event_ids": causal_ids,
            "complete": bool(causal_ids) and not routes_truncated["graph"],
            "truncated": routes_truncated["graph"],
        }
    return {
        "protocol": PROTOCOL + ".candidate-receipt",
        "decision": "CANDIDATES" if ranked else "NO_EVIDENCE",
        "query": normalized,
        "routes": bounded_routes,
        "candidate_cursors": ranked,
        "source_locators": {str(cursor): sources[cursor] for cursor in ranked if cursor in sources},
        "causal_path": causal_path,
        "lookup_bounds": {
            "manifest_count": manifest_count,
            "scanned_manifest_count": scanned_manifest_count,
            "early_stopped": lookup_early_stopped,
            "candidate_population": candidate_population,
            "ranking_state_max": ranking_state_max,
            "ranking_state_limit": limit,
            "ranking_mode": "lexical-top-k-then-vector-rerank-v1",
            "routed_query_terms": sorted(routed_query_terms),
            "route_populations": route_populations,
            "routes_truncated": routes_truncated,
        },
        "exact_raw_readback_required": True,
        "candidate_only_not_truth": True,
        "production_authority": False,
        "memory_grants_authority": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build-live")
    build.add_argument("--receipts", type=Path, default=Path(_integrity_value('path_f5a9a1727fe8')))
    build.add_argument("--minio-env", type=Path, default=Path("/etc/integrity-memory-p2/projection-minio.env"))
    build.add_argument("--s3-endpoint", default=_integrity_value('endpoint_1940bdd68a0a'))
    build.add_argument("--root", type=Path, required=True)
    build.add_argument("--bucket-span", type=int, default=DEFAULT_BUCKET_SPAN)
    build.add_argument("--seal-head", action="store_true")
    verify = sub.add_parser("verify")
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--catalog-root", type=Path, required=True)
    lookup = sub.add_parser("lookup")
    lookup.add_argument("query")
    lookup.add_argument("--root", type=Path, required=True)
    lookup.add_argument("--catalog-root", type=Path)
    lookup.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()
    if args.command == "build-live":
        receipts = committed_receipts(args.receipts)
        client = s3_client(load_env(args.minio_env), args.s3_endpoint)
        events = source_events(receipts, client)
        result = build_store(events, args.root, bucket_span=args.bucket_span, raw_head_cursor=int(receipts[-1][1]["batch"]["last_cursor"]), seal_head=args.seal_head)
    elif args.command == "verify":
        result = verify_store(args.root, args.catalog_root)
    else:
        result = candidate_lookup(args.root, args.query, args.limit, args.catalog_root)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
