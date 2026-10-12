#!/opt/integrity/current/venv/bin/python
"""P0 candidate: bounded Seed delta import with an append-only event MMR."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any

from seed_catalog_read_seal import (
    SeedCatalogReadSealError,
    seal_catalog_for_immutable_read as _seal_catalog_once,
)

from integrity_guardian.seed_action_log import fetch_seed_snapshot
from integrity_guardian.seed_catalog import (
    SEED_NAMESPACE,
    SeedCatalogError,
    _canonical_text,
    _counts,
    _derive_event,
    _event_digest,
    _parse_seed_json,
    _seed_canonical_bytes,
    _string,
    _string_list,
    _verify_connection,
    validate_seed_events,
)

PROTOCOL = "integrity-guardian/seed-delta-checkpoint/v1"
MMR_LEAF_DOMAIN = b"integrity-seed-event-mmr-leaf-v1\0"
MMR_NODE_DOMAIN = b"integrity-seed-event-mmr-node-v1\0"
MMR_ROOT_DOMAIN = b"integrity-seed-event-mmr-root-v1\0"
CHECKPOINT_DOMAIN = b"integrity-seed-delta-checkpoint-v1\0"

_DELTA_SCHEMA = """
CREATE TABLE IF NOT EXISTS seed_delta_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    protocol TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    event_cursor INTEGER NOT NULL,
    mmr_peaks_json TEXT NOT NULL,
    mmr_root TEXT NOT NULL,
    checkpoint_digest TEXT NOT NULL,
    counts_json TEXT NOT NULL,
    last_full_source_digest TEXT NOT NULL,
    last_full_catalog_digest TEXT NOT NULL,
    last_full_verified_at TEXT NOT NULL,
    delta_since_full INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS seed_delta_runs (
    checkpoint_digest TEXT PRIMARY KEY,
    previous_checkpoint_digest TEXT NOT NULL,
    profile TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    event_cursor INTEGER NOT NULL,
    inserted_event_count INTEGER NOT NULL,
    delta_digest TEXT NOT NULL,
    mmr_root TEXT NOT NULL,
    verification_mode TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL
) WITHOUT ROWID;
"""


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def digest(domain: bytes, value: bytes) -> str:
    return "sha256:" + hashlib.sha256(domain + value).hexdigest()


def leaf_hash(event_id: int, event_digest: str) -> str:
    if not event_digest.startswith("sha256:"):
        raise SeedCatalogError("Seed event digest is outside the SHA-256 profile")
    payload = event_id.to_bytes(8, "big") + bytes.fromhex(event_digest.split(":", 1)[1])
    return digest(MMR_LEAF_DOMAIN, payload)


def append_peak(peaks: list[dict[str, Any]], event_id: int, event_digest: str) -> None:
    node = leaf_hash(event_id, event_digest)
    height = 0
    while peaks and int(peaks[-1]["height"]) == height:
        left = str(peaks.pop()["hash"])
        node = digest(MMR_NODE_DOMAIN, bytes.fromhex(left.split(":", 1)[1]) + bytes.fromhex(node.split(":", 1)[1]))
        height += 1
    peaks.append({"height": height, "hash": node})


def mmr_root(peaks: list[dict[str, Any]], event_count: int) -> str:
    material = event_count.to_bytes(8, "big")
    for peak in peaks:
        material += int(peak["height"]).to_bytes(2, "big")
        material += bytes.fromhex(str(peak["hash"]).split(":", 1)[1])
    return digest(MMR_ROOT_DOMAIN, material)


def rebuild_mmr(connection: sqlite3.Connection) -> tuple[list[dict[str, Any]], str, int, int]:
    peaks: list[dict[str, Any]] = []
    count = 0
    cursor = 0
    for event_id, canonical_json, recorded_digest, source_namespace in connection.execute(
        "SELECT event_id,canonical_json,event_digest,source_namespace FROM seed_events ORDER BY event_id"
    ):
        if source_namespace != SEED_NAMESPACE:
            raise SeedCatalogError("full MMR scan found a noncanonical Seed namespace")
        value = _parse_seed_json(str(canonical_json).encode("utf-8"))
        if not isinstance(value, dict) or int(value.get("id") or 0) != int(event_id):
            raise SeedCatalogError(f"raw Seed event identity mismatch at id {event_id}")
        computed_digest = _event_digest(value)
        if computed_digest != recorded_digest:
            raise SeedCatalogError(f"raw Seed event digest mismatch at id {event_id}")
        append_peak(peaks, int(event_id), computed_digest)
        count += 1
        cursor = int(event_id)
    return peaks, mmr_root(peaks, count), count, cursor


def checkpoint_core(state: dict[str, Any]) -> dict[str, Any]:
    return {
        key: state[key]
        for key in (
            "protocol", "event_count", "event_cursor", "mmr_peaks_json", "mmr_root",
            "counts_json", "last_full_source_digest", "last_full_catalog_digest",
            "last_full_verified_at", "delta_since_full", "updated_at",
        )
    }


def checkpoint_digest(state: dict[str, Any]) -> str:
    return digest(CHECKPOINT_DOMAIN, _seed_canonical_bytes(checkpoint_core(state)))


def read_state(connection: sqlite3.Connection) -> dict[str, Any] | None:
    connection.row_factory = sqlite3.Row
    row = connection.execute("SELECT * FROM seed_delta_state WHERE singleton = 1").fetchone()
    return dict(row) if row is not None else None


def validate_state(connection: sqlite3.Connection, state: dict[str, Any]) -> list[dict[str, Any]]:
    if state["protocol"] != PROTOCOL:
        raise SeedCatalogError("Seed delta state protocol mismatch")
    peaks = json.loads(str(state["mmr_peaks_json"]))
    if not isinstance(peaks, list):
        raise SeedCatalogError("Seed delta MMR peaks are invalid")
    if mmr_root(peaks, int(state["event_count"])) != state["mmr_root"]:
        raise SeedCatalogError("Seed delta MMR root does not match its peaks")
    if checkpoint_digest(state) != state["checkpoint_digest"]:
        raise SeedCatalogError("Seed previous checkpoint digest mismatch")
    count, cursor = connection.execute("SELECT COUNT(*), COALESCE(MAX(event_id),0) FROM seed_events").fetchone()
    if int(count) != int(state["event_count"]) or int(cursor) != int(state["event_cursor"]):
        raise SeedCatalogError("Seed catalog cursor/count differs from previous checkpoint")
    return peaks


def _generation_from_state(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "checkpoint_digest": str(state["checkpoint_digest"]),
        "mmr_root": str(state["mmr_root"]),
        "event_count": int(state["event_count"]),
        "event_cursor": int(state["event_cursor"]),
    }


def delta_generation(connection: sqlite3.Connection) -> dict[str, Any]:
    state = read_state(connection)
    if state is None:
        raise SeedCatalogError("Seed delta state is not initialized")
    validate_state(connection, state)
    return _generation_from_state(state)


def write_state(connection: sqlite3.Connection, state: dict[str, Any]) -> None:
    state["checkpoint_digest"] = checkpoint_digest(state)
    connection.execute(
        """
        INSERT INTO seed_delta_state(
          singleton,protocol,event_count,event_cursor,mmr_peaks_json,mmr_root,
          checkpoint_digest,counts_json,last_full_source_digest,last_full_catalog_digest,
          last_full_verified_at,delta_since_full,updated_at
        ) VALUES(1,:protocol,:event_count,:event_cursor,:mmr_peaks_json,:mmr_root,
          :checkpoint_digest,:counts_json,:last_full_source_digest,:last_full_catalog_digest,
          :last_full_verified_at,:delta_since_full,:updated_at)
        ON CONFLICT(singleton) DO UPDATE SET
          protocol=excluded.protocol,event_count=excluded.event_count,event_cursor=excluded.event_cursor,
          mmr_peaks_json=excluded.mmr_peaks_json,mmr_root=excluded.mmr_root,
          checkpoint_digest=excluded.checkpoint_digest,counts_json=excluded.counts_json,
          last_full_source_digest=excluded.last_full_source_digest,
          last_full_catalog_digest=excluded.last_full_catalog_digest,
          last_full_verified_at=excluded.last_full_verified_at,
          delta_since_full=excluded.delta_since_full,updated_at=excluded.updated_at
        """,
        state,
    )


READ_SEAL_RETRY_DELAYS = (1.0, 2.0)


def seal_catalog_for_immutable_read(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Retry a transient checkpoint only; never replay the committed import.

    The strict helper revalidates custody and the caller's pinned generation
    on each attempt. Three 5-second checkpoints plus bounded delays fit within
    the existing 90-second sync unit. Persistent locks still fail closed.
    """
    for attempt in range(len(READ_SEAL_RETRY_DELAYS) + 1):
        try:
            seal = _seal_catalog_once(*args, **kwargs)
            return {**seal, "checkpoint_attempts": attempt + 1}
        except SeedCatalogReadSealError as exc:
            if (
                exc.reason_code != "seed_catalog_checkpoint_busy"
                or attempt == len(READ_SEAL_RETRY_DELAYS)
            ):
                raise
        time.sleep(READ_SEAL_RETRY_DELAYS[attempt])
    raise AssertionError("unreachable read-seal retry state")


def initialize(catalog: Path, profile: str = "delta-migration-full") -> dict[str, Any]:
    started = utc_now()
    with closing(sqlite3.connect(catalog, timeout=30)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.executescript(_DELTA_SCHEMA)
        existing = read_state(connection)
        if existing is not None:
            validate_state(connection, existing)
            expected_generation = _generation_from_state(existing)
            read_seal = seal_catalog_for_immutable_read(
                connection,
                catalog,
                generation_reader=delta_generation,
                expected_generation=expected_generation,
            )
            return {**existing, "catalog_read_seal": read_seal}
        connection.execute("BEGIN IMMEDIATE")
        verification = _verify_connection(connection)
        peaks, root, count, cursor = rebuild_mmr(connection)
        finished = utc_now()
        state = {
            "protocol": PROTOCOL,
            "event_count": count,
            "event_cursor": cursor,
            "mmr_peaks_json": _canonical_text(peaks),
            "mmr_root": root,
            "counts_json": _canonical_text({key: verification[key] for key in _counts(connection)}),
            "last_full_source_digest": verification["source_digest"],
            "last_full_catalog_digest": verification["catalog_digest"],
            "last_full_verified_at": finished,
            "delta_since_full": 0,
            "updated_at": finished,
        }
        write_state(connection, state)
        connection.execute(
            "INSERT INTO seed_delta_runs VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (state["checkpoint_digest"], "", profile, count, cursor, 0, root, root, "full-migration", started, finished),
        )
        expected_generation = delta_generation(connection)
        connection.commit()
        read_seal = seal_catalog_for_immutable_read(
            connection,
            catalog,
            generation_reader=delta_generation,
            expected_generation=expected_generation,
        )
        return {**state, "catalog_read_seal": read_seal}


def read_seal(catalog: Path) -> dict[str, Any]:
    """Checkpoint one already initialized delta catalog without logical writes."""

    try:
        connection = sqlite3.connect(f"file:{catalog}?mode=rw", uri=True, timeout=30)
    except sqlite3.OperationalError as exc:
        raise SeedCatalogError("Seed delta state is not initialized") from exc
    with closing(connection):
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        try:
            state = read_state(connection)
        except sqlite3.OperationalError as exc:
            raise SeedCatalogError("Seed delta state is not initialized") from exc
        if state is None:
            raise SeedCatalogError("Seed delta state is not initialized")
        validate_state(connection, state)
        expected_generation = _generation_from_state(state)
        catalog_read_seal = seal_catalog_for_immutable_read(
            connection,
            catalog,
            generation_reader=delta_generation,
            expected_generation=expected_generation,
        )
        return {**state, "catalog_read_seal": catalog_read_seal}


def _insert_event(connection: sqlite3.Connection, event: dict[str, Any]) -> None:
    canonical = _canonical_text(event)
    event_digest = _event_digest(event)
    existing = connection.execute(
        "SELECT canonical_json,event_digest FROM seed_events WHERE event_id=?", (event["id"],)
    ).fetchone()
    if existing is not None:
        if existing[0] != canonical or existing[1] != event_digest:
            raise SeedCatalogError(f"immutable Seed event conflict at id {event['id']}")
        raise SeedCatalogError(f"delta contains existing Seed event id {event['id']}")
    connection.execute(
        """
        INSERT INTO seed_events(event_id,event_uid,ts_utc,actor,action,level,summary,
          details_json,tags_json,canonical_json,event_digest,source_namespace)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            event["id"], _string(event.get("event_uid", "")), event["ts_utc"],
            _string(event.get("actor", "")), event["action"], _string(event.get("level", "")),
            _string(event.get("summary", "")), _canonical_text(event.get("details") or {}),
            _canonical_text(_string_list(event.get("tags"))), canonical, event_digest, SEED_NAMESPACE,
        ),
    )
    _derive_event(connection, event)


def import_delta(catalog: Path, events: list[dict[str, Any]], *, expected_cursor: int, profile: str) -> dict[str, Any]:
    started_clock = time.monotonic()
    started = utc_now()
    normalized = validate_seed_events(events, source_namespace=SEED_NAMESPACE)
    with closing(sqlite3.connect(catalog, timeout=30)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("BEGIN IMMEDIATE")
        state = read_state(connection)
        if state is None:
            raise SeedCatalogError("Seed delta state is not initialized")
        peaks = validate_state(connection, state)
        previous_checkpoint = str(state["checkpoint_digest"])
        previous_count = int(state["event_count"])
        previous_cursor = int(state["event_cursor"])
        if normalized[0]["id"] <= previous_cursor or normalized[-1]["id"] != expected_cursor:
            raise SeedCatalogError("Seed delta range does not advance exactly to the pinned cursor")
        event_digests: list[str] = []
        for event in normalized:
            _insert_event(connection, event)
            value = _event_digest(event)
            event_digests.append(value)
            append_peak(peaks, int(event["id"]), value)
        new_count = previous_count + len(normalized)
        root = mmr_root(peaks, new_count)
        actual_count, actual_cursor = connection.execute(
            "SELECT COUNT(*), COALESCE(MAX(event_id),0) FROM seed_events"
        ).fetchone()
        if int(actual_count) != new_count or int(actual_cursor) != expected_cursor:
            raise SeedCatalogError("Seed delta post-import cursor/count mismatch")
        placeholders = ",".join("?" for _ in normalized)
        dangling = connection.execute(
            f"""
            SELECT COUNT(*) FROM seed_relations r
            LEFT JOIN seed_entities f ON f.entity_id=r.from_entity_id
            LEFT JOIN seed_entities t ON t.entity_id=r.to_entity_id
            WHERE r.event_id IN ({placeholders}) AND (f.entity_id IS NULL OR t.entity_id IS NULL)
            """,
            [event["id"] for event in normalized],
        ).fetchone()[0]
        if int(dangling):
            raise SeedCatalogError("Seed delta created dangling relations")
        counts = _counts(connection)
        if counts["home_record_count"] != 0:
            raise SeedCatalogError("Integrity Home leaked into the Seed delta")
        finished = utc_now()
        next_state = {
            "protocol": PROTOCOL,
            "event_count": new_count,
            "event_cursor": expected_cursor,
            "mmr_peaks_json": _canonical_text(peaks),
            "mmr_root": root,
            "counts_json": _canonical_text(counts),
            "last_full_source_digest": state["last_full_source_digest"],
            "last_full_catalog_digest": state["last_full_catalog_digest"],
            "last_full_verified_at": state["last_full_verified_at"],
            "delta_since_full": int(state["delta_since_full"]) + len(normalized),
            "updated_at": finished,
        }
        write_state(connection, next_state)
        delta_digest = digest(b"integrity-seed-delta-v1\0", _seed_canonical_bytes(normalized))
        connection.execute(
            "INSERT INTO seed_delta_runs VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                next_state["checkpoint_digest"], previous_checkpoint, profile, new_count,
                expected_cursor, len(normalized), delta_digest, root, "delta", started, finished,
            ),
        )
        expected_generation = delta_generation(connection)
        connection.commit()
        read_seal = seal_catalog_for_immutable_read(
            connection,
            catalog,
            generation_reader=delta_generation,
            expected_generation=expected_generation,
        )
    return {
        "protocol": PROTOCOL + ".receipt", "result": "PASS", "verification_mode": "delta",
        "previous_event_cursor": previous_cursor, "event_cursor": expected_cursor,
        "event_count": new_count, "inserted_event_count": len(normalized),
        "delta_digest": delta_digest, "mmr_root": root,
        "previous_checkpoint_digest": previous_checkpoint,
        "checkpoint_digest": next_state["checkpoint_digest"],
        "last_full_verified_at": next_state["last_full_verified_at"],
        "catalog_read_seal": read_seal,
        "elapsed_ms": round((time.monotonic() - started_clock) * 1000, 3),
        "production_authority": False,
    }


def full_verify(catalog: Path, profile: str = "scheduled-full-verify") -> dict[str, Any]:
    started_clock = time.monotonic()
    started = utc_now()
    with closing(sqlite3.connect(catalog, timeout=30)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("BEGIN IMMEDIATE")
        state = read_state(connection)
        if state is None:
            raise SeedCatalogError("Seed delta state is not initialized")
        validate_state(connection, state)
        verification = _verify_connection(connection)
        peaks, root, count, cursor = rebuild_mmr(connection)
        if root != state["mmr_root"] or count != int(state["event_count"]) or cursor != int(state["event_cursor"]):
            raise SeedCatalogError("full MMR recomputation differs from the delta checkpoint")
        previous = str(state["checkpoint_digest"])
        finished = utc_now()
        state.update(
            {
                "mmr_peaks_json": _canonical_text(peaks), "mmr_root": root,
                "counts_json": _canonical_text({key: verification[key] for key in _counts(connection)}),
                "last_full_source_digest": verification["source_digest"],
                "last_full_catalog_digest": verification["catalog_digest"],
                "last_full_verified_at": finished, "delta_since_full": 0, "updated_at": finished,
            }
        )
        write_state(connection, state)
        connection.execute(
            "INSERT INTO seed_delta_runs VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (state["checkpoint_digest"], previous, profile, count, cursor, 0, root, root, "full", started, finished),
        )
        expected_generation = delta_generation(connection)
        connection.commit()
        read_seal = seal_catalog_for_immutable_read(
            connection,
            catalog,
            generation_reader=delta_generation,
            expected_generation=expected_generation,
        )
    return {
        "protocol": PROTOCOL + ".full-verify-receipt", "result": "PASS",
        "verification_mode": "full", "event_count": count, "event_cursor": cursor,
        "mmr_root": root, "checkpoint_digest": state["checkpoint_digest"],
        "source_digest": verification["source_digest"], "catalog_digest": verification["catalog_digest"],
        "catalog_read_seal": read_seal,
        "elapsed_ms": round((time.monotonic() - started_clock) * 1000, 3),
        "production_authority": False,
    }


def _status_from_state(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL + ".status",
        "status": "READY-DELTA",
        "event_count": int(state["event_count"]),
        "event_cursor": int(state["event_cursor"]),
        "mmr_root": state["mmr_root"],
        "checkpoint_digest": state["checkpoint_digest"],
        "last_full_source_digest": state["last_full_source_digest"],
        "last_full_catalog_digest": state["last_full_catalog_digest"],
        "last_full_verified_at": state["last_full_verified_at"],
        "delta_since_full": int(state["delta_since_full"]),
        "counts": json.loads(str(state["counts_json"])),
        "production_authority": False,
    }


def fast_status(catalog: Path) -> dict[str, Any]:
    with closing(sqlite3.connect(f"file:{catalog}?mode=ro", uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        state = read_state(connection)
        if state is None:
            raise SeedCatalogError("Seed delta state is not initialized")
        validate_state(connection, state)
        return _status_from_state(state)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=("initialize", "read-seal", "sync", "full-verify", "status"),
    )
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--source-url", default="http://127.0.0.1:8765")
    parser.add_argument("--profile", default="systemd-delta-sync")
    parser.add_argument("--page-size", type=int, default=1000)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.mode == "initialize":
        result = initialize(args.catalog, profile=args.profile)
    elif args.mode == "read-seal":
        result = read_seal(args.catalog)
    elif args.mode == "full-verify":
        result = full_verify(args.catalog, profile=args.profile)
    elif args.mode == "status":
        result = fast_status(args.catalog)
    else:
        state = initialize(args.catalog)
        snapshot = fetch_seed_snapshot(
            base_url=args.source_url, page_size=args.page_size, after_event_id=int(state["event_cursor"])
        )
        if not snapshot.events:
            state = initialize(args.catalog, profile=args.profile)
            result = {
                **_status_from_state(state),
                "result": "PASS",
                "verification_mode": "delta-noop",
                "inserted_event_count": 0,
                "catalog_read_seal": state["catalog_read_seal"],
            }
        else:
            result = import_delta(
                args.catalog, snapshot.events, expected_cursor=snapshot.maximum_event_id, profile=args.profile
            )
        result.update(
            {
                "source_url": snapshot.source_url, "fetched_event_count": len(snapshot.events),
                "stabilization_passes": snapshot.stabilization_passes,
            }
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
