from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import seed_catalog_read_seal as read_seal_module
import seed_delta_sync as seed_delta_sync_module
from seed_catalog_read_seal import SeedCatalogReadSealError
from seed_delta_sync import (
    delta_generation,
    fast_status,
    full_verify,
    import_delta,
    initialize,
    read_seal,
    seal_catalog_for_immutable_read,
)

from integrity_guardian.seed_catalog import (
    SeedCatalog,
    SeedCatalogError,
)
from integrity_guardian.seed_catalog import (
    seal_catalog_for_immutable_read as core_seal_catalog_for_immutable_read,
)


def event(event_id: int, uid: str) -> dict[str, object]:
    return {
        "id": event_id,
        "event_uid": uid,
        "ts_utc": f"2026-08-08T00:00:{event_id:02d}Z",
        "actor": "test",
        "action": "agent_change_progress",
        "level": "info",
        "summary": f"event {event_id}",
        "details": {"task_id": "delta-test", "result": "partial"},
        "tags": ["seed", "delta"],
    }


def assert_read_seal(receipt: dict[str, object]) -> None:
    seal = receipt["catalog_read_seal"]
    assert isinstance(seal, dict)
    assert seal["protocol"] == "integrity-guardian/seed-catalog-read-seal/v1"
    assert seal["status"] == "SEALED"
    assert seal["scope"] == "point-in-time-not-a-lease"
    assert seal["checkpoint_mode"] == "TRUNCATE"
    assert seal["busy"] == 0
    assert (seal["log_frames"], seal["checkpointed_frames"]) in ((0, 0), (-1, -1))
    assert seal["wal_state"] in ("ABSENT", "PRESENT_EMPTY")
    assert seal["wal_bytes"] == 0
    assert seal["production_authority"] is False
    if "checkpoint_digest" in receipt:
        assert seal["logical_generation"]["checkpoint_digest"] == receipt[
            "checkpoint_digest"
        ]


def wal_bytes(catalog: Path) -> int:
    wal = catalog.with_name(catalog.name + "-wal")
    return wal.stat().st_size if wal.exists() else 0


def test_delta_checkpoint_matches_independent_full_verifier(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.sqlite3"
    SeedCatalog(catalog).import_events([event(1, "u1"), event(2, "u2")], profile="fixture")
    initial = initialize(catalog)
    assert_read_seal(initial)
    receipt = import_delta(catalog, [event(4, "u4")], expected_cursor=4, profile="test-delta")
    assert receipt["result"] == "PASS"
    assert_read_seal(receipt)
    assert receipt["inserted_event_count"] == 1
    assert receipt["previous_event_cursor"] == 2
    assert receipt["event_cursor"] == 4
    status = fast_status(catalog)
    assert status["event_count"] == 3
    assert status["event_cursor"] == 4
    assert status["mmr_root"] != initial["mmr_root"]
    verified = full_verify(catalog, profile="test-full")
    assert verified["result"] == "PASS"
    assert_read_seal(verified)
    assert verified["mmr_root"] == status["mmr_root"]
    assert fast_status(catalog)["delta_since_full"] == 0
    assert wal_bytes(catalog) == 0


def test_read_seal_fails_closed_for_pinned_reader_then_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog = tmp_path / "catalog.sqlite3"
    SeedCatalog(catalog).import_events([event(1, "u1")], profile="fixture")
    assert_read_seal(initialize(catalog))
    monkeypatch.setattr(read_seal_module, "READ_SEAL_BUSY_TIMEOUT_MS", 10)

    reader = sqlite3.connect(catalog)
    try:
        reader.execute("BEGIN")
        assert reader.execute("SELECT COUNT(*) FROM seed_events").fetchone()[0] == 1
        with pytest.raises(SeedCatalogReadSealError) as captured:
            import_delta(
                catalog,
                [event(2, "u2")],
                expected_cursor=2,
                profile="busy-reader",
            )
        assert captured.value.reason_code == "seed_catalog_checkpoint_busy"
        assert captured.value.catalog_state == "COMMITTED_UNSEALED"
        assert fast_status(catalog)["event_cursor"] == 2
        assert wal_bytes(catalog) > 0
    finally:
        reader.rollback()
        reader.close()

    recovered = initialize(catalog, profile="test-read-seal-recovery")
    assert_read_seal(recovered)
    assert wal_bytes(catalog) == 0


def test_read_seal_accepts_quiescent_catalog_without_wal_data(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.sqlite3"
    SeedCatalog(catalog).import_events([event(1, "u1")], profile="fixture")
    initialized = initialize(catalog)
    expected = {
        key: initialized[key]
        for key in ("checkpoint_digest", "mmr_root", "event_count", "event_cursor")
    }
    with closing(sqlite3.connect(catalog)) as connection:
        seal = seal_catalog_for_immutable_read(
            connection,
            catalog,
            generation_reader=delta_generation,
            expected_generation=expected,
        )
    assert seal["status"] == "SEALED"
    assert seal["wal_bytes"] == 0


def test_read_seal_wraps_generation_failure_and_matches_core_digest(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.sqlite3"
    SeedCatalog(catalog).import_events([event(1, "u1")], profile="fixture")
    initialize(catalog)
    def generation_reader(connection: sqlite3.Connection) -> dict[str, object]:
        return {
            "event_count": int(
                connection.execute("SELECT COUNT(*) FROM seed_events").fetchone()[0]
            )
        }
    with closing(sqlite3.connect(catalog)) as connection:
        operator_seal = seal_catalog_for_immutable_read(
            connection,
            catalog,
            generation_reader=generation_reader,
        )
        core_seal = core_seal_catalog_for_immutable_read(
            connection,
            catalog,
            generation_reader=generation_reader,
            durable_commit=True,
        )
        assert operator_seal["generation_digest"] == core_seal["generation_digest"]

        def fail_generation(current: sqlite3.Connection) -> dict[str, object]:
            del current
            raise RuntimeError("synthetic generation failure")

        with pytest.raises(SeedCatalogReadSealError) as captured:
            seal_catalog_for_immutable_read(
                connection,
                catalog,
                generation_reader=fail_generation,
            )
    assert captured.value.reason_code == "seed_catalog_generation_verification_failed"
    assert captured.value.catalog_state == "COMMITTED_UNSEALED"


def test_read_seal_mode_refuses_uninitialized_catalog_without_migration(
    tmp_path: Path,
) -> None:
    catalog = tmp_path / "catalog.sqlite3"
    SeedCatalog(catalog).import_events([event(1, "u1")], profile="fixture")
    with pytest.raises(SeedCatalogError, match="not initialized"):
        read_seal(catalog)
    with closing(sqlite3.connect(f"file:{catalog}?mode=ro", uri=True)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'seed_delta_%'"
        ).fetchone()[0] == 0

    initialized = initialize(catalog)
    recovered = read_seal(catalog)
    assert_read_seal(recovered)
    assert recovered["checkpoint_digest"] == initialized["checkpoint_digest"]


def test_read_seal_rejects_connection_for_another_catalog(tmp_path: Path) -> None:
    first = tmp_path / "first.sqlite3"
    second = tmp_path / "second.sqlite3"
    SeedCatalog(first).import_events([event(1, "u1")], profile="fixture")
    SeedCatalog(second).import_events([event(1, "v1")], profile="fixture")
    initialize(first)
    initialize(second)
    with (
        closing(sqlite3.connect(first)) as connection,
        pytest.raises(SeedCatalogReadSealError) as captured,
    ):
        seal_catalog_for_immutable_read(
            connection,
            second,
            generation_reader=delta_generation,
        )
    assert captured.value.reason_code == "seed_catalog_connection_mismatch"


def test_delta_noop_reseals_after_source_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    catalog = tmp_path / "catalog.sqlite3"
    SeedCatalog(catalog).import_events([event(1, "u1")], profile="fixture")
    initialize(catalog)
    writers: list[sqlite3.Connection] = []

    def fetch_with_concurrent_commit(**kwargs: object) -> SimpleNamespace:
        del kwargs
        writer = sqlite3.connect(catalog)
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE source_fetch_probe(value INTEGER NOT NULL)")
        writer.execute("INSERT INTO source_fetch_probe VALUES(1)")
        writer.commit()
        writers.append(writer)
        assert wal_bytes(catalog) > 0
        return SimpleNamespace(
            events=[],
            source_url="http://127.0.0.1:8765",
            stabilization_passes=1,
        )

    monkeypatch.setattr(
        seed_delta_sync_module,
        "parse_args",
        lambda: argparse.Namespace(
            mode="sync",
            catalog=catalog,
            source_url="http://127.0.0.1:8765",
            profile="test-noop-reseal",
            page_size=1000,
        ),
    )
    monkeypatch.setattr(
        seed_delta_sync_module,
        "fetch_seed_snapshot",
        fetch_with_concurrent_commit,
    )
    monkeypatch.setattr(
        seed_delta_sync_module,
        "fast_status",
        lambda catalog_path: pytest.fail(f"noop reopened {catalog_path}"),
    )
    try:
        assert seed_delta_sync_module.main() == 0
    finally:
        for writer in writers:
            writer.close()
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["verification_mode"] == "delta-noop"
    assert_read_seal(receipt)
    assert wal_bytes(catalog) == 0


def test_delta_conflict_rolls_back_without_advancing_checkpoint(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.sqlite3"
    SeedCatalog(catalog).import_events([event(1, "u1")], profile="fixture")
    before = initialize(catalog)
    conflict = event(2, "u1")
    with pytest.raises(sqlite3.IntegrityError):
        import_delta(catalog, [conflict], expected_cursor=2, profile="conflict")
    after = fast_status(catalog)
    assert after["checkpoint_digest"] == before["checkpoint_digest"]
    assert after["event_count"] == 1


def test_tampered_checkpoint_is_rejected_before_delta(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.sqlite3"
    SeedCatalog(catalog).import_events([event(1, "u1")], profile="fixture")
    initialize(catalog)
    with sqlite3.connect(catalog) as connection:
        connection.execute("UPDATE seed_delta_state SET event_cursor=99 WHERE singleton=1")
        connection.commit()
    with pytest.raises(SeedCatalogError, match="checkpoint digest mismatch"):
        fast_status(catalog)


def test_full_verify_rejects_tampered_raw_event_bytes(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.sqlite3"
    SeedCatalog(catalog).import_events([event(1, "u1")], profile="fixture")
    initialize(catalog)
    with sqlite3.connect(catalog) as connection:
        connection.execute(
            "UPDATE seed_events SET canonical_json=replace(canonical_json,'event 1','forged event') WHERE event_id=1"
        )
        connection.commit()
    with pytest.raises(SeedCatalogError, match="raw Seed event digest mismatch"):
        full_verify(catalog, profile="tamper-check")
