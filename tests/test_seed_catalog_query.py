"""Exact, index-backed Seed event queries versus free-text search."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from integrity_guardian.seed_catalog import SeedCatalog, SeedCatalogError

NAMESPACE = "seed://project/fixture"
EVENTS = [
    {"id": 1, "ts_utc": "2026-09-01T10:00:00Z", "actor": "agent:a", "action": "task_start",
     "summary": "start", "details": {"task_id": "task-1"}},
    {"id": 2, "ts_utc": "2026-09-01T11:00:00Z", "actor": "agent:b", "action": "note",
     "summary": "mentions task-1 only in text", "details": {}},
    {"id": 3, "ts_utc": "2026-09-01T12:00:00Z", "actor": "agent:a", "action": "task_done",
     "summary": "done", "details": {"task_id": "task-1"}},
]


@pytest.fixture
def catalog(tmp_path: Path) -> SeedCatalog:
    value = SeedCatalog(tmp_path / "catalog.sqlite")
    value.import_events(EVENTS, source_namespace=NAMESPACE)
    return value


def ids(rows: list[dict]) -> list[int]:
    return [row["event_id"] for row in rows]


def test_find_events_is_exact_where_search_is_textual(catalog: SeedCatalog) -> None:
    assert ids(catalog.search("task-1")) == [3, 2, 1]
    assert ids(catalog.find_events(task_id="task-1")) == [3, 1]


def test_find_events_combines_filters(catalog: SeedCatalog) -> None:
    assert ids(catalog.find_events(actor="agent:a")) == [3, 1]
    assert ids(catalog.find_events(actor="agent:a", since="2026-09-01T11:30:00Z")) == [3]
    assert ids(catalog.find_events(action="note")) == [2]
    assert ids(catalog.find_events(actor="agent:b", task_id="task-1")) == []
    assert ids(catalog.find_events(actor="agent:a", limit=1)) == [3]


def test_find_events_validates_filters(catalog: SeedCatalog) -> None:
    with pytest.raises(SeedCatalogError):
        catalog.find_events()
    with pytest.raises(SeedCatalogError):
        catalog.find_events(actor=" ")
    with pytest.raises(SeedCatalogError):
        catalog.find_events(actor="agent:a", limit=0)


def test_find_events_uses_indexes(catalog: SeedCatalog) -> None:
    with sqlite3.connect(catalog.path) as connection:
        actor_plan = " ".join(
            row[3] for row in connection.execute(
                "EXPLAIN QUERY PLAN SELECT event_id FROM seed_events WHERE actor = ?", ("x",)
            )
        )
        task_plan = " ".join(
            row[3] for row in connection.execute(
                "EXPLAIN QUERY PLAN SELECT link.event_id FROM seed_entities AS entity "
                "JOIN seed_event_entities AS link ON link.entity_id = entity.entity_id "
                "AND link.role = 'task' WHERE entity.kind = 'task' AND entity.natural_key = ?",
                ("x",),
            )
        )
    assert "idx_seed_events_actor" in actor_plan
    assert "idx_seed_event_entities_entity" in task_plan


def test_catalog_still_verifies_and_survives_reopen(catalog: SeedCatalog) -> None:
    assert catalog.verify()["ok"] is True
    reopened = SeedCatalog(catalog.path)
    assert reopened.event_cursor() == (3, 3)
    assert ids(reopened.find_events(task_id="task-1")) == [3, 1]
