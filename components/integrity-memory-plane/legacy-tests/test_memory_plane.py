from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from action_log_full_backup import online_backup, test_sqlite_guards  # noqa: E402
from memory_plane_common import REQUIRED_APPEND_ONLY_TRIGGERS, database_facts, readonly_connection, safe_copy, snapshot_connection  # noqa: E402


def fixture(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts_utc TEXT NOT NULL, actor TEXT NOT NULL, session_id TEXT NOT NULL DEFAULT '',
          level TEXT NOT NULL, action TEXT NOT NULL, summary TEXT NOT NULL,
          details TEXT NOT NULL, tags TEXT NOT NULL, created_utc TEXT NOT NULL,
          event_uid TEXT NOT NULL DEFAULT ''
        );
        CREATE UNIQUE INDEX idx_events_event_uid ON events(event_uid) WHERE event_uid <> '';
        CREATE TRIGGER events_append_only_no_update BEFORE UPDATE ON events BEGIN
          SELECT RAISE(ABORT, 'append-only Action Log: UPDATE forbidden'); END;
        CREATE TRIGGER events_append_only_no_delete BEFORE DELETE ON events BEGIN
          SELECT RAISE(ABORT, 'append-only Action Log: DELETE forbidden'); END;
        """
    )
    for index in range(1, 5):
        connection.execute(
            "INSERT INTO events(ts_utc,actor,session_id,level,action,summary,details,tags,created_utc,event_uid) VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("2026-08-08T00:00:00Z", "test", "s", "info", "note", f"event {index}", json.dumps({"n": index}), "[]", "2026-08-08T00:00:00Z", f"u-{index}"),
        )
    connection.commit()
    connection.close()


class MemoryPlaneTests(unittest.TestCase):
    def test_snapshot_connection_allows_wal_coordination_but_rejects_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.sqlite3"
            fixture(source)
            with snapshot_connection(source) as connection:
                self.assertEqual(1, connection.execute("PRAGMA query_only").fetchone()[0])
                self.assertEqual(4, connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
                with self.assertRaises(sqlite3.OperationalError):
                    connection.execute(
                        "INSERT INTO events(ts_utc,actor,level,action,summary,details,tags,created_utc) "
                        "VALUES('x','x','info','x','x','{}','[]','x')"
                    )

    def test_online_backup_preserves_facts_and_guards(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.sqlite3"
            target = root / "target.sqlite3"
            fixture(source)
            with readonly_connection(source) as connection:
                before = database_facts(connection)
            after = online_backup(source, target)
            self.assertEqual(before, after)
            self.assertTrue(REQUIRED_APPEND_ONLY_TRIGGERS.issubset(after["append_only_triggers"]))
            self.assertEqual({"update_rejected": True, "delete_rejected": True}, test_sqlite_guards(target))

    def test_safe_copy_requires_identical_readback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "nested" / "destination"
            source.write_bytes(b"canonical-memory")
            digest = safe_copy(source, destination)
            self.assertEqual(source.read_bytes(), destination.read_bytes())
            self.assertEqual(64, len(digest))


if __name__ == "__main__":
    unittest.main()
