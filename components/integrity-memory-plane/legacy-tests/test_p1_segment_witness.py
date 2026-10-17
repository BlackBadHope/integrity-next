from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from p1_segment_witness import immutable_write, write_witness  # noqa: E402


def make_db(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        PRAGMA journal_mode=WAL;
        CREATE TABLE events(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ts_utc TEXT NOT NULL,
          actor TEXT NOT NULL, session_id TEXT NOT NULL DEFAULT '',
          level TEXT NOT NULL, action TEXT NOT NULL, summary TEXT NOT NULL,
          details TEXT NOT NULL, tags TEXT NOT NULL, created_utc TEXT NOT NULL,
          event_uid TEXT NOT NULL DEFAULT ''
        );
        CREATE UNIQUE INDEX idx_events_event_uid ON events(event_uid) WHERE event_uid <> '';
        CREATE TRIGGER events_append_only_no_update BEFORE UPDATE ON events BEGIN
          SELECT RAISE(ABORT, 'append-only'); END;
        CREATE TRIGGER events_append_only_no_delete BEFORE DELETE ON events BEGIN
          SELECT RAISE(ABORT, 'append-only'); END;
        """
    )
    values = [
        (1, "first", "uid-1"),
        (2, "second", "uid-2"),
        (4, "fourth", "uid-4"),
    ]
    for event_id, summary, uid in values:
        connection.execute(
            "INSERT INTO events(id,ts_utc,actor,session_id,level,action,summary,details,tags,created_utc,event_uid) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, "2026-08-08T00:00:00Z", "test", "s", "info", "note", summary, json.dumps({"id": event_id}), "[]", "2026-08-08T00:00:00Z", uid),
        )
    connection.commit()
    connection.close()


class P1SegmentWitnessTests(unittest.TestCase):
    def args(self, root: Path, db: Path) -> SimpleNamespace:
        return SimpleNamespace(
            source_db=db,
            store_root=root / "store",
            lock=root / "writer.lock",
            namespace="seed://project/test",
            segment_events=2,
            max_events=0,
        )

    def test_full_backfill_noop_and_incremental_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db = root / "events.sqlite3"
            make_db(db)
            args = self.args(root, db)
            first = write_witness(args)
            self.assertEqual("pass", first["status"])
            self.assertEqual(4, first["witness_cursor"])
            self.assertEqual(3, first["witness_event_count"])
            self.assertEqual(2, first["segment_count"])
            self.assertEqual("noop", write_witness(args)["status"])
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "INSERT INTO events(id,ts_utc,actor,session_id,level,action,summary,details,tags,created_utc,event_uid) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (5, "2026-08-08T00:01:00Z", "test", "s", "info", "note", "fifth", "{}", "[]", "2026-08-08T00:01:00Z", "uid-5"),
                )
                connection.commit()
            third = write_witness(args)
            self.assertEqual(5, third["witness_cursor"])
            self.assertEqual(4, third["witness_event_count"])
            references = sorted((args.store_root / "segments").glob("*.json"))
            self.assertEqual(3, len(references))
            manifests = [json.loads(path.read_text()) for path in references]
            self.assertEqual("", manifests[0]["previous_manifest_sha256"])
            for previous, current in zip(references, manifests[1:]):
                expected = previous.name.rsplit("-", 1)[-1].removesuffix(".json")
                self.assertEqual(expected, current["previous_manifest_sha256"])

    def test_immutable_collision_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "object"
            immutable_write(path, b"first")
            self.assertEqual(immutable_write(path, b"first"), immutable_write(path, b"first"))
            with self.assertRaises(RuntimeError):
                immutable_write(path, b"different")


if __name__ == "__main__":
    unittest.main()
