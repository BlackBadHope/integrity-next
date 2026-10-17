from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from p1_projection import projection_status, rebuild_projection, sparse_vector, sync_projection  # noqa: E402
from p1_segment_witness import write_witness  # noqa: E402
from tests.test_p1_segment_witness import make_db  # noqa: E402


class P1ProjectionTests(unittest.TestCase):
    def test_rebuild_then_incremental_sync(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.sqlite3"
            make_db(source)
            args = type("Args", (), {"source_db": source, "store_root": root / "store", "lock": root / "writer.lock", "namespace": "seed://project/test", "segment_events": 2, "max_events": 0})()
            write_witness(args)
            projection = root / "projection.sqlite3"
            rebuilt = rebuild_projection(args.store_root, projection)
            self.assertEqual(3, rebuilt["counts"]["events"])
            self.assertEqual(3, rebuilt["counts"]["fts"])
            self.assertEqual(3, rebuilt["counts"]["vectors"])
            self.assertGreater(rebuilt["counts"]["graph_nodes"], 0)
            with sqlite3.connect(projection) as connection:
                hits = connection.execute("SELECT event_id FROM events_fts WHERE events_fts MATCH 'first'").fetchall()
                self.assertEqual([(1,)], hits)
            with sqlite3.connect(source) as connection:
                connection.execute(
                    "INSERT INTO events(id,ts_utc,actor,session_id,level,action,summary,details,tags,created_utc,event_uid) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (5, "2026-08-08T00:02:00Z", "test", "s", "info", "note", "task progress", json.dumps({"task_id": "task-5", "result": "partial"}), json.dumps(["p1"]), "2026-08-08T00:02:00Z", "uid-5"),
                )
                connection.commit()
            write_witness(args)
            synced = sync_projection(args.store_root, projection)
            self.assertEqual(1, synced["inserted_event_count"])
            status = projection_status(projection)
            self.assertEqual(4, status["counts"]["events"])
            self.assertEqual(1, status["counts"]["task_state"])
            with sqlite3.connect(f"file:{projection.resolve()}?mode=ro", uri=True) as connection:
                self.assertEqual("delete", connection.execute("PRAGMA journal_mode").fetchone()[0])
                self.assertEqual("ok", connection.execute("PRAGMA quick_check").fetchone()[0])

    def test_sparse_vector_is_deterministic_and_bounded(self) -> None:
        first, first_norm = sparse_vector("Action Log canonical memory")
        second, second_norm = sparse_vector("Action Log canonical memory")
        self.assertEqual(first, second)
        self.assertEqual(first_norm, second_norm)
        self.assertTrue(all(0 <= int(item[0]) < 256 for item in first))


if __name__ == "__main__":
    unittest.main()
