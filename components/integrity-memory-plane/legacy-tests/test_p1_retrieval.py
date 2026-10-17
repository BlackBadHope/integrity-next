from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from p1_projection import rebuild_projection, sparse_vector  # noqa: E402
from p1_retrieval import retrieve  # noqa: E402
from p1_segment_witness import write_witness  # noqa: E402
from tests.test_p1_segment_witness import make_db  # noqa: E402


class P1RetrievalTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path]:
        source = root / "source.sqlite3"
        make_db(source)
        args = type("Args", (), {"source_db": source, "store_root": root / "store", "lock": root / "writer.lock", "namespace": "seed://project/test", "segment_events": 2, "max_events": 0})()
        write_witness(args)
        projection = root / "projection.sqlite3"
        rebuild_projection(args.store_root, projection)
        return args.store_root, projection

    def test_exact_and_fts_receipts_are_bounded_and_proven(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store, projection = self.fixture(Path(temporary))
            exact = retrieve("#1", projection, store, limit=10, capsule_budget=8192)
            self.assertEqual("SUPPORTED", exact["decision"])
            self.assertEqual(1, exact["included_event_ids"][0])
            self.assertTrue(exact["all_included_proven"])
            self.assertEqual(0, exact["unsupported_green_count"])
            self.assertLessEqual(exact["capsule_bytes"], 8192)
            fts = retrieve("first", projection, store, limit=10, capsule_budget=8192)
            self.assertEqual("SUPPORTED", fts["decision"])
            self.assertIn(1, fts["included_event_ids"])
            self.assertGreater(fts["routes"]["fts"]["candidate_count"], 0)

    def test_unknown_query_never_becomes_green(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store, projection = self.fixture(Path(temporary))
            result = retrieve("zzzz-no-such-memory-zzzz", projection, store, limit=10, capsule_budget=8192)
            self.assertEqual("NO_EVIDENCE", result["decision"])
            self.assertEqual(0, result["unsupported_green_count"])

    def test_vector_collision_cannot_create_support(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store, projection = self.fixture(Path(temporary))
            query = "qzxwvutnomemory987654321"
            sparse, norm = sparse_vector(query)
            with sqlite3.connect(projection) as connection:
                connection.execute(
                    "UPDATE event_vectors SET sparse_json=?,norm=? WHERE event_id=1",
                    (json.dumps(sparse, separators=(",", ":")), norm),
                )
                connection.commit()
            result = retrieve(query, projection, store, limit=10, capsule_budget=8192)
            self.assertGreater(result["routes"]["vector"]["candidate_count"], 0)
            self.assertEqual("NO_EVIDENCE", result["decision"])
            self.assertEqual([], result["included_event_ids"])
            self.assertFalse(result["support_gate"]["vector_only_support_allowed"])

    def test_unproven_manifest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store, projection = self.fixture(Path(temporary))
            with sqlite3.connect(projection) as connection:
                connection.execute("UPDATE events SET source_manifest_sha256='0' WHERE id=1")
                connection.commit()
            result = retrieve("#1", projection, store, limit=10, capsule_budget=8192)
            self.assertEqual("NO_EVIDENCE", result["decision"])
            self.assertEqual(1, result["rejected_unproven_count"])
            self.assertEqual(0, result["unsupported_green_count"])

    def test_task_path_is_ordered_and_receipted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store, projection = self.fixture(Path(temporary))
            with sqlite3.connect(projection) as connection:
                connection.execute("INSERT OR IGNORE INTO graph_nodes(node_key,kind,value) VALUES('task_id:demo','task_id','demo')")
                connection.execute("INSERT INTO graph_edges(event_id,node_key,relation) VALUES(1,'task_id:demo','REFERENCES')")
                connection.execute("INSERT INTO graph_edges(event_id,node_key,relation) VALUES(2,'task_id:demo','REFERENCES')")
                connection.commit()
            result = retrieve("task_path:demo", projection, store, limit=10, capsule_budget=8192)
            self.assertEqual("SUPPORTED", result["decision"])
            self.assertEqual([1, 2], result["causal_path"]["event_ids"])
            self.assertEqual([1, 2], result["included_event_ids"][:2])
            self.assertTrue(result["causal_path"]["complete"])


if __name__ == "__main__":
    unittest.main()
