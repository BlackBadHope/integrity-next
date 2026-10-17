from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from p1_segment_verify import verify_store  # noqa: E402
from p1_segment_witness import write_witness  # noqa: E402
from tests.test_p1_segment_witness import make_db  # noqa: E402


class P1SegmentVerifyTests(unittest.TestCase):
    def test_source_parity_and_segment_only_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.sqlite3"
            make_db(source)
            args = type(
                "Args",
                (),
                {
                    "source_db": source,
                    "store_root": root / "store",
                    "lock": root / "writer.lock",
                    "namespace": "seed://project/test",
                    "segment_events": 2,
                    "max_events": 0,
                },
            )()
            write_witness(args)
            restored = root / "restored.sqlite3"
            result = verify_store(args.store_root, source, restored)
            self.assertEqual("pass", result["status"])
            self.assertTrue(all(result["checks"].values()), result["checks"])
            self.assertEqual(0, result["duplicate_event_uid_count"])
            with sqlite3.connect(restored) as connection:
                self.assertEqual(3, connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
                with self.assertRaises(sqlite3.DatabaseError):
                    connection.execute("DELETE FROM events WHERE id=1")

    def test_tampered_payload_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.sqlite3"
            make_db(source)
            args = type(
                "Args",
                (),
                {
                    "source_db": source,
                    "store_root": root / "store",
                    "lock": root / "writer.lock",
                    "namespace": "seed://project/test",
                    "segment_events": 10,
                    "max_events": 0,
                },
            )()
            write_witness(args)
            manifest = json.loads(next((args.store_root / "segments").glob("*.json")).read_text())
            payload = args.store_root / manifest["payload"]["key"]
            payload.chmod(0o600)
            payload.write_bytes(b"tampered")
            with self.assertRaises(RuntimeError):
                verify_store(args.store_root, source, root / "restore.sqlite3")


if __name__ == "__main__":
    unittest.main()
