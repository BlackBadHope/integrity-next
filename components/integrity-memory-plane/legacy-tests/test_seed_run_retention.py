from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from seed_run_retention import choose_delta_runs, choose_runs, main


def row(index: int, day: int, profile: str = "systemd-live-sync", result: str = "PASS") -> dict[str, object]:
    return {
        "run_id": f"run-{index}",
        "profile": profile,
        "result": result,
        "finished_at": f"2026-08-{day:02d}T00:{index % 60:02d}:00Z",
    }


def delta_row(index: int, day: int, profile: str = "systemd-live-delta", mode: str = "delta") -> dict[str, object]:
    return {
        "checkpoint_digest": f"checkpoint-{index}",
        "profile": profile,
        "verification_mode": mode,
        "finished_at": f"2026-08-{day:02d}T00:{index % 60:02d}:00Z",
    }


class SeedRunRetentionTests(unittest.TestCase):
    def test_keeps_recent_daily_edges_failures_and_release_runs(self) -> None:
        rows = [row(index, 1 + index // 10) for index in range(30)]
        rows.append(row(31, 4, result="FAIL"))
        rows.append(row(32, 4, profile="signed-release-seal"))
        keep, archived = choose_runs(rows, keep_recent=5)
        self.assertTrue({"run-27", "run-28", "run-29"}.issubset(keep))
        self.assertIn("run-31", keep)
        self.assertIn("run-32", keep)
        self.assertIn("run-0", keep)
        self.assertIn("run-9", keep)
        self.assertGreater(len(archived), 0)
        self.assertEqual(len(rows), len(keep) + len(archived))

    def test_archives_before_bounded_delete_and_keeps_catalog_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalog = root / "catalog.sqlite3"
            connection = sqlite3.connect(catalog)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "CREATE TABLE seed_catalog_runs(run_id TEXT PRIMARY KEY, profile TEXT, result TEXT, finished_at TEXT)"
            )
            connection.execute(
                "CREATE TABLE seed_delta_runs(checkpoint_digest TEXT PRIMARY KEY, profile TEXT, verification_mode TEXT, finished_at TEXT)"
            )
            rows = [row(index, 1 + index // 10) for index in range(30)]
            delta_rows = [delta_row(index, 1 + index // 10) for index in range(30)]
            connection.executemany(
                "INSERT INTO seed_catalog_runs(run_id,profile,result,finished_at) VALUES(:run_id,:profile,:result,:finished_at)",
                rows,
            )
            connection.executemany(
                "INSERT INTO seed_delta_runs(checkpoint_digest,profile,verification_mode,finished_at) VALUES(:checkpoint_digest,:profile,:verification_mode,:finished_at)",
                delta_rows,
            )
            connection.commit()
            connection.close()
            arguments = [
                "seed_run_retention.py", "--catalog", str(catalog),
                "--local-root", str(root / "local"), "--vdb-root", str(root / "vdb"),
                "--evidence-root", str(root / "evidence"), "--lock", str(root / "retention.lock"),
                "--keep-recent", "5",
            ]
            with patch.object(sys, "argv", arguments):
                self.assertEqual(0, main())
            with sqlite3.connect(catalog) as connection:
                remaining = connection.execute("SELECT COUNT(*) FROM seed_catalog_runs").fetchone()[0]
                delta_remaining = connection.execute("SELECT COUNT(*) FROM seed_delta_runs").fetchone()[0]
                self.assertEqual("ok", connection.execute("PRAGMA quick_check").fetchone()[0])
            self.assertLess(remaining, len(rows))
            self.assertLess(delta_remaining, len(delta_rows))
            wal = catalog.with_name(catalog.name + "-wal")
            self.assertEqual(0, wal.stat().st_size if wal.exists() else 0)
            retention_receipt = next(
                path
                for path in (root / "evidence").glob("seed-run-retention-*.json")
            )
            seal = json.loads(retention_receipt.read_text(encoding="utf-8"))[
                "catalog_read_seal"
            ]
            self.assertEqual("SEALED", seal["status"])
            self.assertEqual(0, seal["wal_bytes"])
            self.assertEqual(1, len(list((root / "local").glob("*.jsonl.gz"))))
            self.assertEqual(1, len(list((root / "vdb").glob("*.jsonl.gz"))))
            self.assertEqual(1, len(list((root / "local" / "delta").glob("*.jsonl.gz"))))
            self.assertEqual(1, len(list((root / "vdb" / "delta").glob("*.jsonl.gz"))))

    def test_delta_policy_keeps_recent_daily_edges_and_release_checkpoints(self) -> None:
        rows = [delta_row(index, 1 + index // 10) for index in range(30)]
        rows.append(delta_row(31, 4, profile="release-seal", mode="full"))
        keep, archived = choose_delta_runs(rows, keep_recent=5)
        self.assertTrue({"checkpoint-27", "checkpoint-28", "checkpoint-29"}.issubset(keep))
        self.assertIn("checkpoint-31", keep)
        self.assertIn("checkpoint-0", keep)
        self.assertIn("checkpoint-9", keep)
        self.assertGreater(len(archived), 0)
        self.assertEqual(len(rows), len(keep) + len(archived))

    def test_noop_reseals_pending_wal_from_previous_writer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalog = root / "catalog.sqlite3"
            connection = sqlite3.connect(catalog)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "CREATE TABLE seed_catalog_runs(run_id TEXT PRIMARY KEY, profile TEXT, result TEXT, finished_at TEXT)"
            )
            connection.execute(
                "INSERT INTO seed_catalog_runs VALUES('run-1','test','PASS','2026-08-01T00:00:00Z')"
            )
            connection.commit()
            connection.close()

            writer = sqlite3.connect(catalog)
            writer.execute("PRAGMA wal_autocheckpoint=0")
            writer.execute("CREATE TABLE prior_writer_probe(value INTEGER NOT NULL)")
            writer.execute("INSERT INTO prior_writer_probe VALUES(1)")
            writer.commit()
            wal = catalog.with_name(catalog.name + "-wal")
            self.assertGreater(wal.stat().st_size, 0)

            arguments = [
                "seed_run_retention.py", "--catalog", str(catalog),
                "--local-root", str(root / "local"), "--vdb-root", str(root / "vdb"),
                "--evidence-root", str(root / "evidence"), "--lock", str(root / "retention.lock"),
                "--keep-recent", "256",
            ]
            try:
                with patch.object(sys, "argv", arguments):
                    self.assertEqual(0, main())
            finally:
                writer.close()

            receipt_path = next(
                path
                for path in (root / "evidence").glob("seed-run-retention-*.json")
            )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual("noop", receipt["status"])
            self.assertEqual("SEALED", receipt["catalog_read_seal"]["status"])
            self.assertEqual(0, receipt["catalog_read_seal"]["wal_bytes"])
            self.assertEqual(0, wal.stat().st_size if wal.exists() else 0)


if __name__ == "__main__":
    unittest.main()
