from __future__ import annotations

import os
import pwd
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from integrity_guardian.seed_catalog import SeedCatalog  # noqa: E402
from restore_drill import delta_runtime_rebuild  # noqa: E402


def event(event_id: int, summary: str) -> dict[str, object]:
    return {
        "id": event_id,
        "event_uid": f"restore-{event_id}",
        "ts_utc": "2026-08-08T00:00:00Z",
        "actor": "test",
        "action": "agent_change_progress",
        "level": "info",
        "summary": summary,
        "details": {"task_id": "restore-test", "result": "partial"},
        "tags": ["seed", "restore"],
    }


class RestoreDrillDeltaTests(unittest.TestCase):
    def test_delta_runtime_total_loss_boundary(self) -> None:
        account = pwd.getpwnam("integrity-seed")
        with tempfile.TemporaryDirectory(prefix="restore-delta-test-") as temporary:
            root = Path(temporary)
            os.chown(root, account.pw_uid, account.pw_gid)
            os.chmod(root, 0o700)
            catalog = root / "catalog.sqlite3"
            SeedCatalog(catalog).import_events(
                [
                    event(1, "Action Log canonical memory"),
                    event(2, "Guardian verification"),
                    event(3, "Seed Synapse power outage"),
                    event(1803, "OWNER CONCEPT Action Log is canonical project memory"),
                ],
                profile="restore-delta-fixture",
            )
            os.chown(catalog, account.pw_uid, account.pw_gid)
            args = SimpleNamespace(
                seed_user="integrity-seed",
                delta_sync=Path("/usr/local/libexec/integrity-memory-plane/seed_delta_sync.py"),
                delta_runtime=Path("/usr/local/libexec/integrity-memory-plane/seed_delta_runtime.py"),
            )
            result = delta_runtime_rebuild(args, catalog, 1803, 4, root)
            self.assertTrue(result["ok"], result["checks"])
            self.assertTrue(all(result["checks"].values()), result["checks"])
            self.assertEqual("5.5.2rc2", result["runtime_health"]["version"])
            self.assertEqual(0, result["runtime_health"]["home_record_count"])
            self.assertEqual(405, result["post_rejection"]["status"])


if __name__ == "__main__":
    unittest.main()
