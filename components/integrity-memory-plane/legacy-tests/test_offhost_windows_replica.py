from __future__ import annotations

import gzip
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from memory_plane_common import atomic_json, canonical_json, sha256_file  # noqa: E402
from offhost_windows_replica import PROTOCOL, TAIL_PROTOCOL, build_capsule, parse_exec_wrapper, remote_pull_command, verified_source  # noqa: E402


class OffhostWindowsReplicaTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path]:
        full = root / "full"
        tail = root / "tail"
        full.mkdir()
        tail.mkdir()
        archive = full / "action-log-full-test-cursor-2.tar.gz"
        archive.write_bytes(b"full-backup")
        atomic_json(
            full / "full-backup-test.json",
            {"archive": {"name": archive.name, "bytes": archive.stat().st_size, "sha256": sha256_file(archive)}, "snapshot": {"event_cursor": 2}},
        )
        columns = ["id", "summary"]
        rows = [[3, "three"]]
        payload = tail / "events-00000000000000000003-00000000000000000003.jsonl.gz"
        with payload.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as handle:
                handle.write(canonical_json({"protocol": TAIL_PROTOCOL, "columns": columns}) + b"\n")
                for row in rows:
                    handle.write(canonical_json(row) + b"\n")
        row_digest = hashlib.sha256()
        for row in rows:
            encoded = canonical_json(row)
            row_digest.update(len(encoded).to_bytes(8, "big"))
            row_digest.update(encoded)
        manifest = {
            "protocol": TAIL_PROTOCOL,
            "first_cursor": 3,
            "last_cursor": 3,
            "event_count": 1,
            "columns": columns,
            "row_sha256": row_digest.hexdigest(),
            "previous_manifest_sha256": "",
            "payload": {"name": payload.name, "bytes": payload.stat().st_size, "sha256": sha256_file(payload)},
        }
        manifest_path = tail / "events-00000000000000000003-00000000000000000003.manifest.json"
        atomic_json(manifest_path, manifest)
        atomic_json(
            tail / "state.json",
            {"protocol": TAIL_PROTOCOL + ".state", "archived_cursor": 3, "previous_manifest_sha256": sha256_file(manifest_path), "segment_count": 1},
        )
        return full, tail

    def test_verified_source_and_capsule_bind_full_and_tail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            full, tail = self.fixture(root)
            source = verified_source(full, tail)
            capsule = build_capsule(source, root / "export", "workspace")
            repeated = build_capsule(source, root / "export", "workspace")
            self.assertEqual(2, source["full_cursor"])
            self.assertEqual(3, source["tail_cursor"])
            self.assertEqual(64, len(capsule["sha256"]))
            self.assertEqual(PROTOCOL + ".capsule", capsule["inventory"]["protocol"])
            self.assertGreaterEqual(len(capsule["inventory"]["files"]), 5)
            self.assertEqual(capsule["name"], repeated["name"])
            self.assertEqual(capsule["sha256"], repeated["sha256"])

    def test_hash_chain_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            full, tail = self.fixture(Path(temporary))
            state = json.loads((tail / "state.json").read_text())
            state["previous_manifest_sha256"] = "0" * 64
            atomic_json(tail / "state.json", state)
            with self.assertRaisesRegex(RuntimeError, "tail state"):
                verified_source(full, tail)

    def test_remote_command_is_strict_and_never_overwrites_mismatch(self) -> None:
        args = type(
            "Args",
            (),
            {
                "remote_root": r"D:\workspace\IntegrityMemoryPlane\action-log\capsules",
                "pull_user": "workspace",
                "pull_port": 22111,
                "pull_key": r"C:/workspace/example-data",
                "pull_known_hosts": r"C:/workspace/example-data",
                "pull_host_key_alias": "integrity-offhost",
            },
        )()
        command = remote_pull_command(args, {"path": Path("/var/lib/export/capsule.tar.gz"), "name": "capsule.tar.gz", "sha256": "a" * 64})
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("existing offhost capsule digest mismatch", command)
        self.assertNotIn("Move-Item -Force", command)

    def test_zero_exit_code_is_accepted_and_nonzero_is_rejected(self) -> None:
        remote = {"ok": True, "sha256": "a" * 64}
        wrapper = {"ok": True, "timed_out": False, "exit_code": 0, "stdout": json.dumps(remote), "stderr": ""}
        self.assertEqual(remote, parse_exec_wrapper(wrapper))
        wrapper["exit_code"] = 1
        with self.assertRaisesRegex(RuntimeError, "off-host pull failed"):
            parse_exec_wrapper(wrapper)


if __name__ == "__main__":
    unittest.main()
