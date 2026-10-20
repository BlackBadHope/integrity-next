import hashlib
import os
from pathlib import Path
import sqlite3

import pytest

from integrity_guardian.memory_synapse_mcp import (
    FrozenSeedCatalogSnapshot, ReadPlaneUnavailableError,
)

pytestmark = pytest.mark.skipif(os.name != "posix", reason="production Linux owner-lock boundary")


def paths(tmp_path):
    source = tmp_path / "source.sqlite3"
    with sqlite3.connect(source) as db:
        db.execute("CREATE TABLE fixture(value TEXT)")
        db.execute("INSERT INTO fixture VALUES('original')")
    source.chmod(0o600)
    root = tmp_path / "sessions"
    root.mkdir(mode=0o700)
    return source, root


def test_pragmas_are_destination_only_and_copy_is_immutable(tmp_path, monkeypatch):
    source, root = paths(tmp_path)
    source_before = hashlib.sha256(source.read_bytes()).hexdigest()
    real_connect = sqlite3.connect
    commands = []
    class TracedConnection(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            commands.append((self.role, sql))
            return super().execute(sql, *args, **kwargs)
    def connect(database, *args, **kwargs):
        connection = real_connect(database, *args, factory=TracedConnection, **kwargs)
        connection.role = "source" if str(database).startswith("file:") else "destination"
        return connection
    monkeypatch.setattr(sqlite3, "connect", connect)
    frozen = FrozenSeedCatalogSnapshot(source, root)
    try:
        assert ("destination", "PRAGMA journal_mode=OFF") in commands
        assert ("destination", "PRAGMA synchronous=OFF") in commands
        assert ("destination", "PRAGMA quick_check") in commands
        assert not any(role == "source" and sql.startswith("PRAGMA") for role, sql in commands)
        assert hashlib.sha256(source.read_bytes()).hexdigest() == source_before
        with real_connect(source) as writer:
            writer.execute("UPDATE fixture SET value='new source value'")
        with real_connect(f"file:{frozen.path}?mode=ro&immutable=1", uri=True) as reader:
            assert reader.execute("SELECT value FROM fixture").fetchone()[0] == "original"
    finally:
        frozen.close()
    assert not list(root.glob(".seed-session-*"))


def test_backup_failure_removes_disposable_copy(tmp_path, monkeypatch):
    source, root = paths(tmp_path)
    real_connect = sqlite3.connect
    class FailedConnection(sqlite3.Connection):
        def backup(self, *args, **kwargs):
            raise RuntimeError("synthetic interrupted backup")
    monkeypatch.setattr(sqlite3, "connect", lambda *args, **kwargs: real_connect(*args, factory=FailedConnection, **kwargs))
    with pytest.raises(RuntimeError, match="synthetic interrupted"):
        FrozenSeedCatalogSnapshot(source, root)
    assert not list(root.glob(".seed-session-*"))


def test_pending_source_wal_still_refused(tmp_path):
    source, root = paths(tmp_path)
    with sqlite3.connect(source) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("INSERT INTO fixture VALUES('pending WAL')")
        writer.commit()
        for suffix in ("-wal", "-shm"):
            source.with_name(source.name + suffix).chmod(0o600)
        assert source.with_name(source.name + "-wal").stat().st_size > 0
        with pytest.raises(ReadPlaneUnavailableError) as error:
            FrozenSeedCatalogSnapshot(source, root)
        assert error.value.reason_code == "seed_catalog_checkpoint_required"
        assert not list(root.glob(".seed-session-*"))
