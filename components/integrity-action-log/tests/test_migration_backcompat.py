"""An old Action Log gains seat columns without dropping append-only triggers."""
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path


def _load(tmp_path, monkeypatch):
    component = Path(__file__).resolve().parents[1]
    source = component / "src/integrity_action_log/resources"
    template = json.loads((component / "configuration.example.json").read_text())
    template.update(configured=True)
    template["values"] = {key: str(tmp_path / key) for key in template["values"]}
    config = tmp_path / "config.json"
    config.write_text(json.dumps(template), encoding="utf-8")
    monkeypatch.setenv("INTEGRITY_ACTION_LOG_CONFIG", str(config))
    monkeypatch.setenv("CODEX_LOG_DB", str(tmp_path / "legacy.sqlite3"))
    monkeypatch.setenv("CODEX_LOG_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("INTEGRITY_ISOLATION_MODE", raising=False)
    monkeypatch.syspath_prepend(str(source))
    spec = importlib.util.spec_from_file_location(
        "seat_migration_action_log", source / "codex_action_log.py"
    )
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


def test_old_database_upgrades_and_keeps_append_only_triggers(tmp_path, monkeypatch):
    database = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute(
        """
        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_utc TEXT NOT NULL,
            actor TEXT NOT NULL,
            session_id TEXT NOT NULL DEFAULT '',
            level TEXT NOT NULL,
            action TEXT NOT NULL,
            summary TEXT NOT NULL,
            details TEXT NOT NULL,
            tags TEXT NOT NULL,
            created_utc TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        INSERT INTO events
          (ts_utc, actor, session_id, level, action, summary, details, tags, created_utc)
        VALUES ('2020-01-01T00:00:00Z', 'owner', '', 'info', 'note', 'legacy', '{}', '[]',
                '2020-01-01T00:00:00Z')
        """
    )
    for name, verb in (
        ("events_append_only_no_update", "UPDATE"),
        ("events_append_only_no_delete", "DELETE"),
    ):
        connection.execute(
            f"""
            CREATE TRIGGER {name}
            BEFORE {verb} ON events
            BEGIN
                SELECT RAISE(ABORT, 'append-only Action Log: {verb} forbidden');
            END
            """
        )
    connection.commit()
    before = {
        row[0]: row[1]
        for row in connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' ORDER BY name"
        )
    }
    connection.close()

    log = _load(tmp_path, monkeypatch)
    log.ensure_db()
    inspected = sqlite3.connect(database)
    columns = {row[1]: row for row in inspected.execute("PRAGMA table_info(events)")}
    assert columns["seat_id"][4] in {"seat_owner", "'seat_owner'"}
    assert columns["host_id"][4] in {"local", "'local'"}
    assert columns["namespace"][4] in {"team/default", "'team/default'"}
    assert columns["auth_principal_sha256"][4] in {"", "''"}
    row = inspected.execute(
        "SELECT seat_id, host_id, namespace, auth_principal_sha256 FROM events"
    ).fetchone()
    assert row == ("seat_owner", "local", "team/default", "")
    after = {
        name: sql
        for name, sql in inspected.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'trigger'"
        )
    }
    assert before == {name: after[name] for name in before}
    inspected.close()
    with log.open_db() as guarded:
        try:
            guarded.execute("DROP TRIGGER events_append_only_no_update")
        except sqlite3.DatabaseError:
            denied = True
        else:
            denied = False
    assert denied
