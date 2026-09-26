"""Seed catalog sync: id-ordered cursor, one bound source, precise verification claims.

Regressions for defects reported against v6.0.0 (b66dd68): the sync tail was
found by ts_utc while pages were read by id, so a backdated or near-future
event broke or silently stalled seed-sync; and one catalog accepted events
from other Seed instances. Each test starts real local runtimes with the
shipped integrity_seed.py launcher in disposable state.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

from integrity_guardian.cli import main as guardian_main
from integrity_guardian.seed_action_log import sync_action_log_seed
from integrity_guardian.seed_catalog import SeedCatalog, SeedCatalogError

REPO = Path(__file__).resolve().parents[1]
LAUNCHER = (
    REPO
    / "components/integrity-seed/plugins/integrity-seed/skills/integrity-seed/scripts"
    / "integrity_seed.py"
)
DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class Runtime:
    def __init__(self, root: Path) -> None:
        self.home = root / "seed"
        self.work = root / "work"
        self.work.mkdir(parents=True, exist_ok=True)

    def cli(self, *args: str) -> subprocess.CompletedProcess:
        env = {
            **os.environ,
            "INTEGRITY_SEED_HOME": str(self.home),
            "CODEX_HOME": str(self.home.parent / "codex-home"),
        }
        return subprocess.run(
            [sys.executable, str(LAUNCHER), *args],
            cwd=self.work, env=env, capture_output=True, text=True, timeout=120, check=False,
        )

    def setup(self) -> Runtime:
        result = self.cli("setup", "--json")
        assert json.loads(result.stdout)["ok"] is True, result.stderr
        return self

    def stop(self) -> None:
        self.cli("stop", "--json")

    @property
    def url(self) -> str:
        receipt = json.loads((self.home / "runtime" / "runtime.json").read_text())
        return f"http://127.0.0.1:{receipt['port']}"

    @property
    def token(self) -> str:
        return (self.home / "runtime" / "token").read_text().strip()

    def post(self, summary: str, **fields) -> dict:
        body = json.dumps({"actor": "agent", "action": "note", "summary": summary, **fields})
        request = urllib.request.Request(
            self.url + "/api/events", data=body.encode(), method="POST",
            headers={"Content-Type": "application/json", "X-Codex-Log-Token": self.token},
        )
        with DIRECT.open(request, timeout=15) as response:
            return json.load(response)


@pytest.fixture
def runtimes(tmp_path: Path):
    started: list[Runtime] = []

    def start(name: str) -> Runtime:
        runtime = Runtime(tmp_path / name).setup()
        started.append(runtime)
        return runtime

    yield start
    for runtime in started:
        runtime.stop()


def sync(runtime: Runtime, catalog: Path, monkeypatch, **kwargs):
    monkeypatch.setenv("CODEX_LOG_TOKEN", runtime.token)
    return sync_action_log_seed(SeedCatalog(catalog), base_url=runtime.url, **kwargs)


def soon(minutes: int) -> str:
    moment = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=minutes)
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def catalog_state(catalog: Path) -> tuple:
    with sqlite3.connect(catalog) as connection:
        return (
            connection.execute("SELECT COUNT(*), MAX(event_id) FROM seed_events").fetchone(),
            SeedCatalog(catalog).verify()["catalog_digest"],
        )


# -- cursor order ---------------------------------------------------------------


def test_backdated_tail_event_is_synced(runtimes, tmp_path, monkeypatch) -> None:
    source = runtimes("a")
    source.post("first")
    source.post("second")
    catalog = tmp_path / "catalog.sqlite3"
    sync(source, catalog, monkeypatch)
    source.post("fact from the past", ts_utc="2020-01-01T00:00:00Z")
    snapshot, report = sync(source, catalog, monkeypatch)
    assert [event["id"] for event in snapshot.events] == [3]
    assert report.maximum_event_id == 3
    assert SeedCatalog(catalog).event_at(3)["ts_utc"] == "2020-01-01T00:00:00Z"
    _, fresh = sync(source, tmp_path / "fresh.sqlite3", monkeypatch)
    assert fresh.maximum_event_id == 3


def test_near_future_event_before_the_tail_is_synced(runtimes, tmp_path, monkeypatch) -> None:
    source = runtimes("a")
    source.post("near future", ts_utc=soon(3))
    source.post("now")
    _, report = sync(source, tmp_path / "catalog.sqlite3", monkeypatch)
    assert (report.event_count, report.maximum_event_id) == (2, 2)


def test_append_and_restart_keep_the_same_source(runtimes, tmp_path, monkeypatch) -> None:
    source = runtimes("a")
    source.post("one")
    catalog = tmp_path / "catalog.sqlite3"
    first, _ = sync(source, catalog, monkeypatch)
    assert first.source_binding == "established"
    source.stop()
    source.setup()
    source.post("two")
    second, report = sync(source, catalog, monkeypatch)
    assert second.source_binding == "matched"
    assert second.source_identity == first.source_identity
    assert second.compared_event_ids == (1,)
    assert report.maximum_event_id == 2


# -- one source per catalog -------------------------------------------------------


@pytest.mark.parametrize("other_count", [1, 4], ids=["overlapping-ids", "higher-last-id"])
def test_other_source_is_refused_before_any_change(
    runtimes, tmp_path, monkeypatch, other_count
) -> None:
    source, other = runtimes("a"), runtimes("b")
    source.post("a1")
    for index in range(other_count):
        other.post(f"b{index}")
    catalog = tmp_path / "catalog.sqlite3"
    sync(source, catalog, monkeypatch)
    before = catalog_state(catalog)
    with pytest.raises(SeedCatalogError, match="different Seed source"):
        sync(other, catalog, monkeypatch)
    assert catalog_state(catalog) == before


def test_recreated_state_at_the_same_path_is_refused(runtimes, tmp_path, monkeypatch) -> None:
    source = runtimes("a")
    source.post("original history")
    catalog = tmp_path / "catalog.sqlite3"
    sync(source, catalog, monkeypatch)
    before = catalog_state(catalog)
    source.stop()
    shutil.rmtree(source.home)
    source.setup()  # same path, so the same workspace_id, but new history
    source.post("replacement history")
    source.post("more")
    with pytest.raises(SeedCatalogError, match="differs from the catalog"):
        sync(source, catalog, monkeypatch)
    assert catalog_state(catalog) == before


def test_unbound_catalog_is_still_checked_against_stored_events(
    runtimes, tmp_path, monkeypatch
) -> None:
    source, other = runtimes("a"), runtimes("b")
    source.post("a1")
    other.post("b1")
    other.post("b2")
    catalog = tmp_path / "catalog.sqlite3"
    sync(source, catalog, monkeypatch)
    with sqlite3.connect(catalog) as connection:  # a catalog written before binding existed
        connection.execute("DELETE FROM seed_metadata WHERE key = 'source_workspace_id'")
    with pytest.raises(SeedCatalogError, match="differs from the catalog"):
        sync(other, catalog, monkeypatch)


def test_namespace_is_bound_explicitly_or_by_default(runtimes, tmp_path, monkeypatch) -> None:
    source = runtimes("a")
    source.post("one")
    explicit = tmp_path / "explicit.sqlite3"
    sync(source, explicit, monkeypatch, source_namespace="seed://project/alpha")
    source.post("two")
    _, report = sync(source, explicit, monkeypatch)  # reuses the bound namespace
    assert report.source_namespace == "seed://project/alpha"
    with pytest.raises(SeedCatalogError, match="namespace differs"):
        sync(source, explicit, monkeypatch, source_namespace="seed://project/beta")
    _, default = sync(source, tmp_path / "default.sqlite3", monkeypatch)
    assert default.source_namespace == "seed://project/default"


# -- what a sync report claims ----------------------------------------------------


def test_sync_report_separates_read_range_from_history(
    runtimes, tmp_path, monkeypatch, capsys
) -> None:
    source = runtimes("a")
    for summary in ("one", "two", "three"):
        source.post(summary)
    catalog = tmp_path / "catalog.sqlite3"
    monkeypatch.setenv("CODEX_LOG_TOKEN", source.token)
    guardian_main(["seed-sync", "--catalog", str(catalog), "--source-url", source.url])
    source.post("four")
    capsys.readouterr()
    guardian_main(["seed-sync", "--catalog", str(catalog), "--source-url", source.url])
    report = json.loads(capsys.readouterr().out)
    assert report["source"]["binding"] == "matched"
    assert report["verification"]["source_read"] == {
        "after_event_id": 3, "through_event_id": 4, "event_count": 1, "contiguous": True,
    }
    assert report["verification"]["stored_events_rechecked_against_source"] == [1, 3]
    assert report["verification"]["earlier_history_proven_unchanged"] is False
    guardian_main(["seed-catalog-verify", "--catalog", str(catalog)])
    verify = json.loads(capsys.readouterr().out)
    assert verify["verification_scope"] == "catalog-self-consistency"
    assert verify["source_compared"] is False


# -- the CLI shows an explicit refusal --------------------------------------------


def test_remember_reports_a_refused_write(runtimes) -> None:
    source = runtimes("a")
    result = source.cli("remember", "--task-id", "t-1", "x" * 2001)
    assert result.returncode == 1
    refusal = json.loads(result.stderr.strip().splitlines()[-1])
    assert refusal["error"] == "summary_too_long" and refusal["limit"] == 2000
