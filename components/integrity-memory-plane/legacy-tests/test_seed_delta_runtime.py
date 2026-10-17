from __future__ import annotations

import json
import sys
import threading
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from integrity_guardian.seed_catalog import SeedCatalog  # noqa: E402
from seed_delta_runtime import DELTA_RUNTIME_VERSION, DeltaSeedRuntimeServer  # noqa: E402
from seed_delta_sync import import_delta, initialize  # noqa: E402


def event(event_id: int) -> dict[str, object]:
    return {
        "id": event_id,
        "event_uid": f"runtime-{event_id}",
        "ts_utc": f"2026-08-08T00:00:{event_id:02d}Z",
        "actor": "test",
        "action": "agent_change_progress",
        "level": "info",
        "summary": f"runtime event {event_id}",
        "details": {"task_id": "runtime-test", "result": "partial"},
        "tags": ["seed", "delta"],
    }


def get_json(url: str) -> dict[str, object]:
    with urllib.request.urlopen(url, timeout=3) as response:
        return json.load(response)


def test_runtime_refreshes_by_checkpoint_without_legacy_run(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.sqlite3"
    SeedCatalog(catalog).import_events([event(1)], profile="fixture")
    initialize(catalog)
    server = DeltaSeedRuntimeServer(("127.0.0.1", 0), catalog)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        first = get_json(f"http://127.0.0.1:{port}/healthz")
        assert first["version"] == DELTA_RUNTIME_VERSION
        assert first["event_count"] == 1
        import_delta(catalog, [event(2)], expected_cursor=2, profile="test-delta")
        second = get_json(f"http://127.0.0.1:{port}/healthz")
        assert second["event_count"] == 2
        assert second["event_cursor"] == 2
        assert second["source_digest"] != first["source_digest"]
        capsule = get_json(f"http://127.0.0.1:{port}/v1/seed/capsule")
        assert capsule["production_authority"] is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
