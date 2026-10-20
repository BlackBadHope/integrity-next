"""Record a public-source maintenance decision in a fresh, disposable catalog."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from integrity_guardian.seed_catalog import SeedCatalog

DECISION = {
    "id": 1,
    "event_uid": "client:public-remote-timeout-decision",
    "ts_utc": "2026-10-20T00:00:00Z",
    "actor": "example-maintainer",
    "action": "configuration_decision",
    "level": "info",
    "summary": "For the Windows remote broker, keep the outer MCP tool timeout at least 210 seconds: the nested public request budget is 180 seconds and initialization can take 45 seconds.",
    "details": {
        "task_id": "remote-broker-client-setup",
        "source": "components/integrity-client-memory/README.md, Weekly Windows source profiles (2026-10-20)",
        "source_code": "components/integrity-client-memory/src/integrity_client_memory/resources/windows-remote/integrity-client-turn-broker.py",
        "decision": {"tool_timeout_sec": 210, "request_budget_sec": 180, "initialize_timeout_sec": 45},
        "scope": "Public-source maintenance rehearsal; this is not an imported production event."
    },
    "tags": ["public-example", "timeout", "windows-remote"],
}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    raw = json.dumps(DECISION, ensure_ascii=False, indent=2) + "\n"
    (a.output / "decision.json").write_text(raw, encoding="utf-8")
    (a.output / "saved-note.txt").write_text(DECISION["summary"] + "\n", encoding="utf-8")
    c = SeedCatalog(a.output / "private" / "catalog.sqlite")
    c.import_events([DECISION], source_namespace="seed://project/public-onboarding-case")
    print(json.dumps({"ok": c.verify()["ok"], "event_count": 1,
                      "catalog": str(c.path), "event_uid": DECISION["event_uid"]}))


if __name__ == "__main__":
    main()
