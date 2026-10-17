# SPDX-License-Identifier: Apache-2.0
"""bus_integrity_adapter.py - LLM bus <-> Integrity canonical memory (design v1, no direct writes).

Why no direct writes: integrity_append_event requires a context_admission_id bound to the CURRENT OWNER
TURN of a Codex/Claude session (admission hook) and consumes a one-use Ledger grant. A background
process has no owner turn, so writing from here would mean bypassing the guard. The adapter therefore:
  1. validates bus messages whose body starts with the line `integrity.event.request` + JSON;
  2. normalises them to the append_event schema under the non-core scope tag `bus/orchestration`;
  3. queues them in state/integrity-requests.jsonl and forwards ONE pointer to codex, who writes the
     event inside an owner-admitted turn and replies `integrity.event.result {event_id, event_uid}`.
Reads (`integrity.events.query`) are routed the same way (codex runs integrity_read_events/home_search).
Usage: python bus_integrity_adapter.py --once [--dry-run]
"""

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config
import argparse, json, re, sqlite3, sys, time
from pathlib import Path
HERE = Path(__file__).resolve().parent
QUEUE = Path(_integrity_value('state_directory')) / "integrity-requests.jsonl"
SEEN = Path(_integrity_value('state_directory')) / "integrity-adapter-seen.json"
UID = re.compile(r"^client:bus\.orchestration[A-Za-z0-9._:-]{1,130}$")
KINDS = {"concept", "task", "thought"}

def parse(body: str):
    head, _, rest = body.partition("\n")
    kind = head.strip()
    if kind not in ("integrity.event.request", "integrity.events.query"):
        return None
    req = json.loads(rest)
    if kind == "integrity.event.request":
        if not UID.match(req.get("event_uid", "")): raise ValueError("event_uid must be client:bus.orchestration...")
        if req.get("kind") not in KINDS: raise ValueError("kind must be concept|task|thought")
        if not 1 <= len(req.get("summary", "")) <= 2000: raise ValueError("summary 1..2000")
        tags = list(dict.fromkeys(["bus/orchestration"] + list(req.get("tags", []))))[:20]
        return {"op": "append_event", "event_uid": req["event_uid"], "kind": req["kind"],
                "summary": req["summary"], "details": req.get("details", {}), "tags": tags}
    return {"op": "read_events", "query": req}

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--once", action="store_true", required=True)
    ap.add_argument("--dry-run", action="store_true"); a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")
    seen = set(json.loads(SEEN.read_text(encoding="utf-8"))) if SEEN.exists() else set()
    db = sqlite3.connect(f"file:{Path(_integrity_value('state_directory')) / 'bus.sqlite3'}?mode=ro", uri=True)
    rows = db.execute("SELECT id,sender,body FROM messages WHERE body LIKE 'integrity.event%' "
                      "AND status='pending' AND expires_at>? ORDER BY seq LIMIT 50", (int(time.time()),)).fetchall()
    out = []
    for mid, sender, body in rows:
        if mid in seen: continue
        try: req = parse(body)
        except Exception as exc: out.append({"id": mid, "error": str(exc)}); continue
        if req: out.append({"id": mid, "from": sender, **req})
    print(json.dumps(out, ensure_ascii=False, indent=1))
    if a.dry_run or not out: return
    with QUEUE.open("a", encoding="utf-8") as q:
        for r in out:
            if "error" not in r: q.write(json.dumps(r, ensure_ascii=False) + "\n")
    SEEN.write_text(json.dumps(sorted(seen | {r["id"] for r in out})), encoding="utf-8")

if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    main()