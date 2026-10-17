# SPDX-License-Identifier: Apache-2.0
"""bus_health.py - read-only LLM bus status: processes, watchdog heartbeat, pending, last delivery per agent."""

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config
import json, sqlite3, subprocess, sys, time
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.stdout.reconfigure(encoding="utf-8")
def procs():
    ps = ("Get-CimInstance Win32_Process -Filter \"Name='python.exe' OR Name='pythonw.exe'\" | "
          "? { $_.CommandLine -like '*llm-bus-20261009*' } | % { \"$($_.ProcessId)`t$($_.CommandLine)\" }")
    out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True).stdout
    res = {"bridge": None, "relay": None}
    for line in out.splitlines():
        pid, _, cmd = line.partition("\t")
        if "file_bridge.py" in cmd: res["bridge"] = int(pid)
        if "relay.py" in cmd: res["relay"] = int(pid)
    return res
now = time.time()
hb = Path(_integrity_value('state_directory')) / "watchdog-heartbeat.json"
db = sqlite3.connect(f"file:{Path(_integrity_value('state_directory')) / 'bus.sqlite3'}?mode=ro", uri=True)
pending = dict(db.execute("SELECT recipient, COUNT(*) FROM messages WHERE status='pending' AND expires_at>? GROUP BY recipient", (int(now),)).fetchall())
last_ack = {r: t for r, t in db.execute("SELECT recipient, MAX(acked_at) FROM messages GROUP BY recipient")}
last_sent = {s: t for s, t in db.execute("SELECT sender, MAX(created_at) FROM messages GROUP BY sender")}
def age(t): return None if not t else round((now - t) / 60, 1)
journal = Path(_integrity_value('state_directory')) / "relay-journal.json"
last_relay = {}
if journal.exists():
    for b in json.loads(journal.read_text(encoding="utf-8")).get("batches", {}).values():
        if b.get("state") == "accepted": last_relay[b["target"]] = max(last_relay.get(b["target"], 0), b.get("timestamp", 0))
report = {
    "processes": procs(),
    "watchdog_heartbeat_age_min": age(hb.stat().st_mtime) if hb.exists() else None,
    "watchdog_last": json.loads(hb.read_text(encoding="utf-8-sig")) if hb.exists() else None,
    "pending": pending,
    "minutes_since_last_ack_by": {k: age(v) for k, v in last_ack.items()},
    "minutes_since_last_sent_by": {k: age(v) for k, v in last_sent.items()},
    "minutes_since_last_relay_delivery": {k: age(v) for k, v in last_relay.items()},
}
try:
    report["relay_threads"] = json.loads((Path(__file__).resolve().parent / "state" / "relay-threads.json").read_text(encoding="utf-8"))
except Exception as exc:
    report["relay_threads"] = f"unreadable: {type(exc).__name__}"
print(json.dumps(report, ensure_ascii=False, indent=1))