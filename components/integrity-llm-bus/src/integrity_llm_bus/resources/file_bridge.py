# SPDX-License-Identifier: Apache-2.0
"""Bidirectional mirror: file bus (work\\llm-bus\\messages) <-> SQLite bus (this dir).

Canonical store = SQLite (bus.py / local_cli.py, Codex). The file bus (Claude's
draft, used by Claude and Grok) is mirrored so every agent can use either side.

Id mapping
  file -> SQLite : f.<fileid>.<to>   (to=all fans out to both other agents)
  SQLite -> file : s.<sqliteid>      (file JSON gets "via":"bridge","mirror_of")
Loop prevention
  * SQLite rows whose id starts with "f." are never written back to files.
  * Files with "via":"bridge" are never pushed into SQLite.
Dedupe
  state/bridge.json keeps processed file ids + last SQLite seq; SQLite post()
  and file names are idempotent anyway (same id -> no duplicate).
reply_to mapping
  file reply_to X: if X is a mirror of SQLite id S -> S; else f.X.<sender>.
  SQLite rejects a reply_to that is not a message from the addressee; then the
  bridge posts with reply_to=null and prefixes the body with "[reply_to file:X]".
  SQLite reply_to "f.X.agent" -> file reply_to X; other S -> "s.S".

  py -3.12 file_bridge.py --once        one pass
  pythonw file_bridge.py --watch        loop (see bridge.ps1 start/stop/status)
Stop: create file bridge-state\\STOP (bridge.ps1 stop does it), or kill PID in bridge-state\\bridge.pid.
Stdlib only; never sends network traffic; never runs message text.
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse, json, os, sys, time, traceback, uuid
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import agent_registry  # noqa: E402
from bus import AGENTS, MAX_BODY_BYTES, _row, _validate_message  # noqa: E402
from local_cli import open_store  # noqa: E402

FILE_ROOT = Path(os.environ.get("LLM_FILE_BUS_ROOT", _integrity_value('path_d4f3db5417f4')))
BSTATE = HERE / "bridge-state"
STATE_F = BSTATE / "bridge.json"
LOG_F = BSTATE / "bridge.log"
PID_F = BSTATE / "bridge.pid"
STOP_F = BSTATE / "STOP"


def log(line: str) -> None:
    BSTATE.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with LOG_F.open("a", encoding="utf-8") as f:
        f.write(f"{stamp} {line}\n")


def load_state() -> dict:
    if STATE_F.exists():
        return json.loads(STATE_F.read_text(encoding="utf-8"))
    return {"files_done": [], "sqlite_seq": 0}


def save_state(st: dict) -> None:
    BSTATE.mkdir(exist_ok=True)
    tmp = STATE_F.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, STATE_F)


def file_messages() -> list[dict]:
    out = []
    md = FILE_ROOT / "messages"
    if not md.exists():
        return out
    for p in sorted(md.glob("*.json")):
        try:
            m = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(m, dict) and isinstance(m.get("id"), str):
            out.append(m)
    return out


def safe(s: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in s)


def write_file_msg(msg: dict) -> bool:
    md = FILE_ROOT / "messages"
    md.mkdir(parents=True, exist_ok=True)
    if any(md.glob(f"*_{safe(msg['id'])}.json")):
        return False
    stamp = msg["ts"].replace(":", "").replace(".", "")
    name = f"{stamp}_{msg['from']}_{msg['to']}_{safe(msg['id'])}.json"
    tmp = md / (name + ".tmp")
    tmp.write_text(json.dumps(msg, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, md / name)
    return True


def sqlite_has(store, mid: str) -> bool:
    with store._connection() as db:
        return db.execute("SELECT 1 FROM messages WHERE id=?", (mid,)).fetchone() is not None


def file_to_sqlite(store, st: dict, files: list[dict]) -> int:
    done = set(st["files_done"])
    mirror_of = {m["id"]: m.get("mirror_of") for m in files if m.get("via") == "bridge"}
    n = 0
    for m in files:
        fid = m["id"]
        if fid in done:
            continue
        if m.get("via") == "bridge":
            done.add(fid)
            continue
        sender, to = m.get("from"), m.get("to")
        body = m.get("body")
        if sender not in AGENTS or not isinstance(body, str) or not body.strip():
            done.add(fid); log(f"skip file {fid}: bad sender/body"); continue
        targets = [a for a in AGENTS if a != sender] if to == "all" else [to] if to in agent_registry.all_agents() and to != sender else []
        if not targets:
            done.add(fid); log(f"skip file {fid}: bad to={to}"); continue
        if len(body.encode("utf-8")) > MAX_BODY_BYTES:
            body = body.encode("utf-8")[: MAX_BODY_BYTES - 64].decode("utf-8", "ignore") + "\n[truncated by bridge]"
        rid = m.get("reply_to")
        for tgt in targets:
            sid = f"f.{safe(fid)}.{tgt}"[:128]
            parent = None
            if isinstance(rid, str) and rid:
                parent = mirror_of.get(rid) or (rid if sqlite_has(store, rid) else f"f.{safe(rid)}.{sender}"[:128])
            msg = {"id": sid, "from": sender, "to": tgt, "body": body, "reply_to": parent}
            try:
                _validate_message(msg, sender)
                store.post(msg)
            except FileExistsError:
                pass
            except ValueError:
                msg["reply_to"] = None
                if rid:
                    msg["body"] = f"[reply_to file:{rid}] " + body
                try:
                    store.post(_validate_message(msg, sender))
                except FileExistsError:
                    pass
            n += 1
            log(f"file->sqlite {fid} => {sid} ({sender}->{tgt}) reply_to={msg['reply_to']}")
        done.add(fid)
    st["files_done"] = sorted(done)
    return n


def sqlite_to_file(store, st: dict) -> int:
    with store._connection() as db:
        rows = db.execute("SELECT seq, * FROM messages WHERE seq > ? ORDER BY seq", (st["sqlite_seq"],)).fetchall()
    n = 0
    for r in rows:
        st["sqlite_seq"] = max(st["sqlite_seq"], r["seq"])
        m = _row(r)
        if m["id"].startswith("f."):
            continue
        rid = m["reply_to"]
        if rid and rid.startswith("f."):
            frid = rid[2:].rsplit(".", 1)[0]
        elif rid:
            frid = f"s.{rid}"
        else:
            frid = None
        ts = datetime.fromtimestamp(m["created_at"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        fm = {"id": f"s.{m['id']}", "ts": ts, "from": m["from"], "to": m["to"], "reply_to": frid,
              "body": m["body"], "via": "bridge", "mirror_of": m["id"]}
        if write_file_msg(fm):
            n += 1
            log(f"sqlite->file {m['id']} => {fm['id']} ({m['from']}->{m['to']}) reply_to={frid}")
    return n


def one_pass(store) -> tuple[int, int]:
    st = load_state()
    b = sqlite_to_file(store, st)       # first, so mirror_of map is fresh for replies
    a = file_to_sqlite(store, st, file_messages())
    save_state(st)
    return a, b


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--once", action="store_true")
    g.add_argument("--watch", action="store_true")
    p.add_argument("-i", "--interval", type=float, default=3.0)
    a = p.parse_args()
    store = open_store(Path(_integrity_value('state_directory')))
    if a.once:
        print(json.dumps(dict(zip(("file_to_sqlite", "sqlite_to_file"), one_pass(store)))))
        return 0
    BSTATE.mkdir(exist_ok=True)
    STOP_F.unlink(missing_ok=True)
    PID_F.write_text(str(os.getpid()), encoding="ascii")
    log(f"bridge started pid={os.getpid()} file_root={FILE_ROOT}")
    try:
        while not STOP_F.exists():
            try:
                one_pass(store)
            except Exception:  # keep running; record and back off
                log("error " + traceback.format_exc().replace("\n", " | "))
                time.sleep(10)
            time.sleep(a.interval)
    finally:
        log("bridge stopped")
        PID_F.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
