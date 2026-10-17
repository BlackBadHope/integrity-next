# SPDX-License-Identifier: Apache-2.0
"""Native thread self-registration: state/agents-registry.json (address -> Codex thread).

Built-in addresses (codex, claude, grok, codexfc) always exist and never change here.
A registered address is local-only like codexfc: no HTTP token, reached via local_cli/relay.
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import json
from contextlib import contextmanager
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid

BUILTIN = ("codex", "claude", "grok", "codexfc")
BUILTIN_CODEX = ("codex", "codexfc")
ADDRESS_RE = re.compile(r"[a-z0-9-]{2,32}\Z")
THREAD_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
HARNESSES = ("codex", "claude", "gemini", "antigravity")
DEFAULT_STATE = Path(_integrity_value('state_directory'))


def _path(state_dir: Path | None) -> Path:
    return (state_dir or DEFAULT_STATE) / "agents-registry.json"


def _document(path: Path) -> dict:
    if not path.exists():
        return {"version": 1, "agents": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") not in (1, 2) or not isinstance(data.get("agents"), dict):
        raise ValueError("invalid registry; refusing overwrite")
    for name, entry in data["agents"].items():
        if (not isinstance(name, str) or not ADDRESS_RE.fullmatch(name) or name in BUILTIN
                or not isinstance(entry, dict) or not THREAD_RE.fullmatch(str(entry.get("thread", "")))
                or entry.get("harness", "codex") not in HARNESSES):
            raise ValueError("invalid registry entry; refusing overwrite")
        if entry.get("harness") == "claude" and entry.get("session_id") != entry["thread"]:
            raise ValueError("Claude session binding is invalid")
    if not isinstance(data.get("aliases", {}), dict):
        raise ValueError("invalid registry aliases")
    for name, target in data.get('aliases', {}).items():
        if (name != 'claude' or not isinstance(target, str) or target not in data['agents']
                or data['agents'][target].get('harness') != 'claude'):
            raise ValueError('invalid Claude alias target')
    return data


@contextmanager
def _writer(state_dir: Path | None):
    path = _path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_suffix('.lock').open('a+b') as stream:
        stream.seek(0, 2)
        if not stream.tell():
            stream.write(b'0'); stream.flush()
        stream.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise ValueError('registry busy; no registration changed') from error
        try:
            yield path
        finally:
            if os.name == 'nt':
                stream.seek(0); msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


def load(state_dir: Path | None = None) -> dict:
    try:
        return _document(_path(state_dir))["agents"]
    except (OSError, ValueError, AttributeError):
        return {}


def builtin_threads(state_dir: Path | None) -> dict:
    try:
        data = json.loads(((state_dir or DEFAULT_STATE) / "relay-threads.json").read_text(encoding="utf-8"))
        return {k: v for k, v in data.items() if isinstance(v, str)}
    except (OSError, ValueError, AttributeError):
        return {}


def all_agents(state_dir: Path | None = None) -> tuple[str, ...]:
    return BUILTIN + tuple(sorted(load(state_dir)))


def codex_threads(state_dir: Path | None = None) -> dict:
    """address -> thread for every Codex address (built-ins from relay-threads.json + registry)."""
    result = {k: v for k, v in builtin_threads(state_dir).items() if k in BUILTIN_CODEX}
    result.update({k: v["thread"] for k, v in load(state_dir).items() if v.get("harness", "codex") == "codex"})
    return result


def register(address: str, thread: str, harness: str = "codex", topic: str = "",
             state_dir: Path | None = None) -> tuple[dict, bool]:
    with _writer(state_dir):
        return _register(address, thread, harness, topic, state_dir)


def _register(address: str, thread: str, harness: str, topic: str,
              state_dir: Path | None) -> tuple[dict, bool]:
    """Returns (entry, already_registered). Same address+thread is idempotent (topic may update)."""
    if not isinstance(address, str) or not ADDRESS_RE.fullmatch(address):
        raise ValueError("address must match [a-z0-9-]{2,32}")
    if not isinstance(thread, str) or not THREAD_RE.fullmatch(thread):
        raise ValueError("thread/session must be a lowercase UUID")
    if harness not in HARNESSES:
        raise ValueError("harness must be codex, claude, gemini or antigravity")
    topic = (topic or "").strip()
    if len(topic) > 200:
        raise ValueError("topic is too long (max 200)")
    taken = {v: k for k, v in builtin_threads(state_dir).items()}
    if address in BUILTIN:
        raise ValueError(f"address {address} is built-in and cannot be re-registered")
    if thread in taken:
        raise ValueError(f"thread is already the built-in address {taken[thread]}")
    path = _path(state_dir)
    agents = _document(path)["agents"]
    for name, entry in agents.items():
        if entry["thread"] == thread and name != address:
            raise ValueError(f"thread is already registered as {name}")
    if address in agents:
        entry = agents[address]
        if entry["thread"] != thread or entry.get("harness", "codex") != harness:
            raise ValueError(f"address {address} is already registered to another thread")
        if topic and topic != entry.get("topic"):
            entry["topic"] = topic
            _save(path, agents)
        return entry, True
    entry = {"thread": thread, "harness": harness, "topic": topic,
             "registered_at": int(time.time()),
             "registered_local": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}
    if harness == "claude":
        entry["session_id"] = thread
        _initialize_claude_cursor(path.parent, thread, address)
    agents[address] = entry
    _save(path, agents)
    return entry, False


def _save(path: Path, agents: dict) -> None:
    data = _document(path)
    data["agents"] = agents
    _save_document(path, data)


def _save_document(path: Path, data: dict) -> None:
    tmp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    with tmp.open('x', encoding='utf-8') as stream:
        json.dump(data, stream, ensure_ascii=False, indent=1)
        stream.flush(); os.fsync(stream.fileno())
    os.replace(tmp, path)


def set_claude_alias(address: str, expected: str | None = None,
                     state_dir: Path | None = None) -> dict:
    """CAS only: route the legacy claude mailbox to one registered lead session."""
    with _writer(state_dir) as path:
        data = _document(path)
        entry = data['agents'].get(address)
        if not entry or entry.get('harness') != 'claude':
            raise ValueError('alias target must be a registered Claude address')
        aliases = data.setdefault('aliases', {})
        previous = aliases.get('claude')
        if previous == address:
            return {'alias': 'claude', 'address': address, 'session_id': entry['session_id'], 'unchanged': True}
        if previous != expected:
            raise ValueError('claude alias preimage changed; no overwrite')
        _initialize_claude_cursor(path.parent, entry['session_id'], 'claude')
        aliases['claude'] = address
        data['version'] = 2
        _save_document(path, data)
        return {'alias': 'claude', 'address': address, 'session_id': entry['session_id'], 'unchanged': False}


def _initialize_claude_cursor(state_dir: Path, session: str, address: str) -> None:
    """Writer lock required. Snapshot backlog before publishing a new route.

    Skips old pointers only: no message is ACKed or removed. Registrations and
    alias changes are explicit; idempotent re-registration never resets cursors.
    """
    db_path = state_dir / 'bus.sqlite3'
    seq = 0
    if db_path.exists():
        db = sqlite3.connect(db_path.resolve().as_uri() + '?mode=ro', uri=True, timeout=2)
        try:
            seq = db.execute('SELECT COALESCE(MAX(seq),0) FROM messages WHERE recipient=?', (address,)).fetchone()[0]
        finally:
            db.close()
    path = state_dir / 'claude-hook-seen' / (session + '.json')
    seen = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
    if not isinstance(seen, dict) or any(type(value) is not int or value < 0 for value in seen.values()):
        raise ValueError('invalid session cursor; no route published')
    seen[address] = max(seen.get(address, 0), seq)
    path.parent.mkdir(exist_ok=True)
    _save_document(path, seen)


def claude_mailboxes(session: str, state_dir: Path | None = None) -> tuple[str, ...]:
    """Transport routing only, never Integrity session admission or authority."""
    if not isinstance(session, str) or not THREAD_RE.fullmatch(session):
        return ()
    try:
        data = _document(_path(state_dir))
    except (OSError, ValueError):
        return ()
    addresses = sorted(name for name, entry in data['agents'].items()
                       if entry.get('harness') == 'claude' and entry.get('session_id') == session)
    if len(addresses) != 1:
        return ()
    if data.get('aliases', {}).get('claude') == addresses[0]:
        addresses.append('claude')
    return tuple(addresses)


def listing(state_dir: Path | None = None) -> list[dict]:
    threads = builtin_threads(state_dir)
    rows = [{"address": a, "source": "builtin", "harness": "codex" if a in BUILTIN_CODEX else a,
             "thread": threads.get(a), "token": "required" if a in ("codex", "claude", "grok") else "local-only"}
            for a in BUILTIN]
    rows += [{"address": a, "source": "registry", "token": "local-only", **e} for a, e in sorted(load(state_dir).items())]
    try:
        data = _document(_path(state_dir))
        lead = data.get('aliases', {}).get('claude')
        if lead in data['agents'] and data['agents'][lead].get('harness') == 'claude':
            for row in rows:
                if row['address'] == 'claude':
                    row.update(alias_to=lead, session_id=data['agents'][lead]['session_id'])
    except (OSError, ValueError):
        pass
    return rows
