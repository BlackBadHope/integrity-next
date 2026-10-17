# SPDX-License-Identifier: Apache-2.0
"""Mid-turn delivery of bus pointers to an existing Codex thread.

The Desktop queue (``codex queue``) dispatches only after the active turn ends,
so a busy thread would leave bus notices waiting. Instead a pointer for an
active thread is staged here and handed to the model by ``codex_steer_hook.py``
as PostToolUse additional context: it arrives after the next tool call, like a
steer, and never passes through UserPromptSubmit, so Integrity LTS does not
record it as owner scope. Idle threads still use the queue, which dispatches
immediately. Every entry moves once: staged -> steered | queued.
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import time

HERE = Path(__file__).resolve().parent
STEER_DIR = Path(_integrity_value('state_directory')) / "codex-steer"
THREAD_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
TAIL_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 50


def _paths(thread_id: str, root: Path) -> tuple[Path, Path]:
    if not THREAD_RE.fullmatch(thread_id):
        raise ValueError("invalid thread id")
    return root / f"{thread_id}.json", root / f"{thread_id}.lock"


@contextmanager
def _locked(lock_path: Path, attempts: int = 50):
    lock_path.parent.mkdir(exist_ok=True)
    stream = lock_path.open("a+b")
    try:
        for attempt in range(attempts):
            try:
                if os.name == "nt":
                    import msvcrt
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if attempt == attempts - 1:
                    raise
                time.sleep(0.02)
        yield
    finally:
        stream.close()


def _load(path: Path) -> dict:
    if not path.exists():
        return {"version": 1, "entries": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != 1 or not isinstance(data.get("entries"), list):
        raise ValueError("invalid steer state")
    return data


def _save(path: Path, data: dict) -> None:
    data["entries"] = data["entries"][-MAX_ENTRIES:]
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    os.replace(temporary, path)


def stage(thread_id: str, key: str, ids: list[str], text: str, root: Path = STEER_DIR) -> bool:
    """Stage one pointer; False when this key was staged before."""
    path, lock = _paths(thread_id, root)
    with _locked(lock):
        data = _load(path)
        if any(entry["key"] == key for entry in data["entries"]):
            return False
        data["entries"].append({"key": key, "ids": ids, "text": text, "state": "staged",
                                "staged_at": int(time.time())})
        _save(path, data)
    return True


def take_for_hook(thread_id: str, turn_id: str | None, root: Path = STEER_DIR) -> list[str]:
    """Hook side: claim every staged pointer of this thread for the current turn."""
    path, lock = _paths(thread_id, root)
    if not path.exists():
        return []
    with _locked(lock):
        data = _load(path)
        texts = []
        for entry in data["entries"]:
            if entry["state"] == "staged":
                entry.update(state="steered", done_at=int(time.time()), turn_id=turn_id)
                texts.append(entry["text"])
        if texts:
            _save(path, data)
    return texts


def take_for_queue(thread_id: str, key: str, root: Path = STEER_DIR) -> str | None:
    """Relay side: claim one still-staged pointer for the Desktop queue."""
    path, lock = _paths(thread_id, root)
    with _locked(lock):
        data = _load(path)
        for entry in data["entries"]:
            if entry["key"] == key and entry["state"] == "staged":
                entry.update(state="queued", done_at=int(time.time()))
                _save(path, data)
                return entry["text"]
    return None


def entries(thread_id: str, root: Path = STEER_DIR) -> list[dict]:
    path, _ = _paths(thread_id, root)
    return _load(path)["entries"] if path.exists() else []


def staged_threads(root: Path = STEER_DIR) -> list[str]:
    if not root.is_dir():
        return []
    return [p.stem for p in root.glob("*.json") if THREAD_RE.fullmatch(p.stem)]


def turn_active(transcript: Path) -> bool | None:
    """True while the last task event is task_started; None when unknown."""
    with transcript.open("rb") as stream:
        size = stream.seek(0, os.SEEK_END)
        stream.seek(max(0, size - TAIL_BYTES))
        tail = stream.read()
    for raw in reversed(tail.splitlines()):
        if b'"type":"event_msg"' not in raw:
            continue
        if b'"type":"task_started"' in raw:
            return True
        if b'"type":"task_complete"' in raw or b'"type":"turn_aborted"' in raw:
            return False
    return None
