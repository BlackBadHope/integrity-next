#!/usr/bin/env python3
"""Integrity scope synapse: turn a context compaction into a scope update the model must take.

A model does not poll anything after its context is compacted. It continues from
the summary, and a summary can revive an older goal, a stale precondition or a
file from earlier work. This hook makes the compaction itself an event:

* ``UserPromptSubmit`` records the owner's instructions outside the model (the
  anchor). A long prompt starts a new task; a short one is a correction to it.
* ``PreCompact``/``PostCompact`` arm the synapse: the compaction epoch grows and
  the current lease is void. They cannot inject text into the model.
* ``SessionStart`` with ``source=compact`` (and the next ``UserPromptSubmit``)
  delivers the anchor capsule into the model context.
* ``PreToolUse`` is the reflex. While armed, effects are denied and the denial
  reason carries the same capsule. Reading and Integrity memory reads stay
  allowed so the model can re-orient. ``echo INTEGRITY_REATTEST <digest>``
  with the current anchor digest renews the lease.

The hook is harness-neutral (Codex and Claude Code share the payload shape it
uses) and never grants authority: an allowed tool still goes through every
other gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

PROTOCOL = "integrity-scope-synapse/v1"
TASK_PROMPT_CHARS = 200
MAX_INSTRUCTIONS = 8
MAX_INSTRUCTION_CHARS = 1500
MAX_SUPERSEDED = 5
SUPERSEDED_EXCERPT_CHARS = 160
REATTEST_RE = re.compile(r"\bINTEGRITY_REATTEST\s+(sha256:[a-f0-9]{64})\b")
# Only a standalone echo re-attests; `echo INTEGRITY_REATTEST <d>; rm -rf build` does not.
EXACT_REATTEST_RE = re.compile(r"\s*echo\s+(['\"]?)INTEGRITY_REATTEST\s+(sha256:[a-f0-9]{64})\1\s*")
SHELL_TOOLS = frozenset({"Bash", "shell", "local_shell", "exec_command", "unified_exec", "PowerShell"})
SHELL_WRAPPER_FLAGS = frozenset({"-c", "-lc", "-Command", "/c", "/C"})
RETENTION_SECONDS = 14 * 24 * 3600
MAX_SESSION_FILES = 200
SESSION_FILE_RE = re.compile(r"[0-9a-f]{32}\.json")
PING_RE = re.compile(
    r"\[INTEGRITY_PING workflow=([A-Za-z0-9][A-Za-z0-9._:-]{7,127}) sequence=([1-9][0-9]{0,8})"
    r"(?: anchor=(sha256:[a-f0-9]{64}))?\]"
)
READ_ONLY_TOOLS = frozenset({
    "Read", "Grep", "Glob", "LS", "NotebookRead", "TodoWrite", "TodoRead",
    "view_image", "read_file", "list_dir", "grep_files",
})
MEMORY_READ_RE = re.compile(
    r"integrity_(context_admission(_current_turn)?|memory_capabilities|read_events|seed_\w+"
    r"|home_(search|fetch)|mind_graph|architecture_admission|memory_entity_brief"
    r"|memory_link_audit|turn_memory_coverage)$"
)
LOCK_TIMEOUT_SECONDS = 10.0


class SynapseError(RuntimeError):
    pass


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _digest(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def state_root(harness: str, configured: str | None = None) -> Path:
    if configured:
        return Path(configured)
    configured = os.environ.get("INTEGRITY_SCOPE_SYNAPSE_STATE", "").strip()
    if configured:
        return Path(configured)
    if harness == "codex":
        home = os.environ.get("CODEX_HOME", "").strip() or str(Path.home() / ".codex")
        return Path(home) / "integrity-memory" / "scope-synapse"
    return Path.home() / ".claude" / "integrity-memory" / "scope-synapse"


def session_key(payload: dict[str, Any]) -> str:
    value = payload.get("session_id") or payload.get("sessionId") or payload.get("thread_id")
    if not isinstance(value, str) or not value.strip():
        raise SynapseError("hook payload has no session identity")
    return value.strip()


class Store:
    def __init__(self, root: Path):
        self.root = root

    def _path(self, session: str) -> Path:
        name = hashlib.sha256(session.encode("utf-8")).hexdigest()[:32]
        return self.root / f"{name}.json"

    def ensure_root(self) -> None:
        # Session files hold owner instructions; keep the directory private.
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)

    def prune(self, keep_session: str, *, now: float | None = None) -> int:
        """Remove session files older than the retention window or beyond the count bound."""

        keep = self._path(keep_session).name
        now = time.time() if now is None else now
        entries = []
        for path in self.root.iterdir():
            if not SESSION_FILE_RE.fullmatch(path.name) or path.name == keep:
                continue
            if path.with_suffix(".lock").exists():
                continue
            try:
                entries.append((path.stat().st_mtime, path))
            except FileNotFoundError:
                continue
        entries.sort(reverse=True)
        removed = 0
        for index, (mtime, path) in enumerate(entries):
            if now - mtime > RETENTION_SECONDS or index >= MAX_SESSION_FILES - 1:
                try:
                    path.unlink()
                    removed += 1
                except FileNotFoundError:
                    pass
        return removed

    @contextmanager
    def locked(self, session: str):
        self.ensure_root()
        lock = self._path(session).with_suffix(".lock")
        deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except FileExistsError:
                try:
                    if time.time() - lock.stat().st_mtime > 60:
                        lock.unlink()
                        continue
                except FileNotFoundError:
                    continue
                if time.monotonic() > deadline:
                    raise SynapseError("scope synapse state is locked") from None
                time.sleep(0.05)
        try:
            os.close(fd)
            yield
        finally:
            try:
                lock.unlink()
            except FileNotFoundError:
                pass

    def load(self, session: str) -> dict[str, Any] | None:
        path = self._path(session)
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return None
        try:
            state = json.loads(raw)
        except ValueError as exc:
            raise SynapseError("scope synapse state is unreadable") from exc
        if not isinstance(state, dict) or state.get("protocol") != PROTOCOL or state.get("session") != session:
            raise SynapseError("scope synapse state is invalid")
        return state

    def save(self, session: str, state: dict[str, Any]) -> None:
        self.ensure_root()
        path = self._path(session)
        fd, temporary = tempfile.mkstemp(dir=self.root, prefix=".synapse-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, ensure_ascii=False, sort_keys=True, indent=1)
            os.replace(temporary, path)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise


def new_state(session: str) -> dict[str, Any]:
    return {"protocol": PROTOCOL, "session": session, "instructions": [], "superseded": [],
            "anchor_digest": None, "ping": None, "epoch": 0, "lease_epoch": 0, "armed": False,
            "armed_trigger": None, "armed_at": None, "delivered_epoch": 0, "delivered_anchor": None,
            "reflex_count": 0}


def anchor_digest(state: dict[str, Any]) -> str | None:
    if not state["instructions"]:
        return None
    return _digest({"instructions": [item["text"] for item in state["instructions"]], "ping": state["ping"]})


def record_prompt(state: dict[str, Any], prompt: str, turn: str | None) -> None:
    text = prompt.strip()
    if not text:
        return
    # A marker only counts at the very start: a quoted transcript must not become the scope.
    ping = PING_RE.match(text)
    starts_task = bool(ping) or len(text) >= TASK_PROMPT_CHARS or not state["instructions"]
    item = {"kind": "task" if starts_task else "correction", "text": text[:MAX_INSTRUCTION_CHARS],
            "truncated": len(text) > MAX_INSTRUCTION_CHARS, "turn_id": turn, "received_at": _now()}
    if starts_task:
        previous = [entry for entry in state["instructions"] if entry["kind"] == "task"]
        for entry in previous[-1:]:
            state["superseded"].append({"excerpt": entry["text"][:SUPERSEDED_EXCERPT_CHARS],
                                        "received_at": entry["received_at"]})
        state["superseded"] = state["superseded"][-MAX_SUPERSEDED:]
        state["instructions"] = [item]
        state["ping"] = ({"workflow_id": ping.group(1), "sequence": int(ping.group(2)),
                          "anchor": ping.group(3)} if ping else None)
    else:
        state["instructions"] = (state["instructions"] + [item])[-MAX_INSTRUCTIONS:]
    state["anchor_digest"] = anchor_digest(state)


def arm(state: dict[str, Any], trigger: str | None, *, event: str) -> None:
    if state["armed"] and event == "PostCompact":
        return
    state["epoch"] += 1
    state["armed"] = True
    state["armed_trigger"] = f"{event}:{trigger or 'unknown'}"
    state["armed_at"] = _now()


def mark_delivered(state: dict[str, Any]) -> None:
    state["delivered_epoch"] = state["epoch"]
    state["delivered_anchor"] = state["anchor_digest"]


def capsule(state: dict[str, Any]) -> str:
    lines = [
        f"INTEGRITY SCOPE SYNAPSE (compaction #{state['epoch']}, anchor {state['anchor_digest']}).",
        (
            "Your context was just compacted. The summary may revive older goals, preconditions, "
            "hashes or files from earlier work. The only current owner scope is recorded by the host "
            "outside the model, oldest first; on conflict the newest instruction wins:"
        ),
    ]
    if state.get("ping"):
        ping = state["ping"]
        lines.append(f"PING workflow={ping['workflow_id']} sequence={ping['sequence']}"
                     + (f" anchor={ping['anchor']}" if ping.get("anchor") else ""))
    for number, item in enumerate(state["instructions"], 1):
        suffix = " [truncated]" if item.get("truncated") else ""
        lines.append(f"{number}. [{item['kind']}] {item['text']}{suffix}")
    if state["superseded"]:
        lines.append("Superseded earlier tasks in this session. Do not resume them unless the scope above "
                     "names them:")
        lines.extend(f"- {item['excerpt']}" for item in state["superseded"])
    lines.append(
        "Reading and Integrity memory reads are allowed to re-orient. Every other action is blocked "
        f"until you restate the scope in one line and run exactly: echo INTEGRITY_REATTEST {state['anchor_digest']}"
    )
    return "\n".join(lines)


def _tool_text(payload: dict[str, Any]) -> str:
    value = payload.get("tool_input")
    if isinstance(value, dict):
        command = value.get("command") or value.get("cmd")
        if isinstance(command, list):
            return " ".join(str(part) for part in command)
        if isinstance(command, str):
            return command
        return json.dumps(value, ensure_ascii=False)
    return value if isinstance(value, str) else ""


def shell_command(payload: dict[str, Any]) -> str | None:
    """Return the script a shell tool will run, or None for any other tool."""

    if str(payload.get("tool_name") or "") not in SHELL_TOOLS:
        return None
    value = payload.get("tool_input")
    command = (value.get("command") or value.get("cmd")) if isinstance(value, dict) else value
    if isinstance(command, list):
        parts = [str(part) for part in command]
        if len(parts) >= 3 and parts[-2] in SHELL_WRAPPER_FLAGS:
            return parts[-1]
        return " ".join(parts)
    return command if isinstance(command, str) else None


def reattest_digest(payload: dict[str, Any]) -> str | None:
    command = shell_command(payload)
    match = EXACT_REATTEST_RE.fullmatch(command) if command is not None else None
    return match.group(2) if match else None


def recovery_tool(payload: dict[str, Any]) -> bool:
    name = str(payload.get("tool_name") or "")
    return name in READ_ONLY_TOOLS or bool(MEMORY_READ_RE.search(name))


def context_output(event: str, text: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": event, "additionalContext": text}}


def deny_output(reason: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def handle(event: str, payload: dict[str, Any], store: Store) -> dict[str, Any] | None:
    """Return the hook output for one event, or None when the synapse has no opinion."""

    session = session_key(payload)
    with store.locked(session):
        try:
            state = store.load(session)
        except SynapseError as exc:
            if event == "PreToolUse" and not recovery_tool(payload):
                return deny_output(f"INTEGRITY SCOPE SYNAPSE fault: {exc}. Actions stay blocked until the "
                                   "owner repairs or removes the scope state.")
            return None
        if state is None:
            if event not in {"UserPromptSubmit", "PreCompact", "PostCompact"}:
                return None
            state = new_state(session)
        output: dict[str, Any] | None = None
        if event == "UserPromptSubmit":
            prompt = payload.get("prompt") or payload.get("user_prompt") or ""
            record_prompt(state, prompt if isinstance(prompt, str) else "", payload.get("turn_id"))
            # Redeliver when this epoch has not seen the capsule, or when the owner's prompt
            # changed the anchor after it was delivered (the old digest would no longer re-attest).
            if state["armed"] and state["anchor_digest"] and (
                    state["delivered_epoch"] < state["epoch"]
                    or state.get("delivered_anchor") != state["anchor_digest"]):
                mark_delivered(state)
                output = context_output(event, capsule(state))
        elif event in {"PreCompact", "PostCompact"}:
            arm(state, payload.get("trigger"), event=event)
        elif event == "SessionStart":
            if payload.get("source") == "compact":
                if not state["armed"]:
                    arm(state, "session-start", event=event)
                if state["anchor_digest"]:
                    mark_delivered(state)
                    output = context_output(event, capsule(state))
        elif event == "PreToolUse" and state["armed"] and state["anchor_digest"]:
            digest = reattest_digest(payload)
            if digest == state["anchor_digest"]:
                state["armed"] = False
                state["lease_epoch"] = state["epoch"]
            elif not recovery_tool(payload):
                state["reflex_count"] += 1
                mark_delivered(state)
                if digest:
                    prefix = "INTEGRITY_REATTEST digest does not match the current anchor. "
                elif REATTEST_RE.search(_tool_text(payload)):
                    prefix = "INTEGRITY_REATTEST must be the whole command of a shell tool, alone. "
                else:
                    prefix = "INTEGRITY SCOPE REFLEX: action blocked after context compaction. "
                output = deny_output(prefix + capsule(state))
        store.save(session, state)
        if event in {"UserPromptSubmit", "SessionStart"}:
            store.prune(session)
        return output


def status_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="integrity_scope_synapse.py status")
    parser.add_argument("--harness", choices=("codex", "claude"), required=True)
    parser.add_argument("--session", required=True)
    parser.add_argument("--state")
    args = parser.parse_args(argv)
    state = Store(state_root(args.harness, args.state)).load(args.session)
    print(json.dumps(state or {"protocol": PROTOCOL, "session": args.session, "state": "absent"},
                     ensure_ascii=False, indent=1))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["status"]:
        return status_command(argv[1:])
    parser = argparse.ArgumentParser(prog="integrity_scope_synapse.py")
    parser.add_argument("--harness", choices=("codex", "claude"), required=True)
    parser.add_argument("--event", required=True, choices=(
        "SessionStart", "UserPromptSubmit", "PreCompact", "PostCompact", "PreToolUse"))
    parser.add_argument("--state", help="state directory bound at installation")
    args = parser.parse_args(argv)
    try:
        raw = sys.stdin.buffer.read().decode("utf-8")
        payload = json.loads(raw) if raw.strip() else {}
        if not isinstance(payload, dict):
            raise SynapseError("hook payload is not an object")
        output = handle(args.event, payload, Store(state_root(args.harness, args.state)))
    except (SynapseError, ValueError, OSError) as exc:
        # Fail closed only for effects; never block the owner's prompt or a session start.
        print(f"Integrity scope synapse fault: {exc}", file=sys.stderr)
        output = (deny_output(f"INTEGRITY SCOPE SYNAPSE fault: {exc}. Actions stay blocked until the "
                              "owner repairs the scope state.") if args.event == "PreToolUse" else None)
    sys.stdout.write(json.dumps(output or {}, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
