# SPDX-License-Identifier: Apache-2.0
"""Same-owner local CLI for the durable bus; no HTTP credentials required."""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys

import agent_registry
from bus import AGENTS, DEFAULT_TTL_HOURS, DELIVERY_MODES, MAX_BODY_BYTES, MessageStore, _row, _validate_message, queue_page, queue_view


def open_store(state_dir: Path, ttl_hours: int = DEFAULT_TTL_HOURS) -> MessageStore:
    state_dir = state_dir.absolute()
    if not 1 <= ttl_hours <= 720:
        raise ValueError("invalid retention")
    if state_dir.is_symlink() or (hasattr(state_dir, "is_junction") and state_dir.is_junction()):
        raise ValueError("state directory must not be a link")
    if os.name == "nt":
        from win_acl import secure_state_directory
        secure_state_directory(state_dir)
    else:
        state_dir.mkdir(mode=0o700, exist_ok=True)
        state_dir.chmod(0o700)
    store = MessageStore(state_dir / "bus.sqlite3", ttl_hours * 3600)
    if os.name == "nt":
        secure_state_directory(state_dir)
    else:
        store.path.chmod(0o600)
    return store


def summary(message: dict) -> dict:
    result = {k: v for k, v in message.items() if k != "body"}
    result["body_sha256"] = hashlib.sha256(message["body"].encode("utf-8")).hexdigest()
    return result


def status(store: MessageStore, mid: str) -> dict:
    with store._connection() as db:
        row = db.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
        replies = db.execute("SELECT * FROM messages WHERE reply_to=? ORDER BY seq", (mid,)).fetchall()
    return {"message": summary(_row(row)) if row else None,
            "replies": [summary(_row(row)) for row in replies]}


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Local same-owner Codex/Claude/Grok bus client")
    parser.add_argument("--state-dir", type=Path, default=Path(__file__).resolve().parent / "state")
    sub = parser.add_subparsers(dest="command", required=True)
    send = sub.add_parser("send")
    send.add_argument("--from", dest="sender", required=True)
    send.add_argument("--to", dest="recipient", required=True)
    send.add_argument("--id", required=True)
    send.add_argument("--body-file", type=Path, required=True)
    send.add_argument("--reply-to")
    send.add_argument("--delivery", choices=DELIVERY_MODES,
                      help="Codex recipients: automatic steer by default (running-turn hook, idle queue fallback); "
                           "explicit queue = fresh next turn. Ignored for claude/grok. Check `queue --agent <to>` first.")
    queue = sub.add_parser("queue", help="read-only: pending (undelivered/unread) messages of any address with relay state")
    queue.add_argument("--agent", required=True)
    queue.add_argument("--limit", type=int, default=50)
    queue.add_argument("--after-seq", type=int, default=0,
                       help="next page: use next_seq from the previous queue result when has_more is true")
    inbox = sub.add_parser("inbox")
    inbox.add_argument("--agent", required=True)
    inbox.add_argument("--status", choices=("pending", "acked", "replied", "all"), default="pending")
    inbox.add_argument("--limit", type=int, default=20)
    inbox.add_argument("--summary", action="store_true")
    ack = sub.add_parser("ack")
    ack.add_argument("--agent", required=True)
    ack.add_argument("--id", required=True)
    get = sub.add_parser("status")
    get.add_argument("--id", required=True)
    read = sub.add_parser("get", help="full message for its recipient; does not ACK")
    read.add_argument("--agent", required=True)
    read.add_argument("--id", required=True)
    reg = sub.add_parser("register", help="register a Codex thread, Claude session or Antigravity (gemini/antigravity) conversation (local-only, no token)")
    reg.add_argument("--address", required=True, help="[a-z0-9-]{2,32}")
    reg.add_argument("--thread",
                     help="Codex thread UUID (default: $CODEX_THREAD_ID, set by Codex in its own shell); "
                          "for harness=gemini the explicit Antigravity conversation UUID")
    reg.add_argument("--harness", default="codex", choices=agent_registry.HARNESSES)
    reg.add_argument("--session", help="Explicit Claude session UUID; never inferred from CODEX_THREAD_ID")
    reg.add_argument("--topic", default="")
    alias = sub.add_parser("claude-alias", help="CAS bind legacy claude mailbox to one registered lead address")
    alias.add_argument("--address", required=True)
    alias.add_argument("--expected", help="Current lead address; omit only for an unbound alias")
    sub.add_parser("agents", help="list built-in and registered addresses")
    args = parser.parse_args(argv)
    known = agent_registry.all_agents(args.state_dir.absolute())
    for name in ("sender", "recipient", "agent"):
        if getattr(args, name, None) is not None and getattr(args, name) not in known:
            parser.error(f"unknown address {getattr(args, name)!r}; see `local_cli.py agents`")
    try:
        store = open_store(args.state_dir)
        if args.command == "register":
            identity = args.session if args.harness == "claude" else (args.thread or os.environ.get("CODEX_THREAD_ID"))
            if args.harness == "claude" and args.thread:
                raise ValueError("Claude uses --session, not --thread")
            if args.harness in ("codex", "gemini", "antigravity") and args.session:
                raise ValueError("--session is only for harness=claude")
            if args.harness in ("gemini", "antigravity") and not args.thread:
                raise ValueError("Antigravity/Gemini registration requires explicit --thread (Antigravity conversation UUID)")
            if args.harness == "claude" and not args.session:
                raise ValueError("Claude registration requires explicit --session UUID")
            if not identity:
                raise ValueError("no --thread and CODEX_THREAD_ID is not set")
            entry, existing = agent_registry.register(args.address, identity.strip().lower(), args.harness,
                                                      args.topic, args.state_dir.absolute())
            result = {"address": args.address, "already_registered": existing, "token": "local-only (like codexfc)", **entry}
        elif args.command == "claude-alias":
            result = agent_registry.set_claude_alias(args.address, args.expected, args.state_dir.absolute())
        elif args.command == "agents":
            result = {"agents": agent_registry.listing(args.state_dir.absolute())}
        elif args.command == "send":
            raw = args.body_file.read_bytes()
            if len(raw) > MAX_BODY_BYTES + 3:
                raise ValueError("body too large")
            message = _validate_message({"id": args.id, "from": args.sender, "to": args.recipient,
                                         "body": raw.decode("utf-8-sig"), "reply_to": args.reply_to,
                                         "delivery": args.delivery}, args.sender, args.state_dir.absolute())
            row, duplicate = store.post(message)
            result = {"message": summary(row), "duplicate": duplicate}
        elif args.command == "inbox":
            if not 1 <= args.limit <= 50:
                raise ValueError("limit must be 1-50")
            rows = store.inbox(args.agent, args.status, args.limit)
            result = {"messages": [summary(row) for row in rows] if args.summary else rows}
        elif args.command == "queue":
            result = queue_page(store, args.agent, args.limit, args.after_seq)
        elif args.command == "ack":
            row = store.ack(args.id, args.agent)
            if row is None:
                raise ValueError("message not found for recipient")
            result = {"message": summary(row)}
        elif args.command == "get":
            with store._connection() as db:
                row = db.execute("SELECT * FROM messages WHERE id=? AND recipient=?", (args.id, args.agent)).fetchone()
            if row is None:
                raise ValueError("message not found for recipient")
            result = {"message": _row(row)}
        else:
            result = status(store, args.id)
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        return 0
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(json.dumps({"error": type(exc).__name__, "detail": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
