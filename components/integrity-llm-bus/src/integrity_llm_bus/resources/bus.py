# SPDX-License-Identifier: Apache-2.0
"""Local, persistent message transport for Codex, Claude and Grok Bot.

Messages are data. This server never runs message contents or calls an LLM.
"""

from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
from contextlib import contextmanager
import hmac
import json
import os
import re
import sqlite3
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import agent_registry


AGENTS = ("codex", "claude", "grok", "codexfc")  # built-ins; more via agent_registry (self-registration)
TOKEN_ENV = {agent: f"LLM_BUS_TOKEN_{agent.upper()}" for agent in AGENTS}
ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
MAX_BODY_BYTES = 32 * 1024
MAX_REQUEST_BYTES = 48 * 1024
MAX_INBOX_LIMIT = 50
DEFAULT_TTL_HOURS = 168
DELIVERY_MODES = ("steer", "queue")  # Codex recipients only; None means default queue
MESSAGE_KEYS = {"id", "from", "to", "body", "reply_to"}


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON value: {value}")


def _validate_message(value: object, sender: str, state_dir: Path | None = None) -> dict:
    if not isinstance(value, dict) or not MESSAGE_KEYS <= set(value) or set(value) - MESSAGE_KEYS - {"delivery"}:
        raise ValueError("message needs id, from, to, body and reply_to (optional delivery)")
    if value.get("delivery") is not None and value["delivery"] not in DELIVERY_MODES:
        raise ValueError("delivery must be steer or queue")
    mid = value["id"]
    if not isinstance(mid, str) or not ID_RE.fullmatch(mid):
        raise ValueError("invalid message id")
    if value["from"] != sender:
        raise ValueError("from must match authenticated agent")
    if value["to"] not in agent_registry.all_agents(state_dir) or value["to"] == sender:
        raise ValueError("to must be another configured agent")
    if not isinstance(value["body"], str) or not value["body"]:
        raise ValueError("body must be a nonempty string")
    if len(value["body"].encode("utf-8")) > MAX_BODY_BYTES:
        raise ValueError("body is too large")
    parent = value["reply_to"]
    if parent is not None and (not isinstance(parent, str) or not ID_RE.fullmatch(parent)):
        raise ValueError("invalid reply_to")
    return value


def _row(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "from": row["sender"],
        "to": row["recipient"],
        "body": row["body"],
        "reply_to": row["reply_to"],
        "status": row["status"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "acked_at": row["acked_at"],
        "replied_at": row["replied_at"],
        "delivery": row["delivery"] if "delivery" in row.keys() else None,
    }


def _first_line(body: str, limit: int = 100) -> str:
    for line in body.splitlines():
        if line.strip():
            line = line.strip()
            return line if len(line) <= limit else line[:limit - 1] + "\u2026"
    return ""


def queue_view(store: "MessageStore", recipient: str, limit: int = 50, after_seq: int = 0) -> list[dict]:
    """Read-only: undelivered/unread messages for one address plus relay/steer state."""
    state_dir = store.path.parent
    journal, steer = {}, {}
    try:
        for key, batch in json.loads((state_dir / "relay-journal.json").read_text(encoding="utf-8"))["batches"].items():
            for mid in batch.get("ids", []):
                journal[mid] = (key, batch)
    except (OSError, ValueError, KeyError, TypeError):
        pass
    for path in (state_dir / "codex-steer").glob("*.json") if (state_dir / "codex-steer").is_dir() else []:
        try:
            for entry in json.loads(path.read_text(encoding="utf-8")).get("entries", []):
                for mid in entry.get("ids", []):
                    steer[mid] = entry.get("state")
        except (OSError, ValueError, AttributeError):
            continue
    now = int(time.time())
    with store._connection() as db:
        rows = db.execute("SELECT * FROM messages WHERE recipient=? AND status='pending' AND expires_at>? AND seq>? ORDER BY seq LIMIT ?",
                          (recipient, now, after_seq, limit)).fetchall()
    result = []
    for row in rows:
        message = _row(row)
        key, batch = journal.get(message["id"], (None, None))
        if batch is None:
            relay_state = "not_notified"
        elif batch.get("state") == "accepted":
            relay_state = (batch.get("receipt") or {}).get("status", "notified")
            if message["id"] in steer:
                relay_state = steer[message["id"]]  # staged | steered | queued
        else:
            relay_state = batch.get("state")
        relay_receipt = (batch or {}).get("receipt") or {}
        result.append({"seq": row["seq"], "id": message["id"], "from": message["from"],
                       "delivery": message["delivery"] or "steer", "delivery_explicit": message["delivery"] is not None,
                       "created_at": message["created_at"],
                       "created_local": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(message["created_at"])),
                       "subject": _first_line(message["body"]), "status": message["status"],
                       "relay_state": relay_state, "relay_batch": key,
                       "relay_http_status": (batch or {}).get("http_status", relay_receipt.get("http_status")),
                       "relay_error_type": (batch or {}).get("error_type"),
                       "application_verified": relay_receipt.get("application_verified"),
                       "execution_complete": relay_receipt.get("execution_complete")})
    return result


def queue_page(store: "MessageStore", recipient: str, limit: int = 50, after_seq: int = 0) -> dict:
    """Bounded keyset page; ACK/expiry cannot shift the next page like an offset."""
    if type(limit) is not int or not 1 <= limit <= MAX_INBOX_LIMIT:
        raise ValueError("limit must be 1-50")
    if type(after_seq) is not int or not 0 <= after_seq <= 2**63 - 1:
        raise ValueError("after-seq must be a nonnegative SQLite integer")
    rows = queue_view(store, recipient, limit + 1, after_seq)
    has_more = len(rows) > limit
    rows = rows[:limit]
    return {"agent": recipient, "queue": rows, "has_more": has_more,
            "next_seq": rows[-1]["seq"] if has_more else None}


class MessageStore:
    def __init__(self, path: Path, ttl_seconds: int):
        self.path = path
        self.ttl_seconds = ttl_seconds
        with self._connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS messages (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT NOT NULL UNIQUE,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    body TEXT NOT NULL,
                    reply_to TEXT,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','acked','replied')),
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    acked_at INTEGER,
                    replied_at INTEGER
                );
                CREATE INDEX IF NOT EXISTS messages_inbox
                    ON messages(recipient, status, seq);
                CREATE INDEX IF NOT EXISTS messages_expiry
                    ON messages(expires_at);
            """)
            # Additive, nullable migration (2026-10-13): per-message Codex delivery mode.
            if "delivery" not in {r[1] for r in db.execute("PRAGMA table_info(messages)")}:
                db.execute("ALTER TABLE messages ADD COLUMN delivery TEXT")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout = 5000")
        db.execute("PRAGMA secure_delete = ON")
        return db

    @contextmanager
    def _connection(self):
        db = self._connect()
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def _prune(db: sqlite3.Connection, now: int) -> None:
        db.execute("DELETE FROM messages WHERE expires_at <= ?", (now,))

    def post(self, message: dict) -> tuple[dict, bool]:
        now = int(time.time())
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._prune(db, now)
            existing = db.execute("SELECT * FROM messages WHERE id = ?", (message["id"],)).fetchone()
            if existing:
                same = (
                    existing["sender"] == message["from"]
                    and existing["recipient"] == message["to"]
                    and existing["body"] == message["body"]
                    and existing["reply_to"] == message["reply_to"]
                    and existing["delivery"] == message.get("delivery")
                )
                if not same:
                    raise FileExistsError("message id is already used for different content")
                return _row(existing), True
            if message["reply_to"] is not None:
                parent = db.execute("SELECT * FROM messages WHERE id = ?", (message["reply_to"],)).fetchone()
                if not parent or parent["recipient"] != message["from"] or parent["sender"] != message["to"]:
                    raise ValueError("reply_to must reference a message received from the addressee")
                db.execute("UPDATE messages SET status = 'replied', replied_at = COALESCE(replied_at, ?) WHERE id = ?", (now, message["reply_to"]))
            db.execute(
                """INSERT INTO messages
                   (id, sender, recipient, body, reply_to, created_at, expires_at, delivery)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (message["id"], message["from"], message["to"], message["body"], message["reply_to"], now, now + self.ttl_seconds,
                 message.get("delivery")),
            )
            result = db.execute("SELECT * FROM messages WHERE id = ?", (message["id"],)).fetchone()
            return _row(result), False

    def inbox(self, recipient: str, status: str, limit: int) -> list[dict]:
        now = int(time.time())
        with self._connection() as db:
            self._prune(db, now)
            if status == "all":
                rows = db.execute("SELECT * FROM messages WHERE recipient = ? ORDER BY seq LIMIT ?", (recipient, limit)).fetchall()
            else:
                rows = db.execute("SELECT * FROM messages WHERE recipient = ? AND status = ? ORDER BY seq LIMIT ?", (recipient, status, limit)).fetchall()
            return [_row(row) for row in rows]

    def ack(self, mid: str, recipient: str) -> dict | None:
        now = int(time.time())
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._prune(db, now)
            row = db.execute("SELECT * FROM messages WHERE id = ? AND recipient = ?", (mid, recipient)).fetchone()
            if not row:
                return None
            if row["status"] == "pending":
                db.execute("UPDATE messages SET status = 'acked', acked_at = ? WHERE id = ?", (now, mid))
                row = db.execute("SELECT * FROM messages WHERE id = ?", (mid,)).fetchone()
            return _row(row)


class TokenRegistry:
    def __init__(self, tokens: dict[str, str]):
        if not set(AGENTS[:3]) <= set(tokens) or not set(tokens) <= set(AGENTS):  # codexfc token optional (local-only address)
            raise ValueError("tokens are required for codex, claude and grok")
        if any(not isinstance(token, str) or len(token) < 24 or not token.isascii() for token in tokens.values()):
            raise ValueError("each agent token must be ASCII and at least 24 characters")
        if len(set(tokens.values())) != len(tokens):
            raise ValueError("agent tokens must be distinct")
        self._tokens = tokens.copy()

    @classmethod
    def from_environment(cls) -> "TokenRegistry":
        return cls({agent: os.environ.get(name, "") for agent, name in TOKEN_ENV.items()})

    def identify(self, authorization: str) -> str | None:
        if not authorization.startswith("Bearer "):
            return None
        supplied = authorization[7:]
        if not supplied or len(supplied) > 512 or not supplied.isascii():
            return None
        found = None
        for agent, token in self._tokens.items():
            if hmac.compare_digest(supplied, token):
                found = agent
        return found


class BusServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, store: MessageStore, registry: TokenRegistry, port: int):
        self.store = store
        self.registry = registry
        super().__init__(("127.0.0.1", port), BusHandler)


class BusHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: BusServer

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, _format: str, *_args: object) -> None:
        # HTTP request lines and headers can contain sensitive message data.
        return

    def _json(self, code: int, value: dict) -> None:
        data = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.close_connection = True
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _agent(self) -> str | None:
        agent = self.server.registry.identify(self.headers.get("Authorization", ""))
        if agent is None:
            self._json(401, {"error": "unauthorized"})
        return agent

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/v1/health" and not parsed.query:
            self._json(200, {"ok": True})
            return
        agent = self._agent()
        if agent is None:
            return
        if parsed.path == "/v1/queue":
            try:
                params = parse_qs(parsed.query, strict_parsing=True)
                if set(params) - {"agent", "limit"} or any(len(v) != 1 for v in params.values()):
                    raise ValueError("invalid query")
                target = params.get("agent", [agent])[0]
                limit = int(params.get("limit", ["50"])[0])
                if target not in agent_registry.all_agents(self.server.store.path.parent) or not 1 <= limit <= MAX_INBOX_LIMIT:
                    raise ValueError("invalid query")
                queue = queue_view(self.server.store, target, limit)
            except ValueError:
                self._json(400, {"error": "invalid queue query"})
                return
            except sqlite3.Error:
                self._json(500, {"error": "storage unavailable"})
                return
            self._json(200, {"agent": target, "queue": queue})
            return
        if parsed.path == "/v1/agents" and not parsed.query:
            self._json(200, {"agents": agent_registry.listing(self.server.store.path.parent)})
            return
        if parsed.path != "/v1/inbox":
            self._json(404, {"error": "not found"})
            return
        try:
            params = parse_qs(parsed.query, strict_parsing=True)
            if set(params) - {"status", "limit"} or any(len(v) != 1 for v in params.values()):
                raise ValueError("invalid query")
            status = params.get("status", ["pending"])[0]
            limit = int(params.get("limit", ["20"])[0])
            if status not in {"pending", "acked", "replied", "all"} or not 1 <= limit <= MAX_INBOX_LIMIT:
                raise ValueError("invalid query")
            messages = self.server.store.inbox(agent, status, limit)
        except ValueError:
            self._json(400, {"error": "invalid inbox query"})
            return
        except sqlite3.Error:
            self._json(500, {"error": "storage unavailable"})
            return
        self._json(200, {"messages": messages})

    def do_POST(self) -> None:
        agent = self._agent()
        if agent is None:
            return
        path = urlsplit(self.path)
        if path.query:
            self._json(404, {"error": "not found"})
            return
        if path.path == "/v1/messages":
            self._post_message(agent)
            return
        if path.path == "/v1/register":
            self._register()
            return
        match = re.fullmatch(r"/v1/messages/([A-Za-z0-9._:-]{1,128})/ack", path.path)
        if match:
            length = self.headers.get("Content-Length", "0")
            if length != "0":
                self._json(400, {"error": "ack has no request body"})
                return
            try:
                row = self.server.store.ack(match.group(1), agent)
            except sqlite3.Error:
                self._json(500, {"error": "storage unavailable"})
                return
            if row:
                self._json(200, {"message": row})
            else:
                self._json(404, {"error": "not found"})
            return
        self._json(404, {"error": "not found"})

    def _register(self) -> None:
        """Any authenticated agent may register a Codex thread address (same owner, loopback only)."""
        try:
            length = int(self.headers.get("Content-Length", ""))
            if not 1 <= length <= 4096:
                raise ValueError("invalid size")
            payload = json.loads(self.rfile.read(length).decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
            if not isinstance(payload, dict) or set(payload) - {"address", "thread", "harness", "topic"}:
                raise ValueError("register needs address, thread (optional harness, topic)")
            entry, existing = agent_registry.register(payload.get("address"), payload.get("thread"),
                                                      payload.get("harness") or "codex", payload.get("topic") or "",
                                                      self.server.store.path.parent)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            self._json(409 if "already" in str(exc) else 400, {"error": str(exc)[:200]})
            return
        self._json(200 if existing else 201, {"address": payload["address"], "already_registered": existing, **entry})

    def _post_message(self, agent: str) -> None:
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            self._json(415, {"error": "Content-Type must be application/json"})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
            if not 1 <= length <= MAX_REQUEST_BYTES:
                raise ValueError("invalid size")
        except ValueError:
            self._json(413, {"error": "invalid request size"})
            return
        try:
            payload = json.loads(
                self.rfile.read(length).decode("utf-8"),
                object_pairs_hook=_no_duplicate_keys,
                parse_constant=_reject_constant,
            )
            message = _validate_message(payload, agent, self.server.store.path.parent)
            row, duplicate = self.server.store.post(message)
        except FileExistsError:
            self._json(409, {"error": "message id conflict"})
            return
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self._json(400, {"error": "invalid message"})
            return
        except sqlite3.Error:
            self._json(500, {"error": "storage unavailable"})
            return
        self._json(200 if duplicate else 201, {"message": row, "duplicate": duplicate})


def create_server(state_dir: Path, tokens: dict[str, str], port: int = 0, ttl_hours: int = DEFAULT_TTL_HOURS) -> BusServer:
    if not 1 <= ttl_hours <= 720:
        raise ValueError("ttl_hours must be between 1 and 720")
    registry = TokenRegistry(tokens)
    if state_dir.is_symlink() or (hasattr(state_dir, "is_junction") and state_dir.is_junction()):
        raise OSError("Bus state path must not be a link")
    if os.name == "nt":
        from win_acl import secure_state_directory
        secure_state_directory(state_dir)
    else:
        state_dir.mkdir(mode=0o700, parents=False, exist_ok=True)
        os.chmod(state_dir, 0o700)
    store = MessageStore(state_dir / "bus.sqlite3", ttl_hours * 3600)
    if os.name == "nt":
        secure_state_directory(state_dir)
    else:
        os.chmod(store.path, 0o600)
    return BusServer(store, registry, port)


def main() -> int:
    parser = argparse.ArgumentParser(description="Loopback-only, persistent Codex/Claude/Grok message bus")
    parser.add_argument("--port", type=int, default=8768, help="127.0.0.1 port (default: 8768)")
    parser.add_argument("--ttl-hours", type=int, default=DEFAULT_TTL_HOURS, help="message lifetime, 1-720 hours (default: 168)")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    state_dir = Path(__file__).resolve().parent / "state"
    try:
        server = create_server(state_dir, {agent: os.environ.get(name, "") for agent, name in TOKEN_ENV.items()}, args.port, args.ttl_hours)
    except (ValueError, OSError, sqlite3.Error) as exc:
        parser.exit(2, f"Bus startup failed: {exc}\n")
    print(f"LLM bus listening on http://127.0.0.1:{server.server_port} (state: {state_dir})", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    sys.exit(main())
