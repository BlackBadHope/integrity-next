"""Shared-core bus. Seat identity comes from the verified token, never JSON."""

from __future__ import annotations

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sqlite3
import threading
from pathlib import Path

from .mesh import Mesh, MeshError, StaleFencingTokenError
from .schema import BusSchemaError, load_limits, normalize_message


class BusError(Exception):
    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


class BusSeat:
    def __init__(self, seat_id: str, host_id: str, roles: frozenset[str], namespaces: tuple[str, ...]) -> None:
        self.seat_id = seat_id
        self.host_id = host_id
        self.roles = frozenset(roles)
        self.namespaces = tuple(namespaces)


def namespace_visible(patterns: tuple[str, ...], namespace: str) -> bool:
    parts = namespace.split("/")
    if not namespace or any(not part or part == "*" for part in parts):
        return False
    for pattern in patterns:
        pattern_parts = pattern.split("/")
        if len(pattern_parts) != len(parts):
            continue
        if all(item == "*" or item == part for item, part in zip(pattern_parts, parts)):
            return True
    return False


def _utc(now: datetime | None = None) -> str:
    current = datetime.now(timezone.utc) if now is None else now.astimezone(timezone.utc)
    return current.strftime("%Y-%m-%dT%H:%M:%SZ")


class BusCore:
    def __init__(self, path: Path, resolver, *, limits: dict | None = None, core_instance_id: str = "core-local", mesh: Mesh | None = None) -> None:
        self.path = path
        self.resolver = resolver
        self.limits = load_limits(limits)
        self.core_instance_id = core_instance_id
        self.mesh = mesh or Mesh(Path(str(path) + ".mesh"))
        self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS bus_messages (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                id TEXT NOT NULL,
                sender_seat TEXT NOT NULL,
                recipient_seat TEXT NOT NULL,
                host_id TEXT NOT NULL,
                k TEXT NOT NULL,
                th TEXT NOT NULL,
                reply_to TEXT,
                delivery TEXT NOT NULL,
                body TEXT NOT NULL,
                body_sha256 TEXT NOT NULL,
                namespace TEXT NOT NULL,
                created_utc TEXT NOT NULL,
                acked_utc TEXT,
                status TEXT NOT NULL,
                UNIQUE (id, sender_seat, recipient_seat, body_sha256)
            );
            CREATE TABLE IF NOT EXISTS bus_agents (
                name TEXT PRIMARY KEY,
                seat_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                registered_utc TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS bus_presence (
                seat_id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL,
                namespace TEXT NOT NULL,
                seen_utc TEXT NOT NULL
            );
            """
        )

    def close(self) -> None:
        self._db.close()
        self.mesh.close()

    def mesh_open(self, seat: BusSeat, work_id: str, title: str) -> dict:
        namespace = "team/work" if namespace_visible(seat.namespaces, "team/work") else f"seat/{seat.seat_id}/work"
        if not namespace_visible(seat.namespaces, namespace):
            raise BusError("namespace forbidden", 403)
        return self.mesh.open(seat.seat_id, work_id, title, namespace, now=datetime.now(timezone.utc))

    def mesh_claim(self, seat: BusSeat, work_id: str, ttl: int) -> dict:
        if seat.roles.isdisjoint({"write", "admin"}):
            raise BusError("write forbidden", 403)
        return self.mesh.claim(seat.seat_id, work_id, ttl_seconds=ttl, now=datetime.now(timezone.utc))

    def mesh_progress(self, seat: BusSeat, work_id: str, fence: int, note: str) -> dict:
        return self.mesh.progress(seat.seat_id, work_id, fence, note, now=datetime.now(timezone.utc))

    def seat_from_headers(self, headers) -> BusSeat:
        token = None
        for key, value in headers.items():
            if str(key).lower() == "x-integrity-seat-token":
                token = value
        if not token:
            raise BusError("seat required", 401)
        try:
            seat = self.resolver(token)
        except BusError:
            raise
        except Exception as err:
            raise BusError("seat rejected", 401) from err
        if not isinstance(seat, BusSeat):
            raise BusError("seat rejected", 401)
        return seat

    def register_agent(self, seat: BusSeat, name: str) -> None:
        if name != seat.seat_id:
            raise BusError("agent name must match the authenticated seat", 403)
        with self._lock:
            self._db.execute(
                """
                INSERT INTO bus_agents (name, seat_id, host_id, registered_utc)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    host_id = excluded.host_id,
                    registered_utc = excluded.registered_utc
                """,
                (name, seat.seat_id, seat.host_id, _utc()),
            )

    def presence(self, seat: BusSeat) -> dict:
        namespace = "team/presence" if namespace_visible(seat.namespaces, "team/presence") else f"seat/{seat.seat_id}/presence"
        with self._lock:
            self._db.execute(
                """
                INSERT INTO bus_presence (seat_id, host_id, namespace, seen_utc)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(seat_id) DO UPDATE SET seen_utc = excluded.seen_utc, host_id = excluded.host_id
                """,
                (seat.seat_id, seat.host_id, namespace, _utc()),
            )
            rows = self._db.execute("SELECT * FROM bus_presence ORDER BY seat_id").fetchall()
        visible = [dict(row) for row in rows if namespace_visible(seat.namespaces, row["namespace"]) or row["seat_id"] == seat.seat_id]
        return {"presence": visible}

    def post(self, seat: BusSeat, raw: dict) -> dict:
        if "write" not in seat.roles and "admin" not in seat.roles:
            raise BusError("write forbidden", 403)
        message = normalize_message(raw, sender=seat.seat_id, created_utc=_utc())
        recipient = message["to"]
        with self._lock:
            known = self._db.execute("SELECT 1 FROM bus_agents WHERE name = ?", (recipient,)).fetchone()
            if known is None:
                raise BusError("recipient unknown", 403)
            namespace = self._namespace_for(seat, message["k"])
            if not namespace_visible(seat.namespaces, namespace):
                raise BusError("namespace forbidden", 403)
            if message.get("reply_to"):
                parent = self._visible(seat, message["reply_to"])
                if parent is None:
                    raise BusError("reply_to forbidden", 403)
            try:
                self._db.execute("BEGIN IMMEDIATE")
                cursor = self._db.execute(
                    """
                    INSERT INTO bus_messages (
                        id, sender_seat, recipient_seat, host_id, k, th, reply_to, delivery,
                        body, body_sha256, namespace, created_utc, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'accepted')
                    """,
                    (
                        message["id"], seat.seat_id, recipient, seat.host_id, message["k"], message["th"],
                        message.get("reply_to"), message["delivery"], message["body"], message["body_sha256"],
                        namespace, message["created_utc"],
                    ),
                )
                seq = int(cursor.lastrowid)
                self._db.execute("COMMIT")
                duplicate = False
            except sqlite3.IntegrityError:
                self._db.execute("ROLLBACK")
                existing = self._db.execute(
                    """
                    SELECT seq FROM bus_messages
                     WHERE id = ? AND sender_seat = ? AND recipient_seat = ? AND body_sha256 = ?
                    """,
                    (message["id"], seat.seat_id, recipient, message["body_sha256"]),
                ).fetchone()
                if existing is None:
                    raise BusError("message conflict", 409) from None
                seq = int(existing["seq"])
                duplicate = True
        stored = self.fetch(seat, message["id"])
        stored.update({"seq": seq, "duplicate": duplicate, "delivered": False})
        if message["delivery"] == "pull":
            stored["status"] = "route=pull"
        return stored

    def fetch(self, seat: BusSeat, message_id: str) -> dict:
        with self._lock:
            rows = self._db.execute("SELECT * FROM bus_messages WHERE id = ? ORDER BY seq", (message_id,)).fetchall()
        if not rows:
            raise BusError("message not found", 404)
        visible = [row for row in rows if self._can_read(seat, row)]
        if not visible:
            raise BusError("message forbidden", 403)
        return self._public(visible[-1])

    def fetch_seq(self, seat: BusSeat, seq: int) -> dict:
        with self._lock:
            row = self._db.execute("SELECT * FROM bus_messages WHERE seq = ?", (seq,)).fetchone()
        if row is None:
            raise BusError("message not found", 404)
        if not self._can_read(seat, row):
            raise BusError("message forbidden", 403)
        return self._public(row)

    def after(self, seat: BusSeat, after_seq: int) -> dict:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM bus_messages WHERE seq > ? ORDER BY seq", (after_seq,)
            ).fetchall()
        visible = [self._public(row) for row in rows if self._can_read(seat, row)]
        next_seq = visible[-1]["seq"] if visible else after_seq
        return {"messages": visible, "next_seq": next_seq}

    def ack(self, seat: BusSeat, message_id: str) -> dict:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM bus_messages WHERE id = ? ORDER BY seq DESC LIMIT 1", (message_id,)
            ).fetchone()
            if row is None or not self._can_read(seat, row):
                raise BusError("message forbidden", 403)
            if row["recipient_seat"] != seat.seat_id:
                raise BusError("ack forbidden", 403)
            self._db.execute(
                "UPDATE bus_messages SET acked_utc = ?, status = 'acked' WHERE seq = ?",
                (_utc(), row["seq"]),
            )
        return {"ok": True, "id": message_id, "status": "acked"}

    def meta(self, seat: BusSeat) -> dict:
        with self._lock:
            rows = self._db.execute("SELECT namespace, sender_seat, recipient_seat FROM bus_messages").fetchall()
        count = sum(1 for row in rows if self._can_read(seat, row))
        return {"visible_count": count, "arbiter": self.limits["arbiter"], "core_instance_id": self.core_instance_id}

    def _namespace_for(self, seat: BusSeat, kind: str) -> str:
        if kind == "private":
            return f"seat/{seat.seat_id}/bus"
        if namespace_visible(seat.namespaces, "team/bus"):
            return "team/bus"
        return f"seat/{seat.seat_id}/bus"

    def _can_read(self, seat: BusSeat, row) -> bool:
        if "read" not in seat.roles and "write" not in seat.roles and "admin" not in seat.roles and "go_approver" not in seat.roles:
            return False
        if row["sender_seat"] == seat.seat_id or row["recipient_seat"] == seat.seat_id:
            return namespace_visible(seat.namespaces, row["namespace"])
        return False

    def _visible(self, seat: BusSeat, message_id: str):
        rows = self._db.execute("SELECT * FROM bus_messages WHERE id = ?", (message_id,)).fetchall()
        for row in rows:
            if self._can_read(seat, row):
                return row
        return None

    @staticmethod
    def _public(row) -> dict:
        return {
            "seq": row["seq"],
            "id": row["id"],
            "from": row["sender_seat"],
            "to": row["recipient_seat"],
            "k": row["k"],
            "th": row["th"],
            "reply_to": row["reply_to"],
            "delivery": row["delivery"],
            "body": row["body"],
            "body_sha256": row["body_sha256"],
            "namespace": row["namespace"],
            "created_utc": row["created_utc"],
            "status": row["status"],
            "host_id": row["host_id"],
        }


class BusHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(core: BusCore, host: str = "127.0.0.1", port: int = 0) -> BusHTTPServer:
    def handler_class(*args, **kwargs):
        return _Handler(*args, core=core, **kwargs)

    server = BusHTTPServer((host, port), handler_class)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server.bus_thread = thread  # type: ignore[attr-defined]
    return server


class _Handler(BaseHTTPRequestHandler):
    def __init__(self, *args, core: BusCore, **kwargs):
        self.core = core
        super().__init__(*args, **kwargs)

    def log_message(self, fmt: str, *args) -> None:
        return

    def _read(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 65536:
            raise BusError("request too large", 413)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            value = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeError, json.JSONDecodeError) as err:
            raise BusError("json invalid", 400) from err
        if not isinstance(value, dict):
            raise BusError("json invalid", 400)
        return value

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        try:
            seat = self.core.seat_from_headers(self.headers)
            path = self.path.split("?", 1)[0]
            if method == "POST" and path == "/v1/messages":
                self._send(200, self.core.post(seat, self._read()))
                return
            if method == "POST" and path == "/v1/presence":
                self._send(200, self.core.presence(seat))
                return
            if method == "GET" and path == "/v1/presence":
                self._send(200, self.core.presence(seat))
                return
            if method == "GET" and path == "/v1/meta":
                self._send(200, self.core.meta(seat))
                return
            if method == "GET" and path == "/v1/messages":
                query = self.path.split("?", 1)[1] if "?" in self.path else ""
                after = 0
                for part in query.split("&"):
                    if part.startswith("after_seq="):
                        after = int(part.split("=", 1)[1])
                self._send(200, self.core.after(seat, after))
                return
            if method == "GET" and path.startswith("/v1/messages/"):
                self._send(200, self.core.fetch(seat, path.rsplit("/", 1)[-1]))
                return
            if method == "POST" and path.startswith("/v1/messages/") and path.endswith("/ack"):
                message_id = path[len("/v1/messages/"):-len("/ack")]
                self._send(200, self.core.ack(seat, message_id))
                return
            if method == "POST" and path == "/v1/agents":
                name = self._read().get("name")
                self.core.register_agent(seat, str(name))
                self._send(200, {"ok": True, "name": seat.seat_id})
                return
            if method == "POST" and path == "/v1/mesh/open":
                body = self._read()
                self._send(200, self.core.mesh_open(seat, str(body.get("work_id")), str(body.get("title") or "work")))
                return
            if method == "POST" and path == "/v1/mesh/claim":
                body = self._read()
                self._send(200, self.core.mesh_claim(seat, str(body.get("work_id")), int(body.get("ttl") or 30)))
                return
            if method == "POST" and path == "/v1/mesh/progress":
                body = self._read()
                self._send(200, self.core.mesh_progress(seat, str(body.get("work_id")), int(body["fence"]), str(body.get("note") or "")))
                return
            self._send(404, {"error": "not found"})
        except StaleFencingTokenError as err:
            self._send(409, {"error": "stale fencing token", "record": err.record})
        except MeshError as err:
            self._send(409, {"error": str(err)})
        except (BusError, BusSchemaError) as err:
            status = getattr(err, "status", 400)
            self._send(status, {"error": err.code if isinstance(err, BusError) else str(err)})
        except Exception as err:  # noqa: BLE001
            self._send(400, {"error": "request failed"})
