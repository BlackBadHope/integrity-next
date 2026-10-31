"""Work projection ordered by core sequence, with monotonic fencing.

progress and done require the current fence and an unexpired lease. assign
issues a new fence. A stale token is rejected and recorded.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import sqlite3
import threading
from pathlib import Path


class MeshError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class StaleFencingTokenError(MeshError):
    def __init__(self, code: str, record: dict) -> None:
        super().__init__(code)
        self.record = record


def _utc(now: datetime) -> str:
    if now.tzinfo is None:
        raise MeshError("time invalid")
    return now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _serialized(method):
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper


def _parse(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class Mesh:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS mesh_fence (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                last_fence INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO mesh_fence(singleton, last_fence) VALUES (1, 0);
            CREATE TABLE IF NOT EXISTS mesh_work (
                work_id TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                owner_seat TEXT,
                fence INTEGER,
                lease_expires_utc TEXT,
                namespace TEXT NOT NULL,
                title TEXT NOT NULL,
                opened_by TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS mesh_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                work_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                seat_id TEXT NOT NULL,
                fence INTEGER,
                detail TEXT NOT NULL,
                created_utc TEXT NOT NULL
            );
            """
        )

    def close(self) -> None:
        self._db.close()

    @_serialized
    def events(self, work_id: str | None = None) -> list[dict]:
        if work_id is None:
            rows = self._db.execute("SELECT * FROM mesh_events ORDER BY seq").fetchall()
        else:
            rows = self._db.execute(
                "SELECT * FROM mesh_events WHERE work_id = ? ORDER BY seq", (work_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    @_serialized
    def projection(self) -> list[dict]:
        rows = self._db.execute(
            """
            SELECT w.*, MAX(e.seq) AS seq
              FROM mesh_work w
              JOIN mesh_events e ON e.work_id = w.work_id
             GROUP BY w.work_id
             ORDER BY seq
            """
        ).fetchall()
        return [dict(row) for row in rows]

    def open(self, seat_id: str, work_id: str, title: str, namespace: str, *, now: datetime) -> dict:
        with self._lock:
            return self._open(seat_id, work_id, title, namespace, now)

    def _open(self, seat_id: str, work_id: str, title: str, namespace: str, now: datetime) -> dict:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._db.execute(
                """
                INSERT INTO mesh_work
                  (work_id, state, owner_seat, fence, lease_expires_utc, namespace, title, opened_by)
                VALUES (?, 'open', NULL, NULL, NULL, ?, ?, ?)
                """,
                (work_id, namespace, title, seat_id),
            )
            record = self._event(work_id, "open", seat_id, None, {"title": title}, now)
            self._db.execute("COMMIT")
        except sqlite3.IntegrityError as err:
            self._db.execute("ROLLBACK")
            raise MeshError("work exists") from err
        except Exception:
            self._db.execute("ROLLBACK")
            raise
        return record

    @_serialized
    def claim(self, seat_id: str, work_id: str, *, ttl_seconds: int, now: datetime) -> dict:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            row = self._work(work_id)
            self._expire(row, now)
            row = self._work(work_id)
            if row["state"] == "claimed" and row["owner_seat"] == seat_id:
                record = self._event(work_id, "claim", seat_id, row["fence"], {"renewed": False}, now)
                self._db.execute("COMMIT")
                return {"ok": True, "status": "acquired", "fence": row["fence"], "record": record}
            if row["state"] == "claimed" and row["owner_seat"] not in (None, seat_id):
                record = self._event(work_id, "reject", seat_id, row["fence"], {"reason": "held"}, now)
                self._db.execute("COMMIT")
                return {"ok": False, "status": "rejected", "record": record}
            fence = self._next_fence()
            expires = _utc(now.astimezone(timezone.utc) + timedelta(seconds=ttl_seconds))
            self._db.execute(
                """
                UPDATE mesh_work
                   SET state = 'claimed', owner_seat = ?, fence = ?, lease_expires_utc = ?
                 WHERE work_id = ?
                """,
                (seat_id, fence, expires, work_id),
            )
            record = self._event(work_id, "claim", seat_id, fence, {"lease_expires_utc": expires}, now)
            self._db.execute("COMMIT")
        except Exception:
            self._db.execute("ROLLBACK")
            raise
        return {"ok": True, "status": "acquired", "fence": fence, "record": record}

    @_serialized
    def progress(self, seat_id: str, work_id: str, fence: int, note: str, *, now: datetime) -> dict:
        return self._fenced(seat_id, work_id, fence, "progress", {"note": note}, now)

    @_serialized
    def done(self, seat_id: str, work_id: str, fence: int, *, now: datetime) -> dict:
        result = self._fenced(seat_id, work_id, fence, "done", {}, now, close=True)
        return result

    @_serialized
    def release(self, seat_id: str, work_id: str, fence: int, *, now: datetime) -> dict:
        return self._fenced(seat_id, work_id, fence, "release", {}, now, reopen=True)

    @_serialized
    def assign(self, seat_id: str, work_id: str, fence: int, successor: str, *, ttl_seconds: int, now: datetime) -> dict:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._require_fence(seat_id, work_id, fence, now)
            new_fence = self._next_fence()
            expires = _utc(now.astimezone(timezone.utc) + timedelta(seconds=ttl_seconds))
            self._db.execute(
                """
                UPDATE mesh_work
                   SET owner_seat = ?, fence = ?, lease_expires_utc = ?, state = 'claimed'
                 WHERE work_id = ?
                """,
                (successor, new_fence, expires, work_id),
            )
            record = self._event(
                work_id, "assign", seat_id, new_fence, {"successor": successor, "previous_fence": fence}, now
            )
            self._db.execute("COMMIT")
        except StaleFencingTokenError:
            self._db.execute("COMMIT")
            raise
        except Exception:
            self._db.execute("ROLLBACK")
            raise
        return {"ok": True, "fence": new_fence, "record": record}

    @_serialized
    def cancel(self, seat_id: str, work_id: str, *, now: datetime) -> dict:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            row = self._work(work_id)
            if row["state"] == "done":
                raise MeshError("work closed")
            self._db.execute(
                "UPDATE mesh_work SET state = 'cancelled', owner_seat = NULL, fence = NULL WHERE work_id = ?",
                (work_id,),
            )
            record = self._event(work_id, "cancel", seat_id, row["fence"], {}, now)
            self._db.execute("COMMIT")
        except Exception:
            self._db.execute("ROLLBACK")
            raise
        return {"ok": True, "record": record}

    @_serialized
    def decision_request(self, seat_id: str, work_id: str, request_digest: str, *, now: datetime) -> dict:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            record = self._event(
                work_id, "decision-request", seat_id, None, {"request_digest": request_digest}, now
            )
            self._db.execute("COMMIT")
        except Exception:
            self._db.execute("ROLLBACK")
            raise
        return {"ok": True, "seq": record["seq"], "record": record}

    @_serialized
    def decision(self, seat_id: str, work_id: str, *, request_seq: int, detail: dict, now: datetime) -> dict:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            latest = self._db.execute(
                "SELECT COALESCE(MAX(seq), 0) FROM mesh_events"
            ).fetchone()[0]
            if int(latest) < request_seq or request_seq < 1:
                record = self._event(work_id, "reject", seat_id, None, {"reason": "decision seq"}, now)
                self._db.execute("COMMIT")
                raise StaleFencingTokenError("decision seq invalid", record)
            record = self._event(work_id, "decision", seat_id, None, detail, now)
            if record["seq"] <= request_seq:
                raise MeshError("decision seq invalid")
            self._db.execute("COMMIT")
        except StaleFencingTokenError:
            raise
        except Exception:
            self._db.execute("ROLLBACK")
            raise
        return {"ok": True, "seq": record["seq"], "record": record}

    def _fenced(self, seat_id, work_id, fence, kind, detail, now, *, close=False, reopen=False) -> dict:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._require_fence(seat_id, work_id, fence, now)
            if close:
                self._db.execute(
                    "UPDATE mesh_work SET state = 'done', lease_expires_utc = NULL WHERE work_id = ?",
                    (work_id,),
                )
            if reopen:
                self._db.execute(
                    """
                    UPDATE mesh_work
                       SET state = 'open', owner_seat = NULL, fence = NULL, lease_expires_utc = NULL
                     WHERE work_id = ?
                    """,
                    (work_id,),
                )
            record = self._event(work_id, kind, seat_id, fence, detail, now)
            self._db.execute("COMMIT")
        except StaleFencingTokenError:
            self._db.execute("COMMIT")
            raise
        except Exception:
            self._db.execute("ROLLBACK")
            raise
        return {"ok": True, "record": record}

    def _require_fence(self, seat_id: str, work_id: str, fence: int, now: datetime) -> None:
        row = self._work(work_id)
        self._expire(row, now)
        row = self._work(work_id)
        expires = _parse(row["lease_expires_utc"])
        current = now.astimezone(timezone.utc)
        if (
            row["state"] != "claimed"
            or row["owner_seat"] != seat_id
            or row["fence"] != fence
            or expires is None
            or expires <= current
        ):
            record = self._event(
                work_id, "reject", seat_id, fence, {"reason": "stale fence"}, now
            )
            raise StaleFencingTokenError("stale fencing token", record)

    def _expire(self, row: sqlite3.Row, now: datetime) -> None:
        expires = _parse(row["lease_expires_utc"])
        if row["state"] == "claimed" and expires is not None and expires <= now.astimezone(timezone.utc):
            self._db.execute(
                """
                UPDATE mesh_work
                   SET state = 'open', owner_seat = NULL, fence = NULL, lease_expires_utc = NULL
                 WHERE work_id = ?
                """,
                (row["work_id"],),
            )
            self._event(row["work_id"], "lease-expired", row["owner_seat"] or "", row["fence"], {}, now)

    def _work(self, work_id: str) -> sqlite3.Row:
        row = self._db.execute("SELECT * FROM mesh_work WHERE work_id = ?", (work_id,)).fetchone()
        if row is None:
            raise MeshError("work unknown")
        return row

    def _next_fence(self) -> int:
        self._db.execute("UPDATE mesh_fence SET last_fence = last_fence + 1 WHERE singleton = 1")
        return int(self._db.execute("SELECT last_fence FROM mesh_fence").fetchone()[0])

    def _event(self, work_id, kind, seat_id, fence, detail, now) -> dict:
        cursor = self._db.execute(
            """
            INSERT INTO mesh_events (work_id, kind, seat_id, fence, detail, created_utc)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (work_id, kind, seat_id, fence, json.dumps(detail, sort_keys=True), _utc(now)),
        )
        return {"seq": int(cursor.lastrowid), "work_id": work_id, "kind": kind, "fence": fence}
