"""One-time host enrollment tokens and heartbeat leases.

The token is stored as a SHA-256 digest. Join writes host and peer keys with
mode 0600. A dropped lease or revocation removes the host from the active set.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat

from .seat_registry import SeatRegistryError, _check_seat_id


TRANSPORTS = frozenset({
    "local",
    "ssh_reverse_loopback",
    "ssh_stdio",
    "https_seat_mcp",
    "webhook",
})


def _utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now(moment: datetime | None) -> datetime:
    current = datetime.now(timezone.utc) if moment is None else moment
    if current.tzinfo is None:
        raise SeatRegistryError("time invalid", 400)
    return current.astimezone(timezone.utc)


class HostDirectory:
    def __init__(self, path: Path) -> None:
        if not path.is_absolute():
            raise SeatRegistryError("host directory path must be absolute", 400)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        connection = sqlite3.connect(path)
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS host_enroll_tokens (
                token_sha256 TEXT PRIMARY KEY,
                seat_id TEXT NOT NULL,
                host_id TEXT NOT NULL,
                transport TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS enrolled_hosts (
                host_id TEXT PRIMARY KEY,
                seat_id TEXT NOT NULL,
                transport TEXT NOT NULL,
                lease_expires_utc TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                key_dir TEXT NOT NULL
            );
            """
        )
        connection.commit()
        connection.close()
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def create_token(self, seat_id: str, host_id: str, transport: str, expires_at: str) -> str:
        _check_seat_id(seat_id)
        if transport not in TRANSPORTS or not host_id or len(host_id) > 128:
            raise SeatRegistryError("enrollment invalid", 400)
        token = secrets.token_urlsafe(32)
        digest = sha256(token.encode("utf-8")).hexdigest()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO host_enroll_tokens
                  (token_sha256, seat_id, host_id, transport, expires_at, consumed)
                VALUES (?, ?, ?, ?, ?, 0)
                """,
                (digest, seat_id, host_id, transport, expires_at),
            )
        return token

    def join(self, token: str, key_dir: Path, *, now: datetime | None = None, ttl_seconds: int = 30) -> dict:
        current = _now(now)
        digest = sha256(token.encode("utf-8")).hexdigest()
        key_dir.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM host_enroll_tokens WHERE token_sha256 = ?", (digest,)
            ).fetchone()
            if row is None or int(row["consumed"]) == 1 or row["expires_at"] <= _utc(current):
                connection.execute("ROLLBACK")
                raise SeatRegistryError("enrollment token rejected", 401)
            connection.execute(
                "UPDATE host_enroll_tokens SET consumed = 1 WHERE token_sha256 = ?", (digest,)
            )
            lease = _utc(current + timedelta(seconds=ttl_seconds))
            connection.execute(
                """
                INSERT INTO enrolled_hosts (host_id, seat_id, transport, lease_expires_utc, revoked, key_dir)
                VALUES (?, ?, ?, ?, 0, ?)
                ON CONFLICT(host_id) DO UPDATE SET
                    seat_id = excluded.seat_id,
                    transport = excluded.transport,
                    lease_expires_utc = excluded.lease_expires_utc,
                    revoked = 0,
                    key_dir = excluded.key_dir
                """,
                (row["host_id"], row["seat_id"], row["transport"], lease, str(key_dir)),
            )
            connection.execute("COMMIT")
            host_id = row["host_id"]
            seat_id = row["seat_id"]
            transport = row["transport"]
        host_key = secrets.token_hex(32)
        peer_key = secrets.token_hex(32)
        _write_secret(key_dir / "host.key", host_key)
        _write_secret(key_dir / "peer.key", peer_key)
        return {"ok": True, "host_id": host_id, "seat_id": seat_id, "transport": transport, "lease_expires_utc": lease}

    def heartbeat(self, host_id: str, *, now: datetime | None = None, ttl_seconds: int = 30) -> dict:
        current = _now(now)
        lease = _utc(current + timedelta(seconds=ttl_seconds))
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE enrolled_hosts
                   SET lease_expires_utc = ?
                 WHERE host_id = ? AND revoked = 0
                """,
                (lease, host_id),
            )
            updated = cursor.rowcount
        if updated != 1:
            raise SeatRegistryError("host inactive", 403)
        return {"ok": True, "host_id": host_id, "lease_expires_utc": lease}

    def drop_link(self, host_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE enrolled_hosts SET lease_expires_utc = '1970-01-01T00:00:00Z' WHERE host_id = ?",
                (host_id,),
            )

    def revoke(self, host_id: str) -> None:
        with self._connect() as connection:
            connection.execute("UPDATE enrolled_hosts SET revoked = 1 WHERE host_id = ?", (host_id,))

    def active(self, *, now: datetime | None = None) -> list[dict]:
        current = _utc(_now(now))
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT host_id, seat_id, transport, lease_expires_utc
                  FROM enrolled_hosts
                 WHERE revoked = 0 AND lease_expires_utc > ?
                 ORDER BY host_id
                """,
                (current,),
            ).fetchall()
        return [dict(row) for row in rows]


def _write_secret(path: Path, text: str) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, (text + "\n").encode("utf-8"))
    finally:
        os.close(descriptor)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    if os.name != "nt":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise SeatRegistryError("host key mode invalid", 500)
