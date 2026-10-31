"""Local seat registry. Tokens are stored as SHA-256 only.

A seat is an Integrity access seat. This store never accepts or records a
model-provider credential.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
from typing import Iterable

_SEAT_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_HOST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ROLES = frozenset({"read", "write", "go_approver", "admin"})
_NAMESPACE = re.compile(r"^[a-z][a-z0-9_*:/-]{0,127}$")


class SeatRegistryError(ValueError):
    def __init__(self, code: str, status: int = 403) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class SeatRecord:
    seat_id: str
    display_name: str
    roles: frozenset[str]
    namespaces: tuple[str, ...]
    status: str
    revocation_epoch: int


@dataclass(frozen=True)
class IssuedToken:
    token: str
    token_sha256: str
    seat_id: str
    host_id: str
    expires_at: str
    epoch: int


def _check_seat_id(seat_id: str) -> str:
    if not isinstance(seat_id, str) or _SEAT_ID.fullmatch(seat_id) is None:
        raise SeatRegistryError("seat_id invalid", 400)
    return seat_id


def _check_roles(roles: Iterable[str]) -> tuple[str, ...]:
    values = tuple(roles)
    if not values or any(role not in _ROLES for role in values):
        raise SeatRegistryError("roles invalid", 400)
    return tuple(sorted(set(values)))


def _check_namespaces(namespaces: Iterable[str]) -> tuple[str, ...]:
    values = tuple(namespaces)
    if not values or len(values) > 32:
        raise SeatRegistryError("namespaces invalid", 400)
    for namespace in values:
        if not isinstance(namespace, str) or _NAMESPACE.fullmatch(namespace) is None:
            raise SeatRegistryError("namespaces invalid", 400)
        if namespace.count("*") > 1 or ("*" in namespace and not namespace.endswith("/*")):
            raise SeatRegistryError("namespaces invalid", 400)
    return tuple(sorted(set(values)))


def token_digest(token: str) -> str:
    if not isinstance(token, str) or not token or len(token) > 512 or any(ch.isspace() for ch in token):
        raise SeatRegistryError("seat token invalid", 401)
    return sha256(token.encode("utf-8")).hexdigest()


class SeatRegistry:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise SeatRegistryError("seat registry path must be absolute", 400)
        candidate.parent.mkdir(parents=True, exist_ok=True)
        self.path = candidate
        self._ensure()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def _ensure(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS seats (
                    seat_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    roles_json TEXT NOT NULL,
                    namespaces_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    revocation_epoch INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS seat_identities (
                    issuer TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    seat_id TEXT NOT NULL,
                    PRIMARY KEY (issuer, subject)
                );
                CREATE TABLE IF NOT EXISTS seat_tokens (
                    token_sha256 TEXT PRIMARY KEY,
                    seat_id TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS seat_signing_keys (
                    key_id TEXT PRIMARY KEY,
                    seat_id TEXT NOT NULL,
                    alg TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    valid_from TEXT NOT NULL,
                    retired_at TEXT
                );
                """
            )
        try:
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    def create_seat(
        self,
        seat_id: str,
        display_name: str,
        roles: Iterable[str],
        namespaces: Iterable[str],
    ) -> SeatRecord:
        seat_id = _check_seat_id(seat_id)
        role_values = _check_roles(roles)
        namespace_values = _check_namespaces(namespaces)
        if not isinstance(display_name, str) or not display_name.strip() or len(display_name) > 128:
            raise SeatRegistryError("display_name invalid", 400)
        with self._connect() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO seats
                      (seat_id, display_name, roles_json, namespaces_json, status, revocation_epoch)
                    VALUES (?, ?, ?, ?, 'active', 0)
                    """,
                    (
                        seat_id,
                        display_name.strip(),
                        json.dumps(role_values),
                        json.dumps(namespace_values),
                    ),
                )
            except sqlite3.IntegrityError as err:
                raise SeatRegistryError("seat exists", 409) from err
        return self.get_seat(seat_id)

    def get_seat(self, seat_id: str) -> SeatRecord:
        seat_id = _check_seat_id(seat_id)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM seats WHERE seat_id = ?", (seat_id,)
            ).fetchone()
        if row is None:
            raise SeatRegistryError("seat unknown", 401)
        return SeatRecord(
            seat_id=row["seat_id"],
            display_name=row["display_name"],
            roles=frozenset(json.loads(row["roles_json"])),
            namespaces=tuple(json.loads(row["namespaces_json"])),
            status=row["status"],
            revocation_epoch=int(row["revocation_epoch"]),
        )

    def list_seats(self) -> list[SeatRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT seat_id FROM seats ORDER BY seat_id"
            ).fetchall()
        return [self.get_seat(row["seat_id"]) for row in rows]

    def revoke_seat(self, seat_id: str) -> SeatRecord:
        current = self.get_seat(seat_id)
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE seats
                   SET status = 'revoked', revocation_epoch = revocation_epoch + 1
                 WHERE seat_id = ?
                """,
                (current.seat_id,),
            )
        return self.get_seat(current.seat_id)

    def bind_identity(self, issuer: str, subject: str, seat_id: str) -> None:
        seat = self.get_seat(seat_id)
        if not isinstance(issuer, str) or not issuer.startswith("https://") or len(issuer) > 512:
            raise SeatRegistryError("issuer invalid", 400)
        if not isinstance(subject, str) or not subject or len(subject) > 512:
            raise SeatRegistryError("subject invalid", 400)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO seat_identities (issuer, subject, seat_id)
                VALUES (?, ?, ?)
                ON CONFLICT(issuer, subject) DO UPDATE SET seat_id = excluded.seat_id
                """,
                (issuer, subject, seat.seat_id),
            )

    def seat_for_identity(self, issuer: str, subject: str) -> SeatRecord:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT seat_id FROM seat_identities WHERE issuer = ? AND subject = ?",
                (issuer, subject),
            ).fetchone()
        if row is None:
            raise SeatRegistryError("identity unknown", 401)
        return self.get_seat(row["seat_id"])

    def issue_token(self, seat_id: str, host_id: str, expires_at: str) -> IssuedToken:
        seat = self.get_seat(seat_id)
        if seat.status != "active":
            raise SeatRegistryError("seat revoked", 403)
        if not isinstance(host_id, str) or _HOST_ID.fullmatch(host_id) is None:
            raise SeatRegistryError("host_id invalid", 400)
        if not isinstance(expires_at, str) or not expires_at.endswith("Z"):
            raise SeatRegistryError("expires_at invalid", 400)
        token = secrets.token_urlsafe(32)
        digest = token_digest(token)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO seat_tokens
                  (token_sha256, seat_id, host_id, expires_at, epoch, revoked)
                VALUES (?, ?, ?, ?, ?, 0)
                """,
                (digest, seat.seat_id, host_id, expires_at, seat.revocation_epoch),
            )
        return IssuedToken(
            token=token,
            token_sha256=digest,
            seat_id=seat.seat_id,
            host_id=host_id,
            expires_at=expires_at,
            epoch=seat.revocation_epoch,
        )

    def revoke_token(self, token: str) -> None:
        digest = token_digest(token)
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE seat_tokens SET revoked = 1 WHERE token_sha256 = ? AND revoked = 0",
                (digest,),
            )
        if cursor.rowcount != 1:
            raise SeatRegistryError("token unknown", 401)

    def resolve_token(self, token: str, *, now_utc: str) -> tuple[SeatRecord, str, str]:
        digest = token_digest(token)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM seat_tokens WHERE token_sha256 = ?", (digest,)
            ).fetchone()
        if row is None or int(row["revoked"]) == 1:
            raise SeatRegistryError("token unknown", 401)
        if str(row["expires_at"]) <= now_utc:
            raise SeatRegistryError("token expired", 401)
        seat = self.get_seat(row["seat_id"])
        if seat.status != "active" or seat.revocation_epoch != int(row["epoch"]):
            raise SeatRegistryError("seat revoked", 403)
        return seat, str(row["host_id"]), digest

    def register_signing_key(
        self,
        key_id: str,
        seat_id: str,
        alg: str,
        public_key: str,
        valid_from: str,
    ) -> None:
        seat = self.get_seat(seat_id)
        if alg not in {"Ed25519", "ECDSA-P256", "RSA-2048"}:
            raise SeatRegistryError("signing alg invalid", 400)
        if not isinstance(key_id, str) or not _HOST_ID.fullmatch(key_id):
            raise SeatRegistryError("key_id invalid", 400)
        if not isinstance(public_key, str) or not public_key or len(public_key) > 8192:
            raise SeatRegistryError("public_key invalid", 400)
        if "PRIVATE" in public_key:
            raise SeatRegistryError("public_key invalid", 400)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO seat_signing_keys
                  (key_id, seat_id, alg, public_key, valid_from, retired_at)
                VALUES (?, ?, ?, ?, ?, NULL)
                """,
                (key_id, seat.seat_id, alg, public_key, valid_from),
            )
