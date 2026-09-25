"""One-use custody for signed ChangeIntents.

``reconcile()`` is a pure classifier: the same signed intent classifies the
same observation identically every time it is called. That is correct for
replaying evidence, but it means a signed intent is not by itself a one-use
authorization. This module supplies the durable half of the lifecycle on one
local SQLite database:

    verify -> reserve (exactly once) -> execute -> consume against an
    independent observation -> consumption receipt

A second reservation or consumption of the same ``(tenant_id, intent_id)`` is
rejected as replay, including after a crash or from another process. A
reservation that is never consumed stays reserved; it is closed explicitly
with ``abandon()`` and never becomes reusable. Custody is local-SQLite scoped
and grants no authority beyond the signed intent itself.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .reconciler import ObservedDelta, _parse_time, reconcile, verify_change_intent
from .signing import Ed25519Signer, TrustedKey, verify_trusted_signature

PROTOCOL = "integrity-guardian/change-intent-consumption/v1"
INTENT_DIGEST_DOMAIN = "change-intent-custody-v1"
RECEIPT_DOMAIN = "change-intent-consumption-receipt-v1"
MAX_HOLDER_LENGTH = 256


class IntentCustodyError(ValueError):
    """Raised when an intent cannot be reserved or consumed."""


class IntentReplayError(IntentCustodyError):
    """Raised when an intent was already reserved, consumed or abandoned."""


@dataclass(frozen=True)
class IntentReservation:
    tenant_id: str
    intent_id: str
    intent_digest: str
    holder: str
    reservation_id: str
    reserved_at: str


def _timestamp(value: datetime | None) -> datetime:
    current = datetime.now(UTC) if value is None else value
    if current.tzinfo is None:
        raise IntentCustodyError("custody time must include a timezone")
    return current.astimezone(UTC)


def _render(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def intent_digest(intent: dict[str, Any]) -> str:
    """Return the custody identity of one exact signed intent."""

    return digest_object(intent, domain=INTENT_DIGEST_DOMAIN)


class IntentCustody:
    """Durable, local, one-use custody for signed ChangeIntents."""

    def __init__(
        self,
        path: Path,
        *,
        tenant_id: str,
        authority_key: TrustedKey,
        signer: Ed25519Signer | None = None,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        if (
            isinstance(busy_timeout_ms, bool)
            or not isinstance(busy_timeout_ms, int)
            or not 0 <= busy_timeout_ms <= 60_000
        ):
            raise ValueError("custody busy timeout must be between 0 and 60000 milliseconds")
        if not isinstance(tenant_id, str) or not tenant_id:
            raise ValueError("custody tenant_id is required")
        self.path = path
        self.tenant_id = tenant_id
        self.authority_key = authority_key
        self._signer = signer
        # Autocommit mode: every state change runs in an explicit
        # BEGIN IMMEDIATE transaction so check-and-set is serialized.
        self._connection = sqlite3.connect(
            path, timeout=busy_timeout_ms / 1_000, isolation_level=None
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS intent_custody (
                tenant_id TEXT NOT NULL,
                intent_id TEXT NOT NULL,
                intent_digest TEXT NOT NULL,
                holder TEXT NOT NULL,
                reservation_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL
                    CHECK (status IN ('reserved', 'consumed', 'abandoned')),
                reserved_at TEXT NOT NULL,
                closed_at TEXT,
                receipt_json BLOB,
                PRIMARY KEY (tenant_id, intent_id)
            )
            """
        )

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _row(self, intent_id: str) -> sqlite3.Row | None:
        return self._connection.execute(
            "SELECT * FROM intent_custody WHERE tenant_id = ? AND intent_id = ?",
            (self.tenant_id, intent_id),
        ).fetchone()

    def status(self, intent_id: str) -> dict[str, Any] | None:
        """Return the custody state of one intent, or None if never reserved."""

        row = self._row(intent_id)
        if row is None:
            return None
        return {
            "tenant_id": row["tenant_id"],
            "intent_id": row["intent_id"],
            "intent_digest": row["intent_digest"],
            "holder": row["holder"],
            "status": row["status"],
            "reserved_at": row["reserved_at"],
            "closed_at": row["closed_at"],
        }

    def receipt(self, intent_id: str) -> dict[str, Any] | None:
        row = self._row(intent_id)
        if row is None or row["receipt_json"] is None:
            return None
        return parse_json_strict(row["receipt_json"])

    def reserve(
        self,
        intent: dict[str, Any],
        *,
        holder: str,
        now: datetime | None = None,
    ) -> IntentReservation:
        """Atomically claim the single use of a valid signed intent."""

        if (
            not isinstance(holder, str)
            or not holder
            or len(holder) > MAX_HOLDER_LENGTH
            or any(char.isspace() for char in holder)
        ):
            raise IntentCustodyError("holder must be a non-empty token without whitespace")
        verify_change_intent(intent, self.authority_key)
        if intent["tenant_id"] != self.tenant_id:
            raise IntentCustodyError("cross-tenant intent reservation is prohibited")
        current = _timestamp(now)
        if current < _parse_time(intent["valid_from"]):
            raise IntentCustodyError("ChangeIntent is not yet valid")
        if current > _parse_time(intent["valid_until"]):
            raise IntentCustodyError("ChangeIntent validity has ended")

        digest = intent_digest(intent)
        reserved_at = _render(current)
        reservation_id = "reservation:" + digest_object(
            {
                "tenant_id": self.tenant_id,
                "intent_id": intent["intent_id"],
                "intent_digest": digest,
                "holder": holder,
                "reserved_at": reserved_at,
            },
            domain="change-intent-reservation-v1",
        )
        with self._transaction():
            existing = self._row(intent["intent_id"])
            if existing is not None:
                raise IntentReplayError(
                    f"ChangeIntent {intent['intent_id']} is already {existing['status']}"
                )
            self._connection.execute(
                """
                INSERT INTO intent_custody(
                    tenant_id, intent_id, intent_digest, holder,
                    reservation_id, status, reserved_at
                ) VALUES (?, ?, ?, ?, ?, 'reserved', ?)
                """,
                (
                    self.tenant_id,
                    intent["intent_id"],
                    digest,
                    holder,
                    reservation_id,
                    reserved_at,
                ),
            )
        return IntentReservation(
            tenant_id=self.tenant_id,
            intent_id=intent["intent_id"],
            intent_digest=digest,
            holder=holder,
            reservation_id=reservation_id,
            reserved_at=reserved_at,
        )

    def consume(
        self,
        reservation: IntentReservation,
        intent: dict[str, Any],
        observed: Iterable[ObservedDelta],
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Close a reservation once, against independently observed deltas."""

        verify_change_intent(intent, self.authority_key)
        if intent_digest(intent) != reservation.intent_digest:
            raise IntentCustodyError("intent does not match its reservation")
        deltas = list(observed)
        results = reconcile(intent=intent, observed=deltas, authority_key=self.authority_key)
        closed_at = _render(_timestamp(now))
        with self._transaction():
            row = self._checked_reservation(reservation)
            receipt: dict[str, Any] = {
                "protocol": PROTOCOL,
                "outcome": "consumed",
                "tenant_id": self.tenant_id,
                "intent_id": reservation.intent_id,
                "intent_digest": reservation.intent_digest,
                "reservation_id": reservation.reservation_id,
                "holder": row["holder"],
                "reserved_at": row["reserved_at"],
                "closed_at": closed_at,
                "observation_event_ids": [delta.source_event_id for delta in deltas],
                "classifications": [item["classification"] for item in results],
                "results": results,
            }
            receipt = self._seal(receipt)
            self._close_row(reservation, "consumed", closed_at, receipt)
        return receipt

    def abandon(
        self,
        reservation: IntentReservation,
        *,
        reason: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Close a reservation without an outcome; the intent stays spent."""

        if not isinstance(reason, str) or not reason.strip():
            raise IntentCustodyError("abandon reason is required")
        closed_at = _render(_timestamp(now))
        with self._transaction():
            row = self._checked_reservation(reservation)
            receipt = self._seal(
                {
                    "protocol": PROTOCOL,
                    "outcome": "abandoned",
                    "tenant_id": self.tenant_id,
                    "intent_id": reservation.intent_id,
                    "intent_digest": reservation.intent_digest,
                    "reservation_id": reservation.reservation_id,
                    "holder": row["holder"],
                    "reserved_at": row["reserved_at"],
                    "closed_at": closed_at,
                    "reason": reason,
                }
            )
            self._close_row(reservation, "abandoned", closed_at, receipt)
        return receipt

    def _checked_reservation(self, reservation: IntentReservation) -> sqlite3.Row:
        row = self._row(reservation.intent_id)
        if row is None or row["reservation_id"] != reservation.reservation_id:
            raise IntentCustodyError("reservation is unknown to this custody store")
        if row["intent_digest"] != reservation.intent_digest:
            raise IntentCustodyError("reservation intent digest mismatch")
        if row["status"] != "reserved":
            raise IntentReplayError(
                f"ChangeIntent {reservation.intent_id} is already {row['status']}"
            )
        return row

    def _close_row(
        self,
        reservation: IntentReservation,
        status: str,
        closed_at: str,
        receipt: dict[str, Any],
    ) -> None:
        updated = self._connection.execute(
            """
            UPDATE intent_custody
            SET status = ?, closed_at = ?, receipt_json = ?
            WHERE tenant_id = ? AND intent_id = ? AND reservation_id = ?
              AND status = 'reserved'
            """,
            (
                status,
                closed_at,
                canonical_bytes(receipt),
                self.tenant_id,
                reservation.intent_id,
                reservation.reservation_id,
            ),
        )
        if updated.rowcount != 1:
            raise IntentReplayError("reservation was closed concurrently")

    def _seal(self, receipt: dict[str, Any]) -> dict[str, Any]:
        receipt["receipt_id"] = "receipt:" + digest_object(receipt, domain=RECEIPT_DOMAIN)
        if self._signer is not None:
            receipt = self._signer.sign(receipt)
        return receipt

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise
        self._connection.execute("COMMIT")


def verify_consumption_receipt(
    receipt: dict[str, Any], *, custody_key: TrustedKey | None = None
) -> None:
    """Recompute a receipt identity and, when a key is given, its signature."""

    if not isinstance(receipt, dict) or receipt.get("protocol") != PROTOCOL:
        raise IntentCustodyError("not a ChangeIntent consumption receipt")
    unsigned = {
        key: value for key, value in receipt.items() if key not in {"receipt_id", "signature"}
    }
    expected = "receipt:" + digest_object(unsigned, domain=RECEIPT_DOMAIN)
    if receipt.get("receipt_id") != expected:
        raise IntentCustodyError("consumption receipt identity mismatch")
    if custody_key is not None and not verify_trusted_signature(receipt, custody_key):
        raise IntentCustodyError("consumption receipt signature verification failed")
