"""Local blast-radius coordination for agents that share one machine.

Agents declare the resources an action may touch (its blast radius) before
they write. One SQLite database serializes every decision with
``BEGIN IMMEDIATE``:

* a claim that overlaps no live claim is ``acquired`` with a fresh fencing
  token, so disjoint work runs in parallel;
* a claim that overlaps a live claim of another agent is ``waiting``; it is
  promoted in arrival order as soon as the blocking claims are released,
  handed off or expired. A waiting claim also expires unless its requester
  keeps polling, so a crashed waiter never blocks the queue;
* a claim that overlaps the requester's own live claim is ``rejected``.

Writers call ``assert_fence`` before every write. Fencing tokens are strictly
increasing across the registry, so an agent whose lease expired or was
handed off cannot keep writing after a successor acquired the resources.
Every transition is appended to a hash-chained event log that all agents can
read, which is how a waiting agent sees the holder's release receipt.

Scope: one local SQLite database. Agent identities are caller-asserted and
not authenticated here, and nothing in this module provides cross-machine
consensus.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Self

from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object

PROTOCOL = "integrity-guardian/work-claim/v1"
EVENT_DOMAIN = "work-claim-event-v1"
MAX_RESOURCES = 64
MAX_TTL_SECONDS = 86_400
_AGENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}")
_KIND = re.compile(r"[a-z][a-z0-9-]{0,63}")


class WorkClaimError(ValueError):
    """Raised when a claim request or transition is invalid."""


class StaleFenceError(WorkClaimError):
    """Raised when a writer no longer holds the claim it is writing under."""


class ClaimStatus(StrEnum):
    ACQUIRED = "acquired"
    WAITING = "waiting"
    REJECTED = "rejected"
    RELEASED = "released"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    HANDED_OFF = "handed_off"


_OPEN = (ClaimStatus.ACQUIRED.value, ClaimStatus.WAITING.value)


@dataclass(frozen=True)
class ClaimDecision:
    status: ClaimStatus
    claim_id: str
    agent_id: str
    resources: tuple[str, ...]
    fence_token: int | None = None
    expires_at: str | None = None
    blocked_by: tuple[str, ...] = ()
    reason: str = ""


def normalize_resource(resource: str) -> str:
    """Return ``kind:value`` with a canonical, comparison-ready value.

    Values are compared case-insensitively and as ``/``-separated paths, which
    over-approximates overlap rather than missing it.
    """

    if not isinstance(resource, str) or ":" not in resource:
        raise WorkClaimError("resource must be written as kind:value")
    kind, value = resource.split(":", 1)
    if _KIND.fullmatch(kind) is None:
        raise WorkClaimError(f"invalid resource kind: {kind!r}")
    value = value.replace("\\", "/").strip()
    if not value or any(char.isspace() or not char.isprintable() for char in value):
        raise WorkClaimError("resource value must be a printable token without whitespace")
    parts = value.split("/")
    if any(part in {".", ".."} for part in parts):
        raise WorkClaimError("resource value may not contain . or .. segments")
    collapsed = "/".join(part for index, part in enumerate(parts) if part or index == 0)
    if len(collapsed) > 1:
        collapsed = collapsed.rstrip("/")
    return f"{kind}:{collapsed.casefold()}"


def resources_overlap(left: str, right: str) -> bool:
    """Two normalized resources overlap when equal or one contains the other."""

    left_kind, left_value = left.split(":", 1)
    right_kind, right_value = right.split(":", 1)
    if left_kind != right_kind:
        return False
    if left_value == right_value:
        return True
    return _contains(left_value, right_value) or _contains(right_value, left_value)


def _contains(parent: str, child: str) -> bool:
    prefix = parent if parent.endswith("/") else parent + "/"
    return child.startswith(prefix)


def _sets_overlap(left: Iterable[str], right: Iterable[str]) -> bool:
    right = tuple(right)
    return any(resources_overlap(a, b) for a in left for b in right)


def _time(value: datetime | None) -> datetime:
    current = datetime.now(UTC) if value is None else value
    if current.tzinfo is None:
        raise WorkClaimError("claim time must include a timezone")
    return current.astimezone(UTC)


def _render(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _agent(agent_id: str) -> str:
    if not isinstance(agent_id, str) or _AGENT.fullmatch(agent_id) is None:
        raise WorkClaimError("agent_id must be a token of 1..256 safe characters")
    return agent_id


def _ttl(ttl_seconds: int) -> int:
    if (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, int)
        or not 1 <= ttl_seconds <= MAX_TTL_SECONDS
    ):
        raise WorkClaimError(f"ttl_seconds must be between 1 and {MAX_TTL_SECONDS}")
    return ttl_seconds


class WorkClaimRegistry:
    """Serialized, fenced blast-radius claims on one local SQLite database."""

    def __init__(self, path: Path, *, busy_timeout_ms: int = 5_000) -> None:
        if (
            isinstance(busy_timeout_ms, bool)
            or not isinstance(busy_timeout_ms, int)
            or not 0 <= busy_timeout_ms <= 60_000
        ):
            raise ValueError("claim busy timeout must be between 0 and 60000 milliseconds")
        self.path = path
        self._connection = sqlite3.connect(
            path, timeout=busy_timeout_ms / 1_000, isolation_level=None
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS work_claims (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                claim_id TEXT NOT NULL UNIQUE,
                agent_id TEXT NOT NULL,
                resources_json TEXT NOT NULL,
                status TEXT NOT NULL,
                fence_token INTEGER,
                ttl_seconds INTEGER NOT NULL,
                requested_at TEXT NOT NULL,
                expires_at TEXT,
                closed_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_work_claims_open
            ON work_claims(status, seq);
            CREATE TABLE IF NOT EXISTS work_claim_fence (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                last_fence INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO work_claim_fence(singleton, last_fence) VALUES (1, 0);
            CREATE TABLE IF NOT EXISTS work_claim_events (
                event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_digest TEXT NOT NULL UNIQUE,
                previous_digest TEXT,
                event_json BLOB NOT NULL
            );
            """
        )

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # -- public operations -------------------------------------------------

    def claim(
        self,
        *,
        agent_id: str,
        resources: Iterable[str],
        ttl_seconds: int = 300,
        now: datetime | None = None,
    ) -> ClaimDecision:
        """Request exclusive write access to a blast radius."""

        agent = _agent(agent_id)
        ttl = _ttl(ttl_seconds)
        normalized = tuple(sorted({normalize_resource(item) for item in resources}))
        if not normalized or len(normalized) > MAX_RESOURCES:
            raise WorkClaimError(f"a claim must name 1..{MAX_RESOURCES} resources")
        current = _time(now)
        with self._transaction():
            self._expire(current)
            own = [
                row
                for row in self._open_rows()
                if row["agent_id"] == agent and _sets_overlap(normalized, _resources(row))
            ]
            if own:
                decision = ClaimDecision(
                    status=ClaimStatus.REJECTED,
                    claim_id="",
                    agent_id=agent,
                    resources=normalized,
                    blocked_by=tuple(row["claim_id"] for row in own),
                    reason="overlaps a claim this agent already holds or awaits",
                )
                self._append_event("claim-rejected", decision, current)
                return decision
            claim_id = "claim:" + digest_object(
                {
                    "agent_id": agent,
                    "resources": list(normalized),
                    "requested_at": _render(current),
                    "nonce": self._next_seq(),
                },
                domain="work-claim-id-v1",
            ).split(":", 1)[1]
            self._connection.execute(
                """
                INSERT INTO work_claims(
                    claim_id, agent_id, resources_json, status, ttl_seconds,
                    requested_at, expires_at
                ) VALUES (?, ?, ?, 'waiting', ?, ?, ?)
                """,
                (claim_id, agent, canonical_bytes(list(normalized)).decode(), ttl,
                 _render(current), _render(current + timedelta(seconds=ttl))),
            )
            decision = self._try_promote(claim_id, current)
            self._append_event(
                "claim-acquired" if decision.status is ClaimStatus.ACQUIRED else "claim-waiting",
                decision,
                current,
            )
            return decision

    def poll(self, claim_id: str, *, now: datetime | None = None) -> ClaimDecision:
        """Report a claim's state; keeps a waiting claim alive for another TTL."""

        current = _time(now)
        with self._transaction():
            self._expire(current)
            row = self._row(claim_id)
            if row["status"] != ClaimStatus.WAITING.value:
                return self._decision(row)
            self._connection.execute(
                "UPDATE work_claims SET expires_at = ? WHERE claim_id = ?",
                (_render(current + timedelta(seconds=row["ttl_seconds"])), claim_id),
            )
            return self._try_promote(claim_id, current)

    def assert_fence(
        self,
        claim_id: str,
        *,
        agent_id: str,
        fence_token: int,
        now: datetime | None = None,
    ) -> ClaimDecision:
        """Raise unless the caller still holds the claim under this exact fence."""

        current = _time(now)
        row = self._row(claim_id)
        if (
            row["status"] != ClaimStatus.ACQUIRED.value
            or row["agent_id"] != agent_id
            or row["fence_token"] != fence_token
            or row["expires_at"] is None
            or _parse(row["expires_at"]) <= current
        ):
            raise StaleFenceError(f"{claim_id} is not held by {agent_id} under fence {fence_token}")
        return self._decision(row)

    def renew(
        self,
        claim_id: str,
        *,
        agent_id: str,
        fence_token: int,
        ttl_seconds: int | None = None,
        now: datetime | None = None,
    ) -> ClaimDecision:
        current = _time(now)
        with self._transaction():
            row = self._held(claim_id, agent_id, fence_token, current)
            ttl = row["ttl_seconds"] if ttl_seconds is None else _ttl(ttl_seconds)
            expires_at = _render(current + timedelta(seconds=ttl))
            self._connection.execute(
                "UPDATE work_claims SET expires_at = ?, ttl_seconds = ? WHERE claim_id = ?",
                (expires_at, ttl, claim_id),
            )
            decision = self._decision(self._row(claim_id))
            self._append_event("claim-renewed", decision, current)
            return decision

    def release(
        self,
        claim_id: str,
        *,
        agent_id: str,
        fence_token: int,
        outcome: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Close a held claim and publish its outcome to every agent."""

        if not isinstance(outcome, str) or not outcome.strip():
            raise WorkClaimError("release outcome is required")
        current = _time(now)
        with self._transaction():
            self._held(claim_id, agent_id, fence_token, current)
            self._close(claim_id, ClaimStatus.RELEASED, current)
            receipt = self._append_event(
                "claim-released",
                self._decision(self._row(claim_id)),
                current,
                extra={"outcome": outcome},
            )
            self._promote_waiters(current)
            return receipt

    def cancel(self, claim_id: str, *, agent_id: str, now: datetime | None = None) -> None:
        """Withdraw a waiting claim."""

        current = _time(now)
        with self._transaction():
            row = self._row(claim_id)
            if row["agent_id"] != agent_id or row["status"] != ClaimStatus.WAITING.value:
                raise WorkClaimError("only the requester can cancel its waiting claim")
            self._close(claim_id, ClaimStatus.CANCELLED, current)
            self._append_event("claim-cancelled", self._decision(self._row(claim_id)), current)
            self._promote_waiters(current)

    def handoff(
        self,
        claim_id: str,
        *,
        agent_id: str,
        fence_token: int,
        successor_id: str,
        note: str = "",
        now: datetime | None = None,
    ) -> ClaimDecision:
        """Transfer a held claim to a successor under a new fencing token."""

        successor = _agent(successor_id)
        current = _time(now)
        with self._transaction():
            row = self._held(claim_id, agent_id, fence_token, current)
            if successor == agent_id:
                raise WorkClaimError("handoff successor must differ from the holder")
            self._close(claim_id, ClaimStatus.HANDED_OFF, current)
            resources = _resources(row)
            new_id = "claim:" + digest_object(
                {"handoff_from": claim_id, "successor": successor, "at": _render(current)},
                domain="work-claim-id-v1",
            ).split(":", 1)[1]
            fence = self._next_fence()
            self._connection.execute(
                """
                INSERT INTO work_claims(
                    claim_id, agent_id, resources_json, status, fence_token,
                    ttl_seconds, requested_at, expires_at
                ) VALUES (?, ?, ?, 'acquired', ?, ?, ?, ?)
                """,
                (new_id, successor, canonical_bytes(list(resources)).decode(), fence,
                 row["ttl_seconds"], _render(current),
                 _render(current + timedelta(seconds=row["ttl_seconds"]))),
            )
            decision = self._decision(self._row(new_id))
            self._append_event(
                "claim-handed-off",
                decision,
                current,
                extra={"from_claim_id": claim_id, "from_agent_id": agent_id, "note": note},
            )
            return decision

    def events(self, *, after: int = 0, limit: int = 200) -> list[dict[str, Any]]:
        """Read the shared transition log after one event sequence number."""

        if not 1 <= limit <= 1_000:
            raise WorkClaimError("event limit is outside 1..1000")
        rows = self._connection.execute(
            """
            SELECT event_seq, event_json FROM work_claim_events
            WHERE event_seq > ? ORDER BY event_seq LIMIT ?
            """,
            (after, limit),
        ).fetchall()
        return [
            {"event_seq": row["event_seq"], **parse_json_strict(row["event_json"])}
            for row in rows
        ]

    def verify_events(self) -> int:
        """Recompute the event hash chain; return the number of verified events."""

        previous: str | None = None
        count = 0
        for row in self._connection.execute(
            "SELECT event_digest, previous_digest, event_json FROM work_claim_events "
            "ORDER BY event_seq"
        ):
            event = parse_json_strict(row["event_json"])
            if event.get("previous_digest") != previous or row["previous_digest"] != previous:
                raise WorkClaimError("work claim event chain is broken")
            if digest_object(event, domain=EVENT_DOMAIN) != row["event_digest"]:
                raise WorkClaimError("work claim event digest mismatch")
            previous = row["event_digest"]
            count += 1
        return count

    def status(self, claim_id: str) -> ClaimDecision:
        return self._decision(self._row(claim_id))

    # -- internals ---------------------------------------------------------

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise
        self._connection.execute("COMMIT")

    def _row(self, claim_id: str) -> sqlite3.Row:
        row = self._connection.execute(
            "SELECT * FROM work_claims WHERE claim_id = ?", (claim_id,)
        ).fetchone()
        if row is None:
            raise WorkClaimError(f"unknown claim {claim_id}")
        return row

    def _open_rows(self) -> list[sqlite3.Row]:
        return self._connection.execute(
            "SELECT * FROM work_claims WHERE status IN (?, ?) ORDER BY seq", _OPEN
        ).fetchall()

    def _held(
        self, claim_id: str, agent_id: str, fence_token: int, current: datetime
    ) -> sqlite3.Row:
        self._expire(current)
        row = self._row(claim_id)
        if (
            row["status"] != ClaimStatus.ACQUIRED.value
            or row["agent_id"] != agent_id
            or row["fence_token"] != fence_token
        ):
            raise StaleFenceError(f"{claim_id} is not held by {agent_id} under fence {fence_token}")
        return row

    def _expire(self, current: datetime) -> None:
        expired = False
        for row in self._open_rows():
            if _parse(row["expires_at"]) <= current:
                self._close(row["claim_id"], ClaimStatus.EXPIRED, current)
                self._append_event("claim-expired", self._decision(self._row(row["claim_id"])),
                                   current)
                expired = True
        if expired:
            self._promote_waiters(current)

    def _promote_waiters(self, current: datetime) -> None:
        for row in self._open_rows():
            if row["status"] != ClaimStatus.WAITING.value:
                continue
            decision = self._try_promote(row["claim_id"], current)
            if decision.status is ClaimStatus.ACQUIRED:
                self._append_event("claim-acquired", decision, current)

    def _try_promote(self, claim_id: str, current: datetime) -> ClaimDecision:
        row = self._row(claim_id)
        mine = _resources(row)
        blockers = [
            other["claim_id"]
            for other in self._open_rows()
            if other["claim_id"] != claim_id
            and (
                other["status"] == ClaimStatus.ACQUIRED.value
                or other["seq"] < row["seq"]  # earlier waiters keep their turn
            )
            and _sets_overlap(mine, _resources(other))
        ]
        if blockers:
            return self._decision(row, blocked_by=tuple(blockers),
                                  reason="overlapping blast radius is held or queued earlier")
        fence = self._next_fence()
        self._connection.execute(
            """
            UPDATE work_claims SET status = 'acquired', fence_token = ?, expires_at = ?
            WHERE claim_id = ?
            """,
            (fence, _render(current + timedelta(seconds=row["ttl_seconds"])), claim_id),
        )
        return self._decision(self._row(claim_id))

    def _close(self, claim_id: str, status: ClaimStatus, current: datetime) -> None:
        self._connection.execute(
            "UPDATE work_claims SET status = ?, closed_at = ? WHERE claim_id = ?",
            (status.value, _render(current), claim_id),
        )

    def _next_fence(self) -> int:
        self._connection.execute(
            "UPDATE work_claim_fence SET last_fence = last_fence + 1 WHERE singleton = 1"
        )
        return int(
            self._connection.execute(
                "SELECT last_fence FROM work_claim_fence WHERE singleton = 1"
            ).fetchone()[0]
        )

    def _next_seq(self) -> int:
        return int(
            self._connection.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM work_claims")
            .fetchone()[0]
        )

    def _decision(
        self, row: sqlite3.Row, *, blocked_by: tuple[str, ...] = (), reason: str = ""
    ) -> ClaimDecision:
        return ClaimDecision(
            status=ClaimStatus(row["status"]),
            claim_id=row["claim_id"],
            agent_id=row["agent_id"],
            resources=_resources(row),
            fence_token=row["fence_token"],
            expires_at=row["expires_at"],
            blocked_by=blocked_by,
            reason=reason,
        )

    def _append_event(
        self,
        kind: str,
        decision: ClaimDecision,
        current: datetime,
        *,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        tip = self._connection.execute(
            "SELECT event_digest FROM work_claim_events ORDER BY event_seq DESC LIMIT 1"
        ).fetchone()
        previous = None if tip is None else tip["event_digest"]
        event: dict[str, Any] = {
            "protocol": PROTOCOL,
            "kind": kind,
            "at": _render(current),
            "claim_id": decision.claim_id,
            "agent_id": decision.agent_id,
            "status": decision.status.value,
            "resources": list(decision.resources),
            "fence_token": decision.fence_token,
            "blocked_by": list(decision.blocked_by),
            "previous_digest": previous,
            **(extra or {}),
        }
        digest = digest_object(event, domain=EVENT_DOMAIN)
        self._connection.execute(
            """
            INSERT INTO work_claim_events(event_digest, previous_digest, event_json)
            VALUES (?, ?, ?)
            """,
            (digest, previous, canonical_bytes(event)),
        )
        return {**event, "event_digest": digest}


def _resources(row: sqlite3.Row) -> tuple[str, ...]:
    return tuple(parse_json_strict(row["resources_json"]))


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value)
