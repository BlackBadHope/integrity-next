"""Private checkpoint-pinned anti-replay ledger for Uroboros authority.

The wrapper reuses the project append-only ``LedgerStore``.  Each a12 request
owns one source chain: sequence 0 records its exact signed decision and
sequence 1 records the sole grant consumption.  No sequence 2 is accepted.
The caller must retain the returned signed checkpoint outside the database.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Self

from .ledger import (
    LedgerError,
    LedgerStore,
    build_ledger_event,
    event_digest,
    verify_ledger_event,
)
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
)
from .uroboros_toolzs_authority import (
    ToolzAuthorityDecision,
    ToolzAuthorityDecisionOutcome,
    ToolzAuthorityDecisionReason,
    ToolzAuthorityError,
    ToolzAuthorityPolicy,
    ToolzAuthorizationEvidence,
    ToolzGrantConsumption,
    build_toolz_authority_decision,
    build_toolz_grant_consumption,
    toolz_authority_decision_digest,
    toolz_authority_policy_digest,
    toolz_grant_consumption_digest,
    verify_toolz_authority_decision,
    verify_toolz_grant_consumption,
)

AUTHORITY_LEDGER_DATABASE_NAME = "toolz-authority.sqlite3"

_REQUEST_ID = re.compile(r"^toolz-authorization-request:[a-f0-9]{64}$")
_LEDGER_BOUNDARY = {
    "browser_control": False,
    "credentials": False,
    "execution": False,
    "external_effect": False,
    "local_storage": True,
    "model_sdk": False,
    "network": False,
    "production_authority": False,
    "raw_ui_data": False,
    "route_memory_store_write": False,
    "tool_invocation": False,
}


@dataclass(frozen=True)
class ToolzAuthorityDecisionRecord:
    """One decision plus its exact ledger event and new rollback pin."""

    decision: dict[str, Any]
    ledger_event: dict[str, Any]
    checkpoint: dict[str, Any]

    @property
    def execution_performed(self) -> bool:
        return False


@dataclass(frozen=True)
class ToolzGrantConsumptionRecord:
    """One consumption plus its exact ledger event and new rollback pin."""

    consumption: dict[str, Any]
    ledger_event: dict[str, Any]
    checkpoint: dict[str, Any]

    @property
    def execution_performed(self) -> bool:
        return False

    @property
    def external_effect_performed(self) -> bool:
        return False

    @property
    def consumption_recorded(self) -> bool:
        return True


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ToolzAuthorityError(f"Toolzs authority ledger {field} rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ToolzAuthorityError(f"Toolzs authority ledger {field} rejected") from exc
    if parsed.tzinfo is None:
        raise ToolzAuthorityError(f"Toolzs authority ledger {field} rejected")
    return parsed


def _assert_root_binding(candidate: Path, descriptor: int) -> os.stat_result:
    try:
        linked = candidate.lstat()
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise ToolzAuthorityError("Toolzs authority ledger root rejected") from exc
    if (
        stat.S_ISLNK(linked.st_mode)
        or not stat.S_ISDIR(linked.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
        or (linked.st_dev, linked.st_ino) != (opened.st_dev, opened.st_ino)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) != 0o700
    ):
        raise ToolzAuthorityError("Toolzs authority ledger root is unsafe")
    return opened


def _prepare_root(root: Path, *, create: bool) -> tuple[Path, int]:
    candidate = Path(root).absolute()
    try:
        if create:
            candidate.mkdir(mode=0o700, parents=True, exist_ok=False)
        details = candidate.lstat()
    except (FileExistsError, FileNotFoundError, OSError) as exc:
        raise ToolzAuthorityError("Toolzs authority ledger root rejected") from exc
    if (
        stat.S_ISLNK(details.st_mode)
        or not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != 0o700
    ):
        raise ToolzAuthorityError("Toolzs authority ledger root is unsafe")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(candidate, flags)
        _assert_root_binding(candidate, descriptor)
    except OSError as exc:
        raise ToolzAuthorityError("Toolzs authority ledger root rejected") from exc
    except Exception:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    return candidate, descriptor


def _prepare_database(
    root: Path,
    root_descriptor: int,
    *,
    create: bool,
) -> tuple[Path, int]:
    path = root / AUTHORITY_LEDGER_DATABASE_NAME
    flags = os.O_RDWR
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        _assert_root_binding(root, root_descriptor)
        descriptor = os.open(
            AUTHORITY_LEDGER_DATABASE_NAME,
            flags,
            0o600,
            dir_fd=root_descriptor,
        )
        if create:
            os.fchmod(descriptor, 0o600)
        details = os.fstat(descriptor)
        linked = os.stat(
            AUTHORITY_LEDGER_DATABASE_NAME,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        _assert_root_binding(root, root_descriptor)
    except (FileExistsError, FileNotFoundError, OSError) as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise ToolzAuthorityError("Toolzs authority ledger database rejected") from exc
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        raise
    assert descriptor is not None
    if (
        not stat.S_ISREG(details.st_mode)
        or not stat.S_ISREG(linked.st_mode)
        or (details.st_dev, details.st_ino) != (linked.st_dev, linked.st_ino)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise ToolzAuthorityError("Toolzs authority ledger database is unsafe")
    return path, descriptor


def _descriptor_path(descriptor: int) -> Path:
    proc = Path("/proc/self/fd")
    if not proc.is_dir():
        raise ToolzAuthorityError("Toolzs authority ledger requires Linux procfs")
    return proc / str(descriptor)


def _checkpoint_id(checkpoint: Mapping[str, Any]) -> str:
    root = checkpoint["root_digest"].split(":", 1)[1]
    return f"toolz-authority-checkpoint:{checkpoint['tree_size']}:{root}"


class ToolzAuthorityLedger:
    """One private ledger with an externally pinned exact signed checkpoint."""

    def __init__(
        self,
        *,
        root: Path,
        root_descriptor: int,
        database_descriptor: int,
        store: LedgerStore,
        policy: ToolzAuthorityPolicy,
        ledger_key: TrustedKey,
    ) -> None:
        self.root = root
        self.database_path = root / AUTHORITY_LEDGER_DATABASE_NAME
        self._root_descriptor = root_descriptor
        self._database_descriptor = database_descriptor
        self.policy = policy
        self.ledger_key = ledger_key
        self._store = store
        self._closed = False
        self._checkpoint: dict[str, Any] | None = None

    @classmethod
    def initialize(
        cls,
        root: Path,
        *,
        policy: ToolzAuthorityPolicy,
        ledger_key: TrustedKey,
        ledger_signer: Ed25519Signer,
        created_at: str,
    ) -> ToolzAuthorityLedger:
        """Create the private ledger and its first externally retained pin."""

        if not isinstance(policy, ToolzAuthorityPolicy):
            raise ToolzAuthorityError("Toolzs authority ledger policy rejected")
        cls._assert_signer_values(ledger_signer, ledger_key)
        _parse_time(created_at, "initialization time")
        root_descriptor: int | None = None
        database_descriptor: int | None = None
        store: LedgerStore | None = None
        try:
            prepared_root, root_descriptor = _prepare_root(root, create=True)
            _, database_descriptor = _prepare_database(
                prepared_root,
                root_descriptor,
                create=True,
            )
            store = LedgerStore(
                _descriptor_path(database_descriptor),
                tenant_id="tenant:public-6e3cdbebaafc8efa",
                ledger_id=policy.ledger_id,
            )
            ledger = cls(
                root=prepared_root,
                root_descriptor=root_descriptor,
                database_descriptor=database_descriptor,
                store=store,
                policy=policy,
                ledger_key=ledger_key,
            )
            initial = build_ledger_event(
                tenant_id="tenant:public-6e3cdbebaafc8efa",
                source_id=policy.ledger_id,
                source_sequence=0,
                event_type="key-event",
                payload_digest=toolz_authority_policy_digest(policy),
                previous_event_digest=None,
                signer=ledger_signer,
                recorded_at=created_at,
            )
            store.append(initial)
            checkpoint = ledger._new_checkpoint(
                ledger_signer=ledger_signer,
                created_at=created_at,
            )
            ledger._refresh(checkpoint)
            return ledger
        except Exception:
            if store is not None:
                store.close()
            if database_descriptor is not None:
                os.close(database_descriptor)
            if root_descriptor is not None:
                os.close(root_descriptor)
            raise

    @classmethod
    def open(
        cls,
        root: Path,
        *,
        policy: ToolzAuthorityPolicy,
        ledger_key: TrustedKey,
        expected_checkpoint: Mapping[str, Any],
    ) -> ToolzAuthorityLedger:
        """Open only the exact externally retained ledger head."""

        if not isinstance(policy, ToolzAuthorityPolicy):
            raise ToolzAuthorityError("Toolzs authority ledger policy rejected")
        if not isinstance(ledger_key, TrustedKey):
            raise ToolzAuthorityError("Toolzs authority ledger key rejected")
        root_descriptor: int | None = None
        database_descriptor: int | None = None
        store: LedgerStore | None = None
        try:
            prepared_root, root_descriptor = _prepare_root(root, create=False)
            _, database_descriptor = _prepare_database(
                prepared_root,
                root_descriptor,
                create=False,
            )
            store = LedgerStore(
                _descriptor_path(database_descriptor),
                tenant_id="tenant:public-6e3cdbebaafc8efa",
                ledger_id=policy.ledger_id,
            )
            ledger = cls(
                root=prepared_root,
                root_descriptor=root_descriptor,
                database_descriptor=database_descriptor,
                store=store,
                policy=policy,
                ledger_key=ledger_key,
            )
            ledger._refresh(expected_checkpoint)
            return ledger
        except Exception:
            if store is not None:
                store.close()
            if database_descriptor is not None:
                os.close(database_descriptor)
            if root_descriptor is not None:
                os.close(root_descriptor)
            raise

    @staticmethod
    def _assert_signer_values(
        signer: Ed25519Signer,
        trusted_key: TrustedKey,
    ) -> None:
        if (
            not isinstance(signer, Ed25519Signer)
            or not isinstance(trusted_key, TrustedKey)
            or signer.key_id != trusted_key.key_id
            or public_key_fingerprint(signer.public_key)
            != public_key_fingerprint(trusted_key.public_key)
        ):
            raise ToolzAuthorityError("Toolzs authority ledger signer rejected")

    def _assert_open(self) -> None:
        if self._closed:
            raise ToolzAuthorityError("Toolzs authority ledger is closed")

    def _assert_signer(self, signer: Ed25519Signer) -> None:
        self._assert_signer_values(signer, self.ledger_key)

    def close(self) -> None:
        if not self._closed:
            try:
                self._store.close()
            finally:
                os.close(self._database_descriptor)
                os.close(self._root_descriptor)
                self._closed = True

    def __enter__(self) -> Self:
        self._assert_open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def checkpoint(self) -> dict[str, Any]:
        self._assert_open()
        if self._checkpoint is None:
            raise ToolzAuthorityError("Toolzs authority ledger is not verified")
        return deepcopy(self._checkpoint)

    def _source_keys(self) -> dict[str, TrustedKey]:
        return {event["source_id"]: self.ledger_key for event in self._store.events()}

    def _verify_structure(self, events: list[dict[str, Any]]) -> None:
        if not events:
            raise ToolzAuthorityError("Toolzs authority ledger is empty")
        initial = verify_ledger_event(
            events[0],
            self.ledger_key,
            expected_tenant_id="tenant:public-6e3cdbebaafc8efa",
            expected_source_id=self.policy.ledger_id,
            expected_event_type="key-event",
            expected_payload_digest=toolz_authority_policy_digest(self.policy),
        )
        if initial["source_sequence"] != 0 or initial["previous_event_digest"] is not None:
            raise ToolzAuthorityError("Toolzs authority ledger initialization rejected")
        initial_time = _parse_time(initial["recorded_at"], "initial event time")
        by_request: dict[str, list[dict[str, Any]]] = {}
        previous_global_time = initial_time
        for event in events[1:]:
            verified = verify_ledger_event(
                event,
                self.ledger_key,
                expected_tenant_id="tenant:public-6e3cdbebaafc8efa",
            )
            if _REQUEST_ID.fullmatch(verified["source_id"]) is None:
                raise ToolzAuthorityError("Toolzs authority ledger request source rejected")
            recorded = _parse_time(verified["recorded_at"], "event time")
            if recorded < previous_global_time:
                raise ToolzAuthorityError("Toolzs authority ledger clock rollback")
            previous_global_time = recorded
            by_request.setdefault(verified["source_id"], []).append(verified)
        for request_id, chain in by_request.items():
            if not 1 <= len(chain) <= 2:
                raise ToolzAuthorityError("Toolzs authority ledger source sequence exhausted")
            decision = chain[0]
            if (
                decision["source_id"] != request_id
                or decision["source_sequence"] != 0
                or decision["previous_event_digest"] is not None
                or decision["event_type"] != "toolz-authorization-decision"
            ):
                raise ToolzAuthorityError("Toolzs authority ledger decision sequence rejected")
            if len(chain) == 2:
                consumption = chain[1]
                if (
                    consumption["source_sequence"] != 1
                    or consumption["event_type"] != "toolz-authorization-consumption"
                    or consumption["previous_event_digest"] != event_digest(decision)
                ):
                    raise ToolzAuthorityError(
                        "Toolzs authority ledger consumption sequence rejected"
                    )

    def _refresh(self, expected_checkpoint: Mapping[str, Any]) -> None:
        self._assert_open()
        try:
            checkpoint = deepcopy(dict(expected_checkpoint))
            events = self._store.events()
            result = self._store.verify(
                source_public_keys=self._source_keys(),
                checkpoint=checkpoint,
                checkpoint_key=self.ledger_key,
            )
            if (
                result["tenant_id"] != "tenant:public-6e3cdbebaafc8efa"
                or result["ledger_id"] != self.policy.ledger_id
                or checkpoint["checkpoint_id"] != _checkpoint_id(checkpoint)
            ):
                raise ToolzAuthorityError("Toolzs authority ledger checkpoint binding rejected")
            self._verify_structure(events)
            if _parse_time(
                checkpoint["created_at"],
                "checkpoint time",
            ) < _parse_time(events[-1]["recorded_at"], "last event time"):
                raise ToolzAuthorityError("Toolzs authority ledger checkpoint timing rejected")
        except (LedgerError, KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, ToolzAuthorityError):
                raise
            raise ToolzAuthorityError("Toolzs authority ledger checkpoint rejected") from exc
        self._checkpoint = checkpoint

    def verify(
        self,
        *,
        expected_checkpoint: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Verify the complete ledger against one external rollback pin."""

        self._refresh(expected_checkpoint)
        events = self._store.events()
        return {
            "ok": True,
            "tenant_id": "tenant:public-6e3cdbebaafc8efa",
            "ledger_id": self.policy.ledger_id,
            "tree_size": len(events),
            "request_count": len(
                {
                    event["source_id"]
                    for event in events
                    if event["source_id"] != self.policy.ledger_id
                }
            ),
            "rollback_checkpoint_verified": True,
            "authority_boundary": deepcopy(_LEDGER_BOUNDARY),
        }

    def _new_checkpoint(
        self,
        *,
        ledger_signer: Ed25519Signer,
        created_at: str,
    ) -> dict[str, Any]:
        self._assert_signer(ledger_signer)
        _parse_time(created_at, "checkpoint creation time")
        digests = self._store.event_digests()
        if not digests:
            raise ToolzAuthorityError("Toolzs authority ledger is empty")
        provisional = self._store.checkpoint(
            checkpoint_id="toolz-authority-checkpoint:pending",
            signer=ledger_signer,
            created_at=created_at,
        )
        return self._store.checkpoint(
            checkpoint_id=_checkpoint_id(provisional),
            signer=ledger_signer,
            created_at=created_at,
        )

    def _request_events(self, request_id: str) -> list[dict[str, Any]]:
        return [event for event in self._store.events() if event["source_id"] == request_id]

    def _append_at_checkpoint(
        self,
        *,
        event: dict[str, Any],
        expected_checkpoint: Mapping[str, Any],
        ledger_signer: Ed25519Signer,
        checkpoint_created_at: str,
    ) -> dict[str, Any]:
        self._assert_signer(ledger_signer)
        self._refresh(expected_checkpoint)
        try:
            self._store.append_at_checkpoint(
                event,
                source_public_keys=self._source_keys(),
                checkpoint=deepcopy(dict(expected_checkpoint)),
                checkpoint_key=self.ledger_key,
                precommit_validator=self._verify_structure,
            )
            checkpoint = self._new_checkpoint(
                ledger_signer=ledger_signer,
                created_at=checkpoint_created_at,
            )
            self._refresh(checkpoint)
            return checkpoint
        except LedgerError as exc:
            raise ToolzAuthorityError("Toolzs authority ledger append rejected") from exc

    def decide(
        self,
        *,
        evidence: ToolzAuthorizationEvidence,
        outcome: ToolzAuthorityDecisionOutcome | str,
        reason: ToolzAuthorityDecisionReason | str,
        decided_at: str,
        created_at: str,
        decision_key: TrustedKey,
        decision_signer: Ed25519Signer,
        ledger_signer: Ed25519Signer,
        expected_checkpoint: Mapping[str, Any],
    ) -> ToolzAuthorityDecisionRecord:
        """Record exactly one decision at request source sequence zero."""

        self._refresh(expected_checkpoint)
        decision_result: ToolzAuthorityDecision = build_toolz_authority_decision(
            policy=self.policy,
            evidence=evidence,
            outcome=outcome,
            reason=reason,
            decided_at=decided_at,
            created_at=created_at,
            decision_key=decision_key,
            decision_signer=decision_signer,
        )
        request_id = decision_result.decision["request"]["request_id"]
        if self._request_events(request_id):
            raise ToolzAuthorityError("Toolzs authority request already has a decision")
        event = build_ledger_event(
            tenant_id="tenant:public-6e3cdbebaafc8efa",
            source_id=request_id,
            source_sequence=0,
            event_type="toolz-authorization-decision",
            payload_digest=toolz_authority_decision_digest(decision_result.decision),
            previous_event_digest=None,
            signer=ledger_signer,
            recorded_at=created_at,
        )
        checkpoint = self._append_at_checkpoint(
            event=event,
            expected_checkpoint=expected_checkpoint,
            ledger_signer=ledger_signer,
            checkpoint_created_at=created_at,
        )
        return ToolzAuthorityDecisionRecord(
            decision=decision_result.decision,
            ledger_event=event,
            checkpoint=checkpoint,
        )

    def consume(
        self,
        *,
        evidence: ToolzAuthorizationEvidence,
        decision: Mapping[str, Any],
        decision_key: TrustedKey,
        consumed_at: str,
        ledger_signer: Ed25519Signer,
        expected_checkpoint: Mapping[str, Any],
    ) -> ToolzGrantConsumptionRecord:
        """Record the sole grant consumption without executing the transition."""

        self._refresh(expected_checkpoint)
        verified_decision = verify_toolz_authority_decision(
            decision,
            policy=self.policy,
            evidence=evidence,
            decision_key=decision_key,
            used_at=consumed_at,
        )
        request_id = verified_decision["request"]["request_id"]
        events = self._request_events(request_id)
        if (
            len(events) != 1
            or events[0]["event_type"] != "toolz-authorization-decision"
            or events[0]["payload_digest"] != toolz_authority_decision_digest(verified_decision)
        ):
            raise ToolzAuthorityError("Toolzs authority decision ledger proof rejected")
        consumption_result: ToolzGrantConsumption = build_toolz_grant_consumption(
            policy=self.policy,
            evidence=evidence,
            decision=verified_decision,
            decision_key=decision_key,
            consumed_at=consumed_at,
            ledger_key=self.ledger_key,
            ledger_signer=ledger_signer,
        )
        event = build_ledger_event(
            tenant_id="tenant:public-6e3cdbebaafc8efa",
            source_id=request_id,
            source_sequence=1,
            event_type="toolz-authorization-consumption",
            payload_digest=toolz_grant_consumption_digest(consumption_result.consumption),
            previous_event_digest=event_digest(events[0]),
            signer=ledger_signer,
            recorded_at=consumed_at,
        )
        checkpoint = self._append_at_checkpoint(
            event=event,
            expected_checkpoint=expected_checkpoint,
            ledger_signer=ledger_signer,
            checkpoint_created_at=consumed_at,
        )
        return ToolzGrantConsumptionRecord(
            consumption=consumption_result.consumption,
            ledger_event=event,
            checkpoint=checkpoint,
        )

    def verify_decision_record(
        self,
        *,
        evidence: ToolzAuthorizationEvidence,
        decision: Mapping[str, Any],
        decision_key: TrustedKey,
        expected_checkpoint: Mapping[str, Any],
        used_at: str,
    ) -> dict[str, Any]:
        """Verify one exact decision and its sequence-zero ledger proof."""

        self._refresh(expected_checkpoint)
        verified = verify_toolz_authority_decision(
            decision,
            policy=self.policy,
            evidence=evidence,
            decision_key=decision_key,
            used_at=used_at,
        )
        events = self._request_events(verified["request"]["request_id"])
        if (
            not events
            or events[0]["source_sequence"] != 0
            or events[0]["payload_digest"] != toolz_authority_decision_digest(verified)
        ):
            raise ToolzAuthorityError("Toolzs authority decision ledger proof rejected")
        return verified

    def verify_consumption_record(
        self,
        *,
        evidence: ToolzAuthorizationEvidence,
        decision: Mapping[str, Any],
        consumption: Mapping[str, Any],
        decision_key: TrustedKey,
        expected_checkpoint: Mapping[str, Any],
        used_at: str,
    ) -> dict[str, Any]:
        """Verify the exact decision/consumption chain at sequences zero/one."""

        self._refresh(expected_checkpoint)
        verified_decision = verify_toolz_authority_decision(
            decision,
            policy=self.policy,
            evidence=evidence,
            decision_key=decision_key,
            used_at=used_at,
        )
        verified_consumption = verify_toolz_grant_consumption(
            consumption,
            policy=self.policy,
            evidence=evidence,
            decision=verified_decision,
            decision_key=decision_key,
            ledger_key=self.ledger_key,
            used_at=used_at,
        )
        events = self._request_events(verified_decision["request"]["request_id"])
        if (
            len(events) != 2
            or events[0]["payload_digest"] != toolz_authority_decision_digest(verified_decision)
            or events[1]["payload_digest"] != toolz_grant_consumption_digest(verified_consumption)
            or events[1]["previous_event_digest"] != event_digest(events[0])
        ):
            raise ToolzAuthorityError("Toolzs authority consumption ledger proof rejected")
        return verified_consumption
