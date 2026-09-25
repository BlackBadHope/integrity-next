"""Durable zero-model-call L0 runtime for Guardian Atlas."""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Self

from .agent_continuity import (
    AgentContinuityError,
    _build_cognitive_continuation,
    verify_current_module_agent_lease,
)
from .canonical import canonical_bytes, parse_json_strict
from .cognitive_runtime import (
    CognitiveRuntimeError,
    verify_cognitive_run_request,
    verify_cognitive_run_result,
)
from .cognitive_runtime import (
    build_cognitive_run_request as _build_cognitive_run_request,
)
from .hashing import digest_object
from .local_lock import LocalLockError, lock_exclusive, unlock
from .model_router import (
    TIER_RANK,
    AlarmKind,
    AlarmSignal,
    CognitiveTier,
    ModelDescriptor,
    ModelRoutePolicy,
    Severity,
    _verify_model_route_receipt,
    route_model,
)
from .policy import CustomerPolicyError, verify_customer_policy_binding
from .signing import TrustedKey, public_key_fingerprint
from .tenant import (
    TenantWorkspace,
    tenant_enrollment_status,
    verify_tenant_governance,
)

MAX_RUNTIME_EVENTS = 4096
SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class AtlasRuntimeError(RuntimeError):
    """Raised when durable L0 state cannot be trusted or advanced safely."""


@dataclass(frozen=True)
class AtlasRuntimePolicy:
    policy_id: str
    coalesce_window_seconds: int = 60
    cooldown_seconds: int = 300
    max_events: int = MAX_RUNTIME_EVENTS
    max_cognitive_elapsed_ms: int = 900_000
    max_cognitive_attempts: int = 1

    def __post_init__(self) -> None:
        if not self.policy_id.startswith("policy:"):
            raise AtlasRuntimeError("runtime policy identity is not canonical")
        if self.coalesce_window_seconds < 0 or self.cooldown_seconds < 0:
            raise AtlasRuntimeError("runtime windows cannot be negative")
        if not 1 <= self.max_events <= MAX_RUNTIME_EVENTS:
            raise AtlasRuntimeError("runtime event limit is outside the safe range")
        if not 1 <= self.max_cognitive_elapsed_ms <= 3_600_000:
            raise AtlasRuntimeError(
                "runtime cognitive elapsed-time limit is outside the safe range"
            )
        if not 1 <= self.max_cognitive_attempts <= 3:
            raise AtlasRuntimeError(
                "runtime cognitive attempt limit is outside the safe range"
            )

    def record(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "coalesce_window_seconds": self.coalesce_window_seconds,
            "cooldown_seconds": self.cooldown_seconds,
            "max_events": self.max_events,
            "max_cognitive_elapsed_ms": self.max_cognitive_elapsed_ms,
            "max_cognitive_attempts": self.max_cognitive_attempts,
        }


def atlas_customer_policy_digest(
    *,
    tenant_id: str,
    module_id: str,
    route_policy: ModelRoutePolicy,
    model_registry: list[ModelDescriptor],
    runtime_policy: AtlasRuntimePolicy,
    agent_key_fingerprint: str | None = None,
) -> str:
    """Digest the complete customer-authorized Atlas routing configuration."""

    registry = sorted(
        (model.record() for model in model_registry),
        key=lambda item: item["model_id"],
    )
    model_ids = [record["model_id"] for record in registry]
    if len(set(model_ids)) != len(model_ids):
        raise AtlasRuntimeError("model registry identities must be unique")
    return digest_object(
        {
            "protocol": "integrity-guardian/atlas-customer-policy/v1",
            "tenant_id": tenant_id,
            "module_id": module_id,
            "route_policy": route_policy.record(),
            "model_registry": registry,
            "runtime_policy": runtime_policy.record(),
            "agent_key_fingerprint": agent_key_fingerprint,
        },
        domain="atlas-customer-policy-v1",
    )


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise AtlasRuntimeError("runtime timestamp requires a timezone")
    return parsed


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _clock_time(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AtlasRuntimeError("runtime clock must return a timezone-aware datetime")
    return value


def _runtime_clock_time() -> datetime:
    """Return the runtime-owned authorization clock."""

    return datetime.now(UTC)


def _signal_record(signal: AlarmSignal) -> dict[str, Any]:
    return {
        "tenant_id": signal.tenant_id,
        "incident_id": signal.incident_id,
        "alarm_id": signal.alarm_id,
        "kind": signal.kind.value,
        "severity": signal.severity.value,
        "protected_scope": signal.protected_scope,
        "evidence_complete": signal.evidence_complete,
        "blast_radius": signal.blast_radius,
        "age_seconds": signal.age_seconds,
        "recurrence_count": signal.recurrence_count,
        "optional_budget_exhausted": signal.optional_budget_exhausted,
    }


def _signal_from_record(record: dict[str, Any]) -> AlarmSignal:
    required = {
        "tenant_id",
        "incident_id",
        "alarm_id",
        "kind",
        "severity",
        "protected_scope",
        "evidence_complete",
        "blast_radius",
        "age_seconds",
        "recurrence_count",
        "optional_budget_exhausted",
    }
    if set(record) != required:
        raise AtlasRuntimeError("runtime alarm signal keys mismatch")
    try:
        return AlarmSignal(
            tenant_id=record["tenant_id"],
            incident_id=record["incident_id"],
            alarm_id=record["alarm_id"],
            kind=AlarmKind(record["kind"]),
            severity=Severity(record["severity"]),
            protected_scope=record["protected_scope"],
            evidence_complete=record["evidence_complete"],
            blast_radius=record["blast_radius"],
            age_seconds=record["age_seconds"],
            recurrence_count=record["recurrence_count"],
            optional_budget_exhausted=record["optional_budget_exhausted"],
        )
    except (TypeError, ValueError) as exc:
        raise AtlasRuntimeError("runtime alarm signal is invalid") from exc


def _alarm_group_key(signal: AlarmSignal, subject_ref: str) -> str:
    return digest_object(
        {
            "tenant_id": signal.tenant_id,
            "incident_id": signal.incident_id,
            "subject_ref": subject_ref,
        },
        domain="atlas-runtime-alarm-group-v1",
    )


def _event_fingerprint(
    signal: AlarmSignal,
    evidence_digest: str,
    subject_ref: str,
) -> str:
    return digest_object(
        {
            "signal": _signal_record(signal),
            "evidence_digest": evidence_digest,
            "subject_ref": subject_ref,
        },
        domain="atlas-runtime-event-fingerprint-v1",
    )


def _build_record(
    *,
    sequence: int,
    previous_record_id: str | None,
    kind: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "protocol": "integrity-guardian/atlas-runtime-record/v1",
        "record_id": "runtime-record:pending",
        "sequence": sequence,
        "previous_record_id": previous_record_id,
        "kind": kind,
        "payload": payload,
    }
    identity = digest_object(record, domain="atlas-runtime-record-identity-v1").split(
        ":", 1
    )[1]
    record["record_id"] = f"runtime-record:{identity}"
    return record


def _verify_record(
    record: dict[str, Any],
    *,
    expected_sequence: int,
    expected_previous: str | None,
) -> None:
    required = {
        "protocol",
        "record_id",
        "sequence",
        "previous_record_id",
        "kind",
        "payload",
    }
    if set(record) != required:
        raise AtlasRuntimeError("runtime record keys mismatch")
    if record["protocol"] != "integrity-guardian/atlas-runtime-record/v1":
        raise AtlasRuntimeError("runtime record protocol mismatch")
    if record["sequence"] != expected_sequence:
        raise AtlasRuntimeError("runtime record sequence discontinuity")
    if record["previous_record_id"] != expected_previous:
        raise AtlasRuntimeError("runtime record chain discontinuity")
    if record["kind"] not in {
        "init",
        "alarm",
        "route-ack",
        "cognitive-run-request",
        "cognitive-run-result",
    }:
        raise AtlasRuntimeError("runtime record kind is not recognized")
    if not isinstance(record["payload"], dict):
        raise AtlasRuntimeError("runtime record payload is not an object")
    unsigned = dict(record)
    actual = unsigned["record_id"]
    unsigned["record_id"] = "runtime-record:pending"
    expected = "runtime-record:" + digest_object(
        unsigned, domain="atlas-runtime-record-identity-v1"
    ).split(":", 1)[1]
    if actual != expected:
        raise AtlasRuntimeError("runtime record identity mismatch")


class AtlasL0Runtime:
    """One locked, customer-local Atlas L0 journal."""

    def __init__(
        self,
        *,
        workspace: TenantWorkspace,
        lease: dict[str, Any],
        lease_head: dict[str, Any],
        trusted_lease_head_id: str,
        authority_key: TrustedKey,
        route_policy: ModelRoutePolicy,
        model_registry: list[ModelDescriptor],
        runtime_policy: AtlasRuntimePolicy,
        agent_key: TrustedKey | None = None,
    ) -> None:
        runtime_clock = _runtime_clock_time
        opened_at = _clock_time(runtime_clock)
        opened_timestamp = _timestamp(opened_at)
        profile = workspace.verify()
        try:
            governance = verify_tenant_governance(
                profile,
                policy_authority_key=authority_key,
                at_time=opened_timestamp,
            )
        except CustomerPolicyError as exc:
            raise AtlasRuntimeError("Atlas L0 customer policy rejected") from exc
        if (
            tenant_enrollment_status(profile) != "ENROLLED"
            or governance["customer_policy"] != "VERIFIED"
        ):
            raise AtlasRuntimeError(
                "Atlas L0 requires enrolled registries and verified customer policy"
            )
        try:
            lease_verification = verify_current_module_agent_lease(
                lease,
                lease_head=lease_head,
                trusted_head_id=trusted_lease_head_id,
                authority_key=authority_key,
                at_time=opened_timestamp,
            )
        except AgentContinuityError as exc:
            raise AtlasRuntimeError("Atlas L0 module lease head rejected") from exc
        if not lease_verification["active"]:
            raise AtlasRuntimeError("Atlas L0 requires an active module lease")
        if lease["tenant_id"] != workspace.tenant_id:
            raise AtlasRuntimeError("runtime workspace and lease tenant mismatch")
        if agent_key is not None and agent_key.key_id != lease["agent_key_id"]:
            raise AtlasRuntimeError("runtime agent public key differs from module lease")
        customer_policy_binding = profile["governance"]["customer_policy"]["binding"]
        expected_policy_digest = atlas_customer_policy_digest(
            tenant_id=lease["tenant_id"],
            module_id=lease["module_id"],
            route_policy=route_policy,
            model_registry=model_registry,
            runtime_policy=runtime_policy,
            agent_key_fingerprint=(
                None
                if agent_key is None
                else public_key_fingerprint(agent_key.public_key)
            ),
        )
        if customer_policy_binding["policy_digest"] != expected_policy_digest:
            raise AtlasRuntimeError(
                "signed customer policy does not match Atlas configuration"
            )

        self.workspace = workspace
        self.lease = lease
        self.lease_head = lease_head
        self.trusted_lease_head_id = trusted_lease_head_id
        self._authority_key = authority_key
        self._clock = runtime_clock
        self._opened_at = opened_at
        self._last_clock_time = opened_at
        self._customer_policy_binding = customer_policy_binding
        self._customer_policy_digest = expected_policy_digest
        self._route_policy = route_policy
        self._model_registry = tuple(model_registry)
        self._runtime_policy = runtime_policy
        self._agent_key = agent_key
        self._lock_descriptor: int | None = None
        self._journal_descriptor: int | None = None
        self._records: list[dict[str, Any]] = []
        self._events: dict[tuple[str, int, str], dict[str, Any]] = {}
        self._groups: dict[str, dict[str, Any]] = {}
        self._pending_routes: dict[str, dict[str, Any]] = {}
        self._pending_runs: dict[str, dict[str, Any]] = {}
        self._run_results: dict[str, dict[str, Any]] = {}
        self._cursor = lease["event_cursor"]
        self._recovered_partial_tail = False
        self._model_calls = 0

        try:
            self._lock_descriptor = workspace.open_artifact(
                "ledger",
                "atlas-runtime.lock",
                flags=os.O_RDWR | os.O_CREAT,
                mode=0o600,
            )
            if hasattr(os, "fchmod"):
                os.fchmod(self._lock_descriptor, 0o600)
            try:
                lock_exclusive(
                    self._lock_descriptor,
                    nonblocking=True,
                )
            except LocalLockError as exc:
                raise AtlasRuntimeError(
                    "another Atlas L0 runtime holds the module lock"
                ) from exc
            self._journal_descriptor = workspace.open_artifact(
                "ledger",
                "atlas-runtime.journal",
                flags=os.O_RDWR | os.O_CREAT,
                mode=0o600,
            )
            if hasattr(os, "fchmod"):
                os.fchmod(self._journal_descriptor, 0o600)
            self._load_or_initialize()
        except Exception:
            self.close()
            raise

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._journal_descriptor is not None:
            os.close(self._journal_descriptor)
            self._journal_descriptor = None
        if self._lock_descriptor is not None:
            try:
                unlock(self._lock_descriptor)
            finally:
                os.close(self._lock_descriptor)
                self._lock_descriptor = None

    def _configuration(self) -> dict[str, Any]:
        registry = sorted(
            (model.record() for model in self._model_registry),
            key=lambda item: item["model_id"],
        )
        return {
            "tenant_id": self.lease["tenant_id"],
            "module_id": self.lease["module_id"],
            "agent_id": self.lease["agent_id"],
            "generation": self.lease["generation"],
            "lease_id": self.lease["lease_id"],
            "lease_head_id": self.trusted_lease_head_id,
            "lease_head_revision": self.lease_head["head_revision"],
            "initial_event_cursor": self.lease["event_cursor"],
            "state_digest": self.lease["state_digest"],
            "agent_key_fingerprint": (
                None
                if self._agent_key is None
                else public_key_fingerprint(self._agent_key.public_key)
            ),
            "customer_policy_binding_id": self._customer_policy_binding["binding_id"],
            "customer_policy_digest": self._customer_policy_digest,
            "runtime_policy_digest": digest_object(
                self._runtime_policy.record(),
                domain="atlas-runtime-policy-v1",
            ),
            "route_policy_digest": digest_object(
                self._route_policy.record(),
                domain="model-route-policy-v1",
            ),
            "registry_digest": digest_object(
                registry,
                domain="model-capability-registry-v1",
            ),
            "production_authority": False,
        }

    def _read_journal(self) -> bytes:
        if self._journal_descriptor is None:
            raise AtlasRuntimeError("runtime journal is closed")
        os.lseek(self._journal_descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while chunk := os.read(self._journal_descriptor, 64 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)

    def _load_or_initialize(self) -> None:
        data = self._read_journal()
        if data and not data.endswith(b"\n"):
            boundary = data.rfind(b"\n") + 1
            if self._journal_descriptor is None:
                raise AtlasRuntimeError("runtime journal is closed")
            os.ftruncate(self._journal_descriptor, boundary)
            os.fsync(self._journal_descriptor)
            data = data[:boundary]
            self._recovered_partial_tail = True
        if not data:
            self._append("init", self._configuration())
            return

        expected_previous: str | None = None
        for expected_sequence, line in enumerate(data.splitlines()):
            try:
                record = parse_json_strict(line)
            except Exception as exc:
                raise AtlasRuntimeError("runtime journal contains invalid JSON") from exc
            if not isinstance(record, dict):
                raise AtlasRuntimeError("runtime journal record is not an object")
            _verify_record(
                record,
                expected_sequence=expected_sequence,
                expected_previous=expected_previous,
            )
            self._apply_record(record)
            self._records.append(record)
            expected_previous = record["record_id"]
        if not self._records or self._records[0]["kind"] != "init":
            raise AtlasRuntimeError("runtime journal has no init record")
        if self._records[0]["payload"] != self._configuration():
            raise AtlasRuntimeError("runtime journal configuration mismatch")

    def _append(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        if self._journal_descriptor is None:
            raise AtlasRuntimeError("runtime journal is closed")
        durable_payload = deepcopy(payload)
        record = _build_record(
            sequence=len(self._records),
            previous_record_id=(
                None if not self._records else self._records[-1]["record_id"]
            ),
            kind=kind,
            payload=durable_payload,
        )
        rendered = canonical_bytes(record) + b"\n"
        os.lseek(self._journal_descriptor, 0, os.SEEK_END)
        view = memoryview(rendered)
        while view:
            written = os.write(self._journal_descriptor, view)
            if written <= 0:
                raise AtlasRuntimeError(
                    "runtime journal write made no progress"
                )
            view = view[written:]
        os.fsync(self._journal_descriptor)
        self._apply_record(record)
        self._records.append(record)
        return record

    def _apply_record(self, record: dict[str, Any]) -> None:
        payload = record["payload"]
        if record["kind"] == "init":
            required = set(self._configuration())
            if set(payload) != required:
                raise AtlasRuntimeError("runtime init payload keys mismatch")
            self._cursor = payload["initial_event_cursor"]
            return
        if record["kind"] == "alarm":
            required = {
                "event_fingerprint",
                "event_cursor",
                "group_id",
                "group_key",
                "observed_at",
                "authorization_at",
                "subject_ref",
                "evidence_digest",
                "signal",
                "action",
                "required_tier",
                "cooldown_until",
                "route_receipt",
                "superseded_route_id",
            }
            if set(payload) != required:
                raise AtlasRuntimeError("runtime alarm payload keys mismatch")
            if payload["event_cursor"] != self._cursor + 1:
                raise AtlasRuntimeError("runtime alarm cursor discontinuity")
            signal = _signal_from_record(payload["signal"])
            if signal.tenant_id != self.lease["tenant_id"]:
                raise AtlasRuntimeError("runtime journal alarm tenant mismatch")
            if (
                SHA256_DIGEST.fullmatch(payload["evidence_digest"]) is None
                or not payload["subject_ref"]
            ):
                raise AtlasRuntimeError("runtime journal alarm evidence is invalid")
            observed_at = _time(payload["observed_at"])
            authorization_at = _time(payload["authorization_at"])
            if observed_at > authorization_at:
                raise AtlasRuntimeError(
                    "runtime alarm time is after authorization time"
                )
            try:
                policy_verification = verify_customer_policy_binding(
                    self._customer_policy_binding,
                    tenant_id=self.lease["tenant_id"],
                    authority_key=self._authority_key,
                    at_time=payload["authorization_at"],
                )
                lease_verification = verify_current_module_agent_lease(
                    self.lease,
                    lease_head=self.lease_head,
                    trusted_head_id=self.trusted_lease_head_id,
                    authority_key=self._authority_key,
                    at_time=payload["authorization_at"],
                )
            except (CustomerPolicyError, ValueError) as exc:
                raise AtlasRuntimeError(
                    "runtime journal authorization is invalid"
                ) from exc
            if (
                policy_verification["policy_digest"]
                != self._customer_policy_digest
                or not lease_verification["active"]
            ):
                raise AtlasRuntimeError(
                    "runtime journal authorization is invalid"
                )
            _time(payload["cooldown_until"])
            if payload["group_key"] != _alarm_group_key(
                signal,
                payload["subject_ref"],
            ):
                raise AtlasRuntimeError("runtime alarm group identity mismatch")
            fingerprint = payload["event_fingerprint"]
            if fingerprint != _event_fingerprint(
                signal,
                payload["evidence_digest"],
                payload["subject_ref"],
            ):
                raise AtlasRuntimeError("runtime event fingerprint mismatch")
            event_identity = (
                fingerprint,
                payload["event_cursor"],
                payload["observed_at"],
            )
            if event_identity in self._events:
                raise AtlasRuntimeError("duplicate runtime event in journal")
            if payload["action"] not in {"routed", "coalesced"}:
                raise AtlasRuntimeError("runtime alarm action is invalid")
            route = payload["route_receipt"]
            if payload["action"] == "routed" and not isinstance(route, dict):
                raise AtlasRuntimeError("routed alarm has no route receipt")
            if payload["action"] == "coalesced" and route is not None:
                raise AtlasRuntimeError("coalesced alarm unexpectedly has a route")
            if isinstance(route, dict):
                try:
                    verification = _verify_model_route_receipt(
                        route,
                        signal=signal,
                        policy=self._route_policy,
                        registry=list(self._model_registry),
                    )
                except (TypeError, ValueError) as exc:
                    raise AtlasRuntimeError(
                        "runtime model route receipt is invalid"
                    ) from exc
                if not verification["authorized"]:
                    raise AtlasRuntimeError(
                        "runtime model route receipt has no trusted provenance"
                    )
                if (
                    route["tenant_id"] != signal.tenant_id
                    or route["incident_id"] != signal.incident_id
                    or route["alarm_id"] != signal.alarm_id
                    or route["required_tier"] != payload["required_tier"]
                ):
                    raise AtlasRuntimeError(
                        "runtime model route does not bind the alarm"
                    )
            elif payload["required_tier"] not in {
                tier.value for tier in CognitiveTier
            }:
                raise AtlasRuntimeError("runtime required tier is invalid")
            current = self._groups.get(payload["group_key"])
            if current is not None and _time(payload["observed_at"]) < _time(
                current["last_seen"]
            ):
                raise AtlasRuntimeError("runtime alarm time moved backwards")
            superseded = payload["superseded_route_id"]
            if superseded is not None:
                if superseded not in self._pending_routes:
                    raise AtlasRuntimeError(
                        "runtime alarm supersedes no pending route"
                    )
                if superseded in self._pending_runs:
                    raise AtlasRuntimeError(
                        "runtime alarm cannot supersede route while cognitive run "
                        "is pending"
                    )
                self._pending_routes.pop(superseded, None)
            if isinstance(route, dict):
                self._pending_routes[route["route_id"]] = route
            self._events[event_identity] = payload
            self._groups[payload["group_key"]] = {
                "group_id": payload["group_id"],
                "last_seen": payload["observed_at"],
                "cooldown_until": payload["cooldown_until"],
                "required_tier": payload["required_tier"],
                "route_id": (
                    route["route_id"]
                    if isinstance(route, dict)
                    else (
                        None
                        if superseded is not None
                        else self._groups.get(payload["group_key"], {}).get("route_id")
                    )
                ),
            }
            self._cursor = payload["event_cursor"]
            self._last_clock_time = max(
                self._last_clock_time,
                authorization_at,
            )
            return
        if record["kind"] == "route-ack":
            if set(payload) != {"route_id"}:
                raise AtlasRuntimeError("runtime route ACK payload keys mismatch")
            if payload["route_id"] not in self._pending_routes:
                raise AtlasRuntimeError("runtime route ACK references no pending route")
            if payload["route_id"] in self._pending_runs:
                raise AtlasRuntimeError(
                    "runtime route ACK rejected while cognitive run is pending"
                )
            self._pending_routes.pop(payload["route_id"])
            return
        if record["kind"] == "cognitive-run-request":
            if set(payload) != {"package", "request"}:
                raise AtlasRuntimeError(
                    "runtime cognitive request payload keys mismatch"
                )
            package = payload["package"]
            request = payload["request"]
            try:
                verification = verify_cognitive_run_request(package, request)
            except (CognitiveRuntimeError, TypeError, ValueError) as exc:
                raise AtlasRuntimeError(
                    "runtime cognitive request is invalid"
                ) from exc
            route_id = verification["route_id"]
            route = self._pending_routes.get(route_id)
            if route is None:
                raise AtlasRuntimeError(
                    "runtime cognitive request references no pending route"
                )
            expected = {
                "tenant_id": self.lease["tenant_id"],
                "module_id": self.lease["module_id"],
                "agent_id": self.lease["agent_id"],
                "agent_key_id": self.lease["agent_key_id"],
                "generation": self.lease["generation"],
                "lease_id": self.lease["lease_id"],
                "lease_head_id": self.trusted_lease_head_id,
                "lease_head_revision": self.lease_head["head_revision"],
                "event_cursor": self.lease["event_cursor"],
                "state_digest": self.lease["state_digest"],
                "route_id": route_id,
                "target_model_id": route["selected_model"]["model_id"],
                "target_reasoning": route["minimum_reasoning"],
                "budgets": route["budgets"],
            }
            for field, value in expected.items():
                if package[field] != value:
                    raise AtlasRuntimeError(
                        f"runtime cognitive package {field} mismatch"
                    )
            if route_id in self._pending_runs or route_id in self._run_results:
                raise AtlasRuntimeError(
                    "runtime cognitive route already has an execution"
                )
            if any(
                state["request"]["request_id"] == request["request_id"]
                for state in self._pending_runs.values()
            ):
                raise AtlasRuntimeError("runtime cognitive request identity duplicated")
            self._pending_runs[route_id] = payload
            self._last_clock_time = max(
                self._last_clock_time,
                _time(request["requested_at"]),
            )
            return
        if record["kind"] == "cognitive-run-result":
            if set(payload) != {"request_id", "route_id", "result"}:
                raise AtlasRuntimeError("runtime cognitive result payload keys mismatch")
            route_id = payload["route_id"]
            run = self._pending_runs.get(route_id)
            if run is None:
                raise AtlasRuntimeError(
                    "runtime cognitive result references no pending request"
                )
            if run["request"]["request_id"] != payload["request_id"]:
                raise AtlasRuntimeError(
                    "runtime cognitive result request identity mismatch"
                )
            if self._agent_key is None:
                raise AtlasRuntimeError(
                    "runtime cognitive result has no pinned agent public key"
                )
            try:
                verification = verify_cognitive_run_result(
                    run["request"],
                    payload["result"],
                    agent_key=self._agent_key,
                )
            except (CognitiveRuntimeError, TypeError, ValueError) as exc:
                raise AtlasRuntimeError(
                    "runtime cognitive result is invalid"
                ) from exc
            if verification["route_id"] != route_id:
                raise AtlasRuntimeError(
                    "runtime cognitive result route identity mismatch"
                )
            if route_id in self._run_results:
                raise AtlasRuntimeError("runtime cognitive result identity duplicated")
            if (
                verification["status"] == "completed"
                and route_id not in self._pending_routes
            ):
                raise AtlasRuntimeError(
                    "completed cognitive result references no pending route"
                )
            self._pending_runs.pop(route_id)
            self._run_results[route_id] = payload
            self._model_calls += verification["usage"]["model_calls"]
            if verification["status"] == "completed":
                self._pending_routes.pop(route_id)
            return

    def _authorize_now(self) -> tuple[datetime, str]:
        authorization_time = _clock_time(self._clock)
        if authorization_time < self._last_clock_time:
            raise AtlasRuntimeError("runtime clock moved backwards")
        self._last_clock_time = authorization_time
        authorization_at = _timestamp(authorization_time)
        try:
            policy_verification = verify_customer_policy_binding(
                self._customer_policy_binding,
                tenant_id=self.lease["tenant_id"],
                authority_key=self._authority_key,
                at_time=authorization_at,
            )
            lease_verification = verify_current_module_agent_lease(
                self.lease,
                lease_head=self.lease_head,
                trusted_head_id=self.trusted_lease_head_id,
                authority_key=self._authority_key,
                at_time=authorization_at,
            )
        except (CustomerPolicyError, ValueError) as exc:
            raise AtlasRuntimeError(
                "runtime authorization is not active"
            ) from exc
        if (
            not policy_verification["active"]
            or policy_verification["policy_digest"] != self._customer_policy_digest
            or not lease_verification["active"]
        ):
            raise AtlasRuntimeError("runtime authorization is not active")
        live_policy_digest = atlas_customer_policy_digest(
            tenant_id=self.lease["tenant_id"],
            module_id=self.lease["module_id"],
            route_policy=self._route_policy,
            model_registry=list(self._model_registry),
            runtime_policy=self._runtime_policy,
            agent_key_fingerprint=(
                None
                if self._agent_key is None
                else public_key_fingerprint(self._agent_key.public_key)
            ),
        )
        if live_policy_digest != self._customer_policy_digest:
            raise AtlasRuntimeError(
                "live Atlas configuration differs from signed customer policy"
            )
        return authorization_time, authorization_at

    def ingest_alarm(
        self,
        *,
        signal: AlarmSignal,
        evidence_digest: str,
        subject_ref: str,
        observed_at: str,
        event_cursor: int,
    ) -> dict[str, Any]:
        """Persist one event and produce at most one route receipt."""

        observed = _time(observed_at)
        authorization_time, authorization_at = self._authorize_now()
        if observed > authorization_time:
            raise AtlasRuntimeError("runtime alarm time is after authorization time")
        if signal.tenant_id != self.lease["tenant_id"]:
            raise AtlasRuntimeError("runtime alarm tenant mismatch")
        if SHA256_DIGEST.fullmatch(evidence_digest) is None:
            raise AtlasRuntimeError("runtime evidence digest is invalid")
        if not subject_ref:
            raise AtlasRuntimeError("runtime subject reference is empty")
        signal_record = _signal_record(signal)
        fingerprint = _event_fingerprint(signal, evidence_digest, subject_ref)
        event_identity = (fingerprint, event_cursor, observed_at)
        existing_event = self._events.get(event_identity)
        if existing_event is not None:
            return {
                "accepted": True,
                "duplicate": True,
                "action": existing_event["action"],
                "event_fingerprint": fingerprint,
                "event_cursor": existing_event["event_cursor"],
                "route_id": (
                    None
                    if existing_event["route_receipt"] is None
                    else existing_event["route_receipt"]["route_id"]
                ),
                "model_calls": 0,
                "production_authority": False,
            }
        if len(self._events) >= self._runtime_policy.max_events:
            raise AtlasRuntimeError("runtime event capacity reached")
        if event_cursor != self._cursor + 1:
            raise AtlasRuntimeError("runtime event cursor is not the next value")

        group_key = _alarm_group_key(signal, subject_ref)
        candidate = route_model(
            signal=signal,
            policy=self._route_policy,
            registry=list(self._model_registry),
        )
        current = self._groups.get(group_key)
        within_window = False
        tier_upgrade = False
        if current is not None:
            last_seen = _time(current["last_seen"])
            if observed < last_seen:
                raise AtlasRuntimeError("runtime alarm time moved backwards")
            cooldown_until = _time(current["cooldown_until"])
            coalesce_until = last_seen + timedelta(
                seconds=self._runtime_policy.coalesce_window_seconds
            )
            within_window = observed <= max(coalesce_until, cooldown_until)
            tier_upgrade = (
                TIER_RANK[CognitiveTier(candidate["required_tier"])]
                > TIER_RANK[CognitiveTier(current["required_tier"])]
            )

        route_pending = (
            current is not None
            and current.get("route_id") in self._pending_routes
        )
        routed = (
            current is None
            or tier_upgrade
            or (not within_window and not route_pending)
        )
        if routed:
            group_id = (
                current["group_id"]
                if current is not None and tier_upgrade
                else "alarm-group:"
                + digest_object(
                    {"group_key": group_key, "event_cursor": event_cursor},
                    domain="atlas-runtime-group-instance-v1",
                ).split(":", 1)[1]
            )
            cooldown_until = _timestamp(
                observed + timedelta(seconds=self._runtime_policy.cooldown_seconds)
            )
            route_receipt: dict[str, Any] | None = candidate
            superseded_route_id = (
                current.get("route_id")
                if current is not None and tier_upgrade and route_pending
                else None
            )
            if superseded_route_id in self._pending_runs:
                raise AtlasRuntimeError(
                    "runtime alarm cannot supersede route while cognitive run is pending"
                )
            action = "routed"
        else:
            group_id = current["group_id"]
            cooldown_until = current["cooldown_until"]
            route_receipt = None
            superseded_route_id = None
            action = "coalesced"
        retained_tier = (
            candidate["required_tier"]
            if routed
            else current["required_tier"]
        )

        payload = {
            "event_fingerprint": fingerprint,
            "event_cursor": event_cursor,
            "group_id": group_id,
            "group_key": group_key,
            "observed_at": observed_at,
            "authorization_at": authorization_at,
            "subject_ref": subject_ref,
            "evidence_digest": evidence_digest,
            "signal": signal_record,
            "action": action,
            "required_tier": retained_tier,
            "cooldown_until": cooldown_until,
            "route_receipt": route_receipt,
            "superseded_route_id": superseded_route_id,
        }
        self._append("alarm", payload)
        return {
            "accepted": True,
            "duplicate": False,
            "action": action,
            "event_fingerprint": fingerprint,
            "event_cursor": event_cursor,
            "route_id": (
                None if route_receipt is None else route_receipt["route_id"]
            ),
            "model_calls": 0,
            "production_authority": False,
        }

    def build_cognitive_continuation(
        self,
        *,
        route_id: str,
        atlas_projection: dict[str, Any],
        source_model_id: str | None,
        unresolved_questions: list[str],
        stop_conditions: list[str],
    ) -> dict[str, Any]:
        """Build continuation only from one runtime-owned pending route."""

        _, authorization_at = self._authorize_now()
        route_receipt = self._pending_routes.get(route_id)
        if route_receipt is None:
            raise AtlasRuntimeError("continuation route is not pending")
        matching_events = [
            payload
            for payload in self._events.values()
            if isinstance(payload["route_receipt"], dict)
            and payload["route_receipt"]["route_id"] == route_id
        ]
        if len(matching_events) != 1:
            raise AtlasRuntimeError("continuation route provenance is ambiguous")
        route_signal = _signal_from_record(matching_events[0]["signal"])
        return _build_cognitive_continuation(
            lease=self.lease,
            lease_head=self.lease_head,
            trusted_lease_head_id=self.trusted_lease_head_id,
            authority_key=self._authority_key,
            at_time=authorization_at,
            atlas_projection=atlas_projection,
            route_receipt=route_receipt,
            route_signal=route_signal,
            route_policy=self._route_policy,
            model_registry=list(self._model_registry),
            source_model_id=source_model_id,
            unresolved_questions=unresolved_questions,
            stop_conditions=stop_conditions,
        )

    def build_cognitive_run_request(
        self,
        *,
        route_id: str,
        atlas_projection: dict[str, Any],
        source_model_id: str | None,
        unresolved_questions: list[str],
        stop_conditions: list[str],
        output_contract_digest: str,
    ) -> dict[str, Any]:
        """Persist one bounded request for an external cognitive executor."""

        if route_id in self._pending_runs or route_id in self._run_results:
            raise AtlasRuntimeError(
                "cognitive route already has an execution request"
            )
        package = self.build_cognitive_continuation(
            route_id=route_id,
            atlas_projection=atlas_projection,
            source_model_id=source_model_id,
            unresolved_questions=unresolved_questions,
            stop_conditions=stop_conditions,
        )
        _, requested_at = self._authorize_now()
        try:
            request = _build_cognitive_run_request(
                package,
                requested_at=requested_at,
                output_contract_digest=output_contract_digest,
                max_elapsed_ms=self._runtime_policy.max_cognitive_elapsed_ms,
                max_attempts=self._runtime_policy.max_cognitive_attempts,
            )
        except (CognitiveRuntimeError, TypeError, ValueError) as exc:
            raise AtlasRuntimeError(
                "cognitive execution request could not be built"
            ) from exc
        self._append(
            "cognitive-run-request",
            {"package": package, "request": request},
        )
        return {"package": package, "request": request}

    def pending_cognitive_runs(self) -> list[dict[str, Any]]:
        """Return deterministic pending request envelopes without side effects."""

        return deepcopy(
            [
                self._pending_runs[route_id]
                for route_id in sorted(self._pending_runs)
            ]
        )

    def accept_cognitive_run_result(
        self,
        *,
        request_id: str,
        route_id: str,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        """Verify and durably accept one externally signed terminal result."""

        existing = self._run_results.get(route_id)
        if existing is not None:
            if existing["request_id"] != request_id:
                raise AtlasRuntimeError(
                    "cognitive result references a different terminal request"
                )
            if existing["result"] != result:
                raise AtlasRuntimeError(
                    "cognitive route already has a different terminal result"
                )
            return {
                "accepted": True,
                "duplicate": True,
                "result_id": result["result_id"],
                "route_id": route_id,
                "status": result["status"],
                "production_authority": False,
            }
        run = self._pending_runs.get(route_id)
        if run is None or run["request"]["request_id"] != request_id:
            raise AtlasRuntimeError(
                "cognitive result references no matching pending request"
            )
        if self._agent_key is None:
            raise AtlasRuntimeError(
                "cognitive result requires a pinned agent public key"
            )
        try:
            verification = verify_cognitive_run_result(
                run["request"],
                result,
                agent_key=self._agent_key,
            )
        except (CognitiveRuntimeError, TypeError, ValueError) as exc:
            raise AtlasRuntimeError("cognitive result rejected") from exc
        if (
            verification["status"] == "completed"
            and route_id not in self._pending_routes
        ):
            raise AtlasRuntimeError(
                "completed cognitive result references no pending route"
            )
        self._append(
            "cognitive-run-result",
            {
                "request_id": request_id,
                "route_id": route_id,
                "result": result,
            },
        )
        return {
            "accepted": True,
            "duplicate": False,
            **verification,
        }

    def pending_routes(self) -> list[dict[str, Any]]:
        return deepcopy(
            [
                self._pending_routes[route_id]
                for route_id in sorted(self._pending_routes)
            ]
        )

    def acknowledge_route(self, route_id: str) -> None:
        if route_id not in self._pending_routes:
            raise AtlasRuntimeError("route is not pending")
        if route_id in self._pending_runs:
            raise AtlasRuntimeError(
                "route cannot be acknowledged while cognitive run is pending"
            )
        self._append("route-ack", {"route_id": route_id})

    def idle_status(self) -> dict[str, Any]:
        """Return liveness without polling or invoking a cognitive engine."""

        return {
            "ok": True,
            "tenant_id": self.lease["tenant_id"],
            "module_id": self.lease["module_id"],
            "agent_id": self.lease["agent_id"],
            "generation": self.lease["generation"],
            "lease_id": self.lease["lease_id"],
            "event_cursor": self._cursor,
            "event_count": len(self._events),
            "pending_route_count": len(self._pending_routes),
            "pending_cognitive_run_count": len(self._pending_runs),
            "terminal_cognitive_run_count": len(self._run_results),
            "record_count": len(self._records),
            "recovered_partial_tail": self._recovered_partial_tail,
            "model_calls": self._model_calls,
            "zero_idle_model_calls": self._model_calls == 0,
            "production_authority": False,
        }
