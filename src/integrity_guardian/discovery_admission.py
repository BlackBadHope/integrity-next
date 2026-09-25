"""Deterministic admission rules for new Fog of War discovery deltas.

The firewall classifies source epochs out of band and decides whether one
already verified discovery record may replace a source-owned active record.
It does not alter discovery records or snapshots, grant authority, perform I/O
or treat review priority as permission.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from .hashing import digest_object

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_ADMISSION_BOUNDARY = {
    "execution": False,
    "network": False,
    "priority_is_authority": False,
    "production_authority": False,
    "record_mutation": False,
}
_STABLE_CLASSES = {
    "static",
    "quasi-static",
}
_WEAK_CLASSES = {
    "dynamic",
    "cache",
    "derived",
    "theoretical",
    "unknown",
}


class DiscoveryAdmissionError(ValueError):
    """Raised when an admission policy or candidate cannot be evaluated."""


class DiscoveryFactClass(StrEnum):
    """Operational stability class supplied by an out-of-band source binding."""

    STATIC = "static"
    QUASI_STATIC = "quasi-static"
    DYNAMIC = "dynamic"
    CACHE = "cache"
    DERIVED = "derived"
    THEORETICAL = "theoretical"
    UNKNOWN = "unknown"


class DiscoveryLifecycle(StrEnum):
    """Lifecycle namespace used to keep facts with different expiry apart."""

    PERSISTENT = "persistent"
    ACTIVE = "active"
    EPHEMERAL = "ephemeral"
    DERIVED = "derived"
    THEORETICAL = "theoretical"
    UNKNOWN = "unknown"


class DiscoveryAdmissionAction(StrEnum):
    ADMIT = "admit"
    QUARANTINE = "quarantine"


@dataclass(frozen=True)
class DiscoverySourceBinding:
    """Exact classification of one independently trusted discovery epoch."""

    source_id: str
    source_epoch: str
    fact_class: DiscoveryFactClass
    lifecycle: DiscoveryLifecycle

    def __post_init__(self) -> None:
        for field_name, value in (
            ("source_id", self.source_id),
            ("source_epoch", self.source_epoch),
        ):
            if not isinstance(value, str) or _ID.fullmatch(value) is None:
                raise DiscoveryAdmissionError(
                    f"admission {field_name} rejected"
                )
        if not isinstance(self.fact_class, DiscoveryFactClass):
            raise DiscoveryAdmissionError("admission fact class rejected")
        if not isinstance(self.lifecycle, DiscoveryLifecycle):
            raise DiscoveryAdmissionError("admission lifecycle rejected")

    def document(self) -> dict[str, str]:
        return {
            "source_id": self.source_id,
            "source_epoch": self.source_epoch,
            "fact_class": self.fact_class.value,
            "lifecycle": self.lifecycle.value,
        }


@dataclass(frozen=True)
class DiscoveryAdmissionPolicy:
    """Closed source-epoch classification for one delta-admission boundary."""

    policy_id: str
    source_bindings: tuple[DiscoverySourceBinding, ...]
    _binding_index: Mapping[
        tuple[str, str],
        DiscoverySourceBinding,
    ] = field(init=False, repr=False, compare=False)
    _digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.policy_id, str) or _ID.fullmatch(self.policy_id) is None:
            raise DiscoveryAdmissionError("admission policy id rejected")
        if (
            not isinstance(self.source_bindings, tuple)
            or not self.source_bindings
            or len(self.source_bindings) > 1_000
        ):
            raise DiscoveryAdmissionError("admission source bindings rejected")
        for binding in self.source_bindings:
            if not isinstance(binding, DiscoverySourceBinding):
                raise DiscoveryAdmissionError("admission source binding rejected")
        ordered = tuple(
            sorted(
                self.source_bindings,
                key=lambda item: (item.source_id, item.source_epoch),
            )
        )
        keys = [(item.source_id, item.source_epoch) for item in ordered]
        if len(keys) != len(set(keys)):
            raise DiscoveryAdmissionError("duplicate admission source binding")
        object.__setattr__(self, "source_bindings", ordered)
        object.__setattr__(
            self,
            "_binding_index",
            MappingProxyType(
                {
                    (item.source_id, item.source_epoch): item
                    for item in ordered
                }
            ),
        )
        object.__setattr__(
            self,
            "_digest",
            digest_object(
                self.document(),
                domain="discovery-admission-policy-v1",
            ),
        )

    def document(self) -> dict[str, Any]:
        return {
            "protocol": "integrity-guardian/discovery-admission-policy/v1",
            "policy_id": self.policy_id,
            "source_bindings": [item.document() for item in self.source_bindings],
            "boundary": dict(_ADMISSION_BOUNDARY),
        }

    @property
    def digest(self) -> str:
        return self._digest

    def binding_for(self, record: Mapping[str, Any]) -> DiscoverySourceBinding | None:
        try:
            key = (str(record["source_id"]), str(record["source_epoch"]))
        except (KeyError, TypeError) as exc:
            raise DiscoveryAdmissionError("admission source identity unreadable") from exc
        return self._binding_index.get(key)


@dataclass(frozen=True)
class DiscoveryAdmissionDecision:
    """Deterministic, authority-free decision for one candidate record."""

    action: DiscoveryAdmissionAction
    reason: str
    candidate_record_id: str
    current_record_id: str | None
    policy_digest: str
    semantic_identity: str | None
    review_priority: int

    def document(self) -> dict[str, Any]:
        return {
            "protocol": "integrity-guardian/discovery-admission-decision/v1",
            "action": self.action.value,
            "reason": self.reason,
            "candidate_record_id": self.candidate_record_id,
            "current_record_id": self.current_record_id,
            "policy_digest": self.policy_digest,
            "semantic_identity": self.semantic_identity,
            "review_priority": self.review_priority,
            "boundary": dict(_ADMISSION_BOUNDARY),
        }


def _assertion_identity(record: Mapping[str, Any]) -> tuple[str, str]:
    try:
        assertion = record["assertion"]
        kind = str(assertion["kind"])
        identity_field = {
            "entity": "entity_id",
            "relation": "relation_id",
            "gap": "gap_id",
        }[kind]
        return kind, str(assertion[identity_field])
    except (KeyError, TypeError) as exc:
        raise DiscoveryAdmissionError("admission assertion identity unreadable") from exc


def _semantic_identity(
    record: Mapping[str, Any],
    binding: DiscoverySourceBinding,
) -> str:
    try:
        assertion = record["assertion"]
        kind, assertion_id = _assertion_identity(record)
        if kind == "entity":
            predicate = {
                "entity_type": str(assertion["entity_type"]),
            }
        elif kind == "relation":
            predicate = {
                "relation_type": str(assertion["relation_type"]),
                "from_entity_id": str(assertion["from_entity_id"]),
                "to_entity_id": str(assertion["to_entity_id"]),
                "from_zone_id": str(assertion["from_zone_id"]),
                "to_zone_id": str(assertion["to_zone_id"]),
            }
        else:
            predicate = {
                "classification": str(assertion["classification"]),
                "subject_id": assertion["subject_id"],
            }
    except (KeyError, TypeError) as exc:
        raise DiscoveryAdmissionError("admission typed predicate unreadable") from exc
    core = {
        "source_id": binding.source_id,
        "kind": kind,
        "assertion_id": assertion_id,
        "predicate": predicate,
        "fact_class": binding.fact_class.value,
        "lifecycle": binding.lifecycle.value,
    }
    suffix = digest_object(core, domain="discovery-semantic-identity-v1").split(":", 1)[1]
    return f"discovery-semantic:{suffix}"


def discovery_semantic_identity(
    policy: DiscoveryAdmissionPolicy,
    record: Mapping[str, Any],
) -> str:
    """Return the policy-bound meaning retained across active tombstones."""

    if not isinstance(policy, DiscoveryAdmissionPolicy):
        raise DiscoveryAdmissionError("admission policy rejected")
    binding = policy.binding_for(record)
    if binding is None:
        raise DiscoveryAdmissionError("unbound semantic identity source")
    return _semantic_identity(record, binding)


def _decision(
    *,
    action: DiscoveryAdmissionAction,
    reason: str,
    candidate: Mapping[str, Any],
    current: Mapping[str, Any] | None,
    policy: DiscoveryAdmissionPolicy,
    semantic_identity: str | None,
    review_priority: int,
) -> DiscoveryAdmissionDecision:
    try:
        candidate_record_id = str(candidate["record_id"])
        current_record_id = None if current is None else str(current["record_id"])
    except (KeyError, TypeError) as exc:
        raise DiscoveryAdmissionError("admission record identity unreadable") from exc
    return DiscoveryAdmissionDecision(
        action=action,
        reason=reason,
        candidate_record_id=candidate_record_id,
        current_record_id=current_record_id,
        policy_digest=policy.digest,
        semantic_identity=semantic_identity,
        review_priority=review_priority,
    )


def evaluate_discovery_admission(
    *,
    policy: DiscoveryAdmissionPolicy,
    candidate: Mapping[str, Any],
    current: Mapping[str, Any] | None,
    historical_semantic_identity: str | None = None,
    review_priority: int = 0,
) -> DiscoveryAdmissionDecision:
    """Decide whether ``candidate`` may replace ``current``.

    Records must already have passed the normal Discovery signature and source
    checks. Priority is retained for review ordering but never changes action.
    """

    if not isinstance(policy, DiscoveryAdmissionPolicy):
        raise DiscoveryAdmissionError("admission policy rejected")
    if (
        not isinstance(review_priority, int)
        or isinstance(review_priority, bool)
        or not 0 <= review_priority <= 1_000_000
    ):
        raise DiscoveryAdmissionError("admission review priority rejected")
    if (
        historical_semantic_identity is not None
        and (
            not isinstance(historical_semantic_identity, str)
            or re.fullmatch(
                r"discovery-semantic:[a-f0-9]{64}",
                historical_semantic_identity,
            )
            is None
        )
    ):
        raise DiscoveryAdmissionError(
            "admission historical semantic identity rejected"
        )

    def decide(
        action: DiscoveryAdmissionAction,
        reason: str,
        semantic_identity: str | None,
    ) -> DiscoveryAdmissionDecision:
        return _decision(
            action=action,
            reason=reason,
            candidate=candidate,
            current=current,
            policy=policy,
            semantic_identity=semantic_identity,
            review_priority=review_priority,
        )

    candidate_binding = policy.binding_for(candidate)
    if candidate_binding is None:
        return decide(
            DiscoveryAdmissionAction.QUARANTINE,
            "unbound-candidate-source",
            None,
        )
    candidate_identity = _semantic_identity(candidate, candidate_binding)
    if current is None:
        if (
            historical_semantic_identity is not None
            and candidate_identity != historical_semantic_identity
        ):
            return decide(
                DiscoveryAdmissionAction.QUARANTINE,
                "historical-semantic-identity-conflict",
                candidate_identity,
            )
        return decide(
            DiscoveryAdmissionAction.ADMIT,
            (
                "historical-semantic-reintroduction"
                if historical_semantic_identity is not None
                else "new-source-owned-assertion"
            ),
            candidate_identity,
        )

    current_binding = policy.binding_for(current)
    if current_binding is None:
        return decide(
            DiscoveryAdmissionAction.QUARANTINE,
            "unbound-current-source",
            candidate_identity,
        )
    if _assertion_identity(candidate) != _assertion_identity(current):
        raise DiscoveryAdmissionError("admission compared unrelated assertions")
    if (
        current_binding.fact_class.value in _STABLE_CLASSES
        and candidate_binding.fact_class.value in _WEAK_CLASSES
    ):
        return decide(
            DiscoveryAdmissionAction.QUARANTINE,
            "weaker-class-cannot-replace-stable-fact",
            candidate_identity,
        )

    current_identity = _semantic_identity(current, current_binding)
    if candidate_identity != current_identity:
        return decide(
            DiscoveryAdmissionAction.QUARANTINE,
            "semantic-identity-conflict",
            candidate_identity,
        )
    if candidate_binding.source_epoch != current_binding.source_epoch:
        return decide(
            DiscoveryAdmissionAction.QUARANTINE,
            "source-epoch-replacement-requires-explicit-migration",
            candidate_identity,
        )
    return decide(
        DiscoveryAdmissionAction.ADMIT,
        (
            "exact-source-owned-tombstone"
            if candidate.get("change") == "delete"
            else "exact-lifecycle-refresh"
        ),
        candidate_identity,
    )


def evaluate_discovery_admission_batch(
    *,
    policy: DiscoveryAdmissionPolicy,
    candidates: Sequence[Mapping[str, Any]],
    active_records: Sequence[Mapping[str, Any]],
    review_priority: int = 0,
) -> list[DiscoveryAdmissionDecision]:
    """Evaluate a batch against staged state without mutating either input."""

    staged: dict[tuple[str, str, str], Mapping[str, Any]] = {}
    history: dict[tuple[str, str, str], str] = {}
    for record in active_records:
        kind, assertion_id = _assertion_identity(record)
        key = (str(record["source_id"]), kind, assertion_id)
        binding = policy.binding_for(record)
        if binding is None:
            raise DiscoveryAdmissionError("unbound active source")
        staged[key] = record
        history[key] = _semantic_identity(record, binding)
    decisions: list[DiscoveryAdmissionDecision] = []
    for candidate in candidates:
        kind, assertion_id = _assertion_identity(candidate)
        key = (str(candidate["source_id"]), kind, assertion_id)
        current = staged.get(key)
        decision = evaluate_discovery_admission(
            policy=policy,
            candidate=candidate,
            current=current,
            historical_semantic_identity=history.get(key),
            review_priority=review_priority,
        )
        decisions.append(decision)
        if decision.action is DiscoveryAdmissionAction.QUARANTINE:
            break
        if candidate.get("change") == "delete":
            staged.pop(key, None)
        else:
            staged[key] = candidate
        if decision.semantic_identity is not None:
            history[key] = decision.semantic_identity
    return decisions


__all__ = [
    "DiscoveryAdmissionAction",
    "DiscoveryAdmissionDecision",
    "DiscoveryAdmissionError",
    "DiscoveryAdmissionPolicy",
    "DiscoveryFactClass",
    "DiscoveryLifecycle",
    "DiscoverySourceBinding",
    "discovery_semantic_identity",
    "evaluate_discovery_admission",
    "evaluate_discovery_admission_batch",
]
