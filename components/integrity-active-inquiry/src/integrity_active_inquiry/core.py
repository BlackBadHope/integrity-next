"""Bounded, offline inquiry planning. All local observations are synthetic.

This module has no target executor, signer, grant verifier or persistent store.
A supplied prediction table is a model, not a claim about a real environment.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import asdict, dataclass, fields
from fractions import Fraction
from types import MappingProxyType
from typing import Any

MAX_DOCUMENT_BYTES = 262_144
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
PROTOCOL = "integrity-active-inquiry/request/v1"


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(b"integrity-active-inquiry-v1\0" + canonical(value)).hexdigest()


def identifier(value: str) -> str:
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError("invalid bounded identifier")
    return value


def checksum(value: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ValueError("expected qualified SHA-256")
    return value


def integer(value: int, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError("integer outside bound")
    return value


def _closed(cls: type, data: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(data, Mapping) or set(data) != {f.name for f in fields(cls)}:
        raise ValueError("missing or unknown contract field")
    return dict(data)


def _pairs(items: set[str] | frozenset[str], answers: Mapping[str, bool]) -> int:
    yes = sum(answers[item] for item in items)
    return yes * (len(items) - yes)


@dataclass(frozen=True)
class Goal:
    goal_id: str
    tenant_id: str
    subject: str
    environment: str
    revision: str
    predicate_id: str
    context_digest: str
    required_basis: str = "synthetic"
    max_steps: int = 8
    max_cost: int = 16
    max_duration_ms: int = 30_000
    max_output_bytes: int = 4096

    def __post_init__(self) -> None:
        for name in ("goal_id", "tenant_id", "subject", "environment", "revision", "predicate_id"):
            identifier(getattr(self, name))
        checksum(self.context_digest)
        if self.required_basis not in {"synthetic", "reported", "witnessed"}:
            raise ValueError("invalid required evidence basis")
        integer(self.max_steps, 1, 64)
        integer(self.max_cost, 1, 1_000_000)
        integer(self.max_duration_ms, 1, 3_600_000)
        integer(self.max_output_bytes, 1, 1_048_576)


@dataclass(frozen=True)
class Probe:
    probe_id: str
    edge_id: str
    capability_id: str
    manifest_digest: str
    operation_digest: str
    response_schema_digest: str
    predictions: Mapping[str, str]
    cost: int = 1
    timeout_ms: int = 100
    max_output_bytes: int = 32
    safety_rank: tuple[int, int, int, int] = (0, 0, 0, 0)
    availability: str = "available"

    def __post_init__(self) -> None:
        for name in ("probe_id", "edge_id", "capability_id"):
            identifier(getattr(self, name))
        for name in ("manifest_digest", "operation_digest", "response_schema_digest"):
            checksum(getattr(self, name))
        integer(self.cost, 1, 1_000_000)
        integer(self.timeout_ms, 1, 3_600_000)
        integer(self.max_output_bytes, 1, 4096)
        if len(self.safety_rank) != 4:
            raise ValueError("four safety dimensions required")
        for part in self.safety_rank:
            integer(part, 0, 1_000_000)
        object.__setattr__(self, "safety_rank", tuple(self.safety_rank))
        if self.availability not in {"available", "unavailable", "denied", "proposed"}:
            raise ValueError("invalid probe availability")
        if not isinstance(self.predictions, Mapping) or not 1 <= len(self.predictions) <= 64:
            raise ValueError("prediction table outside bound")
        for world, token in self.predictions.items():
            identifier(world)
            if not isinstance(token, str) or not 1 <= len(token.encode("utf-8")) <= 64:
                raise ValueError("invalid prediction token")
            if len(token.encode("utf-8")) > self.max_output_bytes:
                raise ValueError("prediction exceeds response payload bound")
        object.__setattr__(self, "predictions", MappingProxyType(dict(sorted(self.predictions.items()))))

    def document(self) -> dict[str, Any]:
        return {f.name: (dict(self.predictions) if f.name == "predictions"
                         else list(self.safety_rank) if f.name == "safety_rank"
                         else getattr(self, f.name)) for f in fields(self)}


class Inquiry:
    """Finite-model selector plus explicitly synthetic in-memory lifecycle.

    begin_simulation does not dispatch an operation or grant authority. Restart
    safety and actual time/transport limits belong to the existing Adapter SDK.
    """

    def __init__(self, goal: Goal, answers: Mapping[str, bool], probes: tuple[Probe, ...], *,
                 session_id: str = "synthetic-session", task_allowed: bool = True) -> None:
        if not isinstance(goal, Goal) or not isinstance(answers, Mapping):
            raise ValueError("typed goal and model required")
        if not 1 <= len(answers) <= 64 or not 1 <= len(probes) <= 32:
            raise ValueError("model outside bounds")
        for world, answer in answers.items():
            identifier(world)
            if type(answer) is not bool:
                raise ValueError("goal answers must be boolean")
        if any(not isinstance(p, Probe) for p in probes):
            raise ValueError("typed probes required")
        if len({p.probe_id for p in probes}) != len(probes):
            raise ValueError("duplicate probe identity")
        if any(set(p.predictions) != set(answers) for p in probes):
            raise ValueError("predictions must cover exactly the supplied model")
        if type(task_allowed) is not bool:
            raise ValueError("task decision must be boolean")
        self.goal = goal
        self.answers = MappingProxyType(dict(sorted(answers.items())))
        self.probes = tuple(sorted(probes, key=lambda p: p.probe_id))
        self.session_id = identifier(session_id)
        self.task_allowed = task_allowed
        self.remaining = frozenset(answers)
        self.steps = self.cost = self.reserved_ms = self.reserved_bytes = 0
        self._used: set[str] = set()
        self._pending: dict[str, Any] | None = None
        self._terminal: str | None = None
        self._events: list[dict[str, Any]] = []

    @property
    def model_digest(self) -> str:
        return digest({"answers": dict(self.answers), "probes": [p.document() for p in self.probes]})

    @property
    def events(self) -> list[dict[str, Any]]:
        return deepcopy(self._events)

    def document(self) -> dict[str, Any]:
        return {"protocol": PROTOCOL, "goal": asdict(self.goal), "answers": dict(self.answers),
                "probes": [p.document() for p in self.probes], "session_id": self.session_id,
                "task_allowed": self.task_allowed}

    def _fits(self, probe: Probe) -> bool:
        g = self.goal
        return (self.steps < g.max_steps and self.cost + probe.cost <= g.max_cost
                and self.reserved_ms + probe.timeout_ms <= g.max_duration_ms
                and self.reserved_bytes + probe.max_output_bytes <= g.max_output_bytes)

    def _quality(self, probe: Probe) -> tuple[int, int]:
        groups: dict[str, set[str]] = {}
        for world in self.remaining:
            groups.setdefault(probe.predictions[world], set()).add(world)
        counts = [_pairs(group, self.answers) for group in groups.values()]
        return max(counts), _pairs(self.remaining, self.answers) - sum(counts)

    def plan(self, gate: Mapping[str, tuple[int, int, int, int]] | None = None) -> dict[str, Any]:
        """gate is a planning projection, never proof of real execution permission."""
        if gate is not None:
            known = {p.probe_id for p in self.probes}
            if not isinstance(gate, Mapping) or not set(gate) <= known:
                raise ValueError("unknown probe in planning gate")
            for rank in gate.values():
                if len(rank) != 4:
                    raise ValueError("invalid gate rank")
                for part in rank:
                    integer(part, 0, 1_000_000)
        out: dict[str, Any] = {
            "protocol": "integrity-active-inquiry/plan/v1", "execution_authority": False,
            "evidence_basis": "synthetic-finite-model", "goal_id": self.goal.goal_id,
            "context_digest": self.goal.context_digest, "model_digest": self.model_digest,
            "remaining": sorted(self.remaining), "excluded": {},
            "reserved": {"steps": self.steps, "cost": self.cost, "duration_ms": self.reserved_ms,
                         "payload_bytes": self.reserved_bytes},
        }
        if self._terminal:
            out["status"] = self._terminal
            if self._pending is not None:
                out["operation_id"] = self._pending["operation_id"]
        elif not self.task_allowed:
            out["status"] = "TASK_DENIED"
        elif self._pending is not None:
            out.update(status="WAITING", operation_id=self._pending["operation_id"])
        elif len({self.answers[w] for w in self.remaining}) == 1:
            value = self.answers[next(iter(self.remaining))]
            if self.goal.required_basis == "synthetic":
                out.update(status="ANSWERED_IN_MODEL", answer=value)
            else:
                out.update(status="EXTERNAL_EVIDENCE_REQUIRED", model_answer=value)
        else:
            candidates = []
            available = []
            for probe in self.probes:
                reason = None
                if probe.availability != "available":
                    reason = probe.availability
                elif gate is not None and probe.probe_id not in gate:
                    reason = "synapse-unavailable"
                elif probe.probe_id in self._used:
                    reason = "already-observed"
                elif self._quality(probe)[1] == 0:
                    reason = "no-goal-discrimination"
                if reason:
                    out["excluded"][probe.probe_id] = reason
                    continue
                available.append(probe)
                if not self._fits(probe):
                    out["excluded"][probe.probe_id] = "budget"
                    continue
                worst, gain = self._quality(probe)
                rank = tuple(gate[probe.probe_id]) if gate is not None else probe.safety_rank
                candidates.append(((*rank, worst, -Fraction(gain, probe.cost), probe.cost,
                                    probe.max_output_bytes, probe.probe_id), probe))
            # Even all eligible probes together may leave opposite answers indistinguishable.
            groups: dict[tuple[str, ...], set[bool]] = {}
            for world in sorted(self.remaining):
                signature = tuple(p.predictions[world] for p in available)
                groups.setdefault(signature, set()).add(self.answers[world])
            if any(len(values) > 1 for values in groups.values()):
                out["status"] = "NEEDS_OBSERVATION"
            elif not candidates:
                out["status"] = "BUDGET_EXHAUSTED"
            else:
                selected = min(candidates, key=lambda pair: pair[0])[1]
                out.update(status="PROPOSED", probe_id=selected.probe_id,
                           edge_id=selected.edge_id, operation_digest=selected.operation_digest,
                           response_schema_digest=selected.response_schema_digest,
                           worst_goal_disagreements=self._quality(selected)[0])
        out["plan_digest"] = digest(out)
        return out

    def begin_simulation(
        self, *, gate: Mapping[str, tuple[int, int, int, int]] | None = None,
        expected_plan_digest: str | None = None,
    ) -> dict[str, Any]:
        """Reserve exactly a current synthetic selection; never dispatch a target.

        Native callers use begin_from_synapse, which refreshes the projection.
        A supplied gate is still only a planning input, not a real permission.
        """
        plan = self.plan(gate)
        if expected_plan_digest is not None:
            checksum(expected_plan_digest)
            if plan["plan_digest"] != expected_plan_digest:
                raise ValueError("stale synthetic plan; no reservation made")
        if plan["status"] != "PROPOSED":
            raise ValueError("no next synthetic step")
        probe = next(p for p in self.probes if p.probe_id == plan["probe_id"])
        self.steps += 1
        self.cost += probe.cost
        self.reserved_ms += probe.timeout_ms
        self.reserved_bytes += probe.max_output_bytes
        binding = {"session_id": self.session_id, "goal_digest": digest(asdict(self.goal)),
                   "context_digest": self.goal.context_digest, "model_digest": self.model_digest,
                   "probe_id": probe.probe_id, "manifest_digest": probe.manifest_digest,
                   "operation_digest": probe.operation_digest,
                   "response_schema_digest": probe.response_schema_digest,
                   "request_digest": plan["plan_digest"], "sequence": self.steps}
        binding["operation_id"] = digest(binding)
        self._pending = binding
        self._events.append({"stage": "synthetic-start", "binding": deepcopy(binding)})
        return deepcopy(binding)

    def receive_simulation(self, binding: Mapping[str, Any], *, stage: str,
                           token: str | None = None) -> None:
        if self._terminal or self._pending is None:
            raise ValueError("no open attempt; replay rejected")
        if canonical(dict(binding)) != canonical(self._pending):
            raise ValueError("exact operation/context/contract binding mismatch")
        if stage not in {"ack", "ready", "completed", "unknown", "synthetic-fact"}:
            raise ValueError("unsupported synthetic stage")
        if stage != "synthetic-fact" and token is not None:
            raise ValueError("only fact stage accepts a token")
        probe = next(p for p in self.probes if p.probe_id == self._pending["probe_id"])
        if stage == "synthetic-fact":
            if not isinstance(token, str) or not token:
                raise ValueError("fact token required")
            if len(token.encode("utf-8")) > probe.max_output_bytes:
                self._terminal = "RESPONSE_LIMIT_NO_RETRY"
                return
        if len(self._events) >= 256:
            self._terminal = "EVENT_LIMIT_NO_RETRY"
            return
        self._events.append({"stage": stage, "binding": deepcopy(self._pending), "token": token})
        if stage in {"ack", "ready", "completed"}:
            return
        if stage == "unknown":
            self._terminal = "UNKNOWN_OUTCOME_NO_RETRY"
            return
        narrowed = frozenset(w for w in self.remaining if probe.predictions[w] == token)
        if not narrowed:
            self._terminal = "MODEL_MISMATCH_NO_RETRY"
            return
        self._used.add(probe.probe_id)
        self.remaining = narrowed
        self._pending = None

    def observation_request(self) -> dict[str, Any]:
        """An inert development proposal, never an installed channel or new grant."""
        status = self.plan()["status"]
        pending = self._pending is not None and status.endswith("NO_RETRY")
        request_status = "PROPOSED_NOT_ADMITTED" if status == "NEEDS_OBSERVATION" or pending else "NOT_NEEDED"
        if not self.task_allowed:
            request_status = "BLOCKED"
        return {"protocol": "integrity-active-inquiry/observation-request/v1",
                "status": request_status,
                "goal_id": self.goal.goal_id, "subject": self.goal.subject,
                "environment": self.goal.environment, "revision": self.goal.revision,
                "predicate_id": self.goal.predicate_id,
                "required_basis": self.goal.required_basis, "execution_authority": False,
                "suggested_kind": "operation-readback" if pending else "predicate-readback",
                "operation_id": self._pending["operation_id"] if pending else None,
                "requires_separate_admission": True}

    def human_question(self) -> dict[str, Any]:
        if not self.task_allowed:
            raise ValueError("denied task cannot be delegated to a human")
        return {"protocol": "integrity-active-inquiry/human-question/v1",
                "goal_id": self.goal.goal_id, "subject": self.goal.subject,
                "environment": self.goal.environment, "revision": self.goal.revision,
                "predicate_id": self.goal.predicate_id,
                "question": "Report only the displayed value for this predicate and its source.",
                "attribution_required": True, "evidence_basis": "human-reported",
                "execution_authority": False}

    def human_report(self, actor_id: str, value: str, source_id: str) -> dict[str, Any]:
        identifier(actor_id)
        identifier(source_id)
        if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= 1024:
            raise ValueError("human report outside bound")
        return {"protocol": "integrity-active-inquiry/human-report/v1",
                "question_digest": digest(self.human_question()), "actor_id": actor_id,
                "source_id": source_id, "value": value, "evidence_basis": "human-reported",
                "independent_machine_verification": False, "execution_authority": False}

    def recipe_candidate(self, *, created_at: int, ttl_seconds: int = 3600) -> dict[str, Any]:
        integer(created_at, 0, 253_402_000_000)
        integer(ttl_seconds, 1, 86_400)
        if self.plan()["status"] != "ANSWERED_IN_MODEL" or not self._events:
            raise ValueError("observed synthetic completion required for recipe candidate")
        recipe = {"protocol": "integrity-active-inquiry/recipe-candidate/v1",
                  "tenant_id": self.goal.tenant_id, "subject": self.goal.subject,
                  "environment": self.goal.environment, "revision": self.goal.revision,
                  "predicate_id": self.goal.predicate_id, "model_digest": self.model_digest,
                  "origin_context_digest": self.goal.context_digest,
                  "probe_ids": sorted(self._used), "events_digest": digest(self._events),
                  "created_at": created_at, "expires_at": created_at + ttl_seconds,
                  "evidence_basis": "synthetic-finite-model", "execution_authority": False,
                  "feedback_admitted": False}
        recipe["recipe_digest"] = digest(recipe)
        return recipe

    def capsule(self, max_bytes: int = 2048) -> dict[str, Any]:
        integer(max_bytes, 1, 65_536)
        plan = self.plan()
        card = {"protocol": "integrity-active-inquiry/capsule/v1", "goal_id": self.goal.goal_id,
                "status": plan["status"], "evidence_basis": plan["evidence_basis"],
                "context_digest": self.goal.context_digest, "plan_digest": plan["plan_digest"],
                "content_is_authority": False, "execution_authority": False,
                "unverified": ["real-target", "independent-witness", "canonical-feedback"]}
        for key in ("answer", "model_answer", "probe_id", "operation_id"):
            if key in plan:
                card[key] = plan[key]
        if len(canonical(card)) > max_bytes:
            raise ValueError("capsule does not fit; no evidence/status truncation")
        return card


def recipe_compatibility(recipe: Mapping[str, Any], inquiry: Inquiry, *, now: int) -> dict[str, Any]:
    """Checks an untrusted draft for reuse planning, not for truth or permission."""
    integer(now, 0, 253_402_300_000)
    expected = {"protocol", "tenant_id", "subject", "environment", "revision", "predicate_id",
                "model_digest", "origin_context_digest", "probe_ids", "events_digest", "created_at",
                "expires_at", "evidence_basis", "execution_authority", "feedback_admitted",
                "recipe_digest"}
    if not isinstance(recipe, Mapping) or set(recipe) != expected:
        raise ValueError("invalid recipe shape")
    item = deepcopy(dict(recipe))
    claimed = item.pop("recipe_digest")
    if claimed != digest(item):
        raise ValueError("recipe changed")
    if (item["protocol"] != "integrity-active-inquiry/recipe-candidate/v1"
            or item["execution_authority"] is not False or item["feedback_admitted"] is not False
            or item["evidence_basis"] != "synthetic-finite-model"):
        raise ValueError("recipe cannot promote evidence or authority")
    for key in ("tenant_id", "subject", "environment", "revision", "predicate_id"):
        identifier(item[key])
    for key in ("model_digest", "origin_context_digest", "events_digest"):
        checksum(item[key])
    probes = item["probe_ids"]
    if (not isinstance(probes, list) or not 1 <= len(probes) <= 32
            or any(not isinstance(p, str) for p in probes)
            or probes != sorted(set(probes))):
        raise ValueError("invalid recipe probe references")
    for probe_id in probes:
        identifier(probe_id)
    integer(item["created_at"], 0, 253_402_000_000)
    integer(item["expires_at"], 1, 253_402_300_000)
    if not 1 <= item["expires_at"] - item["created_at"] <= 86_400:
        raise ValueError("invalid recipe lifetime")
    reasons = []
    if not set(probes) <= {p.probe_id for p in inquiry.probes}:
        reasons.append("unknown-probe-reference")
    if not item["created_at"] <= now < item["expires_at"]:
        reasons.append("expired-or-future")
    for key in ("tenant_id", "subject", "environment", "revision", "predicate_id"):
        if item[key] != getattr(inquiry.goal, key):
            reasons.append(key + "-changed")
    if item["model_digest"] != inquiry.model_digest:
        reasons.append("model-or-catalog-changed")
    return {"status": "STALE" if reasons else "CANDIDATE_COMPATIBLE", "reasons": reasons,
            "fresh_synapse_and_sdk_checks_required": True, "execution_authority": False,
            "truth_verified": False}


def load_request(data: bytes) -> Inquiry:
    """Closed, size-bounded JSON grammar; duplicate keys/NaN/unknown fields rejected."""
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_DOCUMENT_BYTES:
        raise ValueError("request outside byte bound")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise ValueError("nonfinite JSON number")

    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        if not isinstance(doc, dict) or set(doc) != {
            "protocol", "goal", "answers", "probes", "session_id", "task_allowed"}:
            raise ValueError("invalid request shape")
        if doc["protocol"] != PROTOCOL or not isinstance(doc["probes"], list):
            raise ValueError("invalid request protocol")
        if not 1 <= len(doc["probes"]) <= 32:
            raise ValueError("probe count outside bound")
        goal = Goal(**_closed(Goal, doc["goal"]))
        probes = tuple(Probe(**_closed(Probe, p)) for p in doc["probes"])
        return Inquiry(goal, doc["answers"], probes, session_id=doc["session_id"],
                       task_allowed=doc["task_allowed"])
    except (KeyError, TypeError, UnicodeError, RecursionError) as exc:
        raise ValueError("invalid inquiry document") from exc
