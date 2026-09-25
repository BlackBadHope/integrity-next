"""Codex App Server telemetry projection; no provider calls or dispatch authority.

The App Server's ``total`` token record is a cumulative THREAD counter, not a
per-invocation bill. ``last`` must never be added to it. A checkpoint must name
all participating threads and their starting counters. The host retains that
checkpoint through its existing custody mechanism; this module creates no store.
"""
from __future__ import annotations

import json
from dataclasses import replace
from typing import Any, BinaryIO

from .core import Candidate, Interval, Stage
from .metering import AdviceError, Rates, UsageSummary, digest, identity, integer, symbol

MAX_FRAME = 262_144
MAX_THREADS = 64
MAX_TURNS = 1024
MAX_CAPTURE = 8 * 1024 * 1024
MAX_CAPTURE_EVENTS = 4096
COUNTERS = ("inputTokens", "cachedInputTokens", "outputTokens", "reasoningOutputTokens", "totalTokens")
TERMINAL = ("completed", "failed", "interrupted")


def decode_frame(raw: bytes) -> dict[str, Any]:
    """Decode one bounded frame, rejecting ambiguous JSON at the byte boundary."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_FRAME:
        raise AdviceError("codex-frame-size")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise AdviceError("codex-duplicate-key")
            result[key] = value
        return result

    def invalid_number(_):
        raise AdviceError("codex-noninteger-number")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                           parse_constant=invalid_number, parse_float=invalid_number)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise AdviceError("codex-invalid-json") from exc
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > 24 or nodes > 8192:
            raise AdviceError("codex-document-bound")
        if type(item) is dict:
            pending.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            pending.extend((v, depth + 1) for v in item)
    if type(value) is not dict:
        raise AdviceError("codex-object-required")
    return value


def _counts(value: Any) -> tuple[int, ...]:
    if type(value) is not dict or not set(COUNTERS).issubset(value):
        raise AdviceError("codex-usage-fields-missing")
    # Newer catalogs also report cache writes. They are not an additional token
    # charge here: this adapter compares raw total tokens, never money or quota.
    if "cacheWriteInputTokens" in value:
        integer(value["cacheWriteInputTokens"])
    counts = tuple(integer(value[name]) for name in COUNTERS)
    inp, cached, output, reasoning, total = counts
    if cached > inp or reasoning > output or total != inp + output:
        raise AdviceError("codex-inconsistent-counters")
    return counts


def _mapping(counts: tuple[int, ...]) -> dict[str, int]:
    return dict(zip(COUNTERS, counts, strict=True))


def _object(value: Any, code: str) -> dict:
    if type(value) is not dict:
        raise AdviceError(code)
    return value


class CodexProjection:
    """Monotone per-thread usage and turn status, scoped to one parent task.

    Input authenticity and a complete child-thread inventory are host obligations.
    Constructor bindings explicitly identify a starting snapshot; missing usage is
    never interpreted as zero. Replayed notifications are not additional charges.
    """

    def __init__(self, root_task_id: str, bindings: tuple[dict, ...]):
        self.root_task_id = symbol(root_task_id)
        if type(bindings) is not tuple or not 1 <= len(bindings) <= MAX_THREADS:
            raise AdviceError("codex-thread-inventory-bound")
        self._threads: dict[str, dict] = {}
        for binding in bindings:
            _object(binding, "codex-binding-object")
            if set(binding) != {"thread_id", "task_id", "baseline"}:
                raise AdviceError("codex-binding-fields")
            thread = symbol(binding["thread_id"])
            if thread in self._threads:
                raise AdviceError("codex-duplicate-thread")
            baseline = _counts(binding["baseline"])
            self._threads[thread] = {
                "task_id": symbol(binding["task_id"]), "baseline": _mapping(baseline),
                "total": _mapping(baseline), "observed": False, "turns": {}, "latest_turn": None, "usage_turn": None,
                "plan_digest": None, "checkpoint": 0, "boundary": "entry",
                "rerouted_turns": [],
            }

    def ingest(self, raw: bytes) -> dict:
        """Apply only content-free telemetry. Messages/commands/reasoning are not retained."""
        frame = decode_frame(raw)
        if "id" in frame:
            raise AdviceError("codex-request-or-response-not-telemetry")
        method = frame.get("method")
        if type(method) is not str:
            raise AdviceError("codex-notification-method")
        if method not in {"thread/tokenUsage/updated", "turn/started", "turn/completed",
                          "turn/plan/updated", "model/rerouted"}:
            return {"applied": False, "reason": "unhandled-notification"}
        params = _object(frame.get("params"), "codex-params-required")
        thread_id = symbol(params.get("threadId"))
        if thread_id not in self._threads:
            raise AdviceError("codex-undeclared-thread")
        # Copy first: a malformed event cannot partly mutate a valid checkpoint.
        state = json.loads(json.dumps(self._threads[thread_id]))
        if method == "thread/tokenUsage/updated":
            usage_turn = symbol(params.get("turnId"))
            if (state["latest_turn"] is None and state["usage_turn"] is not None
                    and usage_turn != state["usage_turn"]):
                raise AdviceError("codex-unbound-usage-reconcile")
            record = _object(params.get("tokenUsage"), "codex-usage-required")
            new = _counts(record.get("total"))
            old = _counts(state["total"])
            if all(n <= o for n, o in zip(new, old, strict=True)) and new != old:
                # It may be delayed replay OR a reset. Never silently call either complete.
                raise AdviceError("codex-counter-regression-reconcile")
            if any(n < o for n, o in zip(new, old, strict=True)):
                raise AdviceError("codex-counter-conflict")
            # Validate the delta too: cached/reasoning increments cannot exceed their parent.
            _counts(_mapping(tuple(n - o for n, o in zip(new, old, strict=True))))
            if state["latest_turn"] is not None and usage_turn != state["latest_turn"]:
                if new == old:
                    return {"applied": False, "reason": "old-turn-usage-replay"}
                raise AdviceError("codex-out-of-order-usage-reconcile")
            state["total"] = _mapping(new)
            state["usage_turn"] = usage_turn
            state["observed"] = True
        elif method in ("turn/started", "turn/completed"):
            turn = _object(params.get("turn"), "codex-turn-required")
            turn_id = symbol(turn.get("id"))
            status = turn.get("status")
            if ((method == "turn/started" and status != "inProgress") or
                    (method == "turn/completed" and status not in TERMINAL)):
                raise AdviceError("codex-turn-status")
            old = state["turns"].get(turn_id)
            if old is None:
                # Without a start, a later terminal may be delayed historical data.
                # Do not infer chronology or retire unbound usage from another turn.
                if (state["latest_turn"] is None and state["usage_turn"] is not None
                        and state["usage_turn"] != turn_id):
                    raise AdviceError("codex-unbound-usage-reconcile")
                if method == "turn/completed" and state["latest_turn"] is not None:
                    raise AdviceError("codex-unseen-terminal-reconcile")
                if any(v == "inProgress" for v in state["turns"].values()):
                    raise AdviceError("codex-concurrent-turn-reconcile")
                state["latest_turn"] = turn_id
                state["boundary"] = "entry"
                state["observed"] = state["usage_turn"] == turn_id
            if old in TERMINAL:
                if status == "inProgress":
                    return {"applied": False, "reason": "terminal-turn-retained"}
                if old != status:
                    raise AdviceError("codex-terminal-conflict")
            elif status in TERMINAL:
                state["checkpoint"] += 1
                state["boundary"] = (state["boundary"] if state["boundary"] in ("phase", "drift")
                                     else "checkpoint") if status == "completed" else "failure"
            if turn_id not in state["turns"] and len(state["turns"]) >= MAX_TURNS:
                raise AdviceError("codex-turn-inventory-bound")
            state["turns"][turn_id] = status
        elif method == "turn/plan/updated":
            turn_id = symbol(params.get("turnId"))
            if turn_id != state["latest_turn"] or state["turns"].get(turn_id) != "inProgress":
                return {"applied": False, "reason": "noncurrent-plan-ignored"}
            plan = params.get("plan")
            if type(plan) is not list or len(plan) > 128:
                raise AdviceError("codex-plan-bound")
            for step in plan:
                if (type(step) is not dict or set(step) != {"step", "status"}
                        or type(step["step"]) is not str or len(step["step"]) > 4096
                        or step["status"] not in ("pending", "inProgress", "completed")):
                    raise AdviceError("codex-plan-shape")
            # The plan is an agent proposal, not task authority or proof of complexity.
            new = identity(plan, "codex-plan-observation-v1")
            if state["plan_digest"] != new:
                state["plan_digest"] = new
                # New plan text cannot erase a stronger service-reroute signal.
                if state["boundary"] != "drift":
                    state["boundary"] = "phase"
        else:
            turn_id = symbol(params.get("turnId"))
            if turn_id != state["latest_turn"] or state["turns"].get(turn_id) != "inProgress":
                return {"applied": False, "reason": "noncurrent-reroute-ignored"}
            symbol(params.get("fromModel"))
            symbol(params.get("toModel"))
            if turn_id not in state["rerouted_turns"]:
                if len(state["rerouted_turns"]) >= MAX_TURNS:
                    raise AdviceError("codex-reroute-inventory-bound")
                state["rerouted_turns"].append(turn_id)
                state["rerouted_turns"].sort()
            state["boundary"] = "drift"
        # Ensure every accepted state remains serializable/restorable within the same bounds.
        prospective = {**self._threads, thread_id: state}
        self._snapshot_for(prospective)
        changed = state != self._threads[thread_id]
        self._threads[thread_id] = state
        return {"applied": changed, "reason": "updated" if changed else "duplicate-snapshot"}

    def snapshot(self) -> dict:
        return self._snapshot_for(self._threads)

    def _snapshot_for(self, threads: dict) -> dict:
        payload = {"protocol": "integrity-resource-advisor/codex-projection/v1",
                   "root_task_id": self.root_task_id,
                   "threads": {k: threads[k] for k in sorted(threads)},
                   "accounting_scope": "cumulative-thread-window",
                   "provider_report_only": True, "canonical_memory": False}
        result = json.loads(json.dumps(payload))
        result["snapshot_digest"] = identity(payload, "codex-projection-v1")
        decode_frame(json.dumps(result).encode("utf-8"))
        return result

    @classmethod
    def restore(cls, raw: bytes, *, expected_digest: str) -> CodexProjection:
        """The caller supplies an independently retained pin, not a hash from the same file."""
        digest(expected_digest)
        document = decode_frame(raw)
        actual = document.pop("snapshot_digest", None)
        if actual != expected_digest or identity(document, "codex-projection-v1") != expected_digest:
            raise AdviceError("codex-checkpoint-identity")
        if (set(document) != {"protocol", "root_task_id", "threads", "accounting_scope",
                              "provider_report_only", "canonical_memory"}
                or document["protocol"] != "integrity-resource-advisor/codex-projection/v1"
                or document["accounting_scope"] != "cumulative-thread-window"
                or document["provider_report_only"] is not True
                or document["canonical_memory"] is not False):
            raise AdviceError("codex-checkpoint-fields")
        threads = _object(document["threads"], "codex-checkpoint-threads")
        for state in threads.values():
            _object(state, "codex-checkpoint-thread-object")
            if not {"task_id", "baseline"}.issubset(state):
                raise AdviceError("codex-checkpoint-thread-fields")
        result = cls(document["root_task_id"], tuple({"thread_id": k, "task_id": v["task_id"],
                     "baseline": v["baseline"]} for k, v in threads.items()))
        for key, state in threads.items():
            if set(state) != set(result._threads[key]):
                raise AdviceError("codex-checkpoint-thread-fields")
            if type(state["observed"]) is not bool:
                raise AdviceError("codex-checkpoint-observed")
            baseline, total = _counts(state["baseline"]), _counts(state["total"])
            # Wire records may have extensions; producer checkpoints are normalized.
            # Reject hidden payloads rather than retaining arbitrary extra fields.
            if any(set(state[field]) != set(COUNTERS) for field in ("baseline", "total")):
                raise AdviceError("codex-checkpoint-counter-fields")
            _counts(_mapping(tuple(t - b for b, t in zip(baseline, total, strict=True))))
            if not state["observed"] and state["usage_turn"] is None and baseline != total:
                raise AdviceError("codex-unobserved-counter-change")
            turns = _object(state["turns"], "codex-checkpoint-turns")
            if len(turns) > MAX_TURNS:
                raise AdviceError("codex-turn-inventory-bound")
            for turn, status in turns.items():
                symbol(turn)
                if status not in (*TERMINAL, "inProgress"):
                    raise AdviceError("codex-turn-status")
            for field in ("latest_turn", "usage_turn"):
                if state[field] is not None:
                    symbol(state[field])
            if state["latest_turn"] is not None and state["latest_turn"] not in turns:
                raise AdviceError("codex-checkpoint-latest-turn")
            active = [turn for turn, status in turns.items() if status == "inProgress"]
            if (len(active) > 1 or (active and active[0] != state["latest_turn"])
                    or (turns and state["latest_turn"] is None)):
                raise AdviceError("codex-checkpoint-active-turn")
            if turns and state["usage_turn"] is not None and state["usage_turn"] not in turns:
                raise AdviceError("codex-checkpoint-usage-turn")
            expected_observed = state["usage_turn"] is not None and (
                state["latest_turn"] is None or state["usage_turn"] == state["latest_turn"])
            if state["observed"] != expected_observed:
                raise AdviceError("codex-checkpoint-observation-binding")
            integer(state["checkpoint"], 0, MAX_TURNS)
            if state["checkpoint"] != sum(v in TERMINAL for v in turns.values()):
                raise AdviceError("codex-checkpoint-count")
            if state["boundary"] not in ("entry", "checkpoint", "failure", "phase", "drift"):
                raise AdviceError("codex-checkpoint-boundary")
            if state["plan_digest"] is not None:
                digest(state["plan_digest"])
            routed = state["rerouted_turns"]
            if type(routed) is not list or len(routed) > MAX_TURNS:
                raise AdviceError("codex-checkpoint-reroutes")
            for turn in routed:
                symbol(turn)
            if routed != sorted(set(routed)) or not set(routed).issubset(turns):
                raise AdviceError("codex-checkpoint-reroutes")
            latest_status = turns.get(state["latest_turn"])
            boundary = state["boundary"]
            if (latest_status in ("failed", "interrupted")) != (boundary == "failure"):
                raise AdviceError("codex-checkpoint-failure-boundary")
            if (latest_status in TERMINAL and boundary == "entry") or (
                    latest_status == "inProgress" and boundary == "checkpoint"):
                raise AdviceError("codex-checkpoint-terminal-boundary")
            if boundary == "phase" and state["plan_digest"] is None:
                raise AdviceError("codex-checkpoint-phase-without-plan")
            if boundary == "drift" and state["latest_turn"] not in routed:
                raise AdviceError("codex-checkpoint-drift-without-reroute")
            if not turns and (boundary != "entry" or state["plan_digest"] is not None):
                raise AdviceError("codex-checkpoint-unobserved-boundary")
        result._threads = threads
        return result

    def usage(self) -> UsageSummary:
        """Count observed tokens, never infer money/quota or individual model calls."""
        missing, unresolved, known = [], [], 0
        for thread, state in self._threads.items():
            if (not state["observed"] or state["latest_turn"] is None
                    or state["usage_turn"] != state["latest_turn"]):
                missing.append(thread)
            known += state["total"]["totalTokens"] - state["baseline"]["totalTokens"]
            unresolved.extend("turn:" + identity([thread, turn], "codex-turn-v1").split(":")[1]
                              for turn, status in state["turns"].items() if status not in TERMINAL)
        return UsageSummary(self.root_task_id, "tokens", known, not missing, known, not missing,
                            tuple(sorted(missing)), tuple(sorted(unresolved)),
                            self.snapshot()["snapshot_digest"])

    def stage(self, *, thread_id: str, template: Stage) -> Stage:
        """Derive lifecycle fields from a FIXED capture-entry template, not last output.

        The template's checkpoint is the capture's offset in the host task. Its
        Workload/complexity stays host-assessed; model plan text cannot change it.
        """
        if type(template) is not Stage or template.root_task_id != self.root_task_id:
            raise AdviceError("codex-stage-root-mismatch")
        if thread_id not in self._threads:
            raise AdviceError("codex-undeclared-thread")
        state = self._threads[thread_id]
        checkpoint = template.checkpoint + state["checkpoint"]
        return replace(template, checkpoint=checkpoint, boundary=state["boundary"])


def token_candidate(candidate: Candidate, *, valid_from: int, valid_until: int,
                    projection_digest: str) -> Candidate:
    """An explicit token objective, NOT an inferred subscription price.

    Forecast tokens must already include all calls/rework. Currency-denominated
    overhead is rejected rather than silently being reinterpreted as tokens.
    """
    if type(candidate) is not Candidate:
        raise AdviceError("invalid-candidate")
    if candidate.extra_units != Interval(0, 0) or candidate.handoff_units != Interval(0, 0):
        raise AdviceError("codex-token-objective-requires-token-overheads")
    rates = Rates(candidate.configuration.key, "tokens", (1_000_000,) * 4,
                  valid_from, valid_until, projection_digest)
    return replace(candidate, rates=rates,
                   handoff_units=Interval(candidate.handoff_tokens, candidate.handoff_tokens))


def validate_next_turn(*, configuration, catalog: dict, thread_id: str,
                       text: str, provider: str) -> dict:
    """Build a catalog-validated request. It is a PROPOSAL, never dispatch permission."""
    from .core import Configuration

    if type(configuration) is not Configuration or configuration.provider != provider:
        raise AdviceError("codex-provider-transition-not-admitted")
    symbol(thread_id)
    symbol(provider)
    if type(text) is not str or not text:
        raise AdviceError("codex-input-bound")
    try:
        encoded = text.encode("utf-8")
    except UnicodeError:
        raise AdviceError("codex-input-encoding") from None
    if len(encoded) > 65_536:
        raise AdviceError("codex-input-bound")
    if configuration.speed != "standard":
        raise AdviceError("codex-speed-override-not-established")
    _object(catalog, "codex-catalog-object")
    rows = catalog.get("data")
    if (type(rows) is not list or len(rows) > 256 or "nextCursor" not in catalog
            or catalog["nextCursor"] is not None):
        raise AdviceError("codex-catalog-incomplete")
    matches = [row for row in rows if type(row) is dict and row.get("model") == configuration.model]
    if len(matches) != 1:
        raise AdviceError("codex-model-not-uniquely-available")
    row = matches[0]
    # App Server documents this backward-compatible default for older catalogs.
    modalities = row.get("inputModalities", ["text", "image"])
    if (type(modalities) is not list or not 1 <= len(modalities) <= 16
            or any(type(value) is not str for value in modalities)
            or len(modalities) != len(set(modalities)) or "text" not in modalities):
        raise AdviceError("codex-text-input-not-supported")
    supported = row.get("supportedReasoningEfforts")
    if type(supported) is not list or not 1 <= len(supported) <= 16:
        raise AdviceError("codex-effort-catalog-missing")
    efforts = []
    for option in supported:
        if type(option) is not dict or type(option.get("reasoningEffort")) is not str:
            raise AdviceError("codex-effort-catalog-shape")
        effort = symbol(option["reasoningEffort"])
        if effort in efforts:
            raise AdviceError("codex-effort-catalog-duplicate")
        efforts.append(effort)
    if configuration.effort not in efforts:
        raise AdviceError("codex-unsupported-effort")
    return {"method": "turn/start", "params": {"threadId": thread_id,
            "model": configuration.model, "effort": configuration.effort,
            "input": [{"type": "text", "text": text}]}}


def project_jsonl(projection: CodexProjection, stream: BinaryIO) -> dict:
    """Project a finite capture transactionally; no partial report on invalid input.

    The admitted host owns transport, lifetime and completeness. This reader has
    byte/event limits, not a wall-clock timeout for a blocking caller-owned stream.
    """
    if type(projection) is not CodexProjection:
        raise AdviceError("codex-projection-required")
    initial = projection.snapshot()
    current = CodexProjection.restore(json.dumps(initial).encode(),
                                      expected_digest=initial["snapshot_digest"])
    consumed = count = 0
    while True:
        raw = stream.readline(MAX_FRAME + 1)
        if type(raw) is not bytes:
            raise AdviceError("codex-binary-stream-required")
        if not raw:
            return current.snapshot()
        consumed += len(raw)
        count += 1
        if consumed > MAX_CAPTURE or count > MAX_CAPTURE_EVENTS:
            raise AdviceError("codex-capture-bound")
        if not raw.endswith(b"\n"):
            raise AdviceError("codex-truncated-jsonl-frame")
        current.ingest(raw)


def main() -> None:
    """Read explicit capture files/stdin, emit one snapshot; never launch Codex."""
    import argparse
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bindings", type=Path, help="root_task_id and explicit thread baselines JSON")
    source.add_argument("--checkpoint", type=Path, help="previous projected snapshot")
    parser.add_argument("--pin", help="independently retained checkpoint digest")
    parser.add_argument("--events", type=Path, help="finite notification JSONL capture; default stdin")
    args = parser.parse_args()
    if bool(args.checkpoint) != bool(args.pin):
        parser.error("--checkpoint requires --pin; --pin is not valid with --bindings")
    try:
        with (args.bindings or args.checkpoint).open("rb") as handle:
            raw = handle.read(MAX_FRAME + 1)
        if args.checkpoint:
            projection = CodexProjection.restore(raw, expected_digest=args.pin)
        else:
            binding = decode_frame(raw)
            if set(binding) != {"root_task_id", "bindings"} or type(binding["bindings"]) is not list:
                raise AdviceError("codex-binding-document")
            projection = CodexProjection(binding["root_task_id"], tuple(binding["bindings"]))
        if args.events:
            with args.events.open("rb") as handle:
                result = project_jsonl(projection, handle)
        else:
            result = project_jsonl(projection, sys.stdin.buffer)
        print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    except AdviceError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2) from None
    except OSError:
        print("codex-capture-io-error", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
