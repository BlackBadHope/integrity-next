"""Attach-only observer/controller: a terminal protocol event is NOT acceptance.

The host must have admitted and launched the exact turn through its existing
Galaxy/PPv4/SDK path. This module neither verifies a grant nor claims to contain
native tools. Permission denial and interrupt are its only outgoing operations.
"""

from __future__ import annotations

import asyncio
import time
import math
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Awaitable, Callable

from .connection import EventConnection, ProtocolError, validate_message
from .policy import Binding, Budget, ControlView, JobPolicy, integer

ControlReader = Callable[[], Awaitable[ControlView]]

_NATIVE_AGENT_ITEMS = frozenset({"collabAgentToolCall", "subAgentActivity", "collabToolCall"})
_KNOWN_ITEMS = frozenset({
    "userMessage", "hookPrompt", "agentMessage", "functionCallOutput", "plan", "reasoning",
    "commandExecution", "fileChange", "mcpToolCall", "dynamicToolCall", "webSearch",
    "imageView", "sleep", "imageGeneration", "enteredReviewMode", "exitedReviewMode",
    "contextCompaction",
}) | _NATIVE_AGENT_ITEMS


def _clock(value: float) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError("non-finite clock observation")
    return float(value)


def _usage_limit(error: object) -> bool:
    if not isinstance(error, dict):
        return False
    info = error.get("codexErrorInfo")
    return info in ("usageLimitExceeded", "UsageLimitExceeded") if isinstance(info, str) else False


@dataclass(frozen=True)
class Observation:
    job_id: str
    thread_id: str
    turn_id: str
    snapshot_id: str
    control_generation: int
    outcome: str
    stop_reason: str | None
    terminal_status: str | None
    observed_events: int
    used_tokens: int
    deadline_epoch: float
    cleanup_required: bool
    # Provider notifications are observations, not a proof of final billed usage.
    usage_is_lower_bound: bool = field(default=True, init=False)
    independent_acceptance: bool = field(default=False, init=False)
    replay_allowed: bool = field(default=False, init=False)

    def as_dict(self) -> dict[str, Any]:
        """Content-free observation for the host's existing journal, not a signature."""
        return asdict(self)


class Supervisor:
    """One invocation per instance; attach to an externally owned exact turn.

    ControlReader reads trusted coordinator state and must not invoke a model.
    Interrupt acknowledgment does not prove termination. Without a matching
    terminal notification, return unknown-outcome and require host cleanup and
    reconciliation. Cancellation is propagated after bounded interrupt cleanup.
    """

    def __init__(
        self, binding: Binding, budget: Budget, policy: JobPolicy,
        *, monotonic: Callable[[], float] = time.monotonic,
        epoch: Callable[[], float] = time.time,
    ) -> None:
        if not policy.enabled:
            raise ValueError("candidate supervisor is disabled by default")
        self.binding = binding
        self.budget = budget
        self.policy = policy
        self.monotonic = lambda: _clock(monotonic())
        # Anchor once: wall clock rollback must not extend an active mission.
        self.deadline = _clock(self.monotonic() + max(0.0, budget.deadline_epoch - _clock(epoch())))
        self.used_tokens = budget.used_tokens
        self.last_total = budget.thread_baseline_tokens
        self.events = 0
        self.stop_reason: str | None = None
        self.terminal: str | None = None
        self.outcome: str | None = None
        self.last_observation: Observation | None = None
        self._used = False
        self._interrupt_id = "integrity-persistent-" + uuid.uuid4().hex
        self._interrupt_sent = False
        self._stop_deadline: float | None = None
        self._requires_runtime_reconciliation = False
        self._request_ids: set[tuple[type, str | int]] = set()

    def _stop(self, reason: str) -> None:
        # Owner stop/budget failure must never be erased by a later completed event.
        if self.stop_reason is None:
            self.stop_reason = reason
            # Start once, BEFORE any refusal/interrupt I/O; sends consume this
            # same grace window rather than replenishing it after backpressure.
            self._stop_deadline = self.monotonic() + self.budget.stop_grace_seconds

    def _control(self, value: ControlView) -> None:
        if not isinstance(value, ControlView):
            raise ProtocolError("invalid host control observation")
        if value.state == "STOPPED":
            self._stop("owner_stopped")
        elif value.state == "PAUSED":
            self._stop("owner_paused")
        elif value.generation != self.binding.control_generation:
            self._stop("control_superseded")
        elif value.snapshot_id != self.binding.snapshot_id:
            self._stop("context_readmission_required")

    async def _send(self, connection: EventConnection, message: dict[str, Any]) -> None:
        timeout = self.budget.poll_seconds
        if self._stop_deadline is not None:
            timeout = min(timeout, self._stop_deadline - self.monotonic())
        if timeout <= 0:
            raise TimeoutError("stop reconciliation deadline exhausted")
        await asyncio.wait_for(connection.send(message), timeout)
        if self._stop_deadline is not None and self.monotonic() >= self._stop_deadline:
            raise TimeoutError("send completed after stop reconciliation deadline")

    async def _interrupt(self, connection: EventConnection) -> None:
        if self._interrupt_sent:
            return
        # Mark before send: partial write/timeout must NOT cause a resend.
        self._interrupt_sent = True
        await self._send(connection, {
            "id": self._interrupt_id,
            "method": "turn/interrupt",
            "params": {"threadId": self.binding.thread_id, "turnId": self.binding.turn_id},
        })

    def _scope(self, params: dict[str, Any], *, turn_required: bool) -> bool:
        if not isinstance(params.get("threadId"), str) or not params["threadId"]:
            raise ProtocolError("missing event thread identity")
        if params["threadId"] != self.binding.thread_id:
            return False
        turn_id = params.get("turnId")
        if isinstance(params.get("turn"), dict):
            nested_id = params["turn"].get("id")
            if turn_id is not None and turn_id != nested_id:
                raise ProtocolError("conflicting event turn identities")
            turn_id = nested_id
        if turn_id is None:
            if turn_required:
                raise ProtocolError("missing event turn identity")
            return True
        if not isinstance(turn_id, str) or not turn_id:
            raise ProtocolError("invalid event turn identity")
        return turn_id == self.binding.turn_id

    async def _request(self, connection: EventConnection, message: dict[str, Any]) -> None:
        request_id = message["id"]
        if type(request_id) not in (str, int) or len(str(request_id)) > 256:
            raise ProtocolError("invalid server request identity")
        key = (type(request_id), request_id)
        if key in self._request_ids:
            raise ProtocolError("server request was already answered")
        self._request_ids.add(key)
        method = message["method"]
        params = message.get("params")
        if not isinstance(params, dict):
            raise ProtocolError("invalid server request params")
        # Dedicated/demultiplexed channels are required. Never silently discard
        # another turn's request or answer it on behalf of the other owner.
        if not self._scope(params, turn_required=method != "mcpServer/elicitation/request"):
            raise ProtocolError("server request belongs to another turn")
        if method in {"item/commandExecution/requestApproval", "item/fileChange/requestApproval"}:
            reply = {"id": request_id, "result": {"decision": "decline"}}
        elif method == "item/permissions/requestApproval":
            reply = {"id": request_id, "result": {"permissions": {}, "scope": "turn"}}
        elif method == "mcpServer/elicitation/request":
            reply = {"id": request_id, "result": {"action": "decline", "content": None}}
        else:
            reply = {"id": request_id, "error": {
                "code": -32601, "message": "Unsupported by supervisor",
            }}
        self._stop("host_action_required")
        await self._send(connection, reply)

    def _item(self, value: object) -> None:
        if not isinstance(value, dict) or not isinstance(value.get("type"), str):
            raise ProtocolError("invalid item event")
        kind = value["type"]
        if kind in _NATIVE_AGENT_ITEMS:
            self._requires_runtime_reconciliation = True
            self._stop("unexpected_native_fanout")
        elif kind == "contextCompaction":
            self._stop("context_readmission_required")
        elif kind not in _KNOWN_ITEMS:
            self._stop("protocol_readmission_required")
        # Text, including phase=final_answer, cannot establish termination.

    async def _event(self, connection: EventConnection, message: dict[str, Any]) -> None:
        validate_message(message)
        self.events += 1
        if self.events > self.budget.max_events:
            self._stop("event_budget")
            self._requires_runtime_reconciliation = True
            # Bound both processing and request-id memory during a flood. Permit
            # only a small terminal/ACK tail; skipped events are NOT complete
            # evidence, even if the parent subsequently reports termination.
            if self.events > self.budget.max_events + 32:
                raise ProtocolError("terminal reconciliation event budget exhausted")
            if not (message.get("method") == "turn/completed" or (
                "method" not in message and message.get("id") == self._interrupt_id
            )):
                return
        if not isinstance(message, dict):
            raise ProtocolError("event is not an object")
        method = message.get("method")
        if method is None:
            # Host-demultiplexed streams must not lend another request's result
            # to this turn. An ACK is never proof of a completed interruption.
            if not self._interrupt_sent or message.get("id") != self._interrupt_id:
                raise ProtocolError("unexpected response identity")
            if "error" in message:
                raise ProtocolError("interrupt rejected")
            if message["result"] != {}:
                raise ProtocolError("invalid interrupt acknowledgment")
            return
        if not isinstance(method, str):
            raise ProtocolError("invalid event method")
        if "id" in message:
            await self._request(connection, message)
            return
        params = message.get("params")
        if not isinstance(params, dict):
            raise ProtocolError("invalid event params")
        lifecycle = method in {"turn/started", "turn/completed", "error", "model/rerouted"}
        usage = method == "thread/tokenUsage/updated"
        item = method in {"item/started", "item/completed"}
        legacy_compact = method == "thread/compacted"
        if not (lifecycle or usage or item or legacy_compact):
            return  # Deltas, plans, text and warnings never prove completion.
        if not self._scope(params, turn_required=not legacy_compact):
            return
        if usage:
            try:
                total = integer(params["tokenUsage"]["total"]["totalTokens"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ProtocolError("invalid cumulative usage") from exc
            if total < self.last_total:
                raise ProtocolError("usage epoch changed; reconciliation required")
            self.last_total = total
            self.used_tokens = self.budget.used_tokens + total - self.budget.thread_baseline_tokens
            if self.used_tokens >= self.budget.max_tokens:
                self._stop("token_budget")
        elif item:
            self._item(params.get("item"))
        elif legacy_compact:
            self._stop("context_readmission_required")
        elif method == "model/rerouted":
            self._stop("model_readmission_required")
        elif method == "error":
            if _usage_limit(params.get("error")):
                self._stop("usage_limit")
            elif params.get("willRetry") is not True:
                self._stop("provider_error")
        else:
            turn = params.get("turn")
            if not isinstance(turn, dict):
                raise ProtocolError("invalid turn event")
            status = turn.get("status")
            if method == "turn/started":
                if status != "inProgress":
                    raise ProtocolError("invalid turn start status")
                return
            if status not in {"completed", "interrupted", "failed"}:
                raise ProtocolError("unknown terminal status")
            if status == "completed" and turn.get("error") is not None:
                raise ProtocolError("completed turn carries an error")
            # A host may attach after item events were delivered. Inspect any
            # retained terminal inventory too; parent completion cannot discharge
            # cleanup of a native child that Galaxy never owned.
            if "items" in turn:
                items = turn["items"]
                if not isinstance(items, list) or len(items) > self.budget.max_events:
                    raise ProtocolError("invalid terminal item inventory")
                for value in items:
                    self._item(value)
            self.terminal = status
            if _usage_limit(turn.get("error")):
                self._stop("usage_limit")
            self.outcome = self.stop_reason or {
                "completed": "protocol_completed", "failed": "failed", "interrupted": "interrupted",
            }[status]

    def _observe(self) -> Observation:
        value = Observation(
            **asdict(self.binding), outcome=self.outcome or "unknown_outcome",
            stop_reason=self.stop_reason, terminal_status=self.terminal,
            observed_events=self.events, used_tokens=self.used_tokens,
            deadline_epoch=self.budget.deadline_epoch,
            cleanup_required=self.terminal is None or self._requires_runtime_reconciliation,
        )
        self.last_observation = value
        return value

    async def run(self, connection: EventConnection, control: ControlReader) -> Observation:
        if self._used:
            raise RuntimeError("supervisor is single-use; re-admission belongs to the host")
        self._used = True
        try:
            while self.terminal is None:
                now = self.monotonic()
                if now >= self.deadline:
                    self._stop("deadline")
                if self.used_tokens >= self.budget.max_tokens:
                    self._stop("token_budget")
                if self.stop_reason is None:
                    remaining = max(0.001, min(self.budget.poll_seconds, self.deadline - now))
                    try:
                        self._control(await asyncio.wait_for(control(), remaining))
                    except Exception:
                        self._stop("control_unavailable")
                # Re-evaluate after the await; never extend the deadline by polling.
                if self.monotonic() >= self.deadline:
                    self._stop("deadline")
                if self.stop_reason is not None:
                    await self._interrupt(connection)
                end = self._stop_deadline if self._stop_deadline is not None else self.deadline
                remaining = end - self.monotonic()
                if remaining <= 0:
                    if self._stop_deadline is not None:
                        break  # No terminal evidence; host must clean up/reconcile.
                    continue
                try:
                    wait = min(self.budget.poll_seconds, remaining)
                    message = await asyncio.wait_for(connection.receive(wait), wait)
                except TimeoutError:
                    continue
                if self._stop_deadline is not None and self.monotonic() >= self._stop_deadline:
                    break  # A late result does not extend the bounded reconciliation phase.
                if message is None:
                    self._stop("transport_eof")
                    await self._interrupt(connection)
                    break
                if self.monotonic() >= self.deadline:
                    self._stop("deadline")
                await self._event(connection, message)
                if self.terminal is not None and self.stop_reason is None:
                    try:
                        self._control(await asyncio.wait_for(control(), self.budget.poll_seconds))
                    except Exception:
                        self._stop("control_unavailable")
                    if self.monotonic() >= self.deadline:
                        self._stop("deadline")
                    if self.stop_reason is not None:
                        self.outcome = self.stop_reason
        except asyncio.CancelledError:
            self._stop("supervisor_cancelled")
            self.outcome = "supervisor_cancelled" if self.terminal is not None else None
            try:
                await self._interrupt(connection)
            except Exception:
                pass
            raise
        except Exception:
            self._stop("protocol_or_transport_failure")
            try:
                await self._interrupt(connection)
            except Exception:
                pass
        finally:
            # A second task.cancel() can interrupt the cancellation handler's
            # await. Never lose the last content-free observation in that race.
            self._observe()
        # finally has already retained this observation, including cancellation.
        assert self.last_observation is not None
        return self.last_observation
