"""Bounded delivery of an already admitted operation, never a new admission.

The server remains the authority for identity, revocation, deduplication and
canonical effects. This module only retains the original request and decides
whether a transport retry has sufficient evidence. An absent read alone is not
proof that a previously sent request cannot still commit.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Callable

RECOVERY_PROTOCOL = "integrity-client/session-recovery/v1"
STATUS_PROTOCOL = "integrity-client/operation-status/v1"
CONTROL_FIELDS = (
    "replay_id", "request_digest", "response_digest", "context_admission_id",
    "snapshot_id", "prompt_binding", "logical_generation",
)
TOOLS = {"integrity_append_event", "integrity_turn_memory_close"}


class DeliveryPending(RuntimeError):
    """An unresolved result is retained as debt, never inferred as no-event."""


class RecoveryDenied(RuntimeError):
    pass


class DeliveryFault(RuntimeError):
    def __init__(self, *, request_sent: bool, retryable: bool):
        super().__init__("operation transport failed")
        self.request_sent = request_sent
        self.retryable = retryable


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def operation_key(tool, arguments):
    if tool == "integrity_append_event":
        uid = arguments.get("event_uid")
        if not isinstance(uid, str) or not uid:
            raise RecoveryDenied("append UID missing")
        return "append:" + uid
    if tool == "integrity_turn_memory_close":
        return "close:" + arguments["registration_id"]
    raise RecoveryDenied("unsupported recovery operation")


def unpack(result):
    if not isinstance(result, dict):
        raise RecoveryDenied("malformed operation result")
    content = result.get("content")
    if not isinstance(content, list) or len(content) != 1:
        raise RecoveryDenied("operation result has no unique body")
    if content[0].get("type") != "text":
        raise RecoveryDenied("operation result body is not JSON")
    value = json.loads(content[0]["text"])
    if not isinstance(value, dict):
        raise RecoveryDenied("operation result is not an object")
    return value


def confirmed_result(tool, arguments, result):
    """Validate normal domain receipts; never turn an error into success."""
    value = unpack(result)
    if result.get("isError") is True:
        return False
    receipt = value.get("terminal_receipt", value.get("receipt", value))
    if not isinstance(receipt, dict):
        return False
    if tool == "integrity_turn_memory_close":
        if (receipt.get("protocol") != "integrity-guardian/turn-memory-terminal-receipt/v1"
                or receipt.get("registration_id") != arguments["registration_id"]
                or receipt.get("outcome") != arguments.get("outcome")
                or receipt.get("signature", {}).get("algorithm") != "ed25519"
                or not isinstance(receipt.get("signature", {}).get("value"), str)
                or not receipt["signature"]["value"]
                or re.fullmatch(r"sha256:[a-f0-9]{64}", str(receipt.get("receipt_id"))) is None):
            return False
        if arguments["outcome"] == "no-event":
            return receipt.get("no_event_reason") == arguments.get("no_event_reason")
        return sorted(receipt.get("events", []), key=canonical) == sorted(
            arguments.get("events", []), key=canonical)
    tags = list(dict.fromkeys([
        *(tag.strip() for tag in arguments.get("tags", [])),
        "client-workstation", "medor", "remote-append", arguments.get("kind"),
    ]))
    normalized = {"event_uid": arguments.get("event_uid"), "kind": arguments.get("kind"),
                  "summary": arguments.get("summary", "").strip(),
                  "details": arguments.get("details", {}), "tags": tags}
    return (receipt.get("protocol") == "integrity-client-memory-mcp/v3/append-receipt"
            and receipt.get("action_outcome") == "confirmed-success"
            and receipt.get("event_uid") == arguments.get("event_uid")
            and receipt.get("request_sha256") == hashlib.sha256(canonical(normalized)).hexdigest()
            and receipt.get("context_admission_id") == arguments.get("context_admission_id")
            and type(receipt.get("event_id")) is int and receipt["event_id"] > 0
            and receipt.get("witness_observer_available") is True)


def empty_context_denial(tool, result):
    """Only a definitive domain pre-write denial permits a known-unsent retry."""
    value = unpack(result)
    receipt = value.get("receipt", value)
    if not isinstance(receipt, dict) or result.get("isError") is not True:
        return False
    return (receipt.get("tool") == tool and receipt.get("outcome") == "denied"
            and receipt.get("canonical_writes") == 0
            and receipt.get("request_sent") is False
            and (receipt.get("reason_code") == "current_context_unavailable"
                 or receipt.get("failure_layer") == "context-binding"
                    and receipt.get("context_binding_state") == "empty"))


class RecoveryClient:
    """One durable operation, at most two sends across process restarts.

    connection exposes send(tool,args), status(params), recover(params), close().
    connect() opens only a private control transport, never admission/open.
    validate_own() must reread the protected current Native owner on every call.
    """
    def __init__(self, ledger, *, validate_own: Callable, connect: Callable,
                 validate_result=confirmed_result):
        self.ledger = ledger
        self.validate_own = validate_own
        self.connect = connect
        self.validate_result = validate_result
        self.trace = []

    def execute(self, tool, arguments, *, registration_id, control, connection):
        if tool not in TOOLS or set(control) != set(CONTROL_FIELDS):
            raise RecoveryDenied("operation or recovery descriptor invalid")
        original = json.loads(canonical(arguments))
        if tool.endswith("close") and original.get("registration_id") != registration_id:
            raise RecoveryDenied("foreign terminal registration")
        if tool.endswith("append_event") and original.get("context_admission_id") != control["context_admission_id"]:
            raise RecoveryDenied("foreign append admission")
        key = operation_key(tool, original)
        owner = registration_id
        self.validate_own()
        record = self.ledger.prepare(owner, key, tool, original)
        restored = False
        target = connection

        def status():
            self.validate_own()
            response = target.status({"control": control, "registration_id": registration_id,
                                      "tool": tool, "arguments": original,
                                      "request_sha256": record["request_sha256"]})
            if (response.get("protocol") != STATUS_PROTOCOL
                    or response.get("registration_id") != registration_id
                    or response.get("tool") != tool
                    or response.get("request_sha256") != record["request_sha256"]):
                raise RecoveryDenied("operation status binding mismatch")
            return response

        def committed(response):
            result = response.get("result")
            if not self.validate_result(tool, original, result):
                raise RecoveryDenied("unverified operation receipt")
            prior = self.ledger.get(owner, key)
            if prior["state"] == "committed":
                # Preserve the original delivered receipt. A witness-based
                # reconciliation may have different observation timestamps.
                old = unpack(prior["receipt"])
                new = unpack(result)
                old = old.get("terminal_receipt", old.get("receipt", old))
                new = new.get("terminal_receipt", new.get("receipt", new))
                fields = ("receipt_id",) if tool.endswith("close") else (
                    "event_id", "event_uid", "request_sha256", "context_admission_id")
                if any(old.get(field) != new.get(field) for field in fields):
                    raise RecoveryDenied("committed operation reference changed")
                self.trace.append("confirmed-cached-receipt")
                return prior["receipt"]
            self.ledger.mark(owner, key, "committed", receipt=result)
            self.trace.append("confirmed-by-status")
            return result

        def reconnect():
            nonlocal target
            try:
                target.close()
            finally:
                target = self.connect()
            self.trace.append("control-reconnected")

        def restore():
            nonlocal restored
            self.validate_own()
            response = target.recover({**control, "registration_id": registration_id})
            if (response.get("protocol") != RECOVERY_PROTOCOL
                    or response.get("restored") is not True
                    or response.get("same_session") is not True
                    or response.get("read_only") is not False
                    or response.get("canonical_writes") != 0
                    or response.get("action_authority") is not False
                    or response.get("registration_id") != registration_id
                    or any(response.get(field) != control[field] for field in CONTROL_FIELDS)):
                raise RecoveryDenied("same-session restoration proof mismatch")
            self.validate_own()
            restored = True
            self.trace.append("same-session-restored")

        if record["state"] in {"unknown", "sending", "committed"} or getattr(target, "requires_restore", False):
            try:
                observed = status()
            except DeliveryFault:
                reconnect()
                observed = status()
            if observed.get("state") == "committed":
                return committed(observed)
            is_fresh = record["state"] in {"prepared", "known-unsent"}
            if observed.get("state") != "absent-authoritative" or (not is_fresh and observed.get("replay_safe") is not True):
                raise DeliveryPending("previous operation has no safe authoritative replay proof")
            # A prior process may have died after PREPARE/SENDING. The backend
            # must promise atomic dedup, because its old request may still run.
            if record["state"] == "committed":
                raise RecoveryDenied("server cannot lose a previously committed operation")
            if record["state"] == "sending":
                self.ledger.mark(owner, key, "unknown", expected_state="sending")
            if not is_fresh:
                self.ledger.mark(owner, key, "reconciled-absent", expected_state="unknown")
            restore()
        elif record["state"] == "blocked":
            raise DeliveryPending("operation remains blocked for explicit reconciliation")

        while True:
            self.validate_own()
            record = self.ledger.claim_send(owner, key, max_attempts=2)
            self.trace.append("dispatch:" + str(record["attempts"]))
            try:
                result = target.send(tool, json.loads(canonical(original)))
            except DeliveryFault as error:
                state = "unknown" if error.request_sent else "known-unsent"
                self.ledger.mark(owner, key, state)
                if not error.retryable:
                    raise DeliveryPending("non-retryable transport failure") from error
                reconnect()
                if error.request_sent:
                    observed = status()
                    if observed.get("state") == "committed":
                        return committed(observed)
                    if (observed.get("state") != "absent-authoritative"
                            or observed.get("replay_safe") is not True):
                        raise DeliveryPending("sent operation remains unresolved; no blind replay")
                    self.ledger.mark(owner, key, "reconciled-absent", expected_state="unknown")
                if restored:
                    raise DeliveryPending("same-session recovery bound reached")
                restore()
                continue
            if self.validate_result(tool, original, result):
                self.ledger.mark(owner, key, "committed", receipt=result)
                self.trace.append("confirmed-by-send")
                return result
            if empty_context_denial(tool, result) and not restored:
                self.ledger.mark(owner, key, "known-unsent")
                restore()
                continue
            # The RPC arrived, but its result does not prove commit or absence.
            # Preserve its outcome; do not manufacture a terminal classification.
            self.ledger.mark(owner, key, "unknown")
            if result.get("isError") is not True:
                # Legacy duplicate receipts omit the observer flag. Their
                # canonical effect still needs an authoritative witness read.
                try:
                    observed = status()
                    if observed.get("state") == "committed":
                        return committed(observed)
                except DeliveryFault:
                    pass  # Keep UNKNOWN and return the unmodified domain result.
            return result
