"""Opt-in adapter for the canonical Windows broker, no public tool changes.

The original owner factory, Native head, registration content checks, and
external-outcome close guard are kept. Recovery capability is negotiated on the
authenticated transport; model tool arguments cannot select a route or a path.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


def install(namespace, recovery, ledger_module):
    Broker = namespace["TurnBroker"]
    BrokerError = namespace["BrokerError"]
    envelope = namespace["turn_envelope"]
    old_resume = Broker._ensure_delivered_context_resume
    old_lifecycle = Broker._standalone_turn_memory_call

    def capable(target):
        caps = getattr(target, "_same_session_capabilities", {})
        resume = caps.get("integrity/session-recovery", {})
        status = caps.get("integrity/operation-status", {
            "protocol": resume.get("operation_status_protocol"),
            "method": resume.get("operation_status_method"),
        })
        return (resume.get("protocol") == recovery.RECOVERY_PROTOCOL
                and resume.get("method") == "integrity/session_recover"
                and status.get("protocol") == recovery.STATUS_PROTOCOL
                and status.get("method") == "integrity/operation_status")

    def _own(broker, tool=None, arguments=None, expected=None):
        payload = envelope.load_context_resume()
        if payload is None or expected is not None and payload != expected:
            raise recovery.RecoveryDenied("current delivered descriptor unavailable or superseded")
        identity = envelope._resume_identity()
        state = envelope._resume_read_state(identity)
        binding = payload["binding"]
        registration = state.get("turn_memory_registration_id")
        if not broker._own_registration_content(state, binding):
            raise recovery.RecoveryDenied("current signed registration does not join descriptor")
        if arguments is not None:
            if tool == "integrity_turn_memory_close" and arguments.get("registration_id") != registration:
                raise recovery.RecoveryDenied("terminal owner mismatch")
            if tool == "integrity_append_event" and arguments.get("context_admission_id") != binding["context_admission_id"]:
                raise recovery.RecoveryDenied("append owner mismatch")
        return payload, registration

    def own(broker, tool=None, arguments=None, expected=None):
        try:
            return _own(broker, tool, arguments, expected)
        except (OSError, ValueError, KeyError, TypeError, AttributeError,
                envelope.TurnEnvelopeError):
            raise recovery.RecoveryDenied("protected current owner unavailable") from None

    def custody_path():
        base = envelope._owning_state_root()
        if not base.is_dir():
            raise recovery.RecoveryDenied("existing owning state directory required")
        for member in (base, *base.parents):
            info = member.lstat()
            if member.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                raise recovery.RecoveryDenied("owning state custody changed")
        # Parent is the existing protected broker state; no fallback directory,
        # model path, credentials, or replay-control secret is stored here.
        return base/"same-session-operations.sqlite3"

    def remember_open(broker, arguments, result):
        """Keep the exact authenticated response, never synthesize a denial class."""
        broker._session_recovery_open = None
        try:
            value = recovery.unpack(result)
            receipt = value["receipt"]
            marker = value["session_recovery"]
            binding = broker._own_turn_binding
            if (result.get("isError") is True or not isinstance(binding, dict)
                    or binding.get("admitted") is not True
                    or marker.get("available") is not False
                    or marker.get("protocol") != recovery.RECOVERY_PROTOCOL
                    or marker.get("reason") != "admission-not-retained"
                    or marker.get("canonical_registration_unchanged") is not True
                    or marker.get("registration_id") != receipt.get("receipt_id")
                    or receipt.get("protocol") != "integrity-guardian/turn-memory-registration/v1"
                    or receipt.get("identity") != {k: arguments[k] for k in
                        ("machine_id", "thread_id", "turn_id", "intent_id")}
                    or receipt.get("prompt_sha256") != arguments.get("prompt_sha256")):
                return
            broker._session_recovery_open = {"receipt": json.loads(json.dumps(receipt)),
                "binding": dict(binding), "transport": broker.upstream}
        except (KeyError, ValueError, TypeError, AttributeError):
            return

    def ordinary_current(broker, tool, arguments):
        """Only a proven current open may opt out before sending anything.

        Missing, corrupt or stale recovery evidence is never this opt-out.
        Reconnection invalidates it; possibly sent operations use the ordinary
        broker's unchanged uncertainty guard and can never cross into recovery.
        """
        proof = getattr(broker, "_session_recovery_open", None)
        if proof is None:
            return False
        binding = broker._own_turn_binding
        if (not broker.bound or proof["transport"] is not broker.upstream
                or proof["binding"] != binding):
            raise recovery.RecoveryDenied("non-retained admission is no longer current")
        def protected_read(phase, read):
            try:
                return read()
            except (OSError, ValueError, KeyError, TypeError, envelope.TurnEnvelopeError) as error:
                error.integrity_failure_phase = phase
                raise

        # This call still validates any existing protected descriptor; a broken
        # descriptor raises and cannot be silently downgraded to ordinary mode.
        if protected_read("resume-descriptor", envelope.load_context_resume) is not None:
            raise recovery.RecoveryDenied("non-retained admission conflicts with recovery proof")
        identity = protected_read("owner-identity", envelope._resume_identity)
        state = protected_read("owner-state", lambda: envelope._resume_read_state(identity))
        hashes = binding.get("hashes", {})

        def owner_join(current):
            if (not broker._own_registration_content(current, binding)
                    or hashes.get("thread_id") != hashlib.sha256(identity.encode()).hexdigest()
                    or hashes.get("turn_id") != hashlib.sha256(str(current.get("turn_id", "")).encode()).hexdigest()
                    or hashes.get("machine_id") != hashlib.sha256(envelope._machine_id().encode()).hexdigest()
                    or current.get("turn_memory_registration_receipt") != proof["receipt"]
                    or current.get("turn_memory_terminal_receipt_id") is not None
                    or current.get("turn_memory_status") != "open"
                    or current.get("turn_memory_generation") != binding.get("generation")
                    or current.get("turn_memory_intent_id") != binding.get("intent_id")
                    or current.get("model_mcp_admission_status") != "ready"
                    or current.get("model_mcp_context_admission_id") != binding.get("context_admission_id")
                    or current.get("prompt_sha256") != binding.get("prompt_sha256")
                    or envelope._ref_digest(current.get("turn_ref", "")) != binding.get("turn_ref_digest")):
                raise recovery.RecoveryDenied("non-retained current owner proof changed")
            # Keep the complete registration and authority-relevant join, while
            # allowing compaction/observer diagnostics to advance independently.
            return json.dumps({key: current.get(key) for key in (
                "turn_id", "turn_memory_registration_id", "turn_memory_registration_receipt",
                "turn_memory_namespace_fingerprint", "turn_memory_terminal_receipt_id",
                "turn_memory_status", "turn_memory_generation", "turn_memory_intent_id",
                "model_mcp_admission_status", "model_mcp_context_admission_id",
                "prompt_sha256", "turn_ref")}, sort_keys=True, allow_nan=False)

        before = owner_join(state)
        head = protected_read("native-head", lambda: envelope._native_owning_head(identity))
        after_identity = protected_read("owner-identity-recheck", envelope._resume_identity)
        after = protected_read("owner-state-recheck", lambda: envelope._resume_read_state(identity))
        if (identity != after_identity or before != owner_join(after)
                or not broker.bound or proof["transport"] is not broker.upstream
                or proof["binding"] != broker._own_turn_binding
                or protected_read("resume-descriptor-recheck", envelope.load_context_resume) is not None
                or not isinstance(head, dict) or head.get("id") != after.get("turn_id")
                or head.get("status") != "inProgress"):
            raise recovery.RecoveryDenied("non-retained current owner proof changed")
        registration = proof["receipt"]["receipt_id"]
        if ((tool == "integrity_turn_memory_close" and arguments.get("registration_id") != registration)
                or (tool == "integrity_append_event" and
                    arguments.get("context_admission_id") != binding.get("context_admission_id"))):
            raise recovery.RecoveryDenied("non-retained operation owner mismatch")
        return True

    def safe_failure(error, message, broker):
        failure = BrokerError(message + type(error).__name__, layer="broker-safe-operation",
            request_sent=possibly_sent(broker), retryable=False)
        phases = {"resume-descriptor", "owner-identity", "owner-state", "native-head",
                  "owner-identity-recheck", "owner-state-recheck", "resume-descriptor-recheck"}
        phase = getattr(error, "integrity_failure_phase", None)
        code = getattr(error, "integrity_failure_code", None)
        failure.diagnostic = {"protocol": "integrity-client/safe-operation-diagnostic/v1",
            "phase": phase if phase in phases else "safe-operation",
            "failure_code": code if code == "native-read-unavailable" else "protected-evidence-unavailable"}
        return failure

    class Connection:
        def __init__(self, broker, target, payload, registration, *, restore_required=False):
            self.broker, self.target = broker, target
            self.payload, self.registration = payload, registration
            self.requires_restore = restore_required

        def _request(self, method, arguments):
            try:
                return self.target.request(method, arguments,
                    timeout=namespace["CONTEXT_ADMISSION_REPLAY_CONTROL_TIMEOUT_SECONDS"])
            except BrokerError as error:
                raise recovery.DeliveryFault(request_sent=error.request_sent,
                                             retryable=error.retryable) from None

        def send(self, tool, arguments):
            try:
                return self.target.call_tool(tool, arguments)
            except BrokerError as error:
                raise recovery.DeliveryFault(request_sent=error.request_sent,
                                             retryable=error.retryable) from None

        def status(self, arguments):
            return self._request("integrity/operation_status", arguments)

        def recover(self, arguments):
            own(self.broker, expected=self.payload)
            result = self._request("integrity/session_recover", arguments)
            if (result.get("protocol") != recovery.RECOVERY_PROTOCOL
                    or result.get("restored") is not True
                    or result.get("same_session") is not True
                    or result.get("read_only") is not False
                    or result.get("action_authority") is not False
                    or result.get("canonical_writes") != 0
                    or result.get("registration_id") != self.registration
                    or any(result.get(field) != self.payload["control"][field]
                           for field in recovery.CONTROL_FIELDS)):
                raise recovery.RecoveryDenied("private recovery receipt mismatched")
            own(self.broker, expected=self.payload)
            self.broker.upstream = self.target
            self.broker.bound = True
            self.broker._own_turn_binding = dict(self.payload["binding"])
            self.broker._context_reattach_read_only = False
            self.requires_restore = False
            return result

        def close(self):
            self.target.close()
            if self.broker.upstream is self.target:
                self.broker.upstream = None
                self.broker.bound = False

    def execute(broker, tool, arguments):
        payload, registration = own(broker, tool, arguments)
        target = broker.upstream
        if not capable(target):
            raise recovery.RecoveryDenied("safe recovery/status contract not negotiated")
        outbox = ledger_module.OperationLedger(custody_path())
        broker._safe_active_operation = (outbox, registration,
                                         recovery.operation_key(tool, arguments))

        def validate():
            own(broker, tool, arguments, expected=payload)
            claims = getattr(broker, "_consumed_owning_lifecycle_claims", None)
            if tool == "integrity_turn_memory_close":
                if claims is not None:
                    envelope.revalidate_consumed_own_lifecycle(claims, tool, arguments)
                else:
                    broker._check_own_lifecycle(tool, arguments)
                namespace["_local_routes"].guard_close(arguments, payload["binding"],
                    envelope._owning_state_root())

        def connect():
            target = broker._new_upstream(None, context_control_only=True)
            if not capable(target):
                target.close()
                raise recovery.RecoveryDenied("replacement transport lost recovery contract")
            # Keep even a detached read-only status transport under broker
            # ownership. A lost-close ACK must not leave an orphan process.
            broker.upstream = target
            broker.bound = False
            return Connection(broker, target, payload, registration, restore_required=True)

        client = recovery.RecoveryClient(outbox, validate_own=validate, connect=connect)
        return client.execute(tool, arguments, registration_id=registration,
            control=payload["control"], connection=Connection(broker, target, payload,
                registration, restore_required=not broker.bound))

    def _resume(broker):
        if broker.upstream is not None and broker.bound and not broker._context_reattach_read_only:
            return
        payload = envelope.load_context_resume()
        if payload is None:
            return old_resume(broker)
        payload, registration = own(broker, expected=payload)
        target = broker.upstream
        created = target is None or target.process.poll() is not None
        if created:
            target = broker._new_upstream(None, context_control_only=True)
        if not capable(target):
            if created:
                target.close()
            return old_resume(broker)
        if created:
            broker.upstream = target
            broker.bound = False
        # This path recovers no append/close and changes no canonical record.
        Connection(broker, target, payload, registration).recover(
            {**payload["control"], "registration_id": registration})

    def resume(broker):
        try:
            return _resume(broker)
        except (recovery.RecoveryDenied, recovery.DeliveryFault, OSError,
                ValueError, KeyError, TypeError, envelope.TurnEnvelopeError):
            raise BrokerError("same-session resume unavailable",
                layer="broker-safe-context-recovery", request_sent=False,
                retryable=False) from None

    def possibly_sent(broker):
        active = getattr(broker, "_safe_active_operation", None)
        if active is None:
            return False
        try:
            outbox, registration, key = active
            record = outbox.get(registration, key)
            return record is not None and record["state"] in {"sending", "unknown", "committed", "reconciled-absent"}
        except ledger_module.LedgerError:
            return True

    def reliable_append(broker, tool, arguments):
        if tool != "integrity_append_event" or not capable(broker.upstream):
            return broker.upstream.call_tool(tool, arguments)
        broker._safe_active_operation = None
        try:
            if ordinary_current(broker, tool, arguments):
                return broker.upstream.call_tool(tool, arguments)
            return execute(broker, tool, arguments)
        except (recovery.RecoveryDenied, recovery.DeliveryPending,
                recovery.DeliveryFault, ledger_module.LedgerError,
                OSError, ValueError, KeyError, TypeError, envelope.TurnEnvelopeError) as error:
            raise safe_failure(error, "safe operation recovery incomplete: ", broker) from None

    def _lifecycle(broker, tool, arguments):
        if tool == "integrity_turn_memory_open":
            result = old_lifecycle(broker, tool, arguments)
            remember_open(broker, arguments, result)
            return result
        if tool != "integrity_turn_memory_close" or broker._owning_hook_lifecycle_ref is not None:
            return old_lifecycle(broker, tool, arguments)
        # Protected factory callers retain their original isolated, one-use path.
        # Current admitted callers may negotiate recovery without new admission.
        target = broker.upstream
        if target is not None and capable(target) and ordinary_current(broker, tool, arguments):
            return old_lifecycle(broker, tool, arguments)
        if target is None:
            payload = envelope.load_context_resume()
            if payload is None:
                return old_lifecycle(broker, tool, arguments)
            own(broker, tool, arguments, expected=payload)
            target = broker._new_upstream(None, context_control_only=True)
            if not capable(target):
                target.close()
                return old_lifecycle(broker, tool, arguments)
            broker.upstream = target
        if not capable(target):
            return old_lifecycle(broker, tool, arguments)
        broker._consumed_owning_lifecycle_claims = None
        broker._check_own_lifecycle(tool, arguments)
        return execute(broker, tool, arguments)

    def lifecycle(broker, tool, arguments):
        broker._safe_active_operation = None
        try:
            return _lifecycle(broker, tool, arguments)
        except (recovery.RecoveryDenied, recovery.DeliveryPending,
                recovery.DeliveryFault, ledger_module.LedgerError,
                OSError, ValueError, KeyError, TypeError, envelope.TurnEnvelopeError) as error:
            raise safe_failure(error, "safe lifecycle recovery incomplete: ", broker) from None

    Broker._ensure_delivered_context_resume = resume
    Broker._standalone_turn_memory_call = lifecycle
    Broker._same_session_mutation = reliable_append
