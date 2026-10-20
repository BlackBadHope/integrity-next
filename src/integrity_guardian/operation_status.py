"""Private operation reconciliation + derived request custody, source candidate.

Canonical append mutation stays in the existing Action Log. Its unique UID
constraint must be verified separately before absence can permit append retry.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
from .operation_ledger import OperationLedger, Conflict, LedgerError, canonical_request, request_digest

PROTOCOL = "integrity-client/operation-status/v1"
METHOD = "integrity/operation_status"
APPEND_SOURCE_SHA256 = "8e144fe559445d34caa05fe9a0a5d633468b636e1fd23e414a952a10d6c8293a"


class AtomicAppendDedup:
    """Server-configured exact source + live schema predicate, never model input.

    Custodian must additionally bind this source to the running service. This
    class alone proves file/schema parity, not process/deployment provenance.
    """
    def __init__(self, source_path, database_path, *, service_source_verified=False):
        self.source_path, self.database_path = Path(source_path), Path(database_path)
        self.service_source_verified = service_source_verified is True

    def verified(self):
        if not self.service_source_verified: return False
        if (not self.source_path.is_absolute() or not self.database_path.is_absolute()
                or self.source_path.is_symlink() or self.database_path.is_symlink()
                or hashlib.sha256(self.source_path.read_bytes()).hexdigest() != APPEND_SOURCE_SHA256):
            return False
        db = sqlite3.connect(self.database_path.as_uri() + "?mode=ro", uri=True, timeout=2)
        try:
            db.execute("PRAGMA query_only=ON")
            rows = db.execute("PRAGMA index_list(events)").fetchall()
            found = next((r for r in rows if r[1] == "idx_events_event_uid"), None)
            if found is None or found[2] != 1 or found[4] != 1: return False
            info = db.execute("PRAGMA index_info(idx_events_event_uid)").fetchall()
            if len(info) != 1 or info[0][2] != "event_uid": return False
            sql = db.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_events_event_uid'").fetchone()[0]
            normalized = " ".join(sql.lower().replace("if not exists ", "").split())
            if normalized != "create unique index idx_events_event_uid on events(event_uid) where event_uid <> ''": return False
            triggers = dict(db.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name='events'"))
            expected = {
                "events_append_only_no_update": "create trigger events_append_only_no_update before update on events begin select raise(abort, 'append-only action log: update forbidden'); end",
                "events_append_only_no_delete": "create trigger events_append_only_no_delete before delete on events begin select raise(abort, 'append-only action log: delete forbidden'); end",
                "events_append_only_no_replace": "create trigger events_append_only_no_replace before insert on events when exists (select 1 from events where id = new.id or (new.event_uid <> '' and event_uid = new.event_uid)) begin select raise(abort, 'append-only action log: replace forbidden'); end",
            }
            return all(" ".join(triggers.get(k, "").lower().replace("if not exists ", "").split()) == v for k, v in expected.items())
        finally: db.close()


def _same_effect(tool, first, second):
    a, b = first.get("receipt", {}), second.get("receipt", {})
    keys = ("event_id", "event_uid", "request_sha256") if tool == "integrity_append_event" else ("receipt_id", "registration_id", "outcome")
    return all(a.get(k) is not None and a.get(k) == b.get(k) for k in keys)


class OperationStatusMixin:
    def _operation_store(self, store):
        # One verified service custody root across legacy/native Turn profiles:
        # canonical event UIDs are global and must not be reserved per profile.
        self._prepare_context_replay_custody()
        return OperationLedger(self._context_admission_replay_root.parent / "same-session-operations-v1.sqlite3")

    def _operation_binding(self, registration_id, *, allow_detached=False):
        store, registration, record = self._recovery_status_binding(registration_id)
        capsule, _ = self._recovery_capsule(registration_id, allow_terminal=True)
        if self._session_recovery_binding != registration_id and not (allow_detached and self._session_recovery_binding is None):
            raise ValueError("operation requires current own registration")
        return store, registration, record, capsule

    def _operation_call(self, name, arguments, call):
        if not self._session_recovery_enabled or name not in {"integrity_append_event", "integrity_turn_memory_close"}:
            return call(name, arguments)
        if self._session_recovery_unretained_admission is not None:
            # An explicitly unretained current registration uses the existing
            # Native path. It has neither durable replay nor retry authority.
            self._recovery_before_unretained_write(name, arguments)
            return call(name, arguments)
        # Existing same-session guard runs before capture and again in the
        # original facade call. No recovery/cached reply expands its authority.
        self._recovery_before_write(name, arguments)
        registration_id = self._session_recovery_binding
        store, registration, record, capsule = self._operation_binding(registration_id)
        if name == "integrity_append_event":
            # Exact original context echo and normal payload validation precede
            # the global UID reservation; no foreign intent can squat an UID.
            event_args, _ = self._bind_append_to_current_context(arguments)
            checked = dict(event_args); checked.pop("authority_decision", None)
            self.action_log.prepare_append(checked)
            key = "append:" + str(arguments.get("event_uid"))
        else:
            if arguments.get("registration_id") != registration_id: raise ValueError("foreign close operation")
            from .turn_memory import normalize_event_references, NO_EVENT_REASONS
            if set(arguments) - {"registration_id", "outcome", "events", "no_event_reason"}:
                raise ValueError("unknown close operation fields")
            if arguments.get("outcome") == "events":
                if arguments.get("no_event_reason") is not None: raise ValueError("mixed terminal outcomes")
                normalize_event_references(arguments.get("events") or ())
            elif arguments.get("outcome") == "no-event":
                if arguments.get("events") is not None or arguments.get("no_event_reason") not in NO_EVENT_REASONS:
                    raise ValueError("invalid no-event close operation")
            else: raise ValueError("invalid close operation outcome")
            key = "close:" + registration_id
        ledger = self._operation_store(store)
        saved = ledger.prepare(registration_id, key, name, arguments)
        if saved["state"] == "committed":
            status = self._operation_status({"control": capsule["controls"], "registration_id": registration_id,
                "tool": name, "arguments": arguments, "request_sha256": saved["request_sha256"]})
            if status["state"] == "committed": return saved["receipt"]
            raise ValueError("cached operation requires authoritative reconciliation")
        result = call(name, arguments)
        receipt = result.get("receipt", {}) if isinstance(result, dict) else {}
        committed = (isinstance(receipt.get("event_id"), int) and receipt.get("event_id", 0) > 0
            and receipt.get("action_outcome") == "confirmed-success") if name == "integrity_append_event" else (
                receipt.get("registration_id") == registration_id and receipt.get("protocol") == "integrity-guardian/turn-memory-terminal-receipt/v1")
        if committed:
            try:
                return ledger.mark(registration_id, key, "committed", receipt=result)["receipt"]
            except Conflict:
                previous = ledger.get(registration_id, key)
                if previous and previous["state"] == "committed" and _same_effect(name, previous["receipt"], result): return previous["receipt"]
                raise
            except LedgerError:
                # The action may already be committed. Preserve its real ACK;
                # the captured request + canonical witness can reconcile later.
                return result
        return result

    def _operation_status(self, arguments):
        from .memory_synapse_mcp import McpFacadeError
        fields = {"control", "registration_id", "tool", "arguments", "request_sha256"}
        if (not self._session_recovery_enabled or not self._broker_tool_surface_authenticated
                or not isinstance(arguments, dict) or set(arguments) != fields):
            raise ValueError("operation status was not negotiated")
        registration_id, tool, original = arguments["registration_id"], arguments["tool"], arguments["arguments"]
        supplied = arguments["request_sha256"]
        if supplied != request_digest(tool, original): raise ValueError("operation original request digest mismatch")
        store, registration, record, capsule = self._operation_binding(registration_id, allow_detached=True)
        if arguments["control"] != capsule["controls"]: raise ValueError("operation control binding mismatch")
        if tool == "integrity_append_event":
            if original.get("context_admission_id") != capsule["controls"]["context_admission_id"]:
                raise ValueError("operation original context mismatch")
            key = "append:" + str(original.get("event_uid"))
        elif tool == "integrity_turn_memory_close":
            if original.get("registration_id") != registration_id: raise ValueError("foreign close operation")
            key = "close:" + registration_id
        else: raise ValueError("unsupported operation status")
        result = {"protocol": PROTOCOL, "registration_id": registration_id, "tool": tool,
            "request_sha256": supplied, "state": "unknown", "replay_safe": False,
            "canonical_writes": 0, "production_authority": False}
        try:
            ledger = self._operation_store(store)
            saved = ledger.get(registration_id, key)
            if saved is not None and saved["request_sha256"] != supplied:
                return {**result, "state": "conflict"}
            if tool == "integrity_turn_memory_close":
                from .turn_memory import normalize_event_references
                terminal = store.find_terminal(registration_id)
                if terminal is None: return {**result, "state": "absent-authoritative", "replay_safe": True}
                expected = {"registration_id": registration_id, "outcome": original.get("outcome")}
                if original.get("outcome") == "events":
                    if original.get("no_event_reason") is not None: raise ValueError("mixed terminal outcomes")
                    expected["events"] = normalize_event_references(original.get("events") or ())
                elif original.get("outcome") == "no-event":
                    if "events" in original: raise ValueError("mixed terminal outcomes")
                    expected["no_event_reason"] = original.get("no_event_reason")
                else: raise ValueError("invalid terminal outcome")
                actual = {k:terminal.get(k) for k in expected}
                if actual != expected: return {**result, "state": "conflict"}
                if saved is not None and saved["state"] == "committed":
                    if saved["receipt"].get("receipt") != terminal: return {**result, "state": "conflict"}
                    return self._operation_committed_status(result, saved["receipt"], "original-server-result")
                return self._operation_committed_status(result, {"receipt": terminal, "replayed": True}, "original-signed-terminal")
            # Absence alone does not permit a send while an earlier request may
            # still be in flight. The canonical atomic UID index is mandatory.
            event_args = dict(original); event_args.pop("context_admission_id", None); event_args.pop("authority_decision", None)
            prepared = self.action_log.prepare_append(event_args)
            observed = self.action_witness.observe(event_uid=prepared["event_uid"], request_sha256=prepared["request_sha256"])
            if observed.get("status") == "collision": return {**result, "state": "conflict"}
            if observed.get("status") == "absent":
                proof = getattr(self, "_operation_atomic_append_dedup", None)
                safe = isinstance(proof, AtomicAppendDedup) and proof.verified()
                return {**result, "state": "absent-authoritative", "replay_safe": safe}
            # Existing UID/hash without own durable request capture is not proof
            # that this owner performed it. Never borrow another turn's event.
            if observed.get("status") != "exact" or saved is None: return result
            if saved["state"] == "committed":
                cached = saved["receipt"].get("receipt", {})
                if (cached.get("event_uid") != prepared["event_uid"] or cached.get("request_sha256") != prepared["request_sha256"]
                        or cached.get("event_id") != observed["event_id"] or cached.get("action_outcome") != "confirmed-success"):
                    return {**result, "state": "conflict"}
                return self._operation_committed_status(result, saved["receipt"], "original-server-result")
            witness = self.architecture.sign_passive_witness({"protocol": "integrity-client/operation-reconciliation-witness/v1", "phase": "reconciliation", **observed})
            from .memory_synapse_mcp import BRIDGE_PROTOCOL
            receipt = {"protocol": BRIDGE_PROTOCOL + "/append-receipt",
                "event_uid": prepared["event_uid"], "event_id": observed["event_id"],
                "request_sha256": prepared["request_sha256"], "action_outcome": "confirmed-success",
                "outcome": "duplicate", "route_memory": "reconcile-existing-exact-event",
                "request_sent": False, "grant_consumed": False, "automatic_retry_allowed": False,
                "passive_witness": witness, "witness_observer_available": True,
                "reconciled": True, "original_transport_receipt": False,
                "context_admission_id": original["context_admission_id"], "production_authority": False}
            return self._operation_committed_status(result, {"receipt": receipt}, "reconciled-witness")
        except (OSError, sqlite3.Error, LedgerError, McpFacadeError):
            return result

    @staticmethod
    def _operation_committed_status(base, result, source):
        from .memory_synapse_mcp import _tool_result
        return {**base, "state": "committed", "result": _tool_result(result), "result_source": source}
