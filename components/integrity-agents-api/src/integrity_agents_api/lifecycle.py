"""Bounded lifecycle operations. Provider state never becomes canonical truth."""
from __future__ import annotations

from .contracts import (MAX_BYTES, SCHEMA, Rejected, Unknown, aggregate_usage, decode, digest,
                        encode, frozen, identifier, keys, need, number, sha, validate_arguments)
from .journal import Journal
from .transport import GuardianGate, Request

FINAL = frozenset({"completed", "failed", "cancelled", "incomplete"})


def reconcile(session_id: str, items: list[dict], turns: list[dict], buffered: list[dict]) -> dict:
    """Use persisted items, then bounded buffered updates; never replay a missed call."""
    identifier(session_id)
    need(len(items) <= 4096 and len(turns) <= 4096 and len(buffered) <= 1024, "recovery_limit")
    saved, seen_events, roots, unsupported = {}, {}, {}, []
    for item in items:
        key = identifier(item["id"])
        need(key not in saved, "duplicate_saved_item")
        saved[key] = frozen(item)
    for turn in turns:
        key = identifier(turn["id"])
        need(key not in roots, "duplicate_turn")
        need(type(turn.get("status")) is str, "turn_status_missing")
        roots[key] = frozen(turn)
    for event in buffered:
        encode(event)
        need(event.get("session_id") == session_id, "foreign_event")
        key = identifier(event["event_id"])
        fingerprint = sha(encode(event))
        if key in seen_events:
            need(seen_events[key] == fingerprint, "event_identity_conflict")
            continue
        seen_events[key] = fingerprint
        typ = event.get("type")
        if typ in ("agent.session.turn.item.added", "agent.session.turn.item.done"):
            item = event["item"]
            key = identifier(item["id"])
            # Persisted terminal items cannot be downgraded or replaced by stale stream data.
            if key in saved and saved[key].get("status") in FINAL:
                if item.get("status") in FINAL:
                    need(encode(saved[key]) == encode(item), "conflicting_terminal_item")
            else:
                saved[key] = frozen(item)
        elif typ in ("agent.session.turn.completed", "agent.session.turn.failed",
                     "agent.session.turn.cancelled", "agent.session.turn.started"):
            turn = event["turn"]
            key = identifier(turn["id"])
            need("subagent_id" in turn, "turn_attribution_missing")
            expected = typ.rsplit(".", 1)[1]
            need((turn.get("status") not in FINAL) if expected == "started"
                 else turn.get("status") == expected, "event_turn_status_mismatch")
            if key in roots and roots[key].get("status") in FINAL:
                if turn.get("status") in FINAL:
                    prior_identity = {k: v for k, v in roots[key].items() if k != "usage"}
                    next_identity = {k: v for k, v in turn.items() if k != "usage"}
                    need(encode(prior_identity) == encode(next_identity), "conflicting_terminal_turn")
            else:
                roots[key] = frozen(turn)
        elif typ in ("agent.session.idle", "agent.session.requires_action", "agent.session.created",
                     "agent.session.environment.connected", "agent.session.environment.pending",
                     "agent.session.environment.failed", "agent.session.turn.output_text.delta",
                     "agent.session.turn.output_text.done", "agent.session.subagent.created"):
            pass  # Hints only; do not manufacture complete text, authority or environment custody.
        else:
            unsupported.append(key)
    # Include missing subagent attribution as unknown rather than assuming a root agent.
    root_turns = [t for t in roots.values() if "subagent_id" in t and t["subagent_id"] is None]
    return {"schema": "integrity-agents-projection/v1", "session_id": session_id,
            "items": list(saved.values()), "turns": list(roots.values()),
            "root_turn_ids": [t["id"] for t in root_turns],
            "active_or_unknown_turns": [t["id"] for t in roots.values() if t["status"] not in FINAL or "subagent_id" not in t],
            "unsupported_events": unsupported, "missed_events_replayed": False,
            "provider_report_only": True, "independent_outcome_verified": False,
            "canonical_completion_recorded": False}


class Sessions:
    """No daemon and no automatic model loop. Each mutation is an explicit bounded step."""
    def __init__(self, transport, journal: Journal, configuration: dict, catalog: list[dict]):
        self.transport, self.journal = transport, journal
        self._configuration_bytes = encode(configuration)
        self.configuration_sha256 = sha(self._configuration_bytes)
        self._catalog_bytes = encode(catalog)
        self.catalog_sha256 = sha(self._catalog_bytes)
        capsule = decode(self.configuration["input"].encode("utf-8"))
        self._task_ref = identifier(capsule["task_ref"])
        self._tools = {}
        for tool in self.catalog:
            if tool["wire"]["type"] == "function":
                name = identifier(tool["wire"]["name"])
                need(name not in self._tools, "duplicate_function")
                self._tools[name] = tool["wire"]
        configured = [x for x in self.configuration["agent"]["tools"] if x["type"] == "function"]
        need(sorted(configured, key=lambda x: x["name"]) ==
             sorted(self._tools.values(), key=lambda x: x["name"]), "catalog_configuration_mismatch")

    @property
    def configuration(self) -> dict:
        """Detached readback of the exact request bytes bound at construction."""
        return decode(self._configuration_bytes)

    @property
    def catalog(self) -> list[dict]:
        return decode(self._catalog_bytes)

    @staticmethod
    def _is_required(action: dict, snapshot: dict) -> bool:
        wanted = encode(action)
        return any(encode(candidate) == wanted for candidate in snapshot.get("required_actions", []))

    def _bound(self, session: str):
        row = self.journal.require_session(session)
        need(row[1] == self.configuration_sha256, "foreign_session_configuration")
        return "/v1/agents/sessions/" + session

    def start(self, operation_id: str, task_ref: str, reserve_microusd: int) -> dict:
        identifier(task_ref)
        need(task_ref == self._task_ref, "task_capsule_binding_mismatch")
        number(reserve_microusd, 1)
        request = Request("POST", "/v1/agents/sessions", self._configuration_bytes)
        pending_scope = "create-" + sha(encode([operation_id, task_ref])).split(":", 1)[1]
        def send():
            response = self.transport.send(request)
            session = identifier(response["id"])
            environment = response.get("environment")
            env_id = None if environment is None else identifier(environment["id"])
            # Never retain remote_url, credentials, prompts or raw provider response.
            return encode({"id": session, "environment_id": env_id})
        result = decode(self.journal.run_once(operation_id, {
            "request": request.descriptor(self.journal.namespace), "task_ref": task_ref}, send,
            reserve_microusd=reserve_microusd, usage_scope=pending_scope))
        self.journal.bind_session(result["id"], task_ref, self.configuration_sha256, result["environment_id"])
        self.journal.attach_usage(pending_scope, result["id"])
        return result

    def snapshot(self, session: str) -> dict:
        result = self.transport.send(Request("GET", self._bound(session)))
        need(result.get("id") == session, "session_response_identity")
        need(type(result.get("required_actions", [])) is list, "required_actions_shape")
        return frozen(result)

    def environment_state(self, session: str) -> dict:
        self._bound(session)
        environment_id = self.journal.require_session(session)[2]
        if environment_id is None:
            return {"type": "none", "execution_environment_present": False}
        result = self.transport.send(Request("GET", "/v1/agents/environments/" + environment_id))
        need(result.get("id") == environment_id, "environment_identity_mismatch")
        return {"id": environment_id, "provider_status": result.get("status", "unknown"),
                "filesystem_restored": False, "execution_custody_verified": False,
                "automatic_reprovision": False}

    def pages(self, session: str, collection: str) -> list[dict]:
        need(collection in ("items", "turns"), "unsupported_collection")
        base = self._bound(session) + "/" + collection + "?order=asc&limit=100"
        cursor, cursors, result, ids = "", set(), [], set()
        for _ in range(20):
            page = self.transport.send(Request("GET", base + ("&after=" + cursor if cursor else "")))
            need(type(page.get("data")) is list and type(page.get("has_more")) is bool, "page_shape")
            need(len(page["data"]) <= 100, "page_limit")
            for item in page["data"]:
                key = identifier(item["id"])
                need(key not in ids, "duplicate_paginated_item")
                ids.add(key)
                result.append(frozen(item))
            need(len(encode(result)) <= MAX_BYTES, "history_bytes")
            if not page["has_more"]:
                return result
            need(bool(page["data"]), "empty_nonterminal_page")
            cursor = identifier(page["last_id"])
            need(cursor == page["data"][-1]["id"] and cursor not in cursors, "cursor_conflict")
            cursors.add(cursor)
        raise Unknown("history_page_limit_no_partial_success")

    def recover(self, session: str, buffered_events: list[dict] | None = None) -> dict:
        # A host that needs live UI continuity opens transport.stream first and
        # buffers events. Poll-only recovery never claims replay or atomic snapshots.
        usage_scope, usage_epoch = self.journal.usage_checkpoint()
        first = self.snapshot(session)
        items, turns = self.pages(session, "items"), self.pages(session, "turns")
        last = self.snapshot(session)
        def boundary(snapshot):
            return {key: snapshot.get(key) for key in ("id", "status", "required_actions", "environment")}
        need(encode(boundary(first)) == encode(boundary(last)), "session_changed_during_recovery")
        projection = reconcile(session, items, turns, buffered_events or [])
        projection["required_actions"] = last.get("required_actions", [])
        projection["provider_status"] = last.get("status", "unknown")
        projection["atomic_provider_snapshot"] = False
        usage = aggregate_usage(turns)
        settled = (usage["complete_observation"] and projection["provider_status"] == "idle"
                   and not projection["required_actions"]
                   and not projection["active_or_unknown_turns"]
                   and not projection["unsupported_events"])
        projection["usage_observation_applied"] = (usage_scope == session and
            self.journal.usage_observed(settled, session=session, expected_epoch=usage_epoch))
        projection["usage"] = usage
        return projection

    def _post_events(self, operation_id: str, session: str, events: list[dict], *, reserve: int = 0):
        request = Request("POST", self._bound(session) + "/events", encode({"events": events}))
        def send():
            self.transport.send(request)
            return encode({"provider_acknowledged_request": True, "operation_completed": False})
        return decode(self.journal.run_once(operation_id, request.descriptor(self.journal.namespace),
                                           send, reserve_microusd=reserve, usage_scope=session))

    def message(self, operation_id: str, session: str, capsule: dict, reserve_microusd: int) -> dict:
        number(reserve_microusd, 1)
        # Caller supplies another reviewed digest-bound capsule, never complete memory by default.
        from .contracts import context_capsule
        capsule = context_capsule(capsule["task_ref"], capsule["snapshot_sha256"], capsule["extracts"])
        need(capsule["task_ref"] == self.journal.require_session(session)[0], "task_binding")
        return self._post_events(operation_id, session, [{"type": "agent.session.input.message",
            "input": [{"role": "user", "content": [{"type": "input_text", "text": encode(capsule).decode()}]}]}],
            reserve=reserve_microusd)

    def cancel(self, operation_id: str, session: str) -> dict:
        return self._post_events(operation_id, session, [{"type": "agent.session.input.cancel"}])

    def watchdog_tick(self, operation_id: str, session: str, *, now: int, deadline: int) -> dict:
        number(now)
        number(deadline)
        if now >= deadline:
            return self.cancel(operation_id, session)
        return {"cancel_requested": False, "provider_execution_stopped": False}

    def _call(self, session: str, action: dict) -> tuple[str, dict]:
        self._bound(session)
        keys(action, {"type", "turn_id", "call_id", "name", "arguments"})
        need(action["type"] == "function_call", "function_required")
        identifier(action["turn_id"])
        identifier(action["call_id"])
        need(action["name"] in self._tools, "unregistered_tool")
        validate_arguments(self._tools[action["name"]]["parameters"], action["arguments"])
        document = {"session": session, "action": frozen(action), "catalog_sha256": self.catalog_sha256}
        key = sha(encode([session, action["turn_id"], action["call_id"]])).replace(":", "-")
        return key, document

    def execute_function(self, session: str, action: dict, handler, gate: GuardianGate) -> dict:
        action = frozen(action)
        key, document = self._call(session, action)
        snapshot = self.snapshot(session)
        need(self._is_required(action, snapshot), "call_not_currently_required")
        need(type(gate) is GuardianGate, "sdk_function_gate_required")
        descriptor = {"schema": SCHEMA, "namespace": self.journal.namespace,
                      "operation": "function " + action["name"], "input_sha256": sha(encode(document))}
        def execute():
            result = gate.invoke(descriptor, lambda: handler(frozen(action["arguments"])))
            text = encode(result, 32768).decode("utf-8")
            return encode({"type": "agent.session.input.tool_result", "turn_id": action["turn_id"],
                           "call_id": action["call_id"], "success": True, "output": text})
        return decode(self.journal.run_once(key, document, execute))

    def submit_retained_result(self, operation_id: str, session: str, action: dict) -> dict:
        action = frozen(action)
        key, document = self._call(session, action)
        need(self._is_required(action, self.snapshot(session)), "result_not_pending")
        # A pure read: absent output must not poison the real execution identity.
        event = decode(self.journal.retained(key, document))
        return self._post_events(operation_id, session, [event])

    def delete(self, operation_id: str, session: str, exported_evidence_sha256: str) -> dict:
        digest(exported_evidence_sha256)
        need(self.journal.unresolved() == 0, "unresolved_operations_block_delete")
        view = self.recover(session)
        need(view["provider_status"] == "idle" and not view["required_actions"]
             and not view["active_or_unknown_turns"] and not view["unsupported_events"],
             "active_delete_rejected")
        request = Request("DELETE", self._bound(session))
        def execute():
            result = self.transport.send(request)
            need(result.get("id") == session and result.get("deleted") is True, "delete_unconfirmed")
            return encode({"provider_session_deleted": True, "canonical_evidence_deleted": False})
        return decode(self.journal.run_once(operation_id, {
            "request": request.descriptor(self.journal.namespace),
            "exported_evidence_sha256": exported_evidence_sha256}, execute))

    def handoff_candidate(self, session: str, next_executor: str, snapshot_sha256: str) -> dict:
        identifier(next_executor)
        digest(snapshot_sha256)
        need(self.journal.unresolved() == 0, "unresolved_handoff")
        view = self.recover(session)
        need(view["provider_status"] == "idle" and not view["required_actions"]
             and not view["active_or_unknown_turns"] and not view["unsupported_events"], "active_handoff")
        return {"schema": "integrity-executor-handoff-candidate/v1", "from_session": session,
                "to_executor": next_executor, "canonical_snapshot_sha256": snapshot_sha256,
                "task_ref": self.journal.require_session(session)[0],
                "context_source": "canonical_integrity_snapshot_not_provider_summary",
                "executed": False, "requires_existing_owner_guard_and_observer": True}
