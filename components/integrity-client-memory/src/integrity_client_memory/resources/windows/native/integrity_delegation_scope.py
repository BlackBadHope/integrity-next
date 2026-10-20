#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Capture a verified delegated goal through the installed original Scope engine.

The isolated selector and its special signed target stay intact. This helper
loads only its pinned embedded legacy engine, never invokes a synthetic hook
event and never creates SDK/profile authority. Its input comes from the same
owning process after the receiving adapter's Native joins. The original private
operation ledger independently pins that input before Scope is touched.
"""

from __future__ import annotations

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import ast
import base64
import hashlib
import json
import sys
import time
import types
from pathlib import Path

PROTOCOL = "integrity/delegation-scope-capture/v1"
MANAGED_SELECTOR_SHA = _integrity_value('pin_bf1b77212b80')
LEGACY_ENGINE_SHA = _integrity_value('pin_ab575f59568f')
MAX_BYTES = 1024 * 1024
MAX_OPERATIONS = 64


class ScopeCaptureError(ValueError):
    """Safe content-free code only."""


def need(value, code):
    if not value:
        raise ScopeCaptureError(code)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "scope_duplicate_json_key")
        result[key] = value
    return result


def object_json(raw):
    try:
        value = json.loads(raw, object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ScopeCaptureError("scope_json_constant_invalid")))
    except ScopeCaptureError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ScopeCaptureError("scope_json_invalid") from None
    need(isinstance(value, dict), "scope_object_required")
    return value


def _read_pinned(path, expected):
    need(isinstance(path, str) and Path(path).is_absolute(), "scope_source_path_invalid")
    try:
        actual = Path(path).resolve(strict=True)
        need(actual.is_file() and not Path(path).is_symlink(), "scope_source_not_plain")
        raw = actual.read_bytes()
    except OSError:
        raise ScopeCaptureError("scope_source_unavailable") from None
    need(isinstance(expected, str) and hashlib.sha256(raw).hexdigest() == expected, "scope_source_pin_mismatch")
    return actual, raw


def load_engine(path, expected_sha256):
    need(expected_sha256 == MANAGED_SELECTOR_SHA, "scope_selector_not_admitted")
    actual, raw = _read_pinned(path, expected_sha256)
    try:
        tree = ast.parse(raw)
        selected = {}
        for statement in tree.body:
            if not isinstance(statement, ast.Assign):
                continue
            for target in statement.targets:
                if not isinstance(target, ast.Name) or target.id not in {"LEGACY_SOURCE", "LEGACY_SHA", "TARGET_SESSION"}:
                    continue
                need(target.id not in selected, "scope_selector_assignment_ambiguous")
                value = statement.value
                if target.id == "LEGACY_SOURCE":
                    need(isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                         and isinstance(value.func.value, ast.Name) and value.func.value.id == "base64"
                         and value.func.attr == "b64decode" and len(value.args) == 1 and not value.keywords,
                         "scope_legacy_source_shape_invalid")
                    encoded = ast.literal_eval(value.args[0])
                    need(isinstance(encoded, str), "scope_legacy_source_shape_invalid")
                    selected[target.id] = base64.b64decode(encoded, validate=True)
                else:
                    selected[target.id] = ast.literal_eval(value)
        need(set(selected) == {"LEGACY_SOURCE", "LEGACY_SHA", "TARGET_SESSION"}, "scope_legacy_source_missing")
        need(selected["LEGACY_SHA"] == LEGACY_ENGINE_SHA
             and hashlib.sha256(selected["LEGACY_SOURCE"]).hexdigest() == LEGACY_ENGINE_SHA,
             "scope_legacy_source_pin_mismatch")
        need(isinstance(selected["TARGET_SESSION"], str) and bool(selected["TARGET_SESSION"]), "scope_special_target_invalid")
    except ScopeCaptureError:
        raise
    except Exception:
        raise ScopeCaptureError("scope_selector_ast_invalid") from None
    engine = types.ModuleType("integrity_delegation_original_scope_engine")
    engine.__file__ = str(actual)
    # __name__ deliberately differs from __main__; no original hook/selector
    # entrypoint or its special target/profile code is executed.
    exec(compile(selected["LEGACY_SOURCE"], str(actual), "exec"), engine.__dict__)
    return engine, selected["TARGET_SESSION"]


def load_core(config):
    actual, raw = _read_pinned(config.get("core_path"), config.get("core_sha256"))
    core = types.ModuleType("integrity_delegation_scope_private_core")
    core.__file__ = str(actual)
    exec(compile(raw, str(actual), "exec"), core.__dict__)
    return core


def _validate_owned(config, delegation, payload, core, *, now):
    need(isinstance(delegation, dict) and delegation.get("status") == "accepted"
         and delegation.get("protocol") == "integrity/delegation-codex-receiving/v1", "scope_verified_delegation_required")
    need(isinstance(payload, dict), "scope_payload_invalid")
    session = payload.get("session_id") or payload.get("sessionId") or payload.get("thread_id")
    turn = payload.get("turn_id") or payload.get("turnId")
    request = delegation.get("request")
    need(isinstance(request, dict) and isinstance(request.get("target"), dict)
         and request["target"].get("thread_id") == session
         and request["target"].get("host_id") == config.get("target_machine_id")
         and isinstance(session, str) and bool(session) and isinstance(turn, str) and bool(turn), "scope_receiving_identity_mismatch")
    operation = request.get("operation_id")
    core.parse_request(request, now=now, source_thread_id=config["source_thread_id"],
                       receiving_host_id=config["target_machine_id"], receiving_thread_id=session,
                       allowed_owner_threads=set(config["allowed_owner_threads"]))
    request_digest = core.digest(request)
    need(delegation.get("operation_id") == operation and delegation.get("request_digest") == request_digest,
         "scope_request_binding_mismatch")
    ledger = core.Ledger(config["ledger_path"])
    with ledger._db() as db:
        row = db.execute("SELECT * FROM delegation_operations WHERE operation_id=?", (operation,)).fetchone()
        need(row is not None and row["state"] == "executing" and row["request_digest"] == request_digest
             and json.loads(row["request_json"]) == request, "scope_owned_operation_not_current")
        need(db.execute("SELECT 1 FROM delegation_revocations WHERE operation_id=?", (operation,)).fetchone() is None,
             "scope_operation_revoked")
        delivery = json.loads(row["delivery_json"] or "null")
        binding = json.loads(row["binding_json"] or "null")
        need(isinstance(delivery, dict) and delivery.get("target_thread_id") == session
             and delivery.get("receiving_turn_id") == turn and delivery.get("request_digest") == request_digest,
             "scope_owned_receiving_binding_mismatch")
        need(isinstance(binding, dict) and binding == delegation.get("scope_receipt"), "scope_owned_binding_mismatch")
    metadata = {"operation_id": operation, "request_digest": request_digest,
                "task_sha256": core.text_digest(request["task"]), "actual_turn_id": turn,
                "scope_receipt": binding, "origin": "verified-native-delegation"}
    return session, turn, request, metadata


def _receipt(state, metadata, *, status):
    return {"protocol": PROTOCOL, "status": status, "origin": "verified-native-delegation",
            "operation_id": metadata["operation_id"], "actual_turn_id": metadata["actual_turn_id"],
            "task_sha256": metadata["task_sha256"], "anchor_digest": state["anchor_digest"],
            "epoch": state["epoch"], "armed": state["armed"], "action_authority": "not-evaluated",
            "managed_selector_sha256": MANAGED_SELECTOR_SHA, "original_engine_sha256": LEGACY_ENGINE_SHA}


def sync(config_or_path, verified_delegation_result, payload, *, store=None, core=None, now=None):
    config = object_json(Path(config_or_path).read_text(encoding="utf-8")) if isinstance(config_or_path, (str, Path)) else config_or_path
    need(isinstance(config, dict), "scope_config_invalid")
    loaded, special = load_engine(config.get("managed_scope_path"), config.get("managed_scope_sha256"))
    session = loaded.session_key(payload)
    need(session != special, "scope_signed_special_target_not_supported")
    core = load_core(config) if core is None else core
    instant = int(time.time()) if now is None else now
    session, turn, request, metadata = _validate_owned(config, verified_delegation_result, payload, core, now=instant)
    engine = loaded
    store = engine.Store(engine.state_root("codex")) if store is None else store
    with store.locked(session):
        core.parse_request(request, now=int(time.time()) if now is None else now,
                           source_thread_id=config["source_thread_id"], receiving_host_id=config["target_machine_id"],
                           receiving_thread_id=session, allowed_owner_threads=set(config["allowed_owner_threads"]))
        pending = store.capture_pending(session)
        state = store.load(session)
        state = engine.new_state(session) if state is None else state
        need(type(state.get("epoch")) is int and state["epoch"] >= 0, "scope_epoch_invalid")
        history = state.setdefault("native_delegation_operations", {})
        need(isinstance(history, dict), "scope_operation_history_invalid")
        prior = history.get(metadata["operation_id"])
        if prior is not None:
            need(prior.get("binding") == metadata, "scope_operation_collision")
            need(not pending, "scope_capture_pending")
            current = state.get("active_native_delegation")
            need(current == metadata and state.get("anchor_digest") == prior.get("anchor_digest")
                 and engine.anchor_digest(state) == state["anchor_digest"], "scope_operation_superseded")
            return _receipt(state, metadata, status="current")
        sequence = state.get("native_delegation_sequence", 0)
        need(type(sequence) is int and sequence >= 0, "scope_operation_sequence_invalid")
        indexes = [entry.get("capture_index", 0) for entry in history.values() if isinstance(entry, dict)]
        need(all(type(index) is int and index >= 0 for index in indexes), "scope_operation_sequence_invalid")
        sequence = max([sequence, *indexes]) + 1
        previous_anchor = state.get("anchor_digest")
        recovering = pending or bool(state.get("capture_fault"))
        store.begin_capture(session)
        # Original capture rules, including QuestionReply, superseded bounded
        # history and epoch/reflex behavior, stay inside the original engine.
        engine.record_prompt(state, request["task"], turn, force_task=True)
        # This task is bounded and proved in full by the owning Core claim.
        # Preserve that exact body for compaction; an excerpt cannot carry
        # constraints or the requested result at the end of a long task.
        state["instructions"][0]["text"] = request["task"]
        state["instructions"][0]["truncated"] = False
        state["capture_fault"] = None
        # This new independently verified claim owns a fresh task/turn.
        # A failed observation of an older Native cycle cannot block it.
        state.pop("native_cycle_fault", None)
        state["instructions"][0].update(origin="verified-native-delegation", operation_id=metadata["operation_id"],
                                        scope_receipt=metadata["scope_receipt"])
        state["active_native_delegation"] = metadata
        history[metadata["operation_id"]] = {"binding": metadata, "anchor_digest": state["anchor_digest"],
                                             "capture_epoch": state["epoch"], "capture_index": sequence}
        state["native_delegation_sequence"] = sequence
        if len(history) > MAX_OPERATIONS:
            # This is bounded current Scope metadata. The private operation
            # ledger retains durable one-use/replay state after these entries
            # leave the capsule. Store.save sorts JSON keys, so an explicit
            # local capture index (not dict order) preserves recency.
            others = [(key, entry) for key, entry in history.items() if key != metadata["operation_id"]]
            others.sort(key=lambda row: (row[1].get("capture_index", 0),
                                         row[1].get("binding", {}).get("actual_turn_id", "")), reverse=True)
            history = dict(others[:MAX_OPERATIONS - 1])
            history[metadata["operation_id"]] = state["native_delegation_operations"][metadata["operation_id"]]
            state["native_delegation_operations"] = history
        if recovering or state["epoch"] > 0 and state["anchor_digest"] != previous_anchor:
            engine.require_reattest(state, "verified-delegation-anchor-changed", event="verified-native-delegation")
        store.save(session, state)
        observed = store.load(session)
        need(observed == state and observed["anchor_digest"] == engine.anchor_digest(observed), "scope_capture_readback_mismatch")
        # A failure before exact successful readback intentionally retains the
        # original pending marker; no helper error path removes that fence.
        store.finish_capture(session)
        return _receipt(observed, metadata, status="captured")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--stdin", action="store_true")
    args = parser.parse_args(argv)
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        need(0 < len(raw) <= MAX_BYTES, "scope_payload_oversized")
        body = object_json(raw.decode("utf-8"))
        need(set(body) == {"payload", "delegation"}, "scope_cli_payload_invalid")
        result = sync(args.config, body["delegation"], body["payload"])
    except Exception:
        result = {"protocol": PROTOCOL, "status": "denied", "code": "scope_capture_not_committed", "action_authority": "not-evaluated"}
    sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
    return 0 if result["status"] != "denied" else 2


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
