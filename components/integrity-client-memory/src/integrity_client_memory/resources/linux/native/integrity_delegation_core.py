# SPDX-License-Identifier: Apache-2.0
"""Portable delegated-task evidence and one-use operation state.

The caller is a fixed receiving/sending adapter which obtains Native pages.
Dictionary shape is not an authenticated channel: these functions check the
adapter's observations and never grant target-action authority, issue a Memory
reference, sign evidence, access a network or execute a task.  A model receives
the original owner text separately to evaluate the task's authorized scope.
"""

from __future__ import annotations

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config

import hashlib
import json
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

PROTOCOL = "integrity/delegated-task/v1"
CONTROL_PROTOCOL = "integrity/delegation-control/v1"
MEDOR_THREAD = _integrity_value('binding_medor_thread')
BEGIN = "BEGIN_INTEGRITY_DELEGATED_TASK"
END = "END_INTEGRITY_DELEGATED_TASK"
MAX_BYTES = 1024 * 1024
MAX_LIFETIME = 24 * 60 * 60
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
REQUEST_KEYS = frozenset({"protocol", "operation_id", "source_thread_id", "owner_ref",
                          "target", "task", "not_before", "expires", "reply_thread_id"})
OWNER_KEYS = frozenset({"thread_id", "turn_id", "item_id", "room_id", "message_id", "prompt_sha256"})


class DelegationError(ValueError):
    """Content-free public failure code; rejected text is never echoed."""


def _need(ok, code):
    if not ok:
        raise DelegationError(code)


def _token(value, *, stable=False):
    return isinstance(value, str) and TOKEN.fullmatch(value) is not None and (not stable or len(value) >= 8)


def canonical_json(value):
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, UnicodeError):
        raise DelegationError("invalid_json_value") from None


def digest(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def text_digest(value):
    _need(isinstance(value, str), "text_required")
    try:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()
    except UnicodeError:
        raise DelegationError("invalid_text_encoding") from None


def _unique(pairs):
    value = {}
    for key, item in pairs:
        _need(key not in value, "duplicate_json_key")
        value[key] = item
    return value


def _json(raw):
    if isinstance(raw, dict):
        raw = canonical_json(raw)
    if isinstance(raw, bytes):
        _need(len(raw) <= MAX_BYTES, "body_oversized")
        try:
            raw = raw.decode("utf-8", errors="strict")
        except UnicodeError:
            raise DelegationError("invalid_text_encoding") from None
    _need(isinstance(raw, str) and 0 < len(raw.encode("utf-8")) <= MAX_BYTES, "body_invalid")
    try:
        value = json.loads(raw, object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(DelegationError("invalid_json_constant")))
    except DelegationError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise DelegationError("body_not_json") from None
    _need(isinstance(value, dict), "object_required")
    return value


def extract_request_body(body):
    """Extract an exact transport body; a displayed delegation source is ignored.

    The adapter passes the observed inner input after transport-specific parsing.
    Marker framing may have a harmless bootstrap instruction outside the frame.
    Multiple frames, incomplete frames and surrounding JSON fragments reject.
    """
    _need(isinstance(body, str) and 0 < len(body.encode("utf-8")) <= MAX_BYTES, "body_invalid")
    stripped = body.strip()
    if BEGIN in stripped or END in stripped:
        _need(stripped.count(BEGIN) == 1 and stripped.count(END) == 1, "request_frame_ambiguous")
        before, rest = stripped.split(BEGIN, 1)
        middle, after = rest.split(END, 1)
        _need(not before.strip() and middle.startswith("\n") and middle.endswith("\n"), "request_frame_invalid")
        _need(BEGIN not in after and END not in after, "request_frame_ambiguous")
        stripped = middle.strip()
    return canonical_json(_json(stripped))


def _now(value):
    value = int(time.time()) if value is None else value
    _need(type(value) is int and value >= 0, "clock_invalid")
    return value


def _owner_ref_kind(owner):
    _need(isinstance(owner, dict) and set(owner) == OWNER_KEYS
          and _token(owner.get("thread_id"), stable=True), "owner_ref_invalid")
    room, message = owner["room_id"], owner["message_id"]
    has_service = _token(room) and _token(message)
    _need((room is None and message is None) or has_service, "owner_room_message_invalid")
    native = (owner["turn_id"], owner["item_id"], owner["prompt_sha256"])
    if all(value is None for value in native):
        _need(has_service, "native_owner_ref_required")
        return "service-message"
    _need(_token(owner["turn_id"], stable=True) and _token(owner["item_id"], stable=True)
          and isinstance(owner["prompt_sha256"], str) and DIGEST.fullmatch(owner["prompt_sha256"]) is not None,
          "owner_ref_invalid")
    return "native-item"


def parse_request(raw, *, now=None, source_thread_id=MEDOR_THREAD,
                  receiving_host_id=None, receiving_thread_id=None, allowed_owner_threads=None):
    request = _json(raw)
    _need(set(request) == REQUEST_KEYS and request.get("protocol") == PROTOCOL, "request_shape_invalid")
    _need(_token(request["operation_id"], stable=True), "operation_id_invalid")
    _need(request["source_thread_id"] == source_thread_id and request["reply_thread_id"] == source_thread_id
          and _token(source_thread_id, stable=True), "source_or_reply_mismatch")
    owner = request["owner_ref"]
    _owner_ref_kind(owner)
    owner_threads = (source_thread_id,) if allowed_owner_threads is None else tuple(allowed_owner_threads)
    _need(bool(owner_threads) and all(_token(v, stable=True) for v in owner_threads), "owner_allowlist_invalid")
    _need(owner["thread_id"] in owner_threads, "owner_ref_invalid")
    target = request["target"]
    _need(isinstance(target, dict) and set(target) == {"host_id", "thread_id"}
          and _token(target["host_id"]) and _token(target["thread_id"], stable=True), "target_invalid")
    _need(receiving_host_id is None or receiving_host_id == target["host_id"], "target_host_mismatch")
    _need(receiving_thread_id is None or receiving_thread_id == target["thread_id"], "target_thread_mismatch")
    task = request["task"]
    _need(isinstance(task, str) and bool(task.strip()) and "\x00" not in task
          and len(task.encode("utf-8")) <= MAX_BYTES // 2, "task_invalid")
    start, expiry, instant = request["not_before"], request["expires"], _now(now)
    _need(type(start) is int and type(expiry) is int and 0 <= start < expiry
          and expiry - start <= MAX_LIFETIME, "validity_invalid")
    _need(start <= instant < expiry, "request_not_current")
    return request


def _owner_text(item):
    _need(isinstance(item, dict) and item.get("type") == "userMessage"
          and item.get("truncated") is False, "owner_message_not_complete_human_input")
    blocks = item.get("content")
    _need(isinstance(blocks, list) and bool(blocks), "owner_content_invalid")
    texts = []
    for block in blocks:
        _need(isinstance(block, dict) and block.get("type") == "text"
              and block.get("truncated") is False and isinstance(block.get("text"), str), "owner_content_not_complete_text")
        texts.append(block["text"])
    text = "\n".join(texts)
    _need(bool(text.strip()) and len(text.encode("utf-8")) <= MAX_BYTES, "owner_text_invalid")
    _need(BEGIN not in text and END not in text,
          "owner_message_is_delegated_input")
    return text


def verify_owner_item(request, item, *, delivery_context=None):
    """Verify exact owner item DATA from the adapter's full Native source read."""
    _need(isinstance(request, dict) and isinstance(request.get("owner_ref"), dict), "request_shape_invalid")
    owner = request["owner_ref"]
    kind = _owner_ref_kind(owner)
    text = _owner_text(item)
    _need(isinstance(delivery_context, dict) and delivery_context.get("thread_id") == owner["thread_id"]
          and _token(delivery_context.get("turn_id"), stable=True)
          and _token(item.get("id"), stable=True), "owner_native_context_mismatch")
    actual = {**owner, "turn_id": delivery_context["turn_id"], "item_id": item["id"], "prompt_sha256": text_digest(text)}
    if kind == "native-item":
        _need(item.get("id") == owner["item_id"] and actual["prompt_sha256"] == owner["prompt_sha256"], "owner_item_binding_mismatch")
        _need(delivery_context["turn_id"] == owner["turn_id"], "owner_native_context_mismatch")
    if owner["room_id"] is not None:
        _need(delivery_context.get("room_id") == owner["room_id"]
              and delivery_context.get("message_id") == owner["message_id"], "owner_service_context_mismatch")
    _need(delivery_context.get("origin_kind", "owner") in {"owner", "owner-ui", "human"}, "owner_origin_invalid")
    receipt = {"protocol": "integrity/delegation-owner-evidence/v1", "request_digest": digest(request),
               "owner_ref": dict(owner), "resolved_owner_ref": actual, "owner_text_sha256": text_digest(text),
               "source_thread_id": request["source_thread_id"], "origin_kind": "observed-owner-message",
               "action_authority": "not-evaluated", "verification": "exact-complete-native-user-message"}
    receipt["evidence_digest"] = digest(receipt)
    return receipt


def _prepared_ledger_request(path, current_request, current_owner_evidence):
    """Read only an existing private request; never tokens/results or CREATE."""
    with _projection_readonly(path) as db:
        if db is None:
            return None
        operation_id = current_request["operation_id"]
        row = None
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='delegation_operations'").fetchone() is not None:
            row = db.execute("SELECT operation_id,request_json,request_digest,owner_json,state FROM delegation_operations WHERE operation_id=?", (operation_id,)).fetchone()
        globally_revoked = False
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='delegation_revocations'").fetchone() is not None:
            globally_revoked = db.execute("SELECT 1 FROM delegation_revocations WHERE operation_id=?", (operation_id,)).fetchone() is not None
        if row is None:
            # This is a readonly question about the current verified request,
            # never a revocation tombstone for an unknown/foreign owner.
            current = {"operation_id": operation_id, "request_json": canonical_json(current_request),
                       "owner_json": canonical_json(current_owner_evidence)}
            revoked = _projected_revoked(db, current) or globally_revoked
            return {"request": None, "state": None, "revoked": True} if revoked else None
        request = _json(row["request_json"])
        _need(request.get("operation_id") == operation_id and digest(request) == row["request_digest"],
              "preparation_prior_request_corrupt")
        _need(row["state"] in {"reserved", "executing", "completed", "failed", "unknown"}, "preparation_prior_state_invalid")
        return {"request": request, "state": row["state"],
                "revoked": _projected_revoked(db, row) or globally_revoked}


def prepare_request(*, owner_item, delivery_context, owner_started_at, source_thread_id,
                    target_host_id, target_thread_id, task, not_before, expires, now=None,
                    allowed_owner_threads=None, ledger_path=None):
    """Prepare request DATA from a fixed adapter's independently LIVE owner read.

    Normalized dictionaries are not authentication or action authority. The
    adapter must obtain them from its trusted source API, pin source/owner/room
    and target enrollment, and evaluate the original owner's authorized scope.
    This function does not send, reserve, claim, revoke, grant or admit Memory.

    Operation identity excludes timestamps. For a service message, its native
    turn/item are live locators; the owner thread/room/message/hash identify it.
    A readonly existing private request
    freezes all its original bytes/times. Without that request, changed timing
    keeps the same operation identity; the receiving ledger rejects a conflicting
    digest rather than treating it as a new action. Never retry with a new ID.
    """
    instant = _now(now)
    _need(isinstance(delivery_context, dict)
          and all(key in delivery_context for key in ("thread_id", "turn_id", "room_id", "message_id", "origin_kind"))
          and delivery_context["origin_kind"] in {"owner", "owner-ui", "human"}, "preparation_owner_context_invalid")
    _need(type(owner_started_at) is int and 0 <= owner_started_at <= instant,
          "preparation_owner_timestamp_invalid")
    _need(instant - owner_started_at < MAX_LIFETIME, "preparation_owner_stale")
    _need(type(not_before) is int and type(expires) is int and not_before >= owner_started_at
          and expires <= owner_started_at + MAX_LIFETIME, "preparation_validity_invalid")
    text = _owner_text(owner_item)
    owner = {"thread_id": delivery_context["thread_id"], "turn_id": delivery_context["turn_id"],
             "item_id": owner_item.get("id"), "room_id": delivery_context["room_id"],
             "message_id": delivery_context["message_id"], "prompt_sha256": text_digest(text)}
    _need("item_id" not in delivery_context or delivery_context["item_id"] == owner["item_id"],
          "preparation_owner_item_mismatch")
    _need("prompt_sha256" not in delivery_context or delivery_context["prompt_sha256"] == owner["prompt_sha256"],
          "preparation_owner_digest_mismatch")
    target = {"host_id": target_host_id, "thread_id": target_thread_id}
    identity_owner = owner if owner["room_id"] is None else {
        key: owner[key] for key in ("thread_id", "room_id", "message_id", "prompt_sha256")}
    operation_id = "delegation-" + digest({"owner_ref": identity_owner, "target": target, "task": task})
    request = {"protocol": PROTOCOL, "operation_id": operation_id, "source_thread_id": source_thread_id,
               "owner_ref": owner, "target": target, "task": task, "not_before": not_before,
               "expires": expires, "reply_thread_id": source_thread_id}
    request = parse_request(request, now=instant, source_thread_id=source_thread_id,
                            allowed_owner_threads=allowed_owner_threads)
    owner_evidence = verify_owner_item(request, owner_item, delivery_context=delivery_context)
    prior_state = _prepared_ledger_request(ledger_path, request, owner_evidence) if ledger_path is not None else None
    prior = None if prior_state is None else prior_state["request"]
    if prior is not None:
        _need(prior.get("source_thread_id") == source_thread_id and prior.get("reply_thread_id") == source_thread_id,
              "preparation_prior_source_mismatch")
        _need(prior.get("owner_ref") == owner and prior.get("target") == target and prior.get("task") == task,
              "preparation_prior_request_conflict")
        request = parse_request(prior, now=instant, source_thread_id=source_thread_id,
                                allowed_owner_threads=allowed_owner_threads)
        _need(request["not_before"] >= owner_started_at and request["expires"] <= owner_started_at + MAX_LIFETIME,
              "preparation_prior_validity_invalid")
        owner_evidence = verify_owner_item(request, owner_item, delivery_context=delivery_context)
    body = canonical_json(request)
    return {"request": request, "frame": BEGIN + "\n" + body + "\n" + END,
            "owner_evidence": owner_evidence, "operation_id": operation_id,
            "request_digest": digest(request), "reused_prior_request": prior is not None,
            "dispatchable": prior_state is None,
            "preparation_status": "new-request" if prior_state is None else
                ("operation-revoked" if prior_state["revoked"] else "existing-" + prior_state["state"]),
            "action_authority": "not-evaluated"}


def verify_delivery(request, source_evidence, receiving_evidence):
    """Join actual completed sender arguments with the actual receiving item.

    Native/Claude adapters provide normalized evidence obtained from their own
    APIs. The wrapper's self-reported source has no bearing on this join.
    """
    _need(isinstance(source_evidence, dict) and isinstance(receiving_evidence, dict), "delivery_evidence_invalid")
    _need(source_evidence.get("thread_id") == request["source_thread_id"]
          and _token(source_evidence.get("turn_id"), stable=True)
          and _token(source_evidence.get("item_id"), stable=True)
          and source_evidence.get("status") == "completed", "sender_not_observed_complete")
    args = source_evidence.get("arguments")
    _need(isinstance(args, dict), "sender_arguments_missing")
    target_thread = args.get("thread_id", args.get("threadId"))
    _need(target_thread == request["target"]["thread_id"], "sender_target_mismatch")
    if "thread_id" in args and "threadId" in args:
        _need(args["thread_id"] == args["threadId"], "sender_target_mismatch")
    host = args.get("host_id", args.get("hostId", request["target"]["host_id"]))
    _need(host == request["target"]["host_id"], "sender_host_mismatch")
    body = args.get("prompt", args.get("body"))
    sent = extract_request_body(body)
    expected = canonical_json(request)
    _need(sent == expected, "sent_request_mismatch")
    _need(receiving_evidence.get("host_id") == request["target"]["host_id"]
          and receiving_evidence.get("thread_id") == request["target"]["thread_id"]
          and all(_token(receiving_evidence.get(k), stable=True) for k in ("turn_id", "item_id")), "receiving_target_mismatch")
    _need(extract_request_body(receiving_evidence.get("body")) == expected, "received_request_mismatch")
    request_digest = digest(request)
    _need(receiving_evidence.get("request_digest", request_digest) == request_digest, "receiving_digest_mismatch")
    receipt = {"protocol": "integrity/delegation-delivery-evidence/v1", "operation_id": request["operation_id"],
               "request_digest": request_digest, "body_sha256": text_digest(expected),
               "source_thread_id": source_evidence["thread_id"], "source_turn_id": source_evidence["turn_id"],
               "source_item_id": source_evidence["item_id"], "target_host_id": receiving_evidence["host_id"],
               "target_thread_id": receiving_evidence["thread_id"], "receiving_turn_id": receiving_evidence["turn_id"],
               "receiving_item_id": receiving_evidence["item_id"], "origin_kind": "verified-delegated-delivery",
               "action_authority": "not-evaluated", "reported_wrapper_source_trusted": False}
    receipt["evidence_digest"] = digest(receipt)
    return receipt


def binding_receipt(request, *, epoch=0, owner_receipt=None):
    _need(type(epoch) is int and epoch >= 0, "scope_epoch_invalid")
    bound = {"operation_id": request["operation_id"], "owner_ref": request["owner_ref"],
             "source_thread_id": request["source_thread_id"], "target": request["target"], "task": request["task"]}
    if owner_receipt is not None:
        actual = _resolved_owner_ref(request, owner_receipt)
        bound.update(resolved_owner_ref=actual, owner_evidence_digest=owner_receipt["evidence_digest"])
    else:
        _need(_owner_ref_kind(request["owner_ref"]) == "native-item", "owner_resolution_required")
    anchor = digest(bound)
    receipt = {"protocol": "integrity/delegated-scope-binding/v1", "operation_id": request["operation_id"],
               "task_id": "delegated-task:" + anchor, "scope_id": "delegated-scope:" + anchor,
               "anchor": anchor, "epoch": epoch, "request_digest": digest(request),
               "prompt_sha256": text_digest(request["task"]), "action_authority": "not-evaluated"}
    if owner_receipt is not None:
        receipt.update(resolved_owner_ref=actual, owner_evidence_digest=owner_receipt["evidence_digest"])
    receipt["binding_digest"] = digest(receipt)
    return receipt


def parse_control(raw):
    value = _json(raw)
    _need(set(value) == {"protocol", "operation_id", "action"} and value.get("protocol") == CONTROL_PROTOCOL
          and _token(value.get("operation_id"), stable=True) and value.get("action") == "revoke", "control_invalid")
    return value


def verify_control_item(item, *, delivery_context, source_thread_id=MEDOR_THREAD):
    text = _owner_text(item)
    control = parse_control(text)
    _need(isinstance(delivery_context, dict) and delivery_context.get("thread_id") == source_thread_id
          and _token(delivery_context.get("turn_id"), stable=True) and _token(item.get("id"), stable=True)
          and delivery_context.get("origin_kind", "owner") in {"owner", "owner-ui", "human"}
          and "room_id" in delivery_context
          and (delivery_context["room_id"] is None or _token(delivery_context["room_id"], stable=True)), "control_owner_context_invalid")
    receipt = {"protocol": "integrity/delegation-control-evidence/v1", "operation_id": control["operation_id"],
               "action": "revoke", "source_thread_id": source_thread_id,
               "owner_turn_id": delivery_context["turn_id"], "owner_item_id": item["id"],
               "owner_text_sha256": text_digest(text), "origin_kind": "observed-owner-message",
               "room_id": delivery_context["room_id"]}
    receipt["evidence_digest"] = digest(receipt)
    return receipt


def _check_receipt(value, protocol, *, digest_field="evidence_digest"):
    _need(isinstance(value, dict) and value.get("protocol") == protocol, "evidence_receipt_invalid")
    public = dict(value)
    actual = public.pop(digest_field, None)
    _need(isinstance(actual, str) and DIGEST.fullmatch(actual) is not None and actual == digest(public), "evidence_receipt_digest_mismatch")


def _resolved_owner_ref(request, owner_receipt):
    _check_receipt(owner_receipt, "integrity/delegation-owner-evidence/v1")
    owner = request["owner_ref"]
    kind = _owner_ref_kind(owner)
    # Older fully specified v1 receipts remain readable. A nullable reference
    # always needs a resolved observation from the installed receiving adapter.
    actual = owner_receipt.get("resolved_owner_ref")
    if actual is None:
        _need(kind == "native-item", "owner_resolution_required")
        actual = dict(owner)
    _need(_owner_ref_kind(actual) == "native-item", "resolved_owner_ref_invalid")
    _need(owner_receipt.get("request_digest") == digest(request)
          and owner_receipt.get("owner_ref") == owner
          and all(actual[k] == owner[k] for k in ("thread_id", "room_id", "message_id"))
          and owner_receipt.get("owner_text_sha256") == actual["prompt_sha256"]
          and (kind == "service-message" or actual == owner), "resolved_owner_binding_mismatch")
    return dict(actual)


# Internal adapter observations, not a new wire protocol or an authority route.
_COVERAGE_KEYS = frozenset({"source_thread_id", "host_id", "source_provider", "source_room_id",
                          "frontier_turn_id", "previous_frontier_turn_id", "history_end_observed",
                          "boundary_turn_complete", "coverage_complete", "control_evidence_digests", "evidence_digest"})
_FRONTIER_KEYS = frozenset({"source_thread_id", "host_id", "source_provider", "source_room_id",
                          "frontier_turn_id", "version", "receipt_digest", "controls_digest"})
_OBS_SCOPE = ("source_thread_id", "host_id", "source_provider", "source_room_id")
_OBS_PINS = ("observer_schema", "observer_runtime_digest", "original_head_turn_id")
_OBS_STATE_KEYS = frozenset(_OBS_SCOPE + _OBS_PINS + ("generation", "seq", "pages_total", "cursor",
    "history_end_observed", "last_page_input_cursor", "last_page_turn_ids", "seen_cursor_digests",
    "controls_digest", "control_count", "stage_digest"))
_OBS_SOURCE_KEYS = frozenset(_OBS_SCOPE + ("generation", "controls_digest", "stage_digest", "source_digest"))
_OBS_PAGE_KEYS = frozenset(_OBS_SCOPE + _OBS_PINS + ("input_cursor", "next_cursor", "turn_ids",
    "page_complete", "history_end_observed", "control_evidence_digests", "evidence_digest"))
_OBS_REFRESH_KEYS = frozenset(_OBS_SCOPE + _OBS_PINS + ("frontier_turn_id", "boundary_turn_complete",
    "coverage_complete", "control_evidence_digests", "evidence_digest"))


def _observation_scope(value):
    _need(_token(value.get("source_thread_id"), stable=True) and _token(value.get("host_id"))
          and _token(value.get("source_provider"))
          and (value.get("source_room_id") is None or _token(value["source_room_id"], stable=True)),
          "control_observation_scope_invalid")


def _observation_pins(value):
    _observation_scope(value)
    _need(isinstance(value.get("observer_schema"), str) and 1 <= len(value["observer_schema"]) <= 128
          and isinstance(value.get("observer_runtime_digest"), str) and DIGEST.fullmatch(value["observer_runtime_digest"])
          and _token(value.get("original_head_turn_id"), stable=True), "control_observation_pins_invalid")


def _observation_checksum(value, keys, field):
    _need(isinstance(value, dict) and set(value) == keys, "control_observation_schema_invalid")
    public = dict(value)
    actual = public.pop(field)
    _need(isinstance(actual, str) and DIGEST.fullmatch(actual) and actual == digest(public),
          "control_observation_corrupt")


def _cursor(value):
    _need(value is None or (isinstance(value, str) and 0 < len(value) <= 16384 and "\x00" not in value),
          "control_observation_cursor_invalid")
    return value


def _control_facts(controls, receipt):
    _need(isinstance(controls, list) and len(controls) <= 10000, "control_projection_controls_invalid")
    facts, identities = {}, {}
    for control in controls:
        control = _projection_control(control, source_thread_id=receipt["source_thread_id"], room_id=receipt["source_room_id"])
        identity = (control["owner_turn_id"], control["owner_item_id"])
        proof = control["evidence_digest"]
        _need(identity not in identities or identities[identity] == proof, "control_projection_identity_conflict")
        identities[identity] = proof
        facts[proof] = control
    _need(sorted(facts) == receipt["control_evidence_digests"], "control_projection_controls_incomplete")
    return facts


def _create_projection(db):
    db.execute("CREATE TABLE IF NOT EXISTS observed_controls (source_thread_id TEXT NOT NULL, operation_id TEXT NOT NULL, evidence_digest TEXT NOT NULL, receipt_json TEXT NOT NULL, owner_turn_id TEXT NOT NULL, owner_item_id TEXT NOT NULL, PRIMARY KEY(source_thread_id,operation_id,evidence_digest), UNIQUE(source_thread_id,owner_turn_id,owner_item_id))")
    db.execute("CREATE TABLE IF NOT EXISTS frontiers (source_thread_id TEXT PRIMARY KEY, host_id TEXT NOT NULL, source_provider TEXT NOT NULL, source_room_id TEXT, frontier_turn_id TEXT NOT NULL, version INTEGER NOT NULL, receipt_digest TEXT NOT NULL, controls_digest TEXT NOT NULL, receipt_json TEXT NOT NULL)")


def _store_control_facts(db, facts):
    for control in facts.values():
        source = control["source_thread_id"]
        row = db.execute("SELECT evidence_digest,receipt_json FROM observed_controls WHERE source_thread_id=? AND owner_turn_id=? AND owner_item_id=?",
                         (source, control["owner_turn_id"], control["owner_item_id"])).fetchone()
        encoded = canonical_json(control)
        _need(row is None or (row["evidence_digest"] == control["evidence_digest"] and row["receipt_json"] == encoded),
              "control_projection_identity_conflict")
        db.execute("INSERT OR IGNORE INTO observed_controls VALUES (?,?,?,?,?,?)", (source, control["operation_id"],
                   control["evidence_digest"], encoded, control["owner_turn_id"], control["owner_item_id"]))


def _observation_tables(db):
    names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('observation_sources','observation_sessions')")}
    _need(not names or names == {"observation_sources", "observation_sessions"}, "control_observation_schema_incomplete")
    return bool(names)


def _read_observation_source(db, source):
    if not _observation_tables(db):
        return None
    row = db.execute("SELECT source_json FROM observation_sources WHERE source_thread_id=?", (source,)).fetchone()
    if row is None:
        _need(db.execute("SELECT 1 FROM observation_sessions WHERE source_thread_id=?", (source,)).fetchone() is None,
              "control_observation_corrupt")
        return None
    value = _json(row["source_json"])
    _observation_checksum(value, _OBS_SOURCE_KEYS, "source_digest")
    _observation_scope(value)
    _need(value["source_thread_id"] == source and type(value["generation"]) is int and value["generation"] >= 1
          and isinstance(value["controls_digest"], str) and DIGEST.fullmatch(value["controls_digest"])
          and (value["stage_digest"] is None or isinstance(value["stage_digest"], str) and DIGEST.fullmatch(value["stage_digest"])),
          "control_observation_corrupt")
    _need(_projection_tables(db) and value["controls_digest"] == _controls_digest(_source_controls(db, source, value["source_room_id"])),
          "control_projection_fact_corrupt")
    stage = db.execute("SELECT state_json FROM observation_sessions WHERE source_thread_id=?", (source,)).fetchone()
    _need((stage is None) == (value["stage_digest"] is None), "control_observation_corrupt")
    if stage is not None:
        state = _json(stage["state_json"])
        _observation_checksum(state, _OBS_STATE_KEYS, "stage_digest")
        _observation_pins(state)
        _need(all(state[k] == value[k] for k in _OBS_SCOPE + ("generation", "controls_digest", "stage_digest")),
              "control_observation_corrupt")
        _validate_observation_state(state)
    return value


def _validate_observation_state(state):
    _need(all(type(state[k]) is int and state[k] >= 0 for k in ("seq", "pages_total", "control_count"))
          and type(state["generation"]) is int and state["generation"] >= 1
          and state["pages_total"] <= state["seq"] and type(state["history_end_observed"]) is bool,
          "control_observation_corrupt")
    _cursor(state["cursor"])
    _cursor(state["last_page_input_cursor"])
    turns = state["last_page_turn_ids"]
    seen = state["seen_cursor_digests"]
    _need(isinstance(turns, list) and len(turns) <= 100 and len(set(turns)) == len(turns)
          and all(_token(v, stable=True) for v in turns)
          and isinstance(seen, list) and len(seen) <= 100000 and len(set(seen)) == len(seen)
          and all(isinstance(v, str) and DIGEST.fullmatch(v) for v in seen), "control_observation_corrupt")
    _need((state["pages_total"] == 0 and state["seq"] == 0 and not turns and state["cursor"] is None and not state["history_end_observed"])
          or (state["pages_total"] > 0 and bool(turns) and state["history_end_observed"] == (state["cursor"] is None)),
          "control_observation_corrupt")


def _read_observation(db, source):
    metadata = _read_observation_source(db, source)
    if metadata is None or metadata["stage_digest"] is None:
        return None
    state = _json(db.execute("SELECT state_json FROM observation_sessions WHERE source_thread_id=?", (source,)).fetchone()[0])
    _need(state["control_count"] == len(_source_controls(db, source, state["source_room_id"])), "control_observation_corrupt")
    return state


def _write_observation(db, source_meta, state):
    source_meta = dict(source_meta)
    if state is not None:
        state = dict(state)
        state["stage_digest"] = digest({k: v for k, v in state.items() if k != "stage_digest"})
        source_meta.update(generation=state["generation"], controls_digest=state["controls_digest"], stage_digest=state["stage_digest"])
        db.execute("INSERT INTO observation_sessions VALUES (?,?) ON CONFLICT(source_thread_id) DO UPDATE SET state_json=excluded.state_json",
                   (state["source_thread_id"], canonical_json(state)))
    else:
        source_meta["stage_digest"] = None
        db.execute("DELETE FROM observation_sessions WHERE source_thread_id=?", (source_meta["source_thread_id"],))
    source_meta["source_digest"] = digest({k: v for k, v in source_meta.items() if k != "source_digest"})
    db.execute("INSERT INTO observation_sources VALUES (?,?) ON CONFLICT(source_thread_id) DO UPDATE SET source_json=excluded.source_json",
               (source_meta["source_thread_id"], canonical_json(source_meta)))
    return state


def read_observation(path, source_thread_id, *, host_id, source_provider, source_room_id, observer_schema, observer_runtime_digest):
    """Read protected derived progress only. An absent database stays absent."""
    context = dict(source_thread_id=source_thread_id, host_id=host_id, source_provider=source_provider,
                   source_room_id=source_room_id, observer_schema=observer_schema, observer_runtime_digest=observer_runtime_digest)
    _observation_pins({**context, "original_head_turn_id": "validation-head-0001"})
    with _projection_readonly(path) as db:
        if db is None:
            return None
        metadata = _read_observation_source(db, source_thread_id)
        if metadata is not None:
            _need(all(metadata[k] == context[k] for k in _OBS_SCOPE), "control_observation_scope_changed")
        state = _read_observation(db, source_thread_id)
        if state is not None:
            _need(all(state[k] == context[k] for k in _OBS_SCOPE + ("observer_schema", "observer_runtime_digest")),
                  "control_observation_runtime_changed")
        return state


def _projection_control(receipt, *, source_thread_id, room_id):
    _check_receipt(receipt, "integrity/delegation-control-evidence/v1")
    _need(receipt.get("source_thread_id") == source_thread_id
          and receipt.get("origin_kind") == "observed-owner-message" and receipt.get("action") == "revoke"
          and "room_id" in receipt and receipt["room_id"] == room_id
          and all(_token(receipt.get(k), stable=True) for k in ("operation_id", "owner_turn_id", "owner_item_id"))
          and isinstance(receipt.get("owner_text_sha256"), str) and DIGEST.fullmatch(receipt["owner_text_sha256"]),
          "control_projection_receipt_invalid")
    return receipt


def _coverage(receipt):
    _need(isinstance(receipt, dict) and set(receipt) == _COVERAGE_KEYS, "control_coverage_schema_invalid")
    value = dict(receipt)
    proof_digest = value.pop("evidence_digest")
    _need(isinstance(proof_digest, str) and DIGEST.fullmatch(proof_digest) and proof_digest == digest(value),
          "control_coverage_digest_invalid")
    _need(_token(receipt["source_thread_id"], stable=True) and _token(receipt["host_id"])
          and _token(receipt["source_provider"])
          and (receipt["source_room_id"] is None or _token(receipt["source_room_id"], stable=True))
          and _token(receipt["frontier_turn_id"], stable=True)
          and (receipt["previous_frontier_turn_id"] is None or _token(receipt["previous_frontier_turn_id"], stable=True)),
          "control_coverage_scope_invalid")
    _need(receipt["coverage_complete"] is True and type(receipt["history_end_observed"]) is bool
          and type(receipt["boundary_turn_complete"]) is bool, "control_coverage_incomplete")
    controls = receipt["control_evidence_digests"]
    _need(isinstance(controls, list) and len(controls) <= 10000
          and all(isinstance(v, str) and DIGEST.fullmatch(v) for v in controls)
          and controls == sorted(set(controls)), "control_coverage_controls_invalid")
    return receipt


def _frontier_public(row):
    result = {key: row[key] for key in _FRONTIER_KEYS}
    _need(type(result["version"]) is int and result["version"] >= 1
          and all(isinstance(result[key], str) and DIGEST.fullmatch(result[key])
                  for key in ("receipt_digest", "controls_digest")), "control_frontier_invalid")
    receipt = _coverage(_json(row["receipt_json"]))
    _need(all(result[key] == receipt[key] for key in ("source_thread_id", "host_id", "source_provider",
                                                    "source_room_id", "frontier_turn_id"))
          and result["receipt_digest"] == receipt["evidence_digest"], "control_frontier_corrupt")
    return result, receipt


def _projection_tables(db):
    names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('observed_controls','frontiers')")}
    _need(not names or names == {"observed_controls", "frontiers"}, "control_projection_schema_incomplete")
    return bool(names)


def _source_controls(db, source_thread_id, room_id):
    result = []
    for row in db.execute("SELECT * FROM observed_controls WHERE source_thread_id=? ORDER BY operation_id,evidence_digest", (source_thread_id,)):
        receipt = _projection_control(_json(row["receipt_json"]), source_thread_id=source_thread_id, room_id=room_id)
        _need(receipt["operation_id"] == row["operation_id"] and receipt["evidence_digest"] == row["evidence_digest"]
              and receipt["owner_turn_id"] == row["owner_turn_id"] and receipt["owner_item_id"] == row["owner_item_id"],
              "control_projection_fact_corrupt")
        result.append(receipt)
    return result


def _controls_digest(controls):
    return digest(sorted((item["operation_id"], item["evidence_digest"]) for item in controls))


def _read_frontier(db, source_thread_id):
    if not _projection_tables(db):
        return None
    row = db.execute("SELECT * FROM frontiers WHERE source_thread_id=?", (source_thread_id,)).fetchone()
    if row is None:
        partial = _read_observation_source(db, source_thread_id)
        _need(partial is not None or db.execute("SELECT 1 FROM observed_controls WHERE source_thread_id=?", (source_thread_id,)).fetchone() is None,
              "control_projection_unfrontiered")
        return None
    frontier, coverage = _frontier_public(row)
    controls = _source_controls(db, source_thread_id, frontier["source_room_id"])
    _need(frontier["controls_digest"] == _controls_digest(controls)
          and set(coverage["control_evidence_digests"]).issubset(item["evidence_digest"] for item in controls),
          "control_projection_fact_corrupt")
    partial = _read_observation_source(db, source_thread_id)
    if partial is not None:
        _need(all(partial[k] == frontier[k] for k in _OBS_SCOPE) and partial["stage_digest"] is None,
              "control_observation_scope_changed")
    return frontier


@contextmanager
def _projection_readonly(path):
    """Absent ledger stays absent, including its parent; never open CREATE mode."""
    path = Path(path)
    if not path.exists():
        yield None
        return
    _need(path.is_file(), "control_projection_store_invalid")
    db = None
    try:
        db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        yield db
    except sqlite3.Error:
        raise DelegationError("control_projection_store_invalid") from None
    finally:
        if db is not None:
            db.close()


def read_frontier(path, source_thread_id):
    _need(_token(source_thread_id, stable=True), "control_projection_source_invalid")
    with _projection_readonly(path) as db:
        return None if db is None else _read_frontier(db, source_thread_id)


def read_controls(path, operation_id, source_thread_ids):
    _need(_token(operation_id, stable=True), "operation_id_invalid")
    _need(isinstance(source_thread_ids, (tuple, list)) and 0 < len(source_thread_ids) <= 8
          and all(_token(value, stable=True) for value in source_thread_ids)
          and len(set(source_thread_ids)) == len(source_thread_ids), "control_projection_source_invalid")
    with _projection_readonly(path) as db:
        if db is None:
            return []
        result = []
        for source in source_thread_ids:
            frontier = _read_frontier(db, source)
            context = frontier if frontier is not None else _read_observation_source(db, source)
            if context is not None:
                result.extend(item for item in _source_controls(db, source, context["source_room_id"])
                              if item["operation_id"] == operation_id)
        return result


def _projected_revoked(db, row):
    """Revalidate facts for this KNOWN operation while holding its write lock.

    All authorized source checksums and Native identities are checked, including
    unrelated-operation facts in those sources. An unrelated owner's source
    cannot revoke a request or produce a global tombstone.
    """
    if not _projection_tables(db):
        return False
    request = _json(row["request_json"])
    owner = _resolved_owner_ref(request, _json(row["owner_json"]))
    revoked = False
    for source in {request["source_thread_id"], owner["thread_id"]}:
        frontier = _read_frontier(db, source)
        context = frontier if frontier is not None else _read_observation_source(db, source)
        if context is None:
            continue
        if source == owner["thread_id"]:
            _need(context["source_room_id"] == owner["room_id"], "control_projection_scope_changed")
        controls = _source_controls(db, source, context["source_room_id"])
        revoked = revoked or any(control["operation_id"] == row["operation_id"] for control in controls)
    return revoked


class Ledger:
    """Durable one-use gate. A crash after claim leaves a non-replayable state.

    Only the explicitly supplied SQLite path is accessed. The ledger records
    request/result DATA; it is not a signed canonical Memory or authority store.
    Existing parent-directory protection is owned by the installed adapter.
    """

    def __init__(self, path):
        self.path = str(Path(path))
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS delegation_operations (operation_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, request_json TEXT NOT NULL, owner_json TEXT NOT NULL, state TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL, claim_token TEXT, delivery_json TEXT, binding_json TEXT, result_json TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS delegation_revocations (operation_id TEXT PRIMARY KEY, receipt_json TEXT NOT NULL, created INTEGER NOT NULL)")

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA busy_timeout=10000")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    @staticmethod
    def _public(row):
        if row is None:
            return None
        result = {"operation_id": row["operation_id"], "request_digest": row["request_digest"],
                  "state": row["state"], "created": row["created"], "updated": row["updated"]}
        for column, name in (("delivery_json", "delivery"), ("binding_json", "binding"), ("result_json", "result")):
            if row[column] is not None:
                result[name] = json.loads(row[column])
        return result

    def reserve(self, request, owner_receipt, *, now=None):
        instant = _now(now)
        _need(isinstance(request, dict) and isinstance(request.get("owner_ref"), dict), "request_shape_invalid")
        # The fixed adapter has already pinned its owner-thread allowlist and
        # verified the actual owner item. This is shape/time revalidation of
        # that same receipt, not a second model-configurable enrollment route.
        request = parse_request(request, now=instant, source_thread_id=request.get("source_thread_id"),
                                allowed_owner_threads=(request["owner_ref"].get("thread_id"),))
        _check_receipt(owner_receipt, "integrity/delegation-owner-evidence/v1")
        request_digest = digest(request)
        _need(owner_receipt.get("request_digest") == request_digest and owner_receipt.get("owner_ref") == request["owner_ref"]
              and owner_receipt.get("source_thread_id") == request["source_thread_id"]
              and owner_receipt.get("origin_kind") == "observed-owner-message"
              and owner_receipt.get("action_authority") == "not-evaluated", "owner_receipt_binding_mismatch")
        actual_owner = _resolved_owner_ref(request, owner_receipt)
        with self._db() as db:
            _need(db.execute("SELECT 1 FROM delegation_revocations WHERE operation_id=?", (request["operation_id"],)).fetchone() is None, "operation_revoked")
            row = db.execute("SELECT * FROM delegation_operations WHERE operation_id=?", (request["operation_id"],)).fetchone()
            if row is not None:
                _need(row["request_digest"] == request_digest, "operation_request_conflict")
                saved_owner = json.loads(row["owner_json"])
                _need(_resolved_owner_ref(request, saved_owner) == actual_owner
                      and saved_owner.get("evidence_digest") == owner_receipt.get("evidence_digest"),
                      "operation_owner_evidence_conflict")
                return {"reserved": False, "duplicate": True, **self._public(row)}
            db.execute("INSERT INTO delegation_operations (operation_id,request_digest,request_json,owner_json,state,created,updated) VALUES (?,?,?,?,?,?,?)",
                       (request["operation_id"], request_digest, canonical_json(request), canonical_json(owner_receipt), "reserved", instant, instant))
            return {"operation_id": request["operation_id"], "request_digest": request_digest, "reserved": True, "duplicate": False, "state": "reserved"}

    def begin_observation(self, *, source_thread_id, host_id, source_provider, source_room_id,
                          observer_schema, observer_runtime_digest, original_head_turn_id):
        """Begin only after a complete LIVE first page was parsed by the adapter.

        This progress grants no action. Typed control facts may deny a known
        scoped request before completion; no global tombstone is minted here.
        """
        context = dict(source_thread_id=source_thread_id, host_id=host_id, source_provider=source_provider,
                       source_room_id=source_room_id, observer_schema=observer_schema,
                       observer_runtime_digest=observer_runtime_digest, original_head_turn_id=original_head_turn_id)
        _observation_pins(context)
        try:
            with self._db() as db:
                _need(_read_frontier(db, source_thread_id) is None, "control_observation_frontier_exists")
                old = _read_observation_source(db, source_thread_id)
                _need(old is None or all(old[k] == context[k] for k in _OBS_SCOPE), "control_observation_scope_changed")
                _need(_read_observation(db, source_thread_id) is None, "control_observation_already_started")
                _create_projection(db)
                db.execute("CREATE TABLE IF NOT EXISTS observation_sources (source_thread_id TEXT PRIMARY KEY,source_json TEXT NOT NULL)")
                db.execute("CREATE TABLE IF NOT EXISTS observation_sessions (source_thread_id TEXT PRIMARY KEY,state_json TEXT NOT NULL)")
                facts = _source_controls(db, source_thread_id, source_room_id)
                generation = 1 if old is None else old["generation"] + 1
                state = {**context, "generation": generation, "seq": 0, "pages_total": 0, "cursor": None,
                         "history_end_observed": False, "last_page_input_cursor": None, "last_page_turn_ids": [],
                         "seen_cursor_digests": [], "controls_digest": _controls_digest(facts), "control_count": len(facts)}
                metadata = {k: context[k] for k in _OBS_SCOPE}
                metadata.update(generation=generation, controls_digest=state["controls_digest"], stage_digest=None)
                return _write_observation(db, metadata, state)
        except sqlite3.Error:
            raise DelegationError("control_observation_store_invalid") from None

    def _advance_observation(self, *, expected_observation, controls, page_receipt, overlap):
        _observation_checksum(expected_observation, _OBS_STATE_KEYS, "stage_digest")
        _validate_observation_state(expected_observation)
        _observation_checksum(page_receipt, _OBS_PAGE_KEYS, "evidence_digest")
        _observation_pins(page_receipt)
        _need(all(page_receipt[k] == expected_observation[k] for k in _OBS_SCOPE + _OBS_PINS),
              "control_observation_runtime_changed")
        _cursor(page_receipt["input_cursor"])
        _cursor(page_receipt["next_cursor"])
        turns = page_receipt["turn_ids"]
        _need(isinstance(turns, list) and 0 < len(turns) <= 100 and len(set(turns)) == len(turns)
              and all(_token(t, stable=True) for t in turns) and page_receipt["page_complete"] is True
              and type(page_receipt["history_end_observed"]) is bool
              and page_receipt["history_end_observed"] == (page_receipt["next_cursor"] is None),
              "control_observation_page_incomplete")
        facts = _control_facts(controls, page_receipt)
        _need(all(control.get("owner_turn_id") in turns for control in facts.values()), "control_observation_control_outside_page")
        if overlap:
            _need(expected_observation["pages_total"] > 0
                  and page_receipt["input_cursor"] == expected_observation["last_page_input_cursor"]
                  and turns == expected_observation["last_page_turn_ids"], "control_observation_boundary_shifted")
        else:
            _need(not expected_observation["history_end_observed"]
                  and page_receipt["input_cursor"] == expected_observation["cursor"], "control_observation_cursor_conflict")
            if expected_observation["pages_total"] == 0:
                _need(turns[0] == expected_observation["original_head_turn_id"], "control_observation_head_mismatch")
        next_cursor = page_receipt["next_cursor"]
        next_hash = None if next_cursor is None else text_digest(next_cursor)
        allowed = overlap and next_cursor == expected_observation["cursor"]
        _need(next_hash is None or next_hash not in expected_observation["seen_cursor_digests"] or allowed,
              "control_observation_cursor_cycle")
        _need(next_cursor is None or next_cursor != page_receipt["input_cursor"], "control_observation_cursor_cycle")
        try:
            with self._db() as db:
                source = expected_observation["source_thread_id"]
                current = _read_observation(db, source)
                _need(current == expected_observation, "control_observation_sequence_conflict")
                _need(_read_frontier(db, source) is None, "control_observation_frontier_exists")
                metadata = _read_observation_source(db, source)
                _store_control_facts(db, facts)
                all_controls = _source_controls(db, source, current["source_room_id"])
                seen = list(current["seen_cursor_digests"])
                if next_hash is not None and next_hash not in seen:
                    seen.append(next_hash)
                state = {**current, "seq": current["seq"] + 1, "pages_total": current["pages_total"] + (0 if overlap else 1),
                         "cursor": next_cursor, "history_end_observed": page_receipt["history_end_observed"],
                         "last_page_input_cursor": page_receipt["input_cursor"], "last_page_turn_ids": list(turns),
                         "seen_cursor_digests": seen, "controls_digest": _controls_digest(all_controls), "control_count": len(all_controls)}
                return _write_observation(db, metadata, state)
        except sqlite3.Error:
            raise DelegationError("control_observation_store_invalid") from None

    def append_observation(self, *, expected_observation, controls, page_receipt):
        return self._advance_observation(expected_observation=expected_observation, controls=controls,
                                         page_receipt=page_receipt, overlap=False)

    def resume_observation(self, *, expected_observation, controls, page_receipt):
        """LIVE reread of the whole last committed page, including new controls.

        Saved cursors are locators only. The adapter resumes from this newly
        observed next cursor; shifted/missing page anchors fail closed.
        """
        return self._advance_observation(expected_observation=expected_observation, controls=controls,
                                         page_receipt=page_receipt, overlap=True)

    def discard_observation(self, *, expected_observation):
        _observation_checksum(expected_observation, _OBS_STATE_KEYS, "stage_digest")
        with self._db() as db:
            source = expected_observation["source_thread_id"]
            _need(_read_observation(db, source) == expected_observation, "control_observation_sequence_conflict")
            _write_observation(db, _read_observation_source(db, source), None)

    def finalize_observation(self, *, expected_observation, controls, refresh_receipt):
        _observation_checksum(expected_observation, _OBS_STATE_KEYS, "stage_digest")
        _observation_checksum(refresh_receipt, _OBS_REFRESH_KEYS, "evidence_digest")
        _observation_pins(refresh_receipt)
        _need(expected_observation["history_end_observed"] is True and expected_observation["pages_total"] > 0,
              "control_observation_history_incomplete")
        _need(all(refresh_receipt[k] == expected_observation[k] for k in _OBS_SCOPE + _OBS_PINS)
              and _token(refresh_receipt["frontier_turn_id"], stable=True)
              and refresh_receipt["boundary_turn_complete"] is True and refresh_receipt["coverage_complete"] is True,
              "control_observation_refresh_incomplete")
        facts = _control_facts(controls, refresh_receipt)
        try:
            with self._db() as db:
                source = expected_observation["source_thread_id"]
                _need(_read_observation(db, source) == expected_observation, "control_observation_sequence_conflict")
                _need(_read_frontier(db, source) is None, "control_observation_frontier_exists")
                metadata = _read_observation_source(db, source)
                _store_control_facts(db, facts)
                all_controls = _source_controls(db, source, expected_observation["source_room_id"])
                coverage = {k: expected_observation[k] for k in _OBS_SCOPE}
                coverage.update(frontier_turn_id=refresh_receipt["frontier_turn_id"], previous_frontier_turn_id=None,
                                history_end_observed=True, boundary_turn_complete=True, coverage_complete=True,
                                control_evidence_digests=sorted(c["evidence_digest"] for c in all_controls))
                coverage["evidence_digest"] = digest(coverage)
                _coverage(coverage)
                checksum = _controls_digest(all_controls)
                frontier = {k: coverage[k] for k in _OBS_SCOPE + ("frontier_turn_id",)}
                frontier.update(version=1, receipt_digest=coverage["evidence_digest"], controls_digest=checksum)
                metadata["controls_digest"] = checksum
                _write_observation(db, metadata, None)
                db.execute("INSERT INTO frontiers VALUES (?,?,?,?,?,?,?,?,?)", (source, coverage["host_id"],
                           coverage["source_provider"], coverage["source_room_id"], coverage["frontier_turn_id"], 1,
                           frontier["receipt_digest"], checksum, canonical_json(coverage)))
                return frontier
        except sqlite3.Error:
            raise DelegationError("control_observation_store_invalid") from None

    def capture_projection(self, *, source_thread_id, host_id, expected_frontier, controls, coverage_receipt):
        """Store Native-derived facts only, after full proof in the fixed adapter.

        Every control, for every operation, precedes the frontier in ONE CAS
        transaction. No reservation, revocation tombstone, execution or Memory
        admission is performed. No external cache/projection JSON is imported.
        """
        coverage = _coverage(coverage_receipt)
        _need(coverage["source_thread_id"] == source_thread_id and coverage["host_id"] == host_id,
              "control_coverage_source_mismatch")
        if expected_frontier is None:
            _need(coverage["previous_frontier_turn_id"] is None and coverage["history_end_observed"] is True,
                  "control_projection_bootstrap_incomplete")
        else:
            _need(isinstance(expected_frontier, dict) and set(expected_frontier) == _FRONTIER_KEYS,
                  "control_frontier_invalid")
            _need(all(expected_frontier[key] == coverage[key] for key in ("source_thread_id", "host_id", "source_provider", "source_room_id")),
                  "control_projection_scope_changed")
            _need(coverage["previous_frontier_turn_id"] == expected_frontier["frontier_turn_id"]
                  and coverage["boundary_turn_complete"] is True, "control_projection_boundary_incomplete")
        _need(isinstance(controls, list) and len(controls) <= 10000, "control_projection_controls_invalid")
        facts = {}
        identities = {}
        for control in controls:
            control = _projection_control(control, source_thread_id=source_thread_id, room_id=coverage["source_room_id"])
            identity = (control["owner_turn_id"], control["owner_item_id"])
            proof_digest = control["evidence_digest"]
            _need(identity not in identities or identities[identity] == proof_digest, "control_projection_identity_conflict")
            identities[identity] = proof_digest
            facts[proof_digest] = control
        _need(sorted(facts) == coverage["control_evidence_digests"], "control_projection_controls_incomplete")
        try:
            with self._db() as db:
                if _projection_tables(db):
                    actual = _read_frontier(db, source_thread_id)
                else:
                    actual = None
                _need(actual == expected_frontier, "control_projection_frontier_conflict")
                _need(_read_observation(db, source_thread_id) is None, "control_observation_already_started")
                metadata = _read_observation_source(db, source_thread_id)
                _need(metadata is None or all(metadata[k] == coverage[k] for k in _OBS_SCOPE),
                      "control_projection_scope_changed")
                db.execute("CREATE TABLE IF NOT EXISTS observed_controls (source_thread_id TEXT NOT NULL, operation_id TEXT NOT NULL, evidence_digest TEXT NOT NULL, receipt_json TEXT NOT NULL, owner_turn_id TEXT NOT NULL, owner_item_id TEXT NOT NULL, PRIMARY KEY(source_thread_id,operation_id,evidence_digest), UNIQUE(source_thread_id,owner_turn_id,owner_item_id))")
                db.execute("CREATE TABLE IF NOT EXISTS frontiers (source_thread_id TEXT PRIMARY KEY, host_id TEXT NOT NULL, source_provider TEXT NOT NULL, source_room_id TEXT, frontier_turn_id TEXT NOT NULL, version INTEGER NOT NULL, receipt_digest TEXT NOT NULL, controls_digest TEXT NOT NULL, receipt_json TEXT NOT NULL)")
                for control in facts.values():
                    row = db.execute("SELECT evidence_digest,receipt_json FROM observed_controls WHERE source_thread_id=? AND owner_turn_id=? AND owner_item_id=?",
                                     (source_thread_id, control["owner_turn_id"], control["owner_item_id"])).fetchone()
                    encoded = canonical_json(control)
                    _need(row is None or (row["evidence_digest"] == control["evidence_digest"] and row["receipt_json"] == encoded),
                          "control_projection_identity_conflict")
                    db.execute("INSERT OR IGNORE INTO observed_controls VALUES (?,?,?,?,?,?)",
                               (source_thread_id, control["operation_id"], control["evidence_digest"], encoded,
                                control["owner_turn_id"], control["owner_item_id"]))
                all_controls = _source_controls(db, source_thread_id, coverage["source_room_id"])
                frontier = {key: coverage[key] for key in ("source_thread_id", "host_id", "source_provider", "source_room_id", "frontier_turn_id")}
                controls_digest = _controls_digest(all_controls)
                # Exact CAS and all Native fact/identity checks above still apply.
                # A verified reobservation of identical coverage is not a new
                # frontier generation and must not invalidate another observer.
                if (actual is not None and all(actual[key] == frontier[key] for key in frontier)
                        and actual["controls_digest"] == controls_digest):
                    return actual
                frontier.update(version=1 if actual is None else actual["version"] + 1,
                                receipt_digest=coverage["evidence_digest"], controls_digest=controls_digest)
                if metadata is not None:
                    metadata["controls_digest"] = frontier["controls_digest"]
                    _write_observation(db, metadata, None)
                db.execute("INSERT INTO frontiers VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(source_thread_id) DO UPDATE SET host_id=excluded.host_id,source_provider=excluded.source_provider,source_room_id=excluded.source_room_id,frontier_turn_id=excluded.frontier_turn_id,version=excluded.version,receipt_digest=excluded.receipt_digest,controls_digest=excluded.controls_digest,receipt_json=excluded.receipt_json",
                           (source_thread_id, host_id, frontier["source_provider"], frontier["source_room_id"], frontier["frontier_turn_id"],
                            frontier["version"], frontier["receipt_digest"], frontier["controls_digest"], canonical_json(coverage)))
                return frontier
        except sqlite3.Error:
            raise DelegationError("control_projection_store_invalid") from None

    def claim(self, operation_id, request_digest, receiving_evidence, *, now=None, epoch=0):
        instant = _now(now)
        _need(_token(operation_id, stable=True), "operation_id_invalid")
        _check_receipt(receiving_evidence, "integrity/delegation-delivery-evidence/v1")
        with self._db() as db:
            row = db.execute("SELECT * FROM delegation_operations WHERE operation_id=?", (operation_id,)).fetchone()
            _need(row is not None, "operation_not_reserved")
            _need(row["request_digest"] == request_digest, "operation_request_conflict")
            _need(db.execute("SELECT 1 FROM delegation_revocations WHERE operation_id=?", (operation_id,)).fetchone() is None, "operation_revoked")
            request = json.loads(row["request_json"])
            # Capture and claim share the same SQLite write lock. A control
            # captured after an adapter's earlier read cannot slip into the
            # read-controls -> claim gap. Facts for unrelated owners stay DATA.
            _need(not _projected_revoked(db, row), "operation_revoked")
            _need(receiving_evidence.get("operation_id") == operation_id
                  and receiving_evidence.get("request_digest") == request_digest
                  and receiving_evidence.get("body_sha256") == text_digest(canonical_json(request))
                  and receiving_evidence.get("source_thread_id") == request["source_thread_id"]
                  and receiving_evidence.get("target_host_id") == request["target"]["host_id"]
                  and receiving_evidence.get("target_thread_id") == request["target"]["thread_id"]
                  and all(_token(receiving_evidence.get(k), stable=True) for k in ("source_turn_id", "source_item_id", "receiving_turn_id", "receiving_item_id"))
                  and receiving_evidence.get("action_authority") == "not-evaluated"
                  and receiving_evidence.get("reported_wrapper_source_trusted") is False, "delivery_receipt_binding_mismatch")
            if row["state"] != "reserved":
                return {"execute": False, "duplicate": True, **self._public(row)}
            parse_request(request, now=instant, source_thread_id=request["source_thread_id"],
                          allowed_owner_threads=(request["owner_ref"]["thread_id"],))
            binding = binding_receipt(request, epoch=epoch, owner_receipt=json.loads(row["owner_json"]))
            claim_token = secrets.token_urlsafe(32)
            db.execute("UPDATE delegation_operations SET state='executing',updated=?,claim_token=?,delivery_json=?,binding_json=? WHERE operation_id=? AND state='reserved'",
                       (instant, claim_token, canonical_json(receiving_evidence), canonical_json(binding), operation_id))
            return {"execute": True, "duplicate": False, "operation_id": operation_id, "request_digest": request_digest,
                    "state": "executing", "claim_token": claim_token, "binding": binding}

    def finish(self, operation_id, claim_token, *, status, result, now=None):
        _need(status in {"completed", "failed", "unknown"}, "terminal_status_invalid")
        encoded = canonical_json(result)
        _need(len(encoded.encode("utf-8")) <= MAX_BYTES // 2, "result_oversized")
        instant = _now(now)
        with self._db() as db:
            row = db.execute("SELECT * FROM delegation_operations WHERE operation_id=?", (operation_id,)).fetchone()
            _need(row is not None and isinstance(claim_token, str) and secrets.compare_digest(row["claim_token"] or "", claim_token), "claim_not_owned")
            if row["state"] in {"completed", "failed", "unknown"}:
                _need(row["state"] == status and row["result_json"] == encoded, "terminal_result_conflict")
                return self._public(row)
            _need(row["state"] == "executing", "operation_not_executing")
            db.execute("UPDATE delegation_operations SET state=?,result_json=?,updated=? WHERE operation_id=?", (status, encoded, instant, operation_id))
            return self._public(db.execute("SELECT * FROM delegation_operations WHERE operation_id=?", (operation_id,)).fetchone())

    def revoke(self, operation_id, verified_control_receipt, *, now=None):
        _check_receipt(verified_control_receipt, "integrity/delegation-control-evidence/v1")
        _need(verified_control_receipt.get("operation_id") == operation_id
              and verified_control_receipt.get("action") == "revoke"
              and verified_control_receipt.get("origin_kind") == "observed-owner-message"
              and _token(verified_control_receipt.get("source_thread_id"), stable=True), "control_receipt_binding_mismatch")
        with self._db() as db:
            row = db.execute("SELECT * FROM delegation_operations WHERE operation_id=?", (operation_id,)).fetchone()
            if row is not None:
                request = json.loads(row["request_json"])
                _need(verified_control_receipt["source_thread_id"] in {request["source_thread_id"], request["owner_ref"]["thread_id"]}, "control_source_mismatch")
            else:
                _need(verified_control_receipt["source_thread_id"] == MEDOR_THREAD, "control_source_mismatch")
            db.execute("INSERT OR IGNORE INTO delegation_revocations VALUES (?,?,?)", (operation_id, canonical_json(verified_control_receipt), _now(now)))
            return {"operation_id": operation_id, "revoked": True, "already_started": row is not None and row["state"] != "reserved"}

    def status(self, operation_id):
        _need(_token(operation_id, stable=True), "operation_id_invalid")
        with self._db() as db:
            row = db.execute("SELECT * FROM delegation_operations WHERE operation_id=?", (operation_id,)).fetchone()
            revoked = db.execute("SELECT 1 FROM delegation_revocations WHERE operation_id=?", (operation_id,)).fetchone() is not None
            projected_revoked = _projected_revoked(db, row) if row is not None else False
            return {"operation_id": operation_id, "found": row is not None, "revoked": revoked or projected_revoked, **(self._public(row) or {})}
