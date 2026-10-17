# SPDX-License-Identifier: Apache-2.0
"""Deterministic Web/Codex handoff state; Computer Use is an external adapter."""
from __future__ import annotations

from integrity_bridges.configuration import value as _integrity_value, require_config as _integrity_require_config
from integrity_bridges.web_url import CONVERSATION_PATTERN as _public_web_pattern


import hashlib
import json
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

PROTOCOL_VERSION = "integrity-ping-pong/v1"
FINAL_CODEX = {"completed", "failed", "interrupted", "cancelled"}
STATUSES = {"DONE", "NEED_WEB", "BLOCKED"}
DIRECTIONS = {"PING", "PONG"}
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}")
HOST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
WEB_URL = re.compile(_public_web_pattern)
EFFECT_CLASSES = {"read-only", "mutation"}
SCOPE_FIELDS = {"goal", "allowed_targets", "effect_class", "acceptance", "verification"}


def validate_scope(scope) -> dict:
    """Validate the owner scope a PING carries: goal, means, acceptance and how it is checked.

    Anything not declared in ``allowed_targets`` is outside the workflow. The scope is
    bound once at registration; its digest is the anchor that PING markers and the
    scope synapse echo after a context compaction.
    """
    if not isinstance(scope, dict) or set(scope) != SCOPE_FIELDS:
        raise HandoffError("scope_shape_invalid")
    goal, targets = scope["goal"], scope["allowed_targets"]
    if not isinstance(goal, str) or not 1 <= len(goal.strip()) <= 2000:
        raise HandoffError("scope_goal_invalid")
    if (not isinstance(targets, list) or not 1 <= len(targets) <= 64
            or any(not isinstance(item, str) or not 1 <= len(item.strip()) <= 256 for item in targets)):
        raise HandoffError("scope_targets_invalid")
    if scope["effect_class"] not in EFFECT_CLASSES:
        raise HandoffError("scope_effect_class_invalid")
    acceptance = scope["acceptance"]
    if (not isinstance(acceptance, list) or not 1 <= len(acceptance) <= 32
            or any(not isinstance(item, str) or not item.strip() for item in acceptance)):
        raise HandoffError("scope_acceptance_invalid")
    if not isinstance(scope["verification"], str) or not scope["verification"].strip():
        raise HandoffError("scope_verification_invalid")
    return scope


def scope_digest(scope: dict) -> str:
    return "sha256:" + hashlib.sha256(_canonical(validate_scope(scope)).encode("utf-8")).hexdigest()


class HandoffError(RuntimeError):
    pass


# The executor states its outcome on one line; the host then checks that claim against what it observed.
PONG_CLAIM = re.compile(r"(?im)^[ \t>*`]*PONG\s+status=(DONE|NEED_WEB|BLOCKED)\b")
PONG_FOOTER = (
    "End your final message with one line `PONG status=DONE`, `PONG status=NEED_WEB` or "
    "`PONG status=BLOCKED` and name the blocking target if BLOCKED. The host checks this "
    "claim against the commands, file changes and turn status it observed."
)
MAX_OBSERVED = 40


def observe_turn(turn: dict) -> dict:
    """What the host saw in one Codex turn, independent of what the executor wrote about it."""
    commands, files, tools, last_text = [], set(), [], ""
    for item in turn.get("items") or []:
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        if kind == "commandExecution":
            exit_code = item.get("exitCode")
            commands.append({"command": str(item.get("command") or "")[:300],
                             "exit_code": exit_code if type(exit_code) is int else None,
                             "status": str(item.get("status") or "")})
        elif kind == "fileChange":
            for change in item.get("changes") or []:
                if isinstance(change, dict) and change.get("path"):
                    files.add(str(change["path"])[:400])
        elif kind == "mcpToolCall":
            tools.append(f"{item.get('server') or 'unknown'}/{item.get('tool') or 'unknown'}:{item.get('status') or 'unknown'}")
        elif kind == "agentMessage":
            last_text = str(item.get("text") or "")
    failed = [c for c in commands if c["exit_code"] not in (None, 0)]
    return {"turn_status": str(turn.get("status") or ""), "command_count": len(commands),
            "failed_command_count": len(failed), "commands": commands[-MAX_OBSERVED:],
            "last_command_failed": bool(commands) and commands[-1]["exit_code"] not in (None, 0),
            "files_changed": sorted(files)[:200], "tool_calls": tools[-MAX_OBSERVED:],
            "final_message_tail": last_text[-2000:]}


def claimed_status(observation: dict):
    claims = PONG_CLAIM.findall(observation.get("final_message_tail") or "")
    return claims[-1].upper() if claims else None


def host_verdict(observation: dict, claim, scope) -> tuple[str, list]:
    """Status the workflow may take from this PONG, and every contradiction the host saw.

    A DONE claim stops the workflow only when nothing observed contradicts it; otherwise
    the PONG goes back to the Web planner as NEED_WEB with the contradictions attached.
    """
    contradictions = []
    if claim is None:
        contradictions.append("no_status_claim")
    if observation["turn_status"] != "completed":
        contradictions.append("turn_" + (observation["turn_status"] or "unknown"))
    effect = (scope or {}).get("effect_class")
    if effect == "read-only" and observation["files_changed"]:
        contradictions.append("read_only_scope_changed_files")
    if claim == "DONE":
        if observation["last_command_failed"]:
            contradictions.append("last_command_failed")
        if (effect == "mutation" and not observation["files_changed"] and not observation["command_count"]
                and not observation["tool_calls"]):
            contradictions.append("no_observed_effect")
    status = claim or "NEED_WEB"
    if contradictions and status == "DONE":
        status = "NEED_WEB"
    return status, contradictions


def _canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _material_digest(payload: dict) -> str:
    """Digest business progress, excluding transport and sequence metadata."""
    material = {
        "status": payload["status"],
        "delta": payload["delta"],
        "result": payload["result"],
        "evidence": payload["evidence"],
    }
    return "sha256:" + hashlib.sha256(_canonical(material).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Envelope:
    protocol_version: str
    workflow_id: str
    direction: str
    host_id: str
    codex_thread_id: str
    codex_turn_id: str
    sequence: int
    status: str
    checkpoint_digest: str
    delta: object
    result: object
    evidence: object
    previous_sequence: int | None
    request_id: str

    @classmethod
    def build(cls, *, workflow_id, direction, host_id, codex_thread_id, codex_turn_id,
              sequence, status, delta, result, evidence, previous_sequence, request_id):
        core = {
            "protocol_version": PROTOCOL_VERSION, "workflow_id": workflow_id,
            "direction": direction, "host_id": host_id, "codex_thread_id": codex_thread_id,
            "codex_turn_id": codex_turn_id, "sequence": sequence, "status": status,
            "delta": delta, "result": result, "evidence": evidence,
            "previous_sequence": previous_sequence, "request_id": request_id,
        }
        digest = "sha256:" + hashlib.sha256(_canonical(core).encode("utf-8")).hexdigest()
        return cls(checkpoint_digest=digest, **core)

    def validate(self):
        if self.protocol_version != PROTOCOL_VERSION:
            raise HandoffError("protocol_version_mismatch")
        for value in (self.workflow_id, self.codex_thread_id,
                      self.codex_turn_id, self.request_id):
            if not isinstance(value, str) or not ID.fullmatch(value):
                raise HandoffError("invalid_identity")
        if not isinstance(self.host_id, str) or not HOST_ID.fullmatch(self.host_id):
            raise HandoffError("invalid_host_identity")
        if self.direction not in DIRECTIONS or self.status not in STATUSES:
            raise HandoffError("invalid_envelope_enum")
        if type(self.sequence) is not int or self.sequence < 1:
            raise HandoffError("invalid_sequence")
        if self.previous_sequence is not None and (
            type(self.previous_sequence) is not int or self.previous_sequence < 1
        ):
            raise HandoffError("invalid_previous_sequence")
        if not isinstance(self.checkpoint_digest, str) or not DIGEST.fullmatch(self.checkpoint_digest):
            raise HandoffError("invalid_checkpoint_digest")
        expected = Envelope.build(
            workflow_id=self.workflow_id, direction=self.direction, host_id=self.host_id,
            codex_thread_id=self.codex_thread_id, codex_turn_id=self.codex_turn_id,
            sequence=self.sequence, status=self.status, delta=self.delta, result=self.result,
            evidence=self.evidence, previous_sequence=self.previous_sequence,
            request_id=self.request_id,
        ).checkpoint_digest
        if expected != self.checkpoint_digest:
            raise HandoffError("checkpoint_digest_mismatch")

    def as_dict(self):
        return dict(self.__dict__)


class HandoffStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS workflows (
                id TEXT PRIMARY KEY, web_url TEXT NOT NULL, host_id TEXT NOT NULL,
                thread_id TEXT NOT NULL, last_sequence INTEGER NOT NULL DEFAULT 0,
                last_direction TEXT, last_digest TEXT, stopped TEXT)""")
            columns = {row[1] for row in db.execute("PRAGMA table_info(workflows)")}
            if "scope" not in columns:
                db.execute("ALTER TABLE workflows ADD COLUMN scope TEXT")
            try:
                db.execute("CREATE UNIQUE INDEX IF NOT EXISTS one_live_workflow_per_thread "
                           "ON workflows(host_id, thread_id) WHERE stopped IS NULL")
            except sqlite3.IntegrityError:
                # A legacy ledger already holds two live workflows on one thread; register()
                # still serializes new registrations under an immediate write lock.
                pass
            db.execute("""CREATE TABLE IF NOT EXISTS envelopes (
                workflow_id TEXT NOT NULL, sequence INTEGER NOT NULL, direction TEXT NOT NULL,
                digest TEXT NOT NULL, payload TEXT NOT NULL, delivery_state TEXT,
                PRIMARY KEY(workflow_id, sequence))""")

    def register(self, workflow_id, web_url, host_id, thread_id, scope=None):
        if not ID.fullmatch(workflow_id) or not HOST_ID.fullmatch(host_id) or not ID.fullmatch(thread_id):
            raise HandoffError("invalid_workflow_identity")
        if not WEB_URL.fullmatch(web_url):
            raise HandoffError("exact_web_target_required")
        encoded_scope = None if scope is None else _canonical(validate_scope(scope))
        identity = (web_url, host_id, thread_id)
        with closing(sqlite3.connect(self.path, isolation_level=None, timeout=10)) as db:
            # The check and the insert run under one write lock, so concurrent callers
            # cannot both see a free thread.
            db.execute("BEGIN IMMEDIATE")
            try:
                current = db.execute("SELECT web_url,host_id,thread_id,scope FROM workflows WHERE id=?",
                                     (workflow_id,)).fetchone()
                if current and (current[:3] != identity or current[3] != encoded_scope):
                    raise HandoffError("workflow_identity_conflict")
                # One thread holds one live workflow: a thread that carried another task must not
                # bring that task's goals, preconditions or acceptance into this one.
                other = db.execute(
                    "SELECT id FROM workflows WHERE host_id=? AND thread_id=? AND id<>? AND stopped IS NULL",
                    (host_id, thread_id, workflow_id)).fetchone()
                if other:
                    raise HandoffError("thread_bound_to_active_workflow")
                if not current:
                    try:
                        db.execute("INSERT INTO workflows(id,web_url,host_id,thread_id,scope) VALUES(?,?,?,?,?)",
                                   (workflow_id, *identity, encoded_scope))
                    except sqlite3.IntegrityError as exc:
                        raise HandoffError("thread_bound_to_active_workflow") from exc
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def workflow(self, workflow_id):
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute("SELECT id,web_url,host_id,thread_id,last_sequence,last_direction,stopped,scope "
                             "FROM workflows WHERE id=?", (workflow_id,)).fetchone()
        if not row:
            return None
        keys = ("id", "web_url", "host_id", "thread_id", "last_sequence", "last_direction", "stopped", "scope")
        value = dict(zip(keys, row))
        value["scope"] = None if value["scope"] is None else json.loads(value["scope"])
        return value

    def envelope(self, workflow_id, sequence):
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute("SELECT payload,delivery_state FROM envelopes WHERE workflow_id=? AND sequence=?",
                             (workflow_id, sequence)).fetchone()
        return None if not row else {**json.loads(row[0]), "delivery_state": row[1]}

    def ping_marker(self, workflow_id, sequence):
        """Return the marker a delivered PING prompt starts with; hooks anchor the scope on it."""
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute("SELECT scope FROM workflows WHERE id=?", (workflow_id,)).fetchone()
        if not row:
            raise HandoffError("workflow_not_registered")
        if type(sequence) is not int or sequence < 1:
            raise HandoffError("invalid_sequence")
        anchor = "" if row[0] is None else " anchor=" + scope_digest(json.loads(row[0]))
        return f"[INTEGRITY_PING workflow={workflow_id} sequence={sequence}{anchor}]"

    def accept(self, envelope: Envelope, *, codex_status=None):
        envelope.validate()
        if envelope.direction == "PONG" and codex_status not in FINAL_CODEX:
            raise HandoffError("codex_turn_not_terminal")
        payload = _canonical(envelope.as_dict())
        with closing(sqlite3.connect(self.path)) as db, db:
            workflow = db.execute(
                "SELECT host_id,thread_id,last_sequence,last_direction,stopped,scope "
                "FROM workflows WHERE id=?", (envelope.workflow_id,)).fetchone()
            if not workflow:
                raise HandoffError("workflow_not_registered")
            host_id, thread_id, last_seq, last_direction, stopped, scope = workflow
            if (envelope.host_id, envelope.codex_thread_id) != (host_id, thread_id):
                raise HandoffError("workflow_target_mismatch")
            existing = db.execute(
                "SELECT digest,payload FROM envelopes WHERE workflow_id=? AND sequence=?",
                (envelope.workflow_id, envelope.sequence)).fetchone()
            if existing:
                if existing != (envelope.checkpoint_digest, payload):
                    raise HandoffError("sequence_content_conflict")
                return {"accepted": False, "replayed": True}
            if stopped:
                raise HandoffError("workflow_stopped")
            if envelope.sequence != last_seq + 1 or envelope.previous_sequence != (last_seq or None):
                raise HandoffError("sequence_gap_or_replay")
            if last_direction == envelope.direction:
                raise HandoffError("direction_must_alternate")
            if scope and envelope.direction == "PONG" and envelope.status == "BLOCKED":
                # A blocker stops the workflow, so it must name something the owner put in
                # scope. A precondition revived from an earlier task does not qualify.
                evidence = _canonical({"result": envelope.result, "evidence": envelope.evidence}).casefold()
                targets = json.loads(scope)["allowed_targets"]
                if not any(target.casefold() in evidence for target in targets):
                    raise HandoffError("blocker_outside_scope")
            if last_seq:
                previous_payload = db.execute(
                    "SELECT payload FROM envelopes WHERE workflow_id=? AND sequence=?",
                    (envelope.workflow_id, last_seq),
                ).fetchone()
                if previous_payload and _material_digest(json.loads(previous_payload[0])) == _material_digest(
                    envelope.as_dict()
                ):
                    raise HandoffError("no_material_delta")
            delivery = "prepared" if envelope.direction == "PONG" else None
            db.execute("INSERT INTO envelopes VALUES(?,?,?,?,?,?)", (
                envelope.workflow_id, envelope.sequence, envelope.direction,
                envelope.checkpoint_digest, payload, delivery))
            stop = envelope.status if envelope.status in {"DONE", "BLOCKED"} else None
            db.execute("UPDATE workflows SET last_sequence=?,last_direction=?,last_digest=?,stopped=? WHERE id=?",
                       (envelope.sequence, envelope.direction, envelope.checkpoint_digest,
                        stop, envelope.workflow_id))
            return {"accepted": True, "replayed": False, "stopped": stop}

    def begin_delivery(self, workflow_id, sequence, web_url):
        with closing(sqlite3.connect(self.path)) as db, db:
            row = db.execute(
                "SELECT w.web_url,e.payload,e.digest,e.delivery_state,e.direction "
                "FROM workflows w JOIN envelopes e ON e.workflow_id=w.id "
                "WHERE w.id=? AND e.sequence=?", (workflow_id, sequence)).fetchone()
            if not row or row[4] != "PONG":
                raise HandoffError("pong_not_prepared")
            expected_url, payload, digest, state, _ = row
            if web_url != expected_url:
                raise HandoffError("web_target_mismatch")
            if state == "delivered":
                return {"deliver": False, "already_delivered": True}
            if state == "delivering":
                raise HandoffError("delivery_outcome_unknown_reconcile_target")
            db.execute("UPDATE envelopes SET delivery_state='delivering' WHERE workflow_id=? AND sequence=?",
                       (workflow_id, sequence))
            marker = f"[INTEGRITY_PONG workflow={workflow_id} sequence={sequence} checkpoint={digest}]"
            return {"deliver": True, "web_url": expected_url, "marker": marker,
                    "message": marker + "\n" + payload}

    def reconcile_delivery(self, workflow_id, sequence, observed_marker):
        with closing(sqlite3.connect(self.path)) as db, db:
            row = db.execute("SELECT digest,delivery_state FROM envelopes WHERE workflow_id=? AND sequence=?",
                             (workflow_id, sequence)).fetchone()
            if not row:
                raise HandoffError("pong_not_prepared")
            marker = f"[INTEGRITY_PONG workflow={workflow_id} sequence={sequence} checkpoint={row[0]}]"
            if observed_marker == marker:
                db.execute("UPDATE envelopes SET delivery_state='delivered' WHERE workflow_id=? AND sequence=?",
                           (workflow_id, sequence))
                return {"delivered": True}
            if row[1] == "delivering":
                db.execute("UPDATE envelopes SET delivery_state='prepared' WHERE workflow_id=? AND sequence=?",
                           (workflow_id, sequence))
            return {"delivered": False, "retry_same_envelope_only": True}
