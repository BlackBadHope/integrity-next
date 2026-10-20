#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Codex Native evidence adapter for an owning receiving hook.

Only pinned installed code and the existing owner Desktop Native tool host are
used. Hook stdin and the displayed XML source are discovery DATA. The selected
Native thread/turn, completed source tool call and original human item establish
provenance. The portable ledger claims an operation once; this adapter neither
executes its task nor transfers a Memory turn reference or target permission.
"""

from __future__ import annotations

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import sys
import time
import uuid
import xml.etree.ElementTree as XML
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

PROTOCOL = "integrity/delegation-codex-receiving/v1"
CONFIG_PROTOCOL = "integrity/delegation-codex-config/v1"
MAX_CHARS = 20000
MAX_PAGES = 12
OWNER_LOOKUP_PAGES = 24
PREPARATION_DEADLINE = 180.0
MAX_HOOK_BYTES = 1024 * 1024
# Twelve bounded durable history pages take about five seconds each on this host.
# This is one total evidence budget; each IPC request retains its shorter cap.
NATIVE_DEADLINE = 65.0
NATIVE_READ_TIMEOUT = 30.0
MAX_OWNER_AGE = 24 * 60 * 60
OBSERVER_SCHEMA = "integrity/codex-native-control-observer/v1"
MAX_SESSION_HEADER = 1024 * 1024
FRAME = "BEGIN_INTEGRITY_DELEGATED_TASK"
NATIVE_BRIDGE_SEND_TOOLS = frozenset({"codex_send_prompt",
                                     "integrity_private_memory_v2.codex_send_prompt"})
IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z")
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
NATIVE_THREAD = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z")
DIAGNOSTIC_ACTOR = _integrity_value('binding_diagnostic_actor')
DIAGNOSTIC_NODENY_ACTOR = _integrity_value('binding_diagnostic_nodeny_actor')
DIAGNOSTIC_ACTORS = frozenset({DIAGNOSTIC_ACTOR, DIAGNOSTIC_NODENY_ACTOR})
DIAGNOSTIC_PHASE_ROOT = Path(_integrity_value('path_d5fd52cfb7f6'))
DIAGNOSTIC_PHASES = frozenset({"payload-ready", "core-import-start", "core-import-done",
    "bridge-import-start", "bridge-import-done", "discovery-start", "discovery-done",
    "list-tools-start", "list-tools-done", "read-current-start", "read-current-done",
    "read-source-start", "read-source-done", "read-owner-start", "read-owner-done",
    "proof-ready", "result-ready", "error"})
WEB_CONTEXT = re.compile(
    r"<delivery_context>\nclient=(web/windows|android)\ndelivery_channel=chatgpt\n"
    r"room_id=([A-Za-z0-9._:-]{1,128}) message_id=([A-Za-z0-9._:-]{1,128}) "
    r"reply_to_message_id=(?:null|[A-Za-z0-9._:-]{1,128})\n(.*?)</delivery_context>\Z", re.DOTALL
)
WRAPPER = re.compile(
    r"<codex_delegation>\s*<source_thread_id>[^<]*</source_thread_id>\s*"
    r"<input>(.*?)</input>\s*</codex_delegation>\Z", re.DOTALL
)
XML_ENTITY = re.compile(r"&(?:amp|lt|gt|apos|quot|#[0-9]+|#x[0-9a-fA-F]+);")


class AdapterError(ValueError):
    """Content-free error; never include rejected payloads or exception text."""


def need(condition: bool, code: str) -> None:
    if not condition:
        raise AdapterError(code)


def identity(value: Any, code: str) -> str:
    need(isinstance(value, str) and IDENTITY.fullmatch(value) is not None, code)
    return value


def token(value: Any, code: str) -> str:
    need(isinstance(value, str) and TOKEN.fullmatch(value) is not None, code)
    return value


def unique(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def object_json(raw: str) -> dict:
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(
                               AdapterError("invalid_json_constant")))
    except AdapterError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise AdapterError("invalid_json") from None
    need(isinstance(value, dict), "object_required")
    return value


def load_pinned(path: str, sha256: str, name: str):
    need(isinstance(path, str) and Path(path).is_absolute(), "module_path_invalid")
    need(isinstance(sha256, str) and SHA256.fullmatch(sha256) is not None,
         "module_digest_invalid")
    source = Path(path)
    try:
        raw = source.read_bytes()
    except OSError:
        raise AdapterError("pinned_module_unavailable") from None
    need(hashlib.sha256(raw).hexdigest() == sha256, "pinned_module_digest_mismatch")
    # Execute the exact verified bytes, avoiding a read/import replacement race.
    spec = importlib.util.spec_from_file_location(name, source)
    need(spec is not None, "pinned_module_invalid")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(raw, str(source), "exec"), module.__dict__)
    return module


def validate_config(config: dict) -> dict:
    need(config.get("protocol") == CONFIG_PROTOCOL, "config_protocol_invalid")
    identity(config.get("source_thread_id"), "config_identity_invalid")
    for field in ("source_host_id", "source_room_id", "target_machine_id"):
        token(config.get(field), "config_identity_invalid")
    owner_threads = config.get("allowed_owner_threads")
    need(isinstance(owner_threads, dict) and bool(owner_threads), "config_owners_invalid")
    for thread, context in owner_threads.items():
        identity(thread, "config_owner_thread_invalid")
        need(isinstance(context, dict) and set(context) == {"host_id", "room_id"},
             "config_owner_context_invalid")
        token(context["host_id"], "config_owner_host_invalid")
        if context["room_id"] is not None:
            token(context["room_id"], "config_owner_room_invalid")
    need(owner_threads.get(config["source_thread_id"]) == {
        "host_id": config["source_host_id"], "room_id": config["source_room_id"]},
        "config_source_owner_mismatch")
    temporary = config.get("temporary_owner_expiry", {})
    need(isinstance(temporary, dict), "config_temporary_owners_invalid")
    for thread, expiry in temporary.items():
        need(thread in owner_threads and thread != config["source_thread_id"]
             and type(expiry) is int and expiry > 0, "config_temporary_owner_invalid")
    hosts = config.get("allowed_native_target_host_ids")
    need(isinstance(hosts, list) and hosts == ["local"], "config_target_hosts_invalid")
    ledger_path = config.get("ledger_path")
    need(isinstance(ledger_path, str) and Path(ledger_path).is_absolute(),
         "config_ledger_path_invalid")
    return config


def owner_current(config: dict, owner_thread_id: str) -> None:
    """An explicitly temporary owner source never becomes permanent trust."""
    expiry = config.get("temporary_owner_expiry", {}).get(owner_thread_id)
    need(expiry is None or int(time.time()) < expiry, "temporary_owner_expired")


def owner_freshness(request: dict, started_at: Any, *, turn_id: str | None = None,
                    item_id: str | None = None) -> dict:
    """Use observed Native turn time; a fresh envelope cannot refresh old input."""
    now = int(time.time())
    need(type(started_at) is int and 0 <= started_at <= now,
         "owner_native_timestamp_invalid")
    need(now - started_at <= MAX_OWNER_AGE, "owner_native_reference_stale")
    need(request["not_before"] >= started_at, "request_predates_owner_input")
    return {"protocol": "integrity/delegation-owner-freshness/v1",
            "owner_thread_id": request["owner_ref"]["thread_id"],
            "owner_turn_id": request["owner_ref"]["turn_id"] if turn_id is None else turn_id,
            "owner_item_id": request["owner_ref"]["item_id"] if item_id is None else item_id,
            "native_turn_started_at": started_at, "verified_at": now,
            "maximum_age_seconds": MAX_OWNER_AGE, "request_not_before": request["not_before"]}


def native_receiving_identity(hook_thread_id: str, hook_payload: dict) -> tuple[str, dict | None]:
    """Resolve the Native caller of an internal subagent tool, without exemption.

    Codex's actual PreToolUse payload passes the root session_id and a child
    agent_id plus its transcript_path. The tool command environment is created
    later and is not the hook's caller identity. A constrained existing Native
    session header must bind the declared child to this exact hook session, after which
    the ordinary Native current-turn and frame validation still applies.
    """
    child = hook_payload.get("agent_id", "")
    if child is None:
        child = ""
    need(isinstance(child, str), "subagent_native_identity_invalid")
    child = child.strip()
    if not child or child == hook_thread_id:
        return hook_thread_id, None
    need(NATIVE_THREAD.fullmatch(child) is not None, "subagent_native_identity_invalid")
    configured_home = os.environ.get("CODEX_HOME", "").strip()
    codex_root = Path(configured_home) if configured_home else Path.home() / ".codex"
    need(codex_root.is_absolute(), "subagent_session_root_invalid")
    transcript = hook_payload.get("transcript_path", hook_payload.get("transcriptPath"))
    need(isinstance(transcript, str) and Path(transcript).is_absolute(),
         "subagent_transcript_identity_missing")
    try:
        parsed_child = uuid.UUID(child)
        need(parsed_child.version == 7, "subagent_native_identity_invalid")
        creation_day = datetime.fromtimestamp(int(child.replace("-", "")[:12], 16) / 1000,
                                              timezone.utc).date()
        prefix = [codex_root, codex_root / "sessions"]
        for directory in prefix:
            info = directory.lstat()
            need(stat.S_ISDIR(info.st_mode)
                 and not (getattr(info, "st_file_attributes", 0) & 0x400)
                 and not directory.is_symlink(), "subagent_session_path_unsafe")
        filename = re.compile(r"rollout-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-"
                              + re.escape(child) + r"\.jsonl\Z")
        candidates = []
        # UUIDv7 fixes the creation day. At most three exact day directories
        # accommodate a local filename date around midnight, even on later turns.
        for delta in (-1, 0, 1):
            day = creation_day + timedelta(days=delta)
            directory = prefix[-1]
            missing = False
            for part in (f"{day.year:04d}", f"{day.month:02d}", f"{day.day:02d}"):
                directory = directory / part
                try:
                    info = directory.lstat()
                except FileNotFoundError:
                    missing = True
                    break
                need(stat.S_ISDIR(info.st_mode)
                     and not (getattr(info, "st_file_attributes", 0) & 0x400)
                     and not directory.is_symlink(), "subagent_session_path_unsafe")
            if not missing:
                candidates.extend(path for path in directory.iterdir() if filename.fullmatch(path.name))
        need(len(candidates) == 1, "subagent_session_header_not_unique")
        source = candidates[0]
        need(os.path.normcase(os.path.abspath(source)) == os.path.normcase(os.path.abspath(transcript)),
             "subagent_transcript_identity_mismatch")
        info = source.lstat()
        need(stat.S_ISREG(info.st_mode)
             and not (getattr(info, "st_file_attributes", 0) & 0x400)
             and not source.is_symlink(), "subagent_session_path_unsafe")
        with source.open("rb") as stream:
            raw = stream.readline(MAX_SESSION_HEADER + 1)
        need(0 < len(raw) <= MAX_SESSION_HEADER and raw.endswith(b"\n"),
             "subagent_session_header_incomplete")
        header = object_json(raw.decode("utf-8"))
    except AdapterError:
        raise
    except (OSError, UnicodeError, ValueError, OverflowError):
        raise AdapterError("subagent_session_header_unavailable") from None
    payload = header.get("payload")
    need(header.get("type") == "session_meta" and isinstance(payload, dict)
         and payload.get("id") == child, "subagent_session_identity_mismatch")
    source_kind = payload.get("source")
    subagent = source_kind.get("subagent") if isinstance(source_kind, dict) else None
    spawn = subagent.get("thread_spawn") if isinstance(subagent, dict) else None
    need(isinstance(spawn, dict) and spawn.get("parent_thread_id") == hook_thread_id,
         "subagent_parent_identity_mismatch")
    need(isinstance(spawn.get("agent_path"), str) and spawn["agent_path"].startswith("/root/"),
         "subagent_path_identity_invalid")
    return child, {"protocol": "integrity/codex-native-receiving-identity/v1",
                   "hook_session_id": hook_thread_id, "native_thread_id": child,
                   "origin": "observed-native-subagent-session-header",
                   "parent_thread_id": spawn["parent_thread_id"],
                   "agent_path": spawn["agent_path"], "action_authority": "not-evaluated"}


class PhaseTrace:
    """Temporary actor-only phase enums, one bounded atomic metadata file."""

    def __init__(self, config: dict, payload: dict):
        self.started = time.monotonic()
        self.path = None
        self.records = []
        self.phase = None
        self.config = config
        self.native_environment = None
        thread = payload.get("session_id") or payload.get("thread_id")
        turn = payload.get("turn_id") or payload.get("turnId")
        self.thread = thread
        self.turn = turn
        diagnostic = config.get("diagnostic")
        agent = payload.get("agent_id")
        if (active_receiving_observation(config, thread) is None
                or not (agent is None or isinstance(agent, str) and agent in {"", thread})
                or not isinstance(turn, str) or NATIVE_THREAD.fullmatch(turn) is None
                or not isinstance(diagnostic, dict) or diagnostic.get("max_files") != 128):
            return
        configured = diagnostic.get("path")
        if not isinstance(configured, str):
            return
        if os.path.normcase(os.path.abspath(configured)) != os.path.normcase(os.path.abspath(DIAGNOSTIC_PHASE_ROOT)):
            return
        try:
            info = DIAGNOSTIC_PHASE_ROOT.lstat()
            if (not stat.S_ISDIR(info.st_mode) or DIAGNOSTIC_PHASE_ROOT.is_symlink()
                    or getattr(info, "st_file_attributes", 0) & 0x400):
                return
            if sum(1 for entry in DIAGNOSTIC_PHASE_ROOT.glob("*.json")) >= 128:
                return
            self.path = DIAGNOSTIC_PHASE_ROOT / f"receiver-phase-{turn}-{os.getpid()}.json"
        except OSError:
            return

    def capture_native(self, reader=None) -> None:
        if active_receiving_observation(self.config, self.thread) is None:
            self.native_environment = None
            return
        try:
            self.native_environment = native_environment_observation(reader)
        except Exception:
            # Observation failure must not affect Native decisions or output.
            self.native_environment = None

    def emit(self, phase: str) -> None:
        if phase not in DIAGNOSTIC_PHASES:
            return
        self.phase = phase
        if self.path is None or active_receiving_observation(self.config, self.thread) is None:
            return
        try:
            if len(self.records) < 48:
                self.records.append({"phase": phase,
                                     "elapsed_ms": int((time.monotonic() - self.started) * 1000)})
            record = {"protocol": "integrity/codex-receiving-phase-observation/v1",
                      "thread_id": self.thread, "turn_id": self.turn, "pid": os.getpid(),
                      "phase": phase, "records": self.records}
            if self.native_environment is not None:
                record["native_environment"] = self.native_environment
            temporary = self.path.with_suffix(".tmp")
            with temporary.open("w", encoding="utf-8") as stream:
                stream.write(json.dumps(record, separators=(",", ":")) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except OSError:
            # Diagnostic IO never alters receiving decisions.
            return


class NativeReader:
    """Bounded transport through the existing NativeAppHostRpc implementation."""

    def __init__(self, bridge, context_thread_id: str, *, deadline: float | None = None,
                 phase_trace: PhaseTrace | None = None, read_retries: int = 0,
                 read_observer=None):
        need(type(read_retries) is int and 0 <= read_retries <= 1, "native_retry_budget_invalid")
        self.bridge = bridge
        self.context_thread_id = context_thread_id
        self.deadline = time.monotonic() + NATIVE_DEADLINE if deadline is None else deadline
        self.started = time.monotonic()
        self.phase_trace = phase_trace
        self.read_phase = "read-current"
        self.read_retries = read_retries
        self.read_observer = read_observer
        self.read_sequence = 0
        self.last_read = None
        self.selected_pipe_sha256 = None
        if isinstance(phase_trace, PhaseTrace):
            phase_trace.capture_native(self)
        reader = self

        class DeadlineHost(bridge.NativeAppHostRpc):
            def request(self, method, params, timeout=10.0):
                remaining = reader.deadline - time.monotonic()
                need(remaining > 0, "native_evidence_deadline")
                cap = NATIVE_READ_TIMEOUT if method == "tools/call" and isinstance(params, dict) and params.get("tool") == "read_thread" else timeout
                return super().request(method, params, min(cap, remaining))

        self.host = None
        if phase_trace is not None:
            phase_trace.emit("discovery-start")
        candidates = bridge.discover_codex_app_tool_pipes()
        if phase_trace is not None:
            phase_trace.emit("discovery-done")
        for pipe in candidates:
            need(time.monotonic() < self.deadline, "native_evidence_deadline")
            candidate = DeadlineHost(pipe)
            try:
                if phase_trace is not None:
                    phase_trace.emit("list-tools-start")
                available = candidate.list_tools()
                if phase_trace is not None:
                    phase_trace.emit("list-tools-done")
            except Exception:
                continue
            names = {(tool.get("namespace"), tool.get("name"))
                     for tool in available if isinstance(tool, dict)}
            required = {(bridge.CODEX_APP_TOOLS_NAMESPACE, "read_thread"),
                        (bridge.CODEX_APP_TOOLS_NAMESPACE, "send_message_to_thread")}
            if required.issubset(names):
                self.host = candidate
                self.selected_pipe_sha256 = hashlib.sha256(pipe.encode()).hexdigest() if isinstance(pipe, str) else None
                if isinstance(phase_trace, PhaseTrace):
                    phase_trace.capture_native(self)
                break
        need(self.host is not None, "native_host_unavailable")

    def read(self, thread_id: str, host_id: str, *, cursor: str | None = None,
             limit: int = 10, outputs: bool = False) -> dict:
        need(time.monotonic() < self.deadline, "native_evidence_deadline")
        args = {"threadId": thread_id, "hostId": host_id, "turnLimit": limit,
                "includeOutputs": outputs, "maxOutputCharsPerItem": MAX_CHARS}
        if cursor is not None:
            args["cursor"] = cursor
        self.read_sequence += 1
        for attempt in range(self.read_retries + 1):
            need(time.monotonic() < self.deadline, "native_evidence_deadline")
            started = time.monotonic()
            self.last_read = {"phase": self.read_phase, "sequence": self.read_sequence,
                "attempt": attempt + 1, "thread_id": thread_id, "host_id": host_id,
                "cursor": cursor, "cursor_sha256": hashlib.sha256(cursor.encode()).hexdigest() if cursor is not None else None,
                "status": "started"}
            if self.read_observer is not None:
                self.read_observer(self.last_read)
            try:
                if self.phase_trace is not None:
                    self.phase_trace.emit(self.read_phase + "-start")
                page = self.bridge._host_tool_json(self.host, "read_thread", args,
                                                   self.context_thread_id)
                if self.phase_trace is not None:
                    self.phase_trace.emit(self.read_phase + "-done")
            except Exception as error:
                self.last_read.update(status="failed", elapsed_ms=int((time.monotonic() - started) * 1000),
                                      **native_fault(error, self.bridge))
                if self.read_observer is not None:
                    self.read_observer(self.last_read)
                if isinstance(self.phase_trace, PhaseTrace):
                    self.phase_trace.capture_native(self)
                if self.last_read["fault_kind"] == "read-timeout" and attempt < self.read_retries:
                    continue
                raise AdapterError("native_read_unavailable") from None
            self.last_read.update(status="completed", elapsed_ms=int((time.monotonic() - started) * 1000))
            if self.read_observer is not None:
                self.read_observer(self.last_read)
            if isinstance(self.phase_trace, PhaseTrace):
                self.phase_trace.capture_native(self)
            break
        need(time.monotonic() < self.deadline, "native_evidence_deadline")
        check_page(page, thread_id, host_id)
        return page


def native_fault(error: Exception, bridge) -> dict:
    """Classify fixed bridge literals; arbitrary RPC text never crosses this boundary."""
    allowed_classes = {"RpcError", "TimeoutError", "OSError", "PermissionError",
                       "FileNotFoundError", "BrokenPipeError", "JSONDecodeError", "AdapterError"}
    fault_class = type(error).__name__ if type(error).__name__ in allowed_classes else "other"
    kind = "unclassified"
    rpc_code = None
    rpc_class = getattr(bridge, "RpcError", ())
    if isinstance(error, rpc_class):
        literal = str(error)
        if literal == "codex_app_host_timeout:tools/call":
            kind = "read-timeout"
        elif literal == "codex_app_host_tool_failed:read_thread":
            kind = "tool-failed"
        elif literal == "codex_app_host_tool_result_invalid:read_thread":
            kind = "tool-result-invalid"
        elif literal in {"codex_app_host_invalid_response", "codex_app_host_invalid_result"}:
            kind = "rpc-result-invalid"
        elif literal.startswith("codex_app_host_rejected:"):
            kind = "rpc-rejected"
            encoded = literal[len("codex_app_host_rejected:"):]
            if len(encoded) <= 4096 and encoded.lstrip().startswith("{"):
                try:
                    value = object_json(encoded).get("code")
                    if type(value) is int and -(2 ** 31) <= value < 2 ** 31:
                        rpc_code = value
                except AdapterError:
                    pass
        elif literal.startswith("codex_app_host_unavailable:"):
            kind = "transport-unavailable"
            cause = error.__cause__
            if isinstance(cause, rpc_class) and str(cause) == "codex_app_host_response_too_large":
                kind = "response-too-large"
    elif isinstance(error, AdapterError) and str(error) == "native_evidence_deadline":
        kind = "evidence-deadline"
    result = {"fault_kind": kind, "fault_class": fault_class}
    if rpc_code is not None:
        result["rpc_code"] = rpc_code
    return result


def native_failure_observation(reader=None) -> dict:
    """Failure-only bounded DATA. No raw exceptions, paths, hints or cursors."""
    result = {}
    last = getattr(reader, "last_read", None)
    if isinstance(last, dict):
        enums = {"phase": {"read-current", "read-source", "read-owner", "read-owner-locator"},
                 "status": {"started", "completed", "failed"},
                 "fault_kind": {"unclassified", "read-timeout", "tool-failed", "tool-result-invalid", "rpc-result-invalid", "rpc-rejected", "transport-unavailable", "response-too-large", "evidence-deadline"},
                 "fault_class": {"RpcError", "TimeoutError", "OSError", "PermissionError", "FileNotFoundError", "BrokenPipeError", "JSONDecodeError", "AdapterError", "other"}}
        for key, choices in enums.items():
            if isinstance(last.get(key), str) and last[key] in choices:
                result[key] = last[key]
        for key, lower, upper in (("sequence", 0, 1000000), ("attempt", 0, 2),
                                  ("elapsed_ms", 0, 3600000), ("rpc_code", -(2 ** 31), 2 ** 31 - 1)):
            if type(last.get(key)) is int and lower <= last[key] <= upper:
                result[key] = last[key]
    environment = native_environment_observation(reader)
    version = environment.get("runtime_version")
    if isinstance(version, str) and re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){2}", version):
        result["runtime_version"] = version
    result["selected_pipe_sha256"] = environment.get("selected_pipe_sha256")
    result["env_pipe_hint_sha256"] = {key: value for key, value in environment.get("env_pipe_hint_sha256", {}).items()
        if key in {"CODEX_APP_TOOLS_PIPE_PATH", "INTEGRITY_CODEX_APP_TOOLS_PIPE_PATH"}
        and (value is None or isinstance(value, str) and SHA256.fullmatch(value))}
    return result


def write_native_checkpoint(path: Path, observation: dict) -> None:
    """One bounded, atomic locator file; it is never imported as authority."""
    raw = (json.dumps(observation, sort_keys=True, separators=(",", ":")) + "\n").encode()
    need(len(raw) <= 32768, "native_checkpoint_oversized")
    temporary = path.with_name(path.name + "." + str(os.getpid()) + ".tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(raw.decode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def check_page(page: dict, thread_id: str, host_id: str) -> None:
    need(isinstance(page, dict) and isinstance(page.get("thread"), dict),
         "native_page_invalid")
    thread = page["thread"]
    need(thread.get("id") == thread_id and thread.get("hostId") == host_id
         and thread.get("kind") == "codex", "native_thread_context_mismatch")
    need(isinstance(page.get("turns"), list), "native_turns_invalid")
    need(isinstance(page.get("page"), dict)
         and page["page"].get("order") == "newest_first", "native_page_order_invalid")


def pages(reader, thread_id: str, host_id: str, *, first: dict | None = None,
          maximum: int = MAX_PAGES):
    need(type(maximum) is int and 1 <= maximum <= 100, "native_page_budget_invalid")
    cursor = None
    seen = set()
    for index in range(maximum):
        page = first if index == 0 and first is not None else reader.read(
            thread_id, host_id, cursor=cursor)
        check_page(page, thread_id, host_id)
        more = page["page"].get("hasMore")
        next_cursor = page["page"].get("nextCursor")
        need(type(more) is bool and more == bool(next_cursor)
             and page.get("truncated", False) is False
             and page["page"].get("truncated", False) is False,
             "control_coverage_incomplete")
        yield page
        cursor = next_cursor
        if not cursor:
            return
        need(isinstance(cursor, str) and cursor not in seen, "native_cursor_invalid")
        seen.add(cursor)
    raise AdapterError("native_evidence_page_bound")


def delivery_context(metadata: Any) -> dict | None:
    """Parse Native service identity; optional device DATA is never retained."""
    if not isinstance(metadata, str) or len(metadata) > 8192:
        return None
    match = WEB_CONTEXT.fullmatch(metadata)
    if match is None:
        return None
    extra = match.group(4)
    if not extra:
        return {"room_id": match.group(2), "message_id": match.group(3)}
    if not extra.endswith("\n"):
        return None
    lines = extra.splitlines()
    try:
        offset = False
        if lines and lines[0].startswith("sender_current_utc_offset="):
            offset = True
            value = re.fullmatch(r"sender_current_utc_offset=UTC[+-]([0-9]{2}):([0-9]{2})", lines.pop(0))
            need(value is not None and int(value.group(1)) <= 14 and int(value.group(2)) < 60
                 and (int(value.group(1)) != 14 or int(value.group(2)) == 0), "owner_service_context_invalid")
        if offset and lines and lines[0] == "":
            lines.pop(0)
            need(bool(lines), "owner_service_context_invalid")
        if lines:
            label = "Current location snapshot: "
            need(len(lines) == 1 and lines[0].startswith(label), "owner_service_context_invalid")
            raw = lines.pop(0)[len(label):]
            need(0 < len(raw) <= 2048, "owner_service_context_invalid")
            location = object_json(raw)
            need(set(location) == {"latitude", "longitude", "horizontal_accuracy_m", "message_sent_at"},
                 "owner_service_context_invalid")
            for key, minimum, maximum in (("latitude", -90, 90), ("longitude", -180, 180),
                                          ("horizontal_accuracy_m", 0, 100000)):
                value = location[key]
                need(type(value) in {int, float} and math.isfinite(value) and minimum <= value <= maximum,
                     "owner_service_context_invalid")
            timestamp = location["message_sent_at"]
            need(isinstance(timestamp, str) and len(timestamp) <= 64
                 and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})", timestamp),
                 "owner_service_context_invalid")
            need(datetime.fromisoformat(timestamp.replace("Z", "+00:00")).utcoffset() is not None,
                 "owner_service_context_invalid")
        need(not lines, "owner_service_context_invalid")
    except (AdapterError, ValueError, TypeError, OverflowError, KeyError):
        return None
    return {"room_id": match.group(2), "message_id": match.group(3)}


def discard_untrusted_quote(block: Any) -> None:
    """Validate only Native's outer DATA wrapper; never decode or retain it."""
    need(isinstance(block, dict) and block.get("type") == "text"
         and block.get("truncated", False) is False, "owner_untrusted_text_incomplete")
    raw = block.get("text")
    need(isinstance(raw, str) and 0 < len(raw) < MAX_CHARS and "\x00" not in raw,
         "owner_untrusted_text_incomplete")
    wrapped = raw.strip()
    opening, closing = "<untrusted_text>", "</untrusted_text>"
    need(wrapped.startswith(opening) and wrapped.endswith(closing), "owner_untrusted_text_invalid")
    inner = wrapped[len(opening):-len(closing)]
    need(bool(inner.strip()) and "<untrusted_text" not in inner and "</untrusted_text" not in inner
         and "<!" not in wrapped and "<?" not in wrapped, "owner_untrusted_text_invalid")


def normalized_owner(item: dict) -> tuple[dict, dict]:
    """Native userMessage has no truncation fields for ordinary complete text.

    Explicit truncation rejects. A text at the output limit rejects rather than
    guessing. Web transport metadata is parsed separately from the owner's text.
    """
    need(isinstance(item, dict) and item.get("type") == "userMessage"
         and item.get("truncated", False) is False, "owner_not_complete_human")
    need(item.get("codexDelegation") is None, "owner_message_is_delegated_input")
    blocks = item.get("content")
    need(isinstance(blocks, list) and len(blocks) in {1, 2, 3}, "owner_content_invalid")
    if len(blocks) == 3:
        discard_untrusted_quote(blocks[2])
        # The remaining two blocks must still pass the existing exact service
        # context + complete human body path. DATA cannot mint scope/control.
        blocks = blocks[:2]
    text_blocks = []
    for block in blocks:
        need(isinstance(block, dict) and block.get("type") == "text"
             and block.get("truncated", False) is False, "owner_text_incomplete")
        text = block.get("text")
        need(isinstance(text, str) and 0 < len(text) < MAX_CHARS, "owner_text_incomplete")
        need("<codex_delegation>" not in text, "owner_message_is_delegated_input")
        text_blocks.append(text)
    service = {"room_id": None, "message_id": None, "origin_kind": "owner"}
    if len(text_blocks) == 2:
        context = delivery_context(text_blocks[0])
        need(context is not None, "owner_service_context_invalid")
        service.update(context)
        text = text_blocks[1]
    else:
        text = text_blocks[0]
        need(not text.startswith("<delivery_context>"), "owner_service_context_invalid")
    normalized = {"type": "userMessage", "id": item.get("id"), "truncated": False,
                  "content": [{"type": "text", "text": text, "truncated": False}]}
    return normalized, service


def xml_transport_body(raw: str) -> str:
    """Validate Native's text-only wrapper and decode XML text exactly once."""
    wrapped = raw.strip()
    need(not any(marker in wrapped for marker in ("<!", "<?")), "receiving_wrapper_invalid")
    try:
        root = XML.fromstring(wrapped)
    except (XML.ParseError, ValueError):
        raise AdapterError("receiving_wrapper_invalid") from None
    children = list(root)
    need(root.tag == "codex_delegation" and not root.attrib
         and (root.text is None or not root.text.strip()) and len(children) == 2,
         "receiving_wrapper_invalid")
    source, input_node = children
    need(source.tag == "source_thread_id" and input_node.tag == "input"
         and not source.attrib and not input_node.attrib and not list(source) and not list(input_node)
         and isinstance(source.text, str) and IDENTITY.fullmatch(source.text.strip()) is not None
         and (source.tail is None or not source.tail.strip())
         and (input_node.tail is None or not input_node.tail.strip()), "receiving_wrapper_invalid")
    match = WRAPPER.fullmatch(wrapped)
    need(match is not None, "receiving_wrapper_invalid")
    # Decode the raw text slice after structural validation. This preserves
    # source CR/LF bytes which an XML parser would otherwise normalize, and
    # replacement text is never rescanned (literal &lt; stays literal).
    named = {"amp":"&", "lt":"<", "gt":">", "apos":"'", "quot":'"'}
    def decode(entity):
        token = entity.group(0)[1:-1]
        if token in named:
            return named[token]
        return chr(int(token[2:], 16) if token.startswith("#x") else int(token[1:]))
    return XML_ENTITY.sub(decode, match.group(1))


def receiving_body(item: dict) -> str | None:
    if not isinstance(item, dict):
        return None
    if item.get("type") == "functionCallOutput":
        if item.get("name") != "send_message_to_thread" or item.get("namespace") != "codex_app":
            return None
        output = item.get("output")
        need(isinstance(output, dict) and output.get("truncated") is False
             and isinstance(output.get("text"), str), "receiving_output_incomplete")
        return xml_transport_body(output["text"])
    if item.get("type") == "userMessage":
        normalized, context = normalized_owner(item)
        need(context["room_id"] is None, "receiving_owner_metadata_invalid")
        return normalized["content"][0]["text"]
    return None


def active_receiving_observation(config: dict, thread_id: str) -> dict | None:
    """Opt-in, content-free observation; the receiving decision is unchanged."""
    diagnostic = config.get("diagnostic")
    if not isinstance(diagnostic, dict):
        return None
    expiry = diagnostic.get("expires")
    now = int(time.time())
    lifetime = 600 if thread_id == DIAGNOSTIC_NODENY_ACTOR else 3600
    if (diagnostic.get("target_thread_ids") != [thread_id]
            or thread_id not in DIAGNOSTIC_ACTORS or type(expiry) is not int
            or not now < expiry <= now + lifetime):
        return None
    return {"protocol": "integrity/codex-receiving-observation/v1"}


def native_environment_observation(reader=None) -> dict:
    """Explicit opt-in caller only. Hash locator hints; whitelist fault DATA."""
    result = {"runtime_executable": sys.executable if isinstance(sys.executable, str) and len(sys.executable) <= 1024 else None,
              "runtime_version": ".".join(str(v) for v in sys.version_info[:3]),
              "selected_pipe_sha256": None, "env_pipe_hint_sha256": {}}
    for key in ("CODEX_APP_TOOLS_PIPE_PATH", "INTEGRITY_CODEX_APP_TOOLS_PIPE_PATH"):
        value = os.environ.get(key)
        result["env_pipe_hint_sha256"][key] = hashlib.sha256(value.encode()).hexdigest() if value else None
    selected = getattr(reader, "selected_pipe_sha256", None)
    if isinstance(selected, str) and SHA256.fullmatch(selected):
        result["selected_pipe_sha256"] = selected
    last = getattr(reader, "last_read", None)
    if isinstance(last, dict):
        safe = {}
        enums = {"phase": {"read-current", "read-source", "read-owner", "read-owner-locator"},
                 "status": {"started", "completed", "failed"},
                 "fault_kind": {"unclassified", "read-timeout", "tool-failed", "tool-result-invalid", "rpc-result-invalid",
                                "rpc-rejected", "transport-unavailable", "response-too-large", "evidence-deadline"},
                 "fault_class": {"RpcError", "TimeoutError", "OSError", "PermissionError", "FileNotFoundError",
                                 "BrokenPipeError", "JSONDecodeError", "AdapterError", "other"}}
        for key, values in enums.items():
            if isinstance(last.get(key), str) and last[key] in values:
                safe[key] = last[key]
        for key, maximum in (("sequence", 1000000), ("attempt", 2), ("elapsed_ms", 3600000)):
            if type(last.get(key)) is int and 0 <= last[key] <= maximum:
                safe[key] = last[key]
        result["last_read"] = safe
    return result


def observation_token(value: Any) -> str | None:
    return value if isinstance(value, str) and TOKEN.fullmatch(value) is not None else None


def capture_receiving_observation(observation: dict, thread_id: str, turn_id: str,
                                  turns: list[dict]) -> None:
    """Use only input metadata already in the requested Native page."""
    observation.update(requested_thread_id=thread_id, requested_turn_id=turn_id,
                       matched_current_turn_count=len(turns), matched_current_turn_status=None,
                       input_candidates=[])
    if len(turns) != 1:
        return
    status = turns[0].get("status")
    if status in {"inProgress", "completed", "interrupted", "failed", "cancelled"}:
        observation["matched_current_turn_status"] = status
    for item in turns[0].get("items") or []:
        if not isinstance(item, dict) or item.get("type") not in {"functionCallOutput", "userMessage"}:
            continue
        if len(observation["input_candidates"]) == 8:
            break
        candidate = {"item_id": observation_token(item.get("id")), "type": item["type"],
                     "name": observation_token(item.get("name")),
                     "namespace": observation_token(item.get("namespace")),
                     "outer_wrapper": False, "marker_present": False,
                     "output_truncated": None, "decoded_inner_starts_frame": None}
        output = item.get("output")
        if item["type"] == "functionCallOutput" and isinstance(output, dict):
            if type(output.get("truncated")) is bool:
                candidate["output_truncated"] = output["truncated"]
            raw = output.get("text")
            if isinstance(raw, str):
                wrapper = WRAPPER.fullmatch(raw.strip())
                candidate["outer_wrapper"] = wrapper is not None
                candidate["marker_present"] = FRAME in raw
                if wrapper is not None:
                    candidate["decoded_inner_starts_frame"] = wrapper.group(1).lstrip().startswith(FRAME)
        elif item["type"] == "userMessage":
            blocks = item.get("content")
            if isinstance(blocks, list):
                raw = "\n".join(block.get("text", "") for block in blocks
                                if isinstance(block, dict) and isinstance(block.get("text"), str))
                candidate["marker_present"] = FRAME in raw
                candidate["decoded_inner_starts_frame"] = raw.lstrip().startswith(FRAME)
        observation["input_candidates"].append(candidate)


def find_receiving(reader, config: dict, thread_id: str, turn_id: str, core,
                   *, observation: dict | None = None):
    first = reader.read(thread_id, "local", limit=3, outputs=True)
    check_page(first, thread_id, "local")
    turns = [turn for turn in first["turns"]
             if isinstance(turn, dict) and turn.get("id") == turn_id]
    if observation is not None:
        capture_receiving_observation(observation, thread_id, turn_id, turns)
    need(len(turns) == 1, "receiving_turn_not_current")
    turn = turns[0]
    need(turn.get("status") in {"inProgress", "completed", "interrupted", "failed", "cancelled"},
         "receiving_turn_state_invalid")
    found = []
    for item in turn.get("items") or []:
        # Ordinary tool responses and human prompts are unrelated to delegation.
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        if kind == "functionCallOutput":
            if item.get("name") != "send_message_to_thread" or item.get("namespace") != "codex_app":
                continue
        elif kind != "userMessage":
            continue
        raw = item.get("output", {}).get("text", "") if isinstance(
            item.get("output"), dict) else ""
        if kind == "userMessage":
            raw = "\n".join(block.get("text", "") for block in item.get("content", [])
                            if isinstance(block, dict) and isinstance(block.get("text"), str))
            if not raw.lstrip().startswith(FRAME):
                continue
        if kind == "functionCallOutput" and FRAME not in raw:
            continue
        body = receiving_body(item)
        need(body is not None, "receiving_transport_invalid")
        # Receiving output may carry status DATA or quote the protocol in an
        # ordinary message. Decode the actual transport input before deciding
        # whether it is a typed task; substring mentions never mint a binding.
        if not body.lstrip().startswith(FRAME):
            continue
        request = core.parse_request(core.extract_request_body(body),
                                     source_thread_id=config["source_thread_id"],
                                     receiving_host_id=config["target_machine_id"],
                                     receiving_thread_id=thread_id,
                                     allowed_owner_threads=set(config["allowed_owner_threads"]))
        owner_current(config, request["owner_ref"]["thread_id"])
        found.append((request, {"host_id": config["target_machine_id"],
                               "thread_id": thread_id, "turn_id": turn_id,
                               "item_id": identity(item.get("id"), "receiving_item_id_invalid"),
                               "body": body}))
    need(len(found) <= 1, "receiving_request_ambiguous")
    return found[0] if found else None


def is_sender(item: dict) -> bool:
    if item.get("type") != "mcpToolCall" or item.get("status") != "completed":
        return False
    server, tool = item.get("server"), item.get("tool")
    return (server == "codex_app" and tool == "send_message_to_thread") or (
        server == "codex_apps" and tool in NATIVE_BRIDGE_SEND_TOOLS)


def control_receipts(page: dict, config: dict, core, operation_id: str | None,
                     *, control_thread_id: str | None = None) -> list[dict]:
    receipts = []
    control_thread_id = config["source_thread_id"] if control_thread_id is None else control_thread_id
    context_config = config["allowed_owner_threads"].get(control_thread_id)
    need(context_config is not None, "control_thread_not_allowed")
    for turn in page["turns"]:
        need(isinstance(turn, dict) and isinstance(turn.get("items"), list)
             and turn.get("truncated", False) is False, "control_coverage_incomplete")
        for item in turn["items"]:
            need(isinstance(item, dict), "control_coverage_incomplete")
            if not isinstance(item, dict) or item.get("type") != "userMessage":
                continue
            try:
                normalized, service = normalized_owner(item)
            except AdapterError:
                # Multimodal or truncated unrelated history cannot authenticate
                # a control and must not disable a complete referenced owner.
                # A visibly structured control with incomplete evidence stays
                # fail-closed because a possible revocation cannot be discarded.
                blocks = item.get("content")
                potential = isinstance(blocks, list) and any(
                    isinstance(block, dict) and isinstance(block.get("text"), str)
                    and block["text"].lstrip().startswith("{") for block in blocks)
                if potential:
                    # A fully observed strict JSON object with another protocol
                    # cannot be a v1 control. This does not authenticate its
                    # transport or relax exact owner/control normalization.
                    need(proven_non_control_json(item, core), "control_evidence_incomplete")
                continue
            try:
                text = normalized["content"][0]["text"]
                if not text.lstrip().startswith("{"):
                    continue
                control = core.parse_control(text)
                if operation_id is not None and control["operation_id"] != operation_id:
                    continue
                need(service["room_id"] == context_config["room_id"],
                     "control_room_mismatch")
                receipts.append(core.verify_control_item(normalized, delivery_context={
                    **service, "thread_id": control_thread_id,
                    "turn_id": turn["id"]}, source_thread_id=control_thread_id))
            except core.DelegationError:
                continue
    return receipts


def proven_non_control_json(item: dict, core) -> bool:
    """Exclude complete non-control DATA; never guess from a clipped substring."""
    if item.get("truncated", False) is not False:
        return False
    candidates = [block for block in item.get("content", [])
                  if isinstance(block, dict) and isinstance(block.get("text"), str)
                  and block["text"].lstrip().startswith("{")]
    if not candidates:
        return False
    for block in candidates:
        text = block["text"]
        if (block.get("type") != "text" or block.get("truncated", False) is not False
                or not 0 < len(text) < MAX_CHARS):
            return False
        try:
            value = object_json(text)
        except AdapterError:
            return False
        if value.get("protocol") == core.CONTROL_PROTOCOL:
            return False
    return True


def projection_scope(config: dict, thread_id: str, host_id: str) -> dict:
    context = config["allowed_owner_threads"].get(thread_id)
    need(context is not None and context["host_id"] == host_id, "control_thread_not_allowed")
    return {"source_thread_id": thread_id, "host_id": host_id,
            "source_provider": "codex", "source_room_id": context["room_id"]}


def scan_control_history(reader, config: dict, core, thread_id: str, host_id: str,
                         expected_frontier: dict | None, *, visit_page=None, proof_ready=None,
                         maximum: int = MAX_PAGES, force_history_end: bool = False,
                         progress=None) -> dict:
    """Observe continuous live pages; a saved frontier contains only control facts."""
    scope = projection_scope(config, thread_id, host_id)
    if expected_frontier is not None:
        need(all(expected_frontier.get(key) == value for key, value in scope.items()),
             "control_projection_scope_mismatch")
        boundary = identity(expected_frontier.get("frontier_turn_id"), "control_frontier_invalid")
    else:
        boundary = None
    head = None
    controls = []
    complete = False
    history_end = False
    boundary_complete = False
    count = 0
    for page in pages(reader, thread_id, host_id, maximum=maximum):
        count += 1
        turns = page["turns"]
        if head is None:
            need(bool(turns) and isinstance(turns[0], dict), "control_frontier_missing")
            head = identity(turns[0].get("id"), "control_frontier_invalid")
        observed = control_receipts(page, config, core, None, control_thread_id=thread_id)
        if not complete or force_history_end:
            controls.extend(observed)
        if visit_page is not None:
            visit_page(page)
        actual_end = page["page"]["hasMore"] is False and not page["page"].get("nextCursor")
        if progress is not None and (count % 5 == 0 or actual_end):
            progress({"phase": "history-scan", "pages": count,
                      "observed_controls": len(controls), "history_end_observed": actual_end})
        if not complete:
            boundary_complete = boundary_complete or (boundary is not None and any(
                turn["id"] == boundary for turn in turns))
            history_end = actual_end
            complete = actual_end if boundary is None or force_history_end else boundary_complete
        if force_history_end and actual_end:
            complete = True
            history_end = True
        if complete and (proof_ready is None or proof_ready()):
            break
    need(complete and (boundary is None or boundary_complete), "control_coverage_incomplete")
    unique_controls = {item["evidence_digest"]: item for item in controls}
    receipt = {**scope, "frontier_turn_id": head, "previous_frontier_turn_id": boundary,
               "history_end_observed": history_end, "boundary_turn_complete": boundary_complete,
               "coverage_complete": True, "control_evidence_digests": sorted(unique_controls)}
    receipt["evidence_digest"] = core.digest(receipt)
    return {"scope": scope, "expected_frontier": expected_frontier,
            "controls": list(unique_controls.values()), "coverage_receipt": receipt,
            "pages": count}


def refresh_control_history(reader, config: dict, core, batch: dict) -> dict:
    """After owner proof, reread new head through the complete observed old head."""
    receipt = batch["coverage_receipt"]
    observed_boundary = {**batch["scope"], "frontier_turn_id": receipt["frontier_turn_id"]}
    refreshed = scan_control_history(reader, config, core, batch["scope"]["source_thread_id"],
                                     batch["scope"]["host_id"], observed_boundary)
    unique_controls = {item["evidence_digest"]: item for item in batch["controls"] + refreshed["controls"]}
    combined = {**receipt, "frontier_turn_id": refreshed["coverage_receipt"]["frontier_turn_id"],
                "control_evidence_digests": sorted(unique_controls)}
    combined.pop("evidence_digest")
    combined["evidence_digest"] = core.digest(combined)
    return {**batch, "controls": list(unique_controls.values()), "coverage_receipt": combined,
            "pages": batch["pages"] + refreshed["pages"]}


def collect_proof(reader, config: dict, core, request: dict, receiving: dict) -> dict:
    source = None
    owner_item = None
    owner_context = None
    owner_time = None
    controls = []
    owner_ref = request["owner_ref"]
    service_lookup = owner_ref["turn_id"] is None
    owner_config = config["allowed_owner_threads"].get(owner_ref["thread_id"])
    need(owner_config is not None, "owner_thread_not_allowed")
    owner_current(config, owner_ref["thread_id"])
    need(owner_config["room_id"] == owner_ref["room_id"], "owner_room_not_allowed")
    same_owner = owner_ref["thread_id"] == config["source_thread_id"]
    owner_matches = []
    cached_owner_match = None
    lookup_receipt = None

    def observe_owner(turn, item):
        if service_lookup:
            if item.get("type") != "userMessage":
                return
            blocks = item.get("content")
            if not isinstance(blocks, list) or not blocks or not isinstance(blocks[0], dict):
                return
            metadata = blocks[0].get("text")
            context = delivery_context(metadata)
            if context is None:
                possible = (isinstance(metadata, str) and metadata.startswith("<delivery_context>")
                            and "room_id=" + owner_ref["room_id"] in metadata
                            and "message_id=" + owner_ref["message_id"] in metadata)
                need(not possible, "owner_service_evidence_incomplete")
                return
            if context is None or (context["room_id"], context["message_id"]) != (
                    owner_ref["room_id"], owner_ref["message_id"]):
                return
        elif turn.get("id") != owner_ref["turn_id"] or item.get("id") != owner_ref["item_id"]:
            return
        actual_turn = identity(turn.get("id"), "owner_native_turn_invalid")
        actual_item = identity(item.get("id"), "owner_native_item_invalid")
        freshness = owner_freshness(request, turn.get("startedAt"),
                                    turn_id=actual_turn, item_id=actual_item)
        normalized, service = normalized_owner(item)
        candidate = (normalized, {**service, "thread_id": owner_ref["thread_id"],
                                  "turn_id": actual_turn}, freshness)
        if cached_owner_match is not None:
            cached_freshness = {key:value for key,value in cached_owner_match[2].items() if key != "verified_at"}
            actual_freshness = {key:value for key,value in freshness.items() if key != "verified_at"}
            if candidate[:2] == cached_owner_match[:2] and actual_freshness == cached_freshness:
                return
        owner_matches.append(candidate)
        need(len(owner_matches) == 1, "owner_service_reference_ambiguous")

    def observed_lookup(page):
        # An exact concrete Native item is observed, rather than absence of a
        # second identity in unread history. Retain the service page's own
        # continuation flags and explicitly avoid a global uniqueness claim.
        native_flags = page["page"]
        return {"owner_lookup": "exact-service-identity-in-observed-native-page",
                "observed_page_complete": native_flags.get("hasMore") is False
                and not native_flags.get("nextCursor"),
                "global_history_uniqueness": "not-asserted",
                "owner_thread_id": owner_ref["thread_id"],
                "resolved_turn_id": owner_matches[0][1]["turn_id"],
                "resolved_item_id": owner_matches[0][0]["id"]}

    owner_cursor = read_owner_locator(config, owner_ref)
    if owner_cursor is not None:
        reader.read_phase = "read-owner-locator"
        hinted_page = read_optional_owner_hint(reader, owner_ref["thread_id"], owner_config["host_id"], owner_cursor)
        if hinted_page is not None:
            check_page(hinted_page, owner_ref["thread_id"], owner_config["host_id"])
        for hinted_turn in hinted_page["turns"] if hinted_page is not None else []:
            for hinted_item in hinted_turn.get("items") or []:
                if isinstance(hinted_item, dict):
                    observe_owner(hinted_turn, hinted_item)
        if owner_matches:
            cached_owner_match = owner_matches[0]
        if service_lookup and owner_matches:
            lookup_receipt = observed_lookup(hinted_page)

    def visit_source(page):
        nonlocal source, lookup_receipt
        for turn in page["turns"]:
            if not isinstance(turn, dict):
                continue
            for item in turn.get("items") or []:
                if not isinstance(item, dict):
                    continue
                if source is None and is_sender(item):
                    args = item.get("arguments")
                    if not isinstance(args, dict):
                        continue
                    target = args.get("thread_id", args.get("threadId"))
                    if target != request["target"]["thread_id"]:
                        continue
                    if args.get("prompt") != receiving["body"]:
                        continue
                    if "request_id" in args and args["request_id"] != request["operation_id"]:
                        continue
                    # Host argument belongs to the actual selected source tool.
                    host = args.get("host_id", args.get("hostId"))
                    if item["server"] == "codex_apps" and host != config["target_machine_id"]:
                        continue
                    if item["server"] == "codex_app" and host not in {None, "local"}:
                        continue
                    try:
                        if core.extract_request_body(args.get("prompt")) != core.canonical_json(request):
                            continue
                    except core.DelegationError:
                        continue
                    # Core uses canonical machine IDs; Native's local host is an
                    # adapter mapping checked above, never supplied by a model.
                    normalized_args = dict(args)
                    normalized_args.pop("hostId", None)
                    normalized_args["host_id"] = config["target_machine_id"]
                    source = {"thread_id": config["source_thread_id"], "turn_id": turn["id"],
                              "item_id": item["id"], "status": "completed",
                              "arguments": normalized_args}
                if same_owner:
                    if not service_lookup or lookup_receipt is None:
                        observe_owner(turn, item)
        if service_lookup and same_owner and owner_matches and lookup_receipt is None:
            lookup_receipt = observed_lookup(page)

    source_prior = core.read_frontier(config["ledger_path"], config["source_thread_id"])
    reader.read_phase = "read-source"
    source_batch = scan_control_history(reader, config, core, config["source_thread_id"],
        config["source_host_id"], source_prior, visit_page=visit_source,
        maximum=OWNER_LOOKUP_PAGES if source_prior is not None else MAX_PAGES,
        proof_ready=lambda: source is not None and (not same_owner or bool(owner_matches)))
    need(source is not None, "sender_call_not_observed")
    batches = [source_batch]
    if not same_owner:
        def visit_original_owner(page):
            nonlocal lookup_receipt
            for turn in page["turns"]:
                if not isinstance(turn, dict):
                    continue
                for item in turn.get("items") or []:
                    if isinstance(item, dict) and (not service_lookup or lookup_receipt is None):
                        observe_owner(turn, item)
            if owner_matches and lookup_receipt is None:
                if service_lookup:
                    lookup_receipt = observed_lookup(page)
        owner_prior = core.read_frontier(config["ledger_path"], owner_ref["thread_id"])
        reader.read_phase = "read-owner"
        owner_batch = scan_control_history(reader, config, core, owner_ref["thread_id"],
            owner_config["host_id"], owner_prior, visit_page=visit_original_owner,
            maximum=OWNER_LOOKUP_PAGES if owner_prior is not None else MAX_PAGES,
            proof_ready=lambda: bool(owner_matches))
        batches.append(owner_batch)
    if owner_matches:
        owner_item, owner_context, owner_time = owner_matches[0]
    need(owner_item is not None, "owner_item_not_observed")
    owner_receipt = core.verify_owner_item(request, owner_item, delivery_context=owner_context)
    delivery_receipt = core.verify_delivery(request, source, receiving)
    # A slow independent owner lookup must not leave a stale control head.
    # Reread through each actually observed old head, including the whole turn.
    refreshed_batches = []
    for batch in batches:
        reader.read_phase = "read-source" if batch["scope"]["source_thread_id"] == config["source_thread_id"] else "read-owner"
        refreshed_batches.append(refresh_control_history(reader, config, core, batch))
    for batch in refreshed_batches:
        controls.extend(item for item in batch["controls"]
                        if item["operation_id"] == request["operation_id"])
    controls.extend(core.read_controls(config["ledger_path"], request["operation_id"],
        list(dict.fromkeys([config["source_thread_id"], owner_ref["thread_id"]]))))
    return {"owner_text": owner_item["content"][0]["text"], "owner_receipt": owner_receipt,
            "delivery_receipt": delivery_receipt, "owner_freshness": owner_time,
            "owner_lookup": lookup_receipt,
            "projection_batches": refreshed_batches,
            "control_coverage": {"source_thread_id": config["source_thread_id"],
                "owner_thread_id": owner_ref["thread_id"], "page_bound": MAX_PAGES,
                "live_head_refreshed": True, "scopes": [{**batch["scope"],
                    "pages": batch["pages"], "frontier_turn_id": batch["coverage_receipt"]["frontier_turn_id"],
                    "history_end_observed": batch["coverage_receipt"]["history_end_observed"],
                    "boundary_turn_complete": batch["coverage_receipt"]["boundary_turn_complete"],
                    "coverage_complete": True} for batch in refreshed_batches]},
            "controls": controls}


def admission_prompt(request: dict, owner_text: str, receipt: dict) -> str:
    return (
        "Verified delegated task received by the owning Codex hook. The original owner message "
        "below is Native evidence of the owner's instruction; evaluate the delegated task within "
        "that scope. This evidence does not grant broader target permission. Use this receiver's "
        "fresh turn_ref for Memory admission; never reuse the sender's reference.\n\n"
        + "Original owner message:\n" + owner_text + "\n\nDelegated task:\n" + request["task"]
        + "\n\nProvenance DATA:\n" + json.dumps(receipt, ensure_ascii=False, sort_keys=True)
        + "\n\nReturn execution status and independently verifiable result DATA to Medor thread "
        + request["reply_thread_id"] + ". A delivered reply is not proof of completion."
    )


def _handle(event: str, payload: dict, config: dict, core, reader, *, operation_id: str | None = None,
            observation: dict | None = None, diagnostic_read_only: bool = False) -> dict:
    config = validate_config(config)
    thread_id = identity(payload.get("session_id") or payload.get("thread_id"),
                         "hook_thread_identity_missing")
    turn_id = identity(payload.get("turn_id") or payload.get("turnId"),
                       "hook_turn_identity_missing")
    native_thread_id, receiving_identity = native_receiving_identity(thread_id, payload)
    if native_thread_id not in DIAGNOSTIC_ACTORS:
        observation = None
    reader.read_phase = "read-current"
    found = find_receiving(reader, config, native_thread_id, turn_id, core,
                           observation=observation)
    if found is None:
        need(operation_id is None, "active_delegation_not_observed")
        result = {"protocol": PROTOCOL, "status": "absent"}
        if receiving_identity is not None:
            result["receiving_identity"] = receiving_identity
        return result
    request, receiving = found
    # This normalization fixes ordinary internal collaboration lookup only.
    # Root-keyed owning state cannot mint a child-targeted Memory/Scope binding.
    need(receiving_identity is None, "subagent_delegated_binding_unsupported")
    need(operation_id is None or request["operation_id"] == operation_id,
         "active_operation_mismatch")
    proof = collect_proof(reader, config, core, request, receiving)
    owner_current(config, request["owner_ref"]["thread_id"])
    proof["owner_freshness"] = owner_freshness(
        request, proof["owner_freshness"]["native_turn_started_at"],
        turn_id=proof["owner_freshness"]["owner_turn_id"],
        item_id=proof["owner_freshness"]["owner_item_id"])
    phase_trace = getattr(reader, "phase_trace", None)
    if phase_trace is not None:
        phase_trace.emit("proof-ready")
    if diagnostic_read_only:
        return {"protocol": PROTOCOL, "status": "denied", "code": "diagnostic_read_only",
                "execute": False, "provenance_verified": True}
    # No durable state is touched before all independent Native joins validate.
    ledger = core.Ledger(config["ledger_path"])
    for batch in proof["projection_batches"]:
        ledger.capture_projection(source_thread_id=batch["scope"]["source_thread_id"],
            host_id=batch["scope"]["host_id"], expected_frontier=batch["expected_frontier"],
            controls=batch["controls"], coverage_receipt=batch["coverage_receipt"])
    proof["controls"] = core.read_controls(config["ledger_path"], request["operation_id"],
        list(dict.fromkeys([config["source_thread_id"], request["owner_ref"]["thread_id"]])))
    state = ledger.status(request["operation_id"])
    need(not state.get("found") or state.get("request_digest") == core.digest(request),
         "operation_request_conflict")
    if state.get("binding") and (request["owner_ref"]["turn_id"] is None
                                 or "resolved_owner_ref" in state["binding"]):
        need(state["binding"].get("resolved_owner_ref") == proof["owner_receipt"]["resolved_owner_ref"]
             and state["binding"].get("owner_evidence_digest") == proof["owner_receipt"]["evidence_digest"],
             "owner_resolved_reference_changed")
    need(event != "Stop" or state.get("found"), "delegated_task_not_admitted")
    if proof["controls"] and not state.get("found"):
        # Reserve the fully proved request before accepting a control from its
        # original owner thread; core binds that control to this saved owner.
        ledger.reserve(request, proof["owner_receipt"])
    for control in proof["controls"]:
        ledger.revoke(request["operation_id"], control)
    state = ledger.status(request["operation_id"])
    need(not state["revoked"], "operation_revoked")
    if state.get("found") and state.get("state") != "reserved":
        delivery = state.get("delivery") or {}
        current = (state.get("state") == "executing"
                   and state.get("request_digest") == core.digest(request)
                   and delivery.get("target_thread_id") == thread_id
                   and delivery.get("receiving_turn_id") == turn_id
                   and delivery.get("receiving_item_id") == receiving["item_id"])
        if current:
            return {"protocol": PROTOCOL, "status": "current", "operation_id": request["operation_id"],
                    "request_digest": core.digest(request), "scope_receipt": state["binding"],
                    "state": "awaiting-terminal" if event == "Stop" else "executing"}
        return {"protocol": PROTOCOL, "status": "duplicate", "operation_id": request["operation_id"],
                "request_digest": core.digest(request), "cached_status": state, "execute": False}
    ledger.reserve(request, proof["owner_receipt"])
    claim = ledger.claim(request["operation_id"], core.digest(request), proof["delivery_receipt"])
    if not claim["execute"]:
        return {"protocol": PROTOCOL, "status": "duplicate", "operation_id": request["operation_id"],
                "request_digest": core.digest(request), "cached_status": claim, "execute": False}
    provenance = {"owner": proof["owner_receipt"], "delivery": proof["delivery_receipt"],
                  "owner_freshness": proof["owner_freshness"],
                  "control_coverage": proof["control_coverage"]}
    if proof["owner_lookup"] is not None:
        provenance["owner_lookup"] = proof["owner_lookup"]
    return {"protocol": PROTOCOL, "status": "accepted", "operation_id": request["operation_id"],
            "request_digest": core.digest(request), "request": request, "owner_text": proof["owner_text"],
            "provenance_receipt": provenance, "claim": claim, "scope_receipt": claim["binding"],
            "admission_prompt": admission_prompt(request, proof["owner_text"], provenance)}


def handle(event: str, payload: dict, config: dict, core, reader, *, operation_id: str | None = None,
           observation: dict | None = None, diagnostic_read_only: bool = False) -> dict:
    validate_config(config)
    thread_id = identity(payload.get("session_id") or payload.get("thread_id"),
                         "hook_thread_identity_missing")
    enabled = active_receiving_observation(config, thread_id)
    if diagnostic_read_only:
        need(enabled is not None and payload.get("agent_id") in (None, "", thread_id),
             "diagnostic_mode_unauthorized")
    if enabled is not None:
        if observation is None:
            observation = enabled
        else:
            observation.update(enabled)
    else:
        observation = None
    try:
        result = _handle(event, payload, config, core, reader, operation_id=operation_id,
                         observation=observation, diagnostic_read_only=diagnostic_read_only)
    except core.DelegationError as error:
        if str(error) != "control_projection_frontier_conflict":
            raise
        # A concurrent verified observer may advance a frontier while this
        # proof is collected. Reread the WHOLE proof once; the same reader
        # retains its original deadline. Never rebase or reuse stale evidence.
        result = _handle(event, payload, config, core, reader, operation_id=operation_id,
                         observation=observation, diagnostic_read_only=diagnostic_read_only)
    if observation is not None and "requested_thread_id" in observation:
        result["receiving_observation"] = observation
    if diagnostic_read_only and result["status"] == "absent":
        result.update(code="diagnostic_no_task_frame", execute=False, provenance_verified=False)
    return result


def backfill_controls(config: dict, core, reader, *, dry_run: bool = True,
                      maximum: int = 100, progress=None) -> dict:
    """Standalone actual Native history scan. No input JSON can supply evidence."""
    validate_config(config)
    thread_id, host_id = config["source_thread_id"], config["source_host_id"]
    prior = core.read_frontier(config["ledger_path"], thread_id)
    reader.read_phase = "read-source"
    if not dry_run and prior is None:
        return resume_initial_backfill(config, core, reader, maximum=maximum, progress=progress)
    batch = scan_control_history(reader, config, core, thread_id, host_id, prior,
                                 maximum=maximum, force_history_end=True, progress=progress)
    batch = refresh_control_history(reader, config, core, batch)
    need(batch["coverage_receipt"]["history_end_observed"], "control_coverage_incomplete")
    result = {"protocol": PROTOCOL, "mode": "backfill-controls",
              "status": "dry-run-complete" if dry_run else "projection-captured",
              "execute": False, "claims_mutated": False,
              "source_thread_id": thread_id, "host_id": host_id,
              "pages": batch["pages"], "control_count": len(batch["controls"]),
              "coverage_receipt": batch["coverage_receipt"],
              "controls": batch["controls"], "frontier_advanced": False}
    if not dry_run:
        ledger = core.Ledger(config["ledger_path"])
        result["frontier"] = ledger.capture_projection(source_thread_id=thread_id,
            host_id=host_id, expected_frontier=prior, controls=batch["controls"],
            coverage_receipt=batch["coverage_receipt"])
        result["frontier_advanced"] = True
    return result


def observer_context(config: dict, core) -> dict:
    """Bind private progress to reviewed code bytes, without pinning copy paths."""
    pins = {key: config.get(key) for key in ("adapter_sha256", "core_sha256", "bridge_sha256")}
    need(all(isinstance(value, str) and SHA256.fullmatch(value) for value in pins.values()),
         "bootstrap_observer_pins_invalid")
    need(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == pins["adapter_sha256"],
         "bootstrap_observer_runtime_mismatch")
    return {**projection_scope(config, config["source_thread_id"], config["source_host_id"]),
            "observer_schema": OBSERVER_SCHEMA,
            "observer_runtime_digest": core.digest({"schema":OBSERVER_SCHEMA,"pins":pins,
                "native_max_chars":MAX_CHARS,"native_turn_limit":10})}


def observation_page(page: dict, config: dict, core, observer: dict,
                     original_head: str, input_cursor: str | None) -> tuple[list, dict]:
    check_page(page, observer["source_thread_id"], observer["host_id"])
    flags = page["page"]
    more, cursor = flags.get("hasMore"), flags.get("nextCursor")
    need(type(more) is bool and more == bool(cursor)
         and page.get("truncated",False) is False and flags.get("truncated",False) is False,
         "control_coverage_incomplete")
    need(cursor is None or isinstance(cursor,str) and 0 < len(cursor) <= 16384,
         "native_cursor_invalid")
    turns = page["turns"]
    need(0 < len(turns) <= 10, "control_coverage_incomplete")
    turn_ids = [identity(turn.get("id"),"control_frontier_invalid")
                for turn in turns if isinstance(turn,dict)]
    need(len(turn_ids) == len(turns) and len(set(turn_ids)) == len(turn_ids),
         "control_coverage_incomplete")
    controls = control_receipts(page,config,core,None,
                                control_thread_id=observer["source_thread_id"])
    controls = list({item["evidence_digest"]:item for item in controls}.values())
    receipt = {**observer,"original_head_turn_id":original_head,
               "input_cursor":input_cursor,"next_cursor":cursor,"turn_ids":turn_ids,
               "page_complete":True,"history_end_observed":not more,
               "control_evidence_digests":sorted(item["evidence_digest"] for item in controls)}
    receipt["evidence_digest"] = core.digest(receipt)
    return controls,receipt


def public_observation(state: dict) -> dict:
    """Opaque continuation locators remain private; public progress grants nothing."""
    cursor = state["cursor"]
    return {key:state[key] for key in ("generation","seq","pages_total","control_count",
                                      "original_head_turn_id","history_end_observed","stage_digest")} | {
        "cursor_sha256":hashlib.sha256(cursor.encode()).hexdigest() if cursor is not None else None}


def resume_initial_backfill(config: dict, core, reader, *, maximum: int, progress=None) -> dict:
    """Persist only actual Native observations; incomplete progress is never a frontier."""
    need(type(maximum) is int and 1 <= maximum <= 100,"native_page_budget_invalid")
    observer = observer_context(config,core)
    state = core.read_observation(config["ledger_path"],**observer)
    ledger = None
    committed = 0
    resumed = state is not None
    if state is None:
        page = reader.read(observer["source_thread_id"],observer["host_id"])
        check_page(page,observer["source_thread_id"],observer["host_id"])
        need(bool(page["turns"]) and isinstance(page["turns"][0],dict),"control_frontier_missing")
        head = identity(page["turns"][0].get("id"),"control_frontier_invalid")
        controls,receipt = observation_page(page,config,core,observer,head,None)
        ledger = core.Ledger(config["ledger_path"])
        state = ledger.begin_observation(**observer,original_head_turn_id=head)
        state = ledger.append_observation(expected_observation=state,controls=controls,page_receipt=receipt)
        committed += 1
    else:
        # The stored cursor is only a locator. Reread its producing page and
        # prove the complete saved boundary before using a fresh continuation.
        input_cursor = state["last_page_input_cursor"] if state["pages_total"] else None
        page = reader.read(observer["source_thread_id"],observer["host_id"],cursor=input_cursor)
        controls,receipt = observation_page(page,config,core,observer,
                                            state["original_head_turn_id"],input_cursor)
        ledger = core.Ledger(config["ledger_path"])
        if state["pages_total"]:
            state = ledger.resume_observation(expected_observation=state,controls=controls,page_receipt=receipt)
        else:
            state = ledger.append_observation(expected_observation=state,controls=controls,page_receipt=receipt)
            committed += 1
    while not state["history_end_observed"] and committed < maximum:
        input_cursor = state["cursor"]
        page = reader.read(observer["source_thread_id"],observer["host_id"],cursor=input_cursor)
        controls,receipt = observation_page(page,config,core,observer,
                                            state["original_head_turn_id"],input_cursor)
        state = ledger.append_observation(expected_observation=state,controls=controls,page_receipt=receipt)
        committed += 1
        if progress is not None and (committed % 5 == 0 or state["history_end_observed"]):
            progress({"phase":"history-staging","pages":committed,"pages_total":state["pages_total"],
                      "observed_controls":state["control_count"],"history_end_observed":state["history_end_observed"]})
    result = {"protocol":PROTOCOL,"mode":"backfill-controls","status":"staging-incomplete",
              "execute":False,"claims_mutated":False,"frontier_advanced":False,
              "source_thread_id":observer["source_thread_id"],"host_id":observer["host_id"],
              "pages":committed,"resumed":resumed,"observation":public_observation(state)}
    if not state["history_end_observed"]:
        return result
    # Publishing requires a new live read, through the whole original head
    # turn. Staged progress cannot substitute for fresh revocation evidence.
    boundary = {**projection_scope(config,observer["source_thread_id"],observer["host_id"]),
                "frontier_turn_id":state["original_head_turn_id"]}
    refreshed = scan_control_history(reader,config,core,observer["source_thread_id"],
                                     observer["host_id"],boundary)
    controls = refreshed["controls"]
    receipt = {**observer,"original_head_turn_id":state["original_head_turn_id"],
               "frontier_turn_id":refreshed["coverage_receipt"]["frontier_turn_id"],
               "boundary_turn_complete":True,"coverage_complete":True,
               "control_evidence_digests":sorted(item["evidence_digest"] for item in controls)}
    receipt["evidence_digest"] = core.digest(receipt)
    frontier = ledger.finalize_observation(expected_observation=state,controls=controls,refresh_receipt=receipt)
    result.update(status="projection-captured",frontier_advanced=True,frontier=frontier,
                  pages=committed+refreshed["pages"],
                  staged_control_count=state["control_count"],refresh_control_count=len(controls))
    if "control_count" in frontier:
        result["control_count"] = frontier["control_count"]
    return result


def owner_locator_path(config, owner_ref):
    if not all(isinstance(owner_ref.get(k), str) and TOKEN.fullmatch(owner_ref[k])
               for k in ("thread_id", "turn_id", "item_id")):
        return None
    key = hashlib.sha256(json.dumps(owner_ref, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return Path(config["ledger_path"]).parent / "owner-locators" / (key + ".json")


def read_owner_locator(config, owner_ref):
    """An untrusted pagination hint, never evidence or authority."""
    path = owner_locator_path(config, owner_ref)
    try:
        if path is None or path.is_symlink() or path.parent.is_symlink() or not path.is_file():
            return None
        if getattr(path, "is_junction", lambda: False)() or getattr(path.parent, "is_junction", lambda: False)():
            return None
        raw = path.read_bytes()
        if len(raw) > 16384:
            return None
        def pairs(items):
            value = {}
            for key, item in items:
                if key in value: raise ValueError("duplicate_locator_key")
                value[key] = item
            return value
        value = json.loads(raw, object_pairs_hook=pairs)
        if set(value) != {"protocol", "owner_ref", "cursor", "expires"} or value["protocol"] != "integrity/codex-owner-locator/v1":
            return None
        if value["owner_ref"] != owner_ref or type(value["expires"]) is not int or value["expires"] <= time.time():
            return None
        cursor = value["cursor"]
        return cursor if isinstance(cursor, str) and 0 < len(cursor) < 12000 else None
    except (OSError, ValueError, TypeError, RecursionError):
        return None


def save_owner_locator(config, request, cursor):
    """Derived locator cache. Receiving must re-read Native and verify the owner."""
    path = owner_locator_path(config, request["owner_ref"])
    if path is None or not isinstance(cursor, str) or not 0 < len(cursor) < 12000:
        return
    try:
        if path.parent.is_symlink() or getattr(path.parent, "is_junction", lambda: False)():
            return
        path.parent.mkdir(exist_ok=True)
        if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
            return
        if not path.exists() and sum(1 for _ in path.parent.glob("*.json")) >= 128:
            return
        raw = json.dumps({"protocol":"integrity/codex-owner-locator/v1", "owner_ref":request["owner_ref"],
                          "cursor":cursor, "expires":request["expires"]}, sort_keys=True).encode()
        if len(raw) > 16384: return
        temporary = path.with_name(path.name + "." + str(os.getpid()) + ".tmp")
        with temporary.open("xb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError:
        return


def preparation_owner_locator(config, owner_thread_id, owner_message_id, owner_turn_id, owner_item_id):
    """Find a bounded untrusted hint; preparation still re-reads Native."""
    if owner_message_id is None and owner_turn_id is None:
        return None
    root = Path(config["ledger_path"]).parent / "owner-locators"
    try:
        if not root.is_dir() or root.is_symlink() or getattr(root, "is_junction", lambda: False)():
            return None
        found = []
        for index, path in enumerate(root.glob("*.json")):
            if index >= 128:
                return None
            if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
                continue
            raw = path.read_bytes()
            if len(raw) > 16384:
                continue
            value = object_json(raw.decode("utf-8"))
            ref = value.get("owner_ref")
            if not isinstance(ref, dict) or ref.get("thread_id") != owner_thread_id:
                continue
            if owner_message_id is not None and ref.get("message_id") != owner_message_id:
                continue
            if owner_turn_id is not None and (ref.get("turn_id"), ref.get("item_id")) != (owner_turn_id, owner_item_id):
                continue
            if owner_locator_path(config, ref) != path:
                continue
            cursor = read_owner_locator(config, ref)
            if cursor is not None:
                found.append((ref, cursor))
        return found[0] if len(found) == 1 else None
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        return None


def read_optional_owner_hint(reader, thread_id, host_id, cursor):
    """A failed locator grants nothing; canonical history still proves everything.

    Discard only the Native tool's fixed failure on this optional cursor. Keep
    the same reader, transport, identity and deadline. Malformed successful
    pages and every other failure remain fatal at their existing boundary.
    """
    try:
        return reader.read(thread_id, host_id, cursor=cursor)
    except AdapterError as error:
        last = getattr(reader, "last_read", None)
        if (str(error) != "native_read_unavailable" or not isinstance(last, dict)
                or last.get("fault_kind") != "tool-failed"):
            raise
        return None


def prepare_delegation(config: dict, core, reader, *, target_thread_id: str, task: str,
                       owner_thread_id: str | None = None, owner_message_id: str | None = None,
                       owner_turn_id: str | None = None, owner_item_id: str | None = None) -> dict:
    """Prepare DATA from a concrete live human item; no send, state write, or grant."""
    validate_config(config)
    target_thread_id = identity(target_thread_id, "preparation_target_invalid")
    owner_thread_id = owner_thread_id or config["source_thread_id"]
    context = config["allowed_owner_threads"].get(owner_thread_id)
    need(context is not None, "owner_thread_not_allowed")
    owner_current(config, owner_thread_id)
    need((owner_turn_id is None) == (owner_item_id is None), "preparation_native_locator_incomplete")
    need(not (owner_message_id is not None and owner_turn_id is not None), "preparation_locator_ambiguous")
    if owner_message_id is not None:
        identity(owner_message_id, "preparation_service_locator_invalid")
        need(context["room_id"] is not None, "preparation_service_room_missing")
    elif owner_turn_id is not None:
        identity(owner_turn_id, "preparation_native_locator_invalid")
        identity(owner_item_id, "preparation_native_locator_invalid")
    else:
        need(owner_thread_id == config["source_thread_id"], "preparation_owner_requires_exact_locator")
    target = reader.read(target_thread_id, "local", limit=1, outputs=False)
    check_page(target, target_thread_id, "local")
    selected = []
    owner_cursor = None
    locator = preparation_owner_locator(config, owner_thread_id, owner_message_id, owner_turn_id, owner_item_id)
    first = None
    if locator is not None:
        first = read_optional_owner_hint(reader, owner_thread_id, context["host_id"], locator[1])
        if first is not None:
            check_page(first, owner_thread_id, context["host_id"])
            owner_cursor = locator[1]
    for page in pages(reader, owner_thread_id, context["host_id"], first=first, maximum=OWNER_LOOKUP_PAGES):
        turns = page["turns"] if owner_message_id is not None or owner_turn_id is not None else page["turns"][:1]
        for turn in turns:
            need(isinstance(turn, dict) and isinstance(turn.get("items"), list), "preparation_owner_incomplete")
            for item in turn["items"]:
                if not isinstance(item, dict) or item.get("type") != "userMessage":
                    continue
                if owner_turn_id is not None and (turn.get("id") != owner_turn_id or item.get("id") != owner_item_id):
                    continue
                if owner_message_id is not None:
                    blocks = item.get("content")
                    metadata = blocks[0].get("text") if isinstance(blocks, list) and blocks and isinstance(blocks[0], dict) else None
                    service = delivery_context(metadata)
                    if service is None or service["message_id"] != owner_message_id:
                        if isinstance(metadata, str) and "message_id=" + owner_message_id in metadata:
                            raise AdapterError("owner_service_evidence_incomplete")
                        continue
                normalized, service_context = normalized_owner(item)
                need(service_context["room_id"] == context["room_id"], "owner_room_not_allowed")
                selected.append((normalized, {**service_context, "thread_id": owner_thread_id,
                    "turn_id": identity(turn.get("id"), "owner_native_turn_invalid")}, turn.get("startedAt")))
        if selected or owner_message_id is None and owner_turn_id is None:
            break
        owner_cursor = page["page"].get("nextCursor")
    need(len(selected) == 1, "preparation_owner_ambiguous" if selected else "preparation_owner_requires_exact_locator")
    item, actual_context, started = selected[0]
    need(type(started) is int, "owner_native_timestamp_invalid")
    expiry = min(started + MAX_OWNER_AGE,
                 config.get("temporary_owner_expiry", {}).get(owner_thread_id, started + MAX_OWNER_AGE))
    prepared = core.prepare_request(owner_item=item, delivery_context=actual_context,
        owner_started_at=started, source_thread_id=config["source_thread_id"],
        target_host_id=config["target_machine_id"], target_thread_id=target_thread_id,
        task=task, not_before=started, expires=expiry,
        allowed_owner_threads=set(config["allowed_owner_threads"]), ledger_path=config["ledger_path"])
    if locator is not None:
        need(prepared["request"]["owner_ref"] == locator[0], "preparation_cached_owner_reference_changed")
    save_owner_locator(config, prepared["request"], owner_cursor)
    frame = prepared["frame"]
    # Leave room for the observed Native XML transport around the exact frame.
    # UTF-8 bytes also bound the MCP DATA output without silently truncating it.
    need(isinstance(frame, str) and len(frame.encode("utf-8")) < MAX_CHARS - 256,
         "preparation_native_frame_oversized")
    return {"protocol": PROTOCOL, "status": "prepared-data", "execute": False,
            "sent": False, "claims_mutated": False, "action_authority": "not-evaluated", **prepared,
            "frame_sha256": hashlib.sha256(frame.encode("utf-8")).hexdigest()}


def preparation_stdin(raw: bytes) -> dict:
    need(0 < len(raw) <= MAX_HOOK_BYTES, "preparation_input_oversized")
    try:
        data = object_json(raw.decode("utf-8"))
    except UnicodeError:
        raise AdapterError("preparation_input_invalid_utf8") from None
    need(set(data) <= {"target_thread_id", "task", "owner_thread_id", "owner_message_id",
                       "owner_turn_id", "owner_item_id"}
         and {"target_thread_id", "task"} <= set(data), "preparation_input_fields_invalid")
    need(isinstance(data["task"], str), "preparation_task_invalid")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", choices=("PreToolUse", "Stop"))
    parser.add_argument("--config", required=True)
    parser.add_argument("--operation-id")
    parser.add_argument("--diagnostic-read-only", action="store_true")
    parser.add_argument("--native-budget-seconds", type=int, choices=range(1, 66),
                        default=int(NATIVE_DEADLINE))
    parser.add_argument("--backfill-controls", action="store_true")
    parser.add_argument("--prepare-delegation", action="store_true")
    parser.add_argument("--prepare-stdin", action="store_true")
    parser.add_argument("--target-thread-id")
    parser.add_argument("--task-text")
    parser.add_argument("--owner-thread-id")
    parser.add_argument("--owner-message-id")
    parser.add_argument("--owner-turn-id")
    parser.add_argument("--owner-item-id")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--backfill-max-pages", type=int, choices=range(1, 101), default=100)
    parser.add_argument("--backfill-budget-seconds", type=int, choices=range(1, 601), default=600)
    parser.add_argument("--context-thread-id")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    if not args.backfill_controls and not args.prepare_delegation and args.event is None:
        parser.error("--event is required for owning-hook mode")
    if args.backfill_controls and (args.event is not None or args.operation_id is not None
                                  or args.diagnostic_read_only or args.prepare_delegation):
        parser.error("backfill mode is separate from receiving-hook mode")
    if args.prepare_stdin and not args.prepare_delegation:
        parser.error("prepare stdin requires prepare mode")
    prepare_arguments = (args.target_thread_id, args.task_text, args.owner_thread_id,
                         args.owner_message_id, args.owner_turn_id, args.owner_item_id)
    if args.prepare_delegation and (args.event is not None or args.operation_id is not None
                                   or args.diagnostic_read_only
                                   or args.prepare_stdin and any(value is not None for value in prepare_arguments)
                                   or not args.prepare_stdin and (args.target_thread_id is None or args.task_text is None)):
        parser.error("prepare mode requires target/task data and no hook mode or claimed operation")
    observation = {}
    phase_trace = None
    reader = None
    output = None
    try:
        config = validate_config(object_json(Path(args.config).read_text(encoding="utf-8")))
        if args.prepare_delegation:
            prepared_input = preparation_stdin(sys.stdin.buffer.read(MAX_HOOK_BYTES + 1)) if args.prepare_stdin else {
                "target_thread_id":args.target_thread_id, "task":args.task_text,
                "owner_thread_id":args.owner_thread_id, "owner_message_id":args.owner_message_id,
                "owner_turn_id":args.owner_turn_id, "owner_item_id":args.owner_item_id}
            core = load_pinned(config["core_path"], config["core_sha256"], "integrity_prepare_core")
            bridge = load_pinned(config["bridge_path"], config["bridge_sha256"], "integrity_prepare_native")
            reader = NativeReader(bridge, identity(args.context_thread_id or config["source_thread_id"],
                "native_context_identity_missing"), deadline=time.monotonic() + PREPARATION_DEADLINE)
            result = prepare_delegation(config, core, reader, **prepared_input)
            sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
            return 0
        if args.backfill_controls:
            if args.output is not None:
                requested_output = Path(args.output)
                task_root = DIAGNOSTIC_PHASE_ROOT.parent.resolve()
                need(requested_output.is_absolute() and requested_output.resolve().is_relative_to(task_root)
                     and not requested_output.exists()
                     and not any(path.is_symlink() or path.is_junction() for path in (requested_output, *requested_output.parents)),
                     "backfill_output_path_invalid")
                checkpoint = requested_output.with_name(requested_output.name + ".checkpoint.json")
                need(not checkpoint.is_symlink() and not checkpoint.is_junction(), "backfill_output_path_invalid")
                output = requested_output
            core = load_pinned(config["core_path"], config["core_sha256"], "integrity_control_backfill_core")
            bridge = load_pinned(config["bridge_path"], config["bridge_sha256"], "integrity_control_backfill_native")
            context_id = identity(args.context_thread_id or os.environ.get("CODEX_THREAD_ID")
                                  or config["source_thread_id"], "native_context_identity_missing")
            reader = NativeReader(bridge, context_id,
                deadline=time.monotonic() + args.backfill_budget_seconds, read_retries=1,
                read_observer=(lambda value: write_native_checkpoint(checkpoint, value)) if output is not None else None)
            def progress(value):
                sys.stderr.write(json.dumps({"mode": "backfill-controls", **value}, separators=(",", ":")) + "\n")
                sys.stderr.flush()
            result = backfill_controls(config, core, reader, dry_run=args.dry_run,
                                       maximum=args.backfill_max_pages, progress=progress)
            if output is not None:
                with output.open("x", encoding="utf-8", newline="\n") as stream:
                    stream.write(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
            public_result = {key: value for key, value in result.items() if key != "controls"}
            public_result["native_elapsed_seconds"] = round(time.monotonic() - reader.started, 3)
            sys.stdout.write(json.dumps(public_result, ensure_ascii=False, separators=(",", ":")) + "\n")
            return 0
        raw = sys.stdin.buffer.read(MAX_HOOK_BYTES + 1)
        need(0 < len(raw) <= MAX_HOOK_BYTES, "hook_payload_oversized")
        payload = object_json(raw.decode("utf-8"))
        phase_trace = PhaseTrace(config, payload)
        phase_trace.capture_native()
        phase_trace.emit("payload-ready")
        if args.diagnostic_read_only:
            need(active_receiving_observation(config, payload.get("session_id") or payload.get("thread_id")) is not None
                 and payload.get("agent_id") in (None, "", payload.get("session_id") or payload.get("thread_id")), "diagnostic_mode_unauthorized")
        phase_trace.emit("core-import-start")
        core = load_pinned(config["core_path"], config["core_sha256"], "integrity_delegation_core_pinned")
        phase_trace.emit("core-import-done")
        phase_trace.emit("bridge-import-start")
        bridge = load_pinned(config["bridge_path"], config["bridge_sha256"], "integrity_native_bridge_pinned")
        phase_trace.emit("bridge-import-done")
        thread_id = identity(payload.get("session_id") or payload.get("thread_id"),
                             "hook_thread_identity_missing")
        reader = NativeReader(bridge, thread_id,
                              deadline=time.monotonic() + args.native_budget_seconds,
                              phase_trace=phase_trace)
        result = handle(args.event, payload, config, core, reader,
                        operation_id=args.operation_id, observation=observation,
                        diagnostic_read_only=args.diagnostic_read_only)
    except AdapterError as error:
        if phase_trace is not None:
            phase_trace.emit("error")
        result = {"protocol": PROTOCOL, "status": "denied", "code": str(error), "execute": False}
    except Exception as error:
        if phase_trace is not None:
            phase_trace.emit("error")
        # Only core's documented safe error code crosses the model boundary.
        safe_core = locals().get("core")
        code = str(error) if safe_core is not None and isinstance(error, safe_core.DelegationError) else "receiving_adapter_unavailable"
        result = {"protocol": PROTOCOL, "status": "denied", "code": code, "execute": False}
    if result.get("status") == "denied" and result.get("code") in {
            "native_read_unavailable", "native_evidence_deadline", "native_host_unavailable"}:
        result["native_failure"] = native_failure_observation(reader)
    if "requested_thread_id" in observation:
        result["receiving_observation"] = observation
    if phase_trace is not None:
        if reader is not None:
            phase_trace.capture_native(reader)
        if phase_trace.native_environment is not None:
            result.setdefault("receiving_observation", {"protocol": "integrity/codex-receiving-observation/v1"})["native_environment"] = phase_trace.native_environment
        phase_trace.emit("result-ready")
    if args.diagnostic_read_only:
        result["diagnostic_phase"] = phase_trace.phase if phase_trace is not None else "not-started"
        result["native_elapsed_seconds"] = round(time.monotonic() - reader.started, 3) if reader is not None else None
    if args.backfill_controls:
        result["mode"] = "backfill-controls"
        result["native_elapsed_seconds"] = round(time.monotonic() - reader.started, 3) if reader is not None else None
        if reader is not None and reader.last_read is not None:
            result["read_observation"] = {key: value for key, value in reader.last_read.items() if key != "cursor"}
        if output is not None and not output.exists():
            try:
                with output.open("x", encoding="utf-8", newline="\n") as stream:
                    stream.write(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
                result["outcome_persisted"] = True
            except OSError:
                result["outcome_persisted"] = False
    sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
    return 2 if (args.backfill_controls or args.prepare_delegation) and result.get("status") == "denied" else 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
