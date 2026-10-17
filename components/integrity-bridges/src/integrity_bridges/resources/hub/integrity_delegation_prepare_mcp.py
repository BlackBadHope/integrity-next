# SPDX-License-Identifier: Apache-2.0
"""Thin owner-host read-only MCP client for the protected Native preparation CLI.

Only the installed adapter obtains live owner evidence. This client neither
manufactures evidence nor sends, claims, reserves, admits or authorizes actions.
The registry must load its separately pinned release copy, never model code.
"""
from __future__ import annotations

from integrity_bridges.configuration import value as _integrity_value, require_config as _integrity_require_config

import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import types

SOURCE_THREAD_ID = _integrity_value('delegation_source_thread_id')
HOST = "owner-host"
PROJECT = Path(_integrity_value('path_dd2435d503a6'))
RUNTIME = Path(_integrity_value('path_5164c4d20152'))
CONFIG = RUNTIME / "delegation-config.json"
ADAPTER = RUNTIME / "integrity_delegation_codex.py"
CORE = RUNTIME / "integrity_delegation_core.py"
LEDGER = Path(_integrity_value('path_04d9ee0e8d07'))
SOURCE_HOST = _integrity_value('binding_source_host')
SOURCE_ROOM = _integrity_value('binding_source_room')
PYTHON = Path(_integrity_value('path_70ff966bc499'))
PYTHON_SHA256 = _integrity_value('pin_f223e53008dd')
PROTOCOL = "integrity/delegation-codex-receiving/v1"
REQUEST_PROTOCOL = "integrity/delegated-task/v1"
BEGIN, END = "BEGIN_INTEGRITY_DELEGATED_TASK", "END_INTEGRITY_DELEGATED_TASK"
MAX_TASK_BYTES, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES, MAX_FRAME_BYTES = 16000, 65536, 131072, 19744
TIMEOUT = 185
IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z")
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
ARGUMENTS = {"target_thread_id", "task", "host_id", "source_thread_id", "owner_thread_id",
             "owner_message_id", "owner_turn_id", "owner_item_id"}
OWNER_ARGUMENTS = {"owner_thread_id", "owner_message_id", "owner_turn_id", "owner_item_id"}
PREPARATION_STATUSES = {"new-request", "existing-reserved", "existing-executing", "existing-completed",
                        "existing-failed", "existing-unknown", "operation-revoked"}
SAFE_CODES = {"invalid_arguments", "source_not_ready", "pin_mismatch", "helper_timeout", "helper_unavailable",
              "helper_denied", "helper_output_invalid", "preparation_owner_requires_exact_locator",
              "preparation_owner_ambiguous", "owner_thread_not_allowed", "owner_room_not_allowed",
              "temporary_owner_expired", "preparation_owner_stale", "request_not_current",
              "preparation_prior_source_mismatch", "preparation_prior_request_conflict",
              "preparation_native_frame_oversized", "native_evidence_deadline", "native_read_unavailable"}

TOOL_SPEC = {"name": "codex_prepare_delegated_task",
    "description": "Prepare exact delegated-task DATA from a live human message in the explicitly configured source chat. This tool does not send or authorize actions. If the owner is older, give its service message ID or exact native turn/item. Retain dispatchable=false; never replace the returned operation ID.",
    "inputSchema": {"type": "object", "additionalProperties": False,
        "properties": {"host_id": {"type": "string", "enum": [HOST]},
            "source_thread_id": {"type": "string", "enum": [SOURCE_THREAD_ID]},
            "target_thread_id": {"type": "string", "minLength": 8, "maxLength": 128},
            "task": {"type": "string", "minLength": 1, "maxLength": MAX_TASK_BYTES},
            **{key: {"type": "string", "minLength": 8, "maxLength": 128} for key in OWNER_ARGUMENTS}},
        "required": ["target_thread_id", "task"]},
    "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}}


class PreparationClientError(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise PreparationClientError(code)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "helper_output_invalid")
        result[key] = value
    return result


def json_object(raw, maximum):
    need(isinstance(raw, bytes) and 0 < len(raw) <= maximum, "helper_output_invalid")
    value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(PreparationClientError("helper_output_invalid")))
    need(isinstance(value, dict), "helper_output_invalid")
    return value


def identifier(value):
    return isinstance(value, str) and IDENTITY.fullmatch(value) is not None and not value.startswith("turnref:")


def validate_arguments(arguments):
    need(isinstance(arguments, dict) and set(arguments).issubset(ARGUMENTS)
         and {"target_thread_id", "task"}.issubset(arguments), "invalid_arguments")
    need(arguments.get("host_id", HOST) == HOST and arguments.get("source_thread_id", SOURCE_THREAD_ID) == SOURCE_THREAD_ID,
         "invalid_arguments")
    need(identifier(arguments["target_thread_id"]), "invalid_arguments")
    task = arguments["task"]
    need(isinstance(task, str) and bool(task.strip()) and "\x00" not in task
         and len(task.encode("utf-8")) <= MAX_TASK_BYTES, "invalid_arguments")
    for key in OWNER_ARGUMENTS:
        need(key not in arguments or identifier(arguments[key]), "invalid_arguments")
    native = ("owner_turn_id" in arguments, "owner_item_id" in arguments)
    need(native[0] == native[1] and not (native[0] and "owner_message_id" in arguments), "invalid_arguments")
    need(arguments.get("owner_thread_id", SOURCE_THREAD_ID) == SOURCE_THREAD_ID or native[0] or "owner_message_id" in arguments,
         "invalid_arguments")
    payload = {key: value for key, value in arguments.items() if key not in {"host_id", "source_thread_id"}}
    encoded = canonical(payload).encode("utf-8")
    need(len(encoded) <= MAX_INPUT_BYTES, "invalid_arguments")
    return payload, encoded


def _read_pins():
    try:
        for path in (CONFIG, ADAPTER, PYTHON):
            need(path.is_file() and not path.is_symlink() and not path.is_junction(), "source_not_ready")
        config = json_object(CONFIG.read_bytes(), 65536)
        need(config.get("protocol") == "integrity/delegation-codex-config/v1"
             and config.get("source_thread_id") == SOURCE_THREAD_ID and config.get("target_machine_id") == HOST
             and isinstance(config.get("adapter_path"), str)
             and os.path.normcase(os.path.normpath(config["adapter_path"])) == os.path.normcase(os.path.normpath(str(ADAPTER))),
             "source_not_ready")
        expected = config.get("adapter_sha256")
        need(isinstance(expected, str) and SHA256.fullmatch(expected) is not None, "source_not_ready")
        raw_adapter = ADAPTER.read_bytes()
        need(0 < len(raw_adapter) <= 3 * 1024 * 1024 and sha(raw_adapter) == expected,
             "pin_mismatch")
        need(sha(PYTHON.read_bytes()) == PYTHON_SHA256, "pin_mismatch")
        tree = ast.parse(raw_adapter.decode("utf-8"))
        functions = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
        flags = {node.args[0].value for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument"
                 and node.args and isinstance(node.args[0], ast.Constant)}
        need("prepare_delegation" in functions and {"--prepare-delegation", "--prepare-stdin"}.issubset(flags),
             "source_not_ready")
        _source_ready(config)
    except PreparationClientError as error:
        raise PreparationClientError(str(error) if str(error) == "pin_mismatch" else "source_not_ready") from None
    except Exception:
        raise PreparationClientError("source_not_ready") from None


def _source_ready(config):
    """A COMPLETE protected frontier is prerequisite DATA, never action authority.

    Execute the exact already hashed Core bytes, not a second path read. Its
    existing read-only API rejects corrupt/mismatched facts and returns None
    for partial observation. The receiver still verifies the new LIVE prefix
    and owner at the execution boundary after preparation.
    """
    need(config.get("source_host_id") == SOURCE_HOST and config.get("source_room_id") == SOURCE_ROOM
         and isinstance(config.get("core_path"), str) and isinstance(config.get("ledger_path"), str)
         and os.path.normcase(os.path.normpath(config["core_path"])) == os.path.normcase(os.path.normpath(str(CORE)))
         and os.path.normcase(os.path.normpath(config["ledger_path"])) == os.path.normcase(os.path.normpath(str(LEDGER))),
         "source_not_ready")
    expected = config.get("core_sha256")
    need(isinstance(expected, str) and SHA256.fullmatch(expected) is not None and CORE.is_file()
         and not CORE.is_symlink() and not CORE.is_junction(), "source_not_ready")
    raw_core = CORE.read_bytes()
    need(0 < len(raw_core) <= 3 * 1024 * 1024 and sha(raw_core) == expected, "pin_mismatch")
    need(not LEDGER.is_symlink() and not LEDGER.is_junction(), "source_not_ready")
    module = types.ModuleType("_integrity_verified_readiness_core")
    module.__file__ = str(CORE)
    exec(compile(raw_core, str(CORE), "exec"), module.__dict__)
    need(callable(getattr(module, "read_frontier", None)), "source_not_ready")
    frontier = module.read_frontier(LEDGER, SOURCE_THREAD_ID)
    need(isinstance(frontier, dict) and frontier.get("source_thread_id") == SOURCE_THREAD_ID
         and frontier.get("source_provider") == "codex" and frontier.get("host_id") == SOURCE_HOST
         and frontier.get("source_room_id") == SOURCE_ROOM and identifier(frontier.get("frontier_turn_id"))
         and type(frontier.get("version")) is int and frontier["version"] >= 1, "source_not_ready")


def _execute(encoded):
    # Native needs an existing local execution context. The fixed configured source
    # and live human owner evidence are independently checked by the adapter.
    target = json_object(encoded, MAX_INPUT_BYTES).get("target_thread_id")
    need(identifier(target), "invalid_arguments")
    command = [str(PYTHON), "-I", "-S", "-X", "utf8", str(ADAPTER), "--prepare-delegation",
               "--prepare-stdin", "--config", str(CONFIG), "--context-thread-id", target]
    options = {"input": encoded, "capture_output": True, "shell": False, "timeout": TIMEOUT, "cwd": str(PROJECT)}
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NO_WINDOW
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = 0
        options["startupinfo"] = startup
    return subprocess.run(command, **options)


def validate_output(output, payload):
    need(set(output) == {"protocol", "status", "execute", "sent", "claims_mutated", "action_authority",
         "request", "frame", "owner_evidence", "operation_id", "request_digest", "reused_prior_request",
         "dispatchable", "preparation_status", "frame_sha256"}
         and output.get("protocol") == PROTOCOL and output.get("status") == "prepared-data"
         and output.get("execute") is False and output.get("sent") is False
         and output.get("claims_mutated") is False and output.get("action_authority") == "not-evaluated",
         "helper_output_invalid")
    request, frame = output.get("request"), output.get("frame")
    need(isinstance(request, dict) and isinstance(frame, str) and len(frame.encode("utf-8")) < MAX_FRAME_BYTES,
         "helper_output_invalid")
    need(set(request) == {"protocol", "operation_id", "source_thread_id", "owner_ref", "target", "task", "not_before", "expires", "reply_thread_id"}
         and request["protocol"] == REQUEST_PROTOCOL and request["source_thread_id"] == SOURCE_THREAD_ID
         and request["reply_thread_id"] == SOURCE_THREAD_ID and request["target"] == {"host_id": HOST, "thread_id": payload["target_thread_id"]}
         and request["task"] == payload["task"] and identifier(request["operation_id"])
         and output.get("operation_id") == request["operation_id"], "helper_output_invalid")
    need(type(request["not_before"]) is int and type(request["expires"]) is int
         and 0 <= request["not_before"] < request["expires"]
         and request["expires"] - request["not_before"] <= 86400, "helper_output_invalid")
    body = canonical(request)
    need(frame == BEGIN + "\n" + body + "\n" + END
         and output.get("frame_sha256") == sha(frame.encode("utf-8"))
         and output.get("request_digest") == sha(body.encode("utf-8")), "helper_output_invalid")
    owner = request["owner_ref"]
    need(isinstance(owner, dict) and set(owner) == {"thread_id", "turn_id", "item_id", "room_id", "message_id", "prompt_sha256"}
         and owner.get("thread_id") == payload.get("owner_thread_id", SOURCE_THREAD_ID)
         and all(identifier(owner.get(key)) for key in ("thread_id", "turn_id", "item_id"))
         and isinstance(owner.get("prompt_sha256"), str) and SHA256.fullmatch(owner["prompt_sha256"]), "helper_output_invalid")
    need((owner["room_id"] is None and owner["message_id"] is None)
         or (identifier(owner["room_id"]) and identifier(owner["message_id"])), "helper_output_invalid")
    for argument, field in (("owner_message_id", "message_id"), ("owner_turn_id", "turn_id"), ("owner_item_id", "item_id")):
        need(argument not in payload or owner.get(field) == payload[argument], "helper_output_invalid")
    evidence = output.get("owner_evidence")
    need(isinstance(evidence, dict) and evidence.get("protocol") == "integrity/delegation-owner-evidence/v1"
         and evidence.get("action_authority") == "not-evaluated" and evidence.get("source_thread_id") == SOURCE_THREAD_ID
         and evidence.get("request_digest") == output["request_digest"] and evidence.get("owner_ref") == owner,
         "helper_output_invalid")
    observed = dict(evidence)
    evidence_digest = observed.pop("evidence_digest", None)
    need(evidence_digest == sha(canonical(observed).encode("utf-8")), "helper_output_invalid")
    status = output.get("preparation_status")
    need(type(output.get("dispatchable")) is bool and type(output.get("reused_prior_request")) is bool
         and status in PREPARATION_STATUSES
         and (output["dispatchable"] is False or (status == "new-request" and output["reused_prior_request"] is False))
         and (status == "new-request" or output["dispatchable"] is False), "helper_output_invalid")
    return output


def _denied(code):
    return {"protocol": PROTOCOL, "status": "denied", "code": code if code in SAFE_CODES else "helper_denied",
            "execute": False, "sent": False, "claims_mutated": False, "action_authority": "not-evaluated"}


def prepare_delegated_task(arguments):
    """MCP handler. Input/output are DATA; do not resend nondispatchable results."""
    try:
        payload, encoded = validate_arguments(arguments)
        _read_pins()
        result = _execute(encoded)
        output = json_object(result.stdout, MAX_OUTPUT_BYTES)
        if result.returncode != 0 or output.get("status") == "denied":
            return _denied(output.get("code", "helper_denied"))
        return validate_output(output, payload)
    except subprocess.TimeoutExpired:
        return _denied("helper_timeout")
    except PreparationClientError as error:
        return _denied(str(error))
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return _denied("helper_output_invalid")
    except Exception:
        return _denied("helper_unavailable")
