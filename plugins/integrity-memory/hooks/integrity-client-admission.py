#!/usr/bin/env python3
"""Cross-platform stdlib hook for Integrity admission and Turn Memory coverage."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import select
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import integrity_client_turn_envelope as turn_envelope

EXPECTED_TOOLS = [
    "integrity_read_events",
    "integrity_append_event",
    "integrity_turn_memory_open",
    "integrity_turn_memory_close",
    "integrity_turn_memory_gap",
    "integrity_turn_memory_coverage",
    "integrity_home_search",
    "integrity_home_fetch",
    "integrity_context_admission",
    "integrity_context_admission_current_turn",
    "integrity_memory_capabilities",
    "integrity_seed_snapshot",
    "integrity_mind_graph",
    "integrity_architecture_admission",
    "integrity_seed_tasks",
    "integrity_seed_event_uid",
    "integrity_seed_connections",
    "integrity_memory_entity_brief",
    "integrity_memory_link_audit",
    "integrity_seed_replay",
]
DIRECT_CURRENT_EXPECTED_TOOLS = [
    name for name in EXPECTED_TOOLS if name != "integrity_context_admission_current_turn"
]
PREVIOUS_EXPECTED_TOOLS = [
    name
    for name in DIRECT_CURRENT_EXPECTED_TOOLS
    if name != "integrity_seed_event_uid"
]
LEGACY_EXPECTED_TOOLS = [
    name
    for name in PREVIOUS_EXPECTED_TOOLS
    if name not in {"integrity_memory_entity_brief", "integrity_memory_link_audit"}
]
SERVER_NAME = "integrity-client-memory"
BROKER_SERVER_VERSION = "1.4.1"
SERVER_VERSION = "2.10.0"
PREVIOUS_SERVER_VERSION = "2.9.0"
OLDER_SERVER_VERSION = "2.8.0"
LEGACY_SERVER_VERSION = "2.7.0"
ROLLOUT_LEGACY_SERVER_VERSION = "2.6.0"
HOOK_VERSION = "1.7.2"
LIFECYCLE_BUDGET_SECONDS = 45
LIFECYCLE_DEADLINE: float | None = None
SEMANTIC_CADENCE_MAX_AGE_SECONDS = 3600
SEMANTIC_CADENCE_MAX_ACTIONS = 24
SEMANTIC_CADENCE_MIN_TIMED_ACTIONS = 3
INTEGRITY_TOOL_RE = re.compile(r"(?i)(?:^|__)integrity_[a-z0-9_]+$")
APPEND_TOOL_RE = re.compile(r"(?i)integrity_append_event$")
CONTEXT_TOOL_RE = re.compile(
    r"(?i)integrity_context_admission(?:_current_turn)?$"
)
CURRENT_CONTEXT_TOOL_RE = re.compile(r"(?i)integrity_context_admission_current_turn$")
EVENT_UID_RE = re.compile(r"^client:[A-Za-z0-9][A-Za-z0-9._:-]{7,154}$")
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
MEANINGFUL_TOOL_RE = re.compile(r"(?i)(?:apply_patch|\bEdit\b|\bWrite\b|NotebookEdit)")
MUTATION_TEXT_RE = re.compile(
    r"(?i)\b(?:apply_patch|rm|mv|cp|install|chmod|chown|setfacl|git\s+(?:commit|push)|"
    r"systemctl\s+(?:start|stop|restart|enable|disable)|sed\s+-i|tee)\b"
)


class HookError(RuntimeError):
    pass


class HookTransportError(HookError):
    """A response may be lost; only an idempotent lifecycle call may replay."""


def remaining_lifecycle_seconds(maximum: float) -> float:
    if LIFECYCLE_DEADLINE is None:
        return maximum
    remaining = LIFECYCLE_DEADLINE - time.monotonic()
    if remaining <= 0:
        raise HookError("lifecycle_deadline_exhausted")
    return min(maximum, remaining)


def tool_failure(name: str, result: dict[str, Any]) -> HookError:
    """Keep safe error identity without reflecting arbitrary provider text."""
    document = find_document(result.get("content"), lambda item: "reason" in item)
    reason = str((document or {}).get("reason", ""))
    code = (document or {}).get("reason_code")
    if reason == "turn identity collides with another prompt":
        code = "turn_identity_prompt_collision"
    if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", code):
        code = "provider_denied"
    # Broker lifecycle calls already perform their bounded transport replay.
    return HookError(f"tool_{name}:{code}:reason_sha256={sha256_text(reason)}")


def compact(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def digest_object(value: object) -> str:
    return "sha256:" + sha256_text(compact(value))


def _require_exact_keys(value: object, expected: set[str], error: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise HookError(error)
    return value


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None


def validate_authority_contract(value: object, expected_status: str) -> None:
    contract = _require_exact_keys(
        value,
        {
            "protocol",
            "provider_authority",
            "target_action_authority",
            "coordination",
            "legacy_projection",
        },
        "model_mcp_authority_contract_shape_invalid",
    )
    provider = _require_exact_keys(
        contract.get("provider_authority"),
        {"provider", "scope", "execution", "production", "route", "canonical_seed_append"},
        "model_mcp_provider_authority_shape_invalid",
    )
    target = _require_exact_keys(
        contract.get("target_action_authority"),
        {"decision", "authoritative_source", "provider_boundary_is_target_denial"},
        "model_mcp_target_authority_shape_invalid",
    )
    coordination = _require_exact_keys(
        contract.get("coordination"),
        {
            "scope",
            "status",
            "canonical_seed_append_affected",
            "external_target_actions_affected",
        },
        "model_mcp_coordination_scope_shape_invalid",
    )
    legacy = _require_exact_keys(
        contract.get("legacy_projection"),
        {"production_authority", "semantics", "deprecated", "replacement"},
        "model_mcp_legacy_authority_shape_invalid",
    )
    if (
        contract.get("protocol") != "integrity-guardian/authority-separation/v1"
        or provider
        != {
            "provider": "integrity-client-memory",
            "scope": "canonical-seed-memory",
            "execution": "absent",
            "production": "absent",
            "route": "absent",
            "canonical_seed_append": "one-use-only",
        }
        or target
        != {
            "decision": "not-evaluated",
            "authoritative_source": "target-specific-action-guard",
            "provider_boundary_is_target_denial": False,
        }
        or coordination
        != {
            "scope": "integrity-memory-route",
            "status": expected_status,
            "canonical_seed_append_affected": False,
            "external_target_actions_affected": False,
        }
        or legacy
        != {
            "production_authority": False,
            "semantics": "memory-provider-does-not-grant-production-authority",
            "deprecated": True,
            "replacement": "authority_contract.provider_authority.production",
        }
    ):
        raise HookError("model_mcp_authority_contract_invalid")


def negotiated_context_protocol(context: dict[str, Any], requested_protocol: str) -> str:
    if requested_protocol not in {
        "integrity-client-memory-mcp/v3/context-admission/v1",
        "integrity-client-memory-mcp/v3/context-admission/v2",
    }:
        raise HookError("model_mcp_context_presentation_not_bound")
    capabilities = context.get("capabilities")
    if not isinstance(capabilities, dict):
        raise HookError("model_mcp_capabilities_invalid")
    facade = capabilities.get("facade")
    if not isinstance(facade, dict):
        raise HookError("model_mcp_facade_capabilities_invalid")
    identity = (capabilities.get("contract_version"), facade.get("server_version"))
    if identity == ("1.5.0", ROLLOUT_LEGACY_SERVER_VERSION):
        return "integrity-client-memory-mcp/v3/context-admission/v1"
    if identity not in {
        ("1.6.0", LEGACY_SERVER_VERSION),
        ("1.7.0", OLDER_SERVER_VERSION),
        ("1.8.0", PREVIOUS_SERVER_VERSION),
        ("1.9.0", SERVER_VERSION),
    }:
        raise HookError("model_mcp_contract_identity_invalid")
    session = facade.get("session_admission")
    if not isinstance(session, dict):
        raise HookError("model_mcp_session_capabilities_invalid")
    presentation = _require_exact_keys(
        session.get("context_presentation"),
        {"default_protocol", "supported_protocols", "legacy_fixed_selector"},
        "model_mcp_context_capability_shape_invalid",
    )
    if (
        presentation.get("default_protocol") != "integrity-client-memory-mcp/v3/context-admission/v2"
        or presentation.get("supported_protocols")
        != [
            "integrity-client-memory-mcp/v3/context-admission/v2",
            "integrity-client-memory-mcp/v3/context-admission/v1",
        ]
        or presentation.get("legacy_fixed_selector") != "explicit-limit"
    ):
        raise HookError("model_mcp_context_capability_invalid")
    if identity == ("1.9.0", SERVER_VERSION):
        validate_authority_contract(capabilities.get("authority_contract"), "not-evaluated")
    return requested_protocol


def validate_architecture_presentation(envelope: object, mind_receipt: dict[str, Any]) -> bool:
    if not isinstance(envelope, dict):
        raise HookError("model_mcp_architecture_envelope_invalid")
    protocol = envelope.get("protocol")
    if protocol == "integrity-client-memory-mcp/v3/architecture-unavailable/v1":
        _require_exact_keys(
            envelope,
            {
                "protocol",
                "outcome",
                "failure_layer",
                "reason_digest",
                "canonical_writes",
                "production_authority",
            },
            "model_mcp_architecture_unavailable_shape_invalid",
        )
        if (
            envelope.get("outcome") != "unavailable"
            or envelope.get("failure_layer") != "write-plane-admission"
            or not _is_digest(envelope.get("reason_digest"))
            or isinstance(envelope.get("canonical_writes"), bool)
            or envelope.get("canonical_writes") != 0
            or envelope.get("production_authority") is not False
        ):
            raise HookError("model_mcp_architecture_unavailable_invalid")
        return False
    if protocol != "integrity-client-memory-mcp/v3/architecture-capsule/v1":
        raise HookError("model_mcp_architecture_protocol_invalid")
    _require_exact_keys(
        envelope,
        {
            "protocol",
            "architecture",
            "custody",
            "source_architecture_digest",
            "complete",
            "home_record_count",
            "production_authority",
        },
        "model_mcp_architecture_capsule_shape_invalid",
    )
    if (
        not _is_digest(envelope.get("source_architecture_digest"))
        or envelope.get("complete") is not False
        or isinstance(envelope.get("home_record_count"), bool)
        or envelope.get("home_record_count") != 0
        or envelope.get("production_authority") is not False
    ):
        raise HookError("model_mcp_architecture_capsule_boundary_invalid")
    architecture = _require_exact_keys(
        envelope.get("architecture"),
        {"admission_id", "summary"},
        "model_mcp_architecture_shape_invalid",
    )
    summary_fields = {
        "mind_admission_receipt_id",
        "concept_recovery_digest",
        "coordination_digest",
        "coordination_stop_required",
        "route_disposition",
        "ledger_event_digest",
        "checkpoint_digest",
        "atlas_projection_digest",
        "connectome_compilation_id",
        "synapse_plan_id",
    }
    summary = _require_exact_keys(
        architecture.get("summary"),
        summary_fields,
        "model_mcp_architecture_summary_shape_invalid",
    )
    digest_fields = summary_fields - {"coordination_stop_required", "route_disposition"}
    if not _is_digest(architecture.get("admission_id")) or any(
        not _is_digest(summary.get(field)) for field in digest_fields
    ):
        raise HookError("model_mcp_architecture_digest_invalid")
    stop_required = summary.get("coordination_stop_required")
    if not isinstance(stop_required, bool):
        raise HookError("model_mcp_architecture_stop_invalid")
    if (
        summary.get("mind_admission_receipt_id") != mind_receipt.get("receipt_id")
        or summary.get("concept_recovery_digest") != mind_receipt.get("concept_recovery_digest")
        or summary.get("coordination_digest") != mind_receipt.get("coordination_digest")
        or stop_required != mind_receipt.get("coordination_stop_required")
        or summary.get("route_disposition") != ("stopped" if stop_required else "ready")
    ):
        raise HookError("model_mcp_architecture_mind_binding_invalid")
    custody = _require_exact_keys(
        envelope.get("custody"),
        {
            "receipt_id",
            "architecture_admission_id",
            "mind_admission_receipt_id",
            "write_status",
            "checkpoint",
            "home_record_count",
            "production_authority",
        },
        "model_mcp_architecture_custody_shape_invalid",
    )
    checkpoint = _require_exact_keys(
        custody.get("checkpoint"),
        {"checkpoint_id", "root_digest", "tree_size"},
        "model_mcp_architecture_checkpoint_shape_invalid",
    )
    tree_size = checkpoint.get("tree_size")
    if (
        not _is_digest(custody.get("receipt_id"))
        or custody.get("architecture_admission_id") != architecture.get("admission_id")
        or custody.get("mind_admission_receipt_id") != mind_receipt.get("receipt_id")
        or custody.get("write_status") not in {"recorded", "already-recorded"}
        or isinstance(custody.get("home_record_count"), bool)
        or custody.get("home_record_count") != 0
        or custody.get("production_authority") is not False
        or checkpoint.get("checkpoint_id") != "checkpoint:medor-architecture-custody"
        or not _is_digest(checkpoint.get("root_digest"))
        or isinstance(tree_size, bool)
        or not isinstance(tree_size, int)
        or tree_size < 1
    ):
        raise HookError("model_mcp_architecture_custody_invalid")
    return True


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")


def output_context(event: str, context: str) -> None:
    print(
        compact(
            {
                "continue": True,
                "hookSpecificOutput": {
                    "hookEventName": event,
                    "additionalContext": context,
                },
            }
        )
    )


def deny(reason: str) -> None:
    print(f"Integrity admission blocked this lifecycle step: {reason}", file=sys.stderr)
    raise SystemExit(2)


def payload_value(payload: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in payload:
            return payload[name]
    return default


def session_id(payload: dict[str, Any]) -> str:
    value = payload_value(payload, "session_id", "thread_id", default="")
    if not isinstance(value, str) or not value.strip():
        raise HookError("missing_session_id")
    return value.strip()


def turn_id(payload: dict[str, Any]) -> str:
    value = payload_value(payload, "turn_id", "turnId", default="")
    return value.strip() if isinstance(value, str) else ""


def prompt(payload: dict[str, Any]) -> str:
    value = payload_value(
        payload,
        "prompt",
        "user_prompt",
        "userPrompt",
        "message",
        "input",
        default="",
    )
    if not isinstance(value, str) or not value.strip():
        raise HookError("missing_user_prompt")
    if len(value.encode("utf-8")) > turn_envelope.MAX_PROMPT_BYTES:
        raise HookError("user_prompt_exceeds_256_kib")
    return value


def machine_id() -> str:
    value = re.sub(r"[^a-z0-9._-]", "-", socket.gethostname().lower())
    if not value:
        raise HookError("missing_machine_id")
    return f"machine:{value}"


def state_root() -> Path:
    root = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))).resolve()
    target = root / "integrity-memory" / "state"
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target.is_symlink():
        raise HookError("unsafe_state_root")
    try:
        target.chmod(0o700)
    except OSError:
        pass
    return target


def state_path(identity: str) -> Path:
    return state_root() / f"{sha256_text(identity)}.json"


@contextlib.contextmanager
def session_state_lock(identity: str):
    """Serialize hook state transactions, never the model-owned MCP request."""
    path = state_path(identity)
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        kernel.CreateMutexW.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.ReleaseMutex.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        name = "Local\\IntegrityClientState-" + sha256_text(str(path.absolute()).lower())
        handle = kernel.CreateMutexW(None, False, name)
        if not handle:
            raise HookError("session_state_lock_unavailable")
        acquired = False
        try:
            acquired = kernel.WaitForSingleObject(handle, 10000) in (0, 0x80)
            if not acquired:
                raise HookError("session_state_lock_timeout")
            yield
        finally:
            if acquired:
                kernel.ReleaseMutex(handle)
            kernel.CloseHandle(handle)
    else:
        import fcntl

        descriptor = os.open(
            path.with_suffix(".lock"),
            os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        deadline = time.monotonic() + 10
        try:
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise HookError("session_state_lock_timeout")
                    time.sleep(0.02)
            yield
        finally:
            os.close(descriptor)


def load_state(identity: str) -> dict[str, Any]:
    path = state_path(identity)
    if not path.exists():
        return {}
    if path.is_symlink() or not path.is_file():
        raise HookError("unsafe_state_file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise HookError("invalid_session_state")
    return value


def save_state(identity: str, state: dict[str, Any]) -> None:
    path = state_path(identity)
    state = dict(state)
    state["protocol"] = "integrity-memory/session-state/v1"
    state["session_hash"] = sha256_text(identity)
    temporary = path.with_name(f".state-{uuid.uuid4().hex}.tmp")
    try:
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(compact(state) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


class McpClient:
    def __init__(self) -> None:
        completed = subprocess.run(
            ["codex", "mcp", "get", "integrity_client_memory", "--json"],
            check=False,
            capture_output=True,
            text=True,
            timeout=remaining_lifecycle_seconds(15),
        )
        if completed.returncode != 0:
            raise HookError("mcp_registration_unavailable")
        entry = json.loads(completed.stdout)
        transport = entry.get("transport")
        if not isinstance(transport, dict) or transport.get("type") != "stdio":
            raise HookError("transport_type_mismatch")
        command = transport.get("command")
        arguments = transport.get("args", [])
        environment = transport.get("env") or {}
        if (
            not isinstance(command, str)
            or not isinstance(arguments, list)
            or not all(isinstance(item, str) for item in arguments)
            or not isinstance(environment, dict)
        ):
            raise HookError("invalid_mcp_transport")
        child_environment = dict(os.environ)
        child_environment.update({str(key): str(value) for key, value in environment.items()})
        self.process = subprocess.Popen(
            [command, *arguments],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env=child_environment,
            cwd=transport.get("cwd") or None,
        )
        self.next_id = 1
        try:
            self._initialize_transport()
        except Exception:
            self.close()
            raise

    def _initialize_transport(self) -> None:
        initialized = self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "integrity-client-linux-hook", "version": HOOK_VERSION},
            },
        )
        server = initialized.get("serverInfo")
        if (
            not isinstance(server, dict)
            or server.get("name") != SERVER_NAME
            or server.get("version")
            not in {
                BROKER_SERVER_VERSION,
                "1.4.0",
                ROLLOUT_LEGACY_SERVER_VERSION,
                LEGACY_SERVER_VERSION,
                OLDER_SERVER_VERSION,
                PREVIOUS_SERVER_VERSION,
                SERVER_VERSION,
            }
            or set(server) != {"name", "version"}
        ):
            raise HookError("server_identity_mismatch")
        self.notify("notifications/initialized", {})
        listed = self.request("tools/list", {})
        tools = listed.get("tools")
        server_version = server.get("version")
        expected_tools = (
            EXPECTED_TOOLS
            if server_version in {BROKER_SERVER_VERSION, "1.4.0"}
            else LEGACY_EXPECTED_TOOLS
            if server_version in {ROLLOUT_LEGACY_SERVER_VERSION, LEGACY_SERVER_VERSION}
            else PREVIOUS_EXPECTED_TOOLS
            if server_version == OLDER_SERVER_VERSION
            else DIRECT_CURRENT_EXPECTED_TOOLS
        )
        if not isinstance(tools, list) or [item.get("name") for item in tools] != expected_tools:
            raise HookError("tool_contract_mismatch")

    def _send(self, value: dict[str, Any]) -> None:
        if self.process.stdin is None:
            raise HookError("connector_input_closed")
        try:
            self.process.stdin.write(compact(value) + "\n")
            self.process.stdin.flush()
        except (BrokenPipeError, ConnectionError) as exc:
            raise HookTransportError("connector_input_lost") from exc

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        if self.process.stdout is None:
            raise HookError("connector_output_closed")
        ready, _, _ = select.select(
            [self.process.stdout], [], [], remaining_lifecycle_seconds(35)
        )
        if not ready:
            raise HookTransportError("response_timeout")
        line = self.process.stdout.readline()
        if not line:
            raise HookTransportError("response_stream_closed")
        response = json.loads(line)
        if response.get("id") != request_id or response.get("error") is not None:
            raise HookError("json_rpc_error")
        result = response.get("result")
        if not isinstance(result, dict):
            raise HookError("invalid_rpc_result")
        return result

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError") is True:
            raise tool_failure(name, result)
        content = result.get("content")
        if (
            not isinstance(content, list)
            or len(content) != 1
            or not isinstance(content[0], dict)
            or content[0].get("type") != "text"
        ):
            raise HookError("invalid_tool_content")
        value = json.loads(content[0].get("text", ""))
        if not isinstance(value, dict):
            raise HookError("invalid_tool_value")
        return value

    def close(self) -> None:
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except OSError:
                pass
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2)


def lifecycle_call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    global LIFECYCLE_DEADLINE
    previous_deadline = LIFECYCLE_DEADLINE
    if previous_deadline is None:
        LIFECYCLE_DEADLINE = time.monotonic() + LIFECYCLE_BUDGET_SECONDS
    client = None
    try:
        client = McpClient()
        return client.call(name, arguments)
    finally:
        if client is not None:
            client.close()
        LIFECYCLE_DEADLINE = previous_deadline


def tool_name(payload: dict[str, Any]) -> str:
    value = payload.get("tool_name", "")
    return value if isinstance(value, str) else ""


def tool_input(payload: dict[str, Any]) -> dict[str, Any]:
    value = payload.get("tool_input", {})
    if isinstance(value, str):
        value = json.loads(value)
    return value if isinstance(value, dict) else {}


def is_substantive_action(payload: dict[str, Any]) -> bool:
    """Treat any non-Integrity tool as work while keeping memory recovery available."""

    name = tool_name(payload).strip()
    return bool(name) and INTEGRITY_TOOL_RE.search(name) is None and not re.search(
        r"(?i)(?:^|__|codex_app)set_thread_title$", name
    )


def validate_append_tool_input(payload: dict[str, Any]) -> None:
    value = tool_input(payload)
    allowed = {"event_uid", "kind", "summary", "details", "tags", "authority_decision", "context_admission_id"}
    if set(value) - allowed:
        raise ValueError("append arguments contain unknown fields")
    # The canonical MCP verifies equality with its current admitted context.
    # Mirror the required wire field here without replacing that authority.
    if not _is_digest(value.get("context_admission_id")):
        raise ValueError("context_admission_id must be a sha256 digest")
    event_uid = value.get("event_uid")
    if not isinstance(event_uid, str) or EVENT_UID_RE.fullmatch(event_uid) is None:
        raise ValueError("event_uid must match the bounded immutable client: identity")
    if value.get("kind") not in {"concept", "task", "thought"}:
        raise ValueError("kind must be one of: concept, task, thought")
    summary = value.get("summary")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 2_000:
        raise ValueError("summary must contain 1 to 2000 characters")
    details = value.get("details", {})
    if not isinstance(details, dict):
        raise TypeError("details must be an object")
    tags = value.get("tags", [])
    if (
        not isinstance(tags, list)
        or len(tags) > 20
        or not all(isinstance(tag, str) and 1 <= len(tag.strip()) <= 80 for tag in tags)
    ):
        raise ValueError("tags must be a bounded string array")
    authority = value.get("authority_decision")
    if "authority_decision" in value and not isinstance(authority, dict):
        raise TypeError("authority_decision must be an object")


def validate_context_presentation(
    context: dict[str, Any], expected_protocol: str
) -> dict[str, Any] | None:
    protocol = context.get("protocol")
    if protocol != expected_protocol:
        raise HookError("model_mcp_context_presentation_mismatch")
    if protocol.endswith("/context-admission/v1"):
        return None
    if protocol != "integrity-client-memory-mcp/v3/context-admission/v2":
        raise HookError("model_mcp_context_protocol_invalid")
    if context.get("presentation_mode") != "adaptive":
        raise HookError("model_mcp_context_mode_invalid")
    mind_envelope = context.get("mind")
    if not isinstance(mind_envelope, dict):
        raise HookError("model_mcp_mind_envelope_invalid")
    admission = mind_envelope.get("admission_receipt")
    capsule = mind_envelope.get("mind")
    selection = mind_envelope.get("selection_receipt")
    if not all(isinstance(value, dict) for value in (admission, capsule, selection)):
        raise HookError("model_mcp_context_selection_missing")
    assert isinstance(admission, dict)
    assert isinstance(capsule, dict)
    assert isinstance(selection, dict)
    if capsule.get("protocol") != "integrity-client-memory-mcp/v3/context-capsule/v1":
        raise HookError("model_mcp_context_capsule_protocol_invalid")
    if capsule.get("memory_source") != "canonical-seed-action-log":
        raise HookError("model_mcp_context_capsule_source_invalid")
    if capsule.get("home_record_count") != 0 or capsule.get("production_authority") is not False:
        raise HookError("model_mcp_context_capsule_boundary_invalid")
    source_projection = capsule.get("source_projection")
    if not isinstance(source_projection, dict) or source_projection.get("complete") is not False:
        raise HookError("model_mcp_context_source_projection_invalid")
    projection_digest = admission.get("projection_digest")
    if not isinstance(projection_digest, str) or DIGEST_RE.fullmatch(projection_digest) is None:
        raise HookError("model_mcp_projection_digest_invalid")
    if source_projection.get("projection_digest") != projection_digest:
        raise HookError("model_mcp_context_source_projection_mismatch")
    if (
        selection.get("protocol") != ("integrity-client-memory-mcp/v3/adaptive-context-selection/v1")
        or selection.get("mode") != "adaptive"
    ):
        raise HookError("model_mcp_context_selection_protocol_invalid")
    if selection.get("policy_version") != "adaptive-context-v1":
        raise HookError("model_mcp_context_selection_policy_invalid")
    if selection.get("stop_reason") not in {
        "bounded-projection-complete",
        "candidate-cap-reached",
        "byte-budget-exhausted",
    }:
        raise HookError("model_mcp_context_selection_stop_reason_invalid")
    if selection.get("truncated") is not True or not isinstance(
        selection.get("candidates_truncated"), bool
    ):
        raise HookError("model_mcp_context_selection_truncation_invalid")
    if selection.get("source_projection_digest") != projection_digest:
        raise HookError("model_mcp_context_selection_source_mismatch")
    if (
        selection.get("home_record_count") != 0
        or selection.get("production_authority") is not False
    ):
        raise HookError("model_mcp_context_selection_boundary_invalid")
    max_context_bytes = selection.get("max_context_bytes")
    capsule_bytes = selection.get("capsule_bytes")
    max_candidates = selection.get("max_candidates")
    candidate_cap = selection.get("transport_candidate_cap")
    integer_values = (max_context_bytes, capsule_bytes, max_candidates, candidate_cap)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in integer_values):
        raise HookError("model_mcp_context_selection_bounds_invalid")
    assert isinstance(max_context_bytes, int)
    assert isinstance(capsule_bytes, int)
    assert isinstance(max_candidates, int)
    assert isinstance(candidate_cap, int)
    if not (
        8_192 <= max_context_bytes <= 262_144
        and 1 <= capsule_bytes <= max_context_bytes
        and 1 <= candidate_cap <= max_candidates <= 50
    ):
        raise HookError("model_mcp_context_selection_bounds_invalid")
    for field in ("source_projection_bytes", "intent_term_count"):
        value = selection.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise HookError("model_mcp_context_selection_counts_invalid")
    if selection["source_projection_bytes"] < 1:
        raise HookError("model_mcp_context_selection_counts_invalid")
    if not isinstance(selection.get("available_candidates"), dict) or not isinstance(
        selection.get("selected_candidates"), dict
    ):
        raise HookError("model_mcp_context_selection_counts_invalid")
    encoded_capsule = compact(capsule).encode("utf-8")
    if len(encoded_capsule) != capsule_bytes:
        raise HookError("model_mcp_context_capsule_size_mismatch")
    if selection.get("capsule_digest") != digest_object(capsule):
        raise HookError("model_mcp_context_capsule_digest_mismatch")
    receipt_id = selection.get("receipt_id")
    if not isinstance(receipt_id, str) or DIGEST_RE.fullmatch(receipt_id) is None:
        raise HookError("model_mcp_context_selection_receipt_invalid")
    receipt_core = dict(selection)
    receipt_core.pop("receipt_id", None)
    if receipt_id != digest_object(receipt_core):
        raise HookError("model_mcp_context_selection_receipt_mismatch")
    validate_architecture_presentation(context.get("architecture"), admission)
    identity = (
        context["capabilities"].get("contract_version"),
        context["capabilities"].get("facade", {}).get("server_version"),
    )
    if identity == ("1.9.0", SERVER_VERSION):
        expected_status = (
            "stopped" if admission.get("coordination_stop_required") is True else "ready"
        )
        validate_authority_contract(
            context.get("snapshot", {}).get("authority_contract"), "not-evaluated"
        )
        validate_authority_contract(context.get("authority_contract"), expected_status)
    return selection


def semantic_cadence(state: dict[str, Any], *, now: dt.datetime | None = None) -> dict[str, Any]:
    """Return the bounded cross-turn semantic checkpoint state."""

    if state.get("semantic_checkpoint_open") is not True:
        return {"open": False, "due": False, "age_seconds": 0, "actions": 0}
    actions = state.get("semantic_checkpoint_actions")
    started_value = state.get("semantic_checkpoint_started_utc")
    if (
        isinstance(actions, bool)
        or not isinstance(actions, int)
        or actions < 1
        or not isinstance(started_value, str)
        or not started_value
    ):
        return {
            "open": True,
            "due": True,
            "age_seconds": SEMANTIC_CADENCE_MAX_AGE_SECONDS,
            "actions": max(1, actions) if isinstance(actions, int) else 1,
            "state_invalid": True,
        }
    try:
        started = dt.datetime.fromisoformat(started_value)
    except ValueError:
        started = None
    current = now or dt.datetime.now(dt.UTC)
    if started is None or started.tzinfo is None or current.tzinfo is None:
        return {
            "open": True,
            "due": True,
            "age_seconds": SEMANTIC_CADENCE_MAX_AGE_SECONDS,
            "actions": actions,
            "state_invalid": True,
        }
    age_seconds = max(
        0,
        int((current.astimezone(dt.UTC) - started.astimezone(dt.UTC)).total_seconds()),
    )
    timed_work = (
        state.get("semantic_checkpoint_mutation_seen") is True
        or actions >= SEMANTIC_CADENCE_MIN_TIMED_ACTIONS
    )
    return {
        "open": True,
        "due": actions >= SEMANTIC_CADENCE_MAX_ACTIONS
        or (timed_work and age_seconds >= SEMANTIC_CADENCE_MAX_AGE_SECONDS),
        "age_seconds": age_seconds,
        "actions": actions,
        "mutation_seen": state.get("semantic_checkpoint_mutation_seen") is True,
        "state_invalid": False,
    }


def mark_semantic_progress(state: dict[str, Any], *, tool: str, mutation: bool) -> dict[str, Any]:
    if state.get("semantic_checkpoint_open") is not True:
        state["semantic_checkpoint_open"] = True
        state["semantic_checkpoint_started_utc"] = utc_now()
        state["semantic_checkpoint_actions"] = 0
        state["semantic_checkpoint_mutation_seen"] = False
    actions = state.get("semantic_checkpoint_actions", 0)
    if isinstance(actions, bool) or not isinstance(actions, int) or actions < 0:
        actions = SEMANTIC_CADENCE_MAX_ACTIONS
    state["semantic_checkpoint_actions"] = min(actions + 1, 1_000_000)
    state["semantic_checkpoint_mutation_seen"] = bool(
        state.get("semantic_checkpoint_mutation_seen") is True or mutation
    )
    state["semantic_checkpoint_last_tool"] = tool[:256]
    return semantic_cadence(state)


def close_semantic_checkpoint(state: dict[str, Any], *, event_id: object) -> None:
    state["semantic_checkpoint_open"] = False
    state["semantic_checkpoint_actions"] = 0
    state["semantic_checkpoint_mutation_seen"] = False
    state["semantic_checkpoint_event_id"] = event_id
    state["semantic_checkpoint_closed_utc"] = utc_now()
    state.pop("semantic_checkpoint_started_utc", None)
    state.pop("semantic_checkpoint_last_tool", None)
    state.pop("semantic_checkpoint_notice_key", None)


def new_semantic_notice(state: dict[str, Any]) -> bool:
    """Emit once per checkpoint/disposition, not once per tool or counter tick."""
    if not semantic_cadence(state)["due"]:
        return False
    disposition = (
        "ready" if append_ready(state) else
        "unknown" if state.get("append_outcome") == "unknown-outcome" else
        "spent" if state.get("append_attempted") is True else "unavailable"
    )
    key = f"{state.get('semantic_checkpoint_started_utc', '')}:{disposition}"
    if state.get("semantic_checkpoint_notice_key") == key:
        return False
    state["semantic_checkpoint_notice_key"] = key
    return True


def semantic_context(state: dict[str, Any]) -> str:
    cadence = semantic_cadence(state)
    if not cadence["open"]:
        return (
            "SEMANTIC CADENCE CLEAR: event-per-turn=false; create a Seed event only for "
            "a durable decision, result or checkpoint."
        )
    disposition = "OVERDUE" if cadence["due"] else "OPEN"
    if cadence["due"] and append_ready(state):
        instruction = (
            "ADVISORY ONLY: preserve progress in the existing local checkpoint; "
            "cadence does not require a canonical append. Reserve the one append attempt "
            "for a durable result. Mandatory prior ChangeIntent remains separately required."
        )
    elif cadence["due"] and state.get("append_outcome") == "unknown-outcome":
        instruction = (
            "ADVISORY ONLY: prior append outcome is unknown; continue work and "
            "preserve the checkpoint debt. Do not retry; reconcile event_uid."
        )
    elif cadence["due"] and state.get("append_attempted") is True:
        instruction = (
            "ADVISORY ONLY: the current turn already used its one append attempt; "
            "continue work and preserve the checkpoint debt for a later admitted turn. "
            "Do not attempt another append in this turn."
        )
    elif cadence["due"]:
        instruction = (
            "ADVISORY ONLY: canonical append readiness is unavailable; continue work, "
            "preserve the checkpoint debt, and append after a live/current registration exists."
        )
    else:
        instruction = (
            "Continue normally; keep intermediate progress locally and append a durable result. "
            "Cadence alone does not require a canonical write."
        )
    return (
        f"SEMANTIC CHECKPOINT {disposition}: age_seconds={cadence['age_seconds']} "
        f"actions={cadence['actions']} event_per_turn=false. {instruction}"
    )


def find_document(value: Any, predicate: Any, depth: int = 0) -> dict[str, Any] | None:
    if depth > 24:
        return None
    if isinstance(value, dict):
        if predicate(value):
            return value
        for child in value.values():
            found = find_document(child, predicate, depth + 1)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_document(child, predicate, depth + 1)
            if found is not None:
                return found
    elif isinstance(value, str) and value.lstrip().startswith(("{", "[")):
        try:
            return find_document(json.loads(value), predicate, depth + 1)
        except json.JSONDecodeError:
            return None
    return None


def next_turn_memory_generation(state: dict[str, Any]) -> int:
    value = state.get("turn_memory_generation", 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        value = 0
    return value + 1


def clear_turn_memory_registration(state: dict[str, Any]) -> None:
    for name in (
        "turn_memory_registration_id",
        "turn_memory_namespace_fingerprint",
        "turn_memory_opened_utc",
        "turn_memory_terminal_receipt_id",
        "turn_memory_gap_receipt_id",
        "turn_memory_failure",
    ):
        state.pop(name, None)


def preserve_turn_memory_recovery_handle(state: dict[str, Any]) -> None:
    """Retain bounded identities whose canonical open outcome is unresolved."""

    handle = state.get("turn_memory_unresolved_handle")
    if not isinstance(handle, dict):
        return
    handles = state.get("turn_memory_recovery_handles")
    if not isinstance(handles, list):
        handles = []
    identity = digest_object(handle)
    retained = [item for item in handles if isinstance(item, dict)]
    if not any(digest_object(item) == identity for item in retained):
        retained.append(handle)
    state["turn_memory_recovery_handles"] = retained[-8:]
    state.pop("turn_memory_unresolved_handle", None)


def append_ready(state: dict[str, Any]) -> bool:
    return bool(
        state.get("model_mcp_admission_status") == "ready"
        and state.get("write_plane_status") == "ready"
        and state.get("coordination_stop_required") is not True
        and state.get("turn_memory_status") == "open"
        and state.get("turn_memory_lease") == "live"
        and state.get("turn_memory_queue") == "current"
        and _is_digest(state.get("turn_memory_registration_id"))
        # A mandatory checkpoint must be satisfiable under the one-attempt guard.
        and state.get("append_attempted") is not True
        and state.get("append_outcome") != "unknown-outcome"
    )


def detach_turn_memory(state: dict[str, Any], reason: object) -> None:
    clear_turn_memory_registration(state)
    state.update(
        {
            "admission_status": "detached",
            "model_mcp_admission_status": "invalid",
            "turn_memory_status": "detached",
            "turn_memory_lease": "expired",
            "turn_memory_queue": "recovery",
            "turn_memory_lease_updated_utc": utc_now(),
            "turn_memory_failure": str(reason)[:300],
            "coordination_stop_required": False,
            "route_disposition": "detached",
            "write_plane_status": "unavailable",
        }
    )


def open_admitted_turn_memory(identity: str, state: dict[str, Any]) -> dict[str, Any]:
    global LIFECYCLE_DEADLINE
    current_turn = state.get("turn_memory_intent_id", state.get("turn_id"))
    prompt_sha256 = state.get("prompt_sha256")
    if not isinstance(current_turn, str) or not current_turn:
        raise HookError("turn_registration_turn_missing")
    if not isinstance(prompt_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", prompt_sha256):
        raise HookError("turn_registration_prompt_missing")
    machine = re.sub(r"[^a-z0-9._-]", "-", socket.gethostname().lower())
    arguments = {
        "machine_id": f"machine:{machine}",
        "thread_id": identity,
        "turn_id": current_turn,
        "prompt_sha256": prompt_sha256,
    }
    state["turn_memory_unresolved_handle"] = {
        **arguments,
        "generation": state.get("turn_memory_generation"),
    }
    LIFECYCLE_DEADLINE = time.monotonic() + LIFECYCLE_BUDGET_SECONDS
    try:
        try:
            opened = lifecycle_call("integrity_turn_memory_open", arguments)
        except HookTransportError:
            remaining_lifecycle_seconds(1)
            opened = lifecycle_call("integrity_turn_memory_open", arguments)
    finally:
        LIFECYCLE_DEADLINE = None
    receipt = opened.get("receipt")
    if not isinstance(receipt, dict):
        raise HookError("turn_registration_receipt_missing")
    if (
        receipt.get("terminal_required") is not True
        or receipt.get("production_authority") is not False
        or receipt.get("prompt_sha256") != prompt_sha256
        or receipt.get("identity") != {
            key: arguments[key] for key in ("machine_id", "thread_id", "turn_id")
        }
        or not _is_digest(receipt.get("receipt_id"))
        or not _is_digest(receipt.get("namespace_fingerprint"))
    ):
        raise HookError("turn_registration_invalid")
    state.pop("turn_memory_unresolved_handle", None)
    return receipt


def handle_prompt(event: str, payload: dict[str, Any], identity: str) -> None:
    intent = (
        prompt(payload)
        if event == "UserPromptSubmit"
        else "Initialize this fresh subagent with current canonical project coordination and safety context."
    )
    current_turn = turn_id(payload) or f"turn:{uuid.uuid4()}"
    state = load_state(identity)
    generation = next_turn_memory_generation(state)
    prior_turn_ref = state.get("turn_ref")
    if isinstance(prior_turn_ref, str):
        try:
            turn_envelope.retire(prior_turn_ref, preserve_claimed=True)
        except (OSError, turn_envelope.TurnEnvelopeError):
            pass
    envelope = turn_envelope.stage(
        intent,
        machine_id=machine_id(),
        thread_id=identity,
        turn_id=current_turn,
        generation=generation,
    )
    preserve_turn_memory_recovery_handle(state)
    clear_turn_memory_registration(state)
    state.update(
        {
            "admission_status": "provisional",
            "turn_id": current_turn,
            # The native turn can contain several owner intents (steering).
            # The staged/authenticated envelope pins retries to this exact intent.
            "turn_memory_intent_id": "intent:" + envelope["turn_ref_digest"][7:],
            "prompt_sha256": sha256_text(intent),
            "prompt_bytes": envelope["prompt_bytes"],
            "prompt_segment_count": envelope["segment_count"],
            "prompt_coverage": envelope["prompt_coverage"],
            "prompt_truncation": False,
            "turn_ref": envelope["turn_ref"],
            "turn_ref_digest": envelope["turn_ref_digest"],
            "turn_ref_expires_utc": envelope["expires_utc"],
            "coordination_stop_required": False,
            "route_disposition": "pending",
            "write_plane_status": "pending",
            "model_mcp_admission_status": "required",
            "model_mcp_admission_attempted": False,
            "model_mcp_read_seal_retry_count": 0,
            "model_mcp_transport_retry_count": 0,
            "production_authority": False,
            "home_record_count": 0,
            "turn_memory_generation": generation,
            "turn_memory_status": "provisional",
            "turn_memory_lease": "provisional",
            "turn_memory_queue": "current",
            "turn_memory_lease_updated_utc": utc_now(),
        }
    )
    state.pop("model_mcp_expected_context_protocol", None)
    state.pop("model_mcp_selection_receipt_id", None)
    state.pop("retry_disposition", None)
    if state.get("append_outcome") != "unknown-outcome":
        state["append_outcome"] = "not-started"
        state["append_attempted"] = False
        state["automatic_retry_allowed"] = True
    save_state(identity, state)
    output_context(
        event,
        f"INTEGRITY client READ PLANE PENDING v3\n"
        "No hook-owned Seed admission/snapshot process was opened. No canonical Turn Memory "
        "registration was opened.\n"
        "Invoke integrity_context_admission_current_turn exactly once in the model-owned MCP "
        f"session with turn_ref={envelope['turn_ref']!r} and omit limit for adaptive selection. "
        "Do not repeat or reconstruct the prompt in tool arguments.\n"
        "Write/action blockers never make the returned read-only Seed snapshot unavailable.\n"
        "MEMORY AUTHORITY: provider=memory-only; target_action=not-evaluated; "
        "provider boundary is not a target denial. coordination scope=integrity-memory-route; "
        "Seed append and external targets are unaffected.\n"
        f"Home=0 canonical_writes=0\nTURN MEMORY PROVISIONAL generation={generation} "
        "lease=provisional queue=current. A canonical registration is created only after the "
        "context admission receipt validates.\n"
        + semantic_context(state),
    )


def handle_pre_tool(payload: dict[str, Any], identity: str, state: dict[str, Any]) -> None:
    name = tool_name(payload)
    arguments = tool_input(payload)
    encoded = compact(arguments)
    if re.search(r"(?is)\bdelete\s+from\s+.{0,64}\bevents\b", encoded):
        deny("canonical Action Log events are immutable")
    retry_pending = state.get("retry_disposition") in {
        "exact-envelope-after-supported-read-seal",
        "exact-envelope-after-pre-send-transport",
    }
    if (
        retry_pending
        and INTEGRITY_TOOL_RE.search(name)
        and not CURRENT_CONTEXT_TOOL_RE.search(name)
    ):
        deny("only the identical current-turn admission is allowed while retry is pending")
    if CONTEXT_TOOL_RE.search(name):
        if state.get("model_mcp_admission_attempted") is True:
            deny("model MCP context admission is single-shot for the current turn")
        if CURRENT_CONTEXT_TOOL_RE.search(name):
            turn_ref = arguments.get("turn_ref")
            if not isinstance(turn_ref, str) or turn_ref != state.get("turn_ref"):
                deny("model MCP turn_ref does not match the current prompt envelope")
            try:
                turn_envelope.arm(
                    turn_ref,
                    machine_id=machine_id(),
                    thread_id=identity,
                    turn_id=str(state.get("turn_id", "")),
                    generation=int(state.get("turn_memory_generation", 0)),
                    prompt_sha256=str(state.get("prompt_sha256", "")),
                )
            except (OSError, ValueError, turn_envelope.TurnEnvelopeError) as exc:
                deny(f"turn envelope cannot be armed: {exc}")
            if retry_pending:
                state.pop("retry_disposition", None)
        else:
            intent = arguments.get("intent")
            if not isinstance(intent, str) or sha256_text(intent) != state.get("prompt_sha256"):
                deny("model MCP intent does not match the current prompt")
        state["model_mcp_admission_attempted"] = True
        state["model_mcp_admission_status"] = "pending"
        state["model_mcp_expected_context_protocol"] = (
            "integrity-client-memory-mcp/v3/context-admission/v1"
            if "limit" in arguments
            else "integrity-client-memory-mcp/v3/context-admission/v2"
        )
        save_state(identity, state)
        return
    if INTEGRITY_TOOL_RE.search(name) and not APPEND_TOOL_RE.search(name):
        return
    if APPEND_TOOL_RE.search(name):
        try:
            validate_append_tool_input(payload)
        except (TypeError, ValueError) as exc:
            deny(str(exc))
        if state.get("model_mcp_admission_status") != "ready":
            deny("model_mcp_context_admission_required")
        if (
            state.get("turn_memory_status") != "open"
            or state.get("turn_memory_lease") != "live"
            or state.get("turn_memory_queue") != "current"
            or not _is_digest(state.get("turn_memory_registration_id"))
        ):
            deny("turn_memory_registration_required")
        if state.get("append_outcome") == "unknown-outcome":
            deny("prior append outcome is unknown; automatic retry is forbidden")
        if state.get("append_attempted") is True:
            deny("only one append attempt is allowed in the current turn")
        state.update(
            {
                "append_attempted": True,
                "append_outcome": "started",
                "unresolved_mutation": True,
                "automatic_retry_allowed": False,
            }
        )
        save_state(identity, state)
        return
    # Cadence tracks local progress; it must not spend the sole append attempt
    # before a terminal result exists. Admission/append/unknown-outcome guards
    # above and target-specific prior authority are unchanged.


def handle_post_tool(
    event: str, payload: dict[str, Any], identity: str, state: dict[str, Any]
) -> None:
    name = tool_name(payload)
    response = payload.get("tool_response", {})
    if CONTEXT_TOOL_RE.search(name):
        completed = tool_input(payload)
        if CURRENT_CONTEXT_TOOL_RE.search(name):
            superseded = bool(completed.get("turn_ref")) and (
                completed["turn_ref"] != state.get("turn_ref")
            )
        else:
            superseded = bool(completed.get("intent")) and (
                sha256_text(str(completed["intent"])) != state.get("prompt_sha256")
            )
        if superseded:
            output_context(
                event,
                "INTEGRITY SUPERSEDED ADMISSION: late response belongs to an earlier intent; "
                "current admission state is unchanged. Do not bind that receipt to the current intent.",
            )
            return
        context = find_document(
            response,
            lambda item: any(
                str(item.get("protocol", "")).endswith(suffix)
                for suffix in ("/context-admission/v1", "/context-admission/v2")
            ),
        )
        retryable_wal = find_document(
            response,
            lambda item: (
                item.get("reason_code") == "seed_catalog_checkpoint_required"
                and item.get("automatic_retry_allowed") is True
                and item.get("canonical_writes") == 0
                and item.get("retry_disposition")
                == "exact-envelope-after-supported-read-seal"
            ),
        )
        retryable_transport = find_document(
            response,
            lambda item: (
                item.get("protocol") == "integrity-client/turn-broker-denial/v1"
                and item.get("failure_layer") == "broker-upstream"
                and item.get("request_sent") is False
                and item.get("automatic_retry_allowed") is True
                and item.get("canonical_writes") == 0
                and item.get("retry_disposition")
                == "exact-envelope-after-pre-send-transport"
            ),
        )
        if (
            context is None
            and CURRENT_CONTEXT_TOOL_RE.search(name)
            and retryable_wal is not None
            and int(state.get("model_mcp_read_seal_retry_count", 0)) < 1
        ):
            state["model_mcp_read_seal_retry_count"] = 1
            state["model_mcp_admission_attempted"] = False
            state["model_mcp_admission_status"] = "required"
            state["automatic_retry_allowed"] = True
            state["retry_disposition"] = "exact-envelope-after-supported-read-seal"
            save_state(identity, state)
            output_context(
                event,
                "INTEGRITY READ PLANE RETRYABLE: the exact current turn_ref was not consumed. "
                "After the Seed owner completes the supported read-seal recovery, retry "
                "integrity_context_admission_current_turn once with the identical turn_ref. "
                "No other tool is admitted before that retry.",
            )
            return
        if (
            context is None
            and CURRENT_CONTEXT_TOOL_RE.search(name)
            and retryable_transport is not None
            and int(state.get("model_mcp_transport_retry_count", 0)) < 1
        ):
            try:
                turn_envelope.arm(
                    str(state.get("turn_ref", "")),
                    machine_id=machine_id(),
                    thread_id=identity,
                    turn_id=str(state.get("turn_id", "")),
                    generation=int(state.get("turn_memory_generation", 0)),
                    prompt_sha256=str(state.get("prompt_sha256", "")),
                )
            except (OSError, ValueError, turn_envelope.TurnEnvelopeError):
                retryable_transport = None
            else:
                state["model_mcp_transport_retry_count"] = 1
                state["model_mcp_admission_attempted"] = False
                state["model_mcp_admission_status"] = "required"
                state["automatic_retry_allowed"] = True
                state["retry_disposition"] = "exact-envelope-after-pre-send-transport"
                save_state(identity, state)
                output_context(
                    event,
                    "INTEGRITY TRANSPORT RETRYABLE: no admission request bytes were sent and "
                    "the exact current turn_ref remains armed. Retry "
                    "integrity_context_admission_current_turn once with the identical turn_ref. "
                    "No other Integrity tool is admitted before that retry.",
                )
                return
        try:
            if context is None or context.get("production_authority") is not False:
                raise HookError("model_mcp_context_receipt_missing")
            if context.get("home_record_count") != 0 or context.get("canonical_writes") != 0:
                raise HookError("model_mcp_context_boundary_invalid")
            expected_protocol = state.get("model_mcp_expected_context_protocol")
            if not isinstance(expected_protocol, str):
                raise HookError("model_mcp_context_presentation_not_bound")
            negotiated_protocol = negotiated_context_protocol(context, expected_protocol)
            selection = validate_context_presentation(context, negotiated_protocol)
            if CURRENT_CONTEXT_TOOL_RE.search(name):
                binding = context.get("prompt_binding")
                if not isinstance(binding, dict):
                    raise HookError("model_mcp_prompt_binding_missing")
                expected_binding = {
                    "turn_ref_digest": state.get("turn_ref_digest"),
                    "prompt_sha256": state.get("prompt_sha256"),
                    "prompt_bytes": state.get("prompt_bytes"),
                    "segment_count": state.get("prompt_segment_count"),
                    "prompt_coverage": "text-only",
                    "truncation": False,
                }
                if any(binding.get(key) != value for key, value in expected_binding.items()):
                    raise HookError("model_mcp_prompt_binding_mismatch")
            snapshot = context["snapshot"]
            mind_receipt = context["mind"]["admission_receipt"]
        except (
            HookError,
            OSError,
            ValueError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
            subprocess.SubprocessError,
        ) as exc:
            detach_turn_memory(state, exc)
            save_state(identity, state)
            output_context(
                event,
                f"INTEGRITY READ PLANE RECEIPT INVALID: {exc}. TURN MEMORY DETACHED "
                "lease=expired queue=recovery; no validated canonical registration is bound "
                "to this intent. Report the canonical MCP infrastructure fault.",
            )
            return

        state.update(
            {
                "admission_status": "ready",
                "model_mcp_admission_status": "ready",
                "model_mcp_snapshot_id": snapshot["snapshot_id"],
                "model_mcp_mind_receipt_id": mind_receipt["receipt_id"],
                "event_count": snapshot["cursor"]["event_count"],
                "maximum_event_id": snapshot["cursor"]["maximum_event_id"],
                "coordination_stop_required": bool(
                    mind_receipt.get("coordination_stop_required", True)
                ),
                "production_authority": False,
                "home_record_count": 0,
                "model_mcp_negotiated_context_protocol": negotiated_protocol,
                "route_disposition": (
                    "stopped"
                    if mind_receipt.get("coordination_stop_required") is True
                    else "ready"
                ),
            }
        )
        state.pop("retry_disposition", None)
        if selection is not None:
            state["model_mcp_selection_receipt_id"] = selection["receipt_id"]
        architecture = context.get("architecture", {}).get("architecture")
        state["write_plane_status"] = "ready" if architecture else "unavailable"

        try:
            registration = open_admitted_turn_memory(identity, state)
        except (
            HookError,
            OSError,
            ValueError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
            subprocess.SubprocessError,
        ) as exc:
            preserve_turn_memory_recovery_handle(state)
            clear_turn_memory_registration(state)
            state.update(
                {
                    "turn_memory_status": "registration-unavailable",
                    "turn_memory_lease": "expired",
                    "turn_memory_queue": "recovery",
                    "turn_memory_lease_updated_utc": utc_now(),
                    "turn_memory_failure": str(exc)[:300],
                }
            )
            turn_memory_context = (
                f"TURN MEMORY REGISTRATION UNAVAILABLE (OUTCOME UNRESOLVED): {exc}. The canonical read plane "
                "remains ready; the exact open identity is retained in bounded recovery, "
                "no validated registration id is bound, and append remains gated."
            )
        else:
            state.update(
                {
                    "turn_memory_status": "open",
                    "turn_memory_lease": "live",
                    "turn_memory_queue": "current",
                    "turn_memory_registration_id": registration["receipt_id"],
                    "turn_memory_namespace_fingerprint": registration[
                        "namespace_fingerprint"
                    ],
                    "turn_memory_opened_utc": utc_now(),
                    "turn_memory_lease_updated_utc": utc_now(),
                }
            )
            state.pop("turn_memory_failure", None)
            turn_memory_context = (
                f"TURN MEMORY LIVE registration_id={registration['receipt_id']} "
                f"generation={state['turn_memory_generation']} lease=live queue=current."
            )
        save_state(identity, state)
        output_context(
            event,
            f"INTEGRITY CANONICAL READ PLANE READY: snapshot={state['model_mcp_snapshot_id']} "
            f"cursor={state['event_count']}/{state['maximum_event_id']} Home=0 "
            "canonical_writes=0. MEMORY AUTHORITY: provider=memory-only; "
            "target_action=not-evaluated; provider boundary is not a target denial; "
            "coordination scope=integrity-memory-route; Seed append and external targets "
            f"are unaffected. {turn_memory_context}",
        )
        return
    if APPEND_TOOL_RE.search(name):
        receipt = find_document(
            response,
            lambda item: str(item.get("protocol", "")).endswith("/append-receipt"),
        )
        if receipt is None:
            state["append_outcome"] = "unknown-outcome"
            state["unresolved_mutation"] = True
            save_state(identity, state)
            output_context(
                event,
                "INTEGRITY APPEND UNKNOWN-OUTCOME: automatic retry is forbidden; reconcile event_uid.",
            )
            return
        outcome = receipt.get("outcome")
        state["append_outcome"] = outcome
        state["append_event_id"] = receipt.get("event_id")
        state["append_event_uid"] = receipt.get("event_uid")
        state["append_request_sha256"] = receipt.get("request_sha256")
        state["unresolved_mutation"] = outcome not in {"created", "duplicate"}
        if outcome in {"created", "duplicate"}:
            close_semantic_checkpoint(state, event_id=receipt.get("event_id"))
        save_state(identity, state)
        output_context(
            event,
            f"INTEGRITY APPEND PASSIVE WITNESS: outcome={outcome} event_id={receipt.get('event_id')} "
            "automatic_retry_allowed=false.",
        )
        return
    mutation = bool(
        MEANINGFUL_TOOL_RE.search(name) or MUTATION_TEXT_RE.search(compact(tool_input(payload)))
    )
    if is_substantive_action(payload):
        if mutation:
            state["unresolved_mutation"] = True
        mark_semantic_progress(state, tool=name, mutation=mutation)
        notice = new_semantic_notice(state)
        save_state(identity, state)
        if notice:
            output_context(event, semantic_context(state))


def handle_stop(event: str, identity: str, state: dict[str, Any]) -> None:
    current_turn_ref = state.get("turn_ref")
    if isinstance(current_turn_ref, str):
        try:
            turn_envelope.retire(current_turn_ref, preserve_claimed=True)
        except (OSError, turn_envelope.TurnEnvelopeError):
            pass
    registration = state.get("turn_memory_registration_id")
    if isinstance(registration, str) and registration:
        try:
            coverage = lifecycle_call(
                "integrity_turn_memory_gap",
                {"registration_id": registration, "stage": "stop"},
            )
            terminal = coverage.get("terminal_receipt")
            if isinstance(terminal, dict):
                state["turn_memory_status"] = "closed"
                state["turn_memory_queue"] = "archive"
                state["turn_memory_terminal_receipt_id"] = terminal.get("receipt_id")
                context = (
                    f"TURN MEMORY TERMINAL RECEIPT VERIFIED: outcome={terminal.get('outcome')} "
                    f"receipt_id={terminal.get('receipt_id')}."
                )
            else:
                gap = coverage.get("receipt", {})
                state["turn_memory_status"] = "coverage-debt"
                state["turn_memory_queue"] = "recovery"
                state["turn_memory_gap_receipt_id"] = gap.get("receipt_id")
                context = (
                    "TURN MEMORY COVERAGE GAP RECORDED: terminal receipt is missing; "
                    f"gap_receipt_id={gap.get('receipt_id')}. Do not claim no-event."
                )
        except (
            HookError,
            OSError,
            ValueError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
            subprocess.SubprocessError,
        ) as exc:
            state["turn_memory_status"] = "coverage-unobservable"
            state["turn_memory_queue"] = "recovery"
            state["turn_memory_failure"] = str(exc)[:300]
            context = (
                f"TURN MEMORY COVERAGE UNOBSERVABLE: {exc}. Do not claim this turn is covered."
            )
        state["turn_memory_lease"] = "expired"
        state["turn_memory_lease_updated_utc"] = utc_now()
    elif state.get("turn_memory_status") == "provisional":
        state["turn_memory_lease"] = "expired"
        state["turn_memory_lease_updated_utc"] = utc_now()
        if state.get("model_mcp_admission_attempted") is True:
            state["turn_memory_status"] = "detached"
            state["turn_memory_queue"] = "recovery"
            context = (
                "TURN MEMORY ADMISSION DETACHED: the attempted context admission never "
                "produced a validated receipt; no canonical registration exists and this "
                "local generation is queued for recovery, not coverage debt."
            )
        else:
            state["turn_memory_status"] = "expired-provisional"
            state["turn_memory_queue"] = "archive"
            context = (
                "TURN MEMORY PROVISIONAL EXPIRED: context admission was never attempted, so "
                "no canonical registration or coverage debt exists; the local generation is archived."
            )
    elif state.get("turn_memory_status") == "detached":
        state["turn_memory_lease"] = "expired"
        state["turn_memory_queue"] = "recovery"
        state["turn_memory_lease_updated_utc"] = utc_now()
        context = (
            "TURN MEMORY DETACHED: no validated canonical registration exists; the local "
            "generation remains in recovery and is not coverage debt."
        )
    elif state.get("turn_memory_status") in {
        "registration-unavailable",
        "registration-unresolved",
    }:
        state["turn_memory_lease"] = "expired"
        state["turn_memory_queue"] = "recovery"
        state["turn_memory_lease_updated_utc"] = utc_now()
        context = (
            "TURN MEMORY REGISTRATION UNAVAILABLE: the canonical read plane was admitted, "
            "but no validated registration id is bound; recovery is required and no coverage "
            "gap can be recorded locally."
        )
    else:
        context = "TURN MEMORY COVERAGE UNOBSERVABLE: no canonical registration id."
    if state:
        save_state(identity, state)
    if state.get("append_outcome") == "unknown-outcome":
        context += "\nINTEGRITY APPEND UNKNOWN-OUTCOME: do not retry."
    elif state.get("unresolved_mutation") is True:
        context += "\nINTEGRITY ACTION-PLANE WARNING: meaningful mutation lacks verified closure."
    cadence = semantic_cadence(state)
    if cadence["open"]:
        context += "\n" + semantic_context(state)
    output_context(event, context)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--event",
        required=True,
        choices=(
            "SessionStart",
            "UserPromptSubmit",
            "PreToolUse",
            "PostToolUse",
            "SubagentStart",
            "Stop",
            "SubagentStop",
        ),
    )
    args = parser.parse_args()
    raw = sys.stdin.read()
    payload = json.loads(raw) if raw.strip() else {}
    if not isinstance(payload, dict):
        raise HookError("invalid_hook_payload")
    identity = session_id(payload)
    if args.event == "SessionStart":
        output_context(
            args.event,
            "INTEGRITY client SESSION PENDING INTENT ADMISSION. No Seed snapshot was opened at startup.",
        )
        return 0
    with session_state_lock(identity):
        if args.event in {"UserPromptSubmit", "SubagentStart"}:
            handle_prompt(args.event, payload, identity)
            return 0
        state = load_state(identity)
        if args.event == "PreToolUse":
            handle_pre_tool(payload, identity, state)
        elif args.event == "PostToolUse":
            handle_post_tool(args.event, payload, identity, state)
        else:
            handle_stop(args.event, identity, state)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HookError as exc:
        print(f"Integrity hook infrastructure fault: {exc}", file=sys.stderr)
        raise SystemExit(2)
