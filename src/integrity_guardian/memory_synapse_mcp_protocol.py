"""Versioned MCP protocol host for the Integrity Memory/Synapse domain facade.

The domain implementation remains in :mod:`integrity_guardian.memory_synapse_mcp`.
This module owns wire-version negotiation so protocol compatibility cannot become
an authority decision. MCP 2026 request metadata is self-reported context only;
it never authenticates the client broker, grants replay custody, or changes any
Integrity production/append authority.
"""

from __future__ import annotations

import argparse
import atexit
import ctypes
import gc
import json
import math
import sys
import threading
import time
from copy import deepcopy
from typing import Any, BinaryIO

from jsonschema import Draft202012Validator, SchemaError, ValidationError

from . import memory_synapse_mcp as legacy

MODERN_MCP_VERSION = "2026-07-28"
LEGACY_MCP_VERSIONS = (
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
)
SUPPORTED_MODERN_MCP_VERSIONS = (MODERN_MCP_VERSION,)
SUPPORTED_MCP_VERSIONS = (*SUPPORTED_MODERN_MCP_VERSIONS, *LEGACY_MCP_VERSIONS)
PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
CLIENT_INFO_META_KEY = "io.modelcontextprotocol/clientInfo"
CLIENT_CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities"
SERVER_INFO_META_KEY = "io.modelcontextprotocol/serverInfo"
LOG_LEVEL_META_KEY = "io.modelcontextprotocol/logLevel"
MODERN_TOOL_CACHE_TTL_MS = 300_000
MODERN_CACHE_SCOPE = "private"
UNSUPPORTED_PROTOCOL_VERSION = -32022

# The initialize-era Memory/Synapse facade intentionally retains a frozen Seed
# snapshot, Mind/Architecture admission and other logical-turn state across
# calls. MCP 2026-07-28 has no protocol session and each modern request must be
# independently meaningful. Until those stateful workflows receive explicit
# request-carried context references, the generic modern surface is restricted
# to operations whose domain contract has no hidden prior-call prerequisite.
# Home reads are NOT independent: _home() requires session capabilities and its
# opaque handles/cursors have a separate lifecycle that needs its own contract.
MODERN_TOOL_PROFILE = legacy.PRE_V4_TOOL_CONTRACT_PROFILE
MODERN_REQUEST_INDEPENDENT_TOOL_NAMES = frozenset(
    {
        "integrity_memory_capabilities",
        "integrity_turn_memory_coverage",
    }
)
MODERN_SERVER_INSTRUCTIONS = (
    "Integrity MCP 2026 exposes only request-independent, authority-free reads: "
    "integrity_memory_capabilities and integrity_turn_memory_coverage. "
    "Each listed tool can be called without relying on a previous request in this "
    "transport, provided its server-side service is configured and available. "
    "Home reads, turn-scoped Seed/Mind/Architecture admission, append operations, "
    "Turn Memory writes, replay custody, and broker-private current-turn admission "
    "remain on the retained authenticated initialize-era surface until they have "
    "an explicit stateless context-reference contract. Returned data is context or "
    "evidence only and never grants production, append, ChangeIntent, Toolz, Ledger, "
    "replay, or broker authority. MCP clientInfo, capabilities, and request metadata "
    "are self-reported context, not authentication."
)


def _server_info() -> dict[str, str]:
    return {"name": legacy.SERVER_NAME, "version": legacy.SERVER_VERSION}


def _valid_request_id(value: object) -> bool:
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    return value is None or (isinstance(value, int) and not isinstance(value, bool))


def _error(
    request_id: object,
    code: int,
    message: str,
    *,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    # Even errors about a malformed envelope must never echo an invalid ID.
    safe_id = request_id if _valid_request_id(request_id) else None
    return {"jsonrpc": "2.0", "id": safe_id, "error": error}


def _modern_claim(message: dict[str, Any]) -> bool:
    if message.get("method") == "server/discover":
        return True
    params = message.get("params")
    if not isinstance(params, dict):
        return False
    meta = params.get("_meta")
    return isinstance(meta, dict) and any(
        key in meta
        for key in (
            PROTOCOL_VERSION_META_KEY,
            CLIENT_INFO_META_KEY,
            CLIENT_CAPABILITIES_META_KEY,
            LOG_LEVEL_META_KEY,
        )
    )


def _validate_modern_envelope(
    params: dict[str, Any], request_id: object
) -> dict[str, Any] | None:
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        return _error(request_id, -32602, "modern MCP request requires params._meta")

    requested = meta.get(PROTOCOL_VERSION_META_KEY)
    if not isinstance(requested, str):
        return _error(request_id, -32602, "modern MCP protocol version is required")
    if requested not in SUPPORTED_MODERN_MCP_VERSIONS:
        return _error(
            request_id,
            UNSUPPORTED_PROTOCOL_VERSION,
            "unsupported MCP protocol version",
            data={"supported": list(SUPPORTED_MODERN_MCP_VERSIONS), "requested": requested},
        )

    capabilities = meta.get(CLIENT_CAPABILITIES_META_KEY)
    if not isinstance(capabilities, dict):
        return _error(request_id, -32602, "modern MCP client capabilities are required")

    client_info = meta.get(CLIENT_INFO_META_KEY)
    if client_info is not None:
        if not isinstance(client_info, dict):
            return _error(request_id, -32602, "modern MCP clientInfo is invalid")
        name = client_info.get("name")
        version = client_info.get("version")
        if (
            not isinstance(name, str)
            or not name.strip()
            or not isinstance(version, str)
            or not version.strip()
        ):
            return _error(request_id, -32602, "modern MCP clientInfo is invalid")

    log_level = meta.get(LOG_LEVEL_META_KEY)
    if log_level is not None and not isinstance(log_level, str):
        return _error(request_id, -32602, "modern MCP logLevel is invalid")
    return None


def _modern_tools() -> list[dict[str, Any]]:
    catalog = {
        tool["name"]: tool
        for tool in legacy.tools(profile=MODERN_TOOL_PROFILE)
        if isinstance(tool.get("name"), str)
    }
    missing = sorted(MODERN_REQUEST_INDEPENDENT_TOOL_NAMES - set(catalog))
    if missing:
        raise RuntimeError("modern request-independent tool contract is missing: " + ", ".join(missing))
    exposed = [deepcopy(catalog[name]) for name in MODERN_REQUEST_INDEPENDENT_TOOL_NAMES]
    for tool in exposed:
        annotations = tool.get("annotations")
        if (
            not isinstance(annotations, dict)
            or annotations.get("readOnlyHint") is not True
            or annotations.get("destructiveHint") is not False
        ):
            raise RuntimeError(
                f"modern request-independent tool lost read-only boundary: {tool['name']}"
            )
        # The retained domain facade returns one canonical JSON object for each
        # of these reads. Keep output broad but machine-checkable until a closed
        # public result schema exists for the individual operation.
        tool["outputSchema"] = {"type": "object"}
        Draft202012Validator.check_schema(tool["inputSchema"])
        Draft202012Validator.check_schema(tool["outputSchema"])
    return sorted(exposed, key=lambda item: item["name"])


def _result_meta() -> dict[str, Any]:
    return {SERVER_INFO_META_KEY: _server_info()}


def _discover_result() -> dict[str, Any]:
    return {
        "resultType": "complete",
        "supportedVersions": list(SUPPORTED_MODERN_MCP_VERSIONS),
        "capabilities": {"tools": {}},
        "instructions": MODERN_SERVER_INSTRUCTIONS,
        "ttlMs": MODERN_TOOL_CACHE_TTL_MS,
        "cacheScope": MODERN_CACHE_SCOPE,
        "_meta": _result_meta(),
    }


def _decorate_tool_result(result: dict[str, Any]) -> dict[str, Any]:
    content = result.get("content")
    if (
        not isinstance(content, list)
        or len(content) != 1
        or not isinstance(content[0], dict)
        or content[0].get("type") != "text"
        or not isinstance(content[0].get("text"), str)
    ):
        raise ValueError("legacy tool result is not canonical text content")
    structured = json.loads(content[0]["text"])
    if not isinstance(structured, dict):
        raise TypeError("Integrity tool result must be a JSON object")
    Draft202012Validator({"type": "object"}).validate(structured)
    return {
        **result,
        "resultType": "complete",
        "structuredContent": structured,
        "_meta": _result_meta(),
    }


def _modern_dispatch(
    server: legacy.MemorySynapseMcp,
    message: dict[str, Any],
) -> dict[str, Any] | None:
    request_id = message.get("id")
    method = message["method"]

    if "id" not in message:
        # This facade has no client->server notification surface in the modern
        # era. Notifications never receive a response and never execute a domain
        # tool here.
        return None

    params = message.get("params", {})
    if not isinstance(params, dict):
        return _error(request_id, -32602, "params must be an object")
    envelope_error = _validate_modern_envelope(params, request_id)
    if envelope_error is not None:
        return envelope_error

    visible_params = {key: value for key, value in params.items() if key != "_meta"}

    if method == "server/discover":
        if visible_params:
            return _error(request_id, -32602, "server/discover accepts only _meta")
        return {"jsonrpc": "2.0", "id": request_id, "result": _discover_result()}

    if method == "tools/list":
        cursor = visible_params.pop("cursor", None)
        if visible_params:
            return _error(request_id, -32602, "invalid tools/list parameters")
        if cursor not in (None, ""):
            return _error(request_id, -32602, "tool catalog has no continuation cursor")
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "resultType": "complete",
                "tools": _modern_tools(),
                "ttlMs": MODERN_TOOL_CACHE_TTL_MS,
                "cacheScope": MODERN_CACHE_SCOPE,
                "_meta": _result_meta(),
            },
        }

    if method != "tools/call":
        return _error(request_id, -32601, "method not found")

    if set(visible_params) - {"name", "arguments"}:
        return _error(request_id, -32602, "invalid tool call parameters")
    name = visible_params.get("name")
    arguments = visible_params.get("arguments", {})
    if not isinstance(name, str) or not isinstance(arguments, dict):
        return _error(request_id, -32602, "invalid tool call")

    definitions = {tool["name"]: tool for tool in _modern_tools()}
    definition = definitions.get(name)
    if definition is None:
        return _error(request_id, -32602, f"unknown or stateful tool: {name[:120]}")
    try:
        Draft202012Validator(definition["inputSchema"]).validate(arguments)
    except (SchemaError, ValidationError):
        return _error(request_id, -32602, "invalid tool arguments")

    # These modern tools are an explicit request-independent read subset. The
    # mature dispatcher remains responsible for domain validation and receipts,
    # but no modern tool relies on hidden Seed/Mind/Architecture state created by
    # an earlier request.
    legacy_response = legacy.dispatch(
        server,
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )
    if legacy_response is None:
        return _error(request_id, -32603, "tool execution produced no response")
    if "error" in legacy_response:
        return legacy_response
    result = legacy_response.get("result")
    if not isinstance(result, dict):
        return _error(request_id, -32603, "tool execution returned an invalid result")
    try:
        decorated = _decorate_tool_result(result)
    except (TypeError, ValueError, RecursionError, SchemaError, ValidationError):
        return _error(request_id, -32603, "tool result failed output validation")
    return {"jsonrpc": "2.0", "id": request_id, "result": decorated}


def dispatch(
    server: legacy.MemorySynapseMcp,
    message: dict[str, Any],
) -> dict[str, Any] | None:
    request_id = message.get("id")
    if "id" in message and not _valid_request_id(request_id):
        return _error(None, -32600, "invalid request id")
    if message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
        return _error(request_id, -32600, "invalid request")
    if not _modern_claim(message):
        return legacy.dispatch(server, message)
    return _modern_dispatch(server, message)


def _read_frame(stream: BinaryIO) -> tuple[bytes | None, bool]:
    raw = stream.readline(legacy.MAX_REQUEST_BYTES + 1)
    if not raw:
        return None, False
    if len(raw) <= legacy.MAX_REQUEST_BYTES:
        return raw, False

    # readline(limit) returns a prefix and leaves the suffix buffered. Drain
    # through the frame's newline so attacker-controlled suffix bytes can never
    # become a second JSON-RPC request on the next loop iteration.
    while raw and not raw.endswith(b"\n"):
        raw = stream.readline(legacy.MAX_REQUEST_BYTES + 1)
    return b"", True


def _encode_response(response: dict[str, Any]) -> bytes:
    try:
        payload = legacy.canonical_json(response) + b"\n"
    except (TypeError, ValueError, RecursionError):
        # A malformed domain result must not kill the shared stdio host. This
        # is an output failure, not authority to retry a domain operation.
        reason = "response is not serializable JSON"
    else:
        if len(payload) <= legacy.MAX_RESPONSE_BYTES:
            return payload
        reason = "response exceeds the stdio limit"
    fallback = _error(response.get("id"), -32603, reason)
    payload = legacy.canonical_json(fallback) + b"\n"
    if len(payload) > legacy.MAX_RESPONSE_BYTES:
        # The request ID itself can exceed a response budget. Never echo an
        # unbounded identifier from the bounded-error path.
        fallback["id"] = None
        payload = legacy.canonical_json(fallback) + b"\n"
    return payload


def _finite_json_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("non-finite JSON number")
    return value


def _reject_json_constant(_text: str) -> None:
    raise ValueError("non-finite JSON constant")


DEFAULT_IDLE_RELEASE_SECONDS = 3600
MIN_IDLE_RELEASE_SECONDS = 60
MAX_IDLE_RELEASE_SECONDS = 86_400


def _return_freed_heap() -> None:
    gc.collect()
    if sys.platform.startswith("linux"):
        try:
            ctypes.CDLL("libc.so.6").malloc_trim(0)
        except (OSError, AttributeError):
            pass


class _IdleReleaseWatchdog:
    """Release an idle session's Seed copy without closing its transport.

    Requests run under ``lock``; the watchdog acts only when it can take the
    same lock, so a release never interleaves with a request.
    """

    def __init__(
        self,
        server: legacy.MemorySynapseMcp,
        lock: threading.Lock,
        idle_seconds: float,
        *,
        clock=time.monotonic,
    ) -> None:
        self._server = server
        self._lock = lock
        self._idle_seconds = idle_seconds
        self._clock = clock
        self._last_activity = clock()
        self._released = False
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="integrity-idle-release", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def touch(self) -> None:
        self._last_activity = self._clock()
        self._released = False

    def check(self) -> bool:
        if self._released or self._clock() - self._last_activity < self._idle_seconds:
            return False
        if not self._lock.acquire(blocking=False):
            return False
        try:
            if self._clock() - self._last_activity < self._idle_seconds:
                return False
            self._released = True
            released = self._server.release_idle_context()
        except Exception:  # noqa: BLE001 - the watchdog must never kill the host
            return False
        finally:
            self._lock.release()
        if released:
            _return_freed_heap()
        return released

    def _run(self) -> None:
        interval = max(1.0, min(60.0, self._idle_seconds / 4))
        while not self._stop.wait(interval):
            self.check()


def _handle_frame(
    server: legacy.MemorySynapseMcp,
    raw: bytes,
    oversized: bool,
) -> dict[str, Any] | None:
    if oversized:
        return _error(None, -32700, "parse error: stdio frame exceeds limit")
    try:
        message = json.loads(
            raw,
            parse_float=_finite_json_float,
            parse_constant=_reject_json_constant,
        )
        # JSON escapes may decode to lone surrogates. Validate the
        # complete frame before domain execution: the legacy denial
        # path also hashes arguments as canonical UTF-8 JSON.
        legacy.canonical_json(message)
    except (ValueError, RecursionError):
        # ValueError includes decoding failures and Python's integer
        # digit limit. Reject non-finite values anywhere, before any
        # modern or legacy domain tool can observe the request.
        return _error(None, -32700, "parse error")
    if not isinstance(message, dict):
        return _error(None, -32600, "invalid request")
    return dispatch(server, message)


def serve(
    server: legacy.MemorySynapseMcp,
    *,
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
    idle_release_seconds: float | None = None,
) -> int:
    input_stream = stdin or sys.stdin.buffer
    output_stream = stdout or sys.stdout.buffer
    lock = threading.Lock()
    watchdog = (
        _IdleReleaseWatchdog(server, lock, idle_release_seconds)
        if idle_release_seconds
        else None
    )
    if watchdog is not None:
        watchdog.start()
    try:
        while True:
            raw, oversized = _read_frame(input_stream)
            if raw is None:
                break
            with lock:
                if watchdog is not None:
                    watchdog.touch()
                response = _handle_frame(server, raw, oversized)
            if response is not None:
                output_stream.write(_encode_response(response))
                output_stream.flush()
        return 0
    finally:
        if watchdog is not None:
            watchdog.stop()
        server.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=legacy.Path)
    parser.add_argument("--ttt-path-catalog", type=legacy.Path)
    parser.add_argument("--expected-ttt-path-catalog-digest")
    parser.add_argument("--evidence-root", type=legacy.Path)
    parser.add_argument("--evidence-source-prefix", type=legacy.Path)
    parser.add_argument("--architecture-root", type=legacy.Path)
    parser.add_argument("--snapshot-root", type=legacy.Path)
    parser.add_argument("--architecture-source-key", type=legacy.Path)
    parser.add_argument("--architecture-checkpoint-key", type=legacy.Path)
    parser.add_argument("--security-admission-bundle", type=legacy.Path)
    parser.add_argument("--security-authority-public-key", type=legacy.Path)
    parser.add_argument("--event-authority-public-key", type=legacy.Path)
    parser.add_argument("--action-log-witness-helper", type=legacy.Path)
    parser.add_argument(
        "--trust-profile",
        choices=("personal-native", "managed-external"),
        default="managed-external",
    )
    parser.add_argument("--native-state-root", type=legacy.Path)
    parser.add_argument("--native-instance-id")
    parser.add_argument("--native-device-id")
    parser.add_argument(
        "--idle-release-seconds",
        type=int,
        default=DEFAULT_IDLE_RELEASE_SECONDS,
        help="release an idle session's Seed copy after this many seconds; 0 disables",
    )
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args(argv)
    if args.idle_release_seconds and not (
        MIN_IDLE_RELEASE_SECONDS <= args.idle_release_seconds <= MAX_IDLE_RELEASE_SECONDS
    ):
        parser.error("--idle-release-seconds must be 0 or within 60..86400")
    if args.version:
        print(f"{legacy.SERVER_NAME} {legacy.SERVER_VERSION}")
        return 0
    if args.catalog is None:
        parser.error("--catalog is required unless --version is used")
    if any(
        value is None
        for value in (
            args.architecture_root,
            args.snapshot_root,
            args.action_log_witness_helper,
        )
    ):
        parser.error(
            "--architecture-root, --snapshot-root, and --action-log-witness-helper are required"
        )
    managed_inputs = (
        args.architecture_source_key,
        args.architecture_checkpoint_key,
        args.security_admission_bundle,
        args.security_authority_public_key,
        args.event_authority_public_key,
    )
    native_inputs = (
        args.native_state_root,
        args.native_instance_id,
        args.native_device_id,
    )
    if args.trust_profile == "managed-external" and any(
        value is None for value in managed_inputs
    ):
        parser.error(
            "managed-external requires architecture keys, Security bundle, and authority public keys"
        )
    if args.trust_profile == legacy.NATIVE_TRUST_PROFILE and any(
        value is None for value in native_inputs
    ):
        parser.error(
            "personal-native requires --native-state-root, --native-instance-id, and --native-device-id"
        )
    if (args.evidence_root is None) != (args.evidence_source_prefix is None):
        parser.error("--evidence-root and --evidence-source-prefix must be supplied together")

    try:
        ttt_path_catalog = legacy.load_runbook_path_catalog(
            args.ttt_path_catalog,
            args.expected_ttt_path_catalog_digest,
        )
    except (legacy.MemoryTttPathError, OSError, ValueError) as exc:
        parser.error(f"TTT path catalogue rejected: {exc}")

    package_lts = legacy.MemorySynapseLtsService(
        args.catalog,
        evidence_root=args.evidence_root,
        evidence_source_prefix=args.evidence_source_prefix,
    )
    runtime = legacy._build_write_plane_runtime(args, package_lts)
    server = legacy.MemorySynapseMcp(
        package_lts,
        architecture=runtime.architecture,
        action_witness=runtime.action_witness,
        security_admission=runtime.security_admission,
        write_plane_status=runtime.status,
        snapshot_source=args.catalog,
        snapshot_root=args.snapshot_root,
        native_trust=runtime.native_trust,
        native_device_id=runtime.native_device_id,
        turn_memory=runtime.turn_memory,
        memory_ttt_path_catalog=ttt_path_catalog,
        write_plane_reinitializer=lambda: legacy._build_write_plane_runtime(
            args,
            package_lts,
            emit_component_audit=False,
        ),
    )
    atexit.register(server.close)
    return serve(server, idle_release_seconds=args.idle_release_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
