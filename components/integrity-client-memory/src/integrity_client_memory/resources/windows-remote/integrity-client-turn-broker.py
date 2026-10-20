#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Lazy MCP broker that retains one upstream transport for logical contexts."""

from __future__ import annotations

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
from contextlib import contextmanager
from contextvars import ContextVar
import time
import hashlib
import json
import os
import queue
import re
import secrets
import subprocess
import sys
import threading
import tomllib
from pathlib import Path
from typing import Any

import integrity_client_turn_envelope as turn_envelope

# Portable read-only session declaration from the existing common source.
import types as _reader_session_types
_reader_session_module = _reader_session_types.ModuleType('integrity_reader_session')
exec(compile('# SPDX-License-Identifier: Apache-2.0\n"""Request-local, read-only AL admission. No canonical writes or ambient identity.\n\nThe admitted local broker is the identity authority within the existing reader\ntrust boundary. The proof authenticates transport binding, not target authority.\n"""\nfrom __future__ import annotations\n\nfrom integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config\n\nimport datetime as dt\nimport hashlib\nimport hmac\nimport json\nimport re\n\nPROTOCOL = \'integrity-reader-session/v1\'\nMAX_TTL_SECONDS = 300\nHEX = re.compile(r\'[a-f0-9]{64}\\Z\')\nDIGEST = re.compile(r\'sha256:[a-f0-9]{64}\\Z\')\nKEYS = {\'protocol\', \'identity_hashes\', \'agent_product\', \'agent_id\', \'session_id\',\n        \'turn_ref_digest\', \'prompt_sha256\', \'declared_at\', \'expires_at\',\n        \'external_action_authority\'}\n\n\nclass ReadSessionError(ValueError):\n    pass\n\n\ndef canonical(value):\n    return json.dumps(value, sort_keys=True, ensure_ascii=False,\n                      separators=(\',\', \':\'), allow_nan=False).encode(\'utf-8\')\n\n\ndef timestamp(value):\n    if not isinstance(value, str) or len(value) > 40:\n        raise ReadSessionError(\'reader session timestamp invalid\')\n    try:\n        result = dt.datetime.fromisoformat(value.replace(\'Z\', \'+00:00\'))\n    except ValueError:\n        raise ReadSessionError(\'reader session timestamp invalid\') from None\n    if result.tzinfo is None or result.utcoffset() != dt.timedelta(0):\n        raise ReadSessionError(\'reader session requires UTC\')\n    return result\n\n\ndef validate(value, *, prompt_sha256=None, turn_ref_digest=None, now=None):\n    if not isinstance(value, dict) or set(value) != KEYS:\n        raise ReadSessionError(\'reader session shape invalid\')\n    hashes = value.get(\'identity_hashes\')\n    if (value.get(\'protocol\') != PROTOCOL or not isinstance(hashes, dict)\n            or set(hashes) != {\'machine_id\', \'thread_id\', \'turn_id\'}\n            or any(not isinstance(v, str) or not HEX.fullmatch(v) for v in hashes.values())\n            or value.get(\'agent_product\') not in {\'codex\', \'claude\'}\n            or value.get(\'external_action_authority\') is not False):\n        raise ReadSessionError(\'reader session identity invalid\')\n    expected_session = \'reader:\' + value[\'agent_product\'] + \':\' + hashes[\'machine_id\'] + \':\' + hashes[\'thread_id\']\n    expected_agent = value[\'agent_product\'] + \':\' + hashes[\'machine_id\']\n    if (value.get(\'session_id\') != expected_session or value.get(\'agent_id\') != expected_agent\n            or not isinstance(value.get(\'prompt_sha256\'), str)\n            or not HEX.fullmatch(value[\'prompt_sha256\'])\n            or not isinstance(value.get(\'turn_ref_digest\'), str)\n            or not DIGEST.fullmatch(value[\'turn_ref_digest\'])\n            or prompt_sha256 is not None and value[\'prompt_sha256\'] != prompt_sha256\n            or turn_ref_digest is not None and value[\'turn_ref_digest\'] != turn_ref_digest):\n        raise ReadSessionError(\'reader session binding mismatch\')\n    start, end = timestamp(value[\'declared_at\']), timestamp(value[\'expires_at\'])\n    current = now if now is not None else dt.datetime.now(dt.timezone.utc)\n    if not 0 < (end - start).total_seconds() <= MAX_TTL_SECONDS or not start <= current < end:\n        raise ReadSessionError(\'reader session expired or outside its window\')\n    return json.loads(canonical(value))\n\n\ndef issue(envelope, *, product, now=None):\n    """Called only after native claim/owning-head revalidation by the broker."""\n    current = now if now is not None else dt.datetime.now(dt.timezone.utc)\n    hashes = envelope[\'native_identity_hashes\']\n    end = min(timestamp(envelope[\'expires_utc\']), current + dt.timedelta(seconds=MAX_TTL_SECONDS))\n    value = {\'protocol\': PROTOCOL, \'identity_hashes\': hashes, \'agent_product\': product,\n             \'agent_id\': product + \':\' + hashes[\'machine_id\'],\n             \'session_id\': \'reader:\' + product + \':\' + hashes[\'machine_id\'] + \':\' + hashes[\'thread_id\'],\n             \'turn_ref_digest\': envelope[\'turn_ref_digest\'], \'prompt_sha256\': envelope[\'prompt_sha256\'],\n             \'declared_at\': current.isoformat().replace(\'+00:00\', \'Z\'),\n             \'expires_at\': end.isoformat().replace(\'+00:00\', \'Z\'),\n             \'external_action_authority\': False}\n    return validate(value, now=current)\n\n\ndef request_proof(declaration, *, snapshot_event_id, token):\n    if not isinstance(token, str) or not token:\n        raise ReadSessionError(\'reader session authentication required\')\n    if isinstance(snapshot_event_id, bool) or not isinstance(snapshot_event_id, int) or snapshot_event_id < 1:\n        raise ReadSessionError(\'reader session snapshot invalid\')\n    material = {\'declaration\': declaration, \'snapshot_event_id\': snapshot_event_id}\n    return hmac.new(token.encode(), PROTOCOL.encode() + b\'\\0\' + canonical(material), hashlib.sha256).hexdigest()\n\n\ndef accept(payload, *, token, now=None):\n    """Authenticate before AL projection/recall; proof never leaves this request."""\n    if not isinstance(payload, dict) or set(payload) != {\'declaration\', \'proof\', \'snapshot_event_id\'}:\n        raise ReadSessionError(\'reader session request invalid\')\n    declaration = validate(payload[\'declaration\'], now=now)\n    proof = payload.get(\'proof\')\n    expected = request_proof(declaration, snapshot_event_id=payload[\'snapshot_event_id\'], token=token)\n    if not isinstance(proof, str) or not hmac.compare_digest(expected, proof):\n        raise ReadSessionError(\'reader session proof mismatch\')\n    return declaration\n\n\ndef speaker(declaration):\n    return {\'agent_id\': declaration[\'agent_id\'], \'agent_product\': declaration[\'agent_product\'],\n            \'agent_vendor\': \'OpenAI\' if declaration[\'agent_product\'] == \'codex\' else \'Anthropic\',\n            \'admission_id\': \'sha256:\' + hashlib.sha256(canonical(declaration)).hexdigest(),\n            \'admission_declared_at\': declaration[\'declared_at\'],\n            \'admission_expires_at\': declaration[\'expires_at\'],\n            \'capability_class\': [\'context-read\'], \'admitted_agents\': []}\n', '<managed-read-session.py>', 'exec'), _reader_session_module.__dict__)

BROKER_NAME = "integrity-client-memory"
BROKER_VERSION = "1.4.1"
DEFAULT_MCP_VERSION = "2025-06-18"
MAX_MESSAGE_BYTES = 4 * 1024 * 1024
BROKER_TOOL_SURFACE_PROTOCOL = "integrity-client/broker-tool-surface/v1"
BROKER_TOOL_SURFACE_CAPABILITY = "integrityClientToolSurface"
CONTEXT_ADMISSION_REPLAY_PROTOCOL = "integrity-client/context-admission-replay/v2"
CONTEXT_ADMISSION_REPLAY_CAPABILITY = "integrityClientContextAdmissionReplay"
CONTEXT_ADMISSION_REPLAY_FIELD = "_integrity_replay_id"
CONTEXT_ADMISSION_REPLAY_ACK_NOTIFICATION = (
    "notifications/integrity_context_admission_replay_ack"
)
CONTEXT_ADMISSION_REPLAY_RESERVE_METHOD = (
    "integrity/context_admission_replay_reserve"
)
CONTEXT_ADMISSION_REPLAY_ACK_METHOD = "integrity/context_admission_replay_ack"
CONTEXT_ADMISSION_REPLAY_CONTROL_TIMEOUT_SECONDS = 15
STANDALONE_TURN_MEMORY_TOOLS = {
    "integrity_turn_memory_open",
    "integrity_turn_memory_close",
    "integrity_turn_memory_gap",
    "integrity_turn_memory_coverage",
}
CURRENT_TURN_CONTEXT_TOOL = "integrity_context_admission_current_turn"
UPSTREAM_INITIALIZE_TIMEOUT_SECONDS = 45
PUBLIC_REQUEST_BUDGET_SECONDS = 180
_REQUEST_DEADLINE = ContextVar("integrity_rpc_deadline", default=None)
UPSTREAM_TOOL_TIMEOUT_SECONDS = 90
UPSTREAM_CONTEXT_ADMISSION_TIMEOUT_SECONDS = 180
SERVER_INSTRUCTIONS = (
    "Integrity memory is turn-scoped. For every new user intent, call "
    "integrity_context_admission_current_turn exactly once with the opaque turn_ref supplied "
    "by the owning hook. Never repeat or reconstruct the prompt in tool arguments. "
    "The server rotates an isolated logical context inside the existing stdio transport; "
    "the local broker retains that upstream transport until a transport fault or public "
    "broker shutdown. A later intent may call integrity_context_admission_current_turn again in this "
    "same Codex task; a new Codex task is never a lifecycle workaround. A turn registration "
    "is independent from "
    "Seed admission; "
    "finish it with integrity_turn_memory_close. Missing close is signed coverage debt, not "
    "an inferred no-event. Memory is evidence and grants no production authority."
)
LEGACY_SERVER_INSTRUCTIONS = (
    "Integrity memory is turn-scoped. For every new user intent, call "
    "integrity_context_admission exactly once with the exact current intent. "
    "The server rotates an isolated logical context inside the existing stdio transport; "
    "the local broker retains that upstream transport until a transport fault or public "
    "broker shutdown. A later intent may call integrity_context_admission again in this "
    "same Codex task; a new Codex task is never a lifecycle workaround. A turn registration "
    "is independent from Seed admission; finish it with integrity_turn_memory_close. "
    "Missing close is signed coverage debt, not an inferred no-event. Memory is evidence "
    "and grants no production authority."
)


class BrokerError(RuntimeError):
    """A fail-closed local broker or upstream transport failure."""

    def __init__(
        self,
        message: str,
        *,
        layer: str,
        request_sent: bool = False,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.layer = layer
        self.request_sent = request_sent
        self.retryable = retryable


@contextmanager
def _public_request_budget():
    # Nested work and reconnects share the outer deadline. Never extend it.
    existing = _REQUEST_DEADLINE.get()
    deadline = time.monotonic() + PUBLIC_REQUEST_BUDGET_SECONDS
    token = _REQUEST_DEADLINE.set(min(existing, deadline) if existing is not None else deadline)
    try:
        yield
    finally:
        _REQUEST_DEADLINE.reset(token)


def _remaining_timeout(timeout: float) -> float:
    deadline = _REQUEST_DEADLINE.get()
    return timeout if deadline is None else max(0.0, min(timeout, deadline - time.monotonic()))


def _require_request_budget() -> None:
    if _remaining_timeout(PUBLIC_REQUEST_BUDGET_SECONDS) <= 0:
        raise BrokerError("public request time budget exhausted", layer="broker-upstream",
                          request_sent=False, retryable=False)


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _load_tools_contract(path: Path) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerError("tools contract is unavailable", layer="broker-config") from exc
    if not isinstance(value, list) or not value:
        raise BrokerError("tools contract is invalid", layer="broker-config")
    names: list[str] = []
    for item in value:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("name"), str)
            or not isinstance(item.get("description"), str)
            or not isinstance(item.get("inputSchema"), dict)
            or not isinstance(item.get("annotations"), dict)
        ):
            raise BrokerError("tools contract entry is invalid", layer="broker-config")
        names.append(item["name"])
    if len(names) != len(set(names)) or "integrity_context_admission" not in names:
        raise BrokerError("tools contract names are invalid", layer="broker-config")
    return value


def _tool_surface(value: list[dict[str, Any]]) -> bytes:
    if not all(isinstance(item, dict) for item in value):
        raise BrokerError("upstream tool contract changed", layer="broker-upstream")
    return _json_bytes(
        [
            {
                "name": item.get("name"),
                "inputSchema": item.get("inputSchema"),
                "annotations": item.get("annotations"),
            }
            for item in value
        ]
    )


def _tool_surface_sha256(value: list[dict[str, Any]]) -> str:
    return "sha256:" + hashlib.sha256(_tool_surface(value)).hexdigest()


def _surface_acknowledged(initialized: dict[str, Any], expected_sha256: str) -> bool:
    capabilities = initialized.get("capabilities")
    experimental = capabilities.get("experimental") if isinstance(capabilities, dict) else None
    acknowledgement = (
        experimental.get(BROKER_TOOL_SURFACE_CAPABILITY) if isinstance(experimental, dict) else None
    )
    return bool(
        isinstance(acknowledgement, dict)
        and acknowledgement.get("protocol") == BROKER_TOOL_SURFACE_PROTOCOL
        and acknowledgement.get("accepted_tools_surface_sha256") == expected_sha256
        and acknowledgement.get("compatibility")
        == "local-contract-facade-with-upstream-name-subset/v1"
    )


def _context_admission_replay_acknowledgement(
    initialized: dict[str, Any],
    reservation_id: str | None,
) -> dict[str, Any] | None:
    capabilities = initialized.get("capabilities")
    experimental = capabilities.get("experimental") if isinstance(capabilities, dict) else None
    acknowledgement = (
        experimental.get(CONTEXT_ADMISSION_REPLAY_CAPABILITY)
        if isinstance(experimental, dict)
        else None
    )
    if not (
        isinstance(acknowledgement, dict)
        and acknowledgement.get("protocol") == CONTEXT_ADMISSION_REPLAY_PROTOCOL
        and acknowledgement.get("request_identity_field")
        == CONTEXT_ADMISSION_REPLAY_FIELD
        and acknowledgement.get("request_identity_format") == "sha256/v1"
        and reservation_id is not None
        and acknowledgement.get("reservation_id") == reservation_id
        and acknowledgement.get("reservation_method")
        == CONTEXT_ADMISSION_REPLAY_RESERVE_METHOD
        and acknowledgement.get("ack_method") == CONTEXT_ADMISSION_REPLAY_ACK_METHOD
        and acknowledgement.get("durability") == "architecture-custody-root/v1"
        and acknowledgement.get("replay_semantics") == "exact-response/v1"
        and acknowledgement.get("max_transport_retries") == 1
        and acknowledgement.get("reservation_status")
        in {None, "reserved", "unavailable"}
    ):
        return None
    return acknowledgement


def _upstream_supports_local_tools(
    upstream_tools: list[dict[str, Any]], tools_contract: list[dict[str, Any]]
) -> bool:
    """Require every broker-exposed contract to remain byte-structurally callable.

    An acknowledgement permits additive upstream tools; it never permits a
    same-name schema or annotation change.  Comparing only names let an
    upstream release acknowledge a retained digest while silently breaking
    the installed broker's arguments contract.
    """

    if not all(isinstance(item, dict) for item in upstream_tools):
        return False
    upstream_names = [item.get("name") for item in upstream_tools]
    if not all(isinstance(name, str) and name for name in upstream_names):
        return False
    upstream_by_name = dict(zip(upstream_names, upstream_tools, strict=True))
    if len(upstream_by_name) != len(upstream_tools):
        return False
    for local in tools_contract:
        upstream = upstream_by_name.get(local["name"])
        if upstream is None or any(
            upstream.get(field) != local.get(field)
            for field in ("inputSchema", "annotations")
        ):
            return False
    return True


def _load_upstream(
    config_path: Path, server_name: str
) -> tuple[list[str], dict[str, str], str | None]:
    try:
        with config_path.open("rb") as stream:
            config = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise BrokerError("Codex MCP config is unavailable", layer="broker-config") from exc
    servers = config.get("mcp_servers")
    server = servers.get(server_name) if isinstance(servers, dict) else None
    if not isinstance(server, dict):
        raise BrokerError("internal upstream registration is missing", layer="broker-config")
    if server.get("enabled") is not False:
        raise BrokerError("internal upstream must be disabled for Codex", layer="broker-config")
    command = server.get("command")
    arguments = server.get("args", [])
    configured_env = server.get("env")
    cwd = server.get("cwd")
    if not isinstance(command, str) or not command.strip():
        raise BrokerError("internal upstream command is invalid", layer="broker-config")
    if not isinstance(arguments, list) or not all(isinstance(item, str) for item in arguments):
        raise BrokerError("internal upstream arguments are invalid", layer="broker-config")
    if configured_env is None:
        configured_env = {}
    if not isinstance(configured_env, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in configured_env.items()
    ):
        raise BrokerError("internal upstream environment is invalid", layer="broker-config")
    if cwd is not None and not isinstance(cwd, str):
        raise BrokerError("internal upstream working directory is invalid", layer="broker-config")
    environment = dict(os.environ)
    environment.update(configured_env)
    return [command, *arguments], environment, cwd


class UpstreamFacade:
    """One initialized upstream stdio process shared by sequential logical contexts."""

    def __init__(
        self,
        command: list[str],
        environment: dict[str, str],
        cwd: str | None,
        tools_contract: list[dict[str, Any]],
        initialize_params: dict[str, Any],
        context_replay_reservation_id: str | None = None,
    ) -> None:
        self._responses: queue.Queue[bytes | None] = queue.Queue()
        self._next_id = 1_000_000_000
        self.context_admission_replay_safe = False
        self.context_admission_replay_contract_safe = False
        self.context_admission_replay_ack_request_safe = False
        self._context_replay_reservation_id = context_replay_reservation_id
        _require_request_budget()
        try:
            self.process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                env=environment,
                cwd=cwd,
                bufsize=0,
            )
        except OSError as exc:
            raise BrokerError(
                "upstream process could not start",
                layer="broker-upstream",
                retryable=True,
            ) from exc
        assert self.process.stdin is not None and self.process.stdout is not None
        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._reader.start()
        try:
            params = dict(initialize_params)
            tools_surface_sha256 = _tool_surface_sha256(tools_contract)
            capabilities = params.get("capabilities")
            capabilities = dict(capabilities) if isinstance(capabilities, dict) else {}
            experimental = capabilities.get("experimental")
            experimental = dict(experimental) if isinstance(experimental, dict) else {}
            experimental[BROKER_TOOL_SURFACE_CAPABILITY] = {
                "protocol": BROKER_TOOL_SURFACE_PROTOCOL,
                "tools_surface_sha256": tools_surface_sha256,
            }
            experimental[CONTEXT_ADMISSION_REPLAY_CAPABILITY] = {
                "protocol": CONTEXT_ADMISSION_REPLAY_PROTOCOL,
                "request_identity_field": CONTEXT_ADMISSION_REPLAY_FIELD,
                "request_identity_format": "sha256/v1",
                **(
                    {"reservation_id": context_replay_reservation_id}
                    if context_replay_reservation_id is not None
                    else {}
                ),
            }
            capabilities["experimental"] = experimental
            params["capabilities"] = capabilities
            params["clientInfo"] = {
                "name": "integrity-client-turn-broker",
                "version": BROKER_VERSION,
            }
            initialized = self.request(
                "initialize",
                params,
                timeout=UPSTREAM_INITIALIZE_TIMEOUT_SECONDS,
            )
            server_info = initialized.get("serverInfo")
            if not isinstance(server_info, dict) or server_info.get("name") != BROKER_NAME:
                raise BrokerError("upstream identity mismatch", layer="broker-upstream")
            replay_acknowledgement = _context_admission_replay_acknowledgement(
                initialized,
                context_replay_reservation_id,
            )
            self.context_admission_replay_contract_safe = (
                replay_acknowledgement is not None
            )
            self.context_admission_replay_safe = bool(
                replay_acknowledgement is not None
                and replay_acknowledgement.get("reservation_status")
                != "unavailable"
            )
            self.context_admission_replay_ack_request_safe = (
                self.context_admission_replay_contract_safe
            )
            self.notify("notifications/initialized", {})
            listed = self.request(
                "tools/list",
                {},
                timeout=UPSTREAM_INITIALIZE_TIMEOUT_SECONDS,
            )
            upstream_tools = listed.get("tools")
            acknowledged = _surface_acknowledged(initialized, tools_surface_sha256)
            if (
                not isinstance(upstream_tools, list)
                or (
                    acknowledged
                    and not _upstream_supports_local_tools(upstream_tools, tools_contract)
                )
                or (
                    not acknowledged
                    and _tool_surface(upstream_tools) != _tool_surface(tools_contract)
                )
            ):
                raise BrokerError("upstream tool contract changed", layer="broker-upstream")
        except BaseException:
            if (
                self.context_admission_replay_ack_request_safe
                and self._context_replay_reservation_id is not None
            ):
                empty_digest = "sha256:" + hashlib.sha256(_json_bytes({})).hexdigest()
                try:
                    self.acknowledge_context_admission_replay(
                        {
                            "replay_id": self._context_replay_reservation_id,
                            "request_digest": empty_digest,
                            "response_digest": empty_digest,
                        }
                    )
                except BrokerError:
                    pass
            self.close()
            raise

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        try:
            while True:
                raw = self.process.stdout.readline(MAX_MESSAGE_BYTES + 1)
                if not raw:
                    break
                self._responses.put(raw)
        finally:
            self._responses.put(None)

    def _write(self, message: dict[str, Any]) -> None:
        assert self.process.stdin is not None
        _require_request_budget()
        payload = _json_bytes(message)
        if len(payload) > MAX_MESSAGE_BYTES:
            raise BrokerError("upstream request exceeds limit", layer="broker-upstream")
        wire_payload = payload + b"\n"
        written_total = 0
        _require_request_budget()
        try:
            while written_total < len(wire_payload):
                if _remaining_timeout(PUBLIC_REQUEST_BUDGET_SECONDS) <= 0:
                    raise BrokerError("public request time budget exhausted", layer="broker-upstream",
                                      request_sent=written_total > 0, retryable=False)
                written = self.process.stdin.write(
                    memoryview(wire_payload)[written_total:]
                )
                if (
                    not isinstance(written, int)
                    or isinstance(written, bool)
                    or written <= 0
                    or written > len(wire_payload) - written_total
                ):
                    raise OSError("upstream request transport made no progress")
                written_total += written
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise BrokerError(
                "upstream request transport failed",
                layer="broker-upstream",
                request_sent=written_total > 0,
                retryable=True,
            ) from exc

    def _receive(self, request_id: Any, *, timeout: int, request_sent: bool) -> dict[str, Any]:
        self._last_response_stage = "waiting-for-response"
        self._last_response_bytes = None
        try:
            raw = self._responses.get(timeout=_remaining_timeout(timeout))
        except queue.Empty as exc:
            raise BrokerError(
                "upstream response timed out",
                layer="broker-upstream",
                request_sent=request_sent,
                retryable=True,
            ) from exc
        if raw is None:
            raise BrokerError(
                "upstream closed its response stream",
                layer="broker-upstream",
                request_sent=request_sent,
                retryable=True,
            )
        self._last_response_stage = "response-bytes-received"
        self._last_response_bytes = len(raw)
        if len(raw) > MAX_MESSAGE_BYTES:
            raise BrokerError(
                "upstream response exceeds limit",
                layer="broker-upstream",
                request_sent=request_sent,
                retryable=True,
            )
        try:
            response = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BrokerError(
                "upstream returned invalid JSON",
                layer="broker-upstream",
                request_sent=request_sent,
                retryable=True,
            ) from exc
        if not isinstance(response, dict) or response.get("id") != request_id:
            raise BrokerError(
                "upstream response id mismatch",
                layer="broker-upstream",
                request_sent=request_sent,
                retryable=True,
            )
        self._last_response_stage = "response-id-validated"
        if response.get("error") is not None:
            raise BrokerError(
                "upstream rejected the MCP request",
                layer="broker-upstream",
                request_sent=request_sent,
            )
        result = response.get("result")
        if not isinstance(result, dict):
            raise BrokerError(
                "upstream result is invalid",
                layer="broker-upstream",
                request_sent=request_sent,
            )
        return result

    def request(self, method: str, params: dict[str, Any], *, timeout: int) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        self._write({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        return self._receive(request_id, timeout=timeout, request_sent=True)

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.request(
            "tools/call",
            {"name": name, "arguments": arguments},
            timeout=(
                UPSTREAM_CONTEXT_ADMISSION_TIMEOUT_SECONDS
                if name == "integrity_context_admission"
                else UPSTREAM_TOOL_TIMEOUT_SECONDS
            ),
        )

    def reserve_context_admission_replay(self, reservation_id: str) -> bool:
        if not self.context_admission_replay_contract_safe:
            return False
        try:
            result = self.request(
                CONTEXT_ADMISSION_REPLAY_RESERVE_METHOD,
                {"reservation_id": reservation_id},
                timeout=CONTEXT_ADMISSION_REPLAY_CONTROL_TIMEOUT_SECONDS,
            )
        except BrokerError as exc:
            if exc.retryable:
                raise
            return False
        reserved = bool(
            result.get("protocol")
            == "integrity-client/context-admission-replay-reservation/v1"
            and result.get("reservation_id") == reservation_id
            and result.get("reserved") is True
        )
        if reserved:
            self.context_admission_replay_safe = True
            self.context_admission_replay_ack_request_safe = True
        return reserved

    def acknowledge_context_admission_replay(
        self,
        acknowledgement: dict[str, str],
    ) -> bool:
        result = self.request(
            CONTEXT_ADMISSION_REPLAY_ACK_METHOD,
            acknowledgement,
            timeout=CONTEXT_ADMISSION_REPLAY_CONTROL_TIMEOUT_SECONDS,
        )
        return bool(
            result.get("protocol")
            == "integrity-client/context-admission-replay-reservation/v1"
            and result.get("replay_id") == acknowledgement.get("replay_id")
            and result.get("retired") is True
        )

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self._write({"jsonrpc": "2.0", "method": method, "params": params})

    def close(self) -> None:
        process = getattr(self, "process", None)
        if process is None:
            return
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        if process.poll() is None:
            try:
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.terminate()
                    process.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    try:
                        process.kill()
                        process.wait(timeout=2)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is None or stream.closed:
                continue
            try:
                stream.close()
            except OSError:
                pass
        reader = getattr(self, "_reader", None)
        if reader is not None and reader is not threading.current_thread():
            reader.join(timeout=2)
        self.process = None


class TurnBroker:
    """Local MCP surface with one lazy upstream and server-owned context rotation."""

    def __init__(
        self,
        config_path: Path,
        upstream_server: str,
        tools_contract: list[dict[str, Any]],
    ) -> None:
        self.config_path = config_path
        self.upstream_server = upstream_server
        self.tools_contract = tools_contract
        self.tool_names = {item["name"] for item in tools_contract}
        self.initialize_params: dict[str, Any] = {
            "protocolVersion": DEFAULT_MCP_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "unknown-client", "version": "0"},
        }
        self.upstream: UpstreamFacade | None = None
        self.bound = False
        self._own_turn_binding = None
        self._owning_hook_lifecycle_ref = os.environ.get('INTEGRITY_OWNING_LIFECYCLE_REF')
        self._binding_loss_receipt_digest: str | None = None
        self._uncertain_append_receipt_digest: str | None = None
        self._last_cleanup_failure_type: str | None = None
        self._pending_context_replay_acks: list[dict[str, str]] = []
        self._context_replay_acks_awaiting_public_delivery: set[str] = set()
        self._turn_envelopes_awaiting_public_delivery: list[tuple[str, str]] = []

    def close(self) -> None:
        upstream = self.upstream
        self.upstream = None
        self.bound = False
        if upstream is not None:
            upstream.close()

    def _observe_upstream_denial(self, name: str, result: dict[str, Any]) -> None:
        """Invalidate local beliefs only; never replay, restore or replace an error."""
        if result.get("isError") is not True and name != "integrity_append_event":
            return
        content = result.get("content")
        if not isinstance(content, list):
            return
        for item in content:
            if not isinstance(item, dict) or item.get("type") != "text":
                continue
            raw = item.get("text")
            if not isinstance(raw, str) or len(raw) > MAX_MESSAGE_BYTES:
                continue
            try:
                value = json.loads(raw)
            except (ValueError, RecursionError):
                continue
            if not isinstance(value, dict):
                continue
            receipt = value.get("receipt", value)
            if not isinstance(receipt, dict):
                continue
            outcome = receipt.get("outcome")
            action_outcome = receipt.get("action_outcome")
            reason = receipt.get("reason")
            lost = result.get("isError") is True and outcome == "denied" and (
                (receipt.get("failure_layer") == "context-binding"
                 and receipt.get("context_binding_state") == "empty")
                or (isinstance(reason, str) and reason in {
                    "append context binding DENY: current logical context is empty",
                    "append context binding DENY: no composite context admission is active",
                })
            )
            uncertain = name == "integrity_append_event" and any(
                isinstance(candidate, str) and candidate in {"unknown", "unknown-outcome"}
                for candidate in (outcome, action_outcome)
            )
            if not lost and not uncertain:
                continue
            # Observation references are not canonical receipt IDs. ASCII escaping
            # also permits valid JSON containing unpaired Unicode surrogates.
            reference_fields = {
                key: value for key, value in receipt.items()
                if key in {"protocol", "tool", "outcome", "action_outcome", "reason", "reason_code",
                           "arguments_digest", "context_binding_state", "logical_generation"}
                and isinstance(value, (str, int, bool))
            }
            reference = "sha256:" + hashlib.sha256(json.dumps(
                reference_fields, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            ).encode("ascii")).hexdigest()
            if lost:
                self.bound = False
                self._binding_loss_receipt_digest = reference
            if uncertain:
                self._uncertain_append_receipt_digest = reference

    def _new_upstream(
        self,
        context_replay_reservation_id: str | None = None,
    ) -> UpstreamFacade:
        command, environment, cwd = _load_upstream(
            self.config_path,
            self.upstream_server,
        )
        return UpstreamFacade(
            command,
            environment,
            cwd,
            self.tools_contract,
            self.initialize_params,
            context_replay_reservation_id,
        )

    def _open_upstream(
        self,
        context_replay_reservation_id: str | None = None,
    ) -> None:
        self.close()
        self.upstream = self._new_upstream(context_replay_reservation_id)

    def _denial(self, name: str, exc: BrokerError) -> dict[str, Any]:
        write_outcome_unknown = (
            name in {
                "integrity_append_event", "integrity_turn_memory_open",
                "integrity_turn_memory_close", "integrity_turn_memory_gap",
            } and exc.request_sent
        )
        safe_current_turn_retry = (
            name == CURRENT_TURN_CONTEXT_TOOL
            and not exc.request_sent
            and exc.layer == "broker-upstream"
        )
        value = {
            "protocol": "integrity-client/turn-broker-denial/v1",
            "outcome": "unknown" if write_outcome_unknown else "denied",
            "failure_layer": exc.layer,
            "tool": name,
            "reason": str(exc)[:500],
            "request_sent": exc.request_sent,
            "automatic_retry_allowed": safe_current_turn_retry,
            "canonical_writes": "unknown" if write_outcome_unknown else 0,
            "production_authority": False,
        }
        if safe_current_turn_retry:
            value["retry_disposition"] = "exact-envelope-after-pre-send-transport"
        if write_outcome_unknown and name in STANDALONE_TURN_MEMORY_TOOLS:
            value["reconciliation_required"] = True
            value["retry_disposition"] = "readback-before-any-new-lifecycle-request"
        if exc.layer == "broker-context-lost":
            value["primary_denial_reference"] = self._binding_loss_receipt_digest
            value["coverage_disposition"] = "preserve-registration-and-gap"
        if exc.layer == "broker-append-uncertain":
            value["prior_canonical_write_outcome"] = "unknown"
            value["primary_denial_reference"] = self._uncertain_append_receipt_digest
            value["reconciliation_required"] = True
        trace = getattr(exc, "lifecycle_stage_evidence", None)
        if isinstance(trace, dict) and len(_json_bytes(trace)) <= 4096:
            # Diagnostic only: never evidence of a commit or authority to retry.
            value["lifecycle_stage_evidence"] = trace
        return {
            "content": [{"type": "text", "text": _json_bytes(value).decode("utf-8")}],
            "isError": True,
        }

    @staticmethod
    def _digest(value: Any) -> str:
        return "sha256:" + hashlib.sha256(_json_bytes(value)).hexdigest()

    def _ack_pending_context_replays(
        self,
        upstream: UpstreamFacade | None = None,
    ) -> None:
        target = self.upstream if upstream is None else upstream
        if target is None or not self._pending_context_replay_acks:
            return
        remaining: list[dict[str, str]] = []
        pending = list(self._pending_context_replay_acks)
        for index, acknowledgement in enumerate(pending):
            if (
                acknowledgement["replay_id"]
                in self._context_replay_acks_awaiting_public_delivery
            ):
                remaining.append(acknowledgement)
                continue
            try:
                acknowledge = getattr(
                    target,
                    "acknowledge_context_admission_replay",
                    None,
                )
                if callable(acknowledge):
                    request_ack_safe = bool(
                        getattr(
                            target,
                            "context_admission_replay_ack_request_safe",
                            getattr(target, "context_admission_replay_safe", False),
                        )
                    )
                else:
                    request_ack_safe = False
                if callable(acknowledge) and request_ack_safe:
                    if acknowledge(acknowledgement) is not True:
                        remaining.append(acknowledgement)
                else:
                    target.notify(
                        CONTEXT_ADMISSION_REPLAY_ACK_NOTIFICATION,
                        acknowledgement,
                    )
            except BrokerError as exc:
                if exc.retryable:
                    remaining.extend(pending[index:])
                    self._pending_context_replay_acks = remaining
                    raise
                try:
                    target.notify(
                        CONTEXT_ADMISSION_REPLAY_ACK_NOTIFICATION,
                        acknowledgement,
                    )
                except BrokerError:
                    remaining.extend(pending[index:])
                    break
        self._pending_context_replay_acks = remaining

    def _context_admission(
        self,
        arguments: dict[str, Any],
        *,
        defer_replay_ack_until_public_delivery: bool = False,
    ) -> dict[str, Any]:
        """Rotate one logical context, reconnecting the transport at most once."""

        first_error: BrokerError | None = None
        request_ever_sent = False
        replay_id = "sha256:" + secrets.token_hex(32)
        replay_arguments: dict[str, Any] | None = None
        for attempt in range(2):
            replay_after_send = False
            admission_call_started = False
            try:
                if self.upstream is None:
                    self._open_upstream(replay_id)
                    assert self.upstream is not None
                    replay_after_send = bool(
                        getattr(
                            self.upstream,
                            "context_admission_replay_safe",
                            False,
                        )
                    )
                    self._ack_pending_context_replays()
                    if not replay_after_send:
                        reserve = getattr(
                            self.upstream,
                            "reserve_context_admission_replay",
                            None,
                        )
                        replay_after_send = bool(
                            callable(reserve)
                            and getattr(
                                self.upstream,
                                "context_admission_replay_contract_safe",
                                getattr(
                                    self.upstream,
                                    "context_admission_replay_safe",
                                    False,
                                ),
                            )
                            and reserve(replay_id)
                        )
                else:
                    self._ack_pending_context_replays()
                    reserve = getattr(
                        self.upstream,
                        "reserve_context_admission_replay",
                        None,
                    )
                    replay_after_send = bool(
                        callable(reserve)
                        and getattr(
                            self.upstream,
                            "context_admission_replay_contract_safe",
                            getattr(
                                self.upstream,
                                "context_admission_replay_safe",
                                False,
                            ),
                        )
                        and reserve(replay_id)
                    )
                assert self.upstream is not None
                if replay_arguments is not None and not replay_after_send:
                    raise BrokerError(
                        "replacement upstream did not retain replay contract",
                        layer="broker-upstream",
                    )
                if replay_after_send:
                    if replay_arguments is None:
                        replay_arguments = {**arguments, CONTEXT_ADMISSION_REPLAY_FIELD: replay_id}
                    call_arguments = replay_arguments
                else:
                    call_arguments = arguments
                admission_call_started = True
                result = self.upstream.call_tool(
                    "integrity_context_admission",
                    call_arguments,
                )
                if replay_after_send:
                    acknowledgement = {
                        "replay_id": replay_id,
                        "request_digest": self._digest(arguments),
                        "response_digest": self._digest(result),
                    }
                    if acknowledgement not in self._pending_context_replay_acks:
                        self._pending_context_replay_acks.append(acknowledgement)
                    if defer_replay_ack_until_public_delivery:
                        self._context_replay_acks_awaiting_public_delivery.add(
                            replay_id
                        )
                return result
            except BrokerError as exc:
                request_ever_sent = request_ever_sent or (
                    admission_call_started and exc.request_sent
                )
                self.close()
                if (
                    attempt
                    or not exc.retryable
                    or (
                        admission_call_started
                        and exc.request_sent
                        and not replay_after_send
                    )
                ):
                    terminal_error = exc
                    if exc.request_sent != request_ever_sent:
                        terminal_error = BrokerError(
                            str(exc),
                            layer=exc.layer,
                            request_sent=request_ever_sent,
                            retryable=exc.retryable,
                        )
                        if request_ever_sent:
                            terminal_error.add_note(
                                "an earlier replay-protected admission attempt sent request bytes"
                            )
                        else:
                            terminal_error.add_note(
                                "only upstream initialization bytes were sent"
                            )
                    if first_error is not None:
                        terminal_error.add_note(
                            f"context admission reconnect followed: {first_error}"
                        )
                    raise terminal_error
                first_error = exc
        raise AssertionError("unreachable context admission retry state")

    @staticmethod
    def _read_seal_retry(result: dict[str, Any]) -> bool:
        """Accept only the upstream's explicit pre-admission checkpoint denial."""
        if result.get("isError") is not True:
            return False
        content = result.get("content")
        if not isinstance(content, list) or len(content) != 1:
            return False
        block = content[0]
        if not isinstance(block, dict) or block.get("type") != "text":
            return False
        try:
            document = json.loads(block["text"])
        except (KeyError, TypeError, ValueError):
            return False
        receipt = document.get("receipt") if isinstance(document, dict) else None
        return isinstance(receipt, dict) and all(
            type(receipt.get(key)) is type(value) and receipt.get(key) == value
            for key, value in {
                "tool": "integrity_context_admission",
                "outcome": "denied",
                "failure_layer": "read-plane-initialization",
                "reason_code": "seed_catalog_checkpoint_required",
                "read_plane_status": "unavailable",
                "automatic_retry_allowed": True,
                "canonical_writes": 0,
                "retry_disposition": "exact-envelope-after-supported-read-seal",
            }.items()
        )

    def _resolve_current_turn(
        self, arguments: dict[str, Any],
    ) -> tuple[str, str, dict[str, Any]]:
        unknown = set(arguments) - {"turn_ref", "budget", "limit"}
        turn_ref = arguments.get("turn_ref")
        if unknown or not isinstance(turn_ref, str):
            raise BrokerError(
                "current-turn admission arguments are invalid",
                layer="broker-envelope",
            )
        if "budget" in arguments and "limit" in arguments:
            raise BrokerError(
                "budget and limit are mutually exclusive",
                layer="broker-envelope",
            )
        try:
            prompt, envelope, claim_id = turn_envelope.resolve(turn_ref)
        except (OSError, turn_envelope.TurnEnvelopeError) as exc:
            raise BrokerError(str(exc), layer="broker-envelope") from exc
        self._own_turn_binding = {'hashes': envelope.get('native_identity_hashes'),
            'intent_id': envelope.get('registration_intent_id'),
            'prompt_sha256': envelope['prompt_sha256'], 'generation': envelope['generation'],
            'admitted': False, 'turn_ref_digest': envelope['turn_ref_digest'],
            'project_scope_sha256': envelope.get('project_scope_sha256')}
        binding = {
            key: envelope[key]
            for key in (
                "protocol",
                "turn_ref_digest",
                "prompt_sha256",
                "prompt_bytes",
                "segment_count",
                "prompt_coverage",
                "truncation",
                "generation",
            )
        }
        expanded: dict[str, Any] = {
            "intent": prompt,
            "_integrity_turn_binding": binding,
        }
        if "project_scope" in envelope:
            binding["project_scope"] = envelope["project_scope"]
            binding["project_scope_sha256"] = envelope["project_scope_sha256"]
        for key in ("budget", "limit"):
            if key in arguments:
                expanded[key] = arguments[key]
        try:
            expanded['_integrity_read_session'] = _reader_session_module.issue(envelope, product='codex')
        except (ValueError, KeyError, TypeError):
            turn_envelope.release_claim(turn_ref, claim_id)
            self._own_turn_binding = None
            raise BrokerError('own_read_session_unavailable', layer='broker-envelope') from None
        return turn_ref, claim_id, expanded

    def _standalone_turn_memory_call(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Run one idempotent lifecycle call on an isolated, retryable transport."""
        self._consumed_owning_lifecycle_claims = None
        self._check_own_lifecycle(name, arguments)

        if self.upstream is not None:
            try:
                self._ack_pending_context_replays()
            except BrokerError as exc:
                # A request-based ACK transport fault desynchronizes only the
                # admitted stream. The lifecycle call remains independently
                # idempotent and can continue on its isolated transport.
                try:
                    self.close()
                except Exception as cleanup_error:
                    self._last_cleanup_failure_type = type(cleanup_error).__name__
                    exc.add_note(f"secondary cleanup failed: {type(cleanup_error).__name__}")
        first_error: BrokerError | None = None
        for attempt in range(2):
            target: UpstreamFacade | None = None
            primary_error: BrokerError | None = None
            lifecycle_call_started = False
            stage = "before-upstream-initialize"
            request_id = None
            transport_pid = None
            request_digest = None
            try:
                cleanup_reservation_id = (
                    self._pending_context_replay_acks[0]["replay_id"]
                    if self._pending_context_replay_acks
                    else None
                )
                target = self._new_upstream(cleanup_reservation_id)
                stage = "upstream-initialized"
                transport_pid = getattr(getattr(target, "process", None), "pid", None)
                self._ack_pending_context_replays(target)
                stage = "replay-acks-complete"
                claims = self._consumed_owning_lifecycle_claims
                if claims is not None:
                    try:
                        turn_envelope.revalidate_consumed_own_lifecycle(claims,name,arguments)
                    except (OSError,ValueError,ImportError,turn_envelope.TurnEnvelopeError):
                        raise BrokerError('owning_hook_lifecycle_superseded_before_send',
                            layer='broker-owning-lifecycle',request_sent=False,retryable=False) from None
                lifecycle_call_started = True
                stage = "lifecycle-call-entered"
                request_id = getattr(target, "_next_id", None)
                request_digest = self._digest({"jsonrpc":"2.0", "id":request_id,
                    "method":"tools/call", "params":{"name":name, "arguments":arguments}})
                # Do not attribute initialize/list response bytes to this call.
                target._last_response_stage = "lifecycle-write-not-complete"
                target._last_response_bytes = None
                return target.call_tool(name, arguments)
            except BrokerError as exc:
                if not lifecycle_call_started and exc.request_sent:
                    # initialize/list/ACK sending is not a lifecycle side effect.
                    exc = BrokerError(
                        "turn-memory pre-dispatch transport fault", layer=exc.layer,
                        request_sent=False, retryable=exc.retryable,
                    )
                primary_error = exc
                binding = self._own_turn_binding
                hashes = binding.get("hashes", {}) if isinstance(binding, dict) else {}
                exc.lifecycle_stage_evidence = {
                    "protocol":"integrity-client/lifecycle-stage-evidence/v1",
                    "stage":stage, "attempt":attempt+1,
                    "broker_pid":os.getpid(), "transport_pid":transport_pid,
                    "upstream_request_id":request_id, "upstream_request_digest":request_digest,
                    "arguments_digest":self._digest(arguments),
                    "thread_id_sha256":hashes.get("thread_id"),
                    "turn_id_sha256":hashes.get("turn_id"),
                    "lifecycle_call_entered":lifecycle_call_started,
                    "request_sent":exc.request_sent,
                    "response_stage":getattr(target,"_last_response_stage","unobserved"),
                    "response_bytes":getattr(target,"_last_response_bytes",None),
                    "accepted_result_returned":False, "provider_commit":"unobserved",
                    "diagnostic_only":True, "retry_authority":False,
                }
                if attempt or not exc.retryable or (
                    exc.request_sent and name != "integrity_turn_memory_coverage"
                ):
                    if first_error is not None:
                        exc.add_note(f"turn-memory reconnect followed: {first_error}")
                    raise
                first_error = exc
            finally:
                if target is not None:
                    try:
                        target.close()
                    except Exception as cleanup_error:
                        self._last_cleanup_failure_type = type(cleanup_error).__name__
                        if primary_error is not None:
                            primary_error.add_note(
                                f"secondary cleanup failed: {type(cleanup_error).__name__}"
                            )
        raise AssertionError("unreachable Turn Memory retry state")

    def _adopt_admitted_own_binding(self, result):
        binding = self._own_turn_binding
        if not isinstance(binding, dict):
            return
        binding['admitted'] = False
        try:
            content = result['content']
            if result.get('isError') is True or len(content) != 1 or content[0]['type'] != 'text':
                return
            value = json.loads(content[0]['text'])
            prompt = value['prompt_binding']
            valid = (value['protocol'] in {'integrity-client-memory-mcp/v3/context-admission/v1',
                                          'integrity-client-memory-mcp/v3/context-admission/v2'}
                and re.fullmatch(r'sha256:[a-f0-9]{64}', value['context_admission_id']) is not None
                and value['snapshot']['immutable'] is True
                and value['snapshot']['source_namespace'] == _integrity_value('seed_namespace')
                and value['home_record_count'] == 0 and value['production_authority'] is False
                and prompt['prompt_sha256'] == binding['prompt_sha256']
                and prompt['generation'] == binding['generation']
                and prompt['turn_ref_digest'] == binding['turn_ref_digest']
                and prompt['truncation'] is False
                and (binding['project_scope_sha256'] is None or
                     prompt.get('project_scope_sha256') == binding['project_scope_sha256']))
            if valid:
                binding['admitted'] = True
                binding['context_admission_id'] = value['context_admission_id']
        except (KeyError, TypeError, ValueError, RecursionError):
            return

    @staticmethod
    def _own_registration_content(state, binding):
        # Verify the content-addressed signed registration's COMPLETE subject.
        # The canonical service independently verifies its stored Ed25519
        # signature/row join before mutation. This is not a local signature claim.
        try:
            receipt = state['turn_memory_registration_receipt']
            unsigned = {k:v for k,v in receipt.items() if k not in {'signature','receipt_id'}}
            raw = json.dumps(unsigned,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
            expected = 'sha256:' + hashlib.sha256(b'turn-memory-registration-v1\0' + raw).hexdigest()
            identity = receipt['identity']
            hashes = binding['hashes']
            return (set(identity) == {'machine_id','thread_id','turn_id','intent_id'}
                and receipt['protocol'] == 'integrity-guardian/turn-memory-registration/v1'
                and receipt['receipt_id'] == expected == state['turn_memory_registration_id']
                and receipt['namespace_fingerprint'] == state['turn_memory_namespace_fingerprint']
                    == _integrity_value('pin_dd9fa64be3f2')
                and receipt['prompt_sha256'] == binding['prompt_sha256']
                and identity['intent_id'] == binding['intent_id']
                and all(hashlib.sha256(identity[key].encode()).hexdigest() == hashes[key]
                        for key in ('machine_id','thread_id','turn_id'))
                and receipt['signature']['algorithm'] == 'ed25519'
                and receipt['terminal_required'] is True and receipt['production_authority'] is False)
        except (KeyError, TypeError, ValueError, AttributeError):
            return False

    def _check_own_lifecycle(self, name, arguments):
        if name == 'integrity_turn_memory_coverage':
            return
        if 'recovery_binding' in arguments and self._owning_hook_lifecycle_ref is None:
            raise BrokerError('historical_context_requires_protected_owning_factory', layer='broker-owning-lifecycle')
        if self._owning_hook_lifecycle_ref is not None:
            ref=self._owning_hook_lifecycle_ref
            self._owning_hook_lifecycle_ref=None
            try:
                self._consumed_owning_lifecycle_claims = turn_envelope.consume_owning_lifecycle(ref,name,arguments)
            except (OSError,ValueError,ImportError,turn_envelope.TurnEnvelopeError):
                raise BrokerError('owning_hook_lifecycle_handoff_invalid',layer='broker-owning-lifecycle') from None
            return
        binding = self._own_turn_binding
        if (not isinstance(binding, dict) or binding.get('admitted') is not True
                or name == 'integrity_turn_memory_open' and not self.bound):
            raise BrokerError('owning_admitted_binding_required', layer='broker-owning-lifecycle')
        if not isinstance(binding, dict) or not isinstance(binding.get('hashes'), dict):
            raise BrokerError('owning_turn_binding_required', layer='broker-owning-lifecycle')
        hashes = binding['hashes']
        sha = lambda value: hashlib.sha256(value.encode('utf-8')).hexdigest()
        if name == 'integrity_turn_memory_open':
            expected = {'machine_id','thread_id','turn_id','intent_id','prompt_sha256'}
            if (set(arguments) != expected or arguments.get('intent_id') != binding['intent_id']
                    or re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',arguments.get('turn_id','')) is None
                    or arguments.get('prompt_sha256') != binding['prompt_sha256']
                    or any(not isinstance(arguments.get(key), str) or sha(arguments[key]) != hashes.get(key)
                           for key in ('machine_id','thread_id','turn_id'))):
                raise BrokerError('foreign_registration_open_denied', layer='broker-owning-lifecycle')
            return
        if name not in {'integrity_turn_memory_close','integrity_turn_memory_gap'}:
            raise BrokerError('owning_lifecycle_tool_invalid', layer='broker-owning-lifecycle')
        root = Path(os.environ.get('INTEGRITY_CLIENT_STATE_ROOT', str(Path.home()/'.codex/integrity-memory/state')))
        path = root / (hashes['thread_id'] + '.json')
        try:
            if path.is_symlink() or not path.is_file():
                raise ValueError('state unavailable')
            state = json.loads(path.read_bytes())
            valid = (state.get('turn_memory_registration_id') == arguments.get('registration_id')
                and ('model_mcp_context_admission_id' not in state or
                     state['model_mcp_context_admission_id'] == binding.get('context_admission_id'))
                and self._own_registration_content(state,binding)
                and state.get('prompt_sha256') == binding['prompt_sha256']
                and state.get('turn_memory_generation') == binding['generation']
                and state.get('turn_memory_intent_id') == binding['intent_id']
                and isinstance(state.get('turn_id'), str) and sha(state['turn_id']) == hashes['turn_id'])
        except (OSError, ValueError, KeyError, TypeError):
            valid = False
        if not valid:
            raise BrokerError('foreign_or_historical_close_requires_owning_recovery', layer='broker-owning-lifecycle')

    def dispatch(
        self,
        message: dict[str, Any],
        *,
        defer_replay_ack_until_public_delivery: bool = False,
    ) -> dict[str, Any] | None:
        request_id = message.get("id")
        method = message.get("method")
        if message.get("jsonrpc") != "2.0" or not isinstance(method, str):
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32600, "message": "invalid request"},
            }
        if method.startswith("notifications/") or "id" not in message:
            return None
        params = message.get("params", {})
        if not isinstance(params, dict):
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32602, "message": "params must be an object"},
            }
        if method == "initialize":
            self.initialize_params = dict(params)
            requested = params.get("protocolVersion")
            protocol = requested if isinstance(requested, str) else DEFAULT_MCP_VERSION
            result = {
                "protocolVersion": protocol,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": BROKER_NAME, "version": BROKER_VERSION},
                "instructions": (
                    SERVER_INSTRUCTIONS
                    if CURRENT_TURN_CONTEXT_TOOL in self.tool_names
                    else LEGACY_SERVER_INSTRUCTIONS
                ),
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": self.tools_contract}
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(name, str) or not isinstance(arguments, dict):
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32602, "message": "invalid tool call"},
                }
            if name not in self.tool_names:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32602, "message": "unknown tool"},
                }
            try:
                if name in STANDALONE_TURN_MEMORY_TOOLS:
                    result = self._standalone_turn_memory_call(name, arguments)
                    return {"jsonrpc": "2.0", "id": request_id, "result": result}
                if name in {"integrity_context_admission", CURRENT_TURN_CONTEXT_TOOL}:
                    # A new owner intent supersedes the preceding context, so
                    # its response no longer needs transport-loss replay.
                    self.bound = False
                    self._own_turn_binding = None
                    turn_ref: str | None = None
                    claim_id: str | None = None
                    admission_arguments = arguments
                    if name == CURRENT_TURN_CONTEXT_TOOL:
                        turn_ref, claim_id, admission_arguments = (
                            self._resolve_current_turn(arguments)
                        )
                    elif set(arguments) - {"intent", "budget", "limit"}:
                        raise BrokerError(
                            "legacy admission accepts only public intent/budget/limit fields",
                            layer="broker-envelope",
                        )
                    result = self._context_admission(
                        admission_arguments,
                        defer_replay_ack_until_public_delivery=(
                            defer_replay_ack_until_public_delivery
                        ),
                    )
                    self.bound = result.get("isError") is not True
                    if self.bound:
                        self._binding_loss_receipt_digest = None
                        self._adopt_admitted_own_binding(result)
                    if turn_ref is not None and claim_id is not None:
                        if self._read_seal_retry(result):
                            try:
                                turn_envelope.release_claim(turn_ref, claim_id)
                            except (OSError, turn_envelope.TurnEnvelopeError) as error:
                                raise BrokerError(
                                    "read-seal retry claim could not be released",
                                    layer="broker-envelope",
                                    request_sent=True,
                                    retryable=False,
                                ) from error
                            turn_ref = claim_id = None
                        elif defer_replay_ack_until_public_delivery:
                            pending = (turn_ref, claim_id)
                            if pending not in self._turn_envelopes_awaiting_public_delivery:
                                self._turn_envelopes_awaiting_public_delivery.append(pending)
                        else:
                            delivered_ref, delivered_claim = turn_ref, claim_id
                            turn_ref = claim_id = None
                            self._consume_delivered_turn_envelope(
                                delivered_ref,
                                delivered_claim,
                            )
                    return {"jsonrpc": "2.0", "id": request_id, "result": result}
                elif name == "integrity_append_event" and self._uncertain_append_receipt_digest:
                    raise BrokerError(
                        "append outcome unresolved; reconcile through owning writer before further writes",
                        layer="broker-append-uncertain",
                        request_sent=False, retryable=False,
                    )
                elif self.upstream is None or not self.bound:
                    if self.upstream is not None:
                        try:
                            self._ack_pending_context_replays()
                        except BrokerError as exc:
                            raise BrokerError(
                                str(exc),
                                layer=exc.layer,
                                request_sent=False,
                                retryable=exc.retryable,
                            ) from exc
                    raise BrokerError(
                        ("upstream logical context was lost; delivered admission has no supported reattach"
                         if self._binding_loss_receipt_digest else
                         "current intent has no admitted upstream facade"),
                        layer=("broker-context-lost" if self._binding_loss_receipt_digest else
                               "broker-binding-missing"),
                    )
                assert self.upstream is not None
                try:
                    self._ack_pending_context_replays()
                except BrokerError as exc:
                    raise BrokerError(
                        str(exc),
                        layer=exc.layer,
                        request_sent=False,
                        retryable=exc.retryable,
                    ) from exc
                result = self.upstream.call_tool(name, arguments)
                self._observe_upstream_denial(name, result)
            except BrokerError as exc:
                if name == "integrity_append_event" and exc.request_sent:
                    self._uncertain_append_receipt_digest = self._digest({
                        "tool": name, "arguments_digest": self._digest(arguments),
                        "outcome": "unknown", "failure_layer": exc.layer,
                    })
                if (
                    name == CURRENT_TURN_CONTEXT_TOOL
                    and turn_ref is not None
                    and claim_id is not None
                ):
                    if not exc.request_sent and exc.layer == "broker-upstream":
                        try:
                            turn_envelope.release_claim(turn_ref, claim_id)
                            turn_ref = claim_id = None
                        except (OSError, turn_envelope.TurnEnvelopeError) as release_error:
                            exc = BrokerError(
                                "pre-send turn envelope claim could not be released",
                                layer="broker-envelope",
                                request_sent=False,
                                retryable=False,
                            )
                            exc.add_note(str(release_error))
                    elif defer_replay_ack_until_public_delivery:
                        pending = (turn_ref, claim_id)
                        if pending not in self._turn_envelopes_awaiting_public_delivery:
                            self._turn_envelopes_awaiting_public_delivery.append(pending)
                        turn_ref = claim_id = None
                    else:
                        delivered_ref, delivered_claim = turn_ref, claim_id
                        turn_ref = claim_id = None
                        try:
                            self._consume_delivered_turn_envelope(
                                delivered_ref,
                                delivered_claim,
                            )
                        except BrokerError as consume_error:
                            exc = consume_error
                if name not in STANDALONE_TURN_MEMORY_TOOLS and name not in {
                    "integrity_context_admission",
                    CURRENT_TURN_CONTEXT_TOOL,
                } and (
                    exc.retryable or not self._pending_context_replay_acks
                ) and exc.layer not in {"broker-append-uncertain", "broker-context-lost"}:
                    try:
                        self.close()
                    except Exception as cleanup_error:  # noqa: BLE001 - retain the primary error
                        exc.add_note(f"secondary broker cleanup failed: {type(cleanup_error).__name__}")
                result = self._denial(name, exc)
        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "method not found"},
            }
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _consume_delivered_turn_envelope(
        self,
        turn_ref: str,
        claim_id: str,
    ) -> None:
        try:
            turn_envelope.commit(turn_ref, claim_id)
            return
        except (OSError, turn_envelope.TurnEnvelopeError) as commit_error:
            # The response was already delivered. Never leave its exact
            # prompt armed merely because the content-free tombstone failed.
            try:
                turn_envelope.retire(turn_ref)
            except (OSError, turn_envelope.TurnEnvelopeError) as retire_error:
                self.close()
                raise BrokerError(
                    "delivered turn envelope could not be consumed",
                    layer="broker-envelope",
                    request_sent=True,
                    retryable=False,
                ) from retire_error
            self.close()
            raise BrokerError(
                "delivered turn envelope tombstone failed; payload retired",
                layer="broker-envelope",
                request_sent=True,
                retryable=False,
            ) from commit_error

    def confirm_public_response_delivery(self) -> None:
        """Make only responses flushed to the public client eligible for ACK."""

        self._context_replay_acks_awaiting_public_delivery.clear()
        pending = self._turn_envelopes_awaiting_public_delivery
        self._turn_envelopes_awaiting_public_delivery = []
        for turn_ref, claim_id in pending:
            self._consume_delivered_turn_envelope(turn_ref, claim_id)

    def shutdown(self) -> None:
        """Retire delivered replay state only on graceful public EOF."""

        try:
            if self.upstream is None and self._pending_context_replay_acks:
                self._open_upstream(
                    self._pending_context_replay_acks[0]["replay_id"]
                )
            self._ack_pending_context_replays()
        except BrokerError:
            pass
        finally:
            self.close()


def serve(broker: TurnBroker) -> int:
    try:
        while True:
            raw = sys.stdin.buffer.readline(MAX_MESSAGE_BYTES + 1)
            if not raw:
                break
            try:
                if len(raw) > MAX_MESSAGE_BYTES:
                    raise ValueError("request exceeds limit")
                message = json.loads(raw)
                if not isinstance(message, dict):
                    raise TypeError("request must be an object")
                with _public_request_budget():
                    response = broker.dispatch(
                        message,
                        defer_replay_ack_until_public_delivery=True,
                    )
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "parse error"},
                }
            if response is not None:
                payload = _json_bytes(response) + b"\n"
                written_total = 0
                while written_total < len(payload):
                    written = sys.stdout.buffer.write(
                        memoryview(payload)[written_total:]
                    )
                    if (
                        not isinstance(written, int)
                        or isinstance(written, bool)
                        or written <= 0
                        or written > len(payload) - written_total
                    ):
                        raise BrokenPipeError(
                            "public response transport made no progress"
                        )
                    written_total += written
                sys.stdout.buffer.flush()
                try:
                    broker.confirm_public_response_delivery()
                except BrokerError:
                    # The public response is already flushed: do not send a
                    # second response or retry the admitted operation. Drop only
                    # that upstream binding; a later intent may admit afresh on
                    # this same public transport. Keep diagnostics content-free.
                    broker.close()
                    print(
                        "Integrity broker: post-delivery custody failure; binding closed",
                        file=sys.stderr,
                        flush=True,
                    )
        return 0
    finally:
        broker.shutdown()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--upstream-server", required=True)
    parser.add_argument("--tools-contract", type=Path, required=True)
    args = parser.parse_args(argv)
    tools_contract = _load_tools_contract(args.tools_contract)
    return serve(TurnBroker(args.config, args.upstream_server, tools_contract))


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
