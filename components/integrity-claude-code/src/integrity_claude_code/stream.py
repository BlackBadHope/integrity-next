"""Strict, bounded parser for ``claude -p --output-format stream-json --verbose``.

Contract enforced: first event is system/init for the exact session; every event that
names a session names this one; exactly one terminal ``result`` and nothing after it;
no blank, oversized, truncated, non-UTF-8, duplicate-key or non-finite lines.

Nothing untrusted is kept verbatim: provider strings become closed enum members,
equality against trusted expected values, or SHA-256 digests. ``reported_success``
is a provider claim, never verified success.
"""
from __future__ import annotations

from .canonical import Rejected, bounded_int, canonical_bytes, session_uuid, sha256_bytes, strict_loads
from .record import EVENT_TYPES, PERMISSION_MODES, RESULT_SUBTYPES


def _member(value, members: frozenset, fallback: str) -> str:
    return value if type(value) is str and value in members else fallback


def _digest_of(value) -> str | None:
    return sha256_bytes(value.encode("utf-8")) if type(value) is str else None


class ClaudeStream:
    def __init__(self, session_id: str, *, max_line_bytes: int, max_events: int,
                 expected_model: str, expected_tools: tuple, expected_mcp_servers: tuple,
                 expected_version: str | None = None,
                 expected_api_key_source: str | None = None,
                 expected_permission_mode: str | None = None):
        self.session_id = session_uuid(session_id)
        self.max_line = bounded_int(max_line_bytes, 256, 16 * 1024 * 1024, "max_line_bytes")
        self.max_events = bounded_int(max_events, 2, 10_000_000, "max_events")
        self.expected = (expected_model, expected_version, expected_api_key_source)
        self.tools = tuple(sorted(expected_tools))
        self.servers = tuple(sorted(expected_mcp_servers))
        self.permission = expected_permission_mode
        self.tool_uses: dict[str, int] = {}
        self._pending = bytearray()
        self.events = 0
        self.init: dict | None = None
        self.result: dict | None = None
        self._result_raw: bytes | None = None
        self.violation: str | None = None
        self.types: dict[str, int] = {}

    def _fail(self, code: str):
        if self.violation is None:
            self.violation = code
        raise Rejected(code)

    def feed(self, data: bytes) -> None:
        if self.violation is not None:
            raise Rejected(self.violation)
        self._pending.extend(data)
        while True:
            index = self._pending.find(b"\n")
            if index < 0:
                if len(self._pending) > self.max_line:
                    self._fail("line_limit")
                return
            line = bytes(self._pending[:index])
            del self._pending[:index + 1]
            if len(line) > self.max_line:
                self._fail("line_limit")
            self._line(line)

    def _line(self, line: bytes) -> None:
        if self.result is not None:
            if line == self._result_raw:
                self._fail("duplicate_result")
            try:
                later = strict_loads(line, self.max_line)
            except Rejected:
                later = None
            if type(later) is dict and later.get("type") == "result":
                self._fail("conflicting_result")
            self._fail("trailing_after_result")
        if line.endswith(b"\r"):
            line = line[:-1]
        if not line.strip():
            self._fail("blank_line")
        try:
            event = strict_loads(line, self.max_line)
        except Rejected as exc:
            self._fail("malformed_" + exc.code)
        if type(event) is not dict or type(event.get("type")) is not str:
            self._fail("event_shape")
        self.events += 1
        if self.events > self.max_events:
            self._fail("event_limit")
        kind = event["type"]
        name = _member(kind, EVENT_TYPES, "unknown")
        self.types[name] = self.types.get(name, 0) + 1
        if "session_id" in event and event["session_id"] != self.session_id:
            self._fail("session_mismatch")
        if self.init is None:
            if not (kind == "system" and event.get("subtype") == "init"
                    and event.get("session_id") == self.session_id):
                self._fail("missing_init")
            self.init = self._init_summary(event)
            self._check_surface(event)
            return
        if kind == "system" and event.get("subtype") == "init":
            self._fail("duplicate_init")
        if kind == "assistant":
            self._check_tool_uses(event)
        if kind == "result":
            if event.get("session_id") != self.session_id:
                self._fail("session_mismatch")
            text = event.get("result")
            if type(event.get("is_error")) is not bool or type(event.get("subtype")) is not str \
                    or (text is not None and type(text) is not str):
                self._fail("result_shape")
            raw_text = (text or "").encode("utf-8")
            turns = event.get("num_turns")
            self.result = {
                "subtype": _member(event["subtype"], RESULT_SUBTYPES, "unrecognized"),
                "is_error": event["is_error"],
                "num_turns": turns if type(turns) is int and 0 <= turns < 2**31 else None,
                "result_bytes": len(raw_text), "result_sha256": sha256_bytes(raw_text),
                "event_sha256": sha256_bytes(line),
            }
            self._result_raw = line

    def _check_surface(self, event: dict) -> None:
        """Init must match the trusted expectation exactly: else immediate kill.

        This does not replace the pre-launch auth preflight; it detects drift after start.
        """
        model, version, source = self.expected
        if event.get("model") != model:
            self._fail("init_model_mismatch")
        if version is not None and event.get("claude_code_version") != version:
            self._fail("init_version_mismatch")
        if source is not None and event.get("apiKeySource") != source:
            self._fail("init_auth_source_mismatch")
        if self.permission is not None and event.get("permissionMode") != self.permission:
            self._fail("init_permission_mismatch")
        tools = event.get("tools")
        if type(tools) is not list or tuple(sorted(t for t in tools if type(t) is str)) != self.tools \
                or len(tools) != len(self.tools):
            self._fail("init_tools_mismatch")
        servers = event.get("mcp_servers")
        names = [s.get("name") for s in servers if type(s) is dict] if type(servers) is list else None
        if names is None or len(names) != len(servers) or tuple(sorted(
                n for n in names if type(n) is str)) != self.servers or len(names) != len(self.servers):
            self._fail("init_mcp_mismatch")

    def _check_tool_uses(self, event: dict) -> None:
        message = event.get("message")
        content = message.get("content") if type(message) is dict else None
        if type(content) is str:
            return
        if type(content) is not list:
            self._fail("tool_use_shape")
        for block in content:
            if type(block) is not dict or type(block.get("type")) is not str:
                self._fail("tool_use_shape")
            if block["type"] != "tool_use":
                continue
            name = block.get("name")
            if type(name) is not str or name not in self.tools:
                self._fail("uncataloged_tool_use")  # names/arguments are never stored
            short = name.rsplit("__", 1)[1]
            self.tool_uses[short] = self.tool_uses.get(short, 0) + 1

    def _init_summary(self, event: dict) -> dict:
        model, version, key_source = self.expected
        tools = event.get("tools")
        tools = [t for t in tools if type(t) is str] if type(tools) is list else []
        servers = event.get("mcp_servers")
        observed_source = event.get("apiKeySource")
        mode = event.get("permissionMode")
        return {
            "model_matches": event.get("model") == model,
            "version_matches": None if version is None else event.get("claude_code_version") == version,
            "api_key_source_matches": None if key_source is None else observed_source == key_source,
            "api_key_source_sha256": _digest_of(observed_source),
            "permission_mode": "absent" if mode is None else _member(mode, PERMISSION_MODES - {"absent"},
                                                                     "unrecognized"),
            "tools_count": len(tools),
            "tools_sha256": sha256_bytes(canonical_bytes(sorted(tools))),
            "mcp_servers_count": len(servers) if type(servers) is list else 0,
        }

    def finish(self) -> None:
        """Call once after EOF. A dangling partial line is a truncation, not a result."""
        if self.violation is None and self._pending:
            self.violation = "truncated_line"

    def summary(self) -> dict:
        return {"events": self.events, "event_types": dict(sorted(self.types.items())),
                "init": self.init, "result": self.result, "violation": self.violation,
                "tool_uses": dict(sorted(self.tool_uses.items()))}


def classify(stream: dict, job: dict) -> str:
    """Closed classification of one run from facts; provider claims stay claims.

    An error result is recorded as ``reported_error`` whatever the exit code; the exit
    code itself is kept as a separate fact (no provider exit contract is assumed).
    """
    termination = job.get("termination")
    if termination == "cancelled":
        return "cancelled"
    if stream.get("violation"):
        return "protocol_violation"
    if termination in ("stdout_limit", "stderr_limit"):
        return "output_limit"
    if termination == "deadline":
        return "deadline"
    if termination is not None:
        return "supervisor_error"
    if stream.get("init") is None:
        return "missing_init"
    result = stream.get("result")
    if result is None:
        return "missing_result"
    if result["is_error"] or result["subtype"] != "success":
        return "reported_error"
    if job.get("exit_code") != 0:
        return "result_exit_mismatch"
    if not job.get("stdin_complete", False):
        return "stdin_incomplete"
    return "reported_success"
