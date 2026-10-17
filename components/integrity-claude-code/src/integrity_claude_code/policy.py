"""Immutable executor policy and the ONE argv builder derived from it.

The CLI profile is not free-form: every flag comes from this policy, so config and
argv cannot diverge (the descriptor re-derives argv and compares). Every flag below is
DECLARED in the owner-captured ``--help`` of native CLI 2.1.281 (help digest pinned
below); declaration is not behaviour. The native CLI profile is refused unless the
policy pins a retained activation artifact AND the launcher receives that artifact
verified with SDK-backed host acceptance (``activation.verify_activation``).

What argv does NOT switch off (stated, not assumed): managed/admin policy settings,
CLAUDE.md memory loading, built-in plugins. ``--restricted`` ignores user/project/
local settings files only; ``--safe-mode`` is not used because its compatibility
with an explicit ``--mcp-config`` is unproven.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

from .canonical import bounded_int, digest_object, digest_value, identifier, need

SERVER = "integrity"
CATALOG = ("read_file", "write_file", "edit_file", "list_dir")
TOOL_NAMES = tuple(f"mcp__{SERVER}__{name}" for name in CATALOG)
CLI_PROFILE = "claude-cli/v1"
FIXTURE_PROFILE = "offline-fixture/v1"
# Auth method names that denote API-key/provider/helper billing paths; never allowable.
API_OR_PROVIDER = re.compile(r"(?i)api|key|token|console|bedrock|vertex|foundry|gateway|provider|helper|proxy")
CLI_VERSION_DECLARED = "2.1.281"
CLI_HELP_SHA256 = "sha256:06f5c4560d04939252e707e0bdee9c047e50aeb81ad8926a7ba74ec27f2432cd"


def _pattern(value) -> str:
    need(type(value) is str and 0 < len(value) <= 256 and value == value.strip()
         and "\\" not in value and ":" not in value and not value.startswith("/")
         and ".." not in value.split("/") and value.isprintable(), "policy_pattern")
    return value


@dataclass(frozen=True)
class ExecutorPolicy:
    model: str
    allow: tuple            # fnmatch patterns over normalized relative POSIX paths
    max_read_bytes: int
    max_write_bytes: int
    max_list_entries: int
    max_tool_calls: int
    tool_timeout_seconds: int
    relay_python_sha256: str
    relay_script_sha256: str
    expected_api_key_source: str | None = None
    # Owner-declared subscription auth methods the preflight may accept (default: none).
    allowed_auth_methods: tuple = ()
    # Pinned state of each known managed-policy source: (source_id, "absent" | sha256).
    managed_pins: tuple = ()
    # Digest of the retained activation artifact. A pointer only: launches additionally
    # need that artifact verified (binding + SDK host acceptance). None = refused.
    cli_activation_sha256: str | None = None

    def __post_init__(self):
        identifier(self.model, "policy_model")
        need(type(self.allow) is tuple and 0 < len(self.allow) <= 64, "policy_allow")
        for pattern in self.allow:
            _pattern(pattern)
        bounded_int(self.max_read_bytes, 1, 4 * 1024 * 1024, "policy_max_read")
        bounded_int(self.max_write_bytes, 1, 4 * 1024 * 1024, "policy_max_write")
        bounded_int(self.max_list_entries, 1, 10_000, "policy_max_list")
        bounded_int(self.max_tool_calls, 1, 10_000, "policy_max_calls")
        bounded_int(self.tool_timeout_seconds, 1, 600, "policy_tool_timeout")
        digest_value(self.relay_python_sha256, "policy_relay_python")
        digest_value(self.relay_script_sha256, "policy_relay_script")
        need(self.expected_api_key_source is None or identifier(self.expected_api_key_source),
             "policy_api_key_source")
        need(type(self.allowed_auth_methods) is tuple and len(self.allowed_auth_methods) <= 8
             and all(identifier(m) and not API_OR_PROVIDER.search(m) for m in self.allowed_auth_methods),
             "policy_auth_methods")
        need(type(self.managed_pins) is tuple and all(
            type(pin) is tuple and len(pin) == 2 and identifier(pin[0])
            and (pin[1] == "absent" or digest_value(pin[1])) for pin in self.managed_pins),
            "policy_managed_pins")
        if self.cli_activation_sha256 is not None:
            digest_value(self.cli_activation_sha256, "policy_activation")

    def document(self) -> dict:
        return {**self.core_document(), "cli_activation_sha256": self.cli_activation_sha256}

    def core_document(self) -> dict:
        """Everything except the activation pin (the activation artifact binds this)."""
        return {"schema": "integrity-claude-code/policy/v1", "model": self.model,
                "allow": list(self.allow), "max_read_bytes": self.max_read_bytes,
                "max_write_bytes": self.max_write_bytes, "max_list_entries": self.max_list_entries,
                "max_tool_calls": self.max_tool_calls,
                "tool_timeout_seconds": self.tool_timeout_seconds,
                "relay_python_sha256": self.relay_python_sha256,
                "relay_script_sha256": self.relay_script_sha256,
                "expected_api_key_source": self.expected_api_key_source,
                "allowed_auth_methods": list(self.allowed_auth_methods),
                "managed_pins": [list(pin) for pin in self.managed_pins],
                "server": SERVER, "tools": list(TOOL_NAMES), "profile": cli_profile_document()}

    def digest(self) -> str:
        return digest_object("integrity-claude-code-policy-v1", self.document())

    def core_digest(self) -> str:
        return digest_object("integrity-claude-code-policy-core-v1", self.core_document())

    def allows(self, relative: str) -> bool:
        return any(fnmatch.fnmatchcase(relative.lower(), pattern.lower()) for pattern in self.allow)

    def allows_dir(self, relative: str) -> bool:
        """A directory may be listed/named only if some allow pattern can reach below it."""
        if relative == "":
            return True
        probe = relative.lower() + "/"
        for pattern in self.allow:
            literal = pattern.lower()
            for index, char in enumerate(literal):
                if char in "*?[":
                    literal = literal[:index]
                    break
            if literal.startswith(probe) or probe.startswith(literal):
                return True
        return False


def cli_profile_document() -> dict:
    """Normalized tool/permission flags; bound into the policy and the session profile."""
    return {"declared_in_help": CLI_HELP_SHA256, "declared_version": CLI_VERSION_DECLARED,
            "builtin_tools": "none", "mcp": "strict-single-server",
            "restricted": True, "user_project_local_settings": "ignored-by-restricted",
            "permission_mode": "dontAsk", "permission_prompts": "none",
            "allowed_tools": list(TOOL_NAMES), "skills": "disabled", "prompt": "stdin-only",
            "not_disabled_by_argv": ["managed-settings", "claude-md", "builtin-plugins"],
            "live_verified": False}


def cli_profile_blocker(policy: "ExecutorPolicy") -> str | None:
    """Static part of the activation gate: no pinned activation artifact, no launch.

    A pin alone never activates: ``ClaudeRun`` also requires a ``VerifiedActivation``
    for exactly this pin, binary, profile and policy core.
    """
    if policy.cli_activation_sha256 is None:
        return "cli_activation_not_pinned"
    if policy.expected_api_key_source is None or not policy.allowed_auth_methods:
        return "cli_auth_expectation_missing"
    return None


def cli_argv(policy: ExecutorPolicy, *, mode: str, session_id: str, mcp_config: str) -> list:
    need(mode in ("new", "resume"), "run_mode")
    need(type(mcp_config) is str and mcp_config, "mcp_config_path")
    session = ["--session-id", session_id] if mode == "new" else ["--resume", session_id]
    return ["-p", "--output-format", "stream-json", "--verbose", "--input-format", "text",
            "--model", policy.model,
            "--tools", "",                       # help: "" disables all built-in tools
            "--restricted",                      # help: ignores user/project/local settings
            "--strict-mcp-config", "--mcp-config", mcp_config,  # only the relay
            "--disable-slash-commands",          # help: disable all skills
            "--permission-mode", "dontAsk",
            "--permission-prompts", "none",      # help: anything that would prompt is denied
            "--allowedTools", ",".join(TOOL_NAMES),  # exactly the four mediated tools
            *session]
