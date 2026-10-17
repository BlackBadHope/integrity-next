"""Static, offline capability statement. Reading it performs no probe and grants nothing."""
from __future__ import annotations

from . import __version__


def capabilities() -> dict:
    return {
        "schema": "integrity-claude-code/capabilities/v1", "version": __version__,
        "platform": "windows-only runtime (Job Objects, named pipes, handle-verified files)",
        "entrypoints": {
            "launch": "integrity_claude_code.launcher.ClaudeRun (native CLI profile only)",
            "auth_preflight": "integrity_claude_code.auth.preflight_auth",
            "activation": "integrity_claude_code.activation.verify_activation",
            "authority": "integrity_claude_code.authority.SdkAuthority",
            "observer": "integrity_claude_code.observer.observe_workspace / evaluate",
            "terminal_receipt": "integrity_claude_code.observer.terminal_receipt",
            "closure_handoff": "integrity_claude_code.observer.closure_handoff",
            "recover": "integrity_claude_code.authority.recover_attempt",
        },
        "tools": ["read_file", "write_file", "edit_file", "list_dir"],
        "shell_tool": False, "network_tool": False, "subagents": False,
        "billing": "subscription-only; API-key/provider paths refused",
        "authority_source": "genuine Adapter SDK facade only (require_guardian)",
        "writes": "handle-bound in place; mid-write failure is UNKNOWN (not atomic)",
        "isolation": "Job Object process tree; NOT a filesystem/network sandbox; same-account trust",
        "observer": "unsigned local observation; witness/receipt signing is host-supplied",
        "canonical_append": False, "production_authority": False,
        "live_activation_present": False,
    }
