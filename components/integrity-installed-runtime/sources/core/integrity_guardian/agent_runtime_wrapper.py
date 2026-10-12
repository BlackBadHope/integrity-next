"""Generic Integrity agent runtime wrapper that can block.

The Codex Memory LTS hook injects policy text and cannot deny a tool.
This wrapper is the enforceable equivalent for Grok Build and any later
vendor: default-deny until a live session admission exists.
"""

from __future__ import annotations

from typing import Any

from .agent_session_gate import (
    HOST_WRAPPER_TOOLS,
    MEDIATED_TOOLS,
    evaluate_mediated_tool,
)

CODEX_MEMORY_LTS_HOOK_CAN_BLOCK = False
WRAPPER_CAN_BLOCK = True


def wrapper_can_block() -> bool:
    return WRAPPER_CAN_BLOCK


def decide_tool_use(
    *,
    tool: str,
    now: str,
    speaker: dict[str, Any] | None = None,
    admission: dict[str, Any] | None = None,
    principal: dict[str, Any] | None = None,
    surface: str = "agent-runtime-wrapper",
) -> dict[str, Any]:
    """Allow or deny one proposed tool. Denial is the success path for safety."""

    return evaluate_mediated_tool(
        tool=tool,
        surface=surface,
        now=now,
        speaker=speaker,
        admission=admission,
        principal=principal,
    )


def default_denied_until_admitted() -> frozenset[str]:
    """Tools the wrapper withholds until Rule 1 succeeds."""

    return frozenset(MEDIATED_TOOLS | HOST_WRAPPER_TOOLS)
