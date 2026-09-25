"""Emit the deterministic Agent A -> B -> C continuity acceptance report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from integrity_guardian.agent_handoff import AgentHandoffError
from integrity_guardian.canonical import canonical_bytes
from integrity_guardian.cross_agent_acceptance_core import CrossAgentAcceptanceError
from integrity_guardian.cross_agent_acceptance_verify import run_acceptance
from integrity_guardian.cross_agent_continuity import CrossAgentContinuityError


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        payload = canonical_bytes(run_acceptance()) + b"\n"
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(payload)
        print(payload.decode(), end="")
        return 0
    except (
        AgentHandoffError,
        CrossAgentAcceptanceError,
        CrossAgentContinuityError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
