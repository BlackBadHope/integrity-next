# SPDX-License-Identifier: Apache-2.0
"""Codex PostToolUse hook: hand staged bus pointers to the active turn.

Fail-open by design: any problem prints nothing and exits 0, so a bus fault
never blocks or alters a Codex tool call. Only fixed pointer text produced by
relay.codex_prompts is emitted; message bodies stay in SQLite.
"""

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config
import json
import sys

from codex_steer import take_for_hook


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        if payload.get("hook_event_name", "PostToolUse") != "PostToolUse":
            return 0
        thread = payload.get("session_id") or payload.get("thread_id")
        if not isinstance(thread, str):
            return 0
        texts = take_for_hook(thread.strip(), payload.get("turn_id"))
        if texts:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8")
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                                     "additionalContext": "\n\n".join(texts)}},
                             ensure_ascii=False))
    except Exception:
        return 0
    return 0


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
