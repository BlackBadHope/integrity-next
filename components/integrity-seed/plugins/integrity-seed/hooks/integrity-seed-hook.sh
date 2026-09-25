#!/bin/sh
set -eu

event=${1:-}
case "$event" in
  SessionStart|UserPromptSubmit|PostToolUse|PreCompact|PostCompact|SubagentStart|SubagentStop|Stop) ;;
  *) exit 0 ;;
esac

emit_unavailable() {
  reason=${1:-the local runtime failed before it produced a trusted continuity result}
  case "$event" in
    SessionStart|UserPromptSubmit|PostToolUse|SubagentStart)
      printf '%s\n' "{\"hookSpecificOutput\":{\"hookEventName\":\"$event\",\"additionalContext\":\"INTEGRITY MEMORY UNAVAILABLE. $reason; no continuity claim is valid.\"}}"
      ;;
    *)
      printf '%s\n' "{\"continue\":true,\"systemMessage\":\"Integrity Seed unavailable: $reason.\"}"
      ;;
  esac
  exit 0
}

plugin_root=${PLUGIN_ROOT:-}
[ -n "$plugin_root" ] || emit_unavailable 'the trusted plugin root was not provided'
launcher=$plugin_root/skills/integrity-seed/scripts/integrity_seed.py
[ -f "$launcher" ] || emit_unavailable 'the bundled launcher was not found'
provider_guard=$plugin_root/hooks/canonical-provider-guard.py

candidates=""
if [ -n "${INTEGRITY_SEED_PYTHON:-}" ]; then
  case "$INTEGRITY_SEED_PYTHON" in
    /*) candidates=$INTEGRITY_SEED_PYTHON ;;
  esac
fi
if [ "${INTEGRITY_SEED_PYTHON_ONLY:-0}" != "1" ]; then
  candidates="$candidates /usr/bin/python3 /usr/local/bin/python3 /opt/homebrew/bin/python3"
fi

for candidate in $candidates; do
  [ -x "$candidate" ] || continue
  if "$candidate" -X utf8 -I -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)' >/dev/null 2>&1; then
    codex_home=${CODEX_HOME:-${HOME:+$HOME/.codex}}
    if [ -n "$codex_home" ] && [ -f "$provider_guard" ]; then
      provider_marker=$codex_home/integrity-seed/canonical-provider.json
      if "$candidate" -X utf8 -I "$provider_guard" "$provider_marker" >/dev/null 2>&1; then
        exit 0
      fi
    fi
    if output=$("$candidate" -X utf8 -I "$launcher" hook --event "$event" 2>/dev/null); then
      if [ -n "$output" ]; then
        printf '%s\n' "$output"
      fi
      exit 0
    fi
    emit_unavailable
  fi
done

emit_unavailable 'a trusted Python 3.11+ interpreter was not found'
