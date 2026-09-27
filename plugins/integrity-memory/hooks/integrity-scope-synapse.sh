#!/bin/sh
set -u
event=${1:?hook event is required}
runtime=${CODEX_HOME:-"$HOME/.codex"}/integrity-memory/integrity_scope_synapse.py
if [ -f "$runtime" ] && command -v python3 >/dev/null 2>&1; then
  exec python3 "$runtime" --harness codex --event "$event"
fi
printf 'Integrity scope synapse runtime is unavailable: %s\n' "$runtime" >&2
# Fail closed only for effects; never block the owner's prompt or a session start.
if [ "$event" = PreToolUse ]; then
  printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"INTEGRITY SCOPE SYNAPSE fault: runtime unavailable. Actions stay blocked until the owner repairs the scope synapse."}}'
else
  printf '%s\n' '{}'
fi
exit 0
