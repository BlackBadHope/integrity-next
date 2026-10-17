#!/bin/sh
set -eu
: "${INTEGRITY_CLIENT_MEMORY_CONFIG:?own client configuration is required}"
event=${1:?hook event is required}
harness=${2:?owner-selected harness (codex or claude) is required}
case "$harness" in codex|claude) ;; *) echo "harness must be codex or claude" >&2; exit 2 ;; esac
exec integrity-client-memory --config "$INTEGRITY_CLIENT_MEMORY_CONFIG" common/integrity_scope_synapse --event "$event" --harness "$harness"
