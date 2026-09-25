#!/bin/sh
set -eu
event=${1:?hook event is required}
runtime=${CODEX_HOME:-"$HOME/.codex"}/integrity-memory/integrity-client-admission.py
if [ ! -f "$runtime" ]; then
  printf 'Integrity Linux hook runtime is unavailable: %s\n' "$runtime" >&2
  exit 2
fi
exec python3 "$runtime" --event "$event"
