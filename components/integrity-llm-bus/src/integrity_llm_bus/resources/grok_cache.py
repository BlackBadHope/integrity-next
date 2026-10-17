# SPDX-License-Identifier: Apache-2.0
"""Observe explicitly marked bus replies in one configured Grok desktop cache.

This is an app-cache adapter, not an official Grok result API. Other conversation
content is never returned or logged. The connector checks reply relationships.
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import json
from pathlib import Path
import re

from bus import MAX_REQUEST_BYTES, _validate_message

MARKER = re.compile(r"LLM_BUS_BEGIN\s*(\{.*?\})\s*LLM_BUS_END", re.DOTALL)
MAX_CACHE_BYTES = 32 * 1024 * 1024


def read_envelopes(path: Path, after_seq: int, seen: set[str]) -> tuple[list[dict], int, set[str]]:
    if path.stat().st_size > MAX_CACHE_BYTES:
        raise ValueError("configured Grok cache exceeds bounded reader size")
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schemaVersion") != 1:
        raise ValueError("unsupported Grok cache schema")
    entries = document.get("value", {}).get("entries")
    if not isinstance(entries, list) or len(entries) > 10000:
        raise ValueError("invalid Grok cache entries")
    output: list[dict] = []
    maximum = after_seq
    next_seen = set(seen)
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        seq, eid = entry.get("seq"), entry.get("id")
        if not isinstance(seq, int) or not isinstance(eid, str):
            continue
        maximum = max(maximum, seq)
        if seq <= after_seq or eid in seen or entry.get("kind") != "send-message":
            continue
        message = entry.get("message", {})
        if message.get("type") != "text" or not isinstance(message.get("content"), str):
            continue
        for match in MARKER.finditer(message["content"]):
            if len(match.group(1).encode("utf-8")) > MAX_REQUEST_BYTES:
                continue
            try:
                value = json.loads(match.group(1))
                value = _validate_message(value, "grok")
            except (ValueError, json.JSONDecodeError, TypeError):
                continue
            output.append(value)
        next_seen.add(eid)
    return output, maximum, next_seen
