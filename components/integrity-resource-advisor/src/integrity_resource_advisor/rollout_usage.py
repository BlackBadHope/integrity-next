"""Bounded, content-free usage snapshots from one exact local Codex rollout.

This adapter reads only the caller-selected file up to a boundary fixed before
the read.  Codex rollout ``event_msg/token_count`` records are cumulative thread
observations; they are never summed.  Message, reasoning and tool payloads are
parsed only as enclosing JSON records and are neither retained nor emitted.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from typing import Any

from .metering import AdviceError, digest, identity, integer, symbol

PROTOCOL = "integrity-resource-advisor/local-rollout-usage/v1"
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 2 * 1024 * 1024
MAX_RECORDS = 100_000
COUNTERS = (
    "input_tokens",
    "cached_input_tokens",
    "cache_write_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
    "total_tokens",
)


def _decode(raw: bytes, *, allow_ignored_floats: bool = False) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_LINE_BYTES:
        raise AdviceError("codex-rollout-record-size")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise AdviceError("codex-rollout-duplicate-key")
            result[key] = value
        return result

    def invalid_number(_):
        raise AdviceError("codex-rollout-noninteger-number")

    try:
        options = {"object_pairs_hook": unique, "parse_constant": invalid_number}
        if not allow_ignored_floats:
            options["parse_float"] = invalid_number
        value = json.loads(raw.decode("utf-8"), **options)
    except AdviceError:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise AdviceError("codex-rollout-invalid-json") from exc
    if type(value) is not dict:
        raise AdviceError("codex-rollout-object-required")
    return value


def _safe_text(value: Any, *, code: str, limit: int = 128) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not 0 < len(value.encode("utf-8")) <= limit:
        raise AdviceError(code)
    return value


def _counter(value: Any) -> int | None:
    if value is None:
        return None
    return integer(value)


def _counters(value: Any) -> dict[str, int | None]:
    if type(value) is not dict:
        raise AdviceError("codex-rollout-total-required")
    result = {name: _counter(value.get(name)) for name in COUNTERS}
    inp, cached, write, output, reasoning, total = (result[name] for name in COUNTERS)
    if inp is not None and cached is not None and write is not None and cached + write > inp:
        raise AdviceError("codex-rollout-cache-exceeds-input")
    if output is not None and reasoning is not None and reasoning > output:
        raise AdviceError("codex-rollout-reasoning-exceeds-output")
    if None not in (inp, output, total) and total != inp + output:
        raise AdviceError("codex-rollout-total-inconsistent")
    return result


def _path_digest(path: Path) -> str:
    return "sha256:" + sha256(str(path).encode("utf-8")).hexdigest()


def _source_instance(path: Path, stat: os.stat_result) -> str:
    return identity({"path": _path_digest(path), "device": int(stat.st_dev),
                     "inode": int(stat.st_ino)}, "codex-rollout-source-v1")


def _checkpoint(raw: bytes, *, expected_digest: str) -> dict[str, Any]:
    digest(expected_digest)
    if len(raw) > MAX_LINE_BYTES:
        raise AdviceError("codex-rollout-checkpoint-size")
    document = _decode(raw)
    actual = document.pop("snapshot_digest", None)
    if actual != expected_digest or identity(document, "local-rollout-usage-v1") != expected_digest:
        raise AdviceError("codex-rollout-checkpoint-identity")
    if set(document) != {"protocol", "thread_id", "source", "boundary", "totals", "delta",
                         "last_covered", "completeness", "accounting"}:
        raise AdviceError("codex-rollout-checkpoint-fields")
    if document["protocol"] != PROTOCOL:
        raise AdviceError("codex-rollout-checkpoint-protocol")
    symbol(document["thread_id"])
    if type(document["source"]) is not dict or type(document["boundary"]) is not dict:
        raise AdviceError("codex-rollout-checkpoint-shape")
    digest(document["source"].get("source_instance"))
    integer(document["boundary"].get("bytes"), 0, MAX_SOURCE_BYTES)
    if type(document["totals"]) is not dict or set(document["totals"]) != set(COUNTERS):
        raise AdviceError("codex-rollout-checkpoint-counters")
    _counters(document["totals"])
    document["snapshot_digest"] = actual
    return document


def _read_boundary(path: Path) -> tuple[bytes, os.stat_result, bool]:
    resolved = path.resolve(strict=True)
    before = resolved.stat()
    if not resolved.is_file() or before.st_size > MAX_SOURCE_BYTES:
        raise AdviceError("codex-rollout-source-bound")
    descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise AdviceError("codex-rollout-source-replaced")
        chunks, remaining = [], before.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                raise AdviceError("codex-rollout-source-truncated")
            chunks.append(block)
            remaining -= len(block)
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino) or after.st_size < before.st_size:
            raise AdviceError("codex-rollout-source-changed")
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    return raw, before, not raw or raw.endswith(b"\n")


def snapshot_rollout(path: Path, *, thread_id: str,
                     previous: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read one exact rollout and return a content-free cumulative observation."""
    thread_id = symbol(thread_id)
    resolved = path.resolve(strict=True)
    raw, stat, trailing_complete = _read_boundary(resolved)
    complete_lines = raw.splitlines() if trailing_complete else raw.splitlines()[:-1]
    if len(complete_lines) > MAX_RECORDS:
        raise AdviceError("codex-rollout-record-bound")

    meta = None
    current_turn = None
    turn_states: dict[str, str] = {}
    totals = {name: None for name in COUNTERS}
    high_water = {name: None for name in COUNTERS}
    observed_at = None
    covered_turn = None
    token_events = 0
    companion_records = 0

    for line in complete_lines:
        record = _decode(line, allow_ignored_floats=True)
        kind = record.get("type")
        payload = record.get("payload")
        if kind == "session_meta":
            if type(payload) is not dict or meta is not None:
                raise AdviceError("codex-rollout-session-meta")
            actual_thread = symbol(payload.get("id"))
            if actual_thread != thread_id:
                raise AdviceError("codex-rollout-thread-mismatch")
            meta = {
                "writer_cli_version": _safe_text(payload.get("cli_version"),
                                                 code="codex-rollout-writer-version"),
                "originator": _safe_text(payload.get("originator"),
                                         code="codex-rollout-originator"),
                "writer_source": _safe_text(payload.get("source"),
                                            code="codex-rollout-writer-source"),
                "session_started_at": _safe_text(payload.get("timestamp"),
                                                 code="codex-rollout-timestamp"),
            }
        elif kind == "turn_context" and type(payload) is dict:
            candidate = payload.get("turn_id")
            if candidate is not None:
                current_turn = symbol(candidate)
                turn_states.setdefault(current_turn, "unknown")
        elif kind == "event_msg" and type(payload) is dict:
            event_type = payload.get("type")
            if event_type == "task_started":
                current_turn = symbol(payload.get("turn_id"))
                turn_states[current_turn] = "active"
            elif event_type == "task_complete":
                completed = symbol(payload.get("turn_id"))
                turn_states[completed] = "completed"
                current_turn = completed
            elif event_type == "token_count":
                info = payload.get("info")
                if type(info) is not dict:
                    raise AdviceError("codex-rollout-token-info")
                new = _counters(info.get("total_token_usage"))
                for name in COUNTERS:
                    old_value, new_value = high_water[name], new[name]
                    if old_value is not None and new_value is not None and new_value < old_value:
                        raise AdviceError("codex-rollout-counter-regression-reconcile")
                    if new_value is not None:
                        high_water[name] = new_value
                totals = new
                token_events += 1
                covered_turn = current_turn
                observed_at = _safe_text(record.get("timestamp"),
                                         code="codex-rollout-timestamp")
        elif kind == "token_usage_record":
            # Companion local records are intentionally not mixed with the
            # event_msg/token_count format or counted a second time.
            companion_records += 1

    if meta is None:
        raise AdviceError("codex-rollout-session-meta-missing")

    source_instance = _source_instance(resolved, stat)
    prior_digest = None
    delta_values = {name: None for name in COUNTERS}
    delta_status = "baseline_unavailable"
    if previous is not None:
        if previous["thread_id"] != thread_id:
            raise AdviceError("codex-rollout-checkpoint-thread")
        if previous["source"].get("source_instance") != source_instance:
            raise AdviceError("codex-rollout-source-replaced")
        if previous["boundary"]["bytes"] > stat.st_size:
            raise AdviceError("codex-rollout-source-truncated")
        for name in COUNTERS:
            old_value, new_value = previous["totals"][name], totals[name]
            if old_value is not None and new_value is not None and new_value < old_value:
                raise AdviceError("codex-rollout-counter-regression-reconcile")
            if old_value is not None and new_value is not None:
                delta_values[name] = new_value - old_value
        delta_status = ("observed" if all(delta_values[name] is not None for name in COUNTERS)
                        else "partial-missing-counters")
        prior_digest = previous["snapshot_digest"]

    counter_complete = all(totals[name] is not None for name in COUNTERS)
    turn_state = turn_states.get(covered_turn, "unknown") if covered_turn else "unknown"
    payload = {
        "protocol": PROTOCOL,
        "thread_id": thread_id,
        "source": {
            "kind": "codex-local-rollout-jsonl",
            "record_format": "event_msg/token_count",
            "source_path_digest": _path_digest(resolved),
            "source_instance": source_instance,
            **meta,
        },
        "boundary": {
            "bytes": integer(stat.st_size, 0, MAX_SOURCE_BYTES),
            "complete_records": integer(len(complete_lines), 0, MAX_RECORDS),
            "trailing_record_complete": trailing_complete,
        },
        "totals": totals,
        "delta": {"status": delta_status, "counters": delta_values,
                  "previous_snapshot_digest": prior_digest},
        "last_covered": {"turn_id": covered_turn, "observed_at": observed_at,
                         "turn_state": turn_state},
        "completeness": {
            "thread_counters_complete_to_observation": counter_complete,
            "source_complete_to_boundary": trailing_complete,
            "observation_final": turn_state == "completed" and trailing_complete,
            "scope": "selected-thread-only",
            "child_inventory_complete": False,
            "overall_task_total_complete": False,
        },
        "accounting": {
            "cumulative_snapshots_summed": False,
            "input_tokens_include_cached": True,
            "output_tokens_include_reasoning": True,
            "token_count_records": integer(token_events, 0, MAX_RECORDS),
            "companion_token_usage_records_ignored": integer(companion_records, 0, MAX_RECORDS),
            "quota_percent_is_tokens": False,
            "billing_proof": False,
        },
    }
    result = json.loads(json.dumps(payload))
    result["snapshot_digest"] = identity(payload, "local-rollout-usage-v1")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rollout", required=True, type=Path,
                        help="one exact local rollout JSONL path")
    parser.add_argument("--thread-id", required=True,
                        help="exact thread id expected in session_meta")
    parser.add_argument("--checkpoint", type=Path,
                        help="previous normalized snapshot")
    parser.add_argument("--pin", help="independently retained previous snapshot digest")
    args = parser.parse_args()
    if bool(args.checkpoint) != bool(args.pin):
        parser.error("--checkpoint requires --pin; --pin requires --checkpoint")
    try:
        previous = None
        if args.checkpoint:
            previous = _checkpoint(args.checkpoint.read_bytes(), expected_digest=args.pin)
        result = snapshot_rollout(args.rollout, thread_id=args.thread_id, previous=previous)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    except AdviceError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2) from None
    except OSError:
        print("codex-rollout-io-error", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
