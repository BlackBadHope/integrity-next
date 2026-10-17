# SPDX-License-Identifier: Apache-2.0
"""Transfer deliberate final Codex message frames, not arbitrary chat text.

This reads only the current configured chat's newly appended assistant final
outputs for message transport. It is not a prior-context or Memory reader.
It transports deliberate text replies to already-notified messages only.
It never performs ACK, interprets tool results or grants action authority.
The receipt identifies a relay observation, not a model-executed write.
"""
from __future__ import annotations

from integrity_llm_bus.configuration import value as _integrity_value, require_config as _integrity_require_config

import hashlib
import json
from pathlib import Path
import re

from bus import _no_duplicate_keys, _reject_constant, _validate_message

FRAME = re.compile(r"LLM_BUS_(REPLY)_BEGIN\s*(\{.*?\})\s*LLM_BUS_\1_END", re.DOTALL)
MAX_LINE = 4 * 1024 * 1024


def parse_frames(text: str, agent: str = "codex") -> list[tuple[str, dict]]:
    matches = list(FRAME.finditer(text))
    if len(matches) > 12:
        raise ValueError("too many reply frames")
    end = 0
    frames = []
    for match in matches:
        if text[end:match.start()].strip():
            return []
        value = json.loads(match.group(2), object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant)
        value = _validate_message(value, agent)
        if value["reply_to"] is None:
            raise ValueError("outbox accepts correlated replies only")
        if re.search(r"crsr_[A-Za-z0-9]{30,}|-----BEGIN .*PRIVATE KEY-----|Bearer\s+[A-Za-z0-9._-]{24,}", value["body"]):
            raise ValueError("credential-like reply text is not transported")
        frames.append((match.group(1), value))
        end = match.end()
    return frames if matches and not text[end:].strip() else []


class CodexOutbox:
    def __init__(self, state_dir: Path, transcript: Path, store, agent: str = "codex"):
        self.state_dir, self.transcript, self.store = state_dir, transcript, store
        self.agent = agent
        self.cursor_path = state_dir / ("codex-outbox-cursor.json" if agent == "codex" else f"{agent}-outbox-cursor.json")
        if self.cursor_path.exists():
            cursor = json.loads(self.cursor_path.read_text(encoding="utf-8"))
            if cursor["path"] != str(transcript):
                raise ValueError("outbox source changed; reconciliation required")
            self.offset = cursor["offset"]
        else:
            self.offset = transcript.stat().st_size
            self.save()

    def save(self):
        tmp = self.cursor_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"path": str(self.transcript), "offset": self.offset}), encoding="utf-8")
        tmp.replace(self.cursor_path)

    def poll(self, notified_ids: set[str]) -> list[dict]:
        outcomes = []
        if self.transcript.stat().st_size < self.offset:
            raise ValueError("outbox transcript shrank; reconciliation required")
        consumed = 0
        with self.transcript.open("rb") as stream:
            stream.seek(self.offset)
            while consumed < 16 * 1024 * 1024:
                start = stream.tell()
                raw = stream.readline(MAX_LINE + 1)
                if not raw:
                    break
                if len(raw) > MAX_LINE:
                    raise ValueError("outbox record exceeds bounded size")
                if not raw.endswith(b"\n"):
                    stream.seek(start)
                    break  # App writer has not committed the complete record.
                consumed += len(raw)
                self.offset = stream.tell()
                try:
                    record = json.loads(raw)
                    payload = record.get("payload", {})
                    if record.get("type") != "response_item" or payload.get("type") != "message" or payload.get("role") != "assistant":
                        continue
                    if payload.get("phase") != "final_answer" and payload.get("channel") != "final":
                        continue
                    text = "".join(c.get("text", "") for c in payload.get("content", []) if c.get("type") == "output_text")
                    frames = parse_frames(text, self.agent)
                    for kind, value in frames:
                        ids = [value["reply_to"]]
                        if any(mid not in notified_ids for mid in ids):
                            raise ValueError("frame is outside notified message ids")
                        with self.store._connection() as db:
                            rows = [db.execute("SELECT recipient FROM messages WHERE id=?", (mid,)).fetchone() for mid in ids]
                        if any(row is None or row["recipient"] != self.agent for row in rows):
                            raise ValueError("frame recipient mismatch")
                        message, duplicate = self.store.post(value)
                        result = {"event": "observed-text-reply", "transport_actor": "relay",
                                  "model_tool_execution": False, "ack_performed": False,
                                  "id": message["id"], "reply_to": message["reply_to"],
                                  "duplicate": duplicate, "body_sha256": hashlib.sha256(message["body"].encode("utf-8")).hexdigest()}
                        result["source_message_id"] = payload.get("id")
                        result["source_record_sha256"] = hashlib.sha256(raw).hexdigest()
                        outcomes.append(result)
                except (ValueError, TypeError, KeyError, AttributeError, json.JSONDecodeError):
                    outcomes.append({"action": "rejected-frame", "record_sha256": hashlib.sha256(raw).hexdigest()})
        self.save()
        if outcomes:
            with (self.state_dir / ("codex-outbox-receipts.jsonl" if self.agent == "codex" else f"{self.agent}-outbox-receipts.jsonl")).open("a", encoding="utf-8") as log:
                for outcome in outcomes:
                    log.write(json.dumps(outcome, ensure_ascii=False) + "\n")
        return outcomes
