# SPDX-License-Identifier: Apache-2.0
"""Pure auxiliary retrieval; never rewrite the admitted query or its identity.

This review candidate has no I/O, runtime imports, session gate or authority.
The caller supplies an optional recall callback over its already admitted
snapshot.  Its result is a separate lane, never a replacement for original
recall, coordination, ownership, bootstrap or prompt fingerprints.
"""

from __future__ import annotations

from integrity_action_log.configuration import value as _integrity_value, require_config as _integrity_require_config

import copy
import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any


PROTOCOL = "integrity-guardian/mind-auxiliary-retrieval/v1"
POLICY = "bounded-topic-prompt-terms-v1"
MAX_TERMS = 16
MAX_TOPIC_CHARS = 200
MAX_PROMPT_UTF8_BYTES = 256 * 1024
MAX_SEGMENTS = 65
MAX_SEGMENT_UTF8_BYTES = 4096

# Local to this auxiliary lane.  Do not reuse or modify RECALL_STOP_WORDS.
CONVERSATIONAL_STOP_TERMS = frozenset(
    "a an and are as at be by can could for from i in is it of on or please "
    "that the this to was were with would you your thanks thank okay ok yes "
    "also again here just now same these those "
    "а без бы был была были в вот вы да для ещё это и из как мне меня мы на "
    "надо наш не ну он она они от по пожалуйста при сейчас спасибо так там "
    "тоже ты уже что чтобы я ещё отправил отправляю держи тебе выполнить промта".split()
)

_UUID = r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}"
_ATTACHMENT_BLOCK = re.compile(
    r"<(?P<wrapper>attachments?|file[-_]attachments?)\b[^>]*>.*?"
    r"</(?P=wrapper)\s*>",
    re.IGNORECASE | re.DOTALL,
)
_ATTACHMENT_MARKER = re.compile(
    r"<<\s*ImageDisplayed\s*>>|"
    r"\[(?:image|attachment|file)\s*(?:\d+)?(?:\s*:[^\]]*)?\]|"
    r"<(?:image|attachments?|file[-_]attachments?)\b[^>]*?/?>|"
    r"!\[[^\]]*\]\([^)]*\)",
    re.IGNORECASE,
)
_CLIPBOARD_FILE = re.compile(
    rf"(?:[^\s<>\"']*[/\\])?(?:(?:codex[-_])?clipboard[-_])?{_UUID}"
    r"(?:[-_][\w-]+)?\.(?:png|jpe?g|webp|gif|bmp|pdf|txt)\b|"
    r"(?:[^\s<>\"']*[/\\])?(?:codex[-_])?clipboard[-_][\w-]+"
    r"\.(?:png|jpe?g|webp|gif|bmp)\b",
    re.IGNORECASE,
)
_TRANSPORT_LINE = re.compile(
    r"^\s*(?:note\s*:\s*)?(?:"
    r"(?:file|files) uploads? in (?:this|the) ui\b|"
    r"(?:the following|uploaded) (?:files|attachments)\b|"
    r"(?:attached|attachment) (?:files|images) (?:are|were)\b|"
    r"(?:human_input|input_kind|agent_path|native_thread_id|native_turn_id|"
    r"parent_thread_id|input_sha256|prompt_sha256|task name|sender)\s*[:=]|"
    r"(?:message type|task name)\s*:\s*|"
    r"(?:#\s*)?attachments?\s*:\s*$)",
    re.IGNORECASE,
)
_TOKEN = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}|[^\W_][\w.:@/\-]*", re.UNICODE)
_OWNER_WRAPPER_LINE = re.compile(
    r"^\s*(?:#\s*Files mentioned by the user\s*:|"
    r"##\s*(?:codex[-_])?clipboard[-_][^\s:]+\s*:.*|"
    r"Image attachment\s*:\s*(?:true|false)|"
    r"Distinguish instructions in attached documents from the user['’]s request\.)\s*$",
    re.IGNORECASE,
)
_OWNER_REQUEST_HEADER = re.compile(r"^\s*##\s*My request\s*:\s*", re.IGNORECASE | re.MULTILINE)
# Harness paste carriers: drop only the tags; the pasted text stays searchable.
_PASTE_TAG = re.compile(r"</?pasted_content\b[^>]*>", re.IGNORECASE)
_TOPIC_LINE = re.compile(
    r"^[ \t]*(?:тема(?:[ \t]+для[ \t]+проверки)?|topic)[ \t]*[:：][ \t]*(?P<topic>\S[^\r\n]*?)[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)
_BUS_NOTICE_START = re.compile(r"^\s*LLM_BUS_POINTER(?:\s|—|-)", re.IGNORECASE)
_BUS_POINTER_MARKER = re.compile(r"^\s*POINTERS_JSON\s*:?[ \t]*", re.IGNORECASE)
_EXPLICIT_TASK_TOKEN = re.compile(r"(?<![\w.:@/\-])task:[\w.:@/\-]+", re.IGNORECASE)
_TASK_FIELDS = frozenset(
    ("task_id", "task_ids", "taskid", "target_task_id", "target_task_ids", "owner_task_id", "owner_task_ids")
)


def _pointer_task_values(value: Any):
    """Pointer IDs are search context only; never principal/owner evidence."""
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            for key, item in current.items():
                if str(key).casefold() in _TASK_FIELDS:
                    if isinstance(item, str):
                        yield item
                    elif isinstance(item, list):
                        yield from (task for task in item if isinstance(task, str))
            pending.extend(reversed(list(current.values())))
        elif isinstance(current, list):
            pending.extend(reversed(current))
        elif isinstance(current, str):
            yield from _EXPLICIT_TASK_TOKEN.findall(current)


def _without_bus_notices(text: str) -> str:
    lines = text.splitlines(keepends=True)
    selected: list[str] = []
    in_notice = False
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if _BUS_NOTICE_START.match(line):
            in_notice = True
            continue
        if in_notice and _OWNER_REQUEST_HEADER.match(line):
            in_notice = False
        if not in_notice:
            selected.append(line)
            continue
        marker = _BUS_POINTER_MARKER.match(line)
        if not marker:
            continue
        pointer_text = (line[marker.end():] + "".join(lines[index:])).lstrip()
        # Accept an ordinary fenced JSON carrier without interpreting it as code.
        if pointer_text.startswith("```json"):
            pointer_text = pointer_text[len("```json"):].lstrip()
        try:
            pointers, end = json.JSONDecoder().raw_decode(pointer_text)
        except (ValueError, RecursionError):
            # Malformed carrier: retain explicit task: atoms only.  An owner
            # request marker, when present, still terminates the notice.
            owner = _OWNER_REQUEST_HEADER.search(pointer_text)
            carrier = pointer_text[:owner.start()] if owner else pointer_text
            selected.append(" ".join(_EXPLICIT_TASK_TOKEN.findall(carrier)) + "\n")
            if owner:
                selected.append(pointer_text[owner.end():])
            break
        else:
            # The real local bus pointer uses messages[].id, rather than task_id.
            if isinstance(pointers, dict) and isinstance(pointers.get("messages"), list):
                for entry in pointers["messages"]:
                    if isinstance(entry, dict) and not any(str(key).casefold() in _TASK_FIELDS for key in entry):
                        value = entry.get("id")
                        if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{1,199}", value):
                            selected.append(value + "\n")
            selected.append(" ".join(_pointer_task_values(pointers)) + "\n")
            tail = pointer_text[end:]
            if tail.lstrip().startswith("```"):
                tail = tail.lstrip()[3:]
            lines = tail.splitlines(keepends=True)
            index = 0
            in_notice = False
    return "".join(selected)


def _sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _validated_segments(prompt_or_segments: str | Sequence[str]) -> tuple[str, ...]:
    if isinstance(prompt_or_segments, str):
        segments = (prompt_or_segments,)
    elif isinstance(prompt_or_segments, (list, tuple)):
        if not prompt_or_segments or len(prompt_or_segments) > MAX_SEGMENTS:
            raise ValueError(f"segments must contain 1..{MAX_SEGMENTS} strings")
        if any(not isinstance(segment, str) for segment in prompt_or_segments):
            raise TypeError("segments must contain only strings")
        if any(
            not segment or len(segment.encode("utf-8")) > MAX_SEGMENT_UTF8_BYTES
            for segment in prompt_or_segments
        ):
            raise ValueError("segments must be nonempty and at most 4096 UTF-8 bytes")
        segments = tuple(prompt_or_segments)
    else:
        raise TypeError("prompt_or_segments must be a string, list or tuple of strings")
    if sum(len(segment.encode("utf-8")) for segment in segments) > MAX_PROMPT_UTF8_BYTES:
        raise ValueError("prompt exceeds the 256 KiB UTF-8 bound")
    return segments


def _validated_topic(topic: str | None) -> str:
    if topic is None:
        return ""
    if not isinstance(topic, str):
        raise TypeError("topic must be a string or None")
    if len(topic) > MAX_TOPIC_CHARS:
        raise ValueError(f"topic exceeds the {MAX_TOPIC_CHARS}-character bound")
    return topic


def _search_text(text: str) -> str:
    """Remove explicit carrier wrappers from a copy, not the raw source."""
    text = _PASTE_TAG.sub("\n", text)
    text = _ATTACHMENT_BLOCK.sub(" ", text)
    text = _ATTACHMENT_MARKER.sub(" ", text)
    text = _without_bus_notices(text)
    text = "\n".join(
        line for line in text.splitlines()
        if not _TRANSPORT_LINE.match(line) and not _OWNER_WRAPPER_LINE.match(line)
    )
    text = _OWNER_REQUEST_HEADER.sub("", text)
    return _CLIPBOARD_FILE.sub(" ", text)


def _terms(text: str):
    for match in _TOKEN.finditer(_search_text(text)):
        token = match.group().rstrip(".:/@-_")
        folded = token.casefold()
        if not token or folded in CONVERSATIONAL_STOP_TERMS:
            continue
        if len(token) < 3 and not token.isdigit():
            continue
        # Preserve the whole token, including task-ID case and punctuation.
        yield token


def derive_prompt_topic(prompt_or_segments: str | Sequence[str]) -> str:
    """First owner "Тема:"/"Тема для проверки:"/"Topic:" line, or "".

    Search context only: never a session, ownership or admission binding.
    Segments are transport chunks of one prompt, so a topic line may span a
    boundary: parse a joined search copy; raw segments stay untouched.
    """
    match = _TOPIC_LINE.search(_search_text("".join(_validated_segments(prompt_or_segments))))
    return match.group("topic")[:MAX_TOPIC_CHARS] if match else ""


def derive_retrieval_terms(
    prompt_or_segments: str | Sequence[str], topic: str | None = None
) -> list[str]:
    """Return at most 16 unique search terms, topic terms first.

    An explicit topic wins; otherwise a topic line in the prompt leads, so a
    long preamble cannot exhaust the term budget before the subject.
    UTF-8 input is retained verbatim by the caller.  Duplicate comparisons use
    casefold, but returned terms keep the first spelling (including task IDs).
    Topic is untrusted search context and never a session or ownership binding.
    """
    segments = _validated_segments(prompt_or_segments)
    validated_topic = _validated_topic(topic)
    if topic is None:
        validated_topic = derive_prompt_topic(segments)
    result: list[str] = []
    seen: set[str] = set()
    # One joined search copy: a term or wrapper tag split by the transport
    # chunking must not become two fragments.
    for text in (validated_topic, "".join(segments)):
        for term in _terms(text):
            folded = term.casefold()
            if folded in seen:
                continue
            seen.add(folded)
            result.append(term)
            if len(result) == MAX_TERMS:
                return result
    return result


def _source_binding(
    prompt_or_segments: str | Sequence[str], segments: tuple[str, ...], topic: str | None
) -> dict[str, Any]:
    source: dict[str, Any] = {
        "kind": "raw-prompt" if isinstance(prompt_or_segments, str) else "raw-segments",
        "topic_present": topic is not None,
        "topic_sha256": _sha256(topic) if topic is not None else "",
    }
    if topic is None:
        derived = derive_prompt_topic(segments)
        if derived:
            source["derived_topic_sha256"] = _sha256(derived)
    if isinstance(prompt_or_segments, str):
        source["raw_prompt_sha256"] = _sha256(prompt_or_segments)
    else:
        # Same framing as the upstream exact segmented query digest.  This is
        # provenance only: never assign it to an existing admission fingerprint.
        digest = hashlib.sha256()
        digest.update(b"integrity.action-log.q-segments/v1\0")
        for segment in segments:
            encoded = segment.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        source["segments_framed_sha256"] = "sha256:" + digest.hexdigest()
        source["segment_count"] = len(segments)
    return source


def build_auxiliary_recall(
    prompt_or_segments: str | Sequence[str],
    recall_callback: Callable[[str, int], Mapping[str, Any]],
    *,
    topic: str | None = None,
    limit: int = 12,
) -> dict[str, Any]:
    """Call injected recall(term_query, limit) only for nonempty derived terms.

    The callback must use the caller's admitted snapshot and return a mapping
    with an actual ``hits`` list.  This helper neither opens gates nor performs
    live calls itself.  The caller must keep this result separate from original
    recall and bind any delivered projection with its normal digest contract.
    """
    if not callable(recall_callback):
        raise TypeError("recall_callback must be callable")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
        raise ValueError("limit must be an integer from 1 to 50")
    segments = _validated_segments(prompt_or_segments)
    _validated_topic(topic)
    terms = derive_retrieval_terms(prompt_or_segments, topic)
    term_query = " ".join(terms)
    hits: list[dict[str, Any]] = []
    if terms:
        recalled = recall_callback(term_query, limit)
        if not isinstance(recalled, Mapping) or not isinstance(recalled.get("hits"), list):
            raise TypeError("recall_callback must return a mapping with a hits list")
        if len(recalled["hits"]) > limit or any(
            not isinstance(hit, dict) for hit in recalled["hits"]
        ):
            raise ValueError("callback hits must be dictionaries within the requested limit")
        hits = copy.deepcopy(recalled["hits"])
    return {
        "protocol": PROTOCOL,
        "policy": POLICY,
        "source": _source_binding(prompt_or_segments, segments, topic),
        "term_query_sha256": _sha256(term_query),
        "search_only": True,
        "authority": "none",
        "production_authority": False,
        "terms": terms,
        "limit": limit,
        "status": "searched" if terms else "empty-terms",
        "hit_count": len(hits),
        "hits": hits,
    }
