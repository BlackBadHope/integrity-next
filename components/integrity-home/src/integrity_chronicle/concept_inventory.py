"""Deterministic, offline compiler for private concept-recall conversations.

The compiler is deliberately a post-corpus step.  It treats only text written
by the user as a possible concept anchor.  Search hits in assistant messages,
titles, attachments, quoted material, and code remain useful evidence, but
they never become user-owned concepts.

Both generated artifacts are private mode-0600 files.  The receipt contains
only integer counts and SHA-256 digests; paths, record identifiers, locators,
and excerpts exist only in the private inventory.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
import unicodedata

from .json_integrity import DuplicateJsonKeyError, loads_json_strict


RECALL_SCHEMA_VERSION = "integrity-home-private-concept-conversation/1"
INVENTORY_SCHEMA_VERSION = "integrity-home-concept-inventory/1"
RECEIPT_SCHEMA_VERSION = "integrity-home-concept-inventory-receipt/1"
RULES_VERSION = "integrity-home-concept-rules/1"

_OUTER_KEYS = {
    "schema_version",
    "run_id",
    "corpus_id",
    "index_generation",
    "source_id",
    "conversation_id",
    "matched_queries",
    "matched_record_ids",
    "conversation",
}
_CONVERSATION_KEYS = {
    "source_id",
    "provider",
    "provider_schema_version",
    "conversation_id",
    "provider_conversation_id",
    "title",
    "created_at",
    "canonical_conversation",
    "messages",
}
_MESSAGE_KEYS = {
    "record_id",
    "source_id",
    "provider",
    "conversation_id",
    "message_id",
    "parent_message_id",
    "role",
    "model",
    "content_type",
    "created_at",
    "branch_path",
    "content",
    "locator",
    "record_type",
    "provider_schema_version",
    "projection_sha256",
    "provider_conversation_id",
    "conversation_index",
    "message_index",
    "branch_depth",
    "has_unknown_parent",
    "has_unknown_timestamp",
    "content_sha256",
    "canonical_message",
    "attachments",
    "matched_text_leaves",
    "matched_text_leaves_truncated",
    "excluded_text_leaves",
    "authoritative",
    "evidence_only",
    "context",
}
_MESSAGE_LOCATOR_KEYS = {
    "source_id",
    "provider",
    "provider_schema_version",
    "projection_sha256",
    "conversation_id",
    "provider_conversation_id",
    "conversation_index",
    "message_id",
    "message_index",
    "canonical_pointer",
    "record_id",
}
_TITLE_LOCATOR_KEYS = {
    "source_id",
    "provider",
    "provider_schema_version",
    "projection_sha256",
    "conversation_id",
    "provider_conversation_id",
    "conversation_index",
    "canonical_pointer",
    "record_id",
}
_CONTEXT_KEYS = {"previous", "next", "parent", "children", "children_truncated"}
_CANONICAL_MESSAGE_FIELDS = (
    "message_id",
    "parent_message_id",
    "role",
    "model",
    "content_type",
    "created_at",
    "branch_path",
    "branch_depth",
    "has_unknown_parent",
    "has_unknown_timestamp",
    "content",
)
_ALLOWED_QUERIES = {"concept*", "концеп*"}
_KINDS = {
    "project",
    "hypothesis",
    "creative_concept",
    "reference",
    "bulk_context",
    "quarantined",
    "unknown",
}
_SCOPES = {"personal_project", "domain_operations", "unknown"}
# Historical concept inventories stored one retired scope name. Validation
# reads that stored value as domain_operations. Public-export hygiene
# allowlists this assignment only.
LEGACY_DOMAIN_SCOPE_ALIAS = "direct_job_subnet"
DOMAIN_SCOPE = "domain_operations"
DOMAIN_KEYWORDS_SCHEMA = "integrity-home-domain-keywords/1"
_EVIDENCE_DISPOSITIONS = {
    "user_authored",
    "assistant_recap",
    "quoted_or_copied",
    "reference_only",
    "noise",
}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_OWN_CONCEPT = re.compile(r"(?<!\w)(?:концеп\w*|concept\w*)", re.IGNORECASE)
_OWNERSHIP_EVIDENCE_CHARS = 800
_COPY_TAIL_MARKERS = (
    "вот диалог",
    "вот твой же текст",
    "вот твой текст",
    "я дам тебе анализ от",
    "вот анализ от",
    "ниже дословный фрагмент",
    "вот ещё одно сообщение от",
    "вот сообщение от",
    "цитирую",
)


class ConceptInventoryError(RuntimeError):
    """Fail-closed validation or compilation error with no private values."""


@dataclass(frozen=True)
class InventoryLimits:
    """Hard, deterministic work and input bounds."""

    max_input_bytes: int = 4 * 1024 * 1024 * 1024
    max_line_bytes: int = 64 * 1024 * 1024
    max_lines: int = 250_000
    max_messages_per_conversation: int = 100_000
    max_total_messages: int = 2_000_000
    max_content_bytes: int = 16 * 1024 * 1024
    max_candidates: int = 250_000
    max_tokens_per_candidate: int = 4_096
    max_total_candidate_tokens: int = 4_000_000
    max_comparisons: int = 2_000_000
    max_excerpt_chars: int = 800
    possible_duplicate_threshold_millionths: int = 820_000


@dataclass(frozen=True)
class DomainKeywordConfig:
    """Operator-supplied domain keywords. The shipped default is empty.

    Infrastructure-specific terms are not part of the public source. A user
    loads them from a JSON file (``INTEGRITY_DOMAIN_KEYWORDS`` or an explicit
    path) with schema ``integrity-home-domain-keywords/1``.
    """

    keywords: Tuple[str, ...] = ()

    def matches(self, text: str) -> bool:
        if not self.keywords:
            return False
        return _has_any(text, self.keywords)


def canonical_scope(scope: str) -> str:
    """Map the historical scope alias onto ``domain_operations``."""

    if scope == LEGACY_DOMAIN_SCOPE_ALIAS:
        return DOMAIN_SCOPE
    return scope


def load_domain_keywords(path: os.PathLike[str] | str | None = None) -> DomainKeywordConfig:
    """Load domain keywords. A missing path and unset environment yield ``()``."""

    source = path if path is not None else os.environ.get("INTEGRITY_DOMAIN_KEYWORDS")
    if source is None or source == "":
        return DomainKeywordConfig()
    file_path = Path(os.fspath(source))
    try:
        raw = file_path.read_text(encoding="utf-8")
    except OSError as err:
        raise ConceptInventoryError("domain_keywords_unreadable") from err
    if len(raw.encode("utf-8")) > 64 * 1024:
        raise ConceptInventoryError("domain_keywords_too_large")
    try:
        document = loads_json_strict(raw)
    except (json.JSONDecodeError, DuplicateJsonKeyError, RecursionError) as err:
        raise ConceptInventoryError("domain_keywords_invalid") from err
    if not isinstance(document, dict):
        raise ConceptInventoryError("domain_keywords_invalid")
    if document.get("schema") != DOMAIN_KEYWORDS_SCHEMA:
        raise ConceptInventoryError("domain_keywords_schema_invalid")
    keywords = document.get("keywords")
    if not isinstance(keywords, list) or len(keywords) > 64:
        raise ConceptInventoryError("domain_keywords_invalid")
    cleaned: List[str] = []
    for keyword in keywords:
        if (
            not isinstance(keyword, str)
            or not keyword
            or keyword != keyword.strip()
            or len(keyword) > 64
            or any(ord(char) < 32 for char in keyword)
        ):
            raise ConceptInventoryError("domain_keywords_invalid")
        cleaned.append(keyword.casefold())
    return DomainKeywordConfig(keywords=tuple(cleaned))


def _stable_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, UnicodeEncodeError) as err:
        raise ConceptInventoryError("value_not_stable_json") from err


def _stable_bytes(value: Any) -> bytes:
    return (_stable_json(value) + "\n").encode("utf-8", errors="strict")


def _digest_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _digest_json(value: Any, *, domain: str = "") -> str:
    data = _stable_json(value).encode("utf-8", errors="strict")
    prefix = domain.encode("ascii") + b"\0" if domain else b""
    return sha256(prefix + data).hexdigest()


def _require_dict(value: Any, code: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ConceptInventoryError(code)
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        raise ConceptInventoryError(code)


def _string(value: Any, code: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise ConceptInventoryError(code)
    if len(value) > 16_777_216:
        raise ConceptInventoryError(code)
    return value


def _optional_string(value: Any, code: str) -> Optional[str]:
    if value is None:
        return None
    return _string(value, code, empty=True)


def _integer(value: Any, code: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ConceptInventoryError(code)
    return value


def _boolean(value: Any, code: str) -> bool:
    if not isinstance(value, bool):
        raise ConceptInventoryError(code)
    return value


def _hex(value: Any, pattern: re.Pattern[str], code: str) -> str:
    text = _string(value, code)
    if pattern.fullmatch(text) is None:
        raise ConceptInventoryError(code)
    return text


def _coerce_limits(value: Optional[InventoryLimits | Mapping[str, Any]]) -> InventoryLimits:
    if value is None:
        result = InventoryLimits()
    elif isinstance(value, InventoryLimits):
        result = value
    elif isinstance(value, Mapping):
        allowed = {field.name for field in fields(InventoryLimits)}
        if set(value) - allowed:
            raise ConceptInventoryError("limits_unknown_field")
        try:
            result = InventoryLimits(**dict(value))
        except TypeError as err:
            raise ConceptInventoryError("limits_invalid") from err
    else:
        raise ConceptInventoryError("limits_invalid")
    data = asdict(result)
    for name, item in data.items():
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            raise ConceptInventoryError("limits_invalid")
        if name == "possible_duplicate_threshold_millionths" and item > 1_000_000:
            raise ConceptInventoryError("limits_invalid")
    if result.max_line_bytes > result.max_input_bytes:
        raise ConceptInventoryError("limits_invalid")
    return result


def _locator_record_id(locator: Mapping[str, Any]) -> str:
    unsigned = dict(locator)
    unsigned.pop("record_id", None)
    return _digest_json(unsigned)


def _validate_locator(locator_value: Any, expected: Mapping[str, Any], *, title: bool = False) -> Dict[str, Any]:
    locator = _require_dict(locator_value, "locator_invalid")
    _exact_keys(locator, _TITLE_LOCATOR_KEYS if title else _MESSAGE_LOCATOR_KEYS, "locator_fields_invalid")
    if locator != expected:
        raise ConceptInventoryError("locator_mismatch")
    record_id = _hex(locator.get("record_id"), _HEX64, "locator_record_id_invalid")
    if record_id != _locator_record_id(locator):
        raise ConceptInventoryError("locator_record_id_mismatch")
    return dict(locator)


def _validate_message(
    value: Any,
    *,
    outer: Mapping[str, Any],
    conversation: Mapping[str, Any],
    index: int,
    limits: InventoryLimits,
) -> Dict[str, Any]:
    message = _require_dict(value, "message_invalid")
    _exact_keys(message, _MESSAGE_KEYS, "message_fields_invalid")
    if message.get("record_type") != "message":
        raise ConceptInventoryError("message_record_type_invalid")
    for field, expected in (
        ("source_id", outer["source_id"]),
        ("provider", conversation["provider"]),
        ("provider_schema_version", conversation["provider_schema_version"]),
        ("conversation_id", outer["conversation_id"]),
        ("provider_conversation_id", conversation["provider_conversation_id"]),
    ):
        if message.get(field) != expected:
            raise ConceptInventoryError("message_selector_mismatch")
    record_id = _hex(message.get("record_id"), _HEX64, "message_record_id_invalid")
    message_id = _string(message.get("message_id"), "message_id_invalid")
    parent_id = _optional_string(message.get("parent_message_id"), "parent_message_id_invalid")
    role = _string(message.get("role"), "message_role_invalid")
    _optional_string(message.get("model"), "message_model_invalid")
    _string(message.get("content_type"), "message_content_type_invalid")
    _optional_string(message.get("created_at"), "message_created_at_invalid")
    branch_path = _string(message.get("branch_path"), "message_branch_path_invalid")
    branch_depth = _integer(message.get("branch_depth"), "message_branch_depth_invalid")
    has_unknown_parent = _boolean(message.get("has_unknown_parent"), "message_unknown_parent_invalid")
    _boolean(message.get("has_unknown_timestamp"), "message_unknown_timestamp_invalid")
    content = _string(message.get("content"), "message_content_invalid", empty=True)
    content_bytes = content.encode("utf-8", errors="strict")
    if len(content_bytes) > limits.max_content_bytes:
        raise ConceptInventoryError("message_content_limit_exceeded")
    if message.get("content_sha256") != _digest_bytes(content_bytes):
        raise ConceptInventoryError("message_content_sha256_mismatch")
    projection = _hex(message.get("projection_sha256"), _HEX64, "projection_sha256_invalid")
    conversation_index = _integer(message.get("conversation_index"), "conversation_index_invalid")
    message_index = _integer(message.get("message_index"), "message_index_invalid")
    if message_index != index:
        raise ConceptInventoryError("message_index_mismatch")
    canonical = _require_dict(message.get("canonical_message"), "canonical_message_invalid")
    for field in _CANONICAL_MESSAGE_FIELDS:
        if field not in canonical or canonical[field] != message[field]:
            raise ConceptInventoryError("canonical_message_mismatch")
    _stable_json(canonical)
    expected_locator = {
        "source_id": outer["source_id"],
        "provider": conversation["provider"],
        "provider_schema_version": conversation["provider_schema_version"],
        "projection_sha256": projection,
        "conversation_id": outer["conversation_id"],
        "provider_conversation_id": conversation["provider_conversation_id"],
        "conversation_index": conversation_index,
        "message_id": message_id,
        "message_index": message_index,
        "canonical_pointer": f"/conversations/{conversation_index}/messages/{message_index}",
    }
    expected_locator["record_id"] = _digest_json(expected_locator)
    locator = _validate_locator(message.get("locator"), expected_locator)
    if locator["record_id"] != record_id:
        raise ConceptInventoryError("message_record_id_mismatch")
    attachments = message.get("attachments")
    if not isinstance(attachments, list):
        raise ConceptInventoryError("message_attachments_invalid")
    canonical_attachments = canonical.get("attachments", [])
    if canonical_attachments is None:
        canonical_attachments = []
    if not isinstance(canonical_attachments, list) or len(attachments) != len(canonical_attachments):
        raise ConceptInventoryError("message_attachment_count_mismatch")
    attachment_keys = {
        "attachment_id",
        "media_type",
        "name",
        "source_locator",
        "searchable",
        "text",
        "text_sha256",
        "canonical_attachment",
    }
    for index, attachment_value in enumerate(attachments):
        attachment = _require_dict(attachment_value, "message_attachment_invalid")
        _exact_keys(attachment, attachment_keys, "message_attachment_fields_invalid")
        for key in ("attachment_id", "media_type", "name", "source_locator"):
            _string(
                attachment.get(key),
                "message_attachment_text_field_invalid",
                empty=(key != "attachment_id"),
            )
        searchable = _boolean(
            attachment.get("searchable"), "message_attachment_searchable_invalid"
        )
        text_value = attachment.get("text")
        text_sha256 = attachment.get("text_sha256")
        if text_value is None:
            if text_sha256 is not None or searchable:
                raise ConceptInventoryError("message_attachment_text_digest_invalid")
        else:
            text = _string(text_value, "message_attachment_text_invalid", empty=True)
            if not searchable or text_sha256 != _digest_bytes(text.encode("utf-8")):
                raise ConceptInventoryError("message_attachment_text_digest_invalid")
        canonical_attachment = _require_dict(
            attachment.get("canonical_attachment"),
            "canonical_attachment_invalid",
        )
        if canonical_attachment != canonical_attachments[index]:
            raise ConceptInventoryError("canonical_attachment_mismatch")
        _stable_json(canonical_attachment)
    if message.get("matched_text_leaves") != [] or message.get("matched_text_leaves_truncated") is not False:
        raise ConceptInventoryError("conversation_message_search_projection_invalid")
    if not isinstance(message.get("excluded_text_leaves"), list):
        raise ConceptInventoryError("excluded_text_leaves_invalid")
    if message.get("authoritative") is not False or message.get("evidence_only") is not True:
        raise ConceptInventoryError("message_authority_invalid")
    context = _require_dict(message.get("context"), "message_context_invalid")
    _exact_keys(context, _CONTEXT_KEYS, "message_context_fields_invalid")
    if context != {"previous": [], "next": [], "parent": None, "children": [], "children_truncated": False}:
        raise ConceptInventoryError("message_context_not_unbounded_export")
    result = dict(message)
    result["_parent_id"] = parent_id
    result["_role"] = role
    result["_branch_path"] = branch_path
    result["_branch_depth"] = branch_depth
    result["_unknown_parent"] = has_unknown_parent
    return result


def _validate_parent_graph(messages: Sequence[Mapping[str, Any]]) -> None:
    by_id = {message["message_id"]: message for message in messages}
    if len(by_id) != len(messages):
        raise ConceptInventoryError("duplicate_message_id")
    for message in messages:
        parent_id = message["_parent_id"]
        if parent_id is None:
            if message["_unknown_parent"] or message["_branch_depth"] != 0 or message["_branch_path"] != message["message_id"]:
                raise ConceptInventoryError("root_branch_ancestry_invalid")
            continue
        parent = by_id.get(parent_id)
        if parent is None:
            if not message["_unknown_parent"]:
                raise ConceptInventoryError("missing_parent_not_marked_unknown")
            continue
        if message["_unknown_parent"]:
            raise ConceptInventoryError("known_parent_marked_unknown")
        if message["_branch_depth"] != parent["_branch_depth"] + 1:
            raise ConceptInventoryError("branch_depth_mismatch")
        if message["_branch_path"] != f"{parent['_branch_path']}/{message['message_id']}":
            raise ConceptInventoryError("branch_path_mismatch")
        seen: set[str] = set()
        cursor: Optional[Mapping[str, Any]] = message
        while cursor is not None:
            current_id = cursor["message_id"]
            if current_id in seen:
                raise ConceptInventoryError("parent_cycle")
            seen.add(current_id)
            next_id = cursor["_parent_id"]
            cursor = by_id.get(next_id) if next_id is not None else None


def _validate_recall_record(value: Any, limits: InventoryLimits) -> Dict[str, Any]:
    outer = _require_dict(value, "recall_record_invalid")
    _exact_keys(outer, _OUTER_KEYS, "recall_outer_fields_invalid")
    if outer.get("schema_version") != RECALL_SCHEMA_VERSION:
        raise ConceptInventoryError("recall_schema_invalid")
    _hex(outer.get("run_id"), _HEX32, "run_id_invalid")
    _hex(outer.get("corpus_id"), _HEX64, "corpus_id_invalid")
    _hex(outer.get("index_generation"), _HEX64, "index_generation_invalid")
    source_id = _string(outer.get("source_id"), "source_id_invalid")
    conversation_id = _string(outer.get("conversation_id"), "conversation_id_invalid")
    queries = outer.get("matched_queries")
    if not isinstance(queries, list) or not queries or any(query not in _ALLOWED_QUERIES for query in queries):
        raise ConceptInventoryError("matched_queries_invalid")
    if queries != sorted(set(queries)):
        raise ConceptInventoryError("matched_queries_not_canonical")
    matched_ids = outer.get("matched_record_ids")
    if not isinstance(matched_ids, list) or not matched_ids:
        raise ConceptInventoryError("matched_record_ids_invalid")
    if matched_ids != sorted(set(matched_ids)) or any(_HEX64.fullmatch(item) is None for item in matched_ids if isinstance(item, str)) or any(not isinstance(item, str) for item in matched_ids):
        raise ConceptInventoryError("matched_record_ids_not_canonical")
    conversation = _require_dict(outer.get("conversation"), "conversation_invalid")
    _exact_keys(conversation, _CONVERSATION_KEYS, "conversation_fields_invalid")
    if conversation.get("source_id") != source_id or conversation.get("conversation_id") != conversation_id:
        raise ConceptInventoryError("conversation_selector_mismatch")
    provider = _string(conversation.get("provider"), "conversation_provider_invalid")
    provider_schema = _string(conversation.get("provider_schema_version"), "conversation_schema_invalid")
    provider_conversation_id = _string(conversation.get("provider_conversation_id"), "provider_conversation_id_invalid")
    title = _string(conversation.get("title"), "conversation_title_invalid", empty=True)
    _optional_string(conversation.get("created_at"), "conversation_created_at_invalid")
    messages_value = conversation.get("messages")
    if not isinstance(messages_value, list) or len(messages_value) > limits.max_messages_per_conversation:
        raise ConceptInventoryError("conversation_messages_invalid")
    messages = [
        _validate_message(item, outer=outer, conversation=conversation, index=index, limits=limits)
        for index, item in enumerate(messages_value)
    ]
    _validate_parent_graph(messages)
    projection_values = {message["projection_sha256"] for message in messages}
    conversation_indexes = {message["conversation_index"] for message in messages}
    if len(projection_values) != 1 or len(conversation_indexes) != 1:
        raise ConceptInventoryError("conversation_projection_inconsistent")
    projection = next(iter(projection_values))
    conversation_index = next(iter(conversation_indexes))
    canonical_conversation = _require_dict(conversation.get("canonical_conversation"), "canonical_conversation_invalid")
    canonical_messages = canonical_conversation.get("messages")
    if not isinstance(canonical_messages, list) or canonical_messages != [message["canonical_message"] for message in messages]:
        raise ConceptInventoryError("canonical_conversation_messages_mismatch")
    for field in ("conversation_id", "provider_conversation_id", "title", "created_at"):
        if field in canonical_conversation and canonical_conversation[field] != conversation[field]:
            raise ConceptInventoryError("canonical_conversation_mismatch")
    if "message_count" in canonical_conversation and canonical_conversation["message_count"] != len(messages):
        raise ConceptInventoryError("canonical_conversation_message_count_mismatch")
    _stable_json(canonical_conversation)
    title_locator = {
        "source_id": source_id,
        "provider": provider,
        "provider_schema_version": provider_schema,
        "projection_sha256": projection,
        "conversation_id": conversation_id,
        "provider_conversation_id": provider_conversation_id,
        "conversation_index": conversation_index,
        "canonical_pointer": f"/conversations/{conversation_index}/title",
    }
    title_locator["record_id"] = _digest_json(title_locator)
    valid_ids = {message["record_id"] for message in messages} | {title_locator["record_id"]}
    if not set(matched_ids) <= valid_ids:
        raise ConceptInventoryError("matched_record_locator_invalid")
    result = dict(outer)
    result["conversation"] = dict(conversation)
    result["conversation"]["messages"] = messages
    result["_title_locator"] = title_locator
    result["_title_sha256"] = _digest_bytes(title.encode("utf-8", errors="strict"))
    return result


def _read_recall(
    path_value: os.PathLike[str] | str, limits: InventoryLimits
) -> Tuple[List[Dict[str, Any]], str, int]:
    path = Path(path_value)
    try:
        before = path.lstat()
    except OSError as err:
        raise ConceptInventoryError("recall_input_unavailable") from err
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise ConceptInventoryError("recall_input_not_regular")
    if before.st_size > limits.max_input_bytes:
        raise ConceptInventoryError("input_byte_limit_exceeded")
    if os.name != "nt":
        if stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.geteuid():
            raise ConceptInventoryError("recall_input_not_private")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as err:
        raise ConceptInventoryError("recall_input_secure_open_failed") from err
    records: List[Dict[str, Any]] = []
    line_digests: List[str] = []
    total = 0
    try:
        opened = os.fstat(descriptor)
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        )
        expected_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        if opened_identity != expected_identity or not stat.S_ISREG(opened.st_mode):
            raise ConceptInventoryError("recall_input_changed_before_open")
        if os.name != "nt" and (
            stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_uid != os.geteuid()
        ):
            raise ConceptInventoryError("recall_input_not_private")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            while True:
                line = handle.readline(limits.max_line_bytes + 1)
                if not line:
                    break
                total += len(line)
                if total > limits.max_input_bytes:
                    raise ConceptInventoryError("input_byte_limit_exceeded")
                if len(line) > limits.max_line_bytes:
                    raise ConceptInventoryError("input_line_limit_exceeded")
                if len(records) >= limits.max_lines:
                    raise ConceptInventoryError("input_line_count_exceeded")
                if not line.endswith(b"\n"):
                    raise ConceptInventoryError("input_line_not_newline_terminated")
                body = line[:-1]
                if body.endswith(b"\r"):
                    body = body[:-1]
                if not body:
                    raise ConceptInventoryError("input_blank_line")
                try:
                    parsed = loads_json_strict(body.decode("utf-8", errors="strict"))
                except (UnicodeDecodeError, json.JSONDecodeError, DuplicateJsonKeyError, RecursionError) as err:
                    raise ConceptInventoryError("input_json_invalid") from err
                records.append(_validate_recall_record(parsed, limits))
                line_digests.append(_digest_bytes(body))
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as err:
        raise ConceptInventoryError("recall_input_changed") from err
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or total != before.st_size:
        raise ConceptInventoryError("recall_input_changed")
    if not records:
        raise ConceptInventoryError("input_empty")
    selector_set: set[Tuple[str, str]] = set()
    identity: Optional[Tuple[str, str, str]] = None
    total_messages = 0
    total_matched_records = 0
    for record in records:
        selector = (record["source_id"], record["conversation_id"])
        if selector in selector_set:
            raise ConceptInventoryError("duplicate_conversation_record")
        selector_set.add(selector)
        current = (record["run_id"], record["corpus_id"], record["index_generation"])
        if identity is None:
            identity = current
        elif identity != current:
            raise ConceptInventoryError("recall_corpus_identity_mismatch")
        total_messages += len(record["conversation"]["messages"])
        total_matched_records += len(record["matched_record_ids"])
        if total_messages > limits.max_total_messages:
            raise ConceptInventoryError("total_message_limit_exceeded")
    input_digest = _digest_json(
        sorted(line_digests), domain="integrity-home-private-concept-jsonl-lines/1"
    )
    return (
        sorted(records, key=lambda item: (item["source_id"], item["conversation_id"])),
        input_digest,
        total_matched_records,
    )


def _strip_non_owned_text(value: str) -> str:
    # Fenced code, inline code, markdown blockquotes, and explicit quotations
    # are context supplied by the user, not statements authored by the user.
    kept_lines: List[str] = []
    fence: Optional[str] = None
    for line in value.splitlines(keepends=True):
        stripped = line.lstrip()
        marker = "```" if stripped.startswith("```") else "~~~" if stripped.startswith("~~~") else None
        if fence is not None:
            if marker == fence:
                fence = None
            kept_lines.append("\n" if line.endswith(("\n", "\r")) else " ")
            continue
        if marker is not None:
            fence = marker
            kept_lines.append("\n" if line.endswith(("\n", "\r")) else " ")
            continue
        kept_lines.append(line)
    value = "".join(kept_lines)
    value = re.sub(r"`[^`\n]*`", " ", value)
    value = re.sub(r"(?m)^[ \t]*>.*$", " ", value)
    for pattern in (r'"[^"\n]*"', r"«[^»\n]*»", r"“[^”\n]*”", r"„[^“\n]*“"):
        value = re.sub(pattern, " ", value)
    return value


def _normalize(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    output: List[str] = []
    spaced = True
    for char in normalized:
        if char.isalnum():
            output.append(char)
            spaced = False
        elif not spaced:
            output.append(" ")
            spaced = True
    return "".join(output).strip()


def _tokens(normalized: str) -> Tuple[str, ...]:
    return tuple(part for part in normalized.split(" ") if part)


def _has_any(text: str, phrases: Iterable[str]) -> bool:
    return any(phrase in text for phrase in phrases)


def _is_quarantined(message: Mapping[str, Any]) -> bool:
    metadata = message["canonical_message"].get("provider_metadata")
    return isinstance(metadata, dict) and metadata.get("integrity_quarantine") is True


def _ownership_evidence(normalized: str) -> str:
    for prefix in ("імпортовано запит ", "импортировано запрос ", "imported prompt "):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
            break
    cut_positions = [
        position
        for marker in _COPY_TAIL_MARKERS
        if (position := normalized.find(marker)) >= 0
    ]
    if cut_positions:
        normalized = normalized[: min(cut_positions)]
    return normalized[:_OWNERSHIP_EVIDENCE_CHARS].strip()


def _classify_user(
    message: Mapping[str, Any],
    *,
    domain_keywords: Optional[DomainKeywordConfig] = None,
) -> Tuple[Dict[str, Any], str, Tuple[str, ...], str]:
    original = message["content"]
    owned = _strip_non_owned_text(original)
    normalized_full = _normalize(owned)
    normalized = _ownership_evidence(normalized_full)
    signals: List[str] = []
    if _is_quarantined(message):
        kind = "quarantined"
        signals.append("integrity.quarantine")
        reason = "quarantined_user_message"
        disposition = "noise"
    elif len(original.encode("utf-8")) > 200_000 or original.count("\n") > 200:
        kind = "bulk_context"
        signals.append("shape.bulk_text")
        reason = "bulk_user_context"
        disposition = "noise"
    elif (
        normalized_full.startswith(("запит запам", "запрос запомни обо мне", "remember the following about me"))
        and _has_any(normalized_full, ("про мене", "обо мне", "about me"))
    ):
        kind = "bulk_context"
        signals.append("provenance.memory_dump")
        reason = "memory_dump_context"
        disposition = "quoted_or_copied"
    elif _has_any(
        normalized_full,
        (
            "створено полотно gemini",
            "создано полотно gemini",
            "created gemini canvas",
            "gemini canvas created",
        ),
    ):
        kind = "bulk_context"
        signals.append("provenance.generated_canvas")
        reason = "generated_canvas_context"
        disposition = "quoted_or_copied"
    elif _OWN_CONCEPT.search(normalized) is None:
        kind = "reference"
        signals.append("ownership.no_concept_token_in_user_prose")
        reason = "non_owned_or_attachment_only_match"
        disposition = (
            "quoted_or_copied"
            if _OWN_CONCEPT.search(normalized_full) is not None
            else "noise"
        )
    else:
        lower = normalized
        delegated = _has_any(lower, (
            "предложи идеи", "предложи концеп", "придумай идеи",
            "придумай концеп", "сгенерируй идеи", "generate concepts",
            "suggest ideas", "propose ideas", "brainstorm concepts",
            "ваша миссия", "твоя миссия", "ваша задача", "твоя задача",
            "от вас требуется", "от тебя требуется",
        ))
        technical_log = _has_any(lower, (
            "ошибку выдало", "invalid parameter", "unrecognized parameter",
            "stack trace", "traceback", "error log",
        )) or ("parameter" in lower and "imagine" in lower)
        negated = _has_any(lower, (
            "не хочу делать", "не будем реализовывать", "отказался от концеп",
            "отказались от концеп", "не планирую реализовывать", "do not build",
            "don't build", "not planning to", "decided against the concept",
        ))
        reference = _has_any(lower, (
            "что такое", "расскажи о", "объясни концеп", "смысл концеп",
            "what is", "explain the concept", "concept of the movie", "concept in the book",
        )) or _has_any(lower, ("фильм", "movie", "книг", "book", "стать", "article")) and "?" in owned
        project = _has_any(lower, (
            "мой проект", "наш проект", "хочу сделать", "надо сделать",
            "разработать", "реализовать", "прототип", "mvp", "roadmap",
            "my project", "our project", "i want to build", "we should build", "implement",
            "идея создать", "идея сделать", "реализовать идею",
            "idea to build", "idea to create",
        )) or _has_any(lower, ("концепция приложен", "концепт сервис", "app concept", "service concept"))
        hypothesis = _has_any(lower, (
            "гипотез", "предполагаю", "что если", "может быть",
            "hypothesis", "i hypothesize", "what if", "could it be that",
            "насколько реализуем", "можно ли реализовать", "реально ли сделать",
            "насколько существенн", "how feasible", "is it feasible",
        ))
        creative = _has_any(lower, (
            "идея игр", "концепция игр", "сюжет", "персонаж", "вселенн",
            "игров", "игра", "game concept", "story concept", "plot", "character", "fictional world",
        ))
        owned = lower.startswith(("концепт ", "концепция ", "concept ")) or _has_any(
            lower,
            (
                "моя идея", "мой концепт", "моя концепция",
                "наша идея", "наш концепт", "наша концепция",
                "я придумал", "я придумала", "себе придумал", "себе придумала",
                "суть идеи", "идея создать", "идея сделать",
                "предлагаю идею", "предлагаю концепт", "предлагаю концепцию",
                "my idea", "my concept", "our idea", "our concept", "i came up with",
            ),
        )
        if negated:
            kind, reason = "reference", "rejected_or_negated_concept"
            signals.append("intent.negated")
            disposition = "reference_only"
        elif delegated:
            kind, reason = "reference", "delegated_generation_request"
            signals.append("ownership.delegated_generation")
            disposition = "reference_only"
        elif technical_log:
            kind, reason = "reference", "technical_log_context"
            signals.append("context.technical_log")
            disposition = "noise"
        elif reference:
            kind, reason = "reference", "reference_or_explanation_request"
            signals.append("intent.reference_question")
            disposition = "reference_only"
        elif hypothesis:
            kind, reason = "hypothesis", "candidate"
            signals.append("intent.hypothesis")
            disposition = "user_authored"
        elif creative and owned:
            kind, reason = "creative_concept", "candidate"
            signals.append("intent.creative")
            disposition = "user_authored"
        elif project:
            kind, reason = "project", "candidate"
            signals.append("intent.build_or_project")
            disposition = "user_authored"
        elif owned:
            kind, reason = "unknown", "candidate"
            signals.append("intent.unresolved_owned_concept")
            disposition = "user_authored"
        else:
            kind, reason = "reference", "unowned_concept_mention"
            signals.append("ownership.no_positive_signal")
            disposition = "reference_only"
    scope_text = normalized
    keywords = domain_keywords if domain_keywords is not None else DomainKeywordConfig()
    subnet_domain = keywords.matches(scope_text)
    explicit_work = _has_any(
        scope_text,
        (
            "для работы", "рабочая задача", "в эксплуатации", "операционная задача",
            "production operations", "work task",
        ),
    )
    hosting_context = _has_any(
        scope_text,
        ("разместить", "хостить", "тестовый стенд", "test bed", "host on"),
    )
    if subnet_domain and explicit_work and not hosting_context:
        scope = DOMAIN_SCOPE
        signals.extend(("scope.subnet_domain", "scope.explicit_work"))
    elif _has_any(scope_text, ("мой проект", "личный проект", "personal project", "integrity home")):
        scope = "personal_project"
        signals.append("scope.personal")
    else:
        scope = "unknown"
        signals.append("scope.unknown")
    classification = {
        "kind": kind,
        "scope": scope,
        "status": "pending",
        "authoritative": False,
        "signals": sorted(signals),
    }
    return classification, reason, _tokens(normalized), disposition


def _excerpt(content: str, limit: int) -> Dict[str, Any]:
    text = content[:limit]
    return {
        "text": text,
        "text_sha256": _digest_bytes(text.encode("utf-8", errors="strict")),
        "truncated": len(content) > limit,
    }


def _candidate_id(locator: Mapping[str, Any]) -> str:
    return _digest_json(locator, domain="integrity-home-user-concept-anchor/1")


def _nearest_user_ancestor(message: Mapping[str, Any], by_id: Mapping[str, Mapping[str, Any]]) -> Optional[Mapping[str, Any]]:
    parent_id = message["parent_message_id"]
    seen: set[str] = set()
    while parent_id is not None:
        if parent_id in seen:
            raise ConceptInventoryError("parent_cycle")
        seen.add(parent_id)
        parent = by_id.get(parent_id)
        if parent is None:
            return None
        if parent["role"] == "user":
            return parent
        parent_id = parent["parent_message_id"]
    return None


def _context_classification(reason: str, message: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    if message is not None and _is_quarantined(message):
        kind, signal = "quarantined", "integrity.quarantine"
    elif reason == "title_only_match":
        kind, signal = "reference", "context.title_match"
    else:
        kind, signal = "unknown", f"context.{reason}"
    return {"kind": kind, "scope": "unknown", "status": "pending", "authoritative": False, "signals": [signal]}


def _build_inventory(
    records: Sequence[Mapping[str, Any]],
    limits: InventoryLimits,
    *,
    semantic_input_sha256: str,
    input_matched_records: int,
    domain_keywords: Optional[DomainKeywordConfig] = None,
) -> Dict[str, Any]:
    first = records[0]
    candidates: Dict[str, Dict[str, Any]] = {}
    candidate_tokens: Dict[str, Tuple[str, ...]] = {}
    contexts: Dict[str, Dict[str, Any]] = {}
    total_tokens = 0

    for record in records:
        conversation = record["conversation"]
        messages = conversation["messages"]
        by_id = {message["record_id"]: message for message in messages}
        by_message_id = {message["message_id"]: message for message in messages}
        matched = set(record["matched_record_ids"])
        title_locator = record["_title_locator"]
        title_record_id = title_locator["record_id"]
        potential_anchors: Dict[str, Dict[str, Any]] = {}

        if title_record_id in matched:
            content = conversation["title"]
            context_id = _digest_json({"reason": "title_only_match", "locator": title_locator}, domain="integrity-home-concept-context/1")
            contexts[context_id] = {
                "context_id": context_id,
                "reason": "title_only_match",
                "evidence_disposition": "reference_only",
                "classification": _context_classification("title_only_match"),
                "role": None,
                "parent_message_id": None,
                "branch_path": None,
                "branch_depth": None,
                "content_sha256": record["_title_sha256"],
                "excerpt": _excerpt(content, limits.max_excerpt_chars),
                "locator": title_locator,
                "linked_candidate_id": None,
            }

        for record_id in sorted(matched):
            message = by_id.get(record_id)
            if message is None:
                continue  # already validated as the title record
            role = message["role"]
            anchor: Optional[Mapping[str, Any]] = None
            if role == "user":
                anchor = message
            elif role == "assistant":
                anchor = _nearest_user_ancestor(message, by_message_id)
            if anchor is not None:
                entry = potential_anchors.setdefault(anchor["record_id"], {"message": anchor, "matches": set()})
                entry["matches"].add(record_id)
            if role != "user":
                reason = "assistant_match" if role == "assistant" else "non_user_message_match"
                locator = message["locator"]
                context_id = _digest_json({"reason": reason, "locator": locator}, domain="integrity-home-concept-context/1")
                contexts[context_id] = {
                    "context_id": context_id,
                    "reason": reason,
                    "evidence_disposition": (
                        "assistant_recap" if role == "assistant" else "noise"
                    ),
                    "classification": _context_classification(reason, message),
                    "role": role,
                    "parent_message_id": message["parent_message_id"],
                    "branch_path": message["branch_path"],
                    "branch_depth": message["branch_depth"],
                    "content_sha256": message["content_sha256"],
                    "excerpt": _excerpt(message["content"], limits.max_excerpt_chars),
                    "locator": locator,
                    "linked_candidate_id": _candidate_id(anchor["locator"]) if anchor is not None else None,
                }

        for anchor_record_id in sorted(potential_anchors):
            anchor_info = potential_anchors[anchor_record_id]
            message = anchor_info["message"]
            classification, reason, tokens, disposition = _classify_user(
                message, domain_keywords=domain_keywords
            )
            candidate_id = _candidate_id(message["locator"])
            if reason == "candidate" and len(tokens) > limits.max_tokens_per_candidate:
                # Preserve evidence for a likely pasted/bulk payload without
                # treating it as one concept or aborting the remaining scan.
                classification = {
                    **classification,
                    "kind": "bulk_context",
                    "scope": "unknown",
                    "signals": sorted(
                        set(classification["signals"]) | {"shape.candidate_token_limit"}
                    ),
                }
                reason = "oversized_user_context"
                disposition = "noise"
            eligible = reason == "candidate"
            if eligible:
                if len(candidates) >= limits.max_candidates:
                    raise ConceptInventoryError("candidate_limit_exceeded")
                total_tokens += len(tokens)
                if total_tokens > limits.max_total_candidate_tokens:
                    raise ConceptInventoryError("total_candidate_token_limit_exceeded")
                normalized = " ".join(tokens)
                candidate = {
                    "candidate_id": candidate_id,
                    "evidence_disposition": "user_authored",
                    "classification": classification,
                    "anchor": {
                        "role": "user",
                        "parent_message_id": message["parent_message_id"],
                        "branch_path": message["branch_path"],
                        "branch_depth": message["branch_depth"],
                        "content_sha256": message["content_sha256"],
                        "excerpt": _excerpt(message["content"], limits.max_excerpt_chars),
                        "locator": message["locator"],
                    },
                    "normalized_text_sha256": _digest_bytes(normalized.encode("utf-8")),
                    "token_count": len(tokens),
                    "matched_record_ids": sorted(anchor_info["matches"]),
                }
                candidates[candidate_id] = candidate
                candidate_tokens[candidate_id] = tokens
            else:
                context_id = _digest_json({"reason": reason, "locator": message["locator"]}, domain="integrity-home-concept-context/1")
                contexts[context_id] = {
                    "context_id": context_id,
                    "reason": reason,
                    "evidence_disposition": disposition,
                    "classification": classification,
                    "role": "user",
                    "parent_message_id": message["parent_message_id"],
                    "branch_path": message["branch_path"],
                    "branch_depth": message["branch_depth"],
                    "content_sha256": message["content_sha256"],
                    "excerpt": _excerpt(message["content"], limits.max_excerpt_chars),
                    "locator": message["locator"],
                    "linked_candidate_id": None,
                }
                for context in contexts.values():
                    if context["linked_candidate_id"] == candidate_id:
                        context["linked_candidate_id"] = None
                        context["evidence_disposition"] = (
                            "reference_only"
                            if disposition in {"reference_only", "quoted_or_copied"}
                            else "noise"
                        )

    # No assistant link is published unless its exact parent-ancestry anchor
    # survived the user-ownership and classification gates above.
    for context in contexts.values():
        linked = context["linked_candidate_id"]
        if linked is not None and linked not in candidates:
            context["linked_candidate_id"] = None

    ordered_candidates = [candidates[key] for key in sorted(candidates)]
    exact_groups: Dict[str, List[str]] = {}
    for candidate in ordered_candidates:
        exact_groups.setdefault(candidate["normalized_text_sha256"], []).append(candidate["candidate_id"])
    clusters: List[Dict[str, Any]] = []
    cluster_tokens: Dict[str, frozenset[str]] = {}
    for normalized_digest, members in sorted(exact_groups.items()):
        members = sorted(members)
        cluster_id = _digest_json({"normalized_text_sha256": normalized_digest}, domain="integrity-home-exact-concept-cluster/1")
        clusters.append({
            "cluster_id": cluster_id,
            "normalized_text_sha256": normalized_digest,
            "primary_candidate_id": members[0],
            "member_candidate_ids": members,
            "alias_candidate_ids": members[1:],
        })
        cluster_tokens[cluster_id] = frozenset(candidate_tokens[members[0]])

    possible_links: List[Dict[str, Any]] = []
    comparisons = 0
    cluster_ids = sorted(cluster_tokens)
    threshold = limits.possible_duplicate_threshold_millionths
    for left_index, left_id in enumerate(cluster_ids):
        left = cluster_tokens[left_id]
        for right_id in cluster_ids[left_index + 1 :]:
            comparisons += 1
            if comparisons > limits.max_comparisons:
                raise ConceptInventoryError("comparison_limit_exceeded")
            right = cluster_tokens[right_id]
            if len(left) < 3 or len(right) < 3:
                continue
            union = len(left | right)
            intersection = len(left & right)
            score = intersection * 1_000_000 // union
            if score >= threshold:
                possible_links.append({
                    "left_cluster_id": left_id,
                    "right_cluster_id": right_id,
                    "jaccard_millionths": score,
                    "status": "possible_duplicate",
                    "merged": False,
                })

    rules = {
        "version": RULES_VERSION,
        "possible_duplicate_threshold_millionths": threshold,
        "limits_sha256": _digest_json(asdict(limits), domain="integrity-home-concept-limits/1"),
    }
    return {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "policy": {
            "status": "pending",
            "authoritative": False,
            "hosted_model_used": False,
            "network_used": False,
        },
        "corpus": {
            "run_id": first["run_id"],
            "corpus_id": first["corpus_id"],
            "index_generation": first["index_generation"],
            "semantic_input_sha256": semantic_input_sha256,
        },
        "rules": rules,
        "candidates": ordered_candidates,
        "exact_duplicate_clusters": sorted(clusters, key=lambda item: item["cluster_id"]),
        "possible_duplicate_links": possible_links,
        "context_only": [contexts[key] for key in sorted(contexts)],
        "work_counts": {
            "input_records": len(records),
            "input_matched_records": input_matched_records,
            "candidate_tokens": total_tokens,
            "jaccard_comparisons": comparisons,
        },
    }


def _parse_json_payload(payload: Any, code: str) -> Dict[str, Any]:
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, bytes):
        try:
            payload = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as err:
            raise ConceptInventoryError(code) from err
    if isinstance(payload, str):
        try:
            value = loads_json_strict(payload)
        except (json.JSONDecodeError, DuplicateJsonKeyError, RecursionError) as err:
            raise ConceptInventoryError(code) from err
        return _require_dict(value, code)
    raise ConceptInventoryError(code)


def _validate_classification(value: Any) -> Dict[str, Any]:
    item = _require_dict(value, "classification_invalid")
    _exact_keys(item, {"kind", "scope", "status", "authoritative", "signals"}, "classification_fields_invalid")
    if item.get("scope") == LEGACY_DOMAIN_SCOPE_ALIAS:
        item["scope"] = DOMAIN_SCOPE
    if item.get("kind") not in _KINDS or item.get("scope") not in _SCOPES or item.get("status") != "pending" or item.get("authoritative") is not False:
        raise ConceptInventoryError("classification_invalid")
    signals = item.get("signals")
    if not isinstance(signals, list) or signals != sorted(set(signals)) or any(not isinstance(signal, str) or not signal for signal in signals):
        raise ConceptInventoryError("classification_signals_invalid")
    return item


def _validate_excerpt(value: Any, content_sha256: str) -> None:
    excerpt = _require_dict(value, "excerpt_invalid")
    _exact_keys(excerpt, {"text", "text_sha256", "truncated"}, "excerpt_fields_invalid")
    text = _string(excerpt.get("text"), "excerpt_text_invalid", empty=True)
    if excerpt.get("text_sha256") != _digest_bytes(text.encode("utf-8")) or not isinstance(excerpt.get("truncated"), bool):
        raise ConceptInventoryError("excerpt_digest_invalid")
    if excerpt["truncated"] is False and excerpt["text_sha256"] != content_sha256:
        raise ConceptInventoryError("excerpt_content_digest_mismatch")


def _validate_output_locator(value: Any) -> Dict[str, Any]:
    locator = _require_dict(value, "inventory_locator_invalid")
    if set(locator) == _MESSAGE_LOCATOR_KEYS:
        title = False
    elif set(locator) == _TITLE_LOCATOR_KEYS:
        title = True
    else:
        raise ConceptInventoryError("inventory_locator_fields_invalid")
    if _locator_record_id(locator) != locator.get("record_id") or _HEX64.fullmatch(str(locator.get("record_id"))) is None:
        raise ConceptInventoryError("inventory_locator_digest_invalid")
    if title != (str(locator.get("canonical_pointer", "")).endswith("/title")):
        raise ConceptInventoryError("inventory_locator_pointer_invalid")
    return locator


def _validate_inventory_ancestry(
    *,
    role: Any,
    parent_message_id: Any,
    branch_path: Any,
    branch_depth: Any,
    locator: Mapping[str, Any],
    title: bool,
) -> None:
    if title:
        if any(
            value is not None
            for value in (role, parent_message_id, branch_path, branch_depth)
        ):
            raise ConceptInventoryError("inventory_title_ancestry_invalid")
        return
    role_value = _string(role, "inventory_evidence_role_invalid")
    del role_value
    parent = _optional_string(
        parent_message_id, "inventory_evidence_parent_message_id_invalid"
    )
    path = _string(branch_path, "inventory_evidence_branch_path_invalid")
    depth = _integer(branch_depth, "inventory_evidence_branch_depth_invalid")
    message_id = _string(
        locator.get("message_id"), "inventory_evidence_locator_message_id_invalid"
    )
    if depth == 0:
        if parent is not None or path != message_id:
            raise ConceptInventoryError("inventory_root_ancestry_invalid")
    elif parent is None or not path.endswith(f"/{message_id}"):
        raise ConceptInventoryError("inventory_branch_ancestry_invalid")


def validate_concept_inventory(payload: Any) -> Dict[str, Any]:
    """Validate and return one private inventory payload."""

    inventory = _parse_json_payload(payload, "inventory_json_invalid")
    _exact_keys(inventory, {"schema_version", "policy", "corpus", "rules", "candidates", "exact_duplicate_clusters", "possible_duplicate_links", "context_only", "work_counts"}, "inventory_fields_invalid")
    if inventory.get("schema_version") != INVENTORY_SCHEMA_VERSION:
        raise ConceptInventoryError("inventory_schema_invalid")
    if inventory.get("policy") != {"status": "pending", "authoritative": False, "hosted_model_used": False, "network_used": False}:
        raise ConceptInventoryError("inventory_policy_invalid")
    corpus = _require_dict(inventory.get("corpus"), "inventory_corpus_invalid")
    _exact_keys(corpus, {"run_id", "corpus_id", "index_generation", "semantic_input_sha256"}, "inventory_corpus_fields_invalid")
    _hex(corpus.get("run_id"), _HEX32, "inventory_run_id_invalid")
    for key in ("corpus_id", "index_generation", "semantic_input_sha256"):
        _hex(corpus.get(key), _HEX64, "inventory_corpus_digest_invalid")
    rules = _require_dict(inventory.get("rules"), "inventory_rules_invalid")
    _exact_keys(rules, {"version", "possible_duplicate_threshold_millionths", "limits_sha256"}, "inventory_rules_fields_invalid")
    if rules.get("version") != RULES_VERSION:
        raise ConceptInventoryError("inventory_rules_version_invalid")
    threshold = _integer(rules.get("possible_duplicate_threshold_millionths"), "inventory_threshold_invalid", minimum=1)
    if threshold > 1_000_000:
        raise ConceptInventoryError("inventory_threshold_invalid")
    _hex(rules.get("limits_sha256"), _HEX64, "inventory_limits_digest_invalid")
    candidates = inventory.get("candidates")
    if not isinstance(candidates, list):
        raise ConceptInventoryError("inventory_candidates_invalid")
    candidate_ids: List[str] = []
    normalized_by_id: Dict[str, str] = {}
    for candidate in candidates:
        item = _require_dict(candidate, "inventory_candidate_invalid")
        _exact_keys(item, {"candidate_id", "evidence_disposition", "classification", "anchor", "normalized_text_sha256", "token_count", "matched_record_ids"}, "inventory_candidate_fields_invalid")
        candidate_id = _hex(item.get("candidate_id"), _HEX64, "inventory_candidate_id_invalid")
        if item.get("evidence_disposition") != "user_authored":
            raise ConceptInventoryError("inventory_candidate_evidence_disposition_invalid")
        _validate_classification(item.get("classification"))
        anchor = _require_dict(item.get("anchor"), "inventory_anchor_invalid")
        _exact_keys(anchor, {"role", "parent_message_id", "branch_path", "branch_depth", "content_sha256", "excerpt", "locator"}, "inventory_anchor_fields_invalid")
        content_sha = _hex(anchor.get("content_sha256"), _HEX64, "inventory_content_digest_invalid")
        locator = _validate_output_locator(anchor.get("locator"))
        if set(locator) != _MESSAGE_LOCATOR_KEYS or _candidate_id(locator) != candidate_id:
            raise ConceptInventoryError("inventory_candidate_locator_mismatch")
        if anchor.get("role") != "user":
            raise ConceptInventoryError("inventory_candidate_role_invalid")
        _validate_inventory_ancestry(
            role=anchor.get("role"),
            parent_message_id=anchor.get("parent_message_id"),
            branch_path=anchor.get("branch_path"),
            branch_depth=anchor.get("branch_depth"),
            locator=locator,
            title=False,
        )
        _validate_excerpt(anchor.get("excerpt"), content_sha)
        normalized_by_id[candidate_id] = _hex(item.get("normalized_text_sha256"), _HEX64, "inventory_normalized_digest_invalid")
        _integer(item.get("token_count"), "inventory_token_count_invalid")
        matched_ids = item.get("matched_record_ids")
        if not isinstance(matched_ids, list) or matched_ids != sorted(set(matched_ids)) or any(_HEX64.fullmatch(str(value)) is None for value in matched_ids):
            raise ConceptInventoryError("inventory_matched_ids_invalid")
        candidate_ids.append(candidate_id)
    if candidate_ids != sorted(set(candidate_ids)):
        raise ConceptInventoryError("inventory_candidates_not_canonical")
    clusters = inventory.get("exact_duplicate_clusters")
    if not isinstance(clusters, list):
        raise ConceptInventoryError("inventory_clusters_invalid")
    seen_members: List[str] = []
    cluster_ids: List[str] = []
    for cluster in clusters:
        item = _require_dict(cluster, "inventory_cluster_invalid")
        _exact_keys(item, {"cluster_id", "normalized_text_sha256", "primary_candidate_id", "member_candidate_ids", "alias_candidate_ids"}, "inventory_cluster_fields_invalid")
        cluster_id = _hex(item.get("cluster_id"), _HEX64, "inventory_cluster_id_invalid")
        normalized_digest = _hex(item.get("normalized_text_sha256"), _HEX64, "inventory_cluster_digest_invalid")
        if cluster_id != _digest_json({"normalized_text_sha256": normalized_digest}, domain="integrity-home-exact-concept-cluster/1"):
            raise ConceptInventoryError("inventory_cluster_id_mismatch")
        members = item.get("member_candidate_ids")
        aliases = item.get("alias_candidate_ids")
        if not isinstance(members, list) or not members or members != sorted(set(members)) or item.get("primary_candidate_id") != members[0] or aliases != members[1:]:
            raise ConceptInventoryError("inventory_cluster_members_invalid")
        if any(member not in normalized_by_id or normalized_by_id[member] != normalized_digest for member in members):
            raise ConceptInventoryError("inventory_cluster_member_digest_mismatch")
        seen_members.extend(members)
        cluster_ids.append(cluster_id)
    if cluster_ids != sorted(set(cluster_ids)) or sorted(seen_members) != candidate_ids or len(seen_members) != len(set(seen_members)):
        raise ConceptInventoryError("inventory_cluster_partition_invalid")
    links = inventory.get("possible_duplicate_links")
    if not isinstance(links, list):
        raise ConceptInventoryError("inventory_duplicate_links_invalid")
    link_keys: List[Tuple[str, str]] = []
    cluster_set = set(cluster_ids)
    for link in links:
        item = _require_dict(link, "inventory_duplicate_link_invalid")
        _exact_keys(item, {"left_cluster_id", "right_cluster_id", "jaccard_millionths", "status", "merged"}, "inventory_duplicate_link_fields_invalid")
        left, right = item.get("left_cluster_id"), item.get("right_cluster_id")
        if left not in cluster_set or right not in cluster_set or not isinstance(left, str) or not isinstance(right, str) or left >= right:
            raise ConceptInventoryError("inventory_duplicate_link_selector_invalid")
        score = _integer(item.get("jaccard_millionths"), "inventory_duplicate_score_invalid")
        if score < threshold or score > 1_000_000 or item.get("status") != "possible_duplicate" or item.get("merged") is not False:
            raise ConceptInventoryError("inventory_duplicate_link_invalid")
        link_keys.append((left, right))
    if link_keys != sorted(set(link_keys)):
        raise ConceptInventoryError("inventory_duplicate_links_not_canonical")
    contexts = inventory.get("context_only")
    if not isinstance(contexts, list):
        raise ConceptInventoryError("inventory_context_invalid")
    context_ids: List[str] = []
    for context in contexts:
        item = _require_dict(context, "inventory_context_item_invalid")
        _exact_keys(item, {"context_id", "reason", "evidence_disposition", "classification", "role", "parent_message_id", "branch_path", "branch_depth", "content_sha256", "excerpt", "locator", "linked_candidate_id"}, "inventory_context_fields_invalid")
        context_id = _hex(item.get("context_id"), _HEX64, "inventory_context_id_invalid")
        reason = _string(item.get("reason"), "inventory_context_reason_invalid")
        if item.get("evidence_disposition") not in _EVIDENCE_DISPOSITIONS - {"user_authored"}:
            raise ConceptInventoryError("inventory_context_evidence_disposition_invalid")
        _validate_classification(item.get("classification"))
        content_sha = _hex(item.get("content_sha256"), _HEX64, "inventory_context_content_digest_invalid")
        _validate_excerpt(item.get("excerpt"), content_sha)
        locator = _validate_output_locator(item.get("locator"))
        is_title = set(locator) == _TITLE_LOCATOR_KEYS
        _validate_inventory_ancestry(
            role=item.get("role"),
            parent_message_id=item.get("parent_message_id"),
            branch_path=item.get("branch_path"),
            branch_depth=item.get("branch_depth"),
            locator=locator,
            title=is_title,
        )
        expected_id = _digest_json({"reason": reason, "locator": locator}, domain="integrity-home-concept-context/1")
        if expected_id != context_id:
            raise ConceptInventoryError("inventory_context_id_mismatch")
        linked = item.get("linked_candidate_id")
        if linked is not None and linked not in set(candidate_ids):
            raise ConceptInventoryError("inventory_context_link_invalid")
        context_ids.append(context_id)
    if context_ids != sorted(set(context_ids)):
        raise ConceptInventoryError("inventory_context_not_canonical")
    work = _require_dict(inventory.get("work_counts"), "inventory_work_counts_invalid")
    _exact_keys(work, {"input_records", "input_matched_records", "candidate_tokens", "jaccard_comparisons"}, "inventory_work_count_fields_invalid")
    for key in work:
        _integer(work.get(key), "inventory_work_count_invalid")
    if work["candidate_tokens"] != sum(candidate["token_count"] for candidate in candidates):
        raise ConceptInventoryError("inventory_candidate_token_count_mismatch")
    expected_comparisons = len(clusters) * (len(clusters) - 1) // 2
    if work["jaccard_comparisons"] != expected_comparisons:
        raise ConceptInventoryError("inventory_comparison_count_mismatch")
    _stable_json(inventory)
    return inventory


def _inventory_counts(inventory: Mapping[str, Any]) -> Dict[str, Any]:
    by_kind = {kind: 0 for kind in sorted(_KINDS)}
    alias_count = 0
    for candidate in inventory["candidates"]:
        by_kind[candidate["classification"]["kind"]] += 1
    for context in inventory["context_only"]:
        by_kind[context["classification"]["kind"]] += 1
    for cluster in inventory["exact_duplicate_clusters"]:
        alias_count += len(cluster["alias_candidate_ids"])
    return {
        "input_records": inventory["work_counts"]["input_records"],
        "input_matched_records": inventory["work_counts"]["input_matched_records"],
        "candidate_occurrences": len(inventory["candidates"]),
        "exact_duplicate_clusters": len(inventory["exact_duplicate_clusters"]),
        "exact_duplicate_aliases": alias_count,
        "possible_duplicate_links": len(inventory["possible_duplicate_links"]),
        "context_only": len(inventory["context_only"]),
        "inventory_bytes": 0,
        "by_kind": by_kind,
    }


def validate_concept_receipt(receipt: Any, *, inventory_bytes: Optional[bytes] = None) -> Dict[str, Any]:
    """Validate a content-free receipt, optionally binding it to inventory bytes."""

    value = _parse_json_payload(receipt, "receipt_json_invalid")
    _exact_keys(value, {"schema_version", "scan_complete", "review_required", "authoritative", "counts", "digests"}, "receipt_fields_invalid")
    if value.get("schema_version") != RECEIPT_SCHEMA_VERSION:
        raise ConceptInventoryError("receipt_schema_invalid")
    if value.get("scan_complete") is not True or value.get("review_required") is not True or value.get("authoritative") is not False:
        raise ConceptInventoryError("receipt_policy_invalid")
    counts = _require_dict(value.get("counts"), "receipt_counts_invalid")
    expected_count_keys = {"input_records", "input_matched_records", "candidate_occurrences", "exact_duplicate_clusters", "exact_duplicate_aliases", "possible_duplicate_links", "context_only", "inventory_bytes", "by_kind"}
    _exact_keys(counts, expected_count_keys, "receipt_count_fields_invalid")
    for key in expected_count_keys - {"by_kind"}:
        _integer(counts.get(key), "receipt_count_invalid")
    by_kind = _require_dict(counts.get("by_kind"), "receipt_kind_counts_invalid")
    _exact_keys(by_kind, _KINDS, "receipt_kind_count_fields_invalid")
    for count in by_kind.values():
        _integer(count, "receipt_kind_count_invalid")
    digests = _require_dict(value.get("digests"), "receipt_digests_invalid")
    _exact_keys(digests, {"inventory_sha256", "semantic_input_sha256", "corpus_id_sha256", "index_generation_sha256", "run_id_sha256", "rules_sha256"}, "receipt_digest_fields_invalid")
    for digest in digests.values():
        _hex(digest, _HEX64, "receipt_digest_invalid")
    if inventory_bytes is not None:
        if not isinstance(inventory_bytes, bytes):
            raise ConceptInventoryError("receipt_inventory_bytes_invalid")
        if counts["inventory_bytes"] != len(inventory_bytes) or digests["inventory_sha256"] != _digest_bytes(inventory_bytes):
            raise ConceptInventoryError("receipt_inventory_binding_mismatch")
        inventory = validate_concept_inventory(inventory_bytes)
        expected = _inventory_counts(inventory)
        expected["inventory_bytes"] = len(inventory_bytes)
        if counts != expected:
            raise ConceptInventoryError("receipt_inventory_counts_mismatch")
        if digests["semantic_input_sha256"] != inventory["corpus"]["semantic_input_sha256"]:
            raise ConceptInventoryError("receipt_semantic_input_mismatch")
        if digests["corpus_id_sha256"] != _digest_json(inventory["corpus"]["corpus_id"], domain="receipt-corpus-id"):
            raise ConceptInventoryError("receipt_corpus_digest_mismatch")
        if digests["index_generation_sha256"] != _digest_json(inventory["corpus"]["index_generation"], domain="receipt-index-generation"):
            raise ConceptInventoryError("receipt_generation_digest_mismatch")
        if digests["run_id_sha256"] != _digest_json(inventory["corpus"]["run_id"], domain="receipt-run-id"):
            raise ConceptInventoryError("receipt_run_digest_mismatch")
        if digests["rules_sha256"] != _digest_json(inventory["rules"], domain="receipt-rules"):
            raise ConceptInventoryError("receipt_rules_digest_mismatch")
    _stable_json(value)
    return value


def _assert_private_parent(path: Path) -> None:
    try:
        state = path.lstat()
    except OSError as err:
        raise ConceptInventoryError("output_parent_unavailable") from err
    if not stat.S_ISDIR(state.st_mode) or stat.S_ISLNK(state.st_mode):
        raise ConceptInventoryError("output_parent_not_directory")
    if os.name != "nt" and (stat.S_IMODE(state.st_mode) != 0o700 or state.st_uid != os.geteuid()):
        raise ConceptInventoryError("output_parent_not_private")
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            component = current.lstat()
        except OSError as err:
            raise ConceptInventoryError("output_parent_component_unavailable") from err
        if stat.S_ISLNK(component.st_mode):
            raise ConceptInventoryError("output_parent_symlink_rejected")


def _write_pair_atomic(
    inventory_path: Path,
    inventory_bytes: bytes,
    receipt_path: Path,
    receipt_bytes: bytes,
    *,
    replace: bool,
) -> None:
    inventory_path = Path(os.path.abspath(inventory_path))
    receipt_path = Path(os.path.abspath(receipt_path))
    if inventory_path == receipt_path or inventory_path.parent != receipt_path.parent:
        raise ConceptInventoryError("output_paths_invalid")
    parent = inventory_path.parent
    _assert_private_parent(parent)
    if replace:
        raise ConceptInventoryError("replace_not_supported")
    targets = ((inventory_path.name, inventory_bytes), (receipt_path.name, receipt_bytes))
    if any(name in {"", ".", ".."} for name, _ in targets):
        raise ConceptInventoryError("output_name_invalid")

    if os.name != "nt":
        expected_parent = parent.lstat()
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            parent_fd = os.open(parent, flags)
        except OSError as err:
            raise ConceptInventoryError("output_parent_secure_open_failed") from err
        staged: List[Tuple[str, str, Tuple[int, int]]] = []
        published: List[Tuple[str, Tuple[int, int]]] = []
        try:
            opened_parent = os.fstat(parent_fd)
            if (
                (opened_parent.st_dev, opened_parent.st_ino)
                != (expected_parent.st_dev, expected_parent.st_ino)
                or not stat.S_ISDIR(opened_parent.st_mode)
                or stat.S_IMODE(opened_parent.st_mode) != 0o700
                or opened_parent.st_uid != os.geteuid()
            ):
                raise ConceptInventoryError("output_parent_changed")
            for name, _ in targets:
                try:
                    state = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                except OSError as err:
                    raise ConceptInventoryError("output_target_stat_failed") from err
                if stat.S_ISLNK(state.st_mode) or not stat.S_ISREG(state.st_mode):
                    raise ConceptInventoryError("output_target_invalid")
                raise ConceptInventoryError("output_exists")
            for (target_name, body) in targets:
                temporary_name = f".{target_name}.{secrets.token_hex(16)}.tmp"
                descriptor = os.open(
                    temporary_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=parent_fd,
                )
                try:
                    os.fchmod(descriptor, 0o600)
                    state = os.fstat(descriptor)
                    identity = (state.st_dev, state.st_ino)
                    with os.fdopen(descriptor, "wb") as handle:
                        descriptor = -1
                        handle.write(body)
                        handle.flush()
                        os.fsync(handle.fileno())
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
                staged.append((temporary_name, target_name, identity))
            for temporary_name, target_name, identity in staged:
                os.link(
                    temporary_name,
                    target_name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                published.append((target_name, identity))
                os.unlink(temporary_name, dir_fd=parent_fd)
            os.fsync(parent_fd)
            for target_name, identity in published:
                state = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
                if (
                    (state.st_dev, state.st_ino) != identity
                    or not stat.S_ISREG(state.st_mode)
                    or stat.S_IMODE(state.st_mode) != 0o600
                    or state.st_uid != os.geteuid()
                ):
                    raise ConceptInventoryError("output_identity_or_mode_invalid")
            return
        except Exception as err:
            for target_name, identity in reversed(published):
                try:
                    state = os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
                    if (state.st_dev, state.st_ino) == identity:
                        os.unlink(target_name, dir_fd=parent_fd)
                except OSError:
                    pass
            for temporary_name, _, _ in staged:
                try:
                    os.unlink(temporary_name, dir_fd=parent_fd)
                except OSError:
                    pass
            try:
                os.fsync(parent_fd)
            except OSError:
                pass
            if isinstance(err, ConceptInventoryError):
                raise
            if isinstance(err, FileExistsError):
                raise ConceptInventoryError("output_exists") from err
            raise ConceptInventoryError("output_atomic_write_failed") from err
        finally:
            os.close(parent_fd)

    for target in (inventory_path, receipt_path):
        try:
            state = target.lstat()
        except FileNotFoundError:
            continue
        except OSError as err:
            raise ConceptInventoryError("output_target_stat_failed") from err
        if stat.S_ISLNK(state.st_mode) or not stat.S_ISREG(state.st_mode):
            raise ConceptInventoryError("output_target_invalid")
        raise ConceptInventoryError("output_exists")
    staged: List[Tuple[Path, Path]] = []
    published: List[Tuple[Path, Path]] = []
    try:
        for target, body in ((inventory_path, inventory_bytes), (receipt_path, receipt_bytes)):
            temporary = parent / f".{target.name}.{secrets.token_hex(16)}.tmp"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(temporary, flags, 0o600)
            try:
                if os.name != "nt":
                    os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    descriptor = -1
                    handle.write(body)
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            staged.append((temporary, target))
        for temporary, target in staged:
            os.link(temporary, target, follow_symlinks=False)
            os.unlink(temporary)
            published.append((temporary, target))
        for _, target in published:
            state = target.lstat()
            if not stat.S_ISREG(state.st_mode):
                raise ConceptInventoryError("output_mode_invalid")
    except Exception as err:
        for _, target in reversed(published):
            try:
                target.unlink()
            except OSError:
                pass
        for temporary, _ in staged:
            try:
                temporary.unlink()
            except OSError:
                pass
        if isinstance(err, ConceptInventoryError):
            raise
        if isinstance(err, FileExistsError):
            raise ConceptInventoryError("output_exists") from err
        raise ConceptInventoryError("output_atomic_write_failed") from err


def compile_concept_inventory(
    recall_path: os.PathLike[str] | str,
    inventory_path: os.PathLike[str] | str,
    receipt_path: os.PathLike[str] | str,
    *,
    replace: bool = False,
    limits: Optional[InventoryLimits | Mapping[str, Any]] = None,
    domain_keywords: Optional[DomainKeywordConfig] = None,
    domain_keywords_path: os.PathLike[str] | str | None = None,
) -> Dict[str, Any]:
    """Compile one validated recall JSONL into a private inventory and receipt."""

    if not isinstance(replace, bool):
        raise ConceptInventoryError("replace_invalid")
    if replace:
        # v1 publishes a two-file evidence set.  Safe no-overwrite publication
        # is supported; pair-atomic replacement requires a transaction marker
        # protocol and is intentionally not claimed here.
        raise ConceptInventoryError("replace_not_supported")
    bounded = _coerce_limits(limits)
    recall = Path(os.path.abspath(recall_path))
    inventory_target = Path(os.path.abspath(inventory_path))
    receipt_target = Path(os.path.abspath(receipt_path))
    if recall in {inventory_target, receipt_target}:
        raise ConceptInventoryError("input_output_overlap")
    records, input_digest, input_matched_records = _read_recall(recall, bounded)
    if domain_keywords is None:
        domain_keywords = load_domain_keywords(domain_keywords_path)
    inventory = _build_inventory(
        records,
        bounded,
        semantic_input_sha256=input_digest,
        input_matched_records=input_matched_records,
        domain_keywords=domain_keywords,
    )
    validate_concept_inventory(inventory)
    inventory_bytes = _stable_bytes(inventory)
    counts = _inventory_counts(inventory)
    counts["inventory_bytes"] = len(inventory_bytes)
    receipt = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "scan_complete": True,
        "review_required": True,
        "authoritative": False,
        "counts": counts,
        "digests": {
            "inventory_sha256": _digest_bytes(inventory_bytes),
            "semantic_input_sha256": inventory["corpus"]["semantic_input_sha256"],
            "corpus_id_sha256": _digest_json(inventory["corpus"]["corpus_id"], domain="receipt-corpus-id"),
            "index_generation_sha256": _digest_json(inventory["corpus"]["index_generation"], domain="receipt-index-generation"),
            "run_id_sha256": _digest_json(inventory["corpus"]["run_id"], domain="receipt-run-id"),
            "rules_sha256": _digest_json(inventory["rules"], domain="receipt-rules"),
        },
    }
    validate_concept_receipt(receipt, inventory_bytes=inventory_bytes)
    receipt_bytes = _stable_bytes(receipt)
    _write_pair_atomic(inventory_target, inventory_bytes, receipt_target, receipt_bytes, replace=replace)
    return receipt


__all__ = [
    "ConceptInventoryError",
    "InventoryLimits",
    "INVENTORY_SCHEMA_VERSION",
    "RECEIPT_SCHEMA_VERSION",
    "DOMAIN_SCOPE",
    "DomainKeywordConfig",
    "LEGACY_DOMAIN_SCOPE_ALIAS",
    "canonical_scope",
    "compile_concept_inventory",
    "load_domain_keywords",
    "validate_concept_inventory",
    "validate_concept_receipt",
]
