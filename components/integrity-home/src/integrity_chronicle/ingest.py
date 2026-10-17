"""Deterministic staged-adapter parsing for provider exports."""

from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from importlib import import_module
from inspect import isclass
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
import json
import math
import re
import tempfile

from .semantic_extraction import (
    CLAIM_UNKNOWN_TIME_SORT_KEY,
    FakeSemanticExtractor,
    SemanticExtractor,
    build_claim_records as build_fake_claim_records,
)
from .gemini_takeout import (
    TAKEOUT_HTML_ADAPTER_ORIGIN,
    TAKEOUT_HTML_COUNT_FIELDS,
    TAKEOUT_HTML_SCHEMA_VERSION,
    GeminiTakeoutHtmlError,
    gemini_takeout_html_candidates,
    parse_gemini_takeout_html,
)


CANONICAL_SCHEMA_VERSION = "chronicle-canonical/1"
OPENAI_SCHEMA_VERSIONS = {"openai-chatgpt/1", "openai-chatgpt/unversioned"}
CLAUDE_SCHEMA_VERSIONS = {"anthropic-claude/1", "anthropic-claude/unversioned"}
GEMINI_SCHEMA_VERSIONS = {
    "google-gemini/1",
    "google-gemini/unversioned",
}
OPENAI_SCHEMA_PREFIX = "openai-chatgpt/"
CLAUDE_SCHEMA_PREFIX = "anthropic-claude/"
GEMINI_SCHEMA_PREFIX = "google-gemini/"
PROVIDER_HINT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
MAX_DUPLICATE_NORMALIZED_CHARS = 128 * 1024**2
MAX_DUPLICATE_TOKEN_WORK = 20_000_000
MAX_DUPLICATE_COMPARISONS = 2_000_000
OPENAI_CONVERSATION_SHARD_RE = re.compile(
    r"^conversations-(\d+)\.json$", re.IGNORECASE
)
SOURCE_PROVENANCE_FIELD = "__integrity_chronicle_source_provenance__"
SUPPLEMENTAL_PAYLOAD_FILES_FIELD = (
    "__integrity_chronicle_supplemental_payload_files__"
)
GENERIC_PROVIDER_FILES = (
    "conversations.json",
    "threads.json",
    "messages.json",
    "chat.json",
    "history.json",
    "messages_export.json",
    "export.json",
    "openai_export.json",
    "chatgpt_export.json",
    "claude_export.json",
    "gemini_export.json",
    "gemini_conversations.json",
)
PROVIDER_SCHEMA_NAMESPACES = {
    "openai_chatgpt": "openai-chatgpt",
    "anthropic_claude": "anthropic-claude",
    "google_gemini": "google-gemini",
}
CONVERSATION_ID_FIELDS = ("conversation_id", "conversationId", "id", "uuid")
MESSAGE_ID_FIELDS = ("message_id", "messageId", "id", "uuid")
MESSAGE_PARENT_FIELDS = (
    "parent_message_id",
    "parentMessageId",
    "parent_id",
    "parentId",
    "parent",
    "parent_uuid",
    "parentUuid",
)
ROLE_FIELDS = ("role", "speaker", "sender", "type", "author", "actor")
CREATED_TIMESTAMP_FIELDS = (
    "created_at",
    "createdAt",
    "created_on",
    "createdOn",
    "createdTime",
    "create_time",
    "createTime",
    "timestamp",
)
UPDATED_TIMESTAMP_FIELDS = (
    "updated_at",
    "updatedAt",
    "updated_on",
    "updatedOn",
    "updatedTime",
    "update_time",
    "updateTime",
    "modified_at",
    "modifiedAt",
)
CONTENT_FIELDS = ("content", "text", "body", "parts")
ATTACHMENT_FIELDS = (
    "attachments",
    "attachment",
    "files",
    "file",
    "file_attachments",
    "fileAttachments",
    "images",
    "image",
)
SEMANTIC_MODULE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
SEMANTIC_CLASS_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SEMANTIC_CLAIM_REQUIRED_STRING_FIELDS = {
    "claim_id",
    "claim_type",
    "claim_text",
    "claim_signature",
    "claim_polarity",
    "temporal_state",
}
_SEMANTIC_CLAIM_REQUIRED_BOOL_FIELDS = {
    "has_negation",
    "is_user_assertion",
    "has_correction_marker",
    "has_unknown_timestamp",
}
_SEMANTIC_CLAIM_REQUIRED_LIST_FIELDS = {
    "supersedes",
    "superseded_by",
    "contradicts",
}
_SEMANTIC_CLAIM_ALLOWED_TEMPORAL_STATES = {"active", "contradicted", "superseded"}


def _canonical_role(value: Any) -> Optional[str]:
    if isinstance(value, str):
        value = value.strip().lower()
        if not value:
            return None
        if value in {"human", "user", "customer"}:
            return "user"
        if value in {"assistant", "model", "bot"}:
            return "assistant"
        if value in {"system", "tool", "function"}:
            return value
        return value

    if isinstance(value, dict):
        for key in ("type", "role", "name", "speaker", "sender"):
            candidate = value.get(key)
            canonical = _canonical_role(candidate)
            if canonical:
                return canonical
    return None


class CanonicalizationError(ValueError):
    """Raised when provider fixture shape cannot be converted deterministically."""


@dataclass(frozen=True)
class CanonicalMessage:
    message_id: str
    provider_message_id: str
    parent_message_id: Optional[str]
    provider_parent_message_id: Optional[str]
    role: str
    provider_roles: Dict[str, Any]
    created_at: Optional[str]
    updated_at: Optional[str]
    provider_timestamps: Dict[str, Any]
    content: str
    content_type: str
    content_blocks: List[Dict[str, Any]]
    attachments: List[Dict[str, Any]]
    model: Optional[str]
    provider_identifiers: Dict[str, Any]
    provider_parent_identifiers: Dict[str, Any]
    provider_metadata: Dict[str, Any]
    source_index: int
    branch_path: str
    branch_depth: int
    has_unknown_parent: bool
    has_unknown_timestamp: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "provider_message_id": self.provider_message_id,
            "parent_message_id": self.parent_message_id,
            "provider_parent_message_id": self.provider_parent_message_id,
            "role": self.role,
            "provider_roles": self.provider_roles,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "provider_timestamps": self.provider_timestamps,
            "content": self.content,
            "content_type": self.content_type,
            "content_blocks": self.content_blocks,
            "attachments": self.attachments,
            "model": self.model,
            "provider_identifiers": self.provider_identifiers,
            "provider_parent_identifiers": self.provider_parent_identifiers,
            "provider_metadata": self.provider_metadata,
            "source_index": self.source_index,
            "branch_path": self.branch_path,
            "branch_depth": self.branch_depth,
            "has_unknown_parent": self.has_unknown_parent,
            "has_unknown_timestamp": self.has_unknown_timestamp,
        }


def _is_file(path: Path) -> bool:
    return path.is_file()


def _reject_duplicate_object_pairs(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """Build one JSON object while rejecting duplicate keys at any depth.

    Python's default JSON decoder silently keeps the last duplicate member.
    Provider exports are evidence, so that behaviour would destroy one of the
    conflicting values before an adapter could report or preserve it.
    ``object_pairs_hook`` invokes this function for every nested object.
    """

    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalizationError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _load_json(path: Path) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as fp:
            return json.load(fp, object_pairs_hook=_reject_duplicate_object_pairs)
    except json.JSONDecodeError as err:
        raise CanonicalizationError(
            f"invalid JSON payload {path.name}: line {err.lineno} column {err.colno}"
        ) from err


def _first_existing_file(base: Path, *candidates: str) -> Optional[Path]:
    existing = [base / name for name in candidates if _is_file(base / name)]
    if len(existing) > 1:
        names = ", ".join(path.name for path in existing)
        raise CanonicalizationError(f"multiple provider payload files found: {names}")
    return existing[0] if existing else None


def _openai_conversation_shards(base: Path) -> List[Path]:
    """Return split ChatGPT conversation files in deterministic numeric order."""

    matches: List[Tuple[int, str, Path]] = []
    by_shard_index: Dict[int, str] = {}
    for path in base.iterdir():
        if not _is_file(path):
            continue
        match = OPENAI_CONVERSATION_SHARD_RE.fullmatch(path.name)
        if match is None:
            continue
        shard_index = int(match.group(1))
        previous = by_shard_index.get(shard_index)
        if previous is not None:
            raise CanonicalizationError(
                "multiple ChatGPT conversation shards use index "
                f"{shard_index}: {previous}, {path.name}"
            )
        by_shard_index[shard_index] = path.name
        matches.append((shard_index, path.name.lower(), path))
    matches.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in matches]


def _json_clone(value: Any, *, context: str) -> Any:
    """Return a deterministic JSON-compatible copy or reject the value."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError(f"non-finite number in {context}")
        return value
    if isinstance(value, list):
        return [
            _json_clone(item, context=f"{context}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        copied: Dict[str, Any] = {}
        keys = list(value)
        for key in keys:
            if not isinstance(key, str):
                raise CanonicalizationError(f"non-string object key in {context}")
        for key in sorted(keys):
            copied[key] = _json_clone(value[key], context=f"{context}.{key}")
        return copied
    raise CanonicalizationError(
        f"unsupported JSON value type in {context}: {type(value).__name__}"
    )


def _field_snapshot(candidate: Dict[str, Any], fields: Sequence[str], *, context: str) -> Dict[str, Any]:
    return {
        field: _json_clone(candidate[field], context=f"{context}.{field}")
        for field in fields
        if field in candidate
    }


def _unknown_fields(
    candidate: Dict[str, Any],
    consumed_fields: Set[str],
    *,
    context: str,
) -> Dict[str, Any]:
    return {
        field: _json_clone(candidate[field], context=f"{context}.{field}")
        for field in sorted(candidate)
        if field not in consumed_fields
    }


def _normalize_payload_object(payload: Any, provider: str) -> Dict[str, Any]:
    """Normalize unversioned provider list exports without inventing a version."""

    namespace = PROVIDER_SCHEMA_NAMESPACES.get(provider, provider)
    if isinstance(payload, list):
        return {
            "schema_version": f"{namespace}/unversioned",
            "conversations": _json_clone(payload, context=f"{provider} payload"),
            "source_shape": "top-level-list",
        }
    if not isinstance(payload, dict):
        raise CanonicalizationError(
            f"payload is neither an object nor an array for provider {provider}"
        )
    normalized = _json_clone(payload, context=f"{provider} payload")
    if "schema_version" not in normalized:
        normalized["schema_version"] = f"{namespace}/unversioned"
    return normalized


def build_semantic_extractor(spec: str = "fake") -> SemanticExtractor:
    if not isinstance(spec, str):
        raise CanonicalizationError("semantic backend spec must be a string")

    if spec == "fake":
        return FakeSemanticExtractor()

    module_name, _, class_name = spec.rpartition(":")
    if not module_name or not class_name:
        raise CanonicalizationError(
            "semantic backend spec must be 'fake' or 'module.path:ClassName'"
        )
    if not SEMANTIC_MODULE_NAME_RE.fullmatch(module_name):
        raise CanonicalizationError(f"invalid semantic backend module name: {module_name}")
    if not SEMANTIC_CLASS_NAME_RE.fullmatch(class_name):
        raise CanonicalizationError(f"invalid semantic backend class name: {class_name}")

    try:
        module = import_module(module_name)
    except ModuleNotFoundError as err:
        raise CanonicalizationError(f"semantic backend module not found: {module_name}") from err
    except Exception as err:
        raise CanonicalizationError(
            f"semantic backend module import failed: {module_name}"
        ) from err

    extractor = getattr(module, class_name, None)
    if extractor is None:
        raise CanonicalizationError(f"semantic backend not found: {class_name} in {module_name}")

    if not isclass(extractor):
        raise CanonicalizationError(
            f"semantic backend target must be a class: {class_name} in {module_name}"
        )

    try:
        extractor_instance = extractor()
    except TypeError as err:
        raise CanonicalizationError(
            f"semantic backend class must be constructible without arguments: {spec}"
        ) from err
    except Exception as err:
        raise CanonicalizationError(
            f"semantic backend construction failed: {spec}"
        ) from err

    if not callable(getattr(extractor_instance, "extract_claim_records", None)):
        raise CanonicalizationError(
            f"semantic backend does not implement extract_claim_records: {spec}"
        )
    return extractor_instance


def _provider_signature(payload: Any) -> Optional[str]:
    if isinstance(payload, dict):
        schema = payload.get("schema_version")
        if isinstance(schema, str):
            if schema.startswith(OPENAI_SCHEMA_PREFIX):
                return "openai_chatgpt"
            if schema.startswith(CLAUDE_SCHEMA_PREFIX):
                return "anthropic_claude"
            if schema.startswith(GEMINI_SCHEMA_PREFIX):
                return "google_gemini"
        containers = [
            payload.get(key)
            for key in ("conversations", "threads", "chats")
            if isinstance(payload.get(key), list)
        ]
        records = [item for container in containers for item in container]
    elif isinstance(payload, list):
        records = list(payload)
    else:
        return None

    signatures: Set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        if "mapping" in record:
            signatures.add("openai_chatgpt")
        if "chat_messages" in record:
            signatures.add("anthropic_claude")
        if "turns" in record:
            signatures.add("google_gemini")
    return next(iter(signatures)) if len(signatures) == 1 else None


def _infer_provider(base: Path, provider_hint: Optional[str] = None) -> str:
    if provider_hint:
        if not isinstance(provider_hint, str):
            raise CanonicalizationError("provider hint must be a string")
        normalized = provider_hint.strip()
        if not normalized:
            raise CanonicalizationError("provider hint must be a non-empty string")
        if normalized in {"openai_chatgpt", "anthropic_claude", "google_gemini"}:
            return normalized
        if not PROVIDER_HINT_RE.fullmatch(normalized):
            raise CanonicalizationError(f"unsupported provider hint: {provider_hint}")
        return normalized

    names = {p.name.lower() for p in base.iterdir() if p.is_file()}
    openai_hits = [
        n
        for n in names
        if n.startswith("openai")
        or "chatgpt" in n
        or OPENAI_CONVERSATION_SHARD_RE.fullmatch(n)
    ]
    claude_hits = [n for n in names if n.startswith("claude") or "memories.json" in n]
    gemini_hits = [n for n in names if n.startswith("gemini") or n.startswith("bard")]
    try:
        gemini_takeout_hits = gemini_takeout_html_candidates(base)
    except GeminiTakeoutHtmlError as err:
        raise CanonicalizationError(str(err)) from err
    has_openai = bool(openai_hits)
    has_claude = bool(claude_hits)
    has_gemini = bool(gemini_hits or gemini_takeout_hits)
    if sum((has_openai, has_claude, has_gemini)) > 1:
        raise CanonicalizationError("provider ambiguous in staged payload")
    if has_openai:
        return "openai_chatgpt"
    if has_claude:
        return "anthropic_claude"
    if has_gemini:
        return "google_gemini"

    generic_paths = [base / name for name in GENERIC_PROVIDER_FILES if _is_file(base / name)]
    if len(generic_paths) > 1:
        raise CanonicalizationError("provider ambiguous across multiple generic payload files")
    if generic_paths:
        inferred = _provider_signature(_load_json(generic_paths[0]))
        if inferred:
            return inferred
    raise CanonicalizationError("no provider fixture found in staged payload")


def _coerce_schema_version(raw: Any, provider: str) -> str:
    if not isinstance(raw, str):
        if raw is None:
            namespace = PROVIDER_SCHEMA_NAMESPACES.get(provider, provider)
            return f"{namespace}/unversioned"
        raise CanonicalizationError(
            f"invalid schema_version type for provider {provider}: {type(raw).__name__}"
        )

    normalized = raw.strip()
    if not normalized:
        return f"{provider}/unversioned"

    if provider == "openai_chatgpt" and not normalized.startswith(OPENAI_SCHEMA_PREFIX):
        raise CanonicalizationError(
            f"unsupported schema namespace for {provider}: {normalized}"
        )
    if provider == "anthropic_claude" and not normalized.startswith(CLAUDE_SCHEMA_PREFIX):
        raise CanonicalizationError(
            f"unsupported schema namespace for {provider}: {normalized}"
        )
    if provider == "google_gemini" and not normalized.startswith(GEMINI_SCHEMA_PREFIX):
        raise CanonicalizationError(
            f"unsupported schema namespace for {provider}: {normalized}"
        )
    return normalized


def _coerce_text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return default


def _source_staging_id(staging_path: str) -> str:
    return Path(staging_path).name


def _stable_projection_id(record: Dict[str, Any]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return sha256(payload).hexdigest()


def _coerce_conversation_id(candidate: Dict[str, Any], index: int) -> str:
    conversation_id = (
        candidate.get("conversation_id")
        or candidate.get("conversationId")
        or candidate.get("id")
        or candidate.get("uuid")
    )
    if isinstance(conversation_id, str) and conversation_id:
        return conversation_id
    return f"conv-{index:04d}"


def _coerce_message_id(candidate: Dict[str, Any], index: int) -> str:
    message_id = (
        candidate.get("message_id")
        or candidate.get("messageId")
        or candidate.get("id")
        or candidate.get("uuid")
    )
    if isinstance(message_id, str) and message_id:
        return message_id
    payload = json.dumps(candidate, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"msg-{digest}-{index:04d}"


def _coerce_role(candidate: Dict[str, Any]) -> str:
    role = (
        candidate.get("role")
        or candidate.get("speaker")
        or candidate.get("sender")
        or candidate.get("type")
        or candidate.get("author")
        or candidate.get("actor")
    )
    canonical = _canonical_role(role)
    if canonical:
        return canonical
    if isinstance(role, str) and role:
        return role
    return "unknown"


def _coerce_parent_id(candidate: Dict[str, Any]) -> Optional[str]:
    parent_id = (
        candidate.get("parent_message_id")
        or candidate.get("parentMessageId")
        or candidate.get("parent_id")
        or candidate.get("parentId")
        or candidate.get("parent")
        or candidate.get("parent_uuid")
        or candidate.get("parentUuid")
    )
    if isinstance(parent_id, str) and parent_id:
        return parent_id
    return None


def _coerce_timestamp_value(value: Any) -> Optional[str]:
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return None
        try:
            parsed = datetime.fromisoformat(
                candidate[:-1] + "+00:00" if candidate.endswith("Z") else candidate
            )
        except (OverflowError, ValueError):
            return None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed.astimezone(timezone.utc).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        numeric = float(value)
        if not math.isfinite(numeric):
            return None
        # Published ChatGPT-style exports use Unix seconds. Accept milliseconds
        # as a bounded compatibility form while retaining the exact raw value in
        # provider_timestamps.
        seconds = numeric / 1000.0 if abs(numeric) >= 100_000_000_000 else numeric
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat(
                timespec="microseconds"
            ).replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return None
    return None


def _coerce_named_timestamp(
    candidate: Dict[str, Any], fields: Sequence[str]
) -> Optional[str]:
    for key in fields:
        if key not in candidate:
            continue
        timestamp = _coerce_timestamp_value(candidate[key])
        if timestamp is not None:
            return timestamp
    return None


def _coerce_timestamp(candidate: Dict[str, Any]) -> tuple[Optional[str], bool]:
    timestamp = _coerce_named_timestamp(candidate, CREATED_TIMESTAMP_FIELDS)
    return timestamp, timestamp is None


def _coerce_updated_timestamp(candidate: Dict[str, Any]) -> Optional[str]:
    return _coerce_named_timestamp(candidate, UPDATED_TIMESTAMP_FIELDS)


def _provider_timestamps(candidate: Dict[str, Any], *, context: str) -> Dict[str, Any]:
    return _field_snapshot(
        candidate,
        (*CREATED_TIMESTAMP_FIELDS, *UPDATED_TIMESTAMP_FIELDS),
        context=context,
    )


def _coerce_label_list(
    claim: Dict[str, Any],
    *,
    index: int,
    field_name: str,
) -> None:
    value = claim.get(field_name)
    if value is None:
        return
    if not isinstance(value, list):
        raise CanonicalizationError(
            f"semantic backend claim record at index {index} has invalid {field_name}; expected a list"
        )

    normalized: List[str] = []
    for item in value:
        if not isinstance(item, str):
            raise CanonicalizationError(
                f"semantic backend claim record at index {index} has non-string {field_name} item"
            )
        candidate = item.strip()
        if not candidate:
            raise CanonicalizationError(
                f"semantic backend claim record at index {index} has invalid {field_name} value"
            )
        normalized.append(candidate)
    claim[field_name] = normalized


def _extract_text_fragments(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        parts: List[str] = []
        for item in value:
            parts.extend(_extract_text_fragments(item))
        return parts
    if isinstance(value, dict):
        parts: List[str] = []
        for key in (
            "text",
            "value",
            "content",
            "body",
            "parts",
            "blocks",
            "children",
            "caption",
            "transcript",
            "alt_text",
            "title",
            "code",
            "output",
            "result",
        ):
            if key in value:
                parts.extend(_extract_text_fragments(value[key]))
        return parts
    return []


def _coerce_content(
    candidate: Dict[str, Any], *, context: str
) -> tuple[str, str, List[Dict[str, Any]]]:
    blocks: List[Dict[str, Any]] = []
    fragments: List[str] = []
    saw_structured = False
    for field in CONTENT_FIELDS:
        if field not in candidate:
            continue
        value = candidate[field]
        copied = _json_clone(value, context=f"{context}.{field}")
        blocks.append({"source_field": field, "value": copied})
        extracted = _extract_text_fragments(value)
        if extracted:
            fragments.append("".join(extracted))
        elif isinstance(value, str):
            fragments.append(value)
        if isinstance(value, (dict, list)):
            saw_structured = True

    explicit_type = candidate.get("content_type") or candidate.get("contentType")
    if not isinstance(explicit_type, str) or not explicit_type.strip():
        explicit_type = None
        for field in CONTENT_FIELDS:
            value = candidate.get(field)
            if not isinstance(value, dict):
                continue
            for key in ("content_type", "contentType", "type", "kind"):
                nested_type = value.get(key)
                if isinstance(nested_type, str) and nested_type.strip():
                    explicit_type = nested_type.strip()
                    break
            if explicit_type:
                break

    if fragments:
        content = "\n".join(fragments)
        content_type = explicit_type or "text"
    elif blocks:
        content = json.dumps(blocks, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        content_type = explicit_type or ("json" if saw_structured else "text")
    else:
        content = ""
        content_type = explicit_type or "text"
    return content, content_type, blocks


def _attachment_like(value: Dict[str, Any]) -> bool:
    kind = value.get("type") or value.get("kind") or value.get("content_type")
    if isinstance(kind, str) and any(
        marker in kind.lower()
        for marker in ("attachment", "file", "image", "audio", "video", "document")
    ):
        return True
    return any(
        key in value
        for key in (
            "asset_pointer",
            "file_id",
            "fileId",
            "filename",
            "file_name",
            "mime_type",
            "mimeType",
        )
    )


def _collect_nested_attachments(
    value: Any,
    *,
    path: str,
    target: List[Dict[str, Any]],
) -> None:
    if isinstance(value, dict):
        if _attachment_like(value):
            target.append(
                {
                    "source_path": path,
                    "metadata": _json_clone(value, context=f"attachment {path}"),
                }
            )
        for key in sorted(value):
            _collect_nested_attachments(value[key], path=f"{path}.{key}", target=target)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _collect_nested_attachments(item, path=f"{path}[{index}]", target=target)


def _collect_attachments(candidate: Dict[str, Any], *, context: str) -> List[Dict[str, Any]]:
    attachments: List[Dict[str, Any]] = []
    for field in ATTACHMENT_FIELDS:
        if field not in candidate:
            continue
        value = candidate[field]
        items = value if isinstance(value, list) else [value]
        for index, item in enumerate(items):
            suffix = f"[{index}]" if isinstance(value, list) else ""
            attachments.append(
                {
                    "source_path": f"{field}{suffix}",
                    "metadata": _json_clone(item, context=f"{context}.{field}{suffix}"),
                }
            )
    for field in CONTENT_FIELDS:
        if field in candidate:
            _collect_nested_attachments(
                candidate[field], path=field, target=attachments
            )
    attachments.sort(
        key=lambda item: (
            item["source_path"],
            json.dumps(item["metadata"], sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        )
    )
    return attachments


def _normalize_for_duplicate_detection(value: str) -> str:
    normalized = value.lower().strip()
    normalized = re.sub(r"\s+", " ", normalized)
    normalized = re.sub(r"[^\w\s]", " ", normalized, flags=re.UNICODE)
    return re.sub(r"\s+", " ", normalized).strip()


def _tokenize_for_duplicate_detection(value: str) -> List[str]:
    if not value:
        return []
    return [token for token in value.split(" ") if token]


def _build_claim_records(
    source_id: str,
    conversations: List[Dict[str, Any]],
    extractor: Optional[SemanticExtractor] = None,
) -> List[Dict[str, Any]]:
    original_message_locations: Dict[Tuple[Any, Any], int] = {}
    for conversation in conversations:
        conversation_id = conversation.get("conversation_id")
        for message_index, message in enumerate(conversation.get("messages", [])):
            if isinstance(message, dict):
                original_message_locations[(conversation_id, message.get("message_id"))] = message_index
    quarantined_message_refs = {
        (conversation.get("conversation_id"), message.get("message_id"))
        for conversation in conversations
        for message in conversation.get("messages", [])
        if isinstance(message, dict)
        and isinstance(message.get("provider_metadata"), dict)
        and message["provider_metadata"].get("integrity_quarantine") is True
    }
    active_extractor = extractor or FakeSemanticExtractor()
    try:
        extractor_conversations = _json_clone(
            conversations, context="semantic backend conversation input"
        )
        raw_claims = active_extractor.extract_claim_records(
            source_id, extractor_conversations
        )
    except Exception as err:
        raise CanonicalizationError(f"semantic backend claim extraction failed: {err}") from err

    if not isinstance(raw_claims, list):
        raise CanonicalizationError("semantic backend returned non-list claim records")

    claims: List[Dict[str, Any]] = []
    seen_claim_ids: Set[str] = set()
    for index, claim in enumerate(raw_claims):
        if not isinstance(claim, dict):
            raise CanonicalizationError(
                f"semantic backend returned non-dict claim record at index {index}"
            )
        claim_id = claim.get("claim_id")
        if not isinstance(claim_id, str) or not claim_id:
            raise CanonicalizationError(
                f"semantic backend claim record at index {index} has invalid claim_id"
            )

        if claim_id in seen_claim_ids:
            raise CanonicalizationError(
                f"semantic backend returned duplicate claim_id {claim_id} at index {index}"
            )
        seen_claim_ids.add(claim_id)

        if not isinstance(claim.get("conversation_id"), str):
            raise CanonicalizationError(
                f"semantic backend claim record at index {index} missing required string field: conversation_id"
            )

        if not isinstance(claim.get("message_id"), str):
            raise CanonicalizationError(
                f"semantic backend claim record at index {index} missing required string field: message_id"
            )
        for key in sorted(_SEMANTIC_CLAIM_REQUIRED_STRING_FIELDS):
            value = claim.get(key)
            if not isinstance(value, str):
                raise CanonicalizationError(
                    f"semantic backend claim record at index {index} missing required string field: {key}"
                )
            if key in {"claim_id", "claim_type", "claim_signature", "claim_polarity", "temporal_state"} and not value:
                raise CanonicalizationError(
                    f"semantic backend claim record at index {index} missing required string field: {key}"
                )

        for key in sorted(_SEMANTIC_CLAIM_REQUIRED_BOOL_FIELDS):
            if not isinstance(claim.get(key), bool):
                raise CanonicalizationError(
                    f"semantic backend claim record at index {index} missing required bool field: {key}"
                )

        for key in sorted(_SEMANTIC_CLAIM_REQUIRED_LIST_FIELDS):
            links = claim.get(key)
            if not isinstance(links, list):
                raise CanonicalizationError(
                    f"semantic backend claim record at index {index} missing required list field: {key}"
                )
            if not all(isinstance(item, str) for item in links):
                raise CanonicalizationError(
                    f"semantic backend claim record at index {index} has non-string {key} item"
                )

        created_at = claim.get("created_at")
        if created_at is not None and not isinstance(created_at, str):
            raise CanonicalizationError(
                f"semantic backend claim record at index {index} has invalid created_at"
            )

        has_unknown_timestamp = claim.get("has_unknown_timestamp")
        if not isinstance(has_unknown_timestamp, bool):
            raise CanonicalizationError(
                f"semantic backend claim record at index {index} missing required bool field: has_unknown_timestamp"
            )

        valid_from = claim.get("valid_from")
        if valid_from is not None and not isinstance(valid_from, str):
            raise CanonicalizationError(
                f"semantic backend claim record at index {index} has invalid valid_from"
            )

        valid_to = claim.get("valid_to")
        if valid_to is not None and not isinstance(valid_to, str):
            raise CanonicalizationError(
                f"semantic backend claim record at index {index} has invalid valid_to"
            )

        source_message_index = claim.get("source_message_index")
        if not isinstance(source_message_index, int) or source_message_index < 0:
            raise CanonicalizationError(
                f"semantic backend claim record at index {index} has invalid source_message_index"
            )
        message_ref = (claim["conversation_id"], claim["message_id"])
        if message_ref not in original_message_locations:
            raise CanonicalizationError(
                f"semantic backend claim record at index {index} does not resolve to an original message"
            )
        if source_message_index != original_message_locations[message_ref]:
            raise CanonicalizationError(
                f"semantic backend claim record at index {index} has inconsistent source_message_index"
            )
        if message_ref in quarantined_message_refs:
            raise CanonicalizationError(
                "semantic backend returned a claim for an integrity-quarantined message"
            )

        if not isinstance(claim.get("provenance"), dict):
            raise CanonicalizationError(
                f"semantic backend claim record at index {index} missing required dict field: provenance"
            )

        temporal_state = claim.get("temporal_state")
        if temporal_state not in _SEMANTIC_CLAIM_ALLOWED_TEMPORAL_STATES:
            raise CanonicalizationError(
                f"semantic backend claim record at index {index} has invalid temporal_state: {temporal_state}"
            )

        _coerce_label_list(claim, index=index, field_name="sensitivity_labels")
        _coerce_label_list(claim, index=index, field_name="scope_labels")
        claims.append(claim)
    return claims


def _jaccard_similarity(left_tokens: List[str], right_tokens: List[str]) -> float:
    left = set(left_tokens)
    right = set(right_tokens)
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return len(left.intersection(right)) / len(left.union(right))


def _jaccard_token_sets(left: Set[str], right: Set[str]) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    smaller, larger = (left, right) if len(left) <= len(right) else (right, left)
    intersection_size = sum(token in larger for token in smaller)
    return intersection_size / (len(left) + len(right) - intersection_size)


def _ceil_similarity_product(similarity: float, size: int) -> int:
    """Return a conservative ceil for a float threshold times a set size.

    ``nextafter`` prevents a binary-float product that lands just above an
    integer from shortening a prefix or excluding a boundary-length candidate.
    A longer prefix can add work, but cannot hide a qualifying pair.
    """

    return math.ceil(math.nextafter(similarity * size, -math.inf))


def _build_duplicate_candidate_clusters(
    conversations: List[Dict[str, Any]],
    *,
    near_similarity_threshold: float = 0.70,
) -> List[Dict[str, Any]]:
    if (
        isinstance(near_similarity_threshold, bool)
        or not isinstance(near_similarity_threshold, (int, float))
        or not math.isfinite(near_similarity_threshold)
        or not 0 < near_similarity_threshold <= 1
    ):
        raise CanonicalizationError(
            "duplicate-candidate similarity threshold must be finite and in (0, 1]"
        )

    message_rows: List[Dict[str, Any]] = []
    token_cache: Dict[str, Tuple[str, ...]] = {}
    normalized_char_work = 0
    token_work = 0
    for conversation in conversations:
        conversation_id = str(conversation.get("conversation_id", ""))
        for message in conversation.get("messages", []):
            if not isinstance(message, dict):
                continue
            message_id = message.get("message_id")
            if not isinstance(message_id, str) or not message_id:
                continue
            content = message.get("content", "")
            if not isinstance(content, str):
                continue
            normalized_content = _normalize_for_duplicate_detection(content)
            if not normalized_content:
                continue
            normalized_char_work += len(normalized_content)
            if normalized_char_work > MAX_DUPLICATE_NORMALIZED_CHARS:
                raise CanonicalizationError(
                    "duplicate-candidate normalized-content budget exceeded"
                )
            cached_tokens = token_cache.get(normalized_content)
            if cached_tokens is None:
                cached_tokens = tuple(
                    _tokenize_for_duplicate_detection(normalized_content)
                )
                token_cache[normalized_content] = cached_tokens
                token_work += len(cached_tokens)
                if token_work > MAX_DUPLICATE_TOKEN_WORK:
                    raise CanonicalizationError(
                        "duplicate-candidate token-work budget exceeded"
                    )
            tokens = cached_tokens
            if len(tokens) < 2:
                continue
            message_rows.append(
                {
                    "conversation_id": conversation_id,
                    "message_id": message_id,
                    "role": str(message.get("role", "")),
                    "message_ref": f"{conversation_id}/{message_id}",
                    "normalized": normalized_content,
                    "tokens": tokens,
                    "branch_path": str(message.get("branch_path", "")),
                }
            )

    if len(message_rows) < 2:
        return []

    exact_groups: List[Dict[str, Any]] = []
    exact_ref_signatures: Set[Tuple[str, ...]] = set()
    exact_buckets: Dict[str, List[Dict[str, Any]]] = {}
    for row in message_rows:
        exact_buckets.setdefault(row["normalized"], []).append(row)

    for normalized, group in sorted(exact_buckets.items(), key=lambda item: item[0]):
        if len(group) < 2:
            continue
        refs = sorted(row["message_ref"] for row in group)
        branch_paths = sorted(
            {
                row["branch_path"]
                for row in group
                if row.get("branch_path")
            }
        )
        exact_groups.append(
            {
                "candidate_type": "exact_duplicate",
                "message_count": len(refs),
                "message_refs": refs,
                "branch_paths": branch_paths,
                "normalized_content": normalized,
                "content_digest": sha256(normalized.encode("utf-8")).hexdigest(),
            }
        )
        exact_ref_signatures.add(tuple(refs))

    if not message_rows:
        return exact_groups

    # Compare each distinct (role, normalized-content) value once.  Exact
    # duplicates remain fully represented through ``members`` but cannot turn
    # one common prefix into quadratic repeated similarity work.
    unique_rows: List[Dict[str, Any]] = []
    unique_by_key: Dict[Tuple[str, str], int] = {}
    for row in message_rows:
        key = (row["role"], row["normalized"])
        unique_index = unique_by_key.get(key)
        if unique_index is None:
            unique_index = len(unique_rows)
            unique_by_key[key] = unique_index
            unique_rows.append(
                {
                    **row,
                    "token_set": frozenset(row["tokens"]),
                    "members": [row],
                }
            )
        else:
            unique_rows[unique_index]["members"].append(row)

    parent = list(range(len(unique_rows)))
    order = {index: index for index in range(len(unique_rows))}
    component_max_similarity = [0.0] * len(unique_rows)

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int, similarity: float) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root == right_root:
            component_max_similarity[left_root] = max(
                component_max_similarity[left_root], similarity
            )
            return
        left_order = order[left_root]
        right_order = order[right_root]
        if left_order <= right_order:
            parent[right_root] = left_root
            component_max_similarity[left_root] = max(
                component_max_similarity[left_root],
                component_max_similarity[right_root],
                similarity,
            )
        else:
            parent[left_root] = right_root
            component_max_similarity[right_root] = max(
                component_max_similarity[left_root],
                component_max_similarity[right_root],
                similarity,
            )

    buckets: Dict[Tuple[str, Tuple[str, ...]], List[int]] = {}
    for index, row in enumerate(unique_rows):
        if row["role"] == "unknown":
            continue
        key = (row["role"], row["tokens"][:2])
        buckets.setdefault(key, []).append(index)

    comparison_count = 0
    for bucket in buckets.values():
        if len(bucket) < 2:
            continue

        # Jaccard operates on sets, so distinct normalized strings with an
        # identical token set are provably 1.0-similar. Link each such group as
        # a star instead of evaluating every redundant pair.
        token_set_groups: Dict[frozenset[str], List[int]] = {}
        for index in bucket:
            token_set_groups.setdefault(unique_rows[index]["token_set"], []).append(
                index
            )
        representatives: List[int] = []
        for members in token_set_groups.values():
            representative = members[0]
            representatives.append(representative)
            for member in members[1:]:
                comparison_count += 1
                if comparison_count > MAX_DUPLICATE_COMPARISONS:
                    raise CanonicalizationError(
                        "duplicate-candidate comparison budget exceeded"
                    )
                union(representative, member, 1.0)

        if len(representatives) < 2:
            continue

        # Exact set-similarity prefix filtering. For a globally ordered token
        # set S and Jaccard threshold t, every qualifying pair shares a token
        # in prefixes of length |S| - ceil(t*|S|) + 1. Rare-first ordering is
        # only a performance choice; the prefix theorem makes the filter exact.
        token_frequency: Dict[str, int] = {}
        for index in representatives:
            token_set = unique_rows[index]["token_set"]
            token_work += len(token_set)
            if token_work > MAX_DUPLICATE_TOKEN_WORK:
                raise CanonicalizationError(
                    "duplicate-candidate token-work budget exceeded"
                )
            for token in token_set:
                token_frequency[token] = token_frequency.get(token, 0) + 1

        prefixes: Dict[int, Tuple[str, ...]] = {}
        for index in representatives:
            token_set = unique_rows[index]["token_set"]
            token_work += len(token_set)
            if token_work > MAX_DUPLICATE_TOKEN_WORK:
                raise CanonicalizationError(
                    "duplicate-candidate token-work budget exceeded"
                )
            ordered_tokens = sorted(
                token_set,
                key=lambda token: (token_frequency[token], token),
            )
            required_overlap = _ceil_similarity_product(
                near_similarity_threshold, len(ordered_tokens)
            )
            prefix_length = len(ordered_tokens) - required_overlap + 1
            prefixes[index] = tuple(ordered_tokens[:prefix_length])

        representatives.sort(
            key=lambda index: (len(unique_rows[index]["token_set"]), index)
        )
        postings: Dict[str, List[Tuple[int, int]]] = {}
        for right_index in representatives:
            right = unique_rows[right_index]
            right_size = len(right["token_set"])
            minimum_left_size = _ceil_similarity_product(
                near_similarity_threshold, right_size
            )
            candidate_indices: List[int] = []
            seen_candidates: Set[int] = set()
            for token in prefixes[right_index]:
                posting = postings.get(token, [])
                start = bisect_left(posting, (minimum_left_size, -1))
                token_work += len(posting) - start
                if token_work > MAX_DUPLICATE_TOKEN_WORK:
                    raise CanonicalizationError(
                        "duplicate-candidate token-work budget exceeded"
                    )
                for _, left_index in posting[start:]:
                    if left_index not in seen_candidates:
                        if (
                            comparison_count + len(candidate_indices) + 1
                            > MAX_DUPLICATE_COMPARISONS
                        ):
                            raise CanonicalizationError(
                                "duplicate-candidate comparison budget exceeded"
                            )
                        seen_candidates.add(left_index)
                        candidate_indices.append(left_index)

            for left_index in candidate_indices:
                left = unique_rows[left_index]
                left_size = len(left["token_set"])
                comparison_count += 1
                if comparison_count > MAX_DUPLICATE_COMPARISONS:
                    raise CanonicalizationError(
                        "duplicate-candidate comparison budget exceeded"
                    )
                token_work += left_size
                if token_work > MAX_DUPLICATE_TOKEN_WORK:
                    raise CanonicalizationError(
                        "duplicate-candidate token-work budget exceeded"
                    )
                if left_size / right_size < near_similarity_threshold:
                    continue
                similarity = _jaccard_token_sets(
                    left["token_set"], right["token_set"]
                )
                if similarity >= near_similarity_threshold:
                    union(left_index, right_index, similarity)

            for token in prefixes[right_index]:
                postings.setdefault(token, []).append((right_size, right_index))

    clusters: Dict[int, List[Dict[str, Any]]] = {}
    for index, row in enumerate(unique_rows):
        clusters.setdefault(find(index), []).append(row)

    near_candidates: List[Dict[str, Any]] = []
    for root, unique_group in clusters.items():
        group = [member for row in unique_group for member in row["members"]]
        if len(group) < 2:
            continue
        normalized_values = {row["normalized"] for row in group}
        if len(normalized_values) == 1:
            continue
        refs = sorted(row["message_ref"] for row in group)
        branch_paths = sorted(
            {
                row["branch_path"]
                for row in group
                if row.get("branch_path")
            }
        )
        if tuple(refs) in exact_ref_signatures:
            continue
        max_similarity = component_max_similarity[root]
        if max_similarity >= near_similarity_threshold:
            near_candidates.append(
                {
                    "candidate_type": "near_duplicate",
                    "message_count": len(group),
                    "message_refs": refs,
                    "branch_paths": branch_paths,
                    "max_similarity": round(max_similarity, 3),
                }
            )

    near_candidates.sort(key=lambda candidate: candidate["message_refs"])
    exact_groups.extend(near_candidates)
    return exact_groups


def _build_message_topology(message_payloads: Sequence[Dict[str, Any]]) -> List[CanonicalMessage]:
    raw_messages: List[Dict[str, Any]] = []
    base_counts: Dict[str, int] = {}
    by_base_id: Dict[str, List[str]] = {}
    for index, source in enumerate(message_payloads):
        if not isinstance(source, dict):
            raise CanonicalizationError(
                f"message record at index {index} is not an object"
            )
        context = f"message[{index}]"
        base_message_id = _coerce_message_id(source, index)
        duplicate = base_counts.get(base_message_id, 0)
        base_counts[base_message_id] = duplicate + 1
        message_id = base_message_id if duplicate == 0 else f"{base_message_id}#{duplicate:04d}"

        parent = _coerce_parent_id(source)
        created_at, has_unknown_timestamp = _coerce_timestamp(source)
        updated_at = _coerce_updated_timestamp(source)
        content, content_type, content_blocks = _coerce_content(
            source, context=context
        )
        consumed_fields = set(
            (
                *MESSAGE_ID_FIELDS,
                *MESSAGE_PARENT_FIELDS,
                *ROLE_FIELDS,
                *CREATED_TIMESTAMP_FIELDS,
                *UPDATED_TIMESTAMP_FIELDS,
                *CONTENT_FIELDS,
                *ATTACHMENT_FIELDS,
            )
        )
        raw_payload = {
            "base_message_id": base_message_id,
            "message_id": message_id,
            "parent_message_id_raw": parent,
            "role": _coerce_role(source),
            "provider_roles": _field_snapshot(source, ROLE_FIELDS, context=context),
            "created_at": created_at,
            "updated_at": updated_at,
            "provider_timestamps": _provider_timestamps(source, context=context),
            "content": content,
            "content_type": content_type,
            "content_blocks": content_blocks,
            "attachments": _collect_attachments(source, context=context),
            "model": _coerce_text(source.get("model"), None),
            "provider_identifiers": _field_snapshot(
                source, MESSAGE_ID_FIELDS, context=context
            ),
            "provider_parent_identifiers": _field_snapshot(
                source, MESSAGE_PARENT_FIELDS, context=context
            ),
            "provider_metadata": _unknown_fields(
                source, consumed_fields, context=context
            ),
            "source_index": index,
            "has_unknown_parent": False,
            "has_unknown_timestamp": has_unknown_timestamp,
            "parent_message_id": None,
        }
        raw_messages.append(raw_payload)
        by_base_id.setdefault(base_message_id, []).append(message_id)

    messages: Dict[str, Dict[str, Any]] = {
        message["message_id"]: message for message in raw_messages
    }
    if not messages:
        return []

    for message_id, record in messages.items():
        parent = record["parent_message_id_raw"]
        if parent is None:
            resolved_parent = None
        elif parent in messages:
            base_hits = by_base_id.get(parent, [])
            if len(base_hits) > 1:
                resolved_parent = None
                record["has_unknown_parent"] = True
            else:
                resolved_parent = parent
        else:
            candidates = by_base_id.get(parent, [])
            if len(candidates) == 1:
                resolved_parent = candidates[0]
            else:
                resolved_parent = None
                record["has_unknown_parent"] = True
        record["parent_message_id"] = resolved_parent

    by_parent: Dict[Optional[str], List[str]] = {}

    for message_id, record in messages.items():
        by_parent.setdefault(record["parent_message_id"], []).append(message_id)

    normalized_input = {
        message_id: {"created_at": record["created_at"], "parent_id": record["parent_message_id"]}
        for message_id, record in messages.items()
    }
    for parent_group in by_parent.values():
        parent_group.sort(
            key=lambda value: (
                normalized_input[value]["created_at"] or "9999-12-31T23:59:59Z",
                value,
            )
        )

    cycle_nodes: set[str] = set()
    state: Dict[str, int] = {message_id: 0 for message_id in messages}

    # Every message has at most one parent, so cycle detection can walk the
    # parent chain iteratively. A recursive DFS failed on otherwise valid long
    # conversations (for example, 1,500 sequential messages).
    for start_id in sorted(messages):
        if state[start_id] != 0:
            continue

        chain: List[str] = []
        positions: Dict[str, int] = {}
        current = start_id
        while current in messages:
            if state[current] == 2:
                break
            if current in positions:
                cycle_nodes.update(chain[positions[current]:])
                break
            if state[current] == 1:
                break

            positions[current] = len(chain)
            chain.append(current)
            state[current] = 1
            parent = messages[current]["parent_message_id"]
            if parent is None or parent not in messages:
                break
            current = parent

        for message_id in chain:
            state[message_id] = 2

    if cycle_nodes:
        for message_id in cycle_nodes:
            messages[message_id]["has_unknown_parent"] = True
            messages[message_id]["parent_message_id"] = None

    by_parent = {}
    for message_id, record in messages.items():
        by_parent.setdefault(record["parent_message_id"], []).append(message_id)
    for parent_group in by_parent.values():
        parent_group.sort(
            key=lambda value: (
                normalized_input[value]["created_at"] or "9999-12-31T23:59:59Z",
                value,
            )
        )

    normalized_input = {
        message_id: {"created_at": record["created_at"], "parent_id": record["parent_message_id"]}
        for message_id, record in messages.items()
    }
    for parent_group in by_parent.values():
        parent_group.sort(
            key=lambda value: (
                normalized_input[value]["created_at"] or "9999-12-31T23:59:59Z",
                value,
            )
        )

    ordered: List[str] = []
    visited: set[str] = set()

    roots = [
        message_id
        for message_id, record in messages.items()
        if not record["parent_message_id"] or record["parent_message_id"] not in messages
    ]
    roots.sort(key=lambda message_id: (messages[message_id]["created_at"] or "9999-12-31T23:59:59Z", message_id))

    def append_subtree(message_id: str) -> None:
        stack = [message_id]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            ordered.append(current)
            # Reverse push preserves the existing deterministic pre-order.
            children = by_parent.get(current, [])
            stack.extend(reversed(children))

    for root in roots:
        append_subtree(root)

    for missing in [message_id for message_id in messages if message_id not in visited]:
        append_subtree(missing)

    cache_path: Dict[str, List[str]] = {}

    def branch_path(message_id: str) -> List[str]:
        if message_id in cache_path:
            return cache_path[message_id]
        current = message_id
        chain: List[str] = []
        seen: set[str] = set()
        while current in messages and current not in seen:
            seen.add(current)
            chain.append(current)
            parent = messages[current]["parent_message_id"]
            if not parent or parent not in messages:
                break
            current = parent
        path = chain[::-1]
        cache_path[message_id] = path
        return path

    canonical_messages: List[CanonicalMessage] = []
    for message_id in ordered:
        record = messages[message_id]
        path = branch_path(message_id)
        canonical_messages.append(
            CanonicalMessage(
                message_id=message_id,
                provider_message_id=record["base_message_id"],
                parent_message_id=record["parent_message_id"],
                provider_parent_message_id=record["parent_message_id_raw"],
                role=record["role"],
                provider_roles=record["provider_roles"],
                created_at=record["created_at"],
                updated_at=record["updated_at"],
                provider_timestamps=record["provider_timestamps"],
                content=record["content"],
                content_type=record["content_type"],
                content_blocks=record["content_blocks"],
                attachments=record["attachments"],
                model=record["model"],
                provider_identifiers=record["provider_identifiers"],
                provider_parent_identifiers=record["provider_parent_identifiers"],
                provider_metadata=record["provider_metadata"],
                source_index=record["source_index"],
                branch_path="/".join(path),
                branch_depth=len(path) - 1,
                has_unknown_parent=record["has_unknown_parent"],
                has_unknown_timestamp=record["has_unknown_timestamp"],
            )
        )
    return canonical_messages


def _collect_array_fields(
    record: Dict[str, Any],
    fields: Sequence[str],
    *,
    context: str,
    required: bool,
) -> List[Any]:
    collected: List[Any] = []
    found = False
    for field in fields:
        if field not in record:
            continue
        found = True
        value = record[field]
        if not isinstance(value, list):
            raise CanonicalizationError(f"{context}.{field} is not an array")
        collected.extend(value)
    if required and not found:
        joined = ", ".join(fields)
        raise CanonicalizationError(f"{context} missing required array ({joined})")
    return collected


def _openai_mapping_messages(
    raw: Dict[str, Any], *, conversation_index: int
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    if "mapping" not in raw:
        return [], []
    mapping = raw["mapping"]
    if not isinstance(mapping, dict):
        raise CanonicalizationError(
            f"openai conversation[{conversation_index}].mapping is not an object"
        )

    nodes: Dict[str, Dict[str, Any]] = {}
    for raw_key, node in mapping.items():
        if not isinstance(raw_key, str):
            raise CanonicalizationError(
                f"openai conversation[{conversation_index}] mapping key is not a string"
            )
        if not isinstance(node, dict):
            raise CanonicalizationError(
                f"openai conversation[{conversation_index}].mapping[{raw_key}] is not an object"
            )
        nodes[raw_key] = node

    node_message_ids: Dict[str, str] = {}
    for node_index, node_id in enumerate(sorted(nodes)):
        message = nodes[node_id].get("message")
        if message is None:
            continue
        if not isinstance(message, dict):
            raise CanonicalizationError(
                f"openai conversation[{conversation_index}].mapping[{node_id}].message is not an object"
            )
        candidate = dict(message)
        if not any(
            isinstance(candidate.get(field), str) and candidate.get(field)
            for field in MESSAGE_ID_FIELDS
        ):
            candidate["message_id"] = node_id
        node_message_ids[node_id] = _coerce_message_id(candidate, node_index)

    def nearest_message_parent(node_id: str) -> Optional[str]:
        parent = nodes[node_id].get("parent")
        seen: Set[str] = set()
        while isinstance(parent, str) and parent and parent not in seen:
            seen.add(parent)
            if parent in node_message_ids:
                return node_message_ids[parent]
            parent_node = nodes.get(parent)
            if parent_node is None:
                return parent
            parent = parent_node.get("parent")
        return None

    messages: List[Dict[str, Any]] = []
    message_less_nodes: List[Dict[str, Any]] = []
    reserved = "__integrity_chronicle_mapping_node__"
    for node_id in sorted(nodes):
        node = nodes[node_id]
        message = node.get("message")
        node_metadata = {
            "mapping_key": node_id,
            "node": _unknown_fields(
                node,
                {"message"},
                context=f"openai conversation[{conversation_index}].mapping[{node_id}]",
            ),
        }
        if message is None:
            message_less_nodes.append(node_metadata)
            continue
        candidate = _json_clone(
            message,
            context=f"openai conversation[{conversation_index}].mapping[{node_id}].message",
        )
        if reserved in candidate:
            raise CanonicalizationError(
                f"reserved adapter field collision in mapping node {node_id}"
            )
        if not any(
            isinstance(candidate.get(field), str) and candidate.get(field)
            for field in MESSAGE_ID_FIELDS
        ):
            candidate["message_id"] = node_id
        if _coerce_parent_id(candidate) is None:
            parent_message_id = nearest_message_parent(node_id)
            if parent_message_id:
                candidate["parent_message_id"] = parent_message_id
        candidate[reserved] = node_metadata
        messages.append(candidate)
    return messages, message_less_nodes


def _conversation_candidate(
    raw: Dict[str, Any],
    *,
    index: int,
    message_fields: Sequence[str],
    provider: str,
    include_openai_mapping: bool = False,
) -> Dict[str, Any]:
    context = f"{provider} conversation[{index}]"
    message_list = _collect_array_fields(
        raw, message_fields, context=context, required=False
    )
    adapter_evidence: Dict[str, Any] = {}
    if include_openai_mapping:
        mapping_messages, message_less_nodes = _openai_mapping_messages(
            raw, conversation_index=index
        )
        message_list.extend(mapping_messages)
        if message_less_nodes:
            adapter_evidence["message_less_mapping_nodes"] = message_less_nodes
    if not message_list and not any(field in raw for field in message_fields) and not (
        include_openai_mapping and "mapping" in raw
    ):
        raise CanonicalizationError(f"{context} missing message container")

    for message_index, message in enumerate(message_list):
        if not isinstance(message, dict):
            raise CanonicalizationError(
                f"{context} message at index {message_index} is not an object"
            )
    adapter_evidence["source_counts"] = {
        "message_records": len(message_list),
        "content_blocks": sum(
            sum(1 for field in CONTENT_FIELDS if field in message)
            for message in message_list
        ),
        "attachment_records": sum(
            len(
                _collect_attachments(
                    message,
                    context=f"{context} source message[{message_index}]",
                )
            )
            for message_index, message in enumerate(message_list)
        ),
    }

    base_conversation_id = _coerce_conversation_id(raw, index)
    created_at, has_unknown_timestamp = _coerce_timestamp(raw)
    consumed_fields = set(
        (
            *CONVERSATION_ID_FIELDS,
            "title",
            "name",
            *CREATED_TIMESTAMP_FIELDS,
            *UPDATED_TIMESTAMP_FIELDS,
            *message_fields,
        )
    )
    if include_openai_mapping:
        consumed_fields.add("mapping")
    title = (
        _coerce_text(raw.get("name"), _coerce_text(raw.get("title"), ""))
        if provider == "claude"
        else _coerce_text(raw.get("title"), _coerce_text(raw.get("name"), ""))
    )
    return {
        "base_conversation_id": base_conversation_id,
        "provider_conversation_id": base_conversation_id,
        "provider_identifiers": _field_snapshot(
            raw, CONVERSATION_ID_FIELDS, context=context
        ),
        "provider_titles": _field_snapshot(raw, ("title", "name"), context=context),
        "title": title,
        "created_at": created_at,
        "updated_at": _coerce_updated_timestamp(raw),
        "provider_timestamps": _provider_timestamps(raw, context=context),
        "messages": [message.to_dict() for message in _build_message_topology(message_list)],
        "has_unknown_timestamp": has_unknown_timestamp,
        "source_index": index,
        "provider_metadata": _unknown_fields(
            raw, consumed_fields, context=context
        ),
        "adapter_evidence": adapter_evidence,
    }


def _finalize_conversations(
    candidates: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    candidates.sort(
        key=lambda item: (
            item["created_at"] or "9999-12-31T23:59:59Z",
            item["base_conversation_id"],
            item["source_index"],
        )
    )
    canonical: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {}
    for candidate in candidates:
        base = candidate["base_conversation_id"]
        duplicate = counts.get(base, 0)
        counts[base] = duplicate + 1
        conversation_id = base if duplicate == 0 else f"{base}#{duplicate:04d}"
        canonical.append(
            {
                "conversation_id": conversation_id,
                "provider_conversation_id": candidate["provider_conversation_id"],
                "provider_identifiers": candidate["provider_identifiers"],
                "provider_titles": candidate["provider_titles"],
                "title": candidate["title"],
                "created_at": candidate["created_at"],
                "updated_at": candidate["updated_at"],
                "provider_timestamps": candidate["provider_timestamps"],
                "messages": candidate["messages"],
                "message_count": len(candidate["messages"]),
                "has_unknown_timestamp": candidate["has_unknown_timestamp"],
                "source_index": candidate["source_index"],
                "provider_metadata": candidate["provider_metadata"],
                "adapter_evidence": candidate["adapter_evidence"],
            }
        )
    return canonical


def _parse_openai_payload(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    schema_version = _coerce_schema_version(payload.get("schema_version"), "openai_chatgpt")
    if schema_version not in OPENAI_SCHEMA_VERSIONS:
        raise CanonicalizationError(
            f"unsupported openai schema_version: {schema_version}"
        )
    conversations_raw = _collect_array_fields(
        payload,
        ("conversations",),
        context="openai payload",
        required=True,
    )
    conversation_candidates: List[Dict[str, Any]] = []
    for index, raw in enumerate(conversations_raw):
        if not isinstance(raw, dict):
            raise CanonicalizationError(
                f"openai conversation record at index {index} is not an object"
            )
        conversation_candidates.append(
            _conversation_candidate(
                raw,
                index=index,
                message_fields=("messages",),
                provider="openai",
                include_openai_mapping=True,
            )
        )
    return _finalize_conversations(conversation_candidates)


def _parse_claude_payload(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    schema_version = _coerce_schema_version(payload.get("schema_version"), "anthropic_claude")
    if schema_version not in CLAUDE_SCHEMA_VERSIONS:
        raise CanonicalizationError(
            f"unsupported claude schema_version: {schema_version}"
        )
    conversations_raw = _collect_array_fields(
        payload,
        ("threads", "conversations"),
        context="claude payload",
        required=True,
    )
    conversation_candidates: List[Dict[str, Any]] = []
    for index, raw in enumerate(conversations_raw):
        if not isinstance(raw, dict):
            raise CanonicalizationError(
                f"claude conversation record at index {index} is not an object"
            )
        conversation_candidates.append(
            _conversation_candidate(
                raw,
                index=index,
                message_fields=("messages", "history", "chat_messages"),
                provider="claude",
            )
        )
    return _finalize_conversations(conversation_candidates)


def _parse_generic_payload(payload: Dict[str, Any], provider: str) -> List[Dict[str, Any]]:
    _coerce_schema_version(payload.get("schema_version"), provider)
    conversations_raw = _collect_array_fields(
        payload,
        ("conversations", "threads", "chats"),
        context=f"{provider} payload",
        required=True,
    )
    conversation_candidates: List[Dict[str, Any]] = []
    for index, raw in enumerate(conversations_raw):
        if not isinstance(raw, dict):
            raise CanonicalizationError(
                f"{provider} conversation record at index {index} is not an object"
            )
        conversation_candidates.append(
            _conversation_candidate(
                raw,
                index=index,
                message_fields=("messages",),
                provider=provider,
            )
        )
    return _finalize_conversations(conversation_candidates)


def _parse_gemini_payload(
    payload: Dict[str, Any], *, trusted_takeout_html: bool = False
) -> List[Dict[str, Any]]:
    schema_version = _coerce_schema_version(payload.get("schema_version"), "google_gemini")
    if trusted_takeout_html:
        if schema_version != TAKEOUT_HTML_SCHEMA_VERSION:
            raise CanonicalizationError(
                "trusted Gemini Takeout HTML adapter returned an unexpected schema_version"
            )
    elif schema_version == TAKEOUT_HTML_SCHEMA_VERSION:
        raise CanonicalizationError(
            "Gemini Takeout HTML schema_version is reserved for the trusted HTML adapter"
        )
    elif schema_version not in GEMINI_SCHEMA_VERSIONS:
        raise CanonicalizationError(
            f"unsupported gemini schema_version: {schema_version}"
        )

    conversations = _collect_array_fields(
        payload,
        ("conversations", "chats"),
        context="gemini payload",
        required=True,
    )
    candidates: List[Dict[str, Any]] = []
    for index, raw in enumerate(conversations):
        if not isinstance(raw, dict):
            raise CanonicalizationError(
                f"gemini conversation record at index {index} is not an object"
            )
        candidates.append(
            _conversation_candidate(
                raw,
                index=index,
                message_fields=("messages", "turns"),
                provider="gemini",
            )
        )
    return _finalize_conversations(candidates)


def _json_pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _annotate_openai_shard_messages(
    raw_conversation: Dict[str, Any],
    *,
    shard_path: Path,
    conversation_pointer: str,
    shard_ordinal: int,
    record_index: int,
) -> None:
    def annotate(message: Any, json_pointer: str) -> None:
        if not isinstance(message, dict):
            return
        if SOURCE_PROVENANCE_FIELD in message:
            raise CanonicalizationError(
                "reserved adapter field collision in ChatGPT shard "
                f"{shard_path.name} message at {json_pointer}"
            )
        message[SOURCE_PROVENANCE_FIELD] = {
            "source_file": shard_path.name,
            "json_pointer": json_pointer,
            "source_reference": f"{shard_path.name}#{json_pointer}",
            "conversation_json_pointer": conversation_pointer,
            "shard_ordinal": shard_ordinal,
            "record_index": record_index,
        }

    direct_messages = raw_conversation.get("messages")
    if isinstance(direct_messages, list):
        for message_index, message in enumerate(direct_messages):
            annotate(message, f"{conversation_pointer}/messages/{message_index}")

    mapping = raw_conversation.get("mapping")
    if isinstance(mapping, dict):
        for node_id, node in mapping.items():
            if not isinstance(node, dict) or "message" not in node:
                continue
            node_pointer = _json_pointer_token(node_id)
            annotate(
                node.get("message"),
                f"{conversation_pointer}/mapping/{node_pointer}/message",
            )


def _load_openai_staged_payload(
    root: Path,
) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    payload_path = _first_existing_file(
        root,
        "openai_export.json",
        "chatgpt_export.json",
        "conversations.json",
    )
    shard_paths = _openai_conversation_shards(root)
    if payload_path is not None and shard_paths:
        names = ", ".join([payload_path.name, *(path.name for path in shard_paths)])
        raise CanonicalizationError(f"multiple provider payload files found: {names}")
    if payload_path is not None:
        return (
            _normalize_payload_object(_load_json(payload_path), "openai_chatgpt"),
            payload_path.name,
        )
    if not shard_paths:
        return None, None

    combined_conversations: List[Dict[str, Any]] = []
    source_shards: List[Dict[str, Any]] = []
    schema_version: Optional[str] = None
    for shard_ordinal, shard_path in enumerate(shard_paths):
        raw_payload = _load_json(shard_path)
        top_level_list = isinstance(raw_payload, list)
        normalized = _normalize_payload_object(raw_payload, "openai_chatgpt")
        current_schema_version = _coerce_schema_version(
            normalized.get("schema_version"), "openai_chatgpt"
        )
        if schema_version is None:
            schema_version = current_schema_version
        elif current_schema_version != schema_version:
            raise CanonicalizationError(
                "ChatGPT conversation shards use inconsistent schema versions: "
                f"{schema_version}, {current_schema_version}"
            )

        shard_conversations = _collect_array_fields(
            normalized,
            ("conversations",),
            context=f"openai shard {shard_path.name}",
            required=True,
        )
        pointer_prefix = "" if top_level_list else "/conversations"
        for record_index, raw_conversation in enumerate(shard_conversations):
            if not isinstance(raw_conversation, dict):
                raise CanonicalizationError(
                    f"openai shard {shard_path.name} conversation record at "
                    f"index {record_index} is not an object"
                )
            if SOURCE_PROVENANCE_FIELD in raw_conversation:
                raise CanonicalizationError(
                    "reserved adapter field collision in ChatGPT shard "
                    f"{shard_path.name} conversation {record_index}"
                )
            json_pointer = f"{pointer_prefix}/{record_index}"
            raw_conversation[SOURCE_PROVENANCE_FIELD] = {
                "source_file": shard_path.name,
                "json_pointer": json_pointer,
                "source_reference": f"{shard_path.name}#{json_pointer}",
                "shard_ordinal": shard_ordinal,
                "record_index": record_index,
            }
            _annotate_openai_shard_messages(
                raw_conversation,
                shard_path=shard_path,
                conversation_pointer=json_pointer,
                shard_ordinal=shard_ordinal,
                record_index=record_index,
            )
            combined_conversations.append(raw_conversation)

        source_shards.append(
            {
                "source_file": shard_path.name,
                "shard_ordinal": shard_ordinal,
                "conversation_record_count": len(shard_conversations),
                "provider_payload_metadata": _unknown_fields(
                    normalized,
                    {"schema_version", "conversations"},
                    context=f"openai shard {shard_path.name}",
                ),
            }
        )

    return (
        {
            "schema_version": schema_version,
            "conversations": combined_conversations,
            "source_shape": "split-conversation-shards",
            "source_shards": source_shards,
        },
        "conversations-*.json",
    )


def _claude_memory_conversations(memories_path: Path) -> List[Dict[str, Any]]:
    raw_memories = _load_json(memories_path)
    if not isinstance(raw_memories, list):
        raise CanonicalizationError("Claude memories.json is not an array")

    conversations: List[Dict[str, Any]] = []
    for record_index, record in enumerate(raw_memories):
        context = f"Claude memories.json[{record_index}]"
        if not isinstance(record, dict):
            raise CanonicalizationError(f"{context} is not an object")
        account_uuid = record.get("account_uuid")
        if not isinstance(account_uuid, str) or not account_uuid.strip():
            raise CanonicalizationError(f"{context}.account_uuid is not a non-empty string")
        memory_text = record.get("conversations_memory")
        if not isinstance(memory_text, str):
            raise CanonicalizationError(f"{context}.conversations_memory is not a string")

        identity_payload = json.dumps(
            [account_uuid, memory_text],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        identity_digest = sha256(identity_payload).hexdigest()
        conversation_id = f"claude-global-memory-{identity_digest}"
        message_id = f"claude-global-memory-message-{identity_digest}"
        conversation_pointer = f"/{record_index}"
        content_pointer = f"/{record_index}/conversations_memory"
        source_record_metadata = _unknown_fields(
            record,
            {"conversations_memory"},
            context=context,
        )
        conversations.append(
            {
                "uuid": conversation_id,
                "name": "Claude global memory",
                "messages": [
                    {
                        "uuid": message_id,
                        "sender": "assistant",
                        "text": memory_text,
                        SOURCE_PROVENANCE_FIELD: {
                            "source_file": memories_path.name,
                            "json_pointer": content_pointer,
                            "source_reference": (
                                f"{memories_path.name}#{content_pointer}"
                            ),
                            "record_index": record_index,
                            "account_uuid": account_uuid,
                        },
                    }
                ],
                SOURCE_PROVENANCE_FIELD: {
                    "source_file": memories_path.name,
                    "json_pointer": conversation_pointer,
                    "source_reference": (
                        f"{memories_path.name}#{conversation_pointer}"
                    ),
                    "content_json_pointer": content_pointer,
                    "record_index": record_index,
                    "account_uuid": account_uuid,
                    "source_record_metadata": source_record_metadata,
                },
            }
        )
    return conversations


def _load_claude_staged_payload(
    root: Path,
) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    payload_path = _first_existing_file(
        root,
        "claude_export.json",
        "conversations.json",
        "threads.json",
    )
    memories_path = root / "memories.json"
    has_memories = _is_file(memories_path)
    if payload_path is None and not has_memories:
        return None, None

    if payload_path is None:
        payload: Dict[str, Any] = {
            "schema_version": "anthropic-claude/unversioned",
            "conversations": [],
        }
        provider_payload_file = memories_path.name
    else:
        payload = _normalize_payload_object(
            _load_json(payload_path), "anthropic_claude"
        )
        provider_payload_file = payload_path.name

    if has_memories:
        if SUPPLEMENTAL_PAYLOAD_FILES_FIELD in payload:
            raise CanonicalizationError(
                "reserved adapter field collision in Claude provider payload"
            )
        memory_conversations = _claude_memory_conversations(memories_path)
        conversation_container = payload.setdefault("conversations", [])
        if not isinstance(conversation_container, list):
            raise CanonicalizationError("claude payload.conversations is not an array")
        conversation_container.extend(memory_conversations)
        payload[SUPPLEMENTAL_PAYLOAD_FILES_FIELD] = [
            {
                "source_file": memories_path.name,
                "record_count": len(memory_conversations),
            }
        ]

    return payload, provider_payload_file


def parse_staged_archive(
    staging_path: str,
    provider_hint: Optional[str] = None,
    *,
    semantic_extractor: Optional[SemanticExtractor] = None,
) -> Dict[str, Any]:
    root = Path(staging_path)
    if not root.is_dir():
        raise CanonicalizationError(f"staging path is not a directory: {root}")
    extractor = semantic_extractor or FakeSemanticExtractor()

    provider = _infer_provider(root, provider_hint=provider_hint)
    if provider == "openai_chatgpt":
        payload, provider_payload_file = _load_openai_staged_payload(root)
        if payload is None or provider_payload_file is None:
            raise CanonicalizationError("openai payload fixture not found")
        conversations = _parse_openai_payload(payload)
        adapter_version = payload.get("schema_version")
        if not isinstance(adapter_version, str):
            raise CanonicalizationError("invalid openai adapter schema_version")
        return _build_canonical_record(
            "openai_chatgpt",
            adapter_version,
            staging_path,
            conversations,
            extractor=extractor,
            provider_payload_file=provider_payload_file,
            provider_payload_metadata=_unknown_fields(
                payload,
                {"schema_version", "conversations"},
                context="openai payload",
            ),
        )

    if provider == "anthropic_claude":
        payload, provider_payload_file = _load_claude_staged_payload(root)
        if payload is None or provider_payload_file is None:
            raise CanonicalizationError("claude payload fixture not found")
        conversations = _parse_claude_payload(payload)
        adapter_version = payload.get("schema_version")
        if not isinstance(adapter_version, str):
            raise CanonicalizationError("invalid claude adapter schema_version")
        return _build_canonical_record(
            "anthropic_claude",
            adapter_version,
            staging_path,
            conversations,
            extractor=extractor,
            provider_payload_file=provider_payload_file,
            provider_payload_metadata=_unknown_fields(
                payload,
                {"schema_version", "threads", "conversations"},
                context="claude payload",
            ),
        )

    if provider == "google_gemini":
        payload_path = _first_existing_file(
            root,
            "gemini_export.json",
            "gemini_conversations.json",
            "conversations.json",
        )
        try:
            html_paths = gemini_takeout_html_candidates(root)
        except GeminiTakeoutHtmlError as err:
            raise CanonicalizationError(str(err)) from err
        if len(html_paths) > 1:
            raise CanonicalizationError(
                "multiple Gemini Takeout MyActivity HTML members found"
            )
        if payload_path is not None and html_paths:
            raise CanonicalizationError("multiple Gemini provider payload files found")
        trusted_takeout_html = bool(html_paths)
        if html_paths:
            html_path = html_paths[0]
            provider_payload_file = html_path.relative_to(root).as_posix()
            try:
                payload = parse_gemini_takeout_html(
                    html_path,
                    source_name=provider_payload_file,
                    staged_root=root,
                )
            except GeminiTakeoutHtmlError as err:
                raise CanonicalizationError(str(err)) from err
        elif payload_path is not None:
            payload = _normalize_payload_object(_load_json(payload_path), provider)
            provider_payload_file = payload_path.name
        else:
            raise CanonicalizationError("gemini payload fixture not found")
        conversations = _parse_gemini_payload(
            payload, trusted_takeout_html=trusted_takeout_html
        )
        adapter_version = payload.get("schema_version")
        if not isinstance(adapter_version, str):
            raise CanonicalizationError("invalid gemini adapter schema_version")
        return _build_canonical_record(
            "google_gemini",
            adapter_version,
            staging_path,
            conversations,
            extractor=extractor,
            provider_payload_file=provider_payload_file,
            provider_payload_metadata=_unknown_fields(
                payload,
                {"schema_version", "adapter_origin", "conversations", "chats"},
                context="gemini payload",
            ),
            adapter_origin=(
                TAKEOUT_HTML_ADAPTER_ORIGIN if trusted_takeout_html else None
            ),
        )

    payload_path = _first_existing_file(root, *GENERIC_PROVIDER_FILES)
    if payload_path is None:
        raise CanonicalizationError(f"{provider} payload fixture not found")
    payload = _normalize_payload_object(_load_json(payload_path), provider)
    conversations = _parse_generic_payload(payload, provider)
    adapter_version = _coerce_schema_version(payload.get("schema_version"), provider)
    return _build_canonical_record(
        provider,
        adapter_version,
        staging_path,
        conversations,
        extractor=extractor,
        provider_payload_file=payload_path.name,
        provider_payload_metadata=_unknown_fields(
            payload,
            {"schema_version", "conversations", "threads", "chats"},
            context=f"{provider} payload",
        ),
    )


def _validate_takeout_html_coverage(
    counts: Any,
    empty_slots: Any,
    *,
    conversation_count: int,
    message_count: int,
    attachment_count: int,
) -> None:
    if not isinstance(counts, dict) or frozenset(counts) != TAKEOUT_HTML_COUNT_FIELDS:
        raise CanonicalizationError("Gemini Takeout HTML coverage count schema mismatch")
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in counts.values()
    ):
        raise CanonicalizationError("Gemini Takeout HTML coverage counts must be non-negative integers")
    if not isinstance(empty_slots, list):
        raise CanonicalizationError("Gemini Takeout HTML empty-slot metadata malformed")
    seen_slots: Set[Tuple[str, str]] = set()
    slot_counts = {"prompt": 0, "response": 0}
    for item in empty_slots:
        if not isinstance(item, dict) or frozenset(item) != {"source_reference", "slot"}:
            raise CanonicalizationError("Gemini Takeout HTML empty-slot metadata malformed")
        reference = item.get("source_reference")
        slot = item.get("slot")
        if not isinstance(reference, str) or not reference or slot not in slot_counts:
            raise CanonicalizationError("Gemini Takeout HTML empty-slot metadata malformed")
        key = (reference, slot)
        if key in seen_slots:
            raise CanonicalizationError("Gemini Takeout HTML empty-slot metadata is duplicated")
        seen_slots.add(key)
        slot_counts[slot] += 1

    prompt_kinds = sum(
        counts[f"prompt_{kind}_records"]
        for kind in ("text", "media_only", "reference_only", "markup_only")
    )
    response_kinds = sum(
        counts[f"response_{kind}_records"]
        for kind in ("text", "media_only", "reference_only", "markup_only")
    )
    if counts["prompt_records"] != prompt_kinds or counts["response_records"] != response_kinds:
        raise CanonicalizationError("Gemini Takeout HTML typed message coverage mismatch")
    if counts["canonical_messages"] != counts["prompt_records"] + counts["response_records"]:
        raise CanonicalizationError("Gemini Takeout HTML canonical message count mismatch")
    if counts["source_cards"] != counts["prompt_records"] + counts["empty_prompt_slots"]:
        raise CanonicalizationError("Gemini Takeout HTML prompt-slot coverage mismatch")
    if counts["source_cards"] != counts["response_records"] + counts["empty_response_slots"]:
        raise CanonicalizationError("Gemini Takeout HTML response-slot coverage mismatch")
    if slot_counts != {
        "prompt": counts["empty_prompt_slots"],
        "response": counts["empty_response_slots"],
    }:
        raise CanonicalizationError("Gemini Takeout HTML empty-slot count mismatch")
    if counts["source_cards"] != conversation_count or counts["canonical_messages"] != message_count:
        raise CanonicalizationError("Gemini Takeout HTML coverage mismatch")
    if counts["relative_reference_count"] != (
        counts["missing_relative_reference_count"]
        + counts["existing_relative_reference_count"]
    ):
        raise CanonicalizationError("Gemini Takeout HTML relative-reference coverage mismatch")
    if counts["reference_count"] != (
        counts["relative_reference_count"]
        + counts["external_reference_count"]
        + counts["document_reference_count"]
        + counts["opaque_reference_count"]
    ):
        raise CanonicalizationError("Gemini Takeout HTML reference classification mismatch")
    if counts["reference_count"] != (
        counts["message_reference_count"] + counts["metadata_reference_count"]
    ):
        raise CanonicalizationError("Gemini Takeout HTML reference-channel coverage mismatch")
    if counts["relative_reference_count"] != (
        counts["message_relative_reference_count"]
        + counts["metadata_relative_reference_count"]
    ):
        raise CanonicalizationError("Gemini Takeout HTML relative-reference channel mismatch")
    if not (
        counts["local_image_reference_count"]
        <= counts["local_media_reference_count"]
        <= counts["relative_reference_count"]
    ):
        raise CanonicalizationError("Gemini Takeout HTML local-media coverage mismatch")
    if counts["message_relative_reference_count"] != attachment_count:
        raise CanonicalizationError("Gemini Takeout HTML attachment coverage mismatch")
    if counts["quarantined_card_count"] > counts["source_cards"]:
        raise CanonicalizationError("Gemini Takeout HTML quarantine coverage mismatch")
    if bool(counts["replacement_character_count"]) != bool(counts["quarantined_card_count"]):
        raise CanonicalizationError("Gemini Takeout HTML replacement quarantine mismatch")


def _build_adapter_coverage(projection: Dict[str, Any]) -> Dict[str, Any]:
    conversations = projection.get("conversations", [])
    messages = [
        message
        for conversation in conversations
        for message in conversation.get("messages", [])
    ]
    content_blocks = [
        block for message in messages for block in message.get("content_blocks", [])
    ]
    attachments = [
        attachment for message in messages for attachment in message.get("attachments", [])
    ]
    opaque_blocks = 0
    for block in content_blocks:
        if not _extract_text_fragments(block.get("value")):
            opaque_blocks += 1

    unknown_field_count = len(projection.get("provider_payload_metadata", {}))
    message_less_graph_nodes = 0
    for conversation in conversations:
        unknown_field_count += len(conversation.get("provider_metadata", {}))
        evidence = conversation.get("adapter_evidence", {})
        message_less_graph_nodes += len(
            evidence.get("message_less_mapping_nodes", [])
        )
        for message in conversation.get("messages", []):
            unknown_field_count += len(message.get("provider_metadata", {}))

    source_counts = {
        "conversation_records": len(conversations),
        "message_records": sum(
            conversation.get("adapter_evidence", {})
            .get("source_counts", {})
            .get("message_records", 0)
            for conversation in conversations
        ),
        "content_blocks": sum(
            conversation.get("adapter_evidence", {})
            .get("source_counts", {})
            .get("content_blocks", 0)
            for conversation in conversations
        ),
        "attachment_records": sum(
            conversation.get("adapter_evidence", {})
            .get("source_counts", {})
            .get("attachment_records", 0)
            for conversation in conversations
        ),
        "non_message_graph_nodes": message_less_graph_nodes,
    }
    canonical_counts = {
        "conversation_records": len(conversations),
        "message_records": len(messages),
        "content_blocks": len(content_blocks),
        "attachment_records": len(attachments),
        "non_message_graph_nodes": message_less_graph_nodes,
    }
    if source_counts != canonical_counts:
        raise CanonicalizationError(
            "adapter coverage mismatch; refusing a projection with dropped records"
        )
    coverage = {
        "schema_version": "chronicle-adapter-coverage/1",
        "status": "complete",
        "source": source_counts,
        "canonicalized": canonical_counts,
        "preserved_unknown_field_count": unknown_field_count,
        "preserved_opaque_content_block_count": opaque_blocks,
        "unsupported_records": [],
        "dropped_records": [],
    }
    if projection.get("provider_schema_version") == TAKEOUT_HTML_SCHEMA_VERSION:
        if projection.get("adapter_origin") != TAKEOUT_HTML_ADAPTER_ORIGIN:
            raise CanonicalizationError("Gemini Takeout HTML trusted adapter origin missing")
        metadata = projection.get("provider_payload_metadata", {})
        takeout_counts = metadata.get("takeout_html_counts")
        empty_slots = metadata.get("empty_slots")
        _validate_takeout_html_coverage(
            takeout_counts,
            empty_slots,
            conversation_count=len(conversations),
            message_count=len(messages),
            attachment_count=len(attachments),
        )
        coverage["provider_records"] = _json_clone(
            takeout_counts, context="Gemini Takeout HTML coverage"
        )
        coverage["empty_slots"] = _json_clone(
            empty_slots, context="Gemini Takeout HTML empty slots"
        )
        degradation_reasons = []
        if takeout_counts.get("missing_relative_reference_count", 0):
            degradation_reasons.append("upstream_missing_relative_references")
        if takeout_counts.get("replacement_character_count", 0):
            degradation_reasons.append("literal_replacement_characters_quarantined")
        if degradation_reasons:
            coverage["status"] = "degraded"
            coverage["degradation_reasons"] = degradation_reasons
    return coverage


def _build_canonical_record(
    provider: str,
    provider_schema_version: str,
    staging_path: str,
    conversations: List[Dict[str, Any]],
    extractor: Optional[SemanticExtractor] = None,
    provider_payload_file: Optional[str] = None,
    provider_payload_metadata: Optional[Dict[str, Any]] = None,
    adapter_origin: Optional[str] = None,
) -> Dict[str, Any]:
    message_count = sum(conversation["message_count"] for conversation in conversations)
    claims = _build_claim_records(
        _source_staging_id(staging_path),
        conversations,
        extractor=extractor,
    )
    projection = {
        "schema_version": CANONICAL_SCHEMA_VERSION,
        "provider": provider,
        "provider_schema_version": provider_schema_version,
        "provider_payload_file": provider_payload_file,
        "provider_payload_metadata": provider_payload_metadata or {},
        "source_id": _source_staging_id(staging_path),
        "staged_path": _source_staging_id(staging_path),
        "conversation_count": len(conversations),
        "message_count": message_count,
        "claim_count": len(claims),
        "claims": claims,
        "message_duplicate_candidates": _build_duplicate_candidate_clusters(conversations),
        "conversations": conversations,
    }
    if adapter_origin is not None:
        projection["adapter_origin"] = adapter_origin
    projection["adapter_coverage"] = _build_adapter_coverage(projection)
    projection["projection_sha256"] = _stable_projection_id(projection)
    return projection


def write_canonical_manifest(payload: Dict[str, Any], path: str) -> str:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload_text = json.dumps(payload, sort_keys=True, indent=2) + "\n"
    fd, tmp = tempfile.mkstemp(prefix="chronicle-canonical-", suffix=".json", dir=target.parent)
    with open(fd, "w", encoding="utf-8") as fp:
        fp.write(payload_text)
    Path(tmp).replace(target)
    return str(target)
