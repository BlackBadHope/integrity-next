"""Deterministic in-process search over canonical projections.

The implementation is intentionally lightweight and filesystem-free:
it keeps the current repository on deterministic, bounded computation
before delegating larger indexing stages to future incremental work.
"""

from __future__ import annotations

import re
import shlex
import unicodedata
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from .search_index import SearchIndexError, search_projection_rows


SEARCH_RESULT_SCHEMA_VERSION = "chronicle-search/1"


_ALLOWED_TEMPORAL_STATES = {"active", "superseded", "contradicted"}
_KNOWN_SPEAKERS = {"user", "assistant", "other"}
_REQUIRED_SEARCH_CLAIM_STRING_FIELDS = (
    "claim_id",
    "claim_type",
    "claim_text",
    "temporal_state",
    "conversation_id",
    "message_id",
)
_WORD_RE = re.compile(r"\w+", flags=re.UNICODE)


def _coerce_claims(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw_claims = payload.get("claims")
    if not isinstance(raw_claims, list):
        raise ValueError("projection claims must be a list")

    claims: List[Dict[str, Any]] = []
    seen_claim_ids: set[str] = set()
    for index, claim in enumerate(raw_claims):
        if not isinstance(claim, dict):
            raise ValueError(f"projection claims at index {index} must be an object")

        for key in _REQUIRED_SEARCH_CLAIM_STRING_FIELDS:
            value = claim.get(key)
            if not isinstance(value, str):
                raise ValueError(
                    f"projection claim at index {index} missing required string field: {key}"
                )
            if key == "claim_id" and not value:
                raise ValueError(
                    f"projection claim at index {index} has empty required string field: {key}"
                )
            if key == "claim_id":
                if value in seen_claim_ids:
                    raise ValueError(f"duplicate claim_id in projection at index {index}: {value}")
                seen_claim_ids.add(value)

        is_user_assertion = claim.get("is_user_assertion")
        if not isinstance(is_user_assertion, bool):
            raise ValueError(
                f"projection claim at index {index} missing required bool field: is_user_assertion"
            )

        provenance = claim.get("provenance")
        if not isinstance(provenance, dict):
            raise ValueError(
                f"projection claim at index {index} missing required dict field: provenance"
            )

        model = claim.get("model")
        if model is not None and not isinstance(model, str):
            raise ValueError(
                f"projection claim at index {index} has invalid model"
            )

        if "created_at" not in claim:
            raise ValueError(
                f"projection claim at index {index} missing required string field: created_at"
            )
        created_at = claim.get("created_at")
        if created_at is not None and not isinstance(created_at, str):
            raise ValueError(
                f"projection claim at index {index} has invalid created_at"
            )

        if claim.get("speaker") is not None:
            _coerce_speaker(claim.get("speaker"))

        content_type = _coerce_content_type(claim, index=index)
        if content_type is not None and not isinstance(content_type, str):
            raise ValueError(
                f"projection claim at index {index} has invalid content_type"
            )
        _coerce_label_list(claim, index=index, field_name="sensitivity_labels")
        _coerce_label_list(claim, index=index, field_name="scope_labels")
        claims.append(claim)
    return claims


def _coerce_label_list(claim: Dict[str, Any], *, index: int, field_name: str) -> None:
    if field_name not in claim:
        return

    value = claim.get(field_name)
    if value is None:
        return

    if not isinstance(value, list):
        raise ValueError(
            f"projection claim at index {index} has invalid {field_name}; expected a list"
        )

    for item in value:
        if not isinstance(item, str):
            raise ValueError(
                f"projection claim at index {index} has invalid {field_name} value"
            )
        if not item.strip():
            raise ValueError(
                f"projection claim at index {index} has invalid {field_name} value"
            )


def _coerce_projection_provider(payload: Dict[str, Any]) -> str:
    provider = payload.get("provider")
    if not isinstance(provider, str) or not provider:
        raise ValueError("projection missing provider")
    return provider


def _normalize_text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    normalized = unicodedata.normalize("NFKC", value).casefold()
    decomposed = unicodedata.normalize("NFD", normalized)
    normalized = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return " ".join(normalized.strip().split())


def _tokenize_text(value: Any) -> List[str]:
    return [token for token in _WORD_RE.findall(_normalize_text(value)) if token]


@dataclass(frozen=True)
class SearchTerm:
    value: str
    kind: str


def _coerce_set(
    raw: Optional[Iterable[str]], *, field_name: Optional[str] = None
) -> Optional[Set[str]]:
    if raw is None:
        return None
    normalized: Set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            raise ValueError(f"{field_name or 'filter values'} must contain strings")
        candidate = item.strip()
        if candidate:
            normalized.add(candidate)
    return normalized or None


def _coerce_speaker(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("projection claim has invalid speaker")

    speaker = value.strip().lower()
    if not speaker:
        raise ValueError("projection claim has empty speaker")
    if speaker not in _KNOWN_SPEAKERS:
        raise ValueError("projection claim has unsupported speaker")
    return speaker


def _coerce_content_type(claim: Dict[str, Any], *, index: int) -> Optional[str]:
    content_type = claim.get("content_type")
    provenance = claim.get("provenance")
    if isinstance(provenance, dict):
        provenance_content_type = provenance.get("content_type")
        if provenance_content_type is not None and not isinstance(
            provenance_content_type, str
        ):
            raise ValueError(
                f"projection claim at index {index} has invalid content_type in provenance"
            )

    if content_type is not None and not isinstance(content_type, str):
        raise ValueError(f"projection claim at index {index} has invalid content_type")

    if content_type is None and isinstance(provenance, dict):
        provenance_content_type = provenance.get("content_type")
        if provenance_content_type is not None:
            content_type = provenance_content_type

    return content_type


def _claim_speaker(claim: Dict[str, Any]) -> str:
    if claim.get("claim_type") == "other_statement":
        return "other"

    explicit_speaker = claim.get("speaker")
    if explicit_speaker is not None:
        return _coerce_speaker(explicit_speaker)

    role = claim.get("is_user_assertion")
    if isinstance(role, bool):
        return "user" if role else "assistant"
    return "other"


def _timestamp_value(created_at: Any) -> str:
    return _normalize_text(created_at) or "9999-12-31T23:59:59Z"


def _invert_iso_timestamp(created_at: Any) -> str:
    text = _timestamp_value(created_at)
    return "".join(chr(255 - ord(ch)) for ch in text)


def _query_terms(query: Optional[str]) -> List[SearchTerm]:
    if not query:
        return []
    try:
        raw_terms = shlex.split(query)
    except ValueError:
        raw_terms = _normalize_text(query).split()

    terms: List[SearchTerm] = []
    for raw_term in raw_terms:
        normalized = _normalize_text(raw_term)
        if not normalized:
            continue
        if " " in raw_term:
            terms.append(SearchTerm(value=normalized, kind="phrase"))
            continue
        if normalized.endswith("*") and len(normalized) > 1:
            terms.append(SearchTerm(value=normalized[:-1], kind="prefix"))
            continue
        terms.append(SearchTerm(value=normalized, kind="term"))
    return terms


def _term_score(
    normalized_text: str,
    tokens: Sequence[str],
    token_counts: Counter[str],
    terms: Sequence[SearchTerm],
) -> int:
    if not terms:
        return 1
    score = 0
    for term in terms:
        if term.kind == "phrase":
            if term.value and term.value in normalized_text:
                score += normalized_text.count(term.value) * 8
            continue
        if term.kind == "prefix":
            score += sum(1 for token in tokens if token.startswith(term.value))
            continue
        score += token_counts.get(term.value, 0)
    return score


@dataclass
class SearchRequest:
    query: Optional[str] = None
    query_terms: List[SearchTerm] | None = None
    provider: Optional[str] = None
    conversation_ids: Optional[Set[str]] = None
    claim_types: Optional[Set[str]] = None
    temporal_states: Optional[Set[str]] = None
    speakers: Optional[Set[str]] = None
    models: Optional[Set[str]] = None
    content_types: Optional[Set[str]] = None
    min_timestamp: Optional[str] = None
    max_timestamp: Optional[str] = None
    max_results: Optional[int] = None

    def __post_init__(self) -> None:
        self.query_terms = _query_terms(self.query)
        if self.max_results is not None and self.max_results < 0:
            raise ValueError("max_results must be non-negative")

    def matches(self, claim: Dict[str, Any], source_provider: str) -> Optional[Dict[str, Any]]:
        if self.provider is not None and source_provider != self.provider:
            return None

        conversation_ids = self.conversation_ids
        if conversation_ids is not None:
            if str(claim.get("conversation_id") or "") not in conversation_ids:
                return None

        claim_types = self.claim_types
        if claim_types is not None:
            if claim.get("claim_type") not in claim_types:
                return None

        temporal_states = self.temporal_states
        if temporal_states is not None:
            if claim.get("temporal_state") not in temporal_states:
                return None

        speakers = self.speakers
        if speakers is not None:
            speaker = _claim_speaker(claim)
            if speaker not in speakers:
                return None

        models = self.models
        if models is not None:
            if str(claim.get("model") or "") not in models:
                return None

        content_types = self.content_types
        if content_types is not None:
            provenance = claim.get("provenance")
            if not isinstance(provenance, dict):
                return None
            if str(provenance.get("content_type") or "") not in content_types:
                return None

        created_at = _timestamp_value(claim.get("created_at"))
        if self.min_timestamp is not None and created_at < self.min_timestamp:
            return None
        if self.max_timestamp is not None and created_at > self.max_timestamp:
            return None

        text = _normalize_text(claim.get("claim_text"))
        tokens = _tokenize_text(text)
        score = _term_score(text, tokens, Counter(tokens), self.query_terms or [])
        if self.query_terms and score <= 0:
            return None

        return {
            "claim_id": claim.get("claim_id"),
            "score": score,
            "claim_type": claim.get("claim_type"),
            "created_at": claim.get("created_at"),
            "temporal_state": claim.get("temporal_state"),
            "conversation_id": claim.get("conversation_id"),
            "message_id": claim.get("message_id"),
            "is_user_assertion": claim.get("is_user_assertion"),
            "claim_text": claim.get("claim_text"),
            "model": claim.get("model"),
            "provenance": claim.get("provenance", {}),
            "speaker": _claim_speaker(claim),
            "source_id": claim.get("source_id"),
            "content_type": _coerce_content_type(claim, index=-1),
        }


def _coerce_projection_projection_id(payload: Dict[str, Any]) -> str:
    source_id = payload.get("source_id")
    if not isinstance(source_id, str):
        raise ValueError("projection missing source_id")
    return source_id


def _build_request(
    *,
    query: Optional[str],
    provider: Optional[str],
    conversation_ids: Optional[Set[str]],
    claim_types: Optional[Set[str]],
    temporal_states: Optional[Set[str]],
    speakers: Optional[Set[str]],
    models: Optional[Set[str]],
    content_types: Optional[Set[str]],
    from_timestamp: Optional[str],
    to_timestamp: Optional[str],
    max_results: Optional[int],
) -> SearchRequest:
    if from_timestamp is not None and not isinstance(from_timestamp, str):
        raise ValueError("from_timestamp must be a string")
    if to_timestamp is not None and not isinstance(to_timestamp, str):
        raise ValueError("to_timestamp must be a string")

    if temporal_states:
        invalid = [state for state in temporal_states if state not in _ALLOWED_TEMPORAL_STATES]
        if invalid:
            raise ValueError(f"unsupported temporal_states: {', '.join(sorted(invalid))}")

    if speakers:
        normalized = {speaker.strip().lower() for speaker in speakers}
        invalid = [speaker for speaker in normalized if speaker not in _KNOWN_SPEAKERS]
        if invalid:
            raise ValueError(f"unsupported speakers: {', '.join(sorted(invalid))}")
        speakers = normalized

    return SearchRequest(
        query=query,
        provider=provider,
        conversation_ids=_coerce_set(conversation_ids, field_name="conversation_ids"),
        claim_types=_coerce_set(claim_types, field_name="claim_types"),
        temporal_states=_coerce_set(temporal_states, field_name="temporal_states"),
        speakers=_coerce_set(speakers, field_name="speakers"),
        models=_coerce_set(models, field_name="models"),
        content_types=_coerce_set(content_types, field_name="content_types"),
        min_timestamp=from_timestamp,
        max_timestamp=to_timestamp,
        max_results=max_results,
    )


def search_projection(
    projection: Dict[str, Any],
    *,
    query: Optional[str] = None,
    provider: Optional[str] = None,
    conversation_ids: Optional[Iterable[str]] = None,
    claim_types: Optional[Iterable[str]] = None,
    temporal_states: Optional[Iterable[str]] = None,
    speakers: Optional[Iterable[str]] = None,
    models: Optional[Iterable[str]] = None,
    content_types: Optional[Iterable[str]] = None,
    from_timestamp: Optional[str] = None,
    to_timestamp: Optional[str] = None,
    max_results: Optional[int] = None,
    index_path: Optional[str] = None,
) -> Dict[str, Any]:
    if not isinstance(projection, dict):
        raise TypeError("projection must be a mapping")

    source_id = _coerce_projection_projection_id(projection)
    source_provider = _coerce_projection_provider(projection)
    if provider is not None and not isinstance(provider, str):
        raise TypeError("provider must be a string")

    request = _build_request(
        query=query,
        provider=provider,
        conversation_ids=set(conversation_ids) if conversation_ids is not None else None,
        claim_types=set(claim_types) if claim_types is not None else None,
        temporal_states=set(temporal_states) if temporal_states is not None else None,
        speakers=set(speakers) if speakers is not None else None,
        models=set(models) if models is not None else None,
        content_types=set(content_types) if content_types is not None else None,
        from_timestamp=from_timestamp,
        to_timestamp=to_timestamp,
        max_results=max_results,
    )

    matches: List[Dict[str, Any]] = []
    if index_path is not None:
        try:
            matches = []
            for claim in search_projection_rows(
                projection,
                index_path=index_path,
                query=request.query,
            ):
                row = request.matches(claim=claim, source_provider=source_provider)
                if row is None:
                    continue
                matches.append(row)
        except SearchIndexError:
            matches = []
            for claim in _coerce_claims(projection):
                row = request.matches(claim=claim, source_provider=source_provider)
                if row is None:
                    continue
                matches.append(row)
    else:
        for claim in _coerce_claims(projection):
            row = request.matches(claim=claim, source_provider=source_provider)
            if row is None:
                continue
            matches.append(row)

    matches.sort(
        key=lambda item: (
            -int(item["score"]),
            _invert_iso_timestamp(item.get("created_at")),
            str(item.get("claim_id") or ""),
        )
    )

    if request.max_results is not None:
        matches = matches[: request.max_results]

    return {
        "schema_version": SEARCH_RESULT_SCHEMA_VERSION,
        "source_id": source_id,
        "source_provider": source_provider,
        "query": query,
        "result_count": len(matches),
        "results": matches,
    }


__all__ = [
    "SEARCH_RESULT_SCHEMA_VERSION",
    "search_projection",
]
