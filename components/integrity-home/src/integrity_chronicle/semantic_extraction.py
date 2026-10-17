"""Semantic claim extraction abstraction."""

from __future__ import annotations

from hashlib import sha256
from typing import Any, Dict, List, Protocol, Sequence
import json


CLAIM_UNKNOWN_TIME_SORT_KEY = "9999-12-31T23:59:59Z"
CLAIM_NEGATION_TOKENS = {
    "not",
    "no",
    "never",
    "cant",
    "can't",
    "dont",
    "don't",
    "wont",
    "won't",
    "cannot",
    "can't",
    "couldnt",
    "couldn't",
    "shouldnt",
    "shouldn't",
    "isnt",
    "isn't",
    "arent",
    "aren't",
    "wasnt",
    "wasn't",
    "werent",
    "weren't",
    "hasnt",
    "hasn't",
    "havent",
    "haven't",
    "hadnt",
    "hadn't",
    "не",
    "нет",
    "никогда",
    "нельзя",
    "ні",
    "ніколи",
    "немає",
}
CLAIM_CORRECTION_MARKERS = {
    "actually",
    "correction",
    "corrected",
    "update",
    "updated",
    "instead",
    "mistake",
    "retract",
    "retracts",
    "clarify",
    "clarification",
    "supersede",
    "supersedes",
    "поправка",
    "исправление",
    "уточнение",
    "насправді",
    "виправлення",
    "уточнення",
}


class SemanticExtractor(Protocol):
    """Pluggable extractor contract for semantic claim records."""

    def extract_claim_records(
        self,
        source_id: str,
        conversations: Sequence[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Return deterministic claim-like records from canonical messages."""


def _normalize_for_duplicate_detection(value: str) -> str:
    import re

    normalized = value.lower().strip()
    normalized = re.sub(r"\s+", " ", normalized)
    normalized = re.sub(r"[^\w\s]", " ", normalized, flags=re.UNICODE)
    return re.sub(r"\s+", " ", normalized).strip()


def _normalize_for_claim_signature(value: str) -> str:
    return _normalize_for_duplicate_detection(value)


def _claim_tokens(value: str) -> List[str]:
    import re

    # Keep apostrophes inside words so JSON-safe English contractions such as
    # "don't" remain a single token. ``_normalize_for_duplicate_detection``
    # intentionally removes punctuation and therefore cannot be reused for
    # polarity detection.
    normalized = value.casefold().replace("’", "'")
    return re.findall(r"[^\W_]+(?:'[^\W_]+)?", normalized, flags=re.UNICODE)


def _is_negation_token(token: str) -> bool:
    return token in CLAIM_NEGATION_TOKENS or token.endswith("n't")


def _is_user_question(value: str) -> bool:
    return value.rstrip().endswith(("?", "？"))


def _claim_signature_and_polarity(value: str) -> tuple[str, str, bool]:
    tokens = _claim_tokens(value)
    if not tokens:
        return "", "neutral", False

    has_negation = any(_is_negation_token(token) for token in tokens)
    signature_tokens = [
        token for token in tokens
        if not _is_negation_token(token) and token not in CLAIM_CORRECTION_MARKERS
    ]
    signature = " ".join(signature_tokens).strip() or " ".join(tokens)
    return signature, ("negative" if has_negation else "affirmative"), has_negation


def _contains_correction_marker(value: str) -> bool:
    normalized = _normalize_for_claim_signature(value)
    if not normalized:
        return False
    tokens = {token for token in normalized.split(" ") if token}
    return bool(tokens.intersection(CLAIM_CORRECTION_MARKERS))


def build_claim_records(
    source_id: str,
    conversations: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    claims: List[Dict[str, Any]] = []
    by_scope: Dict[tuple[str, str], List[int]] = {}

    for conversation in conversations:
        conversation_id = str(conversation.get("conversation_id", ""))
        provider_conversation_id = str(conversation.get("provider_conversation_id", ""))
        title = str(conversation.get("title", ""))
        for message_index, message in enumerate(conversation.get("messages", [])):
            if not isinstance(message, dict):
                continue

            provider_metadata = message.get("provider_metadata")
            if (
                isinstance(provider_metadata, dict)
                and provider_metadata.get("integrity_quarantine") is True
            ):
                # Keep transport-damaged evidence searchable in the canonical
                # corpus, but do not derive memory claims from it.
                continue

            role = message.get("role", "")
            if not isinstance(role, str):
                continue

            role = role.strip().lower()
            claim_content = str(message.get("content", ""))
            claim_signature, claim_polarity, has_negation = _claim_signature_and_polarity(claim_content)
            if not claim_signature:
                continue

            message_id = str(message.get("message_id", ""))
            if not message_id:
                continue

            branch_path = str(message.get("branch_path", ""))
            created_at = message.get("created_at")
            has_unknown_timestamp = bool(message.get("has_unknown_timestamp", False))

            claim_payload = {
                "source_id": source_id,
                "conversation_id": conversation_id,
                "provider_conversation_id": provider_conversation_id,
                "message_id": message_id,
                "source_message_index": message_index,
            }
            claim_id = f"claim-{sha256(json.dumps(claim_payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')).hexdigest()}"
            is_user_question = role == "user" and _is_user_question(claim_content)
            is_user_assertion = role == "user" and not is_user_question
            claim_type = (
                "user_question" if is_user_question
                else "user_assertion" if role == "user"
                else "assistant_inference" if role == "assistant"
                else "other_statement"
            )

            claim = {
                "claim_id": claim_id,
                "claim_type": claim_type,
                "claim_text": claim_content,
                "conversation_id": conversation_id,
                "provider_conversation_id": provider_conversation_id,
                "message_id": message_id,
                "claim_signature": claim_signature,
                "has_negation": has_negation,
                "claim_polarity": claim_polarity,
                "is_user_assertion": is_user_assertion,
                "has_correction_marker": _contains_correction_marker(claim_content),
                "created_at": created_at,
                "has_unknown_timestamp": has_unknown_timestamp,
                "valid_from": created_at if not has_unknown_timestamp else None,
                "valid_to": None,
                "temporal_state": "active",
                "source_message_index": message_index,
                "provenance": {
                    "conversation_title": title,
                    "message_ref": f"{conversation_id}/{message_id}",
                    "branch_path": branch_path,
                    "content_type": message.get("content_type"),
                },
                "supersedes": [],
                "superseded_by": [],
                "contradicts": [],
            }
            claim_index = len(claims)
            claims.append(claim)
            if not is_user_question:
                by_scope.setdefault((conversation_id, claim_signature), []).append(claim_index)

    for conversation_id, claim_signature in sorted(by_scope):
        claim_indexes = by_scope[(conversation_id, claim_signature)]
        claim_indexes.sort(
            key=lambda index: (
                claims[index]["created_at"] or CLAIM_UNKNOWN_TIME_SORT_KEY,
                claims[index]["claim_id"],
            )
        )
        for next_position in range(1, len(claim_indexes)):
            current_index = claim_indexes[next_position]
            current = claims[current_index]
            for previous_index in claim_indexes[:next_position]:
                previous = claims[previous_index]
                if current["is_user_assertion"] and previous["is_user_assertion"]:
                    if _contains_correction_marker(current["claim_text"]) or (
                        previous["claim_polarity"] != current["claim_polarity"]
                        and _contains_correction_marker(current["claim_text"])
                    ):
                        if current["source_message_index"] > previous["source_message_index"]:
                            if previous["claim_id"] not in current["supersedes"]:
                                current["supersedes"].append(previous["claim_id"])
                            if current["claim_id"] not in previous["superseded_by"]:
                                previous["superseded_by"].append(current["claim_id"])
                if previous["claim_polarity"] != current["claim_polarity"]:
                    if previous["claim_id"] not in current["contradicts"]:
                        current["contradicts"].append(previous["claim_id"])
                    if current["claim_id"] not in previous["contradicts"]:
                        previous["contradicts"].append(current["claim_id"])

    id_to_timestamp = {claim["claim_id"]: claim["created_at"] for claim in claims}
    for claim in claims:
        if claim["superseded_by"]:
            candidates = [
                id_to_timestamp[superseding_id]
                for superseding_id in claim["superseded_by"]
                if id_to_timestamp.get(superseding_id) is not None
            ]
            claim["valid_to"] = min(candidates) if candidates else None
            claim["temporal_state"] = "superseded"
        elif claim["contradicts"] and not claim["is_user_assertion"]:
            # Assistant and other non-user assertions may be marked contradicted,
            # but user assertions are only demoted when explicitly superseded
            # by later user claims.
            claim["temporal_state"] = "contradicted"
        else:
            claim["temporal_state"] = "active"

        if claim["supersedes"]:
            claim["supersedes"].sort()
        if claim["superseded_by"]:
            claim["superseded_by"].sort()
        if claim["contradicts"]:
            claim["contradicts"].sort()

    return claims


class FakeSemanticExtractor:
    """Deterministic built-in extractor for all default local-first flows."""

    def extract_claim_records(
        self,
        source_id: str,
        conversations: Sequence[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        return build_claim_records(source_id, conversations)


__all__ = [
    "CLAIM_CORRECTION_MARKERS",
    "CLAIM_NEGATION_TOKENS",
    "CLAIM_UNKNOWN_TIME_SORT_KEY",
    "FakeSemanticExtractor",
    "SemanticExtractor",
    "build_claim_records",
]
