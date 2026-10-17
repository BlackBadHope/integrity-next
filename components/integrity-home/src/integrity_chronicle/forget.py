"""Projection-forget and rebuild helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, List, Optional, Set, Tuple
import json

from .projection_integrity import canonical_projection_sha256


FORGET_ACTION_SCHEMA_VERSION = "integrity-home-forget-action/2"
FORGET_RECEIPT_SCHEMA_VERSION = "integrity-home-forget-receipt/2"
_FORGET_REQUIRED_STRING_FIELDS = (
    "claim_id",
    "claim_type",
    "claim_text",
    "temporal_state",
    "conversation_id",
)
_FORGET_REQUIRED_BOOL_FIELDS = ("is_user_assertion",)
_FORGET_REQUIRED_LIST_FIELDS = ("supersedes", "superseded_by", "contradicts")
_FORGET_ALLOWED_CLAIM_TYPES = {"user_assertion", "assistant_inference", "other_statement"}
_FORGET_ALLOWED_TEMPORAL_STATES = {"active", "contradicted", "superseded"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _stable_payload(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _projection_digest(payload: Dict[str, Any]) -> str:
    copied = dict(payload)
    copied.pop("projection_sha256", None)
    return sha256(_stable_payload(copied).encode("utf-8")).hexdigest()


def _coerce_projection_id(projection: Dict[str, Any]) -> str:
    source_id = projection.get("source_id")
    if not isinstance(source_id, str) or not source_id:
        raise ValueError("projection missing source_id")
    return source_id


def _coerce_label_list(claim: Dict[str, Any], *, index: int, field_name: str) -> None:
    if field_name not in claim:
        return

    value = claim.get(field_name)
    if value is None:
        return

    if not isinstance(value, list):
        raise TypeError(
            f"projection claim at index {index} has invalid {field_name}; expected a list"
        )

    for item in value:
        if not isinstance(item, str):
            raise TypeError(
                f"projection claim at index {index} has invalid {field_name} value"
            )
        if not item.strip():
            raise ValueError(
                f"projection claim at index {index} has invalid {field_name} value"
            )


def _coerce_ids(values: Optional[Set[str]]) -> Set[str]:
    if not values:
        return set()
    coerced: Set[str] = set()
    for value in values:
        if not isinstance(value, str):
            raise TypeError("forget selector values must be strings")
        candidate = value.strip()
        if not candidate:
            raise ValueError("forget selector values must be non-empty strings")
        coerced.add(candidate)
    return coerced


def _coerce_claims_for_forget(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw_claims = payload.get("claims")
    if not isinstance(raw_claims, list):
        raise TypeError("projection claims must be a list")

    claims: List[Dict[str, Any]] = []
    seen_claim_ids: Set[str] = set()
    for index, claim in enumerate(raw_claims):
        if not isinstance(claim, dict):
            raise TypeError(f"projection claim at index {index} must be an object")

        for key in _FORGET_REQUIRED_STRING_FIELDS:
            value = claim.get(key)
            if not isinstance(value, str):
                raise TypeError(
                    f"projection claim at index {index} missing required string field: {key}"
                )
            if key == "claim_id" and not value:
                raise ValueError(
                    f"projection claim at index {index} has empty required string field: {key}"
                )

        claim_id = str(claim["claim_id"])
        if claim_id in seen_claim_ids:
            raise ValueError(f"duplicate claim_id in projection at index {index}: {claim_id}")
        seen_claim_ids.add(claim_id)

        claim_type = claim["claim_type"]
        if claim_type not in _FORGET_ALLOWED_CLAIM_TYPES:
            raise ValueError(
                f"projection claim at index {index} has invalid claim_type: {claim_type}"
            )

        temporal_state = claim["temporal_state"]
        if temporal_state not in _FORGET_ALLOWED_TEMPORAL_STATES:
            raise ValueError(
                f"projection claim at index {index} has invalid temporal_state: {temporal_state}"
            )

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

        if "created_at" not in claim:
            raise ValueError(
                f"projection claim at index {index} missing required string field: created_at"
            )
        created_at = claim.get("created_at")
        if created_at is not None and not isinstance(created_at, str):
            raise ValueError(
                f"projection claim at index {index} has invalid created_at"
            )

        model = claim.get("model")
        if model is not None and not isinstance(model, str):
            raise ValueError(f"projection claim at index {index} has invalid model")

        content_type = claim.get("content_type")
        if content_type is not None and not isinstance(content_type, str):
            raise ValueError(
                f"projection claim at index {index} has invalid content_type"
            )

        for key in _FORGET_REQUIRED_LIST_FIELDS:
            links = claim.get(key)
            if not isinstance(links, list):
                raise ValueError(
                    f"projection claim at index {index} missing required list field: {key}"
                )
            if not all(isinstance(item, str) for item in links):
                raise ValueError(
                    f"projection claim at index {index} has non-string {key} item"
                )
        _coerce_label_list(claim, index=index, field_name="sensitivity_labels")
        _coerce_label_list(claim, index=index, field_name="scope_labels")

        claims.append(claim)
    return claims


def apply_forget(
    projection: Dict[str, Any],
    *,
    forget_claim_ids: Optional[Set[str]] = None,
    forget_conversation_ids: Optional[Set[str]] = None,
    reason: str = "",
    issued_at: Optional[str] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if not isinstance(projection, dict):
        raise TypeError("projection must be a mapping")
    source_id = _coerce_projection_id(projection)
    before_sha = canonical_projection_sha256(projection)

    claim_filters = _coerce_ids(forget_claim_ids)
    conversation_filters = _coerce_ids(forget_conversation_ids)
    if not claim_filters and not conversation_filters:
        raise ValueError("must provide at least one forget selector")

    claims = _coerce_claims_for_forget(projection)

    survivors: List[Dict[str, Any]] = []
    removed_claim_ids: List[str] = []
    removed_by_claim: Set[str] = set()
    removed_by_conversation: Set[str] = set()

    for claim in claims:
        claim_id = claim.get("claim_id")
        conversation_id = claim.get("conversation_id")

        if isinstance(claim_id, str):
            id_value = claim_id
            if id_value in claim_filters:
                removed_claim_ids.append(id_value)
                removed_by_claim.add(id_value)
                continue

        if isinstance(conversation_id, str) and conversation_id in conversation_filters:
            if isinstance(claim_id, str):
                removed_claim_ids.append(claim_id)
            removed_by_conversation.add(conversation_id)
            continue

        survivors.append(dict(claim))

    survivors_by_id: Dict[str, Dict[str, Any]] = {}
    for claim in survivors:
        claim_id = claim.get("claim_id")
        if isinstance(claim_id, str) and claim_id not in survivors_by_id:
            survivors_by_id[claim_id] = claim

    for claim in survivors:
        for field in ("supersedes", "superseded_by", "contradicts"):
            links = claim.get(field)
            if not isinstance(links, list):
                claim[field] = []
                continue
            normalized = []
            for link in links:
                if isinstance(link, str) and link in survivors_by_id:
                    normalized.append(link)
            claim[field] = sorted(set(normalized))

    id_to_timestamp = {
        claim_id: claim.get("created_at")
        for claim_id, claim in survivors_by_id.items()
        if claim.get("created_at") is not None
    }
    for claim in survivors:
        claim_id = claim.get("claim_id")
        if not isinstance(claim_id, str):
            continue
        superseded_by = claim.get("superseded_by", [])
        if not isinstance(superseded_by, list):
            superseded_by = []

        candidate_timestamps = [
            id_to_timestamp[superseding_id]
            for superseding_id in superseded_by
            if superseding_id in id_to_timestamp
        ]
        claim["valid_to"] = min(candidate_timestamps) if candidate_timestamps else None
        claim["superseded_by"] = superseded_by

        if claim["superseded_by"]:
            claim["temporal_state"] = "superseded"
        elif claim.get("contradicts"):
            claim["contradicts"] = sorted(set(
                contradict_id
                for contradict_id in claim.get("contradicts", [])
                if isinstance(contradict_id, str) and contradict_id in survivors_by_id
            ))
            claim["temporal_state"] = "contradicted"
        else:
            claim["temporal_state"] = "active"

    removed_canonical_conversation_ids: Set[str] = set()
    removed_message_count = 0
    surviving_conversations: Optional[List[Dict[str, Any]]] = None
    if "conversations" in projection:
        raw_conversations = projection.get("conversations")
        if not isinstance(raw_conversations, list):
            raise TypeError("projection conversations must be a list")
        surviving_conversations = []
        seen_conversation_ids: Set[str] = set()
        for index, conversation in enumerate(raw_conversations):
            if not isinstance(conversation, dict):
                raise TypeError(
                    f"projection conversation at index {index} must be an object"
                )
            conversation_id = conversation.get("conversation_id")
            if not isinstance(conversation_id, str) or not conversation_id:
                raise ValueError(
                    f"projection conversation at index {index} has invalid conversation_id"
                )
            if conversation_id in seen_conversation_ids:
                raise ValueError(
                    f"duplicate conversation_id in projection at index {index}: {conversation_id}"
                )
            seen_conversation_ids.add(conversation_id)
            messages = conversation.get("messages", [])
            if not isinstance(messages, list):
                raise TypeError(
                    f"projection conversation at index {index} messages must be a list"
                )
            if conversation_id in conversation_filters:
                removed_canonical_conversation_ids.add(conversation_id)
                removed_message_count += len(messages)
                continue
            surviving_conversations.append(dict(conversation))

    rebuilt = dict(projection)
    rebuilt["claims"] = survivors
    rebuilt["claim_count"] = len(survivors)
    if surviving_conversations is not None:
        rebuilt["conversations"] = surviving_conversations
        rebuilt["conversation_count"] = len(surviving_conversations)
        rebuilt["message_count"] = sum(
            len(conversation.get("messages", []))
            for conversation in surviving_conversations
        )
    if conversation_filters:
        # Duplicate candidates and adapter coverage are projections of the
        # pre-forget corpus.  Keeping them would retain stale message locators.
        if "message_duplicate_candidates" in rebuilt:
            rebuilt["message_duplicate_candidates"] = []
        previous_revocations = rebuilt.get("revoked_conversation_ids", [])
        if not isinstance(previous_revocations, list) or not all(
            isinstance(item, str) for item in previous_revocations
        ):
            raise TypeError("revoked_conversation_ids must be a list of strings")
        rebuilt["revoked_conversation_ids"] = sorted(
            set(previous_revocations) | conversation_filters
        )
        rebuilt["corpus_rebuild_required"] = True
        coverage = rebuilt.get("adapter_coverage")
        if isinstance(coverage, dict):
            coverage = dict(coverage)
            coverage["status"] = "post_forget_rebuild_required"
            coverage["revoked_conversation_ids"] = sorted(conversation_filters)
            rebuilt["adapter_coverage"] = coverage
    rebuilt["projection_sha256"] = _projection_digest(rebuilt)

    issued_at = issued_at or _utc_now()
    operation_material = {
        "source_id": source_id,
        "source_projection_sha256_before": before_sha,
        "source_projection_sha256_after": rebuilt["projection_sha256"],
        "forget_claim_ids": sorted(claim_filters),
        "forget_conversation_ids": sorted(conversation_filters),
    }
    operation_id = (
        "integrity-home-forget-"
        + sha256(_stable_payload(operation_material).encode("utf-8")).hexdigest()[:24]
    )
    removed_payload = {
        "schema_version": FORGET_RECEIPT_SCHEMA_VERSION,
        "receipt_id": operation_id,
        "operation_id": operation_id,
        "operation_state": "prepared",
        "issued_at_utc": issued_at,
        "source_id": source_id,
        "source_projection_sha256_before": before_sha,
        "source_projection_sha256_after": rebuilt["projection_sha256"],
        "action_schema_version": FORGET_ACTION_SCHEMA_VERSION,
        "reason": reason or None,
        "removed_claim_ids": sorted(set(removed_claim_ids)),
        "removed_count": len(removed_claim_ids),
        "removed_conversation_ids": sorted(
            removed_by_conversation | removed_canonical_conversation_ids
        ),
        "revoked_conversation_ids": sorted(conversation_filters),
        "removed_message_count": removed_message_count,
        "corpus_rebuild_required": bool(conversation_filters),
        "removed_claim_id_count_from_selector": len(removed_by_claim),
    }

    return rebuilt, removed_payload


__all__ = [
    "FORGET_ACTION_SCHEMA_VERSION",
    "FORGET_RECEIPT_SCHEMA_VERSION",
    "apply_forget",
]
