"""Context policy and deterministic capsule/receipt generation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
import hmac
import json


CONTEXT_CAPSULE_SCHEMA_VERSION = "chronicle-context-capsule/1"
CONTEXT_RECEIPT_SCHEMA_VERSION = "chronicle-context-receipt/1"
CONTEXT_UNKNOWN_TIMESTAMP_SORT_KEY = "9999-12-31T23:59:59Z"
ALLOWED_CLAIM_TYPES = frozenset(
    ("user_assertion", "user_question", "assistant_inference", "other_statement")
)
ALLOWED_TEMPORAL_STATES = frozenset(("active", "superseded", "contradicted"))
_REQUIRED_CLAIM_STRING_FIELDS = (
    "claim_id",
    "claim_type",
    "claim_text",
    "temporal_state",
    "conversation_id",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _stable_payload(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def parse_csv_set(
    value: Optional[str],
    *,
    field_name: str = "selector list",
    allowed_values: Optional[Sequence[str]] = None,
) -> Optional[Set[str]]:
    if value is None:
        return None
    raw_parts = value.split(",")
    if any(part.strip() == "" for part in raw_parts):
        raise ValueError(
            f"malformed {field_name}; empty value in comma-separated list"
        )
    values = {part.strip() for part in raw_parts}
    if allowed_values is not None:
        allowed = set(allowed_values)
        unsupported = sorted(values - allowed)
        if unsupported:
            raise ValueError(
                f"unsupported {field_name}; {', '.join(unsupported)}"
            )
    return values


def _normalize_labels(value: Any) -> Optional[Set[str]]:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError("malformed labels; expected a list")

    values = tuple(value)

    labels: Set[str] = set()
    for item in values:
        if not isinstance(item, str):
            raise ValueError(f"malformed label value: {item!r}")
        candidate = item.strip()
        if not candidate:
            raise ValueError("label value must not be empty")
        labels.add(candidate)
    return labels


def _coerce_claims(projection: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw_claims = projection.get("claims")
    if not isinstance(raw_claims, list):
        raise ValueError("projection claims must be a list")

    claims: List[Dict[str, Any]] = []
    seen_claim_ids: set[str] = set()
    for index, claim in enumerate(raw_claims):
        if not isinstance(claim, dict):
            raise ValueError(f"projection claim at index {index} must be an object")

        for key in _REQUIRED_CLAIM_STRING_FIELDS:
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

        if "speaker" in claim:
            speaker = claim.get("speaker")
            if not isinstance(speaker, str):
                raise ValueError(f"projection claim at index {index} has invalid speaker")
            if not speaker.strip():
                raise ValueError(f"projection claim at index {index} has empty speaker")

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
        provenance_content_type = provenance.get("content_type")
        if provenance_content_type is not None and not isinstance(
            provenance_content_type, str
        ):
            raise ValueError(
                f"projection claim at index {index} has invalid content_type in provenance"
            )

        claims.append(claim)
    return claims


@dataclass(frozen=True)
class ContextPolicy:
    include_claim_types: Optional[Set[str]] = None
    include_temporal_states: Optional[Set[str]] = None
    include_user_assertion_only: bool = False
    include_conversation_ids: Optional[Set[str]] = None
    include_sensitivity_labels: Optional[Set[str]] = None
    include_scope_labels: Optional[Set[str]] = None
    max_items: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "include_claim_types": sorted(self.include_claim_types) if self.include_claim_types else None,
            "include_temporal_states": sorted(self.include_temporal_states) if self.include_temporal_states else None,
            "include_user_assertion_only": self.include_user_assertion_only,
            "include_conversation_ids": sorted(self.include_conversation_ids) if self.include_conversation_ids else None,
            "include_sensitivity_labels": sorted(self.include_sensitivity_labels)
            if self.include_sensitivity_labels
            else None,
            "include_scope_labels": sorted(self.include_scope_labels) if self.include_scope_labels else None,
            "max_items": self.max_items,
        }


def _normalize_claims(
    projection: Dict[str, Any],
    policy: ContextPolicy,
) -> List[Dict[str, Any]]:
    claims_raw = _coerce_claims(projection)

    selected: List[Dict[str, Any]] = []
    for claim in claims_raw:
        if "sensitivity_labels" in claim and claim.get("sensitivity_labels") is not None:
            normalized = _normalize_labels(claim["sensitivity_labels"])
            claim["sensitivity_labels"] = sorted(normalized) if normalized is not None else None
        if "scope_labels" in claim and claim.get("scope_labels") is not None:
            normalized = _normalize_labels(claim["scope_labels"])
            claim["scope_labels"] = sorted(normalized) if normalized is not None else None

        if policy.include_user_assertion_only and not bool(claim.get("is_user_assertion")):
            continue

        claim_type = claim.get("claim_type")
        if policy.include_claim_types is not None and claim_type not in policy.include_claim_types:
            continue

        temporal_state = claim.get("temporal_state")
        if policy.include_temporal_states is not None and temporal_state not in policy.include_temporal_states:
            continue

        conversation_id = claim.get("conversation_id")
        if policy.include_conversation_ids is not None and conversation_id not in policy.include_conversation_ids:
            continue

        sensitivity_labels = set(claim.get("sensitivity_labels") or [])
        if policy.include_sensitivity_labels is not None and (
            not sensitivity_labels
            or not policy.include_sensitivity_labels.intersection(sensitivity_labels)
        ):
            continue

        scope_labels = set(claim.get("scope_labels") or [])
        if policy.include_scope_labels is not None and (
            not scope_labels
            or not policy.include_scope_labels.intersection(scope_labels)
        ):
            continue

        selected.append(claim.copy())

    selected.sort(
        key=lambda item: (
            str(item.get("created_at") or CONTEXT_UNKNOWN_TIMESTAMP_SORT_KEY),
            str(item.get("claim_id", "")),
        )
    )

    if policy.max_items is not None and policy.max_items > 0:
        return selected[:policy.max_items]
    if policy.max_items is not None and policy.max_items <= 0:
        return []
    return selected


def _projection_digest(payload: Dict[str, Any]) -> str:
    projection_sha = payload.get("projection_sha256")
    if isinstance(projection_sha, str) and projection_sha:
        return projection_sha
    return sha256(_stable_payload(payload).encode("utf-8")).hexdigest()


def build_context_bundle(
    projection: Dict[str, Any],
    policy: ContextPolicy,
    *,
    purpose: str = "",
    task_id: str = "",
    scope: str = "",
    issued_at: Optional[str] = None,
    signing_secret: Optional[str] = None,
) -> Dict[str, Any]:
    if not isinstance(projection, dict):
        raise TypeError("projection must be a mapping")

    source_id = str(projection.get("source_id", ""))
    if not source_id:
        raise ValueError("projection missing source_id")

    claims = _normalize_claims(projection, policy)
    projection_sha = _projection_digest(projection)
    issued_at = issued_at or _utc_now()

    capsule: Dict[str, Any] = {
        "schema_version": CONTEXT_CAPSULE_SCHEMA_VERSION,
        "source_id": source_id,
        "source_projection_sha256": projection_sha,
        "purpose": purpose,
        "task_id": task_id,
        "scope": scope,
        "issued_at_utc": issued_at,
        "policy": policy.to_dict(),
        "claim_count": len(claims),
        "claims": claims,
    }
    capsule_digest = sha256(_stable_payload(capsule).encode("utf-8")).hexdigest()

    receipt: Dict[str, Any] = {
        "schema_version": CONTEXT_RECEIPT_SCHEMA_VERSION,
        "receipt_id": f"context-receipt-{sha256((f'{source_id}:{issued_at}').encode('utf-8')).hexdigest()[:16]}",
        "issued_at_utc": issued_at,
        "source_id": source_id,
        "source_projection_sha256": projection_sha,
        "context_capsule_sha256": capsule_digest,
        "context_capsule_claim_count": len(claims),
        "context_capsule_claim_ids": sorted(
            str(claim["claim_id"]) for claim in claims
        ),
        "corpus_ids": sorted(
            str(value) for value in projection.get("corpus_ids", [])
        )
        if isinstance(projection.get("corpus_ids"), list)
        else [],
        "index_generations": sorted(
            str(value) for value in projection.get("index_generations", [])
        )
        if isinstance(projection.get("index_generations"), list)
        else [],
        "purpose": purpose,
        "task_id": task_id,
        "scope": scope,
    }

    if signing_secret is not None:
        signature_message = f"{capsule_digest}:{issued_at}:{scope}:{task_id}:{purpose}"
        signature = hmac.new(
            signing_secret.encode("utf-8"),
            signature_message.encode("utf-8"),
            sha256,
        ).hexdigest()
        receipt["signature"] = {
            "algorithm": "HMAC-SHA256",
            "value": signature,
        }
    else:
        receipt["signature"] = None

    return {
        "context_capsule": capsule,
        "context_receipt": receipt,
    }


__all__ = [
    "CONTEXT_CAPSULE_SCHEMA_VERSION",
    "CONTEXT_RECEIPT_SCHEMA_VERSION",
    "CONTEXT_UNKNOWN_TIMESTAMP_SORT_KEY",
    "ALLOWED_CLAIM_TYPES",
    "ALLOWED_TEMPORAL_STATES",
    "ContextPolicy",
    "build_context_bundle",
    "parse_csv_set",
]
