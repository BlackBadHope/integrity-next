"""Deterministic local review-candidate bundles and content-free receipts.

Candidate bundles stay beside the canonical projection.  The companion receipt
is deliberately content-free and can be copied into an operational Action Log.
The validators in this module are also the trust boundary used by the reviewed
Action Log bridge: locators and digests are never accepted on trust.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Any, Dict, List, Mapping
import json

from .projection_integrity import canonical_projection_sha256
from .review import extract_review_claims


CANDIDATE_BUNDLE_SCHEMA_VERSION = "chronicle-candidate-bundle/3"
CANDIDATE_RECEIPT_SCHEMA_VERSION = "chronicle-candidate-receipt/3"


def _stable_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(payload: Any) -> str:
    return sha256(_stable_json(payload).encode("utf-8")).hexdigest()


def _required_projection_string(projection: Dict[str, Any], field_name: str) -> str:
    value = projection.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"projection missing {field_name}")
    return value


def _required_string(record: Mapping[str, Any], field_name: str) -> str:
    value = record.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"candidate missing {field_name}")
    return value


def _required_index(record: Mapping[str, Any], field_name: str) -> int:
    value = record.get(field_name)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"candidate missing valid {field_name}")
    return value


def _build_source_locator(
    claim: Mapping[str, Any],
    *,
    source_id: str,
    projection_sha256: str,
) -> Dict[str, Any]:
    conversation_id = _required_string(claim, "conversation_id")
    message_id = _required_string(claim, "message_id")
    source_message_index = _required_index(claim, "source_message_index")
    provenance = claim.get("provenance")
    if not isinstance(provenance, Mapping):
        raise ValueError("candidate missing provenance")

    message_ref = _required_string(provenance, "message_ref")
    expected_ref = f"{conversation_id}/{message_id}"
    if message_ref != expected_ref:
        raise ValueError(
            f"candidate message_ref mismatch: expected {expected_ref!r}"
        )
    branch_path = provenance.get("branch_path", "")
    if not isinstance(branch_path, str):
        raise ValueError("candidate provenance branch_path must be a string")
    content_type = provenance.get("content_type")
    if content_type is not None and not isinstance(content_type, str):
        raise ValueError("candidate provenance content_type must be a string when provided")
    provider_conversation_id = claim.get("provider_conversation_id")
    if provider_conversation_id is not None and not isinstance(
        provider_conversation_id, str
    ):
        raise ValueError("candidate provider_conversation_id must be a string when provided")

    locator: Dict[str, Any] = {
        "source_id": source_id,
        "source_projection_sha256": projection_sha256,
        "conversation_id": conversation_id,
        "provider_conversation_id": provider_conversation_id,
        "message_id": message_id,
        "source_message_index": source_message_index,
        "message_ref": message_ref,
        "branch_path": branch_path,
        "content_type": content_type,
    }
    locator["locator_sha256"] = _digest(locator)
    return locator


def _ground_claim_in_projection(
    projection: Mapping[str, Any],
    claim: Mapping[str, Any],
) -> Dict[str, Any]:
    """Resolve an untrusted extractor claim to one exact canonical message."""

    conversations = projection.get("conversations")
    if not isinstance(conversations, list):
        raise ValueError("projection conversations must be a list")
    conversation_id = _required_string(claim, "conversation_id")
    matches = [
        (index, item)
        for index, item in enumerate(conversations)
        if isinstance(item, Mapping) and item.get("conversation_id") == conversation_id
    ]
    if len(matches) != 1:
        raise ValueError(
            f"candidate locator conversation must resolve exactly once: {conversation_id}"
        )
    conversation_index, conversation = matches[0]
    messages = conversation.get("messages")
    if not isinstance(messages, list):
        raise ValueError(f"candidate locator conversation has no message list: {conversation_id}")
    message_index = _required_index(claim, "source_message_index")
    if message_index >= len(messages):
        raise ValueError(
            f"candidate locator source_message_index out of bounds: {message_index}"
        )
    message = messages[message_index]
    if not isinstance(message, Mapping):
        raise ValueError("candidate locator resolved to a non-object message")
    message_id = _required_string(claim, "message_id")
    if message.get("message_id") != message_id:
        raise ValueError("candidate locator message_id does not match canonical message")

    claim_provider_id = claim.get("provider_conversation_id")
    canonical_provider_id = conversation.get("provider_conversation_id")
    if (
        not isinstance(canonical_provider_id, str)
        or not canonical_provider_id
        or claim_provider_id != canonical_provider_id
    ):
        raise ValueError("candidate locator provider_conversation_id mismatch")
    provenance = claim.get("provenance")
    if not isinstance(provenance, Mapping):
        raise ValueError("candidate missing provenance")
    if provenance.get("branch_path", "") != message.get("branch_path", ""):
        raise ValueError("candidate locator branch_path mismatch")
    if provenance.get("content_type") != message.get("content_type"):
        raise ValueError("candidate locator content_type mismatch")

    is_user_assertion = claim.get("is_user_assertion")
    if is_user_assertion is True:
        if claim.get("claim_type") != "user_assertion":
            raise ValueError("user assertion claim_type mismatch")
        role = message.get("role")
        if not isinstance(role, str) or role.strip().casefold() != "user":
            raise ValueError("user assertion is not grounded in a user message")
        if claim.get("claim_text") != message.get("content"):
            raise ValueError("user assertion text is not grounded in canonical message")
    elif claim.get("claim_type") == "user_assertion":
        raise ValueError("user_assertion claim_type requires is_user_assertion=true")

    return {
        "conversation_index": conversation_index,
        "message_index": message_index,
        "canonical_pointer": f"/conversations/{conversation_index}/messages/{message_index}",
    }


def _validate_source_locator(
    locator: Mapping[str, Any],
    *,
    source_id: str,
    projection_sha256: str,
    conversation_id: str,
) -> Dict[str, Any]:
    if not isinstance(locator, Mapping):
        raise ValueError("candidate source_locator must be an object")
    normalized = dict(locator)
    locator_digest = normalized.pop("locator_sha256", None)
    if not isinstance(locator_digest, str) or locator_digest != _digest(normalized):
        raise ValueError("candidate source_locator digest mismatch")
    if normalized.get("source_id") != source_id:
        raise ValueError("candidate source_locator source_id mismatch")
    if normalized.get("source_projection_sha256") != projection_sha256:
        raise ValueError("candidate source_locator projection mismatch")
    if normalized.get("conversation_id") != conversation_id:
        raise ValueError("candidate source_locator conversation mismatch")
    message_id = _required_string(normalized, "message_id")
    source_message_index = _required_index(normalized, "source_message_index")
    conversation_index = _required_index(normalized, "conversation_index")
    message_index = _required_index(normalized, "message_index")
    if message_index != source_message_index:
        raise ValueError("candidate source_locator message index mismatch")
    expected_pointer = f"/conversations/{conversation_index}/messages/{message_index}"
    if normalized.get("canonical_pointer") != expected_pointer:
        raise ValueError("candidate source_locator canonical_pointer mismatch")
    if normalized.get("message_ref") != f"{conversation_id}/{message_id}":
        raise ValueError("candidate source_locator message_ref mismatch")
    if not isinstance(normalized.get("branch_path"), str):
        raise ValueError("candidate source_locator branch_path must be a string")
    content_type = normalized.get("content_type")
    if content_type is not None and not isinstance(content_type, str):
        raise ValueError("candidate source_locator content_type must be a string when provided")
    normalized["locator_sha256"] = locator_digest
    return normalized


def build_candidate_bundle(projection: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    if not isinstance(projection, dict):
        raise TypeError("projection must be an object")

    source_id = _required_projection_string(projection, "source_id")
    projection_sha256 = canonical_projection_sha256(projection)
    claims = extract_review_claims(projection)

    candidates: List[Dict[str, Any]] = []
    for claim in claims:
        canonical_location = _ground_claim_in_projection(projection, claim)
        candidate: Dict[str, Any] = {
                "candidate_id": claim["claim_id"],
                "claim_id": claim["claim_id"],
                "review_claim_sha256": claim["review_claim_sha256"],
                # The signed review decision binds this exact normalized claim
                # digest. Keeping the detached snapshot lets publication
                # prove that a locator was not swapped after review.
                "review_claim": dict(claim),
                "claim_type": claim["claim_type"],
                "claim_text": claim["claim_text"],
                "temporal_state": claim["temporal_state"],
                "created_at": claim["created_at"],
                "conversation_id": claim["conversation_id"],
                "is_user_assertion": claim["is_user_assertion"],
                "evidence_kind": (
                    "user_assertion"
                    if claim["is_user_assertion"]
                    else "assistant_inference"
                ),
                "source_locator": _build_source_locator(
                    claim,
                    source_id=source_id,
                    projection_sha256=projection_sha256,
                ),
                "review_state": "pending",
                "authoritative": False,
            }
        locator = candidate["source_locator"]
        locator.update(canonical_location)
        locator.pop("locator_sha256", None)
        locator["locator_sha256"] = _digest(locator)
        candidate["candidate_sha256"] = _digest(candidate)
        candidates.append(candidate)

    bundle: Dict[str, Any] = {
        "schema_version": CANDIDATE_BUNDLE_SCHEMA_VERSION,
        "source_id": source_id,
        "source_projection_sha256": projection_sha256,
        "review_policy": "explicit_review_required",
        "authoritative": False,
        "candidate_count": len(candidates),
        "candidates": candidates,
    }
    bundle["candidate_bundle_sha256"] = _digest(bundle)

    receipt: Dict[str, Any] = {
        "schema_version": CANDIDATE_RECEIPT_SCHEMA_VERSION,
        "receipt_id": "",
        "event_type": "candidate_bundle_built",
        "source_id": source_id,
        "corpus_id": source_id,
        "index_generation": projection_sha256,
        "source_projection_sha256": projection_sha256,
        "candidate_bundle_sha256": bundle["candidate_bundle_sha256"],
        "candidate_count": len(candidates),
        "candidate_ids": sorted(candidate["candidate_id"] for candidate in candidates),
        "candidate_id_set_sha256": _digest(
            sorted(candidate["candidate_id"] for candidate in candidates)
        ),
        "review_required": True,
        "contains_raw_content": False,
        "contains_derived_personal_facts": False,
    }
    receipt["receipt_id"] = f"chronicle-candidates-{_digest(receipt)[:24]}"
    return {"candidate_bundle": bundle, "candidate_receipt": receipt}


def validate_candidate_bundle(bundle: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate and return a detached candidate bundle.

    This rejects stale or edited candidate payloads before review decisions can
    be exported.  It intentionally does not infer or repair missing locators.
    """

    if not isinstance(bundle, Mapping):
        raise TypeError("candidate bundle must be an object")
    normalized = dict(bundle)
    bundle_digest = normalized.pop("candidate_bundle_sha256", None)
    if normalized.get("schema_version") != CANDIDATE_BUNDLE_SCHEMA_VERSION:
        raise ValueError("unsupported candidate bundle schema_version")
    if not isinstance(bundle_digest, str) or bundle_digest != _digest(normalized):
        raise ValueError("candidate bundle digest mismatch")
    source_id = _required_string(normalized, "source_id")
    projection_sha256 = _required_string(normalized, "source_projection_sha256")
    if normalized.get("review_policy") != "explicit_review_required":
        raise ValueError("candidate bundle review policy mismatch")
    if normalized.get("authoritative") is not False:
        raise ValueError("candidate bundle must not be authoritative")
    candidates = normalized.get("candidates")
    if not isinstance(candidates, list):
        raise ValueError("candidate bundle candidates must be a list")
    if normalized.get("candidate_count") != len(candidates):
        raise ValueError("candidate bundle candidate_count mismatch")

    seen: set[str] = set()
    validated: List[Dict[str, Any]] = []
    for index, raw_candidate in enumerate(candidates):
        if not isinstance(raw_candidate, Mapping):
            raise ValueError(f"candidate at index {index} must be an object")
        candidate = dict(raw_candidate)
        candidate_digest = candidate.pop("candidate_sha256", None)
        if not isinstance(candidate_digest, str) or candidate_digest != _digest(candidate):
            raise ValueError(f"candidate digest mismatch at index {index}")
        candidate_id = _required_string(candidate, "candidate_id")
        if candidate_id in seen:
            raise ValueError(f"duplicate candidate_id: {candidate_id}")
        seen.add(candidate_id)
        if candidate.get("claim_id") != candidate_id:
            raise ValueError(f"candidate claim_id mismatch at index {index}")
        _required_string(candidate, "review_claim_sha256")
        review_claim = candidate.get("review_claim")
        if not isinstance(review_claim, Mapping):
            raise ValueError(f"candidate review_claim invalid at index {index}")
        review_claim = dict(review_claim)
        review_claim_digest = review_claim.pop("review_claim_sha256", None)
        if review_claim_digest != candidate["review_claim_sha256"]:
            raise ValueError(f"candidate review claim digest field mismatch at index {index}")
        if _digest(review_claim) != candidate["review_claim_sha256"]:
            raise ValueError(f"candidate review claim digest mismatch at index {index}")
        review_claim["review_claim_sha256"] = review_claim_digest
        conversation_id = _required_string(candidate, "conversation_id")
        _required_string(candidate, "claim_type")
        _required_string(candidate, "claim_text")
        _required_string(candidate, "temporal_state")
        if not isinstance(candidate.get("is_user_assertion"), bool):
            raise ValueError(f"candidate is_user_assertion invalid at index {index}")
        if candidate.get("review_state") != "pending":
            raise ValueError(f"candidate review_state invalid at index {index}")
        if candidate.get("authoritative") is not False:
            raise ValueError(f"candidate must not be authoritative at index {index}")
        candidate["source_locator"] = _validate_source_locator(
            candidate.get("source_locator"),
            source_id=source_id,
            projection_sha256=projection_sha256,
            conversation_id=conversation_id,
        )
        locator = candidate["source_locator"]
        linked_fields = {
            "claim_id": candidate_id,
            "claim_type": candidate["claim_type"],
            "claim_text": candidate["claim_text"],
            "temporal_state": candidate["temporal_state"],
            "created_at": candidate.get("created_at"),
            "conversation_id": conversation_id,
            "is_user_assertion": candidate["is_user_assertion"],
            "provider_conversation_id": locator.get("provider_conversation_id"),
            "message_id": locator["message_id"],
            "source_message_index": locator["source_message_index"],
        }
        for field_name, expected in linked_fields.items():
            if review_claim.get(field_name) != expected:
                raise ValueError(
                    f"candidate review claim {field_name} mismatch at index {index}"
                )
        provenance = review_claim.get("provenance")
        if not isinstance(provenance, Mapping):
            raise ValueError(f"candidate review claim provenance invalid at index {index}")
        for field_name in ("message_ref", "branch_path", "content_type"):
            if provenance.get(field_name) != locator.get(field_name):
                raise ValueError(
                    f"candidate review claim provenance {field_name} mismatch at index {index}"
                )
        candidate["review_claim"] = review_claim
        candidate["candidate_sha256"] = candidate_digest
        validated.append(candidate)

    normalized["candidates"] = validated
    normalized["candidate_bundle_sha256"] = bundle_digest
    return normalized


def validate_candidate_receipt(
    receipt: Mapping[str, Any],
    bundle: Mapping[str, Any],
) -> Dict[str, Any]:
    if not isinstance(receipt, Mapping):
        raise TypeError("candidate receipt must be an object")
    normalized_bundle = validate_candidate_bundle(bundle)
    normalized = dict(receipt)
    receipt_id = normalized.get("receipt_id")
    normalized["receipt_id"] = ""
    if normalized.get("schema_version") != CANDIDATE_RECEIPT_SCHEMA_VERSION:
        raise ValueError("unsupported candidate receipt schema_version")
    expected_id = f"chronicle-candidates-{_digest(normalized)[:24]}"
    if receipt_id != expected_id:
        raise ValueError("candidate receipt digest mismatch")
    expected = {
        "source_id": normalized_bundle["source_id"],
        "corpus_id": normalized_bundle["source_id"],
        "index_generation": normalized_bundle["source_projection_sha256"],
        "source_projection_sha256": normalized_bundle["source_projection_sha256"],
        "candidate_bundle_sha256": normalized_bundle["candidate_bundle_sha256"],
        "candidate_count": normalized_bundle["candidate_count"],
        "candidate_ids": sorted(
            candidate["candidate_id"] for candidate in normalized_bundle["candidates"]
        ),
        "candidate_id_set_sha256": _digest(
            sorted(candidate["candidate_id"] for candidate in normalized_bundle["candidates"])
        ),
    }
    for field_name, expected_value in expected.items():
        if normalized.get(field_name) != expected_value:
            raise ValueError(f"candidate receipt {field_name} mismatch")
    if normalized.get("review_required") is not True:
        raise ValueError("candidate receipt must require review")
    if normalized.get("contains_raw_content") is not False:
        raise ValueError("candidate receipt must be content-free")
    if normalized.get("contains_derived_personal_facts") is not False:
        raise ValueError("candidate receipt must omit derived personal facts")
    normalized["receipt_id"] = receipt_id
    return normalized


__all__ = [
    "CANDIDATE_BUNDLE_SCHEMA_VERSION",
    "CANDIDATE_RECEIPT_SCHEMA_VERSION",
    "build_candidate_bundle",
    "validate_candidate_bundle",
    "validate_candidate_receipt",
]
