"""Deterministic Seed ChangeIntent reconciliation.

No language model participates in classification.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from .canonical import canonical_bytes
from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer, TrustedKey, verify_bytes


class Classification(StrEnum):
    AUTHORIZED_SUCCESS = "authorized_success"
    AUTHORIZED_FAILED = "authorized_failed"
    AUTHORIZED_PARTIAL = "authorized_partial"
    SCOPE_BREACH = "scope_breach"
    UNRECORDED_CHANGE = "unrecorded_change"
    RETROSPECTIVE_CLAIM = "retrospective_claim"
    PLANNED_NOT_OBSERVED = "planned_not_observed"
    EXPECTED_DYNAMIC = "expected_dynamic"
    POLICY_DRIFT = "policy_drift"
    SENSOR_GAP = "sensor_gap"
    LEDGER_GAP = "ledger_gap"
    AMBIGUOUS = "ambiguous"
    SUPERSEDED = "superseded"


class PostCheck(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    PENDING = "PENDING"
    NOT_RUN = "NOT_RUN"


class IntentVerificationError(ValueError):
    """Raised when intent cannot be trusted as a prior authorization."""


@dataclass(frozen=True)
class ObservedDelta:
    tenant_id: str
    node_id: str
    selector: str
    operation: str
    observed_at: str
    before_digest: str | None
    after_digest: str | None
    post_check: PostCheck = PostCheck.PENDING
    evidence_complete: bool = True
    source_event_id: str | None = None


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed


def _intent_signature_payload(intent: dict[str, Any]) -> bytes:
    unsigned = deepcopy(intent)
    authorization = unsigned.get("authorization")
    if not isinstance(authorization, dict):
        raise IntentVerificationError("ChangeIntent authorization is missing")
    authorization.pop("signature", None)
    return b"integrity-guardian\x00change-intent-v1\x00" + canonical_bytes(unsigned)


def sign_change_intent(
    unsigned_intent: dict[str, Any], signer: Ed25519Signer
) -> dict[str, Any]:
    intent = deepcopy(unsigned_intent)
    authorization = intent.get("authorization")
    if not isinstance(authorization, dict):
        raise IntentVerificationError("ChangeIntent authorization is missing")
    if "signature" in authorization:
        raise IntentVerificationError("unsigned ChangeIntent already contains a signature")
    authorization["signature"] = {
        "algorithm": "ed25519",
        "key_id": signer.key_id,
        "value": signer.sign_bytes(_intent_signature_payload(intent)),
    }
    validate("change-intent", intent)
    return intent


def verify_change_intent(intent: dict[str, Any], authority_key: TrustedKey) -> None:
    validate("change-intent", intent)
    signature = intent["authorization"]["signature"]
    if signature["key_id"] != authority_key.key_id:
        raise IntentVerificationError("ChangeIntent authority key identity mismatch")
    if not verify_bytes(
        _intent_signature_payload(intent),
        signature["value"],
        authority_key.public_key,
    ):
        raise IntentVerificationError("ChangeIntent signature verification failed")

    created_at = _parse_time(intent["created_at"])
    valid_from = _parse_time(intent["valid_from"])
    valid_until = _parse_time(intent["valid_until"])
    if valid_from > valid_until:
        raise IntentVerificationError("ChangeIntent validity interval is inverted")
    if created_at > valid_until:
        raise IntentVerificationError("ChangeIntent was created after its validity ended")

    selectors = set(intent["scope"]["selectors"])
    operations = set(intent["scope"]["operations"])
    for index, change in enumerate(intent["expected_changes"]):
        if change["selector"] not in selectors or change["operation"] not in operations:
            raise IntentVerificationError(
                f"expected change {index} is outside the declared scope"
            )


def _result(
    *,
    classification: Classification,
    delta: ObservedDelta | None,
    intent: dict[str, Any] | None,
    reason: str,
    expected_index: int | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "classification": classification.value,
        "reason": reason,
        "intent_id": None if intent is None else intent["intent_id"],
        "selector": None if delta is None else delta.selector,
        "operation": None if delta is None else delta.operation,
        "source_event_id": None if delta is None else delta.source_event_id,
        "tenant_id": (
            intent["tenant_id"] if delta is None and intent is not None else
            None if delta is None else delta.tenant_id
        ),
        "node_id": (
            intent["target"]["node_id"] if delta is None and intent is not None else
            None if delta is None else delta.node_id
        ),
        "expected_change_index": expected_index,
    }
    result["decision_id"] = "decision:" + digest_object(
        result, domain="reconciliation-decision-v1"
    ).split(":", 1)[1]
    return result


def reconcile(
    *,
    intent: dict[str, Any] | None,
    observed: list[ObservedDelta],
    authority_key: TrustedKey | None = None,
) -> list[dict[str, Any]]:
    """Classify observed deltas against one exact prior intent.

    Multi-intent ambiguity resolution is intentionally a later layer. This
    primitive makes no probabilistic or semantic authorization decision.
    """

    if intent is None:
        return [
            _result(
                classification=(
                    Classification.SENSOR_GAP
                    if not delta.evidence_complete
                    else Classification.UNRECORDED_CHANGE
                ),
                delta=delta,
                intent=None,
                reason=(
                    "observation evidence is incomplete"
                    if not delta.evidence_complete
                    else "no applicable prior ChangeIntent"
                ),
            )
            for delta in observed
        ]

    if authority_key is None:
        raise IntentVerificationError("trusted ChangeIntent authority key is required")
    verify_change_intent(intent, authority_key)
    expected = intent["expected_changes"]
    matched_expected: set[int] = set()
    results: list[dict[str, Any]] = []
    created_at = _parse_time(intent["created_at"])
    valid_from = _parse_time(intent["valid_from"])
    valid_until = _parse_time(intent["valid_until"])

    if not observed:
        return [
            _result(
                classification=Classification.PLANNED_NOT_OBSERVED,
                delta=None,
                intent=intent,
                reason="valid intent has no observed change",
            )
        ]

    for delta in observed:
        observed_at = _parse_time(delta.observed_at)
        if (
            delta.tenant_id != intent["tenant_id"]
            or delta.node_id != intent["target"]["node_id"]
        ):
            results.append(
                _result(
                    classification=Classification.SCOPE_BREACH,
                    delta=delta,
                    intent=intent,
                    reason="observed tenant or node is outside intent target",
                )
            )
            continue
        if not delta.evidence_complete:
            results.append(
                _result(
                    classification=Classification.SENSOR_GAP,
                    delta=delta,
                    intent=intent,
                    reason="observation evidence is incomplete",
                )
            )
            continue

        exact_scope_indexes = [
            index
            for index, change in enumerate(expected)
            if change["selector"] == delta.selector and change["operation"] == delta.operation
        ]
        if intent.get("retrospective", False) or created_at > observed_at:
            results.append(
                _result(
                    classification=Classification.RETROSPECTIVE_CLAIM,
                    delta=delta,
                    intent=intent,
                    reason="ChangeIntent was created after the observation",
                    expected_index=exact_scope_indexes[0] if len(exact_scope_indexes) == 1 else None,
                )
            )
            continue
        if observed_at < valid_from or observed_at > valid_until:
            results.append(
                _result(
                    classification=Classification.UNRECORDED_CHANGE,
                    delta=delta,
                    intent=intent,
                    reason="ChangeIntent was not valid at observation time",
                    expected_index=exact_scope_indexes[0] if len(exact_scope_indexes) == 1 else None,
                )
            )
            continue
        if len(exact_scope_indexes) > 1:
            results.append(
                _result(
                    classification=Classification.AMBIGUOUS,
                    delta=delta,
                    intent=intent,
                    reason="multiple expected changes match the same selector and operation",
                )
            )
            continue
        if not exact_scope_indexes:
            results.append(
                _result(
                    classification=Classification.SCOPE_BREACH,
                    delta=delta,
                    intent=intent,
                    reason="observed selector or operation is outside intent scope",
                )
            )
            continue

        index = exact_scope_indexes[0]
        change = expected[index]
        matched_expected.add(index)
        exact_diff = (
            change["before_digest"] == delta.before_digest
            and change["after_digest"] == delta.after_digest
        )
        if not exact_diff:
            classification = Classification.AUTHORIZED_PARTIAL
            reason = "inside scope but observed before/after digest is not the exact intended diff"
        elif delta.post_check == PostCheck.PASS:
            classification = Classification.AUTHORIZED_SUCCESS
            reason = "exact prior intent, exact diff and post-check PASS"
        elif delta.post_check == PostCheck.FAIL:
            classification = Classification.AUTHORIZED_FAILED
            reason = "exact intended diff observed but required post-check failed"
        else:
            classification = Classification.AUTHORIZED_PARTIAL
            reason = "exact intended diff observed but post-check is incomplete"
        results.append(
            _result(
                classification=classification,
                delta=delta,
                intent=intent,
                reason=reason,
                expected_index=index,
            )
        )

    missing = set(range(len(expected))) - matched_expected
    if missing:
        classification = (
            Classification.AUTHORIZED_PARTIAL
            if matched_expected
            else Classification.PLANNED_NOT_OBSERVED
        )
        for index in sorted(missing):
            results.append(
                _result(
                    classification=classification,
                    delta=None,
                    intent=intent,
                    reason=f"expected change {index} was not observed",
                    expected_index=index,
                )
            )
    return results
