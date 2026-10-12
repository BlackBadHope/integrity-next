"""Content-free verification of one bounded Action Log recovery claim.

The module performs no I/O.  A separately constrained Action Log-owner helper
may digest exact event records, but this contract accepts and emits only those
digests plus bounded structural metadata.  It grants no recovery or production
authority.  A signed Guardian ``reconciliation`` ledger event may later bind
``action_log_recovery_payload_digest`` without placing raw event content in the
Ledger.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from jsonschema import ValidationError

from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .schemas import validate
from .seed_catalog import ACTION_LOG_ALIAS, SEED_NAMESPACE

RECOVERY_VERIFICATION_PROTOCOL = (
    "integrity-guardian/action-log-recovery-verification/v1"
)
RECOVERY_LEDGER_EVENT_TYPE = "reconciliation"
RECOVERY_LEDGER_ID = "ledger:action-log-recovery"
RECOVERY_LEDGER_SOURCE_ID = "source:action-log-recovery-verifier"
RECOVERY_CHECKPOINT_ID = "checkpoint:action-log-recovery"
TARGET_EVENT_IDS = (5232, 5235, 5236, 5237, 5239, 5240, 5242, 5243)

_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_EVENT_INPUT_FIELDS = {
    "event_id",
    "event_uid_digest",
    "reference_event_digest",
    "observed_event_digest",
}


class ActionLogRecoveryVerificationError(ValueError):
    """Raised before a recovery verification claim can be overstated."""


def _freeze(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    try:
        frozen = parse_json_strict(canonical_bytes(dict(value)))
    except Exception as exc:
        raise ActionLogRecoveryVerificationError(
            f"Action Log recovery {field} rejected"
        ) from exc
    if not isinstance(frozen, dict):
        raise ActionLogRecoveryVerificationError(
            f"Action Log recovery {field} rejected"
        )
    return frozen


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ActionLogRecoveryVerificationError(
            f"Action Log recovery {field} rejected"
        )
    return value


def _require_positive_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ActionLogRecoveryVerificationError(
            f"Action Log recovery {field} rejected"
        )
    return value


def _target_set_digest(events: Sequence[Mapping[str, Any]], digest_field: str) -> str:
    return digest_object(
        [
            {
                "event_id": event["event_id"],
                "event_digest": event[digest_field],
            }
            for event in events
        ],
        domain="action-log-recovery-target-set-v1",
    )


def action_log_recovery_verification_identity(
    receipt: Mapping[str, Any],
) -> str:
    """Return the content identity of one unsigned recovery receipt."""

    core = dict(receipt)
    core.pop("receipt_id", None)
    digest = digest_object(
        core,
        domain="action-log-recovery-verification-receipt-v1",
    )
    return f"action-log-recovery-verification:{digest.split(':', 1)[1]}"


def _normalized_event_inputs(
    event_digests: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if isinstance(event_digests, (str, bytes)) or not isinstance(
        event_digests, Sequence
    ):
        raise ActionLogRecoveryVerificationError(
            "Action Log recovery event digest sequence rejected"
        )
    normalized: list[dict[str, Any]] = []
    for value in event_digests:
        event = _freeze(value, "event digest")
        if set(event) != _EVENT_INPUT_FIELDS:
            raise ActionLogRecoveryVerificationError(
                "Action Log recovery event digest shape rejected"
            )
        normalized.append(
            {
                "event_id": _require_positive_integer(event["event_id"], "event id"),
                "event_uid_digest": _require_digest(
                    event["event_uid_digest"], "event UID digest"
                ),
                "reference_event_digest": _require_digest(
                    event["reference_event_digest"], "reference event digest"
                ),
                "observed_event_digest": _require_digest(
                    event["observed_event_digest"], "observed event digest"
                ),
            }
        )
    if tuple(event["event_id"] for event in normalized) != TARGET_EVENT_IDS:
        raise ActionLogRecoveryVerificationError(
            "Action Log recovery target event ids rejected"
        )
    uid_digests = [event["event_uid_digest"] for event in normalized]
    if len(set(uid_digests)) != len(uid_digests):
        raise ActionLogRecoveryVerificationError(
            "Action Log recovery event UID digests are not unique"
        )
    return normalized


def _expected_result(receipt: Mapping[str, Any]) -> str:
    exact = all(
        event["reference_match_count"] == 1
        and event["post_delete_match_count"] == 0
        and event["observed_match_count"] == 1
        and event["reference_event_digest"] == event["observed_event_digest"]
        and event["exact_match"] is True
        for event in receipt["events"]
    )
    if not exact:
        return "mismatch"
    if receipt["reference_trust"]["externally_pinned_before_incident"]:
        return "exact-pinned-reference"
    return "exact-local-reference"


def build_action_log_recovery_verification_receipt(
    *,
    event_digests: Sequence[Mapping[str, Any]],
    reference_source_digest: str,
    post_delete_source_digest: str,
    observed_source_digest: str,
    observed_event_count: int,
    observed_maximum_event_id: int,
    observed_at: str,
    externally_pinned_before_incident: bool = False,
    checkpoint_digest: str | None = None,
) -> dict[str, Any]:
    """Build one exact eight-event, digest-only recovery observation."""

    if not isinstance(externally_pinned_before_incident, bool):
        raise ActionLogRecoveryVerificationError(
            "Action Log recovery external pin flag rejected"
        )
    if externally_pinned_before_incident:
        _require_digest(checkpoint_digest, "reference checkpoint digest")
    elif checkpoint_digest is not None:
        raise ActionLogRecoveryVerificationError(
            "Action Log recovery unpinned reference has a checkpoint digest"
        )
    normalized = _normalized_event_inputs(event_digests)
    events = [
        {
            "event_id": event["event_id"],
            "event_uid_digest": event["event_uid_digest"],
            "reference_event_digest": event["reference_event_digest"],
            "reference_match_count": 1,
            "post_delete_match_count": 0,
            "observed_event_digest": event["observed_event_digest"],
            "observed_match_count": 1,
            "exact_match": (
                event["reference_event_digest"] == event["observed_event_digest"]
            ),
        }
        for event in normalized
    ]
    core: dict[str, Any] = {
        "protocol": RECOVERY_VERIFICATION_PROTOCOL,
        "source_namespace": SEED_NAMESPACE,
        "action_log_alias": ACTION_LOG_ALIAS,
        "observed_at": observed_at,
        "target_count": len(events),
        "events": events,
        "reference_target_set_digest": _target_set_digest(
            events, "reference_event_digest"
        ),
        "observed_target_set_digest": _target_set_digest(
            events, "observed_event_digest"
        ),
        "reference_source_digest": _require_digest(
            reference_source_digest, "reference source digest"
        ),
        "post_delete_source_digest": _require_digest(
            post_delete_source_digest, "post-delete source digest"
        ),
        "observed_source_digest": _require_digest(
            observed_source_digest, "observed source digest"
        ),
        "observed_cursor": {
            "event_count": _require_positive_integer(
                observed_event_count, "observed event count"
            ),
            "maximum_event_id": _require_positive_integer(
                observed_maximum_event_id, "observed maximum event id"
            ),
        },
        "unique_event_uid_index_verified": True,
        "sqlite_integrity": "ok",
        "verification_result": "mismatch",
        "reference_trust": {
            "externally_pinned_before_incident": externally_pinned_before_incident,
            "checkpoint_digest": checkpoint_digest,
            "same_failure_domain_rollback_protection": False,
        },
        "privacy_boundary": {
            "raw_event_body_emitted": False,
            "raw_event_body_retained": False,
            "database_path_emitted": False,
            "secrets_emitted": False,
            "output_mode": "digest-and-metadata-only",
        },
        "authority_boundary": {
            "canonical_writes": 0,
            "event_update": False,
            "event_delete": False,
            "event_import": False,
            "event_overwrite": False,
            "bulk_write": False,
            "recovery_authority": False,
            "production_authority": False,
        },
    }
    core["verification_result"] = _expected_result(core)
    receipt = {
        **core,
        "receipt_id": action_log_recovery_verification_identity(core),
    }
    return verify_action_log_recovery_verification_receipt(
        receipt,
        expected_reference_checkpoint_digest=(
            checkpoint_digest if externally_pinned_before_incident else None
        ),
    )


def verify_action_log_recovery_verification_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_reference_checkpoint_digest: str | None = None,
) -> dict[str, Any]:
    """Verify shape, identities, result semantics and an optional external pin."""

    candidate = _freeze(receipt, "verification receipt")
    try:
        validate("action-log-recovery-verification", candidate)
    except ValidationError as exc:
        raise ActionLogRecoveryVerificationError(
            "Action Log recovery receipt schema rejected"
        ) from exc
    if tuple(event["event_id"] for event in candidate["events"]) != TARGET_EVENT_IDS:
        raise ActionLogRecoveryVerificationError(
            "Action Log recovery target event ids rejected"
        )
    uid_digests = [event["event_uid_digest"] for event in candidate["events"]]
    if len(set(uid_digests)) != len(uid_digests):
        raise ActionLogRecoveryVerificationError(
            "Action Log recovery event UID digests are not unique"
        )
    for event in candidate["events"]:
        expected_exact = (
            event["reference_event_digest"] == event["observed_event_digest"]
        )
        if event["exact_match"] is not expected_exact:
            raise ActionLogRecoveryVerificationError(
                "Action Log recovery exact-match classification rejected"
            )
    expected_reference_set = _target_set_digest(
        candidate["events"], "reference_event_digest"
    )
    expected_observed_set = _target_set_digest(
        candidate["events"], "observed_event_digest"
    )
    if candidate["reference_target_set_digest"] != expected_reference_set:
        raise ActionLogRecoveryVerificationError(
            "Action Log recovery reference target-set digest mismatch"
        )
    if candidate["observed_target_set_digest"] != expected_observed_set:
        raise ActionLogRecoveryVerificationError(
            "Action Log recovery observed target-set digest mismatch"
        )
    if candidate["verification_result"] != _expected_result(candidate):
        raise ActionLogRecoveryVerificationError(
            "Action Log recovery verification result mismatch"
        )
    pinned = candidate["reference_trust"]["externally_pinned_before_incident"]
    stored_checkpoint = candidate["reference_trust"]["checkpoint_digest"]
    if expected_reference_checkpoint_digest is None:
        if pinned:
            raise ActionLogRecoveryVerificationError(
                "Action Log recovery pinned trust requires an external checkpoint"
            )
    else:
        expected_checkpoint = _require_digest(
            expected_reference_checkpoint_digest,
            "expected reference checkpoint digest",
        )
        if not pinned or stored_checkpoint != expected_checkpoint:
            raise ActionLogRecoveryVerificationError(
                "Action Log recovery external checkpoint mismatch"
            )
    if candidate["receipt_id"] != action_log_recovery_verification_identity(candidate):
        raise ActionLogRecoveryVerificationError(
            "Action Log recovery receipt identity mismatch"
        )
    return candidate


def action_log_recovery_payload_digest(
    receipt: Mapping[str, Any],
    *,
    expected_reference_checkpoint_digest: str | None = None,
) -> str:
    """Return the exact digest suitable for a signed reconciliation ledger event."""

    verified = verify_action_log_recovery_verification_receipt(
        receipt,
        expected_reference_checkpoint_digest=expected_reference_checkpoint_digest,
    )
    return digest_object(
        verified,
        domain="action-log-recovery-verification-payload-v1",
    )


__all__ = [
    "RECOVERY_CHECKPOINT_ID",
    "RECOVERY_LEDGER_EVENT_TYPE",
    "RECOVERY_LEDGER_ID",
    "RECOVERY_LEDGER_SOURCE_ID",
    "RECOVERY_VERIFICATION_PROTOCOL",
    "TARGET_EVENT_IDS",
    "ActionLogRecoveryVerificationError",
    "action_log_recovery_payload_digest",
    "action_log_recovery_verification_identity",
    "build_action_log_recovery_verification_receipt",
    "verify_action_log_recovery_verification_receipt",
]
