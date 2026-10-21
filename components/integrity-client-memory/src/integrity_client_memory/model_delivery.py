"""One-use, process-local proof of a model's canonical-context lookup.

The owning broker supplies authenticated Native bindings and the exact public
admission shown to its model. Only its model-owned MCP dispatch may acknowledge
the challenge. This proves one bounded retrieval, never general understanding,
complete context consumption, append authority, or external action authority.
No source data, receipt key, or proof is persisted by this module.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
import time

CHALLENGE_PROTOCOL = "integrity-model-delivery-challenge/v1"
RECEIPT_PROTOCOL = "integrity-model-delivery-receipt/v1"
MAX_TTL_SECONDS = 300


class ModelDeliveryError(ValueError):
    pass


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError):
        raise ModelDeliveryError("delivery binding is not canonical JSON") from None


def _digest(value):
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _hash(value, *, prefixed=False):
    if not isinstance(value, str):
        return False
    if prefixed:
        if not value.startswith("sha256:"):
            return False
        value = value[7:]
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _owner(value):
    if not isinstance(value, dict) or value.get("admitted") is not True:
        raise ModelDeliveryError("admitted current Native owner required")
    hashes = value.get("hashes")
    if (not isinstance(hashes, dict)
            or set(hashes) != {"machine_id", "thread_id", "turn_id"}
            or any(not _hash(v) for v in hashes.values())
            or type(value.get("generation")) is not int or value["generation"] < 1
            or not _hash(value.get("prompt_sha256"))
            or not _hash(value.get("turn_ref_digest"), prefixed=True)
            or not _hash(value.get("context_admission_id"), prefixed=True)
            or not isinstance(value.get("intent_id"), str)
            or not value["intent_id"].startswith("intent:")):
        raise ModelDeliveryError("current Native owner binding invalid")
    return _digest(value)


def _now(value):
    current = time.time() if value is None else value
    if isinstance(current, bool) or not isinstance(current, (float, int)) or not math.isfinite(current):
        raise ModelDeliveryError("delivery clock invalid")
    return current


def _presented(value):
    if not isinstance(value, dict):
        raise ModelDeliveryError("public canonical admission required")
    # These are the exact model-visible bodies. Transport paths, local secrets,
    # and the challenge itself are deliberately outside this material.
    material = {key: value[key] for key in
                ("context_text", "selected", "canonical_read_context", "mind")
                if key in value}
    context = value.get("canonical_read_context")
    events = context.get("events") if isinstance(context, dict) else None
    if not isinstance(events, list):
        raise ModelDeliveryError("public canonical events unavailable")
    candidates = []
    summaries = [e.get("summary") for e in events if isinstance(e, dict)]
    for event in events:
        if not isinstance(event, dict):
            continue
        event_id, summary = event.get("event_id"), event.get("summary")
        if (type(event_id) is int and event_id > 0 and isinstance(summary, str)
                and 0 < len(summary.encode("utf-8")) <= 4096
                and event.get("summary_truncated") is not True
                and summaries.count(summary) == 1):
            candidates.append((event_id, summary))
    if not candidates:
        raise ModelDeliveryError("unambiguous public canonical event unavailable")
    return _digest(material), candidates


class ModelDeliveryVerifier:
    """In-memory verifier, owned by exactly one model-facing broker instance.

    The caller must revalidate the current Native head and owner before issue,
    verify, and status. Passing a model-supplied owner or snapshot is forbidden.
    Process restart loses this proof; it cannot be imported or replayed.
    """

    def __init__(self, *, ttl_seconds=MAX_TTL_SECONDS):
        if type(ttl_seconds) is not int or not 0 < ttl_seconds <= MAX_TTL_SECONDS:
            raise ModelDeliveryError("delivery challenge lifetime invalid")
        self._ttl = ttl_seconds
        self._key = secrets.token_bytes(32)
        self._active = None

    def issue(self, owner_binding, snapshot_id, presented_capsule, now=None):
        owner_digest, current = _owner(owner_binding), _now(now)
        if not _hash(snapshot_id, prefixed=True):
            raise ModelDeliveryError("delivery snapshot invalid")
        capsule_digest, candidates = _presented(presented_capsule)
        previous = self._active
        subject = (owner_digest, snapshot_id, capsule_digest)
        if previous is not None and previous["subject"] == subject:
            # Repeated presentation cannot extend expiry or reset consumption.
            return json.loads(_canonical(previous["challenge"]))
        event_id, summary = candidates[secrets.randbelow(len(candidates))]
        challenge = {
            "protocol": CHALLENGE_PROTOCOL,
            "challenge_id": "delivery:" + secrets.token_hex(24),
            "nonce": secrets.token_hex(24),
            "snapshot_id": snapshot_id,
            "capsule_sha256": capsule_digest,
            "owner_binding_sha256": owner_digest,
            "issued_at": current,
            "expires_at": current + self._ttl,
            "question": "Return the event_id from canonical_read_context.events whose summary exactly matches event_summary.",
            "event_summary": summary,
            "coverage": "one-canonical-event-lookup",
            "external_action_authority": False,
        }
        self._active = {"subject": subject, "challenge": challenge,
                        "event_id": event_id, "consumed": False, "receipt": None}
        return json.loads(_canonical(challenge))

    def verify(self, arguments, owner_binding, now=None):
        owner_digest, current = _owner(owner_binding), _now(now)
        active = self._active
        if active is None or active["subject"][0] != owner_digest:
            raise ModelDeliveryError("current delivery challenge unavailable")
        challenge = active["challenge"]
        if active["consumed"]:
            raise ModelDeliveryError("delivery challenge already consumed")
        if not challenge["issued_at"] <= current < challenge["expires_at"]:
            raise ModelDeliveryError("delivery challenge expired or outside its window")
        if (not isinstance(arguments, dict)
                or set(arguments) != {"challenge_id", "nonce", "event_id"}):
            raise ModelDeliveryError("delivery acknowledgement shape invalid")
        if (not isinstance(arguments["challenge_id"], str)
                or not hmac.compare_digest(arguments["challenge_id"], challenge["challenge_id"])
                or not isinstance(arguments["nonce"], str)
                or not hmac.compare_digest(arguments["nonce"], challenge["nonce"])
                or type(arguments["event_id"]) is not int
                or arguments["event_id"] != active["event_id"]):
            # A wrong attempt cannot be used as an answer oracle.
            active["consumed"] = True
            raise ModelDeliveryError("delivery acknowledgement mismatch")
        material = {
            "protocol": RECEIPT_PROTOCOL,
            "challenge_id": challenge["challenge_id"],
            "challenge_sha256": _digest(challenge),
            "owner_binding_sha256": owner_digest,
            "snapshot_id": challenge["snapshot_id"],
            "capsule_sha256": challenge["capsule_sha256"],
            "event_id": active["event_id"],
            "verified_at": current,
            "challenge_expires_at": challenge["expires_at"],
            "model_delivery_verified": True,
            "coverage": "one-canonical-event-lookup",
            "limitation": "Does not prove complete context consumption or general semantic understanding.",
            "verifier": "current-model-owned-mcp-broker",
            "authentication_scope": "process-local; unavailable after broker restart",
            "external_action_authority": False,
            "canonical_writes": 0,
        }
        receipt_id = _digest(material)
        signature = hmac.new(self._key, _canonical(material), hashlib.sha256).hexdigest()
        receipt = {**material, "receipt_id": receipt_id,
                   "signature": {"algorithm": "hmac-sha256", "value": signature}}
        active.update(consumed=True, receipt=receipt)
        return json.loads(_canonical(receipt))

    def status(self, owner_binding, snapshot_id, now=None):
        owner_digest = _owner(owner_binding)
        _now(now)
        active = self._active
        if (active is None or active["subject"][:2] != (owner_digest, snapshot_id)
                or active["receipt"] is None):
            return {"model_delivery_verified": False}
        receipt = active["receipt"]
        material = {k: v for k, v in receipt.items() if k not in {"receipt_id", "signature"}}
        expected = hmac.new(self._key, _canonical(material), hashlib.sha256).hexdigest()
        if (receipt["receipt_id"] != _digest(material)
                or not hmac.compare_digest(receipt["signature"]["value"], expected)):
            raise ModelDeliveryError("delivery receipt integrity invalid")
        return {"model_delivery_verified": True,
                "model_delivery_receipt": json.loads(_canonical(receipt))}
