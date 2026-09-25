"""Shared deterministic protocol helpers for installed cross-agent acceptance."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from integrity_guardian.agent_handoff import (
    acknowledge_module_agent_handoff,
    build_module_agent_handoff_checkpoint,
)
from integrity_guardian.canonical import canonical_bytes, parse_json_strict
from integrity_guardian.cross_agent_continuity import (
    acknowledge_cross_agent_continuity_package,
    build_continuity_epistemic_record,
    build_continuity_receipt_reference,
    build_cross_agent_continuity_package,
    continuity_statement_digest,
    verify_cross_agent_continuity_admission,
)
from integrity_guardian.hashing import digest_object
from integrity_guardian.signing import Ed25519Signer, TrustedKey

TASK_ID = "task:cross-agent-deterministic-sum"
TENANT_ID = "tenant:public-0660f95c17ebc298"
MODULE_ID = "module:cross-agent-continuity"
REPORT_PROTOCOL = "integrity-guardian/cross-agent-abc-acceptance-report/v1"
PRIOR_DOMAIN = "cross-agent-continuity-admission-reference-v1"
RESULT_DOMAIN = "cross-agent-abc-acceptance-task-result-v1"
REPORT_DOMAIN = "cross-agent-abc-acceptance-report-v1"
RECEIPT_DOMAIN = "cross-agent-abc-acceptance-synthetic-receipt-v1"
ROLES = ["action", "append", "authority", "observation", "read"]
DEFAULT_KEY_NAMESPACE = b"integrity-cross-agent-acceptance-v1"
KEY_NAMES = (
    "agent:a",
    "agent:b",
    "agent:c",
    "action-log",
    "observer",
    "owner",
)
PUBLIC_KEY_HEX = {
    "agent:a": "0cd41c217c7cb0630308cb4450898ae60c702a2a9b82c31208e3c7551cc39e1f",
    "agent:b": "3bdfdc2b3aee9d4c0061a9e4bc74ee9ef97c2259e255a1bb1c1a6d1a8441a933",
    "agent:c": "be027a55933260017c9daf909d6a7da526237a33f6e0823b56ecdb3c1ed5d0ad",
    "action-log": "a67590c7179aa437fc62085ac25a747744199ff4c7f3916e2838fedc6fbd1b08",
    "observer": "792b85aa154c6885cdb4fe0c9b810d9d2c927e4c4c5af0d25731939b16bdc9d3",
    "owner": "33fb634e51c179e5a98557961df93e456059568f1d3d2399ff6b9ed0d9339748",
}

Spec = tuple[str, str | None, dict[str, Any], str | None, str | None]


class CrossAgentAcceptanceError(ValueError):
    """Raised when the synthetic causal chain is incomplete or ambiguous."""


@dataclass(frozen=True)
class Keys:
    signers: dict[str, Ed25519Signer]
    agents: dict[str, TrustedKey]
    issuers: dict[tuple[str, str], TrustedKey]


@dataclass(frozen=True)
class TrustAnchors:
    agents: dict[str, TrustedKey]
    issuers: dict[tuple[str, str], TrustedKey]


def _signer(key_id: str, *, namespace: bytes) -> Ed25519Signer:
    if not namespace:
        raise CrossAgentAcceptanceError("fixture key namespace must not be empty")
    seed = hashlib.sha256(namespace + b"\0" + key_id.encode()).digest()
    return Ed25519Signer(key_id, Ed25519PrivateKey.from_private_bytes(seed))


def trusted(signer: Ed25519Signer) -> TrustedKey:
    return TrustedKey(signer.key_id, signer.public_key)


def fixture_keys(*, namespace: bytes = DEFAULT_KEY_NAMESPACE) -> Keys:
    signers = {
        name: _signer(f"key:{name}", namespace=namespace) for name in KEY_NAMES
    }
    action_log = trusted(signers["action-log"])
    observer = trusted(signers["observer"])
    return Keys(
        signers,
        {name: trusted(signers[name]) for name in ("agent:a", "agent:b", "agent:c")},
        {
            ("read", "issuer:action-log"): action_log,
            ("append", "issuer:action-log"): action_log,
            ("observation", "issuer:observer"): observer,
            ("action", "issuer:observer"): observer,
            ("authority", "issuer:owner"): trusted(signers["owner"]),
        },
    )


def _public_fixture_key(name: str) -> TrustedKey:
    try:
        raw = bytes.fromhex(PUBLIC_KEY_HEX[name])
    except (KeyError, ValueError) as exc:
        raise CrossAgentAcceptanceError("fixture public key inventory rejected") from exc
    return TrustedKey(f"key:{name}", Ed25519PublicKey.from_public_bytes(raw))


def fixture_trust_anchors() -> TrustAnchors:
    agents = {
        name: _public_fixture_key(name) for name in ("agent:a", "agent:b", "agent:c")
    }
    action_log = _public_fixture_key("action-log")
    observer = _public_fixture_key("observer")
    return TrustAnchors(
        agents,
        {
            ("read", "issuer:action-log"): action_log,
            ("append", "issuer:action-log"): action_log,
            ("observation", "issuer:observer"): observer,
            ("action", "issuer:observer"): observer,
            ("authority", "issuer:owner"): _public_fixture_key("owner"),
        },
    )


def text(value: dict[str, Any]) -> str:
    return canonical_bytes(value).decode()


def _issuer(keys: Keys, role: str) -> tuple[str, Ed25519Signer]:
    if role in {"read", "append"}:
        return "issuer:action-log", keys.signers["action-log"]
    if role in {"observation", "action"}:
        return "issuer:observer", keys.signers["observer"]
    if role == "authority":
        return "issuer:owner", keys.signers["owner"]
    raise CrossAgentAcceptanceError(f"unsupported receipt role: {role}")


def _evidence(
    keys: Keys,
    checkpoint: dict[str, Any],
    actor: str,
    specs: list[Spec],
    minute: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records, references = [], []
    for sequence, (classification, role, statement, protocol, digest) in enumerate(specs):
        reference = None
        if role is not None:
            issuer_id, signer = _issuer(keys, role)
            rendered = text(statement)
            reference = build_continuity_receipt_reference(
                checkpoint=checkpoint,
                receipt_id=f"receipt:abc:{actor}:{statement['kind']}",
                receipt_protocol=protocol or f"integrity-guardian/{role}-receipt/v1",
                receipt_type=role,
                receipt_digest=digest
                or digest_object(
                    {"actor": actor, "role": role, "statement": statement},
                    domain=RECEIPT_DOMAIN,
                ),
                task_id=TASK_ID,
                claim_digest=continuity_statement_digest(rendered),
                subject_actor_id=actor,
                issuer_id=issuer_id,
                observed_at=f"2026-08-19T12:{minute:02d}:{sequence:02d}Z",
                issuer_signer=signer,
            )
            references.append(reference)
        records.append(
            build_continuity_epistemic_record(
                sequence=sequence,
                classification=classification,
                statement=text(statement),
                actor_id=actor,
                source_reference_id=(
                    None if reference is None else reference["reference_id"]
                ),
            )
        )
    return records, references


def build_leg(
    keys: Keys,
    *,
    predecessor: str,
    predecessor_generation: int,
    head_id: str,
    head_digest: str,
    successor: str,
    successor_generation: int,
    cursor: int,
    snapshot: dict[str, Any],
    remaining: str,
    specs: list[Spec],
    minute: int,
    expiry_minutes: tuple[int, int, int],
) -> dict[str, Any]:
    ack_expiry, package_expiry, admission_expiry = expiry_minutes
    predecessor_signer = keys.signers[predecessor]
    successor_signer = keys.signers[successor]
    checkpoint = build_module_agent_handoff_checkpoint(
        tenant_id=TENANT_ID,
        module_id=MODULE_ID,
        predecessor_agent_id=predecessor,
        predecessor_generation=predecessor_generation,
        predecessor_lease_id=f"lease:{predecessor}",
        predecessor_head_id=head_id,
        predecessor_head_digest=head_digest,
        successor_agent_id=successor,
        successor_key_id=successor_signer.key_id,
        successor_generation=successor_generation,
        snapshot_digest=digest_object(
            snapshot,
            domain=f"cross-agent-abc-{predecessor}-snapshot-v1",
        ),
        event_cursor=cursor,
        outstanding_work_digest=digest_object(
            {"task_id": TASK_ID, "remaining": remaining},
            domain="cross-agent-abc-work-v1",
        ),
        created_at=f"2026-08-19T12:{minute:02d}:00Z",
        expires_at="2026-08-19T13:00:00Z",
        predecessor_signer=predecessor_signer,
    )
    ack = acknowledge_module_agent_handoff(
        checkpoint,
        predecessor_key=keys.agents[predecessor],
        successor_signer=successor_signer,
        acknowledged_at=f"2026-08-19T12:{minute + 2:02d}:00Z",
        expires_at=f"2026-08-19T12:{ack_expiry:02d}:00Z",
    )
    records, references = _evidence(keys, checkpoint, predecessor, specs, minute + 1)
    package = build_cross_agent_continuity_package(
        checkpoint=checkpoint,
        ack=ack,
        predecessor_key=keys.agents[predecessor],
        successor_key=keys.agents[successor],
        receipt_issuer_keys=keys.issuers,
        task_id=TASK_ID,
        epistemic_records=records,
        receipt_provenance=references,
        stop_conditions=[
            "Stop before any read, append, mutation, or production operation.",
            "Stop if any exact continuity digest differs.",
        ],
        created_at=f"2026-08-19T12:{minute + 3:02d}:00Z",
        expires_at=f"2026-08-19T12:{package_expiry:02d}:00Z",
        predecessor_signer=predecessor_signer,
    )
    admission = acknowledge_cross_agent_continuity_package(
        package,
        checkpoint,
        ack,
        predecessor_key=keys.agents[predecessor],
        successor_key=keys.agents[successor],
        receipt_issuer_keys=keys.issuers,
        successor_signer=successor_signer,
        accepted_at=f"2026-08-19T12:{minute + 4:02d}:00Z",
        expires_at=f"2026-08-19T12:{admission_expiry:02d}:00Z",
    )
    return {"checkpoint": checkpoint, "ack": ack, "package": package, "admission": admission}


def record_map(
    package: dict[str, Any],
) -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
    mapped = {}
    for record in package["epistemic_records"]:
        value = parse_json_strict(record["statement"])
        if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
            raise CrossAgentAcceptanceError("epistemic statement is not typed")
        if value["kind"] in mapped:
            raise CrossAgentAcceptanceError(f"duplicate epistemic kind: {value['kind']}")
        mapped[value["kind"]] = record, value
    return mapped


def required(
    records: dict[str, tuple[dict[str, Any], dict[str, Any]]],
    kind: str,
    classification: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        record, value = records[kind]
    except KeyError as exc:
        raise CrossAgentAcceptanceError(f"required epistemic kind missing: {kind}") from exc
    if record["classification"] != classification:
        raise CrossAgentAcceptanceError(f"classification mismatch for {kind}")
    return record, value


def context_only(result: dict[str, Any]) -> None:
    if (
        result.get("continuation_permitted") is not True
        or result.get("continuation_scope") != "context-only"
        or result.get("read_authority") is not False
        or result.get("append_authority") is not False
        or result.get("production_authority") is not False
    ):
        raise CrossAgentAcceptanceError("context-only authority boundary rejected")


def verify_leg(
    leg: dict[str, Any],
    *,
    predecessor_key: TrustedKey,
    successor_key: TrustedKey,
    issuer_keys: dict[tuple[str, str], TrustedKey],
    at_time: str,
) -> dict[str, Any]:
    result = verify_cross_agent_continuity_admission(
        leg["package"],
        leg["checkpoint"],
        leg["ack"],
        leg["admission"],
        predecessor_key=predecessor_key,
        successor_key=successor_key,
        receipt_issuer_keys=issuer_keys,
        at_time=at_time,
    )
    context_only(result)
    return result
