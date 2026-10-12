"""Bounded M6 canary for pre-collected read-only platform snapshots.

Collection is deliberately outside this module. The canary accepts only a
small, sanitized contract and has no transport, command, credential or
remediation capability.
"""

from __future__ import annotations

from typing import Any

from .adapters import Platform, SnapshotAdapter, SnapshotFact
from .cyber import BehaviorFact, GuardianCyber, SourceTrust, TruthStatus
from .hashing import digest_object
from .signing import Ed25519Signer, verify_signature

_TOP_LEVEL_KEYS = {
    "observed_at",
    "valid_until",
    "windows",
    "network",
    "external",
}
_WINDOWS_KEYS = {"os_version", "service_name", "service_status"}
_NETWORK_KEYS = {
    "system_state",
    "interface_name",
    "interface_flags",
    "operstate",
}
_EXTERNAL_KEYS = {"probe", "vantage", "success", "expected", "actual"}
_SECRET_MARKERS = ("secret", "password", "passwd", "token", "cookie", "private_key")


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"{label} keys mismatch: missing={missing}, extra={extra}")


def _require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    if len(value) > 128:
        raise ValueError(f"{label} exceeds the 128-character canary bound")
    return value.strip()


def _reject_secret_like_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in _SECRET_MARKERS):
                raise ValueError("snapshot contains a secret-like field name")
            _reject_secret_like_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_secret_like_keys(nested)


def _gate(gates: list[dict[str, Any]], name: str, passed: bool, evidence: str) -> None:
    gates.append({"name": name, "pass": bool(passed), "evidence": evidence})


def run_readonly_adapter_canary(
    snapshot: dict[str, Any],
    *,
    source_revision: str,
) -> dict[str, Any]:
    """Convert sanitized live facts into signed evidence and evaluate gates."""

    if not isinstance(snapshot, dict):
        # The canary exposes one uniform invalid-snapshot contract.
        raise ValueError("snapshot must be an object")  # noqa: TRY004
    _reject_secret_like_keys(snapshot)
    _require_exact_keys(snapshot, _TOP_LEVEL_KEYS, "snapshot")

    observed_at = _require_text(snapshot["observed_at"], "observed_at")
    valid_until = _require_text(snapshot["valid_until"], "valid_until")
    source_revision = _require_text(source_revision, "source_revision")

    windows = snapshot["windows"]
    network = snapshot["network"]
    external = snapshot["external"]
    if not all(isinstance(value, dict) for value in (windows, network, external)):
        raise ValueError("windows, network and external must be objects")
    _require_exact_keys(windows, _WINDOWS_KEYS, "windows")
    _require_exact_keys(network, _NETWORK_KEYS, "network")
    _require_exact_keys(external, _EXTERNAL_KEYS, "external")

    windows_version = _require_text(windows["os_version"], "windows.os_version")
    windows_service = _require_text(windows["service_name"], "windows.service_name")
    windows_status = _require_text(
        windows["service_status"],
        "windows.service_status",
    )
    network_state = _require_text(network["system_state"], "network.system_state")
    interface_name = _require_text(
        network["interface_name"],
        "network.interface_name",
    )
    operstate = _require_text(network["operstate"], "network.operstate")
    flags = network["interface_flags"]
    if (
        not isinstance(flags, list)
        or not flags
        or any(not isinstance(flag, str) or not flag.strip() for flag in flags)
    ):
        raise ValueError("network.interface_flags must be a non-empty string list")
    normalized_flags = sorted({flag.strip().upper() for flag in flags})

    probe = _require_text(external["probe"], "external.probe")
    vantage = _require_text(external["vantage"], "external.vantage")
    expected = _require_text(external["expected"], "external.expected")
    actual = _require_text(external["actual"], "external.actual")
    success = external["success"]
    if not isinstance(success, bool):
        # Keep all invalid snapshot fields under the same public exception.
        raise ValueError("external.success must be boolean")  # noqa: TRY004

    observations: list[dict[str, Any]] = []
    signature_results: dict[str, bool] = {}
    for platform, fact in (
        (
            Platform.WINDOWS,
            SnapshotFact(
                subject_kind="service",
                identity=f"service:{windows_service.lower()}",
                layer="L2",
                state="present",
                content_digest=None,
                metadata={
                    "os_version": windows_version,
                    "service_status": windows_status,
                },
            ),
        ),
        (
            Platform.NETWORK,
            SnapshotFact(
                subject_kind="node",
                identity="node:network-canary",
                layer="L2",
                state="present",
                content_digest=None,
                metadata={
                    "system_state": network_state,
                    "interface_name": interface_name,
                    "interface_flags": ",".join(normalized_flags),
                    "operstate": operstate,
                },
            ),
        ),
    ):
        signer = Ed25519Signer.generate(f"key:m6-{platform.value}")
        adapter = SnapshotAdapter(
            tenant_id="tenant:public-19b422cdda7a5502",
            sensor_id=f"sensor:m6-{platform.value}",
            node_id=f"node:m6-{platform.value}",
            platform=platform,
            signer=signer,
        )
        observation = adapter.emit(fact, observed_at=observed_at)
        observations.append(observation)
        signature_results[platform.value] = verify_signature(
            observation,
            signer.public_key,
        )

    external_fact = BehaviorFact(
        tenant_id="tenant:public-19b422cdda7a5502",
        asset_id="service:management-path-canary",
        fact_type="external-probe",
        source_event_id="event:m6-readonly-external-probe",
        changed=False,
        attributes={
            "probe": probe,
            "vantage": vantage,
            "success": success,
            "expected": expected,
            "actual": actual,
        },
        truth_status=TruthStatus.VERIFIED,
        source_trust=SourceTrust.HIGH,
        observed_at=observed_at,
        valid_until=valid_until,
    )
    findings = GuardianCyber().evaluate(
        reconciliation_decisions=[],
        behavior_facts=[external_fact],
    )

    gates: list[dict[str, Any]] = []
    _gate(
        gates,
        "windows-signed-observation",
        signature_results["windows"],
        "sanitized Windows service fact emitted and Ed25519 signature verified",
    )
    _gate(
        gates,
        "windows-service-healthy",
        windows_status.casefold() == "running",
        f"{windows_service} state is {windows_status}",
    )
    _gate(
        gates,
        "network-signed-observation",
        signature_results["network"],
        "sanitized network node fact emitted and Ed25519 signature verified",
    )
    _gate(
        gates,
        "network-system-healthy",
        network_state.casefold() == "running",
        f"network system state is {network_state}",
    )
    required_flags = {"UP", "LOWER_UP"}
    _gate(
        gates,
        "network-interface-healthy",
        required_flags.issubset(normalized_flags),
        f"{interface_name} flags include {','.join(sorted(required_flags))}",
    )
    _gate(
        gates,
        "external-readonly-path-healthy",
        success and actual == expected and not findings,
        f"{probe} from {vantage}: expected={expected}, actual={actual}",
    )
    _gate(
        gates,
        "transport-outside-guardian",
        True,
        "runner consumed pre-collected values and contains no transport implementation",
    )

    observation_receipts = [
        {
            "platform": observation["evidence"]["metadata"]["platform"],
            "observation_id": observation["observation_id"],
            "observation_digest": digest_object(
                observation,
                domain="m6-readonly-observation-receipt-v1",
            ),
            "signature_ok": signature_results[
                observation["evidence"]["metadata"]["platform"]
            ],
        }
        for observation in observations
    ]
    passed = all(gate["pass"] for gate in gates)
    return {
        "schema": "integrity-guardian/readonly-adapter-canary-report/v1",
        "source_revision": source_revision,
        "observed_at": observed_at,
        "valid_until": valid_until,
        "scope": "pre-collected sanitized owner-controlled read-only snapshots",
        "verdict": "PASS_READONLY" if passed else "FAIL_READONLY",
        "pass": passed,
        "production_mutated": False,
        "production_ready": False,
        "network_retrieval_performed_by_guardian": False,
        "observation_receipts": observation_receipts,
        "gates": gates,
        "finding_count": len(findings),
        "finding_ids": [finding["finding_id"] for finding in findings],
        "limitations": [
            "The Windows and network facts are bounded point-in-time snapshots.",
            "The external check proves only the named management-path behavior.",
            "Collection transport remains operator-controlled and outside Guardian.",
            "This M6 evidence is not an M7 production shadow authorization.",
        ],
    }
