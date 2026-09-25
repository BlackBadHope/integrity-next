"""Disposable, synthetic Integrity Guardian M6 canary.

The canary exercises protocol and failure semantics inside one temporary
directory. It does not discover or mutate production systems.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time
import tracemalloc
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .adapters import Platform, SnapshotAdapter, SnapshotFact
from .cyber import BehaviorFact, GuardianCyber, SourceTrust, TruthStatus
from .hashing import digest_object
from .ledger import (
    LedgerAppendError,
    LedgerStore,
    LedgerVerificationError,
    build_ledger_event,
    event_digest,
)
from .reconciler import (
    Classification,
    ObservedDelta,
    PostCheck,
    reconcile,
    sign_change_intent,
)
from .sensor import LinuxSensor
from .signing import Ed25519Signer, TrustedKey, verify_signature

D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64
D3 = "sha256:" + "3" * 64
BASE_TIME = datetime(2026, 7, 26, 18, 30, tzinfo=UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _rss_kib() -> int | None:
    try:
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (FileNotFoundError, PermissionError, ValueError):
        return None
    return None


def _intent(
    signer: Ed25519Signer,
    *,
    created_at: str = "2026-07-26T18:25:00Z",
) -> dict[str, Any]:
    return sign_change_intent(
        {
            "protocol": "integrity-guardian/change-intent/v1",
            "intent_id": "intent:canary-config",
            "tenant_id": "tenant:public-a0d3e830ed127ef0",
            "actor": {"actor_id": "human:canary-owner", "kind": "human"},
            "target": {"node_id": "node:canary-linux"},
            "scope": {
                "selectors": ["file:/canary/config.json"],
                "operations": ["update-content"],
            },
            "expected_changes": [
                {
                    "selector": "file:/canary/config.json",
                    "operation": "update-content",
                    "before_digest": D1,
                    "after_digest": D2,
                }
            ],
            "created_at": created_at,
            "valid_from": "2026-07-26T18:26:00Z",
            "valid_until": "2026-07-26T18:40:00Z",
            "authorization": {
                "authority_id": "human:canary-owner",
                "decision": "approved",
            },
        },
        signer,
    )


def _delta(
    *,
    selector: str = "file:/canary/config.json",
    post_check: PostCheck = PostCheck.PASS,
    observed_at: str = "2026-07-26T18:30:00Z",
    evidence_complete: bool = True,
) -> ObservedDelta:
    return ObservedDelta(
        tenant_id="tenant:public-a0d3e830ed127ef0",
        node_id="node:canary-linux",
        selector=selector,
        operation="update-content",
        observed_at=observed_at,
        before_digest=D1,
        after_digest=D2,
        post_check=post_check,
        evidence_complete=evidence_complete,
        source_event_id="event:canary-delta",
    )


def _event(
    *,
    number: int,
    previous: str | None,
    signer: Ed25519Signer,
    tenant_id: str = "tenant:public-a0d3e830ed127ef0",
    payload: str | None = None,
) -> dict[str, Any]:
    return build_ledger_event(
        tenant_id=tenant_id,
        source_id="sensor:canary",
        source_sequence=number,
        event_type="observation",
        payload_digest=payload or digest_object(
            {"canary": number},
            domain="canary-payload",
        ),
        previous_event_digest=previous,
        signer=signer,
        recorded_at=_timestamp(BASE_TIME + timedelta(minutes=number)),
    )


def _gate(
    gates: list[dict[str, Any]],
    gate_id: str,
    passed: bool,
    observed: str,
) -> None:
    gates.append(
        {
            "gate_id": gate_id,
            "pass": bool(passed),
            "observed": observed,
        }
    )


def run_isolated_canary() -> dict[str, Any]:
    """Run every synthetic M6 experiment and return a secret-free report."""

    wall_started = time.perf_counter()
    cpu_started = time.process_time()
    rss_before = _rss_kib()
    tracemalloc.start()
    gates: list[dict[str, Any]] = []
    temporary_root = ""
    max_ledger_bytes = 0
    secret_sentinel = "SYNTHETIC-SECRET-MUST-NOT-LEAK-73a5"

    with tempfile.TemporaryDirectory(prefix="integrity-guardian-m6-") as raw_root:
        root = Path(raw_root)
        temporary_root = os.fspath(root)
        authority = Ed25519Signer.generate("key:canary-authority")
        authority_key = TrustedKey("key:canary-authority", authority.public_key)
        signed_intent = _intent(authority)

        exact = reconcile(
            intent=signed_intent,
            observed=[_delta()],
            authority_key=authority_key,
        )
        _gate(
            gates,
            "01-exact-authorized-change",
            [item["classification"] for item in exact]
            == [Classification.AUTHORIZED_SUCCESS],
            "exact prior intent, diff and post-check PASS",
        )

        failed = reconcile(
            intent=signed_intent,
            observed=[_delta(post_check=PostCheck.FAIL)],
            authority_key=authority_key,
        )
        _gate(
            gates,
            "02-authorized-failed-behavior",
            failed[0]["classification"] == Classification.AUTHORIZED_FAILED,
            "exact intended diff retained authorized_failed after post-check FAIL",
        )

        breach = reconcile(
            intent=signed_intent,
            observed=[_delta(selector="file:/canary/out-of-scope")],
            authority_key=authority_key,
        )
        _gate(
            gates,
            "03-extra-out-of-scope-change",
            Classification.SCOPE_BREACH
            in {item["classification"] for item in breach},
            "scope_breach remained visible",
        )

        unrecorded = reconcile(intent=None, observed=[_delta()])
        _gate(
            gates,
            "04-change-without-intent",
            unrecorded[0]["classification"] == Classification.UNRECORDED_CHANGE,
            "unrecorded_change",
        )

        retrospective = reconcile(
            intent=_intent(authority, created_at="2026-07-26T18:31:00Z"),
            observed=[_delta(observed_at="2026-07-26T18:30:00Z")],
            authority_key=authority_key,
        )
        _gate(
            gates,
            "05-retrospective-intent",
            retrospective[0]["classification"] == Classification.RETROSPECTIVE_CLAIM,
            "retrospective_claim",
        )

        protected = root / "protected.json"
        protected.write_text('{"value":"before"}', encoding="utf-8")
        sensor_signer = Ed25519Signer.generate("key:canary-linux")
        sensor = LinuxSensor(
            tenant_id="tenant:public-a0d3e830ed127ef0",
            sensor_id="sensor:canary-linux",
            node_id="node:canary-linux",
            signer=sensor_signer,
            clock=lambda: BASE_TIME,
        )
        before = sensor.observe_path(protected)
        protected.write_text('{"value":"during"}', encoding="utf-8")
        during = sensor.observe_path(protected)
        protected.write_text('{"value":"before"}', encoding="utf-8")
        restored = sensor.observe_path(protected)
        _gate(
            gates,
            "06-change-and-revert-between-full-scans",
            (
                before["evidence"]["content_digest"]
                == restored["evidence"]["content_digest"]
                and before["evidence"]["content_digest"]
                != during["evidence"]["content_digest"]
                and during["previous_observation_digest"]
                == digest_object(before, domain="observation-chain-v1")
            ),
            "transient content digest and signed sequence preserved before restoration",
        )

        source = Ed25519Signer.generate("key:canary-ledger-source")
        sequence_path = root / "sequence-gap.sqlite"
        first = _event(number=0, previous=None, signer=source)
        skipped = _event(number=2, previous=event_digest(first), signer=source)
        sequence_rejected = False
        with LedgerStore(
            sequence_path,
            tenant_id="tenant:public-a0d3e830ed127ef0",
            ledger_id="ledger:sequence-gap",
        ) as store:
            store.append(first)
            try:
                store.append(skipped)
            except LedgerAppendError:
                sequence_rejected = True
        max_ledger_bytes = max(max_ledger_bytes, sequence_path.stat().st_size)
        _gate(
            gates,
            "07-sensor-stop-and-restart",
            sequence_rejected,
            "missing source sequence failed closed",
        )

        clock_values = iter([BASE_TIME, BASE_TIME - timedelta(minutes=1)])
        clock_sensor = LinuxSensor(
            tenant_id="tenant:public-a0d3e830ed127ef0",
            sensor_id="sensor:clock",
            node_id="node:clock",
            signer=Ed25519Signer.generate("key:clock"),
            clock=lambda: next(clock_values),
        )
        clock_sensor.observe_path(protected)
        clock_rollback = clock_sensor.observe_path(protected)
        _gate(
            gates,
            "08-local-clock-rollback",
            (
                clock_rollback["evidence"]["state"] == "sensor-gap"
                and clock_rollback["evidence"]["metadata"]["error_kind"]
                == "clock-rollback"
            ),
            "clock rollback emitted a signed sensor-gap",
        )

        tamper_path = root / "tamper.sqlite"
        tamper_first = _event(number=0, previous=None, signer=source)
        tamper_second = _event(
            number=1,
            previous=event_digest(tamper_first),
            signer=source,
        )
        with LedgerStore(
            tamper_path,
            tenant_id="tenant:public-a0d3e830ed127ef0",
            ledger_id="ledger:tamper",
        ) as store:
            store.append_many([tamper_first, tamper_second])
        connection = sqlite3.connect(tamper_path)
        raw = connection.execute(
            "SELECT event_json FROM ledger_events WHERE ledger_sequence = 2"
        ).fetchone()[0]
        document = json.loads(raw)
        document["payload_digest"] = D3
        connection.execute(
            "UPDATE ledger_events SET event_json = ? WHERE ledger_sequence = 2",
            (json.dumps(document, sort_keys=True, separators=(",", ":")).encode(),),
        )
        connection.commit()
        connection.close()
        tamper_rejected = False
        with LedgerStore(
            tamper_path,
            tenant_id="tenant:public-a0d3e830ed127ef0",
            ledger_id="ledger:tamper",
        ) as store:
            try:
                store.verify(
                    source_public_keys={
                        "sensor:canary": TrustedKey(
                            "key:canary-ledger-source",
                            source.public_key,
                        )
                    }
                )
            except LedgerVerificationError:
                tamper_rejected = True
        max_ledger_bytes = max(max_ledger_bytes, tamper_path.stat().st_size)
        _gate(
            gates,
            "09-ledger-tamper",
            tamper_rejected,
            "modified event bytes failed offline verification",
        )

        checkpoint_signer = Ed25519Signer.generate("key:canary-checkpoint")
        roots: list[str] = []
        for label, payload in (("left", D1), ("right", D2)):
            view_path = root / f"split-{label}.sqlite"
            view_first = _event(
                number=0,
                previous=None,
                signer=source,
                payload=payload,
            )
            view_second = _event(
                number=1,
                previous=event_digest(view_first),
                signer=source,
                payload=D3,
            )
            with LedgerStore(
                view_path,
                tenant_id="tenant:public-a0d3e830ed127ef0",
                ledger_id="ledger:split-view",
            ) as store:
                store.append_many([view_first, view_second])
                roots.append(
                    store.checkpoint(
                        checkpoint_id=f"checkpoint:{label}",
                        signer=checkpoint_signer,
                        created_at="2026-07-26T18:40:00Z",
                    )["root_digest"]
                )
            max_ledger_bytes = max(max_ledger_bytes, view_path.stat().st_size)
        _gate(
            gates,
            "10-conflicting-checkpoint",
            roots[0] != roots[1],
            "same-size split views produced different Merkle roots",
        )

        noisy = root / "dynamic-cache"
        noisy.mkdir()
        excluded = LinuxSensor(
            tenant_id="tenant:public-a0d3e830ed127ef0",
            sensor_id="sensor:exclusion",
            node_id="node:canary-linux",
            signer=Ed25519Signer.generate("key:exclusion"),
            exclusions=(os.fspath(noisy),),
            clock=lambda: BASE_TIME,
        ).observe_path(noisy)
        _gate(
            gates,
            "11-noisy-dynamic-exclusion",
            (
                excluded["evidence"]["state"] == "unknown"
                and excluded["evidence"]["metadata"]["coverage"] == "excluded"
            ),
            "exclusion remained an explicit coverage gap",
        )

        protected_secret = root / "protected-secret.txt"
        protected_secret.write_text(secret_sentinel, encoding="utf-8")
        secret_observation = LinuxSensor(
            tenant_id="tenant:public-a0d3e830ed127ef0",
            sensor_id="sensor:privacy",
            node_id="node:canary-linux",
            signer=Ed25519Signer.generate("key:privacy"),
            clock=lambda: BASE_TIME,
        ).observe_path(protected_secret)
        serialized_observation = json.dumps(secret_observation, sort_keys=True)
        _gate(
            gates,
            "12-synthetic-secret-privacy",
            (
                secret_sentinel not in serialized_observation
                and secret_observation["evidence"]["content_digest"] is not None
            ),
            "only the digest and non-content metadata left the sensor",
        )

        replay_path = root / "disconnected-replay.sqlite"
        replay_events: list[dict[str, Any]] = []
        previous: str | None = None
        for number in range(3):
            buffered = _event(
                number=number,
                previous=previous,
                signer=source,
            )
            replay_events.append(buffered)
            previous = event_digest(buffered)
        with LedgerStore(
            replay_path,
            tenant_id="tenant:public-a0d3e830ed127ef0",
            ledger_id="ledger:replay",
        ) as store:
            store.append_many(replay_events)
            replay_result = store.verify(
                source_public_keys={
                    "sensor:canary": TrustedKey(
                        "key:canary-ledger-source",
                        source.public_key,
                    )
                }
            )
        max_ledger_bytes = max(max_ledger_bytes, replay_path.stat().st_size)
        _gate(
            gates,
            "13-disconnected-buffer-and-replay",
            replay_result["tree_size"] == 3,
            "three buffered source-sequenced events replayed and verified",
        )

        tenant_path = root / "tenant.sqlite"
        foreign = _event(
            number=0,
            previous=None,
            signer=source,
            tenant_id="tenant:public-adc098318f62fb10",
        )
        tenant_rejected = False
        with LedgerStore(
            tenant_path,
            tenant_id="tenant:public-a0d3e830ed127ef0",
            ledger_id="ledger:tenant",
        ) as store:
            try:
                store.append(foreign)
            except LedgerAppendError:
                tenant_rejected = True
        max_ledger_bytes = max(max_ledger_bytes, tenant_path.stat().st_size)
        _gate(
            gates,
            "14-tenant-isolation-negative",
            tenant_rejected,
            "cross-tenant append was rejected before commit",
        )

        external_findings = GuardianCyber().evaluate(
            reconciliation_decisions=[],
            behavior_facts=[
                BehaviorFact(
                    tenant_id="tenant:public-a0d3e830ed127ef0",
                    asset_id="service:canary-http",
                    fact_type="external-probe",
                    source_event_id="event:canary-probe",
                    changed=False,
                    attributes={
                        "probe": "https",
                        "vantage": "isolated-canary",
                        "success": False,
                        "expected": "HTTP 200",
                        "actual": "timeout",
                    },
                    truth_status=TruthStatus.VERIFIED,
                    source_trust=SourceTrust.HIGH,
                    observed_at="2026-07-26T18:30:00Z",
                    valid_until="2026-07-26T18:35:00Z",
                )
            ],
        )
        _gate(
            gates,
            "15-external-failure-unchanged-skeleton",
            (
                len(external_findings) == 1
                and external_findings[0]["policy_id"] == "IG-CYBER-041"
                and external_findings[0]["changed"] is False
            ),
            "failed external behavior remained a finding despite unchanged L1",
        )

        rollback_path = root / "rollback.sqlite"
        rollback_first = _event(number=0, previous=None, signer=source)
        rollback_invalid = _event(
            number=2,
            previous=event_digest(rollback_first),
            signer=source,
        )
        batch_rejected = False
        with LedgerStore(
            rollback_path,
            tenant_id="tenant:public-a0d3e830ed127ef0",
            ledger_id="ledger:rollback",
        ) as store:
            try:
                store.append_many([rollback_first, rollback_invalid])
            except LedgerAppendError:
                batch_rejected = store.event_digests() == []
        with LedgerStore(
            rollback_path,
            tenant_id="tenant:public-a0d3e830ed127ef0",
            ledger_id="ledger:rollback",
        ) as store:
            recovered_empty = store.event_digests() == []
        max_ledger_bytes = max(max_ledger_bytes, rollback_path.stat().st_size)
        _gate(
            gates,
            "16-atomic-crash-rollback-recovery",
            batch_rejected and recovered_empty,
            "invalid batch rolled back and reopened empty",
        )

        platform_observations: list[dict[str, Any]] = []
        for platform in Platform:
            platform_signer = Ed25519Signer.generate(f"key:{platform.value}")
            adapter = SnapshotAdapter(
                tenant_id="tenant:public-a0d3e830ed127ef0",
                sensor_id=f"sensor:{platform.value}",
                node_id=f"node:{platform.value}",
                platform=platform,
                signer=platform_signer,
            )
            observation = adapter.emit(
                SnapshotFact(
                    subject_kind="service",
                    identity=f"service:{platform.value}-canary",
                    layer="L2",
                    state="present",
                    content_digest=None,
                    metadata={"healthy": True},
                ),
                observed_at="2026-07-26T18:30:00Z",
            )
            platform_observations.append(observation)
            if not verify_signature(observation, platform_signer.public_key):
                break
        _gate(
            gates,
            "17-multi-platform-adapter-contract",
            (
                len(platform_observations) == len(Platform)
                and {
                    item["evidence"]["metadata"]["platform"]
                    for item in platform_observations
                }
                == {platform.value for platform in Platform}
            ),
            "OS families and network snapshots used one signed observation contract",
        )

    temporary_removed = not Path(temporary_root).exists()
    current_allocated, peak_allocated = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    wall_seconds = time.perf_counter() - wall_started
    cpu_seconds = time.process_time() - cpu_started
    rss_after = _rss_kib()
    resource_pass = (
        wall_seconds < 10.0
        and cpu_seconds < 10.0
        and peak_allocated < 64 * 1024 * 1024
        and max_ledger_bytes < 8 * 1024 * 1024
    )
    _gate(
        gates,
        "18-bounded-resources",
        resource_pass,
        "wall/cpu/heap/ledger stayed below isolated-canary ceilings",
    )
    _gate(
        gates,
        "19-complete-removal",
        temporary_removed,
        "temporary canary root no longer exists",
    )

    report: dict[str, Any] = {
        "schema": "integrity-guardian/isolated-canary-report/v1",
        "executed_at": datetime.now(UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z"),
        "scope": "single-process disposable synthetic canary",
        "production_mutated": False,
        "credentials_persisted": False,
        "network_io_performed": False,
        "operator_review": {
            "required": True,
            "automatic_baseline_promotion": False,
            "automatic_remediation": False,
        },
        "resources": {
            "wall_seconds": round(wall_seconds, 6),
            "cpu_seconds": round(cpu_seconds, 6),
            "rss_kib_before": rss_before,
            "rss_kib_after": rss_after,
            "rss_kib_delta": (
                None
                if rss_before is None or rss_after is None
                else rss_after - rss_before
            ),
            "tracemalloc_current_bytes": current_allocated,
            "tracemalloc_peak_bytes": peak_allocated,
            "max_ledger_bytes": max_ledger_bytes,
            "ceilings": {
                "wall_seconds": 10.0,
                "cpu_seconds": 10.0,
                "tracemalloc_peak_bytes": 64 * 1024 * 1024,
                "max_ledger_bytes": 8 * 1024 * 1024,
            },
        },
        "gates": gates,
        "limitations": [
            "Windows and network adapter inputs are synthetic sanitized snapshots",
            "The external probe result is synthetic and no endpoint was contacted",
            "This canary does not establish fleet scale or production non-impact",
            "M7 production shadow observation requires separate exact owner approval",
        ],
    }
    report_text = json.dumps(report, sort_keys=True)
    privacy_pass = secret_sentinel not in report_text
    _gate(
        gates,
        "20-report-privacy",
        privacy_pass,
        "synthetic secret is absent from the final report",
    )
    report["pass"] = all(item["pass"] for item in gates)
    report["verdict"] = "PASS_ISOLATED" if report["pass"] else "FAIL"
    report["production_ready"] = False
    return report
