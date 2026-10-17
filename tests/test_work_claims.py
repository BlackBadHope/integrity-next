"""Local blast-radius coordination: parallel, waiting, fencing, handoff, replay."""
from __future__ import annotations

import multiprocessing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from integrity_guardian.work_claims import (
    ClaimStatus,
    StaleFenceError,
    WorkClaimError,
    WorkClaimRegistry,
    normalize_resource,
    resources_overlap,
)

T0 = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)


def at(seconds: int) -> datetime:
    return T0 + timedelta(seconds=seconds)


@pytest.fixture
def registry(tmp_path: Path) -> WorkClaimRegistry:
    with WorkClaimRegistry(tmp_path / "claims.sqlite") as value:
        yield value


def test_resource_normalization_over_approximates_overlap() -> None:
    assert normalize_resource("file:C:\\Repo\\Src\\") == "file:c:/repo/src"
    assert resources_overlap("file:/repo", "file:/repo/src/a.py")
    assert resources_overlap("host:db-1", "host:db-1")
    assert not resources_overlap("file:/repo-a", "file:/repo")
    assert not resources_overlap("file:/repo", "host:/repo")
    for bad in ("no-kind", "file:", "file:/a/../b", "File:/a", "file:a b"):
        with pytest.raises(WorkClaimError):
            normalize_resource(bad)


def test_disjoint_claims_run_in_parallel(registry: WorkClaimRegistry) -> None:
    a = registry.claim(agent_id="agent:a", resources=["file:/repo/src"], now=at(0))
    b = registry.claim(agent_id="agent:b", resources=["file:/repo/docs"], now=at(0))
    assert a.status is b.status is ClaimStatus.ACQUIRED
    assert b.fence_token > a.fence_token


def test_overlap_waits_then_acquires_after_release(registry: WorkClaimRegistry) -> None:
    a = registry.claim(agent_id="agent:a", resources=["file:/repo"], now=at(0))
    b = registry.claim(agent_id="agent:b", resources=["file:/repo/src/x.py"], now=at(1))
    assert b.status is ClaimStatus.WAITING
    assert b.blocked_by == (a.claim_id,)
    with pytest.raises(StaleFenceError):
        registry.assert_fence(b.claim_id, agent_id="agent:b", fence_token=0, now=at(1))

    receipt = registry.release(
        a.claim_id, agent_id="agent:a", fence_token=a.fence_token, outcome="migrated",
        now=at(2),
    )
    assert receipt["kind"] == "claim-released" and receipt["outcome"] == "migrated"
    promoted = registry.status(b.claim_id)
    assert promoted.status is ClaimStatus.ACQUIRED
    assert promoted.fence_token > a.fence_token
    registry.assert_fence(
        b.claim_id, agent_id="agent:b", fence_token=promoted.fence_token, now=at(3)
    )
    kinds = [event["kind"] for event in registry.events()]
    assert kinds == ["claim-acquired", "claim-waiting", "claim-released", "claim-acquired"]
    assert registry.verify_events() == 4


def test_waiters_keep_arrival_order(registry: WorkClaimRegistry) -> None:
    a = registry.claim(agent_id="agent:a", resources=["file:/repo/a"], now=at(0))
    b = registry.claim(agent_id="agent:b", resources=["file:/repo"], now=at(1))
    c = registry.claim(agent_id="agent:c", resources=["file:/repo/c"], now=at(2))
    assert b.status is ClaimStatus.WAITING
    assert c.status is ClaimStatus.WAITING and c.blocked_by == (b.claim_id,)
    registry.release(a.claim_id, agent_id="agent:a", fence_token=a.fence_token,
                     outcome="done", now=at(3))
    assert registry.status(b.claim_id).status is ClaimStatus.ACQUIRED
    assert registry.status(c.claim_id).status is ClaimStatus.WAITING


def test_own_overlap_is_rejected(registry: WorkClaimRegistry) -> None:
    registry.claim(agent_id="agent:a", resources=["host:db-1"], now=at(0))
    again = registry.claim(agent_id="agent:a", resources=["host:db-1"], now=at(1))
    assert again.status is ClaimStatus.REJECTED and again.blocked_by


def test_expired_holder_is_fenced_out(registry: WorkClaimRegistry) -> None:
    a = registry.claim(agent_id="agent:a", resources=["host:db-1"], ttl_seconds=10,
                       now=at(0))
    b = registry.claim(agent_id="agent:b", resources=["host:db-1"], ttl_seconds=60,
                       now=at(1))
    assert b.status is ClaimStatus.WAITING
    taken = registry.poll(b.claim_id, now=at(11))
    assert taken.status is ClaimStatus.ACQUIRED and taken.fence_token > a.fence_token
    with pytest.raises(StaleFenceError):
        registry.assert_fence(a.claim_id, agent_id="agent:a", fence_token=a.fence_token,
                              now=at(11))
    with pytest.raises(StaleFenceError):
        registry.release(a.claim_id, agent_id="agent:a", fence_token=a.fence_token,
                         outcome="late", now=at(12))


def test_abandoned_waiter_expires_and_unblocks_queue(registry: WorkClaimRegistry) -> None:
    a = registry.claim(agent_id="agent:a", resources=["file:/x"], ttl_seconds=100, now=at(0))
    b = registry.claim(agent_id="agent:b", resources=["file:/x"], ttl_seconds=5, now=at(1))
    c = registry.claim(agent_id="agent:c", resources=["file:/x"], ttl_seconds=100, now=at(2))
    assert c.blocked_by == (a.claim_id, b.claim_id)
    registry.release(a.claim_id, agent_id="agent:a", fence_token=a.fence_token,
                     outcome="done", now=at(10))
    assert registry.status(b.claim_id).status is ClaimStatus.EXPIRED
    assert registry.status(c.claim_id).status is ClaimStatus.ACQUIRED


def test_handoff_moves_claim_under_new_fence(registry: WorkClaimRegistry) -> None:
    a = registry.claim(agent_id="agent:a", resources=["service:api"], now=at(0))
    successor = registry.handoff(
        a.claim_id, agent_id="agent:a", fence_token=a.fence_token,
        successor_id="agent:b", note="shift change", now=at(1),
    )
    assert successor.agent_id == "agent:b" and successor.fence_token > a.fence_token
    assert registry.status(a.claim_id).status is ClaimStatus.HANDED_OFF
    with pytest.raises(StaleFenceError):
        registry.assert_fence(a.claim_id, agent_id="agent:a", fence_token=a.fence_token,
                              now=at(2))
    registry.assert_fence(successor.claim_id, agent_id="agent:b",
                          fence_token=successor.fence_token, now=at(2))


def test_event_chain_detects_tampering(tmp_path: Path) -> None:
    path = tmp_path / "claims.sqlite"
    with WorkClaimRegistry(path) as registry:
        registry.claim(agent_id="agent:a", resources=["file:/x"], now=at(0))
        registry.claim(agent_id="agent:b", resources=["file:/x"], now=at(1))
        registry._connection.execute(
            "UPDATE work_claim_events SET event_json = replace(event_json, 'agent:b', "
            "'agent:z') WHERE event_seq = 2"
        )
        with pytest.raises(WorkClaimError):
            registry.verify_events()


def _contend(path: str, agent: str, start, results) -> None:
    with WorkClaimRegistry(Path(path)) as registry:
        start.wait()
        decision = registry.claim(agent_id=agent, resources=["file:/shared/config"])
        results.put((agent, decision.status.value))


def test_two_processes_one_writer(tmp_path: Path) -> None:
    path = tmp_path / "claims.sqlite"
    WorkClaimRegistry(path).close()
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    workers = [
        context.Process(target=_contend, args=(str(path), f"agent:{name}", start, results))
        for name in ("a", "b")
    ]
    for worker in workers:
        worker.start()
    start.set()
    for worker in workers:
        worker.join(60)
        assert worker.exitcode == 0
    statuses = sorted(results.get(timeout=5)[1] for _ in workers)
    assert statuses == ["acquired", "waiting"]
    with WorkClaimRegistry(path) as registry:
        assert registry.verify_events() == 2
