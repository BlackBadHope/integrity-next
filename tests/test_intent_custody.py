"""One-use ChangeIntent custody on top of the pure reconciler."""
from __future__ import annotations

import multiprocessing
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from integrity_guardian.canary import _delta, _intent
from integrity_guardian.intent_custody import (
    IntentCustody,
    IntentCustodyError,
    IntentReplayError,
    verify_consumption_receipt,
)
from integrity_guardian.reconciler import reconcile
from integrity_guardian.signing import Ed25519Signer, TrustedKey

TENANT = "tenant:public-a0d3e830ed127ef0"
INSIDE_WINDOW = datetime(2026, 7, 26, 18, 27, tzinfo=UTC)
AUTHORITY_SEED = bytes(range(32))


def authority() -> tuple[Ed25519Signer, TrustedKey]:
    # A fixed key lets spawned processes rebuild the same authority.
    signer = Ed25519Signer("key:authority", Ed25519PrivateKey.from_private_bytes(AUTHORITY_SEED))
    return signer, TrustedKey("key:authority", signer.public_key)


def custody(path: Path, **kwargs: object) -> IntentCustody:
    _, key = authority()
    return IntentCustody(path, tenant_id=TENANT, authority_key=key, **kwargs)


def test_reconcile_alone_is_not_one_use() -> None:
    signer, key = authority()
    intent = _intent(signer)
    runs = [reconcile(intent=intent, observed=[_delta()], authority_key=key) for _ in range(2)]
    assert runs[0] == runs[1]


def test_reserve_consume_then_replay_is_rejected(tmp_path: Path) -> None:
    signer, _ = authority()
    intent = _intent(signer)
    receipt_signer = Ed25519Signer.generate("key:custody")
    with custody(tmp_path / "custody.sqlite", signer=receipt_signer) as store:
        reservation = store.reserve(intent, holder="agent:a", now=INSIDE_WINDOW)
        with pytest.raises(IntentReplayError):
            store.reserve(intent, holder="agent:b", now=INSIDE_WINDOW)
        receipt = store.consume(reservation, intent, [_delta()], now=INSIDE_WINDOW)
        assert receipt["classifications"] == ["authorized_success"]
        assert receipt["observation_event_ids"] == ["event:canary-delta"]
        verify_consumption_receipt(
            receipt, custody_key=TrustedKey("key:custody", receipt_signer.public_key)
        )
        with pytest.raises(IntentReplayError):
            store.consume(reservation, intent, [_delta()], now=INSIDE_WINDOW)
    with custody(tmp_path / "custody.sqlite") as reopened:
        assert reopened.status(intent["intent_id"])["status"] == "consumed"
        assert reopened.receipt(intent["intent_id"]) == receipt
        with pytest.raises(IntentReplayError):
            reopened.reserve(intent, holder="agent:c", now=INSIDE_WINDOW)


def test_scope_breach_still_spends_the_intent(tmp_path: Path) -> None:
    signer, _ = authority()
    intent = _intent(signer)
    with custody(tmp_path / "custody.sqlite") as store:
        reservation = store.reserve(intent, holder="agent:a", now=INSIDE_WINDOW)
        receipt = store.consume(
            reservation, intent, [_delta(selector="file:/canary/out-of-scope")],
            now=INSIDE_WINDOW,
        )
        assert "scope_breach" in receipt["classifications"]
        assert store.status(intent["intent_id"])["status"] == "consumed"


def test_abandon_closes_without_reuse(tmp_path: Path) -> None:
    signer, _ = authority()
    intent = _intent(signer)
    with custody(tmp_path / "custody.sqlite") as store:
        reservation = store.reserve(intent, holder="agent:a", now=INSIDE_WINDOW)
        receipt = store.abandon(reservation, reason="executor crashed", now=INSIDE_WINDOW)
        assert receipt["outcome"] == "abandoned"
        verify_consumption_receipt(receipt)
        with pytest.raises(IntentReplayError):
            store.reserve(intent, holder="agent:a", now=INSIDE_WINDOW)


@pytest.mark.parametrize(
    "now",
    [datetime(2026, 7, 26, 18, 0, tzinfo=UTC), datetime(2030, 1, 1, tzinfo=UTC)],
)
def test_reservation_requires_validity_window(tmp_path: Path, now: datetime) -> None:
    signer, _ = authority()
    with custody(tmp_path / "custody.sqlite") as store, pytest.raises(IntentCustodyError):
        store.reserve(_intent(signer), holder="agent:a", now=now)


def test_untrusted_or_foreign_intent_is_refused(tmp_path: Path) -> None:
    forger = Ed25519Signer.generate("key:authority")
    with custody(tmp_path / "custody.sqlite") as store, pytest.raises(ValueError):
        store.reserve(_intent(forger), holder="agent:a", now=INSIDE_WINDOW)
    signer, key = authority()
    with IntentCustody(tmp_path / "other.sqlite", tenant_id="tenant:other",
                       authority_key=key) as store, pytest.raises(IntentCustodyError):
        store.reserve(_intent(signer), holder="agent:a", now=INSIDE_WINDOW)


def test_tampered_receipt_is_detected(tmp_path: Path) -> None:
    signer, _ = authority()
    intent = _intent(signer)
    with custody(tmp_path / "custody.sqlite") as store:
        reservation = store.reserve(intent, holder="agent:a", now=INSIDE_WINDOW)
        receipt = store.consume(reservation, intent, [_delta()], now=INSIDE_WINDOW)
    receipt["classifications"] = ["scope_breach"]
    with pytest.raises(IntentCustodyError):
        verify_consumption_receipt(receipt)


def _reserve_from_process(path: str, holder: str, start, results) -> None:
    signer, _ = authority()
    with custody(Path(path)) as store:
        start.wait()
        try:
            store.reserve(_intent(signer), holder=holder, now=INSIDE_WINDOW)
            results.put("reserved")
        except IntentReplayError:
            results.put("replay")


def test_two_processes_race_for_one_intent(tmp_path: Path) -> None:
    path = tmp_path / "custody.sqlite"
    custody(path).close()
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    workers = [
        context.Process(target=_reserve_from_process, args=(str(path), holder, start, results))
        for holder in ("agent:a", "agent:b")
    ]
    for worker in workers:
        worker.start()
    start.set()
    for worker in workers:
        worker.join(60)
        assert worker.exitcode == 0
    assert sorted(results.get(timeout=5) for _ in workers) == ["replay", "reserved"]
