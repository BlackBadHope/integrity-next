"""Core protocol regressions: canonical JSON, digests, signatures and the Ledger."""
from __future__ import annotations

import hashlib
import multiprocessing
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from integrity_guardian.canary import _event, run_isolated_canary
from integrity_guardian.canonical import (
    CanonicalizationError,
    canonical_bytes,
    parse_json_strict,
)
from integrity_guardian.hashing import FRAME_SEPARATOR, digest_object, validate_domain
from integrity_guardian.ledger import (
    LedgerAppendError,
    LedgerStore,
    build_ledger_event,
    event_digest,
)
from integrity_guardian.signing import (
    Ed25519Signer,
    TrustedKey,
    trusted_key_from_value,
    verify_signature,
    verify_trusted_signature,
)

TENANT = "tenant:public-a0d3e830ed127ef0"


# -- canonical JSON ---------------------------------------------------------


def test_canonical_bytes_sort_keys_and_keep_unicode() -> None:
    assert canonical_bytes({"b": 2, "a": [1, "é"]}) == '{"a":[1,"é"],"b":2}'.encode()


@pytest.mark.parametrize(
    "document",
    ['{"a":1,"a":2}', '{"a":1.5}', '{"a":NaN}', '{"a":Infinity}', "{"],
)
def test_strict_parser_rejects_ambiguous_json(document: str) -> None:
    with pytest.raises(CanonicalizationError):
        parse_json_strict(document)


@pytest.mark.parametrize("value", [{"a": 1.0}, {1: "x"}, {"a": {1, 2}}, {"a": b"x"}])
def test_canonical_bytes_reject_values_outside_profile(value: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_bytes(value)


# -- domain-separated digests -------------------------------------------------


def test_digest_vector_is_frozen() -> None:
    # The same vector is printed by the README quick start.
    assert digest_object({"b": 2, "a": 1}, domain="demo") == (
        "sha256:642c2d4d9286b31e56f6090f47b0435de8b034e713fe160d5ba51457138954b8"
    )


def test_digest_frame_is_the_literal_v1_separator() -> None:
    assert FRAME_SEPARATOR == "\\x00" and len(FRAME_SEPARATOR) == 4
    framed = b"integrity-guardian\\x00guardian-json-v1\\x00demo\\x00" + b'{"a":1}'
    assert digest_object({"a": 1}, domain="demo") == (
        "sha256:" + hashlib.sha256(framed).hexdigest()
    )


@pytest.mark.parametrize("domain", ["", "a b", "a\\b", "a\x00b", "a\nb", "a\tb"])
def test_digest_domain_cannot_blur_the_frame(domain: str) -> None:
    with pytest.raises(ValueError):
        validate_domain(domain)
    with pytest.raises(ValueError):
        digest_object({}, domain=domain)


def test_digest_domains_separate_identical_objects() -> None:
    assert digest_object({"a": 1}, domain="one") != digest_object({"a": 1}, domain="two")


# -- signatures -------------------------------------------------------------


def test_signature_round_trip_and_tamper() -> None:
    signer = Ed25519Signer.generate("key:a")
    signed = signer.sign({"claim": "x"})
    assert verify_signature(signed, signer.public_key)
    tampered = {**signed, "claim": "y"}
    assert not verify_signature(tampered, signer.public_key)
    other = Ed25519Signer.generate("key:b")
    assert not verify_signature(signed, other.public_key)


def test_trusted_signature_binds_key_identity() -> None:
    signer = Ed25519Signer.generate("key:a")
    signed = signer.sign({"claim": "x"})
    assert verify_trusted_signature(signed, TrustedKey("key:a", signer.public_key))
    # The same key under another identity is not the trusted key.
    assert not verify_trusted_signature(signed, TrustedKey("key:other", signer.public_key))


@pytest.mark.parametrize("value", ["", "AAAA=", "not base64!", "AAAA"])
def test_trusted_key_rejects_malformed_material(value: str) -> None:
    with pytest.raises(ValueError):
        trusted_key_from_value("key:x", value)


# -- Ledger -----------------------------------------------------------------


def _ledger(path: Path, **kwargs: object) -> LedgerStore:
    return LedgerStore(path, tenant_id=TENANT, ledger_id="ledger:test", **kwargs)


def test_ledger_chain_survives_reopen_and_rejects_replay(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate("key:sensor")
    keys = {"sensor:canary": TrustedKey("key:sensor", signer.public_key)}
    first = _event(number=0, previous=None, signer=signer)
    second = _event(number=1, previous=event_digest(first), signer=signer)
    with _ledger(tmp_path / "ledger.sqlite") as store:
        store.append_many([first, second])
        with pytest.raises(LedgerAppendError):
            store.append(second)
    with _ledger(tmp_path / "ledger.sqlite") as store:
        assert store.verify(source_public_keys=keys)["tree_size"] == 2
        with pytest.raises(LedgerAppendError):
            store.append(first)


def test_ledger_rejects_gap_and_foreign_chain(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate("key:sensor")
    first = _event(number=0, previous=None, signer=signer)
    with _ledger(tmp_path / "ledger.sqlite") as store:
        store.append(first)
        with pytest.raises(LedgerAppendError):
            store.append(_event(number=2, previous=event_digest(first), signer=signer))
        with pytest.raises(LedgerAppendError):
            store.append(_event(number=1, previous=None, signer=signer))


def test_ledger_write_lock_covers_the_tip_read(tmp_path: Path) -> None:
    """A writer that races into the tip-read gap is locked out, not half-applied."""

    signer = Ed25519Signer.generate("key:sensor")
    first = _event(number=0, previous=None, signer=signer)
    winner = _event(number=1, previous=event_digest(first), signer=signer)
    loser = _event(number=1, previous=event_digest(first), signer=signer,
                   payload="sha256:" + "ab" * 32)
    path = tmp_path / "ledger.sqlite"
    with _ledger(path) as store, _ledger(path, busy_timeout_ms=0) as rival:
        store.append(first)
        real_tip = store._source_tip
        outcomes: list[str] = []

        def racing_tip(*args: str):
            tip = real_tip(*args)
            try:
                rival.append(loser)
                outcomes.append("rival appended")
            except Exception as exc:  # noqa: BLE001 - the outcome is the assertion
                outcomes.append(type(exc).__name__)
            return tip

        store._source_tip = racing_tip
        store.append(winner)
        assert outcomes == ["OperationalError"]
        store._source_tip = real_tip
        with pytest.raises(LedgerAppendError):
            rival.append(loser)


def _append_from_process(path: str, key_id: str, results) -> None:
    signer = Ed25519Signer.generate(key_id)
    event = build_ledger_event(
        tenant_id=TENANT,
        source_id=f"sensor:{key_id.split(':')[1]}",
        source_sequence=0,
        event_type="observation",
        payload_digest=digest_object({"from": key_id}, domain="test-payload"),
        previous_event_digest=None,
        signer=signer,
    )
    with LedgerStore(Path(path), tenant_id=TENANT, ledger_id="ledger:test") as store:
        store.append(event)
    results.put((key_id, signer.public_key.public_bytes_raw().hex()))


def test_two_processes_share_one_ledger(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite"
    _ledger(path).close()
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    workers = [
        context.Process(target=_append_from_process, args=(str(path), f"key:{name}", results))
        for name in ("a", "b")
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(60)
        assert worker.exitcode == 0
    keys = {}
    for _ in workers:
        key_id, raw = results.get(timeout=5)
        keys[f"sensor:{key_id.split(':')[1]}"] = TrustedKey(
            key_id, Ed25519PublicKey.from_public_bytes(bytes.fromhex(raw))
        )
    with _ledger(path) as store:
        report = store.verify(source_public_keys=keys)
    assert report["tree_size"] == 2 and report["source_count"] == 2


# -- isolated canary ----------------------------------------------------------


def test_isolated_canary_passes_every_gate() -> None:
    report = run_isolated_canary()
    failed = [gate["gate_id"] for gate in report["gates"] if not gate["pass"]]
    assert failed == []
    assert report["verdict"] == "PASS_ISOLATED"
    assert report["production_ready"] is False
