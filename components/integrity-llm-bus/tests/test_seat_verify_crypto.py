"""GO signatures for three algorithms, plus replay and window rejection."""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from integrity_llm_bus.seat_verify import GoError, GoLedger, canonical_go


def _payload(**overrides):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    value = {
        "approver_seat": "seat_owner",
        "key_id": "key-1",
        "core_instance_id": "core-local",
        "msg_id": "go-1",
        "th": "turn-1",
        "decision_ref": "",
        "request_digest": "ab" * 32,
        "request_seq": 2,
        "action": "mesh.done",
        "scope": "team/work",
        "created_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_utc": (now + timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    value["decision_ref"] = value["request_digest"][:12] + "-decision"
    value.update(overrides)
    if "request_digest" in overrides and "decision_ref" not in overrides:
        value["decision_ref"] = value["request_digest"][:12] + "-decision"
    return value


def _pem(key) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


def _sign(key, payload, alg):
    data = canonical_go(payload)
    if alg == "Ed25519":
        return key.sign(data)
    if alg == "ECDSA-P256":
        return key.sign(data, ec.ECDSA(hashes.SHA256()))
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


@pytest.mark.parametrize(
    ("alg", "key"),
    [
        ("Ed25519", ed25519.Ed25519PrivateKey.generate()),
        ("ECDSA-P256", ec.generate_private_key(ec.SECP256R1())),
        ("RSA-2048", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
    ],
)
def test_three_algorithms_and_replay(tmp_path, alg, key):
    payload = _payload(msg_id="go-" + alg)
    signature = _sign(key, payload, alg)
    ledger = GoLedger(tmp_path / f"{alg}.sqlite3", core_instance_id="core-local")

    def lookup(seat_id, key_id):
        assert seat_id == "seat_owner" and key_id == "key-1"
        return {"alg": alg, "public_key": _pem(key), "roles": ("go_approver",), "retired_at": None}

    now = datetime.now(timezone.utc)
    assert ledger.consume(payload, signature, now=now, decision_seq=3, lookup=lookup)["consumed"] is True
    with pytest.raises(GoError, match="replay"):
        ledger.consume(payload, signature, now=now, decision_seq=4, lookup=lookup)


def test_window_seq_and_non_approver_are_rejected(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    ledger = GoLedger(tmp_path / "go.sqlite3", core_instance_id="core-local")
    now = datetime.now(timezone.utc)
    stale = _payload(created_utc="2020-01-01T00:00:00Z", expires_utc="2020-01-01T00:01:00Z", msg_id="old")
    with pytest.raises(GoError, match="window"):
        ledger.consume(stale, _sign(key, stale, "Ed25519"), now=now, decision_seq=3, lookup=lambda *_: {
            "alg": "Ed25519", "public_key": _pem(key), "roles": ("go_approver",), "retired_at": None
        })
    current = _payload(msg_id="seq")
    with pytest.raises(GoError, match="seq"):
        ledger.consume(current, _sign(key, current, "Ed25519"), now=now, decision_seq=2, lookup=lambda *_: {
            "alg": "Ed25519", "public_key": _pem(key), "roles": ("go_approver",), "retired_at": None
        })
    with pytest.raises(GoError, match="approver"):
        ledger.consume(current, _sign(key, current, "Ed25519"), now=now, decision_seq=5, lookup=lambda *_: {
            "alg": "Ed25519", "public_key": _pem(key), "roles": ("read",), "retired_at": None
        })
