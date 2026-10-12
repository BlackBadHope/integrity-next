"""In-memory Ed25519 signing for Guardian protocol objects."""

from __future__ import annotations

import base64
import hashlib
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .canonical import canonical_bytes


@dataclass(frozen=True)
class TrustedKey:
    key_id: str
    public_key: Ed25519PublicKey


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unbase64url(value: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("base64url value must be canonical and unpadded")
    decoded = base64.b64decode(
        value + "=" * (-len(value) % 4),
        altchars=b"-_",
        validate=True,
    )
    if _base64url(decoded) != value:
        raise ValueError("base64url value is not canonical")
    return decoded


def signature_payload(document: dict[str, Any]) -> bytes:
    unsigned = deepcopy(document)
    unsigned.pop("signature", None)
    return b"integrity-guardian\x00signed-object-v1\x00" + canonical_bytes(unsigned)


class Ed25519Signer:
    """A signer whose private key remains in caller-owned process memory."""

    def __init__(self, key_id: str, private_key: Ed25519PrivateKey) -> None:
        self.key_id = key_id
        self._private_key = private_key

    @classmethod
    def generate(cls, key_id: str) -> Ed25519Signer:
        return cls(key_id, Ed25519PrivateKey.generate())

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def sign(self, document: dict[str, Any]) -> dict[str, Any]:
        signed = deepcopy(document)
        value = self.sign_bytes(signature_payload(signed))
        signed["signature"] = {
            "algorithm": "ed25519",
            "key_id": self.key_id,
            "value": value,
        }
        return signed

    def sign_bytes(self, payload: bytes) -> str:
        return _base64url(self._private_key.sign(payload))


def verify_bytes(payload: bytes, value: str, public_key: Ed25519PublicKey) -> bool:
    try:
        public_key.verify(_unbase64url(value), payload)
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def verify_signature(document: dict[str, Any], public_key: Ed25519PublicKey) -> bool:
    signature = document.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519":
        return False
    try:
        return verify_bytes(signature_payload(document), signature["value"], public_key)
    except (KeyError, TypeError):
        return False


def verify_trusted_signature(document: dict[str, Any], trusted_key: TrustedKey) -> bool:
    """Verify a signature that must also name the trusted key's identity.

    ``key_id`` is not covered by the signed bytes, so a verifier that selects
    keys by identity must compare it explicitly; this helper does both.
    """

    signature = document.get("signature")
    if not isinstance(signature, dict) or signature.get("key_id") != trusted_key.key_id:
        return False
    return verify_signature(document, trusted_key.public_key)


def public_key_value(public_key: Ed25519PublicKey) -> str:
    """Return the canonical base64url form of an Ed25519 public key."""

    return _base64url(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))


def public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    """Return the out-of-band SHA-256 identity of a raw Ed25519 public key."""

    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def trusted_key_from_value(key_id: str, value: str) -> TrustedKey:
    """Build a trusted public key while rejecting malformed key material."""

    try:
        raw = _unbase64url(value)
        if len(raw) != 32:
            raise ValueError("Ed25519 public keys must contain exactly 32 bytes")
        public_key = Ed25519PublicKey.from_public_bytes(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid Ed25519 public key") from exc
    return TrustedKey(key_id=key_id, public_key=public_key)
