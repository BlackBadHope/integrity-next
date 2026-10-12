"""Pure snapshot-to-observation adapters for isolated canaries.

Adapters in this module consume already collected, sanitized facts. They have
no transport, discovery, credential or remediation capability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .hashing import digest_object
from .schemas import validate
from .signing import Ed25519Signer


class Platform(StrEnum):
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    BSD = "bsd"
    OTHER = "other"
    NETWORK = "network"


@dataclass(frozen=True)
class SnapshotFact:
    subject_kind: str
    identity: str
    layer: str
    state: str
    content_digest: str | None
    metadata: dict[str, str | int | bool | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.subject_kind not in {
            "node",
            "host",
            "network-interface",
            "route",
            "file",
            "directory",
            "package",
            "service",
            "policy",
            "behavior",
        }:
            raise ValueError("unsupported observation subject kind")
        if not self.identity:
            raise ValueError("snapshot identity must not be empty")
        if self.layer not in {"L0", "L1", "L2", "L3"}:
            raise ValueError("snapshot layer must be L0, L1, L2 or L3")
        if self.state not in {"present", "absent", "unknown", "sensor-gap"}:
            raise ValueError("snapshot state is not recognized")
        if self.state in {"absent", "unknown", "sensor-gap"} and self.content_digest:
            raise ValueError("non-present snapshot cannot carry a content digest")
        forbidden = ("secret", "password", "passwd", "token", "cookie", "private_key")
        for key in self.metadata:
            lowered = key.lower()
            if any(marker in lowered for marker in forbidden):
                raise ValueError("snapshot metadata contains a secret-like field name")


class SnapshotAdapter:
    """Sign sanitized platform facts into the common observation protocol."""

    def __init__(
        self,
        *,
        tenant_id: str,
        sensor_id: str,
        node_id: str,
        platform: Platform,
        signer: Ed25519Signer,
    ) -> None:
        self.tenant_id = tenant_id
        self.sensor_id = sensor_id
        self.node_id = node_id
        self.platform = platform
        self.signer = signer
        self._sequence = 0
        self._previous_digest: str | None = None

    def emit(self, fact: SnapshotFact, *, observed_at: str) -> dict[str, Any]:
        metadata = dict(fact.metadata)
        metadata["platform"] = self.platform.value
        unsigned: dict[str, Any] = {
            "protocol": "integrity-guardian/observation/v1",
            "observation_id": "observation:pending",
            "tenant_id": self.tenant_id,
            "sensor_id": self.sensor_id,
            "node_id": self.node_id,
            "sequence": self._sequence,
            "observed_at": observed_at,
            "layer": fact.layer,
            "subject": {
                "kind": fact.subject_kind,
                "identity": fact.identity,
            },
            "evidence": {
                "state": fact.state,
                "content_digest": fact.content_digest,
                "metadata": metadata,
            },
            "previous_observation_digest": self._previous_digest,
        }
        identity = digest_object(
            unsigned,
            domain="snapshot-observation-identity-v1",
        ).split(":", 1)[1]
        unsigned["observation_id"] = f"observation:{identity}"
        signed = self.signer.sign(unsigned)
        validate("observation", signed)
        self._previous_digest = digest_object(
            signed,
            domain="observation-chain-v1",
        )
        self._sequence += 1
        return signed
