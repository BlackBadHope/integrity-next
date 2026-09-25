"""Digest-pinned execution boundary for customer-owned read-only collectors."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass, replace
from dataclasses import field as dataclass_field
from datetime import datetime
from pathlib import Path
from typing import Any

from .adapters import SnapshotFact
from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .schemas import validate

_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_CREDENTIAL_REF = re.compile(r"^credential:[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:\d{2})$"
)
_SECRET_MARKERS = ("secret", "password", "passwd", "token", "cookie", "private_key")
_PROFILE_KEYS_V1 = {
    "protocol",
    "tenant_id",
    "collector_id",
    "node_id",
    "executable",
    "executable_digest",
    "argv",
    "timeout_seconds",
    "max_output_bytes",
    "credential_reference",
    "controls",
}
_PROFILE_KEYS_V2 = _PROFILE_KEYS_V1 | {"application_files"}
_APPLICATION_FILE_KEYS = {"relative_path", "content_digest"}
_CONTROLS = {
    "read_only_intent": True,
    "shell": False,
    "inherited_environment": False,
    "production_authority": False,
}
_OUTPUT_KEYS = {"protocol", "observed_at", "facts"}
_FACT_KEYS = {
    "subject_kind",
    "identity",
    "layer",
    "state",
    "content_digest",
    "metadata",
}


class CollectorBoundaryError(ValueError):
    """Raised when a collector crosses its exact read-only execution contract."""


@dataclass(frozen=True)
class CollectorApplicationFile:
    relative_path: str
    content_digest: str


@dataclass(frozen=True)
class CollectorProfile:
    protocol: str
    tenant_id: str
    collector_id: str
    node_id: str
    executable: Path
    executable_digest: str
    argv: tuple[str, ...]
    timeout_seconds: int
    max_output_bytes: int
    credential_reference: str | None
    application_files: tuple[CollectorApplicationFile, ...]
    _profile_digest: str | None = dataclass_field(
        default=None,
        repr=False,
        compare=False,
    )
    _profile_digest_custody: str = dataclass_field(
        default="in-memory-profile",
        repr=False,
        compare=False,
    )

    def to_document(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "protocol": self.protocol,
            "tenant_id": self.tenant_id,
            "collector_id": self.collector_id,
            "node_id": self.node_id,
            "executable": str(self.executable),
            "executable_digest": self.executable_digest,
            "argv": list(self.argv),
            "timeout_seconds": self.timeout_seconds,
            "max_output_bytes": self.max_output_bytes,
            "credential_reference": self.credential_reference,
            "controls": dict(_CONTROLS),
        }
        if self.protocol == "integrity-guardian/collector-profile/v2":
            document["application_files"] = [
                {
                    "relative_path": item.relative_path,
                    "content_digest": item.content_digest,
                }
                for item in self.application_files
            ]
        return document

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> CollectorProfile:
        if not isinstance(document, dict):
            raise CollectorBoundaryError("collector profile field set rejected")
        protocol = document.get("protocol")
        if protocol == "integrity-guardian/collector-profile/v1":
            expected_keys = _PROFILE_KEYS_V1
        elif protocol == "integrity-guardian/collector-profile/v2":
            expected_keys = _PROFILE_KEYS_V2
        else:
            raise CollectorBoundaryError("collector profile protocol rejected")
        if set(document) != expected_keys:
            raise CollectorBoundaryError("collector profile field set rejected")
        if document.get("controls") != _CONTROLS:
            raise CollectorBoundaryError("collector safety controls rejected")
        for field in ("tenant_id", "collector_id", "node_id"):
            if not isinstance(document[field], str) or _ID.fullmatch(document[field]) is None:
                raise CollectorBoundaryError(f"{field} rejected")
        executable = Path(document["executable"])
        if not executable.is_absolute():
            raise CollectorBoundaryError("collector executable must be absolute")
        digest = document["executable_digest"]
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise CollectorBoundaryError("collector executable digest rejected")
        argv = document["argv"]
        if (
            not isinstance(argv, list)
            or len(argv) > 32
            or any(
                not isinstance(value, str)
                or len(value) > 1024
                or "\x00" in value
                for value in argv
            )
        ):
            raise CollectorBoundaryError("collector argv rejected")
        timeout = document["timeout_seconds"]
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 300:
            raise CollectorBoundaryError("collector timeout rejected")
        maximum = document["max_output_bytes"]
        if (
            not isinstance(maximum, int)
            or isinstance(maximum, bool)
            or not 1024 <= maximum <= 4 * 1024 * 1024
        ):
            raise CollectorBoundaryError("collector output bound rejected")
        credential_reference = document["credential_reference"]
        if credential_reference is not None and (
            not isinstance(credential_reference, str)
            or _CREDENTIAL_REF.fullmatch(credential_reference) is None
        ):
            raise CollectorBoundaryError("credential reference rejected")
        application_files: list[CollectorApplicationFile] = []
        if protocol == "integrity-guardian/collector-profile/v2":
            raw_files = document["application_files"]
            if not isinstance(raw_files, list) or len(raw_files) > 256:
                raise CollectorBoundaryError(
                    "collector application file set rejected"
                )
            seen: set[str] = set()
            for item in raw_files:
                if not isinstance(item, dict) or set(item) != _APPLICATION_FILE_KEYS:
                    raise CollectorBoundaryError(
                        "collector application file rejected"
                    )
                relative_path = item["relative_path"]
                content_digest = item["content_digest"]
                if (
                    not isinstance(relative_path, str)
                    or not relative_path
                    or len(relative_path) > 255
                    or Path(relative_path).name != relative_path
                    or "/" in relative_path
                    or "\\" in relative_path
                    or relative_path.casefold() in seen
                    or relative_path.casefold() == executable.name.casefold()
                    or not isinstance(content_digest, str)
                    or _DIGEST.fullmatch(content_digest) is None
                ):
                    raise CollectorBoundaryError(
                        "collector application file rejected"
                    )
                seen.add(relative_path.casefold())
                application_files.append(
                    CollectorApplicationFile(
                        relative_path=relative_path,
                        content_digest=content_digest,
                    )
                )
        return cls(
            protocol=protocol,
            tenant_id=document["tenant_id"],
            collector_id=document["collector_id"],
            node_id=document["node_id"],
            executable=executable,
            executable_digest=digest,
            argv=tuple(argv),
            timeout_seconds=timeout,
            max_output_bytes=maximum,
            credential_reference=credential_reference,
            application_files=tuple(application_files),
        )


_PROFILE_CUSTODY_TOKEN = object()


@dataclass(frozen=True)
class _VerifiedCollectorProfile:
    """One immutable profile proven against an external content digest."""

    profile: CollectorProfile
    profile_digest: str
    _custody_token: object = dataclass_field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.profile, CollectorProfile)
            or _DIGEST.fullmatch(self.profile_digest) is None
            or self._custody_token is not _PROFILE_CUSTODY_TOKEN
        ):
            raise CollectorBoundaryError(
                "verified collector profile custody rejected"
            )


def _bind_verified_profile(
    profile: CollectorProfile,
    profile_digest: str,
) -> _VerifiedCollectorProfile:
    return _VerifiedCollectorProfile(
        profile=profile,
        profile_digest=profile_digest,
        _custody_token=_PROFILE_CUSTODY_TOKEN,
    )


def _require_verified_windows_profile(
    candidate: object,
) -> _VerifiedCollectorProfile:
    if (
        not isinstance(candidate, _VerifiedCollectorProfile)
        or candidate._custody_token is not _PROFILE_CUSTODY_TOKEN
    ):
        raise CollectorBoundaryError(
            "Windows collector requires a digest-verified profile"
        )
    if candidate.profile.protocol != "integrity-guardian/collector-profile/v2":
        raise CollectorBoundaryError(
            "Windows collector requires application-bound profile v2"
        )
    return candidate


def _reject_secret_like_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in _SECRET_MARKERS):
                raise CollectorBoundaryError("collector output contains a secret-like key")
            _reject_secret_like_keys(child)
    elif isinstance(value, list):
        for child in value:
            _reject_secret_like_keys(child)


def _validate_observed_at(value: object) -> str:
    if not isinstance(value, str) or _RFC3339.fullmatch(value) is None:
        raise CollectorBoundaryError("collector observed_at rejected")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise CollectorBoundaryError("collector observed_at rejected") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CollectorBoundaryError("collector observed_at rejected")
    return value


def _parse_output(payload: bytes) -> tuple[dict[str, Any], list[SnapshotFact]]:
    value = parse_json_strict(payload)
    if not isinstance(value, dict) or set(value) != _OUTPUT_KEYS:
        raise CollectorBoundaryError("collector output field set rejected")
    if value["protocol"] != "integrity-guardian/collector-output/v1":
        raise CollectorBoundaryError("collector output protocol rejected")
    _validate_observed_at(value["observed_at"])
    records = value["facts"]
    if not isinstance(records, list) or len(records) > 1000:
        raise CollectorBoundaryError("collector fact count rejected")
    _reject_secret_like_keys(value)
    facts: list[SnapshotFact] = []
    for record in records:
        if not isinstance(record, dict) or set(record) != _FACT_KEYS:
            raise CollectorBoundaryError("collector fact field set rejected")
        metadata = record["metadata"]
        if not isinstance(metadata, dict):
            raise CollectorBoundaryError("collector fact metadata rejected")
        facts.append(
            SnapshotFact(
                subject_kind=record["subject_kind"],
                identity=record["identity"],
                layer=record["layer"],
                state=record["state"],
                content_digest=record["content_digest"],
                metadata=metadata,
            )
        )
    return value, facts


def _build_collector_result(
    profile: CollectorProfile,
    document: dict[str, Any],
    facts: list[SnapshotFact],
    stdout_payload: bytes,
    *,
    profile_digest: str | None = None,
) -> dict[str, Any]:
    effective_profile_digest = profile_digest or profile._profile_digest
    profile_digest_custody = (
        "verified-file"
        if profile_digest is not None
        or (
            profile._profile_digest is not None
            and profile._profile_digest_custody == "verified-file"
        )
        else "in-memory-profile"
    )
    if effective_profile_digest is None:
        effective_profile_digest = "sha256:" + hashlib.sha256(
            canonical_bytes(profile.to_document()) + b"\n"
        ).hexdigest()
    core = {
        "ok": True,
        "profile": {
            "tenant_id": profile.tenant_id,
            "collector_id": profile.collector_id,
            "node_id": profile.node_id,
            "executable_digest": profile.executable_digest,
            "credential_reference": profile.credential_reference,
            "profile_digest": effective_profile_digest,
            "profile_digest_custody": profile_digest_custody,
        },
        "observed_at": document["observed_at"],
        "facts": [
            {
                "subject_kind": fact.subject_kind,
                "identity": fact.identity,
                "layer": fact.layer,
                "state": fact.state,
                "content_digest": fact.content_digest,
                "metadata": fact.metadata,
            }
            for fact in facts
        ],
        "receipt": {
            "stdout_digest": f"sha256:{hashlib.sha256(stdout_payload).hexdigest()}",
            "fact_count": len(facts),
            "read_only_claim": True,
            "shell_used": False,
            "inherited_environment": False,
            "credential_value_exposed": False,
            "production_authority": False,
            "production_mutated": "UNKNOWN",
            "mutation_evidence": "not_observed_by_guardian",
            "profile_digest": effective_profile_digest,
            "profile_digest_custody": profile_digest_custody,
        },
    }
    result = {
        "protocol": "integrity-guardian/collector-result/v1",
        "result_id": "collector-result:"
        + digest_object(core, domain="collector-result-v1").split(":", 1)[1],
        **core,
    }
    verify_collector_result(result)
    return result


def verify_collector_result(result: dict[str, Any]) -> dict[str, Any]:
    validate("collector-result", result)
    core = {
        key: value
        for key, value in result.items()
        if key not in {"protocol", "result_id"}
    }
    expected = "collector-result:" + digest_object(
        core,
        domain="collector-result-v1",
    ).split(":", 1)[1]
    if result["result_id"] != expected:
        raise CollectorBoundaryError("collector result identity mismatch")
    if (
        result["receipt"]["fact_count"] != len(result["facts"])
        or result["profile"]["profile_digest"]
        != result["receipt"]["profile_digest"]
        or result["profile"]["profile_digest_custody"]
        != result["receipt"]["profile_digest_custody"]
    ):
        raise CollectorBoundaryError("collector result semantic binding mismatch")
    _validate_observed_at(result["observed_at"])
    _reject_secret_like_keys(result["facts"])
    return {
        "status": "PASS",
        "result_id": result["result_id"],
        "fact_count": len(result["facts"]),
        "profile_digest": result["profile"]["profile_digest"],
        "profile_digest_custody": result["profile"]["profile_digest_custody"],
        "production_authority": False,
    }


def run_collector(
    profile: CollectorProfile | _VerifiedCollectorProfile,
) -> dict[str, Any]:
    """Dispatch one exact collector to the admitted native execution backend."""

    if os.name == "posix":
        from .collector_posix import run_collector_posix

        if isinstance(profile, _VerifiedCollectorProfile):
            profile = replace(
                profile.profile,
                _profile_digest=profile.profile_digest,
                _profile_digest_custody="verified-file",
            )
        return run_collector_posix(profile)
    if os.name == "nt":
        from .collector_windows import run_collector_windows

        return run_collector_windows(profile)
    raise CollectorBoundaryError("native collector backend is not admitted")


def load_profile(
    path: Path,
    expected_digest: str | None = None,
) -> CollectorProfile | _VerifiedCollectorProfile:
    if expected_digest is not None and _DIGEST.fullmatch(expected_digest) is None:
        raise CollectorBoundaryError("collector profile digest rejected")
    if os.name == "nt":
        from .collector_windows_custody import load_profile_windows_payload

        payload = load_profile_windows_payload(path, expected_digest)
        value = parse_json_strict(payload)
        if not isinstance(value, dict):
            raise CollectorBoundaryError("collector profile must be an object")
        return _bind_verified_profile(
            CollectorProfile.from_document(value),
            expected_digest,
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CollectorBoundaryError("collector profile is absent or unsafe") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size > 1024 * 1024
        ):
            raise CollectorBoundaryError("collector profile owner, mode or size rejected")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 64 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise CollectorBoundaryError("collector profile changed while read")
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    if expected_digest is not None and (
        f"sha256:{hashlib.sha256(payload).hexdigest()}" != expected_digest
    ):
        raise CollectorBoundaryError("collector profile digest mismatch")
    value = parse_json_strict(payload)
    if not isinstance(value, dict):
        raise CollectorBoundaryError("collector profile must be an object")
    profile = CollectorProfile.from_document(value)
    if expected_digest is not None:
        return replace(
            profile,
            _profile_digest=expected_digest,
            _profile_digest_custody="verified-file",
        )
    return profile


def canonical_result(result: dict[str, Any]) -> bytes:
    return canonical_bytes(result) + b"\n"


def write_collector_result(output_directory: Path, result: dict[str, Any]) -> Path:
    """Store one content-addressed receipt without overwriting different bytes."""

    verify_collector_result(result)
    payload = canonical_result(result)
    identity = hashlib.sha256(payload).hexdigest()
    name = f"collector-result-{identity}.json"
    if os.name == "nt":
        from .collector_windows_custody import write_collector_result_windows

        return write_collector_result_windows(output_directory, name, payload)
    output_directory = output_directory.absolute()
    output_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if output_directory.is_symlink() or not output_directory.is_dir():
        raise CollectorBoundaryError("collector output directory is unsafe")
    details = output_directory.stat()
    if details.st_uid != os.geteuid():
        raise CollectorBoundaryError("collector output directory owner mismatch")
    output_directory.chmod(0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(output_directory / name, flags, 0o600)
    except FileExistsError:
        existing = output_directory / name
        if existing.is_symlink() or existing.read_bytes() != payload:
            raise CollectorBoundaryError("collector result identity collision")
        return existing
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise CollectorBoundaryError(
                    "collector result write made no progress"
                )
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    return output_directory / name
