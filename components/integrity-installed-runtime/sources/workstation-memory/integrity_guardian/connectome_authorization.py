"""Signed, time-bounded authority for offline Connectome compilation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import datetime
from typing import Any

from jsonschema import ValidationError

from .canonical import canonical_bytes
from .connectome import (
    ConnectomeError,
    compile_connectome_manifest,
    verify_connectome_manifest,
)
from .hashing import digest_object
from .schemas import validate
from .signing import (
    Ed25519Signer,
    TrustedKey,
    public_key_fingerprint,
    verify_signature,
)

MAX_CONNECTOME_AUTHORIZATION_SECONDS = 86_400
_ZERO_CALLS = {"model_calls": 0, "tool_calls": 0}
_AUTHORIZED_INVARIANTS = {
    "authorization_verified": True,
    "execution_performed": False,
    "manifest_authority_bound": True,
    "model_calls": 0,
    "production_authority": False,
    "replay_context_bound": True,
    "tenant_bound": True,
    "tool_calls": 0,
}


class ConnectomeAuthorizationError(ValueError):
    """Raised when Connectome compilation authority cannot be established."""


def _time(value: str, *, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise ConnectomeAuthorizationError(
            f"{field_name} must be an RFC3339 string"
    )
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ConnectomeAuthorizationError(
            f"{field_name} must be RFC3339"
        ) from exc
    if parsed.tzinfo is None:
        raise ConnectomeAuthorizationError(
            f"{field_name} must include a timezone"
        )
    return parsed


def _authorization_identity(document: Mapping[str, Any]) -> str:
    unsigned = deepcopy(dict(document))
    unsigned.pop("signature", None)
    unsigned["authorization_id"] = "connectome-authorization:pending"
    identity = digest_object(
        unsigned,
        domain="connectome-authorization-identity-v1",
    ).split(":", 1)[1]
    return f"connectome-authorization:{identity}"


def _canonical_subsystems(values: Sequence[str]) -> tuple[str, ...]:
    if (
        not values
        or any(not isinstance(value, str) or not value for value in values)
        or "*" in values
    ):
        raise ConnectomeAuthorizationError(
            "Connectome authorization requires explicit subsystems"
        )
    normalized = tuple(sorted(set(values)))
    if len(normalized) != len(values):
        raise ConnectomeAuthorizationError(
            "Connectome authorization subsystems must be unique"
        )
    return normalized


def _manifest_scope(manifest: Mapping[str, Any]) -> tuple[tuple[str, ...], bool]:
    subsystems = tuple(
        sorted(
            {
                capability["subsystem"]
                for capability in manifest["capabilities"]
            }
        )
    )
    has_disposable_mutation = any(
        capability["transition_kind"] == "disposable_mutation"
        for capability in manifest["capabilities"]
    )
    return subsystems, has_disposable_mutation


def build_connectome_authorization(
    *,
    manifest: Mapping[str, Any],
    compilation_context_id: str,
    allowed_subsystems: Sequence[str],
    allow_disposable_mutation: bool,
    valid_from: str,
    valid_until: str,
    authority_signer: Ed25519Signer,
) -> dict[str, Any]:
    """Sign exact manifest, tenant, replay context, scope and validity."""

    try:
        verification = verify_connectome_manifest(manifest)
    except ConnectomeError as exc:
        raise ConnectomeAuthorizationError(
            "Connectome authorization received an invalid manifest"
        ) from exc
    if (
        not isinstance(compilation_context_id, str)
        or not compilation_context_id.startswith("context:")
    ):
        raise ConnectomeAuthorizationError(
            "Connectome compilation context identity is not canonical"
        )
    normalized_subsystems = _canonical_subsystems(allowed_subsystems)
    manifest_subsystems, has_disposable_mutation = _manifest_scope(manifest)
    if normalized_subsystems != manifest_subsystems:
        raise ConnectomeAuthorizationError(
            "Connectome authorization scope must exactly match the manifest"
        )
    if has_disposable_mutation and not allow_disposable_mutation:
        raise ConnectomeAuthorizationError(
            "Connectome authorization does not allow disposable mutation"
        )
    start = _time(valid_from, field_name="valid_from")
    end = _time(valid_until, field_name="valid_until")
    validity_seconds = (end - start).total_seconds()
    if not 0 < validity_seconds <= MAX_CONNECTOME_AUTHORIZATION_SECONDS:
        raise ConnectomeAuthorizationError(
            "Connectome authorization validity interval is outside the safe bound"
        )

    unsigned: dict[str, Any] = {
        "protocol": "integrity-guardian/connectome-authorization/v1",
        "authorization_id": "connectome-authorization:pending",
        "tenant_id": verification["tenant_id"],
        "manifest_id": verification["manifest_id"],
        "compilation_context_id": compilation_context_id,
        "authority_role": "connectome-publisher",
        "authority_id": authority_signer.key_id,
        "authority_key_fingerprint": public_key_fingerprint(
            authority_signer.public_key
        ),
        "allowed_subsystems": list(normalized_subsystems),
        "allow_disposable_mutation": allow_disposable_mutation,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "production_authority": False,
    }
    unsigned["authorization_id"] = _authorization_identity(unsigned)
    authorization = authority_signer.sign(unsigned)
    validate("connectome-authorization", authorization)
    return authorization


def verify_connectome_authorization(
    authorization: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    authority_key: TrustedKey,
    expected_tenant_id: str,
    expected_context_id: str,
    at_time: str,
) -> dict[str, Any]:
    """Verify signature, identity, scope, tenant, replay context and time."""

    try:
        candidate = deepcopy(dict(authorization))
        validate("connectome-authorization", candidate)
        manifest_verification = verify_connectome_manifest(manifest)
    except (
        ConnectomeError,
        ValidationError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise ConnectomeAuthorizationError(
            "Connectome authorization schema or manifest rejected"
        ) from exc
    if (
        candidate["tenant_id"] != expected_tenant_id
        or manifest_verification["tenant_id"] != expected_tenant_id
    ):
        raise ConnectomeAuthorizationError(
            "Connectome authorization tenant mismatch"
        )
    if candidate["manifest_id"] != manifest_verification["manifest_id"]:
        raise ConnectomeAuthorizationError(
            "Connectome authorization belongs to another manifest"
        )
    if candidate["compilation_context_id"] != expected_context_id:
        raise ConnectomeAuthorizationError(
            "Connectome authorization replay context mismatch"
        )
    expected_fingerprint = public_key_fingerprint(authority_key.public_key)
    if (
        candidate["authority_id"] != authority_key.key_id
        or candidate["signature"]["key_id"] != authority_key.key_id
        or candidate["authority_key_fingerprint"] != expected_fingerprint
        or not verify_signature(candidate, authority_key.public_key)
    ):
        raise ConnectomeAuthorizationError(
            "Connectome authority signature rejected"
        )
    actual_authorization_id = candidate["authorization_id"]
    if actual_authorization_id != _authorization_identity(candidate):
        raise ConnectomeAuthorizationError(
            "Connectome authorization identity mismatch"
        )

    start = _time(candidate["valid_from"], field_name="valid_from")
    end = _time(candidate["valid_until"], field_name="valid_until")
    current = _time(at_time, field_name="at_time")
    validity_seconds = (end - start).total_seconds()
    if not 0 < validity_seconds <= MAX_CONNECTOME_AUTHORIZATION_SECONDS:
        raise ConnectomeAuthorizationError(
            "Connectome authorization validity interval is outside the safe bound"
        )
    if not start <= current < end:
        raise ConnectomeAuthorizationError(
            "Connectome authorization is not active"
        )

    authorized_subsystems = _canonical_subsystems(
        candidate["allowed_subsystems"]
    )
    manifest_subsystems, has_disposable_mutation = _manifest_scope(manifest)
    if authorized_subsystems != manifest_subsystems:
        raise ConnectomeAuthorizationError(
            "Connectome authorization scope does not match the manifest"
        )
    if (
        has_disposable_mutation
        and not candidate["allow_disposable_mutation"]
    ):
        raise ConnectomeAuthorizationError(
            "Connectome authorization forbids disposable mutation"
        )
    return {
        "ok": True,
        "authorization_id": actual_authorization_id,
        "tenant_id": expected_tenant_id,
        "manifest_id": candidate["manifest_id"],
        "compilation_context_id": expected_context_id,
        "authority_id": candidate["authority_id"],
        "authority_key_fingerprint": expected_fingerprint,
        "active": True,
        "allow_disposable_mutation": candidate[
            "allow_disposable_mutation"
        ],
        "production_authority": False,
    }


def compile_authorized_connectome_manifest(
    manifest: Mapping[str, Any],
    authorization: Mapping[str, Any],
    *,
    authority_key: TrustedKey,
    expected_tenant_id: str,
    expected_context_id: str,
    at_time: str,
) -> dict[str, Any]:
    """Verify authority before any compilation cache lookup or graph build."""

    authorization_verification = verify_connectome_authorization(
        authorization,
        manifest=manifest,
        authority_key=authority_key,
        expected_tenant_id=expected_tenant_id,
        expected_context_id=expected_context_id,
        at_time=at_time,
    )
    compilation = compile_connectome_manifest(manifest)
    core: dict[str, Any] = {
        "protocol": "integrity-guardian/connectome-authorized-compilation/v1",
        "tenant_id": authorization_verification["tenant_id"],
        "manifest_id": authorization_verification["manifest_id"],
        "authorization_id": authorization_verification[
            "authorization_id"
        ],
        "compilation_context_id": authorization_verification[
            "compilation_context_id"
        ],
        "compilation_id": compilation["compilation_id"],
        "graph_id": compilation["graph_id"],
        "authorization": deepcopy(dict(authorization)),
        "compilation": compilation,
        "control_plane_calls": deepcopy(_ZERO_CALLS),
        "invariants": deepcopy(_AUTHORIZED_INVARIANTS),
    }
    bundle = {
        "authorized_compilation_id": digest_object(
            core,
            domain="connectome-authorized-compilation-v1",
        ),
        **core,
    }
    validate("connectome-authorized-compilation", bundle)
    return bundle


def verify_authorized_connectome_compilation(
    bundle: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    authority_key: TrustedKey,
    expected_tenant_id: str,
    expected_context_id: str,
    at_time: str,
) -> dict[str, Any]:
    """Rebuild and byte-compare the signed authorized compilation bundle."""

    try:
        candidate = deepcopy(dict(bundle))
        validate("connectome-authorized-compilation", candidate)
    except (ValidationError, KeyError, TypeError, ValueError) as exc:
        raise ConnectomeAuthorizationError(
            "authorized Connectome compilation schema is invalid"
        ) from exc
    unsigned = deepcopy(candidate)
    actual_bundle_id = unsigned.pop("authorized_compilation_id")
    expected_bundle_id = digest_object(
        unsigned,
        domain="connectome-authorized-compilation-v1",
    )
    if actual_bundle_id != expected_bundle_id:
        raise ConnectomeAuthorizationError(
            "authorized Connectome compilation identity mismatch"
        )
    expected = compile_authorized_connectome_manifest(
        manifest,
        candidate["authorization"],
        authority_key=authority_key,
        expected_tenant_id=expected_tenant_id,
        expected_context_id=expected_context_id,
        at_time=at_time,
    )
    if canonical_bytes(candidate) != canonical_bytes(expected):
        raise ConnectomeAuthorizationError(
            "authorized Connectome compilation semantic mismatch"
        )
    return {
        "ok": True,
        "authorized_compilation_id": actual_bundle_id,
        "authorization_id": candidate["authorization_id"],
        "compilation_id": candidate["compilation_id"],
        "manifest_id": candidate["manifest_id"],
        "graph_id": candidate["graph_id"],
        "tenant_id": candidate["tenant_id"],
        "compilation_context_id": candidate["compilation_context_id"],
        "execution_performed": False,
        "model_calls": 0,
        "tool_calls": 0,
        "production_authority": False,
    }
