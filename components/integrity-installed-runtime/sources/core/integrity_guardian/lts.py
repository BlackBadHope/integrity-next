"""Machine-verifiable support contracts for the three Integrity LTS tracks."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from importlib import import_module
from importlib.resources import files
from typing import Any

from .canonical import parse_json_strict
from .hashing import digest_object
from .schemas import SCHEMA_NAMES, validate

LTS_TRACK_IDS = (
    "guardian-core-lts",
    "seed-synapse-lts",
    "adapter-observer-sdk-lts",
)


class LtsContractError(ValueError):
    """Raised when a declared LTS surface is missing or expands authority."""


def load_lts_contracts() -> dict[str, Any]:
    value = parse_json_strict(files("integrity_guardian").joinpath("lts-contracts.json").read_bytes())
    if not isinstance(value, dict):
        raise LtsContractError("LTS contracts must be an object")
    return value


def _public_exports() -> set[str]:
    package = import_module("integrity_guardian")
    exported = getattr(package, "__all__", ())
    return {str(value) for value in exported}


def _cli_commands() -> set[str]:
    cli = import_module("integrity_guardian.cli")
    parser = cli.build_parser()
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict):
            return set(choices)
    raise LtsContractError("Guardian CLI command registry is unavailable")


def verify_lts_contracts(
    contracts: Mapping[str, Any] | None = None,
    *,
    available_exports: set[str] | None = None,
    available_schemas: set[str] | None = None,
    available_commands: set[str] | None = None,
) -> dict[str, Any]:
    candidate = deepcopy(dict(load_lts_contracts() if contracts is None else contracts))
    try:
        validate("lts-support-contracts", candidate)
    except Exception as exc:
        raise LtsContractError("LTS contract schema verification failed") from exc
    tracks = candidate["tracks"]
    track_ids = tuple(track["track_id"] for track in tracks)
    if track_ids != LTS_TRACK_IDS:
        raise LtsContractError("LTS tracks or their canonical order changed")
    exports = _public_exports() if available_exports is None else available_exports
    schemas = set(SCHEMA_NAMES) if available_schemas is None else available_schemas
    commands = _cli_commands() if available_commands is None else available_commands
    missing: dict[str, dict[str, list[str]]] = {}
    for track in tracks:
        absent_exports = sorted(set(track["stable_python_exports"]) - exports)
        absent_schemas = sorted(set(track["stable_schemas"]) - schemas)
        absent_commands = sorted(set(track["stable_commands"]) - commands)
        if absent_exports or absent_schemas or absent_commands:
            missing[track["track_id"]] = {
                "python_exports": absent_exports,
                "schemas": absent_schemas,
                "commands": absent_commands,
            }
        active_surface = " ".join(
            [
                track["component"],
                *track["stable_python_exports"],
                *track["stable_schemas"],
                *track["stable_commands"],
            ]
        ).casefold()
        if "fgd" in active_surface or "integrity-home" in active_surface:
            raise LtsContractError("retired or non-Seed modules entered an active LTS surface")
        if track["support_window_months"] < candidate["policy"]["minimum_support_months"]:
            raise LtsContractError("an LTS track is shorter than the global support floor")
    if missing:
        raise LtsContractError(f"declared LTS surfaces are missing: {missing}")
    contract_digest = digest_object(candidate, domain="integrity-lts-support-contracts-v1")
    return {
        "ok": True,
        "status": candidate["status"],
        "contract_digest": contract_digest,
        "track_ids": list(track_ids),
        "support_window_months": {
            track["track_id"]: track["support_window_months"] for track in tracks
        },
        "production_authority": False,
        "memory_grants_authority": False,
    }


def lts_track_contract_digest(track: Mapping[str, Any]) -> str:
    """Bind one independent LTS lane without coupling candidate siblings."""

    candidate = deepcopy(dict(track))
    if candidate.get("track_id") not in LTS_TRACK_IDS:
        raise LtsContractError("LTS track digest input is not canonical")
    return digest_object(candidate, domain="integrity-lts-track-contract-v1")


def lts_contract_report() -> dict[str, Any]:
    contracts = load_lts_contracts()
    return {"contracts": contracts, "verification": verify_lts_contracts(contracts)}
