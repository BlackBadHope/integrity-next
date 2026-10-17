"""Durable private negative history for the disposable corpus index.

The SQLite corpus is a rebuildable projection.  Conversation revocations live
in its bound ledger so deleting or restoring the database cannot silently
resurrect forgotten material. Provider-controlled identifiers are stored
verbatim and may themselves contain sensitive or message-like text; the whole
ledger is therefore private corpus metadata, never a content-free receipt.
"""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from .json_integrity import loads_json_strict
from .state_lock import corpus_state_lock


DELETION_LEDGER_SCHEMA_VERSION = "integrity-home-deletion-ledger/2"


class DeletionLedgerError(RuntimeError):
    """Raised when durable negative history is missing or invalid."""


def _stable_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError, UnicodeEncodeError) as err:
        raise DeletionLedgerError(f"deletion ledger is not stable JSON: {err}") from err


def _text(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise DeletionLedgerError(f"{field} must be a non-empty string")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as err:
        raise DeletionLedgerError(f"{field} must be valid UTF-8") from err
    return value


def deletion_ledger_path(index_path: str, ledger_path: Optional[str] = None) -> Path:
    if ledger_path is not None:
        if not isinstance(ledger_path, str) or not ledger_path:
            raise DeletionLedgerError("ledger_path must be a non-empty string")
        return Path(ledger_path)
    if not isinstance(index_path, str) or not index_path:
        raise DeletionLedgerError("index_path must be a non-empty string")
    return Path(f"{index_path}.deletions.json")


def conversation_selector(
    *, source_id: str, conversation_id: str
) -> Dict[str, str]:
    source_id = _text(source_id, field="source_id")
    conversation_id = _text(conversation_id, field="conversation_id")
    unsigned = {
        "selector_type": "conversation",
        "source_id": source_id,
        "conversation_id": conversation_id,
    }
    return {
        "selector_id": sha256(_stable_json(unsigned).encode("utf-8")).hexdigest(),
        **unsigned,
    }


def _validated_selectors(values: Iterable[Mapping[str, Any]]) -> List[Dict[str, str]]:
    result: List[Dict[str, str]] = []
    seen: set[Tuple[str, str]] = set()
    for ordinal, value in enumerate(values):
        if not isinstance(value, Mapping):
            raise DeletionLedgerError(f"deletion selector {ordinal} must be an object")
        if set(value) != {
            "selector_id",
            "selector_type",
            "source_id",
            "conversation_id",
        }:
            raise DeletionLedgerError(f"deletion selector {ordinal} has unexpected fields")
        selector_type = _text(
            value.get("selector_type"), field=f"selector[{ordinal}].selector_type"
        )
        if selector_type != "conversation":
            raise DeletionLedgerError(
                f"deletion selector {ordinal} has unsupported selector_type"
            )
        selector = conversation_selector(
            source_id=_text(value.get("source_id"), field=f"selector[{ordinal}].source_id"),
            conversation_id=_text(
                value.get("conversation_id"),
                field=f"selector[{ordinal}].conversation_id",
            ),
        )
        if value.get("selector_id") != selector["selector_id"]:
            raise DeletionLedgerError(f"deletion selector {ordinal} digest mismatch")
        key = (selector["source_id"], selector["conversation_id"])
        if key in seen:
            raise DeletionLedgerError("duplicate deletion selector")
        seen.add(key)
        result.append(selector)
    return sorted(result, key=lambda item: (item["source_id"], item["conversation_id"]))


def build_deletion_ledger(
    selectors: Iterable[Mapping[str, Any]],
) -> Dict[str, Any]:
    normalized = _validated_selectors(selectors)
    payload: Dict[str, Any] = {
        "schema_version": DELETION_LEDGER_SCHEMA_VERSION,
        "privacy_class": "private_opaque_identifier_metadata",
        "stores_raw_identifiers": True,
        "selector_count": len(normalized),
        "selectors": normalized,
    }
    payload["ledger_sha256"] = sha256(_stable_json(payload).encode("utf-8")).hexdigest()
    return payload


def validate_deletion_ledger(payload: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise DeletionLedgerError("deletion ledger must be an object")
    if set(payload) != {
        "schema_version",
        "privacy_class",
        "stores_raw_identifiers",
        "selector_count",
        "selectors",
        "ledger_sha256",
    }:
        raise DeletionLedgerError("deletion ledger has unexpected fields")
    if payload.get("schema_version") != DELETION_LEDGER_SCHEMA_VERSION:
        raise DeletionLedgerError("deletion ledger schema mismatch")
    if payload.get("privacy_class") != "private_opaque_identifier_metadata":
        raise DeletionLedgerError("deletion ledger privacy classification is missing")
    if payload.get("stores_raw_identifiers") is not True:
        raise DeletionLedgerError("deletion ledger raw-identifier disclosure is missing")
    selectors = payload.get("selectors")
    if not isinstance(selectors, list):
        raise DeletionLedgerError("deletion ledger selectors must be a list")
    normalized = _validated_selectors(selectors)
    count = payload.get("selector_count")
    if isinstance(count, bool) or not isinstance(count, int) or count != len(normalized):
        raise DeletionLedgerError("deletion ledger selector_count mismatch")
    rebuilt = build_deletion_ledger(normalized)
    if payload.get("ledger_sha256") != rebuilt["ledger_sha256"]:
        raise DeletionLedgerError("deletion ledger digest mismatch")
    return rebuilt


def load_deletion_ledger(
    index_path: str,
    *,
    ledger_path: Optional[str] = None,
    missing_ok: bool = False,
) -> Optional[Dict[str, Any]]:
    path = deletion_ledger_path(index_path, ledger_path)
    if not path.is_file():
        if missing_ok:
            return None
        raise DeletionLedgerError(f"deletion ledger does not exist: {path}")
    try:
        payload = loads_json_strict(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as err:
        raise DeletionLedgerError(f"cannot read deletion ledger: {err}") from err
    return validate_deletion_ledger(payload)


def _sync_parent_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(str(path), flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_deletion_ledger(
    index_path: str,
    selectors: Iterable[Mapping[str, Any]],
    *,
    ledger_path: Optional[str] = None,
) -> Dict[str, Any]:
    payload = build_deletion_ledger(selectors)
    target = deletion_ledger_path(index_path, ledger_path)
    # Low-level ledger writes must coordinate with readers too. Higher-level
    # forget/rebuild paths already hold this re-entrant lock, while direct
    # callers previously could advance negative history between two corpus
    # freshness checks.
    with corpus_state_lock(index_path):
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix="integrity-home-deletions-", suffix=".json", dir=target.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(
                    json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False)
                )
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            _sync_parent_directory(target.parent)
            return payload
        finally:
            temporary.unlink(missing_ok=True)


__all__ = [
    "DELETION_LEDGER_SCHEMA_VERSION",
    "DeletionLedgerError",
    "build_deletion_ledger",
    "conversation_selector",
    "deletion_ledger_path",
    "load_deletion_ledger",
    "validate_deletion_ledger",
    "write_deletion_ledger",
]
