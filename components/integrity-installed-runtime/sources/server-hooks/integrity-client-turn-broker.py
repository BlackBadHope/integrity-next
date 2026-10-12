#!/usr/bin/env python3
"""Execute one digest-bound immutable Integrity broker generation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

ACTIVE_PROTOCOL = "integrity-memory/active-broker-generation/v1"
GENERATION_PROTOCOL = "integrity-memory/broker-generation/v1"
ACTIVE_FILE = "active-broker-generation.json"
GENERATIONS_DIR = "generations"
BROKER_FILE = "integrity-client-turn-broker.py"
TOOLS_FILE = "integrity-client-tools.json"
TURN_ENVELOPE_FILE = "integrity_client_turn_envelope.py"
MAX_METADATA_BYTES = 64 * 1024
MAX_BROKER_BYTES = 4 * 1024 * 1024
MAX_TOOLS_BYTES = 4 * 1024 * 1024
MAX_TURN_ENVELOPE_BYTES = 4 * 1024 * 1024
BROKER_OPTIONS = ("--config", "--upstream-server", "--tools-contract")


class LaunchError(RuntimeError):
    pass


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _is_reparse(details: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(int(getattr(details, "st_file_attributes", 0)) & reparse_flag)


def _validate_posix_custody(
    details: os.stat_result,
    *,
    label: str,
    expected_mode: int | None = None,
    immutable: bool = False,
) -> None:
    if os.name == "nt":
        return
    if details.st_uid != os.geteuid():
        raise LaunchError(f"{label} owner is unsafe")
    mode = stat.S_IMODE(details.st_mode)
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise LaunchError(f"{label} mode is unsafe")
    if immutable and mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
        raise LaunchError(f"{label} is not immutable")
    if expected_mode is not None and mode != expected_mode:
        raise LaunchError(f"{label} mode is invalid")


def _directory_identity(
    path: Path,
    *,
    label: str,
    expected_mode: int | None = None,
    immutable: bool = False,
) -> tuple[int, int, int]:
    try:
        details = path.lstat()
    except OSError as exc:
        raise LaunchError(f"{label} is unavailable") from exc
    if (
        stat.S_ISLNK(details.st_mode)
        or _is_reparse(details)
        or not stat.S_ISDIR(details.st_mode)
    ):
        raise LaunchError(f"{label} is unsafe")
    _validate_posix_custody(
        details,
        label=label,
        expected_mode=expected_mode,
        immutable=immutable,
    )
    return details.st_dev, details.st_ino, details.st_mode


def _read_regular(
    path: Path,
    *,
    maximum_bytes: int,
    expected_mode: int | None = None,
    immutable: bool = False,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    for attempt in range(3):
        try:
            before = path.lstat()
        except OSError as exc:
            if attempt < 2:
                continue
            raise LaunchError(
                f"generation artifact is unavailable: {path.name}"
            ) from exc
        if (
            stat.S_ISLNK(before.st_mode)
            or _is_reparse(before)
            or not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= maximum_bytes
        ):
            raise LaunchError(f"generation artifact is unsafe: {path.name}")
        _validate_posix_custody(
            before,
            label=f"generation artifact {path.name}",
            expected_mode=expected_mode,
            immutable=immutable,
        )
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            if attempt < 2:
                continue
            raise LaunchError(
                f"generation artifact is unavailable: {path.name}"
            ) from exc
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or opened.st_size != before.st_size
                or not stat.S_ISREG(opened.st_mode)
                or _is_reparse(opened)
            ):
                if attempt < 2:
                    continue
                raise LaunchError(f"generation artifact changed: {path.name}")
            chunks: list[bytes] = []
            total = 0
            while total <= maximum_bytes:
                chunk = os.read(
                    descriptor,
                    min(1_048_576, maximum_bytes + 1 - total),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
            if (
                len(payload) != before.st_size
                or after.st_dev != opened.st_dev
                or after.st_ino != opened.st_ino
                or after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
                or after.st_ctime_ns != opened.st_ctime_ns
            ):
                if attempt < 2:
                    continue
                raise LaunchError(f"generation artifact changed: {path.name}")
            return payload
        finally:
            os.close(descriptor)
    raise LaunchError(f"generation artifact changed: {path.name}")


def _load_object(
    path: Path,
    *,
    maximum_bytes: int,
    expected_mode: int | None = None,
    immutable: bool = False,
) -> tuple[dict[str, Any], bytes]:
    payload = _read_regular(
        path,
        maximum_bytes=maximum_bytes,
        expected_mode=expected_mode,
        immutable=immutable,
    )
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LaunchError(f"generation metadata is invalid: {path.name}") from exc
    if not isinstance(value, dict):
        raise LaunchError(f"generation metadata is invalid: {path.name}")
    return value, payload


def _validate_file_entry(
    entry: Any,
    *,
    expected_name: str,
    path: Path,
    maximum_bytes: int,
    expected_mode: int,
) -> None:
    if (
        not isinstance(entry, dict)
        or set(entry) != {"bytes", "name", "sha256"}
        or entry.get("name") != expected_name
        or not isinstance(entry.get("bytes"), int)
        or isinstance(entry.get("bytes"), bool)
        or not re.fullmatch(r"[a-f0-9]{64}", str(entry.get("sha256", "")))
    ):
        raise LaunchError("broker generation manifest is invalid")
    payload = _read_regular(
        path,
        maximum_bytes=maximum_bytes,
        expected_mode=expected_mode,
        immutable=True,
    )
    if len(payload) != entry["bytes"] or _digest(payload) != entry["sha256"]:
        raise LaunchError(f"generation digest mismatch: {expected_name}")


def _bound_broker_arguments(arguments: list[str], tools: Path) -> list[str]:
    """Accept one exact broker option set and bind its tools contract."""

    if len(arguments) != len(BROKER_OPTIONS) * 2:
        raise LaunchError("broker arguments are invalid")
    values: dict[str, str] = {}
    for index in range(0, len(arguments), 2):
        option = arguments[index]
        value = arguments[index + 1]
        if option not in BROKER_OPTIONS or option in values:
            raise LaunchError("broker arguments are ambiguous")
        if not value or value.startswith("-"):
            raise LaunchError("broker argument value is invalid")
        values[option] = value
    if set(values) != set(BROKER_OPTIONS):
        raise LaunchError("broker arguments are incomplete")
    return [
        "--config",
        values["--config"],
        "--upstream-server",
        values["--upstream-server"],
        "--tools-contract",
        str(tools),
    ]


def main() -> int:
    runtime_root = Path(__file__).absolute().parent
    runtime_identity = _directory_identity(runtime_root, label="broker runtime root")
    generations_root = runtime_root / GENERATIONS_DIR
    generations_identity = _directory_identity(
        generations_root,
        label="broker generations root",
    )
    active, active_payload = _load_object(
        runtime_root / ACTIVE_FILE,
        maximum_bytes=MAX_METADATA_BYTES,
        expected_mode=0o600,
    )
    generation_id = active.get("generation_id")
    if (
        set(active) != {"generation_id", "manifest_sha256", "protocol"}
        or active.get("protocol") != ACTIVE_PROTOCOL
        or not isinstance(generation_id, str)
        or re.fullmatch(r"[a-f0-9]{64}", generation_id) is None
        or re.fullmatch(r"[a-f0-9]{64}", str(active.get("manifest_sha256", ""))) is None
        or not active_payload.endswith(b"\n")
    ):
        raise LaunchError("active broker generation is invalid")
    generation_root = runtime_root / GENERATIONS_DIR / generation_id
    generation_identity = _directory_identity(
        generation_root,
        label="active broker generation",
        expected_mode=0o500,
        immutable=True,
    )
    manifest, manifest_payload = _load_object(
        generation_root / "manifest.json",
        maximum_bytes=MAX_METADATA_BYTES,
        expected_mode=0o400,
        immutable=True,
    )
    if (
        _digest(manifest_payload) != active["manifest_sha256"]
        or set(manifest) != {"files", "generation_id", "protocol"}
        or manifest.get("protocol") != GENERATION_PROTOCOL
        or manifest.get("generation_id") != generation_id
        or not isinstance(manifest.get("files"), dict)
        or set(manifest["files"]) != {"broker", "tools", "turn_envelope"}
        or _digest(
            _canonical(
                {
                    "protocol": GENERATION_PROTOCOL,
                    "files": manifest["files"],
                }
            )
        )
        != generation_id
    ):
        raise LaunchError("broker generation manifest is invalid")
    broker = generation_root / BROKER_FILE
    tools = generation_root / TOOLS_FILE
    turn_envelope = generation_root / TURN_ENVELOPE_FILE
    _validate_file_entry(
        manifest["files"]["broker"],
        expected_name=BROKER_FILE,
        path=broker,
        maximum_bytes=MAX_BROKER_BYTES,
        expected_mode=0o500,
    )
    _validate_file_entry(
        manifest["files"]["tools"],
        expected_name=TOOLS_FILE,
        path=tools,
        maximum_bytes=MAX_TOOLS_BYTES,
        expected_mode=0o400,
    )
    _validate_file_entry(
        manifest["files"]["turn_envelope"],
        expected_name=TURN_ENVELOPE_FILE,
        path=turn_envelope,
        maximum_bytes=MAX_TURN_ENVELOPE_BYTES,
        expected_mode=0o400,
    )
    if _directory_identity(
        generation_root,
        label="active broker generation",
        expected_mode=0o500,
        immutable=True,
    ) != generation_identity:
        raise LaunchError("active broker generation changed")
    if _directory_identity(
        generations_root,
        label="broker generations root",
    ) != generations_identity:
        raise LaunchError("broker generations root changed")
    if _directory_identity(
        runtime_root,
        label="broker runtime root",
    ) != runtime_identity:
        raise LaunchError("broker runtime root changed")
    arguments = _bound_broker_arguments(list(sys.argv[1:]), tools)
    # Windows read-only directory attributes do not prevent Python from adding
    # __pycache__. Keep the digest-bound generation's exact file set unchanged.
    os.execv(sys.executable, [sys.executable, "-B", str(broker), *arguments])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (LaunchError, OSError, ValueError) as exc:
        print(f"Integrity broker generation launch failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
