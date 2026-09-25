#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import unicodedata
import urllib.parse
from pathlib import Path, PurePosixPath

MANIFEST_NAME = "PUBLIC-EXPORT-MANIFEST.json"
FORBIDDEN_DIRS = frozenset({"state", "ledger", "checkpoints", "keys", "secrets", "private"})
FORBIDDEN_NAMES = frozenset(
    {
        ".env",
        "credentials",
        "credentials.json",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "secrets.txt",
    }
)
FORBIDDEN_SUFFIXES = frozenset(
    {
        ".age",
        ".credentials",
        ".db",
        ".key",
        ".p12",
        ".pem",
        ".pfx",
        ".sqlite",
        ".sqlite3",
        ".token",
    }
)
ALLOWED_URL_HOSTS = frozenset(
    {
        "crates.io",
        "docs.github.com",
        "docs.python.org",
        "docs.rs",
        "example.com",
        "example.invalid",
        "example.net",
        "example.org",
        "github.com",
        "api.github.com",
        "api.openai.com",
        "chatgpt.com",
        "developers.openai.com",
        "docs.continue.dev",
        "docs.google.com",
        "git-scm.com",
        "integrity.guardian",
        "json-schema.org",
        "learn.microsoft.com",
        "localhost",
        "modelcontextprotocol.io",
        "openai.com",
        "opencode.ai",
        "packaging.python.org",
        "pillow.readthedocs.io",
        "pypi.org",
        "raw.githubusercontent.com",
        "registry.npmjs.org",
        "snapshot.ubuntu.com",
        "www.apache.org",
        "www.w3.org",
        "www.youtube.com",
    }
)
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6 = re.compile(
    r"(?i)(?<![0-9a-z_:?])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-z_:])"
)
MAC = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")
URL = re.compile(r"https?://[^\s<>\"'`()\[\]{}]+", re.IGNORECASE)
PATTERNS = {
    "private_key_material": re.compile(
        "-" * 5 + r"BEGIN (?:[A-Z0-9][A-Z0-9 -]* )?PRIVATE KEY" + "-" * 5
    ),
    "url_embedded_credentials": re.compile(r"https?://[^\s/@:]+:[^\s/@]+@", re.IGNORECASE),
    "github_access_token": re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"
    ),
    "openai_api_key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "bearer_token": re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    "windows_user_path": re.compile(r"(?i)\b[A-Z]:[\\/]+Users[\\/]+[A-Za-z0-9._~-]+"),
    "windows_program_data_path": re.compile(r"(?i)\b[A-Z]:[\\/]+ProgramData(?:[\\/]+[A-Za-z0-9._-]+)*"),
    "linux_home_path": re.compile("/" + r"home/[^/\s]+"),
    "linux_srv_path": re.compile(r"(?<![A-Za-z0-9_])/srv(?:/[A-Za-z0-9._-]+)+"),
    "private_history_url": re.compile(
        re.escape("https:" + "//" + "github.com")
        + r"/[^/\s]+/[^/\s]+/(?:actions(?:/runs)?|commit|issues|pull)/[^\s<>)\]\"',}]+",
        re.IGNORECASE,
    ),
    "action_log_anchor": re.compile(r"(?i)\bAction Log\s*#\d+\b"),
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def documentation_address(address: ipaddress._BaseAddress) -> bool:
    if isinstance(address, ipaddress.IPv4Address):
        networks = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
        return any(address in ipaddress.ip_network(network) for network in networks)
    return address in ipaddress.ip_network("2001:db8::/32")


def ipv4_safe(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        isinstance(address, ipaddress.IPv4Address)
        and (
            address.is_loopback
            or address.is_unspecified
            or address.is_multicast
            or documentation_address(address)
        )
    )


def ipv6_safe(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        isinstance(address, ipaddress.IPv6Address)
        and (
            address.is_loopback
            or address.is_unspecified
            or address.is_multicast
            or documentation_address(address)
        )
    )

def url_host_safe(host: str | None) -> bool:
    if not host:
        return False
    lowered = host.rstrip(".").lower()
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        return (
            lowered in ALLOWED_URL_HOSTS
            or lowered.endswith(".example")
            or lowered.endswith(".invalid")
            or lowered.endswith(".test")
        )
    return address.is_loopback or address.is_unspecified or documentation_address(address)


def path_markers(relative: str) -> set[str]:
    path = PurePosixPath(relative)
    parts = tuple(part.lower() for part in path.parts)
    name = path.name.lower()
    findings: set[str] = set()
    if any(part in FORBIDDEN_DIRS for part in parts):
        findings.add("forbidden_runtime_state_directory")
    if name in FORBIDDEN_NAMES or name.startswith(".env."):
        findings.add("forbidden_credential_filename")
    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        findings.add("forbidden_credential_or_state_suffix")
    if ".git" in parts:
        findings.add("git_metadata")
    return findings


def line_number(value: str, offset: int) -> int:
    return value.count("\n", 0, offset) + 1


def scan_text(relative: str, value: str, private_literals: tuple[str, ...] = ()) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for label, pattern in PATTERNS.items():
        for match in pattern.finditer(value):
            findings.append(
                {"path": relative, "line": line_number(value, match.start()), "marker": label}
            )
    lowered = value.casefold()
    for literal in private_literals:
        label = "configured_private_literal"
        offset = lowered.find(literal.casefold())
        if offset >= 0:
            findings.append({"path": relative, "line": line_number(value, offset), "marker": label})
    for match in IPV4.finditer(value):
        if not ipv4_safe(match.group(0)):
            findings.append(
                {
                    "path": relative,
                    "line": line_number(value, match.start()),
                    "marker": "non_documentation_ipv4",
                }
            )
    for match in IPV6.finditer(value):
        if not ipv6_safe(match.group(0)):
            findings.append(
                {
                    "path": relative,
                    "line": line_number(value, match.start()),
                    "marker": "non_documentation_ipv6",
                }
            )
    for match in MAC.finditer(value):
        if not match.group(0).lower().startswith("02-00-00-00-"):
            findings.append(
                {
                    "path": relative,
                    "line": line_number(value, match.start()),
                    "marker": "non_synthetic_hardware_address",
                }
            )
    for match in URL.finditer(value):
        if match.group(0) == "http://www.w3.org/2000/svg":
            continue  # Exact public XML namespace; no host-wide exception.
        try:
            parsed = urllib.parse.urlsplit(match.group(0))
            safe_host = url_host_safe(parsed.hostname)
        except ValueError:
            safe_host = False
        if not safe_host:
            findings.append(
                {
                    "path": relative,
                    "line": line_number(value, match.start()),
                    "marker": "unapproved_url_host",
                }
            )
    return findings


MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 100_000


class ManifestError(ValueError):
    """A content-free, deterministic failure marker."""


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError("manifest_duplicate_key")
        result[key] = value
    return result


def reject_constant(_value: str) -> None:
    raise ManifestError("manifest_nonfinite_number")


def is_reparse(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & 0x400)


def read_regular(path: Path, *, limit: int) -> bytes:
    """Read an ordinary file in a quiescent, owner-controlled staging tree.

    Reject links/special files before opening and recheck the opened identity.
    This is not a sandbox against concurrent replacement of ancestor directories.
    """
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or is_reparse(before) or before.st_nlink != 1:
        raise ValueError("non_regular_or_linked_file")
    if before.st_size > limit:
        raise ValueError("file_too_large")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_BINARY", 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("file_identity_changed")
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise ValueError("non_regular_or_linked_file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise ValueError("file_too_large")
        after = os.fstat(fd)
        if (after.st_size, after.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns):
            raise ValueError("file_changed_during_read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def load_manifest(root: Path) -> dict[str, object]:
    data = read_regular(root / MANIFEST_NAME, limit=MAX_MANIFEST_BYTES)
    manifest = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=reject_constant)
    if not isinstance(manifest, dict):
        raise ManifestError("manifest_shape_mismatch")
    if manifest.get("schema") != "integrity.public-export-manifest/v3":
        raise ManifestError("manifest_schema_mismatch")
    return manifest


MANIFEST_KEYS = frozenset(
    {
        "file_count",
        "files",
        "generated_file_count",
        "generated_files",
        "projection_digest",
        "publication_mode",
        "sanitization_edit_count",
        "schema",
        "transformed_file_count",
    }
)
MANIFEST_ENTRY_KEYS = frozenset(
    {"bytes", "mode", "path", "sanitization_edits", "sha256"}
)

def manifest_entries(manifest: dict[str, object]) -> list[dict[str, object]]:
    if set(manifest) != MANIFEST_KEYS:
        raise ManifestError("manifest_shape_mismatch")
    entries: list[dict[str, object]] = []
    for group in ("files", "generated_files"):
        values = manifest[group]
        if not isinstance(values, list) or len(values) > MAX_ENTRIES:
            raise ManifestError("manifest_shape_mismatch")
        for value in values:
            if not isinstance(value, dict) or set(value) != MANIFEST_ENTRY_KEYS:
                raise ManifestError("manifest_shape_mismatch")
            if (type(value["bytes"]) is not int or value["bytes"] < 0
                    or value["bytes"] > MAX_MEMBER_BYTES
                    or type(value["sanitization_edits"]) is not int
                    or value["sanitization_edits"] < 0
                    or not isinstance(value["path"], str)
                    or not isinstance(value["sha256"], str)
                    or re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None
                    or value["mode"] not in ("0o644", "0o755")):
                raise ManifestError("manifest_value_invalid")
            entries.append(value)
    for key in ("file_count", "generated_file_count", "transformed_file_count",
                "sanitization_edit_count"):
        if type(manifest[key]) is not int or manifest[key] < 0:
            raise ManifestError("manifest_value_invalid")
    if len(entries) > MAX_ENTRIES:
        raise ManifestError("manifest_too_many_entries")
    return entries


def canonical_path(relative: str) -> bool:
    """A single portable, canonical POSIX spelling; no Windows aliases."""
    if (not relative or relative.startswith("/") or "\\" in relative
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in relative)
            or any(c in relative for c in ':*?"<>|')
            or any(0xD800 <= ord(c) <= 0xDFFF for c in relative)):
        return False
    for part in relative.split("/"):
        if not part or part in (".", "..") or part.endswith((".", " ")):
            return False
        stem = part.split(".", 1)[0].upper()
        if stem in {"CON", "PRN", "AUX", "NUL"} or re.fullmatch(r"(?:COM|LPT)[1-9]", stem):
            return False
    return True


def verify(root: Path, private_literals: tuple[str, ...] = ()) -> dict[str, object]:
    # Keep a symlink spelling visible instead of resolving it away.
    root = root.absolute()
    findings: list[dict[str, object]] = []

    def add(relative: str, marker: str) -> None:
        findings.append({"path": relative, "line": 0, "marker": marker})

    def report(checked: int = 0) -> dict[str, object]:
        return {"schema": "integrity.public-surface-report/v1", "root": str(root),
                "checked_files": checked, "findings": findings, "passed": not findings}

    try:
        metadata = root.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or is_reparse(metadata):
            raise ValueError("root_not_ordinary_directory")
        manifest = load_manifest(root)
        entries = manifest_entries(manifest)
        # Scan the very same parsed representation, not a second mutable read.
        manifest_text = json.dumps(manifest, ensure_ascii=False, sort_keys=True)
        findings.extend(scan_text(MANIFEST_NAME, manifest_text))
    except ManifestError as exc:
        add(MANIFEST_NAME, str(exc))
        return report()
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        add(MANIFEST_NAME, f"manifest_error:{type(exc).__name__}")
        return report()

    findings.extend(scan_text(MANIFEST_NAME, manifest_text, private_literals))
    files = manifest["files"]
    generated = manifest["generated_files"]
    if manifest["publication_mode"] != "fresh-history-export-only":
        add(MANIFEST_NAME, "manifest_mode_invalid")
    if (manifest["file_count"] != len(files)
            or manifest["generated_file_count"] != len(generated)):
        add(MANIFEST_NAME, "manifest_count_mismatch")
    if (manifest["transformed_file_count"] != sum(e["sanitization_edits"] > 0 for e in files)
            or manifest["sanitization_edit_count"] != sum(e["sanitization_edits"] for e in files)
            or any(e["sanitization_edits"] != 0 for e in generated)):
        add(MANIFEST_NAME, "manifest_edit_count_mismatch")
    digest_entries = sorted(entries, key=lambda entry: entry["path"])
    try:
        digest_payload = json.dumps(digest_entries, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")).encode("utf-8")
    except UnicodeError:
        add(MANIFEST_NAME, "manifest_invalid_unicode")
        return report()
    if manifest["projection_digest"] != "sha256:" + sha256_bytes(digest_payload):
        add(MANIFEST_NAME, "projection_digest_mismatch")

    expected: dict[str, dict[str, object]] = {}
    portable_paths: set[str] = set()
    prefix_spellings: dict[str, str] = {}
    for entry in entries:
        relative = entry["path"]
        portable = unicodedata.normalize("NFC", relative).casefold()
        if (not canonical_path(relative) or portable == MANIFEST_NAME.casefold()
                or relative in expected or portable in portable_paths):
            add(MANIFEST_NAME, "manifest_duplicate_or_invalid_path")
            continue
        for end in range(1, len(relative.split("/")) + 1):
            prefix = "/".join(relative.split("/")[:end])
            key = unicodedata.normalize("NFC", prefix).casefold()
            if key in prefix_spellings and prefix_spellings[key] != prefix:
                add(MANIFEST_NAME, "manifest_portable_directory_collision")
            prefix_spellings[key] = prefix
        expected[relative] = entry
        portable_paths.add(portable)

    actual: set[str] = set()
    ordinary: set[str] = set()
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda item: item.name)
            for child in children:
                path = Path(child.path)
                relative = path.relative_to(root).as_posix()
                metadata = path.lstat()
                # Only the real root checkout directory is exempt; never links,
                # a .git worktree pointer, nested metadata, or case aliases.
                if (relative == ".git" and stat.S_ISDIR(metadata.st_mode)
                        and not is_reparse(metadata)):
                    continue
                if relative == MANIFEST_NAME:
                    continue
                if not canonical_path(relative):
                    add(relative, "noncanonical_member_path")
                for marker in sorted(path_markers(relative)):
                    add(relative, marker)
                if stat.S_ISLNK(metadata.st_mode) or is_reparse(metadata):
                    actual.add(relative)
                    add(relative, "symlink_member")
                elif stat.S_ISDIR(metadata.st_mode):
                    pending.append(path)
                else:
                    actual.add(relative)
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                        add(relative, "non_regular_or_linked_member")
                    else:
                        ordinary.add(relative)
        except OSError:
            add(directory.relative_to(root).as_posix(), "unreadable_directory_or_member")

    if actual != set(expected):
        add(MANIFEST_NAME, "manifest_membership_mismatch")
    for relative in sorted(ordinary & set(expected)):
        entry = expected[relative]
        try:
            path = root / relative
            data = read_regular(path, limit=MAX_MEMBER_BYTES)
            if entry["bytes"] != len(data) or entry["sha256"] != sha256_bytes(data):
                add(relative, "manifest_content_mismatch")
            if os.name != "nt" and entry["mode"] != oct(path.lstat().st_mode & 0o777):
                add(relative, "manifest_mode_mismatch")
            value = data.decode("utf-8")
        except UnicodeError:
            add(relative, "non_utf8_member")
            continue
        except (OSError, ValueError):
            add(relative, "unreadable_or_changed_member")
            continue
        findings.extend(scan_text(relative, value, private_literals))
    return report(len(actual) + 1)


def load_private_literals_file(path: Path) -> tuple[str, ...]:
    with path.open("rb") as source:
        raw = source.read(256 * 1024 + 1)
    if len(raw) > 256 * 1024:
        raise ValueError("private literal file exceeds byte limit")
    value = json.loads(raw, object_pairs_hook=unique_object)
    if isinstance(value, dict) and value.get("schema") == "integrity.publication-owner-profile/v1":
        if set(value) != {"schema", "private_literals"}:
            raise ValueError("owner profile fields are invalid")
        records = value.get("private_literals")
        if not isinstance(records, list) or not 1 <= len(records) <= 256:
            raise ValueError("owner profile literal corpus is invalid")
        literals = []
        identifiers = set()
        for record in records:
            if not isinstance(record, dict) or set(record) != {"id", "value", "replacement"}:
                raise ValueError("owner profile literal record is invalid")
            identifier = record["id"]
            literal = record["value"]
            replacement = record["replacement"]
            if (not isinstance(identifier, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", identifier)
                    or identifier in identifiers or not isinstance(literal, str)
                    or not 1 <= len(literal) <= 512 or not isinstance(replacement, str)
                    or not 1 <= len(replacement) <= 512
                    or any(ord(char) < 32 for char in literal + replacement)):
                raise ValueError("owner profile literal record is invalid")
            identifiers.add(identifier)
            literals.append(literal)
    else:
        if (not isinstance(value, list) or len(value) > 256
                or any(not isinstance(item, str) or not 1 <= len(item) <= 512
                       or any(ord(char) < 32 for char in item) for item in value)):
            raise ValueError("private literal file must contain a bounded string array")
        literals = list(value)
    if len({item.casefold() for item in literals}) != len(literals):
        raise ValueError("private literal file contains duplicate values")
    return tuple(literals)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--private-literals-file", type=Path, help="External JSON array; not stored in the public tree")
    args = parser.parse_args()
    try:
        literals = load_private_literals_file(args.private_literals_file) \
            if args.private_literals_file is not None else ()
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
        parser.error(f"invalid private literal profile: {type(exc).__name__}")
    report = verify(args.root.absolute(), literals)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
