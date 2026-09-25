#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parent
RELEASE = ROOT / "releases" / "integrity-seed-0.1.13-rc26"
ARCHIVE = RELEASE / "integrity-seed-0.1.13-rc26.tar"
MANIFEST = RELEASE / "integrity-seed-0.1.13-rc26-source-manifest.json"
ALLOWLIST = RELEASE / "PACKAGE_ALLOWLIST.txt"
SOURCE_ALLOWLIST = ROOT / "PACKAGE_ALLOWLIST.txt"
DISALLOWED_SCRIPT_NAME = "".join(chr(value) for value in (67, 89, 82, 73, 76, 76, 73, 67))
LOCALE_TOKEN = "".join(chr(value) for value in (114, 117))
COUNTRY_TOKEN = "".join(chr(value) for value in (114, 117, 115, 115, 105, 97))
LANGUAGE_TOKEN = COUNTRY_TOKEN + chr(110)
LANGUAGE_MARKER_RE = re.compile(
    rf"(?i)(?<![a-z])(?:{LOCALE_TOKEN}(?:[-_]{LOCALE_TOKEN})?|{COUNTRY_TOKEN}|{LANGUAGE_TOKEN})(?![a-z])"
)
PRIVATE_MARKER_RE = re.compile(
    r"(?i)(?:[a-z]:\\users\\[^\\/\s]+|[\w.+-]+@[\w.-]+\.[a-z]{2,})"
)
TIMEOUT_PROFILE_PATH_RE = re.compile(
    r"(?i)(?:[a-z]:[\\/]+Users[\\/]+[^\\/\s]+|"
    r"/mnt/[a-z]/Users/[^/\s]+|/(?:root|home/[^/\s]+|Users/[^/\s]+))"
)
EXPECTED_HOOKS = {
    "SessionStart",
    "UserPromptSubmit",
    "PostToolUse",
    "PreCompact",
    "PostCompact",
    "SubagentStart",
    "SubagentStop",
    "Stop",
}
TEST_TIMEOUT_SECONDS = 300


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


class VerifierTimeoutError(RuntimeError):
    """The extracted public suite exceeded its bounded execution window."""

    def __init__(self, timeout_seconds: float, output_tail: str) -> None:
        super().__init__(f"archive test suite exceeded {timeout_seconds}s timeout")
        self.timeout_seconds = timeout_seconds
        self.output_tail = output_tail


def timeout_failure_payload(exc: VerifierTimeoutError) -> dict[str, object]:
    return {
        "passed": False,
        "error": type(exc).__name__,
        "timeout_seconds": exc.timeout_seconds,
        "test_output_tail": exc.output_tail,
    }


def sanitize_timeout_output(output: str, extracted: Path, root: Path) -> str:
    """Remove known repository and user-profile paths from timeout diagnostics."""
    for path, marker in ((extracted, "<extracted-release>"), (root, "<repository>")):
        for representation in {str(path), path.as_posix()}:
            output = output.replace(representation, marker)
    output = PRIVATE_MARKER_RE.sub("<private-marker>", output)
    return TIMEOUT_PROFILE_PATH_RE.sub("<user-profile>", output)


def validate_public_text(label: str, value: str) -> None:
    require(
        all(DISALLOWED_SCRIPT_NAME not in unicodedata.name(character, "") for character in value),
        f"disallowed script in {label}",
    )
    require(LANGUAGE_MARKER_RE.search(value) is None, f"prohibited locale marker in {label}")
    require(PRIVATE_MARKER_RE.search(value) is None, f"private environment marker in {label}")


def safe_file_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = archive.getmembers()
    names: set[str] = set()
    for member in members:
        validate_public_text("archive member name", member.name)
        name = PurePosixPath(member.name)
        require(not name.is_absolute() and ".." not in name.parts, f"unsafe path: {member.name}")
        require(member.isfile(), f"unsupported member type: {member.name}")
        require(member.name not in names, f"duplicate member: {member.name}")
        names.add(member.name)
    return members


def extract_verified(archive: tarfile.TarFile, members: list[tarfile.TarInfo], root: Path) -> None:
    for member in members:
        source = archive.extractfile(member)
        require(source is not None, f"cannot read member: {member.name}")
        target = root.joinpath(*PurePosixPath(member.name).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        with source, target.open("wb") as output:
            while block := source.read(1024 * 1024):
                output.write(block)


def validate_structure(root: Path) -> None:
    plugin = json.loads(
        (root / "plugins/integrity-seed/.codex-plugin/plugin.json").read_text(encoding="utf-8")
    )
    require(plugin.get("name") == "integrity-seed", "plugin name mismatch")
    require(plugin.get("version") == "0.1.13", "plugin version mismatch")
    require(plugin.get("skills") == "./skills/", "plugin skill path mismatch")

    marketplace = json.loads(
        (root / ".agents/plugins/marketplace.json").read_text(encoding="utf-8")
    )
    entries = marketplace.get("plugins")
    require(isinstance(entries, list) and len(entries) == 1, "marketplace entry mismatch")
    require(entries[0].get("name") == "integrity-seed", "marketplace plugin mismatch")

    hooks = json.loads((root / "plugins/integrity-seed/hooks/hooks.json").read_text(encoding="utf-8"))
    require(set(hooks.get("hooks", {})) == EXPECTED_HOOKS, "hook event set mismatch")
    for event, groups in hooks["hooks"].items():
        require(isinstance(groups, list) and len(groups) == 1, f"hook group mismatch: {event}")
        require("matcher" in groups[0], f"hook matcher missing: {event}")
        handlers = groups[0].get("hooks")
        require(isinstance(handlers, list) and len(handlers) == 1, f"handler mismatch: {event}")
        handler = handlers[0]
        require(handler.get("type") == "command", f"handler type mismatch: {event}")
        require(isinstance(handler.get("command"), str), f"POSIX command missing: {event}")
        require(isinstance(handler.get("commandWindows"), str), f"Windows command missing: {event}")

    skill = (root / "plugins/integrity-seed/skills/integrity-seed/SKILL.md").read_text(
        encoding="utf-8"
    )
    require(skill.startswith("---\n"), "skill front matter missing")
    require(re.search(r"(?m)^name:\s*integrity-seed\s*$", skill) is not None, "skill name mismatch")
    require(re.search(r"(?m)^description:\s*\S", skill) is not None, "skill description missing")


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    require(manifest.get("artifact") == ARCHIVE.name, "manifest artifact mismatch")
    require(manifest.get("version") == "0.1.13", "manifest version mismatch")
    require(manifest.get("candidate") == "rc26", "manifest candidate mismatch")
    require(
        manifest.get("privacy_scan")
        == {
            "bytecode_or_state_members": 0,
            "private_identifier_matches": 0,
            "language_marker_matches": 0,
            "allowlist_diff": 0,
        },
        "manifest privacy gate is not closed",
    )
    actual_hash = sha256_file(ARCHIVE)
    require(actual_hash == manifest["sha256"], "archive SHA-256 mismatch")
    require(ARCHIVE.stat().st_size == manifest["bytes"], "archive size mismatch")
    root_readme = (ROOT / "README.md").read_text(encoding="utf-8")
    require(actual_hash in root_readme, "root README archive SHA is stale")

    allowlist = [line for line in ALLOWLIST.read_text(encoding="utf-8").splitlines() if line]
    source_allowlist = [
        line for line in SOURCE_ALLOWLIST.read_text(encoding="utf-8").splitlines() if line
    ]
    require(source_allowlist == allowlist, "source and release allowlists differ")
    expected = {entry["path"]: entry for entry in manifest["members"]}
    require(list(expected) == allowlist, "manifest and allowlist order mismatch")
    require(manifest.get("member_count") == len(allowlist), "manifest member count mismatch")

    for name in allowlist:
        source_path = ROOT.joinpath(*PurePosixPath(name).parts)
        require(source_path.is_file() and not source_path.is_symlink(), f"source member missing: {name}")
        require(source_path.stat().st_size == expected[name]["bytes"], f"source size mismatch: {name}")
        require(sha256_file(source_path) == expected[name]["sha256"], f"source hash mismatch: {name}")

    with tempfile.TemporaryDirectory(prefix="integrity-seed-verify-") as temporary:
        extracted = Path(temporary)
        with tarfile.open(ARCHIVE, "r:") as archive:
            members = safe_file_members(archive)
            require([member.name for member in members] == allowlist, "archive allowlist mismatch")
            for member in members:
                expected_mode = 0o755 if member.name.endswith(".sh") else 0o644
                require(member.mode == expected_mode, f"mode mismatch: {member.name}")
                require(member.uid == 0 and member.gid == 0, f"numeric owner mismatch: {member.name}")
                require(
                    member.uname == "root" and member.gname == "root",
                    f"named owner mismatch: {member.name}",
                )
                require(member.mtime == 0, f"timestamp mismatch: {member.name}")
                require(member.linkname == "", f"unexpected link metadata: {member.name}")
                require(member.pax_headers == {}, f"unexpected PAX metadata: {member.name}")
                source = archive.extractfile(member)
                require(source is not None, f"cannot hash member: {member.name}")
                value = source.read()
                validate_public_text(member.name, value.decode("utf-8"))
                require(len(value) == expected[member.name]["bytes"], f"size mismatch: {member.name}")
                require(
                    hashlib.sha256(value).hexdigest() == expected[member.name]["sha256"],
                    f"hash mismatch: {member.name}",
                )
            extract_verified(archive, members, extracted)

        # The launcher resolves the canonical workspace from a trusted Git
        # boundary. The extracted exact-release harness provides a temporary
        # marker so test state roots created beside this directory remain
        # outside that boundary.
        (extracted / ".git").mkdir(mode=0o700)
        validate_structure(extracted)
        try:
            tests = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-I",
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    str(extracted / "plugins/integrity-seed/tests"),
                    "-p",
                    "test_*.py",
                    "-v",
                ],
                cwd=extracted,
                text=True,
                capture_output=True,
                timeout=TEST_TIMEOUT_SECONDS,
                check=False,
                creationflags=(
                    getattr(subprocess, "CREATE_NO_WINDOW", 0)
                    if sys.platform == "win32"
                    else 0
                ),
            )
        except subprocess.TimeoutExpired as exc:
            output = "".join(
                part.decode(errors="replace") if isinstance(part, bytes) else (part or "")
                for part in (exc.stdout, exc.stderr)
            )
            output = sanitize_timeout_output(output, extracted, ROOT)
            raise VerifierTimeoutError(TEST_TIMEOUT_SECONDS, output[-4000:]) from exc
        combined = tests.stdout + tests.stderr
        require(tests.returncode == 0, combined[-4000:])
        ran = re.search(r"Ran\s+(\d+)\s+tests?", combined)
        require(ran is not None, "test count missing")

    print(
        json.dumps(
            {
                "schema": "integrity-seed.public-verifier.v1",
                "artifact_sha256": actual_hash,
                "artifact_bytes": ARCHIVE.stat().st_size,
                "members": len(allowlist),
                "tests_run": int(ran.group(1)),
                "tests_passed": True,
                "platform": sys.platform,
                "passed": True,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        payload = (
            timeout_failure_payload(exc)
            if isinstance(exc, VerifierTimeoutError)
            else {
                "passed": False,
                "error": type(exc).__name__,
                "detail": sanitize_timeout_output(str(exc), ROOT, ROOT)[-4000:],
            }
        )
        print(json.dumps(payload, indent=2), file=sys.stderr)
        raise SystemExit(1)
