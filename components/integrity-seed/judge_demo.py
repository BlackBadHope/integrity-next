#!/usr/bin/env python3
from __future__ import annotations

import json
import hashlib
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parent
RELEASE = ROOT / "releases" / "integrity-seed-0.1.13-rc26"
ARCHIVE = RELEASE / "integrity-seed-0.1.13-rc26.tar"
ALLOWLIST = RELEASE / "PACKAGE_ALLOWLIST.txt"
EXPECTED_SHA256 = "bc212eb12a411040ca28317a843035ca77f1f14b376297cfc4f22203233d2012"
LAUNCHER_PATH = PurePosixPath(
    "plugins/integrity-seed/skills/integrity-seed/scripts/integrity_seed.py"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def extract_artifact(destination: Path) -> Path:
    require(sha256_file(ARCHIVE) == EXPECTED_SHA256, "release archive SHA-256 mismatch")
    expected = [line for line in ALLOWLIST.read_text(encoding="utf-8").splitlines() if line]
    with tarfile.open(ARCHIVE, "r:") as archive:
        members = archive.getmembers()
        require([member.name for member in members] == expected, "archive allowlist mismatch")
        for member in members:
            path = PurePosixPath(member.name)
            require(member.isfile(), "archive contains a non-file member")
            require(not path.is_absolute() and ".." not in path.parts, "archive path is unsafe")
            source = archive.extractfile(member)
            require(source is not None, "archive member is unreadable")
            target = destination.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, target.open("wb") as output:
                while block := source.read(1024 * 1024):
                    output.write(block)
    launcher = destination.joinpath(*LAUNCHER_PATH.parts)
    require(launcher.is_file(), "Integrity Seed launcher is missing from the artifact")
    return launcher


def run_cli(
    launcher: Path,
    workspace: Path,
    environment: dict[str, str],
    *arguments: str,
) -> dict[str, object]:
    completed = subprocess.run(
        [sys.executable, "-B", "-I", str(launcher), *arguments],
        cwd=workspace,
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
        creationflags=(
            getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
        ),
    )
    require(completed.returncode == 0, f"{arguments[0]} command failed")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{arguments[0]} returned invalid JSON") from exc
    require(isinstance(payload, dict), f"{arguments[0]} returned a non-object")
    return payload


def main() -> int:
    stopped = False
    temporary = tempfile.TemporaryDirectory(prefix="integrity-seed-judge-")
    temporary_root = Path(temporary.name)
    try:
        artifact = temporary_root / "artifact"
        workspace = temporary_root / "workspace"
        codex_home = temporary_root / "codex-home"
        workspace.mkdir()
        (workspace / ".git").mkdir()
        codex_home.mkdir()
        launcher = extract_artifact(artifact)

        environment = os.environ.copy()
        for key in list(environment):
            if (
                key == "CODEX_THREAD_ID"
                or key.startswith("CODEX_LOG_")
                or key.startswith("INTEGRITY_SEED_")
            ):
                environment.pop(key, None)
        environment["CODEX_HOME"] = str(codex_home)
        environment["INTEGRITY_SEED_HOME"] = str(temporary_root / "state")
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        try:
            doctor = run_cli(launcher, workspace, environment, "doctor", "--json")
            require(doctor.get("ok") is True, "runtime doctor failed")
            require(doctor.get("events") == 0, "temporary store was not empty")
            require(doctor.get("loopback_only") is True, "runtime was not loopback-only")
            require(doctor.get("token_auth") is True, "runtime token auth was unavailable")
            require(doctor.get("delete_enabled") is False, "runtime deletion was enabled")

            stored = run_cli(
                launcher,
                workspace,
                environment,
                "remember",
                "Synthetic handoff: preserve the amber compass decision for the next reviewer.",
                "--task-id",
                "JUDGE-DEMO",
                "--kind",
                "handoff",
                "--truth-status",
                "observed",
                "--verification",
                "synthetic-clean-room",
                "--actor",
                "build-week-judge-demo",
                "--session-id",
                "judge-writer",
            )
            event_id = stored.get("id")
            require(type(event_id) is int and event_id > 0, "handoff event ID is invalid")
            require(stored.get("action") == "agent_memory_checkpoint", "handoff action is invalid")
            details = stored.get("details")
            require(isinstance(details, dict) and details.get("kind") == "handoff", "kind is invalid")

            recalled = run_cli(
                launcher,
                workspace,
                environment,
                "recall",
                "amber compass",
                "--session-id",
                "judge-reader",
                "--context-limit",
                "512",
            )
            selected = recalled.get("selected_source_event_ids")
            delivered = recalled.get("delivered_event_ids")
            context = recalled.get("context_text")
            require(recalled.get("ok") is True, "bounded recall failed")
            require(recalled.get("coverage_status") == "strong", "recall coverage is not strong")
            require(recalled.get("semantic_complete") is False, "recall overclaimed completeness")
            require(isinstance(selected, list) and event_id in selected, "event was not selected")
            require(isinstance(delivered, list) and event_id in delivered, "event was not delivered")
            require(isinstance(context, str), "recall context is missing")
            require(len(context) <= 512, "bounded context exceeded its limit")
            require(f"#{event_id}" in context, "rendered context omitted the evidence ID")
            require("MEMORY TRUST BOUNDARY:" in context, "trust boundary was not rendered")
            require(
                context.index("MEMORY TRUST BOUNDARY:") < context.index(f"#{event_id}"),
                "trust boundary was rendered after evidence",
            )

            stop = run_cli(launcher, workspace, environment, "stop", "--json")
            stopped = stop.get("ok") is True
            require(stopped, "runtime did not stop cleanly")
        finally:
            if not stopped:
                try:
                    run_cli(launcher, workspace, environment, "stop", "--json")
                except Exception:
                    pass
    finally:
        temporary.cleanup()
    require(not temporary_root.exists(), "temporary state was not removed")
    print(
        json.dumps(
            {
                "schema": "integrity-seed.judge-demo.v1",
                "artifact_sha256": EXPECTED_SHA256,
                "empty_start_events": 0,
                "handoff_event_id": event_id,
                "coverage_status": recalled.get("coverage_status"),
                "semantic_complete": recalled.get("semantic_complete"),
                "selected_source_event_ids": selected,
                "delivered_event_ids": delivered,
                "bounded_context_chars": len(context),
                "trust_boundary_present": True,
                "runtime_stopped": stopped,
                "temporary_state_removed": True,
                "build_required": False,
                "credentials_required": False,
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
        print(
            json.dumps(
                {
                    "schema": "integrity-seed.judge-demo.v1",
                    "passed": False,
                    "error": type(exc).__name__,
                    "detail": str(exc)[:400],
                }
            ),
            file=sys.stderr,
        )
        raise SystemExit(1)
