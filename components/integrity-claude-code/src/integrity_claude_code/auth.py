"""Pre-launch auth metadata preflight and managed-policy detection (Windows).

``preflight_auth`` (production, no seams) runs the EXACT pinned native CLI through the
same Job Object launcher as a run -- shell-free, bounded stdout/stderr/time, explicit
environment, cwd outside the agent workspace -- with the auth-only argv::

    claude --safe-mode auth status --json

``--safe-mode`` keeps customizations (hooks, plugins, MCP, CLAUDE.md, ...) from loading
in this diagnostic process; the owner's earlier observed probe used it. Exact argv
order is from that observation and must be re-confirmed by J evidence.

Only a closed whitelist is interpreted: ``loggedIn`` (bool) and ``authMethod``
(compared with owner-allowed subscription methods, retained only as a digest). API
key / provider / helper / gateway indications refuse regardless of the allowlist; the
allowlist itself cannot name such methods. Account identities, tokens and all other
fields are never retained. Real managed-policy detection runs in the preflight AND
again at launch. Any doubt refuses (default deny). A positive result is necessary,
never sufficient: the effective subscription method must be proven by the signed
activation evidence for the pinned build.
"""
from __future__ import annotations

import hashlib
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .canonical import Rejected, need, sha256_bytes, strict_loads
from .identity import environment_identity, executable_identity, is_within
from .policy import API_OR_PROVIDER, ExecutorPolicy

AUTH_STATUS_ARGV = ("--safe-mode", "auth", "status", "--json")
FRESHNESS_SECONDS = 300
MAX_STATUS_BYTES = 64 * 1024
_OVERRIDE_KEY = re.compile(r"(?i)api.?key|token|bedrock|vertex|foundry|base.?url|provider|helper|gateway")
_NEUTRAL = (None, False, "", "none", "firstParty", "first_party")
_ISSUER = object()

# Known local managed-policy sources on Windows at authoring time. Presence/path/digest
# metadata only. Sources outside this list (e.g. server-delivered settings) are not
# locally verifiable: the activation evidence must attest them.
MANAGED_FILES = {
    "program_files_managed_settings": ("ProgramFiles", "ClaudeCode", "managed-settings.json"),
    "program_files_managed_mcp": ("ProgramFiles", "ClaudeCode", "managed-mcp.json"),
    "program_data_managed_settings": ("ProgramData", "ClaudeCode", "managed-settings.json"),
    "program_data_managed_mcp": ("ProgramData", "ClaudeCode", "managed-mcp.json"),
}
MANAGED_REGISTRY = {"hklm_policies": ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Policies\ClaudeCode"),
                    "hkcu_policies": ("HKEY_CURRENT_USER", r"SOFTWARE\Policies\ClaudeCode")}


def _file_state(env: dict) -> dict:
    state = {}
    for source, (variable, *parts) in MANAGED_FILES.items():
        base = env.get(variable)
        if not base:
            state[source] = "unverifiable"
            continue
        path = Path(base, *parts)
        try:
            if not path.exists():
                state[source] = "absent"
            elif path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024 * 1024:
                state[source] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            else:
                state[source] = "present-unpinnable"
        except OSError:
            state[source] = "unverifiable"
    return state


def _registry_state() -> dict:
    try:
        import winreg
    except ImportError:
        return {source: "unverifiable" for source in MANAGED_REGISTRY}
    state = {}
    for source, (hive, key) in MANAGED_REGISTRY.items():
        try:
            with winreg.OpenKey(getattr(winreg, hive), key, 0, winreg.KEY_READ):
                state[source] = "present-unpinnable"
        except FileNotFoundError:
            state[source] = "absent"
        except OSError:
            state[source] = "unverifiable"
    return state


def managed_state() -> dict:
    """REAL host state: {source: "absent" | sha256 | "present-unpinnable" | "unverifiable"}."""
    return {**_file_state(os.environ), **_registry_state()}


def check_managed(policy: ExecutorPolicy, state: dict) -> None:
    """Every known source must equal its pin; unpinned/unknown/unverifiable refuses."""
    pins = dict(policy.managed_pins)
    for source, observed in sorted(state.items()):
        need(observed == "absent" or observed.startswith("sha256:"), "managed_source_unverifiable")
        need(pins.get(source, "absent") == observed, "managed_policy_unpinned")


def interpret_status(raw: bytes, policy: ExecutorPolicy) -> dict:
    """Closed interpretation of ``auth status --json`` output. Retains no raw value."""
    need(type(raw) is bytes and 0 < len(raw) <= MAX_STATUS_BYTES, "auth_status_size")
    try:
        document = strict_loads(raw.strip(), MAX_STATUS_BYTES)
    except Rejected:
        raise Rejected("auth_status_unparseable") from None
    need(type(document) is dict, "auth_status_shape")
    logged_in, method = document.get("loggedIn"), document.get("authMethod")
    need(type(logged_in) is bool and type(method) is str, "auth_status_fields")
    need(logged_in, "auth_not_logged_in")
    for key, value in document.items():  # API-key / provider / helper overrides refuse
        if _OVERRIDE_KEY.search(key) and value not in _NEUTRAL:
            raise Rejected("auth_override_present")
    need(not API_OR_PROVIDER.search(method), "auth_method_api_or_provider")  # allowlist cannot widen
    need(method in policy.allowed_auth_methods, "auth_method_not_allowed")
    return {"method_sha256": sha256_bytes(method.encode("utf-8"))}


@dataclass(frozen=True)
class AuthAttestation:
    """Issued only by this module; bound to binary, environment, policy and managed state."""
    executable_sha256: str
    environment_sha256: str
    policy_sha256: str
    method_sha256: str
    managed: tuple
    synthetic: bool
    obtained: float = field(compare=False)
    _issuer: object = field(repr=False, compare=False, default=None)

    def valid_for(self, *, executable_sha256: str, environment_sha256: str, policy_sha256: str,
                  allow_synthetic: bool = False) -> bool:
        return (self._issuer is _ISSUER and (allow_synthetic or not self.synthetic)
                and 0 <= time.monotonic() - self.obtained <= FRESHNESS_SECONDS
                and (self.executable_sha256, self.environment_sha256, self.policy_sha256)
                == (executable_sha256, environment_sha256, policy_sha256))

    def managed_still_matches(self, policy: ExecutorPolicy) -> bool:
        """Re-read REAL managed state at launch; must equal the attested, pinned state."""
        current = managed_state()
        check_managed(policy, current)
        return tuple(sorted(current.items())) == self.managed


def _attest(*, executable, executable_sha256, environment, workdir, agent_workspace, policy,
            managed, run_status, synthetic) -> AuthAttestation:
    need(isinstance(policy, ExecutorPolicy), "policy_type")
    need(policy.allowed_auth_methods, "auth_expectation_missing")
    need(not any(API_OR_PROVIDER.search(m) for m in policy.allowed_auth_methods),
         "auth_method_api_or_provider")
    need(executable_identity(Path(executable))["sha256"] == executable_sha256, "executable_digest_mismatch")
    env = environment_identity(environment)
    need(not is_within(Path(workdir), Path(agent_workspace)), "auth_probe_inside_agent_workspace")
    check_managed(policy, managed)
    verdict = interpret_status(run_status(Path(executable), executable_sha256, dict(environment),
                                          Path(workdir)), policy)
    return AuthAttestation(executable_sha256=executable_sha256, environment_sha256=env["sha256"],
                           policy_sha256=policy.digest(), method_sha256=verdict["method_sha256"],
                           managed=tuple(sorted(managed.items())), synthetic=synthetic,
                           obtained=time.monotonic(), _issuer=_ISSUER)


def preflight_auth(*, executable: Path, executable_sha256: str, environment: dict, workdir: Path,
                   agent_workspace: Path, policy: ExecutorPolicy) -> AuthAttestation:
    """PRODUCTION: real exact-native probe + real managed detection. No injection points."""
    return _attest(executable=executable, executable_sha256=executable_sha256,
                   environment=environment, workdir=workdir, agent_workspace=agent_workspace,
                   policy=policy, managed=managed_state(), run_status=_run_status, synthetic=False)


def _offline_attestation_fixture(*, status: bytes, managed: dict, **kwargs) -> AuthAttestation:
    """INTERNAL offline tests only. The result is marked synthetic; production refuses it."""
    return _attest(managed=managed, run_status=lambda *_: status, synthetic=True, **kwargs)


def _run_status(executable: Path, sha256: str, environment: dict, workdir: Path) -> bytes:
    from .winjob import JobProcess, NotStarted  # Windows-only

    buffer = bytearray()
    limits = {"deadline_seconds": 30, "stop_grace_seconds": 5, "max_stdout_bytes": MAX_STATUS_BYTES,
              "max_stderr_bytes": MAX_STATUS_BYTES, "job_memory_bytes": 1024 * 1024 * 1024,
              "max_processes": 16}
    try:
        job = JobProcess(executable=executable, executable_sha256=sha256, argv=list(AUTH_STATUS_ARGV),
                         cwd=workdir, environment=environment, stdin=b"", limits=limits,
                         stdout_sink=buffer.extend, cancel=threading.Event()).run()
    except NotStarted:
        raise Rejected("auth_probe_not_started") from None
    need(job.stop_verified and job.termination is None and job.exit_code == 0, "auth_probe_failed")
    return bytes(buffer)  # interpreted immediately, never persisted or logged
