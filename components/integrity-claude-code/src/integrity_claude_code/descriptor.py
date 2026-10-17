"""Versioned run descriptor: every input identity a launch depends on, digest-bound.

Digests and bounded metadata only -- never prompt text or environment values. The
argv is not supplied by the caller: it is derived from the immutable policy and a
deterministic per-run MCP config path, then bound by exact parity. The descriptor is
the payload the SDK envelope must bind; by itself it grants nothing.
"""
from __future__ import annotations

from pathlib import Path

from .canonical import (bounded_int, digest_object, digest_value, identifier, need,
                        session_uuid)
from .identity import (argv_identity, environment_identity, executable_identity, is_within,
                       normalized_directory, prompt_identity, repository_identity)
from .policy import CLI_PROFILE, FIXTURE_PROFILE, ExecutorPolicy, cli_argv

RUN_SCHEMA = "integrity-claude-code/run/v1"
_DOMAIN = "integrity-claude-code-run-v1"
LIMIT_BOUNDS = {
    "deadline_seconds": (2, 6 * 3600),
    "stop_grace_seconds": (1, 60),
    "max_prompt_bytes": (1, 1024 * 1024),
    "max_stdout_bytes": (1024, 64 * 1024 * 1024),
    "max_stderr_bytes": (1024, 16 * 1024 * 1024),
    "max_line_bytes": (256, 4 * 1024 * 1024),
    "max_events": (2, 1_000_000),
    "job_memory_bytes": (64 * 1024 * 1024, 16 * 1024 * 1024 * 1024),
    "max_processes": (1, 256),
}
_FIELDS = {"schema", "profile", "task_id", "session_id", "run_id", "request_id", "host_id",
           "mode", "model", "policy_sha256", "executable", "cwd", "repository", "state_dir",
           "mcp_config", "argv", "environment", "prompt", "limits"}


def validate_limits(limits: dict) -> dict:
    need(type(limits) is dict and set(limits) == set(LIMIT_BOUNDS), "limits_fields")
    for name, (low, high) in LIMIT_BOUNDS.items():
        bounded_int(limits[name], low, high, "limit_" + name)
    need(limits["stop_grace_seconds"] < limits["deadline_seconds"], "limit_grace")
    need(limits["max_line_bytes"] <= limits["max_stdout_bytes"], "limit_line")
    return dict(limits)


def mcp_config_path(state_dir: Path, run_id: str) -> Path:
    """Deterministic per-run relay config location inside the owner state directory."""
    return Path(state_dir) / identifier(run_id, "run_id") / "mcp.json"


def _assemble(*, profile: str, prefix_tokens: tuple, task_id: str, session_id: str, run_id: str,
              request_id: str, host_id: str, mode: str, policy: ExecutorPolicy, executable: Path,
              executable_sha256: str, executable_version: str, cwd: Path, expected_head: str,
              state_dir: Path, environment: dict, prompt: bytes, limits: dict) -> dict:
    need(profile in (CLI_PROFILE, FIXTURE_PROFILE), "descriptor_profile")
    need(type(prefix_tokens) is tuple and (profile == FIXTURE_PROFILE or not prefix_tokens),
         "argv_prefix_forbidden_for_cli_profile")
    for value, code in ((task_id, "task_id"), (run_id, "run_id"), (request_id, "request_id"),
                        (host_id, "host_id")):
        identifier(value, code)
    session_uuid(session_id)
    need(mode in ("new", "resume"), "run_mode")
    need(isinstance(policy, ExecutorPolicy), "policy_type")
    need(type(executable_version) is str and 0 < len(executable_version) <= 64
         and executable_version.isprintable(), "executable_version")
    digest_value(executable_sha256, "executable_sha256")
    limits = validate_limits(limits)
    binary = executable_identity(Path(executable))
    need(binary["sha256"] == executable_sha256, "executable_digest_mismatch")
    repository = repository_identity(Path(cwd))
    need(repository["head"] == expected_head, "repository_head_mismatch")
    state = normalized_directory(Path(state_dir))
    need(not is_within(Path(state_dir), Path(cwd)) and not is_within(Path(cwd), Path(state_dir)),
         "state_dir_overlaps_agent_workspace")
    config = str(mcp_config_path(Path(state), run_id))
    tail = cli_argv(policy, mode=mode, session_id=session_id, mcp_config=config)
    return {
        "schema": RUN_SCHEMA, "profile": profile,
        "task_id": task_id, "session_id": session_id, "run_id": run_id,
        "request_id": request_id, "host_id": host_id, "mode": mode, "model": policy.model,
        "policy_sha256": policy.digest(),
        "executable": {**binary, "version": executable_version},
        "cwd": normalized_directory(Path(cwd)),
        "repository": repository,
        "state_dir": state, "mcp_config": config,
        "argv": argv_identity([*prefix_tokens, *tail], expected_tail=tail,
                              prefix=len(prefix_tokens)),
        "environment": environment_identity(environment),
        "prompt": prompt_identity(prompt, limits["max_prompt_bytes"]),
        "limits": limits,
    }


def build_run_descriptor(**inputs) -> dict:
    """Production entrypoint: native CLI profile only, no argv prefix, argv from policy."""
    need("profile" not in inputs and "prefix_tokens" not in inputs, "descriptor_profile")
    return _assemble(profile=CLI_PROFILE, prefix_tokens=(), **inputs)


def run_argv(descriptor: dict, policy: ExecutorPolicy, prefix_tokens: tuple = ()) -> list:
    tail = cli_argv(policy, mode=descriptor["mode"], session_id=descriptor["session_id"],
                    mcp_config=descriptor["mcp_config"])
    return [*prefix_tokens, *tail]


def validate_descriptor(descriptor: dict) -> dict:
    """Structural check of an already-built descriptor (ledger/gate side)."""
    need(type(descriptor) is dict and set(descriptor) == _FIELDS
         and descriptor["schema"] == RUN_SCHEMA, "descriptor_schema")
    need(descriptor["profile"] in (CLI_PROFILE, FIXTURE_PROFILE), "descriptor_profile")
    for key in ("task_id", "run_id", "request_id", "host_id", "model"):
        identifier(descriptor[key], "descriptor_" + key)
    session_uuid(descriptor["session_id"])
    need(descriptor["mode"] in ("new", "resume"), "run_mode")
    digest_value(descriptor["policy_sha256"], "descriptor_policy")
    need(set(descriptor["executable"]) == {"path", "sha256", "bytes", "version"}, "descriptor_executable")
    digest_value(descriptor["executable"]["sha256"], "descriptor_executable")
    need(set(descriptor["repository"]) == {"head", "ref"}, "descriptor_repository")
    need(set(descriptor["argv"]) == {"count", "prefix", "sha256"}, "descriptor_argv")
    need(descriptor["profile"] == FIXTURE_PROFILE or descriptor["argv"]["prefix"] == 0,
         "argv_prefix_forbidden_for_cli_profile")
    need(set(descriptor["environment"]) == {"names", "sha256"}, "descriptor_environment")
    need(set(descriptor["prompt"]) == {"bytes", "sha256"}, "descriptor_prompt")
    validate_limits(descriptor["limits"])
    return descriptor


def descriptor_digest(descriptor: dict) -> str:
    return digest_object(_DOMAIN, validate_descriptor(descriptor))


def session_profile_digest(descriptor: dict) -> str:
    """Immutable per-session workspace/policy/tool-profile/binary identity; resume must match."""
    validate_descriptor(descriptor)
    profile = {key: descriptor[key] for key in ("profile", "task_id", "host_id", "model", "cwd",
                                                "repository", "policy_sha256", "state_dir",
                                                "environment")}
    profile["executable"] = {k: descriptor["executable"][k] for k in ("path", "sha256", "version")}
    profile["argv_prefix"] = descriptor["argv"]["prefix"]
    return digest_object("integrity-claude-code-session-v1", profile)


def rebind(descriptor: dict, *, policy: ExecutorPolicy, executable: Path, cwd: Path,
           state_dir: Path, environment: dict, prompt: bytes, prefix_tokens: tuple = ()) -> str:
    """Recompute every identity at launch time; any drift refuses before claim/spawn."""
    validate_descriptor(descriptor)
    current = _assemble(
        profile=descriptor["profile"], prefix_tokens=prefix_tokens,
        task_id=descriptor["task_id"], session_id=descriptor["session_id"],
        run_id=descriptor["run_id"], request_id=descriptor["request_id"],
        host_id=descriptor["host_id"], mode=descriptor["mode"], policy=policy,
        executable=executable, executable_sha256=descriptor["executable"]["sha256"],
        executable_version=descriptor["executable"]["version"], cwd=cwd,
        expected_head=descriptor["repository"]["head"], state_dir=state_dir,
        environment=environment, prompt=prompt, limits=descriptor["limits"])
    need(current == descriptor, "descriptor_drift")
    return descriptor_digest(current)
