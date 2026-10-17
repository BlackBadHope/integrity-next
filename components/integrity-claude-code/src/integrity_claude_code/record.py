"""Closed, content-free terminal record: the only thing the ledger caches and returns.

Every string is an enum member or a digest; untrusted provider strings never pass
through verbatim. Anything outside the schema is refused, not truncated.
"""
from __future__ import annotations

import re

from .canonical import digest_value, need

CLASSIFICATIONS = frozenset({
    "cancelled", "protocol_violation", "output_limit", "deadline", "supervisor_error",
    "missing_init", "missing_result", "reported_error", "result_exit_mismatch",
    "stdin_incomplete", "reported_success", "not_started"})
TERMINATIONS = frozenset({"cancelled", "deadline", "stdout_limit", "stderr_limit",
                          "protocol_violation", "callback_error", "io_error"})
VIOLATIONS = frozenset({
    "line_limit", "blank_line", "event_shape", "event_limit", "session_mismatch", "missing_init",
    "duplicate_init", "result_shape", "duplicate_result", "conflicting_result",
    "trailing_after_result", "truncated_line", "malformed_json_size", "malformed_json_utf8",
    "malformed_json_syntax", "malformed_json_nonfinite", "malformed_json_duplicate_key",
    "malformed_json_lone_surrogate", "malformed_json_depth", "init_tools_mismatch",
    "init_mcp_mismatch", "uncataloged_tool_use", "tool_use_shape", "init_model_mismatch",
    "init_version_mismatch", "init_auth_source_mismatch", "init_permission_mismatch"})
REASONS = frozenset({
    "authority_denied", "gate_outcome_unknown", "cancelled_before_start",
    "cancelled_before_resume", "resume_refused", "spawn_refused", "job_assign_refused",
    "preflight_rejected", "executable_digest_mismatch", "executable_final_path_mismatch",
    "suspended_kill_unverified", "supervisor_exception", "running_mark_missing",
    "stop_not_verified", "authority_spent_not_started", "launch_outcome_unknown",
    "tool_effect_unknown", "coordinator_failure"})
EVENT_TYPES = frozenset({"system", "assistant", "user", "result", "stream_event", "unknown"})
RESULT_SUBTYPES = frozenset({"success", "error_max_turns", "error_during_execution",
                             "error_max_budget_usd", "error_max_structured_output_retries",
                             "unrecognized"})
PERMISSION_MODES = frozenset({"default", "plan", "dontAsk", "acceptEdits", "bypassPermissions",
                              "auto", "unrecognized", "absent"})
CATALOG_KEYS = frozenset({"read_file", "write_file", "edit_file", "list_dir"})
MEDIATION_KEYS = ("calls", "effects", "denied", "unknown", "foreign_peers")
_WINERROR = re.compile(r"(.+)_winerror_([0-9]{1,10})")
_FIELDS = {"classification", "reason", "winerror", "violation", "descriptor_sha256", "exit_code",
           "termination", "started", "stop_verified", "stop", "orphans_terminated", "stdin",
           "stdout", "stderr", "events", "event_types", "init", "provider_result",
           "provider_claim_only", "verified_success", "tool_uses", "mediation"}


def reason_of(code: str) -> tuple[str, int | None]:
    """Map an internal failure code to a closed reason plus an optional Win32 error number."""
    winerror = None
    match = _WINERROR.fullmatch(code) if type(code) is str else None
    if match:
        code, winerror = match[1], int(match[2])
    return (code if code in REASONS else "preflight_rejected"), winerror


def _int(value, low=0, high=2**32 - 1, *, optional=False):
    if optional and value is None:
        return
    need(type(value) is int and low <= value <= high, "record_integer")


def _bool(value, *, optional=False):
    need(type(value) is bool or (optional and value is None), "record_bool")


def _digest(value, *, optional=False):
    if optional and value is None:
        return
    digest_value(value, "record_digest")


def _enum(value, members, *, optional=False):
    need((optional and value is None) or value in members, "record_enum")


def _closed(value, keys, *, optional=False):
    if optional and value is None:
        return False
    need(type(value) is dict and set(value) == set(keys), "record_shape")
    return True


def validate_record(record: dict) -> dict:
    need(type(record) is dict and set(record) == _FIELDS, "record_shape")
    _enum(record["classification"], CLASSIFICATIONS)
    _enum(record["reason"], REASONS, optional=True)
    _int(record["winerror"], optional=True)
    _enum(record["violation"], VIOLATIONS, optional=True)
    _digest(record["descriptor_sha256"])
    _int(record["exit_code"], optional=True)
    _enum(record["termination"], TERMINATIONS, optional=True)
    _bool(record["started"])
    _bool(record["stop_verified"])
    if _closed(record["stop"], ("verified", "active_processes", "assigned_processes",
                                "processes_total", "handles_held", "handles_signaled",
                                "processes_unopened", "pid_reuse_detected", "zero_notification"),
               optional=True):
        stop = record["stop"]
        _bool(stop["verified"])
        _bool(stop["zero_notification"])
        for key in ("active_processes", "assigned_processes", "processes_total"):
            _int(stop[key], optional=True)
        for key in ("handles_held", "handles_signaled", "processes_unopened", "pid_reuse_detected"):
            _int(stop[key])
    _int(record["orphans_terminated"])
    if _closed(record["stdin"], ("bytes", "written", "complete"), optional=True):
        _int(record["stdin"]["bytes"])
        _int(record["stdin"]["written"])
        _bool(record["stdin"]["complete"])
    for name in ("stdout", "stderr"):
        if _closed(record[name], ("bytes", "sha256", "overflow"), optional=True):
            _int(record[name]["bytes"])
            _digest(record[name]["sha256"])
            _bool(record[name]["overflow"])
    _int(record["events"])
    need(type(record["event_types"]) is dict and set(record["event_types"]) <= EVENT_TYPES,
         "record_event_types")
    for count in record["event_types"].values():
        _int(count)
    if _closed(record["init"], ("model_matches", "version_matches", "api_key_source_matches",
                                "api_key_source_sha256", "permission_mode", "tools_count",
                                "tools_sha256", "mcp_servers_count"), optional=True):
        init = record["init"]
        _bool(init["model_matches"])
        _bool(init["version_matches"], optional=True)
        _bool(init["api_key_source_matches"], optional=True)
        _digest(init["api_key_source_sha256"], optional=True)
        _enum(init["permission_mode"], PERMISSION_MODES)
        _int(init["tools_count"])
        _digest(init["tools_sha256"])
        _int(init["mcp_servers_count"])
    if _closed(record["provider_result"], ("subtype", "is_error", "num_turns", "result_bytes",
                                           "result_sha256", "event_sha256"), optional=True):
        result = record["provider_result"]
        _enum(result["subtype"], RESULT_SUBTYPES)
        _bool(result["is_error"])
        _int(result["num_turns"], optional=True)
        _int(result["result_bytes"])
        _digest(result["result_sha256"])
        _digest(result["event_sha256"])
    need(type(record["tool_uses"]) is dict and set(record["tool_uses"]) <= CATALOG_KEYS,
         "record_tool_uses")
    for count in record["tool_uses"].values():
        _int(count)
    if _closed(record["mediation"], MEDIATION_KEYS, optional=True):
        for key in MEDIATION_KEYS:
            _int(record["mediation"][key])
    need(record["provider_claim_only"] is True and record["verified_success"] is False,
         "record_claim_boundary")
    return record


def empty_record(classification: str, descriptor_sha256: str, *, reason: str | None = None,
                 winerror: int | None = None) -> dict:
    return validate_record({
        "classification": classification, "reason": reason, "winerror": winerror,
        "violation": None, "descriptor_sha256": descriptor_sha256, "exit_code": None,
        "termination": None, "started": False, "stop_verified": False, "stop": None,
        "orphans_terminated": 0, "stdin": None, "stdout": None, "stderr": None, "events": 0,
        "event_types": {}, "init": None, "provider_result": None,
        "provider_claim_only": True, "verified_success": False, "tool_uses": {},
        "mediation": None})
