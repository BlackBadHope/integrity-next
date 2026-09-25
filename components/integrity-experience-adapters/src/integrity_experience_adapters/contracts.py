"""Pure, bounded transforms. No models, network, subprocesses or credential access.

These are candidate/preflight documents, NOT Guardian signed evidence or permits.
A calling host must use the existing Adapter SDK for admission and execution.
"""

from __future__ import annotations

import hashlib
import html
import json
import math
import re
from html.parser import HTMLParser
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Mapping
from urllib.parse import urlsplit

VERSION = "0.1.0rc3"
MAX_JSON_BYTES = 262_144
FEATURES = (
    "contract-parity", "transcription", "mcp-preflight", "realtime-preflight",
    "release-inventory", "tts-catalog", "inert-preview", "memory-estimate", "companion",
)
EXECUTION_REQUIREMENTS = (
    "existing-sdk-admission", "exact-target-change-intent",
    "one-use-target-guard", "independent-outcome-observer",
)


class ContractError(ValueError):
    """Fail-closed validation failure; messages never echo input contents."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ContractError(code)


def integer(value: Any, low: int, high: int, code: str) -> int:
    require(type(value) is int and low <= value <= high, code)
    return value


def text(value: Any, limit: int = 256) -> str:
    require(isinstance(value, str) and 0 < len(value) <= limit, "invalid_text")
    require(not any(ord(c) < 32 for c in value), "control_character")
    return value


def digest(value: Any) -> str:
    require(isinstance(value, str) and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", value)),
            "invalid_sha256")
    return value


def revision(value: Any) -> str:
    require(isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{40}", value)),
            "immutable_revision_required")
    return value


def exact(value: Any, keys: set[str]) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == keys, "unexpected_object_fields")
    return value


def canonical(value: Any) -> bytes:
    def check(node: Any, depth: int = 0) -> None:
        require(depth <= 48, "json_depth_limit")
        if node is None or type(node) in (str, bool, int):
            if isinstance(node, str):
                require(len(node) <= MAX_JSON_BYTES, "json_string_limit")
            if type(node) is int:
                require(node.bit_length() <= 256, "json_integer_limit")
            return
        if type(node) is float:
            require(math.isfinite(node), "non_finite_number")
        elif type(node) is list:
            require(len(node) <= 8192, "json_array_limit")
            for item in node:
                check(item, depth + 1)
        elif type(node) is dict:
            require(len(node) <= 8192 and all(type(k) is str for k in node),
                    "invalid_object_keys")
            for key, item in node.items():
                check(key, depth + 1)
                check(item, depth + 1)
        else:
            raise ContractError("non_json_value")
    try:
        check(value)
        result = json.dumps(value, sort_keys=True, ensure_ascii=False,
                            separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (UnicodeError, RecursionError, ValueError) as exc:
        raise ContractError("invalid_json_value") from exc
    require(len(result) <= MAX_JSON_BYTES, "json_size_limit")
    return result


def load_json(raw: bytes) -> Any:
    require(type(raw) is bytes and len(raw) <= MAX_JSON_BYTES, "json_size_limit")
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    def bad_constant(_: str) -> None:
        raise ContractError("non_finite_number")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=bad_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ContractError("invalid_json_document") from exc
    canonical(value)
    return value


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def path(value: Any) -> str:
    value = text(value, 512)
    p = PurePosixPath(value)
    require(not p.is_absolute() and str(p) == value and ".." not in p.parts
            and value != "." and not any(c in value for c in "\\:*?[]<>\"|")
            and all(part and not part.endswith((".", " ")) for part in p.parts),
            "unsafe_relative_path")
    # Portable inventories must not alias Windows reserved filenames.
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                *(f"lpt{i}" for i in range(1, 10))}
    require(all(part.split(".")[0].casefold() not in reserved for part in p.parts),
            "reserved_path")
    return value


def candidate(kind: str, payload: Any) -> dict[str, Any]:
    # Detach mutable caller objects; the returned digest identifies these bytes.
    snapshot = load_json(canonical(payload))
    return {"schema": "integrity-experience/" + kind + "/v1", "version": VERSION,
            "status": "candidate", "execution_authority": False,
            "payload_sha256": sha(canonical(snapshot)), "payload": snapshot}


def capabilities() -> dict[str, Any]:
    return candidate("capabilities", {
        "features": list(FEATURES), "network_calls": False, "model_execution": False,
        "capability_scope": "offline_contract_api_only",
        "optional_host_runtime": ["local-whisper", "local-espeak", "stdio-mcp-client",
                                  "webrtc-sdp-broker", "image-decoder", "git-inventory"],
        "host_runtime_auto_started": False,
        "credential_access": False, "canonical_log_writer": False,
        "signed_evidence": False, "runtime_admitted": False,
        "guardian_version_changed": False,
    })


def compare_contract(expected: bytes, actual: bytes) -> dict[str, Any]:
    left, right = canonical(load_json(expected)), canonical(load_json(actual))
    return candidate("parity", {"equal": left == right, "expected_sha256": sha(left),
                                "actual_sha256": sha(right), "comparison": "typed-json"})


def validate_workplan(plan: dict[str, Any]) -> dict[str, Any]:
    exact(plan, {"contract_sha256", "jobs"})
    digest(plan["contract_sha256"])
    jobs = plan["jobs"]
    require(type(jobs) is list and len(jobs) == 6, "six_roles_required")
    roles = {"contract", "baseline", "migration_a", "migration_b", "verification", "docs"}
    seen: set[str] = set()
    owners: list[tuple[str, str]] = []
    actors: dict[str, str] = {}
    for job in jobs:
        exact(job, {"role", "actor_ref", "write_paths"})
        role = text(job["role"])
        require(role in roles and role not in seen, "duplicate_or_unknown_role")
        seen.add(role)
        actors[role] = text(job["actor_ref"])
        writes = job["write_paths"]
        require(type(writes) is list and 1 <= len(writes) <= 32, "invalid_write_scope")
        for item in writes:
            current = path(item).casefold()
            require(not any(current == other or current.startswith(other + "/")
                            or other.startswith(current + "/") for other, _ in owners),
                    "overlapping_write_scope")
            owners.append((current, role))
    require(actors["verification"] not in {v for k, v in actors.items()
                                         if k != "verification"}, "self_verification")
    return candidate("workplan", {"plan": plan, "identity_verified": False,
        "runtime_lease_enforced": False,
        "handoff": ["contract", "baseline", ["migration_a", "migration_b"],
                    "verification", "docs"],
        "requires": ["authenticated_actor_binding", "external_path_leases",
                     "independent_verification_receipt"]})


def model_identity(model: Any) -> dict[str, Any]:
    exact(model, {"id", "revision", "weights_sha256", "license_id", "license_sha256"})
    text(model["id"])
    revision(model["revision"])
    digest(model["weights_sha256"])
    text(model["license_id"])
    digest(model["license_sha256"])
    return model


def transcript_observation(report: dict[str, Any]) -> dict[str, Any]:
    exact(report, {"audio_sha256", "duration_ms", "language", "model", "segments"})
    digest(report["audio_sha256"])
    duration = integer(report["duration_ms"], 1, 86_400_000, "invalid_duration")
    text(report["language"], 24)
    model_identity(report["model"])
    segments = report["segments"]
    require(type(segments) is list and len(segments) <= 4096, "invalid_segments")
    last_start = -1
    for segment in segments:
        exact(segment, {"start_ms", "end_ms", "text", "speaker"})
        start = integer(segment["start_ms"], 0, duration, "invalid_segment_start")
        integer(segment["end_ms"], start + 1, duration, "invalid_segment_end")
        require(start >= last_start, "unordered_segments")
        last_start = start
        text(segment["text"], 8192)
        if segment["speaker"] is not None:
            text(segment["speaker"], 64)
    return candidate("transcript", {"report": report,
        "epistemic_state": "unverified_backend_report", "source_bytes_verified": False,
        "text_is_instruction": False, "append_performed": False,
        "requires": ["media_hash_observation", "admitted_local_asr_backend",
                     "independent_transcript_quality_check", *EXECUTION_REQUIREMENTS]})


def select_tts(catalog: list[dict[str, Any]], language: str,
               reviewed_licenses: set[str]) -> dict[str, Any]:
    text(language, 24)
    require(type(catalog) is list and len(catalog) <= 128, "catalog_limit")
    require(type(reviewed_licenses) is set and len(reviewed_licenses) <= 128,
            "invalid_license_policy")
    for license_id in reviewed_licenses:
        text(license_id)
    eligible = []
    identities: set[tuple[str, str]] = set()
    for entry in catalog:
        exact(entry, {"model", "languages", "local", "voice_kind"})
        model = model_identity(entry["model"])
        identity = (model["id"], model["revision"])
        require(identity not in identities, "duplicate_model_identity")
        identities.add(identity)
        require(type(entry["local"]) is bool, "invalid_local_flag")
        require(type(entry["languages"]) is list and 1 <= len(entry["languages"]) <= 128,
                "invalid_languages")
        for lang in entry["languages"]:
            text(lang, 24)
        require(entry["voice_kind"] in ("stock", "cloned"), "invalid_voice_kind")
        if (entry["local"] and entry["voice_kind"] == "stock"
                and language in entry["languages"] and model["license_id"] in reviewed_licenses):
            eligible.append(model)
    eligible.sort(key=lambda item: (item["id"], item["revision"]))
    return candidate("tts-selection", {"language": language, "eligible": eligible,
        "selection_is_license_evidence": False, "synthesis_performed": False,
        "requires": ["verify_license_and_weight_bytes", "admitted_local_tts_backend",
                     "language_quality_measurement", *EXECUTION_REQUIREMENTS]})


def https_endpoint(value: Any) -> str:
    value = text(value, 2048)
    try:
        u = urlsplit(value)
        require(u.scheme == "https" and bool(u.hostname) and not u.username
                and not u.password and not u.query and not u.fragment
                and not any(c in value for c in "\\ \t\r\n") and u.port in (None, 443),
                "invalid_https_endpoint")
        require(u.hostname == u.hostname.encode("idna").decode("ascii")
                and u.netloc in (u.hostname, u.hostname + ":443"), "noncanonical_endpoint")
    except (ValueError, UnicodeError) as exc:
        raise ContractError("invalid_https_endpoint") from exc
    return value


def validate_mcp(config: dict[str, Any], allowed_endpoints: set[str]) -> dict[str, Any]:
    exact(config, {"model_id", "model_revision", "inference_location", "cloud_opt_in", "servers"})
    text(config["model_id"])
    revision(config["model_revision"])
    require(config["inference_location"] in ("local", "cloud"), "unknown_inference_location")
    require(type(config["cloud_opt_in"]) is bool, "invalid_cloud_opt_in")
    servers = config["servers"]
    require(type(servers) is list and 1 <= len(servers) <= 16, "invalid_servers")
    remote = config["inference_location"] == "cloud"
    for server in servers:
        require(type(server) is dict, "invalid_server")
        if server.get("transport") == "stdio":
            exact(server, {"transport", "executable", "executable_sha256", "args"})
            executable = text(server["executable"], 1024)
            posix, windows = PurePosixPath(executable), PureWindowsPath(executable)
            require(posix.is_absolute() or windows.is_absolute(), "absolute_executable_required")
            parts = windows.parts if windows.is_absolute() else posix.parts
            require(".." not in parts, "executable_traversal")
            name = (windows.name if windows.is_absolute() else posix.name).casefold()
            require(name not in {"npx", "npx.cmd", "uvx", "pip", "pip3", "npm", "npm.cmd",
                                 "sh", "bash", "cmd.exe", "powershell.exe", "pwsh", "pwsh.exe"},
                    "installer_or_shell_not_admitted")
            digest(server["executable_sha256"])
            args = server["args"]
            require(type(args) is list and len(args) <= 64, "invalid_argv")
            for arg in args:
                text(arg, 2048)
                require(not re.search(r"@(latest|main|master|next)\b|[\^*]", arg),
                        "floating_dependency")
                if "~" in arg:
                    # A drive-qualified Windows 8.3 alias is a literal path,
                    # not a package version range. Preserve its exact argv bytes.
                    short = PureWindowsPath(arg)
                    require(bool(re.match(r"^[A-Za-z]:[\\/]", arg))
                            and short.is_absolute() and ".." not in short.parts
                            and all("~" not in part or re.fullmatch(
                                r"[A-Za-z0-9_$%-]{1,6}~[1-9][0-9]*(?:\.[A-Za-z0-9_$%-]{1,3})?",
                                part) for part in short.parts), "floating_dependency")
        elif server.get("transport") == "http":
            exact(server, {"transport", "endpoint", "credential_ref"})
            endpoint = https_endpoint(server["endpoint"])
            require(endpoint in allowed_endpoints, "endpoint_not_allowlisted")
            require(bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}",
                                     text(server["credential_ref"], 64))), "invalid_credential_ref")
            remote = True
        else:
            raise ContractError("unknown_transport")
    require(not remote or config["cloud_opt_in"], "cloud_opt_in_required")
    return candidate("mcp-preflight", {"config": config, "connection_performed": False,
        "local_browser_implies_local_model": False, "confinement_verified": False,
        "requires": list(EXECUTION_REQUIREMENTS)})


def realtime_request(spec: dict[str, Any], *, allowed_origins: set[str],
                     allowed_endpoints: set[str], now: int) -> dict[str, Any]:
    exact(spec, {"origin", "endpoint", "model_id", "cloud_opt_in", "session_seconds"})
    origin = https_endpoint(spec["origin"])
    require(urlsplit(origin).path == "" and origin in allowed_origins, "origin_not_allowed")
    endpoint = https_endpoint(spec["endpoint"])
    require(endpoint in allowed_endpoints, "endpoint_not_allowlisted")
    text(spec["model_id"])
    require(spec["cloud_opt_in"] is True, "cloud_opt_in_required")
    seconds = integer(spec["session_seconds"], 1, 60, "session_ttl_limit")
    integer(now, 0, 2**53 - 61, "invalid_clock")
    return candidate("realtime-request", {"request": spec, "request_created_at": now,
        "request_expires_at": now + seconds, "credential_minted": False,
        "network_call_performed": False, "voice_is_authorization": False,
        "requires": ["authenticated_server_session", "csrf_protection", "rate_and_cost_limits",
                     "server_only_provider_key", "exact_offer_bound_broker_admission",
                     "no_store_response", "no_secret_or_audio_logging", *EXECUTION_REQUIREMENTS]})


def estimate_memory(spec: dict[str, Any]) -> dict[str, Any]:
    exact(spec, {"parameters", "weight_bits", "layers", "kv_heads", "head_dim",
                 "context_tokens", "concurrent_sequences", "kv_bits", "workspace_bytes"})
    parameters = integer(spec["parameters"], 1, 10**13, "invalid_parameters")
    weight_bits = integer(spec["weight_bits"], 1, 32, "invalid_weight_bits")
    require(weight_bits in {2, 3, 4, 8, 16, 32}, "unsupported_weight_bits")
    layers = integer(spec["layers"], 1, 2048, "invalid_layers")
    heads = integer(spec["kv_heads"], 1, 1024, "invalid_kv_heads")
    width = integer(spec["head_dim"], 1, 4096, "invalid_head_dim")
    tokens = integer(spec["context_tokens"], 1, 10**7, "invalid_context")
    sequences = integer(spec["concurrent_sequences"], 1, 1024, "invalid_concurrency")
    kv_bits = integer(spec["kv_bits"], 1, 32, "invalid_kv_bits")
    require(kv_bits in {4, 8, 16, 32}, "unsupported_kv_bits")
    workspace = integer(spec["workspace_bytes"], 0, 2**60, "invalid_workspace")
    weights = (parameters * weight_bits + 7) // 8
    cache = (2 * layers * heads * width * tokens * sequences * kv_bits + 7) // 8
    return candidate("memory-estimate", {"inputs": spec, "weight_bytes": weights,
        "kv_cache_bytes": cache, "workspace_bytes": workspace,
        "estimated_total_bytes": weights + cache + workspace, "measured": False,
        "allocation_guaranteed": False, "architecture": "dense-decoder-standard-kv",
        "excluded": ["quantization_metadata", "allocator_fragmentation",
                     "unbudgeted_activations", "nonstandard_attention_or_cache_architectures"]})


class _InertMarkup(HTMLParser):
    allowed = frozenset("p div span h1 h2 h3 h4 ul ol li table thead tbody tr th td "
                        "br hr code pre strong em b i blockquote".split())
    void = frozenset({"br", "hr"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.output: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        require(tag in self.allowed, "active_markup_not_supported")
        # No attributes, URLs, CSS, event handlers or namespaces survive.
        self.output.append("<" + tag + ">")

    def handle_endtag(self, tag: str) -> None:
        require(tag in self.allowed, "active_markup_not_supported")
        if tag not in self.void:
            self.output.append("</" + tag + ">")

    def handle_data(self, data: str) -> None:
        self.output.append(html.escape(data, quote=True))

    def handle_decl(self, decl: str) -> None:
        raise ContractError("declaration_not_supported")

    def unknown_decl(self, data: str) -> None:
        raise ContractError("declaration_not_supported")


def inert_preview(source: str) -> dict[str, Any]:
    require(type(source) is str, "invalid_source")
    try:
        raw = source.encode("utf-8")
    except UnicodeError as exc:
        raise ContractError("invalid_source_encoding") from exc
    require(len(raw) <= 16_384, "preview_size_limit")
    mode = "inert-markup"
    parser = _InertMarkup()
    try:
        parser.feed(source)
        parser.close()
        body = "".join(parser.output)
    except (ContractError, AssertionError):
        mode, body = "escaped-source", "<pre>" + html.escape(source, quote=True) + "</pre>"
    csp = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'"
    document = ('<!doctype html><html><head><meta charset="utf-8">'
                '<meta http-equiv="Content-Security-Policy" content="' +
                html.escape(csp, quote=True) + '"></head><body>' + body + '</body></html>')
    iframe = ('<iframe title="Untrusted candidate preview" sandbox="" '
              'referrerpolicy="no-referrer" allow="camera \'none\'; microphone \'none\'" '
              'srcdoc="' + html.escape(document, quote=True) + '"></iframe>')
    return candidate("preview", {"source_sha256": sha(raw), "render_mode": mode,
        "iframe_html": iframe, "javascript_supported": False, "external_resources": False,
        "browser_confinement_certified": False})


def validate_companion(manifest: dict[str, Any], asset: bytes) -> dict[str, Any]:
    exact(manifest, {"name", "asset", "asset_sha256", "width", "height", "frames", "fps"})
    text(manifest["name"], 64)
    name = path(manifest["asset"])
    require(type(asset) is bytes and 0 < len(asset) <= 8_388_608, "asset_size_limit")
    require(sha(asset) == digest(manifest["asset_sha256"]), "asset_digest_mismatch")
    png = asset.startswith(b"\x89PNG\r\n\x1a\n") and name.endswith(".png")
    webp = len(asset) >= 12 and asset[:4] == b"RIFF" and asset[8:12] == b"WEBP" and name.endswith(".webp")
    require(png or webp, "unsupported_asset")
    width = integer(manifest["width"], 1, 4096, "invalid_width")
    height = integer(manifest["height"], 1, 4096, "invalid_height")
    integer(manifest["fps"], 1, 24, "fps_limit")
    frames = manifest["frames"]
    require(type(frames) is list and 1 <= len(frames) <= 128, "frame_count_limit")
    for frame in frames:
        require(type(frame) is list and len(frame) == 4, "invalid_frame")
        x, y, w, h = frame
        integer(x, 0, width - 1, "frame_x_limit")
        integer(y, 0, height - 1, "frame_y_limit")
        integer(w, 1, width - x, "frame_width_limit")
        integer(h, 1, height - y, "frame_height_limit")
    return candidate("companion", {"manifest": manifest, "asset_bytes_verified": True,
        "image_decode_verified": False, "dimensions_verified": False,
        "installation_performed": False, "executable_hooks": False,
        "requires": ["bounded_image_decode", "original_or_reviewed_asset_license"]})


def release_inventory(files: Mapping[str, bytes], source_revision: str) -> dict[str, Any]:
    revision(source_revision)
    require(1 <= len(files) <= 512, "inventory_size_limit")
    names: set[str] = set()
    total = 0
    entries = []
    for name, data in sorted(files.items()):
        safe = path(name)
        require(safe.casefold() not in names, "portable_path_collision")
        names.add(safe.casefold())
        require(type(data) is bytes and len(data) <= 8_388_608, "file_size_limit")
        total += len(data)
        require(total <= 33_554_432, "inventory_bytes_limit")
        entries.append({"path": safe, "bytes": len(data), "sha256": sha(data)})
    return candidate("release-inventory", {"source_revision": source_revision, "files": entries,
        "git_source_verified": False, "signed": False, "stable": False,
        "source_authenticity": "caller_supplied_unverified",
        "requires": ["git_object_materialization", "exact_head_ci", "independent_review",
                     "owner_signed_release_inventory", "explicit_owner_promotion"]})
