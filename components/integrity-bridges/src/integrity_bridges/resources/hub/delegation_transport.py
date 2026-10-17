# SPDX-License-Identifier: Apache-2.0
"""Typed delegation DATA boundary; owner verification belongs to the adapter."""
from __future__ import annotations

from integrity_bridges.configuration import value as _integrity_value, require_config as _integrity_require_config

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re

BEGIN = "BEGIN_INTEGRITY_DELEGATED_TASK"
END = "END_INTEGRITY_DELEGATED_TASK"
PREPARE_BEGIN = "BEGIN_INTEGRITY_DELEGATION_PREPARE"
PREPARE_END = "END_INTEGRITY_DELEGATION_PREPARE"
MAX_FRAME_BYTES = 19744
MAX_RAW_CHARS = 8000
SOURCE_THREAD_ID = _integrity_value('delegation_source_thread_id')
CLIENT_SHA256 = _integrity_value('pin_9e26652d89d8')
CLIENT_PATH = Path(__file__).with_name("integrity_delegation_prepare_mcp.py")
LINUX_CLIENT_PATH = Path(__file__).with_name("integrity_delegation_prepare_linux_mcp.py")
LINUX_CLIENT_SHA256 = _integrity_value('pin_d03d5e208f04')
SUPPORTED_HOSTS = frozenset({"owner-host", "node-linux"})
TARGET_THREAD_ID = _integrity_value('delegation_target_thread_id')
IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z")
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
REQUEST_KEYS = {"protocol", "operation_id", "source_thread_id", "owner_ref", "target", "task", "not_before", "expires", "reply_thread_id"}
OWNER_KEYS = {"thread_id", "turn_id", "item_id", "room_id", "message_id", "prompt_sha256"}


class BoundaryError(ValueError):
    pass


def need(condition, code="invalid_delegation_frame"):
    if not condition:
        raise BoundaryError(code)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def identifier(value):
    return isinstance(value, str) and IDENTITY.fullmatch(value) is not None and not value.startswith("turnref:")


def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value)
        value[key] = item
    return value


def validate_prompt(prompt, target_thread_id, *, target_host_id="owner-host"):
    """Return the unchanged frame's request or None for an ordinary prompt."""
    need(isinstance(prompt, str) and bool(prompt.strip()) and "\x00" not in prompt, "invalid_prompt")
    if is_preparation_prompt(prompt):
        raise BoundaryError("preparation_recipe_requires_prepare_route")
    attempted = prompt.startswith(BEGIN) or prompt.rstrip().endswith(END)
    if not attempted:
        need(len(prompt) <= MAX_RAW_CHARS, "invalid_prompt")
        return None
    need(target_host_id in SUPPORTED_HOSTS, "delegation_target_host_not_supported")
    need(target_host_id != "node-linux" or target_thread_id == TARGET_THREAD_ID, "delegation_target_thread_not_supported")
    try:
        need(len(prompt.encode("utf-8")) < MAX_FRAME_BYTES)
        need(prompt.startswith(BEGIN + "\n") and prompt.endswith("\n" + END))
        body = prompt[len(BEGIN) + 1:-(len(END) + 1)]
        request = json.loads(body, object_pairs_hook=unique,
                             parse_constant=lambda _: (_ for _ in ()).throw(BoundaryError("invalid_delegation_frame")))
        need(isinstance(request, dict) and set(request) == REQUEST_KEYS)
        need(request["protocol"] == "integrity/delegated-task/v1"
             and identifier(request["operation_id"]) and request["source_thread_id"] == SOURCE_THREAD_ID
             and request["reply_thread_id"] == SOURCE_THREAD_ID)
        need(request["target"] == {"host_id": target_host_id, "thread_id": target_thread_id})
        need(isinstance(request["task"], str) and bool(request["task"].strip())
             and len(request["task"].encode("utf-8")) <= 16000)
        need(type(request["not_before"]) is int and type(request["expires"]) is int
             and 0 <= request["not_before"] < request["expires"]
             and request["expires"] - request["not_before"] <= 86400)
        owner = request["owner_ref"]
        need(isinstance(owner, dict) and set(owner) == OWNER_KEYS
             and all(identifier(owner[key]) for key in ("thread_id", "turn_id", "item_id"))
             and isinstance(owner["prompt_sha256"], str) and SHA256.fullmatch(owner["prompt_sha256"]) is not None)
        need((owner["room_id"] is None and owner["message_id"] is None)
             or (identifier(owner["room_id"]) and identifier(owner["message_id"])))
        need(body == canonical(request))
        return request
    except BoundaryError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, KeyError):
        raise BoundaryError("invalid_delegation_frame") from None


def prompt_schema():
    # anyOf permits shorter frames; runtime enforces canonical DATA and UTF-8.
    return {"anyOf": [
        {"type": "string", "minLength": 1, "maxLength": MAX_RAW_CHARS},
        {"type": "string", "minLength": 1, "maxLength": MAX_FRAME_BYTES - 1,
         "pattern": "^" + BEGIN + "\\n[\\s\\S]+\\n" + END + "$"}]}


def _client(host_id="owner-host"):
    need(host_id in SUPPORTED_HOSTS, "delegation_target_host_not_supported")
    path = CLIENT_PATH if host_id == "owner-host" else LINUX_CLIENT_PATH
    digest = CLIENT_SHA256 if host_id == "owner-host" else LINUX_CLIENT_SHA256
    try:
        need(path.is_file() and not path.is_symlink()
             and not getattr(path, "is_junction", lambda: False)(), "delegation_prepare_client_unavailable")
        raw = path.read_bytes()
        need(hashlib.sha256(raw).hexdigest() == digest, "delegation_prepare_client_pin_mismatch")
        spec = importlib.util.spec_from_file_location("integrity_pinned_prepare_client", path)
        module = importlib.util.module_from_spec(spec)
        # Execute the verified bytes, not a second pathname read or a stale .pyc.
        exec(compile(raw, str(path), "exec"), module.__dict__)
        return module
    except BoundaryError:
        raise
    except Exception:
        raise BoundaryError("delegation_prepare_client_unavailable") from None


def prepare_definition():
    definition = copy.deepcopy(_client().TOOL_SPEC)
    definition["inputSchema"]["properties"]["host_id"]["enum"] = sorted(SUPPORTED_HOSTS)
    return definition


def prepare(arguments, *, host_id="owner-host"):
    need(arguments.get("host_id", host_id) == host_id, "delegation_target_host_mismatch")
    return _client(host_id).prepare_delegated_task(arguments)


def is_preparation_prompt(prompt):
    return isinstance(prompt, str) and (prompt.startswith(PREPARE_BEGIN)
                                       or prompt.rstrip().endswith(PREPARE_END))


def preparation_arguments(prompt, target_thread_id):
    """Prepare-only compatibility DATA for clients with a cached tool catalog.

    This never forwards the recipe as executable text. The existing pinned
    helper independently reads the genuine human source and returns its frame.
    """
    need(identifier(target_thread_id), "invalid_preparation_target")
    need(isinstance(prompt, str) and len(prompt) <= MAX_RAW_CHARS and "\x00" not in prompt,
         "invalid_preparation_recipe")
    need(prompt.startswith(PREPARE_BEGIN + "\n") and prompt.endswith("\n" + PREPARE_END),
         "invalid_preparation_recipe")
    try:
        body = prompt[len(PREPARE_BEGIN) + 1:-(len(PREPARE_END) + 1)]
        recipe = json.loads(body, object_pairs_hook=unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(BoundaryError("invalid_preparation_recipe")))
        need(isinstance(recipe, dict) and set(recipe) == {"protocol", "owner_message_id", "task"}
             and recipe["protocol"] == "integrity/delegation-prepare-request/v1"
             and identifier(recipe["owner_message_id"])
             and isinstance(recipe["task"], str) and bool(recipe["task"].strip())
             and len(recipe["task"].encode("utf-8")) <= 16000
             and body == canonical(recipe), "invalid_preparation_recipe")
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise BoundaryError("invalid_preparation_recipe") from None
    return {"target_thread_id": target_thread_id, "task": recipe["task"],
            "owner_message_id": recipe["owner_message_id"]}


def prepare_via_existing_sender(arguments, *, host_id="owner-host"):
    need(set(arguments) == {"thread_id", "prompt"}, "preparation_sender_options_forbidden")
    result = prepare(preparation_arguments(arguments["prompt"], arguments["thread_id"]), host_id=host_id)
    result = copy.deepcopy(result)
    result["delivery_mode"] = "prepare-only"
    result["native_send_performed"] = False
    return result
