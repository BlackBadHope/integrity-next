#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Lazy MCP broker that retains one upstream transport for logical contexts."""

from __future__ import annotations

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config
from integrity_client_memory.catalogue import load_owner_catalogue as _load_owner_catalogue


import argparse
import hashlib
import json
import os
import queue
import re
import secrets
import subprocess
import sys
import threading
import time
import tomllib
from pathlib import Path
from typing import Any

import integrity_client_turn_envelope as turn_envelope

import types as _attachment_types
_attachment_retrieval = _attachment_types.ModuleType('integrity_attachment_retrieval')
_attachment_retrieval_source = '# SPDX-License-Identifier: Apache-2.0\n"""Bounded attachment search context. Content never changes admission or authority.\n\nThe caller fixes allowed_root; the broker uses only ~/.codex/attachments.\nNo content is evaluated, executed, persisted, or treated as owner instructions.\n"""\nfrom __future__ import annotations\n\nfrom integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config\n\nimport hashlib\nimport os\nfrom pathlib import Path\nimport re\nimport stat\n\nPROTOCOL = "integrity-attachment-search-context/v1"\nMAX_BYTES = 256 * 1024\nMAX_TOPIC_CHARS = 200\n_HEX = re.compile(r"[a-f0-9]{64}\\Z")\n_DIGEST = re.compile(r"sha256:[a-f0-9]{64}\\Z")\n_LINK = re.compile(r"- \\[[^\\]\\r\\n]+\\]\\((?:<(?P<angle>[^<>\\r\\n]+)>|(?P<plain>[^()\\r\\n]+))\\)\\Z")\n_HEADING_FILE = re.compile(r"## [^:\\r\\n]+\\.(?:txt|md): (?P<path>[^\\r\\n]+)\\Z", re.I)\n\n\ndef _sha(raw: bytes) -> str:\n    return hashlib.sha256(raw).hexdigest()\n\n\ndef _attachment_path(prompt: str) -> Path | None:\n    """Recognize only one explicit file and an exact, empty owner request."""\n    lines = prompt.replace("\\r\\n", "\\n").strip().split("\\n")\n    if len(lines) < 3 or lines[0] not in (\n        "# Files mentioned by the user", "# Files mentioned by the user:"\n    ):\n        return None\n    headers = [i for i, line in enumerate(lines) if line == "## My request:"]\n    if len(headers) != 1 or any(line.strip() for line in lines[headers[0] + 1:]):\n        return None\n    files = [line for line in lines[1:headers[0]] if line.strip()]\n    if len(files) != 1:\n        return None\n    match = _LINK.fullmatch(files[0])\n    if match is not None:\n        name = match["angle"] or match["plain"]\n    else:\n        heading = _HEADING_FILE.fullmatch(files[0])\n        if heading is None:\n            return None\n        name = heading["path"]\n    # Reject URL encodings, device paths, ADS, traversal and Win32 aliases.\n    if (not name or any(ord(c) < 32 for c in name) or "%" in name\n            or name.startswith(("\\\\\\\\", "//"))):\n        return None\n    path = Path(name)\n    if (not path.is_absolute() or path.suffix.casefold() not in {".txt", ".md"}\n            or any(part in {".", ".."} or part.endswith((" ", "."))\n                   or ":" in part for part in path.parts[1:])):\n        return None\n    return path\n\n\ndef _fingerprint(info):\n    # Python 3.12 Windows lstat and CRT fstat expose different ctime semantics.\n    # The Windows handle denies writes/deletion; compare stable file identity,\n    # mtime, size and attributes across path/handle rather than those ctimes.\n    changed = info.st_ctime_ns if os.name != "nt" else None\n    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,\n            info.st_mtime_ns, changed,\n            getattr(info, "st_file_attributes", 0))\n\n\ndef _snapshot(path: Path):\n    """Reject every symlink/reparse ancestor before and after the read."""\n    result = []\n    for member in reversed((path, *path.parents)):\n        info = member.lstat()\n        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:\n            raise ValueError("attachment reparse path")\n        if member == path:\n            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BYTES:\n                raise ValueError("attachment size or file type")\n        elif not stat.S_ISDIR(info.st_mode):\n            raise ValueError("attachment ancestor is not a directory")\n        result.append((str(member), _fingerprint(info)))\n    return tuple(result)\n\n\ndef _open_windows(path: Path) -> int:\n    """Open final reparse point itself, deny writers/deletion, verify final path."""\n    import ctypes\n    from ctypes import wintypes as w\n    import msvcrt\n\n    kernel = ctypes.WinDLL("kernel32", use_last_error=True)\n    create = kernel.CreateFileW\n    create.argtypes = (w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID,\n                       w.DWORD, w.DWORD, w.HANDLE)\n    create.restype = w.HANDLE\n    final = kernel.GetFinalPathNameByHandleW\n    final.argtypes = (w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD)\n    final.restype = w.DWORD\n    close = kernel.CloseHandle\n    close.argtypes = (w.HANDLE,)\n    close.restype = w.BOOL\n    # GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, OPEN_REPARSE_POINT|SEQUENTIAL_SCAN.\n    handle = create(str(path), 0x80000000, 1, None, 3, 0x08200000, None)\n    if handle == ctypes.c_void_p(-1).value:\n        raise OSError(ctypes.get_last_error(), "attachment open failed")\n    try:\n        buffer = ctypes.create_unicode_buffer(32768)\n        length = final(handle, buffer, len(buffer), 0)\n        if not 0 < length < len(buffer):\n            raise ValueError("attachment handle path unavailable")\n        actual = buffer.value\n        if actual.startswith("\\\\\\\\?\\\\"):\n            actual = actual[4:]\n        if os.path.normcase(os.path.normpath(actual)) != os.path.normcase(str(path)):\n            raise ValueError("attachment handle escaped expected path")\n        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)\n        handle = None  # The descriptor now owns the handle.\n        return descriptor\n    finally:\n        if handle is not None:\n            close(handle)\n\n\ndef _open_posix(path: Path) -> int:\n    """Traverse through pinned directory descriptors; no ancestor symlinks."""\n    directories = []\n    try:\n        current = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n        directories.append(current)\n        for part in path.parts[1:-1]:\n            current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,\n                              dir_fd=current)\n            directories.append(current)\n        return os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current)\n    finally:\n        for descriptor in reversed(directories):\n            os.close(descriptor)\n\n\ndef _read_stable(path: Path) -> bytes:\n    before = _snapshot(path)\n    descriptor = _open_windows(path) if os.name == "nt" else _open_posix(path)\n    try:\n        opened = os.fstat(descriptor)\n        if (_fingerprint(opened) != before[-1][1]\n                or getattr(opened, "st_file_attributes", 0) & 0x400):\n            raise ValueError("attachment changed before open")\n        chunks = []\n        size = 0\n        while size <= MAX_BYTES:\n            chunk = os.read(descriptor, min(65536, MAX_BYTES + 1 - size))\n            if not chunk:\n                break\n            chunks.append(chunk)\n            size += len(chunk)\n        raw = b"".join(chunks)\n        if (not 0 < len(raw) <= MAX_BYTES or len(raw) != opened.st_size\n                or _fingerprint(os.fstat(descriptor)) != _fingerprint(opened)\n                or _snapshot(path) != before):\n            raise ValueError("attachment changed while reading")\n        return raw\n    finally:\n        os.close(descriptor)\n\n\ndef derive_attachment_context(prompt: str, prompt_binding: dict,\n                              allowed_root: Path) -> dict | None:\n    """Return search-only provenance, or None for any unsupported/unbound input.\n\n    prompt_binding is the broker\'s validated own-turn binding, not model input.\n    The original prompt and its admission binding are never modified.\n    """\n    try:\n        if not isinstance(prompt, str) or not isinstance(prompt_binding, dict):\n            return None\n        prompt_digest = prompt_binding.get("prompt_sha256")\n        turn_digest = prompt_binding.get("turn_ref_digest")\n        thread = (prompt_binding.get("hashes") or {}).get("thread_id")\n        if (not isinstance(prompt_digest, str) or not _HEX.fullmatch(prompt_digest)\n                or _sha(prompt.encode("utf-8")) != prompt_digest\n                or not isinstance(turn_digest, str) or not _DIGEST.fullmatch(turn_digest)\n                or not isinstance(thread, str) or not _HEX.fullmatch(thread)):\n            return None\n        path = _attachment_path(prompt)\n        root = Path(allowed_root)\n        if path is None or not root.is_absolute():\n            return None\n        # Check lexical containment before resolving anything; never probe outsiders.\n        if not path.is_relative_to(root) or path == root:\n            return None\n        _snapshot(path)\n        resolved_root = root.resolve(strict=True)\n        resolved = path.resolve(strict=True)\n        if not resolved.is_relative_to(resolved_root) or resolved == resolved_root:\n            return None\n        raw = _read_stable(resolved)\n        text = raw.decode("utf-8-sig")\n        if any(ord(c) < 32 and c not in "\\t\\r\\n" for c in text):\n            return None\n        topic = " ".join(text.split())[:MAX_TOPIC_CHARS].strip()\n        if not topic:\n            return None\n        return {\n            "protocol": PROTOCOL,\n            "prompt_sha256": prompt_digest,\n            "turn_ref_digest": turn_digest,\n            "thread_sha256": thread,\n            "attachment_sha256": _sha(raw),\n            "attachment_path_sha256": _sha(os.path.normcase(str(resolved)).encode("utf-8")),\n            "topic": topic,\n            "authority": "none",\n        }\n    except (OSError, ValueError, TypeError, AttributeError, UnicodeError, OverflowError):\n        return None\n'
_attachment_retrieval_sha256 = _integrity_value('pin_498c7592d714')
assert hashlib.sha256(_attachment_retrieval_source.encode('utf-8')).hexdigest() == _attachment_retrieval_sha256
exec(compile(_attachment_retrieval_source, '<managed-attachment-retrieval>', 'exec'), _attachment_retrieval.__dict__)

import types as _route_types
_local_routes = _route_types.ModuleType("integrity_local_routes")
exec(compile('# SPDX-License-Identifier: Apache-2.0\n"""Owner-configured local navigation. Never changes canonical admission or authority."""\nfrom __future__ import annotations\n\nfrom integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config\nimport copy\nimport hashlib\nimport ipaddress\nimport json\nimport os\nfrom pathlib import Path\nimport re\nimport tempfile\nimport time\n\nPROTOCOL = \'integrity-local-operational-context/v1\'\nMAX_AGE = 3600\n\n\ndef digest(value):\n    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()\n\n\ndef owner_text(prompt):\n    # Attachment wrappers are data; preserve the original prompt in its own binding.\n    return prompt.split(\'## My request:\', 1)[-1].strip()\n\n\ndef entities(text):\n    result = {}\n    ips = []\n    for match in re.findall(r\'(?<![\\d.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\d.])\', text):\n        try:\n            ipaddress.IPv4Address(match)\n            ips.append(match)\n        except ipaddress.AddressValueError:\n            pass\n    if ips:\n        result[\'olt\'] = ips[0]\n    serial = re.search(r\'\\bFTTH\\s*:?\\s*([0-9A-F]{8})\\b\', text, re.I)\n    if serial:\n        result[\'serial\'] = \'FTTH:\' + serial[1].upper()\n    port = re.search(r\'(?:gpon\\s*)?(\\d+/\\d+\\s*:\\s*\\d+)\', text, re.I)\n    if port:\n        result[\'interface\'] = re.sub(r\'\\s\', \'\', port[1])\n    return result\n\n\ndef _atomic(path, value):\n    path = Path(path)\n    for parent in (path, *path.parents):\n        if parent.exists():\n            info = parent.lstat()\n            if parent.is_symlink() or getattr(info, \'st_file_attributes\', 0) & 0x400:\n                raise ValueError(\'reparse state path\')\n    path.parent.mkdir(parents=True, exist_ok=True)\n    fd, name = tempfile.mkstemp(prefix=\'.navigation-\', dir=path.parent)\n    try:\n        with os.fdopen(fd, \'w\', encoding=\'utf-8\') as stream:\n            json.dump(value, stream, ensure_ascii=False)\n            stream.flush()\n            os.fsync(stream.fileno())\n        os.replace(name, path)\n    finally:\n        if os.path.exists(name):\n            os.unlink(name)\n\n\nclass Navigator:\n    def __init__(self, catalog, state_root, workspace):\n        self.catalog = copy.deepcopy(catalog)\n        self.state_root = Path(state_root)\n        self.workspace = Path(workspace)\n        self.selected = None\n        self.catalog_digest = \'sha256:\' + digest(self.catalog)\n\n    def admit(self, prompt, binding, snapshot_id, now=None):\n        self.selected = None\n        now = time.time() if now is None else now\n        hashes = binding.get(\'hashes\') or {}\n        thread = hashes.get(\'thread_id\')\n        scope = binding.get(\'project_scope_sha256\')\n        if not (isinstance(snapshot_id, str) and re.fullmatch(r\'sha256:[a-f0-9]{64}\', snapshot_id)\n                and isinstance(thread, str) and re.fullmatch(r\'[a-f0-9]{64}\', thread)\n                and isinstance(scope, str) and re.fullmatch(r\'(?:sha256:)?[a-f0-9]{64}\', scope)):\n            return {\'status\': \'unbound\', \'external_action_authority\': False}\n        key = digest([thread, scope])\n        path = self.state_root / (\'navigation-\' + key + \'.json\')\n        previous = None\n        if path.is_file() and not path.is_symlink() and path.stat().st_size <= 16384:\n            try:\n                previous = json.loads(path.read_text(encoding=\'utf-8\'))\n                if (previous.get(\'key\') != key or not 0 <= now - previous[\'at\'] <= MAX_AGE):\n                    previous = None\n            except (ValueError, KeyError, OSError, TypeError):\n                previous = None\n        text = owner_text(prompt)\n        found = entities(text)\n        is_task = bool(re.search(r\'влан|vlan|бидиком|bdcom|gpon\', text, re.I))\n        continuation = bool(re.search(r\'в\\s+onu|в таком случае|дефолтн|продолж|тогда|эт[а-я]+\\s+onu\', text, re.I))\n        forbidden_carry = bool(re.search(r\'друг(?:ая|ой|ую)|нов(?:ая|ый|ую)|забудь|смен[аи]\', text, re.I))\n        inherit = bool(previous and continuation and not forbidden_carry)\n        if inherit and any(k in previous[\'entities\'] and previous[\'entities\'][k] != v for k, v in found.items()):\n            inherit = False\n        target = {**(previous[\'entities\'] if inherit else {}), **found}\n        if not is_task or not (found or inherit):\n            # An unrelated intent is a boundary; do not revive an older target later.\n            _atomic(path, {\'key\': key, \'at\': now, \'entities\': {}, \'source\': binding.get(\'prompt_sha256\')})\n            return {\'status\': \'no-matching-task\', \'external_action_authority\': False}\n        value = {\'key\': key, \'at\': now, \'entities\': target, \'source\': binding.get(\'prompt_sha256\')}\n        _atomic(path, value)\n        candidates = []\n        for route in self.catalog[\'paths\']:\n            if all(target.get(k) == v for k, v in route[\'target\'].items()):\n                candidates.append(route)\n        if len(candidates) != 1:\n            return {\'status\': \'incomplete-or-ambiguous-target\', \'entities\': target, \'external_action_authority\': False}\n        route = candidates[0]\n        for member in route[\'evidence\']:\n            source = (self.workspace / member[\'path\']).resolve()\n            if not source.is_relative_to(self.workspace.resolve()) or not source.is_file() or source.is_symlink():\n                return {\'status\': \'adapter-unavailable\', \'external_action_authority\': False}\n            if hashlib.sha256(source.read_bytes()).hexdigest() != member[\'sha256\']:\n                return {\'status\': \'adapter-drift\', \'external_action_authority\': False}\n        self.selected = {\'protocol\': PROTOCOL, \'status\': \'navigation-ready\',\n            \'source\': \'owner-configured-client-catalog\', \'canonical_graph_admission\': False,\n            \'catalog_digest\': self.catalog_digest, \'snapshot_id\': snapshot_id,\n            \'path_id\': route[\'path_id\'], \'entities\': target,\n            \'inherited\': inherit, \'inherited_prompt_sha256\': previous.get(\'source\') if inherit else None,\n            \'current_prompt_sha256\': binding.get(\'prompt_sha256\'),\n            \'hops\': route[\'hops\'], \'evidence\': route[\'evidence\'],\n            \'external_action_authority\': False, \'automatic_execution\': False,\n            \'fresh_target_readback_required\': True, \'stale_evidence_is_live_acceptance\': False}\n        return self.selected\n\n    def remaining(self, goal, last_hop, snapshot_id):\n        route = self.selected\n        if not route or route[\'snapshot_id\'] != snapshot_id:\n            return {\'status\': \'blocked\', \'reason\': \'local-route-not-bound\', \'external_action_authority\': False}\n        supplied = entities(goal)\n        if any(route[\'entities\'].get(k) != v for k, v in supplied.items()):\n            return {\'status\': \'blocked\', \'reason\': \'target-mismatch\', \'external_action_authority\': False}\n        ids = [hop[\'hop_id\'] for hop in route[\'hops\']]\n        if last_hop not in ids:\n            return {\'status\': \'blocked\', \'reason\': \'unknown-last-hop\', \'external_action_authority\': False}\n        result = copy.deepcopy(route)\n        result[\'remaining_hops\'] = result.pop(\'hops\')[ids.index(last_hop) + 1:]\n        result[\'completed_hop_assertion_verified\'] = False\n        # No invented savings: only the caller-specified suffix, not executed hops.\n        return result\n\n\ndef augment(result, local, limit=8192):\n    result = copy.deepcopy(result)\n    if result.get(\'isError\') or not result.get(\'content\'):\n        return result\n    try:\n        value = json.loads(result[\'content\'][0][\'text\'])\n    except (ValueError, KeyError, TypeError):\n        return result\n    value[\'operational_context\'] = local\n    if local.get(\'status\') == \'navigation-ready\':\n        value[\'context_text\'] = (\'LOCAL NAVIGATION (no authority): \' + json.dumps(local, ensure_ascii=False)\n                                 + \'\\n\' + value.get(\'context_text\', \'\')[:600])\n        value.setdefault(\'presentation\', {})[\'context_text_truncated\'] = True\n    encoded = json.dumps(value, ensure_ascii=False, separators=(\',\', \':\'))\n    def transport_size(text):\n        candidate = copy.deepcopy(result)\n        candidate[\'content\'][0][\'text\'] = text\n        return len(json.dumps(candidate, ensure_ascii=False, separators=(\',\', \':\')).encode())\n    while transport_size(encoded) > limit and value.get(\'context_text\'):\n        value[\'context_text\'] = value[\'context_text\'][:max(0, len(value[\'context_text\']) - 256)]\n        encoded = json.dumps(value, ensure_ascii=False, separators=(\',\', \':\'))\n    if transport_size(encoded) > limit:\n        # Keep canonical diagnostics intact rather than silently cutting them.\n        return result\n    result[\'content\'][0][\'text\'] = encoded\n    return result\n\n\ndef record_outcome(path, *, operation_id, target, sent, writes, independently_verified, evidence_sha256, requested_no_event_reason=None, limitations=None, context_admission_id=None):\n    """Local accounting is separate from a signed canonical terminal receipt."""\n    if type(sent) is not bool or type(writes) is not int or writes < 0 or type(independently_verified) is not bool:\n        raise ValueError(\'invalid outcome\')\n    if requested_no_event_reason == \'read-only\' and (sent or writes):\n        raise ValueError(\'mutation cannot close as read-only\')\n    if not re.fullmatch(r\'[a-f0-9]{64}\', evidence_sha256):\n        raise ValueError(\'outcome evidence digest required\')\n    if context_admission_id is not None and not re.fullmatch(r\'sha256:[a-f0-9]{64}\', context_admission_id):\n        raise ValueError(\'invalid current admission binding\')\n    status = (\'confirmed-success\' if independently_verified else \'unknown-outcome\') if sent else \'not-sent\'\n    value = {\'protocol\': \'integrity-local-operation-outcome/v1\', \'operation_id\': operation_id,\n             \'target\': target, \'sent\': sent, \'writes\': writes, \'outcome\': status,\n             \'evidence_sha256\': evidence_sha256, \'canonical_terminal_status\': \'not-asserted\',\n             \'retry_authority\': False, \'limitations\': limitations or {}}\n    if context_admission_id is not None:\n        value[\'context_admission_id\'] = context_admission_id\n    path = Path(path)\n    if path.exists():\n        if json.loads(path.read_text(encoding=\'utf-8\')) != value:\n            raise ValueError(\'operation outcome immutable; reconcile with new evidence\')\n        return value\n    _atomic(path, value)\n    return value\n\n\ndef guard_close(arguments, binding, state_root):\n    """A recorded external mutation cannot be hidden by a no-event terminal."""\n    admission = (binding or {}).get(\'context_admission_id\')\n    if not admission or arguments.get(\'outcome\') != \'no-event\':\n        return\n    path = Path(state_root) / (\'external-outcome-\' + digest(admission) + \'.json\')\n    if not path.exists():\n        return\n    if path.is_symlink() or path.stat().st_size > 65536:\n        raise ValueError(\'current external outcome unreadable; preserve coverage debt\')\n    value = json.loads(path.read_text(encoding=\'utf-8\'))\n    if value.get(\'context_admission_id\') != admission:\n        raise ValueError(\'current external outcome binding mismatch\')\n    if value.get(\'sent\') is True or value.get(\'writes\', 0):\n        raise ValueError(\'external mutation recorded: verified event terminal or coverage gap required\')\n', "<integrity-local-routes>", "exec"), _local_routes.__dict__)
_LOCAL_ROUTE_CATALOG = {'protocol': 'integrity-owner-runbook-catalog/v1', 'host': 'owner-host', 'production_authority': False, 'paths': []}
import types as _compact_types
_compact_admission = _compact_types.ModuleType("integrity_compact_admission")
exec(compile('# SPDX-License-Identifier: Apache-2.0\n"""File-backed admission presentation; never change canonical admission or receipts."""\nfrom __future__ import annotations\n\nfrom integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config\n\nimport copy\nimport hashlib\nimport json\nimport os\nimport re\nimport stat\nimport tempfile\nfrom pathlib import Path\n\nPROTOCOL = \'integrity-admission-compact/v1\'\nMAX_ARTIFACT = 16 * 1024 * 1024\nMAX_PUBLIC = 8192\nSHA = re.compile(r\'[0-9a-f]{64}\\Z\')\n\n\ndef encode(value):\n    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(\',\', \':\')).encode(\'utf-8\')\n\n\ndef digest(data):\n    return hashlib.sha256(data).hexdigest()\n\n\ndef default_root():\n    # This source revision targets the owner-host Codex and Claude clients together.\n    # No public tool argument or environment override can redirect file reads.\n    return Path.home() / \'.codex\' / \'integrity-memory\' / \'admission-artifacts\'\n\n\ndef safe_chain(path):\n    for item in (*reversed(path.parents), path):\n        s = item.lstat()\n        if stat.S_ISLNK(s.st_mode) or getattr(s, \'st_file_attributes\', 0) & 0x400:\n            raise ValueError(\'artifact_link_refused\')\n\n\ndef read_file(root, hexdigest):\n    if not isinstance(hexdigest, str) or not SHA.fullmatch(hexdigest):\n        raise ValueError(\'artifact_digest_invalid\')\n    root = Path(root).absolute()\n    safe_chain(root)\n    path = root / (hexdigest + \'.json\')\n    safe_chain(path)\n    flags = os.O_RDONLY | getattr(os, \'O_BINARY\', 0) | getattr(os, \'O_NOFOLLOW\', 0)\n    fd = os.open(path, flags)\n    with os.fdopen(fd, \'rb\') as stream:\n        before = os.fstat(stream.fileno())\n        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARTIFACT:\n            raise ValueError(\'artifact_file_invalid\')\n        data = stream.read(MAX_ARTIFACT + 1)\n        after = os.fstat(stream.fileno())\n    if (len(data) > MAX_ARTIFACT or before.st_size != after.st_size\n            or before.st_mtime_ns != after.st_mtime_ns or digest(data) != hexdigest):\n        raise ValueError(\'artifact_digest_mismatch\')\n    return data\n\n\ndef store_file(root, data):\n    if len(data) > MAX_ARTIFACT:\n        raise ValueError(\'artifact_too_large\')\n    root = Path(root).absolute()\n    # Validate existing ancestors before mkdir; validate the complete chain after.\n    existing = root\n    while not existing.exists():\n        existing = existing.parent\n    safe_chain(existing)\n    root.mkdir(parents=True, exist_ok=True, mode=0o700)\n    safe_chain(root)\n    hexdigest = digest(data)\n    path = root / (hexdigest + \'.json\')\n    if path.exists():\n        if read_file(root, hexdigest) != data:\n            raise ValueError(\'artifact_collision\')\n        return {\'sha256\': hexdigest, \'bytes\': len(data), \'path\': str(path)}\n    fd, temporary_name = tempfile.mkstemp(prefix=\'.admission-\', suffix=\'.tmp\', dir=root)\n    temporary = Path(temporary_name)\n    try:\n        with os.fdopen(fd, \'wb\') as stream:\n            stream.write(data)\n            stream.flush()\n            os.fsync(stream.fileno())\n        # Atomic no-clobber publication. A failed/terminated write cannot leave\n        # incomplete bytes under the final digest name. NTFS supports hard links.\n        try:\n            os.link(temporary, path)\n        except FileExistsError:\n            if read_file(root, hexdigest) != data:\n                raise ValueError(\'artifact_collision\')\n    finally:\n        temporary.unlink(missing_ok=True)\n    if read_file(root, hexdigest) != data:\n        raise ValueError(\'artifact_readback_mismatch\')\n    return {\'sha256\': hexdigest, \'bytes\': len(data), \'path\': str(path)}\n\n\ndef admission_document(result):\n    if not isinstance(result, dict) or result.get(\'isError\') is True:\n        return None\n    content = result.get(\'content\')\n    if not isinstance(content, list) or len(content) != 1:\n        return None\n    block = content[0]\n    if not isinstance(block, dict) or block.get(\'type\') != \'text\':\n        return None\n    try:\n        doc = json.loads(block[\'text\'])\n    except (KeyError, ValueError, TypeError):\n        return None\n    if not isinstance(doc, dict) or doc.get(\'protocol\') not in {\n        \'integrity-client-memory-mcp/v3/context-admission/v1\',\n        \'integrity-client-memory-mcp/v3/context-admission/v2\',\n    }:\n        return None\n    return doc\n\n\ndef resolve_wrapper(wrapper, root=None):\n    if not isinstance(wrapper, dict) or wrapper.get(\'protocol\') != PROTOCOL:\n        return wrapper\n    artifact = wrapper.get(\'full_admission\')\n    if not isinstance(artifact, dict):\n        raise ValueError(\'artifact_reference_missing\')\n    # The path is explanatory only; read only the pinned root + digest name.\n    trusted = default_root() if root is None else Path(root)\n    if artifact.get(\'path\') != str(trusted.absolute() / (str(artifact.get(\'sha256\')) + \'.json\')):\n        raise ValueError(\'artifact_path_mismatch\')\n    raw = read_file(trusted, artifact.get(\'sha256\'))\n    if artifact.get(\'bytes\') != len(raw):\n        raise ValueError(\'artifact_size_mismatch\')\n    result = json.loads(raw)\n    doc = admission_document(result)\n    if doc is None:\n        raise ValueError(\'artifact_not_admission\')\n    if not isinstance(doc.get(\'snapshot\'), dict) or not isinstance(doc.get(\'mind\'), dict):\n        raise ValueError(\'artifact_document_shape_invalid\')\n    binding = wrapper.get(\'admission\')\n    expected = {\'context_admission_id\': doc.get(\'context_admission_id\'),\n                \'snapshot_id\': doc.get(\'snapshot\', {}).get(\'snapshot_id\'),\n                \'status\': doc.get(\'status\')}\n    if not isinstance(binding, dict) or any(binding.get(key) != value for key, value in expected.items()):\n        raise ValueError(\'artifact_admission_binding_mismatch\')\n    # The hook still runs its original prompt/snapshot/receipt validation on doc.\n    return doc\n\n\ndef _public_result(wrapper):\n    return {\'content\': [{\'type\': \'text\', \'text\': encode(wrapper).decode(\'utf-8\')}], \'isError\': False}\n\n\ndef public_size(wrapper):\n    return len(encode(_public_result(wrapper)))\n\n\ndef _clip(text, byte_limit):\n    return text.encode(\'utf-8\')[:max(0, byte_limit)].decode(\'utf-8\', errors=\'ignore\')\n\n\nclass Presenter:\n    def __init__(self, root=None):\n        self.root = default_root() if root is None else Path(root)\n        self.capabilities_sha256 = None\n        self.capabilities_by_context = {}\n\n    def present(self, result, *, context_key=None):\n        try:\n            doc = admission_document(result)\n            if doc is None:\n                return result\n            return self._present(result, doc, context_key)\n        except Exception as exc:\n            # Admission may already have succeeded. Do not turn that success into\n            # a retry or hide its identity: retain the original response and mark\n            # presentation degraded. The strict byte bound is explicitly unmet.\n            fault = {\n                \'protocol\': \'integrity-compact-presentation-fault/v1\',\n                \'status\': \'degraded\', \'reason\': type(exc).__name__,\n                \'notify_owner_required\': True, \'byte_budget_met\': False,\n                \'admission_repeated\': False,\n            }\n            # The original admission JSON itself remains byte-identical, so no\n            # top-level field can accidentally enter a signed/digested document.\n            return {**result, \'content\': [{\'type\': \'text\', \'text\': encode(fault).decode(\'utf-8\')},\n                                         *result.get(\'content\', [])]}\n\n    def _present(self, result, doc, context_key):\n        if not isinstance(doc.get(\'snapshot\'), dict) or not isinstance(doc.get(\'mind\'), dict):\n            raise ValueError(\'artifact_document_shape_invalid\')\n        ref = store_file(self.root, encode(result))\n        mind = doc.get(\'mind\', {})\n        capsule = mind.get(\'mind\', {}) if isinstance(mind, dict) else {}\n        if not isinstance(capsule, dict):\n            capsule = {}\n        crc = doc.get(\'canonical_read_context\') or mind.get(\'canonical_read_context\') or {}\n        if not isinstance(crc, dict):\n            crc = {}\n        events = crc.get(\'events\', [])\n        if not isinstance(events, list):\n            events = []\n        ids = crc.get(\'event_ids\') or [e.get(\'event_id\', e.get(\'id\')) for e in events if isinstance(e, dict)]\n        if not isinstance(ids, list):\n            ids = []\n        text = doc.get(\'context_text\') or capsule.get(\'context_text\') or \'\'\n        if not isinstance(text, str):\n            text = \'\'\n        synaptic = capsule.get(\'synaptic\', {})\n        if not isinstance(synaptic, dict):\n            synaptic = {}\n        selection = mind.get(\'selection_receipt\', {})\n        if not isinstance(selection, dict):\n            selection = {}\n        if not text:\n            topic = crc.get(\'topic\') or \'события \' + \', \'.join(str(x) for x in ids)\n            text = \'Тема: \' + str(topic) + \'\\n\' + encode({\n                \'door\': synaptic.get(\'door\'),\n                \'selected_candidates\': selection.get(\'selected_candidates\'),\n                \'canonical_event_ids\': ids,\n            }).decode(\'utf-8\')\n            text += \'\\nSelected: \' + encode(capsule.get(\'working_set\', {})).decode(\'utf-8\')\n            text += \'\\nSynaptic: \' + encode({key: synaptic.get(key)\n                for key in (\'here\', \'links\', \'moves\', \'learned_hints\')}).decode(\'utf-8\')\n        delivery = doc.get(\'context_delivery\') or capsule.get(\'context_delivery\') or {}\n        capabilities = doc.get(\'capabilities\')\n        cap_sha = digest(encode(capabilities))\n        previous = self.capabilities_by_context.get(context_key) if context_key is not None else None\n        cap_change = \'first\' if previous is None else (\n            \'unchanged\' if cap_sha == previous else \'changed\')\n        wrapper = {\n            \'protocol\': PROTOCOL, \'full_admission\': ref,\n            \'context_text\': \'\', \'context_delivery\': delivery,\n            \'admission\': {\'context_admission_id\': doc.get(\'context_admission_id\'),\n                          \'status\': doc.get(\'status\'), \'health\': doc.get(\'health\'),\n                          \'door\': synaptic.get(\'door\'),\n                          \'snapshot_id\': doc.get(\'snapshot\', {}).get(\'snapshot_id\')},\n            \'selected\': selection.get(\'selected_candidates\'),\n            \'canonical_read_context\': {\'event_ids\': ids, \'events\': [],\n                \'admission_json_string_in_full_result\': \'/content/0/text\',\n                \'events_pointer_in_parsed_admission\': (\'/canonical_read_context/events\'\n                    if doc.get(\'canonical_read_context\') else \'/mind/canonical_read_context/events\')},\n            \'presentation\': {\'byte_limit\': MAX_PUBLIC, \'status\': \'file-backed\',\n                             \'context_text_truncated\': False, \'deferred_exact_event_ids\': [],\n                             \'deferred_events\': []},\n            \'capabilities_ref\': {\'sha256\': cap_sha, \'status\': cap_change,\n                                 \'cache_scope\': \'verified-thread\' if context_key is not None else \'disabled-unbound\',\n                                 \'json_pointer_in_admission\': \'/capabilities\'},\n        }\n        # Reserve space for an owner-visible topic/context excerpt first.\n        wrapper[\'context_text\'] = _clip(text, 1024)\n        deferred = []\n        for index, event in enumerate(events):\n            trial = copy.deepcopy(wrapper)\n            trial[\'canonical_read_context\'][\'events\'].append(event)\n            # Keep space for diagnostics, deferred IDs, and capabilities summary.\n            if public_size(trial) <= MAX_PUBLIC - 1200:\n                wrapper = trial\n            else:\n                event_id = event.get(\'event_id\', event.get(\'id\')) if isinstance(event, dict) else None\n                if event_id is not None:\n                    deferred.append(event_id)\n                row = {\'index\': index, \'sha256\': digest(encode(event))}\n                if event_id is not None:\n                    row[\'event_id\'] = event_id\n                wrapper[\'presentation\'][\'deferred_events\'].append(row)\n        wrapper[\'presentation\'][\'deferred_exact_event_ids\'] = deferred\n        if cap_change != \'unchanged\':\n            trial = {**wrapper, \'capabilities\': capabilities}\n            if public_size(trial) <= MAX_PUBLIC - 512:\n                wrapper = trial\n            else:\n                wrapper[\'capabilities_ref\'][\'status\'] = cap_change + \'_deferred\'\n        current_text = wrapper[\'context_text\']\n        remaining = MAX_PUBLIC - public_size(wrapper) - 32\n        if remaining > 0 and current_text != text:\n            trial = {**wrapper, \'context_text\': _clip(text, len(current_text.encode(\'utf-8\')) + remaining // 2)}\n            while public_size(trial) > MAX_PUBLIC:\n                trial[\'context_text\'] = _clip(trial[\'context_text\'], len(trial[\'context_text\'].encode(\'utf-8\')) // 2)\n            wrapper = trial\n        wrapper[\'presentation\'][\'context_text_truncated\'] = wrapper[\'context_text\'] != text\n        if public_size(wrapper) > MAX_PUBLIC:\n            raise ValueError(\'compact_metadata_exceeds_byte_budget\')\n        # Commit advertisement state only after successful serialization/storage.\n        if \'capabilities\' in wrapper:\n            self.capabilities_sha256 = cap_sha\n            if context_key is not None:\n                self.capabilities_by_context[context_key] = cap_sha\n        return _public_result(wrapper)\n', "frozen-compact-admission", "exec"), _compact_admission.__dict__)

from types import ModuleType as _ReadSessionModule
_reader_session_module = _ReadSessionModule("integrity_broker_read_session")
exec(compile('# SPDX-License-Identifier: Apache-2.0\n"""Request-local, read-only AL admission. No canonical writes or ambient identity.\n\nThe admitted local broker is the identity authority within the existing reader\ntrust boundary. The proof authenticates transport binding, not target authority.\n"""\nfrom __future__ import annotations\n\nfrom integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config\n\nimport datetime as dt\nimport hashlib\nimport hmac\nimport json\nimport re\n\nPROTOCOL = \'integrity-reader-session/v1\'\nMAX_TTL_SECONDS = 300\nHEX = re.compile(r\'[a-f0-9]{64}\\Z\')\nDIGEST = re.compile(r\'sha256:[a-f0-9]{64}\\Z\')\nKEYS = {\'protocol\', \'identity_hashes\', \'agent_product\', \'agent_id\', \'session_id\',\n        \'turn_ref_digest\', \'prompt_sha256\', \'declared_at\', \'expires_at\',\n        \'external_action_authority\'}\n\n\nclass ReadSessionError(ValueError):\n    pass\n\n\ndef canonical(value):\n    return json.dumps(value, sort_keys=True, ensure_ascii=False,\n                      separators=(\',\', \':\'), allow_nan=False).encode(\'utf-8\')\n\n\ndef timestamp(value):\n    if not isinstance(value, str) or len(value) > 40:\n        raise ReadSessionError(\'reader session timestamp invalid\')\n    try:\n        result = dt.datetime.fromisoformat(value.replace(\'Z\', \'+00:00\'))\n    except ValueError:\n        raise ReadSessionError(\'reader session timestamp invalid\') from None\n    if result.tzinfo is None or result.utcoffset() != dt.timedelta(0):\n        raise ReadSessionError(\'reader session requires UTC\')\n    return result\n\n\ndef validate(value, *, prompt_sha256=None, turn_ref_digest=None, now=None):\n    if not isinstance(value, dict) or set(value) != KEYS:\n        raise ReadSessionError(\'reader session shape invalid\')\n    hashes = value.get(\'identity_hashes\')\n    if (value.get(\'protocol\') != PROTOCOL or not isinstance(hashes, dict)\n            or set(hashes) != {\'machine_id\', \'thread_id\', \'turn_id\'}\n            or any(not isinstance(v, str) or not HEX.fullmatch(v) for v in hashes.values())\n            or value.get(\'agent_product\') not in {\'codex\', \'claude\'}\n            or value.get(\'external_action_authority\') is not False):\n        raise ReadSessionError(\'reader session identity invalid\')\n    expected_session = \'reader:\' + value[\'agent_product\'] + \':\' + hashes[\'machine_id\'] + \':\' + hashes[\'thread_id\']\n    expected_agent = value[\'agent_product\'] + \':\' + hashes[\'machine_id\']\n    if (value.get(\'session_id\') != expected_session or value.get(\'agent_id\') != expected_agent\n            or not isinstance(value.get(\'prompt_sha256\'), str)\n            or not HEX.fullmatch(value[\'prompt_sha256\'])\n            or not isinstance(value.get(\'turn_ref_digest\'), str)\n            or not DIGEST.fullmatch(value[\'turn_ref_digest\'])\n            or prompt_sha256 is not None and value[\'prompt_sha256\'] != prompt_sha256\n            or turn_ref_digest is not None and value[\'turn_ref_digest\'] != turn_ref_digest):\n        raise ReadSessionError(\'reader session binding mismatch\')\n    start, end = timestamp(value[\'declared_at\']), timestamp(value[\'expires_at\'])\n    current = now if now is not None else dt.datetime.now(dt.timezone.utc)\n    if not 0 < (end - start).total_seconds() <= MAX_TTL_SECONDS or not start <= current < end:\n        raise ReadSessionError(\'reader session expired or outside its window\')\n    return json.loads(canonical(value))\n\n\ndef issue(envelope, *, product, now=None):\n    """Called only after native claim/owning-head revalidation by the broker."""\n    current = now if now is not None else dt.datetime.now(dt.timezone.utc)\n    hashes = envelope[\'native_identity_hashes\']\n    end = min(timestamp(envelope[\'expires_utc\']), current + dt.timedelta(seconds=MAX_TTL_SECONDS))\n    value = {\'protocol\': PROTOCOL, \'identity_hashes\': hashes, \'agent_product\': product,\n             \'agent_id\': product + \':\' + hashes[\'machine_id\'],\n             \'session_id\': \'reader:\' + product + \':\' + hashes[\'machine_id\'] + \':\' + hashes[\'thread_id\'],\n             \'turn_ref_digest\': envelope[\'turn_ref_digest\'], \'prompt_sha256\': envelope[\'prompt_sha256\'],\n             \'declared_at\': current.isoformat().replace(\'+00:00\', \'Z\'),\n             \'expires_at\': end.isoformat().replace(\'+00:00\', \'Z\'),\n             \'external_action_authority\': False}\n    return validate(value, now=current)\n\n\ndef request_proof(declaration, *, snapshot_event_id, token):\n    if not isinstance(token, str) or not token:\n        raise ReadSessionError(\'reader session authentication required\')\n    if isinstance(snapshot_event_id, bool) or not isinstance(snapshot_event_id, int) or snapshot_event_id < 1:\n        raise ReadSessionError(\'reader session snapshot invalid\')\n    material = {\'declaration\': declaration, \'snapshot_event_id\': snapshot_event_id}\n    return hmac.new(token.encode(), PROTOCOL.encode() + b\'\\0\' + canonical(material), hashlib.sha256).hexdigest()\n\n\ndef accept(payload, *, token, now=None):\n    """Authenticate before AL projection/recall; proof never leaves this request."""\n    if not isinstance(payload, dict) or set(payload) != {\'declaration\', \'proof\', \'snapshot_event_id\'}:\n        raise ReadSessionError(\'reader session request invalid\')\n    declaration = validate(payload[\'declaration\'], now=now)\n    proof = payload.get(\'proof\')\n    expected = request_proof(declaration, snapshot_event_id=payload[\'snapshot_event_id\'], token=token)\n    if not isinstance(proof, str) or not hmac.compare_digest(expected, proof):\n        raise ReadSessionError(\'reader session proof mismatch\')\n    return declaration\n\n\ndef speaker(declaration):\n    return {\'agent_id\': declaration[\'agent_id\'], \'agent_product\': declaration[\'agent_product\'],\n            \'agent_vendor\': \'OpenAI\' if declaration[\'agent_product\'] == \'codex\' else \'Anthropic\',\n            \'admission_id\': \'sha256:\' + hashlib.sha256(canonical(declaration)).hexdigest(),\n            \'admission_declared_at\': declaration[\'declared_at\'],\n            \'admission_expires_at\': declaration[\'expires_at\'],\n            \'capability_class\': [\'context-read\'], \'admitted_agents\': []}\n', "frozen-read-session", "exec"), _reader_session_module.__dict__)

import types as _topic_context_types
_topic_context = _topic_context_types.ModuleType("integrity_broker_topic_context")
_topic_context_source = '# SPDX-License-Identifier: Apache-2.0\n"""Non-authoritative search hints bound to one broker-owned thread hash."""\nfrom __future__ import annotations\n\nfrom integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config\nimport hashlib, json, re\nfrom pathlib import Path\n\nPROTOCOL = \'integrity-topic-search-context/v1\'\nSHA = re.compile(r\'sha256:[a-f0-9]{64}\\Z\')\nUUID = re.compile(r\'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\\Z\')\nADDRESS = re.compile(r\'[a-z0-9-]{2,32}\\Z\')\n\ndef validate_hint(value):\n    keys = {\'protocol\',\'address\',\'topic\',\'thread_sha256\',\'registry_sha256\',\'authority\'}\n    if not isinstance(value, dict) or set(value) != keys:\n        raise ValueError(\'retrieval hint shape invalid\')\n    if (value[\'protocol\'] != PROTOCOL or value[\'authority\'] != \'none\'\n            or not isinstance(value[\'address\'], str) or not ADDRESS.fullmatch(value[\'address\'])\n            or not all(isinstance(value[k], str) and SHA.fullmatch(value[k]) for k in (\'thread_sha256\',\'registry_sha256\'))\n            or not isinstance(value[\'topic\'], str) or not value[\'topic\'].strip() or len(value[\'topic\']) > 200\n            or any(ord(c) < 32 for c in value[\'topic\'])):\n        raise ValueError(\'retrieval hint invalid\')\n    return dict(value)\n\ndef registry_hint_for_hash(thread_sha256, registry_path):\n    """Read only the exact own subject. Never use CODEX_THREAD_ID or a parent."""\n    if not isinstance(thread_sha256, str) or not SHA.fullmatch(thread_sha256):\n        return None\n    path = Path(registry_path)\n    try:\n        for ancestor in (path, *path.parents):\n            if ancestor.is_symlink() or ancestor.is_junction():\n                return None\n        if path.stat().st_size > 65536:\n            return None\n        raw = path.read_bytes()\n        if len(raw) > 65536:\n            return None\n        root = json.loads(raw.decode(\'utf-8\'))\n        agents = root.get(\'agents\')\n        if not isinstance(agents, dict):\n            return None\n        matches = []\n        for address, entry in agents.items():\n            if (not isinstance(address, str) or not ADDRESS.fullmatch(address)\n                    or not isinstance(entry, dict) or entry.get(\'harness\') != \'codex\'\n                    or not isinstance(entry.get(\'thread\'), str) or not UUID.fullmatch(entry[\'thread\'])):\n                continue\n            identity = \'sha256:\' + hashlib.sha256(entry[\'thread\'].encode(\'utf-8\')).hexdigest()\n            if identity == thread_sha256:\n                matches.append((address, entry))\n        if len(matches) != 1:\n            return None\n        address, entry = matches[0]\n        return validate_hint({\'protocol\':PROTOCOL,\'address\':address,\'topic\':entry.get(\'topic\'),\n            \'thread_sha256\':thread_sha256,\'registry_sha256\':\'sha256:\'+hashlib.sha256(raw).hexdigest(),\'authority\':\'none\'})\n    except (OSError, ValueError, TypeError, AttributeError, UnicodeError):\n        return None\n'
assert hashlib.sha256(_topic_context_source.encode("utf-8")).hexdigest() == _integrity_value('pin_74e986d01516')
exec(compile(_topic_context_source, "<bound-integrity-topic-context>", "exec"), _topic_context.__dict__)
registry_hint_for_hash = _topic_context.registry_hint_for_hash

BROKER_NAME = "integrity-client-memory"

_native_navigation_scope = _route_types.ModuleType("integrity_native_navigation_scope")
exec(compile('# SPDX-License-Identifier: Apache-2.0\n"""Native-owned cwd witness for optional client navigation, never an admission."""\n\nfrom integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config\nimport copy\nimport hashlib\nimport json\nfrom pathlib import Path\n\n\ndef bind(binding, identity, observation, workspace):\n    result = copy.deepcopy(binding)\n    hashes = binding.get(\'hashes\') or {}\n    sha = lambda x: hashlib.sha256(x.encode()).hexdigest()\n    thread = observation.get(\'thread\') or {}\n    turns = observation.get(\'turns\') or []\n    if (hashes.get(\'thread_id\') != sha(identity) or thread.get(\'id\') != identity\n            or not turns or hashes.get(\'turn_id\') != sha(str(turns[0].get(\'id\', \'\')))\n            or turns[0].get(\'status\') != \'inProgress\'):\n        raise ValueError(\'navigation Native subject mismatch\')\n    cwd = thread.get(\'cwd\')\n    if not isinstance(cwd, str) or not Path(cwd).is_absolute():\n        raise ValueError(\'navigation Native cwd absent\')\n    root = Path(workspace).resolve(strict=True)\n    target = Path(cwd).resolve(strict=True)\n    if not target.is_relative_to(root):\n        raise ValueError(\'navigation workspace mismatch\')\n    for item in (Path(cwd), *Path(cwd).parents):\n        if item.is_symlink() or getattr(item.lstat(), \'st_file_attributes\', 0) & 0x400:\n            raise ValueError(\'navigation workspace reparse\')\n    material = {\'protocol\': \'integrity-native-navigation-scope/v1\',\n                \'host\': \'owner-host\', \'workspace\': str(root).casefold()}\n    # This is local derived navigation. Signed upstream bindings stay unchanged.\n    result[\'project_scope_sha256\'] = \'sha256:\' + sha(json.dumps(material, sort_keys=True))\n    result[\'project_scope_source\'] = \'current-own-Native-thread-cwd\'\n    return result\n\n\ndef observe_binding(envelope, binding, workspace):\n    if binding.get(\'project_scope_sha256\'):\n        return copy.deepcopy(binding)\n    identity = envelope._resume_identity()\n    reader = envelope._load_owning_native_reader()\n    reader.discover_codex_app_tool_pipes = lambda: envelope._owning_codex_app_tool_pipes(reader)\n    try:\n        value = reader._host_tool_json(reader.BACKENDS.get_codex_host(), \'read_thread\',\n            {\'threadId\': identity, \'turnLimit\': 1, \'includeOutputs\': False,\n             \'maxOutputCharsPerItem\': 0}, identity)\n        return bind(binding, identity, value, workspace)\n    except reader.RpcError:\n        raise ValueError(\'navigation Native witness unavailable\') from None\n    finally:\n        reader.BACKENDS.close()\n', "<integrity-native-navigation-scope>", "exec"), _native_navigation_scope.__dict__)
_native_task_route = _route_types.ModuleType('_native_task_route')
exec(compile('# SPDX-License-Identifier: Apache-2.0\n"""Navigation-only projection of an authenticated Native delegation source.\n\nThe admitted carrier is never decrypted, replaced, or relabelled as user text.\nOnly the exact successful originating collaboration call is projected for\nnavigation, after current child identity, lineage and product custody checks.\n"""\n\nfrom integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config\nimport datetime,hashlib,json,os,re,stat\nfrom pathlib import Path\n\nUUID=re.compile(r\'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\\Z\')\nMAX_FILE=128*1024*1024;MAX_LINE=8*1024*1024;MAX_PROMPT=261888\nclass ProjectionError(ValueError):pass\ndef need(ok,code):\n    if not ok:raise ProjectionError(code)\ndef sha(text):return hashlib.sha256(text.encode()).hexdigest()\ndef plain_product(raw,identity):\n    need(isinstance(raw,str),\'native-task-path-missing\')\n    if raw.startswith(\'\\\\\\\\?\\\\\'):\n        need(re.match(r\'^\\\\\\\\\\?\\\\[A-Za-z]:\\\\\',raw) is not None,\'native-task-device-path\');raw=raw[4:]\n    p=Path(raw);home=Path(os.environ.get(\'CODEX_HOME\',str(Path.home()/\'.codex\')))\n    need(p.is_absolute() and p.is_relative_to(home/\'sessions\') and p.name.endswith(\'-\'+identity+\'.jsonl\'),\'native-task-product-subject\')\n    for part in (p,*p.parents):\n        d=part.lstat();need(not part.is_symlink() and not getattr(d,\'st_file_attributes\',0)&1024,\'native-task-reparse\')\n    need(stat.S_ISREG(p.stat().st_mode) and 0<p.stat().st_size<=MAX_FILE,\'native-task-product-bound\')\n    return p\ndef records(path):\n    with path.open(encoding=\'utf-8\') as stream:\n        for ordinal,line in enumerate(stream,1):\n            need(len(line.encode())<=MAX_LINE,\'native-task-line-bound\')\n            yield ordinal,json.loads(line)\ndef timestamp(raw):\n    need(isinstance(raw,str),\'native-task-time-missing\')\n    value=datetime.datetime.fromisoformat(raw.replace(\'Z\',\'+00:00\'))\n    need(value.tzinfo is not None,\'native-task-time-naive\');return value\n\ndef delivery_window(rows,carrier,agent_path):\n    head=None;turn=None;found=[];previous=None\n    for ordinal,row in rows:\n        p=row.get(\'payload\') or {}\n        if row.get(\'type\')==\'session_meta\' and head is None:head=p\n        if row.get(\'type\')==\'turn_context\':turn=p.get(\'turn_id\')\n        if row.get(\'type\')==\'response_item\' and p.get(\'type\')==\'agent_message\' and p.get(\'recipient\')==agent_path:\n            stamp=timestamp(row.get(\'timestamp\'))\n            if p==carrier[\'native_delivery\']:\n                need(turn==carrier[\'native_turn_id\'],\'native-task-delivery-turn\')\n                found.append((previous,stamp,ordinal))\n            previous=stamp\n    need(head is not None and head.get(\'id\')==carrier[\'native_thread_id\'],\'native-task-child-header\')\n    need(len(found)==1,\'native-task-delivery-ambiguous\');return found[0]\n\ndef select_parent_task(rows,*,parent,agent_path,child,window):\n    previous,delivered,_=window;header=None;calls={};matches=[];parent_turn=None\n    parent_path=agent_path.rsplit(\'/\',1)[0]\n    for ordinal,row in rows:\n        p=row.get(\'payload\') or {}\n        if row.get(\'type\')==\'session_meta\' and header is None:header=p\n        if row.get(\'type\')==\'turn_context\':parent_turn=p.get(\'turn_id\')\n        if row.get(\'type\')!=\'response_item\':continue\n        if p.get(\'type\')==\'function_call\' and p.get(\'namespace\')==\'collaboration\' and p.get(\'name\') in [\'spawn_agent\',\'followup_task\']:\n            started=timestamp(row.get(\'timestamp\'))\n            if started>delivered or previous is not None and started<=previous:continue\n            try:a=json.loads(p[\'arguments\'])\n            except (ValueError,KeyError):continue\n            if p[\'name\']==\'spawn_agent\':\n                target=parent_path+\'/\'+str(a.get(\'task_name\',\'\'))\n            else:\n                target=a.get(\'target\')\n                if isinstance(target,str) and not target.startswith(\'/\') and target!=child:target=parent_path+\'/\'+target\n            if target not in (agent_path,child):continue\n            message=a.get(\'message\')\n            need(isinstance(message,str) and 0<len(message.encode())<=MAX_PROMPT,\'native-task-message-bound\')\n            need(\'turnref:\' not in message,\'native-task-ref-not-navigation\')\n            calls[p.get(\'call_id\')]={\'message\':message,\'call_id\':p[\'call_id\'],\'ordinal\':ordinal,\'tool\':p[\'name\'],\'parent_turn_id\':parent_turn}\n        if p.get(\'type\')==\'function_call_output\' and p.get(\'call_id\') in calls:\n            call=calls[p[\'call_id\']];output=p.get(\'output\')\n            if call[\'tool\']==\'spawn_agent\':\n                try:reply=json.loads(output)\n                except (ValueError,TypeError):continue\n                if not isinstance(reply,dict) or set(reply)!={\'task_name\'} or reply[\'task_name\']!=agent_path:continue\n            else:\n                # A triggering authenticated child carrier proves delivery;\n                # still require the Native successful call output, not a request.\n                if output not in (\'\',None):\n                    try:reply=json.loads(output)\n                    except (ValueError,TypeError):continue\n                    if not isinstance(reply,dict) or reply.get(\'isError\') or reply.get(\'error\'):continue\n            matches.append(call)\n    need(header is not None and header.get(\'id\')==parent,\'native-task-parent-header\')\n    need(len(matches)==1,\'native-task-origin-ambiguous\');return matches[0]\n\ndef project(envelope,prompt,binding):\n    try:carrier=json.loads(prompt)\n    except (ValueError,TypeError):return prompt,{\'kind\':\'own-plaintext\',\'external_action_authority\':False}\n    if not isinstance(carrier,dict) or carrier.get(\'input_kind\')!=\'native-agent-task-envelope\':\n        return prompt,{\'kind\':\'own-plaintext\',\'external_action_authority\':False}\n    need(sha(prompt)==binding.get(\'prompt_sha256\'),\'native-task-carrier-binding\')\n    child=carrier.get(\'native_thread_id\');turn=carrier.get(\'native_turn_id\');parent=carrier.get(\'parent_thread_id\')\n    need(all(isinstance(x,str) and UUID.fullmatch(x) for x in (child,turn,parent)),\'native-task-identity\')\n    hashes=binding.get(\'hashes\') or {}\n    need(hashes.get(\'thread_id\')==sha(child) and hashes.get(\'turn_id\')==sha(turn),\'native-task-own-binding\')\n    need(envelope._resume_identity()==child,\'native-task-current-caller\')\n    reader=envelope._load_owning_native_reader()\n    reader.discover_codex_app_tool_pipes=lambda:envelope._owning_codex_app_tool_pipes(reader)\n    try:\n        host=reader.BACKENDS.get_codex_host();head=reader._host_latest_turn(host,child)\n        need(head.get(\'id\')==turn and head.get(\'status\')==\'inProgress\',\'native-task-current-head\')\n        backend=reader.BACKENDS.get_codex()\n        cm=backend.request(\'thread/read\',{\'threadId\':child,\'includeTurns\':False},15)[\'thread\']\n        pm=backend.request(\'thread/read\',{\'threadId\':parent,\'includeTurns\':False},15)[\'thread\']\n        branch=((cm.get(\'source\') or {}).get(\'subAgent\') or {}).get(\'thread_spawn\') or {}\n        need(cm.get(\'id\')==child and pm.get(\'id\')==parent and branch.get(\'parent_thread_id\')==parent,\'native-task-lineage\')\n        agent_path=branch.get(\'agent_path\')\n        need(isinstance(agent_path,str) and agent_path.startswith(\'/root/\') and len(agent_path)<256,\'native-task-agent-path\')\n        delivery=carrier.get(\'native_delivery\') or {}\n        need(delivery.get(\'recipient\')==agent_path and delivery.get(\'author\')==agent_path.rsplit(\'/\',1)[0],\'native-task-carrier-route\')\n        window=delivery_window(records(plain_product(cm.get(\'path\'),child)),carrier,agent_path)\n        source=select_parent_task(records(plain_product(pm.get(\'path\'),parent)),parent=parent,child=child,agent_path=agent_path,window=window)\n        again=reader._host_latest_turn(host,child)\n        need(again.get(\'id\')==turn and again.get(\'status\')==\'inProgress\',\'native-task-head-changed\')\n        opaque=bool(re.fullmatch(r\'gAAAA[A-Za-z0-9_-]{80,}={0,2}\',source[\'message\']))\n        return (\'\' if opaque else source[\'message\']),{\'kind\':\'authenticated-native-delegation-navigation\',\'protocol\':\'integrity-native-task-navigation/v1\',\n            \'navigation_text_available\':not opaque,\'navigation_text_reason\':\'Native-originating-message-encrypted\' if opaque else \'plaintext-originating-message\',\n            \'native_thread_id\':child,\'native_turn_id\':turn,\'parent_thread_id\':parent,\'agent_path\':agent_path,\n            \'parent_turn_id\':source[\'parent_turn_id\'],\n            \'source_call_id\':source[\'call_id\'],\'source_ordinal\':source[\'ordinal\'],\'task_sha256\':sha(source[\'message\']),\n            \'carrier_sha256\':sha(prompt),\'admitted_prompt_replaced\':False,\'canonical_prompt_plaintext_recovered\':False,\n            \'external_action_authority\':False}\n    finally:reader.BACKENDS.close()\n', '<managed-native_task_route.py>', "exec"), _native_task_route.__dict__)
_automatic_Core = _route_types.ModuleType('_automatic_Core')
exec(compile('# SPDX-License-Identifier: Apache-2.0\n"""Automatic same-session Core delivery; no model-supplied runbook content."""\n\nfrom integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config\nimport copy,hashlib,json,time\nfrom pathlib import Path\n\ndef delivery(upstream,local,source,experiment,expected_catalog_digest):\n    local=copy.deepcopy(local);local[\'task_source\']=source\n    # A narrowly scoped owner-configured context ablation, independent from all\n    # authentication, admission, SCOPE and actuator permissions.\n    in_experiment=(source.get(\'parent_thread_id\')==experiment[\'parent_thread_id\']\n        and source.get(\'parent_turn_id\')==experiment[\'parent_turn_id\']\n        and time.time()<experiment[\'expires_epoch\'])\n    if in_experiment and source.get(\'agent_path\') in experiment[\'control_agent_paths\']:\n        return {\'status\':\'task-route-withheld-for-control\',\'scope_source\':local.get(\'scope_source\'),\n                \'task_source\':source,\'entities\':local.get(\'entities\'),\n                \'core_delivery\':{\'status\':\'withheld-by-frozen-experiment\',\'calls\':0},\n                \'external_action_authority\':False,\'automatic_execution\':False}\n    if local.get(\'status\')!=\'navigation-ready\':\n        if source.get(\'navigation_text_available\') is False:\n            local[\'status\']=\'task-route-query-required\'\n            local[\'task_query\']={\'tool\':\'integrity_memory_ttt_autofill\',\'goal\':\'Use only current task identifiers: BDCOM OLT IPv4, GPON interface and ONU serial. No procedure or prior context.\',\n                \'last_hop\':\'identify-switch-ip\',\'snapshot_id\':local.get(\'snapshot_id\'),\n                \'note\':\'First identity read is still mandatory. Opaque Native carrier and its binding remain unchanged. This query is navigation, never authority.\'}\n        return local\n    started=time.monotonic()\n    try:\n        result=upstream.call_tool(\'integrity_memory_ttt_autofill\',{\'goal\':\'bdcom-onu-service-vlan\',\n            \'last_hop\':\'example-operation-0001\',\'snapshot_id\':local[\'snapshot_id\']})\n    except Exception:\n        return {\'status\':\'core-not-delivered\',\'task_source\':source,\'core_delivery\':{\'status\':\'not-delivered\',\'reason\':\'canonical-Core-upstream-unavailable\',\'calls\':1},\'external_action_authority\':False}\n    elapsed=time.monotonic()-started\n    try:value=json.loads(result[\'content\'][0][\'text\'])\n    except (KeyError,IndexError,TypeError,ValueError):value={}\n    binding=value.get(\'snapshot_binding\') or {}\n    valid=(not result.get(\'isError\') and value.get(\'result\')==\'REMAINING\'\n        and value.get(\'path_catalog_digest\')==expected_catalog_digest\n        and binding.get(\'snapshot_id\')==local[\'snapshot_id\']\n        and binding.get(\'ttt_receipt_id\')==value.get(\'receipt_id\')\n        and len(value.get(\'remaining_path\',[]))==6)\n    # Never silently replace missing Core with a locally invented procedure.\n    if not valid:return {\'status\':\'core-not-delivered\',\'task_source\':source,\n        \'core_delivery\':{\'status\':\'not-delivered\',\'reason\':\'canonical-core-response-or-binding-mismatch\',\'calls\':1,\'elapsed_seconds\':elapsed},\n        \'external_action_authority\':False,\'automatic_execution\':False}\n    local[\'hops\']=value[\'remaining_path\'];local.pop(\'evidence\',None)\n    local[\'source\']=\'same-model-owned-upstream-Core-response\'\n    local[\'core_delivery\']={\'status\':\'delivered\',\'calls\':1,\'elapsed_seconds\':elapsed,\n        \'receipt_id\':value[\'receipt_id\'],\'snapshot_binding_receipt_id\':binding[\'receipt_id\'],\n        \'path_catalog_digest\':value[\'path_catalog_digest\'],\'snapshot_id\':local[\'snapshot_id\'],\n        \'snapshot_event_id\':binding.get(\'snapshot_event_id\'),\'remaining_count\':6,\n        \'first_identity_read_still_required\':True,\'completed_hop_assertion_verified\':False,\n        \'response_sha256\':hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False).encode()).hexdigest()}\n    return local\n\ndef query(navigator,upstream,args,binding,scope,source,experiment,catalog):\n    """The admitted model supplies task entities, never the Core procedure."""\n    if not source or source.get(\'navigation_text_available\') is not False:return None\n    if args.get(\'snapshot_id\')!=binding.get(\'snapshot_id\'):raise ValueError(\'task query snapshot mismatch\')\n    local=navigator.admit(args.get(\'goal\',\'\'),scope,args[\'snapshot_id\'])\n    local[\'snapshot_id\']=args[\'snapshot_id\'];local[\'scope_source\']=scope.get(\'project_scope_source\')\n    source=copy.deepcopy(source);source[\'task_selector_source\']=\'current-admitted-model-tool-query\'\n    source[\'task_selector_sha256\']=hashlib.sha256(args.get(\'goal\',\'\').encode()).hexdigest()\n    value=delivery(upstream,local,source,experiment,catalog)\n    journal(value,binding[\'context_admission_id\'],phase=\'query\')\n    if value.get(\'status\') not in (\'navigation-ready\',\'task-route-withheld-for-control\'):\n        return {\'content\':[{\'type\':\'text\',\'text\':json.dumps({\'operational_context\':value})}],\'isError\':True}\n    return {\'content\':[{\'type\':\'text\',\'text\':json.dumps({\'operational_context\':value})}]}\n\ndef guard_curator(envelope,binding,args):\n    """Administrative accounting still requires the current own actor slot."""\n    identity=envelope._resume_identity();head=envelope._native_owning_head(identity)\n    hashes=binding.get(\'hashes\') or {}\n    sha=lambda s:hashlib.sha256(s.encode()).hexdigest()\n    if not (binding.get(\'admitted\') is True and hashes.get(\'thread_id\')==sha(identity)\n            and head.get(\'status\')==\'inProgress\' and hashes.get(\'turn_id\')==sha(head.get(\'id\',\'\'))):\n        raise ValueError(\'curator current own Native binding missing\')\n    path=Path.home()/\'.codex/integrity-memory/state\'/(sha(identity)+\'.json\')\n    if path.is_symlink() or not path.is_file():raise ValueError(\'curator own receipt state missing\')\n    state=json.loads(path.read_bytes())\n    if not (args.get(\'curator_registration_id\')==state.get(\'turn_memory_registration_id\')\n            and args.get(\'context_admission_id\')==binding.get(\'context_admission_id\')==state.get(\'model_mcp_context_admission_id\')\n            and binding.get(\'intent_id\')==state.get(\'turn_memory_intent_id\')\n            and state.get(\'turn_memory_terminal_receipt_id\') in (None,\'\')):\n        raise ValueError(\'curator actor must be the current own open registration\')\n\ndef journal(local,context_admission_id,phase=\'admission\'):\n    # Diagnostics only, never an alternate canonical memory source.\n    value={\'protocol\':\'integrity-client/automatic-Core-delivery/v1\',\'context_admission_id\':context_admission_id,\n        \'status\':local.get(\'status\'),\'task_source\':local.get(\'task_source\'),\'core_delivery\':local.get(\'core_delivery\'),\n        \'external_action_authority\':False}\n    path=Path.home()/\'.codex/integrity-memory/state\'/(\'core-delivery-\'+(\'query-\' if phase==\'query\' else \'\')+hashlib.sha256(context_admission_id.encode()).hexdigest()+\'.json\')\n    if path.exists():\n        previous=json.loads(path.read_bytes())\n        if previous.get(\'context_admission_id\')!=context_admission_id:raise ValueError(\'Core journal binding drift\')\n        return\n    with path.open(\'x\',encoding=\'utf-8\') as out:json.dump(value,out,ensure_ascii=False)\n', '<managed-core_delivery.py>', "exec"), _automatic_Core.__dict__)
_TASK_CONTEXT_EXPERIMENT = {'protocol': 'integrity-optional-task-context-ablation/v1', 'parent_thread_id': '', 'parent_turn_id': '', 'control_agent_paths': [], 'expires_epoch': 0, 'effect': 'disabled-in-clean-distribution'}
_CORE_CATALOG_DIGEST = _integrity_value('pin_fd1c0d5a8471')
BROKER_VERSION = "1.6.0"
DEFAULT_MCP_VERSION = "2025-06-18"
MAX_MESSAGE_BYTES = 4 * 1024 * 1024
BROKER_TOOL_SURFACE_PROTOCOL = "integrity-client/broker-tool-surface/v1"
BROKER_TOOL_SURFACE_CAPABILITY = "integrityClientToolSurface"
CONTEXT_ADMISSION_REPLAY_PROTOCOL = "integrity-client/context-admission-replay/v2"
CONTEXT_ADMISSION_REPLAY_CAPABILITY = "integrityClientContextAdmissionReplay"
CONTEXT_ADMISSION_REPLAY_FIELD = "_integrity_replay_id"
CONTEXT_ADMISSION_REPLAY_ACK_NOTIFICATION = (
    "notifications/integrity_context_admission_replay_ack"
)
CONTEXT_ADMISSION_REPLAY_RESERVE_METHOD = (
    "integrity/context_admission_replay_reserve"
)
CONTEXT_ADMISSION_REPLAY_ACK_METHOD = "integrity/context_admission_replay_ack"
CONTEXT_REATTACH_CAPABILITY = "integrityClientContextReattach"
CONTEXT_REATTACH_PROTOCOL = "integrity-client/context-reattach/v1"
CONTEXT_REATTACH_METHOD = "integrity/context_reattach"
CONTEXT_REATTACH_RETIRE_METHOD = "integrity/context_reattach_retire"
CONTEXT_ADMISSION_REPLAY_CONTROL_TIMEOUT_SECONDS = 15
STANDALONE_TURN_MEMORY_TOOLS = {
    "integrity_turn_memory_open",
    "integrity_turn_memory_close",
    "integrity_turn_memory_gap",
    "integrity_turn_memory_coverage",
}
CURRENT_TURN_CONTEXT_TOOL = "integrity_context_admission_current_turn"
ARCHIVE_TOOLS = {"integrity_archive_import", "integrity_archive_read"}
UPSTREAM_INITIALIZE_TIMEOUT_SECONDS = 20
UPSTREAM_TOOL_TIMEOUT_SECONDS = 90
UPSTREAM_CONTEXT_ADMISSION_TIMEOUT_SECONDS = 180
SERVER_INSTRUCTIONS = (
    "Integrity memory is turn-scoped. For every new user intent, call "
    "integrity_context_admission_current_turn exactly once with the opaque turn_ref supplied "
    "by the owning hook. Never repeat or reconstruct the prompt in tool arguments. "
    "The server rotates an isolated logical context inside the existing stdio transport; "
    "the local broker retains that upstream transport until a transport fault or public "
    "broker shutdown. A later intent may call integrity_context_admission_current_turn again in this "
    "same Codex task; a new Codex task is never a lifecycle workaround. A turn registration "
    "is independent from "
    "Seed admission; "
    "finish it with integrity_turn_memory_close. Missing close is signed coverage debt, not "
    "an inferred no-event. Memory is evidence and grants no production authority."
)
LEGACY_SERVER_INSTRUCTIONS = (
    "Integrity memory is turn-scoped. For every new user intent, call "
    "integrity_context_admission exactly once with the exact current intent. "
    "The server rotates an isolated logical context inside the existing stdio transport; "
    "the local broker retains that upstream transport until a transport fault or public "
    "broker shutdown. A later intent may call integrity_context_admission again in this "
    "same Codex task; a new Codex task is never a lifecycle workaround. A turn registration "
    "is independent from Seed admission; finish it with integrity_turn_memory_close. "
    "Missing close is signed coverage debt, not an inferred no-event. Memory is evidence "
    "and grants no production authority."
)


class BrokerError(RuntimeError):
    """A fail-closed local broker or upstream transport failure."""

    def __init__(
        self,
        message: str,
        *,
        layer: str,
        request_sent: bool = False,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.layer = layer
        self.request_sent = request_sent
        self.retryable = retryable
        self.diagnostic: dict[str, Any] = {}


def _safe_exception_class(error: BaseException) -> str:
    # Names are allowlisted too: custom class names may contain private data.
    names = {"BrokerError", "TimeoutError", "OSError", "BrokenPipeError",
             "FileNotFoundError", "PermissionError", "JSONDecodeError",
             "UnicodeDecodeError", "ValueError", "TypeError", "KeyError",
             "TurnEnvelopeError", "RuntimeError"}
    for member in type(error).__mro__:
        if member.__name__ in names:
            return member.__name__
    return "Exception"


def _diagnostic_exception(error: BaseException) -> str:
    return _safe_exception_class(error.__cause__ or error)


def _diagnostic_failure_kind(error: BaseException) -> str:
    # Only fixed local reasons become codes; never export arbitrary error text.
    return {
        "upstream response timed out": "response_timeout",
        "upstream closed its response stream": "response_eof",
        "upstream request transport failed": "request_write_failed",
        "upstream returned invalid JSON": "response_invalid_json",
        "upstream process could not start": "process_start_failed",
    }.get(str(error), "broker_error")


def _elapsed_ms(started: float) -> int:
    return min(86400000, max(0, int((time.monotonic() - started) * 1000)))


def _diagnostic_exit_code(process: Any) -> int | None:
    try:
        code = process.poll() if process is not None else None
        return code if type(code) is int and -(2**63) < code < 2**63 else None
    except Exception:
        return None


def _persist_transport_diagnostic(diagnostic: dict[str, Any], *, request_sent: bool) -> bool:
    """Eight fixed, atomically replaced metadata slots; no request/error text."""
    try:
        root = Path(os.environ.get("INTEGRITY_CLIENT_STATE_ROOT",
            str(Path.home()/".codex/integrity-memory/state"))).parent / "transport-diagnostics-v1"
        root = turn_envelope._ensure_root(root)
        record = {"protocol": "integrity-client/transport-observation/v1",
                  "observed_epoch_seconds": int(time.time()),
                  "broker_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  "request_sent": bool(request_sent), "diagnostic": diagnostic}
        if len(_json_bytes(record)) > 8192:
            return False
        # Collisions replace older observations; bounded storage is intentional.
        with turn_envelope._exclusive_root_lock(root):
            turn_envelope._write_atomic(root / ("failure-"+str(os.getpid() % 8)+".json"), record)
        return True
    except Exception:
        # Diagnostic custody failure must never replace the actual operation.
        return False


class _StderrDiagnostic:
    """Bounded in-memory classifier. Neither text nor text hashes are exported."""
    _patterns = {
        "ssh_authentication_failed": b"permission denied (publickey",
        "ssh_host_key_failed": b"host key verification failed",
        "ssh_connection_refused": b"connection refused",
        "ssh_connection_timed_out": b"connection timed out",
        "ssh_connection_reset": b"connection reset",
        "ssh_name_resolution_failed": b"could not resolve hostname",
    }

    def __init__(self):
        self.bytes = 0
        self.flags: set[str] = set()
        self._tail = b""
        self._lock = threading.Lock()

    def feed(self, chunk: bytes) -> None:
        with self._lock:
            self.bytes = min(self.bytes + len(chunk), 2**63-1)
            value = self._tail + chunk.lower()
            self.flags.update(name for name, pattern in self._patterns.items() if pattern in value)
            self._tail = value[-64:]

    def clear(self) -> None:
        with self._lock:
            self._tail = b""

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"stderr_bytes": self.bytes, "stderr_hints": sorted(self.flags)}


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _load_tools_contract(path: Path) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerError("tools contract is unavailable", layer="broker-config") from exc
    if not isinstance(value, list) or not value:
        raise BrokerError("tools contract is invalid", layer="broker-config")
    names: list[str] = []
    for item in value:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("name"), str)
            or not isinstance(item.get("description"), str)
            or not isinstance(item.get("inputSchema"), dict)
            or not isinstance(item.get("annotations"), dict)
        ):
            raise BrokerError("tools contract entry is invalid", layer="broker-config")
        names.append(item["name"])
    if len(names) != len(set(names)) or "integrity_context_admission" not in names:
        raise BrokerError("tools contract names are invalid", layer="broker-config")
    return value


def _tool_surface(value: list[dict[str, Any]]) -> bytes:
    if not all(isinstance(item, dict) for item in value):
        raise BrokerError("upstream tool contract changed", layer="broker-upstream")
    return _json_bytes(
        [
            {
                "name": item.get("name"),
                "inputSchema": item.get("inputSchema"),
                "annotations": item.get("annotations"),
            }
            for item in value
        ]
    )


def _tool_surface_sha256(value: list[dict[str, Any]]) -> str:
    return "sha256:" + hashlib.sha256(_tool_surface(value)).hexdigest()


def _surface_acknowledged(initialized: dict[str, Any], expected_sha256: str) -> bool:
    capabilities = initialized.get("capabilities")
    experimental = capabilities.get("experimental") if isinstance(capabilities, dict) else None
    acknowledgement = (
        experimental.get(BROKER_TOOL_SURFACE_CAPABILITY) if isinstance(experimental, dict) else None
    )
    return bool(
        isinstance(acknowledgement, dict)
        and acknowledgement.get("protocol") == BROKER_TOOL_SURFACE_PROTOCOL
        and acknowledgement.get("accepted_tools_surface_sha256") == expected_sha256
        and acknowledgement.get("compatibility")
        == "local-contract-facade-with-upstream-name-subset/v1"
    )


def _context_admission_replay_acknowledgement(
    initialized: dict[str, Any],
    reservation_id: str | None,
) -> dict[str, Any] | None:
    capabilities = initialized.get("capabilities")
    experimental = capabilities.get("experimental") if isinstance(capabilities, dict) else None
    acknowledgement = (
        experimental.get(CONTEXT_ADMISSION_REPLAY_CAPABILITY)
        if isinstance(experimental, dict)
        else None
    )
    if not (
        isinstance(acknowledgement, dict)
        and acknowledgement.get("protocol") == CONTEXT_ADMISSION_REPLAY_PROTOCOL
        and acknowledgement.get("request_identity_field")
        == CONTEXT_ADMISSION_REPLAY_FIELD
        and acknowledgement.get("request_identity_format") == "sha256/v1"
        and reservation_id is not None
        and acknowledgement.get("reservation_id") == reservation_id
        and acknowledgement.get("reservation_method")
        == CONTEXT_ADMISSION_REPLAY_RESERVE_METHOD
        and acknowledgement.get("ack_method") == CONTEXT_ADMISSION_REPLAY_ACK_METHOD
        and acknowledgement.get("durability") == "architecture-custody-root/v1"
        and acknowledgement.get("replay_semantics") == "exact-response/v1"
        and acknowledgement.get("max_transport_retries") == 1
        and acknowledgement.get("reservation_status")
        in {None, "reserved", "unavailable"}
    ):
        return None
    return acknowledgement


def _upstream_supports_local_tools(
    upstream_tools: list[dict[str, Any]], tools_contract: list[dict[str, Any]]
) -> bool:
    """Require every broker-exposed contract to remain byte-structurally callable.

    An acknowledgement permits additive upstream tools; it never permits a
    same-name schema or annotation change.  Comparing only names let an
    upstream release acknowledge a retained digest while silently breaking
    the installed broker's arguments contract.
    """

    if not all(isinstance(item, dict) for item in upstream_tools):
        return False
    upstream_names = [item.get("name") for item in upstream_tools]
    if not all(isinstance(name, str) and name for name in upstream_names):
        return False
    upstream_by_name = dict(zip(upstream_names, upstream_tools, strict=True))
    if len(upstream_by_name) != len(upstream_tools):
        return False
    for local in tools_contract:
        upstream = upstream_by_name.get(local["name"])
        if upstream is None or any(
            upstream.get(field) != local.get(field)
            for field in ("inputSchema", "annotations")
        ):
            return False
    return True


def _load_upstream(
    config_path: Path, server_name: str
) -> tuple[list[str], dict[str, str], str | None]:
    try:
        with config_path.open("rb") as stream:
            config = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise BrokerError("Codex MCP config is unavailable", layer="broker-config") from exc
    servers = config.get("mcp_servers")
    server = servers.get(server_name) if isinstance(servers, dict) else None
    if not isinstance(server, dict):
        raise BrokerError("internal upstream registration is missing", layer="broker-config")
    if server.get("enabled") is not False:
        raise BrokerError("internal upstream must be disabled for Codex", layer="broker-config")
    command = server.get("command")
    arguments = server.get("args", [])
    configured_env = server.get("env")
    cwd = server.get("cwd")
    if not isinstance(command, str) or not command.strip():
        raise BrokerError("internal upstream command is invalid", layer="broker-config")
    if not isinstance(arguments, list) or not all(isinstance(item, str) for item in arguments):
        raise BrokerError("internal upstream arguments are invalid", layer="broker-config")
    if configured_env is None:
        configured_env = {}
    if not isinstance(configured_env, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in configured_env.items()
    ):
        raise BrokerError("internal upstream environment is invalid", layer="broker-config")
    if cwd is not None and not isinstance(cwd, str):
        raise BrokerError("internal upstream working directory is invalid", layer="broker-config")
    environment = dict(os.environ)
    environment.update(configured_env)
    return [command, *arguments], environment, cwd


"""Own one local subprocess tree. Embedded verbatim in the generated broker.

Windows creates the child inside a non-inherited kill-on-close Job, atomically,
using PROC_THREAD_ATTRIBUTE_JOB_LIST. No global process enumeration or shell kill.
The POSIX path retains the existing Popen behavior; it is not Linux acceptance.
"""
import ctypes
import os
import subprocess
import threading
import time


if os.name == "nt":
    from ctypes import wintypes as W
    import msvcrt

    class _IOCounters(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class _BasicLimit(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong), ("LimitFlags", W.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", W.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", W.DWORD),
                    ("SchedulingClass", W.DWORD)]

    class _ExtendedLimit(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", _BasicLimit), ("IoInfo", _IOCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    class _Accounting(ctypes.Structure):
        _fields_ = [(n, ctypes.c_longlong) for n in (
            "TotalUserTime", "TotalKernelTime", "ThisPeriodTotalUserTime", "ThisPeriodTotalKernelTime")] + [
            (n, W.DWORD) for n in ("TotalPageFaultCount", "TotalProcesses", "ActiveProcesses", "TotalTerminatedProcesses")]

    class _Startup(ctypes.Structure):
        _fields_ = [("cb", W.DWORD), ("lpReserved", W.LPWSTR), ("lpDesktop", W.LPWSTR),
                    ("lpTitle", W.LPWSTR)] + [(n, W.DWORD) for n in (
                        "dwX", "dwY", "dwXSize", "dwYSize", "dwXCountChars", "dwYCountChars", "dwFillAttribute", "dwFlags")] + [
                    ("wShowWindow", W.WORD), ("cbReserved2", W.WORD), ("lpReserved2", ctypes.c_void_p),
                    ("hStdInput", W.HANDLE), ("hStdOutput", W.HANDLE), ("hStdError", W.HANDLE)]

    class _StartupEx(ctypes.Structure):
        _fields_ = [("StartupInfo", _Startup), ("lpAttributeList", ctypes.c_void_p)]

    class _ProcessInfo(ctypes.Structure):
        _fields_ = [("hProcess", W.HANDLE), ("hThread", W.HANDLE), ("dwProcessId", W.DWORD), ("dwThreadId", W.DWORD)]

    _kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    def _api(name, args, result=W.BOOL):
        fn = getattr(_kernel, name); fn.argtypes = args; fn.restype = result
        return fn
    _create_job = _api("CreateJobObjectW", [ctypes.c_void_p, W.LPCWSTR], W.HANDLE)
    _set_job = _api("SetInformationJobObject", [W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD])
    _query_job = _api("QueryInformationJobObject", [W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD, ctypes.c_void_p])
    _kill_job = _api("TerminateJobObject", [W.HANDLE, W.UINT])
    _close_handle = _api("CloseHandle", [W.HANDLE])
    _init_attributes = _api("InitializeProcThreadAttributeList", [ctypes.c_void_p, W.DWORD, W.DWORD, ctypes.POINTER(ctypes.c_size_t)])
    _update_attribute = _api("UpdateProcThreadAttribute", [ctypes.c_void_p, W.DWORD, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p])
    _delete_attributes = _api("DeleteProcThreadAttributeList", [ctypes.c_void_p], None)
    _create_process = _api("CreateProcessW", [W.LPCWSTR, W.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, W.BOOL,
        W.DWORD, ctypes.c_void_p, W.LPCWSTR, ctypes.POINTER(_StartupEx), ctypes.POINTER(_ProcessInfo)])
    _wait_handle = _api("WaitForSingleObject", [W.HANDLE, W.DWORD], W.DWORD)
    _exit_code = _api("GetExitCodeProcess", [W.HANDLE, ctypes.POINTER(W.DWORD)])
    _terminate_process = _api("TerminateProcess", [W.HANDLE, W.UINT])
    _spawn_lock = threading.Lock()

    def _check(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    class OwnedProcess:
        def __init__(self, command, *, env, cwd=None):
            if not command or any(not isinstance(x, str) or "\0" in x for x in command):
                raise ValueError("invalid upstream command")
            self.stdin = self.stdout = self.stderr = None
            self._job = self._handle = None
            self.returncode = None
            self.pid = None
            self._job = _create_job(None, None)  # security attributes NULL => non-inherited
            _check(self._job)
            fds = []; attributes = None; attributes_ready = False
            info = _ProcessInfo()
            try:
                limit = _ExtendedLimit(); limit.BasicLimitInformation.LimitFlags = 0x2000
                _check(_set_job(self._job, 9, ctypes.byref(limit), ctypes.sizeof(limit)))
                # Only these explicit pipe handles are inherited. The Job handle is never inherited.
                with _spawn_lock:
                    child_in, parent_in = os.pipe(); fds.extend([child_in, parent_in])
                    parent_out, child_out = os.pipe(); fds.extend([parent_out, child_out])
                    parent_err, child_err = os.pipe(); fds.extend([parent_err, child_err])
                    child_fds = [child_in, child_out, child_err]
                    for fd in child_fds: os.set_inheritable(fd, True)
                    handles = (W.HANDLE * 3)(*[msvcrt.get_osfhandle(fd) for fd in child_fds])
                    jobs = (W.HANDLE * 1)(self._job)
                    size = ctypes.c_size_t()
                    _init_attributes(None, 2, 0, ctypes.byref(size))
                    if not size.value: raise ctypes.WinError(ctypes.get_last_error())
                    attributes = ctypes.create_string_buffer(size.value)
                    _check(_init_attributes(attributes, 2, 0, ctypes.byref(size))); attributes_ready = True
                    _check(_update_attribute(attributes, 0, 0x20002, handles, ctypes.sizeof(handles), None, None))
                    _check(_update_attribute(attributes, 0, 0x2000D, jobs, ctypes.sizeof(jobs), None, None))
                    startup = _StartupEx(); startup.StartupInfo.cb = ctypes.sizeof(startup)
                    startup.StartupInfo.dwFlags = 0x100 | 1; startup.StartupInfo.wShowWindow = 0
                    startup.StartupInfo.hStdInput, startup.StartupInfo.hStdOutput, startup.StartupInfo.hStdError = handles
                    startup.lpAttributeList = ctypes.cast(attributes, ctypes.c_void_p)
                    wire_command = ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
                    for k, v in env.items():
                        if not isinstance(k, str) or not isinstance(v, str) or not k or "=" in k or "\0" in k+v:
                            raise ValueError("invalid upstream environment")
                    environment = ctypes.create_unicode_buffer("\0".join(k+"="+v for k, v in sorted(env.items(), key=lambda x:x[0].upper()))+"\0\0")
                    _check(_create_process(None, wire_command, None, None, True,
                        0x80000 | 0x8000000 | 0x400, environment, cwd, ctypes.byref(startup), ctypes.byref(info)))
                    self._handle, self.pid = info.hProcess, info.dwProcessId
                    _close_handle(info.hThread); info.hThread = None
                    for fd in child_fds: os.close(fd); fds.remove(fd)
                self.stdin = os.fdopen(parent_in, "wb", buffering=0); fds.remove(parent_in)
                self.stdout = os.fdopen(parent_out, "rb", buffering=0); fds.remove(parent_out)
                self.stderr = os.fdopen(parent_err, "rb", buffering=0); fds.remove(parent_err)
            except BaseException:
                if self._job: _kill_job(self._job, 125)
                if self._handle:
                    _wait_handle(self._handle, 2000); _close_handle(self._handle); self._handle = None
                if self._job: _close_handle(self._job); self._job = None
                for stream in (self.stdin, self.stdout, self.stderr):
                    if stream is not None: stream.close()
                raise
            finally:
                for fd in fds: os.close(fd)
                if attributes_ready: _delete_attributes(attributes)

        def poll(self):
            if self.returncode is None:
                state = _wait_handle(self._handle, 0)
                if state == 0:
                    code = W.DWORD(); _check(_exit_code(self._handle, ctypes.byref(code)))
                    self.returncode = code.value
                elif state != 258: raise ctypes.WinError(ctypes.get_last_error())
            return self.returncode

        def wait(self, timeout=None):
            if self.returncode is not None: return self.returncode
            state = _wait_handle(self._handle, 0xffffffff if timeout is None else max(0, int(timeout*1000)))
            if state == 258: raise subprocess.TimeoutExpired("owned upstream", timeout)
            if state != 0: raise ctypes.WinError(ctypes.get_last_error())
            return self.poll()

        def terminate(self):
            if self.poll() is None: _check(_terminate_process(self._handle, 125))
        kill = terminate

        def tree_active(self):
            if self._job is None: return 0
            counts = _Accounting()
            _check(_query_job(self._job, 1, ctypes.byref(counts), ctypes.sizeof(counts), None))
            return counts.ActiveProcesses

        def close_tree(self, timeout=2):
            if self._job is not None:
                if self.tree_active(): _check(_kill_job(self._job, 125))
                deadline = time.monotonic()+timeout
                while self.tree_active():
                    if time.monotonic() >= deadline:
                        raise OSError("owned process tree did not exit")
                    time.sleep(.02)
                _check(_close_handle(self._job)); self._job = None
            self.wait(timeout=timeout)
            if self._handle is not None:
                _check(_close_handle(self._handle)); self._handle = None

else:
    class OwnedProcess(subprocess.Popen):
        def __init__(self, command, *, env, cwd=None):
            super().__init__(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=env, cwd=cwd, bufsize=0)
        def close_tree(self, timeout=2):
            self.wait(timeout=timeout)


class PublicInput:
    """Single stdin reader observes EOF even while dispatch is waiting upstream.

    Bounded read-ahead; overflow closes the transport, never executes unread input.
    It never creates a lifecycle receipt or silently retries a request.
    """
    def __init__(self, stream, limit, cancelled):
        import queue
        self.items = queue.Queue(maxsize=8)
        self.cancelled = cancelled
        self.error = None
        self.thread = threading.Thread(target=self._read, args=(stream, limit), daemon=True)
        self.thread.start()

    def _read(self, stream, limit):
        import queue
        try:
            while not self.cancelled.is_set():
                raw = stream.readline(limit+1)
                if not raw: break
                try: self.items.put_nowait(raw)
                except queue.Full:
                    self.error = "public input backlog exceeded"; break
        except (OSError, ValueError):
            self.error = "public input closed"
        finally:
            self.cancelled.set()

    def next(self):
        import queue
        while True:
            try: return self.items.get(timeout=.1)
            except queue.Empty:
                if self.cancelled.is_set(): return None


class UpstreamFacade:
    """One initialized upstream stdio process shared by sequential logical contexts."""

    def __init__(
        self,
        command: list[str],
        environment: dict[str, str],
        cwd: str | None,
        tools_contract: list[dict[str, Any]],
        initialize_params: dict[str, Any],
        context_replay_reservation_id: str | None = None,
        public_cancelled: threading.Event | None = None,
        context_control_only: bool = False,
    ) -> None:
        self._public_cancelled = public_cancelled
        self._close_lock = threading.Lock()
        self._stderr_bytes = 0
        self._stderr_diagnostic = _StderrDiagnostic()
        self._diagnostic_timings: dict[str, int] = {}
        self._negotiation: dict[str, bool] = {}
        self._diagnostic_phase = "spawn"
        self._responses: queue.Queue[bytes | None] = queue.Queue()
        self._next_id = 1_000_000_000
        self.context_admission_replay_safe = False
        self.context_admission_replay_contract_safe = False
        self.context_admission_replay_ack_request_safe = False
        self.context_reattach_safe = False
        self.context_retire_safe = False
        self.context_control_only = False
        if type(context_control_only) is not bool or context_control_only and context_replay_reservation_id is not None:
            raise BrokerError("private control startup arguments invalid",layer="broker-context-control",request_sent=False)
        self._context_replay_reservation_id = context_replay_reservation_id
        try:
            self._check_public(request_sent=False)
            self.process = OwnedProcess(command, env=environment, cwd=cwd)
        except OSError as exc:
            error = BrokerError(
                "upstream process could not start",
                layer="broker-upstream",
                retryable=True,
            )
            error.diagnostic = {"phase": "spawn", "exception_class": _safe_exception_class(exc),
                                "failure_kind": "process_start_failed"}
            raise error from exc
        try:
            assert self.process.stdin is not None and self.process.stdout is not None
            self._reader = threading.Thread(target=self._read_stdout, daemon=True)
            self._stderr_reader = threading.Thread(target=self._drain_stderr, daemon=True)
            self._reader.start()
            self._stderr_reader.start()
            params = dict(initialize_params)
            tools_surface_sha256 = _tool_surface_sha256(tools_contract)
            capabilities = params.get("capabilities")
            capabilities = dict(capabilities) if isinstance(capabilities, dict) else {}
            experimental = capabilities.get("experimental")
            experimental = dict(experimental) if isinstance(experimental, dict) else {}
            experimental[BROKER_TOOL_SURFACE_CAPABILITY] = {
                "protocol": BROKER_TOOL_SURFACE_PROTOCOL,
                "tools_surface_sha256": tools_surface_sha256,
            }
            experimental[CONTEXT_ADMISSION_REPLAY_CAPABILITY] = {
                "protocol": CONTEXT_ADMISSION_REPLAY_PROTOCOL,
                "request_identity_field": CONTEXT_ADMISSION_REPLAY_FIELD,
                "request_identity_format": "sha256/v1",
                **(
                    {"reservation_id": context_replay_reservation_id}
                    if context_replay_reservation_id is not None
                    else {}
                ),
            }
            experimental[CONTEXT_REATTACH_CAPABILITY] = {
                "protocol": CONTEXT_REATTACH_PROTOCOL,
                **({"control_only":True} if context_control_only else {})}

            experimental["integrity/session-recovery"] = {
                "protocol": "integrity-client/session-recovery/v1"}
            capabilities["experimental"] = experimental
            params["capabilities"] = capabilities
            params["clientInfo"] = {
                "name": "integrity-client-turn-broker",
                "version": BROKER_VERSION,
            }
            initialized = self.request(
                "initialize",
                params,
                timeout=UPSTREAM_INITIALIZE_TIMEOUT_SECONDS,
            )
            server_info = initialized.get("serverInfo")
            if not isinstance(server_info, dict) or server_info.get("name") != BROKER_NAME:
                raise BrokerError("upstream identity mismatch", layer="broker-upstream")
            replay_acknowledgement = _context_admission_replay_acknowledgement(
                initialized,
                context_replay_reservation_id,
            )
            self.context_admission_replay_contract_safe = (
                replay_acknowledgement is not None
            )
            self.context_admission_replay_safe = bool(
                replay_acknowledgement is not None
                and replay_acknowledgement.get("reservation_status")
                != "unavailable"
            )
            self.context_admission_replay_ack_request_safe = (
                self.context_admission_replay_contract_safe
            )
            acknowledged_caps = initialized.get("capabilities")
            acknowledged_caps = acknowledged_caps.get("experimental") if isinstance(acknowledged_caps, dict) else None
            acknowledged_caps = acknowledged_caps if isinstance(acknowledged_caps, dict) else {}
            self._same_session_capabilities = dict(acknowledged_caps)
            resume = acknowledged_caps.get(CONTEXT_REATTACH_CAPABILITY)
            self.context_control_only = bool(
                context_control_only and isinstance(resume,dict)
                and resume.get("control_only") is True
                and resume.get("protocol")==CONTEXT_REATTACH_PROTOCOL
                and resume.get("method")==CONTEXT_REATTACH_METHOD
                and resume.get("retire_method")==CONTEXT_REATTACH_RETIRE_METHOD
                and resume.get("read_only") is True
                and type(resume.get("retention_seconds")) is int
                and 0<resume["retention_seconds"]<=86400
                and _surface_acknowledged(initialized,tools_surface_sha256))
            self.context_admission_replay_ack_request_safe = bool(
                self.context_admission_replay_ack_request_safe or self.context_control_only)
            self.context_reattach_safe = bool(
                (self.context_admission_replay_contract_safe or self.context_control_only) and isinstance(resume, dict)
                and resume.get("protocol") == CONTEXT_REATTACH_PROTOCOL
                and resume.get("method") == CONTEXT_REATTACH_METHOD
                and resume.get("read_only") is True
                and isinstance(resume.get("retention_seconds"), int)
                and not isinstance(resume.get("retention_seconds"), bool)
                and 0 < resume["retention_seconds"] <= 86400
            )
            self.context_retire_safe = bool(self.context_reattach_safe and
                resume.get("retire_method")==CONTEXT_REATTACH_RETIRE_METHOD)
            reattach = resume if isinstance(resume, dict) else {}
            replay = acknowledged_caps.get(CONTEXT_ADMISSION_REPLAY_CAPABILITY)
            replay = replay if isinstance(replay, dict) else {}
            self._negotiation = {
                "tool_surface_acknowledged": _surface_acknowledged(initialized, tools_surface_sha256),
                "replay_contract_safe": self.context_admission_replay_contract_safe,
                "replay_reservation_requested": context_replay_reservation_id is not None,
                "replay_protocol_matches": replay.get("protocol") == CONTEXT_ADMISSION_REPLAY_PROTOCOL,
                "replay_identity_field_matches": replay.get("request_identity_field") == CONTEXT_ADMISSION_REPLAY_FIELD,
                "replay_identity_format_matches": replay.get("request_identity_format") == "sha256/v1",
                "replay_reservation_matches": context_replay_reservation_id is not None and replay.get("reservation_id") == context_replay_reservation_id,
                "replay_reserve_method_matches": replay.get("reservation_method") == CONTEXT_ADMISSION_REPLAY_RESERVE_METHOD,
                "replay_ack_method_matches": replay.get("ack_method") == CONTEXT_ADMISSION_REPLAY_ACK_METHOD,
                "replay_durability_matches": replay.get("durability") == "architecture-custody-root/v1",
                "replay_semantics_matches": replay.get("replay_semantics") == "exact-response/v1",
                "replay_retry_bound_matches": replay.get("max_transport_retries") == 1,
                "replay_reservation_status_valid": replay.get("reservation_status") in (None, "reserved", "unavailable"),
                "control_only_requested": context_control_only,
                "control_only_acknowledged": reattach.get("control_only") is True,
                "control_only_safe": self.context_control_only,
                "reattach_present": isinstance(resume, dict),
                "reattach_protocol_matches": reattach.get("protocol") == CONTEXT_REATTACH_PROTOCOL,
                "reattach_method_matches": reattach.get("method") == CONTEXT_REATTACH_METHOD,
                "reattach_read_only": reattach.get("read_only") is True,
                "reattach_retention_valid": type(reattach.get("retention_seconds")) is int and 0 < reattach["retention_seconds"] <= 86400,
                "retire_method_matches": reattach.get("retire_method") == CONTEXT_REATTACH_RETIRE_METHOD,
                "retirement_safe": self.context_retire_safe,
            }
            self.notify("notifications/initialized", {})
            listed = self.request(
                "tools/list",
                {},
                timeout=UPSTREAM_INITIALIZE_TIMEOUT_SECONDS,
            )
            upstream_tools = listed.get("tools")
            acknowledged = _surface_acknowledged(initialized, tools_surface_sha256)
            if (
                not isinstance(upstream_tools, list)
                or (
                    acknowledged
                    and not _upstream_supports_local_tools(upstream_tools, tools_contract)
                )
                or (
                    not acknowledged
                    and _tool_surface(upstream_tools) != _tool_surface(tools_contract)
                )
            ):
                raise BrokerError("upstream tool contract changed", layer="broker-upstream")
        except BaseException as error:
            if isinstance(error, BrokerError):
                error.diagnostic = {**self.diagnostic(), **error.diagnostic}
            if (
                self.context_admission_replay_ack_request_safe
                and self._context_replay_reservation_id is not None
            ):
                empty_digest = "sha256:" + hashlib.sha256(_json_bytes({})).hexdigest()
                try:
                    self.acknowledge_context_admission_replay(
                        {
                            "replay_id": self._context_replay_reservation_id,
                            "request_digest": empty_digest,
                            "response_digest": empty_digest,
                        }
                    )
                except BrokerError:
                    pass
            failed_process = getattr(self, "process", None)
            try:
                self.close()
            finally:
                if isinstance(error, BrokerError):
                    # Capture bytes/exit after bounded cleanup, preserving the
                    # failing phase and its duration, never the cleanup request.
                    error.diagnostic.update(self._stderr_diagnostic.snapshot())
                    error.diagnostic["exit_code_after_cleanup"] = _diagnostic_exit_code(failed_process)
            raise

    def _exit_code(self):
        return _diagnostic_exit_code(getattr(self, "process", None))

    def diagnostic(self) -> dict[str, Any]:
        return {"protocol": "integrity-client/transport-diagnostic/v1",
                "phase": self._diagnostic_phase, "exit_code": self._exit_code(),
                "timing_ms": dict(self._diagnostic_timings),
                "negotiation": dict(self._negotiation),
                **self._stderr_diagnostic.snapshot()}

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        try:
            while True:
                raw = self.process.stdout.readline(MAX_MESSAGE_BYTES + 1)
                if not raw:
                    break
                self._responses.put(raw)
        finally:
            self._responses.put(None)

    def _check_public(self, *, request_sent: bool) -> None:
        if self._public_cancelled is not None and self._public_cancelled.is_set():
            raise BrokerError("public input transport closed", layer="broker-upstream",
                              request_sent=request_sent, retryable=False)

    def _drain_stderr(self) -> None:
        stream = self.process.stderr
        if stream is None:
            return
        try:
            while chunk := stream.read(8192):
                self._stderr_diagnostic.feed(chunk)
                self._stderr_bytes = self._stderr_diagnostic.bytes
        except (OSError, ValueError):
            pass
        finally:
            self._stderr_diagnostic.clear()

    def _write(self, message: dict[str, Any]) -> None:
        self._check_public(request_sent=False)
        assert self.process.stdin is not None
        payload = _json_bytes(message)
        if len(payload) > MAX_MESSAGE_BYTES:
            raise BrokerError("upstream request exceeds limit", layer="broker-upstream")
        wire_payload = payload + b"\n"
        written_total = 0
        try:
            while written_total < len(wire_payload):
                written = self.process.stdin.write(
                    memoryview(wire_payload)[written_total:]
                )
                if (
                    not isinstance(written, int)
                    or isinstance(written, bool)
                    or written <= 0
                    or written > len(wire_payload) - written_total
                ):
                    raise OSError("upstream request transport made no progress")
                written_total += written
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise BrokerError(
                "upstream request transport failed",
                layer="broker-upstream",
                request_sent=written_total > 0,
                retryable=True,
            ) from exc

    def _receive(self, request_id: Any, *, timeout: int, request_sent: bool) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            self._check_public(request_sent=request_sent)
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise BrokerError("upstream response timed out", layer="broker-upstream",
                                  request_sent=request_sent, retryable=True)
            try:
                raw = self._responses.get(timeout=min(.1, remaining))
            except queue.Empty:
                continue
            if raw is None:
                raise BrokerError("upstream closed its response stream", layer="broker-upstream",
                                  request_sent=request_sent, retryable=True)
            result = self._decode_response(raw, request_id, request_sent)
            if result is not None:
                return result

    def retain_timed_out_append(self, error):
        process = getattr(self, "process", None)
        retain = (str(error) == "upstream response timed out" and error.request_sent
                  and error.layer == "broker-upstream" and process is not None
                  and process.poll() is None)
        if retain:
            self._late_append_id = self._next_id - 1
        return retain

    def _decode_response(self, raw, request_id, request_sent):
        if len(raw) > MAX_MESSAGE_BYTES:
            raise BrokerError(
                "upstream response exceeds limit",
                layer="broker-upstream",
                request_sent=request_sent,
                retryable=True,
            )
        try:
            response = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BrokerError(
                "upstream returned invalid JSON",
                layer="broker-upstream",
                request_sent=request_sent,
                retryable=True,
            ) from exc
        if not isinstance(response, dict):
            raise BrokerError(
                "upstream response id mismatch",
                layer="broker-upstream",
                request_sent=request_sent,
                retryable=True,
            )
        if response.get("id") != request_id:
            late_lifecycle = getattr(self, "_late_lifecycle_requests", {}).pop(response.get("id"), None)
            if late_lifecycle is not None:
                values = getattr(self, "_late_lifecycle_responses", [])
                values.append((late_lifecycle, response))
                self._late_lifecycle_responses = values
                return None
            late_id = getattr(self, "_late_append_id", None)
            if late_id is None or response.get("id") != late_id:
                raise BrokerError("upstream response id mismatch", layer="broker-upstream",
                                  request_sent=request_sent, retryable=True)
            self._late_append_id = None
            self._late_append_response = response
            return None
        if response.get("error") is not None:
            raise BrokerError(
                "upstream rejected the MCP request",
                layer="broker-upstream",
                request_sent=request_sent,
            )
        result = response.get("result")
        if not isinstance(result, dict):
            raise BrokerError(
                "upstream result is invalid",
                layer="broker-upstream",
                request_sent=request_sent,
            )
        return result

    def request(self, method: str, params: dict[str, Any], *, timeout: int) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        phase = {"initialize": "initialize", "tools/list": "tools_list",
                 CONTEXT_REATTACH_RETIRE_METHOD: "context_retirement",
                 CONTEXT_REATTACH_METHOD: "context_reattach",
                 CONTEXT_ADMISSION_REPLAY_RESERVE_METHOD: "replay_reserve",
                 CONTEXT_ADMISSION_REPLAY_ACK_METHOD: "replay_ack"}.get(method, "control")
        if method == "tools/call":
            phase = {"integrity_context_admission": "context_admission",
                     "integrity_turn_memory_open": "turn_open",
                     "integrity_turn_memory_close": "turn_close",
                     "integrity_turn_memory_coverage": "turn_coverage",
                     "integrity_turn_memory_gap": "turn_gap",
                     "integrity_append_event": "append"}.get(params.get("name"), "tool_call")
        self._diagnostic_phase = phase
        started = time.monotonic()
        try:
            self._write({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
            return self._receive(request_id, timeout=timeout, request_sent=True)
        except BrokerError as error:
            self._diagnostic_timings[phase] = _elapsed_ms(started)
            error.diagnostic = {**self.diagnostic(), "exception_class": _diagnostic_exception(error),
                                "failure_kind": _diagnostic_failure_kind(error)}
            raise
        finally:
            self._diagnostic_timings[phase] = _elapsed_ms(started)

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.request(
            "tools/call",
            {"name": name, "arguments": arguments},
            timeout=(
                UPSTREAM_CONTEXT_ADMISSION_TIMEOUT_SECONDS
                if name == "integrity_context_admission"
                else UPSTREAM_TOOL_TIMEOUT_SECONDS
            ),
        )

    def reserve_context_admission_replay(self, reservation_id: str) -> bool:
        if not self.context_admission_replay_contract_safe:
            return False
        try:
            result = self.request(
                CONTEXT_ADMISSION_REPLAY_RESERVE_METHOD,
                {"reservation_id": reservation_id},
                timeout=CONTEXT_ADMISSION_REPLAY_CONTROL_TIMEOUT_SECONDS,
            )
        except BrokerError as exc:
            if exc.retryable:
                raise
            return False
        reserved = bool(
            result.get("protocol")
            == "integrity-client/context-admission-replay-reservation/v1"
            and result.get("reservation_id") == reservation_id
            and result.get("reserved") is True
        )
        if reserved:
            self.context_admission_replay_safe = True
            self.context_admission_replay_ack_request_safe = True
        return reserved

    def acknowledge_context_admission_replay(
        self,
        acknowledgement: dict[str, str],
    ) -> bool:
        result = self.request(
            CONTEXT_ADMISSION_REPLAY_ACK_METHOD,
            acknowledgement,
            timeout=CONTEXT_ADMISSION_REPLAY_CONTROL_TIMEOUT_SECONDS,
        )
        return bool(
            result.get("protocol")
            == "integrity-client/context-admission-replay-reservation/v1"
            and result.get("replay_id") == acknowledgement.get("replay_id")
            and result.get("retired") is True
        )

    def retire_superseded_context(self, control):
        if not self.context_retire_safe:
            error = BrokerError("upstream lacks exact delivered-cache retirement",
                                layer="broker-context-retirement",request_sent=False)
            error.diagnostic = {**self.diagnostic(), "phase": "retirement_negotiation"}
            raise error
        result=self.request(CONTEXT_REATTACH_RETIRE_METHOD,control,
                            timeout=CONTEXT_ADMISSION_REPLAY_CONTROL_TIMEOUT_SECONDS)
        if (result.get("protocol")!=CONTEXT_REATTACH_PROTOCOL
                or result.get("replay_id")!=control["replay_id"]
                or result.get("scope")!="derived-delivered-context-only"
                or result.get("canonical_writes")!=0
                or result.get("action_authority") is not False
                or result.get("automatic_retry_allowed") is not False):
            raise BrokerError("derived-cache retirement receipt mismatch",
                              layer="broker-context-retirement",request_sent=False)
        # An absent DERIVED cache is only a cache observation. Genuine NEW
        # admission remains independently guarded; no old canonical request repeats.
        if not (result.get("retired") is True or
                (result.get("retired") is False and result.get("retained") is False
                 and result.get("retirement_status")=="already-absent")):
            raise BrokerError("derived-cache retirement result rejected",
                              layer="broker-context-retirement",request_sent=False)
        return result

    def reattach_context(self, control):
        if not self.context_reattach_safe:
            raise BrokerError("upstream does not support delivered context reattach",
                              layer="broker-context-reattach", request_sent=False)
        acknowledgement = {key:control[key] for key in
                           ("replay_id","request_digest","response_digest")}
        # This only acknowledges the already delivered exact receipt; it never
        # invokes admission or a lifecycle write. Existing ACK is idempotent.
        if not self.acknowledge_context_admission_replay(acknowledgement):
            raise BrokerError("delivered context retention could not be acknowledged",
                              layer="broker-context-reattach", request_sent=False)
        result = self.request(CONTEXT_REATTACH_METHOD, control,
                             timeout=CONTEXT_ADMISSION_REPLAY_CONTROL_TIMEOUT_SECONDS)
        valid = (result.get("protocol") == CONTEXT_REATTACH_PROTOCOL
                 and result.get("restored") is True and result.get("read_only") is True
                 and result.get("action_authority") is False
                 and result.get("canonical_writes") == 0
                 and result.get("automatic_retry_allowed") is False
                 and all(result.get(key) == control[key] for key in
                         ("context_admission_id","snapshot_id","prompt_binding",
                          "logical_generation","response_digest")))
        if not valid:
            raise BrokerError("delivered context restore response mismatch",
                              layer="broker-context-reattach", request_sent=False)
        return result

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self._write({"jsonrpc": "2.0", "method": method, "params": params})

    def close(self) -> None:
        with self._close_lock:
            process = getattr(self, "process", None)
            if process is None:
                return
            if process.stdin is not None:
                try:
                    process.stdin.close()
                except OSError:
                    pass
            try:
                if process.poll() is None:
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        try:
                            process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=2)
                # Also handles descendants left after the direct child exited.
                process.close_tree(timeout=2)
            except (OSError, subprocess.TimeoutExpired) as exc:
                # Keep custody and prevent starting a replacement over a live tree.
                raise BrokerError("owned upstream cleanup incomplete", layer="broker-upstream",
                                  request_sent=True, retryable=False) from exc
            for name in ("_reader", "_stderr_reader"):
                reader = getattr(self, name, None)
                if reader is not None and reader.ident is not None and reader is not threading.current_thread():
                    reader.join(timeout=2)
                    if reader.is_alive():
                        raise BrokerError("owned pipe reader cleanup incomplete", layer="broker-upstream",
                                          request_sent=True, retryable=False)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
            self.process = None


"""owner-host transport-start slots, no shared memory/admission state.

File locks are released by the OS after owner death. No PID guessing, expiration
deletion, helper process, persisted request, or wall-clock expiry is involved.
Embedded verbatim in the broker generation.
"""
import errno

STARTUP_GATE_DIRECTORY = Path(_integrity_value('path_6417ae8b427b'))
STARTUP_GATE_SLOTS = 2
STARTUP_GATE_WAIT_SECONDS = 30.0


class StartupGate:
    def __init__(self, cancelled):
        self.cancelled = cancelled
        self.stream = None

    @staticmethod
    def _custody(path):
        for member in (path, *path.parents):
            info = member.lstat()
            if member.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise OSError('transport start gate reparse point')

    def __enter__(self):
        if os.name != 'nt':
            raise BrokerError('owner-host start gate platform unavailable', layer='broker-upstream', retryable=False)
        import msvcrt
        root = STARTUP_GATE_DIRECTORY
        self._custody(root.parent)
        root.mkdir(exist_ok=True)
        self._custody(root)
        if not root.is_dir():raise OSError('transport start gate is not a directory')
        streams = []
        try:
            for slot in range(STARTUP_GATE_SLOTS):
                path = root/('slot-'+str(slot)+'.lock')
                if path.exists():self._custody(path)
                fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_BINARY, 0o600)
                stream = os.fdopen(fd, 'r+b', buffering=0);streams.append(stream)
                os.set_inheritable(fd, False)
                self._custody(path)
                if os.fstat(fd).st_size == 0:
                    stream.write(b'\0');stream.flush()
            deadline = time.monotonic()+STARTUP_GATE_WAIT_SECONDS
            # Shuffle starting slot without changing the two-position bound.
            offset = secrets.randbelow(STARTUP_GATE_SLOTS)
            while True:
                if self.cancelled.is_set():
                    raise BrokerError('public input transport closed', layer='broker-upstream', retryable=False)
                for index in range(STARTUP_GATE_SLOTS):
                    stream = streams[(index+offset)%STARTUP_GATE_SLOTS];stream.seek(0)
                    try:
                        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                    except OSError as exc:
                        if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):raise
                        continue
                    self.stream = stream
                    for other in streams:
                        if other is not stream:other.close()
                    return self
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    raise BrokerError('transport start capacity wait expired', layer='broker-upstream',
                                      request_sent=False, retryable=False)
                self.cancelled.wait(min(.1,remaining))
        except BaseException:
            for stream in streams:
                if not stream.closed:stream.close()
            raise

    def __exit__(self, *unused):
        import msvcrt
        stream = self.stream
        self.stream = None
        if stream is not None:
            try:
                stream.seek(0);msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            finally:
                stream.close()


def _startup_cooldown(failures):
    # A cap and bounded jitter, measured with monotonic time. Never persisted
    # as canonical turn state or treated as permission to replay an RPC.
    seconds = min(20.0, 2.0 ** min(failures, 5))
    return seconds*(1.0+secrets.randbelow(251)/1000.0)


class TurnBroker:
    """Local MCP surface with one lazy upstream and server-owned context rotation."""

    def __init__(
        self,
        config_path: Path,
        upstream_server: str,
        tools_contract: list[dict[str, Any]],
    ) -> None:
        self.config_path = config_path
        self.upstream_server = upstream_server
        self.tools_contract = tools_contract
        self.tool_names = {item["name"] for item in tools_contract}
        self.initialize_params: dict[str, Any] = {
            "protocolVersion": DEFAULT_MCP_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "unknown-client", "version": "0"},
        }
        self._public_cancelled = threading.Event()
        self._startup_failures = 0
        self._next_start_at = 0.0
        self._startup_cleanup_pending = None
        self.upstream: UpstreamFacade | None = None
        self.bound = False
        self._own_turn_binding = None
        self._owning_hook_lifecycle_ref = os.environ.get('INTEGRITY_OWNING_LIFECYCLE_REF')
        self._binding_loss_receipt_digest: str | None = None
        self._context_resume_control = None
        self._pending_context_resume_payload = None
        self._context_reattach_read_only = False
        self._context_reattach_attempted = False
        self._context_resume_save_failed = False
        self._context_resume_diagnostic_stage = "not-attempted"
        self._context_resume_error_type = None
        self._uncertain_append_receipt_digest: str | None = None
        self._pending_append_arguments = None
        self._uncertain_archive_uids: set[str] = set()
        self._last_cleanup_failure_type: str | None = None
        self._pending_context_replay_acks: list[dict[str, str]] = []
        self._context_replay_acks_awaiting_public_delivery: set[str] = set()
        self._turn_envelopes_awaiting_public_delivery: list[tuple[str, str]] = []

    def close(self) -> None:
        self.bound = False
        if self.upstream is not None:
            self.upstream.close()
            self.upstream = None
        if self._startup_cleanup_pending is not None:
            self._startup_cleanup_pending.close()
            self._startup_cleanup_pending = None

    def _observe_late_append(self, result):
        response = getattr(self.upstream, "_late_append_response", None)
        if response is None:
            return
        self.upstream._late_append_response = None
        args = self._pending_append_arguments
        if not isinstance(args, dict) or response.get("error") is not None:
            return
        value = response.get("result")
        if not isinstance(value, dict) or value.get("isError") is True:
            return
        # Same normalization as the pinned v3 facade's pure prepare_append.
        tags = list(dict.fromkeys([*(x.strip() for x in args.get("tags", [])),
                                  "client-workstation", "medor", "remote-append", args.get("kind")]))
        normalized = {"event_uid": args.get("event_uid"), "kind": args.get("kind"),
                      "summary": args.get("summary", "").strip(),
                      "details": args.get("details", {}), "tags": tags}
        expected = hashlib.sha256(json.dumps(normalized, ensure_ascii=False, sort_keys=True,
                              separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()
        for block in value.get("content", []):
            if not isinstance(block, dict) or block.get("type") != "text":
                continue
            try:
                receipt = json.loads(block["text"])["receipt"]
            except (KeyError, TypeError, ValueError):
                continue
            if not isinstance(receipt, dict) or not (
                receipt.get("protocol") == "integrity-client-memory-mcp/v3/append-receipt"
                and receipt.get("action_outcome") == "confirmed-success"
                and receipt.get("event_uid") == args.get("event_uid")
                and receipt.get("request_sha256") == expected
                and receipt.get("context_admission_id") == args.get("context_admission_id")
                and type(receipt.get("event_id")) is int and receipt["event_id"] > 0
                and receipt.get("witness_observer_available") is True
            ):
                continue
            self._uncertain_append_receipt_digest = None
            self._pending_append_arguments = None
            result.setdefault("_meta", {})["integrityLateAppendReconciliation"] = {
                key: receipt[key] for key in ("event_id", "event_uid", "request_sha256", "context_admission_id")}
            return

    def _observe_upstream_denial(self, name: str, result: dict[str, Any]) -> None:
        """Invalidate local beliefs only; never replay, restore or replace an error."""
        if result.get("isError") is not True and name != "integrity_append_event":
            return
        content = result.get("content")
        if not isinstance(content, list):
            return
        for item in content:
            if not isinstance(item, dict) or item.get("type") != "text":
                continue
            raw = item.get("text")
            if not isinstance(raw, str) or len(raw) > MAX_MESSAGE_BYTES:
                continue
            try:
                value = json.loads(raw)
            except (ValueError, RecursionError):
                continue
            if not isinstance(value, dict):
                continue
            receipt = value.get("receipt", value)
            if not isinstance(receipt, dict):
                continue
            outcome = receipt.get("outcome")
            action_outcome = receipt.get("action_outcome")
            reason = receipt.get("reason")
            lost = result.get("isError") is True and outcome == "denied" and (
                (receipt.get("failure_layer") == "context-binding"
                 and receipt.get("context_binding_state") == "empty")
                or (isinstance(reason, str) and reason in {
                    "append context binding DENY: current logical context is empty",
                    "append context binding DENY: no composite context admission is active",
                })
            )
            uncertain = name == "integrity_append_event" and any(
                isinstance(candidate, str) and candidate in {"unknown", "unknown-outcome"}
                for candidate in (outcome, action_outcome)
            )
            if not lost and not uncertain:
                continue
            # Observation references are not canonical receipt IDs. ASCII escaping
            # also permits valid JSON containing unpaired Unicode surrogates.
            reference_fields = {
                key: value for key, value in receipt.items()
                if key in {"protocol", "tool", "outcome", "action_outcome", "reason", "reason_code",
                           "arguments_digest", "context_binding_state", "logical_generation"}
                and isinstance(value, (str, int, bool))
            }
            reference = "sha256:" + hashlib.sha256(json.dumps(
                reference_fields, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            ).encode("ascii")).hexdigest()
            if lost:
                self.bound = False
                self._binding_loss_receipt_digest = reference
            if uncertain:
                self._uncertain_append_receipt_digest = reference

    def _new_upstream(
        self,
        context_replay_reservation_id: str | None = None,
        *, context_control_only: bool = False,
    ) -> UpstreamFacade:
        if self._startup_cleanup_pending is not None:
            self._startup_cleanup_pending.close()
            self._startup_cleanup_pending = None
        cooldown_started = time.monotonic()
        remaining = self._next_start_at-time.monotonic()
        if self._public_cancelled.wait(max(0, remaining)):
            raise BrokerError("public input transport closed", layer="broker-upstream", retryable=False)
        command, environment, cwd = _load_upstream(self.config_path, self.upstream_server)
        target = None
        cooldown_ms = _elapsed_ms(cooldown_started)
        gate_started = time.monotonic()
        gate_ms = None
        try:
            with StartupGate(self._public_cancelled):
                gate_ms = _elapsed_ms(gate_started)
                try:
                    target = UpstreamFacade(command, environment, cwd, self.tools_contract,
                        self.initialize_params, context_replay_reservation_id, self._public_cancelled,
                        context_control_only=context_control_only)
                except BaseException:
                    self._startup_failures += 1
                    self._next_start_at = time.monotonic()+_startup_cooldown(self._startup_failures)
                    raise
        except BaseException as exc:
            if isinstance(exc, BrokerError):
                exc.diagnostic.setdefault("phase", "startup_gate")
                exc.diagnostic.setdefault("exception_class", _diagnostic_exception(exc))
                exc.diagnostic["gate_wait_ms"] = _elapsed_ms(gate_started) if gate_ms is None else gate_ms
                exc.diagnostic["cooldown_wait_ms"] = cooldown_ms
            if target is not None:
                try:
                    target.close()
                except BaseException:
                    self._startup_cleanup_pending = target
                    raise
            if isinstance(exc, OSError):
                error = BrokerError("transport start gate unavailable", layer="broker-upstream", retryable=False)
                error.diagnostic = {"phase": "startup_gate", "exception_class": _safe_exception_class(exc),
                                    "gate_wait_ms": _elapsed_ms(gate_started), "cooldown_wait_ms": cooldown_ms}
                raise error from exc
            raise
        self._startup_failures = 0
        self._next_start_at = 0.0
        diagnostic_timings = getattr(target, "_diagnostic_timings", None)
        if isinstance(diagnostic_timings, dict):
            diagnostic_timings["startup_gate"] = gate_ms
            diagnostic_timings["startup_cooldown"] = cooldown_ms
        return target

    def _open_upstream(
        self,
        context_replay_reservation_id: str | None = None,
        *, context_control_only: bool = False,
    ) -> None:
        self.close()
        self.upstream = self._new_upstream(context_replay_reservation_id,
            context_control_only=context_control_only)

    def _denial(self, name: str, exc: BrokerError) -> dict[str, Any]:
        # Preserve a classified transport cause through an outer lifecycle or
        # admission wrapper, without serializing exception strings/tracebacks.
        cause = exc
        for _ in range(4):
            if isinstance(cause, BrokerError) and cause.diagnostic:
                exc.diagnostic = dict(cause.diagnostic)
                break
            cause = cause.__cause__
            if cause is None:
                break
        write_outcome_unknown = (
            name in {
                "integrity_append_event", "integrity_turn_memory_open",
                "integrity_turn_memory_close", "integrity_turn_memory_gap",
            } and exc.request_sent
        )
        safe_current_turn_retry = (
            name == CURRENT_TURN_CONTEXT_TOOL
            and not exc.request_sent
            and exc.layer == "broker-upstream"
        )
        value = {
            "protocol": "integrity-client/turn-broker-denial/v1",
            "outcome": "unknown" if write_outcome_unknown else "denied",
            "failure_layer": exc.layer,
            "tool": name,
            "reason": str(exc)[:500],
            "request_sent": exc.request_sent,
            "automatic_retry_allowed": safe_current_turn_retry,
            "canonical_writes": "unknown" if write_outcome_unknown else 0,
            "production_authority": False,
        }
        if safe_current_turn_retry:
            value["retry_disposition"] = "exact-envelope-after-pre-send-transport"
        if exc.layer == "broker-lifecycle-uncertain":
            value["reason_code"] = "lifecycle_reconciliation_required"
            value["reconciliation_required"] = True
            value["retry_disposition"] = "readback-before-any-new-lifecycle-request"
        if write_outcome_unknown and name in STANDALONE_TURN_MEMORY_TOOLS:
            value["reconciliation_required"] = True
            value["retry_disposition"] = "readback-before-any-new-lifecycle-request"
        if exc.layer == "broker-context-lost":
            value["primary_denial_reference"] = self._binding_loss_receipt_digest
            value["coverage_disposition"] = "preserve-registration-and-gap"
        if exc.layer == "broker-append-uncertain":
            value["prior_canonical_write_outcome"] = "unknown"
            value["primary_denial_reference"] = self._uncertain_append_receipt_digest
            value["reconciliation_required"] = True
        if exc.diagnostic:
            value["diagnostic"] = dict(exc.diagnostic)
            value["diagnostic_persisted"] = _persist_transport_diagnostic(
                value["diagnostic"], request_sent=exc.request_sent)
        return {
            "content": [{"type": "text", "text": _json_bytes(value).decode("utf-8")}],
            "isError": True,
        }

    @staticmethod
    def _digest(value: Any) -> str:
        return "sha256:" + hashlib.sha256(_json_bytes(value)).hexdigest()

    def _ack_pending_context_replays(
        self,
        upstream: UpstreamFacade | None = None,
    ) -> None:
        target = self.upstream if upstream is None else upstream
        if target is None or not self._pending_context_replay_acks:
            return
        remaining: list[dict[str, str]] = []
        pending = list(self._pending_context_replay_acks)
        for index, acknowledgement in enumerate(pending):
            if (
                acknowledgement["replay_id"]
                in self._context_replay_acks_awaiting_public_delivery
            ):
                remaining.append(acknowledgement)
                continue
            try:
                acknowledge = getattr(
                    target,
                    "acknowledge_context_admission_replay",
                    None,
                )
                if callable(acknowledge):
                    request_ack_safe = bool(
                        getattr(
                            target,
                            "context_admission_replay_ack_request_safe",
                            getattr(target, "context_admission_replay_safe", False),
                        )
                    )
                else:
                    request_ack_safe = False
                if callable(acknowledge) and request_ack_safe:
                    if acknowledge(acknowledgement) is not True:
                        remaining.append(acknowledgement)
                else:
                    target.notify(
                        CONTEXT_ADMISSION_REPLAY_ACK_NOTIFICATION,
                        acknowledgement,
                    )
            except BrokerError as exc:
                if exc.retryable:
                    remaining.extend(pending[index:])
                    self._pending_context_replay_acks = remaining
                    raise
                try:
                    target.notify(
                        CONTEXT_ADMISSION_REPLAY_ACK_NOTIFICATION,
                        acknowledgement,
                    )
                except BrokerError:
                    remaining.extend(pending[index:])
                    break
        self._pending_context_replay_acks = remaining

    def _context_admission(
        self,
        arguments: dict[str, Any],
        *,
        defer_replay_ack_until_public_delivery: bool = False,
        owning_producer: tuple[str, str] | None = None,
    ) -> dict[str, Any]:
        """Rotate one logical context, reconnecting the transport at most once."""

        first_error: BrokerError | None = None
        request_ever_sent = False
        replay_id = "sha256:" + secrets.token_hex(32)
        # A private retained-read/control lease cannot carry a new admission.
        # Reopen only this owned upstream with the genuine fresh reservation.
        if self.upstream is not None and getattr(self.upstream,"context_control_only",False):
            self.close()
        replay_arguments: dict[str, Any] | None = None
        for attempt in range(2):
            replay_after_send = False
            admission_call_started = False
            try:
                if self.upstream is None:
                    self._open_upstream(replay_id)
                    assert self.upstream is not None
                    replay_after_send = bool(
                        getattr(
                            self.upstream,
                            "context_admission_replay_safe",
                            False,
                        )
                    )
                    self._ack_pending_context_replays()
                    if not replay_after_send:
                        reserve = getattr(
                            self.upstream,
                            "reserve_context_admission_replay",
                            None,
                        )
                        replay_after_send = bool(
                            callable(reserve)
                            and getattr(
                                self.upstream,
                                "context_admission_replay_contract_safe",
                                getattr(
                                    self.upstream,
                                    "context_admission_replay_safe",
                                    False,
                                ),
                            )
                            and reserve(replay_id)
                        )
                else:
                    self._ack_pending_context_replays()
                    reserve = getattr(
                        self.upstream,
                        "reserve_context_admission_replay",
                        None,
                    )
                    replay_after_send = bool(
                        callable(reserve)
                        and getattr(
                            self.upstream,
                            "context_admission_replay_contract_safe",
                            getattr(
                                self.upstream,
                                "context_admission_replay_safe",
                                False,
                            ),
                        )
                        and reserve(replay_id)
                    )
                assert self.upstream is not None
                if replay_arguments is not None and not replay_after_send:
                    raise BrokerError(
                        "replacement upstream did not retain replay contract",
                        layer="broker-upstream",
                    )
                if replay_after_send:
                    if replay_arguments is None:
                        replay_arguments = {**arguments, CONTEXT_ADMISSION_REPLAY_FIELD: replay_id}
                    call_arguments = replay_arguments
                else:
                    call_arguments = arguments
                if owning_producer is not None:
                    try:
                        turn_envelope.bind_resume_identity_from_claim(
                            producer_turn_ref=owning_producer[0],
                            producer_claim_id=owning_producer[1])
                    except (OSError, ValueError, KeyError, TypeError, AttributeError, turn_envelope.TurnEnvelopeError):
                        raise BrokerError("own producer superseded before admission",
                                          layer="broker-envelope", request_sent=False, retryable=False) from None
                admission_call_started = True
                result = self.upstream.call_tool(
                    "integrity_context_admission",
                    call_arguments,
                )
                if replay_after_send:
                    acknowledgement = {
                        "replay_id": replay_id,
                        "request_digest": self._digest(arguments),
                        "response_digest": self._digest(result),
                    }
                    if getattr(self.upstream,"context_reattach_safe",False):
                        self._context_resume_control = dict(acknowledgement)
                    if acknowledgement not in self._pending_context_replay_acks:
                        self._pending_context_replay_acks.append(acknowledgement)
                    if defer_replay_ack_until_public_delivery:
                        self._context_replay_acks_awaiting_public_delivery.add(
                            replay_id
                        )
                return result
            except BrokerError as exc:
                request_ever_sent = request_ever_sent or (
                    admission_call_started and exc.request_sent
                )
                # A successful existing retry must not erase its first fault.
                if exc.diagnostic:
                    _persist_transport_diagnostic(exc.diagnostic, request_sent=exc.request_sent)
                self.close()
                if (
                    attempt
                    or not exc.retryable
                    or (
                        admission_call_started
                        and exc.request_sent
                        and not replay_after_send
                    )
                ):
                    terminal_error = exc
                    if exc.request_sent != request_ever_sent:
                        terminal_error = BrokerError(
                            str(exc),
                            layer=exc.layer,
                            request_sent=request_ever_sent,
                            retryable=exc.retryable,
                        )
                        terminal_error.diagnostic = dict(exc.diagnostic)
                        if request_ever_sent:
                            terminal_error.add_note(
                                "an earlier replay-protected admission attempt sent request bytes"
                            )
                        else:
                            terminal_error.add_note(
                                "only upstream initialization bytes were sent"
                            )
                    if first_error is not None:
                        terminal_error.add_note(
                            f"context admission reconnect followed: {first_error}"
                        )
                    raise terminal_error
                first_error = exc
        raise AssertionError("unreachable context admission retry state")

    @staticmethod
    def _read_seal_retry(result: dict[str, Any]) -> bool:
        """Accept only the upstream's explicit pre-admission checkpoint denial."""
        if result.get("isError") is not True:
            return False
        content = result.get("content")
        if not isinstance(content, list) or len(content) != 1:
            return False
        block = content[0]
        if not isinstance(block, dict) or block.get("type") != "text":
            return False
        try:
            document = json.loads(block["text"])
        except (KeyError, TypeError, ValueError):
            return False
        receipt = document.get("receipt") if isinstance(document, dict) else None
        return isinstance(receipt, dict) and all(
            type(receipt.get(key)) is type(value) and receipt.get(key) == value
            for key, value in {
                "tool": "integrity_context_admission",
                "outcome": "denied",
                "failure_layer": "read-plane-initialization",
                "reason_code": "seed_catalog_checkpoint_required",
                "read_plane_status": "unavailable",
                "automatic_retry_allowed": True,
                "canonical_writes": 0,
                "retry_disposition": "exact-envelope-after-supported-read-seal",
            }.items()
        )

    def _resolve_current_turn(
        self, arguments: dict[str, Any],
    ) -> tuple[str, str, dict[str, Any]]:
        unknown = set(arguments) - {"turn_ref", "budget", "limit"}
        turn_ref = arguments.get("turn_ref")
        if unknown or not isinstance(turn_ref, str):
            raise BrokerError(
                "current-turn admission arguments are invalid",
                layer="broker-envelope",
            )
        if "budget" in arguments and "limit" in arguments:
            raise BrokerError(
                "budget and limit are mutually exclusive",
                layer="broker-envelope",
            )
        claim_id = None
        try:
            prompt, envelope, claim_id = turn_envelope.resolve(turn_ref)
            turn_envelope.bind_resume_identity_from_claim(
                producer_turn_ref=turn_ref, producer_claim_id=claim_id)
        except (OSError, turn_envelope.TurnEnvelopeError) as exc:
            self._own_turn_binding = None
            if claim_id is not None:
                try:
                    turn_envelope.release_claim(turn_ref, claim_id)
                except (OSError, turn_envelope.TurnEnvelopeError):
                    raise BrokerError("pre-send turn envelope claim could not be released",
                                      layer="broker-envelope") from None
            raise BrokerError(str(exc), layer="broker-envelope") from exc
        self._own_turn_binding = {'hashes': envelope.get('native_identity_hashes'),
            'intent_id': envelope.get('registration_intent_id'),
            'prompt_sha256': envelope['prompt_sha256'], 'generation': envelope['generation'],
            'admitted': False, 'turn_ref_digest': envelope['turn_ref_digest'],
            'project_scope_sha256': envelope.get('project_scope_sha256')}
        binding = {
            key: envelope[key]
            for key in (
                "protocol",
                "turn_ref_digest",
                "prompt_sha256",
                "prompt_bytes",
                "segment_count",
                "prompt_coverage",
                "truncation",
                "generation",
            )
        }
        self._local_route_prompt = prompt
        expanded: dict[str, Any] = {
            "intent": prompt,
            "_integrity_turn_binding": binding,
        }
        if sys.platform == "win32":
            own_hash = (envelope.get("native_identity_hashes") or {}).get("thread_id")
            own_hash = "sha256:" + own_hash if isinstance(own_hash, str) and re.fullmatch(r"[a-f0-9]{64}", own_hash) else ""
            hint = registry_hint_for_hash(own_hash, Path(_integrity_value('path_0b4608844dcc')))
            if hint is not None:
                expanded["_integrity_retrieval_hint"] = hint
        if "project_scope" in envelope:
            binding["project_scope"] = envelope["project_scope"]
            binding["project_scope_sha256"] = envelope["project_scope_sha256"]
        for key in ("budget", "limit"):
            if key in arguments:
                expanded[key] = arguments[key]
        try:
            expanded["_integrity_read_session"] = _reader_session_module.issue(envelope, product='codex')
        except (ValueError, KeyError, TypeError):
            turn_envelope.release_claim(turn_ref, claim_id)
            self._own_turn_binding = None
            raise BrokerError("own_read_session_unavailable", layer="broker-envelope") from None
        # Optional search context never rewrites intent or its identity binding.
        attachment_context = _attachment_retrieval.derive_attachment_context(
            prompt, self._own_turn_binding,
            Path(_integrity_value('path_a136563213bf')))
        if attachment_context is not None:
            expanded['_integrity_attachment_context'] = attachment_context
        return turn_ref, claim_id, expanded

    @staticmethod
    def _lifecycle_request_key(name, arguments):
        return hashlib.sha256(_json_bytes({"tool":name,"arguments":arguments})).hexdigest()

    def _remember_uncertain_lifecycle(self, name, arguments, error):
        if error.request_sent and name != "integrity_turn_memory_coverage":
            pending = getattr(self, "_uncertain_lifecycle_requests", set())
            pending.add(self._lifecycle_request_key(name, arguments))
            self._uncertain_lifecycle_requests = pending

    def _begin_lifecycle_dispatch(self, name, arguments):
        if name == 'integrity_turn_memory_coverage':
            return
        # OPEN is one owning identity; CLOSE/GAP are each one registration.
        # A different reason/outcome cannot bypass an earlier uncertain send.
        subject = (arguments if name == 'integrity_turn_memory_open' else
                   {'registration_id':arguments['registration_id']})
        key = self._lifecycle_request_key(name, subject)
        root = Path(os.environ.get('INTEGRITY_CLIENT_STATE_ROOT',
            str(Path.home()/'.codex/integrity-memory/state')))
        payload = _json_bytes({'protocol':'integrity-client/lifecycle-dispatch/v1',
            'tool':name,'request_sha256':self._lifecycle_request_key(name,arguments),
            'status':'possibly-sent-no-replay','canonical_writes':'unknown'})
        try:
            # Require the existing owning state root; never create a fallback.
            if not root.is_dir():raise OSError('owning state root unavailable')
            for parent in (root,*root.parents):
                info=parent.lstat()
                if parent.is_symlink() or getattr(info,'st_file_attributes',0)&0x400:
                    raise OSError('owning state custody invalid')
            path = root/('lifecycle-dispatch-'+key+'.json')
            # Atomic exclusive create handles competing processes and restart.
            # Even a crash before the send leaves a conservative coverage debt.
            with path.open('xb') as stream:
                stream.write(payload);stream.flush();os.fsync(stream.fileno())
        except FileExistsError:
            raise BrokerError('prior lifecycle dispatch requires canonical readback; no replay',
                layer='broker-lifecycle-uncertain',request_sent=False,retryable=False) from None
        except OSError:
            raise BrokerError('lifecycle dispatch journal unavailable; no send',
                layer='broker-lifecycle-journal',request_sent=False,retryable=False) from None

    def _validate_current_open(self, arguments):
        # Fresh owning state AND Native head, repeated immediately before send.
        # A model cannot use an older admitted binding after user steering.
        try:
            binding = self._own_turn_binding
            path = Path(os.environ.get('INTEGRITY_CLIENT_STATE_ROOT',
                str(Path.home()/'.codex/integrity-memory/state'))) / (binding['hashes']['thread_id']+'.json')
            if path.is_symlink() or not path.is_file():raise ValueError('state unavailable')
            state = json.loads(path.read_bytes())
            head = turn_envelope._native_owning_head(arguments['thread_id'])
            if (state.get('turn_id') != arguments['turn_id']
                    or state.get('turn_memory_generation') != binding['generation']
                    or state.get('turn_memory_intent_id') != arguments['intent_id']
                    or state.get('prompt_sha256') != arguments['prompt_sha256']
                    or state.get('model_mcp_context_admission_id') != binding['context_admission_id']
                    or not isinstance(head,dict) or head.get('id') != arguments['turn_id']
                    or head.get('status') != 'inProgress'):
                raise ValueError('owning source superseded')
        except (OSError,ValueError,KeyError,TypeError,AttributeError,ImportError,turn_envelope.TurnEnvelopeError):
            raise BrokerError('owning_open_source_superseded_before_send',
                layer='broker-owning-lifecycle',request_sent=False,retryable=False) from None

    @staticmethod
    def _lifecycle_terminal(result, registration_id):
        if not isinstance(result, dict) or result.get("isError"):
            return None
        value = result.get("structuredContent")
        if value is None:
            text = [part.get("text") for part in result.get("content", [])
                    if isinstance(part, dict) and part.get("type") == "text"]
            if len(text) != 1:
                return None
            try:
                value = json.loads(text[0])
            except (TypeError, ValueError):
                return None
        if not isinstance(value, dict):
            return None
        receipt = value.get("terminal_receipt", value.get("receipt", value))
        if (not isinstance(receipt, dict)
                or receipt.get("protocol") != "integrity-guardian/turn-memory-terminal-receipt/v1"
                or receipt.get("registration_id") != registration_id
                or receipt.get("outcome") not in {"events", "no-event"}
                or not isinstance(receipt.get("signature"), dict)
                or receipt["signature"].get("algorithm") != "ed25519"
                or not isinstance(receipt["signature"].get("value"), str)
                or not re.fullmatch(r"sha256:[a-f0-9]{64}", str(receipt.get("receipt_id")))):
            return None
        return receipt

    def _observe_late_lifecycle(self, result):
        upstream = self.upstream
        values = getattr(upstream, "_late_lifecycle_responses", [])
        if not values or not isinstance(result.get("_meta", {}), dict):
            return
        upstream._late_lifecycle_responses = []
        receipts = []
        for original, response in values:
            if original.get("tool") != "integrity_turn_memory_close" or response.get("error") is not None:
                continue
            registration = original.get("registration_id")
            terminal = self._lifecycle_terminal(response.get("result"), registration)
            if terminal is None:
                continue
            getattr(self, "_uncertain_lifecycle_registrations", set()).discard(registration)
            receipts.append({"registration_id":registration,"terminal_receipt":terminal,
                "source":"exact recorded timed-out request on this admitted upstream; no retry"})
        if receipts:
            result.setdefault("_meta", {})["integrityLateLifecycleReceipts"] = receipts

    def _observe_current_lifecycle(self, name, arguments, result):
        if name not in {"integrity_turn_memory_close", "integrity_turn_memory_gap"}:
            return
        registration = arguments.get("registration_id")
        if self._lifecycle_terminal(result, registration) is not None:
            getattr(self, "_uncertain_lifecycle_registrations", set()).discard(registration)

    def _standalone_turn_memory_call(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Send one owning lifecycle mutation; preserve unknown outcome across restart."""
        self._consumed_owning_lifecycle_claims = None
        self._check_own_lifecycle(name, arguments)
        if name == "integrity_turn_memory_close":
            try:
                _local_routes.guard_close(arguments, self._own_turn_binding,
                    turn_envelope._owning_state_root())
            except (OSError, ValueError, TypeError) as exc:
                raise BrokerError(str(exc), layer="broker-external-outcome", request_sent=False) from None
        if (name != "integrity_turn_memory_coverage"
                and self._lifecycle_request_key(name, arguments) in
                    getattr(self, "_uncertain_lifecycle_requests", set())):
            raise BrokerError("prior lifecycle outcome requires canonical readback",
                layer="broker-lifecycle-uncertain", request_sent=False, retryable=False)

        if self.upstream is not None:
            try:
                self._ack_pending_context_replays()
            except BrokerError as exc:
                # A request-based ACK transport fault desynchronizes only the
                # admitted stream. The lifecycle call remains independently
                # idempotent and can continue on its isolated transport.
                try:
                    self.close()
                except Exception as cleanup_error:
                    self._last_cleanup_failure_type = type(cleanup_error).__name__
                    exc.add_note(f"secondary cleanup failed: {type(cleanup_error).__name__}")
        # Reuse only an already admitted live facade, after the same current
        # ownership check and replay ACK. Cold hook callers retain their
        # existing isolated transport and all pre-send claim checks.
        pending = getattr(self, "_uncertain_lifecycle_registrations", set())
        if name == "integrity_turn_memory_close" and arguments.get("registration_id") in pending:
            raise BrokerError("prior lifecycle close outcome requires canonical readback",
                layer="broker-lifecycle-uncertain", request_sent=False, retryable=False)
        if self.upstream is not None and self.bound:
            claims = self._consumed_owning_lifecycle_claims
            if claims is not None:
                try:
                    turn_envelope.revalidate_consumed_own_lifecycle(claims,name,arguments)
                except (OSError,ValueError,ImportError,turn_envelope.TurnEnvelopeError):
                    raise BrokerError('owning_hook_lifecycle_superseded_before_send',
                        layer='broker-owning-lifecycle',request_sent=False,retryable=False) from None
            late = getattr(self.upstream, "_late_lifecycle_requests", {})
            if len(late) >= 8:
                raise BrokerError("unreconciled lifecycle response bound reached",
                    layer="broker-lifecycle-uncertain", request_sent=False, retryable=False)
            try:
                if name == "integrity_turn_memory_open" and claims is None:
                    self._validate_current_open(arguments)
                self._begin_lifecycle_dispatch(name, arguments)
                result = self.upstream.call_tool(name, arguments)
            except BrokerError as error:
                self._remember_uncertain_lifecycle(name, arguments, error)
                if error.request_sent and name == "integrity_turn_memory_close":
                    pending.add(arguments["registration_id"])
                    self._uncertain_lifecycle_registrations = pending
                process = getattr(self.upstream, "process", None)
                if (str(error) == "upstream response timed out" and error.request_sent
                        and error.layer == "broker-upstream" and process is not None and process.poll() is None):
                    late[self.upstream._next_id-1] = {"tool":name,
                        "registration_id":arguments.get("registration_id")}
                    self.upstream._late_lifecycle_requests = late
                raise
            self._observe_late_append(result)
            self._observe_late_lifecycle(result)
            self._observe_current_lifecycle(name, arguments, result)
            return result
        first_error: BrokerError | None = None
        for attempt in range(2):
            target: UpstreamFacade | None = None
            primary_error: BrokerError | None = None
            lifecycle_call_started = False
            try:
                cleanup_reservation_id = (
                    self._pending_context_replay_acks[0]["replay_id"]
                    if self._pending_context_replay_acks
                    else None
                )
                target = self._new_upstream(cleanup_reservation_id)
                self._ack_pending_context_replays(target)
                claims = self._consumed_owning_lifecycle_claims
                if claims is not None:
                    try:
                        turn_envelope.revalidate_consumed_own_lifecycle(claims,name,arguments)
                    except (OSError,ValueError,ImportError,turn_envelope.TurnEnvelopeError):
                        raise BrokerError('owning_hook_lifecycle_superseded_before_send',
                            layer='broker-owning-lifecycle',request_sent=False,retryable=False) from None
                if name == "integrity_turn_memory_open" and claims is None:
                    self._validate_current_open(arguments)
                self._begin_lifecycle_dispatch(name, arguments)
                lifecycle_call_started = True
                return target.call_tool(name, arguments)
            except BrokerError as exc:
                if exc.diagnostic:
                    _persist_transport_diagnostic(exc.diagnostic, request_sent=exc.request_sent)
                if not lifecycle_call_started and exc.request_sent:
                    # initialize/list/ACK sending is not a lifecycle side effect.
                    pre_dispatch_error = BrokerError(
                        "turn-memory pre-dispatch transport fault", layer=exc.layer,
                        request_sent=False, retryable=exc.retryable,
                    )
                    pre_dispatch_error.diagnostic = dict(exc.diagnostic)
                    exc = pre_dispatch_error
                primary_error = exc
                if lifecycle_call_started:
                    self._remember_uncertain_lifecycle(name, arguments, exc)
                if lifecycle_call_started and exc.request_sent and name == "integrity_turn_memory_close":
                    pending.add(arguments["registration_id"])
                    self._uncertain_lifecycle_registrations = pending
                if attempt or not exc.retryable or (
                    exc.request_sent and name != "integrity_turn_memory_coverage"
                ):
                    if first_error is not None:
                        exc.add_note(f"turn-memory reconnect followed: {first_error}")
                    raise
                first_error = exc
            finally:
                if target is not None:
                    try:
                        target.close()
                    except Exception as cleanup_error:
                        self._last_cleanup_failure_type = type(cleanup_error).__name__
                        if primary_error is not None:
                            primary_error.add_note(
                                f"secondary cleanup failed: {type(cleanup_error).__name__}"
                            )
        raise AssertionError("unreachable Turn Memory retry state")

    def _retire_superseded_delivered_context(self, turn_ref, claim_id):
        try:
            control=turn_envelope.load_superseded_context_retirement(
                producer_turn_ref=turn_ref,producer_claim_id=claim_id)
        except (OSError,ValueError,KeyError,TypeError,AttributeError,turn_envelope.TurnEnvelopeError):
            raise BrokerError("own supersession source unavailable",
                              layer="broker-context-retirement-owning",request_sent=False) from None
        if control is None:return
        self._open_upstream(None,context_control_only=True)
        # Revalidate current producer after potentially slow connection startup.
        if turn_envelope.load_superseded_context_retirement(
                producer_turn_ref=turn_ref,producer_claim_id=claim_id)!=control:
            self.close()
            raise BrokerError("own supersession subject changed",
                              layer="broker-context-retirement-owning",request_sent=False)
        self.upstream.retire_superseded_context(control)
        self.close()  # New admission negotiates its own NEW replay reservation.

    def _save_delivered_context_resume(self, result):
        binding = self._own_turn_binding
        control = self._context_resume_control
        if (not self.bound or not isinstance(binding,dict) or binding.get("admitted") is not True
                or not isinstance(control,dict)):
            self._context_resume_diagnostic_stage = "no-supported-replay-control"
            return
        try:
            value=json.loads(result["content"][0]["text"])
            control={**control,"context_admission_id":value["context_admission_id"],
                     "snapshot_id":value["snapshot"]["snapshot_id"],
                     "prompt_binding":value["prompt_binding"],
                     "logical_generation":value["logical_generation"]}
            # RAM only. No descriptor exists until public flush is confirmed.
            self._pending_context_resume_payload = {
                "protocol":"integrity-client/own-context-resume/v1",
                "binding":dict(binding),"control":control}
            self._context_resume_save_failed=False
            self._context_resume_error_type = None
            self._context_resume_diagnostic_stage = "staged-for-public-delivery"
        except (OSError,ValueError,KeyError,TypeError,AttributeError,turn_envelope.TurnEnvelopeError) as exc:
            self._context_resume_diagnostic_stage = "stage-failed"
            self._context_resume_error_type = type(exc).__name__
            # Persistence is not admission. Do not change the delivered response
            # or secretly repeat admission when optional resume custody fails.
            self._context_resume_save_failed=True

    def _commit_delivered_context_resume(self, producer_turn_ref, producer_claim_id):
        payload=self._pending_context_resume_payload
        if payload is None:
            return
        try:
            expected="sha256:"+hashlib.sha256(producer_turn_ref.encode()).hexdigest()
            if payload["binding"]["turn_ref_digest"] != expected:
                raise ValueError("delivered own envelope mismatch")
            turn_envelope.save_context_resume(payload,
                producer_turn_ref=producer_turn_ref,producer_claim_id=producer_claim_id)
            self._context_resume_save_failed=False
            self._context_resume_error_type = None
            self._context_resume_diagnostic_stage = "stored-after-public-delivery"
        except (OSError,ValueError,KeyError,TypeError,AttributeError,turn_envelope.TurnEnvelopeError) as exc:
            self._context_resume_diagnostic_stage = "store-failed"
            self._context_resume_error_type = type(exc).__name__
            self._context_resume_save_failed=True
        finally:
            self._pending_context_resume_payload=None

    def _own_context_resume_diagnostic(self):
        # Diagnostic metadata only. No ref/claim/control secret, authority,
        # binding mutation, process operation or added public tool.
        result = {"protocol": "integrity-client/own-context-resume-diagnostic/v1",
                  "authority": "none", "stage": self._context_resume_diagnostic_stage,
                  "save_failed": self._context_resume_save_failed,
                  "error_type": self._context_resume_error_type}
        binding = self._own_turn_binding
        if not isinstance(binding, dict) or binding.get("admitted") is not True:
            return result
        result.update({key: binding.get(key) for key in
                       ("hashes", "generation", "context_admission_id", "prompt_sha256", "turn_ref_digest")})
        result["broker_source_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        result["broker_pid"] = os.getpid()
        def creation(pid):
            if os.name != "nt" or type(pid) is not int or pid <= 0:
                return None
            import ctypes
            from ctypes import wintypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel.OpenProcess.restype = wintypes.HANDLE
            kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            handle = kernel.OpenProcess(0x1000, False, pid)
            if not handle:
                return None
            try:
                values = [wintypes.FILETIME() for _ in range(4)]
                if not kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in values)):
                    return None
                return f"{(values[0].dwHighDateTime << 32) | values[0].dwLowDateTime:016x}"
            finally:
                kernel.CloseHandle(handle)
        result["broker_creation_filetime"] = creation(result["broker_pid"])
        target = self.upstream
        if target is not None:
            pid = target.process.pid
            result.update(upstream_pid=pid, upstream_creation_filetime=creation(pid),
                          upstream_alive=target.process.poll() is None,
                          replay_contract=target.context_admission_replay_contract_safe,
                          replay_reserved=target.context_admission_replay_safe,
                          resume_contract=target.context_reattach_safe,
                          read_only_reattach=self._context_reattach_read_only)
        return result

    def _ensure_delivered_context_resume(self):
        if self.upstream is not None and self.bound:
            return
        if self._context_reattach_attempted:
            return
        self._context_reattach_attempted=True
        target=None
        try:
            payload=turn_envelope.load_context_resume()
            if payload is None:
                return
            if payload.get("protocol")!="integrity-client/own-context-resume/v1":
                raise ValueError("own resume protocol invalid")
            control=payload["control"]
            self._open_upstream(None,context_control_only=True)
            target=self.upstream
            target.reattach_context(control)
            # The Native head and hook generation can change while connecting.
            # Re-read the same fixed protected source before adopting a binding.
            if turn_envelope.load_context_resume()!=payload:
                raise ValueError("own resume subject superseded")
            self._own_turn_binding=dict(payload["binding"])
            self._context_reattach_read_only=True
            self.bound=True
        except (OSError,ValueError,KeyError,TypeError,AttributeError,turn_envelope.TurnEnvelopeError):
            self.close();self.bound=False;self._own_turn_binding=None
            raise BrokerError("own delivered context resume unavailable",
                              layer="broker-context-reattach-owning",request_sent=False) from None
        except BrokerError:
            self.close();self.bound=False;self._own_turn_binding=None
            raise

    def _adopt_admitted_own_binding(self, result):
        binding = self._own_turn_binding
        if not isinstance(binding, dict):
            return
        binding['admitted'] = False
        try:
            content = result['content']
            if result.get('isError') is True or len(content) != 1 or content[0]['type'] != 'text':
                return
            value = json.loads(content[0]['text'])
            prompt = value['prompt_binding']
            valid = (value['protocol'] in {'integrity-client-memory-mcp/v3/context-admission/v1',
                                          'integrity-client-memory-mcp/v3/context-admission/v2'}
                and re.fullmatch(r'sha256:[a-f0-9]{64}', value['context_admission_id']) is not None
                and value['snapshot']['immutable'] is True
                and value['snapshot']['source_namespace'] == _integrity_value('seed_namespace')
                and value['home_record_count'] == 0 and value['production_authority'] is False
                and prompt['prompt_sha256'] == binding['prompt_sha256']
                and prompt['generation'] == binding['generation']
                and prompt['turn_ref_digest'] == binding['turn_ref_digest']
                and prompt['truncation'] is False
                and (binding['project_scope_sha256'] is None or
                     prompt.get('project_scope_sha256') == binding['project_scope_sha256']))
            if valid:
                binding['admitted'] = True
                binding['context_admission_id'] = value['context_admission_id']
        except (KeyError, TypeError, ValueError, RecursionError):
            return

    @staticmethod
    def _own_registration_content(state, binding):
        # Verify the content-addressed signed registration's COMPLETE subject.
        # The canonical service independently verifies its stored Ed25519
        # signature/row join before mutation. This is not a local signature claim.
        try:
            receipt = state['turn_memory_registration_receipt']
            unsigned = {k:v for k,v in receipt.items() if k not in {'signature','receipt_id'}}
            raw = json.dumps(unsigned,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
            expected = 'sha256:' + hashlib.sha256(b'turn-memory-registration-v1\0' + raw).hexdigest()
            identity = receipt['identity']
            hashes = binding['hashes']
            return (set(identity) == {'machine_id','thread_id','turn_id','intent_id'}
                and receipt['protocol'] == 'integrity-guardian/turn-memory-registration/v1'
                and receipt['receipt_id'] == expected == state['turn_memory_registration_id']
                and receipt['namespace_fingerprint'] == state['turn_memory_namespace_fingerprint']
                    == _integrity_value('pin_dd9fa64be3f2')
                and receipt['prompt_sha256'] == binding['prompt_sha256']
                and identity['intent_id'] == binding['intent_id']
                and all(hashlib.sha256(identity[key].encode()).hexdigest() == hashes[key]
                        for key in ('machine_id','thread_id','turn_id'))
                and receipt['signature']['algorithm'] == 'ed25519'
                and receipt['terminal_required'] is True and receipt['production_authority'] is False)
        except (KeyError, TypeError, ValueError, AttributeError):
            return False

    def _bound_archive_arguments(self, name, arguments):
        if "_broker_archive_binding" in arguments:
            raise BrokerError("archive owning subject is broker-only", layer="broker-archive-binding")
        binding = self._own_turn_binding
        if (not isinstance(binding,dict) or binding.get("admitted") is not True
                or not self.bound or arguments.get("context_admission_id")!=binding.get("context_admission_id")):
            raise BrokerError("archive requires current owning admission", layer="broker-archive-binding")
        if name=="integrity_archive_import":
            root=Path(os.environ.get("INTEGRITY_CLIENT_STATE_ROOT",str(Path.home()/".codex/integrity-memory/state")))
            path=root/(binding["hashes"]["thread_id"]+".json")
            try:
                if path.is_symlink() or not path.is_file():raise ValueError()
                state=json.loads(path.read_bytes())
                valid=(self._own_registration_content(state,binding)
                    and state.get("turn_memory_registration_id")==arguments.get("registration_id")
                    and state.get("prompt_sha256")==binding["prompt_sha256"]
                    and state.get("turn_memory_generation")==binding["generation"]
                    and state.get("turn_memory_intent_id")==binding["intent_id"]
                    and state.get("turn_memory_status")=="open")
            except (OSError,ValueError,KeyError,TypeError):
                valid=False
            if not valid:
                raise BrokerError("archive requires live own signed registration",layer="broker-archive-binding")
        return {**arguments,"_broker_archive_binding":{key:binding[key] for key in
            ("prompt_sha256","generation","intent_id","hashes")}}

    def _archive_pending_state(self):
        binding = self._own_turn_binding
        if not isinstance(binding, dict) or binding.get('admitted') is not True:
            return {}
        thread_hash = binding.get('hashes', {}).get('thread_id')
        if not isinstance(thread_hash, str) or len(thread_hash) != 64:
            return {}
        root = Path(os.environ.get('INTEGRITY_CLIENT_STATE_ROOT', str(Path.home()/'.codex/integrity-memory/state')))
        path = root/(thread_hash+'.json')
        try:
            if path.is_symlink() or not path.is_file():
                raise ValueError()
            return json.loads(path.read_bytes())
        except (OSError, ValueError, TypeError):
            raise BrokerError('archive owning state unavailable', layer='broker-archive-state') from None

    def _archive_attempt_path(self, state):
        nonce = state.get('archive_step_attempt_id')
        if not isinstance(nonce, str) or re.fullmatch(r'[a-f0-9]{32}', nonce) is None:
            raise BrokerError('native archive attempt marker unavailable', layer='broker-archive-dispatch', request_sent=False)
        thread_hash = self._own_turn_binding['hashes']['thread_id']
        root = Path(os.environ.get('INTEGRITY_CLIENT_STATE_ROOT', str(Path.home()/'.codex/integrity-memory/state')))
        return root/('archive-dispatch-'+thread_hash+'-'+nonce+'.json')

    def _archive_stage_is_fresh(self, arguments, state):
        clean = {k:v for k,v in arguments.items() if k != '_broker_archive_binding'}
        if (state.get('archive_unresolved') is not True or state.get('archive_step_returned') is not False
                or _json_bytes(state.get('archive_step_input', {})) != _json_bytes(clean)
                or not isinstance(state.get('archive_step_attempt_id'), str)
                or re.fullmatch(r'[a-f0-9]{32}', state['archive_step_attempt_id']) is None):
            return False
        self._bound_archive_arguments('integrity_archive_import', clean)
        path = self._archive_attempt_path(state)
        return not path.exists() and not path.is_symlink()

    def _begin_archive_dispatch(self, arguments):
        clean = {k:v for k,v in arguments.items() if k != '_broker_archive_binding'}
        state = self._archive_pending_state()
        path = self._archive_attempt_path(state)
        try:
            with turn_envelope._exclusive_root_lock(path.parent):
                state = self._archive_pending_state()
                if not self._archive_stage_is_fresh(clean, state):
                    raise BrokerError('archive attempt already dispatched or not native-staged', layer='broker-archive-dispatch', request_sent=False)
                path = self._archive_attempt_path(state)
                record = {'protocol':'integrity/archive-dispatch-journal/v1',
                    'owner_thread_hash':self._own_turn_binding['hashes']['thread_id'],
                    'attempt_id':state['archive_step_attempt_id'],
                    'request_sha256':hashlib.sha256(_json_bytes(clean)).hexdigest(),
                    'context_admission_id':clean['context_admission_id'],
                    'registration_id':clean['registration_id'],
                    'event_uids':[p['event_uid'] for p in clean['parts']]}
                turn_envelope._write_atomic(path, record, create_only=True)
                if json.loads(path.read_bytes()) != record:
                    raise BrokerError('archive dispatch journal postcheck failed', layer='broker-archive-dispatch', request_sent=False)
        except (OSError, ValueError, turn_envelope.TurnEnvelopeError) as exc:
            raise BrokerError('archive dispatch journal unavailable', layer='broker-archive-dispatch', request_sent=False) from exc
        # The durable marker is created before the call. It survives process loss.
        self._uncertain_archive_uids.update(p['event_uid'] for p in clean['parts'])


    def _restore_pending_archive_uncertainty(self, name=None, arguments=None):
        state = self._archive_pending_state()
        if state.get('archive_unresolved') is True:
            if name == 'integrity_archive_import' and self._archive_stage_is_fresh(arguments, state):
                return
            step = state.get('archive_step_input', {})
            if (step.get('manifest_event_uid') != _integrity_value('binding_9627b6210e51')
                    or step.get('source_sha256') != _integrity_value('pin_57b074bde43c')):
                raise BrokerError('pending archive scope mismatch', layer='broker-archive-state')
            self._uncertain_archive_uids.update(p.get('event_uid') for p in step.get('parts', []) if isinstance(p, dict))
            self._uncertain_archive_uids.discard(None)

    def _archive_absence_resolves(self, expected, readback):
        if not isinstance(self._own_turn_binding, dict) or self._own_turn_binding.get('admitted') is not True:
            return False
        if (readback.get('outcome') != 'not-found' or readback.get('live_verification') == 'unavailable'
                or readback.get('event_uid') != expected.get('event_uid')
                or readback.get('part_index') != expected.get('details', {}).get('part_index')):
            return False
        fingerprint = hashlib.sha256(_json_bytes(expected)).hexdigest()
        completed = getattr(self, '_archive_completed_failure_parts', {})
        if completed.get(expected['event_uid']) == {'part_fingerprint':fingerprint,'owner_thread_hash':self._own_turn_binding.get('hashes',{}).get('thread_id')}:
            return True
        if (self._own_turn_binding.get('hashes', {}).get('thread_id') !=
                _integrity_value('pin_3c8ef62afebf')
                or not any(_json_bytes(p) == _json_bytes(expected) for p in self._archive_pending_state().get('archive_step_input', {}).get('parts', []))):
            return False
        pending = self._archive_pending_state().get('archive_step_input', {})
        return (hashlib.sha256(_json_bytes(pending)).hexdigest() in
                {_integrity_value('pin_b3e80aea09e2'),_integrity_value('pin_9ae1c0f33d07'),_integrity_value('pin_3cf6719e1f73'),_integrity_value('pin_10b8b4c69d7c'),_integrity_value('pin_e8a92f8dbfa3')}
                and any(_json_bytes(p) == _json_bytes(expected) for p in pending.get('parts', [])))

    @staticmethod
    def _native_completed_archive_denial(name, result):
        # A returned business denial is complete, although the archive step failed.
        # Preserve its body. isError=True suppresses the host's PostToolUse event.
        if name != 'integrity_archive_import' or not isinstance(result, dict) or result.get('isError') is not True:
            return result
        try:
            content = result['content']
            if len(content) != 1 or content[0].get('type') != 'text':
                return result
            value = json.loads(content[0]['text'])
            if set(value) != {'receipt'}:
                return result
            receipt = value['receipt']
            if (receipt.get('protocol') != 'integrity-client-memory-mcp/v3/denial-receipt'
                    or receipt.get('tool') != 'integrity_archive_import'
                    or receipt.get('outcome') != 'denied'
                    or receipt.get('source_label') != 'client-workstation'
                    or receipt.get('reason') not in {'Action Log passive witness is unavailable','architecture custody lock acquisition timed out'}
                    or re.fullmatch(r'sha256:[a-f0-9]{64}', receipt.get('arguments_digest', '')) is None
                    or not isinstance(receipt.get('observed_utc'), str)):
                return result
        except (KeyError, ValueError, TypeError, AttributeError):
            return result
        return {**result, 'isError': False}


    def _observe_archive_result(self, name, arguments, result):
        originals = {p.get('event_uid'): p for p in arguments.get('parts', []) if isinstance(p, dict)}
        submitted = set(originals)-{None}
        try:
            content = result['content']
            value = json.loads(content[0]['text']) if len(content) == 1 and content[0]['type'] == 'text' else {}
        except (KeyError, ValueError, TypeError, IndexError):
            value = {}
        def verified(readback):
            try:
                event = readback['event']; uid = readback['event_uid']; expected = originals[uid]
                clean = {k: v for k, v in event['details'].items() if k != '_integrity_client'}
                return (readback['outcome'] == 'read-back'
                    and type(readback['event_id']) is int and readback['event_id'] > 0
                    and event['id'] == readback['event_id'] and event['event_uid'] == uid
                    and _json_bytes(clean) == _json_bytes(expected['details'])
                    and readback['readback_digest'] == 'sha256:'+hashlib.sha256(_json_bytes(event)).hexdigest())
            except (KeyError, TypeError, ValueError):
                return False
        if value.get('protocol') != 'integrity-historical-transcript-import/v1':
            if name == 'integrity_archive_import':
                self._uncertain_archive_uids.update(submitted)
                receipt = value.get('receipt', {})
                if (receipt.get('protocol') == 'integrity-client-memory-mcp/v3/denial-receipt'
                        and receipt.get('tool') == 'integrity_archive_import'
                        and receipt.get('outcome') == 'denied'
                        and receipt.get('reason') in {'Action Log passive witness is unavailable','architecture custody lock acquisition timed out'}):
                    if not hasattr(self, '_archive_completed_failure_parts'):
                        self._archive_completed_failure_parts = {}
                    self._archive_completed_failure_parts.update({uid: {'part_fingerprint':hashlib.sha256(_json_bytes(originals[uid])).hexdigest(),'owner_thread_hash':self._own_turn_binding.get('hashes',{}).get('thread_id')} for uid in submitted})
            return
        if name == 'integrity_archive_import':
            if hasattr(self, '_archive_completed_failure_parts'):
                for uid in submitted:
                    self._archive_completed_failure_parts.pop(uid, None)
            if result.get('isError') is True or value.get('status') not in {'STEP_CONFIRMED', 'STOPPED_OUTCOME_UNRESOLVED'}:
                self._uncertain_archive_uids.update(submitted); return
            entries = value.get('parts', [])
            if not entries or any(p.get('event_uid') not in submitted for p in entries):
                self._uncertain_archive_uids.update(submitted); return
            verified_uids = set()
            for part in entries:
                if not verified(part.get('canonical_readback', {})):
                    self._uncertain_archive_uids.add(part.get('event_uid'))
                else:
                    verified_uids.add(part['event_uid'])
            if value.get('status') == 'STEP_CONFIRMED':
                self._uncertain_archive_uids.update(submitted-verified_uids)
                self._uncertain_archive_uids.difference_update(verified_uids)
        elif result.get('isError') is not True:
            entries = value.get('parts', [])
            if not isinstance(entries, list) or any(not isinstance(p, dict) for p in entries):
                return
            valid_read = (value.get('status') == 'READ' and value.get('admission_snapshot_unchanged') is True
                and isinstance(entries, list) and len(entries) == len(submitted)
                and len({p.get('event_uid') for p in entries}) == len(entries)
                and all(p.get('event_uid') in submitted for p in entries))
            for part in entries:
                uid = part.get('event_uid')
                if verified(part) or (valid_read and self._archive_absence_resolves(originals[uid], part)):
                    self._uncertain_archive_uids.discard(uid)
                    getattr(self, '_archive_completed_failure_parts', {}).pop(uid, None)


    def _check_own_lifecycle(self, name, arguments):
        if name == 'integrity_turn_memory_coverage':
            return
        if 'recovery_binding' in arguments and self._owning_hook_lifecycle_ref is None:
            raise BrokerError('historical_context_requires_protected_owning_factory', layer='broker-owning-lifecycle')
        if self._owning_hook_lifecycle_ref is not None:
            ref=self._owning_hook_lifecycle_ref
            self._owning_hook_lifecycle_ref=None
            try:
                self._consumed_owning_lifecycle_claims = turn_envelope.consume_owning_lifecycle(ref,name,arguments)
            except (OSError,ValueError,ImportError,turn_envelope.TurnEnvelopeError):
                raise BrokerError('owning_hook_lifecycle_handoff_invalid',layer='broker-owning-lifecycle') from None
            return
        binding = self._own_turn_binding
        if (not isinstance(binding, dict) or binding.get('admitted') is not True
                or name == 'integrity_turn_memory_open' and not self.bound):
            raise BrokerError('owning_admitted_binding_required', layer='broker-owning-lifecycle')
        if not isinstance(binding, dict) or not isinstance(binding.get('hashes'), dict):
            raise BrokerError('owning_turn_binding_required', layer='broker-owning-lifecycle')
        hashes = binding['hashes']
        sha = lambda value: hashlib.sha256(value.encode('utf-8')).hexdigest()
        if name == 'integrity_turn_memory_open':
            expected = {'machine_id','thread_id','turn_id','intent_id','prompt_sha256'}
            if (set(arguments) != expected or arguments.get('intent_id') != binding['intent_id']
                    or re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',arguments.get('turn_id','')) is None
                    or arguments.get('prompt_sha256') != binding['prompt_sha256']
                    or any(not isinstance(arguments.get(key), str) or sha(arguments[key]) != hashes.get(key)
                           for key in ('machine_id','thread_id','turn_id'))):
                raise BrokerError('foreign_registration_open_denied', layer='broker-owning-lifecycle')
            self._validate_current_open(arguments)
            return
        if name not in {'integrity_turn_memory_close','integrity_turn_memory_gap'}:
            raise BrokerError('owning_lifecycle_tool_invalid', layer='broker-owning-lifecycle')
        root = Path(os.environ.get('INTEGRITY_CLIENT_STATE_ROOT', str(Path.home()/'.codex/integrity-memory/state')))
        path = root / (hashes['thread_id'] + '.json')
        try:
            if path.is_symlink() or not path.is_file():
                raise ValueError('state unavailable')
            state = json.loads(path.read_bytes())
            valid = (state.get('turn_memory_registration_id') == arguments.get('registration_id')
                and ('model_mcp_context_admission_id' not in state or
                     state['model_mcp_context_admission_id'] == binding.get('context_admission_id'))
                and self._own_registration_content(state,binding)
                and state.get('prompt_sha256') == binding['prompt_sha256']
                and state.get('turn_memory_generation') == binding['generation']
                and state.get('turn_memory_intent_id') == binding['intent_id']
                and isinstance(state.get('turn_id'), str) and sha(state['turn_id']) == hashes['turn_id'])
        except (OSError, ValueError, KeyError, TypeError):
            valid = False
        if not valid:
            raise BrokerError('foreign_or_historical_close_requires_owning_recovery', layer='broker-owning-lifecycle')

    def dispatch(
        self,
        message: dict[str, Any],
        *,
        defer_replay_ack_until_public_delivery: bool = False,
    ) -> dict[str, Any] | None:
        request_id = message.get("id")
        method = message.get("method")
        if message.get("jsonrpc") != "2.0" or not isinstance(method, str):
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32600, "message": "invalid request"},
            }
        if method.startswith("notifications/") or "id" not in message:
            return None
        params = message.get("params", {})
        if not isinstance(params, dict):
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32602, "message": "params must be an object"},
            }
        if method == "initialize":
            self.initialize_params = dict(params)
            requested = params.get("protocolVersion")
            protocol = requested if isinstance(requested, str) else DEFAULT_MCP_VERSION
            result = {
                "protocolVersion": protocol,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": BROKER_NAME, "version": BROKER_VERSION},
                "instructions": (
                    SERVER_INSTRUCTIONS
                    if CURRENT_TURN_CONTEXT_TOOL in self.tool_names
                    else LEGACY_SERVER_INSTRUCTIONS
                ),
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": self.tools_contract}
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(name, str) or not isinstance(arguments, dict):
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32602, "message": "invalid tool call"},
                }
            if "_integrity_read_session" in arguments:
                return {"jsonrpc":"2.0", "id":request_id,
                        "error":{"code":-32602,"message":"reserved reader session field"}}
            if name not in self.tool_names:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32602, "message": "unknown tool"},
                }
            try:
                # Owning lifecycle has its own authenticated source and journal.
                # A lost Seed snapshot must not precede that independent check.
                if name not in ({"integrity_context_admission", CURRENT_TURN_CONTEXT_TOOL}
                                | STANDALONE_TURN_MEMORY_TOOLS):
                    self._ensure_delivered_context_resume()
                if self._context_reattach_read_only and name in {
                    "integrity_append_event","integrity_archive_import","integrity_turn_memory_open"
                }:
                    raise BrokerError("reattached context cannot open or append",
                                      layer="broker-context-reattach-read-only",request_sent=False)
                if name in STANDALONE_TURN_MEMORY_TOOLS:
                    result = self._standalone_turn_memory_call(name, arguments)
                    try:
                        diagnostic = self._own_context_resume_diagnostic()
                        if "_meta" not in result:
                            result["_meta"] = {"integrityOwnContextResume": diagnostic}
                        elif isinstance(result["_meta"], dict):
                            result["_meta"] = {**result["_meta"], "integrityOwnContextResume": diagnostic}
                    except Exception:
                        # Optional metadata can never obscure a confirmed
                        # lifecycle result or create a retry of its side effect.
                        pass
                    return {"jsonrpc": "2.0", "id": request_id, "result": result}
                if name in {"integrity_context_admission", CURRENT_TURN_CONTEXT_TOOL}:
                    # A new owner intent supersedes the preceding context, so
                    # its response no longer needs transport-loss replay.
                    self.bound = False
                    if getattr(self, "_local_navigator", None):
                        self._local_navigator.selected = None
                    self._own_turn_binding = None
                    self._context_resume_control = None
                    self._pending_context_resume_payload = None
                    self._context_reattach_read_only = False
                    self._context_reattach_attempted = False
                    self._context_resume_diagnostic_stage = "not-attempted"
                    self._context_resume_error_type = None
                    turn_ref: str | None = None
                    claim_id: str | None = None
                    admission_arguments = arguments
                    if name == CURRENT_TURN_CONTEXT_TOOL:
                        turn_ref, claim_id, admission_arguments = (
                            self._resolve_current_turn(arguments)
                        )
                        self._retire_superseded_delivered_context(turn_ref,claim_id)
                    elif set(arguments) - {"intent", "budget", "limit"}:
                        raise BrokerError(
                            "legacy admission accepts only public intent/budget/limit fields",
                            layer="broker-envelope",
                        )
                    result = self._context_admission(
                        admission_arguments,
                        owning_producer=(turn_ref, claim_id) if turn_ref is not None else None,
                        defer_replay_ack_until_public_delivery=(
                            defer_replay_ack_until_public_delivery
                        ),
                    )
                    self.bound = result.get("isError") is not True
                    if self.bound:
                        self._binding_loss_receipt_digest = None
                        self._adopt_admitted_own_binding(result)
                        self._save_delivered_context_resume(result)
                    if turn_ref is not None and claim_id is not None:
                        if self._read_seal_retry(result):
                            try:
                                turn_envelope.release_claim(turn_ref, claim_id)
                            except (OSError, turn_envelope.TurnEnvelopeError) as error:
                                raise BrokerError(
                                    "read-seal retry claim could not be released",
                                    layer="broker-envelope",
                                    request_sent=True,
                                    retryable=False,
                                ) from error
                            turn_ref = claim_id = None
                        elif defer_replay_ack_until_public_delivery:
                            pending = (turn_ref, claim_id)
                            if pending not in self._turn_envelopes_awaiting_public_delivery:
                                self._turn_envelopes_awaiting_public_delivery.append(pending)
                        else:
                            delivered_ref, delivered_claim = turn_ref, claim_id
                            turn_ref = claim_id = None
                            self._consume_delivered_turn_envelope(
                                delivered_ref,
                                delivered_claim,
                            )
                    presenter = getattr(self, "_compact_presenter", None)
                    if presenter is None:
                        presenter = self._compact_presenter = _compact_admission.Presenter()
                    own_binding = getattr(self, "_own_turn_binding", None) or {}
                    context_key = (own_binding.get("hashes") or {}).get("thread_id")
                    public_result = presenter.present(result, context_key=context_key)
                    # Derived navigation never modifies the signed upstream prompt/admission.
                    if sys.platform == "win32" and self.bound and name == CURRENT_TURN_CONTEXT_TOOL:
                        try:
                            navigator = getattr(self, "_local_navigator", None)
                            if navigator is None:
                                navigator = self._local_navigator = _local_routes.Navigator(
                                    _load_owner_catalogue(_LOCAL_ROUTE_CATALOG), Path.home()/".codex/integrity-memory/state",
                                    Path(_integrity_value('path_dd2435d503a6')))
                            raw_admission = json.loads(public_result['content'][0]['text'])
                            snapshot = raw_admission.get('admission', {}).get('snapshot_id')
                            navigation_binding = _native_navigation_scope.observe_binding(
                                turn_envelope, own_binding, Path(_integrity_value('path_dd2435d503a6')))
                            task_prompt, task_source = _native_task_route.project(turn_envelope, self._local_route_prompt, own_binding)
                            local = navigator.admit(task_prompt, navigation_binding, snapshot)
                            local['snapshot_id'] = snapshot
                            self._native_route_snapshot = snapshot
                            self._native_route_source = task_source
                            self._native_route_scope = navigation_binding
                            local['scope_source'] = navigation_binding.get('project_scope_source', 'hook-project-scope')
                            local = _automatic_Core.delivery(self.upstream, local, task_source, _TASK_CONTEXT_EXPERIMENT, _CORE_CATALOG_DIGEST)
                            _automatic_Core.journal(local, own_binding['context_admission_id'])
                            public_result = _local_routes.augment(public_result, local, limit=32768)
                        except (OSError, ValueError, KeyError, TypeError):
                            # Optional navigation failure cannot deny the canonical read plane.
                            public_result = _local_routes.augment(public_result,
                                {'status': 'native-scope-unavailable', 'external_action_authority': False})
                    return {"jsonrpc": "2.0", "id": request_id, "result": public_result}
                elif name in {"integrity_append_event","integrity_archive_import","integrity_archive_read"} and self._restore_pending_archive_uncertainty(name, arguments):
                    raise AssertionError("archive restoration is observation-only")
                elif name in {"integrity_append_event","integrity_archive_import","integrity_turn_memory_reconcile"} and (
                    self._uncertain_append_receipt_digest or self._uncertain_archive_uids):
                    raise BrokerError(
                        "append outcome unresolved; reconcile through owning writer before further writes",
                        layer="broker-append-uncertain",
                        request_sent=False, retryable=False,
                    )
                elif self.upstream is None or not self.bound:
                    if self.upstream is not None:
                        try:
                            self._ack_pending_context_replays()
                        except BrokerError as exc:
                            raise BrokerError(
                                str(exc),
                                layer=exc.layer,
                                request_sent=False,
                                retryable=exc.retryable,
                            ) from exc
                    raise BrokerError(
                        ("upstream logical context was lost; delivered admission has no supported reattach"
                         if self._binding_loss_receipt_digest else
                         "current intent has no admitted upstream facade"),
                        layer=("broker-context-lost" if self._binding_loss_receipt_digest else
                               "broker-binding-missing"),
                    )
                assert self.upstream is not None
                try:
                    self._ack_pending_context_replays()
                except BrokerError as exc:
                    raise BrokerError(
                        str(exc),
                        layer=exc.layer,
                        request_sent=False,
                        retryable=exc.retryable,
                    ) from exc
                if name in ARCHIVE_TOOLS:
                    arguments=self._bound_archive_arguments(name,arguments)
                if name == "integrity_append_event":
                    self._pending_append_arguments = json.loads(json.dumps(arguments))
                if name == "integrity_archive_import":
                    self._begin_archive_dispatch(arguments)
                if name == 'integrity_memory_ttt_autofill' and getattr(self, '_native_route_source', None):
                    result = _automatic_Core.query(self._local_navigator, self.upstream, arguments,
                        {**(self._own_turn_binding or {}), 'snapshot_id':self._native_route_snapshot},
                        self._native_route_scope, self._native_route_source, _TASK_CONTEXT_EXPERIMENT, _CORE_CATALOG_DIGEST)
                    if result is not None:
                        return {"jsonrpc":"2.0", "id":request_id, "result":result}
                if name == 'integrity_turn_memory_reconcile':
                    try:
                        _automatic_Core.guard_curator(turn_envelope, self._own_turn_binding or {}, arguments)
                    except (OSError, ValueError, KeyError, TypeError) as error:
                        raise BrokerError(str(error), layer='broker-curator-actor', request_sent=False) from None
                result = self._same_session_mutation(name, arguments)
                self._observe_late_append(result)
                self._observe_late_lifecycle(result)
                if name in ARCHIVE_TOOLS:
                    self._observe_archive_result(name,arguments,result)
                self._observe_upstream_denial(name, result)
                if name == 'integrity_memory_ttt_autofill' and getattr(self, '_local_navigator', None):
                    local = self._local_navigator.remaining(arguments.get('goal', ''),
                        arguments.get('last_hop', ''), arguments.get('snapshot_id'))
                    # Keep the upstream BLOCKED/receipt exactly visible. This suffix is
                    # explicitly local navigation, not a canonical graph admission.
                    if local.get('status') == 'navigation-ready':
                        result = _local_routes.augment(result, local, limit=32768)
                result = self._native_completed_archive_denial(name, result)
            except BrokerError as exc:
                if name == "integrity_archive_import" and exc.request_sent:
                    self._uncertain_archive_uids.update(p.get("event_uid") for p in arguments.get("parts",[]) if isinstance(p,dict))
                if name == "integrity_append_event" and exc.request_sent:
                    self._uncertain_append_receipt_digest = self._digest({
                        "tool": name, "arguments_digest": self._digest(arguments),
                        "outcome": "unknown", "failure_layer": exc.layer,
                    })
                if (
                    name == CURRENT_TURN_CONTEXT_TOOL
                    and turn_ref is not None
                    and claim_id is not None
                ):
                    if not exc.request_sent and exc.layer == "broker-upstream":
                        try:
                            turn_envelope.release_claim(turn_ref, claim_id)
                            turn_ref = claim_id = None
                        except (OSError, turn_envelope.TurnEnvelopeError) as release_error:
                            exc = BrokerError(
                                "pre-send turn envelope claim could not be released",
                                layer="broker-envelope",
                                request_sent=False,
                                retryable=False,
                            )
                            exc.add_note(str(release_error))
                    elif defer_replay_ack_until_public_delivery:
                        pending = (turn_ref, claim_id)
                        if pending not in self._turn_envelopes_awaiting_public_delivery:
                            self._turn_envelopes_awaiting_public_delivery.append(pending)
                        turn_ref = claim_id = None
                    else:
                        delivered_ref, delivered_claim = turn_ref, claim_id
                        turn_ref = claim_id = None
                        try:
                            self._consume_delivered_turn_envelope(
                                delivered_ref,
                                delivered_claim,
                            )
                        except BrokerError as consume_error:
                            exc = consume_error
                if name not in STANDALONE_TURN_MEMORY_TOOLS and name not in {
                    "integrity_context_admission",
                    CURRENT_TURN_CONTEXT_TOOL,
                } and (
                    exc.retryable or not self._pending_context_replay_acks
                ) and not (name == "integrity_append_event" and self.upstream is not None
                           and getattr(self.upstream, "retain_timed_out_append", lambda error: False)(exc))                   and exc.layer not in {"broker-append-uncertain", "broker-context-lost"}:
                    try:
                        self.close()
                    except Exception as cleanup_error:  # noqa: BLE001 - retain the primary error
                        exc.add_note(f"secondary broker cleanup failed: {type(cleanup_error).__name__}")
                result = self._denial(name, exc)
        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "method not found"},
            }
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _consume_delivered_turn_envelope(
        self,
        turn_ref: str,
        claim_id: str,
    ) -> None:
        try:
            turn_envelope.commit(turn_ref, claim_id)
            return
        except (OSError, turn_envelope.TurnEnvelopeError) as commit_error:
            # The response was already delivered. Never leave its exact
            # prompt armed merely because the content-free tombstone failed.
            try:
                turn_envelope.retire(turn_ref)
            except (OSError, turn_envelope.TurnEnvelopeError) as retire_error:
                self.close()
                raise BrokerError(
                    "delivered turn envelope could not be consumed",
                    layer="broker-envelope",
                    request_sent=True,
                    retryable=False,
                ) from retire_error
            self.close()
            raise BrokerError(
                "delivered turn envelope tombstone failed; payload retired",
                layer="broker-envelope",
                request_sent=True,
                retryable=False,
            ) from commit_error

    def confirm_public_response_delivery(self) -> None:
        """Make only responses flushed to the public client eligible for ACK."""

        self._context_replay_acks_awaiting_public_delivery.clear()
        pending = self._turn_envelopes_awaiting_public_delivery
        self._turn_envelopes_awaiting_public_delivery = []
        for turn_ref, claim_id in pending:
            self._commit_delivered_context_resume(turn_ref, claim_id)
            self._consume_delivered_turn_envelope(turn_ref, claim_id)

    def shutdown(self) -> None:
        """Retire delivered replay state only on graceful public EOF."""

        try:
            if self._public_cancelled.is_set():
                return
            if self.upstream is None and self._pending_context_replay_acks:
                self._open_upstream(
                    self._pending_context_replay_acks[0]["replay_id"]
                )
            self._ack_pending_context_replays()
        except BrokerError:
            pass
        finally:
            self.close()


# BEGIN CANONICAL SESSION RECOVERY
from integrity_client_memory import operation_ledger as _operation_ledger
from integrity_client_memory import recovery_client as _recovery_client
from integrity_client_memory import broker_adapter as _broker_adapter
_broker_adapter.install(globals(), _recovery_client, _operation_ledger)
# END CANONICAL SESSION RECOVERY


def serve(broker: TurnBroker) -> int:
    public = PublicInput(sys.stdin.buffer, MAX_MESSAGE_BYTES, broker._public_cancelled)
    try:
        while True:
            raw = public.next()
            if raw is None or broker._public_cancelled.is_set():
                break
            try:
                if len(raw) > MAX_MESSAGE_BYTES:
                    raise ValueError("request exceeds limit")
                message = json.loads(raw)
                if not isinstance(message, dict):
                    raise TypeError("request must be an object")
                response = broker.dispatch(
                    message,
                    defer_replay_ack_until_public_delivery=True,
                )
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "parse error"},
                }
            if broker._public_cancelled.is_set():
                break
            if response is not None:
                payload = _json_bytes(response) + b"\n"
                written_total = 0
                while written_total < len(payload):
                    written = sys.stdout.buffer.write(
                        memoryview(payload)[written_total:]
                    )
                    if (
                        not isinstance(written, int)
                        or isinstance(written, bool)
                        or written <= 0
                        or written > len(payload) - written_total
                    ):
                        raise BrokenPipeError(
                            "public response transport made no progress"
                        )
                    written_total += written
                sys.stdout.buffer.flush()
                try:
                    broker.confirm_public_response_delivery()
                except BrokerError:
                    # The public response is already flushed: do not send a
                    # second response or retry the admitted operation. Drop only
                    # that upstream binding; a later intent may admit afresh on
                    # this same public transport. Keep diagnostics content-free.
                    broker.close()
                    print(
                        "Integrity broker: post-delivery custody failure; binding closed",
                        file=sys.stderr,
                        flush=True,
                    )
        return 0
    finally:
        broker._public_cancelled.set()
        broker.shutdown()
        public.thread.join(timeout=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--upstream-server", required=True)
    parser.add_argument("--tools-contract", type=Path, required=True)
    args = parser.parse_args(argv)
    tools_contract = _load_tools_contract(args.tools_contract)
    return serve(TurnBroker(args.config, args.upstream_server, tools_contract))


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
