"""Bounded workspace effects: read_file, write_file, edit_file, list_dir (Windows).

Confinement is checked on the handles actually opened, not only on a resolved path:
every directory from the workspace root to the target is opened share-READ-only (it
cannot be renamed, deleted or opened for writing by anyone else while held), and each
handle must be a non-reparse directory whose final path equals the expected path.
Targets must be regular, non-reparse files with a single link.

Compare-and-swap boundary (handle-bound, stated exactly):
* existing target: opened at prepare time with GENERIC_READ|GENERIC_WRITE and share
  READ only. From the pre-state hash until the write completes no other handle can
  write, truncate, rename or delete it (the OS refuses sharing), so the pre-state
  cannot change underneath us. The write goes through that same handle, in place:
  it is NOT atomic -- a failure mid-write is reported as an UNKNOWN outcome.
* absent target: created at commit with CREATE_NEW (no clobber). If something
  appeared meanwhile the call is a reported failure with nothing written.
The chain is re-verified on the held handles right before the effect and the created
handle's final path is checked after creation; a mismatch is UNKNOWN, never success.

Order per call: syntax/allowlist/size/type -> pre-state digest (local, no export) ->
``prepare`` returns descriptor fields -> the SDK authority consumes a permit ->
``commit`` performs the read-export or the write. No permit, no commit.
"""
from __future__ import annotations

import ctypes
import os
import re
import time
from contextlib import ExitStack
from ctypes import wintypes
from pathlib import Path

from . import _winabi as abi
from .canonical import Rejected, canonical_bytes, need, sha256_bytes
from .policy import ExecutorPolicy

_RESERVED = {"con", "prn", "aux", "nul", "conin$", "conout$",
             *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
_BAD_CHARS = re.compile(r'[\x00-\x1f<>:"|?*\\]')
_SCAN_FACTOR = 4          # entries examined per entry that may be returned
_SCAN_SECONDS = 2.0
TOOL_SCHEMAS = {
    "read_file": {"type": "object", "additionalProperties": False, "required": ["path"],
                  "properties": {"path": {"type": "string", "maxLength": 512}}},
    "list_dir": {"type": "object", "additionalProperties": False, "required": ["path"],
                 "properties": {"path": {"type": "string", "maxLength": 512}}},
    "write_file": {"type": "object", "additionalProperties": False,
                   "required": ["path", "content", "expected_sha256"],
                   "properties": {"path": {"type": "string", "maxLength": 512},
                                  "content": {"type": "string"},
                                  "expected_sha256": {"type": "string", "maxLength": 71}}},
    "edit_file": {"type": "object", "additionalProperties": False,
                  "required": ["path", "old", "new", "expected_sha256"],
                  "properties": {"path": {"type": "string", "maxLength": 512},
                                 "old": {"type": "string"}, "new": {"type": "string"},
                                 "expected_sha256": {"type": "string", "maxLength": 71}}},
}


def normalize(path, *, allow_root: bool = False) -> str:
    """Relative, '/'-separated, no traversal/ADS/devices/.git; returns the normalized form."""
    need(type(path) is str and len(path) <= 512, "path_shape")
    if allow_root and path in ("", "."):
        return ""
    need(path and not path.startswith("/") and not _BAD_CHARS.search(path), "path_syntax")
    parts = path.split("/")
    need(len(parts) <= 32, "path_depth")
    for part in parts:
        need(part not in ("", ".", "..") and len(part) <= 255, "path_component")
        need(not part.endswith((" ", ".")), "path_trailing")
        need(part.split(".", 1)[0].lower() not in _RESERVED, "path_device")
        need(part.lower() != ".git", "path_git")
    return "/".join(parts)


def _args(tool: str, arguments) -> dict:
    schema = TOOL_SCHEMAS.get(tool)
    need(schema is not None, "tool_unknown")
    need(type(arguments) is dict and set(arguments) == set(schema["required"]), "tool_arguments")
    for key, spec in schema["properties"].items():
        need(type(arguments[key]) is str and len(arguments[key]) <= spec.get("maxLength", 1 << 30),
             "tool_arguments")
    return dict(arguments)


class _Handle:
    def __init__(self, k, handle):
        self.k, self.value = k, handle

    def close(self):
        if self.value:
            self.k.CloseHandle(self.value)
            self.value = None


class Prepared:
    """A validated, pre-hashed call holding its handles. ``fields`` feed the descriptor."""

    def __init__(self, fields: dict, commit, stack: ExitStack):
        self.fields, self._commit, self._stack = fields, commit, stack
        self._used = False

    def commit(self) -> tuple:
        need(not self._used, "commit_replay")
        self._used = True
        return self._commit()

    def close(self) -> None:
        self._stack.close()


class Workspace:
    def __init__(self, root: Path, policy: ExecutorPolicy):
        need(os.name == "nt", "windows_required")
        need(isinstance(policy, ExecutorPolicy), "policy_type")
        self.k = abi.load()
        self.root = Path(os.path.abspath(root))
        self.policy = policy

    # -- handle primitives ------------------------------------------------------
    def _open(self, path: Path, *, access: int, share: int, directory: bool,
              disposition: int = abi.OPEN_EXISTING, missing_ok: bool = False,
              exists_ok: bool = False):
        flags = abi.FILE_FLAG_OPEN_REPARSE_POINT | (abi.FILE_FLAG_BACKUP_SEMANTICS if directory else 0)
        handle = self.k.CreateFileW(str(path), access, share, None, disposition, flags, None)
        if handle in (None, abi.INVALID_HANDLE_VALUE):
            code = ctypes.get_last_error()
            if missing_ok and code in (abi.ERROR_FILE_NOT_FOUND, abi.ERROR_PATH_NOT_FOUND):
                return None
            if exists_ok and code in (80, 183):  # ERROR_FILE_EXISTS / ERROR_ALREADY_EXISTS
                return None
            raise Rejected("path_open_failed")
        return _Handle(self.k, handle)

    def _info(self, handle: _Handle) -> abi.FileInformation:
        info = abi.FileInformation()
        need(self.k.GetFileInformationByHandle(handle.value, ctypes.byref(info)), "path_info")
        return info

    @staticmethod
    def _size(info) -> int:
        return (info.size_high << 32) | info.size_low

    def _final(self, handle: _Handle) -> str:
        buffer = ctypes.create_unicode_buffer(32768)
        length = self.k.GetFinalPathNameByHandleW(handle.value, buffer, len(buffer), 0)
        need(0 < length < len(buffer), "path_final")
        value = buffer.value
        need(value.startswith("\\\\?\\") and not value.startswith("\\\\?\\UNC\\"), "path_final_form")
        return os.path.normcase(value[4:])

    def _verify(self, handle: _Handle, expected: Path, *, directory: bool) -> abi.FileInformation:
        info = self._info(handle)
        need(not info.attributes & abi.FILE_ATTRIBUTE_REPARSE_POINT, "path_reparse")
        need(bool(info.attributes & abi.FILE_ATTRIBUTE_DIRECTORY) == directory, "path_type")
        need(self._final(handle) == os.path.normcase(str(expected)), "path_escape")
        if not directory:
            need(info.links == 1, "path_hardlink")
        return info

    def _chain(self, stack: ExitStack, parts: list) -> tuple[Path, list]:
        """Hold (share READ only) and verify root + every directory component."""
        current, held = self.root, []
        for index in range(len(parts) + 1):
            if index:
                current = current / parts[index - 1]
            handle = self._open(current, access=abi.FILE_READ_ATTRIBUTES | abi.SYNCHRONIZE,
                                share=abi.FILE_SHARE_READ, directory=True)
            stack.callback(handle.close)
            self._verify(handle, current, directory=True)
            held.append((handle, current))
        return current, held

    def _reverify(self, held: list) -> None:
        for handle, path in held:
            self._verify(handle, path, directory=True)

    def _read_from(self, handle: _Handle, size: int) -> bytes:
        need(self.k.SetFilePointerEx(handle.value, 0, None, 0), "path_seek")
        buffer, read = ctypes.create_string_buffer(max(size, 1)), wintypes.DWORD()
        data = bytearray()
        while len(data) < size:
            need(self.k.ReadFile(handle.value, buffer, size - len(data), ctypes.byref(read), None),
                 "path_read")
            if read.value == 0:
                break
            data.extend(buffer.raw[: read.value])
        need(len(data) == size, "path_read_size")
        return bytes(data)

    def _text(self, handle: _Handle, target: Path, limit: int) -> bytes:
        info = self._verify(handle, target, directory=False)
        size = self._size(info)
        need(size <= limit, "path_too_large")  # size/type checked before any read/allocation
        raw = self._read_from(handle, size)
        try:
            raw.decode("utf-8", errors="strict")
        except UnicodeError:
            raise Rejected("path_not_text") from None
        return raw

    # -- catalog ----------------------------------------------------------------
    def prepare(self, tool: str, arguments) -> Prepared:
        arguments = _args(tool, arguments)
        stack = ExitStack()
        try:
            return getattr(self, "_prepare_" + tool)(stack, arguments)
        except BaseException:
            stack.close()
            raise

    def _file_target(self, stack: ExitStack, path: str):
        relative = normalize(path)
        need(self.policy.allows(relative), "path_not_allowed")
        parts = relative.split("/")
        parent, held = self._chain(stack, parts[:-1])
        return relative, parent / parts[-1], held

    def _prepare_read_file(self, stack, arguments) -> Prepared:
        relative, target, _ = self._file_target(stack, arguments["path"])
        handle = self._open(target, access=abi.GENERIC_READ, share=abi.FILE_SHARE_READ, directory=False)
        stack.callback(handle.close)
        raw = self._text(handle, target, self.policy.max_read_bytes)
        pre = sha256_bytes(raw)
        fields = {"tool": "read_file", "path": relative, "effect_class": "export",
                  "pre_sha256": pre, "content_sha256": None, "bytes": len(raw)}
        return Prepared(fields, lambda: (raw.decode("utf-8"), "reported-success",
                                         {"tool": "read_file", "pre_sha256": pre}), stack)

    def _prepare_list_dir(self, stack, arguments) -> Prepared:
        relative = normalize(arguments["path"], allow_root=True)
        need(self.policy.allows_dir(relative), "path_not_allowed")
        directory, _ = self._chain(stack, relative.split("/") if relative else [])
        limit = self.policy.max_list_entries
        entries, truncated, scanned = [], False, 0
        deadline = time.monotonic() + _SCAN_SECONDS
        with os.scandir(directory) as iterator:
            for entry in iterator:
                scanned += 1
                if len(entries) >= limit or scanned > limit * _SCAN_FACTOR \
                        or time.monotonic() > deadline:
                    truncated = True
                    break
                if entry.name.lower() == ".git" or entry.is_symlink() or \
                        entry.stat(follow_symlinks=False).st_file_attributes \
                        & abi.FILE_ATTRIBUTE_REPARSE_POINT:
                    continue
                child = f"{relative}/{entry.name}" if relative else entry.name
                if entry.is_dir(follow_symlinks=False):
                    if not self.policy.allows_dir(child):
                        continue  # unauthorized directory names are not exported either
                    entries.append({"name": entry.name, "type": "dir"})
                elif self.policy.allows(child):
                    entries.append({"name": entry.name, "type": "file"})
        entries.sort(key=lambda item: (item["type"], item["name"]))
        listing = {"entries": entries, "truncated": truncated}
        text = canonical_bytes(listing).decode("utf-8")
        pre = sha256_bytes(text.encode("utf-8"))
        fields = {"tool": "list_dir", "path": relative, "effect_class": "export",
                  "pre_sha256": pre, "content_sha256": None, "bytes": len(entries)}
        return Prepared(fields, lambda: (text, "reported-success",
                                         {"tool": "list_dir", "pre_sha256": pre}), stack)

    def _prepare_write_file(self, stack, arguments) -> Prepared:
        return self._prepare_replace(stack, "write_file", arguments["path"],
                                     arguments["expected_sha256"], lambda old: arguments["content"])

    def _prepare_edit_file(self, stack, arguments) -> Prepared:
        old, new = arguments["old"], arguments["new"]
        need(old != "", "edit_old_empty")

        def transform(current: str | None) -> str:
            need(current is not None, "edit_target_missing")
            need(current.count(old) == 1, "edit_old_not_unique")
            return current.replace(old, new, 1)
        return self._prepare_replace(stack, "edit_file", arguments["path"],
                                     arguments["expected_sha256"], transform)

    def _prepare_replace(self, stack, tool, path, expected, transform) -> Prepared:
        need(expected == "absent" or re.fullmatch(r"sha256:[0-9a-f]{64}", expected), "expected_sha256")
        relative, target, held = self._file_target(stack, path)
        handle = self._open(target, access=abi.GENERIC_READ | abi.GENERIC_WRITE,
                            share=abi.FILE_SHARE_READ, directory=False, missing_ok=True)
        raw = None
        if handle is not None:
            stack.callback(handle.close)  # held until commit: nobody else can write/replace it
            raw = self._text(handle, target, self.policy.max_write_bytes)
        pre = "absent" if raw is None else sha256_bytes(raw)
        need(pre == expected, "pre_state_mismatch")  # refused before any authority is used
        content = transform(None if raw is None else raw.decode("utf-8")).encode("utf-8")
        need(len(content) <= self.policy.max_write_bytes, "content_too_large")
        digest = sha256_bytes(content)
        fields = {"tool": tool, "path": relative, "effect_class": "write", "pre_sha256": pre,
                  "content_sha256": digest, "bytes": len(content)}

        def commit():
            self._reverify(held)
            receipt = {"tool": tool, "pre_sha256": pre, "post_sha256": digest}
            if handle is None:
                created = self._open(target, access=abi.GENERIC_READ | abi.GENERIC_WRITE,
                                     share=abi.FILE_SHARE_READ, directory=False,
                                     disposition=abi.CREATE_NEW, exists_ok=True)
                if created is None:  # appeared after prepare: nothing written
                    return ("target changed; not written", "reported-failure",
                            {**receipt, "post_sha256": None})
                stack.callback(created.close)
                self._verify(created, target, directory=False)  # mismatch => UNKNOWN
                self._write_in_place(created, content, digest)
            else:
                self._write_in_place(handle, content, digest)
            return (f"ok {digest}", "reported-success", receipt)
        return Prepared(fields, commit, stack)

    def _write_in_place(self, handle: _Handle, content: bytes, digest: str) -> None:
        """Through the held handle. Not atomic: any failure here is an UNKNOWN outcome."""
        need(self.k.SetFilePointerEx(handle.value, 0, None, 0), "write_seek")
        written, offset = wintypes.DWORD(), 0
        while offset < len(content):
            piece = content[offset:offset + 65536]
            need(self.k.WriteFile(handle.value, piece, len(piece), ctypes.byref(written), None)
                 and written.value, "write_failed")
            offset += written.value
        need(self.k.SetEndOfFile(handle.value), "write_truncate")
        need(self.k.FlushFileBuffers(handle.value), "write_flush")
        size = self._size(self._info(handle))
        need(size == len(content), "post_state_size")  # checked before re-read allocation
        need(sha256_bytes(self._read_from(handle, size)) == digest, "post_state_digest")


EFFECT_SCHEMA = {"schema_id": "integrity-claude-code/tool-effect/v1", "fields": sorted([
    "schema", "run_descriptor_sha256", "session_id", "run_id", "sequence", "arguments_sha256",
    "policy_sha256", "tool", "path", "effect_class", "pre_sha256", "content_sha256", "bytes"])}


def effect_descriptor(*, run_sha256: str, session_id: str, run_id: str, sequence: int,
                      arguments: dict, fields: dict, policy_sha256: str) -> dict:
    return {"schema": "integrity-claude-code/tool-effect/v1", "run_descriptor_sha256": run_sha256,
            "session_id": session_id, "run_id": run_id, "sequence": sequence,
            "arguments_sha256": sha256_bytes(canonical_bytes(arguments)),
            "policy_sha256": policy_sha256, **fields}
