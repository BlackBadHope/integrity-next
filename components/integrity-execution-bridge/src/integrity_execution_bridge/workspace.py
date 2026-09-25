"""POSIX descriptor-relative file operations, not a shell/network sandbox.

The host must give this service exclusive mutation ownership of a disposable
worktree. Expected-hash checks cannot arbitrate a hostile same-UID writer.
"""
from __future__ import annotations

import os
import stat
import threading
import uuid
from pathlib import Path

from .contracts import MAX_OUTPUT, Rejected, require, sha


class Workspace:
    def __init__(self, root: Path):
        require(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "workspace_platform_unproven")
        root = Path(root)
        require(root.is_absolute() and root == root.resolve(strict=True), "noncanonical_workspace")
        self.root = root
        self.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.identity = (os.fstat(self.fd).st_dev, os.fstat(self.fd).st_ino)
        self.lock = threading.RLock()
        self.closed = False

    def close(self):
        with self.lock:
            if not self.closed:
                self.closed = True
                os.close(self.fd)

    def _parts(self, path: str):
        require(type(path) is str and 0 < len(path) <= 1024, "invalid_path")
        parts = path.split("/")
        require(all(part and part not in {".", "..", ".git"} and "\\" not in part
                    and ":" not in part and all(ord(c) >= 32 for c in part) for part in parts),
                "path_not_admitted")
        return parts

    def _parent(self, path):
        require(not self.closed, "workspace_closed")
        require(self.root == self.root.resolve(strict=True)
                and (self.root.stat().st_dev, self.root.stat().st_ino) == self.identity,
                "workspace_identity_changed")
        parts = self._parts(path)
        fd = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            return fd, parts[-1]
        except BaseException:
            os.close(fd)
            raise

    def directory(self, path):
        # Codex receives a native absolute cwd, never a caller-controlled URI.
        with self.lock:
            require(not self.closed, "workspace_closed")
            require(self.root == self.root.resolve(strict=True)
                    and (self.root.stat().st_dev, self.root.stat().st_ino) == self.identity,
                    "workspace_identity_changed")
            if path == ".":
                return str(self.root)
            parts = self._parts(path)
            fd = os.dup(self.fd)
            try:
                for part in parts:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd)
                    fd = child
                return str(self.root.joinpath(*parts))
            finally:
                os.close(fd)

    def _read(self, parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "not_single_regular_file")
            require(before.st_size <= MAX_OUTPUT, "file_limit")
            chunks = bytearray()
            while len(chunks) <= MAX_OUTPUT:
                chunk = os.read(fd, min(8192, MAX_OUTPUT + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
            after = os.fstat(fd)
            require(len(chunks) <= MAX_OUTPUT, "file_limit")
            require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "file_changed_during_read")
            return bytes(chunks), before
        finally:
            os.close(fd)

    def read(self, path, offset=0, limit=8192):
        with self.lock:
            parent, name = self._parent(path)
            try:
                raw, _ = self._read(parent, name)
                try:
                    text = raw.decode("utf-8")
                except UnicodeError:
                    raise Rejected("not_utf8") from None
                require(type(offset) is int and 0 <= offset <= len(text)
                        and type(limit) is int and 1 <= limit <= 8192, "invalid_file_cursor")
                end = min(len(text), offset + limit)
                return {"path": path, "text": text[offset:end], "sha256": sha(raw), "bytes": len(raw),
                        "next_offset": end, "eof": end == len(text)}
            finally:
                os.close(parent)

    def replace(self, path, expected_sha256, old, new, expected_count):
        with self.lock:
            parent, name = self._parent(path)
            temporary = ".integrity-" + uuid.uuid4().hex
            created = False
            try:
                raw, original = self._read(parent, name)
                require(sha(raw) == expected_sha256, "stale_file")
                text = raw.decode("utf-8")
                require(bool(old) and text.count(old) == expected_count, "replacement_count_mismatch")
                result = text.replace(old, new).encode("utf-8")
                require(len(result) <= MAX_OUTPUT, "file_limit")
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
                created = True
                with os.fdopen(fd, "wb") as stream:
                    stream.write(result)
                    stream.flush()
                    os.fchmod(stream.fileno(), stat.S_IMODE(original.st_mode) & 0o777)
                    os.fsync(stream.fileno())
                current, state = self._read(parent, name)
                require((state.st_dev, state.st_ino) == (original.st_dev, original.st_ino)
                        and sha(current) == expected_sha256, "file_changed_before_replace")
                os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
                created = False
                os.fsync(parent)
                observed, _ = self._read(parent, name)
                require(observed == result, "replace_readback_mismatch")
                return {"before_sha256": expected_sha256, "after_sha256": sha(observed),
                        "bytes": len(observed), "independent_acceptance": False}
            finally:
                if created:
                    os.unlink(temporary, dir_fd=parent)
                os.close(parent)
