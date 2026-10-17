"""Cross-process, re-entrant advisory lock for one local corpus state."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import threading
import time
from typing import Iterator


class CorpusStateLockError(RuntimeError):
    """Raised when another writer keeps the local corpus lock."""


_LOCAL = threading.local()


def _lock_path(index_path: str) -> Path:
    return Path(f"{index_path}.state.lock")


def _try_lock(stream) -> bool:
    stream.seek(0)
    if os.name == "nt":
        import msvcrt

        try:
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    import fcntl

    try:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False


def _unlock(stream) -> None:
    stream.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


@contextmanager
def corpus_state_lock(index_path: str, *, timeout_seconds: float = 30.0) -> Iterator[None]:
    if not isinstance(index_path, str) or not index_path:
        raise CorpusStateLockError("index_path is required for corpus state lock")
    if timeout_seconds < 0:
        raise CorpusStateLockError("lock timeout must be non-negative")
    path = _lock_path(index_path).resolve()
    key = str(path).casefold() if os.name == "nt" else str(path)
    held = getattr(_LOCAL, "held", None)
    if held is None:
        held = {}
        _LOCAL.held = held
    if key in held:
        held[key] += 1
        try:
            yield
        finally:
            held[key] -= 1
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        stream = os.fdopen(descriptor, "r+b", closefd=False)
        deadline = time.monotonic() + timeout_seconds
        while not _try_lock(stream):
            if time.monotonic() >= deadline:
                raise CorpusStateLockError(
                    f"timed out waiting for corpus state lock: {path}"
                )
            time.sleep(0.05)
        held[key] = 1
        try:
            yield
        finally:
            held.pop(key, None)
            _unlock(stream)
            stream.close()
    finally:
        os.close(descriptor)


__all__ = ["CorpusStateLockError", "corpus_state_lock"]
