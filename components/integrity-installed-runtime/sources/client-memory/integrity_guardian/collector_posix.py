"""POSIX execution backend for digest-pinned customer collectors."""

from __future__ import annotations

import hashlib
import os
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from .collector import (
    CollectorBoundaryError,
    CollectorProfile,
    _build_collector_result,
    _parse_output,
)

try:
    import resource
except ModuleNotFoundError:  # pragma: no cover - importable on non-POSIX hosts
    resource = None  # type: ignore[assignment]

_COLLECTOR_EXEC_WRAPPER = """
import os
import resource
import sys

maximum = int(sys.argv[1])
cpu_soft = int(sys.argv[2])
descriptor = int(sys.argv[3])
executable = f"/proc/self/fd/{descriptor}"
resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
resource.setrlimit(resource.RLIMIT_CPU, (cpu_soft, cpu_soft + 1))
os.execve(executable, [executable, *sys.argv[4:]], os.environ)
"""


def _open_verified_executable(profile: CollectorProfile) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(profile.executable, flags)
    except OSError as exc:
        raise CollectorBoundaryError("collector executable is absent or unsafe") from exc
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or not details.st_mode & 0o111:
            raise CollectorBoundaryError("collector executable type or mode rejected")
        if details.st_uid not in {0, os.geteuid()}:
            raise CollectorBoundaryError("collector executable owner rejected")
        if stat.S_IMODE(details.st_mode) & 0o022:
            raise CollectorBoundaryError("collector executable is group/world writable")
        hasher = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            hasher.update(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)
        if f"sha256:{hasher.hexdigest()}" != profile.executable_digest:
            raise CollectorBoundaryError("collector executable digest mismatch")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def run_collector_posix(profile: CollectorProfile) -> dict[str, object]:
    """Run one exact executable behind the Linux procfs/resource boundary."""

    if os.name != "posix" or resource is None or not Path("/proc/self/fd").is_dir():
        raise CollectorBoundaryError(
            "digest-pinned collector execution requires Linux procfs"
        )
    descriptor = _open_verified_executable(profile)
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GUARDIAN_CREDENTIAL_REFERENCE": profile.credential_reference or "",
    }
    interpreter = Path(sys.executable)
    if not interpreter.is_absolute() or not interpreter.is_file():
        os.close(descriptor)
        raise CollectorBoundaryError("collector limit wrapper interpreter rejected")
    cpu_limit = max(1, min(profile.timeout_seconds, 60))

    try:
        with tempfile.TemporaryDirectory(prefix="guardian-collector-") as name:
            temporary = Path(name)
            stdout_path = temporary / "stdout.json"
            stderr_path = temporary / "stderr.log"
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                process = subprocess.Popen(
                    [
                        str(interpreter),
                        "-I",
                        "-S",
                        "-c",
                        _COLLECTOR_EXEC_WRAPPER,
                        str(profile.max_output_bytes),
                        str(cpu_limit),
                        str(descriptor),
                        *profile.argv,
                    ],
                    cwd=temporary,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    pass_fds=(descriptor,),
                    close_fds=True,
                    start_new_session=True,
                )
                timed_out: subprocess.TimeoutExpired | None = None
                try:
                    return_code = process.wait(timeout=profile.timeout_seconds)
                except subprocess.TimeoutExpired as exc:
                    timed_out = exc
                    return_code = process.returncode
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if process.poll() is None:
                    process.wait()
                if timed_out is not None:
                    raise CollectorBoundaryError("collector timeout") from timed_out
                if return_code is None:
                    raise CollectorBoundaryError("collector exit status unavailable")
            stdout_payload = stdout_path.read_bytes()
            stderr_payload = stderr_path.read_bytes()
    finally:
        os.close(descriptor)

    if len(stdout_payload) > profile.max_output_bytes or len(stderr_payload) > (
        profile.max_output_bytes
    ):
        raise CollectorBoundaryError("collector output exceeded bound")
    if return_code != 0:
        raise CollectorBoundaryError(f"collector exited nonzero: {return_code}")
    document, facts = _parse_output(stdout_payload)
    return _build_collector_result(profile, document, facts, stdout_payload)
