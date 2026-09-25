"""Task-bound direct execution, with an unsigned delivery/dedup cache.

The cache is NOT the Action Log, authority ledger or independent outcome witness.
It never permits a retry. External SDK permits/checkpoints remain authoritative.
"""
from __future__ import annotations

import os
import sqlite3
import stat
import threading
import time
from pathlib import Path

from . import __version__
from .catalog import CATALOG_SHA256, validate
from .contracts import Control, Rejected, Task, Unknown, encode, freeze, identifier, require, sha
from .sdk_gate import SDKInvoker


class DeliveryCache:
    """Single-process, bounded private metadata cache; no raw code/output/secrets."""
    def __init__(self, directory: Path, namespace: str):
        require(os.name == "posix", "cache_platform_unproven")
        import fcntl
        identifier(namespace)
        directory = Path(directory)
        require(directory.is_absolute(), "cache_absolute_path")
        directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        require(directory == directory.resolve(strict=True), "cache_symlink")
        st = directory.stat()
        require(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) & 0o077 == 0,
                "cache_directory_custody")
        self.root = directory
        self.closed = False
        self.lock = threading.RLock()
        self.fd = os.open(directory / "owner.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            require(stat.S_ISREG(os.fstat(self.fd).st_mode) and os.fstat(self.fd).st_nlink == 1
                    and os.fstat(self.fd).st_uid == os.getuid()
                    and os.fstat(self.fd).st_mode & 0o077 == 0,
                    "cache_lock_custody")
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            db = directory / "delivery.sqlite3"
            created = not db.exists()
            fd = os.open(db, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
                        "cache_file_custody")
            finally:
                os.close(fd)
            self.connection = sqlite3.connect(db, check_same_thread=False)
            if created:
                self.connection.executescript("""
                    CREATE TABLE meta (namespace TEXT NOT NULL);
                    CREATE TABLE operations (identity TEXT PRIMARY KEY, task_digest TEXT NOT NULL, digest TEXT NOT NULL,
                        state TEXT NOT NULL, result_digest TEXT);
                    PRAGMA user_version=1;
                """)
                self.connection.execute("INSERT INTO meta VALUES (?)", (namespace,))
                self.connection.commit()
            require(self.connection.execute("PRAGMA user_version").fetchone()[0] == 1,
                    "cache_schema_version")
            require(self.connection.execute("SELECT namespace FROM meta").fetchall() == [(namespace,)],
                    "cache_namespace_changed")
            self.connection.execute("UPDATE operations SET state='unknown' WHERE state IN ('prepared','running')")
            self.connection.commit()
        except BaseException:
            if hasattr(self, "connection"):
                self.connection.close()
            os.close(self.fd)
            raise

    def reserve(self, identity, task_digest, digest):
        with self.lock, self.connection:
            require(not self.closed, "cache_closed")
            row = self.connection.execute("SELECT digest,state FROM operations WHERE identity=?",
                                          (identity,)).fetchone()
            if row:
                require(row[0] == digest, "operation_identity_conflict")
                raise Rejected("operation_already_recorded_no_replay")
            require(self.connection.execute("SELECT count(*) FROM operations").fetchone()[0] < 1024,
                    "cache_capacity_requires_host_rotation")
            self.connection.execute("INSERT INTO operations VALUES (?,?,?,?,NULL)",
                                    (identity, task_digest, digest, "prepared"))

    def record(self, identity, state, result=None):
        require(state in {"running", "returned", "rejected", "unknown"}, "cache_state")
        result_digest = sha(encode(result)) if result is not None else None
        with self.lock:
            require(not self.closed, "cache_closed")
            with self.connection:
                row = self.connection.execute(
                    "SELECT state,result_digest FROM operations WHERE identity=?", (identity,)
                ).fetchone()
                require(row is not None, "missing_delivery_record")
                previous, prior_digest = row
                if previous == state:
                    require(prior_digest == result_digest, "delivery_result_conflict")
                    return
                allowed = {"prepared": {"running", "returned", "rejected", "unknown"},
                           "running": {"returned", "unknown"}}
                require(state in allowed.get(previous, set()), "terminal_delivery_is_immutable")
                self.connection.execute(
                    "UPDATE operations SET state=?,result_digest=? WHERE identity=?",
                    (state, result_digest, identity))

    def uncertain(self, task_digest):
        with self.lock:
            require(not self.closed, "cache_closed")
            return self.connection.execute(
                "SELECT count(*) FROM operations WHERE task_digest=? AND state='unknown'",
                (task_digest,)).fetchone()[0] > 0

    def close(self):
        with self.lock:
            if not self.closed:
                self.closed = True
                try:
                    self.connection.close()
                finally:
                    os.close(self.fd)



class _Runtime:
    def __init__(self, task, workspace, control):
        self.task, self.workspace, self.control = task, workspace, control
        self.deadline = time.monotonic() + max(0, task.deadline_epoch - time.time())
        self.launch_lock = threading.Lock()
        self.jobs = {}
        self.job_operations = {}
        self.recorded = set()
        self.uncertain = False


class Bridge:
    """Trusted host registration is separate from all model-facing requests.

    The caller authenticates principal before call(). Production embedding must
    supply the genuine SDKInvoker, admitted isolated backend and trusted control
    reader. Test subclasses are not host/SDK conformance evidence.
    """
    def __init__(self, cache: DeliveryCache, backend=None, invoker=None):
        self.cache, self.backend = cache, backend
        self.invoker = invoker if invoker is not None else SDKInvoker()
        require(isinstance(self.invoker, SDKInvoker), "sdk_invoker_required")
        self.tasks = {}
        self._lock = threading.RLock()
        self._dispatch_lock = threading.RLock()
        self._closed = threading.Event()
        self._watcher = threading.Thread(target=self._watch, daemon=True)
        self._watcher.start()

    def register(self, task: Task, workspace, control):
        require(type(task) is Task and callable(control), "host_registration_required")
        with self._lock:
            require(not self._closed.is_set(), "bridge_closed")
            require(not (workspace.root.is_relative_to(self.cache.root)
                         or self.cache.root.is_relative_to(workspace.root)), "workspace_cache_overlap")
            require(all(not (workspace.root.is_relative_to(r.workspace.root)
                             or r.workspace.root.is_relative_to(workspace.root))
                        for r in self.tasks.values()), "workspace_already_owned")
            require(len(self.tasks) < 8 and task.task_id not in self.tasks, "task_capacity_or_duplicate")
            require(all(r.workspace.identity != workspace.identity for r in self.tasks.values()),
                    "workspace_already_owned")
            runtime = _Runtime(task, workspace, control)
            runtime.uncertain = self.cache.uncertain(sha(encode([task.principal, task.task_id])))
            self.tasks[task.task_id] = runtime

    def _runtime(self, principal, args):
        identifier(principal)
        with self._lock:
            runtime = self.tasks.get(args["task_id"])
        require(runtime is not None and runtime.task.principal == principal, "task_not_available")
        require(args["generation"] == runtime.task.generation
                and args["snapshot_id"] == runtime.task.snapshot_id, "request_context_mismatch")
        return runtime

    def _current(self, runtime, effect=False):
        try:
            current = runtime.control()
        except Exception:
            raise Rejected("control_unavailable") from None
        require(type(current) is Control, "control_unavailable")
        require(current.generation == runtime.task.generation
                and current.snapshot_id == runtime.task.snapshot_id, "current_context_changed")
        if effect:
            require(not self._closed.is_set(), "bridge_closed")
            require(not runtime.uncertain, "task_requires_host_reconciliation")
            require(current.state == "ACTIVE" and current.generation == runtime.task.generation
                    and current.snapshot_id == runtime.task.snapshot_id, "owner_control_closed")
            require(time.monotonic() < runtime.deadline, "mission_deadline")
        return current

    def _sync_job(self, runtime, job):
        # The terminal and delivery snapshots are read before any new mutation,
        # not only on a timer. A failed evidence write closes the write plane.
        with self._lock:
            value = job.read(0, 1)
            if value["state"] == "unknown":
                runtime.uncertain = True
            identity = runtime.job_operations.get(job.job_id)
            if (identity is None or job.job_id in runtime.recorded
                    or value["state"] not in {"unknown", "reported_exit"}):
                return
            try:
                self.cache.record(identity, "unknown" if value["state"] == "unknown" else "returned",
                                  {"job_id": job.job_id, "state": value["state"],
                                   "exit_code": value["exit_code"]})
                runtime.recorded.add(job.job_id)
            except Exception:
                runtime.uncertain = True
                try:
                    self.cache.record(identity, "unknown")
                except Exception:
                    pass  # Persistent SDK checkpoint still forbids replay.
                job.stop(wait=False)

    def _watch(self):
        while not self._closed.wait(0.1):
            with self._lock:
                runtimes = list(self.tasks.values())
            for runtime in runtimes:
                try:
                    self._current(runtime, effect=True)
                    revoked = False
                except Exception:
                    revoked = True
                with self._lock:
                    jobs = list(runtime.jobs.values())
                for job in jobs:
                    try:
                        job.tick(revoked=revoked)
                        self._sync_job(runtime, job)
                    except Exception:
                        runtime.uncertain = True
                        job.stop(wait=False)

    def close(self):
        # Close admission immediately, then order the job snapshot after every
        # already-entered sink. No approval callback holds this mutex.
        self._closed.set()
        if not self._dispatch_lock.acquire(timeout=3):
            raise Unknown("shutdown_requires_host_watchdog")
        try:
            with self._lock:
                jobs = [j for r in self.tasks.values() for j in r.jobs.values()]
            for job in jobs:
                job.stop(wait=False)
        finally:
            self._dispatch_lock.release()
        if threading.current_thread() is not self._watcher:
            self._watcher.join(1)
        # Host still owns backend process termination and independent cleanup.

    def _owned_job(self, runtime, args):
        with self._lock:
            job = runtime.jobs.get(args["job_id"])
        require(job is not None, "job_not_available_in_runtime")
        return job

    def _effect(self, runtime, name, args, action):
        self._current(runtime, effect=True)
        task = runtime.task
        admitted_backend = self.backend
        backend_binding = freeze(getattr(admitted_backend, "binding", {"backend": "absent"}))
        descriptor = {
            "protocol": "integrity-execution-bridge/operation/v1", "principal": task.principal,
            "task_id": task.task_id, "generation": task.generation,
            "snapshot_id": task.snapshot_id, "deadline_epoch": task.deadline_epoch,
            "operation_id": args["operation_id"], "tool": name,
            "arguments_sha256": sha(encode(args)), "catalog_sha256": CATALOG_SHA256,
            "workspace_sha256": sha(encode([str(runtime.workspace.root), *runtime.workspace.identity])),
            "backend_sha256": sha(encode(backend_binding)),
        }
        identity = sha(encode([task.principal, task.task_id, args["operation_id"]]))
        self.cache.reserve(identity, sha(encode([task.principal, task.task_id])), sha(encode(descriptor)))
        dispatched = False
        invocation_open = True
        invocation_thread = threading.get_ident()

        def guarded():
            nonlocal dispatched
            with self._dispatch_lock:
                require(invocation_open and not dispatched and threading.get_ident() == invocation_thread,
                        "dispatch_callback_not_available")
                self._current(runtime, effect=True)
                require(self.backend is admitted_backend and
                        freeze(getattr(self.backend, "binding", {"backend": "absent"})) == backend_binding,
                        "backend_binding_changed")
                runtime.workspace.directory(".")
                self.cache.record(identity, "running")
                dispatched = True
                return action()
        try:
            result = self.invoker.invoke(freeze(descriptor), guarded)
            require(dispatched, "invoker_did_not_dispatch")
            if name == "command_start":
                with self._lock:
                    runtime.job_operations[result["job_id"]] = identity
            else:
                self.cache.record(identity, "returned", result)
            return result
        except BaseException:
            if dispatched:
                runtime.uncertain = True
            try:
                self.cache.record(identity, "unknown" if dispatched else "rejected")
            except Exception:
                runtime.uncertain = True
            raise
        finally:
            invocation_open = False

    def call(self, principal, name, arguments):
        identifier(principal)
        args = freeze(arguments)
        validate(name, args)
        for key in ("task_id", "snapshot_id", "operation_id", "job_id"):
            if key in args:
                identifier(args[key])
        require(not self._closed.is_set(), "bridge_closed")
        if name == "bridge_info":
            return {"name": "integrity-execution-bridge", "version": __version__,
                    "catalog_sha256": CATALOG_SHA256, "model_calls": 0,
                    "backend_configured": self.backend is not None,
                    "execution_authority": "existing-sdk-only", "independent_acceptance": False}
        runtime = self._runtime(principal, args)
        if name == "command_stop":
            job = self._owned_job(runtime, args)
            job.stop(wait=False)
            return {"job_id": job.job_id, "stop_requested": True,
                    "termination_confirmed": job.state == "reported_exit",
                    "independent_acceptance": False}
        current = self._current(runtime)
        require(current.read_allowed, "workspace_read_admission_closed")
        if name in {"workspace_read", "command_read"}:
            if name == "workspace_read":
                value = runtime.workspace.read(args["path"], args.get("offset", 0), args.get("limit", 8192))
            else:
                job = self._owned_job(runtime, args)
                self._sync_job(runtime, job)
                value = job.read(args["after"], args["max_bytes"])
            require(self._current(runtime).read_allowed, "workspace_read_admission_closed")
            require(not self._closed.is_set(), "bridge_closed")
            return value
        if name == "command_write":
            job = self._owned_job(runtime, args)
            require(job.admission_lock.acquire(blocking=False), "stdin_busy")
            try:
                return self._effect(runtime, name, args, lambda: {
                    "job_id": job.job_id, "stdin_ack": job.write(args["text"].encode(), args["close_stdin"]),
                    "independent_acceptance": False})
            finally:
                job.admission_lock.release()
        # Single mutable workspace owner; independent reads/stop bypass this lock.
        require(runtime.launch_lock.acquire(blocking=False), "workspace_busy")
        try:
            with self._lock:
                for job in runtime.jobs.values():
                    self._sync_job(runtime, job)
                require(not any(j.state != "reported_exit" for j in runtime.jobs.values()),
                        "workspace_job_unreconciled")
            if name == "workspace_replace":
                return self._effect(runtime, name, args, lambda: runtime.workspace.replace(
                    args["path"], args["expected_sha256"], args["old"], args["new"], args["expected_count"]))
            if name == "command_start":
                require(self.backend is not None, "backend_unavailable")
                require(all("\x00" not in part for part in args["argv"]) and args["argv"][0],
                        "invalid_argv")
                require(Path(args["argv"][0]).is_absolute(), "absolute_executable_required")
                cwd = runtime.workspace.directory(args["cwd"])
                job_id = "job-" + sha(encode([principal, runtime.task.task_id, args["operation_id"]]))[:48]
                deadline = min(runtime.deadline, time.monotonic() + args["timeout_ms"] / 1000)
                with self._lock:
                    require(len(runtime.jobs) < 128, "job_capacity")

                def launch():
                    require(time.monotonic() < deadline, "command_deadline")
                    require(runtime.workspace.directory(args["cwd"]) == cwd, "cwd_changed_during_admission")
                    job = self.backend.start(job_id=job_id, argv=tuple(args["argv"]), cwd=cwd, deadline=deadline)
                    with self._lock:
                        runtime.jobs[job_id] = job
                    return {"job_id": job_id, "state": "submitted", "independent_acceptance": False,
                            "replay_allowed": False}
                return self._effect(runtime, name, args, launch)
            raise Rejected("unknown_tool")
        except (OSError, UnicodeError):
            raise Unknown("filesystem_or_dispatch_unknown") from None
        finally:
            runtime.launch_lock.release()
