"""Host coordinator (outside the Job): authenticates the in-Job relay, mediates every call.

Peer acceptance requires ALL of: the connecting process is a live member of this run's
Job, its image is the pinned relay interpreter, and it presents the per-run nonce and
run id. Anything else is counted as a foreign peer and gets no effect. Calls are
processed one at a time on this coordinator's own thread (which is also the owning
thread of the tool ``SdkAuthority``). A consumed permit with an unknown outcome, a
call that overran its deadline, or a stop while a call is in flight marks the run
UNKNOWN: the run is cancelled and the session blocked; nothing is retried.
"""
from __future__ import annotations

import ctypes
import hmac
import json
import os
import secrets
import threading
import time
from ctypes import wintypes
from pathlib import Path
from typing import Callable

from . import _winabi as abi
from .authority import FILE_CHANNEL, AuthoritySpent, SdkAuthority, StopToken
from .canonical import Rejected, Unknown, need, sha256_bytes
from .identity import executable_identity, require_plain_path
from .pipe import PipeServer
from .policy import CATALOG, SERVER, ExecutorPolicy
from .sinks import EFFECT_SCHEMA, Workspace, effect_descriptor

_ACCEPT_ATTEMPTS = 4


def _image_path(k, handle) -> str | None:
    buffer, size = ctypes.create_unicode_buffer(32768), wintypes.DWORD(32768)
    if not k.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
        return None
    return os.path.normcase(buffer.value)


class Coordinator:
    def __init__(self, *, authority: SdkAuthority, policy: ExecutorPolicy, workspace: Path,
                 run_sha256: str, session_id: str, run_id: str, config_path: Path,
                 relay_python: Path, relay_script: Path, on_unknown: Callable[[], None]):
        need(type(authority) is SdkAuthority, "authority_type")
        need(isinstance(policy, ExecutorPolicy), "policy_type")
        self.authority, self.policy = authority, policy
        self.workspace_root = Path(workspace)
        self.run_sha256, self.session_id, self.run_id = run_sha256, session_id, run_id
        self.config_path = require_plain_path(Path(config_path), "relay_config")
        python = executable_identity(Path(relay_python))
        need(python["sha256"] == policy.relay_python_sha256, "relay_python_digest")
        script = require_plain_path(Path(relay_script), "relay_script")
        need(sha256_bytes(script.read_bytes()) == policy.relay_script_sha256, "relay_script_digest")
        self.relay_python, self.relay_script = Path(python["path"]), script
        self.on_unknown = on_unknown
        self.nonce = secrets.token_hex(32)   # never logged; lives in the owner-dir config only
        self.stats = {"calls": 0, "effects": 0, "denied": 0, "unknown": 0, "foreign_peers": 0}
        # Content-free receipts of applied writes (path + digests), for the observer only.
        self.effects: list[dict] = []
        self.unknown = threading.Event()
        self.failure: str | None = None
        self._in_flight = False
        self._peer_check: Callable[[object], bool] | None = None
        self._peer = None             # ONE live process handle for Job + image + hello
        self.token = StopToken()      # persistent: once stopped, no new effect can begin
        self._thread: threading.Thread | None = None
        self._sequence = 0
        self.pipe = PipeServer()

    def write_config(self) -> None:
        """Owner-dir MCP config naming only the relay (strict single server)."""
        self.config_path.parent.mkdir(parents=False, exist_ok=False)
        document = {"mcpServers": {SERVER: {
            "type": "stdio", "command": str(self.relay_python),
            "args": ["-I", "-S", "-B", str(self.relay_script)],
            "env": {"INTEGRITY_RELAY_PIPE": self.pipe.name, "INTEGRITY_RELAY_NONCE": self.nonce,
                    "INTEGRITY_RELAY_RUN": self.run_id,
                    "INTEGRITY_RELAY_TIMEOUT": str(self.policy.tool_timeout_seconds)}}}}
        with open(self.config_path, "x", encoding="utf-8") as handle:
            json.dump(document, handle)

    def start(self, peer_check: Callable[[object], bool]) -> None:
        self._peer_check = peer_check
        self._thread = threading.Thread(target=self._serve, daemon=True,
                                        name="integrity-claude-coordinator")
        self._thread.start()

    # -- serving (single owning thread) ---------------------------------------------
    def _authentic(self, pid: int) -> bool:
        """Open the peer ONCE and check Job membership and image on that same handle."""
        self._drop_peer()
        k = abi.load()
        handle = k.OpenProcess(abi.SYNCHRONIZE | abi.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        self._peer = handle
        return bool(k.GetProcessId(handle) == pid and self._peer_check
                    and self._peer_check(handle)
                    and k.WaitForSingleObject(handle, 0) == abi.WAIT_TIMEOUT
                    and _image_path(k, handle) == os.path.normcase(str(self.relay_python)))

    def _drop_peer(self) -> None:
        if self._peer:
            abi.load().CloseHandle(self._peer)
            self._peer = None

    def _serve(self) -> None:
        self.pipe.bind_current_thread()
        try:
            workspace = Workspace(self.workspace_root, self.policy)
            for _ in range(_ACCEPT_ATTEMPTS):
                pid = self.pipe.accept()
                if self._authentic(pid) and self._hello():
                    break
                self.stats["foreign_peers"] += 1
                self.pipe.drop_client()
            else:
                return
            while True:
                self._call(workspace, self.pipe.read_frame())
        except Rejected:
            pass  # pipe closed or cancelled: the relay is gone
        except BaseException:
            self.failure = "coordinator_failure"
        finally:
            if self._in_flight:
                self._mark_unknown()
            self._drop_peer()

    def _hello(self) -> bool:
        try:
            frame = self.pipe.read_frame()
        except Rejected:
            return False
        nonce = frame.get("nonce")
        if not (frame.get("type") == "hello" and type(nonce) is str
                and hmac.compare_digest(nonce.encode(), self.nonce.encode())
                and frame.get("run_id") == self.run_id):
            return False
        self.pipe.write_frame({"type": "hello_ok"})
        return True

    def _respond(self, seq, ok: bool, text: str) -> None:
        self.pipe.write_frame({"type": "result", "seq": seq, "ok": ok, "text": text})

    def _mark_unknown(self) -> None:
        self.stats["unknown"] += 1
        if not self.unknown.is_set():
            self.unknown.set()
            try:
                self.on_unknown()
            except Exception:
                pass

    def _call(self, workspace: Workspace, frame: dict) -> None:
        seq, tool = frame.get("seq"), frame.get("tool")
        self._sequence += 1
        need(frame.get("type") == "call" and seq == self._sequence, "call_frame")
        self.stats["calls"] += 1
        if self.unknown.is_set() or self.stats["calls"] > self.policy.max_tool_calls \
                or tool not in CATALOG:
            self.stats["denied"] += 1
            return self._respond(seq, False, "denied: unavailable")
        started = time.monotonic()
        try:
            prepared = workspace.prepare(tool, frame.get("arguments"))
        except Rejected as exc:
            self.stats["denied"] += 1
            return self._respond(seq, False, "denied: " + exc.code)
        document = effect_descriptor(run_sha256=self.run_sha256, session_id=self.session_id,
                                     run_id=self.run_id, sequence=seq,
                                     arguments=frame.get("arguments"), fields=prepared.fields,
                                     policy_sha256=self.policy.digest())
        self._in_flight = True
        try:
            outcome = self.authority.execute(schema_id=EFFECT_SCHEMA["schema_id"],
                                             schema=EFFECT_SCHEMA, document=document,
                                             channel=FILE_CHANNEL, effect=prepared.commit,
                                             stop=self.token,
                                             deadline=started + self.policy.tool_timeout_seconds)
        except (Rejected, AuthoritySpent) as exc:
            self._in_flight = False
            self.stats["denied"] += 1
            return self._respond(seq, False, "denied: " + exc.code)
        except Unknown:
            self._in_flight = False
            self._mark_unknown()
            return self._respond(seq, False, "outcome unknown; run stopping")
        finally:
            prepared.close()
        self._in_flight = False
        if time.monotonic() - started > self.policy.tool_timeout_seconds:
            self._mark_unknown()  # the relay already gave up: model and host views diverged
            return self._respond(seq, False, "outcome unknown; run stopping")
        self.stats["effects"] += 1
        fields = prepared.fields
        if fields["effect_class"] == "write" and outcome.reported_outcome == "reported-success":
            self.effects.append({"tool": fields["tool"], "path": fields["path"],
                                 "pre_sha256": fields["pre_sha256"],
                                 "post_sha256": fields["content_sha256"]})
        self._respond(seq, outcome.reported_outcome == "reported-success", outcome.value)

    def stop(self, budget_seconds: float) -> None:
        """Bounded stop. After ``token.stop()`` no new effect can begin; an effect already
        running, or a worker still alive at the end of the budget, makes the run UNKNOWN."""
        if self.token.stop():
            self._mark_unknown()
        self.pipe.cancel()
        if self._thread is not None:
            self._thread.join(max(0.0, budget_seconds))
            if self._thread.is_alive():
                self.failure = "coordinator_failure"
                self._mark_unknown()
        self.pipe.close()
        try:
            os.unlink(self.config_path)  # the nonce does not outlive the run
        except OSError:
            pass
