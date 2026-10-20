#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Short-lived Native terminal observer and one-use DATA reply to the sender.

Launched by the owning Stop hook after that hook returns. This module never
executes the delegated task, issues a Memory reference or certifies its effect.
Claim tokens remain inside the already protected operation database/process.
"""

from __future__ import annotations

from integrity_client_memory.configuration import value as _integrity_value, require_config as _integrity_require_config

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

PROTOCOL = "integrity/delegation-terminal-worker/v1"
RESULT_PROTOCOL = "integrity/delegated-task-result/v1"
MAX_FINAL_TEXT = 20000
TERMINAL = {"completed", "failed", "interrupted", "cancelled"}
MAPPED_STATUS = {"completed": "completed", "failed": "failed", "interrupted": "unknown", "cancelled": "unknown"}


class TerminalError(ValueError):
    """Safe public code only; never echo Native text or credentials."""


def need(condition, code):
    if not condition:
        raise TerminalError(code)


class TerminalStore:
    """Observer lease and return reservation in the original protected ledger."""

    def __init__(self, core, ledger_path):
        self.core = core
        self.ledger = core.Ledger(ledger_path)
        with self.ledger._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS delegation_terminal_workers (operation_id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, turn_id TEXT NOT NULL, lease_token TEXT NOT NULL, lease_expires INTEGER NOT NULL, state TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS delegation_result_returns (operation_id TEXT PRIMARY KEY, body_digest TEXT NOT NULL, state TEXT NOT NULL, ack_digest TEXT)")

    def _owned_row(self, db, operation_id, thread_id, turn_id):
        row = db.execute("SELECT * FROM delegation_operations WHERE operation_id=?", (operation_id,)).fetchone()
        need(row is not None and row["state"] in {"executing", "completed", "failed", "unknown"}, "owned_operation_missing")
        delivery = json.loads(row["delivery_json"] or "null")
        need(isinstance(delivery, dict) and delivery.get("target_thread_id") == thread_id
             and delivery.get("receiving_turn_id") == turn_id, "owned_receiving_binding_mismatch")
        request = json.loads(row["request_json"])
        need(self.core.digest(request) == row["request_digest"]
             and delivery.get("request_digest") == row["request_digest"], "owned_request_binding_mismatch")
        return row, request, delivery

    def reserve_worker(self, operation_id, thread_id, turn_id, *, now, duration):
        need(type(now) is int and 0 < duration <= 150, "worker_clock_invalid")
        with self.ledger._db() as db:
            self._owned_row(db, operation_id, thread_id, turn_id)
            row = db.execute("SELECT * FROM delegation_terminal_workers WHERE operation_id=?", (operation_id,)).fetchone()
            if row is not None:
                need(row["thread_id"] == thread_id and row["turn_id"] == turn_id, "worker_binding_collision")
                if row["state"] == "done" or row["state"] == "running" and row["lease_expires"] > now:
                    return None
            lease = secrets.token_urlsafe(32)
            db.execute("INSERT OR REPLACE INTO delegation_terminal_workers VALUES (?,?,?,?,?,?)",
                       (operation_id, thread_id, turn_id, lease, now + duration + 2, "running"))
            return lease

    def check_worker(self, operation_id, lease, *, now):
        with self.ledger._db() as db:
            row = db.execute("SELECT * FROM delegation_terminal_workers WHERE operation_id=?", (operation_id,)).fetchone()
            need(row is not None and row["state"] == "running" and row["lease_expires"] > now
                 and secrets.compare_digest(row["lease_token"], lease), "worker_lease_not_owned")

    def release_worker(self, operation_id, lease, *, state):
        with self.ledger._db() as db:
            row = db.execute("SELECT * FROM delegation_terminal_workers WHERE operation_id=?", (operation_id,)).fetchone()
            if row is not None and secrets.compare_digest(row["lease_token"], lease):
                db.execute("UPDATE delegation_terminal_workers SET state=? WHERE operation_id=?", (state, operation_id))

    def request(self, operation_id, thread_id, turn_id):
        with self.ledger._db() as db:
            _, request, _ = self._owned_row(db, operation_id, thread_id, turn_id)
            return request

    def finish_observed(self, operation_id, thread_id, turn_id, result, *, now):
        """Finish using the stored owned claim, without returning its token."""
        need(result.get("native_thread_id") == thread_id and result.get("native_turn_id") == turn_id
             and result.get("native_turn_status") in TERMINAL
             and result.get("action_status") == "reported-result-requires-independent-effect-verification", "terminal_observation_invalid")
        expected_digest = result.get("result_digest")
        need(expected_digest == self.core.digest({k: v for k, v in result.items() if k != "result_digest"}), "terminal_result_digest_mismatch")
        with self.ledger._db() as db:
            row, _, delivery = self._owned_row(db, operation_id, thread_id, turn_id)
            need(result.get("receiving_item_id") == delivery.get("receiving_item_id"), "terminal_receiving_item_mismatch")
            if row["state"] in {"completed", "failed", "unknown"}:
                prior = json.loads(row["result_json"] or "null")
                need(prior == result and row["state"] == MAPPED_STATUS[result["native_turn_status"]], "terminal_result_conflict")
                return self.ledger._public(row)
            token = row["claim_token"]
            need(isinstance(token, str) and bool(token), "owned_claim_missing")
            need(token not in self.core.canonical_json(result), "terminal_result_contains_private_claim")
        # Only this process-local variable ever contains the original claim.
        return self.ledger.finish(operation_id, token, status=MAPPED_STATUS[result["native_turn_status"]], result=result, now=now)

    def reserve_return(self, operation_id, body):
        body_digest = self.core.text_digest(body)
        with self.ledger._db() as db:
            row = db.execute("SELECT * FROM delegation_result_returns WHERE operation_id=?", (operation_id,)).fetchone()
            if row is not None:
                need(row["body_digest"] == body_digest, "return_body_conflict")
                return False
            db.execute("INSERT INTO delegation_result_returns VALUES (?,?,?,NULL)", (operation_id, body_digest, "reserved"))
            return True

    def finish_return(self, operation_id, *, state, acknowledgement=None):
        need(state in {"acknowledged", "unknown"}, "return_state_invalid")
        with self.ledger._db() as db:
            row = db.execute("SELECT * FROM delegation_result_returns WHERE operation_id=?", (operation_id,)).fetchone()
            need(row is not None and row["state"] == "reserved", "return_not_reserved")
            ack_digest = None if acknowledgement is None else self.core.digest(acknowledgement)
            db.execute("UPDATE delegation_result_returns SET state=?,ack_digest=? WHERE operation_id=?", (state, ack_digest, operation_id))


def native_result(page, *, operation_id, thread_id, turn_id, delivery, adapter, core):
    adapter.check_page(page, thread_id, "local")
    turns = [turn for turn in page["turns"] if isinstance(turn, dict) and turn.get("id") == turn_id]
    need(len(turns) == 1, "terminal_turn_not_observed")
    turn = turns[0]
    status = turn.get("status")
    need(status in TERMINAL | {"inProgress"}, "terminal_turn_status_invalid")
    if status == "inProgress":
        return None
    finals = [item for item in turn.get("items", []) if isinstance(item, dict)
              and item.get("type") == "agentMessage" and item.get("phase") == "final_answer"]
    need(len(finals) <= 1 and (status != "completed" or len(finals) == 1), "native_final_answer_not_observed")
    text = ""
    item_id = None
    truncated = False
    if finals:
        final = finals[0]
        item_id = adapter.identity(final.get("id"), "native_final_item_invalid")
        need(final.get("truncated", False) is False and isinstance(final.get("text"), str), "native_final_answer_invalid")
        text = final["text"]
        truncated = len(text) >= MAX_FINAL_TEXT
        text = text[:MAX_FINAL_TEXT]
    result = {"protocol": "integrity/delegation-native-terminal-evidence/v1", "operation_id": operation_id,
              "native_host_id": "local", "native_thread_id": thread_id, "native_turn_id": turn_id,
              "native_final_item_id": item_id, "receiving_item_id": delivery["receiving_item_id"],
              "native_turn_status": status, "action_status": "reported-result-requires-independent-effect-verification",
              "final_text": text, "final_text_truncated": truncated, "independent_effect_verified": False}
    result["result_digest"] = core.digest(result)
    return result


def _proof(reader, adapter, core, config, operation_id, thread_id, turn_id):
    proof = adapter.handle("Stop", {"session_id": thread_id, "turn_id": turn_id}, config, core, reader, operation_id=operation_id)
    need(proof.get("status") in {"current", "duplicate"} and proof.get("operation_id") == operation_id, "terminal_provenance_not_current")
    return proof


def reconcile(config, operation_id, thread_id, turn_id, *, core, adapter, reader_factory,
              deadline_seconds=150, sleep=time.sleep, monotonic=time.monotonic, wall_clock=time.time):
    """Observe once, then changes; stop at terminal, deadline or 3 unchanged."""
    need(type(deadline_seconds) is int and 1 <= deadline_seconds <= 150, "terminal_deadline_invalid")
    adapter.validate_config(config)
    adapter.identity(operation_id, "operation_id_invalid")
    adapter.identity(thread_id, "thread_id_invalid")
    adapter.identity(turn_id, "turn_id_invalid")
    store = TerminalStore(core, config["ledger_path"])
    now = lambda: int(wall_clock())
    lease = store.reserve_worker(operation_id, thread_id, turn_id, now=now(), duration=deadline_seconds)
    if lease is None:
        return {"protocol": PROTOCOL, "status": "already-observed-or-running", "operation_id": operation_id, "return_sent": False}
    limit = monotonic() + deadline_seconds
    samples = 0
    unchanged = 0
    last = None
    final_state = "waiting"
    try:
        while monotonic() < limit:
            store.check_worker(operation_id, lease, now=now())
            reader = reader_factory(min(limit, monotonic() + adapter.NATIVE_DEADLINE))
            _proof(reader, adapter, core, config, operation_id, thread_id, turn_id)
            state = store.ledger.status(operation_id)
            page = reader.read(thread_id, "local", limit=3, outputs=True)
            observed = native_result(page, operation_id=operation_id, thread_id=thread_id, turn_id=turn_id,
                                     delivery=state["delivery"], adapter=adapter, core=core)
            samples += 1
            if observed is not None:
                store.check_worker(operation_id, lease, now=now())
                completed = store.finish_observed(operation_id, thread_id, turn_id, observed, now=now())
                # Read original owner/source/control state again before reply.
                reply_reader = reader_factory(min(limit, monotonic() + adapter.NATIVE_DEADLINE))
                _proof(reply_reader, adapter, core, config, operation_id, thread_id, turn_id)
                store.check_worker(operation_id, lease, now=now())
                request = store.request(operation_id, thread_id, turn_id)
                need(request["reply_thread_id"] == config["source_thread_id"], "return_target_mismatch")
                body = core.canonical_json({"protocol": RESULT_PROTOCOL, "operation_id": operation_id,
                                            "request_digest": completed["request_digest"], "status": completed["state"],
                                            "receiver": {"host_id": config["target_machine_id"], "thread_id": thread_id, "turn_id": turn_id},
                                            "result": observed, "result_digest": observed["result_digest"]})
                if not store.reserve_return(operation_id, body):
                    final_state = "done"
                    return {"protocol": PROTOCOL, "status": completed["state"], "operation_id": operation_id,
                            "samples": samples, "return_sent": False, "return_duplicate": True,
                            "result_digest": observed["result_digest"], "independent_effect_verified": False}
                try:
                    ack = reply_reader.bridge._host_tool_json(reply_reader.host, "send_message_to_thread",
                        {"threadId": request["reply_thread_id"], "hostId": config["source_host_id"], "prompt": body}, thread_id)
                    need(isinstance(ack, dict) and ack.get("threadId") == request["reply_thread_id"], "return_target_ack_unobserved")
                    store.finish_return(operation_id, state="acknowledged", acknowledgement=ack)
                except Exception:
                    store.finish_return(operation_id, state="unknown")
                    final_state = "done"
                    return {"protocol": PROTOCOL, "status": completed["state"], "operation_id": operation_id,
                            "samples": samples, "return_sent": True, "return_outcome": "unknown-no-resend",
                            "result_digest": observed["result_digest"], "independent_effect_verified": False}
                final_state = "done"
                return {"protocol": PROTOCOL, "status": completed["state"], "operation_id": operation_id,
                        "samples": samples, "return_sent": True, "return_outcome": "acknowledged_native_target",
                        "result_digest": observed["result_digest"], "delivery_confirmed": False,
                        "independent_effect_verified": False}
            actual_turn = next(turn for turn in page["turns"] if isinstance(turn, dict) and turn.get("id") == turn_id)
            fingerprint = core.digest(actual_turn)
            unchanged = unchanged + 1 if fingerprint == last else 1
            last = fingerprint
            if unchanged >= 3:
                return {"protocol": PROTOCOL, "status": "waiting-unchanged", "operation_id": operation_id, "samples": samples, "return_sent": False}
            remaining = limit - monotonic()
            if remaining <= 0:
                break
            sleep(min(5.0, remaining))
        return {"protocol": PROTOCOL, "status": "waiting-deadline", "operation_id": operation_id, "samples": samples, "return_sent": False}
    finally:
        store.release_worker(operation_id, lease, state=final_state)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--thread-id", required=True)
    parser.add_argument("--turn-id", required=True)
    parser.add_argument("--deadline", type=int, default=150)
    parser.add_argument("--deadline60", action="store_true")
    parser.add_argument("--detach", action="store_true")
    args = parser.parse_args(argv)
    if args.detach:
        return launch_detached(args)
    # Loader is adjacent installed adapter; pin its bytes before executing it.
    import importlib.util
    safe_config = None
    started = time.monotonic()
    try:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        adapter_path = Path(config["adapter_path"])
        raw = adapter_path.read_bytes()
        need(adapter_path.is_absolute() and hashlib.sha256(raw).hexdigest() == config["adapter_sha256"], "terminal_adapter_pin_mismatch")
        spec = importlib.util.spec_from_file_location("integrity_delegation_terminal_adapter", adapter_path)
        need(spec is not None, "terminal_adapter_invalid")
        adapter = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = adapter
        exec(compile(raw, str(adapter_path), "exec"), adapter.__dict__)
        config = adapter.validate_config(config)
        safe_config = config
        core = adapter.load_pinned(config["core_path"], config["core_sha256"], "integrity_delegation_terminal_core")
        bridge = adapter.load_pinned(config["bridge_path"], config["bridge_sha256"], "integrity_delegation_terminal_bridge")
        write_outcome_receipt(config, operation_id=args.operation_id, thread_id=args.thread_id,
                              turn_id=args.turn_id, result={"status": "worker-started"},
                              elapsed=time.monotonic() - started)
        result = reconcile(config, args.operation_id, args.thread_id, args.turn_id, core=core, adapter=adapter,
                           reader_factory=lambda deadline: adapter.NativeReader(bridge, args.thread_id, deadline=deadline),
                           deadline_seconds=60 if args.deadline60 else args.deadline)
    except Exception:
        # Background worker output contains only an infrastructure code.
        result = {"protocol": PROTOCOL, "status": "observer-unavailable", "code": "terminal_reconciliation_unavailable"}
    if safe_config is not None:
        try:
            write_outcome_receipt(safe_config, operation_id=args.operation_id, thread_id=args.thread_id,
                                  turn_id=args.turn_id, result=result, elapsed=time.monotonic() - started)
        except Exception:
            # Receipt failure cannot cause another return send or hide its
            # existing durable reservation. The ledger remains the witness.
            result["outcome_receipt"] = "unavailable"
    if sys.stdout is not None:
        sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    return 0 if result.get("status") != "observer-unavailable" else 2


def launch_detached(args):
    """Windows Stop children must survive the hook runner's job teardown.

    Breakaway failure is a launch failure, never an inherited-job fallback.
    The worker still validates its pinned modules and exact receiving binding.
    """
    need(os.name == "nt", "terminal_detach_windows_only")
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    need(pythonw.is_file(), "terminal_pythonw_missing")
    command = [str(pythonw), "-X", "utf8", str(Path(__file__).resolve()),
               "--config", args.config, "--operation-id", args.operation_id,
               "--thread-id", args.thread_id, "--turn-id", args.turn_id,
               "--deadline", str(60 if args.deadline60 else args.deadline)]
    try:
        subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, close_fds=True,
                         creationflags=(subprocess.DETACHED_PROCESS |
                                        subprocess.CREATE_NEW_PROCESS_GROUP |
                                        subprocess.CREATE_BREAKAWAY_FROM_JOB))
    except OSError:
        raise TerminalError("terminal_detached_spawn_failed") from None
    return 0


def write_outcome_receipt(config, *, operation_id, thread_id, turn_id, result, elapsed):
    """Save only bounded content-free worker metadata beside its private DB."""
    ledger = Path(config["ledger_path"])
    need(ledger.is_absolute(), "receipt_ledger_path_invalid")
    parent = ledger.parent.resolve(strict=True)
    root = parent / "terminal-receipts"
    if root.exists():
        info = root.lstat()
        need(root.is_dir() and not root.is_symlink() and not getattr(info, "st_file_attributes", 0) & 0x400, "receipt_root_not_plain")
    else:
        root.mkdir()
    need(root.resolve(strict=True).parent == parent, "receipt_root_outside_ledger")
    sha = lambda text: hashlib.sha256(text.encode("utf-8")).hexdigest()
    payload = {"protocol": "integrity/delegation-terminal-worker-outcome/v1",
               "operation_id_sha256": sha(operation_id), "thread_id_sha256": sha(thread_id), "turn_id_sha256": sha(turn_id),
               "worker_pid": os.getpid(), "observed_at": int(time.time()), "elapsed_seconds": round(max(0.0, elapsed), 3)}
    for field in ("status", "code", "samples", "return_sent", "return_outcome", "return_duplicate", "result_digest", "delivery_confirmed", "independent_effect_verified"):
        if field in result:
            value = result[field]
            need(isinstance(value, (str, bool, int)) and (not isinstance(value, str) or len(value) <= 128), "receipt_metadata_invalid")
            payload[field] = value
    path = root / (sha(operation_id) + ".json")
    if path.exists():
        info = path.lstat()
        need(path.is_file() and not path.is_symlink() and not getattr(info, "st_file_attributes", 0) & 0x400, "receipt_file_not_plain")
    temporary = root / (sha(operation_id) + "." + secrets.token_hex(8) + ".tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return path


if __name__ == "__main__":
    _integrity_require_config()

if __name__ == "__main__":
    raise SystemExit(main())
