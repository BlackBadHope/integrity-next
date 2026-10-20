"""Private same-session recovery; no admission, turn creation or event replay.

The compact signed registry is derived state, separate from the evictable Seed
copy. The existing replay catalog remains the only exact-snapshot provider.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import time
from copy import deepcopy
from contextlib import contextmanager
from pathlib import Path

from .canonical import canonical_bytes
from .signing import TrustedKey, verify_trusted_signature

RECOVERY_PROTOCOL = "integrity-client/session-recovery/v1"
RECOVERY_CAPABILITY = "integrity/session-recovery"
RECOVERY_METHOD = "integrity/session_recover"
CONTROL_FIELDS = frozenset({"replay_id", "request_digest", "response_digest",
    "context_admission_id", "snapshot_id", "prompt_binding", "logical_generation"})
MAX_RETENTION = 86400
MAX_RECORDS = 128
MAX_BYTES = 2097152
MAX_CAPSULE_BYTES = 16384
MAX_DATABASE_BYTES = 4194304


class SessionRecoveryError(ValueError):
    pass


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def digest(value):
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def replay_json_digest(value):
    """Hash retained read-model JSON with its existing on-disk encoding.

    Replay state can contain finite read-model scores. It is persisted using
    the facade's JSON profile, not the float-free Guardian signature profile.
    Only state/snapshot commitments use this helper; signed capsule fields,
    registrations and signatures keep the strict ``digest`` contract. Old
    float-free commitments remain byte-identical. Non-finite values still fail.
    """
    from .memory_synapse_mcp import _sha256
    return _sha256(value)


def _epoch(value):
    import datetime
    parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise SessionRecoveryError("recovery expiry must be aware")
    return int(parsed.timestamp())


def _controls(value):
    if not isinstance(value, dict) or set(value) != CONTROL_FIELDS:
        raise SessionRecoveryError("recovery control fields mismatch")
    for key in CONTROL_FIELDS - {"prompt_binding", "logical_generation"}:
        if not isinstance(value[key], str) or re.fullmatch(r"sha256:[a-f0-9]{64}", value[key]) is None:
            raise SessionRecoveryError("recovery digest invalid")
    if type(value["logical_generation"]) is not int or value["logical_generation"] < 1:
        raise SessionRecoveryError("recovery generation invalid")
    if not isinstance(value["prompt_binding"], dict):
        raise SessionRecoveryError("recovery prompt binding invalid")
    return deepcopy(value)


class RecoveryRegistry:
    """Signed immutable capsules + transactional current-owner head/tombstone.

    An older idempotent open never moves a head backwards. Expired heads remain
    for a full retention window, even if their shorter native lease has expired.
    All reads fail closed on a malformed or missing registry; recovery cannot
    bootstrap a missing database. The caller supplies a verified signing role.
    """
    def __init__(self, path, *, signer, namespace, create=False, clock=None):
        self.path = Path(path)
        self.signer = signer
        self.trusted = TrustedKey(signer.key_id, signer.public_key)
        self.namespace = namespace
        self.clock = clock or time.time
        if not self.path.is_absolute() or self.path.parent.is_symlink():
            raise SessionRecoveryError("recovery registry path invalid")
        parent = self.path.parent.stat()
        if not stat.S_ISDIR(parent.st_mode) or (os.name != "nt" and
                (parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o077)):
            raise SessionRecoveryError("recovery registry parent custody invalid")
        if create:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
                with self._connect(write=True) as con:
                    con.executescript("CREATE TABLE meta(namespace TEXT PRIMARY KEY, key_id TEXT NOT NULL);"
                        "CREATE TABLE capsules(registration TEXT PRIMARY KEY, slot TEXT NOT NULL, expires INTEGER NOT NULL,"
                        "retention INTEGER NOT NULL, revoked INTEGER NOT NULL, payload BLOB NOT NULL);"
                        "CREATE TABLE heads(slot TEXT PRIMARY KEY, registration TEXT NOT NULL, retention INTEGER NOT NULL);")
                    con.execute("INSERT INTO meta VALUES(?,?)", (namespace, signer.key_id))
        with self._connect() as con:
            if con.execute("SELECT namespace,key_id FROM meta").fetchall() != [(namespace, signer.key_id)]:
                raise SessionRecoveryError("recovery registry signer/namespace mismatch")

    def _connect(self, *, write=False):
        before = self.path.lstat()
        if self.path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_DATABASE_BYTES or (os.name != "nt" and
                (before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600)):
            raise SessionRecoveryError("recovery registry custody invalid")
        con = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=2,
            isolation_level=None, factory=_ClosingConnection)
        con.execute("PRAGMA trusted_schema=OFF")
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA busy_timeout=2000")
        if con.execute("PRAGMA page_size").fetchone() != (4096,):
            con.close()
            raise SessionRecoveryError("recovery database page bound invalid")
        if write:
            if con.execute("PRAGMA max_page_count=1024").fetchone() != (1024,):
                con.close()
                raise SessionRecoveryError("recovery physical quota unavailable")
        else:
            con.execute("PRAGMA query_only=ON")
        after = self.path.lstat()
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            con.close()
            raise SessionRecoveryError("recovery registry replaced")
        return con

    def bind(self, core):
        now = int(self.clock())
        if (core.get("protocol") != RECOVERY_PROTOCOL or core.get("namespace_fingerprint") != self.namespace
                or type(core.get("expires_at")) is not int or type(core.get("captured_at")) is not int
                or not now - 5 <= core["captured_at"] <= now
                or not now < core["expires_at"] <= core["captured_at"] + MAX_RETENTION
                or core.get("retention_until") != core["captured_at"] + MAX_RETENTION):
            raise SessionRecoveryError("recovery retention invalid")
        signed = self.signer.sign(core)
        encoded = canonical_bytes(signed)
        if len(encoded) > MAX_CAPSULE_BYTES:
            raise SessionRecoveryError("recovery capsule exceeds quota")
        reg, slot = core["registration_id"], core["slot"]
        con = self._connect(write=True)
        try:
            con.execute("BEGIN IMMEDIATE")
            existing = con.execute("SELECT payload FROM capsules WHERE registration=?", (reg,)).fetchone()
            head = con.execute("SELECT registration FROM heads WHERE slot=?", (slot,)).fetchone()
            if existing is not None:
                previous = self._verified(existing[0])
                # TTL is immutable; only exact repeated binding is accepted.
                ignored = {"captured_at", "expires_at", "retention_until", "signature"}
                if ({k:v for k,v in previous.items() if k not in ignored} != {k:v for k,v in core.items() if k not in ignored}
                        or head != (reg,)):
                    raise SessionRecoveryError("recovery binding collision or superseded turn")
                self.load(reg)
                con.execute("COMMIT")
                return previous
            con.execute("DELETE FROM capsules WHERE retention<=?", (now,))
            con.execute("DELETE FROM heads WHERE retention<=?", (now,))
            count, size = con.execute("SELECT COUNT(*),COALESCE(SUM(LENGTH(payload)),0) FROM capsules").fetchone()
            if count >= MAX_RECORDS or size + len(encoded) > MAX_BYTES:
                raise SessionRecoveryError("recovery registry quota exhausted")
            con.execute("UPDATE capsules SET revoked=1 WHERE slot=?", (slot,))
            con.execute("INSERT INTO capsules VALUES(?,?,?,?,0,?)", (reg, slot, core["expires_at"], core["retention_until"], encoded))
            con.execute("INSERT INTO heads VALUES(?,?,?) ON CONFLICT(slot) DO UPDATE SET registration=excluded.registration,retention=excluded.retention",
                (slot, reg, core["retention_until"]))
            con.execute("COMMIT")
            return signed
        except Exception:
            if con.in_transaction: con.execute("ROLLBACK")
            raise
        finally:
            con.close()

    def _verified(self, encoded):
        if len(encoded) > MAX_CAPSULE_BYTES:
            raise SessionRecoveryError("recovery capsule exceeds bound")
        value = json.loads(encoded)
        if (not isinstance(value, dict) or value.get("protocol") != RECOVERY_PROTOCOL
                or value.get("namespace_fingerprint") != self.namespace or not verify_trusted_signature(value, self.trusted)):
            raise SessionRecoveryError("recovery capsule signature invalid")
        return value

    def load(self, registration):
        con = self._connect()
        try:
            con.execute("BEGIN")
            row = con.execute("SELECT slot,expires,retention,revoked,payload FROM capsules WHERE registration=?", (registration,)).fetchone()
            if row is None: raise SessionRecoveryError("recovery capsule missing")
            slot, expires, retention, revoked, encoded = row
            head = con.execute("SELECT registration FROM heads WHERE slot=?", (slot,)).fetchone()
            value = self._verified(encoded)
            if (head != (registration,) or revoked != 0 or not value["captured_at"] <= int(self.clock()) < expires
                    or value["registration_id"] != registration or value["slot"] != slot
                    or value["expires_at"] != expires or value["retention_until"] != retention):
                raise SessionRecoveryError("recovery turn revoked, superseded or expired")
            return value
        finally:
            if con.in_transaction: con.execute("ROLLBACK")
            con.close()

    def revoke(self, registration):
        with self._connect(write=True) as con:
            con.execute("UPDATE capsules SET revoked=1 WHERE registration=?", (registration,))

    @contextmanager
    def write_fence(self, registration):
        # Serialize head/revocation updates with an already authorised write.
        # No other registration can supersede it between check and dispatch.
        con = self._connect(write=True)
        try:
            con.execute("BEGIN IMMEDIATE")
            self.load(registration)
            yield
            con.execute("COMMIT")
        finally:
            if con.in_transaction: con.execute("ROLLBACK")
            con.close()


class SessionRecoveryMixin:
    def call(self, name, arguments):
        if (getattr(self, "_session_recovery_enabled", False)
                and name in {"integrity_append_event", "integrity_turn_memory_close"}):
            if self._session_recovery_unretained_admission is not None:
                self._recovery_before_unretained_write(name, arguments)
                return self._call_without_session_recovery(name, arguments)
            registration_id = self._session_recovery_binding
            if registration_id is None:
                raise SessionRecoveryError("same-session write requires original registration")
            store, _ = self._recovery_registration(registration_id)
            with self._recovery_registry(store).write_fence(registration_id):
                self._recovery_before_write(name, arguments)
                return self._call_without_session_recovery(name, arguments)
        return self._call_without_session_recovery(name, arguments)

    def _recovery_registration(self, registration_id):
        service = self._require_turn_memory()
        if hasattr(service, "_registration_owner"):
            _, store = service._registration_owner(registration_id)
        else:
            store = service
        receipt = store.find_registration(registration_id)
        if receipt is None or receipt.get("receipt_id") != registration_id:
            raise SessionRecoveryError("recovery registration missing")
        return store, receipt

    def _recovery_registry(self, store, *, create=False):
        # Revalidate the existing exact replay-root/architecture-root custody.
        self._prepare_context_replay_custody()
        path = self._context_admission_replay_root.parent / "same-session-recovery-v1.sqlite3"
        return RecoveryRegistry(path, signer=store.signer, namespace=store.namespace, create=create)

    def _remember_recovery_replay(self, record):
        if self._session_recovery_enabled and record.get("phase") == "committed":
            self._session_recovery_unretained_admission = None
            self._session_recovery_unretained_registration = None
            self._session_recovery_replay = (record["request_id"], record["request_digest"])

    def _remember_unretained_admission(self):
        """Mark only a successfully admitted current intent without replay.

        This is a live-context marker, never a recovery capsule or a substitute
        for invalid retained proof. It grants no replay or retry authority.
        """
        if not self._session_recovery_enabled:
            return
        if (self._session_recovery_replay is not None
                or self._session_recovery_binding is not None):
            raise SessionRecoveryError("unretained admission has retained recovery state")
        self._session_recovery_unretained_admission = {
            "context_admission_id": self._context_admission_id,
            "logical_generation": self._context_generation,
            "snapshot": deepcopy(self._session_snapshot),
            "prompt_binding": deepcopy(self._archive_prompt_binding),
            "native_session": deepcopy(self._native_session_lease),
            "architecture": deepcopy(self._session_architecture),
        }
        self._session_recovery_unretained_registration = None

    def _recovery_check_unretained_context(self):
        marker = self._session_recovery_unretained_admission
        if (not isinstance(marker, dict)
                or self._session_recovery_replay is not None
                or self._session_recovery_binding is not None):
            raise SessionRecoveryError("current unretained admission unavailable")
        if self._session_snapshot is None or self._context_admission_id is None:
            from .memory_synapse_mcp import ContextBindingUnavailableError
            raise ContextBindingUnavailableError(
                "same-session context binding DENY: admitted snapshot is empty",
                generation=self._context_generation, loss_reason=self._context_loss_reason)
        if (marker["context_admission_id"] != self._context_admission_id
                or marker["logical_generation"] != self._context_generation
                or marker["snapshot"] != self._session_snapshot
                or marker["prompt_binding"] != self._archive_prompt_binding
                or marker["native_session"] != self._native_session_lease
                or marker["architecture"] != self._session_architecture
                or not isinstance(self._archive_prompt_binding, dict)):
            raise SessionRecoveryError("current unretained admission binding changed")
        self._recovery_check_authority({"state": {
            "native_session": marker["native_session"]}})
        return marker

    def _recovery_bind_unretained_open(self, result):
        marker = self._recovery_check_unretained_context()
        receipt = result["receipt"]
        registration_id = receipt["receipt_id"]
        _, observed = self._recovery_registration(registration_id)
        if (observed != receipt
                or receipt.get("prompt_sha256") != marker["prompt_binding"]["prompt_sha256"]):
            raise SessionRecoveryError("unretained registration receipt changed")
        previous = self._session_recovery_unretained_registration
        binding = {"registration_id": registration_id, "receipt_digest": digest(receipt),
            "identity": deepcopy(receipt["identity"]),
            "prompt_sha256": receipt["prompt_sha256"]}
        if previous is not None and previous != binding:
            raise SessionRecoveryError("unretained registration owner changed")
        self._session_recovery_unretained_registration = binding
        return {**result, "session_recovery": {"available": False,
            "protocol": RECOVERY_PROTOCOL, "reason": "admission-not-retained",
            "registration_id": registration_id, "canonical_registration_unchanged": True}}

    def _recovery_before_unretained_write(self, name, arguments):
        self._recovery_check_unretained_context()
        binding = self._session_recovery_unretained_registration
        if not isinstance(binding, dict):
            raise SessionRecoveryError("ordinary write requires its current registration")
        registration_id = binding["registration_id"]
        store, receipt = self._recovery_registration(registration_id)
        if (digest(receipt) != binding["receipt_digest"]
                or receipt["identity"] != binding["identity"]
                or receipt["prompt_sha256"] != binding["prompt_sha256"]):
            raise SessionRecoveryError("ordinary write registration owner changed")
        if name == "integrity_turn_memory_close":
            if arguments.get("registration_id") != registration_id:
                raise SessionRecoveryError("close requires current own registration")
        elif name == "integrity_append_event":
            if store.find_terminal(registration_id) is not None:
                raise SessionRecoveryError("ordinary write registration already terminal")
            self._bind_append_to_current_context(arguments)

    def _recovery_original_record(self):
        pair = self._session_recovery_replay
        if pair is None: raise SessionRecoveryError("recovery requires retained original admission")
        record = self._load_context_replay(*pair)
        if record is None or record.get("phase") != "committed":
            raise SessionRecoveryError("recovery original admission unavailable")
        return record

    def _recovery_check_authority(self, record):
        if (self.native_trust is None or self.native_device_id is None
                or not self._security_admission_is_active(self.security_admission)):
            raise SessionRecoveryError("recovery requires current native and security admission")
        lease = record["state"].get("native_session")
        if not isinstance(lease, dict): raise SessionRecoveryError("recovery native session missing")
        verified = self.native_trust.verify_session(lease)
        if verified.get("device_id") != self.native_device_id:
            raise SessionRecoveryError("recovery device mismatch")
        return verified

    def _recovery_pre_open(self, arguments):
        if not self._session_recovery_enabled: return
        if self._session_recovery_unretained_admission is not None:
            marker = self._recovery_check_unretained_context()
            binding = self._session_recovery_unretained_registration
            if (arguments.get("prompt_sha256") != marker["prompt_binding"]["prompt_sha256"]
                    or (binding is not None and any(
                        arguments.get(key) != value for key, value in binding["identity"].items()))):
                raise SessionRecoveryError("registration does not match current admitted intent")
            return
        record = self._recovery_original_record()
        result = record["result"]
        if (result.get("context_admission_id") != self._context_admission_id
                or result.get("snapshot") != self._session_snapshot
                or result.get("prompt_binding") != self._archive_prompt_binding
                or arguments.get("prompt_sha256") != self._archive_prompt_binding.get("prompt_sha256")):
            raise SessionRecoveryError("registration does not match current admitted intent")
        self._recovery_check_authority(record)

    def _recovery_bind_open(self, result):
        if not self._session_recovery_enabled: return result
        from .memory_synapse_mcp import _sha256, _tool_result
        # An open already committed; never hide its receipt or repeat it if the
        # optional derived recovery store fails. Recovery itself remains denied.
        try:
            if self._session_recovery_unretained_admission is not None:
                return self._recovery_bind_unretained_open(result)
            receipt = result["receipt"]
            registration_id = receipt["receipt_id"]
            store, observed = self._recovery_registration(registration_id)
            if observed != receipt: raise SessionRecoveryError("registration receipt changed")
            record = self._recovery_original_record()
            original = record["result"]
            lease = self._recovery_check_authority(record)
            now = int(time.time())
            core = {"protocol": RECOVERY_PROTOCOL, "registration_id": registration_id,
                "namespace_fingerprint": store.namespace, "identity": receipt["identity"],
                "prompt_sha256": receipt["prompt_sha256"], "native_device_id": self.native_device_id,
                "native_lease_id": lease["lease_id"], "registration_digest": digest(receipt),
                "slot": digest({"namespace": store.namespace, "device": self.native_device_id,
                    "machine": receipt["identity"]["machine_id"], "thread": receipt["identity"]["thread_id"]}),
                "controls": {"replay_id": record["request_id"], "request_digest": record["request_digest"],
                    "response_digest": _sha256(_tool_result(original)), "context_admission_id": self._context_admission_id,
                    "snapshot_id": self._session_snapshot["snapshot_id"], "prompt_binding": self._archive_prompt_binding,
                    "logical_generation": self._context_generation},
                "snapshot_digest": replay_json_digest(original["snapshot"]), "state_digest": replay_json_digest(record["state"]),
                "captured_at": now, "expires_at": min(now + MAX_RETENTION, _epoch(lease["expires_at"]), _epoch(self.security_admission.expires_at)),
                "retention_until": now + MAX_RETENTION}
            capsule = self._recovery_registry(store, create=True).bind(core)
            self._session_recovery_binding = registration_id
            return {**result, "session_recovery": {"available": True, "protocol": RECOVERY_PROTOCOL,
                "registration_id": registration_id, "expires_at": capsule["expires_at"], "canonical_writes": 0}}
        except Exception as exc:
            self._session_recovery_binding = None
            return {**result, "session_recovery": {"available": False, "protocol": RECOVERY_PROTOCOL,
                "reason": "derived-binding-unavailable", "error_type": type(exc).__name__,
                "canonical_registration_unchanged": True}}

    def _recovery_capsule(self, registration_id, *, allow_terminal=False):
        store, receipt = self._recovery_registration(registration_id)
        capsule = self._recovery_registry(store).load(registration_id)
        if (capsule["native_device_id"] != self.native_device_id or capsule["registration_digest"] != digest(receipt)
                or capsule["identity"] != receipt["identity"] or capsule["prompt_sha256"] != receipt["prompt_sha256"]):
            raise SessionRecoveryError("recovery foreign registration")
        terminal = store.find_terminal(registration_id)
        if terminal is not None and not allow_terminal:
            raise SessionRecoveryError("recovery registration already terminal")
        return capsule, terminal

    def _recovery_status_binding(self, registration_id):
        """Read-only exact ownership/authority join, including terminal turns."""
        store, receipt = self._recovery_registration(registration_id)
        capsule, _ = self._recovery_capsule(registration_id, allow_terminal=True)
        controls = capsule["controls"]
        record = self._load_context_replay(controls["replay_id"], controls["request_digest"])
        if (record is None or record.get("phase") != "committed"
                or replay_json_digest(record["state"]) != capsule["state_digest"]
                or replay_json_digest(record["result"].get("snapshot")) != capsule["snapshot_digest"]):
            raise SessionRecoveryError("recovery status original evidence changed")
        lease = self._recovery_check_authority(record)
        if lease["lease_id"] != capsule["native_lease_id"]:
            raise SessionRecoveryError("recovery status original lease changed")
        return store, receipt, record

    def _recovery_before_write(self, name, arguments):
        if not self._session_recovery_enabled or name not in {"integrity_append_event", "integrity_turn_memory_close"}: return
        registration_id = self._session_recovery_binding
        if registration_id is None: raise SessionRecoveryError("same-session write requires its original registration")
        if name == "integrity_turn_memory_close" and arguments.get("registration_id") != registration_id:
            raise SessionRecoveryError("close requires current own registration")
        if self._session_snapshot is None or self._context_admission_id is None:
            # Preserve the original facade's definitive pre-dispatch empty-
            # context receipt. A generic ValueError hides idle eviction from
            # the broker and cannot justify a safe private recovery attempt.
            if name == "integrity_append_event":
                self._bind_append_to_current_context(arguments)
            from .memory_synapse_mcp import ContextBindingUnavailableError
            raise ContextBindingUnavailableError("same-session context binding DENY: admitted snapshot is empty",
                generation=self._context_generation, loss_reason=self._context_loss_reason)
        capsule, _ = self._recovery_capsule(registration_id, allow_terminal=(name == "integrity_turn_memory_close"))
        record = self._load_context_replay(capsule["controls"]["replay_id"], capsule["controls"]["request_digest"])
        if record is None or replay_json_digest(record["state"]) != capsule["state_digest"]:
            raise SessionRecoveryError("same-session original evidence changed")
        self._recovery_check_authority(record)
        if (self._context_admission_id != capsule["controls"]["context_admission_id"]
                or self._context_generation != capsule["controls"]["logical_generation"]
                or replay_json_digest(self._session_snapshot) != capsule["snapshot_digest"]
                or self._archive_prompt_binding != capsule["controls"]["prompt_binding"]
                or self._native_session_lease != record["state"].get("native_session")
                or self._session_architecture != record["state"].get("architecture")):
            raise SessionRecoveryError("same-session current binding changed")

    def _recovery_revoke(self, reason):
        registration_id = self._session_recovery_binding
        if not self._session_recovery_enabled or registration_id is None: return
        store, _ = self._recovery_registration(registration_id)
        self._recovery_registry(store).revoke(registration_id)
        self._session_recovery_binding = None

    def _recover_same_session(self, arguments):
        from .memory_synapse_mcp import _sha256, _tool_result
        if (not self._session_recovery_enabled or not self._broker_tool_surface_authenticated
                or not isinstance(arguments, dict) or set(arguments) != CONTROL_FIELDS | {"registration_id"}
                or self._active_context_replay_id is not None):
            raise SessionRecoveryError("same-session recovery not negotiated")
        controls = _controls({k:v for k,v in arguments.items() if k != "registration_id"})
        capsule, _ = self._recovery_capsule(arguments["registration_id"])
        if capsule["controls"] != controls: raise SessionRecoveryError("same-session exact controls mismatch")
        if self._session_snapshot is not None or self._context_admission_id is not None:
            # Repeated lost reply can be observed, but never replace a context.
            if (self._session_recovery_binding != arguments["registration_id"]
                    or self._context_admission_id != controls["context_admission_id"]
                    or replay_json_digest(self._session_snapshot) != capsule["snapshot_digest"]):
                raise SessionRecoveryError("same-session cannot replace another active context")
        with self._context_replay_lock(controls["replay_id"], timeout_seconds=0.0):
            record = self._load_context_replay(controls["replay_id"], controls["request_digest"])
            if (record is None or record.get("phase") != "committed"
                    or replay_json_digest(record["state"]) != capsule["state_digest"]
                    or replay_json_digest(record["result"].get("snapshot")) != capsule["snapshot_digest"]
                    or _sha256(_tool_result(record["result"])) != controls["response_digest"]
                    or record["result"].get("context_admission_id") != controls["context_admission_id"]
                    or record["result"].get("prompt_binding") != controls["prompt_binding"]
                    or record["result"].get("logical_generation") != controls["logical_generation"]
                    or record["state"].get("frozen_catalog") is None
                    or self._replay_migration(controls["replay_id"]) is not None):
                raise SessionRecoveryError("same-session retained snapshot or admission changed")
            lease = self._recovery_check_authority(record)
            if lease["lease_id"] != capsule["native_lease_id"]:
                raise SessionRecoveryError("same-session original lease changed")
            try:
                self._restore_context_replay(record)
                self._context_reattach_read_only = False
                self._session_recovery_binding = arguments["registration_id"]
                self._recovery_before_write("integrity_append_event", {})
            except Exception:
                self._clear_intent_context(reason="same-session-recovery-failed")
                self._session_recovery_binding = None
                raise
        return {"protocol": RECOVERY_PROTOCOL, **deepcopy(arguments), "restored": True,
            "same_session": True, "read_only": False, "canonical_writes": 0,
            "production_authority": False, "action_authority": False, "automatic_retry_allowed": False}
