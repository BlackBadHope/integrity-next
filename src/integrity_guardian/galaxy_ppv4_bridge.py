"""Native-owned, authority-free PPv4 lifecycle bridge for Galaxy.

The process is intended to run as the ``integrity-client`` principal behind one
fixed wrapper.  Galaxy sends one bounded request on stdin and receives one
signed response.  Private native keys and the dialogue database never cross
the process boundary.
"""

from __future__ import annotations

import argparse
import os
import socket
import stat
import struct
import sys
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, parse_json_strict
from .hashing import digest_object
from .native_trust import NativeTrustStore
from .perpetual_dialogue import PerpetualDialogueStore
from .signing import TrustedKey, verify_signature

REQUEST_PROTOCOL = "integrity-guardian/galaxy-ppv4-bridge-request/v1"
RESPONSE_PROTOCOL = "integrity-guardian/galaxy-ppv4-bridge-response/v1"
TRUST_BUNDLE_PROTOCOL = "integrity-guardian/galaxy-ppv4-trust-bundle/v1"
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
OPERATIONS = frozenset(
    {
        "prepare_initial_turn",
        "close_continue_and_seal",
        "close_terminal_and_seal",
        "reconcile_close_and_seal",
        "snapshot",
        "stop_and_seal",
    }
)


class GalaxyPPv4BridgeError(ValueError):
    """A bridge request or signed response violated the fixed contract."""


def build_bridge_request(operation: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    if operation not in OPERATIONS or not isinstance(payload, Mapping):
        raise GalaxyPPv4BridgeError("bridge operation is invalid")
    core = {
        "protocol": REQUEST_PROTOCOL,
        "operation": operation,
        "payload": deepcopy(dict(payload)),
        "production_authority": False,
    }
    return {
        **core,
        "request_id": digest_object(core, domain="galaxy-ppv4-bridge-request-v1"),
    }


def verify_bridge_request(request: Mapping[str, Any]) -> dict[str, Any]:
    candidate = deepcopy(dict(request))
    if set(candidate) != {
        "protocol",
        "operation",
        "payload",
        "production_authority",
        "request_id",
    }:
        raise GalaxyPPv4BridgeError("bridge request shape is invalid")
    if (
        candidate["protocol"] != REQUEST_PROTOCOL
        or candidate["operation"] not in OPERATIONS
        or not isinstance(candidate["payload"], dict)
        or candidate["production_authority"] is not False
    ):
        raise GalaxyPPv4BridgeError("bridge request contract is invalid")
    core = deepcopy(candidate)
    request_id = core.pop("request_id")
    if request_id != digest_object(core, domain="galaxy-ppv4-bridge-request-v1"):
        raise GalaxyPPv4BridgeError("bridge request identity mismatch")
    return candidate


def verify_bridge_response(
    response: Mapping[str, Any],
    *,
    trusted_key: TrustedKey,
    expected_request_id: str,
) -> dict[str, Any]:
    candidate = deepcopy(dict(response))
    if set(candidate) != {
        "protocol",
        "operation",
        "request_id",
        "response_id",
        "result",
        "production_authority",
        "signature",
    }:
        raise GalaxyPPv4BridgeError("bridge response shape is invalid")
    if (
        candidate["protocol"] != RESPONSE_PROTOCOL
        or candidate["operation"] not in OPERATIONS
        or candidate["request_id"] != expected_request_id
        or not isinstance(candidate["result"], dict)
        or candidate["production_authority"] is not False
        or candidate["signature"].get("key_id") != trusted_key.key_id
        or not verify_signature(candidate, trusted_key.public_key)
    ):
        raise GalaxyPPv4BridgeError("bridge response signature or binding rejected")
    core = deepcopy(candidate)
    core.pop("signature")
    response_id = core.pop("response_id")
    if response_id != digest_object(core, domain="galaxy-ppv4-bridge-response-v1"):
        raise GalaxyPPv4BridgeError("bridge response identity mismatch")
    return candidate


def _exact_payload(payload: Mapping[str, Any], keys: set[str]) -> dict[str, Any]:
    candidate = deepcopy(dict(payload))
    if set(candidate) != keys:
        raise GalaxyPPv4BridgeError("bridge payload shape is invalid")
    return candidate


class GalaxyPPv4Bridge:
    """One narrow native-state owner; it is not an execution authority."""

    def __init__(
        self,
        *,
        state_root: Path,
        database_path: Path,
        instance_id: str,
        tenant_id: str,
        ledger_id: str,
    ) -> None:
        self.state_root = Path(state_root)
        self.database_path = Path(database_path)
        self.instance_id = instance_id
        self.tenant_id = tenant_id
        self.ledger_id = ledger_id
        if os.name != "nt":
            self.database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                self.database_path.parent.chmod(0o700)
            except OSError:
                pass
        self.trust = NativeTrustStore(self.state_root, instance_id=instance_id)
        self.keys = self.trust.ensure_database(
            tenant_id=tenant_id,
            ledger_id=ledger_id,
        )
        self.store = PerpetualDialogueStore(
            self.database_path,
            tenant_id=tenant_id,
            signer=self.keys.source_signer,
        )

    def public_trust_bundle(self) -> dict[str, Any]:
        core = {
            "protocol": TRUST_BUNDLE_PROTOCOL,
            "instance_id": self.instance_id,
            "tenant_id": self.tenant_id,
            "ledger_id": self.ledger_id,
            "genesis": self.trust.verify_genesis(),
            "enrollment": deepcopy(self.keys.enrollment),
            "production_authority": False,
        }
        return {
            **core,
            "bundle_id": digest_object(core, domain="galaxy-ppv4-trust-bundle-v1"),
        }

    def _prepare(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        value = _exact_payload(
            payload,
            {
                "conversation_id",
                "work_item_id",
                "sender_id",
                "recipient_id",
                "turn_id",
                "claim_digest",
            },
        )
        conversation = self.store.open_conversation(
            conversation_id=value["conversation_id"],
            participants=[value["sender_id"], value["recipient_id"]],
        )
        work = self.store.open_work_item(
            conversation_id=value["conversation_id"],
            work_item_id=value["work_item_id"],
            claim_digest=value["claim_digest"],
        )
        baton = self.store.issue_baton(
            conversation_id=value["conversation_id"],
            work_item_id=value["work_item_id"],
            sender_id=value["sender_id"],
            recipient_id=value["recipient_id"],
            processing_turn_id=value["turn_id"],
            claim_digest=value["claim_digest"],
            authority_digest=None,
        )
        return {
            "conversation_receipt_id": conversation["receipt"]["receipt_id"],
            "work_receipt_id": work["receipt"]["receipt_id"],
            "baton_receipt_id": baton["receipt"]["receipt_id"],
            "baton_id": baton["baton_id"],
            "state": self.store.snapshot(conversation_id=value["conversation_id"]),
        }

    def _close_continue(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        value = _exact_payload(
            payload,
            {
                "conversation_id",
                "baton_id",
                "expected_fence",
                "result_digest",
                "checkpoint",
                "next_agent_id",
                "agent_id",
                "turn_id",
            },
        )
        checkpoint = value["checkpoint"]
        if not isinstance(checkpoint, dict) or checkpoint.get("authority_required") is not False:
            raise GalaxyPPv4BridgeError("bridge continuation authority boundary rejected")
        closed = self.store.close_baton_and_schedule_continuation(
            expected_fence=value["expected_fence"],
            baton_id=value["baton_id"],
            result_digest=value["result_digest"],
            checkpoint=checkpoint,
            next_agent_id=value["next_agent_id"],
        )
        sealed = self.store.seal_turn_exit(
            conversation_id=value["conversation_id"],
            agent_id=value["agent_id"],
            turn_id=value["turn_id"],
        )
        return {
            "receipt_id": closed["receipt"]["receipt_id"],
            "checkpoint_id": closed["checkpoint_id"],
            "wake_id": closed["continuation_id"],
            "turn_exit_receipt_id": sealed["receipt"]["receipt_id"],
            "safe_to_end": sealed["safe_to_end"],
            "state": self.store.snapshot(conversation_id=value["conversation_id"]),
        }

    def _close_terminal(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        value = _exact_payload(
            payload,
            {
                "conversation_id",
                "baton_id",
                "expected_fence",
                "result_digest",
                "disposition",
                "terminal_digest",
                "agent_id",
                "turn_id",
            },
        )
        disposition = value["disposition"]
        if disposition not in {"WORK_COMPLETE", "HOLD"}:
            raise GalaxyPPv4BridgeError("bridge terminal disposition is invalid")
        arguments: dict[str, Any] = {
            "baton_id": value["baton_id"],
            "expected_fence": value["expected_fence"],
            "result_digest": value["result_digest"],
            "disposition": disposition,
        }
        arguments["completion_digest" if disposition == "WORK_COMPLETE" else "blocker_digest"] = (
            value["terminal_digest"]
        )
        closed = self.store.close_baton(**arguments)
        sealed = self.store.seal_turn_exit(
            conversation_id=value["conversation_id"],
            agent_id=value["agent_id"],
            turn_id=value["turn_id"],
        )
        return {
            "receipt_id": closed["receipt"]["receipt_id"],
            "turn_exit_receipt_id": sealed["receipt"]["receipt_id"],
            "safe_to_end": sealed["safe_to_end"],
            "state": self.store.snapshot(conversation_id=value["conversation_id"]),
        }

    def _reconcile(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        value = _exact_payload(
            payload,
            {"conversation_id", "baton_id", "agent_id", "turn_id"},
        )
        reconciled = self.store.reconcile_baton_close(baton_id=value["baton_id"])
        sealed = None
        if reconciled["outcome"] in {"COMMITTED", "CANCELLED"}:
            sealed = self.store.seal_turn_exit(
                conversation_id=value["conversation_id"],
                agent_id=value["agent_id"],
                turn_id=value["turn_id"],
            )
        return {
            "reconciliation": reconciled,
            "turn_exit_receipt_id": (None if sealed is None else sealed["receipt"]["receipt_id"]),
            "safe_to_end": False if sealed is None else sealed["safe_to_end"],
            "state": self.store.snapshot(conversation_id=value["conversation_id"]),
        }

    def _snapshot(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        value = _exact_payload(payload, {"conversation_id"})
        return {"state": self.store.snapshot(conversation_id=value["conversation_id"])}

    def _stop(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        value = _exact_payload(
            payload,
            {
                "conversation_id",
                "expected_control_generation",
                "control_digest",
                "agent_id",
                "turn_id",
            },
        )
        controlled = self.store.control_conversation(
            conversation_id=value["conversation_id"],
            action="STOP",
            expected_control_generation=value["expected_control_generation"],
            control_digest=value["control_digest"],
        )
        sealed = self.store.seal_turn_exit(
            conversation_id=value["conversation_id"],
            agent_id=value["agent_id"],
            turn_id=value["turn_id"],
        )
        return {
            "receipt_id": controlled["receipt"]["receipt_id"],
            "turn_exit_receipt_id": sealed["receipt"]["receipt_id"],
            "safe_to_end": sealed["safe_to_end"],
            "state": self.store.snapshot(conversation_id=value["conversation_id"]),
        }

    def handle(self, request: Mapping[str, Any]) -> dict[str, Any]:
        verified = verify_bridge_request(request)
        operation = verified["operation"]
        handlers = {
            "prepare_initial_turn": self._prepare,
            "close_continue_and_seal": self._close_continue,
            "close_terminal_and_seal": self._close_terminal,
            "reconcile_close_and_seal": self._reconcile,
            "snapshot": self._snapshot,
            "stop_and_seal": self._stop,
        }
        result = handlers[operation](verified["payload"])
        core = {
            "protocol": RESPONSE_PROTOCOL,
            "operation": operation,
            "request_id": verified["request_id"],
            "result": result,
            "production_authority": False,
        }
        unsigned = {
            **core,
            "response_id": digest_object(core, domain="galaxy-ppv4-bridge-response-v1"),
        }
        return self.keys.source_signer.sign(unsigned)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--database-path", required=True, type=Path)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--ledger-id", required=True)
    parser.add_argument("--print-trust-bundle", action="store_true")
    parser.add_argument("--listen-unix", type=Path)
    parser.add_argument("--allowed-peer-uid", type=int)
    return parser


def _read_exact(connection: socket.socket, size: int) -> bytes:
    if size < 0:
        raise GalaxyPPv4BridgeError("bridge frame size is invalid")
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise GalaxyPPv4BridgeError("bridge frame ended early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _peer_uid(connection: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise GalaxyPPv4BridgeError("bridge peer credentials are unavailable")
    payload = connection.getsockopt(
        socket.SOL_SOCKET,
        socket.SO_PEERCRED,
        struct.calcsize("3i"),
    )
    _pid, uid, _gid = struct.unpack("3i", payload)
    return int(uid)


def serve_unix(
    bridge: GalaxyPPv4Bridge,
    *,
    socket_path: Path,
    allowed_peer_uid: int,
) -> None:
    """Serve one framed request per peer-credential-bound local connection."""

    if os.name != "posix" or allowed_peer_uid < 0:
        raise GalaxyPPv4BridgeError("Unix bridge listener configuration is invalid")
    target = Path(socket_path)
    if not target.is_absolute() or target.is_symlink():
        raise GalaxyPPv4BridgeError("Unix bridge socket path is unsafe")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    parent_details = target.parent.stat()
    if (
        not stat.S_ISDIR(parent_details.st_mode)
        or parent_details.st_uid != os.geteuid()
        or stat.S_IMODE(parent_details.st_mode) & 0o007
    ):
        raise GalaxyPPv4BridgeError("Unix bridge socket directory custody is unsafe")
    if target.exists() or target.is_symlink():
        details = target.lstat()
        if not stat.S_ISSOCK(details.st_mode) or details.st_uid != os.geteuid():
            raise GalaxyPPv4BridgeError("existing Unix bridge socket is unsafe")
        target.unlink()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(target))
        os.chmod(target, 0o660)
        listener.listen(32)
        while True:
            connection, _address = listener.accept()
            with connection:
                try:
                    if _peer_uid(connection) != allowed_peer_uid:
                        raise GalaxyPPv4BridgeError("Unix bridge peer is not admitted")
                    header = _read_exact(connection, 4)
                    length = struct.unpack("!I", header)[0]
                    if not 1 <= length <= MAX_REQUEST_BYTES:
                        raise GalaxyPPv4BridgeError("bridge request size is invalid")
                    raw = _read_exact(connection, length)
                    parsed = parse_json_strict(raw)
                    if not isinstance(parsed, dict):
                        raise GalaxyPPv4BridgeError("bridge request must be an object")
                    encoded = canonical_bytes(bridge.handle(parsed))
                    if len(encoded) > MAX_RESPONSE_BYTES:
                        raise GalaxyPPv4BridgeError("bridge response size is invalid")
                    connection.sendall(struct.pack("!I", len(encoded)) + encoded)
                except Exception as exc:  # noqa: BLE001 - reject only this peer
                    print(
                        "galaxy-ppv4-bridge rejected request: " + exc.__class__.__name__,
                        file=sys.stderr,
                        flush=True,
                    )
    finally:
        listener.close()
        try:
            target.unlink()
        except FileNotFoundError:
            pass


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    bridge = GalaxyPPv4Bridge(
        state_root=args.state_root,
        database_path=args.database_path,
        instance_id=args.instance_id,
        tenant_id=args.tenant_id,
        ledger_id=args.ledger_id,
    )
    if args.print_trust_bundle:
        sys.stdout.buffer.write(canonical_bytes(bridge.public_trust_bundle()) + b"\n")
        return 0
    if args.listen_unix is not None:
        if args.allowed_peer_uid is None:
            raise GalaxyPPv4BridgeError("Unix bridge allowed peer UID is required")
        serve_unix(
            bridge,
            socket_path=args.listen_unix,
            allowed_peer_uid=args.allowed_peer_uid,
        )
        return 0
    if args.allowed_peer_uid is not None:
        raise GalaxyPPv4BridgeError("peer UID is valid only for Unix bridge mode")
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if not raw or len(raw) > MAX_REQUEST_BYTES:
        raise GalaxyPPv4BridgeError("bridge request size is invalid")
    parsed = parse_json_strict(raw)
    if not isinstance(parsed, dict):
        raise GalaxyPPv4BridgeError("bridge request must be an object")
    response = bridge.handle(parsed)
    sys.stdout.buffer.write(canonical_bytes(response) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "GalaxyPPv4Bridge",
    "GalaxyPPv4BridgeError",
    "build_bridge_request",
    "serve_unix",
    "verify_bridge_request",
    "verify_bridge_response",
]
