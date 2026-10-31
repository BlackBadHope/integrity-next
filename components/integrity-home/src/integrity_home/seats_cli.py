"""Operator CLI for Integrity Seats. It never reads or stores provider API keys."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import sys

from .host_enrollment import HostDirectory
from .seat_policy import SeatAccessError, write_isolation_mode
from .seat_registry import SeatRegistry, SeatRegistryError


def _registry(path: Path) -> SeatRegistry:
    if not path.is_absolute():
        raise SeatRegistryError("registry path must be absolute", 400)
    return SeatRegistry(path)


def _utc(seconds_from_now: int) -> str:
    moment = datetime.now(timezone.utc) + timedelta(seconds=seconds_from_now)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _migrate_database(source: Path, backup: Path) -> None:
    if not source.is_file():
        raise SeatRegistryError("action log database is missing", 400)
    if backup.exists():
        raise SeatRegistryError("backup path already exists", 400)
    escaped = str(backup).replace("'", "''")
    if "'" in str(backup):
        raise SeatRegistryError("backup path is invalid", 400)
    connection = sqlite3.connect(source)
    try:
        connection.execute(f"VACUUM INTO '{escaped}'")
        columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(events)")}
        additions = (
            ("seat_id", "TEXT NOT NULL DEFAULT 'seat_owner'"),
            ("host_id", "TEXT NOT NULL DEFAULT 'local'"),
            ("namespace", "TEXT NOT NULL DEFAULT 'team/default'"),
            ("auth_principal_sha256", "TEXT NOT NULL DEFAULT ''"),
        )
        for name, declaration in additions:
            if name not in columns:
                connection.execute(f"ALTER TABLE events ADD COLUMN {name} {declaration}")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_namespace ON events(namespace)"
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_events_seat ON events(seat_id)")
        connection.commit()
    finally:
        connection.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="integrity-seats")
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument(
        "--isolation-mode",
        choices=("silo", "shared-core", "single-user"),
        default=None,
        help="recorded for a new root; default shared-core when the root is empty",
    )
    sub = parser.add_subparsers(dest="group", required=True)

    seat = sub.add_parser("seat")
    seat_sub = seat.add_subparsers(dest="action", required=True)
    create = seat_sub.add_parser("create")
    create.add_argument("--seat-id", required=True)
    create.add_argument("--display-name", required=True)
    create.add_argument("--role", action="append", required=True)
    create.add_argument("--namespace", action="append", required=True)
    seat_sub.add_parser("list")
    revoke = seat_sub.add_parser("revoke")
    revoke.add_argument("--seat-id", required=True)

    token = sub.add_parser("token")
    token_sub = token.add_subparsers(dest="action", required=True)
    issue = token_sub.add_parser("issue")
    issue.add_argument("--seat-id", required=True)
    issue.add_argument("--host-id", required=True)
    issue.add_argument("--ttl", type=int, default=3600)
    drop = token_sub.add_parser("revoke")
    drop.add_argument("--token", required=True)

    migrate = sub.add_parser("migrate")
    migrate_sub = migrate.add_subparsers(dest="action", required=True)
    single = migrate_sub.add_parser("from-single-host")
    single.add_argument("--db", type=Path, required=True)
    single.add_argument("--backup", type=Path, required=True)

    init = sub.add_parser("init")
    init.add_argument("--root", type=Path, required=True)

    host = sub.add_parser("host")
    host_sub = host.add_subparsers(dest="action", required=True)
    enroll = host_sub.add_parser("enroll-token")
    enroll_sub = enroll.add_subparsers(dest="step", required=True)
    create_enroll = enroll_sub.add_parser("create")
    create_enroll.add_argument("--seat-id", required=True)
    create_enroll.add_argument("--host-id", required=True)
    create_enroll.add_argument("--transport", required=True)
    create_enroll.add_argument("--ttl", type=int, default=600)

    node = sub.add_parser("node")
    node_sub = node.add_subparsers(dest="action", required=True)
    join = node_sub.add_parser("join")
    join.add_argument("--core", required=True)
    join.add_argument("--enroll-token", required=True)
    join.add_argument("--key-dir", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.group == "init":
            mode = args.isolation_mode or "shared-core"
            write_isolation_mode(args.root, mode)
            print(json.dumps({"ok": True, "isolation_mode": mode}))
            return 0
        if args.group == "migrate":
            _migrate_database(args.db, args.backup)
            print(json.dumps({"ok": True, "backup": str(args.backup)}))
            return 0
        registry = _registry(args.registry)
        if args.group == "seat" and args.action == "create":
            record = registry.create_seat(
                args.seat_id, args.display_name, args.role, args.namespace
            )
            print(json.dumps({"ok": True, "seat_id": record.seat_id, "status": record.status}))
            return 0
        if args.group == "seat" and args.action == "list":
            print(json.dumps({
                "ok": True,
                "seats": [
                    {
                        "seat_id": seat.seat_id,
                        "display_name": seat.display_name,
                        "roles": sorted(seat.roles),
                        "namespaces": list(seat.namespaces),
                        "status": seat.status,
                        "revocation_epoch": seat.revocation_epoch,
                    }
                    for seat in registry.list_seats()
                ],
            }))
            return 0
        if args.group == "seat" and args.action == "revoke":
            record = registry.revoke_seat(args.seat_id)
            print(json.dumps({
                "ok": True,
                "seat_id": record.seat_id,
                "status": record.status,
                "revocation_epoch": record.revocation_epoch,
            }))
            return 0
        if args.group == "token" and args.action == "issue":
            if not 60 <= args.ttl <= 60 * 60 * 24 * 30:
                raise SeatRegistryError("ttl invalid", 400)
            issued = registry.issue_token(args.seat_id, args.host_id, _utc(args.ttl))
            print(json.dumps({
                "ok": True,
                "token": issued.token,
                "token_sha256": issued.token_sha256,
                "seat_id": issued.seat_id,
                "host_id": issued.host_id,
                "expires_at": issued.expires_at,
            }))
            return 0
        if args.group == "token" and args.action == "revoke":
            registry.revoke_token(args.token)
            print(json.dumps({"ok": True, "revoked": True}))
            return 0
        if args.group == "host" and args.action == "enroll-token" and args.step == "create":
            if not 60 <= args.ttl <= 86400:
                raise SeatRegistryError("ttl invalid", 400)
            directory = HostDirectory(args.registry)
            token = directory.create_token(args.seat_id, args.host_id, args.transport, _utc(args.ttl))
            print(json.dumps({"ok": True, "token": token, "host_id": args.host_id, "transport": args.transport}))
            return 0
        if args.group == "node" and args.action == "join":
            if not str(args.core).startswith(("https://", "http://127.0.0.1", "http://localhost")):
                raise SeatRegistryError("core url invalid", 400)
            directory = HostDirectory(args.registry)
            result = directory.join(args.enroll_token, args.key_dir)
            result["core"] = args.core
            print(json.dumps(result))
            return 0
    except (SeatRegistryError, SeatAccessError) as err:
        print(json.dumps({"ok": False, "error": err.code, "status": err.status}), file=sys.stderr)
        return err.status
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
