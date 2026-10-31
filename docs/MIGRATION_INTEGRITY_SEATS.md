# Migrating to Integrity Seats

An existing single-user or silo install keeps that isolation until you migrate
on purpose. A new empty root defaults to `shared-core`.

1. Copy the Action Log with the migrate command. It runs `VACUUM INTO` before
   adding columns:

```bash
integrity-seats --registry /absolute/path/seat-registry.sqlite3 migrate from-single-host --db /absolute/path/codex-action-log.sqlite3 --backup /absolute/path/codex-action-log.backup.sqlite3
```

2. The upgrade adds `seat_id`, `host_id`, `namespace`, and
   `auth_principal_sha256`. Old rows read as `seat_owner`, `local`, and
   `team/default`. Append-only triggers are not dropped.
3. Leave `INTEGRITY_ISOLATION_MODE` unset until you have created seats. Unset
   mode keeps the legacy `seat_owner` view.
4. When the seats exist, set `INTEGRITY_ISOLATION_MODE=shared-core` on the
   core process. Callers then need a verified OAuth principal or a seat token.
   Request JSON cannot choose the seat.
5. Plugin name: `plugins/integrity-seats`. Old server names
   `integrity-private-memory` and `integrity-private-memory-codex-bridge` still
   work as deprecated `--server-name` aliases.

This is a source migration guide, not a claim that a production cutover has
been executed.
