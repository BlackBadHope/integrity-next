# Team quickstart (2–5 people)

Each person keeps their own model account. The shared core holds the Action
Log, Seed, bus, and work claims. Seats are access seats, not shared logins.

## New core

On the machine that will host the core:

```bash
python -m pip install .
integrity-seats init --registry /absolute/path/seat-registry.sqlite3 --root /absolute/path/core --isolation-mode shared-core
integrity-seats --registry /absolute/path/seat-registry.sqlite3 seat create --seat-id seat_owner --display-name Owner --role go_approver --role admin --namespace 'team/*' --namespace 'seat/seat_owner/*'
```

Create one seat per person (`alice`, `bob`, …) with only the roles they need.
Issue a token into a mode `0600` file and give that file only to that person.

Linux, macOS, and Windows can run the same commands. On Windows, protect the
token file with a user-only ACL. The core URL in docs is `<CORE_HOST>`.
Use `example.invalid` in examples. Do not publish a live tunnel port.

Existing single-user or silo installs stay as they are until
`integrity-seats migrate from-single-host`. See
[MIGRATION_INTEGRITY_SEATS.md](MIGRATION_INTEGRITY_SEATS.md).

Mode A (OAuth gateway) is the path for a team. Mode B (personal tunnel) is
optional. Confirm the current OpenAI docs before using a tunnel.
