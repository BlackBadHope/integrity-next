# Two seats, two machines

This example uses placeholders. It does not contain a live host, token, or key.

- Core: `<CORE_HOST>`
- Seat A: `<YOUR_SEAT_ID>` on machine A, with its own model account
- Seat B: `bob` on machine B, with a different model account

Both seats can read `team/*`. Neither can read `seat/<other>/*`.

Machine A joins with a one-time enrollment token:

```bash
integrity-seats --registry /absolute/path/seat-registry.sqlite3 host enroll-token create --seat-id <YOUR_SEAT_ID> --host-id host-a --transport ssh_stdio --ttl 600
integrity-seats --registry /absolute/path/seat-registry.sqlite3 node join --core http://127.0.0.1:9 --enroll-token <TOKEN> --key-dir /absolute/path/host-a-keys
```

`http://127.0.0.1:9` above is a placeholder port, not a deployed service.
Replace `<CORE_HOST>` with the core you operate. The join command writes
`host.key` and `peer.key` with mode 0600.

Codex on each machine uses the Integrity Seats plugin and that machine's seat
token file. Claude Code uses `plugins/integrity-seats` plus
`INTEGRITY_CLIENT_MEMORY_CONFIG`. See
[docs/HOWTO_OPENAI_TUNNEL_SEATS.md](../../docs/HOWTO_OPENAI_TUNNEL_SEATS.md).
