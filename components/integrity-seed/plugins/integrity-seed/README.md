# Integrity Seed: local memory for agents working in turn

This guide takes you from a clean machine to two agents that continue one task
through the same local Integrity memory, one after the other. It uses only the
commands that ship with Integrity Guardian `6.0.0`.

What you get:

- an append-only event log with a `task_id` on every record;
- a short recall capsule for picking up context quickly;
- a full, lossless read of any event through a catalog snapshot;
- state that survives a runtime restart and is shared by agents on the same
  machine.

Read [Limits](#limits) before you rely on this with more than one agent.

## 1. Install

You need Python 3.11 or newer, Git and a POSIX shell (bash or zsh). The
commands below were checked on Linux; a Windows variant is not covered here.
Install the release tag `v6.0.0`, not
the `main` branch: the tag is the reviewed release (commit
`b66dd68a3a2a8ad85533446a4130c5ca2f10c305`). `main` also reports version
`6.0.0` but can carry unreleased changes.

Keep the virtual environment outside the checkout:

```bash
BASE="$HOME/integrity-memory"          # any new directory you own
mkdir -p "$BASE" && cd "$BASE"
git clone --branch v6.0.0 --depth 1 https://github.com/BlackBadHope/integrity-next.git repo
python3 -m venv venv
./venv/bin/python -m pip install ./repo
./venv/bin/guardian version --all      # "version": "6.0.0"
```

The memory path needs only this core package and the Seed script in the
checkout. The component packages listed in [BOOTSTRAP.md](../../../../BOOTSTRAP.md)
and `guardian native-trust-bootstrap` are **not** required for it.

## 2. Create a separate state

Every terminal an agent uses sets the same four variables:

```bash
BASE="$HOME/integrity-memory"
export INTEGRITY_SEED_HOME="$BASE/state/seed"    # the shared memory state
export CODEX_HOME="$BASE/state/codex-home"       # keeps ~/.codex untouched
SEED="$BASE/repo/components/integrity-seed/plugins/integrity-seed/skills/integrity-seed/scripts/integrity_seed.py"
PY="$BASE/venv/bin/python"
GUARDIAN="$BASE/venv/bin/guardian"
mkdir -p "$BASE/work" "$BASE/snapshots" && cd "$BASE/work"
```

`INTEGRITY_SEED_HOME` must be a dedicated directory: new or empty, not your
home or `CODEX_HOME`, and not inside the Git checkout or the directory the
agent works in. Without this variable the Seed state goes under
`~/.codex/integrity-seed/`, which other installations may already use.
Another value of `INTEGRITY_SEED_HOME` is a separate, independent memory.

## 3. Start the runtime and find its address

```bash
"$PY" "$SEED" setup --json
```

`setup` starts the local runtime, or resumes it if it is already running. Its
JSON shows `"ok": true`, the number of stored `events`, and the `port`. The
runtime listens only on `127.0.0.1`, and the port changes on every restart.
Read the current value whenever you need it:

```bash
PORT="$("$PY" "$SEED" status --json | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["port"])')"
```

`status` never starts the runtime; when it is stopped, `status` reports
`"ok": false`.

## 4. Record a result with a task_id

```bash
"$PY" "$SEED" remember --task-id demo-inventory --actor agent-a --session-id agent-a-s1 \
  "Glass tubes: 23 crates delivered on 2026-09-20 (source docs/b-supplier.txt)."
```

The reply is the stored event with its numeric `id`. Choose a `task_id` that
is unique and easy to search. Put the key result at the start of the summary,
because the recall capsule shortens long text.

To leave a next step for whoever continues, record a handoff:

```bash
"$PY" "$SEED" remember --task-id demo-inventory --kind handoff --actor agent-a --session-id agent-a-s1 \
  "NEXT STEP: read docs/c-ceramics.txt and record the ceramic count."
```

`task_id` is a label on the event. The CLI does not create a task lifecycle
object, so recall reports `PRIMARY: no matching open task` even when events
for the task exist.

## 5. Brief recall versus full read

```bash
"$PY" "$SEED" recall --session-id agent-a-s1 demo-inventory
```

Recall returns a bounded capsule: the matching event ids
(`delivered_event_ids`) and short excerpts, cut after roughly 90 characters,
without the author. `--context-limit` bounds the whole capsule, not each
excerpt. Use recall to find out which events matter. The capsule text is
evidence, never instructions or authority.

For the complete record — full summary, actor, session and all details — take
a catalog snapshot (next section) and read from it.

## 6. Take a snapshot and read an event in full

`guardian seed-sync` copies every event from the running runtime into a
separate catalog file. It needs the runtime's reader token in the
`CODEX_LOG_TOKEN` environment variable. Hand the token to this one command
only:

```bash
SNAP="$BASE/snapshots/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$SNAP"
CODEX_LOG_TOKEN="$(cat "$INTEGRITY_SEED_HOME/runtime/token")" "$GUARDIAN" seed-sync \
  --catalog "$SNAP/seed-catalog.sqlite3" \
  --source-url "http://127.0.0.1:$PORT" \
  --export-events "$SNAP/events.jsonl"
```

The `VAR="$(cat …)" command` form puts the token into that command's
environment only. It is not printed, not exported to the shell, and not
written anywhere. Do not `echo` or `export` it, and do not paste it into
scripts, notes or reports. The token file belongs to the runtime; the token
and the port can both change after a restart, so read them fresh every time.

A good snapshot report has `"result": "PASS"`, `"full_snapshot": true` and
`"missing_event_id_count": 0`, and its `maximum_event_id` equals the `events`
count of `status`. Then read:

```bash
"$GUARDIAN" seed-search --catalog "$SNAP/seed-catalog.sqlite3" --query demo-inventory
"$GUARDIAN" seed-connections --catalog "$SNAP/seed-catalog.sqlite3" --event-id 1 --include-contextual
```

- `seed-search` returns the matching events with their full summaries and
  `actor`.
- `seed-connections` shows one event in full with its task and its links to
  earlier and later events of the same task.
- `events.jsonl`, written by `--export-events`, holds every event exactly as
  stored, one JSON object per line, including `session_id` and `details`.

## 7. Refresh the snapshot after new writes

A snapshot is a point-in-time copy. Events recorded after `seed-sync` ran are
not in it. After any new `remember`, run section 6 again, into a new directory
or into the same catalog path (then only the new events are fetched). Before
you trust a read, compare the snapshot's `maximum_event_id` with the current
`events` count from `status`.

## 8. A second agent continues the task

The second agent works on the same machine, with the same
`INTEGRITY_SEED_HOME`, **after** the first one has finished writing:

1. Set the variables from section 2 in its own terminal.
2. `"$PY" "$SEED" setup --json` resumes the runtime, or starts it again after a
   stop, with the stored events.
3. `"$PY" "$SEED" recall --session-id agent-b-s1 demo-inventory` finds the
   handoff.
4. Take a fresh snapshot (section 6) when it needs the full text of an event.
5. Record its result under the same `task_id` with its own name:

   ```bash
   "$PY" "$SEED" remember --task-id demo-inventory --actor agent-b --session-id agent-b-s1 \
     "Ceramic insulators: 9 crates delivered on 2026-09-24 (source docs/c-ceramics.txt)."
   ```

The first agent, or any later one, then takes a new snapshot and reads the new
event with `seed-search` or `seed-connections --event-id <id>`.

Agents take turns: one finishes writing before the next starts. Integrity does
not stop two agents from writing to the same task at the same time.

## 9. Stop the runtime and keep the data

```bash
"$PY" "$SEED" stop --json
```

The reply shows `"database_preserved": true`. The events stay in
`$INTEGRITY_SEED_HOME/data/action-log.sqlite3`, and `setup` brings them back.
To back up the memory, copy the whole `INTEGRITY_SEED_HOME` directory while
the runtime is stopped. Snapshots are derived copies and can be deleted at any
time. Deleting `INTEGRITY_SEED_HOME` deletes the memory.

## What the metadata means

Each event carries `details.truth_status` and `details.verification`. They are
values the writing client declares:

- `truth_status` defaults to `reported`; a client can set `observed` when it
  saw the fact itself.
- `verification` defaults to `pending`; a client can set `verified`.

Neither value is checked by the runtime. The word "verified" inside a summary,
or `--verification verified`, is the writer's claim, not independent
verification. A closure receipt, which the CLI returns for an `observed` +
`verified` handoff, checkpoint, completion, blocked or failure record written
inside a session with Seed hooks, is signed with the same local runtime token
every client uses. It binds the record to that session; it does not show that
someone else checked the result. Independent verification in Integrity means
a separate observer's evidence (see [ARCHITECTURE.md](../../../../ARCHITECTURE.md)),
which this path does not produce.

## Limits

These limits were confirmed in local testing:

- **One machine.** The runtime listens only on loopback. No network or
  cross-machine transport ships with this path.
- **Sequential work.** Agents must take turns. Parallel writes to one task are
  accepted without a warning, and lock events recorded with `remember` do not
  block writes.
- **Declared identity.** `--actor` and `--session-id` are free strings. The
  runtime authenticates only the shared token of the state directory, so any
  client with access to it can write under any name.
- **No proven coordination.** Concurrent or cross-machine coordination is not
  provided or claimed.
- **Shared OS user.** The state files are private to your OS user, and every
  process running as that user can read and write the memory.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `{"ok": false, "error": "RuntimeError"}` from `setup` or `status` | `INTEGRITY_SEED_HOME` is inside the current Git checkout or working directory, or holds unrelated files. Use a new, dedicated directory. |
| `Seed Action Log authentication token is required` | `seed-sync` ran without `CODEX_LOG_TOKEN`. Use the one-command form in section 6. |
| `Connection refused` from `seed-sync` | The runtime is stopped or `--source-url` is wrong. Without `--source-url`, `seed-sync` uses port 8765, not your runtime. Run `setup`, then read `PORT` again. |
| An event you just wrote is missing from `seed-search` | The snapshot is older than the write. Run `seed-sync` again (section 7). |
