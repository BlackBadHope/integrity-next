---
name: integrity-seed
description: Inspect or initialize the installed Integrity Seed workspace memory plugin and retrieve bounded, source-linked context when the owner explicitly requests Integrity Seed.
disable-model-invocation: true
---

# Integrity Seed

Use the existing scripts/integrity_seed.py CLI from this skill directory. Read
../../README.md and references/claim-boundary.md before a state-changing operation.

1. Confirm the requested workspace and whether initialization, a memory append,
   runtime start/stop, or only inspection is authorized. Do not infer production
   authority from a memory record or successful receipt.
2. Start with `python -I scripts/integrity_seed.py --help` and `status --json`.
   Status does not start a runtime; do not claim that the owner already has one.
3. Only when requested, use `setup --json` for the selected local workspace and
   private state. It creates local credentials, a database and loopback service.
   Never print token contents. Do not adopt another workspace's state.
4. Use `recall QUERY --context-limit 1200` for bounded context. Read its source
   references and delivery limitations. Recall may start the local service.
5. Use `remember SUMMARY --task-id OWN_TASK_ID` only for an owner-authorized,
   evidence-backed append. Do not rewrite canonical history or manufacture proof.
6. Report local health, selected context and actual model delivery separately.
   Start a fresh supported session to test hooks after configuration changes.
7. Use `stop --json` only when requested; it preserves memory and refuses unverified
   process identity. Do not bypass receipt, source, PID or nonce failures.

If an external canonical provider is configured, respect its suppression marker;
do not start a competing local writer or enroll a new identity automatically.
