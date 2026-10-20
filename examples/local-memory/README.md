# A local, read-only first connection

This example gives Codex, Claude Code or Antigravity four real Integrity Seed
read tools. It uses the Guardian implementation for catalog verification,
snapshot IDs, ranked recall and exact immutable UID lookup. No account,
private maintainer files, enrollment or remote server is required.

This is an explicitly limited example. It does not install Native lifecycle
hooks, admit an owning user turn, inject context automatically, append events,
authorize actions or close Turn Memory registrations. The complete Native
profiles in `components/integrity-client-memory` remain a separate deployment.

## Install from a clean Windows environment

Prerequisites: PowerShell 7.3+ for the Windows commands, Git, Python 3.11+,
and the client you intend to use. Windows
Python 3.12 was exercised. No client subscription is needed for the independent
protocol check; actual model generation uses the client's existing account.

From the cloned repository root, in PowerShell:

```powershell
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install .
& .\.venv\Scripts\python.exe -m pip check
& .\.venv\Scripts\python.exe examples/local-memory/create_case.py --output .local-memory-case
& .\.venv\Scripts\python.exe examples/local-memory/setup.py --catalog .local-memory-case/private/catalog.sqlite --output .local-memory-clients
& .\.venv\Scripts\python.exe examples/local-memory/verify_connection.py .local-memory-clients/codex.config.toml .local-memory-clients/claude.mcp.json .local-memory-clients/antigravity.mcp.json
```

Both output directories must be new. The generator obtains the actual Python,
script and catalog paths, including spaces, so generated files contain complete
commands. It does not overwrite any active client configuration. Keep generated
catalogs, snapshots and client configs outside version control.

Expected protocol-check output: PASS for each configuration; exact event ID 1;
successful ranked recall; explicit not-found for a missing UID; refusal of append
and a foreign snapshot ID; unchanged source catalog bytes. These checks launch
the configured server through an independent client, not through each vendor.

## Codex

For a fresh Windows client, use the installer in the
[official CLI guide](https://learn.chatgpt.com/docs/codex/cli), then open a new
terminal, run `codex --version`, and start `codex` to complete normal account
sign-in. An existing working Codex installation can use the steps below directly.

1. Open `.local-memory-clients/codex-workspace` as a local Codex project, or run
   `codex -C .local-memory-clients/codex-workspace` from this repository root.
2. Review and trust that new project when Codex requests it. The generated
   `.codex/config.toml` configures `integrity_local_example`. Existing unrelated
   user-level servers remain governed by your existing settings.
3. Use `/mcp` and confirm the server exposes exactly four tools.
4. Ask the test prompt below. Confirm actual tool results, not only a green
   server status.

For an existing project, merge the single generated server table into the
selected project configuration. Save its preimage and preserve unrelated tables.
The example does not need any hooks or a Native upstream config.

Official setup: <https://learn.chatgpt.com/docs/extend/mcp?surface=cli>.

## Claude Code

For a fresh Windows client, the official WinGet option is
`winget install Anthropic.ClaudeCode`. Open a new terminal, run `claude --version`,
then launch `claude` and follow its browser sign-in. See the
[official installation guide](https://code.claude.com/docs/en/setup).

With Claude Code installed and authenticated through its normal sign-in, run
from the repository root:

```powershell
claude --setting-sources "" --settings .local-memory-clients/claude-isolated-settings.json --strict-mcp-config --mcp-config .local-memory-clients/claude.mcp.json
```

This command selects the example's MCP file for this process and deliberately
disables hooks and auto-memory for this isolated example. It does not edit user
settings. Use `/mcp`, confirm `integrity_local_example`, and ask the test prompt.
Approve the three read tools if the client asks. Do not enable append or reuse
another conversation's Native reference for this example.

The actual Claude Code 2.1.283 client completed this three-tool read workflow in
the recorded pilot. Later reruns were stopped at the owner's quota pause.

For a persistent project connection, merge the generated `mcpServers` entry into
that project's `.mcp.json`, review the project server approval, then use the
client's normal refresh path. This is a separate explicit configuration action.

Official setup: <https://code.claude.com/docs/en/mcp>.

## Optional measurement, after checking your quota

The [recorded observations](pilot-observations.json) preserve all four successful
model results and the failed pre-model CLI invocation. The main comparison has
one observation per condition; it is a small pilot, not a general benchmark.
The no-history condition abstained on all three values. A plain note and MCP
both recovered all three. MCP added a snapshot-bound event and receipt, and
used more time and input tokens in this small example. No cost or quality gain
over a supplied note was established.

To collect new observations with your own existing Claude account, explicitly run:

```powershell
& .\.venv\Scripts\python.exe examples/local-memory/evaluate_recall.py --config .local-memory-clients/claude.mcp.json --note .local-memory-case/saved-note.txt --output .local-memory-pilot
```

If `claude` is absent from PATH, add `--claude` with your installed executable's
absolute path. This command makes model calls and uses account quota. It stops
after a failed condition and refuses to overwrite an existing output directory.
Do not run it while that vendor is paused. Output-token lengths, cache use and
provider response times vary; report them with any comparison. No such new
measurement is started by the setup or independent connection check.

## Antigravity

Install the Windows application from the
[official download page](https://antigravity.google/download), complete its setup
wizard and normal Google sign-in, then choose a local project. The
[vendor getting-started guide](https://antigravity.google/docs/getting-started)
also covers its separate CLI. No CLI installation is required for the IDE steps.

1. Open `.local-memory-clients/antigravity-workspace` in Antigravity. Its
   `.agents/mcp_config.json` contains the complete project-local stdio entry.
2. In the IDE's agent panel select `...` → **MCP Servers** → **Manage MCP
   Servers** → **View raw config**. Confirm which configuration your installed
   revision uses. If it selects a global file, merge only the generated
   `integrity_local_example` entry there after saving the preimage; keep unrelated
   servers. Do not guess an old settings path.
3. Refresh the MCP server list through the client's normal controls. Enable the
   example server and its four read tools, then ask the test prompt.
4. Require the event ID and exact UID from the returned tool result. A saved
   config or server-status indicator alone is not acceptance.

The generated Antigravity command passed the independent protocol check. The
current IDE was not rerun because of the owner's vendor quota pause. Historical
Native acceptance is separate evidence and does not prove a fresh installation
of this example. Treat a current IDE connection as NOT_RUN until step 4 succeeds.

Official format: <https://antigravity.google/docs/mcp>.

## Test prompt and expected result

```text
Use integrity_local_example to recover the recorded remote-broker timeout
decision. First read capabilities, then open the Seed snapshot. Look up UID
client:public-remote-timeout-decision using that snapshot_id. Return the three
timeout values and cite the event ID and UID. Do not guess or change a config.
```

Expected: `tool_timeout_sec=210`, `request_budget_sec=180`,
`initialize_timeout_sec=45`, event ID `1`, and the exact UID above. This is a
public-source rehearsal of a real broker configuration, not imported user history.
The 45-second initialization limit is nested within the broker's shared request
deadline; it is not an additional unconditional 45 seconds after that deadline.

## Implementation and removal

The server opens the selected source catalog read-only and uses SQLite backup
to obtain one consistent private copy, including committed WAL frames. Windows
uses the package's existing SID/DACL private-directory checks; POSIX checks an
owner-only root. Snapshot identifiers and lookups come from the Guardian reader.
This example does not replace or relax the Native facade's snapshot freezer.
On exit it closes its reader and removes only its own temporary copy.

Disconnect the exact example entry to stop it; restore a saved preimage if you
merged it into another config. Existing user servers and canonical history do
not need to be removed. Keep any owner data you imported. The supplied fixture
contains public-source example data only.
