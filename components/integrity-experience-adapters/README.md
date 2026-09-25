# Integrity Experience Adapters — 0.1.0rc3

**September integration successor — ChangeIntent #201.** See UPDATE-RC.md (not included in public source) for fixes, journal compatibility and exact evidence boundaries. Original RC evidence is historical, not a claim about this successor.

Optional, separately packaged release candidate in the canonical Integrity
monorepo. Implements ChangeIntent #197 and its RC2 extension on draft PR #198.
Predecessor: `b2e85a73ce8b8caf152663498d52c75ffd0d9ac6`.
Guardian `5.5.1rc16`, Seed, the Adapter SDK and LTS identities are unchanged.

RC1 supplied offline contracts. **RC2 adds concrete host-side backends**, without
an automatic server, model download, credential lookup, independent permission
issuer or canonical memory writer. These are callable implementations, not a
claim that every external model/provider/host has been admitted and tested.

## What works and what was exercised

| Family | RC2 implementation | Evidence boundary |
|---|---|---|
| Contract-preserving migration | Typed-JSON parity, six-role plan, `audit_changed_paths` binds actual changed paths to the retained contract | Actual synthetic Git objects and negative scope tests; not an OS lease manager or a three-language port |
| Local transcription | `LocalWhisper` loads a complete SHA-bound local model bundle into faster-whisper, accepts bounded PCM and consumes segment output | Model-loading API tested through a mock seam; actual neural ASR inference is **not tested** |
| MCP tools | Real bounded stdio MCP client, initialize/list/call, frame and deadline limits, no automatic retry | Actual synthetic subprocess exchanges; **2025-11-25 compatibility only**, not a second MCP host or 2026 conformance claim |
| Realtime voice | `VoiceBroker` authenticated WSGI endpoint, exact SDP binding, one-use request cache; `OpenAIWebRTC` server-side SDP exchange; browser client | Real WSGI logic and browser control flow; HTTP provider, microphone and peer are mocked; no live API call |
| Release preparation | `git_inventory` reads and hashes exact Git objects, ignoring dirty worktree bytes | Actual Git regression; no owner signature or Stable promotion |
| Speech synthesis | `synthesize_espeak` produces local stock-voice WAV using explicit admitted executable | Actual eSpeak English synthesis, WAV decoding and output hashes on Linux; Ukrainian/neural TTS quality not measured |
| Generated UI | Inert static preview, attributes removed, active/unknown markup escaped, restrictive iframe/CSP | Actual Chromium DOM/no-request regressions; no active JS/React execution and no OS sandbox certificate |
| Model capacity | Architecture-dependent weight and KV-cache estimate | Arithmetic and failure tests; no GPU measurement or admission guarantee |
| Companion | Original deterministic sprite, actual image decode/dimension validation, metadata stripping, static CSS animation | Actual Pillow and Chromium, including reduced-motion behavior; no borrowed assets or executable event hooks |

See RC2 runtime and acceptance notes (not included in public source) for exact interfaces,
security boundaries, deployment prerequisites and the test/claim matrix.
`coverage.json` preserves all nine reference families and distinguishes code
implementation, synthetic testing and missing live acceptance.

## Offline suite

Python 3.11+; no third-party runtime dependency is required for the default
suite. From this component directory on POSIX or native Windows PowerShell:

```text
python tools/run_checks.py
```

This runs contract tests plus actual synthetic stdio and Git tests. The optional
model, provider and image/browser libraries are not silently downloaded.

The separate voice lifecycle gate uses an already installed Node.js 20 or newer:
`node --test tests/test_voice_client.mjs`. CI runs this on both declared hosts.
It exercises setup/session timers with synthetic media, peer, admission and fetch
fixtures; it performs no recording, network request or provider call. Missing
Node.js fails this gate rather than skipping it or installing dependencies.

The retained CLI remains offline. Set `PYTHONPATH=src` on POSIX or
`$env:PYTHONPATH = 'src'` in PowerShell, then:

```text
python -m integrity_experience_adapters capabilities
python -m integrity_experience_adapters memory-estimate fixtures/memory.json
python -m integrity_experience_adapters transcript fixtures/transcript.json
python -m integrity_experience_adapters workplan fixtures/workplan.json
python -m integrity_experience_adapters parity expected.json actual.json
python -m integrity_experience_adapters preview candidate.html
```

Exit codes: 0 accepted offline transform, 1 parity mismatch, 2 rejected input.
None of those codes or JSON envelopes authorizes an external operation.
`capabilities` explicitly describes the **offline contract API**, lists the
optional host runtime modules separately, and reports no runtime admission.

## Optional integrations

From a host that already has Pillow, Playwright, Chromium and eSpeak installed:

```text
python tools/run_integration.py --output /absolute/path/to/empty-test-output
```

This explicitly generates synthetic local audio and an original decorative
sprite. It does not record a microphone, download weights or call a provider.
The browser harness uses `set_content` because the current development browser
blocks navigation to local/fixture URLs. Voice-client fetch, crypto, microphone
and peer are declared test bridges; static markup and image rendering use the
real browser engine. Missing optional tools fail the gate, not a skipped pass.
Use an empty output directory for each run; reports contain output hashes.

Optional wheel extras pin their direct packages: `images` uses Pillow 12.3.0,
`asr` uses faster-whisper 1.2.1, and `browser-tests` uses Playwright 1.57.0 and
Pillow. These are **not complete transitive hash locks**. An admitted host still
needs its own exact runtime inventory and platform checks. No runtime dependency
is added to Guardian. The wheel includes `static/voice.mjs` and uses the existing
Apache-2.0 license; external packages, binaries and weights are
not bundled.

## Authority and release boundaries

Host execution follows the existing signed Adapter SDK lifecycle.
`GuardianDispatch` requires the exact installed SDK facade, the existing full
execution-envelope verifier and a real durable `AdapterDispatchPermit`; it
binds the input and configuration before consuming the permit and calling the
host-selected sink. It does not mint a grant, pick a trusted key, enforce OS
containment or produce an independent witness. There is no missing-SDK fallback.

Low-level media/MCP/provider functions are host-side sinks. Direct Python access
to a sink is not a permission system. Do not expose raw sinks or broker `bind`
over an unauthenticated endpoint. Keys, grants, conformance policy, executable
custody and sink identity belong to the trusted coordinator, not request JSON.

PR #198 stays draft. No main merge, release tag, public publication, signing,
Stable/LTS activation, production deployment, paid model review or canonical
Action Log receipt is performed by this candidate. Historical RC1 evidence is
retained unchanged; RC2 reports are separate. Closing the uninstalled draft is
rollback, not successful implementation or certification.
