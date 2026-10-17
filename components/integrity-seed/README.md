# Integrity Seed public source component

This is the independently packaged Codex Seed plugin, distinct from the full
integrity-action-log distribution. Plugin metadata is 0.1.14; its bundled stdlib
runtime is 0.1.4. Their version numbers are independent. The metadata license is
Apache-2.0, matching both existing LICENSE files; no external license was changed.
The package contains no user context, keys, live identity or retained state.

Current source-only artifact build, from this directory:

```sh
python build_release.py --repo . --release-dir OWN_NEW_RELEASE_DIRECTORY --version 0.1.14 --candidate source
python verify_public_surface.py
```

The explicit PACKAGE_ALLOWLIST.txt lists actual public plugin source and generic
usage/skill documentation. It excludes unavailable test copies and all retained
state. Release output must be outside this source tree and in a new directory.
The builder performs source privacy validation, deterministic member hashing and
writes an immutable archive plus source manifest. The public-surface verifier
retains its original privacy, dependency-boundary and state-exclusion checks.
Use the root project's current tests for runtime acceptance; source packaging does
not prove live hook delivery. See plugins/integrity-seed/README.md for local setup.

Historical 0.1.13-rc26 verification remains exact: verify_seed.py and judge_demo.py
retain their original release/version/candidate expectations. The original
PACKAGE_ALLOWLIST bytes are preserved at profiles/0.1.13-rc26/PACKAGE_ALLOWLIST.txt;
verify_seed.py compares that historical list. The old archive and signed evidence
are not reconstructed or rewritten. Historical archive verification is NOT_RUN
unless the exact original release archive, manifest and tests are supplied.
