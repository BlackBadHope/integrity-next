# Integrity Adapter SDK

`integrity-adapter-sdk` is the separately versioned distribution boundary for
the Integrity Adapter Execution SDK. Source candidate `2.0.0rc1` is deliberately a
transitional facade over the exact `integrity-guardian==6.0.0` implementation.
It does not copy files into the `integrity_guardian` import tree and does not
fork Seed, Synapse, authority, outcome, custody or project memory.

The package version and signed document protocol are different identities:

- package version: `2.0.0rc1`;
- signed document protocol value: `ADAPTER_SDK_VERSION == "1.0.0a2"`.

Changing the package version must not silently invalidate retained signed
documents. Extracting the implementation from Guardian into this distribution
is reserved for a later major compatibility boundary.

## Transitional facade

The facade is lazy. Importing package metadata does not import an execution
adapter. Accessing a facade module first verifies the exact installed Guardian
distribution version, every Guardian package file against its `RECORD`, the
complete canonical package-tree digest in the embedded immutable
`guardian-origin.json`, and the `PathFinder` origin of the package and requested
module. A same-version counterfeit distribution, a higher-priority import path
or an already-loaded module from another origin fails closed before
`import_module`. A serialized, narrow MetaPath loader compiles the retained
verified source snapshot directly for every Guardian module, so pip-created or
external bytecode caches are never an executable source for the facade.

```python
import integrity_adapter_sdk as sdk

sdk.require_guardian()
manifest_api = sdk.adapter_sdk
runtime_api = sdk.adapter_runtime
```

The runtime facade includes the coordinator-signed durable dispatch registry.
Each signed envelope is claimed once against an exact attempt-store digest and
journal/checkpoint key fingerprints; permit consumption is persisted before an
executor can reach its sink. A caller-selected alternate journal is not a new
authority namespace.

The available module attributes are listed in `sdk.FACADE_MODULES`. The package
does not grant authority, issue an a13 grant, replace the independent a14
observer, provide credentials or make an unknown outcome retryable.

## Candidate support contract

`adapter-execution-sdk-lts` is a separate LTS candidate track. It is not Stable
and does not activate a support clock. Its machine-readable contract is shipped
at `integrity_adapter_sdk/contracts/adapter-execution-sdk-lts.json`.

The current Linux/client/Windows deployment cohort is not the existing M8
Linux/Windows/macOS portability triad. Package installation evidence must not
be promoted into an M8 claim.

The `windows_bounded_process_adapter` facade exposes the truthful Win32 Job
Object boundary. It contains the process tree but does not claim network,
filesystem-write or Home isolation.

## Provenance-bound reproducible release gate

Build and test tools are exact and hash-pinned in `requirements/ci.lock.txt`.
The PEP 517 backend requirements are exact in `pyproject.toml`. The release
gate requires an exact full Git commit and the SHA-256 of its deterministic
`git archive`. It materializes the component from that commit's Git object
archive, never from mutable worktree bytes. Only then does it check the exact
source allowlist and copy the frozen component into two clean directories,
sets a fixed `SOURCE_DATE_EPOCH` and builds both artifacts twice. It accepts
the result only when the wheel and sdist are byte-identical across both builds.
Because the setuptools sdist backend writes wall-clock ownership, timestamp and
gzip metadata, the gate canonicalizes those transport-only tar fields and the
gzip header to the declared epoch before verification and digest comparison.
Member names and bytes are unchanged.

Both verifiers operate without extracting the archive. They reject unsafe or
duplicate paths, links and special files, excessive archive expansion,
unowned paths and every `integrity_guardian/**` member. They also require exact
package metadata, the exact `integrity-guardian==6.0.0` dependency, the
ownership/LTS contracts and complete content hashes in wheel `RECORD`.
The wheel and sdist must also carry the exact Guardian origin manifest used by
the runtime facade; artifact verification rejects any drift in its protocol,
version, file count or tree digest.

From this component directory, compute the identity outside the package build
and pass both values explicitly:

```bash
PYTHONPATH=src python -m pytest
revision="$(git -C ../.. rev-parse HEAD)"
git -C ../.. archive --format=tar --output=/tmp/integrity-sdk-source.tar "$revision"
source_tree_sha256="sha256:$(sha256sum /tmp/integrity-sdk-source.tar | cut -d ' ' -f 1)"
python tools/run_packaging_gate.py \
  --repository-root ../.. \
  --source-revision "$revision" \
  --source-tree-sha256 "$source_tree_sha256"
```

To retain the two verified artifacts, pass an empty output directory:

```bash
python tools/run_packaging_gate.py \
  --repository-root ../.. \
  --source-revision "$revision" \
  --source-tree-sha256 "$source_tree_sha256" \
  --output-dir dist
```

The canonical package-gate `/v2` result and exact-stack inventory `/v2` retain
the revision, repository tree object ID and source-tree SHA-256 alongside the
artifact digests. Reproducibility without that source identity is not release
evidence.

The verified Guardian loader also supplies a read-only `TraversableResources`
view backed only by the already verified byte snapshot. Nested package resources
such as schemas never fall back to `__file__`, `sys.path` or a second disk read.
After installing an exact Guardian/SDK pair, run
`python tools/verified_resources_smoke.py` in a fresh process to load every
registered Guardian schema and reject an unknown resource.

The dedicated component CI performs the same gate on Linux and Windows. It
also builds Guardian RC16 from the same checkout, installs the two exact wheels
into a clean virtual environment, verifies the combined immutable wheel
inventory and loads every facade module plus the packaged LTS contract. This is
package compatibility evidence; it is not native host lifecycle evidence and
grants no production authority.
