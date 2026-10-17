# Canonical source layout and historical profiles

This directory is source-layout metadata, not a Python distribution or an
installer. Guardian 6.1.0 uses one canonical implementation under
[`src/integrity_guardian`](../../src/integrity_guardian). Integrations have their
own package trees and unique import namespaces; see the root
[component catalogue](../../COMPONENTS.json) and [component table](../../README.md#components).

Earlier public snapshots retained copied kernels, SDK code, hooks and service
scripts under `sources/`. Those duplicate runtime groups were consolidated into
their canonical package locations. Distinct client profiles and plugin
interfaces remain where their contracts differ; they are not arbitrarily
renamed to the Guardian release version.

## Retained metadata

[VARIANTS.json](VARIANTS.json) records canonical source roots, retired duplicate
groups and the two retained historical LTS matrices under `profiles/`.
The matrices describe historical core/client cohorts; a reference shared by
two old profiles is one metadata file, not two runtime copies. They are not
current install constraints, deployment activation or proof of live acceptance.

Active distribution versions and dependencies come from package metadata and
[COMPONENTS.json](../../COMPONENTS.json). The SDK's current origin binding is
derived from canonical Guardian package bytes. Historical signed deployment
and replay contracts retain their original pins and are not rewritten by a
source release.

## Verification

From the repository root, after installing the development dependencies:

```sh
python .github/scripts/component_catalog.py
python components/integrity-installed-runtime/verify_sources.py
python .github/scripts/public_surface_check.py
```

The catalogue check rejects stale versions/origin metadata, incompatible local
dependencies, missing license files and colliding import namespaces. The source
verifier checks canonical files against the closed public manifest, including
size, digest, path custody and executable mode. Git index modes are used on
Windows; POSIX filesystem modes are checked where supported. The privacy and
manifest gate remains separate and rejects unlisted source files.

None of these checks installs a hook, opens a service, initializes a database
or confers authority over an external target. Configure a deployment from your
own identities, paths, endpoints and trust material, outside the source tree.
No maintainer connection, route catalogue, credential, user context or runtime
state is included.
