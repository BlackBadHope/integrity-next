# Public source boundary

This repository is a fresh-history, deny-by-default public source projection of
Integrity. It intentionally omits customer data, operational
endpoints, topology, credentials, deployment overlays, retained private
evidence and private collaboration history.

Every selected file is bound by `PUBLIC-EXPORT-MANIFEST.json`. Public CI rejects
extra files, missing files and content substitution before running the package
tests. Integrity source is independently licensed under Apache-2.0, with
third-party notices retained as described in [LICENSES.md](LICENSES.md). Access
to a private development repository is neither required nor implied.

Issues and pull requests are welcome in this public repository. Maintainers are
responsible for reconciling accepted public changes with the canonical tree and
regenerating the closed projection. Contributors do not need access to private
infrastructure.

This source release is for environments that users own or control. It includes
the portable Guardian implementation without target-specific route aliases.
It does not inherit
credentials, host bindings, signatures or authority over maintainer systems;
users configure those boundaries for their own deployments.
