"""Private-memory resources are the 0.8.0 lineage.

``resources/hub`` remains a script entrypoint for existing manifests. New
transport policy lives in :mod:`integrity_bridges.transports` and both host
hubs call it.
"""

LINEAGE = "0.8.0"
CANONICAL_RESOURCES = "resources/private-memory"
COMPAT_RESOURCES = "resources/hub"
