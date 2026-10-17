"""Public Integrity Home namespace.

The implementation remains in :mod:`integrity_chronicle` during the alpha
rename. This module deliberately re-exports its explicit public API so callers
can migrate while older Chronicle artifacts remain explicitly versioned.
"""

from importlib.metadata import PackageNotFoundError, version

from integrity_chronicle import *  # noqa: F401,F403
from integrity_chronicle import __all__ as _chronicle_public_api


try:
    __version__ = version("integrity-home")
except PackageNotFoundError:
    # Source-tree execution has no installed distribution metadata.
    __version__ = "0.2.0a1"


__all__ = [*_chronicle_public_api, "__version__"]
