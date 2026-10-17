"""Runtime state paths for both a source checkout and an installed wheel."""

from __future__ import annotations

import os
from pathlib import Path


STATE_ROOT_ENV = "INTEGRITY_HOME_STATE_ROOT"


def _platform_name() -> str:
    """Return the local path platform through a narrow, testable seam."""

    return os.name


def state_root() -> Path:
    override = os.environ.get(STATE_ROOT_ENV)
    if override is not None:
        if not override.strip():
            raise ValueError(f"{STATE_ROOT_ENV} must not be empty")
        return Path(override).expanduser().resolve()
    if _platform_name() == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / "IntegrityHome"
    xdg_state = os.environ.get("XDG_STATE_HOME")
    if xdg_state:
        return Path(xdg_state) / "integrity-home"
    return Path.home() / ".local" / "state" / "integrity-home"


def state_path(*parts: str) -> Path:
    return state_root().joinpath(*parts)


__all__ = ["STATE_ROOT_ENV", "state_path", "state_root"]
