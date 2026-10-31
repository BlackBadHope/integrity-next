"""Explicit owner configuration. Importing this module performs no I/O."""
from __future__ import annotations
import json
import os
from pathlib import Path

COMPONENT = 'integrity-memory-plane'
ENVIRONMENT = 'INTEGRITY_MEMORY_PLANE_CONFIG'
SCHEMA = "integrity/component-config/v1"

class ConfigurationError(ValueError):
    """The component has no complete owner configuration."""

def read_config(path=None):
    path = path or os.environ.get(ENVIRONMENT)
    if not path:
        raise ConfigurationError(COMPONENT + ": unconfigured; set " + ENVIRONMENT)
    source = Path(path)
    if not source.is_absolute() or source.is_symlink() or not source.is_file():
        raise ConfigurationError(COMPONENT + ": configuration must be an absolute regular file")
    if source.stat().st_size > 1024 * 1024:
        raise ConfigurationError(COMPONENT + ": configuration exceeds size bound")
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise ConfigurationError(COMPONENT + ": invalid configuration JSON") from None
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise ConfigurationError(COMPONENT + ": configuration schema mismatch")
    if document.get("component") != COMPONENT or document.get("configured") is not True:
        raise ConfigurationError(COMPONENT + ": unconfigured or component mismatch")
    values = document.get("values", {})
    if not isinstance(values, dict) or any(not isinstance(k, str) for k in values):
        raise ConfigurationError(COMPONENT + ": values must be an object")
    if document.get("guardian_version") != "6.1.0" or document.get("memory_api_version") != "2.11.0":
        raise ConfigurationError(COMPONENT + ": expected Guardian 6.1.0 / memory API 2.11.0")
    return document

def require_config(path=None):
    return read_config(path)

def value(name):
    values = read_config().get("values", {})
    result = values.get(name)
    if not isinstance(result, str) or not result.strip() or "\x00" in result:
        raise ConfigurationError(COMPONENT + ": own configuration value required: " + name)
    return result

def configured_command(preferred, legacy):
    import warnings
    values = read_config().get("values", {})
    current = values.get(preferred)
    if isinstance(current, str) and current.strip() and "\x00" not in current:
        return current
    previous = values.get(legacy)
    if isinstance(previous, str) and previous.strip() and "\x00" not in previous:
        warnings.warn(legacy + " is deprecated; use " + preferred, DeprecationWarning, stacklevel=2)
        return previous
    raise ConfigurationError(COMPONENT + ": own configuration value required: " + preferred)
