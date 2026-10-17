"""Optional, owner-local navigation catalogue; disabled in every public profile."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from .configuration import ConfigurationError, read_config


def _private_custody(path):
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode) or path.is_symlink():
        raise ConfigurationError("owner catalogue custody invalid")
    if os.name == "posix":
        if details.st_uid not in {0, os.geteuid()} or stat.S_IMODE(details.st_mode) & 0o077:
            raise ConfigurationError("owner catalogue requires private owner custody")
    elif os.name == "nt":
        # Ask Windows for effective ACL metadata. Do not parse localized icacls
        # strings or trust the catalogue's own claim about its permissions.
        script = r'''
$ErrorActionPreference='Stop'
$a=Get-Acl -LiteralPath $env:INTEGRITY_CATALOGUE_CHECK_PATH
$u=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$trusted=@($u,'S-1-5-18','S-1-5-32-544')
$owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value
$rules=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
$ok=($owner -in $trusted) -and ($rules.Count -gt 0)
foreach($rule in $rules){
 if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
    $rule.IdentityReference.Value -notin $trusted){$ok=$false}
}
if(-not $ok){exit 3}
'''
        environment = dict(os.environ, INTEGRITY_CATALOGUE_CHECK_PATH=str(path))
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        result = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                                env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=10,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode:
            raise ConfigurationError("owner catalogue Windows ACL custody rejected")
    else:
        raise ConfigurationError("owner catalogue custody unsupported on this platform")


def load_owner_catalogue(default):
    """Read a fresh owner-selected digest-bound catalogue, retaining route guards."""
    document = read_config()
    selected = document.get("owner_local_catalogue")
    if selected is None:
        return {**default, "paths": []}
    if not isinstance(selected, dict) or set(selected) != {"path", "sha256", "host_id"}:
        raise ConfigurationError("owner catalogue binding invalid")
    path, digest = selected.get("path"), selected.get("sha256")
    if (not isinstance(path, str) or not Path(path).is_absolute()
            or not isinstance(digest, str) or re.fullmatch(r"[a-f0-9]{64}", digest) is None):
        raise ConfigurationError("owner catalogue explicit path and source digest required")
    path = Path(path)
    _private_custody(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        data = stream.read(256 * 1024 + 1)
        after = os.fstat(stream.fileno())
    if (len(data) > 256 * 1024 or hashlib.sha256(data).hexdigest() != digest
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
               != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise ConfigurationError("owner catalogue source digest or readback mismatch")
    catalogue = json.loads(data)
    if (not isinstance(catalogue, dict)
            or catalogue.get("protocol") != default["protocol"]
            or catalogue.get("host") != selected["host_id"]
            or catalogue.get("production_authority") is not False
            or not isinstance(catalogue.get("paths"), list)):
        raise ConfigurationError("owner catalogue shape or authority invalid")
    # Navigator still validates routes, Native bindings, hashes and closure.
    # This loader grants no target-action authority and never executes a recipe.
    return catalogue
