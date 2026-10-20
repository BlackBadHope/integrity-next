"""Read-only custody checks for explicitly preserved Native profile directories."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess


def absolute_root(value):
    path = Path(value)
    if (not path.is_absolute() or str(path).startswith(("\\\\", "//"))
            or any(part in {".", ".."} or part.endswith((" ", ".")) for part in path.parts[1:])):
        raise ValueError("explicit local absolute directory required")
    return Path(os.path.abspath(path))


def lineage(path):
    result = []
    for member in (path, *path.parents):
        details = member.lstat()
        if (member.is_symlink() or getattr(details, "st_file_attributes", 0) & 0x400
                or not stat.S_ISDIR(details.st_mode)):
            raise ValueError("explicit directory ancestry custody invalid")
        result.append((str(member), details.st_dev, details.st_ino, details.st_mode))
    return result


def _windows_custody(path):
    # This inspects ACL metadata only; no directory contents, protected state,
    # enrollment, credentials, or key material is opened or modified.
    script = r'''
$ErrorActionPreference='Stop'
$a=Get-Acl -LiteralPath $env:INTEGRITY_PROFILE_ROOT_AUDIT
$u=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$owner=$a.GetOwner([Security.Principal.SecurityIdentifier]).Value
$allowed=@($u,'S-1-5-18','S-1-5-32-544','S-1-3-4')
$rules=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
$ok=($owner -eq $u) -and ($rules.Count -gt 0)
$ownAllow=$false
foreach($rule in $rules){
 if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow){
  if($rule.IdentityReference.Value -notin $allowed){$ok=$false}
  if($rule.IdentityReference.Value -in @($u,'S-1-3-4')){$ownAllow=$true}
 }
}
if(-not $ok -or -not $ownAllow){exit 3}
$sha=[Security.Cryptography.SHA256]::Create()
function Digest([string]$text){[Convert]::ToHexString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))).ToLowerInvariant()}
@{owner_sha256=(Digest $owner);dacl_sha256=(Digest $a.Sddl);private_principals=$true}|ConvertTo-Json -Compress
'''
    environment = dict(os.environ, INTEGRITY_PROFILE_ROOT_AUDIT=str(path))
    checked = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        env=environment, capture_output=True, timeout=15,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if checked.returncode:
        raise ValueError("explicit existing root private ownership rejected")
    value = json.loads(checked.stdout)
    if value.get("private_principals") is not True:
        raise ValueError("explicit existing root private ownership unavailable")
    return value


def existing_root(value):
    path = absolute_root(value)
    try:
        before = lineage(path)
        details = path.lstat()
        if os.name == "nt":
            custody = _windows_custody(path)
        elif os.name == "posix":
            if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077:
                raise ValueError("explicit existing root private ownership rejected")
            custody = {"owner_sha256": hashlib.sha256(str(details.st_uid).encode()).hexdigest(),
                       "private_principals": True}
        else:
            raise ValueError("explicit directory custody unsupported")
        if lineage(path) != before:
            raise ValueError("explicit directory changed during custody check")
    except OSError:
        raise ValueError("explicit existing directory unavailable") from None
    return path, {"path": str(path), "identity": [details.st_dev, details.st_ino], **custody}


def deployment_root(value):
    path = absolute_root(value)
    if path.exists() or path.is_symlink():
        raise ValueError("deployment directory must be new")
    # All existing ancestors are inspected without creating or chmod'ing any.
    parent = path.parent
    while not parent.exists() and not parent.is_symlink():
        parent = parent.parent
    existing_root(parent)
    return path


def validate_existing(profile):
    roots = profile.get("preserved_roots", {})
    if not isinstance(roots, dict) or set(roots) - {"state", "envelopes"}:
        raise ValueError("Native preserved root declaration invalid")
    for receipt in roots.values():
        if not isinstance(receipt, dict) or not isinstance(receipt.get("path"), str):
            raise ValueError("Native preserved root receipt invalid")
        path, current = existing_root(receipt["path"])
        if current != receipt:
            raise ValueError("Native preserved root custody changed")
    return roots
