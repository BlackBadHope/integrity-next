"""Real Windows ACL checks in new, disposable synthetic directories only.

No account SID or descriptor bytes are written to evidence; assertions expose
only booleans and fixed error vocabulary. Existing external ACLs are untouched.
"""
from __future__ import annotations

import ctypes
import os

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="requires native Windows DACL APIs")


def _descriptor(path):
    from integrity_guardian import _windows_files as win

    required = win.wintypes.DWORD()
    flags = win._OWNER_SECURITY_INFORMATION | win._DACL_SECURITY_INFORMATION
    win._advapi32.GetFileSecurityW(str(path), flags, None, 0, ctypes.byref(required))
    assert required.value > 0
    result = ctypes.create_string_buffer(required.value)
    ok = bool(win._advapi32.GetFileSecurityW(
        str(path), flags, result, required.value, ctypes.byref(required),
    ))
    assert ok
    return result.raw


def _set_synthetic_wrong_principal_acl(path):
    from integrity_guardian import _windows_files as win

    # All three rules retain the exact required mask/flags; replace only the
    # Administrators rule with the well-known Users group. The exact principal
    # set guard must distinguish this from a correctly private directory.
    current = win.current_user_sid()
    sddl = f"O:{current}D:P(A;OICI;FA;;;{current})(A;OICI;FA;;;SY)(A;OICI;FA;;;BU)"
    descriptor = ctypes.c_void_p()
    required = win.wintypes.DWORD()
    ok = bool(win._advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, win._SDDL_REVISION_1, ctypes.byref(descriptor), ctypes.byref(required),
    ))
    assert ok
    try:
        flags = (win._OWNER_SECURITY_INFORMATION | win._DACL_SECURITY_INFORMATION
                 | win._PROTECTED_DACL_SECURITY_INFORMATION)
        applied = bool(win._advapi32.SetFileSecurityW(str(path), flags, descriptor))
        assert applied
    finally:
        win._kernel32.LocalFree(descriptor.value)


def test_new_private_directory_has_exact_custody_and_safe_repeat(tmp_path):
    from integrity_guardian import _windows_files as win

    path = tmp_path / "new-private"
    assert not path.exists()
    assert win.create_private_directory(path) == path
    evidence = win.inspect_private_directory_acl(path)
    assert evidence["current_principal_is_owner"] is True
    assert evidence["dacl_protected"] is True
    assert evidence["rule_count"] == 3
    assert win.create_private_directory(path) == path


def test_private_tree_creation_does_not_need_to_rewrite_existing_anchor(tmp_path):
    from integrity_guardian import _windows_files as win

    before = _descriptor(tmp_path)
    path = tmp_path / "private-parent" / "private-child"
    assert win.create_private_directory_tree(path) == path
    unchanged = before == _descriptor(tmp_path)
    assert unchanged
    assert win.inspect_private_directory_acl(path)["rule_count"] == 3


def test_wrong_principal_is_rejected_without_silent_acl_repair(tmp_path):
    from integrity_guardian import _windows_files as win

    path = tmp_path / "synthetic-broad"
    path.mkdir()
    _set_synthetic_wrong_principal_acl(path)
    before = _descriptor(path)
    with pytest.raises(win.WindowsFileBoundaryError, match="principal set mismatch"):
        win.create_private_directory(path)
    unchanged = before == _descriptor(path)
    assert unchanged


def test_post_creation_acl_tamper_and_foreign_expected_owner_are_rejected(tmp_path):
    from integrity_guardian import _windows_files as win

    path = win.create_private_directory(tmp_path / "tamper-fixture")
    with pytest.raises(win.WindowsFileBoundaryError, match="owner mismatch"):
        win.inspect_private_directory_acl(path, expected_owner_sid="S-1-5-32-545")
    _set_synthetic_wrong_principal_acl(path)
    with pytest.raises(win.WindowsFileBoundaryError, match="principal set mismatch"):
        win.inspect_private_directory_acl(path)
