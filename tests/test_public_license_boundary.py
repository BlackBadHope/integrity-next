"""License attribution exceptions cannot become a general privacy bypass."""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "public_license_checker", ROOT / ".github/scripts/public_surface_check.py")
assert spec and spec.loader
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
NOTICE = "components/integrity-space/THIRD-PARTY-NOTICES.txt"


def notice() -> str:
    return (ROOT / NOTICE).read_bytes().decode("utf-8")


def test_exact_reviewed_upstream_license_text_is_allowed():
    assert checker.scan_text(NOTICE, notice()) == []


def test_same_text_in_another_file_gets_no_exception():
    markers = {v["marker"] for v in checker.scan_text("unreviewed.txt", notice())}
    assert {"unapproved_url_host", "private_history_url"} <= markers


def test_any_changed_license_bytes_lose_the_exception():
    markers = {v["marker"] for v in checker.scan_text(NOTICE, notice() + "\n")}
    assert {"unapproved_url_host", "private_history_url"} <= markers


def test_secret_markers_remain_rejected_in_a_notice():
    value = notice() + "\nAuthorization: " + "Bearer " + "A" * 40
    assert "bearer_token" in {v["marker"] for v in checker.scan_text(NOTICE, value)}


def test_owner_private_literals_remain_checked_in_exact_notice():
    assert "configured_private_literal" in {
        v["marker"] for v in checker.scan_text(NOTICE, notice(), ("Attribution",))}


def test_reserved_wildcard_csp_example_does_not_allow_other_wildcards():
    assert checker.scan_text("vendor.js", "https://*.example.com") == []
    url = "https:" + "//" + "*.unapproved-vendor.org"
    assert "unapproved_url_host" in {
        v["marker"] for v in checker.scan_text("vendor.js", url)}
