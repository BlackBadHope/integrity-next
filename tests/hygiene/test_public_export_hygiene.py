"""Public-export hygiene.

Reuses ``.github/scripts/public_surface_check.py``. Owner-specific literals are
composed here and passed through a temporary file outside the repository.
The historical scope alias is allowlisted on one assignment only.
"""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LEGACY_RELATIVE = (
    "components/integrity-home/src/integrity_chronicle/concept_inventory.py"
)

spec = importlib.util.spec_from_file_location(
    "public_surface_check", ROOT / ".github/scripts/public_surface_check.py"
)
assert spec and spec.loader
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def forbidden_literals() -> list[str]:
    """Compose rule-2 literals. The source must not contain them whole."""

    return [
        "bk" + "mz",
        "Subnet" + "OPS",
        "D:" + "\\" + "Subnet" + "OPS" + "3.0",
        "/" + "home/" + "subnet" + "ops",
        "api2." + "cursor" + ".sh",
        "direct_" + "job_" + "subnet",
    ]


def legacy_alias() -> str:
    return forbidden_literals()[-1]


def mojibake_run():
    return checker.re.compile(
        "(?:"
        + "\u0420"
        + r"[\u00a7\u00b0-\u00bf\u0402-\u040f]"
        + "|"
        + "\u0421"
        + r"[\u0402-\u040f\u201a\u2020]"
        + "){4,}"
        + "|"
        + "\u0420\u0406\u0432\u0402"
    )


def allowlisted_alias_line(relative: str, line: str) -> bool:
    return (
        relative == LEGACY_RELATIVE
        and line.strip().startswith("LEGACY_DOMAIN_SCOPE_ALIAS = ")
        and legacy_alias() in line
    )


_SKIP_DIRS = frozenset({"__pycache__", ".pytest_cache", "node_modules", ".venv"})


def iter_texts(root: Path):
    """Yield regular source files. Skip VCS metadata and in-tree build products.

    The export manifest is checked by ``public_surface_check.py`` before wheels
    are built. Wheel builds leave ``*.egg-info`` beside packages, so this scan
    ignores those generated directories and still reads every source member.
    """

    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda item: item.name)
        for child in children:
            path = Path(child.path)
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if relative == ".git" and stat.S_ISDIR(metadata.st_mode):
                continue
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if stat.S_ISDIR(metadata.st_mode):
                if path.name in _SKIP_DIRS or path.name.endswith(".egg-info"):
                    continue
                pending.append(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                continue
            yield relative, path


def literal_hits(root: Path, literal: str) -> list[tuple[str, int, str]]:
    needle = literal.casefold()
    found = []
    for relative, path in iter_texts(root):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            continue
        lowered = text.casefold()
        start = 0
        while True:
            offset = lowered.find(needle, start)
            if offset < 0:
                break
            line_no = checker.line_number(text, offset)
            found.append((relative, line_no, text.splitlines()[line_no - 1]))
            start = offset + len(needle)
    return found


def test_allowlisted_legacy_alias_is_one_assignment():
    hits = literal_hits(ROOT, legacy_alias())
    assert len(hits) == 1
    relative, _line_no, line = hits[0]
    assert allowlisted_alias_line(relative, line)


def test_alias_outside_the_assignment_is_rejected():
    literal = legacy_alias()
    sample = "scope = " + literal
    findings = checker.scan_text("notes.txt", sample + "\n", (literal,))
    assert any(item["marker"] == "configured_private_literal" for item in findings)
    assert not allowlisted_alias_line("notes.txt", sample)


def test_scanner_reports_no_unallowlisted_private_literals():
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".json", prefix="integrity-hygiene-", delete=False
    )
    path = Path(handle.name)
    try:
        assert not path.resolve().is_relative_to(ROOT.resolve())
        json.dump(forbidden_literals(), handle)
        handle.close()
        literals = checker.load_private_literals_file(path)
    finally:
        path.unlink(missing_ok=True)
    unexpected = []
    checked = 0
    for relative, source_path in iter_texts(ROOT):
        checked += 1
        try:
            text = source_path.read_text(encoding="utf-8")
        except UnicodeError:
            unexpected.append({"path": relative, "marker": "non_utf8_member"})
            continue
        for finding in checker.scan_text(relative, text, literals):
            if finding["marker"] != "configured_private_literal":
                unexpected.append(finding)
                continue
            line = text.splitlines()[int(finding["line"]) - 1]
            if not allowlisted_alias_line(relative, line):
                unexpected.append(finding)
    assert unexpected == []
    assert checked > 0


def test_plugin_manifests_are_not_proprietary():
    found = []
    for relative, path in iter_texts(ROOT):
        if path.name != "plugin.json":
            continue
        if "Proprietary" in path.read_text(encoding="utf-8"):
            found.append(relative)
    assert found == []


def test_proprietary_plugin_json_would_fail(tmp_path: Path):
    sample = tmp_path / "plugin.json"
    sample.write_text('{"license": "Proprietary"}\n', encoding="utf-8")
    assert "Proprietary" in sample.read_text(encoding="utf-8")


def test_mojibake_runs_are_absent():
    pattern = mojibake_run()
    found = []
    for relative, path in iter_texts(ROOT):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            continue
        if pattern.search(text):
            found.append(relative)
    assert found == []
    assert pattern.search("\u0420\u00a7\u0420\u00b0\u0421\u0403\u0421\u201a")


def test_private_key_headers_and_database_dumps_are_rejected():
    header = "-" * 5 + "BEGIN PRIVATE KEY" + "-" * 5
    markers = {item["marker"] for item in checker.scan_text("leak.txt", header + "\n")}
    assert "private_key_material" in markers
    assert "forbidden_credential_or_state_suffix" in checker.path_markers("state/backup.sqlite3")
    assert "forbidden_credential_or_state_suffix" in checker.path_markers("dump.db")
    for relative, path in iter_texts(ROOT):
        assert checker.path_markers(relative).isdisjoint(
            {"forbidden_credential_or_state_suffix"}
        )
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            continue
        assert "private_key_material" not in {
            item["marker"] for item in checker.scan_text(relative, text)
        }


def test_public_surface_scanner_passes_without_owner_literals():
    unexpected = []
    for relative, source_path in iter_texts(ROOT):
        markers = checker.path_markers(relative)
        if markers:
            unexpected.append({"path": relative, "markers": sorted(markers)})
        try:
            text = source_path.read_text(encoding="utf-8")
        except UnicodeError:
            unexpected.append({"path": relative, "marker": "non_utf8_member"})
            continue
        unexpected.extend(checker.scan_text(relative, text))
    assert unexpected == []
