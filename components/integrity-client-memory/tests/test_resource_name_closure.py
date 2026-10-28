"""Every shipped client-memory resource must define the module-level names it uses.

Static guard for the class of defect fixed in the claude-native envelope, where
``_claude_profile_reader`` called ``_checked_owning_bytes`` without a definition
and only a stubbed test path hid the ``NameError``. ``symtable`` resolves scopes
the way the compiler does, so nested functions, closures and comprehensions are
handled; no resource is imported or executed here.
"""
import builtins
import symtable
from pathlib import Path

import pytest
from integrity_client_memory import native_install

RESOURCES = native_install.RESOURCES
IMPLICIT = set(dir(builtins)) | {
    "__file__", "__name__", "__doc__", "__spec__", "__loader__", "__package__", "__builtins__",
}
# Names a resource receives at run time from a documented injector rather than its own text.
INJECTED = {
    # broker_bundle.py embeds the canonical modules and calls
    # ``_model_delivery_broker.install(globals(), _model_delivery)`` inside the rendered broker.
    "windows/integrity-client-turn-broker.py": {"_model_delivery_broker"},
}


def undefined_module_names(path: Path) -> dict[str, set[str]]:
    source = path.read_text(encoding="utf-8-sig")
    top = symtable.symtable(source, str(path), "exec")
    defined = {s.get_name() for s in top.get_symbols()
               if s.is_assigned() or s.is_imported() or s.is_namespace() or s.is_parameter()}
    missing: dict[str, set[str]] = {}

    def walk(table):
        for symbol in table.get_symbols():
            if not symbol.is_referenced():
                continue
            module_level = table.get_type() == "module"
            unresolved = symbol.is_global() if not module_level else (
                not symbol.is_assigned() and not symbol.is_imported())
            name = symbol.get_name()
            if unresolved and name not in defined and name not in IMPLICIT:
                missing.setdefault(name, set()).add(table.get_name())
        for child in table.get_children():
            walk(child)

    walk(top)
    return missing


def resource_files():
    return sorted(path for path in RESOURCES.rglob("*.py"))


def has_star_import(path: Path) -> bool:
    return any(line.strip().startswith("from ") and line.rstrip().endswith("import *")
               for line in path.read_text(encoding="utf-8-sig").splitlines())


@pytest.mark.parametrize("path", resource_files(), ids=lambda p: p.relative_to(RESOURCES).as_posix())
def test_resource_defines_every_module_name_it_uses(path):
    relative = path.relative_to(RESOURCES).as_posix()
    if has_star_import(path):
        pytest.skip("star import makes module-level names non-static")
    missing = undefined_module_names(path)
    for name in INJECTED.get(relative, set()):
        missing.pop(name, None)
    assert not missing, f"{relative} uses undefined module names: {missing}"


def test_injected_names_are_really_injected_by_the_bundle():
    bundle = (Path(native_install.__file__).with_name("broker_bundle.py")).read_text(encoding="utf-8")
    for relative, names in INJECTED.items():
        assert (RESOURCES / relative).is_file(), relative
        for name in names:
            assert f"{name}.install(globals()" in bundle, f"{name} is no longer injected by broker_bundle"


def test_guard_catches_a_missing_helper(tmp_path):
    sample = tmp_path / "envelope.py"
    sample.write_text("import os\n\ndef reader(path):\n    return _checked_bytes(path, 10)\n", encoding="utf-8")
    assert undefined_module_names(sample) == {"_checked_bytes": {"reader"}}
    sample.write_text("import os\n\ndef _checked_bytes(p, n):\n    return os.stat(p)\n\ndef reader(path):\n    return _checked_bytes(path, 10)\n", encoding="utf-8")
    assert undefined_module_names(sample) == {}
