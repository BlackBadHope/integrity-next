"""New roots default to shared-core. Existing silos stay siloed until migrate."""
from integrity_home.seat_policy import isolation_mode_for, write_isolation_mode


def test_empty_root_defaults_to_shared_core(tmp_path, monkeypatch):
    monkeypatch.delenv("INTEGRITY_ISOLATION_MODE", raising=False)
    root = tmp_path / "new-install"
    root.mkdir()
    assert isolation_mode_for(root) == "shared-core"


def test_existing_tenant_tree_stays_silo_until_marker(tmp_path, monkeypatch):
    monkeypatch.delenv("INTEGRITY_ISOLATION_MODE", raising=False)
    tenants = tmp_path / "tenants" / ("t_" + ("ab" * 32))
    tenants.mkdir(parents=True)
    assert isolation_mode_for(tmp_path) == "silo"
    write_isolation_mode(tmp_path, "shared-core")
    assert isolation_mode_for(tmp_path) == "shared-core"
