import pytest
from integrity_client_memory import catalogue
from integrity_client_memory.configuration import ConfigurationError


def test_no_owner_catalogue_keeps_navigation_empty(monkeypatch):
    monkeypatch.setattr(catalogue, "read_config", lambda: {"owner_local_catalogue": None})
    value = catalogue.load_owner_catalogue({"protocol": "integrity-owner-runbook-catalog/v1",
                                          "production_authority": False, "paths": []})
    assert value["paths"] == [] and value["production_authority"] is False


def test_catalogue_requires_explicit_digest_and_owner_host(monkeypatch):
    monkeypatch.setattr(catalogue, "read_config", lambda: {"owner_local_catalogue": {"path": "relative.json"}})
    with pytest.raises(ConfigurationError, match="binding invalid"):
        catalogue.load_owner_catalogue({"protocol": "integrity-owner-runbook-catalog/v1"})
