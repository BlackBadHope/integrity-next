"""Domain scope alias and operator-supplied keywords."""
from __future__ import annotations

import json

import pytest

from integrity_chronicle.concept_inventory import (
    DOMAIN_SCOPE,
    ConceptInventoryError,
    DomainKeywordConfig,
    _classify_user,
    _validate_classification,
    canonical_scope,
    load_domain_keywords,
)


def _message(content: str) -> dict:
    return {"content": content, "canonical_message": {}}


def test_legacy_scope_reads_as_domain_operations():
    legacy = canonical_scope.__globals__["LEGACY_DOMAIN_SCOPE_ALIAS"]
    assert canonical_scope(legacy) == DOMAIN_SCOPE
    item = _validate_classification(
        {
            "kind": "project",
            "scope": legacy,
            "status": "pending",
            "authoritative": False,
            "signals": ["scope.explicit_work"],
        }
    )
    assert item["scope"] == DOMAIN_SCOPE


def test_empty_keyword_default_does_not_assign_domain_scope():
    assert load_domain_keywords() == DomainKeywordConfig()
    classification, _reason, _tokens, _disposition = _classify_user(
        _message("my concept work task operations vlan"),
        domain_keywords=DomainKeywordConfig(),
    )
    assert classification["scope"] != DOMAIN_SCOPE


def test_user_keywords_assign_domain_operations(tmp_path, monkeypatch):
    monkeypatch.delenv("INTEGRITY_DOMAIN_KEYWORDS", raising=False)
    path = tmp_path / "keywords.json"
    path.write_text(
        json.dumps(
            {
                "schema": "integrity-home-domain-keywords/1",
                "keywords": ["operations"],
            }
        ),
        encoding="utf-8",
    )
    loaded = load_domain_keywords(path)
    classification, _reason, _tokens, _disposition = _classify_user(
        _message("my concept work task operations"),
        domain_keywords=loaded,
    )
    assert classification["scope"] == DOMAIN_SCOPE


def test_keyword_file_rejects_a_wrong_schema(tmp_path):
    path = tmp_path / "keywords.json"
    path.write_text('{"schema": "other", "keywords": []}\n', encoding="utf-8")
    with pytest.raises(ConceptInventoryError, match="domain_keywords_schema_invalid"):
        load_domain_keywords(path)
