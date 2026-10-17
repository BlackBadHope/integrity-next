from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_minio_policy_is_prefix_scoped_and_has_no_mutation_rights() -> None:
    module = load_module("p2_scoped_credentials_test", ROOT / "p2_scoped_credentials.py")
    policy = module.minio_policy()
    statements = policy["Statement"]
    actions = {action for statement in statements for action in statement["Action"]}
    resources = {resource for statement in statements for resource in statement["Resource"]}

    assert "s3:PutObject" in actions
    assert "s3:GetObjectVersion" in actions
    assert "s3:GetObjectRetention" in actions
    assert "s3:PutObjectRetention" not in actions
    assert "s3:BypassGovernanceRetention" not in actions
    assert "s3:DeleteObject" not in actions
    assert "s3:DeleteObjectVersion" not in actions
    assert "s3:PutBucketPolicy" not in actions
    assert f"arn:aws:s3:::{module.RAW_BUCKET}/{module.RAW_PREFIX}*" in resources


def test_relay_uses_only_scoped_environment_names() -> None:
    source = (ROOT / "p2_edge_relay.py").read_text(encoding="utf-8")
    assert 'env["MINIO_ROOT_USER"]' not in source
    assert 'env["MINIO_ROOT_PASSWORD"]' not in source
    assert 'env["POSTGRES_USER"]' not in source
    assert 'env["NATS_USER"]' not in source
    assert "/etc/integrity-memory-p2/relay-shadow.env" in source
    assert "/etc/integrity-memory-p2/relay-minio.env" in source


def test_nats_relay_permissions_are_exact() -> None:
    config = (ROOT / "p2-nats.conf").read_text(encoding="utf-8")
    assert "$NATS_RELAY_USER" in config
    assert '"integrity.p2.raw.workspace.seed_project_workspace.source-linux-action-log"' in config
    assert '"$JS.API.STREAM.INFO.INTEGRITY_P2_RAW"' in config
    assert '"$JS.API.DIRECT.GET.INTEGRITY_P2_RAW"' in config
    assert 'subscribe: { allow: ["_INBOX.>"] }' in config
