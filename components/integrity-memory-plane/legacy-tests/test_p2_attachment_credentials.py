from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from p2_attachment_credentials import BUCKET, PREFIXES, minio_policy  # noqa: E402


def test_attachment_identity_is_scoped_to_two_prefixes_and_has_no_delete() -> None:
    policy = minio_policy()
    actions = {
        action
        for statement in policy["Statement"]
        for action in statement["Action"]
    }
    resources = {
        resource
        for statement in policy["Statement"]
        for resource in statement["Resource"]
    }
    assert not any("Delete" in action or "Admin" in action for action in actions)
    assert "s3:PutObject" in actions
    assert "s3:GetObjectVersion" in actions
    assert resources == {
        f"arn:aws:s3:::{BUCKET}",
        *(f"arn:aws:s3:::{BUCKET}/{prefix}*" for prefix in PREFIXES),
    }


def test_list_permission_cannot_escape_attachment_prefixes() -> None:
    statement = next(item for item in minio_policy()["Statement"] if "s3:ListBucket" in item["Action"])
    assert statement["Condition"] == {
        "StringLike": {"s3:prefix": [f"{prefix}*" for prefix in PREFIXES]}
    }
