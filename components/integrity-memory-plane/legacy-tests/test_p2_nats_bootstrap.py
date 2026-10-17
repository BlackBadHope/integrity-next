from __future__ import annotations

from pathlib import Path
from dataclasses import fields

import pytest

import p2_nats_bootstrap as bootstrap
from nats.js.api import StoreCompression, StreamConsumerLimits


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_STREAM_MAX_BYTES = 104 * 1024**3
EXPECTED_SERVER_MAX_FILE_STORE_BYTES = 112 * 1024**3


def test_capacity_contract_uses_exact_binary_byte_counts() -> None:
    assert bootstrap.MAX_BYTES == EXPECTED_STREAM_MAX_BYTES
    assert bootstrap.SERVER_MAX_FILE_STORE_BYTES == EXPECTED_SERVER_MAX_FILE_STORE_BYTES
    assert bootstrap.expected_config().max_bytes == EXPECTED_STREAM_MAX_BYTES

    server_config = (ROOT / "p2-nats.conf").read_text(encoding="utf-8")
    assert f"max_file_store: {EXPECTED_SERVER_MAX_FILE_STORE_BYTES}" in server_config


def test_verify_config_rejects_stream_capacity_one_byte_short() -> None:
    config = bootstrap.expected_config()
    config.max_bytes = EXPECTED_STREAM_MAX_BYTES - 1

    with pytest.raises(RuntimeError, match=r"JetStream contract drift: max_bytes"):
        bootstrap.verify_config(config)


def test_verify_config_accepts_exact_capacity_contract() -> None:
    bootstrap.verify_config(bootstrap.expected_config())


def test_stream_config_schema_is_explicitly_reviewed() -> None:
    assert bootstrap.STREAM_CONFIG_FIELD_ALLOWLIST == frozenset(
        field.name for field in fields(type(bootstrap.expected_config()))
    )


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    [
        ("discard_new_per_subject", True),
        ("allow_msg_ttl", True),
        ("allow_msg_schedules", True),
        ("allow_atomic", True),
        ("allow_batched", True),
        ("subject_transform", object()),
        ("republish", object()),
        ("compression", StoreCompression.S2),
        ("consumer_limits", StreamConsumerLimits(max_ack_pending=1)),
        ("subject_delete_marker_ttl", 60),
    ],
)
def test_verify_config_rejects_unbounded_or_destructive_stream_features(
    field: str,
    unsafe_value: object,
) -> None:
    config = bootstrap.expected_config()
    setattr(config, field, unsafe_value)

    with pytest.raises(RuntimeError, match="JetStream contract drift"):
        bootstrap.verify_config(config)
