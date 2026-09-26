"""Integrity Seed write contract: identifiers and accepted text are never changed silently.

Regressions for defects reported against v6.0.0 (b66dd68): event_uid values
redacted into collisions or cut at 160 characters, a reused event_uid with a
different operation answered as an ordinary duplicate, summaries cut at 2000
characters, and ordinary details keys (session_id, tokens_used, ...) masked
because their names contained a secret word. All secrets here are synthetic.
"""
from __future__ import annotations

import importlib.util
import json
import sqlite3
import threading
import time
from pathlib import Path

import pytest

RUNTIME = (
    Path(__file__).resolve().parents[1]
    / "components/integrity-seed/plugins/integrity-seed/runtime/action_log.py"
)


@pytest.fixture
def action_log(tmp_path: Path):
    spec = importlib.util.spec_from_file_location(f"action_log_{tmp_path.name}", RUNTIME)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.DATA_DIR = tmp_path / "data"
    module.DB_PATH = module.DATA_DIR / "action-log.sqlite3"
    module.ensure_db()
    return module


def write(action_log, **fields):
    return action_log.insert_event({"actor": "agent-a", "action": "note", "summary": "s", **fields})


def rows(action_log, sql: str, *args):
    with sqlite3.connect(action_log.DB_PATH) as connection:
        return connection.execute(sql, args).fetchall()


# -- event_uid identity -------------------------------------------------------


def test_valid_event_uid_is_stored_unchanged(action_log) -> None:
    client_uid = "client:" + "a" * 155  # the longest uid the MCP facade issues
    stored = write(action_log, event_uid=client_uid)
    assert stored["event_uid"] == client_uid
    assert rows(action_log, "SELECT event_uid FROM events") == [(client_uid,)]


def test_distinct_event_uids_stay_distinct(action_log) -> None:
    first = write(action_log, event_uid="op:alpha-1", summary="first")
    second = write(action_log, event_uid="op:alpha-2", summary="second")
    assert (first["id"], second["id"]) == (1, 2)
    assert second["duplicate"] is False


@pytest.mark.parametrize(
    "event_uid",
    [
        "op:token=AAAA",  # used to be redacted into a shared "token=[REDACTED]"
        "client:token:FAKE-NOT-A-SECRET",
        "op-" + "x" * 200,  # used to be cut to 160 characters
        " leading-space",
        "has space",
    ],
)
def test_invalid_event_uid_is_refused_before_write(action_log, event_uid: str) -> None:
    with pytest.raises(action_log.EventRejectedError) as refused:
        write(action_log, event_uid=event_uid)
    assert refused.value.code in {"event_uid_invalid", "event_uid_secret_like"}
    assert event_uid.strip() not in str(refused.value)
    assert rows(action_log, "SELECT COUNT(*) FROM events") == [(0,)]


def test_same_operation_with_same_uid_is_idempotent(action_log) -> None:
    first = write(action_log, event_uid="op-1", summary="alpha")
    again = write(action_log, event_uid="op-1", summary="alpha")
    assert again["duplicate"] is True and again["id"] == first["id"]
    assert rows(action_log, "SELECT COUNT(*) FROM events") == [(1,)]


@pytest.mark.parametrize(
    "change",
    [{"summary": "beta"}, {"action": "agent_change_complete"}, {"details": {"k": 1}}],
)
def test_same_uid_with_different_operation_is_a_conflict(action_log, change) -> None:
    write(action_log, event_uid="op-1", summary="alpha")
    with pytest.raises(action_log.EventConflictError) as conflict:
        write(action_log, event_uid="op-1", **{"summary": "alpha", **change})
    assert conflict.value.code == "event_uid_conflict"
    assert conflict.value.detail == {"existing_id": 1}
    assert rows(action_log, "SELECT summary, action, details FROM events") == [
        ("alpha", "note", "{}")
    ]


def test_racing_identical_requests_store_exactly_one_event(action_log) -> None:
    barrier = threading.Barrier(8)
    replies: list[dict] = []

    def worker() -> None:
        barrier.wait()
        replies.append(write(action_log, event_uid="op-race", summary="same"))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert rows(action_log, "SELECT COUNT(*) FROM events") == [(1,)]
    assert sorted(reply["duplicate"] for reply in replies) == [False] + [True] * 7


def test_task_acceptance_keeps_first_writer_wins(action_log) -> None:
    first = action_log.accept_task({"summary": "start work", "task_id": "t-1", "session_id": "s"})
    again = action_log.accept_task({"summary": "reworded", "task_id": "t-1", "session_id": "s"})
    assert again["duplicate"] is True and again["event_id"] == first["event_id"]


# -- accepted content is not changed silently ----------------------------------


@pytest.mark.parametrize(
    ("field", "limit"), [("summary", 2000), ("actor", 120), ("session_id", 200), ("action", 160)]
)
def test_over_limit_text_is_refused_not_truncated(action_log, field: str, limit: int) -> None:
    assert len(write(action_log, **{field: "x" * limit})[field]) == limit
    with pytest.raises(action_log.EventRejectedError) as refused:
        write(action_log, **{field: "x" * (limit + 1)})
    assert refused.value.code == f"{field}_too_long"
    assert refused.value.detail == {"field": field, "length": limit + 1, "limit": limit}
    assert rows(action_log, "SELECT COUNT(*) FROM events") == [(1,)]


def test_ordinary_details_keep_values_and_types(action_log) -> None:
    details = {
        "session_id": "sess-1",
        "tokens_used": 12,
        "max_tokens": 4096,
        "session_count": 3,
        "secretary": "Ann",
        "cookie_banner_seen": True,
        "nested": {"sessionId": "s-2", "tokenCount": 5},
    }
    stored = write(action_log, details=details)
    assert stored["details"] == details
    assert stored["transformations"] == []
    [(raw,)] = rows(action_log, "SELECT details FROM events")
    assert json.loads(raw) == details


@pytest.mark.parametrize(
    "key", ["api_key", "access_token", "password", "clientSecret", "set-cookie", "session"]
)
def test_secret_named_keys_are_masked_visibly(action_log, key: str) -> None:
    stored = write(action_log, details={key: "FAKE-NOT-A-SECRET-000", "count": 2})
    assert stored["details"] == {key: "[REDACTED]", "count": 2}
    assert stored["transformations"] == [f"details.{key}: value of a secret-named key redacted"]


def test_secret_like_summary_text_is_redacted_visibly(action_log) -> None:
    stored = write(action_log, summary="rotated password=FAKE-NOT-A-SECRET done")
    assert stored["summary"] == "rotated password=[REDACTED] done"
    assert stored["transformations"] == ["summary: secret-like value redacted"]


def test_redaction_does_not_merge_distinct_uids(action_log) -> None:
    first = write(action_log, event_uid="op-a", summary="password=FAKE-ONE")
    second = write(action_log, event_uid="op-b", summary="password=FAKE-TWO")
    assert first["id"] != second["id"] and second["duplicate"] is False


def test_replaced_timestamp_is_reported(action_log) -> None:
    stored = write(action_log, ts_utc="2999-01-01T00:00:00Z")
    assert stored["ts_utc"] == stored["created_utc"]
    assert any(change.startswith("ts_utc:") for change in stored["transformations"])
    past = write(action_log, ts_utc="2020-01-01T00:00:00Z")
    assert past["ts_utc"] == "2020-01-01T00:00:00Z" and past["transformations"] == []


# -- round 2 (ND-1, ND-1b, ND-2): what identifies a retried operation ----------


def reload_runtime(action_log, tmp_path: Path):
    """Load a fresh module over the same database, like a runtime restart."""
    spec = importlib.util.spec_from_file_location(f"action_log_restart_{tmp_path.name}", RUNTIME)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.DATA_DIR, module.DB_PATH = action_log.DATA_DIR, action_log.DB_PATH
    module.ensure_db()
    return module


@pytest.mark.parametrize("ts_utc", ["not-a-date", "2999-01-01T00:00:00Z"])
@pytest.mark.parametrize("when", ["immediately", "later", "after-restart"])
def test_retry_with_a_replaced_timestamp_is_idempotent(
    action_log, tmp_path, ts_utc, when
) -> None:
    first = write(action_log, event_uid="op-clock", summary="alpha", ts_utc=ts_utc)
    assert first["ts_utc"] == first["created_utc"]  # the server replaced the time
    runtime = action_log
    if when == "later":
        time.sleep(1.1)
    elif when == "after-restart":
        runtime = reload_runtime(action_log, tmp_path)
    again = write(runtime, event_uid="op-clock", summary="alpha", ts_utc=ts_utc)
    assert again["duplicate"] is True and again["id"] == first["id"]
    assert again["ts_utc"] == first["ts_utc"] and again["summary"] == "alpha"
    assert rows(action_log, "SELECT COUNT(*), ts_utc, summary FROM events") == [
        (1, first["ts_utc"], "alpha")
    ]


def test_racing_retries_with_a_replaced_timestamp_store_one_event(action_log) -> None:
    barrier = threading.Barrier(8)
    replies: list[dict] = []

    def worker() -> None:
        barrier.wait()
        replies.append(
            write(action_log, event_uid="op-race-clock", summary="same", ts_utc="2999-01-01")
        )

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert rows(action_log, "SELECT COUNT(*) FROM events") == [(1,)]
    assert sorted(reply["duplicate"] for reply in replies) == [False] + [True] * 7


def test_retry_may_repeat_the_stored_time_from_the_reply(action_log) -> None:
    first = write(action_log, event_uid="op-reply-time", summary="alpha")
    again = write(action_log, event_uid="op-reply-time", summary="alpha", ts_utc=first["ts_utc"])
    assert again["duplicate"] is True and again["id"] == first["id"]
    with pytest.raises(action_log.EventConflictError):
        write(action_log, event_uid="op-reply-time", summary="alpha", ts_utc="2020-01-01T00:00:00Z")


def test_different_accepted_client_times_do_not_merge(action_log) -> None:
    write(action_log, event_uid="op-fact-time", summary="alpha", ts_utc="2020-01-01T00:00:00Z")
    again = write(
        action_log, event_uid="op-fact-time", summary="alpha", ts_utc="2020-01-01T00:00:00.400Z"
    )
    assert again["duplicate"] is True  # the same second: the stored precision
    with pytest.raises(action_log.EventConflictError):
        write(action_log, event_uid="op-fact-time", summary="alpha", ts_utc="2020-01-02T00:00:00Z")


def test_real_conflicts_still_conflict_after_a_replaced_timestamp(action_log) -> None:
    write(action_log, event_uid="op-c", summary="alpha", ts_utc="2999-01-01T00:00:00Z")
    for change in ({"summary": "beta"}, {"action": "agent_change_complete"}, {"details": {"k": 1}}):
        with pytest.raises(action_log.EventConflictError):
            write(action_log, event_uid="op-c", ts_utc="2999-01-01T00:00:00Z",
                  **{"summary": "alpha", **change})


def test_details_key_order_is_not_an_operation_difference(action_log) -> None:
    write(action_log, event_uid="op-order", details={"a": 1, "b": {"x": 1, "y": 2}})
    again = write(action_log, event_uid="op-order", details={"b": {"y": 2, "x": 1}, "a": 1})
    assert again["duplicate"] is True


@pytest.mark.parametrize(
    ("first", "second"),
    [({"details": {"n": 1}}, {"details": {"n": 1.0}}), ({"tags": ["a", "b"]}, {"tags": ["b", "a"]})],
    ids=["int-vs-float", "tag-order"],
)
def test_number_spelling_and_tag_order_stay_significant(action_log, first, second) -> None:
    write(action_log, event_uid="op-kept", **first)
    with pytest.raises(action_log.EventConflictError):
        write(action_log, event_uid="op-kept", **second)


# -- round 2 (C-1): Authorization credentials are masked, not only the scheme -----


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Authorization: Bearer FAKE-NOT-A-TOKEN-0001", "Authorization: Bearer [REDACTED]"),
        ("Authorization=Basic RkFLRTpOT1QtUkVBTA==", "Authorization=Basic [REDACTED]"),
        ("authorization:bearer FAKE-NOT-A-TOKEN-0002", "authorization:bearer [REDACTED]"),
        ("AUTHORIZATION :  Bearer   FAKE-NOT-A-TOKEN-0003", "AUTHORIZATION :  Bearer   [REDACTED]"),
        ("Proxy-Authorization: Basic RkFLRS1QUk9YWQ==, next", "Proxy-Authorization: Basic [REDACTED], next"),
        ("Authorization: FAKE-SCHEMELESS-0004", "Authorization: [REDACTED]"),
    ],
)
def test_authorization_credentials_are_masked(action_log, text: str, expected: str) -> None:
    stored = write(action_log, summary=f"call failed; {text}")
    assert stored["summary"] == f"call failed; {expected}"
    assert stored["transformations"] == ["summary: secret-like value redacted"]
    [(summary,)] = rows(action_log, "SELECT summary FROM events")
    assert "FAKE" not in summary and "RkFLR" not in summary


def test_authorization_in_details_text_and_keys_is_masked(action_log) -> None:
    stored = write(
        action_log,
        details={
            "note": "retry with Authorization: Bearer FAKE-NOT-A-TOKEN-0005",
            "headers": {"Authorization": "Bearer FAKE-NOT-A-TOKEN-0006", "Accept": "json"},
            "attempts": 2,
        },
    )
    assert stored["details"] == {
        "note": "retry with Authorization: Bearer [REDACTED]",
        "headers": {"Authorization": "[REDACTED]", "Accept": "json"},
        "attempts": 2,
    }
    [(raw,)] = rows(action_log, "SELECT details FROM events")
    assert "FAKE" not in raw


def test_masked_authorization_retry_and_distinct_uids(action_log) -> None:
    text = "Authorization: Bearer FAKE-NOT-A-TOKEN-0007"
    first = write(action_log, event_uid="op-auth-1", summary=text)
    again = write(action_log, event_uid="op-auth-1", summary=text)
    other = write(action_log, event_uid="op-auth-2", summary=text)
    assert again["duplicate"] is True and again["id"] == first["id"]
    assert other["duplicate"] is False and other["id"] != first["id"]
    with pytest.raises(action_log.EventRejectedError):
        write(action_log, event_uid="client:authorization:FAKE-0008")
