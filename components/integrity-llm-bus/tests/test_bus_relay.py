"""Steer succeeds. Failure returns not_sent and does not queue. pull is not delivery."""
from integrity_llm_bus.relay import SteerFailure, deliver, pointer
from integrity_llm_bus.schema import body_sha256


def _message(delivery="steer"):
    body = "untrusted body"
    return {
        "id": "msg-1",
        "from": "alice",
        "to": "bob",
        "k": "note",
        "th": "turn-1",
        "reply_to": None,
        "delivery": delivery,
        "body": body,
        "body_sha256": body_sha256(body),
    }


class Transport:
    def __init__(self, fail=None):
        self.fail = fail
        self.steered = []
        self.queued = []

    def steer(self, notice, *, config):
        assert "body" not in notice
        assert set(notice) == {"id", "from", "reply_to", "delivery", "body_sha256"}
        assert config["webhook_url"] == "https://example.invalid/hook"
        if self.fail:
            raise self.fail
        self.steered.append(notice)

    def enqueue(self, notice, *, config):
        self.queued.append(notice)


def test_steer_success_sends_a_pointer_only():
    transport = Transport()
    result = deliver(_message(), transport, {"webhook_url": "https://example.invalid/hook", "workdir": "/tmp/seat"})
    assert result["status"] == "steered" and result["delivered"] is True
    assert result["pointer"] == pointer(_message())
    assert transport.queued == []


def test_steer_failure_is_not_sent_and_never_queues():
    transport = Transport(SteerFailure("downstream"))
    result = deliver(_message(), transport, {"webhook_url": "https://example.invalid/hook"})
    assert result["status"] == "not_sent:downstream"
    assert result["delivered"] is False and result["queued"] is False
    assert transport.queued == [] and transport.steered == []


def test_pull_is_not_delivered():
    transport = Transport()
    result = deliver(_message("pull"), transport, {"webhook_url": "https://example.invalid/hook"})
    assert result["status"] == "route=pull" and result["delivered"] is False
    assert transport.steered == [] and transport.queued == []


def test_stale_turn_retries_once_with_uuid5():
    class Once(Transport):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def steer(self, notice, *, config):
            self.calls += 1
            if self.calls == 1:
                raise SteerFailure("stale", stale_turn=True)
            self.steered.append(notice)

    transport = Once()
    result = deliver(_message(), transport, {"webhook_url": "https://example.invalid/hook"})
    assert result["retried"] is True and result["delivered"] is True
    assert result["pointer"]["id"] != "msg-1"
    assert transport.queued == []
