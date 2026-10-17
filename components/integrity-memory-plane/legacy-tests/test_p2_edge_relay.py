from __future__ import annotations

import tempfile
import types
import unittest
import json
from pathlib import Path
from unittest import mock

import p2_edge_relay as relay
import p2_nats_bootstrap as nats_bootstrap


EVENTS = [
    {
        "id": cursor,
        "ts_utc": f"2026-06-15T19:22:{cursor:02d}Z",
        "actor": "test",
        "session_id": "",
        "level": "info",
        "action": "test",
        "summary": f"event {cursor}",
        "details": {},
        "tags": [],
        "created_utc": f"2026-06-15T19:22:{cursor:02d}Z",
        "event_uid": "",
    }
    for cursor in (1, 4, 5, 6, 8)
]


def api(snapshot: int, count: int):
    def fake(_base: str, path: str, params=None):
        if path == "/api/health":
            return {
                "service": "codex-action-log",
                "service_version": f"2.8.{snapshot}",
                "events": count,
                "append_only": True,
                "update_enabled": False,
                "delete_enabled": False,
                "cursor_pagination": True,
            }
        if path == "/api/events":
            return {
                "events": EVENTS,
                "pagination": {
                    "snapshot_event_id": snapshot,
                    "has_more": True,
                },
            }
        raise AssertionError(path)

    return fake


class P2EdgeRelayTests(unittest.TestCase):
    def test_action_log_reader_auth_denies_before_network(self):
        with (
            mock.patch.dict(relay.os.environ, {}, clear=True),
            mock.patch.object(relay, "open_direct_http_request") as opener,
        ):
            with self.assertRaisesRegex(RuntimeError, "required before network I/O"):
                relay.http_json("http://127.0.0.1:8765", "/api/health")
        opener.assert_not_called()


    def test_action_log_reader_url_cannot_forward_token_off_loopback(self):
        with (
            mock.patch.dict(
                relay.os.environ,
                {"CODEX_LOG_TOKEN": "synthetic-reader-token"},
                clear=True,
            ),
            mock.patch.object(relay, "open_direct_http_request") as opener,
        ):
            with self.assertRaisesRegex(RuntimeError, "Action Log reader URL"):
                relay.http_json("http://attacker.example:8765", "/api/health")
        opener.assert_not_called()

    def test_bus_watermarks_are_integer_exact_and_contract_bound(self):
        config = nats_bootstrap.expected_config()
        below = types.SimpleNamespace(bytes=798, messages=1)
        high = types.SimpleNamespace(bytes=799, messages=1)
        critical = types.SimpleNamespace(bytes=899, messages=1)
        config.max_bytes = 1000
        config.max_msg_size = 1
        self.assertEqual("hysteresis", relay.bus_pressure_observation(config, below, next_message_bytes=1)["pressure"])
        self.assertEqual("high", relay.bus_pressure_observation(config, high, next_message_bytes=1)["pressure"])
        self.assertEqual("critical", relay.bus_pressure_observation(config, critical, next_message_bytes=1)["pressure"])
        config.max_age = 1
        with self.assertRaisesRegex(RuntimeError, "max_age_unbounded"):
            relay.bus_pressure_observation(config, below)

    def test_bootstrap_verifier_rejects_full_history_drift(self):
        config = nats_bootstrap.expected_config()
        nats_bootstrap.verify_config(config)
        config.max_msgs = 0
        with self.assertRaisesRegex(RuntimeError, "max_msgs"):
            nats_bootstrap.verify_config(config)

    def test_backpressure_receipt_is_stable_and_reused(self):
        batch_sha = "a" * 64
        intent_sha = "b" * 64
        error = relay.BusBackpressureError(
            "STREAM_HIGH_WATERMARK",
            {"batch_sha256": batch_sha, "intent_sha256": intent_sha, "bus": {"pressure": "high"}},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, reused_first = relay.record_backpressure_once(root, error)
            second, reused_second = relay.record_backpressure_once(root, error)
            self.assertEqual(first, second)
            self.assertFalse(reused_first)
            self.assertTrue(reused_second)
            self.assertEqual(1, len(list(root.glob("blocked-*.json"))))
            value = json.loads(first.read_text(encoding="utf-8"))
            self.assertFalse(value["source_cursor_advanced"])
            self.assertFalse(value["postgres_committed"])
            self.assertTrue(value["intent_preserved"])

    def test_preflight_backpressure_stops_before_s3_postgres_and_state(self):
        batch_sha = "c" * 64
        intent = {
            "source_manifest": {},
            "source_manifest_sha256": "d" * 64,
            "batch": {"batch_sha256": batch_sha, "object_key": "raw/v1/test", "envelopes": []},
            "last_envelope_sha256": "",
            "raw_body": b"raw",
            "raw_content_sha256": "e" * 64,
            "intent_path": "/intent",
            "intent_sha256": "f" * 64,
        }

        async def blocked(*_args, **_kwargs):
            raise relay.BusBackpressureError(
                "STREAM_HIGH_WATERMARK",
                {"batch_sha256": batch_sha, "intent_sha256": intent["intent_sha256"]},
            )

        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state.json"
            args = types.SimpleNamespace(
                state=state,
                minio_env=Path("/unused-minio"),
                shadow_env=Path("/unused-shadow"),
                nats_server="nats://unused",
                s3_endpoint="http://host-febe1d741b49.example.invalid",
                postgres_host="unused",
                fail_after="",
            )
            with (
                mock.patch.object(relay, "load_or_create_intent", return_value=intent),
                mock.patch.object(relay, "load_env", return_value={}),
                mock.patch.object(relay, "preflight_bus", side_effect=blocked),
                mock.patch.object(relay, "put_raw_once") as put_raw,
                mock.patch.object(relay, "commit_postgres") as commit,
            ):
                with self.assertRaises(relay.BusBackpressureError):
                    relay.process_one(args)
            put_raw.assert_not_called()
            commit.assert_not_called()
            self.assertFalse(state.exists())

    def test_mid_transaction_crash_boundary_is_explicit_and_nonzero(self):
        self.assertEqual(0, relay.postgres_crash_after(200, False))
        self.assertEqual(100, relay.postgres_crash_after(200, True))
        self.assertEqual(1, relay.postgres_crash_after(1, True))

    def test_manifest_is_stable_when_observation_head_changes(self):
        state = relay.initial_state()
        with mock.patch.object(relay, "http_json", side_effect=api(100, 96)):
            first_manifest, first_observation, first_events = relay.fetch_source_page("http://host-50d858e0985e.example.invalid", state, 5)
        with mock.patch.object(relay, "http_json", side_effect=api(999, 995)):
            second_manifest, second_observation, second_events = relay.fetch_source_page("http://host-50d858e0985e.example.invalid", state, 5)
        self.assertEqual(first_events, second_events)
        self.assertEqual(first_manifest, second_manifest)
        self.assertNotEqual(first_observation["snapshot_event_id"], second_observation["snapshot_event_id"])
        self.assertEqual(first_manifest["natural_cursor_gaps"], [2, 3, 7])

    def test_fsynced_intent_is_reused_without_source_api(self):
        state = relay.initial_state()
        with tempfile.TemporaryDirectory() as temporary:
            args = types.SimpleNamespace(
                intents=Path(temporary),
                action_log_url="http://host-50d858e0985e.example.invalid",
                batch_size=5,
            )
            with mock.patch.object(relay, "http_json", side_effect=api(100, 96)):
                first = relay.load_or_create_intent(args, state)
            self.assertIsNotNone(first)
            with mock.patch.object(relay, "http_json", side_effect=AssertionError("source API must not be retried")):
                second = relay.load_or_create_intent(args, state)
            self.assertEqual(first["batch"]["batch_sha256"], second["batch"]["batch_sha256"])
            self.assertEqual(first["raw_content_sha256"], second["raw_content_sha256"])
            self.assertEqual(first["intent_sha256"], second["intent_sha256"])

    def test_legacy_uid_preserves_empty_canonical_uid_in_payload(self):
        event = dict(EVENTS[0])
        digest = relay.payload_digest(event)
        transport_uid, origin = relay.transport_event_uid(event, digest)
        self.assertEqual(origin, "derived_legacy_empty")
        self.assertEqual(event["event_uid"], "")
        self.assertEqual(transport_uid, f"legacy-action-log-1-{digest[:32]}")


if __name__ == "__main__":
    unittest.main()
