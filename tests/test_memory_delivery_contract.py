"""Public, synthetic regressions for snapshot-bound memory delivery.

These tests exercise local contracts and disposable stores. They are not a
claim about automatic delivery by any installed vendor harness.
"""
from __future__ import annotations

import datetime as dt
import copy
import sqlite3
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

from integrity_guardian.canonical_read_context import build_read_context, selectors
from integrity_guardian.context_delivery import LANE_PATHS, evaluate_context_delivery
from integrity_guardian.memory_synapse_lts import (
    MemorySynapseLtsError, MemorySynapseLtsService, package_artifact_digest,
)
from integrity_guardian.memory_synapse_mcp import (
    McpFacadeError, MemorySynapseMcp, _validated_attachment_context, tools,
)
from integrity_guardian.historical_archive import ArchiveImportError, ArchivePolicy, _manifest
from integrity_guardian.memory_synapse_mcp_protocol import (
    MODERN_REQUEST_INDEPENDENT_TOOL_NAMES, main as protocol_main,
)
from integrity_guardian.mind_retrieval import derive_prompt_topic, derive_retrieval_terms
from integrity_guardian.read_session import ReadSessionError, accept, issue, request_proof, validate
from integrity_guardian.seed_catalog import SeedCatalog, SeedCatalogError
from integrity_guardian.signing import Ed25519Signer
from integrity_guardian.turn_memory import TurnMemoryError, TurnMemoryStore
from integrity_guardian.turn_memory_profiles import VersionedTurnMemoryService


def event(number, summary, *, details=None):
    return {
        "id": number, "event_uid": f"client:public-fixture-{number}",
        "ts_utc": "2026-01-01T00:00:00Z", "actor": "fixture", "action": "note",
        "level": "info", "summary": summary, "details": details or {}, "tags": [],
    }


@pytest.fixture
def catalog(tmp_path):
    result = SeedCatalog(tmp_path / "private" / "catalog.sqlite3")
    result.import_events(
        [event(1, "Резервный маршрут готов"), event(2, "Оптическая ветка проверена")],
        source_namespace="seed://project/public-fixture",
    )
    return result


def test_generic_catalog_has_no_private_required_event_ids(tmp_path):
    catalog = SeedCatalog(tmp_path / "private" / "generic.sqlite3")
    catalog.import_events([event(9000, "A new installation can start from any source ID")])
    assert catalog.verify()["event_count"] == 1


def test_exact_context_is_snapshot_bound_and_rejects_boolean_ids(catalog):
    lts = MemorySynapseLtsService(catalog.path, artifact_digest="sha256:" + "a" * 64)
    snapshot = lts.snapshot()
    result = lts.exact_read_context_events(
        expected_snapshot_id=snapshot["snapshot_id"], event_ids=[2, 1],
    )
    assert [e["event_id"] for e in result["events"]] == [2, 1]
    assert result["receipt"]["production_authority"] is False
    with pytest.raises(MemorySynapseLtsError):
        lts.exact_read_context_events(expected_snapshot_id=snapshot["snapshot_id"], event_ids=[True])
    with pytest.raises(MemorySynapseLtsError):
        lts.exact_read_context_events(expected_snapshot_id="sha256:" + "0" * 64, event_ids=[1])


@pytest.mark.parametrize("column", ["summary", "event_digest", "canonical_json"])
def test_catalog_verification_does_not_reuse_mutated_rows(catalog, column):
    assert catalog.verify()["ok"] is True
    with sqlite3.connect(catalog.path) as connection:
        connection.execute(f"UPDATE seed_events SET {column}='tampered' WHERE event_id=1")
    with pytest.raises((SeedCatalogError, ValueError)):
        catalog.verify()


def test_editable_package_hash_observes_changed_bytes(tmp_path, monkeypatch):
    import integrity_guardian

    package = tmp_path / "package"
    package.mkdir()
    module = package / "__init__.py"
    module.write_text("version = 'fixture'", encoding="utf-8")
    monkeypatch.setattr(integrity_guardian, "__file__", str(module))
    before = package_artifact_digest()
    module.write_text("version = 'changed'", encoding="utf-8")
    assert package_artifact_digest() != before


def test_exact_read_context_survives_closed_speaker_capsule(catalog):
    lts = MemorySynapseLtsService(catalog.path, artifact_digest="sha256:" + "a" * 64)
    snapshot = lts.snapshot()
    calls = []

    def recall(**arguments):
        calls.append(arguments)
        return {"snapshot_id": snapshot["snapshot_id"], "events": [],
                "receipt": {"snapshot_id": snapshot["snapshot_id"], "event_ids": [],
                            "receipt_id": "sha256:" + "b" * 64}}

    result = build_read_context(
        prompt="Тема: события 1 и 2. Резервный маршрут.", registry_topic=None,
        snapshot=snapshot, byte_budget=8192,
        exact_read=lts.exact_read_context_events, recall=recall,
    )
    assert result["status"] == "delivered"
    assert {e["event_id"] for e in result["events"]} == {1, 2}
    assert result["topic"].startswith("события 1 и 2")
    assert result["speaker_admission"] == "not-granted"
    assert result["canonical_writes"] == 0
    assert len(calls) == 1


@pytest.mark.parametrize("bad_id", [True, 0, "1"])
def test_malformed_canonical_evidence_is_explicitly_unavailable(bad_id):
    snapshot = {"snapshot_id": "sha256:" + "a" * 64,
                "source_digest": "sha256:" + "b" * 64, "catalog_digest": "sha256:" + "c" * 64}
    answer = {"snapshot_id": snapshot["snapshot_id"],
              "events": [{"event_id": bad_id, "event_digest": "sha256:" + "d" * 64}],
              "receipt": {"snapshot_id": snapshot["snapshot_id"], "event_ids": [bad_id],
                          "receipt_id": "sha256:" + "e" * 64}}
    result = build_read_context(
        prompt="events 1", registry_topic=None, snapshot=snapshot, byte_budget=8192,
        exact_read=lambda **_: answer, recall=lambda **_: answer,
    )
    assert result["status"] == "unavailable"
    assert result["events"] == []
    assert result["issues"]


def delivery(source_count, door="admitted", *, selected=0, available=0):
    counts = dict.fromkeys(LANE_PATHS, available)
    chosen = dict.fromkeys(LANE_PATHS, selected)
    return evaluate_context_delivery(
        {"snapshot": {"event_count": source_count}}, {"synaptic": {"door": door}},
        {"available_candidates": counts, "selected_candidates": chosen,
         "max_candidates": 50, "transport_candidate_cap": 18, "max_context_bytes": 8192},
    )


def test_nonempty_missing_session_warns_independently_of_ready_read_plane():
    result = delivery(3, "session-missing")
    assert result["status"] == "memory-not-delivered"
    assert result["notify_owner_required"] is True
    assert result["read_plane"] == "ready"
    assert "session-missing" in result["reasons"]
    assert result["model_delivery_verified"] is False


def test_unknown_delivery_count_is_not_assumed_zero():
    result = evaluate_context_delivery({}, {}, {})
    assert result["health"] == "unknown"
    assert result["source_event_count"] is None
    assert result["notify_owner_required"] is True


def test_empty_source_is_valid_but_selected_does_not_prove_model_delivery():
    assert delivery(0)["status"] == "ready"
    result = delivery(3, selected=1, available=1)
    assert result["status"] == "ready"
    assert result["model_delivery_verified"] is False


def test_pasted_cyrillic_topic_outranks_service_wrapper():
    prompt = 'Inspect attachment\n<pasted_content id="fixture">\nТема: резервный маршрут / priv0\n</pasted_content>'
    assert derive_prompt_topic(prompt) == "резервный маршрут / priv0"
    selection = selectors(prompt, "generic registry topic")
    assert selection["topic"] == "резервный маршрут / priv0"
    assert "pasted_content" not in derive_retrieval_terms(prompt)
    assert len(derive_retrieval_terms(prompt)) <= 16


def test_ranked_search_does_not_reward_repeated_large_details(tmp_path):
    catalog = SeedCatalog(tmp_path / "private" / "search.sqlite3")
    catalog.import_events([
        event(1, "Резервный канал привязан к маршруту"),
        event(2, "Unrelated aggregate", details={"archive": "резервный канал " * 2000}),
        event(3, "Other subject"),
    ])
    assert catalog.search("резервный канал")[0]["event_id"] == 1


def test_reader_hmac_binds_snapshot_prompt_and_own_native_identity():
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    envelope = {
        "native_identity_hashes": {"machine_id": "1" * 64, "thread_id": "2" * 64, "turn_id": "3" * 64},
        "expires_utc": (now + dt.timedelta(seconds=60)).isoformat(),
        "turn_ref_digest": "sha256:" + "4" * 64, "prompt_sha256": "5" * 64,
    }
    declaration = issue(envelope, product="codex", now=now)
    payload = {"declaration": declaration, "snapshot_event_id": 3,
               "proof": request_proof(declaration, snapshot_event_id=3, token="test-only-token")}
    assert accept(payload, token="test-only-token", now=now)["external_action_authority"] is False
    with pytest.raises(ReadSessionError):
        accept({**payload, "snapshot_event_id": 4}, token="test-only-token", now=now)
    with pytest.raises(ReadSessionError):
        validate(declaration, prompt_sha256="0" * 64, now=now)
    with pytest.raises(ReadSessionError):
        validate(declaration, now=now + dt.timedelta(minutes=6))


def test_unauthenticated_attachment_cannot_supply_search_context():
    with pytest.raises(McpFacadeError, match="authenticated"):
        _validated_attachment_context({"topic": "fixture"}, None, False)


@pytest.mark.parametrize("profile", ["legacy-v1", "native-intent-v1"])
def test_legacy_and_native_intent_receipts_remain_distinct_and_closable(tmp_path, profile):
    store = TurnMemoryStore(
        tmp_path / (profile + ".sqlite3"), namespace="sha256:" + "a" * 64,
        signer=Ed25519Signer.generate("key:public-fixture"), identity_profile=profile,
    )
    identity = {"machine_id": "machine:fixture", "thread_id": "fixture-thread", "turn_id": "fixture-turn"}
    if profile == "native-intent-v1":
        identity.update(thread_id="00000000-0000-4000-8000-000000000001",
                        turn_id="00000000-0000-4000-8000-000000000002", intent_id="intent:" + "b" * 64)
    opened = store.open_turn(**identity, prompt_sha256="c" * 64)
    receipt = opened["receipt"]
    assert receipt["identity"] == identity
    terminal = store.close_turn(registration_id=receipt["receipt_id"], outcome="no-event", no_event_reason="read-only")
    assert terminal["receipt"]["outcome"] == "no-event"
    assert store.coverage()["counts"]["terminal"] == 1
    with pytest.raises(TurnMemoryError):
        store.close_turn(registration_id=receipt["receipt_id"], outcome="no-event", no_event_reason="user-cancelled")


def test_modern_stateless_surface_does_not_expose_hidden_turn_state():
    assert MODERN_REQUEST_INDEPENDENT_TOOL_NAMES == {
        "integrity_memory_capabilities", "integrity_turn_memory_coverage",
    }


def test_archive_requires_explicit_immutable_owner_policy():
    with pytest.raises(ArchiveImportError, match="not_configured"):
        _manifest(SimpleNamespace(), {}, write=True)
    policy = ArchivePolicy("a" * 64, "client:public-fixture-manifest", 3, 2)
    with pytest.raises(FrozenInstanceError):
        policy.message_count = 5
    with pytest.raises(ArchiveImportError):
        ArchivePolicy("a" * 64, "client:public-fixture-manifest", True, 1)


def test_archive_manifest_scope_and_complete_plan_are_validated_before_actions():
    policy = ArchivePolicy("a" * 64, "client:public-fixture-manifest", 3, 2)
    parts = [
        {"part": 1, "event_uid": "client:public-fixture-part-a", "message_first": 1,
         "message_last": 2, "message_count": 2, "details_sha256": "b" * 64},
        {"part": 2, "event_uid": "client:public-fixture-part-b", "message_first": 3,
         "message_last": 3, "message_count": 1, "details_sha256": "c" * 64},
    ]
    manifest = {"archive_protocol": "integrity-historical-transcript-archive/v1",
                "source_metadata": {"source_sha256": policy.source_sha256, "message_count": 3},
                "planned_parts": parts}
    subject = {"prompt_sha256": "d" * 64, "generation": 1}
    facade = SimpleNamespace(
        archive_policy=policy, _broker_tool_surface_authenticated=True,
        _archive_prompt_binding=subject,
        _bind_append_to_current_context=lambda _: (None, subject),
        _require_mind_admission=lambda: {"snapshot_id": "sha256:" + "e" * 64},
        lts=SimpleNamespace(event_uid_lookup=lambda **_: {"outcome": "found", "event": {"details": manifest}}),
    )
    arguments = {"context_admission_id": "sha256:" + "f" * 64,
                 "source_sha256": policy.source_sha256,
                 "manifest_event_uid": policy.manifest_event_uid,
                 "_broker_archive_binding": subject}
    assert _manifest(facade, arguments, write=False)[0] == parts
    with pytest.raises(ArchiveImportError, match="scope_mismatch"):
        _manifest(facade, {**arguments, "source_sha256": "0" * 64}, write=False)
    original = copy.deepcopy(manifest)
    parts[1]["message_first"] = 2
    with pytest.raises(ArchiveImportError, match="coverage_invalid"):
        _manifest(facade, arguments, write=False)
    manifest.update(original)
    manifest["planned_parts"][0]["part"] = True
    with pytest.raises(ArchiveImportError, match="coverage_invalid"):
        _manifest(facade, arguments, write=False)


def test_curator_profile_importable_without_changing_default_tool_surface():
    assert not any(t["name"] == "integrity_turn_memory_reconcile" for t in tools())
    assert any(t["name"] == "integrity_turn_memory_reconcile" for t in tools(profile="turn-curator-v1"))


def test_legacy_store_remains_servable_by_updated_facade(tmp_path):
    store = TurnMemoryStore(tmp_path / "legacy.sqlite3", namespace="sha256:" + "a" * 64,
                            signer=Ed25519Signer.generate("key:public-fixture"))
    server = MemorySynapseMcp(None, turn_memory=store, audit=lambda _: None)
    opened = server.call("integrity_turn_memory_open", {
        "machine_id": "machine:fixture", "thread_id": "fixture-thread",
        "turn_id": "fixture-turn", "prompt_sha256": "b" * 64,
    })
    assert server.call("integrity_turn_memory_coverage", {})["counts"]["registered"] == 1
    server.call("integrity_turn_memory_close", {
        "registration_id": opened["receipt"]["receipt_id"],
        "outcome": "no-event", "no_event_reason": "read-only",
    })
    assert server.call("integrity_turn_memory_coverage", {})["counts"]["terminal"] == 1


@pytest.mark.parametrize("tool", ["integrity_append_event", "integrity_archive_import", "integrity_turn_memory_open"])
def test_reattached_context_cannot_create_fresh_actions(tool):
    server = MemorySynapseMcp(None, audit=lambda _: None)
    server._context_reattach_read_only = True
    with pytest.raises(McpFacadeError, match="reads and existing lifecycle"):
        server.call(tool, {})


def test_protocol_entrypoint_accepts_native_policy_flags(capsys):
    assert protocol_main(["--version", "--native-intent-creation-mode", "rollback-read-close",
                          "--bootstrap-native-intent-store"]) == 0
    assert capsys.readouterr().out.strip() == "integrity-client-memory 2.11.0"


def test_versioned_legacy_registration_closes_when_native_never_configured(tmp_path):
    signer = Ed25519Signer.generate("key:public-fixture")
    path = tmp_path / "legacy.sqlite3"
    TurnMemoryStore(path, namespace="sha256:" + "a" * 64, signer=signer)
    service = VersionedTurnMemoryService(path, namespace="sha256:" + "a" * 64, signer=signer)
    opened = service.open_turn(machine_id="machine:fixture", thread_id="thread:fixture",
                               turn_id="turn:fixture", prompt_sha256="b" * 64)
    closed = service.close_turn(registration_id=opened["receipt"]["receipt_id"],
                                outcome="no-event", no_event_reason="read-only")
    assert closed["receipt"]["outcome"] == "no-event"
    assert service.stores["native-intent-v1"] is None


@pytest.mark.parametrize("before_start", [True, False])
def test_versioned_legacy_routing_refuses_unknown_native_history(tmp_path, before_start):
    signer = Ed25519Signer.generate("key:public-fixture")
    path = tmp_path / "legacy.sqlite3"
    native = tmp_path / "native-intent-v1.sqlite3"
    TurnMemoryStore(path, namespace="sha256:" + "a" * 64, signer=signer)
    if before_start:
        native.write_bytes(b"invalid native history")
    service = VersionedTurnMemoryService(path, namespace="sha256:" + "a" * 64, signer=signer)
    opened = service.open_turn(machine_id="machine:fixture", thread_id="thread:fixture",
                               turn_id="turn:fixture", prompt_sha256="b" * 64)
    if not before_start:
        native.write_bytes(b"new unverified native history")
    with pytest.raises(TurnMemoryError, match="unavailable"):
        service.close_turn(registration_id=opened["receipt"]["receipt_id"],
                            outcome="no-event", no_event_reason="read-only")
