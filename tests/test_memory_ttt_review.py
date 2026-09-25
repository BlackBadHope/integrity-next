"""TIME-TO-TASK runbook catalogue boundary regressions.

Graph fixtures here are explicit mocks; the native-graph suite is not part of
the public projection. These cases do not establish authenticated Seed/snapshot
or live MCP admission.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

import pytest

from integrity_guardian import memory_ttt_paths as ttt
from integrity_guardian.hashing import digest_object
from integrity_guardian.memory_link_graph import MemoryLinkGraphError
from integrity_guardian.schemas import validate

HINT_MODES = ("navigational-hint", "read-only-evidence", "entity-brief", "alias-resolve")


def document(*, refs: bool = False, goal: str = "lookup address reference") -> dict:
    return {
        "path_id": "fixture-route", "title": "Fixture route", "goal_aliases": [goal],
        "hops": [
            {"hop_id": "start", "title": "Start", "node_ref": "node:start" if refs else None},
            {"hop_id": "finish", "title": "Finish", "node_ref": "node:finish" if refs else None},
        ],
    }


def catalog(*, refs: bool = False) -> ttt.RunbookPathCatalog:
    return ttt.register_paths(ttt.RunbookPathCatalog(), [document(refs=refs)])


class FixtureGraph:
    """A synthetic resolver seam, not a genuine admitted MemoryLinkGraph."""

    def __init__(self, refs: tuple[str, ...] = ("node:start", "node:finish")):
        self.source_namespace = "seed://project/fixture"
        self.graph_digest = digest_object(list(refs), domain="ttt-unit-graph")
        self.aliases = {}
        self._node_documents = {}
        for ref in refs:
            key = ref.split(":", 1)[-1]
            uri = "integrity://seed/project/fixture/term/" + key
            self.aliases[ref] = (uri,)
            self.aliases[key] = (uri,)
            self.aliases[uri] = (uri,)
            self._node_documents[uri] = {
                "uri": uri, "key": key, "kind": "term", "title": key,
                "aliases": [key], "source_event_ids": [1],
            }

    def _resolve_uris(self, value: str) -> tuple[str, tuple[str, ...]]:
        if value == "invalid-ref":
            raise MemoryLinkGraphError("synthetic invalid reference")
        return value, self.aliases.get(value, ())


def result(*, graph=None, paths=None, goal="lookup address reference", hop="start") -> dict:
    value = ttt.memory_ttt_autofill(goal, hop, graph=graph, catalog=paths or catalog())
    validate("memory-ttt-autofill", value)
    core = {key: item for key, item in value.items() if key != "receipt_id"}
    assert value["receipt_id"] == digest_object(core, domain="memory-ttt-autofill-v1")
    assert value["production_authority"] is False
    assert value["route_authority"] is False
    assert value["executable"] is False
    return value


def test_default_catalogue_is_empty_without_filesystem_access() -> None:
    with patch.object(Path, "read_bytes", side_effect=AssertionError("no ambient file read")):
        assert ttt.default_runbook_path_catalog().all_paths() == ()
        assert ttt.memory_ttt_list_paths()["paths"] == []
        answer = ttt.memory_ttt_autofill("billing", "match-address-to-user")
    assert answer["result"] == "BLOCKED"
    assert answer["path"] is None
    validate("memory-ttt-autofill", answer)


def test_each_default_catalogue_is_independent() -> None:
    first = ttt.default_runbook_path_catalog()
    ttt.register_paths(first, [document()])
    assert len(first.paths) == 1
    assert ttt.default_runbook_path_catalog().paths == {}


def test_portable_module_has_no_target_operational_definitions() -> None:
    import json

    source = Path(ttt.__file__).read_text(encoding="utf-8")
    repository = Path(__file__).resolve().parents[1]
    profile_path = repository / "private" / "publication" / "owner-profile.json"
    if not profile_path.is_file():
        pytest.skip("the private literal corpus is not part of the public export")
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    for record in profile["private_literals"]:
        assert record["value"] not in source



def test_explicit_theoretical_route_keeps_no_graph_provenance() -> None:
    value = result()
    assert value["result"] == "REMAINING"
    assert value["graph_digest"] is None
    assert value["source_namespace"] is None
    assert value["remaining_path"][0]["hop_id"] == "finish"
    for hop in value["path"]["hops"] + value["remaining_path"]:
        assert hop["executable"] is False
        assert hop["navigational_only"] is True


@pytest.mark.parametrize("goal", ["a", "ad", "addr", "lookup", "refer"])
def test_short_reverse_substring_is_not_a_matched_goal(goal) -> None:
    value = result(goal=goal)
    assert value["result"] == "BLOCKED"
    assert value["blocked"]["reason"] == "goal_unknown_in_path_catalog"


def test_intentional_short_exact_alias_remains_valid() -> None:
    paths = ttt.register_paths(ttt.RunbookPathCatalog(), [document(goal="db")])
    assert result(paths=paths, goal="db")["result"] == "REMAINING"


def test_meaningful_goal_substring_remains_valid() -> None:
    assert result(goal="lookup address")["result"] == "REMAINING"


def test_longer_unmatched_alias_suffix_cannot_win_a_tied_partial_goal() -> None:
    first, second = document(goal="lookup address in first catalogue"), document(goal="lookup address in a much longer second catalogue")
    second["path_id"] = "another-route"
    paths = ttt.register_paths(ttt.RunbookPathCatalog(), [first, second])
    value = result(paths=paths, goal="lookup address")
    assert value["result"] == "AMBIGUOUS"
    assert len(value["ambiguous"]["candidates"]) == 2


@pytest.mark.parametrize("mode", HINT_MODES)
def test_executable_true_rejected_even_for_hint_mode(mode) -> None:
    with pytest.raises(ttt.MemoryTttPathError):
        ttt.RunbookPathHop("hop", "Hop", mode=mode, executable=True)


@pytest.mark.parametrize("flag", ["executable", "production_authority", "mutate_billing"])
@pytest.mark.parametrize("value", [True, 1, 0, "false", None])
def test_mapping_flags_are_exact_false_not_coerced(flag, value) -> None:
    raw = document()
    raw["hops"][1][flag] = value
    with pytest.raises(ttt.MemoryTttPathError):
        ttt.path_from_mapping(raw)


@pytest.mark.parametrize("mode", ["mutate-billing", "production-apply", "sql-write", "schema-migrate", "unknown", "", None, []])
def test_unsupported_or_write_mode_rejected_at_construction(mode) -> None:
    with pytest.raises(ttt.MemoryTttPathError):
        ttt.RunbookPathHop("hop", "Hop", mode=mode)


@pytest.mark.parametrize("flag", ["production_authority", "route_authority", "executable"])
def test_path_level_authority_cannot_be_hidden_in_mapping(flag) -> None:
    raw = document()
    raw[flag] = True
    with pytest.raises(ttt.MemoryTttPathError):
        ttt.path_from_mapping(raw)


def test_safe_descriptors_detach_mutable_input_containers() -> None:
    aliases = ["first"]
    hop = ttt.RunbookPathHop("hop", "Hop", aliases=aliases)
    hops = [hop]
    route = ttt.RunbookPath("path", "Path", ["route goal"], hops)
    aliases.append("late alias")
    hops.append(ttt.RunbookPathHop("late", "Late"))
    assert hop.aliases == ("first",)
    assert route.hops == (hop,)
    with pytest.raises(FrozenInstanceError):
        route.hops = ()


def test_reuse_rejects_corrupted_descriptor_instead_of_sanitizing_it() -> None:
    paths = catalog()
    route = paths.get("fixture-route")
    # Explicit adversarial same-process mutation; frozen API setters are covered above.
    object.__setattr__(route.hops[0], "executable", True)
    with pytest.raises(ttt.MemoryTttPathError):
        paths.register(route)
    with pytest.raises(ttt.MemoryTttPathError):
        route.as_public_dict()
    with pytest.raises(ttt.MemoryTttPathError):
        ttt.memory_ttt_autofill("lookup address reference", "finish", catalog=paths)


def test_invalid_batch_does_not_partially_register() -> None:
    paths = catalog()
    before = ttt.memory_ttt_list_paths(catalog=paths)
    valid, invalid = document(goal="new route"), document(goal="invalid route")
    valid["path_id"] = "new-route"
    invalid["hops"][0]["executable"] = True
    with pytest.raises(ttt.MemoryTttPathError):
        ttt.register_paths(paths, [valid, invalid])
    assert ttt.memory_ttt_list_paths(catalog=paths) == before


def test_public_map_insertion_cannot_bypass_catalogue_validation() -> None:
    paths = catalog()
    paths.paths["wrong-key"] = paths.get("fixture-route")
    with pytest.raises(ttt.MemoryTttPathError):
        ttt.memory_ttt_list_paths(catalog=paths)


@pytest.mark.parametrize("field", ["aliases", "schema_names_as_is"])
def test_hop_sequence_limits_are_checked_before_projection(field) -> None:
    raw = document()
    raw["hops"][0][field] = ["x"] * 33
    with pytest.raises(ttt.MemoryTttPathError):
        ttt.path_from_mapping(raw)


def test_path_bounds_and_projection_roundtrip() -> None:
    raw = document()
    value = ttt.path_from_mapping(raw)
    assert ttt.path_from_mapping(value.as_public_dict()) == value
    for mutation in ({"goal_aliases": ["x"] * 33}, {"hops": raw["hops"] * 17}, {"hop_count": True}):
        with pytest.raises(ttt.MemoryTttPathError):
            ttt.path_from_mapping({**raw, **mutation})


def test_excessive_goal_ties_fail_closed_with_schema_valid_result() -> None:
    rows = []
    for index in range(33):
        row = document()
        row["path_id"] = f"route-{index}"
        rows.append(row)
    value = result(paths=ttt.register_paths(ttt.RunbookPathCatalog(), rows))
    assert value["result"] == "BLOCKED"
    assert value["blocked"]["reason"] == "too_many_matching_paths"


@pytest.mark.parametrize("refs", [(), ("node:start",), ("node:finish",)])
@pytest.mark.parametrize("hop", ["start", "finish"])
def test_unrelated_or_partial_graph_cannot_back_remaining_or_complete(refs, hop) -> None:
    value = result(graph=FixtureGraph(refs), paths=catalog(refs=True), hop=hop)
    assert value["result"] == "BLOCKED"
    assert value["blocked"]["reason"] == "path_nodes_not_in_graph"
    assert value["graph_digest"] is None
    assert value["source_namespace"] is None
    assert value["path"] is None
    assert value["remaining_path"] == []


def test_graph_labels_cannot_replace_missing_explicit_node_references() -> None:
    value = result(graph=FixtureGraph(), paths=catalog())
    assert value["result"] == "BLOCKED"
    assert value["path"] is None


def test_uniquely_resolved_path_retains_positive_graph_route() -> None:
    graph = FixtureGraph()
    value = result(graph=graph, paths=catalog(refs=True))
    assert value["result"] == "REMAINING"
    assert value["graph_digest"] == graph.graph_digest
    assert result(graph=graph, paths=catalog(refs=True), hop="finish")["result"] == "COMPLETE"


def test_ambiguous_node_reference_fails_closed() -> None:
    graph = FixtureGraph()
    graph.aliases["node:finish"] = graph.aliases["start"] + graph.aliases["finish"]
    assert result(graph=graph, paths=catalog(refs=True))["result"] == "BLOCKED"


def test_reported_alias_conflicting_with_graph_is_not_accepted() -> None:
    graph = FixtureGraph(("node:start", "node:finish", "node:foreign"))
    graph.aliases["claimed-start"] = graph.aliases["node:foreign"]
    raw = document(refs=True)
    raw["hops"][0]["aliases"] = ["claimed-start"]
    paths = ttt.register_paths(ttt.RunbookPathCatalog(), [raw])
    assert result(graph=graph, paths=paths, hop="claimed-start")["result"] == "BLOCKED"


def test_invalid_reference_exception_is_fail_closed() -> None:
    raw = document(refs=True)
    raw["hops"][1]["node_ref"] = "invalid-ref"
    paths = ttt.register_paths(ttt.RunbookPathCatalog(), [raw])
    assert result(graph=FixtureGraph(), paths=paths)["result"] == "BLOCKED"


def test_list_cannot_attach_graph_digest_to_unbound_templates() -> None:
    with pytest.raises(ttt.MemoryTttPathError):
        ttt.memory_ttt_list_paths(catalog=catalog(), graph=FixtureGraph())


def test_harvest_pins_resolved_uri_and_keeps_route_non_executable() -> None:
    graph = FixtureGraph()
    route = ttt.harvest_next_hop_paths_from_graph(
        graph, path_id="harvested", title="Harvested", goal_aliases=["lookup address reference"],
        ordered_node_keys=["node:start", "node:finish"],
    )
    assert route.hops[0].node_ref == graph.aliases["node:start"][0]
    paths = ttt.RunbookPathCatalog()
    paths.register(route)
    assert result(graph=graph, paths=paths)["result"] == "REMAINING"
    with pytest.raises(ttt.MemoryTttPathError):
        ttt.harvest_next_hop_paths_from_graph(
            graph, path_id="oversized", title="Oversized", goal_aliases=["oversized"],
            ordered_node_keys=["node:start"] * 33,
        )


def test_snapshot_shaped_string_is_not_a_substitute_for_missing_graph_hops() -> None:
    # The separate standalone snapshot-provenance finding is still outstanding.
    answer = ttt.memory_ttt_autofill(
        "lookup address reference", "start", graph=FixtureGraph(()),
        snapshot_id="sha256:" + "a" * 64, catalog=catalog(refs=True),
    )
    assert answer["result"] == "BLOCKED"
    assert answer["graph_digest"] is None


def test_projection_change_updates_receipt_without_granting_authority() -> None:
    first = result()
    raw = copy.deepcopy(document())
    raw["hops"][1]["hint_template"] = "Changed explicit hint"
    second = result(paths=ttt.register_paths(ttt.RunbookPathCatalog(), [raw]))
    assert first["receipt_id"] != second["receipt_id"]
