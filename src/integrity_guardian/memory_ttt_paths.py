"""TIME-TO-TASK runbook-path overlay atop Memory Link Graph.

A runbook path is NOT execution and NOT the runbook document itself. It is a
chain of navigational hops an LLM agent can follow to cut time-to-task. Edges
are hints/templates (prefer read-only) and never grant production apply
authority.

Target-specific recipes are explicit host inputs, never portable defaults.
Autofill does not execute hops or grant authority. With a graph, every path
node must resolve in that graph; caller-declared order is still only a hint.
Standalone snapshot-ID admission remains a separate integration requirement.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .canonical import parse_json_strict
from .hashing import digest_object
from .memory_link_graph import (
    MemoryLinkGraph,
    MemoryLinkGraphError,
    normalize_memory_alias,
)

MEMORY_TTT_AUTOFILL_PROTOCOL = "integrity-guardian/memory-ttt-autofill/v1"
MEMORY_TTT_PATH_CATALOG_PROTOCOL = "integrity-guardian/memory-ttt-path-catalog/v1"
MEMORY_TTT_PATH_RELATION = "next-hop"

# Closed hop modes. Mutate-shaped modes are always fail-closed at autofill.
_HINT_MODES = frozenset(
    {
        "navigational-hint",
        "read-only-evidence",
        "entity-brief",
        "alias-resolve",
    }
)
_TABOO_MODES = frozenset(
    {
        "mutate-billing",
        "production-apply",
        "sql-write",
        "schema-migrate",
    }
)

_MAX_GOAL_LENGTH = 512
_MAX_HOP_LENGTH = 512
_MAX_PATHS = 64
_MAX_HOPS_PER_PATH = 32
MAX_MEMORY_TTT_PATH_CATALOG_BYTES = 1_048_576

_MEMORY_TTT_LOOKUP_BOUNDARY = {
    "prefer": ("entity_brief", "memory-link-resolve", "memory_ttt_autofill"),
    "forbid_as_search": ("integrity_read_events_pagination",),
    "production_authority": False,
    "mutate_billing_mariadb": False,
}


def memory_alias_equivalence_keys(value: Any) -> tuple[str, ...]:
    """Return the portable exact alias key without target-specific aliases."""

    return (normalize_memory_alias(value),)


class MemoryTttPathError(ValueError):
    """Runbook-path catalog or autofill request is invalid."""


def _bounded_string(value: Any, name: str, maximum: int, *, empty: bool = False) -> str:
    if type(value) is not str or len(value) > maximum or (not empty and not value.strip()):
        raise MemoryTttPathError(f"invalid {name}")
    if any(ord(char) < 32 for char in value):
        raise MemoryTttPathError(f"control character in {name}")
    return value


def _string_tuple(value: Any, name: str, maximum: int) -> tuple[str, ...]:
    if type(value) not in (list, tuple) or len(value) > 32:
        raise MemoryTttPathError(f"invalid {name}")
    return tuple(_bounded_string(item, name, maximum) for item in value)


def _false_flags(document: Mapping[str, Any], names: tuple[str, ...]) -> None:
    if any(document.get(name, False) is not False for name in names):
        raise MemoryTttPathError("runbook declarations cannot claim execution or authority")


@dataclass(frozen=True)
class RunbookPathHop:
    """One navigational hop in a TIME-TO-TASK path."""

    hop_id: str
    title: str
    aliases: tuple[str, ...] = ()
    hint_template: str = ""
    mode: str = "navigational-hint"
    node_ref: str | None = None
    evidence_path: str | None = None
    schema_names_as_is: tuple[str, ...] = ()
    executable: bool = False
    production_authority: bool = False
    mutate_billing: bool = False

    def __post_init__(self) -> None:
        _bounded_string(self.hop_id, "hop_id", 256)
        _bounded_string(self.title, "hop title", 256)
        _bounded_string(self.hint_template, "hint_template", 4096, empty=True)
        object.__setattr__(self, "aliases", _string_tuple(self.aliases, "hop aliases", 256))
        object.__setattr__(self, "schema_names_as_is",
                           _string_tuple(self.schema_names_as_is, "schema names", 256))
        for value in (self.node_ref, self.evidence_path):
            if value is not None:
                _bounded_string(value, "hop reference", 256)
        if self.is_taboo():
            raise MemoryTttPathError("runbook hop is executable, authoritative or unsupported")

    def normalized_keys(self) -> frozenset[str]:
        keys: set[str] = set()
        for raw in (self.hop_id, self.title, *self.aliases):
            normalized = normalize_memory_alias(raw)
            if not normalized:
                continue
            keys.update(memory_alias_equivalence_keys(normalized))
        if self.node_ref:
            normalized = normalize_memory_alias(self.node_ref)
            if normalized:
                keys.update(memory_alias_equivalence_keys(normalized))
        return frozenset(keys)

    def is_taboo(self) -> bool:
        return (
            self.executable is not False
            or self.production_authority is not False
            or self.mutate_billing is not False
            or type(self.mode) is not str
            or self.mode not in _HINT_MODES
        )

    def as_public_dict(self) -> dict[str, Any]:
        self.__post_init__()
        return {
            "hop_id": self.hop_id,
            "title": self.title,
            "aliases": list(self.aliases),
            "hint_template": self.hint_template,
            "mode": self.mode,
            "node_ref": self.node_ref,
            "evidence_path": self.evidence_path,
            "schema_names_as_is": list(self.schema_names_as_is),
            "executable": False,
            "production_authority": False,
            "mutate_billing": False,
            "navigational_only": True,
        }


@dataclass(frozen=True)
class RunbookPath:
    """Ordered chain of hops for one ops goal."""

    path_id: str
    title: str
    goal_aliases: tuple[str, ...]
    hops: tuple[RunbookPathHop, ...]
    description: str = ""
    source: str = "caller-supplied"
    production_authority: bool = False

    def __post_init__(self) -> None:
        _bounded_string(self.path_id, "path_id", 256)
        _bounded_string(self.title, "path title", 256)
        _bounded_string(self.description, "description", 4096, empty=True)
        _bounded_string(self.source, "source", 64)
        object.__setattr__(self, "goal_aliases",
                           _string_tuple(self.goal_aliases, "goal aliases", 256))
        if not self.goal_aliases:
            raise MemoryTttPathError("goal_aliases are required")
        if type(self.hops) not in (list, tuple) or not 1 <= len(self.hops) <= _MAX_HOPS_PER_PATH:
            raise MemoryTttPathError("path requires 1 to 32 hops")
        object.__setattr__(self, "hops", tuple(self.hops))
        if self.production_authority is not False:
            raise MemoryTttPathError("runbook paths cannot claim production_authority")
        seen: set[str] = set()
        for hop in self.hops:
            if type(hop) is not RunbookPathHop:
                raise MemoryTttPathError("path member must be a RunbookPathHop")
            hop.__post_init__()
            if hop.hop_id in seen:
                raise MemoryTttPathError("duplicate hop_id in path")
            seen.add(hop.hop_id)

    def goal_keys(self) -> frozenset[str]:
        keys: set[str] = set()
        for raw in (self.path_id, self.title, *self.goal_aliases):
            normalized = normalize_memory_alias(raw)
            if not normalized:
                continue
            keys.update(memory_alias_equivalence_keys(normalized))
        return frozenset(keys)

    def as_public_dict(self) -> dict[str, Any]:
        self.__post_init__()
        return {
            "path_id": self.path_id,
            "title": self.title,
            "goal_aliases": list(self.goal_aliases),
            "description": self.description,
            "source": self.source,
            "hop_count": len(self.hops),
            "hops": [hop.as_public_dict() for hop in self.hops],
            "production_authority": False,
            "route_authority": False,
            "executable": False,
        }



# Goal->path matching: exact normalized keys, alias substring, or significant
# token overlap. Deterministic; no ML. Prefer the most specific path on ties.
_GOAL_MATCH_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "the",
        "to",
        "of",
        "in",
        "on",
        "for",
        "and",
        "or",
        "not",
        "with",
        "from",
        "by",
        "via",
        "as",
        "is",
        "at",
        "be",
        "it",
        "we",
        "you",
        "this",
        "that",
        "into",
        "over",
        "under",
        "ops",
        "через",
        "когда",
        "как",
        "где",
        "что",
        "это",
        "для",
        "или",
        "не",
        "на",
        "по",
        "из",
        "от",
        "до",
        "без",
        "при",
        "чтобы",
        "если",
    }
)
_TOKEN_SPLIT_RE = re.compile(r"[^0-9a-zа-яёіїєґ]+", re.IGNORECASE)
_MIN_SUBSTRING_ALIAS_LEN = 8
_MIN_TOKEN_OVERLAP = 2


def _hyphen_flex_forms(normalized: str) -> frozenset[str]:
    forms = {normalized}
    flexed = normalize_memory_alias(
        normalized.replace("-", " ").replace("_", " ").replace(".", " ")
    )
    if flexed:
        forms.add(flexed)
    return frozenset(forms)


def _significant_goal_tokens(text: str) -> frozenset[str]:
    tokens: set[str] = set()
    for form in _hyphen_flex_forms(normalize_memory_alias(text)):
        for part in _TOKEN_SPLIT_RE.split(form):
            token = part.strip()
            if len(token) < 2 or token in _GOAL_MATCH_STOPWORDS:
                continue
            tokens.add(token)
    return frozenset(tokens)


def _token_soft_overlap(goal_tokens: frozenset[str], alias_tokens: frozenset[str]) -> int:
    """Count soft token hits (exact or prefix for len>=4). Each alias token once."""

    used: set[str] = set()
    count = 0
    for goal_token in sorted(goal_tokens):
        for alias_token in sorted(alias_tokens):
            if alias_token in used:
                continue
            if goal_token == alias_token or (
                min(len(goal_token), len(alias_token)) >= 4
                and (
                    goal_token.startswith(alias_token)
                    or alias_token.startswith(goal_token)
                )
            ):
                used.add(alias_token)
                count += 1
                break
    return count


def _goal_path_match_score(goal: str, path: RunbookPath) -> tuple[int, int, int] | None:
    """Return a comparable score tuple (higher is better) or None if no match.

    Tiers: 3=exact normalized key, 2=alias substring, 1=significant token overlap.
    Secondary components prefer longer / denser matches (more specific).
    """

    normalized = normalize_memory_alias(goal)
    if not normalized:
        return None

    goal_keys = frozenset(memory_alias_equivalence_keys(normalized))
    for form in _hyphen_flex_forms(normalized):
        goal_keys |= frozenset(memory_alias_equivalence_keys(form))
    path_keys = path.goal_keys()
    intersection = goal_keys & path_keys
    if intersection:
        specificity = max(len(key) for key in intersection)
        return (3, specificity, len(intersection))

    goal_forms = _hyphen_flex_forms(normalized)
    best_sub_len = 0
    for raw in (path.path_id, path.title, *path.goal_aliases):
        alias_norm = normalize_memory_alias(raw)
        if not alias_norm:
            continue
        for alias_form in _hyphen_flex_forms(alias_norm):
            if len(alias_form) < _MIN_SUBSTRING_ALIAS_LEN:
                continue
            for goal_form in goal_forms:
                if len(goal_form) < _MIN_SUBSTRING_ALIAS_LEN:
                    continue
                if alias_form in goal_form or goal_form in alias_form:
                    best_sub_len = max(best_sub_len, min(len(alias_form), len(goal_form)))
    if best_sub_len:
        return (2, best_sub_len, 0)

    goal_tokens = _significant_goal_tokens(goal)
    if not goal_tokens:
        return None
    alias_tokens: set[str] = set()
    for raw in (path.path_id, path.title, *path.goal_aliases):
        alias_tokens.update(_significant_goal_tokens(raw))
    overlap = _token_soft_overlap(goal_tokens, frozenset(alias_tokens))
    if overlap >= _MIN_TOKEN_OVERLAP:
        density = (overlap * 100) // max(len(goal_tokens), 1)
        return (1, overlap, density)
    return None


@dataclass
class RunbookPathCatalog:
    """Explicit bounded hint catalogue; its presence is not Seed admission."""

    paths: dict[str, RunbookPath] = field(default_factory=dict)
    source_digest: str | None = None

    def __post_init__(self) -> None:
        self.validate()
        self.paths = dict(self.paths)

    def validate(self) -> None:
        if type(self.paths) is not dict or len(self.paths) > _MAX_PATHS:
            raise MemoryTttPathError("invalid runbook catalogue")
        for key, path in self.paths.items():
            if type(path) is not RunbookPath or key != path.path_id:
                raise MemoryTttPathError("invalid catalogue member")
            path.__post_init__()
        if self.source_digest is not None and re.fullmatch(
            r"sha256:[a-f0-9]{64}", self.source_digest
        ) is None:
            raise MemoryTttPathError("invalid runbook catalogue source digest")

    def register(self, path: RunbookPath) -> None:
        self.validate()
        if type(path) is not RunbookPath:
            raise MemoryTttPathError("invalid catalogue member")
        path.__post_init__()
        if len(self.paths) >= _MAX_PATHS and path.path_id not in self.paths:
            raise MemoryTttPathError("runbook path catalog limit exceeded")
        self.paths[path.path_id] = path
        # A normal in-process update is no longer the byte-exact file that
        # established this binding.  A fresh digest requires a complete reload.
        self.source_digest = None

    def get(self, path_id: str) -> RunbookPath | None:
        self.validate()
        return self.paths.get(path_id)

    def all_paths(self) -> tuple[RunbookPath, ...]:
        self.validate()
        return tuple(self.paths[key] for key in sorted(self.paths))

    def match_goals(self, goal: str) -> list[RunbookPath]:
        """Match goal to paths via exact key, alias substring, or token overlap.

        Returns only the most specific tied winners (deterministic). Callers that
        see more than one result treat the goal as AMBIGUOUS.
        """

        scored: list[tuple[tuple[int, int, int], RunbookPath]] = []
        for path in self.all_paths():
            score = _goal_path_match_score(goal, path)
            if score is not None:
                scored.append((score, path))
        if not scored:
            return []
        best_score = max(score for score, _path in scored)
        winners = [path for score, path in scored if score == best_score]
        return sorted(winners, key=lambda item: item.path_id)


def default_runbook_path_catalog() -> RunbookPathCatalog:
    """An empty portable catalogue. Hosts must explicitly supply target paths."""
    return RunbookPathCatalog()


def path_from_mapping(document: Mapping[str, Any]) -> RunbookPath:
    """Parse explicit path data; JSON decoding and custody belong to the host."""
    path_fields = {"path_id", "title", "goal_aliases", "hops", "description", "source",
                   "production_authority", "route_authority", "executable", "hop_count"}
    if not isinstance(document, Mapping) or set(document) - path_fields:
        raise MemoryTttPathError("invalid path document")
    _false_flags(document, ("production_authority", "route_authority", "executable"))
    hops_raw = document.get("hops")
    if type(hops_raw) not in (list, tuple) or not 1 <= len(hops_raw) <= _MAX_HOPS_PER_PATH:
        raise MemoryTttPathError("path requires 1 to 32 hops")
    if "hop_count" in document and (
        type(document["hop_count"]) is not int or document["hop_count"] != len(hops_raw)
    ):
        raise MemoryTttPathError("hop_count mismatch")
    hop_fields = {"hop_id", "title", "aliases", "hint_template", "mode", "node_ref",
                  "evidence_path", "schema_names_as_is", "executable", "production_authority",
                  "mutate_billing", "navigational_only"}
    hops = []
    for item in hops_raw:
        if not isinstance(item, Mapping) or set(item) - hop_fields:
            raise MemoryTttPathError("invalid hop document")
        _false_flags(item, ("executable", "production_authority", "mutate_billing"))
        if item.get("navigational_only", True) is not True:
            raise MemoryTttPathError("runbook hops must be navigational")
        hops.append(RunbookPathHop(
            hop_id=item.get("hop_id", ""), title=item.get("title", item.get("hop_id", "")),
            aliases=item.get("aliases", ()), hint_template=item.get("hint_template", ""),
            mode=item.get("mode", "navigational-hint"), node_ref=item.get("node_ref"),
            evidence_path=item.get("evidence_path"),
            schema_names_as_is=item.get("schema_names_as_is", ()),
        ))
    goals = document.get("goal_aliases", ())
    if isinstance(goals, str):
        goals = (goals,)
    return RunbookPath(
        path_id=document.get("path_id", ""),
        title=document.get("title", document.get("path_id", "")),
        goal_aliases=goals, hops=tuple(hops),
        description=document.get("description", ""), source=document.get("source", "caller-supplied"),
    )


def register_paths(
    catalog: RunbookPathCatalog,
    documents: Iterable[Mapping[str, Any]],
) -> RunbookPathCatalog:
    """All-or-nothing bounded admission; a rejected batch leaves no partial paths."""
    candidate = RunbookPathCatalog(dict(catalog.paths), catalog.source_digest)
    for count, document in enumerate(documents, 1):
        if count > _MAX_PATHS:
            raise MemoryTttPathError("runbook path batch limit exceeded")
        candidate.register(path_from_mapping(document))
    catalog.paths = dict(candidate.paths)
    catalog.source_digest = candidate.source_digest
    return catalog


def _read_bounded_regular_file(path: Path, maximum_bytes: int) -> bytes:
    """Read at most one byte beyond a regular-file limit from the held handle."""

    try:
        with path.open("rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise MemoryTttPathError("path catalogue source is not a regular file")
            raw = handle.read(maximum_bytes + 1)
    except MemoryTttPathError:
        raise
    except OSError as exc:
        raise MemoryTttPathError("path catalogue could not be read") from exc
    if len(raw) > maximum_bytes:
        raise MemoryTttPathError("path catalogue exceeds 1048576 bytes")
    return raw


def load_runbook_path_catalog(
    path: Path | None,
    expected_digest: str | None,
) -> RunbookPathCatalog:
    """Load one explicit byte-bound host catalogue; never search for defaults."""

    if path is None:
        if expected_digest is not None:
            raise MemoryTttPathError("expected digest requires a path catalogue")
        return default_runbook_path_catalog()
    if expected_digest is None:
        raise MemoryTttPathError("path catalogue requires an expected digest")
    raw = _read_bounded_regular_file(path, MAX_MEMORY_TTT_PATH_CATALOG_BYTES)
    observed_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if expected_digest != observed_digest:
        raise MemoryTttPathError(
            "path catalogue digest mismatch: "
            f"expected {expected_digest}, observed {observed_digest}"
        )
    document = parse_json_strict(raw)
    if not isinstance(document, dict) or type(document.get("paths")) is not list:
        raise MemoryTttPathError("path catalogue must be a JSON object with a paths array")
    if document.get("automatic_load", False) is not False:
        raise MemoryTttPathError("path catalogue cannot request automatic loading")
    if document.get("production_authority", False) is not False:
        raise MemoryTttPathError("path catalogue cannot claim production authority")
    catalog = register_paths(RunbookPathCatalog(), document["paths"])
    catalog.source_digest = observed_digest
    catalog.validate()
    return catalog


def harvest_next_hop_paths_from_graph(
    graph: MemoryLinkGraph,
    *,
    path_id: str,
    title: str,
    goal_aliases: Sequence[str],
    ordered_node_keys: Sequence[str],
) -> RunbookPath:
    """Build a navigational path whose hops resolve against admitted MLG nodes.

    Missing node keys fail closed (no invention). Edges are next-hop hints only.
    """

    if (type(ordered_node_keys) not in (list, tuple)
            or not 1 <= len(ordered_node_keys) <= _MAX_HOPS_PER_PATH):
        raise MemoryTttPathError("ordered path requires 1 to 32 node keys")
    hops: list[RunbookPathHop] = []
    for index, key in enumerate(ordered_node_keys):
        _query, matches = graph._resolve_uris(str(key))
        if len(matches) != 1:
            raise MemoryTttPathError(
                f"ordered hop {key!r} must resolve to exactly one admitted node"
            )
        node = graph._node_documents[matches[0]]
        hops.append(
            RunbookPathHop(
                hop_id=f"hop-{index + 1}-{node['key']}",
                title=str(node["title"]),
                aliases=tuple(node.get("aliases") or ()),
                hint_template=(
                    f"Follow next-hop hint to admitted {node['kind']} node {node['key']}. "
                    "Navigational only; not execution authority."
                ),
                mode="navigational-hint",
                node_ref=matches[0],
            )
        )
    return RunbookPath(
        path_id=path_id,
        title=title,
        goal_aliases=tuple(goal_aliases),
        hops=tuple(hops),
        source="graph-harvested",
    )


def _graph_path_nodes(path: RunbookPath, graph: MemoryLinkGraph) -> tuple[str, ...]:
    """Resolve every node; this does not prove the caller-declared edge ordering."""
    resolved = []
    for hop in path.hops:
        if not hop.node_ref:
            raise MemoryTttPathError("every graph-backed hop requires a node_ref")
        _query, matches = graph._resolve_uris(hop.node_ref)
        if len(matches) != 1 or matches[0] not in graph._node_documents:
            raise MemoryTttPathError("path node is absent or ambiguous in the graph")
        resolved.append(matches[0])
    return tuple(resolved)


def _match_hop_indexes(
    path: RunbookPath, last_hop: str, graph: MemoryLinkGraph | None
) -> list[int]:
    normalized = normalize_memory_alias(last_hop)
    if not normalized:
        return []
    keys = frozenset(memory_alias_equivalence_keys(normalized))
    indexes: list[int] = []
    graph_uris: tuple[str, ...] = ()
    if graph is not None:
        _query, graph_uris = graph._resolve_uris(last_hop)
    for index, hop in enumerate(path.hops):
        if graph is not None:
            if not hop.node_ref:
                continue
            _node_query, node_uris = graph._resolve_uris(hop.node_ref)
            if len(node_uris) != 1 or (graph_uris and graph_uris != node_uris):
                continue
        if keys & hop.normalized_keys():
            indexes.append(index)
            continue
        if graph is not None and hop.node_ref:
            _node_query, node_uris = graph._resolve_uris(hop.node_ref)
            if len(graph_uris) == 1 and graph_uris == node_uris and len(node_uris) == 1:
                indexes.append(index)
    seen: set[int] = set()
    unique: list[int] = []
    for index in indexes:
        if index not in seen:
            seen.add(index)
            unique.append(index)
    return unique


def _result(
    *,
    result: str,
    goal: str,
    last_hop: str,
    graph: MemoryLinkGraph | None,
    catalog: RunbookPathCatalog,
    path: RunbookPath | None,
    remaining_path: list[dict[str, Any]],
    blocked: dict[str, Any] | None,
    ambiguous: dict[str, Any] | None,
    hops_saved_estimate: int,
) -> dict[str, Any]:
    core = {
        "protocol": MEMORY_TTT_AUTOFILL_PROTOCOL,
        "catalog_protocol": MEMORY_TTT_PATH_CATALOG_PROTOCOL,
        "path_catalog_digest": catalog.source_digest,
        "path_relation": MEMORY_TTT_PATH_RELATION,
        "graph_digest": graph.graph_digest if graph is not None else None,
        "source_namespace": graph.source_namespace if graph is not None else None,
        "goal": goal,
        "normalized_goal": normalize_memory_alias(goal),
        "last_hop": last_hop,
        "normalized_last_hop": normalize_memory_alias(last_hop),
        "result": result,
        "path": path.as_public_dict() if path is not None else None,
        "remaining_path": remaining_path,
        "blocked": blocked,
        "ambiguous": ambiguous,
        "hops_saved_estimate": hops_saved_estimate,
        "path_count": len(catalog.paths),
        "ops_lookup_policy": {
            "production_authority": False,
            "mutate_billing_mariadb": False,
            "prefer": list(_MEMORY_TTT_LOOKUP_BOUNDARY["prefer"]),
            "forbid_as_search": list(_MEMORY_TTT_LOOKUP_BOUNDARY["forbid_as_search"]),
        },
        "executable": False,
        "persistent_derived_state": False,
        "production_authority": False,
        "route_authority": False,
        "live_seed_append": False,
        "mariadb_touched": False,
    }
    return {
        **core,
        "receipt_id": digest_object(core, domain="memory-ttt-autofill-v1"),
    }


def _blocked(
    *,
    reason: str,
    goal: str,
    last_hop: str,
    graph: MemoryLinkGraph | None,
    catalog: RunbookPathCatalog,
    path: RunbookPath | None = None,
    detail: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return _result(
        result="BLOCKED",
        goal=goal,
        last_hop=last_hop,
        graph=graph,
        catalog=catalog,
        path=path,
        remaining_path=[],
        blocked={"reason": reason, **dict(detail or {})},
        ambiguous=None,
        hops_saved_estimate=0,
    )


def _ambiguous(
    *,
    reason: str,
    goal: str,
    last_hop: str,
    graph: MemoryLinkGraph | None,
    catalog: RunbookPathCatalog,
    path: RunbookPath | None = None,
    candidates: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    return _result(
        result="AMBIGUOUS",
        goal=goal,
        last_hop=last_hop,
        graph=graph,
        catalog=catalog,
        path=path,
        remaining_path=[],
        blocked=None,
        ambiguous={"reason": reason, "candidates": list(candidates)},
        hops_saved_estimate=0,
    )


def memory_ttt_autofill(
    goal: str,
    last_hop: str,
    *,
    graph: MemoryLinkGraph | None = None,
    snapshot_id: str | None = None,
    expected_graph_digest: str | None = None,
    catalog: RunbookPathCatalog | None = None,
) -> dict[str, Any]:
    """Autofill a runbook path from the last known hop.

    Returns remaining_path on success, or blocked/ambiguous fail-closed outcomes.
    Never invents hops, never grants production authority, never emits mutate
    billing steps as executable.
    """

    if not isinstance(goal, str) or not goal.strip() or len(goal) > _MAX_GOAL_LENGTH:
        raise MemoryTttPathError("goal must contain 1 to 512 characters")
    if not isinstance(last_hop, str) or not last_hop.strip() or len(last_hop) > _MAX_HOP_LENGTH:
        raise MemoryTttPathError("last_hop must contain 1 to 512 characters")

    active_catalog = catalog or default_runbook_path_catalog()
    active_catalog.validate()

    if snapshot_id is not None:
        if graph is None:
            return _blocked(
                reason="snapshot_id_requires_admitted_graph",
                goal=goal,
                last_hop=last_hop,
                graph=graph,
                catalog=active_catalog,
            )
        if not isinstance(snapshot_id, str) or not snapshot_id.startswith("sha256:"):
            return _blocked(
                reason="snapshot_id_invalid",
                goal=goal,
                last_hop=last_hop,
                graph=graph,
                catalog=active_catalog,
            )

    if expected_graph_digest is not None:
        if graph is None:
            return _blocked(
                reason="graph_digest_requires_admitted_graph",
                goal=goal,
                last_hop=last_hop,
                graph=graph,
                catalog=active_catalog,
            )
        if expected_graph_digest != graph.graph_digest:
            return _blocked(
                reason="graph_digest_mismatch",
                goal=goal,
                last_hop=last_hop,
                graph=graph,
                catalog=active_catalog,
                detail={
                    "expected_graph_digest": expected_graph_digest,
                    "actual_graph_digest": graph.graph_digest,
                },
            )

    matches = active_catalog.match_goals(goal)
    if not matches:
        return _blocked(
            reason="goal_unknown_in_path_catalog",
            goal=goal,
            last_hop=last_hop,
            graph=graph,
            catalog=active_catalog,
        )
    if len(matches) > 32:
        return _blocked(
            reason="too_many_matching_paths", goal=goal, last_hop=last_hop,
            graph=None, catalog=active_catalog,
        )
    if len(matches) > 1:
        return _ambiguous(
            reason="goal_matches_multiple_paths",
            goal=goal,
            last_hop=last_hop,
            graph=graph,
            catalog=active_catalog,
            candidates=[
                {
                    "path_id": path.path_id,
                    "title": path.title,
                    "goal_aliases": list(path.goal_aliases),
                }
                for path in matches
            ],
        )

    path = matches[0]
    if graph is not None:
        try:
            _graph_path_nodes(path, graph)
        except (MemoryTttPathError, MemoryLinkGraphError):
            return _blocked(
                reason="path_nodes_not_in_graph", goal=goal, last_hop=last_hop,
                graph=None, catalog=active_catalog, detail={"path_id": path.path_id},
            )
    hop_indexes = _match_hop_indexes(path, last_hop, graph)
    if not hop_indexes:
        return _blocked(
            reason="last_hop_unknown_in_path",
            goal=goal,
            last_hop=last_hop,
            graph=graph,
            catalog=active_catalog,
            path=path,
            detail={
                "path_id": path.path_id,
                "known_hop_ids": [hop.hop_id for hop in path.hops],
            },
        )
    if len(hop_indexes) > 1:
        return _ambiguous(
            reason="last_hop_matches_multiple_path_hops",
            goal=goal,
            last_hop=last_hop,
            graph=graph,
            catalog=active_catalog,
            path=path,
            candidates=[
                {"hop_id": path.hops[index].hop_id, "title": path.hops[index].title}
                for index in hop_indexes
            ],
        )

    hop_index = hop_indexes[0]
    remaining_hops = path.hops[hop_index + 1 :]
    for hop in remaining_hops:
        if hop.is_taboo():
            return _blocked(
                reason="remaining_path_contains_taboo_or_mutate_step",
                goal=goal,
                last_hop=last_hop,
                graph=graph,
                catalog=active_catalog,
                path=path,
                detail={
                    "taboo_hop_id": hop.hop_id,
                    "taboo_mode": hop.mode,
                    "mutate_billing": hop.mutate_billing,
                    "production_authority": hop.production_authority,
                },
            )
        if hop.executable and (
            hop.mutate_billing
            or "mutate" in hop.mode
            or ("billing" in hop.mode and "read" not in hop.mode)
        ):
            return _blocked(
                reason="refusing_executable_mutate_billing_step",
                goal=goal,
                last_hop=last_hop,
                graph=graph,
                catalog=active_catalog,
                path=path,
                detail={"hop_id": hop.hop_id},
            )

    remaining_path = [hop.as_public_dict() for hop in remaining_hops]
    for item in remaining_path:
        item["executable"] = False
        item["production_authority"] = False
        item["mutate_billing"] = False
        item["navigational_only"] = True

    result = "COMPLETE" if not remaining_path else "REMAINING"
    return _result(
        result=result,
        goal=goal,
        last_hop=last_hop,
        graph=graph,
        catalog=active_catalog,
        path=path,
        remaining_path=remaining_path,
        blocked=None,
        ambiguous=None,
        hops_saved_estimate=hop_index + 1,
    )


def memory_ttt_list_paths(
    *,
    catalog: RunbookPathCatalog | None = None,
    graph: MemoryLinkGraph | None = None,
) -> dict[str, Any]:
    active = catalog or default_runbook_path_catalog()
    paths = active.all_paths()
    if graph is not None:
        for path in paths:
            _graph_path_nodes(path, graph)
    core = {
        "protocol": MEMORY_TTT_PATH_CATALOG_PROTOCOL,
        "path_relation": MEMORY_TTT_PATH_RELATION,
        "graph_digest": graph.graph_digest if graph is not None else None,
        "paths": [path.as_public_dict() for path in paths],
        "path_count": len(active.paths),
        "production_authority": False,
        "route_authority": False,
        "executable": False,
        "mariadb_touched": False,
        "live_seed_append": False,
    }
    return {
        **core,
        "receipt_id": digest_object(core, domain="memory-ttt-path-catalog-v1"),
    }


__all__ = [
    "MEMORY_TTT_AUTOFILL_PROTOCOL",
    "MEMORY_TTT_PATH_CATALOG_PROTOCOL",
    "MEMORY_TTT_PATH_RELATION",
    "MemoryTttPathError",
    "RunbookPath",
    "RunbookPathCatalog",
    "RunbookPathHop",
    "default_runbook_path_catalog",
    "harvest_next_hop_paths_from_graph",
    "memory_ttt_autofill",
    "memory_ttt_list_paths",
    "path_from_mapping",
    "register_paths",
]
