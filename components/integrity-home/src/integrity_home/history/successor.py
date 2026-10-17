"""Deterministic scope ownership plan for a unified corpus successor."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from .decisions import ReviewChoice


def plan_successor_memberships(
    *,
    record_ids: Iterable[str],
    scope_ids: Iterable[str],
    target_scope_id: str,
    imported_record_ids: Iterable[str],
    previous: Mapping[tuple[str, str], str],
) -> tuple[ReviewChoice, ...]:
    """Preserve reviewed ownership and explicitly classify new records.

    Importing into a named scope is an explicit include for that scope only.
    Every other new record/scope pair is ``unknown`` rather than guessed.
    Existing multi-scope choices are retained exactly.
    """

    records = tuple(sorted(set(record_ids)))
    scopes = tuple(sorted(set(scope_ids)))
    imported = frozenset(imported_record_ids)
    if not records or not scopes or target_scope_id not in scopes:
        raise ValueError("successor membership inputs are incomplete")
    if not imported or not imported.issubset(records):
        raise ValueError("imported records are outside the successor corpus")
    valid_pairs = {(record_id, scope_id) for record_id in records for scope_id in scopes}
    if any(pair not in valid_pairs for pair in previous):
        raise ValueError("previous decision is outside the successor inventory")

    choices: list[ReviewChoice] = []
    for record_id in records:
        for scope_id in scopes:
            prior = previous.get((record_id, scope_id))
            if prior is not None:
                membership = prior
            elif record_id in imported:
                membership = "include" if scope_id == target_scope_id else "unknown"
            else:
                membership = "unknown"
            choices.append(ReviewChoice(record_id, scope_id, membership))
    return tuple(choices)
