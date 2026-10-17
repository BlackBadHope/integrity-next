"""Atomic reviewed-decision application for one History sidecar snapshot."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any, cast

from integrity_chronicle.corpus_index import resolve_corpus_deletion_ledger_path
from integrity_chronicle.state_lock import CorpusStateLockError, corpus_state_lock

from .decision_io import (
    _canonical_path,
    _file_identity,
    _path_key,
    _read_bounded_artifact,
)
from .decisions import (
    HISTORY_REVIEW_REASON_CODE,
    history_review_request_json_bytes,
    history_review_result_json_bytes,
    validate_history_review_request,
    validate_history_review_result,
)
from .sidecar import (
    MAX_DECISION_PAGE_SIZE,
    MAX_LOGICAL_SCOPES,
    HistorySidecarError,
    HistorySidecarReader,
    HistorySidecarSchemaError,
    HistorySidecarStaleError,
    LogicalScope,
    ScopeDecision,
    _build_history_sidecar_from_validated_review,
)


def _scope_values(reader: HistorySidecarReader) -> tuple[LogicalScope, ...]:
    values = tuple(
        LogicalScope(
            scope_id=cast(str, item["scope_id"]),
            display_name=cast(str, item["display_name"]),
            scope_kind=cast(Any, item["scope_kind"]),
            realm=cast(Any, item["realm"]),
            project_id=cast(str | None, item.get("project_id")),
        )
        for item in reader.list_scopes()
    )
    if not 1 <= len(values) <= MAX_LOGICAL_SCOPES:
        raise HistorySidecarSchemaError("sidecar scope inventory is invalid")
    return values


def _iter_scope_decisions(reader: HistorySidecarReader) -> Iterator[ScopeDecision]:
    after_record_id: str | None = None
    after_scope_id: str | None = None
    while True:
        page = reader.scan_scope_decisions(
            after_record_id=after_record_id,
            after_scope_id=after_scope_id,
            limit=MAX_DECISION_PAGE_SIZE,
        )
        values = page.get("decisions")
        if type(values) is not list:
            raise HistorySidecarSchemaError("sidecar decision page is invalid")
        for item in values:
            if type(item) is not dict:
                raise HistorySidecarSchemaError("sidecar decision row is invalid")
            yield ScopeDecision(
                record_id=cast(str, item.get("record_id")),
                scope_id=cast(str, item.get("scope_id")),
                membership=cast(Any, item.get("membership")),
                review_state=cast(Any, item.get("review_state")),
                artifact_sha256=cast(str, item.get("artifact_sha256")),
                reason_code=cast(str, item.get("reason_code")),
            )
        if page.get("has_more") is not True:
            break
        cursor = page.get("next_cursor")
        if type(cursor) is not dict:
            raise HistorySidecarSchemaError("sidecar decision cursor is invalid")
        after_record_id = cast(str, cursor.get("record_id"))
        after_scope_id = cast(str, cursor.get("scope_id"))


def _reviewed_decisions(
    result: Mapping[str, object],
) -> tuple[ScopeDecision, ...]:
    artifact_sha256 = cast(str, result["artifact_sha256"])
    return tuple(
        ScopeDecision(
            record_id=cast(str, item["record_id"]),
            scope_id=cast(str, item["scope_id"]),
            membership=cast(Any, item["membership"]),
            review_state="reviewed",
            artifact_sha256=artifact_sha256,
            reason_code=HISTORY_REVIEW_REASON_CODE,
        )
        for item in cast(list[dict[str, str]], result["decisions"])
    )


def _merged_decisions(
    reader: HistorySidecarReader,
    replacements: tuple[ScopeDecision, ...],
) -> Iterator[ScopeDecision]:
    replacement_keys = {(item.record_id, item.scope_id) for item in replacements}
    for current in _iter_scope_decisions(reader):
        if (current.record_id, current.scope_id) not in replacement_keys:
            yield current
    yield from replacements


@contextmanager
def _lock_paths(paths: Iterable[Path]) -> Iterator[None]:
    unique: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = _path_key(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    try:
        with ExitStack() as stack:
            for path in unique:
                stack.enter_context(corpus_state_lock(str(path)))
            yield
    except CorpusStateLockError as err:
        raise HistorySidecarError("could not lock History review apply inputs") from err


def apply_history_review_result(
    corpus_index_path: str,
    sidecar_path: str,
    request_path: str,
    result_path: str,
    *,
    output_sidecar_path: str | None = None,
) -> dict[str, object]:
    """Atomically rebuild a sidecar with one validated complete review result."""

    corpus = _canonical_path(corpus_index_path, label="corpus index", must_exist=True)
    baseline = _canonical_path(sidecar_path, label="History sidecar", must_exist=True)
    request_file = _canonical_path(
        request_path, label="History review request", must_exist=True
    )
    result_file = _canonical_path(
        result_path, label="History review result", must_exist=True
    )
    output = _canonical_path(
        output_sidecar_path or sidecar_path,
        label="output History sidecar",
        must_exist=False,
    )
    ledger = _canonical_path(
        str(Path(resolve_corpus_deletion_ledger_path(str(corpus))).resolve(strict=False)),
        label="corpus deletion ledger",
        must_exist=True,
    )
    protected = {
        _path_key(corpus),
        _path_key(ledger),
        _path_key(request_file),
        _path_key(result_file),
    }
    if len(protected) != 4:
        raise HistorySidecarSchemaError("History review apply input paths must differ")
    if _path_key(baseline) in protected or _path_key(output) in protected:
        raise HistorySidecarSchemaError(
            "History sidecar paths must differ from corpus and review artifacts"
        )

    sidecar_locks = sorted({baseline, output}, key=lambda item: _path_key(item))
    artifact_locks = sorted(
        (request_file, result_file), key=lambda item: _path_key(item)
    )
    # Match the sidecar builder's sidecar -> corpus -> ledger lock order.
    with _lock_paths((*sidecar_locks, corpus, ledger, *artifact_locks)):
        baseline_identity = _file_identity(baseline, label="History sidecar")
        request_bytes, request_identity = _read_bounded_artifact(
            request_file, label="History review request"
        )
        result_bytes, result_identity = _read_bounded_artifact(
            result_file, label="History review result"
        )
        with HistorySidecarReader(str(corpus), str(baseline)) as reader:
            request = validate_history_review_request(request_bytes, reader=reader)
            if history_review_request_json_bytes(request, reader=reader) != request_bytes:
                raise HistorySidecarSchemaError(
                    "History review request bytes are not canonical"
                )
            result = validate_history_review_result(
                result_bytes, request=request, reader=reader
            )
            if history_review_result_json_bytes(
                result, request=request, reader=reader
            ) != result_bytes:
                raise HistorySidecarSchemaError(
                    "History review result bytes are not canonical"
                )
            scopes = _scope_values(reader)
            replacements = _reviewed_decisions(result)
            binding = cast(dict[str, object], request["binding"])
            expected_corpus_binding = {
                key: binding[key]
                for key in (
                    "base_record_count",
                    "base_record_digest",
                    "corpus_deletion_ledger_digest",
                    "corpus_id",
                    "corpus_logical_index_sha256",
                    "index_generation",
                )
            }

            def prepublish_check() -> None:
                if _file_identity(baseline, label="History sidecar") != baseline_identity:
                    raise HistorySidecarStaleError(
                        "History sidecar changed during reviewed apply"
                    )
                current_request, current_request_identity = _read_bounded_artifact(
                    request_file, label="History review request"
                )
                current_result, current_result_identity = _read_bounded_artifact(
                    result_file, label="History review result"
                )
                if (
                    current_request_identity != request_identity
                    or current_result_identity != result_identity
                    or current_request != request_bytes
                    or current_result != result_bytes
                ):
                    raise HistorySidecarStaleError(
                        "History review artifacts changed during apply"
                    )
                validate_history_review_request(request, reader=reader)
                validate_history_review_result(result, request=request, reader=reader)

            summary = _build_history_sidecar_from_validated_review(
                str(corpus),
                str(output),
                scopes=scopes,
                decisions=_merged_decisions(reader, replacements),
                expected_corpus_binding=expected_corpus_binding,
                prepublish_check=prepublish_check,
            )

    return {
        **summary,
        "review_request_sha256": request["artifact_sha256"],
        "review_result_sha256": result["artifact_sha256"],
        "applied_decision_count": len(replacements),
    }


__all__ = ["apply_history_review_result"]
