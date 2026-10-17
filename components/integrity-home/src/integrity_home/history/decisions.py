"""Strict content-free review artifacts for History scope ownership.

Version 1 reviews the exact bounded logical-scope set sealed into its sidecar.
The request names an exact sidecar snapshot and bounded record identities.  A
result must explicitly decide every record/scope pair; uncertainty is stored as
``unknown`` rather than inferred from an omitted row.  Neither artifact stores
message text, source locators, catalog evidence, timestamps, or local paths.

The SHA-256 seals provide deterministic tamper evidence, not reviewer identity
or authorization against a local writer able to replace and re-seal files.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Any, Final, Literal, cast

from integrity_chronicle.json_integrity import (
    DuplicateJsonKeyError,
    loads_json_strict,
)

from .sidecar import (
    DEFAULT_LOGICAL_SCOPES,
    HISTORY_SIDECAR_SCHEMA_VERSION,
    MAX_LOGICAL_SCOPES,
    MAX_PAGE_SIZE,
    MAX_RECORDS,
    PERSONAL_SCOPE_ID,
    REVIEWED_SCOPE_REASON_CODE,
    HistorySidecarReader,
    HistorySidecarSchemaError,
    HistorySidecarStaleError,
)


HISTORY_REVIEW_REQUEST_SCHEMA_VERSION: Final = (
    "integrity-home-history-review-request/1"
)
HISTORY_REVIEW_RESULT_SCHEMA_VERSION: Final = (
    "integrity-home-history-review-result/1"
)
HISTORY_REVIEW_CONTENT_POLICY: Final = "content-free-record-identities/1"
HISTORY_REVIEW_POLICY: Final = "explicit-scopes-complete/1"
HISTORY_REVIEW_COVERAGE: Final = "complete-cartesian/1"
HISTORY_REVIEW_REASON_CODE: Final = REVIEWED_SCOPE_REASON_CODE
HISTORY_REVIEW_SCOPE_IDS: Final = (
    PERSONAL_SCOPE_ID,
)

MAX_HISTORY_REVIEW_RECORDS: Final = MAX_PAGE_SIZE
MAX_HISTORY_REVIEW_DECISIONS: Final = (
    MAX_HISTORY_REVIEW_RECORDS * MAX_LOGICAL_SCOPES
)
MAX_HISTORY_REVIEW_ARTIFACT_BYTES: Final = 1 << 20
MAX_STABLE_ID_CHARS: Final = 128

_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_STABLE_ID = re.compile(
    r"^[a-z0-9](?:[a-z0-9._-]{0,63})(?::[a-z0-9][a-z0-9._-]{0,63})*$"
)
_MEMBERSHIPS = frozenset(("exclude", "include", "unknown"))
_REQUEST_FIELDS = frozenset(
    (
        "artifact_sha256",
        "binding",
        "content_policy",
        "record_count",
        "records",
        "review_policy",
        "schema_version",
        "scope_ids",
    )
)
_BINDING_FIELDS = frozenset(
    (
        "base_record_count",
        "base_record_digest",
        "corpus_deletion_ledger_digest",
        "corpus_id",
        "corpus_logical_index_sha256",
        "index_generation",
        "sidecar_generation",
        "sidecar_schema_version",
    )
)
_RESULT_FIELDS = frozenset(
    (
        "artifact_sha256",
        "content_policy",
        "coverage",
        "decision_count",
        "decisions",
        "request_sha256",
        "review_policy",
        "schema_version",
    )
)
_CHOICE_FIELDS = frozenset(
    ("membership", "record_id", "scope_id")
)
_REQUEST_DOMAIN = "integrity-home-history-review-request/1"
_RESULT_DOMAIN = "integrity-home-history-review-result/1"
_EXPECTED_REVIEW_SCOPES = tuple(
    scope.to_dict()
    for scope in DEFAULT_LOGICAL_SCOPES
    if scope.scope_id in HISTORY_REVIEW_SCOPE_IDS
)

Membership = Literal["exclude", "include", "unknown"]
FileIdentity = tuple[int, int, int, int]


def _stable_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as err:
        raise HistorySidecarSchemaError("History review artifact is not canonical JSON") from err


def _artifact_digest(payload: Mapping[str, object], *, domain: str) -> str:
    unsigned = dict(payload)
    unsigned.pop("artifact_sha256", None)
    digest = sha256()
    digest.update(domain.encode("ascii") + b"\x00")
    encoded = _stable_json(unsigned).encode("utf-8")
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    return digest.hexdigest()


def _hex_digest(value: object, *, field: str) -> str:
    if type(value) is not str or _HEX_256.fullmatch(value) is None:
        raise HistorySidecarSchemaError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _stable_id(value: object, *, field: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > MAX_STABLE_ID_CHARS
        or _STABLE_ID.fullmatch(value) is None
    ):
        raise HistorySidecarSchemaError(f"{field} must be a stable lowercase identifier")
    return value


def _exact_object(
    value: object, fields: frozenset[str], *, label: str
) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != fields:
        raise HistorySidecarSchemaError(f"{label} fields do not match schema v1")
    return cast(dict[str, object], value)


def _bounded_count(value: object, *, field: str, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise HistorySidecarSchemaError(f"{field} is outside its budget")
    return value


def _parse_payload(value: object, *, label: str) -> dict[str, object]:
    if type(value) is dict:
        return cast(dict[str, object], value)
    raw: str
    if type(value) is bytes:
        if not 0 < len(value) <= MAX_HISTORY_REVIEW_ARTIFACT_BYTES:
            raise HistorySidecarSchemaError(f"{label} exceeds its byte budget")
        try:
            raw = value.decode("utf-8", errors="strict")
        except UnicodeDecodeError as err:
            raise HistorySidecarSchemaError(f"{label} is not UTF-8 JSON") from err
    elif type(value) is str:
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as err:
            raise HistorySidecarSchemaError(f"{label} is not UTF-8 JSON") from err
        if not 0 < len(encoded) <= MAX_HISTORY_REVIEW_ARTIFACT_BYTES:
            raise HistorySidecarSchemaError(f"{label} exceeds its byte budget")
        raw = value
    else:
        raise HistorySidecarSchemaError(f"{label} must be a JSON object")
    try:
        payload = loads_json_strict(raw)
    except (
        DuplicateJsonKeyError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
    ) as err:
        raise HistorySidecarSchemaError(f"{label} is not strict JSON") from err
    if type(payload) is not dict:
        raise HistorySidecarSchemaError(f"{label} must be a JSON object")
    return cast(dict[str, object], payload)


def _validate_binding(value: object) -> dict[str, object]:
    raw = _exact_object(value, _BINDING_FIELDS, label="review binding")
    normalized: dict[str, object] = {
        "sidecar_schema_version": raw.get("sidecar_schema_version"),
        "sidecar_generation": _hex_digest(
            raw.get("sidecar_generation"), field="sidecar_generation"
        ),
        "corpus_id": _hex_digest(raw.get("corpus_id"), field="corpus_id"),
        "index_generation": _hex_digest(
            raw.get("index_generation"), field="index_generation"
        ),
        "corpus_deletion_ledger_digest": _hex_digest(
            raw.get("corpus_deletion_ledger_digest"),
            field="corpus_deletion_ledger_digest",
        ),
        "corpus_logical_index_sha256": _hex_digest(
            raw.get("corpus_logical_index_sha256"),
            field="corpus_logical_index_sha256",
        ),
        "base_record_digest": _hex_digest(
            raw.get("base_record_digest"), field="base_record_digest"
        ),
        "base_record_count": _bounded_count(
            raw.get("base_record_count"),
            field="base_record_count",
            maximum=MAX_RECORDS,
        ),
    }
    if normalized["sidecar_schema_version"] != HISTORY_SIDECAR_SCHEMA_VERSION:
        raise HistorySidecarSchemaError("review binding sidecar schema is unsupported")
    return normalized


def _binding_from_reader(reader: HistorySidecarReader) -> dict[str, object]:
    summary = reader.inspect()
    return _validate_binding(
        {
            "sidecar_schema_version": summary.get("schema_version"),
            "sidecar_generation": summary.get("sidecar_generation"),
            "corpus_id": summary.get("corpus_id"),
            "index_generation": summary.get("index_generation"),
            "corpus_deletion_ledger_digest": summary.get(
                "corpus_deletion_ledger_digest"
            ),
            "corpus_logical_index_sha256": summary.get(
                "corpus_logical_index_sha256"
            ),
            "base_record_digest": summary.get("base_record_digest"),
            "base_record_count": summary.get("record_count"),
        }
    )


def _review_scope_ids(reader: HistorySidecarReader) -> tuple[str, ...]:
    descriptors = reader.list_scopes()
    canonical = tuple(
        item for item in descriptors if item.get("scope_id") in HISTORY_REVIEW_SCOPE_IDS
    )
    if canonical != _EXPECTED_REVIEW_SCOPES:
        raise HistorySidecarSchemaError(
            "History review requires canonical Personal scope descriptor"
        )
    actual = tuple(cast(str, item["scope_id"]) for item in descriptors)
    if (
        not actual
        or len(actual) > MAX_LOGICAL_SCOPES
        or actual != tuple(sorted(set(actual)))
        or PERSONAL_SCOPE_ID not in actual
    ):
        raise HistorySidecarSchemaError("History review scope set is invalid")
    return actual


def _normalize_scope_ids(value: object) -> tuple[str, ...]:
    if type(value) is not list or not 1 <= len(value) <= MAX_LOGICAL_SCOPES:
        raise HistorySidecarSchemaError("History review scope set is invalid")
    result = tuple(_stable_id(item, field="scope_id") for item in value)
    if result != tuple(sorted(set(result))) or PERSONAL_SCOPE_ID not in result:
        raise HistorySidecarSchemaError("History review scope set is invalid")
    return result


@dataclass(frozen=True, slots=True)
class ReviewChoice:
    """One explicit membership choice; review state is intentionally absent."""

    record_id: str
    scope_id: str
    membership: Membership

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "record_id", _hex_digest(self.record_id, field="record_id")
        )
        object.__setattr__(
            self, "scope_id", _stable_id(self.scope_id, field="scope_id")
        )
        if self.membership not in _MEMBERSHIPS:
            raise HistorySidecarSchemaError("membership is invalid")

    def to_dict(self) -> dict[str, str]:
        return {
            "membership": self.membership,
            "record_id": self.record_id,
            "scope_id": self.scope_id,
        }


def _normalize_record_ids(record_ids: Iterable[str]) -> tuple[str, ...]:
    values: list[str] = []
    seen: set[str] = set()
    for value in record_ids:
        record_id = _hex_digest(value, field="record_id")
        if record_id in seen:
            raise HistorySidecarSchemaError("review record IDs must be unique")
        seen.add(record_id)
        values.append(record_id)
        if len(values) > MAX_HISTORY_REVIEW_RECORDS:
            raise HistorySidecarSchemaError("History review record budget exceeded")
    if not values:
        raise HistorySidecarSchemaError("History review requires at least one record")
    return tuple(sorted(values))


def validate_history_review_request(
    payload: object,
    *,
    reader: HistorySidecarReader | None = None,
) -> dict[str, object]:
    """Validate one canonical content-free review request."""

    raw = _exact_object(
        _parse_payload(payload, label="History review request"),
        _REQUEST_FIELDS,
        label="History review request",
    )
    if raw.get("schema_version") != HISTORY_REVIEW_REQUEST_SCHEMA_VERSION:
        raise HistorySidecarSchemaError("History review request schema is unsupported")
    if raw.get("content_policy") != HISTORY_REVIEW_CONTENT_POLICY:
        raise HistorySidecarSchemaError("History review request content policy is invalid")
    if raw.get("review_policy") != HISTORY_REVIEW_POLICY:
        raise HistorySidecarSchemaError("History review request policy is invalid")
    binding = _validate_binding(raw.get("binding"))
    scope_ids = _normalize_scope_ids(raw.get("scope_ids"))
    raw_records = raw.get("records")
    if type(raw_records) is not list or not 1 <= len(raw_records) <= MAX_HISTORY_REVIEW_RECORDS:
        raise HistorySidecarSchemaError("History review request records are outside budget")
    records: list[dict[str, str]] = []
    record_ids: list[str] = []
    for value in raw_records:
        item = _exact_object(
            value,
            frozenset(("content_sha256", "record_id")),
            label="History review record",
        )
        record = {
            "content_sha256": _hex_digest(
                item.get("content_sha256"), field="content_sha256"
            ),
            "record_id": _hex_digest(item.get("record_id"), field="record_id"),
        }
        records.append(record)
        record_ids.append(record["record_id"])
    if record_ids != sorted(set(record_ids)):
        raise HistorySidecarSchemaError(
            "History review request records are not canonical and unique"
        )
    record_count = _bounded_count(
        raw.get("record_count"),
        field="record_count",
        maximum=MAX_HISTORY_REVIEW_RECORDS,
    )
    if record_count != len(records):
        raise HistorySidecarSchemaError("History review request record count mismatch")
    normalized: dict[str, object] = {
        "schema_version": HISTORY_REVIEW_REQUEST_SCHEMA_VERSION,
        "content_policy": HISTORY_REVIEW_CONTENT_POLICY,
        "review_policy": HISTORY_REVIEW_POLICY,
        "binding": binding,
        "scope_ids": list(scope_ids),
        "records": records,
        "record_count": record_count,
        "artifact_sha256": _hex_digest(
            raw.get("artifact_sha256"), field="artifact_sha256"
        ),
    }
    if normalized["artifact_sha256"] != _artifact_digest(
        normalized, domain=_REQUEST_DOMAIN
    ):
        raise HistorySidecarSchemaError("History review request digest mismatch")
    if reader is not None:
        if not isinstance(reader, HistorySidecarReader):
            raise HistorySidecarSchemaError("reader must be a HistorySidecarReader")
        if _binding_from_reader(reader) != binding:
            raise HistorySidecarStaleError("History review request sidecar binding is stale")
        if _review_scope_ids(reader) != scope_ids:
            raise HistorySidecarStaleError("History review scope set is stale")
        current = [
            {
                "content_sha256": cast(str, item["content_sha256"]),
                "record_id": cast(str, item["record_id"]),
            }
            for item in reader.get_records(record_ids)
        ]
        if current != records:
            raise HistorySidecarStaleError("History review request records are stale")
    return normalized


def create_history_review_request(
    reader: HistorySidecarReader,
    record_ids: Iterable[str],
) -> dict[str, object]:
    """Create a deterministic request for a bounded explicit record set."""

    if not isinstance(reader, HistorySidecarReader):
        raise HistorySidecarSchemaError("reader must be a HistorySidecarReader")
    ids = _normalize_record_ids(record_ids)
    scope_ids = _review_scope_ids(reader)
    records = [
        {
            "content_sha256": cast(str, item["content_sha256"]),
            "record_id": cast(str, item["record_id"]),
        }
        for item in reader.get_records(ids)
    ]
    request: dict[str, object] = {
        "schema_version": HISTORY_REVIEW_REQUEST_SCHEMA_VERSION,
        "content_policy": HISTORY_REVIEW_CONTENT_POLICY,
        "review_policy": HISTORY_REVIEW_POLICY,
        "binding": _binding_from_reader(reader),
        "scope_ids": list(scope_ids),
        "records": records,
        "record_count": len(records),
    }
    request["artifact_sha256"] = _artifact_digest(request, domain=_REQUEST_DOMAIN)
    return validate_history_review_request(request, reader=reader)


def validate_history_review_result(
    payload: object,
    *,
    request: object,
    reader: HistorySidecarReader | None = None,
) -> dict[str, object]:
    """Validate one complete reviewed result against its exact request."""

    normalized_request = validate_history_review_request(request, reader=reader)
    raw = _exact_object(
        _parse_payload(payload, label="History review result"),
        _RESULT_FIELDS,
        label="History review result",
    )
    if raw.get("schema_version") != HISTORY_REVIEW_RESULT_SCHEMA_VERSION:
        raise HistorySidecarSchemaError("History review result schema is unsupported")
    if raw.get("content_policy") != HISTORY_REVIEW_CONTENT_POLICY:
        raise HistorySidecarSchemaError("History review result content policy is invalid")
    if raw.get("review_policy") != HISTORY_REVIEW_POLICY:
        raise HistorySidecarSchemaError("History review result policy is invalid")
    if raw.get("coverage") != HISTORY_REVIEW_COVERAGE:
        raise HistorySidecarSchemaError("History review result coverage is incomplete")
    request_sha256 = _hex_digest(
        raw.get("request_sha256"), field="request_sha256"
    )
    if request_sha256 != normalized_request["artifact_sha256"]:
        raise HistorySidecarStaleError("History review result targets another request")
    raw_decisions = raw.get("decisions")
    if type(raw_decisions) is not list or not raw_decisions:
        raise HistorySidecarSchemaError("History review result decisions are required")
    if len(raw_decisions) > MAX_HISTORY_REVIEW_DECISIONS:
        raise HistorySidecarSchemaError("History review decision budget exceeded")
    decisions: list[dict[str, str]] = []
    pairs: list[tuple[str, str]] = []
    for value in raw_decisions:
        item = _exact_object(value, _CHOICE_FIELDS, label="History review choice")
        choice = ReviewChoice(
            record_id=cast(str, item.get("record_id")),
            scope_id=cast(str, item.get("scope_id")),
            membership=cast(Membership, item.get("membership")),
        )
        decisions.append(choice.to_dict())
        pairs.append((choice.record_id, choice.scope_id))
    expected_pairs = [
        (cast(str, record["record_id"]), scope_id)
        for record in cast(list[dict[str, str]], normalized_request["records"])
        for scope_id in cast(list[str], normalized_request["scope_ids"])
    ]
    expected_pairs.sort()
    if pairs != expected_pairs:
        raise HistorySidecarSchemaError(
            "History review result must cover each record/scope pair exactly once"
        )
    decision_count = _bounded_count(
        raw.get("decision_count"),
        field="decision_count",
        maximum=MAX_HISTORY_REVIEW_DECISIONS,
    )
    if decision_count != len(decisions):
        raise HistorySidecarSchemaError("History review result decision count mismatch")
    normalized: dict[str, object] = {
        "schema_version": HISTORY_REVIEW_RESULT_SCHEMA_VERSION,
        "content_policy": HISTORY_REVIEW_CONTENT_POLICY,
        "review_policy": HISTORY_REVIEW_POLICY,
        "request_sha256": request_sha256,
        "coverage": HISTORY_REVIEW_COVERAGE,
        "decisions": decisions,
        "decision_count": decision_count,
        "artifact_sha256": _hex_digest(
            raw.get("artifact_sha256"), field="artifact_sha256"
        ),
    }
    if normalized["artifact_sha256"] != _artifact_digest(
        normalized, domain=_RESULT_DOMAIN
    ):
        raise HistorySidecarSchemaError("History review result digest mismatch")
    return normalized


def create_history_review_result(
    request: object,
    choices: Iterable[ReviewChoice],
) -> dict[str, object]:
    """Create a deterministic complete result from explicit typed choices."""

    normalized_request = validate_history_review_request(request)
    values: list[ReviewChoice] = []
    for choice in choices:
        if type(choice) is not ReviewChoice:
            raise HistorySidecarSchemaError(
                "choices must contain ReviewChoice values"
            )
        values.append(choice)
        if len(values) > MAX_HISTORY_REVIEW_DECISIONS:
            raise HistorySidecarSchemaError("History review decision budget exceeded")
    values.sort(key=lambda item: (item.record_id, item.scope_id))
    result: dict[str, object] = {
        "schema_version": HISTORY_REVIEW_RESULT_SCHEMA_VERSION,
        "content_policy": HISTORY_REVIEW_CONTENT_POLICY,
        "review_policy": HISTORY_REVIEW_POLICY,
        "request_sha256": normalized_request["artifact_sha256"],
        "coverage": HISTORY_REVIEW_COVERAGE,
        "decisions": [item.to_dict() for item in values],
        "decision_count": len(values),
    }
    result["artifact_sha256"] = _artifact_digest(result, domain=_RESULT_DOMAIN)
    return validate_history_review_result(result, request=normalized_request)


def history_review_request_json_bytes(
    payload: object,
    *,
    reader: HistorySidecarReader | None = None,
) -> bytes:
    normalized = validate_history_review_request(payload, reader=reader)
    encoded = (_stable_json(normalized) + "\n").encode("utf-8")
    if len(encoded) > MAX_HISTORY_REVIEW_ARTIFACT_BYTES:
        raise HistorySidecarSchemaError("History review request exceeds byte budget")
    return encoded


def history_review_result_json_bytes(
    payload: object,
    *,
    request: object,
    reader: HistorySidecarReader | None = None,
) -> bytes:
    normalized = validate_history_review_result(
        payload, request=request, reader=reader
    )
    encoded = (_stable_json(normalized) + "\n").encode("utf-8")
    if len(encoded) > MAX_HISTORY_REVIEW_ARTIFACT_BYTES:
        raise HistorySidecarSchemaError("History review result exceeds byte budget")
    return encoded



__all__ = [
    "HISTORY_REVIEW_CONTENT_POLICY",
    "HISTORY_REVIEW_COVERAGE",
    "HISTORY_REVIEW_POLICY",
    "HISTORY_REVIEW_REASON_CODE",
    "HISTORY_REVIEW_REQUEST_SCHEMA_VERSION",
    "HISTORY_REVIEW_RESULT_SCHEMA_VERSION",
    "HISTORY_REVIEW_SCOPE_IDS",
    "MAX_HISTORY_REVIEW_ARTIFACT_BYTES",
    "MAX_HISTORY_REVIEW_DECISIONS",
    "MAX_HISTORY_REVIEW_RECORDS",
    "ReviewChoice",
    "create_history_review_request",
    "create_history_review_result",
    "history_review_request_json_bytes",
    "history_review_result_json_bytes",
    "validate_history_review_request",
    "validate_history_review_result",
]
