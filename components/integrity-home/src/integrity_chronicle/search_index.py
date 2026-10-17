"""Persistent lexical index for canonical projection search.

The module stores a deterministic SQLite artifact per source to speed future
search calls while preserving exact text matching and ordering behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import shlex
import sqlite3
import unicodedata
import tempfile
from pathlib import Path
from hashlib import sha256
import os
from typing import Any, Dict, List, Optional, Sequence

from .json_integrity import loads_json_strict


SEARCH_INDEX_SCHEMA_VERSION = "chronicle-search-index/1"
_REQUIRED_SEARCH_INDEX_CLAIM_STRING_FIELDS = (
    "claim_id",
    "claim_type",
    "temporal_state",
    "message_id",
    "conversation_id",
    "claim_text",
)

_KNOWN_SPEAKERS = {"user", "assistant", "other"}


@dataclass(frozen=True)
class SearchTerm:
    value: str
    kind: str


class SearchIndexError(RuntimeError):
    """Raised when the persisted index cannot be loaded or queried."""


def _coerce_projection_id(payload: Dict[str, Any]) -> str:
    source_id = payload.get("source_id")
    if not isinstance(source_id, str) or not source_id:
        raise SearchIndexError("projection missing source_id")
    return source_id


def _coerce_projection_provider(payload: Dict[str, Any]) -> str:
    provider = payload.get("provider")
    if not isinstance(provider, str) or not provider:
        raise SearchIndexError("projection missing provider")
    return provider


def _coerce_projection_signature(payload: Dict[str, Any]) -> str:
    explicit = payload.get("projection_sha256")
    if isinstance(explicit, str) and explicit:
        return explicit

    sanitized = dict(payload)
    sanitized.pop("projection_sha256", None)
    body = json.dumps(
        sanitized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return sha256(body).hexdigest()


def _coerce_claims(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw_claims = payload.get("claims")
    if not isinstance(raw_claims, list):
        raise SearchIndexError("projection claims must be a list")
    claims: List[Dict[str, Any]] = []
    seen_claim_ids: set[str] = set()
    for index, claim in enumerate(raw_claims):
        if not isinstance(claim, dict):
            raise SearchIndexError(f"projection claims at index {index} must be an object")
        for key in _REQUIRED_SEARCH_INDEX_CLAIM_STRING_FIELDS:
            value = claim.get(key)
            if not isinstance(value, str):
                raise SearchIndexError(
                    f"projection claim at index {index} missing required string field: {key}"
                )
            if key == "claim_id" and not value:
                raise SearchIndexError(
                    f"projection claim at index {index} has empty required string field: {key}"
                )
            if key == "claim_id":
                if value in seen_claim_ids:
                    raise SearchIndexError(f"duplicate claim_id in projection at index {index}: {value}")
                seen_claim_ids.add(value)
        is_user_assertion = claim.get("is_user_assertion")
        if not isinstance(is_user_assertion, bool):
            raise SearchIndexError(
                f"projection claim at index {index} missing required bool field: is_user_assertion"
            )
        provenance = claim.get("provenance")
        if not isinstance(provenance, dict):
            raise SearchIndexError(
                f"projection claim at index {index} missing required dict field: provenance"
            )
        model = claim.get("model")
        if model is not None and not isinstance(model, str):
            raise SearchIndexError(f"projection claim at index {index} has invalid model")
        if "created_at" not in claim:
            raise SearchIndexError(
                f"projection claim at index {index} missing required string field: created_at"
            )
        created_at = claim.get("created_at")
        if created_at is not None and not isinstance(created_at, str):
            raise SearchIndexError(
                f"projection claim at index {index} has invalid created_at"
            )

        if claim.get("speaker") is not None:
            _coerce_speaker(claim.get("speaker"), index=index)

        content_type = claim.get("content_type")
        if content_type is not None and not isinstance(content_type, str):
            raise SearchIndexError(
                f"projection claim at index {index} has invalid content_type"
            )
        provenance_content_type = provenance.get("content_type")
        if provenance_content_type is not None and not isinstance(
            provenance_content_type, str
        ):
            raise SearchIndexError(
                f"projection claim at index {index} has invalid content_type in provenance"
            )
        _coerce_label_list(claim, index=index, field_name="sensitivity_labels")
        _coerce_label_list(claim, index=index, field_name="scope_labels")
        claims.append(claim)
    return claims


def _coerce_speaker(value: Any, *, index: int) -> str:
    if value is None:
        return "other"
    if not isinstance(value, str):
        raise SearchIndexError(f"projection claim at index {index} has invalid speaker")
    speaker = value.strip().lower()
    if not speaker:
        raise SearchIndexError(f"projection claim at index {index} has empty speaker")
    if speaker not in _KNOWN_SPEAKERS:
        raise SearchIndexError(
            f"projection claim at index {index} has unsupported speaker"
        )
    return speaker


def _coerce_content_type(claim: Dict[str, Any], *, index: int) -> str:
    content_type = claim.get("content_type")
    if content_type is not None and not isinstance(content_type, str):
        raise SearchIndexError(f"projection claim at index {index} has invalid content_type")

    provenance = claim.get("provenance")
    if isinstance(provenance, dict):
        provenance_content_type = provenance.get("content_type")
        if provenance_content_type is not None and not isinstance(
            provenance_content_type, str
        ):
            raise SearchIndexError(
                f"projection claim at index {index} has invalid content_type in provenance"
            )
        if content_type is None and provenance_content_type is not None:
            return provenance_content_type
    return content_type or ""


def _coerce_label_list(claim: Dict[str, Any], *, index: int, field_name: str) -> None:
    if field_name not in claim:
        return

    value = claim.get(field_name)
    if value is None:
        return

    if not isinstance(value, list):
        raise SearchIndexError(
            f"projection claim at index {index} has invalid {field_name}; expected a list"
        )

    for item in value:
        if not isinstance(item, str):
            raise SearchIndexError(
                f"projection claim at index {index} has invalid {field_name} value"
            )
        if not item.strip():
            raise SearchIndexError(
                f"projection claim at index {index} has invalid {field_name} value"
            )


def _claim_speaker(claim: Dict[str, Any], *, index: int) -> str:
    explicit = claim.get("speaker")
    if explicit is None:
        role = claim.get("is_user_assertion")
        if isinstance(role, bool):
            return "user" if role else "assistant"
        return "other"
    return _coerce_speaker(explicit, index=index)


def _normalize_text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    normalized = unicodedata.normalize("NFKC", value).casefold()
    decomposed = unicodedata.normalize("NFD", normalized)
    normalized = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return " ".join(normalized.strip().split())


def _query_terms(query: Optional[str]) -> List[SearchTerm]:
    if not query:
        return []
    try:
        raw_terms = shlex.split(query)
    except ValueError:
        raw_terms = _normalize_text(query).split()

    terms: List[SearchTerm] = []
    for raw_term in raw_terms:
        normalized = _normalize_text(raw_term)
        if not normalized:
            continue
        if " " in raw_term:
            terms.append(SearchTerm(value=normalized, kind="phrase"))
            continue
        if normalized.endswith("*") and len(normalized) > 1:
            terms.append(SearchTerm(value=normalized[:-1], kind="prefix"))
            continue
        terms.append(SearchTerm(value=normalized, kind="term"))
    return terms


def _escape_fts_token(value: str) -> str:
    # FTS5 treats many punctuation characters as query syntax tokens.
    if not value:
        return ""
    escaped = value.replace('"', '""')
    return "".join(ch for ch in escaped if ch.isalnum() or ch in {"_", "-", "*", "?"})


def _build_fts_query(terms: Sequence[SearchTerm]) -> Optional[str]:
    if not terms:
        return None

    expressions: List[str] = []
    for term in terms:
        if term.kind == "phrase":
            if not term.value:
                continue
            escaped = term.value.replace('"', '""')
            expressions.append(f'"{escaped}"')
            continue
        if term.kind == "prefix":
            expressions.append(f"{_escape_fts_token(term.value)}*")
            continue
        expressions.append(_escape_fts_token(term.value))

    if not expressions:
        return None
    return " AND ".join(expressions)


def _claim_text(claim: Dict[str, Any]) -> str:
    return claim.get("claim_text")


def _claim_content_type(claim: Dict[str, Any]) -> str:
    content_type = claim.get("content_type")
    if isinstance(content_type, str):
        return content_type
    provenance = claim.get("provenance")
    if isinstance(provenance, dict):
        provenance_content_type = provenance.get("content_type")
        if isinstance(provenance_content_type, str):
            return provenance_content_type
    return ""


def _coerce_conversation_id(claim: Dict[str, Any]) -> str:
    conversation_id = claim.get("conversation_id")
    if not isinstance(conversation_id, str):
        raise SearchIndexError("projection claim conversation_id must be a string")
    return conversation_id


def _coerce_claim_rows(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for claim in _coerce_claims(payload):
        rows.append(
            {
                "claim_id": claim["claim_id"],
                "claim_type": claim["claim_type"],
                "temporal_state": claim["temporal_state"],
                "message_id": claim["message_id"],
                "conversation_id": _coerce_conversation_id(claim),
                "speaker": _claim_speaker(claim, index=-1),
                "created_at": claim.get("created_at") or "9999-12-31T23:59:59Z",
                "is_user_assertion": claim["is_user_assertion"],
                "model": claim.get("model", ""),
                "claim_text": _claim_text(claim),
                "provenance": claim["provenance"],
                "content_type": _coerce_content_type(claim, index=-1),
                "source_message_index": claim.get("source_message_index"),
                "claim_signature": claim.get("claim_signature", ""),
            }
        )
    return rows


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS search_index_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS claim_records (
            claim_pk INTEGER PRIMARY KEY AUTOINCREMENT,
            claim_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            source_provider TEXT NOT NULL,
            claim_type TEXT NOT NULL,
            temporal_state TEXT NOT NULL,
            speaker TEXT NOT NULL,
            model TEXT NOT NULL,
            content_type TEXT NOT NULL,
            conversation_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            claim_text TEXT NOT NULL,
            claim_text_norm TEXT NOT NULL,
            message_id TEXT NOT NULL,
            provenance_json TEXT NOT NULL,
            is_user_assertion INTEGER NOT NULL,
            raw_index INTEGER NOT NULL
        )
        """
    )
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS claim_records_claim_id_idx ON claim_records(claim_id)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS claim_records_source_idx ON claim_records(source_id, source_provider)"
    )
    conn.execute(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS claim_fts USING fts5(
            claim_text_norm,
            claim_id UNINDEXED
        )
        """
    )


def _read_meta(conn: sqlite3.Connection) -> Dict[str, str]:
    rows = conn.execute("SELECT key, value FROM search_index_meta").fetchall()
    return {key: value for key, value in rows}


def _metadata_matches(
    conn: sqlite3.Connection,
    source_id: str,
    signature: str,
    projection: Dict[str, Any],
) -> bool:
    meta = _read_meta(conn)
    claim_count = len(_coerce_claims(projection))
    return (
        meta.get("schema_version") == SEARCH_INDEX_SCHEMA_VERSION
        and meta.get("source_id") == source_id
        and meta.get("projection_signature") == signature
        and int(meta.get("claim_count", "-1")) == claim_count
        and meta.get("provider") == _coerce_projection_provider(projection)
    )


def _build_index_payload(projection: Dict[str, Any]) -> str:
    return json.dumps(
        {
            "schema_version": SEARCH_INDEX_SCHEMA_VERSION,
            "source_id": _coerce_projection_id(projection),
            "provider": _coerce_projection_provider(projection),
            "projection_signature": _coerce_projection_signature(projection),
            "claim_count": len(_coerce_claims(projection)),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def build_search_index(projection: Dict[str, Any], index_path: str) -> None:
    source_id = _coerce_projection_id(projection)
    if not index_path:
        raise SearchIndexError("index_path is required")

    target = Path(index_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    tmp_fd, tmp_path = tempfile.mkstemp(
        prefix="chronicle-search-index-",
        suffix=".sqlite",
        dir=target.parent,
    )
    os.close(tmp_fd)

    try:
        conn = sqlite3.connect(tmp_path)
        try:
            conn.execute("PRAGMA journal_mode = OFF")
            conn.execute("PRAGMA synchronous = OFF")
            _init_schema(conn)

            conn.execute("DELETE FROM search_index_meta")
            conn.execute("DELETE FROM claim_records")
            conn.execute("DELETE FROM claim_fts")

            signature = _coerce_projection_signature(projection)
            payload = _coerce_claim_rows(projection)
            provider = _coerce_projection_provider(projection)
            for raw_index, claim in enumerate(payload):
                claim_id = claim["claim_id"]
                claim_text = claim["claim_text"]
                normalized_text = _normalize_text(claim_text)
                provenance_json = json.dumps(claim["provenance"], sort_keys=True, ensure_ascii=False)
                conn.execute(
                    """
                    INSERT INTO claim_records (
                        claim_id, source_id, source_provider, claim_type, temporal_state,
                        speaker, model, content_type, conversation_id, created_at,
                        claim_text, claim_text_norm, message_id, provenance_json,
                        is_user_assertion, raw_index
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        claim_id,
                        source_id,
                        provider,
                        claim["claim_type"],
                        claim["temporal_state"],
                        claim["speaker"],
                        claim["model"],
                        claim["content_type"],
                        claim["conversation_id"],
                        str(claim.get("created_at") or "9999-12-31T23:59:59Z"),
                        claim_text,
                        normalized_text,
                        claim["message_id"],
                        provenance_json,
                        1 if claim["is_user_assertion"] else 0,
                        raw_index,
                    ),
                )
                claim_pk = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                conn.execute(
                    "INSERT INTO claim_fts(rowid, claim_text_norm, claim_id) VALUES (?, ?, ?)",
                    (claim_pk, normalized_text, claim_id),
                )

            conn.execute(
                "INSERT OR REPLACE INTO search_index_meta(key, value) VALUES (?, ?)",
                ("schema_version", SEARCH_INDEX_SCHEMA_VERSION),
            )
            conn.execute(
                "INSERT OR REPLACE INTO search_index_meta(key, value) VALUES (?, ?)",
                ("source_id", source_id),
            )
            conn.execute(
                "INSERT OR REPLACE INTO search_index_meta(key, value) VALUES (?, ?)",
                ("provider", provider),
            )
            conn.execute(
                "INSERT OR REPLACE INTO search_index_meta(key, value) VALUES (?, ?)",
                ("projection_signature", signature),
            )
            conn.execute(
                "INSERT OR REPLACE INTO search_index_meta(key, value) VALUES (?, ?)",
                ("claim_count", str(len(payload))),
            )
            conn.execute(
                "INSERT OR REPLACE INTO search_index_meta(key, value) VALUES (?, ?)",
                ("index_payload_sha256", sha256(_build_index_payload(projection).encode("utf-8")).hexdigest()),
            )
            conn.commit()
        except sqlite3.DatabaseError as err:
            raise SearchIndexError(f"failed to build search index: {err}") from err
        finally:
            conn.close()

        os.replace(tmp_path, target)
    finally:
        if Path(tmp_path).is_file():
            Path(tmp_path).unlink(missing_ok=True)


def _require_index(projection: Dict[str, Any], index_path: str) -> None:
    signature = _coerce_projection_signature(projection)
    source_id = _coerce_projection_id(projection)
    target = Path(index_path)
    if not target.is_file():
        build_search_index(projection, index_path)
        return

    try:
        conn = sqlite3.connect(str(target))
        try:
            _init_schema(conn)
            if not _metadata_matches(conn, source_id, signature, projection):
                raise SearchIndexError("index metadata mismatch")
            return
        finally:
            conn.close()
    except (sqlite3.DatabaseError, SearchIndexError):
        build_search_index(projection, index_path)


def _query_candidate_ids(conn: sqlite3.Connection, query: Optional[str]) -> List[str]:
    terms = _query_terms(query)
    fts_query = _build_fts_query(terms)
    if fts_query is None:
        return []
    try:
        return [
            row["claim_id"]
            for row in conn.execute(
                "SELECT claim_id FROM claim_fts WHERE claim_text_norm MATCH ?",
                (fts_query,),
            ).fetchall()
        ]
    except sqlite3.OperationalError as err:
        raise SearchIndexError(f"fts query failed: {err}") from err


def search_projection_rows(
    projection: Dict[str, Any],
    *,
    index_path: str,
    query: Optional[str] = None,
) -> List[Dict[str, Any]]:
    _require_index(projection, index_path)

    conn = sqlite3.connect(index_path)
    conn.row_factory = sqlite3.Row
    try:
        source_id = _coerce_projection_id(projection)
        provider = _coerce_projection_provider(projection)
        candidate_ids = _query_candidate_ids(conn, query)
        if candidate_ids:
            placeholders = ", ".join(["?"] * len(candidate_ids))
            rows = conn.execute(
                f"""
                SELECT
                    claim_id,
                    claim_type,
                    temporal_state,
                    speaker,
                    model,
                    conversation_id,
                    created_at,
                    message_id,
                    claim_text,
                    provenance_json,
                    content_type,
                    is_user_assertion
                FROM claim_records
                WHERE source_id = ? AND source_provider = ? AND claim_id IN ({placeholders})
                """,
                (source_id, provider, *candidate_ids),
            ).fetchall()
            if not rows and query:
                return []
        else:
            rows = conn.execute(
                "SELECT claim_id, claim_type, temporal_state, speaker, model, conversation_id, created_at, message_id, claim_text, provenance_json, content_type, is_user_assertion FROM claim_records WHERE source_id = ? AND source_provider = ?",
                (source_id, provider),
            ).fetchall()

        matches: List[Dict[str, Any]] = []
        for row in rows:
            try:
                provenance = loads_json_strict(row["provenance_json"])
            except (TypeError, json.JSONDecodeError):
                provenance = {}
            if not isinstance(provenance, dict):
                provenance = {}
            matches.append(
                {
                    "claim_id": row["claim_id"],
                    "claim_type": row["claim_type"],
                    "created_at": row["created_at"],
                    "temporal_state": row["temporal_state"],
                    "conversation_id": row["conversation_id"],
                    "message_id": row["message_id"],
                    "is_user_assertion": bool(row["is_user_assertion"]),
                    "claim_text": row["claim_text"],
                    "model": row["model"],
                    "provenance": provenance,
                    "content_type": row["content_type"],
                    "speaker": row["speaker"],
                }
            )
        return matches
    except sqlite3.DatabaseError as err:
        raise SearchIndexError(f"search index query failed: {err}") from err
    finally:
        conn.close()


__all__ = [
    "SEARCH_INDEX_SCHEMA_VERSION",
    "SearchIndexError",
    "SearchTerm",
    "build_search_index",
    "search_projection_rows",
]
