"""Minimal loopback review API for projection inspection and action capture."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import html
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple
import hmac
import json
import tempfile
import threading
import urllib.parse

from .projection_integrity import canonical_projection_sha256
from .json_integrity import load_json_strict, loads_json_strict


REVIEW_API_SCHEMA_VERSION = "chronicle-review-api/1"
REVIEW_DECISION_SCHEMA_VERSION = "chronicle-review-decision/2"
REVIEW_STATE_SCHEMA_VERSION = "chronicle-review-state/2"
REVIEW_ACTIONS = frozenset(
    {"accept", "reject", "edit", "supersede", "contradict", "forget"}
)
CLAIM_UNKNOWN_TIMESTAMP_SORT_KEY = "9999-12-31T23:59:59Z"
REASON_REQUIRED_FOR_ACTIONS = frozenset({"supersede", "contradict"})
_REQUIRED_REVIEW_CLAIM_STRING_FIELDS = (
    "claim_id",
    "claim_type",
    "claim_text",
    "temporal_state",
    "conversation_id",
)


def _coerce_content_type(claim: Dict[str, Any], *, index: int) -> Optional[str]:
    content_type = claim.get("content_type")
    if content_type is not None and not isinstance(content_type, str):
        raise ValueError(
            f"projection claim at index {index} has invalid content_type"
        )

    provenance = claim.get("provenance")
    if isinstance(provenance, dict):
        provenance_content_type = provenance.get("content_type")
        if provenance_content_type is not None and not isinstance(
            provenance_content_type, str
        ):
            raise ValueError(
                f"projection claim at index {index} has invalid content_type in provenance"
            )

    return content_type


def _coerce_speaker(claim: Dict[str, Any], *, index: int) -> None:
    if "speaker" not in claim:
        return
    speaker = claim.get("speaker")
    if not isinstance(speaker, str):
        raise ValueError(f"projection claim at index {index} has invalid speaker")
    if not speaker.strip():
        raise ValueError(f"projection claim at index {index} has empty speaker")


def _coerce_label_list(claim: Dict[str, Any], *, index: int, field_name: str) -> None:
    if field_name not in claim:
        return

    value = claim.get(field_name)
    if value is None:
        return

    if not isinstance(value, list):
        raise ValueError(
            f"projection claim at index {index} has invalid {field_name}; expected a list"
        )

    for item in value:
        if not isinstance(item, str):
            raise ValueError(
                f"projection claim at index {index} has invalid {field_name} value"
            )
        if not item.strip():
            raise ValueError(
                f"projection claim at index {index} has invalid {field_name} value"
            )



def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _stable_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(payload: Any) -> str:
    return sha256(_stable_json(payload).encode("utf-8")).hexdigest()


def _projection_digest(projection: Mapping[str, Any]) -> str:
    return canonical_projection_sha256(projection)


def _normalize_path(path: str) -> str:
    return str(Path(path))


def _coerce_claims_for_review(projection: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw_claims = projection.get("claims")
    if not isinstance(raw_claims, list):
        raise ValueError("projection claims must be a list")

    claims: List[Dict[str, Any]] = []
    seen_claim_ids: set[str] = set()
    for index, claim in enumerate(raw_claims):
        if not isinstance(claim, dict):
            raise ValueError(f"projection claim at index {index} must be an object")

        for key in _REQUIRED_REVIEW_CLAIM_STRING_FIELDS:
            value = claim.get(key)
            if not isinstance(value, str):
                raise ValueError(
                    f"projection claim at index {index} missing required string field: {key}"
                )
            if key == "claim_id" and not value:
                raise ValueError(
                    f"projection claim at index {index} has empty required string field: {key}"
                )
            if key == "claim_id":
                if value in seen_claim_ids:
                    raise ValueError(f"duplicate claim_id in projection at index {index}: {value}")
                seen_claim_ids.add(value)

        is_user_assertion = claim.get("is_user_assertion")
        if not isinstance(is_user_assertion, bool):
            raise ValueError(
                f"projection claim at index {index} missing required bool field: is_user_assertion"
            )

        provenance = claim.get("provenance")
        if not isinstance(provenance, dict):
            raise ValueError(
                f"projection claim at index {index} missing required dict field: provenance"
            )

        if "created_at" not in claim:
            raise ValueError(
                f"projection claim at index {index} missing required string field: created_at"
            )
        created_at = claim.get("created_at")
        if created_at is not None and not isinstance(created_at, str):
            raise ValueError(
                f"projection claim at index {index} has invalid created_at"
            )

        _coerce_speaker(claim, index=index)
        _coerce_content_type(claim, index=index)
        _coerce_label_list(claim, index=index, field_name="sensitivity_labels")
        _coerce_label_list(claim, index=index, field_name="scope_labels")

        claim_record: Dict[str, Any] = {
            "claim_id": claim["claim_id"],
            "claim_type": claim["claim_type"],
            "is_user_assertion": is_user_assertion,
            "claim_text": claim["claim_text"],
            "temporal_state": claim["temporal_state"],
            "created_at": created_at,
            "conversation_id": claim["conversation_id"],
            "provenance": claim["provenance"],
        }
        for optional_field in (
            "provider_conversation_id",
            "message_id",
            "source_message_index",
            "sensitivity_labels",
            "scope_labels",
        ):
            if optional_field in claim:
                claim_record[optional_field] = claim.get(optional_field)
        claim_record["review_claim_sha256"] = _digest(claim_record)
        claims.append(claim_record)
    claims.sort(
        key=lambda claim: (
            str(claim.get("created_at") or CLAIM_UNKNOWN_TIMESTAMP_SORT_KEY),
            str(claim.get("claim_id", "")),
        )
    )
    return claims


def _extract_claim_rows(projection: Dict[str, Any]) -> List[Dict[str, Any]]:
    return extract_review_claims(projection)


def extract_review_claims(projection: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return validated, deterministically ordered claims for local review."""

    if not isinstance(projection, dict):
        raise TypeError("projection must be an object")
    return _coerce_claims_for_review(projection)


def _validate_review_decision(
    raw: Mapping[str, Any],
    *,
    source_id: str,
    source_projection_sha256: str,
    signing_secret: Optional[str] = None,
) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise ValueError("review decision must be an object")
    decision = dict(raw)
    if decision.get("schema_version") != REVIEW_DECISION_SCHEMA_VERSION:
        raise ValueError("unsupported review decision schema_version")
    if decision.get("source_id") != source_id:
        raise ValueError("review decision source_id mismatch")
    if decision.get("source_projection_sha256") != source_projection_sha256:
        raise ValueError("stale review decision projection")
    for field_name in (
        "decision_id",
        "decision_sha256",
        "issued_at_utc",
        "claim_id",
        "review_claim_sha256",
        "action",
    ):
        value = decision.get(field_name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"review decision missing {field_name}")
    if decision["action"] not in REVIEW_ACTIONS:
        raise ValueError(f"unsupported review action: {decision['action']}")
    review_revision = decision.get("review_revision")
    if isinstance(review_revision, bool) or not isinstance(review_revision, int) or review_revision < 1:
        raise ValueError("review decision has invalid review_revision")

    signature = decision.pop("signature", None)
    decision_id = decision.pop("decision_id")
    decision_sha256 = decision.pop("decision_sha256")
    expected_digest = _digest(decision)
    if decision_sha256 != expected_digest:
        raise ValueError("review decision digest mismatch")
    if decision_id != f"review-decision-{expected_digest[:24]}":
        raise ValueError("review decision id mismatch")

    if signing_secret is not None:
        if not isinstance(signature, Mapping):
            raise ValueError("signed review decision is missing signature")
        if signature.get("algorithm") != "HMAC-SHA256":
            raise ValueError("unsupported review decision signature algorithm")
        expected_signature = hmac.new(
            signing_secret.encode("utf-8"),
            expected_digest.encode("ascii"),
            sha256,
        ).hexdigest()
        if not hmac.compare_digest(str(signature.get("value", "")), expected_signature):
            raise ValueError("review decision signature mismatch")
    elif signature is not None:
        if not isinstance(signature, Mapping) or signature.get("algorithm") != "HMAC-SHA256":
            raise ValueError("malformed review decision signature")

    decision["decision_id"] = decision_id
    decision["decision_sha256"] = decision_sha256
    if signature is not None:
        decision["signature"] = dict(signature)
    return decision


def validate_review_manifest(
    raw: Mapping[str, Any],
    *,
    source_id: str,
    source_projection_sha256: str,
    signing_secret: Optional[str] = None,
) -> Dict[str, Any]:
    """Validate a persisted review state against the exact projection."""

    if not isinstance(raw, Mapping):
        raise ValueError("review state manifest must be an object")
    if raw.get("schema_version") != REVIEW_STATE_SCHEMA_VERSION:
        raise ValueError("unsupported review state schema_version")
    if raw.get("source_id") != source_id:
        raise ValueError("review state source_id mismatch")
    if raw.get("source_projection_sha256") != source_projection_sha256:
        raise ValueError("stale review state projection")
    revision = raw.get("revision", 0)
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise ValueError("review state revision must be a non-negative integer")
    decisions_raw = raw.get("decisions")
    if not isinstance(decisions_raw, list):
        raise ValueError("review state decisions must be a list")
    if revision != len(decisions_raw):
        raise ValueError("review state revision does not match decision count")

    decisions: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_revisions: set[int] = set()
    for decision_raw in decisions_raw:
        decision = _validate_review_decision(
            decision_raw,
            source_id=source_id,
            source_projection_sha256=source_projection_sha256,
            signing_secret=signing_secret,
        )
        if decision["decision_id"] in seen_ids:
            raise ValueError("duplicate review decision_id")
        if decision["review_revision"] in seen_revisions:
            raise ValueError("duplicate review decision revision")
        seen_ids.add(decision["decision_id"])
        seen_revisions.add(decision["review_revision"])
        decisions.append(decision)
    if seen_revisions and seen_revisions != set(range(1, revision + 1)):
        raise ValueError("review decision revisions are not contiguous")

    return {
        "schema_version": REVIEW_STATE_SCHEMA_VERSION,
        "source_id": source_id,
        "source_projection_sha256": source_projection_sha256,
        "projection_path": str(raw.get("projection_path", "")),
        "generated_utc": raw.get("generated_utc"),
        "revision": revision,
        "decisions": decisions,
    }


def _load_state_manifest(
    path: Path,
    source_id: str,
    projection_path: str,
    source_projection_sha256: str,
    signing_secret: Optional[str],
) -> Tuple[Dict[str, Any], int]:
    if not path.exists():
        payload = {
            "schema_version": REVIEW_STATE_SCHEMA_VERSION,
            "source_id": source_id,
            "source_projection_sha256": source_projection_sha256,
            "projection_path": _normalize_path(projection_path),
            "generated_utc": _utc_now(),
            "decisions": [],
        }
        return payload, 0

    with open(path, "r", encoding="utf-8") as fp:
        raw = load_json_strict(fp)

    try:
        payload = validate_review_manifest(
            raw,
            source_id=source_id,
            source_projection_sha256=source_projection_sha256,
            signing_secret=signing_secret,
        )
    except (TypeError, ValueError) as err:
        raise ValueError(f"review state manifest is invalid: {path}: {err}") from err
    return payload, payload["revision"]


def _write_payload(payload: Dict[str, Any], path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix="chronicle-review-", suffix=".tmp", dir=path.parent)
    with open(fd, "w", encoding="utf-8") as fp:
        fp.write(_stable_json(payload) + "\n")
    Path(tmp_path).replace(path)
    return str(path)


@dataclass
class ReviewState:
    source_id: str
    source_projection_sha256: str
    projection_path: str
    state_path: Path
    claims: List[Dict[str, Any]]
    signing_secret: Optional[str] = None
    decisions: List[Dict[str, Any]] = field(default_factory=list)
    revision: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def claim_lookup(self) -> Dict[str, Dict[str, Any]]:
        return {claim["claim_id"]: claim for claim in self.claims if isinstance(claim.get("claim_id"), str)}

    def claim_by_id(self, claim_id: str) -> Optional[Dict[str, Any]]:
        for claim in self.claims:
            if claim.get("claim_id") == claim_id:
                return claim
        return None

    def decisions_for_claim(self, claim_id: str) -> List[Dict[str, Any]]:
        return [decision for decision in self.decisions if decision.get("claim_id") == claim_id]

    def add_decision(
        self,
        *,
        claim_id: str,
        action: str,
        reason: Optional[str],
        replacement_text: Optional[str],
    ) -> Dict[str, Any]:
        if action not in REVIEW_ACTIONS:
            raise ValueError(f"unsupported review action: {action}")
        if action == "edit" and (
            not isinstance(replacement_text, str) or not replacement_text.strip()
        ):
            raise ValueError("edit action requires replacement_text")
        if action in REASON_REQUIRED_FOR_ACTIONS:
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError(f"{action} action requires reason")
        elif reason is not None and not isinstance(reason, str):
            raise ValueError("reason must be a string")
        if replacement_text is not None and not isinstance(replacement_text, str):
            raise ValueError("replacement_text must be a string")

        claim = self.claim_lookup().get(claim_id)
        if claim is None:
            raise KeyError(f"claim not found: {claim_id}")

        with self.lock:
            issued_at = _utc_now()
            next_revision = self.revision + 1
            decision: Dict[str, Any] = {
                "schema_version": REVIEW_DECISION_SCHEMA_VERSION,
                "issued_at_utc": issued_at,
                "source_id": self.source_id,
                "source_projection_sha256": self.source_projection_sha256,
                "claim_id": claim_id,
                "review_claim_sha256": claim["review_claim_sha256"],
                "conversation_id": claim.get("conversation_id"),
                "action": action,
                "reason": reason,
                "replacement_text": replacement_text if action == "edit" else None,
                "review_revision": next_revision,
            }
            decision_sha256 = _digest(decision)
            decision["decision_id"] = f"review-decision-{decision_sha256[:24]}"
            decision["decision_sha256"] = decision_sha256

            if self.signing_secret is not None:
                signature = hmac.new(
                    self.signing_secret.encode("utf-8"),
                    decision_sha256.encode("ascii"),
                    sha256,
                ).hexdigest()
                decision["signature"] = {
                    "algorithm": "HMAC-SHA256",
                    "value": signature,
                }

            self.decisions.append(decision)
            self.revision = next_revision
            self._persist()
        return decision

    def list_decisions(self) -> List[Dict[str, Any]]:
        with self.lock:
            return list(self.decisions)

    def _persist(self) -> str:
        payload = {
            "schema_version": REVIEW_STATE_SCHEMA_VERSION,
            "source_id": self.source_id,
            "source_projection_sha256": self.source_projection_sha256,
            "projection_path": self.projection_path,
            "generated_utc": _utc_now(),
            "revision": self.revision,
            "decisions": list(self.decisions),
        }
        return _write_payload(payload, self.state_path)


def build_review_state(
    projection: Dict[str, Any],
    state_path: str,
    *,
    projection_path: str = "",
    signing_secret: Optional[str] = None,
) -> ReviewState:
    source_id = str(projection.get("source_id", "")).strip()
    if not source_id:
        raise ValueError("projection missing source_id")

    source_projection_sha256 = _projection_digest(projection)
    claims = _extract_claim_rows(projection)
    manifest_path = Path(state_path)
    payload, revision = _load_state_manifest(
        manifest_path,
        source_id,
        projection_path,
        source_projection_sha256,
        signing_secret,
    )
    decisions = list(payload.get("decisions", []))
    return ReviewState(
        source_id=source_id,
        source_projection_sha256=source_projection_sha256,
        projection_path=_normalize_path(projection_path),
        state_path=manifest_path,
        claims=claims,
        signing_secret=signing_secret,
        decisions=decisions,
        revision=revision,
    )


def _json_response(handler: BaseHTTPRequestHandler, payload: Any, status: int = 200) -> None:
    body = json.dumps(payload, sort_keys=True, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _error_response(handler: BaseHTTPRequestHandler, status: int, detail: str) -> None:
    _json_response(handler, {"error": detail}, status=status)


def _parse_request_payload(handler: BaseHTTPRequestHandler) -> Dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0"))
    if length <= 0:
        return {}
    payload = handler.rfile.read(length)
    if not payload:
        return {}
    content_type = handler.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    raw = payload.decode("utf-8")
    if content_type == "application/x-www-form-urlencoded":
        parsed = urllib.parse.parse_qs(raw, keep_blank_values=True)
        return {k: v[-1] if v else "" for k, v in parsed.items()}
    return loads_json_strict(raw)


def _review_ui_html(bind: str, port: int, claims: List[Dict[str, Any]]) -> str:
    allowed_actions = ", ".join(sorted(REVIEW_ACTIONS))
    claim_rows = []
    for claim in claims:
        claim_id = str(claim.get("claim_id", ""))
        if not claim_id:
            continue
        claim_text = html.escape(str(claim.get("claim_text", "")))
        claim_type = html.escape(str(claim.get("claim_type", "")))
        temporal_state = html.escape(str(claim.get("temporal_state", "")))
        safe_id = html.escape(claim_id)
        accept_action = f"/api/v1/review/claims/{safe_id}/decision/accept"
        reject_action = f"/api/v1/review/claims/{safe_id}/decision/reject"
        edit_action = f"/api/v1/review/claims/{safe_id}/decision/edit"
        supersede_action = f"/api/v1/review/claims/{safe_id}/decision/supersede"
        contradict_action = f"/api/v1/review/claims/{safe_id}/decision/contradict"
        claim_rows.append(
            f"""
  <section>
    <h2>Claim {safe_id}</h2>
    <p>{claim_text}</p>
    <ul>
      <li>type={claim_type}</li>
      <li>state={temporal_state}</li>
    </ul>
    <form method=\"post\" action=\"{accept_action}\" enctype=\"application/x-www-form-urlencoded\">
      <button type=\"submit\">Accept claim</button>
    </form>
    <form method=\"post\" action=\"{reject_action}\" enctype=\"application/x-www-form-urlencoded\">
      <label>Reason: <input type=\"text\" name=\"reason\" required></label>
      <button type=\"submit\">Reject claim</button>
    </form>
    <form method=\"post\" action=\"{edit_action}\" enctype=\"application/x-www-form-urlencoded\">
      <label>Reason: <input type=\"text\" name=\"reason\" required></label>
      <label>Replacement text: <input type=\"text\" name=\"replacement_text\" required></label>
      <button type=\"submit\">Edit claim</button>
    </form>
    <form method=\"post\" action=\"{supersede_action}\" enctype=\"application/x-www-form-urlencoded\">
      <label>Reason: <input type=\"text\" name=\"reason\" required></label>
      <button type=\"submit\">Supersede claim</button>
    </form>
    <form method=\"post\" action=\"{contradict_action}\" enctype=\"application/x-www-form-urlencoded\">
      <label>Reason: <input type=\"text\" name=\"reason\" required></label>
      <button type=\"submit\">Contradict claim</button>
    </form>
  </section>
"""
        )

    claims_block = "\n".join(claim_rows) if claim_rows else "<p>No claims available.</p>"
    return f"""<!doctype html>
<html>
<head><meta charset=\"utf-8\"/><title>Chronicle Review</title></head>
<body>
  <h1>Chronicle Review API</h1>
  <p>Loopback endpoint: http://{bind}:{port}/api/v1/review/</p>
  <p>Browse claim actions below; action endpoints accept JSON or form-encoded payloads.</p>
  <ul>
    <li>GET /api/v1/review/claims</li>
    <li>GET /api/v1/review/claims/{{claim_id}}</li>
    <li>GET /api/v1/review/claims/{{claim_id}}/decisions</li>
    <li>GET /api/v1/review/decisions</li>
    <li>POST /api/v1/review/claims/{{claim_id}}/decision</li>
    <li>POST /api/v1/review/claims/{{claim_id}}/decision/{{action}} (allowed actions: {allowed_actions})</li>
    <li>GET /api/v1/review/status</li>
  </ul>
  <h2>Claims</h2>
  {claims_block}
  <p>POST bodies use JSON objects like {{&quot;action&quot;:&quot;accept&quot;}}; edit/supersede/contradict accept reason/replacement_text where required.</p>
</body>
</html>"""


def _build_handler(state: ReviewState, bind: str, port: int):
    def _claim_parts_to_id(parts: List[str], offset: int = 4) -> str:
        return parts[offset]

    class ReviewRequestHandler(BaseHTTPRequestHandler):
        server_version = "ChronicleReview/1.0"

        def do_GET(self) -> None:
            parsed = urllib.parse.urlsplit(self.path)
            path = parsed.path
            parts = [part for part in path.strip("/").split("/") if part]

            if path == "/":
                html = _review_ui_html(bind, port, state.claims)
                body = html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/api/v1/review/claims":
                _json_response(
                    self,
                    {
                        "schema_version": REVIEW_API_SCHEMA_VERSION,
                        "source_id": state.source_id,
                        "source_projection_sha256": state.source_projection_sha256,
                        "claim_count": len(state.claims),
                        "claims": state.claims,
                    },
                )
                return

            if path == "/api/v1/review/decisions":
                _json_response(
                    self,
                    {
                        "schema_version": REVIEW_API_SCHEMA_VERSION,
                        "source_id": state.source_id,
                        "source_projection_sha256": state.source_projection_sha256,
                        "decision_count": len(state.decisions),
                        "decisions": state.list_decisions(),
                    },
                )
                return

            if (
                len(parts) == 5
                and parts[0] == "api"
                and parts[1] == "v1"
                and parts[2] == "review"
                and parts[3] == "claims"
            ):
                claim_id = _claim_parts_to_id(parts)
                claim = state.claim_by_id(claim_id)
                if claim is None:
                    _error_response(self, 404, f"claim not found: {claim_id}")
                    return
                _json_response(
                    self,
                    {
                        "schema_version": REVIEW_API_SCHEMA_VERSION,
                        "source_id": state.source_id,
                        "source_projection_sha256": state.source_projection_sha256,
                        "claim": claim,
                    },
                )
                return

            if (
                len(parts) == 6
                and parts[0] == "api"
                and parts[1] == "v1"
                and parts[2] == "review"
                and parts[3] == "claims"
                and parts[5] == "decisions"
            ):
                claim_id = _claim_parts_to_id(parts)
                claim = state.claim_by_id(claim_id)
                if claim is None:
                    _error_response(self, 404, f"claim not found: {claim_id}")
                    return
                decisions = state.decisions_for_claim(claim_id)
                _json_response(
                    self,
                    {
                        "schema_version": REVIEW_API_SCHEMA_VERSION,
                        "source_id": state.source_id,
                        "source_projection_sha256": state.source_projection_sha256,
                        "claim_id": claim_id,
                        "decision_count": len(decisions),
                        "decisions": decisions,
                    },
                )
                return

            if path == "/api/v1/review/status":
                _json_response(
                    self,
                    {
                        "schema_version": REVIEW_API_SCHEMA_VERSION,
                        "source_id": state.source_id,
                        "source_projection_sha256": state.source_projection_sha256,
                        "state_schema_version": REVIEW_STATE_SCHEMA_VERSION,
                        "state_path": str(state.state_path),
                        "revision": state.revision,
                    },
                )
                return

            _error_response(self, 404, "not found")

        def do_POST(self) -> None:
            parsed = urllib.parse.urlsplit(self.path)
            path = parsed.path
            parts = [part for part in path.strip("/").split("/") if part]

            if (
                len(parts) == 6
                and parts[0] == "api"
                and parts[1] == "v1"
                and parts[2] == "review"
                and parts[3] == "claims"
                and parts[5] == "decision"
            ):
                claim_id = _claim_parts_to_id(parts)
                try:
                    payload = _parse_request_payload(self)
                    if not isinstance(payload, dict):
                        raise ValueError("request body must be a JSON object")
                    action = payload.get("action")
                    if not isinstance(action, str):
                        raise ValueError("missing review action")
                    reason = payload.get("reason")
                    replacement_text = payload.get("replacement_text")
                    decision = state.add_decision(
                        claim_id=claim_id,
                        action=action,
                        reason=reason,
                        replacement_text=replacement_text,
                    )
                    _json_response(
                        self,
                        {"schema_version": REVIEW_API_SCHEMA_VERSION, "decision": decision},
                        status=201,
                    )
                except (TypeError, ValueError, KeyError, json.JSONDecodeError) as err:
                    _error_response(self, 400, str(err))
                return

            if (
                len(parts) == 7
                and parts[0] == "api"
                and parts[1] == "v1"
                and parts[2] == "review"
                and parts[3] == "claims"
                and parts[5] == "decision"
            ):
                claim_id = _claim_parts_to_id(parts)
                action = parts[6]
                try:
                    payload = _parse_request_payload(self)
                    if not isinstance(payload, dict):
                        raise ValueError("request body must be a JSON object")
                    reason = payload.get("reason")
                    replacement_text = payload.get("replacement_text")
                    decision = state.add_decision(
                        claim_id=claim_id,
                        action=action,
                        reason=reason,
                        replacement_text=replacement_text,
                    )
                    _json_response(
                        self,
                        {"schema_version": REVIEW_API_SCHEMA_VERSION, "decision": decision},
                        status=201,
                    )
                except (TypeError, ValueError, KeyError, json.JSONDecodeError) as err:
                    _error_response(self, 400, str(err))
                return

            _error_response(self, 404, "not found")

        def log_message(self, fmt: str, *args) -> None:
            # keep the API loopback surface quiet during tests
            return

    return ReviewRequestHandler


def start_review_api_server(
    *,
    projection: Dict[str, Any],
    state_path: str,
    projection_path: str,
    host: str = "127.0.0.1",
    port: int = 8765,
    signing_secret: Optional[str] = None,
) -> Tuple[ThreadingHTTPServer, ReviewState]:
    state = build_review_state(
        projection,
        state_path,
        projection_path=projection_path,
        signing_secret=signing_secret,
    )
    handler = _build_handler(state, host, port)
    server = ThreadingHTTPServer((host, port), handler)
    return server, state


def run_review_api_server(
    *,
    projection: Dict[str, Any],
    state_path: str,
    projection_path: str,
    host: str = "127.0.0.1",
    port: int = 8765,
    signing_secret: Optional[str] = None,
) -> ThreadingHTTPServer:
    return start_review_api_server(
        projection=projection,
        state_path=state_path,
        projection_path=projection_path,
        host=host,
        port=port,
        signing_secret=signing_secret,
    )[0]


__all__ = [
    "REVIEW_ACTIONS",
    "REVIEW_API_SCHEMA_VERSION",
    "REVIEW_DECISION_SCHEMA_VERSION",
    "REVIEW_STATE_SCHEMA_VERSION",
    "ReviewState",
    "build_review_state",
    "run_review_api_server",
    "start_review_api_server",
    "validate_review_manifest",
]
