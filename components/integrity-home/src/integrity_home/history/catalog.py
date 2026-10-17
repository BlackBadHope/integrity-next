"""Deterministic multilingual catalog hints for History evidence.

This module deliberately performs no model call, I/O, persistence, or corpus
mutation.  Exact normalized token and phrase matches can help a later caller
route, boost, or filter a complete FTS query.  They are not facts, truth
claims, or a replacement for complete lexical retrieval.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import json
from types import MappingProxyType
from typing import Final, Literal, TypeAlias, cast
import unicodedata


CATALOG_INPUT_SCHEMA_VERSION: Final = "integrity-home-history-catalog-input/1"
CATALOG_OUTPUT_SCHEMA_VERSION: Final = "integrity-home-history-catalog-output/1"
CLASSIFIER_ID: Final = "integrity-home.history.catalog.exact-lexicon"
CLASSIFIER_VERSION: Final = "1.0.0"

# Hard ceilings are part of the classifier contract.  Callers cannot raise
# them, and over-budget input is rejected rather than partially classified.
MAX_TEXT_CHARS: Final = 8_192
MAX_NORMALIZED_CHARS: Final = 16_384
MAX_TOKENS: Final = 2_048
MAX_TOKEN_CHARS: Final = 128
MAX_TOKEN_WORK: Final = 16_384
MAX_LABELS_PER_AXIS: Final = 8
MAX_METADATA_LABELS: Final = 4
MAX_EVIDENCE: Final = 64
MAX_PHRASE_TOKENS: Final = 4


RecordKind: TypeAlias = Literal[
    "artifact",
    "concept",
    "conversation",
    "document",
    "event",
    "message",
    "note",
    "project",
    "query",
    "task",
    "unknown",
]
AuthorityLabel: TypeAlias = Literal[
    "assistant_output",
    "quoted_material",
    "reviewed_derived",
    "system_metadata",
    "unknown",
    "user_assertion",
]
SensitivityLabel: TypeAlias = Literal[
    "confidential",
    "internal",
    "private",
    "public",
    "restricted",
    "unknown",
]
EvidenceAxis: TypeAlias = Literal["domain", "subject"]
EvidenceKind: TypeAlias = Literal["phrase", "token"]


_RECORD_KINDS: Final = frozenset(
    {
        "artifact",
        "concept",
        "conversation",
        "document",
        "event",
        "message",
        "note",
        "project",
        "query",
        "task",
        "unknown",
    }
)
_AUTHORITY_LABELS: Final = frozenset(
    {
        "assistant_output",
        "quoted_material",
        "reviewed_derived",
        "system_metadata",
        "unknown",
        "user_assertion",
    }
)
_SENSITIVITY_LABELS: Final = frozenset(
    {"confidential", "internal", "private", "public", "restricted", "unknown"}
)
_DOMAIN_LABELS: Final = frozenset(
    {
        "business",
        "creative",
        "education",
        "media",
        "operations",
        "personal",
        "technology",
        "unknown",
    }
)
_SUBJECT_LABELS: Final = frozenset(
    {
        "conversation",
        "film",
        "game",
        "organization",
        "person",
        "place",
        "project",
        "unknown",
    }
)


class CatalogError(ValueError):
    """Base class for rejected catalog inputs."""


class CatalogSchemaError(CatalogError):
    """The versioned input or its metadata does not match the contract."""


class CatalogBudgetError(CatalogError):
    """Classification stopped before producing a partial over-budget result."""


def _validate_unicode_scalar_text(value: str, *, field_name: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise CatalogSchemaError(f"{field_name} contains an unpaired surrogate")


def _coerce_metadata_labels(
    value: object,
    *,
    field_name: str,
    allowed: frozenset[str],
    expected_container: type[list[object]] | type[tuple[object, ...]],
) -> tuple[str, ...]:
    if type(value) is not expected_container:
        container_name = "array" if expected_container is list else "tuple"
        raise CatalogSchemaError(f"metadata.{field_name} must be a {container_name}")
    values = cast(list[object] | tuple[object, ...], value)
    if len(values) > MAX_METADATA_LABELS:
        raise CatalogBudgetError(
            f"metadata.{field_name} label budget exceeded: "
            f"{len(values)} > {MAX_METADATA_LABELS}"
        )
    labels: list[str] = []
    seen: set[str] = set()
    for item in values:
        if type(item) is not str or item not in allowed:
            raise CatalogSchemaError(f"metadata.{field_name} contains an invalid label")
        if item in seen:
            raise CatalogSchemaError(f"metadata.{field_name} contains a duplicate label")
        seen.add(item)
        labels.append(item)
    if not labels:
        return ("unknown",)
    if "unknown" in seen and len(seen) != 1:
        raise CatalogSchemaError(
            f"metadata.{field_name} cannot combine unknown with another label"
        )
    return tuple(sorted(labels))


@dataclass(frozen=True, slots=True)
class CatalogMetadata:
    """Validated structural facets supplied by a trusted caller.

    ``record_kind`` is never inferred from text.  Authority and sensitivity
    likewise pass through this validated object, defaulting to ``unknown``.
    """

    record_kind: RecordKind = "unknown"
    authority: tuple[AuthorityLabel, ...] = ("unknown",)
    sensitivity: tuple[SensitivityLabel, ...] = ("unknown",)

    def __post_init__(self) -> None:
        if type(self.record_kind) is not str or self.record_kind not in _RECORD_KINDS:
            raise CatalogSchemaError("metadata.record_kind is invalid")
        authority = _coerce_metadata_labels(
            self.authority,
            field_name="authority",
            allowed=_AUTHORITY_LABELS,
            expected_container=tuple,
        )
        sensitivity = _coerce_metadata_labels(
            self.sensitivity,
            field_name="sensitivity",
            allowed=_SENSITIVITY_LABELS,
            expected_container=tuple,
        )
        object.__setattr__(self, "authority", authority)
        object.__setattr__(self, "sensitivity", sensitivity)

    @classmethod
    def from_mapping(cls, value: object) -> CatalogMetadata:
        if not isinstance(value, Mapping):
            raise CatalogSchemaError("metadata must be an object")
        if len(value) > 3:
            raise CatalogSchemaError("metadata contains unsupported keys")
        keys = tuple(value)
        if any(type(key) is not str for key in keys):
            raise CatalogSchemaError("metadata keys must be exact strings")
        unknown_keys = set(keys) - {"record_kind", "authority", "sensitivity"}
        if unknown_keys:
            raise CatalogSchemaError("metadata contains unsupported keys")
        record_kind = value.get("record_kind", "unknown")
        if type(record_kind) is not str or record_kind not in _RECORD_KINDS:
            raise CatalogSchemaError("metadata.record_kind is invalid")
        authority = _coerce_metadata_labels(
            value.get("authority", []),
            field_name="authority",
            allowed=_AUTHORITY_LABELS,
            expected_container=list,
        )
        sensitivity = _coerce_metadata_labels(
            value.get("sensitivity", []),
            field_name="sensitivity",
            allowed=_SENSITIVITY_LABELS,
            expected_container=list,
        )
        return cls(
            record_kind=cast(RecordKind, record_kind),
            authority=cast(tuple[AuthorityLabel, ...], authority),
            sensitivity=cast(tuple[SensitivityLabel, ...], sensitivity),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "authority": list(self.authority),
            "record_kind": self.record_kind,
            "sensitivity": list(self.sensitivity),
        }


@dataclass(frozen=True, slots=True)
class CatalogInput:
    """Typed form of ``integrity-home-history-catalog-input/1``."""

    text: str
    metadata: CatalogMetadata = field(default_factory=CatalogMetadata)
    schema_version: str = CATALOG_INPUT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not str
            or self.schema_version != CATALOG_INPUT_SCHEMA_VERSION
        ):
            raise CatalogSchemaError("catalog input schema version mismatch")
        if type(self.text) is not str:
            raise CatalogSchemaError("text must be a string")
        if len(self.text) > MAX_TEXT_CHARS:
            raise CatalogBudgetError(
                "catalog text character budget exceeded: "
                f"{len(self.text)} > {MAX_TEXT_CHARS}"
            )
        _validate_unicode_scalar_text(self.text, field_name="text")
        if type(self.metadata) is not CatalogMetadata:
            raise CatalogSchemaError("metadata must be CatalogMetadata")

    @classmethod
    def from_mapping(cls, value: object) -> CatalogInput:
        if not isinstance(value, Mapping):
            raise CatalogSchemaError("catalog input must be an object")
        if len(value) != 3:
            raise CatalogSchemaError("catalog input key contract mismatch")
        keys = tuple(value)
        if (
            any(type(key) is not str for key in keys)
            or set(keys) != {"schema_version", "text", "metadata"}
        ):
            raise CatalogSchemaError("catalog input key contract mismatch")
        schema_version = value["schema_version"]
        text = value["text"]
        if (
            type(schema_version) is not str
            or schema_version != CATALOG_INPUT_SCHEMA_VERSION
        ):
            raise CatalogSchemaError("catalog input schema version mismatch")
        if type(text) is not str:
            raise CatalogSchemaError("text must be a string")
        return cls(
            text=text,
            metadata=CatalogMetadata.from_mapping(value["metadata"]),
            schema_version=CATALOG_INPUT_SCHEMA_VERSION,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "metadata": self.metadata.to_dict(),
            "schema_version": self.schema_version,
            "text": self.text,
        }


@dataclass(frozen=True, slots=True)
class CatalogLabels:
    record_kind: tuple[str, ...]
    domain: tuple[str, ...]
    subject: tuple[str, ...]
    authority: tuple[str, ...]
    sensitivity: tuple[str, ...]

    def __post_init__(self) -> None:
        axes = (
            ("record_kind", self.record_kind, _RECORD_KINDS, 1),
            ("domain", self.domain, _DOMAIN_LABELS, MAX_LABELS_PER_AXIS),
            ("subject", self.subject, _SUBJECT_LABELS, MAX_LABELS_PER_AXIS),
            ("authority", self.authority, _AUTHORITY_LABELS, MAX_METADATA_LABELS),
            (
                "sensitivity",
                self.sensitivity,
                _SENSITIVITY_LABELS,
                MAX_METADATA_LABELS,
            ),
        )
        for name, values, allowed, maximum in axes:
            if type(values) is not tuple or not values:
                raise CatalogSchemaError(f"output labels.{name} must be a non-empty tuple")
            if len(values) > maximum:
                raise CatalogBudgetError(f"output labels.{name} budget exceeded")
            if any(type(value) is not str or value not in allowed for value in values):
                raise CatalogSchemaError(f"output labels.{name} contains an invalid label")
            if values != tuple(sorted(set(values))):
                raise CatalogSchemaError(
                    f"output labels.{name} must be sorted and duplicate-free"
                )
            if "unknown" in values and values != ("unknown",):
                raise CatalogSchemaError(
                    f"output labels.{name} cannot mix unknown with another label"
                )

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "authority": list(self.authority),
            "domain": list(self.domain),
            "record_kind": list(self.record_kind),
            "sensitivity": list(self.sensitivity),
            "subject": list(self.subject),
        }


@dataclass(frozen=True, slots=True)
class EvidenceMatch:
    axis: EvidenceAxis
    label: str
    match_kind: EvidenceKind
    matched: str
    token_start: int
    token_end: int

    def __post_init__(self) -> None:
        if self.axis not in {"domain", "subject"}:
            raise CatalogSchemaError("evidence axis is invalid")
        allowed = _DOMAIN_LABELS if self.axis == "domain" else _SUBJECT_LABELS
        if self.label == "unknown" or self.label not in allowed:
            raise CatalogSchemaError("evidence label is invalid")
        if self.match_kind not in {"phrase", "token"}:
            raise CatalogSchemaError("evidence match_kind is invalid")
        if type(self.matched) is not str or not self.matched:
            raise CatalogSchemaError("evidence matched value is invalid")
        if self.matched != unicodedata.normalize("NFKC", self.matched).casefold():
            raise CatalogSchemaError("evidence matched value is not normalized")
        matched_tokens = self.matched.split(" ")
        if any(not token for token in matched_tokens):
            raise CatalogSchemaError("evidence matched value has invalid spacing")
        expected_width = 1 if self.match_kind == "token" else len(matched_tokens)
        if self.match_kind == "token" and len(matched_tokens) != 1:
            raise CatalogSchemaError("token evidence must contain one token")
        if self.match_kind == "phrase" and not 2 <= len(matched_tokens) <= MAX_PHRASE_TOKENS:
            raise CatalogSchemaError("phrase evidence has an invalid token count")
        if (
            type(self.token_start) is not int
            or type(self.token_end) is not int
            or self.token_start < 0
            or self.token_end <= self.token_start
            or self.token_end - self.token_start != expected_width
        ):
            raise CatalogSchemaError("evidence token span is invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "axis": self.axis,
            "label": self.label,
            "match_kind": self.match_kind,
            "matched": self.matched,
            "token_end": self.token_end,
            "token_start": self.token_start,
        }


@dataclass(frozen=True, slots=True)
class WorkSummary:
    normalized_chars: int
    token_count: int
    token_work: int

    def __post_init__(self) -> None:
        limits = (
            ("normalized_chars", self.normalized_chars, MAX_NORMALIZED_CHARS),
            ("token_count", self.token_count, MAX_TOKENS),
            ("token_work", self.token_work, MAX_TOKEN_WORK),
        )
        for name, value, maximum in limits:
            if type(value) is not int or not 0 <= value <= maximum:
                raise CatalogSchemaError(f"work.{name} is outside its contract")

    def to_dict(self) -> dict[str, int]:
        return {
            "normalized_chars": self.normalized_chars,
            "token_count": self.token_count,
            "token_work": self.token_work,
        }


@dataclass(frozen=True, slots=True)
class CatalogResult:
    labels: CatalogLabels
    evidence: tuple[EvidenceMatch, ...]
    work: WorkSummary
    schema_version: str = field(default=CATALOG_OUTPUT_SCHEMA_VERSION, init=False)
    input_schema_version: str = field(default=CATALOG_INPUT_SCHEMA_VERSION, init=False)
    classifier_id: str = field(default=CLASSIFIER_ID, init=False)
    classifier_version: str = field(default=CLASSIFIER_VERSION, init=False)
    authoritative: bool = field(default=False, init=False)
    review_required: bool = field(default=True, init=False)
    truth_status: str = field(default="unknown", init=False)
    classification_role: str = field(default="routing_search_hint", init=False)
    fts_role: str = field(default="lexical_recall_baseline", init=False)

    def __post_init__(self) -> None:
        if type(self.labels) is not CatalogLabels:
            raise CatalogSchemaError("result labels must be CatalogLabels")
        if type(self.evidence) is not tuple:
            raise CatalogSchemaError("result evidence must be a tuple")
        if len(self.evidence) > MAX_EVIDENCE:
            raise CatalogBudgetError("result evidence budget exceeded")
        if any(type(item) is not EvidenceMatch for item in self.evidence):
            raise CatalogSchemaError("result evidence contains an invalid item")
        ordering = lambda item: (
            item.axis,
            item.label,
            item.match_kind,
            item.matched,
            item.token_start,
            item.token_end,
        )
        if self.evidence != tuple(sorted(self.evidence, key=ordering)):
            raise CatalogSchemaError("result evidence must use deterministic ordering")
        if type(self.work) is not WorkSummary:
            raise CatalogSchemaError("result work must be WorkSummary")

    def to_dict(self) -> dict[str, object]:
        return {
            "authoritative": self.authoritative,
            "classification_role": self.classification_role,
            "classifier": {
                "id": self.classifier_id,
                "version": self.classifier_version,
            },
            "evidence": [item.to_dict() for item in self.evidence],
            "fts_role": self.fts_role,
            "input_schema_version": self.input_schema_version,
            "labels": self.labels.to_dict(),
            "review_required": self.review_required,
            "schema_version": self.schema_version,
            "truth_status": self.truth_status,
            "work": self.work.to_dict(),
        }


_TOKEN_LEXICONS: Final = MappingProxyType(
    {
        "domain": MappingProxyType(
            {
                "business": (
                    "business",
                    "commerce",
                    "бизнес",
                    "бізнес",
                    "підприємництво",
                ),
                "creative": (
                    "creative",
                    "design",
                    "music",
                    "story",
                    "дизайн",
                    "музыка",
                    "рассказ",
                    "творческий",
                    "музика",
                    "оповідання",
                    "творчий",
                ),
                "education": (
                    "course",
                    "education",
                    "learning",
                    "training",
                    "курс",
                    "образование",
                    "обучение",
                    "навчання",
                    "освіта",
                ),
                "media": (
                    "film",
                    "game",
                    "media",
                    "movie",
                    "video",
                    "видео",
                    "видеоигра",
                    "игра",
                    "кино",
                    "медиа",
                    "фильм",
                    "відео",
                    "відеогра",
                    "гра",
                    "кіно",
                    "медіа",
                    "фільм",
                ),
                "operations": (
                    "deployment",
                    "incident",
                    "network",
                    "operations",
                    "инцидент",
                    "операции",
                    "развертывание",
                    "сеть",
                    "інцидент",
                    "мережа",
                    "операції",
                    "розгортання",
                ),
                "personal": (
                    "family",
                    "hobby",
                    "personal",
                    "личное",
                    "личный",
                    "семья",
                    "хобби",
                    "особисте",
                    "особистий",
                    "родина",
                ),
                "technology": (
                    "hardware",
                    "programming",
                    "software",
                    "technology",
                    "программирование",
                    "сервер",
                    "технологии",
                    "технология",
                    "програмування",
                    "технології",
                    "технологія",
                ),
            }
        ),
        "subject": MappingProxyType(
            {
                "conversation": (
                    "chat",
                    "conversation",
                    "dialog",
                    "dialogue",
                    "беседа",
                    "диалог",
                    "разговор",
                    "чат",
                    "бесіда",
                    "діалог",
                    "розмова",
                ),
                "film": (
                    "cinema",
                    "film",
                    "movie",
                    "кино",
                    "фильм",
                    "кіно",
                    "фільм",
                ),
                "game": (
                    "game",
                    "gameplay",
                    "геймплей",
                    "видеоигра",
                    "игра",
                    "відеогра",
                    "гра",
                ),
                "organization": (
                    "company",
                    "organisation",
                    "organization",
                    "team",
                    "команда",
                    "компания",
                    "организация",
                    "компанія",
                    "організація",
                ),
                "person": (
                    "human",
                    "person",
                    "персона",
                    "человек",
                    "людина",
                    "особа",
                ),
                "place": (
                    "city",
                    "country",
                    "location",
                    "place",
                    "город",
                    "место",
                    "страна",
                    "країна",
                    "місце",
                    "місто",
                ),
                "project": (
                    "initiative",
                    "project",
                    "инициатива",
                    "проект",
                    "ініціатива",
                    "проєкт",
                ),
            }
        ),
    }
)

_PHRASE_LEXICONS: Final = MappingProxyType(
    {
        "domain": MappingProxyType(
            {
                "business": (
                    "business plan",
                    "customer support",
                    "бизнес план",
                    "поддержка клиентов",
                    "бізнес план",
                    "підтримка клієнтів",
                ),
                "creative": (
                    "creative concept",
                    "visual design",
                    "визуальный дизайн",
                    "творческая концепция",
                    "візуальний дизайн",
                    "творча концепція",
                ),
                "education": (
                    "online course",
                    "study plan",
                    "план обучения",
                    "учебный курс",
                    "навчальний курс",
                    "план навчання",
                ),
                "media": (
                    "board game",
                    "feature film",
                    "video game",
                    "настольная игра",
                    "художественный фильм",
                    "настільна гра",
                    "художній фільм",
                ),
                "operations": (
                    "incident response",
                    "network operations",
                    "service outage",
                    "авария сервиса",
                    "реагирование на инциденты",
                    "сетевые операции",
                    "збій сервісу",
                    "мережеві операції",
                    "реагування на інциденти",
                ),
                "personal": (
                    "family archive",
                    "personal project",
                    "личный проект",
                    "семейный архив",
                    "особистий проєкт",
                    "родинний архів",
                ),
                "technology": (
                    "artificial intelligence",
                    "machine learning",
                    "software engineering",
                    "искусственный интеллект",
                    "машинное обучение",
                    "разработка программного обеспечения",
                    "машинне навчання",
                    "розробка програмного забезпечення",
                    "штучний інтелект",
                ),
            }
        ),
        "subject": MappingProxyType(
            {
                "conversation": (
                    "chat history",
                    "conversation thread",
                    "ветка разговора",
                    "история чата",
                    "гілка розмови",
                    "історія чату",
                ),
                "film": (
                    "documentary film",
                    "feature film",
                    "документальный фильм",
                    "художественный фильм",
                    "документальний фільм",
                    "художній фільм",
                ),
                "game": (
                    "board game",
                    "video game",
                    "настольная игра",
                    "настільна гра",
                ),
                "organization": (
                    "project team",
                    "software company",
                    "проектная команда",
                    "технологическая компания",
                    "проєктна команда",
                    "технологічна компанія",
                ),
                "person": ("team member", "член команды", "член команди"),
                "place": (
                    "city center",
                    "home office",
                    "домашний офис",
                    "центр города",
                    "домашній офіс",
                    "центр міста",
                ),
                "project": (
                    "project roadmap",
                    "дорожная карта проекта",
                    "план проекта",
                    "дорожня карта проєкту",
                    "план проєкту",
                ),
            }
        ),
    }
)


def _compile_token_rules() -> Mapping[str, tuple[tuple[EvidenceAxis, str], ...]]:
    reverse: dict[str, set[tuple[EvidenceAxis, str]]] = {}
    for axis_raw in sorted(_TOKEN_LEXICONS):
        axis = cast(EvidenceAxis, axis_raw)
        for label, tokens in sorted(_TOKEN_LEXICONS[axis_raw].items()):
            for token in tokens:
                if token != unicodedata.normalize("NFKC", token).casefold() or " " in token:
                    raise RuntimeError("catalog token lexicon is not normalized")
                reverse.setdefault(token, set()).add((axis, label))
    return MappingProxyType(
        {token: tuple(sorted(rules)) for token, rules in sorted(reverse.items())}
    )


def _compile_phrase_rules() -> Mapping[
    str, tuple[tuple[tuple[str, ...], EvidenceAxis, str], ...]
]:
    by_first: dict[str, set[tuple[tuple[str, ...], EvidenceAxis, str]]] = {}
    for axis_raw in sorted(_PHRASE_LEXICONS):
        axis = cast(EvidenceAxis, axis_raw)
        for label, phrases in sorted(_PHRASE_LEXICONS[axis_raw].items()):
            for phrase in phrases:
                if phrase != unicodedata.normalize("NFKC", phrase).casefold():
                    raise RuntimeError("catalog phrase lexicon is not normalized")
                tokens = tuple(phrase.split(" "))
                if (
                    not 2 <= len(tokens) <= MAX_PHRASE_TOKENS
                    or any(not token for token in tokens)
                ):
                    raise RuntimeError("catalog phrase lexicon has an invalid shape")
                by_first.setdefault(tokens[0], set()).add((tokens, axis, label))
    return MappingProxyType(
        {token: tuple(sorted(rules)) for token, rules in sorted(by_first.items())}
    )


_TOKEN_RULES: Final = _compile_token_rules()
_PHRASE_RULES: Final = _compile_phrase_rules()


def _check_work(work: int) -> None:
    if work > MAX_TOKEN_WORK:
        raise CatalogBudgetError(
            f"catalog token-work budget exceeded: {work} > {MAX_TOKEN_WORK}"
        )


def _normalize_and_tokenize(text: str) -> tuple[tuple[str, ...], int, int]:
    if len(text) > MAX_TEXT_CHARS:
        raise CatalogBudgetError(
            f"catalog text character budget exceeded: {len(text)} > {MAX_TEXT_CHARS}"
        )
    normalized = unicodedata.normalize("NFKC", text).casefold()
    _validate_unicode_scalar_text(normalized, field_name="normalized text")
    if len(normalized) > MAX_NORMALIZED_CHARS:
        raise CatalogBudgetError(
            "catalog normalized-character budget exceeded: "
            f"{len(normalized)} > {MAX_NORMALIZED_CHARS}"
        )

    # One unit for normalization input and one unit for tokenization input.
    work = len(normalized)
    _check_work(work)
    tokens: list[str] = []
    current: list[str] = []

    def flush() -> None:
        if not current:
            return
        if len(tokens) >= MAX_TOKENS:
            raise CatalogBudgetError(
                f"catalog token-count budget exceeded: > {MAX_TOKENS}"
            )
        tokens.append("".join(current))
        current.clear()

    for character in normalized:
        work += 1
        _check_work(work)
        category = unicodedata.category(character)
        if category.startswith(("L", "N")) or (
            category.startswith("M") and current
        ):
            current.append(character)
            if len(current) > MAX_TOKEN_CHARS:
                raise CatalogBudgetError(
                    f"catalog token character budget exceeded: > {MAX_TOKEN_CHARS}"
                )
        else:
            flush()
    flush()
    return tuple(tokens), len(normalized), work


def _labels_or_unknown(values: set[str]) -> tuple[str, ...]:
    if len(values) > MAX_LABELS_PER_AXIS:
        raise CatalogBudgetError(
            "catalog output label budget exceeded: "
            f"{len(values)} > {MAX_LABELS_PER_AXIS}"
        )
    return tuple(sorted(values)) if values else ("unknown",)


def _classify(record: CatalogInput) -> CatalogResult:
    tokens, normalized_chars, work = _normalize_and_tokenize(record.text)
    matched_labels: dict[EvidenceAxis, set[str]] = {
        "domain": set(),
        "subject": set(),
    }
    evidence: list[EvidenceMatch] = []

    def add_evidence(
        *,
        axis: EvidenceAxis,
        label: str,
        match_kind: EvidenceKind,
        matched: str,
        token_start: int,
        token_end: int,
    ) -> None:
        if len(evidence) >= MAX_EVIDENCE:
            raise CatalogBudgetError(
                f"catalog evidence budget exceeded: > {MAX_EVIDENCE}"
            )
        matched_labels[axis].add(label)
        if len(matched_labels[axis]) > MAX_LABELS_PER_AXIS:
            raise CatalogBudgetError(
                f"catalog {axis} label budget exceeded: > {MAX_LABELS_PER_AXIS}"
            )
        evidence.append(
            EvidenceMatch(
                axis=axis,
                label=label,
                match_kind=match_kind,
                matched=matched,
                token_start=token_start,
                token_end=token_end,
            )
        )

    for index, token in enumerate(tokens):
        work += 1
        _check_work(work)
        token_rules = _TOKEN_RULES.get(token, ())
        work += len(token_rules)
        _check_work(work)
        for axis, label in token_rules:
            add_evidence(
                axis=axis,
                label=label,
                match_kind="token",
                matched=token,
                token_start=index,
                token_end=index + 1,
            )

        for phrase_tokens, axis, label in _PHRASE_RULES.get(token, ()):
            phrase_end = index + len(phrase_tokens)
            if phrase_end > len(tokens):
                continue
            matched = True
            for offset, expected in enumerate(phrase_tokens):
                work += 1
                _check_work(work)
                if tokens[index + offset] != expected:
                    matched = False
                    break
            if matched:
                add_evidence(
                    axis=axis,
                    label=label,
                    match_kind="phrase",
                    matched=" ".join(phrase_tokens),
                    token_start=index,
                    token_end=phrase_end,
                )

    ordered_evidence = tuple(
        sorted(
            evidence,
            key=lambda item: (
                item.axis,
                item.label,
                item.match_kind,
                item.matched,
                item.token_start,
                item.token_end,
            ),
        )
    )
    labels = CatalogLabels(
        record_kind=(record.metadata.record_kind,),
        domain=_labels_or_unknown(matched_labels["domain"]),
        subject=_labels_or_unknown(matched_labels["subject"]),
        authority=tuple(record.metadata.authority),
        sensitivity=tuple(record.metadata.sensitivity),
    )
    return CatalogResult(
        labels=labels,
        evidence=ordered_evidence,
        work=WorkSummary(
            normalized_chars=normalized_chars,
            token_count=len(tokens),
            token_work=work,
        ),
    )


def classify_record(value: CatalogInput | Mapping[str, object]) -> CatalogResult:
    """Classify a validated record into bounded, review-required hints."""

    if type(value) is CatalogInput:
        record = value
    elif isinstance(value, Mapping):
        record = CatalogInput.from_mapping(value)
    else:
        raise CatalogSchemaError("catalog record must be CatalogInput or an object")
    return _classify(record)


def classify_catalog(value: CatalogInput | Mapping[str, object]) -> CatalogResult:
    """Explicit catalog-named alias for :func:`classify_record`."""

    return classify_record(value)


def classify_query(
    query: str,
    *,
    authority: tuple[AuthorityLabel, ...] = ("unknown",),
    sensitivity: tuple[SensitivityLabel, ...] = ("unknown",),
) -> CatalogResult:
    """Apply the exact same label mapping to a future FTS query hint.

    The wrapper supplies the structural ``query`` record kind; all domain and
    subject labels still come from the same exact token/phrase mapping used for
    evidence records.  The catalog cannot claim retrieval completeness; FTS
    remains the lexical recall baseline and provenance remains authoritative.
    """

    metadata = CatalogMetadata(
        record_kind="query",
        authority=authority,
        sensitivity=sensitivity,
    )
    return _classify(CatalogInput(text=query, metadata=metadata))


def catalog_result_json_bytes(result: CatalogResult) -> bytes:
    """Return one canonical UTF-8 JSON line for deterministic replay."""

    if type(result) is not CatalogResult:
        raise TypeError("result must be CatalogResult")
    return (
        json.dumps(
            result.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


__all__ = [
    "CATALOG_INPUT_SCHEMA_VERSION",
    "CATALOG_OUTPUT_SCHEMA_VERSION",
    "CLASSIFIER_ID",
    "CLASSIFIER_VERSION",
    "MAX_EVIDENCE",
    "MAX_LABELS_PER_AXIS",
    "MAX_METADATA_LABELS",
    "MAX_NORMALIZED_CHARS",
    "MAX_TEXT_CHARS",
    "MAX_TOKEN_CHARS",
    "MAX_TOKENS",
    "MAX_TOKEN_WORK",
    "CatalogBudgetError",
    "CatalogError",
    "CatalogInput",
    "CatalogLabels",
    "CatalogMetadata",
    "CatalogResult",
    "CatalogSchemaError",
    "EvidenceMatch",
    "WorkSummary",
    "catalog_result_json_bytes",
    "classify_catalog",
    "classify_query",
    "classify_record",
]
