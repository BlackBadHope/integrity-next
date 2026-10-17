"""Bounded, inert parser for Google Takeout Gemini My Activity HTML.

The supported contract is deliberately narrow.  Takeout stores one activity
card per ``outer-cell`` and does not expose original Gemini conversation IDs.
This module therefore preserves each card as its own conversation and never
fetches, resolves, renders, or executes HTML references.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from html.parser import HTMLParser
import codecs
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import unquote, urlsplit


TAKEOUT_HTML_SCHEMA_VERSION = "google-gemini/takeout-myactivity-html/1"
TAKEOUT_HTML_ADAPTER_ORIGIN = "integrity-home:gemini-takeout-html-parser/1"
TAKEOUT_HTML_COUNT_FIELDS = frozenset(
    {
        "source_cards",
        "prompt_records",
        "prompt_text_records",
        "prompt_media_only_records",
        "prompt_reference_only_records",
        "prompt_markup_only_records",
        "response_records",
        "response_text_records",
        "response_media_only_records",
        "response_reference_only_records",
        "response_markup_only_records",
        "canonical_messages",
        "empty_prompt_slots",
        "empty_response_slots",
        "reference_count",
        "message_reference_count",
        "metadata_reference_count",
        "relative_reference_count",
        "message_relative_reference_count",
        "metadata_relative_reference_count",
        "local_image_reference_count",
        "local_media_reference_count",
        "external_reference_count",
        "document_reference_count",
        "opaque_reference_count",
        "missing_relative_reference_count",
        "existing_relative_reference_count",
        "replacement_character_count",
        "quarantined_card_count",
    }
)
TAKEOUT_PATH_TAILS = {
    ("my activity", "gemini apps", "myactivity.html"),
    ("мої дії", "додатки gemini", "myactivity.html"),
}
OUTER_CELL_CLASSES = frozenset(
    {"outer-cell", "mdl-cell", "mdl-cell--12-col", "mdl-shadow--2dp"}
)
HEADER_CELL_CLASSES = frozenset({"header-cell", "mdl-cell", "mdl-cell--12-col"})
MAIN_CELL_CLASSES = frozenset(
    {"content-cell", "mdl-cell", "mdl-cell--6-col", "mdl-typography--body-1"}
)
RIGHT_CELL_CLASSES = frozenset({*MAIN_CELL_CLASSES, "mdl-typography--text-right"})
CAPTION_CELL_CLASSES = frozenset(
    {"content-cell", "mdl-cell", "mdl-cell--12-col", "mdl-typography--caption"}
)
RESERVED_STRUCTURAL_CLASSES = frozenset(
    {"outer-cell", "mdl-grid", "header-cell", "content-cell"}
)
MAX_DISCOVERY_ENTRIES = 25_000
MAX_HTML_BYTES = 64 * 1024**2
MAX_CARDS = 100_000
MAX_HTML_EVENTS = 2_000_000
MAX_HTML_START_TAGS = 600_000
MAX_TEXT_CHARS = 64 * 1024**2
MAX_DIV_DEPTH = 256
MAX_HTML_TAG_DEPTH = 512
MAX_ATTRIBUTES_PER_TAG = 64
MAX_ATTRIBUTE_CHARS = 1024**2
MAX_CARD_SERIALIZED_BYTES = 2 * 1024**2
MAX_MAIN_TEXT_CHARS = 1_250_000
MAX_PROMPT_TEXT_CHARS = 1_100_000
MAX_RESPONSE_TEXT_CHARS = 150_000
MAX_CARD_REFERENCES = 128
MAX_CARD_START_TAGS = 1024
MAX_CARD_RELATIVE_DEPTH = 16
MAX_CARD_EVENTS = 4096
MAX_CARD_TEXT_CHARS = 1_500_000

_VOID_TAGS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
}
_BLOCK_TAGS = {
    "address", "article", "aside", "blockquote", "div", "dl", "dt", "dd",
    "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3",
    "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol", "p",
    "pre", "section", "table", "tbody", "tfoot", "thead", "tr", "ul",
}
_REFERENCE_ATTRIBUTES = {"href", "src", "srcset", "poster"}
_MEDIA_REFERENCE_TAGS = {"audio", "img", "source", "track", "video"}
_FORBIDDEN_CARD_TAGS = {
    "base", "embed", "form", "iframe", "link", "meta", "object", "script", "style",
}
_TIMESTAMP_RE = re.compile(
    r"^(?P<day>\d{1,2})\s+(?P<month>[^\W\d_]{3,4})\.\s+"
    r"(?P<year>\d{4})\s+[^\W\d_]\.,\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+EEST$",
    re.UNICODE,
)
_UKRAINIAN_MONTHS = {
    "січ": 1, "лют": 2, "бер": 3, "квіт": 4, "трав": 5, "черв": 6,
    "лип": 7, "серп": 8, "вер": 9, "жовт": 10, "лист": 11, "груд": 12,
}


class GeminiTakeoutHtmlError(ValueError):
    """Raised when the instance-bound Takeout HTML contract is not satisfied."""


def _path_matches(path: Path) -> bool:
    parts = tuple(part.casefold() for part in path.parts)
    return len(parts) >= 3 and parts[-3:] in TAKEOUT_PATH_TAILS


def gemini_takeout_html_candidates(root: Path) -> List[Path]:
    """Return bounded, deterministic supported members below a staged root."""

    root = root.resolve()
    if not root.is_dir():
        raise GeminiTakeoutHtmlError("staged root is not a directory")
    candidates: List[Path] = []
    pending = [root]
    seen_entries = 0
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(
                os.scandir(directory), key=lambda item: (item.name.casefold(), item.name)
            )
        except OSError as err:
            raise GeminiTakeoutHtmlError("unable to inspect staged provider tree") from err
        for entry in entries:
            seen_entries += 1
            if seen_entries > MAX_DISCOVERY_ENTRIES:
                raise GeminiTakeoutHtmlError("staged provider tree exceeds discovery limit")
            if entry.is_symlink():
                continue
            path = Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
            elif entry.is_file(follow_symlinks=False) and _path_matches(path.relative_to(root)):
                candidates.append(path)
    return sorted(candidates, key=lambda path: path.relative_to(root).as_posix())


def discover_gemini_takeout_html(root: Path) -> Path:
    candidates = gemini_takeout_html_candidates(root)
    if not candidates:
        raise GeminiTakeoutHtmlError("Gemini Takeout MyActivity HTML member not found")
    if len(candidates) != 1:
        raise GeminiTakeoutHtmlError("multiple Gemini Takeout MyActivity HTML members found")
    return candidates[0]


@dataclass
class _Segment:
    events: List[Dict[str, Any]] = field(default_factory=list)

    def text_fragments(self) -> List[str]:
        return [event["value"] for event in self.events if event["kind"] == "text"]

    def nonblank_text_fragments(self) -> List[str]:
        return [value for value in self.text_fragments() if value.strip()]


@dataclass
class _Cell:
    classes: List[str]
    attributes: List[Dict[str, Any]]
    stack_depth: int
    segment: _Segment = field(default_factory=_Segment)
    text_chars: int = 0


@dataclass
class _Card:
    ordinal: int
    stack_depth: int
    attributes: List[Dict[str, Any]]
    header: Optional[_Cell] = None
    content_cells: List[_Cell] = field(default_factory=list)
    active_cell: Optional[_Cell] = None
    active_kind: Optional[str] = None
    grid_count: int = 0
    grid_attributes: Optional[List[Dict[str, Any]]] = None
    grid_stack_depth: Optional[int] = None
    grid_open: bool = False
    grid_closed: bool = False
    callback_count: int = 0
    start_tag_count: int = 0
    text_chars: int = 0
    serialized_bytes: int = 0
    reference_count: int = 0
    max_relative_depth: int = 0


@dataclass
class _MainSplit:
    prompt: _Segment
    delimiter_before: _Segment
    timestamp: _Segment
    delimiter_after: _Segment
    response: _Segment
    timestamp_raw: str
    normalized_timestamp: str


def _attribute_list(attrs: Sequence[Tuple[str, Optional[str]]]) -> List[Dict[str, Any]]:
    seen = set()
    result = []
    if len(attrs) > MAX_ATTRIBUTES_PER_TAG:
        raise GeminiTakeoutHtmlError("HTML element exceeds attribute limit")
    for name, value in attrs:
        normalized = name.casefold()
        if "\ufffd" in normalized:
            raise GeminiTakeoutHtmlError(
                "replacement character in HTML attribute name"
            )
        if normalized in seen:
            raise GeminiTakeoutHtmlError("HTML element has duplicate attribute")
        seen.add(normalized)
        if value is not None and len(value) > MAX_ATTRIBUTE_CHARS:
            raise GeminiTakeoutHtmlError("HTML attribute exceeds value limit")
        result.append({"name": normalized, "value": value})
    return result


def _class_tokens(attributes: Sequence[Dict[str, Any]]) -> List[str]:
    class_values = [item["value"] for item in attributes if item["name"] == "class"]
    if not class_values or class_values[0] is None:
        return []
    tokens = class_values[0].split()
    if len(tokens) != len(set(tokens)):
        raise GeminiTakeoutHtmlError("HTML class attribute has duplicate token")
    return tokens


def _validate_class_only_attributes(
    attributes: Sequence[Dict[str, Any]],
    expected_classes: frozenset[str],
    *,
    context: str,
) -> None:
    if len(attributes) != 1 or attributes[0].get("name") != "class":
        raise GeminiTakeoutHtmlError(f"{context} has unsupported structural attributes")
    if frozenset(_class_tokens(attributes)) != expected_classes:
        raise GeminiTakeoutHtmlError(f"{context} class contract mismatch")


def _serialized_item_bytes(item: Dict[str, Any]) -> int:
    return len(
        json.dumps(
            item, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ) + 1


class _TakeoutParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.cards: List[_Card] = []
        self._card: Optional[_Card] = None
        self._div_depth = 0
        self._open_tags: List[str] = []
        self._event_count = 0
        self._start_tag_count = 0
        self._text_chars = 0
        self._page_grid_stack_depth: Optional[int] = None
        self._page_grid_open = False
        self._page_grid_closed = False
        self._page_grid_card_count = 0
        self._header_has_trailing_break: Optional[bool] = None

    def _note_event(self) -> None:
        self._event_count += 1
        if self._event_count > MAX_HTML_EVENTS:
            raise GeminiTakeoutHtmlError("HTML exceeds structural event limit")

    def _note_card_callback(self) -> None:
        if self._card is None:
            return
        self._card.callback_count += 1
        if self._card.callback_count > MAX_CARD_EVENTS:
            raise GeminiTakeoutHtmlError("activity card exceeds event limit")

    def _note_card_start(self) -> None:
        if self._card is None:
            return
        self._card.start_tag_count += 1
        if self._card.start_tag_count > MAX_CARD_START_TAGS:
            raise GeminiTakeoutHtmlError("activity card exceeds start-tag limit")

    def _note_card_scaffold(
        self, tag: str, attributes: Sequence[Dict[str, Any]]
    ) -> None:
        if self._card is None:
            return
        scaffold = {"kind": "scaffold_start", "tag": tag, "attributes": attributes}
        self._card.serialized_bytes += _serialized_item_bytes(scaffold)
        if self._card.serialized_bytes > MAX_CARD_SERIALIZED_BYTES:
            raise GeminiTakeoutHtmlError("activity card exceeds serialized-size limit")

    def _bounded_event(self, segment: _Segment, event: Dict[str, Any]) -> None:
        card = self._card
        if card is None:
            raise GeminiTakeoutHtmlError("internal activity-card event without card")
        card.serialized_bytes += _serialized_item_bytes(event)
        if card.serialized_bytes > MAX_CARD_SERIALIZED_BYTES:
            raise GeminiTakeoutHtmlError("activity card exceeds serialized-size limit")
        depth = event.get("depth")
        if isinstance(depth, int):
            card.max_relative_depth = max(card.max_relative_depth, depth)
            if card.max_relative_depth > MAX_CARD_RELATIVE_DEPTH:
                raise GeminiTakeoutHtmlError("activity card exceeds nesting limit")
        if event.get("kind") == "start":
            reference_count = sum(
                attribute.get("name") in _REFERENCE_ATTRIBUTES
                for attribute in event.get("attributes", [])
            )
            card.reference_count += reference_count
            if card.reference_count > MAX_CARD_REFERENCES:
                raise GeminiTakeoutHtmlError("activity card exceeds reference limit")
        segment.events.append(event)

    def _active_segment(self) -> Optional[_Segment]:
        card = self._card
        if card is None or card.active_cell is None:
            return None
        return card.active_cell.segment

    def _relative_depth(self, *, pushed_nonvoid: bool = False) -> int:
        assert self._card is not None and self._card.active_cell is not None
        cell_depth = self._card.active_cell.stack_depth
        depth = len(self._open_tags) - cell_depth - (1 if pushed_nonvoid else 0)
        if depth < 0:
            raise GeminiTakeoutHtmlError("malformed activity-cell nesting")
        return depth

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        self._note_event()
        self._start_tag_count += 1
        if self._start_tag_count > MAX_HTML_START_TAGS:
            raise GeminiTakeoutHtmlError("HTML exceeds start-tag limit")
        tag = tag.casefold()
        if "\ufffd" in tag:
            raise GeminiTakeoutHtmlError("replacement character in HTML tag name")
        attributes = _attribute_list(attrs)
        classes = _class_tokens(attributes)
        if tag != "div" and RESERVED_STRUCTURAL_CLASSES.intersection(classes):
            raise GeminiTakeoutHtmlError(
                "activity structural class tag contract mismatch"
            )
        is_void = tag in _VOID_TAGS
        if not is_void:
            self._open_tags.append(tag)
            if len(self._open_tags) > MAX_HTML_TAG_DEPTH:
                raise GeminiTakeoutHtmlError("HTML exceeds tag nesting limit")
        if tag == "div":
            self._div_depth += 1
            if self._div_depth > MAX_DIV_DEPTH:
                raise GeminiTakeoutHtmlError("HTML exceeds div nesting limit")
            if frozenset(classes) == OUTER_CELL_CLASSES:
                if self._card is not None:
                    raise GeminiTakeoutHtmlError("nested Gemini activity card")
                if self._page_grid_stack_depth is not None and (
                    not self._page_grid_open
                    or len(self._open_tags) != self._page_grid_stack_depth + 1
                ):
                    raise GeminiTakeoutHtmlError(
                        "activity card is outside the direct page grid"
                    )
                if len(self.cards) >= MAX_CARDS:
                    raise GeminiTakeoutHtmlError("HTML exceeds activity-card limit")
                self._card = _Card(
                    len(self.cards), len(self._open_tags), attributes=attributes
                )
                if self._page_grid_open:
                    self._page_grid_card_count += 1
                self._note_card_callback()
                self._note_card_start()
                self._note_card_scaffold(tag, attributes)
                return
            if "outer-cell" in classes and self._card is None:
                raise GeminiTakeoutHtmlError("activity outer-cell class contract mismatch")
            if (
                self._card is None
                and frozenset(classes) == frozenset({"mdl-grid"})
                and self._open_tags[:-1] == ["html", "body"]
            ):
                if self._page_grid_stack_depth is not None:
                    raise GeminiTakeoutHtmlError("duplicate activity page grid")
                if self.cards:
                    raise GeminiTakeoutHtmlError(
                        "activity page grid must precede activity cards"
                    )
                _validate_class_only_attributes(
                    attributes,
                    frozenset({"mdl-grid"}),
                    context="activity page grid",
                )
                self._page_grid_stack_depth = len(self._open_tags)
                self._page_grid_open = True
                return
            if self._card is None and {
                "mdl-grid",
                "header-cell",
                "content-cell",
            }.intersection(classes):
                raise GeminiTakeoutHtmlError(
                    "orphan reserved activity structural marker"
                )

        if self._card is None and self._page_grid_open:
            raise GeminiTakeoutHtmlError(
                "activity page grid contains non-card markup"
            )

        self._note_card_callback()
        self._note_card_start()

        if tag == "div":

            if (
                self._card is not None
                and frozenset(classes) == frozenset({"mdl-grid"})
                and len(self._open_tags) == self._card.stack_depth + 1
            ):
                self._card.grid_count += 1
                if self._card.grid_count > 1:
                    raise GeminiTakeoutHtmlError("activity card has duplicate direct grid")
                self._card.grid_attributes = attributes
                self._card.grid_stack_depth = len(self._open_tags)
                self._card.grid_open = True
                self._note_card_scaffold(tag, attributes)
                return

            if self._card is not None and "header-cell" in classes:
                if self._card.active_cell is not None or self._card.header is not None:
                    raise GeminiTakeoutHtmlError("duplicate or nested activity header")
                if self._card.content_cells:
                    raise GeminiTakeoutHtmlError(
                        "activity header must precede direct content cells"
                    )
                if (
                    self._card.grid_count != 1
                    or not self._card.grid_open
                    or self._card.grid_stack_depth is None
                    or len(self._open_tags) != self._card.grid_stack_depth + 1
                ):
                    raise GeminiTakeoutHtmlError("activity header is outside direct grid")
                cell = _Cell(
                    classes=classes,
                    attributes=attributes,
                    stack_depth=len(self._open_tags),
                )
                self._card.header = cell
                self._card.active_cell = cell
                self._card.active_kind = "header"
                self._note_card_scaffold(tag, attributes)
                return
            if self._card is not None and "content-cell" in classes:
                if self._card.active_cell is not None:
                    raise GeminiTakeoutHtmlError("nested activity content cell")
                if self._card.header is None:
                    raise GeminiTakeoutHtmlError(
                        "activity content cell precedes its direct header"
                    )
                if len(self._card.content_cells) >= 3:
                    raise GeminiTakeoutHtmlError("activity card has excess content cells")
                if (
                    self._card.grid_count != 1
                    or not self._card.grid_open
                    or self._card.grid_stack_depth is None
                    or len(self._open_tags) != self._card.grid_stack_depth + 1
                ):
                    raise GeminiTakeoutHtmlError("activity content cell is outside direct grid")
                cell = _Cell(
                    classes=classes,
                    attributes=attributes,
                    stack_depth=len(self._open_tags),
                )
                self._card.content_cells.append(cell)
                self._card.active_cell = cell
                self._card.active_kind = "content"
                self._note_card_scaffold(tag, attributes)
                return

        segment = self._active_segment()
        if segment is None:
            if self._card is not None:
                raise GeminiTakeoutHtmlError(
                    "activity card contains markup outside its direct cells"
                )
            return
        if tag in _FORBIDDEN_CARD_TAGS:
            raise GeminiTakeoutHtmlError("activity card contains unsupported active-content tag")
        depth = self._relative_depth(pushed_nonvoid=not is_void)
        self._bounded_event(
            segment,
            {"kind": "start", "tag": tag, "depth": depth, "attributes": attributes},
        )
        if is_void:
            self._bounded_event(segment, {"kind": "end", "tag": tag, "depth": depth})

    def handle_startendtag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.casefold() not in _VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        self._note_event()
        self._note_card_callback()
        tag = tag.casefold()
        if "\ufffd" in tag:
            raise GeminiTakeoutHtmlError("replacement character in HTML tag name")
        if tag in _VOID_TAGS:
            if self._card is not None:
                raise GeminiTakeoutHtmlError(
                    "activity card contains an explicit closing void tag"
                )
            if self._page_grid_open:
                raise GeminiTakeoutHtmlError(
                    "activity page grid contains an explicit closing void tag"
                )
            return
        if not self._open_tags or self._open_tags[-1] != tag:
            raise GeminiTakeoutHtmlError("malformed or unbalanced HTML tags")
        card = self._card
        if tag == "div":
            if self._div_depth <= 0:
                raise GeminiTakeoutHtmlError("malformed HTML div closure")
            if card is not None and card.active_cell is not None:
                if card.active_cell.stack_depth == len(self._open_tags):
                    card.active_cell = None
                    card.active_kind = None
                else:
                    segment = self._active_segment()
                    if segment is not None:
                        self._bounded_event(
                            segment,
                            {"kind": "end", "tag": tag, "depth": self._relative_depth(pushed_nonvoid=True)},
                        )
            if (
                card is not None
                and card.grid_open
                and card.grid_stack_depth == len(self._open_tags)
            ):
                card.grid_open = False
                card.grid_closed = True
            if card is not None and card.stack_depth == len(self._open_tags):
                if card.active_cell is not None:
                    raise GeminiTakeoutHtmlError("truncated activity content cell")
                header_has_trailing_break = self._validate_card(card)
                if self._header_has_trailing_break is None:
                    self._header_has_trailing_break = header_has_trailing_break
                elif self._header_has_trailing_break != header_has_trailing_break:
                    raise GeminiTakeoutHtmlError(
                        "activity header form is mixed within the document"
                    )
                self.cards.append(card)
                self._card = None
            if (
                self._page_grid_open
                and self._page_grid_stack_depth == len(self._open_tags)
            ):
                if card is not None:
                    raise GeminiTakeoutHtmlError(
                        "activity page grid closed around an open card"
                    )
                if self._page_grid_card_count == 0:
                    raise GeminiTakeoutHtmlError("activity page grid is empty")
                self._page_grid_open = False
                self._page_grid_closed = True
            self._open_tags.pop()
            self._div_depth -= 1
            return
        segment = self._active_segment()
        if segment is not None:
            self._bounded_event(
                segment,
                {"kind": "end", "tag": tag, "depth": self._relative_depth(pushed_nonvoid=True)},
            )
        self._open_tags.pop()

    def handle_data(self, data: str) -> None:
        self._note_event()
        self._note_card_callback()
        self._text_chars += len(data)
        if self._text_chars > MAX_TEXT_CHARS:
            raise GeminiTakeoutHtmlError("HTML exceeds text limit")
        if self._card is not None:
            self._card.text_chars += len(data)
            if self._card.text_chars > MAX_CARD_TEXT_CHARS:
                raise GeminiTakeoutHtmlError("activity card exceeds text limit")
            if self._card.active_cell is not None:
                self._card.active_cell.text_chars += len(data)
                if (
                    self._card.content_cells
                    and self._card.active_cell is self._card.content_cells[0]
                    and self._card.active_cell.text_chars > MAX_MAIN_TEXT_CHARS
                ):
                    raise GeminiTakeoutHtmlError("activity main cell exceeds text limit")
        segment = self._active_segment()
        if segment is None:
            if self._card is not None and data.strip():
                raise GeminiTakeoutHtmlError(
                    "activity card contains text outside its direct cells"
                )
            if self._page_grid_open and data.strip():
                raise GeminiTakeoutHtmlError(
                    "activity page grid contains non-whitespace text"
                )
            return
        self._bounded_event(
            segment,
            {"kind": "text", "value": data, "depth": self._relative_depth()},
        )

    def handle_comment(self, data: str) -> None:
        self._note_event()
        self._note_card_callback()
        self._text_chars += len(data)
        if self._text_chars > MAX_TEXT_CHARS:
            raise GeminiTakeoutHtmlError("HTML exceeds text limit")
        if self._card is not None:
            self._card.text_chars += len(data)
            if self._card.text_chars > MAX_CARD_TEXT_CHARS:
                raise GeminiTakeoutHtmlError("activity card exceeds text limit")
            if self._card.active_cell is not None:
                self._card.active_cell.text_chars += len(data)
                if (
                    self._card.content_cells
                    and self._card.active_cell is self._card.content_cells[0]
                    and self._card.active_cell.text_chars > MAX_MAIN_TEXT_CHARS
                ):
                    raise GeminiTakeoutHtmlError("activity main cell exceeds text limit")
        segment = self._active_segment()
        if segment is None:
            if self._card is not None:
                raise GeminiTakeoutHtmlError(
                    "activity card contains a comment outside its direct cells"
                )
            if self._page_grid_open:
                raise GeminiTakeoutHtmlError(
                    "activity page grid contains a comment"
                )
            return
        self._bounded_event(
            segment,
            {"kind": "comment", "value": data, "depth": self._relative_depth()},
        )

    def handle_decl(self, decl: str) -> None:
        self._note_event()
        self._note_card_callback()
        if self._card is not None:
            raise GeminiTakeoutHtmlError("activity card contains a declaration")
        if self._page_grid_open:
            raise GeminiTakeoutHtmlError("activity page grid contains a declaration")

    def unknown_decl(self, data: str) -> None:
        self._note_event()
        self._note_card_callback()
        if self._card is not None:
            raise GeminiTakeoutHtmlError("activity card contains an unknown declaration")
        if self._page_grid_open:
            raise GeminiTakeoutHtmlError(
                "activity page grid contains an unknown declaration"
            )

    def handle_pi(self, data: str) -> None:
        self._note_event()
        self._note_card_callback()
        if self._card is not None:
            raise GeminiTakeoutHtmlError(
                "activity card contains a processing instruction"
            )
        if self._page_grid_open:
            raise GeminiTakeoutHtmlError(
                "activity page grid contains a processing instruction"
            )

    def close(self) -> None:
        super().close()
        if self._card is not None:
            raise GeminiTakeoutHtmlError("truncated activity card")
        if self._div_depth != 0:
            raise GeminiTakeoutHtmlError("malformed or truncated HTML div structure")
        if self._open_tags:
            raise GeminiTakeoutHtmlError("malformed or truncated HTML tag structure")
        if self._page_grid_stack_depth is not None and (
            self._page_grid_open or not self._page_grid_closed
        ):
            raise GeminiTakeoutHtmlError("activity page grid is malformed")
        if not self.cards:
            raise GeminiTakeoutHtmlError("HTML contains no supported activity cards")

    @staticmethod
    def _validate_card(card: _Card) -> bool:
        if card.grid_count != 1:
            raise GeminiTakeoutHtmlError("activity card must contain one direct grid")
        if (
            card.grid_attributes is None
            or card.grid_stack_depth is None
            or card.grid_open
            or not card.grid_closed
        ):
            raise GeminiTakeoutHtmlError("activity card direct grid is malformed")
        if card.header is None:
            raise GeminiTakeoutHtmlError("activity card is missing its header")
        if len(card.content_cells) != 3:
            raise GeminiTakeoutHtmlError("activity card must contain three content cells")
        _validate_class_only_attributes(
            card.attributes, OUTER_CELL_CLASSES, context="activity outer cell"
        )
        _validate_class_only_attributes(
            card.grid_attributes, frozenset({"mdl-grid"}), context="activity grid"
        )
        _validate_class_only_attributes(
            card.header.attributes, HEADER_CELL_CLASSES, context="activity header"
        )
        expected_content_classes = (
            MAIN_CELL_CLASSES,
            RIGHT_CELL_CLASSES,
            CAPTION_CELL_CLASSES,
        )
        for index, (cell, expected) in enumerate(
            zip(card.content_cells, expected_content_classes)
        ):
            _validate_class_only_attributes(
                cell.attributes,
                expected,
                context=f"activity content cell {index}",
            )
        header_has_trailing_break = _validate_header(card.header.segment)
        _split_main(card.content_cells[0].segment)
        middle = card.content_cells[1]
        _validate_right_cell(middle.segment)
        segments = [card.header.segment, *(cell.segment for cell in card.content_cells)]
        scaffold_items = [
            {"kind": "scaffold_start", "tag": "div", "attributes": card.attributes},
            {"kind": "scaffold_start", "tag": "div", "attributes": card.grid_attributes},
            {"kind": "scaffold_start", "tag": "div", "attributes": card.header.attributes},
            *(
                {"kind": "scaffold_start", "tag": "div", "attributes": cell.attributes}
                for cell in card.content_cells
            ),
        ]
        start_tags = len(scaffold_items) + sum(
            event["kind"] == "start" for segment in segments for event in segment.events
        )
        references = sum(len(_references(segment, "card")) for segment in segments)
        max_depth = max(
            (event.get("depth", 0) for segment in segments for event in segment.events),
            default=0,
        )
        if start_tags > MAX_CARD_START_TAGS:
            raise GeminiTakeoutHtmlError("activity card exceeds start-tag limit")
        if references > MAX_CARD_REFERENCES:
            raise GeminiTakeoutHtmlError("activity card exceeds reference limit")
        if max_depth > MAX_CARD_RELATIVE_DEPTH:
            raise GeminiTakeoutHtmlError("activity card exceeds nesting limit")
        serialized_size = sum(_serialized_item_bytes(item) for item in scaffold_items)
        serialized_size += sum(
            _serialized_item_bytes(event)
            for segment in segments
            for event in segment.events
        )
        if serialized_size != card.serialized_bytes:
            raise GeminiTakeoutHtmlError("activity card size accounting mismatch")
        if serialized_size > MAX_CARD_SERIALIZED_BYTES:
            raise GeminiTakeoutHtmlError("activity card exceeds serialized-size limit")
        return header_has_trailing_break


def _append_boundary(parts: List[str], value: str) -> None:
    if not parts or parts[-1] != value:
        parts.append(value)


def _normalize_timestamp(value: str) -> Optional[str]:
    match = _TIMESTAMP_RE.fullmatch(value.strip())
    if match is None:
        return None
    month = _UKRAINIAN_MONTHS.get(match.group("month").casefold())
    if month is None:
        raise GeminiTakeoutHtmlError("activity timestamp uses unsupported localized month")
    try:
        parsed = datetime(
            int(match.group("year")),
            month,
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            tzinfo=timezone(timedelta(hours=3)),
        )
    except ValueError as err:
        raise GeminiTakeoutHtmlError("activity timestamp is out of range") from err
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _is_ignorable_whitespace(event: Dict[str, Any]) -> bool:
    return event["kind"] == "text" and not event["value"].strip()


def _split_main(segment: _Segment) -> _MainSplit:
    candidates: List[Tuple[int, int, str, str]] = []
    index = 0
    while index < len(segment.events):
        event = segment.events[index]
        if event["kind"] != "text" or event.get("depth") != 0:
            index += 1
            continue
        start = index
        fragments: List[str] = []
        while index < len(segment.events):
            current = segment.events[index]
            if current["kind"] != "text" or current.get("depth") != 0:
                break
            fragments.append(current["value"])
            index += 1
        raw_value = "".join(fragments)
        normalized = _normalize_timestamp(raw_value)
        if normalized is not None:
            candidates.append((start, index - 1, raw_value, normalized))
    if not candidates:
        raise GeminiTakeoutHtmlError("activity card is missing structural timestamp")
    if len(candidates) != 1:
        raise GeminiTakeoutHtmlError("activity card has duplicate structural timestamp")

    timestamp_start, timestamp_end, timestamp_raw, normalized_timestamp = candidates[0]
    previous = timestamp_start - 1
    while previous >= 0 and _is_ignorable_whitespace(segment.events[previous]):
        previous -= 1
    following = timestamp_end + 1
    while following < len(segment.events) and _is_ignorable_whitespace(segment.events[following]):
        following += 1
    if previous < 1 or following + 1 >= len(segment.events):
        raise GeminiTakeoutHtmlError("structural timestamp is not bracketed by direct BR nodes")
    previous_end = segment.events[previous]
    previous_start = segment.events[previous - 1]
    following_start = segment.events[following]
    following_end = segment.events[following + 1]
    if not (
        previous_start["kind"] == "start"
        and previous_end["kind"] == "end"
        and following_start["kind"] == "start"
        and following_end["kind"] == "end"
        and previous_start["tag"] == previous_end["tag"] == "br"
        and following_start["tag"] == following_end["tag"] == "br"
        and previous_start.get("depth") == previous_end.get("depth") == 0
        and following_start.get("depth") == following_end.get("depth") == 0
    ):
        raise GeminiTakeoutHtmlError("structural timestamp is not bracketed by direct BR nodes")

    prompt = _Segment(events=segment.events[: previous - 1])
    delimiter_before = _Segment(events=segment.events[previous - 1 : previous + 1])
    timestamp = _Segment(events=segment.events[previous + 1 : following])
    delimiter_after = _Segment(events=segment.events[following : following + 2])
    response = _Segment(events=segment.events[following + 2 :])
    reconstructed_events = [
        *prompt.events,
        *delimiter_before.events,
        *timestamp.events,
        *delimiter_after.events,
        *response.events,
    ]
    if reconstructed_events != segment.events:
        raise GeminiTakeoutHtmlError("activity main-cell partition lost structural events")
    main_chars = sum(len(value) for value in segment.text_fragments())
    prompt_chars = sum(len(value) for value in prompt.text_fragments())
    response_chars = sum(len(value) for value in response.text_fragments())
    if main_chars > MAX_MAIN_TEXT_CHARS:
        raise GeminiTakeoutHtmlError("activity main cell exceeds text limit")
    if prompt_chars > MAX_PROMPT_TEXT_CHARS:
        raise GeminiTakeoutHtmlError("activity prompt exceeds text limit")
    if response_chars > MAX_RESPONSE_TEXT_CHARS:
        raise GeminiTakeoutHtmlError("activity response exceeds text limit")
    return _MainSplit(
        prompt=prompt,
        delimiter_before=delimiter_before,
        timestamp=timestamp,
        delimiter_after=delimiter_after,
        response=response,
        timestamp_raw=timestamp_raw,
        normalized_timestamp=normalized_timestamp,
    )


def _validate_header(segment: _Segment) -> bool:
    coalesced: List[Dict[str, Any]] = []
    for event in segment.events:
        if (
            coalesced
            and event["kind"] == "text"
            and coalesced[-1]["kind"] == "text"
            and event.get("depth") == coalesced[-1].get("depth")
        ):
            coalesced[-1] = {
                **coalesced[-1],
                "value": coalesced[-1]["value"] + event["value"],
            }
        else:
            coalesced.append(event)
    significant = [event for event in coalesced if not _is_ignorable_whitespace(event)]
    if len(significant) == 3:
        start, text, end = significant
        has_trailing_break = False
    elif len(significant) == 5:
        start, text, trailing_start, trailing_end, end = significant
        has_trailing_break = True
        if not (
            trailing_start["kind"] == "start"
            and trailing_start.get("tag") == "br"
            and trailing_start.get("depth") == 1
            and trailing_start.get("attributes") == []
            and trailing_end["kind"] == "end"
            and trailing_end.get("tag") == "br"
            and trailing_end.get("depth") == 1
        ):
            raise GeminiTakeoutHtmlError("activity header markup contract mismatch")
    else:
        raise GeminiTakeoutHtmlError("activity header markup contract mismatch")
    if start["kind"] == "start" and start.get("tag") == "p":
        _validate_class_only_attributes(
            start.get("attributes", []),
            frozenset({"mdl-typography--title"}),
            context="activity header title",
        )
    if not (
        start["kind"] == "start"
        and start["tag"] == "p"
        and start.get("depth") == 0
        and text["kind"] == "text"
        and text.get("depth") == 1
        and text["value"].strip() in {"Додатки Gemini", "Gemini Apps"}
        and end["kind"] == "end"
        and end["tag"] == "p"
        and end.get("depth") == 0
    ):
        raise GeminiTakeoutHtmlError("activity header markup contract mismatch")
    return has_trailing_break


def _validate_right_cell(segment: _Segment) -> None:
    significant = [
        event for event in segment.events if not _is_ignorable_whitespace(event)
    ]
    if not significant:
        return
    if len(significant) != 4:
        raise GeminiTakeoutHtmlError(
            "activity card right content cell markup contract mismatch"
        )
    image_start, image_end, break_start, break_end = significant
    if not (
        image_start["kind"] == "start"
        and image_start.get("tag") == "img"
        and image_start.get("depth") == 0
        and image_end["kind"] == "end"
        and image_end.get("tag") == "img"
        and image_end.get("depth") == 0
        and break_start["kind"] == "start"
        and break_start.get("tag") == "br"
        and break_start.get("depth") == 0
        and break_start.get("attributes") == []
        and break_end["kind"] == "end"
        and break_end.get("tag") == "br"
        and break_end.get("depth") == 0
    ):
        raise GeminiTakeoutHtmlError(
            "activity card right content cell markup contract mismatch"
        )
    attributes = image_start.get("attributes", [])
    if (
        len(attributes) != 2
        or {item.get("name") for item in attributes} != {"src", "class"}
        or _class_tokens(attributes) != ["image-preview"]
    ):
        raise GeminiTakeoutHtmlError(
            "activity card right content cell markup contract mismatch"
        )
    source = next(item.get("value") for item in attributes if item.get("name") == "src")
    if not source:
        raise GeminiTakeoutHtmlError(
            "activity card right content cell markup contract mismatch"
        )
    try:
        parsed = urlsplit(source)
        decoded_path = unquote(parsed.path, errors="strict")
    except (TypeError, UnicodeDecodeError, ValueError):
        raise GeminiTakeoutHtmlError(
            "activity card right content cell contains an unsafe preview reference"
        ) from None
    lexical_parts = decoded_path.split("/")
    canonical_path = PurePosixPath(decoded_path)
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or "?" in source
        or "#" in source
        or source != source.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in source)
        or not decoded_path
        or decoded_path.startswith("/")
        or "\\" in decoded_path
        or "\x00" in decoded_path
        or "\ufffd" in decoded_path
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in decoded_path
        )
        or any(part in {"", ".", ".."} for part in lexical_parts)
        or re.fullmatch(r"[A-Za-z]:", lexical_parts[0]) is not None
        or canonical_path.as_posix() != decoded_path
    ):
        raise GeminiTakeoutHtmlError(
            "activity card right content cell contains an unsafe preview reference"
        )


def _render_text(segment: _Segment) -> str:
    parts: List[str] = []
    literal_depth = 0
    for event in segment.events:
        kind = event["kind"]
        if kind == "text":
            value = event["value"].replace("\r\n", "\n").replace("\r", "\n")
            if literal_depth == 0:
                value = re.sub(r"\s+", " ", value)
            parts.append(value)
            continue
        if kind == "comment":
            continue
        tag = event["tag"]
        if kind == "start":
            if tag in _BLOCK_TAGS:
                _append_boundary(parts, "\n")
            elif tag in {"td", "th"}:
                _append_boundary(parts, "\t")
            elif tag == "br":
                _append_boundary(parts, "\n")
            if tag in {"pre", "code"}:
                literal_depth += 1
        elif kind == "end":
            if tag in {"pre", "code"}:
                literal_depth = max(0, literal_depth - 1)
            if tag in _BLOCK_TAGS:
                _append_boundary(parts, "\n")
            elif tag in {"td", "th"}:
                _append_boundary(parts, "\t")
    value = "".join(parts)
    value = re.sub(r"[ \t]+\n", "\n", value)
    value = re.sub(r"\n[ \t]+", "\n", value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()


def _has_markup(segment: _Segment) -> bool:
    return any(event["kind"] != "text" for event in segment.events)


def _segment_record_kind(
    content: str, references: Sequence[Dict[str, Any]], segment: _Segment
) -> str:
    if content:
        return "text"
    if any(item.get("is_media") is True for item in references):
        return "media_only"
    if references:
        return "reference_only"
    if _has_markup(segment):
        return "markup_only"
    return "empty"


def _references(segment: _Segment, segment_name: str) -> List[Dict[str, Any]]:
    references: List[Dict[str, Any]] = []
    ordinal = 0
    for event in segment.events:
        if event["kind"] != "start":
            continue
        for attribute in event["attributes"]:
            if attribute["name"] not in _REFERENCE_ATTRIBUTES:
                continue
            value = attribute["value"]
            attribute_name = attribute["name"]
            scheme: Optional[str] = None
            reference_kind: str
            if value is None:
                reference_kind = "opaque_missing_value"
            elif attribute_name == "srcset":
                # ``srcset`` is a mini-language, not a URL.  Preserve it
                # opaquely rather than guessing at candidates or touching disk.
                reference_kind = "opaque_srcset"
            elif not value:
                reference_kind = "opaque_empty"
            else:
                try:
                    parsed = urlsplit(value)
                except ValueError:
                    reference_kind = "opaque_invalid_url"
                else:
                    scheme = parsed.scheme.casefold() or None
                    if parsed.scheme or parsed.netloc:
                        reference_kind = "external"
                    elif not parsed.path and parsed.fragment:
                        reference_kind = "document_fragment"
                    elif not parsed.path and parsed.query:
                        reference_kind = "document_query"
                    elif parsed.path:
                        reference_kind = "relative_file"
                    else:
                        reference_kind = "opaque_empty_url"
            is_relative = reference_kind == "relative_file"
            is_media = (
                event["tag"] in _MEDIA_REFERENCE_TAGS
                and attribute_name in {"src", "srcset", "poster"}
            )
            references.append(
                {
                    "tag": event["tag"],
                    "attribute": attribute_name,
                    "value": value,
                    "is_relative": is_relative,
                    "is_media": is_media,
                    "reference_kind": reference_kind,
                    "scheme": scheme,
                    "segment": segment_name,
                    "reference_ordinal": ordinal,
                }
            )
            ordinal += 1
    return references


def _replacement_count(segment: _Segment) -> int:
    count = 0
    for event in segment.events:
        if event["kind"] == "text":
            count += event["value"].count("\ufffd")
        elif event["kind"] == "comment":
            count += event["value"].count("\ufffd")
        elif event["kind"] == "start":
            count += sum(
                (attribute["value"] or "").count("\ufffd")
                for attribute in event["attributes"]
            )
    return count


def _with_reference_status(
    references: List[Dict[str, Any]],
    *,
    html_path: Path,
    staged_root: Path,
) -> List[Dict[str, Any]]:
    root = staged_root.resolve()
    enriched: List[Dict[str, Any]] = []
    for item in references:
        current = dict(item)
        if current["reference_kind"] != "relative_file":
            current["resolution_status"] = {
                "external": "external",
                "document_fragment": "document_fragment",
                "document_query": "document_query",
            }.get(current["reference_kind"], "opaque")
            enriched.append(current)
            continue
        try:
            parsed = urlsplit(current["value"])
            decoded_path = unquote(parsed.path)
            if "\\" in decoded_path:
                raise ValueError("backslash in relative reference")
            relative = Path(decoded_path)
            candidate = (html_path.parent / relative).resolve()
            if not candidate.is_relative_to(root):
                current["resolution_status"] = "unsafe"
            elif candidate.is_file():
                current["resolution_status"] = "exists"
            else:
                current["resolution_status"] = "missing"
        except (OSError, ValueError):
            current["resolution_status"] = "unsafe"
        if current["resolution_status"] == "unsafe":
            raise GeminiTakeoutHtmlError("activity card contains unsafe relative reference")
        enriched.append(current)
    return enriched


def _segment_payload(
    segment: _Segment,
    locator: str,
    *,
    references: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    return {
        "source_locator": locator,
        "text_sha256": sha256("".join(segment.text_fragments()).encode("utf-8")).hexdigest(),
        "events": segment.events,
        "references": references if references is not None else _references(segment, locator.rsplit("/", 1)[-1]),
        "replacement_character_count": _replacement_count(segment),
    }


def _identity(source_name: str, ordinal: int, content_digest: str) -> str:
    material = b"\0".join(
        (source_name.encode("utf-8"), str(ordinal).encode("ascii"), content_digest.encode("ascii"))
    )
    return sha256(material).hexdigest()


def parse_gemini_takeout_html(
    path: Path,
    *,
    source_name: str,
    staged_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """Parse one already-staged Takeout member into synthetic adapter records."""

    try:
        size = path.stat().st_size
    except OSError as err:
        raise GeminiTakeoutHtmlError("unable to stat Takeout HTML member") from err
    if size <= 0 or size > MAX_HTML_BYTES:
        raise GeminiTakeoutHtmlError("Takeout HTML member exceeds adapter size limit")

    digest = sha256()
    parser = _TakeoutParser()
    try:
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        bytes_read = 0
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                bytes_read += len(chunk)
                digest.update(chunk)
                parser.feed(decoder.decode(chunk))
        parser.feed(decoder.decode(b"", final=True))
        if bytes_read != size:
            raise GeminiTakeoutHtmlError("Takeout HTML member changed during parsing")
        parser.close()
    except UnicodeDecodeError as err:
        raise GeminiTakeoutHtmlError("Takeout HTML member is not strict UTF-8") from err
    except OSError as err:
        raise GeminiTakeoutHtmlError("unable to read Takeout HTML member") from err

    effective_root = (staged_root or path.parent).resolve()
    conversations: List[Dict[str, Any]] = []
    empty_slots: List[Dict[str, Any]] = []
    side_kind_counts = {
        "prompt": {kind: 0 for kind in ("text", "media_only", "reference_only", "markup_only")},
        "response": {kind: 0 for kind in ("text", "media_only", "reference_only", "markup_only")},
    }
    reference_count = 0
    message_reference_count = 0
    metadata_reference_count = 0
    relative_reference_count = 0
    message_relative_reference_count = 0
    metadata_relative_reference_count = 0
    local_image_reference_count = 0
    local_media_reference_count = 0
    external_reference_count = 0
    document_reference_count = 0
    opaque_reference_count = 0
    missing_relative_reference_count = 0
    existing_relative_reference_count = 0
    replacement_character_count = 0
    quarantined_card_count = 0

    def note_references(
        references: Sequence[Dict[str, Any]], *, channel: str
    ) -> None:
        nonlocal reference_count
        nonlocal message_reference_count
        nonlocal metadata_reference_count
        nonlocal relative_reference_count
        nonlocal message_relative_reference_count
        nonlocal metadata_relative_reference_count
        nonlocal local_image_reference_count
        nonlocal local_media_reference_count
        nonlocal external_reference_count
        nonlocal document_reference_count
        nonlocal opaque_reference_count
        nonlocal missing_relative_reference_count
        nonlocal existing_relative_reference_count
        reference_count += len(references)
        relative_count = sum(item["is_relative"] for item in references)
        relative_reference_count += relative_count
        if channel == "message":
            message_reference_count += len(references)
            message_relative_reference_count += relative_count
        elif channel == "metadata":
            metadata_reference_count += len(references)
            metadata_relative_reference_count += relative_count
        else:
            raise GeminiTakeoutHtmlError("internal reference-channel mismatch")
        missing_relative_reference_count += sum(
            item["resolution_status"] == "missing" for item in references
        )
        existing_relative_reference_count += sum(
            item["resolution_status"] == "exists" for item in references
        )
        local_image_reference_count += sum(
            item["is_relative"]
            and item["tag"] == "img"
            and item["attribute"] == "src"
            for item in references
        )
        local_media_reference_count += sum(
            item["is_relative"] and item["is_media"] for item in references
        )
        external_reference_count += sum(
            item["reference_kind"] == "external" for item in references
        )
        document_reference_count += sum(
            item["reference_kind"] in {"document_fragment", "document_query"}
            for item in references
        )
        opaque_reference_count += sum(
            item["reference_kind"].startswith("opaque_") for item in references
        )

    for card in parser.cards:
        main, middle, caption = card.content_cells
        main_split = _split_main(main.segment)
        prompt_segment = main_split.prompt
        timestamp_segment = main_split.timestamp
        response_segment = main_split.response
        timestamp_raw = main_split.timestamp_raw
        timestamp = main_split.normalized_timestamp
        card_locator = f"outer-cell[{card.ordinal}]"
        card_content_digest = sha256(
            json.dumps(
                {
                    "scaffold": {
                        "outer": card.attributes,
                        "grid": card.grid_attributes,
                        "header": card.header.attributes,
                        "content_cells": [
                            cell.attributes for cell in card.content_cells
                        ],
                    },
                    "header": card.header.segment.events,
                    "main": main.segment.events,
                    "right": middle.segment.events,
                    "caption": caption.segment.events,
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        identity = _identity(source_name, card.ordinal, card_content_digest)
        conversation_id = f"gemini-takeout-card-{identity}"
        prompt_id = f"{conversation_id}-prompt"
        response_id = f"{conversation_id}-response"
        prompt_text = _render_text(prompt_segment)
        response_text = _render_text(response_segment)
        card_replacements = sum(
            _replacement_count(segment)
            for segment in (card.header.segment, main.segment, middle.segment, caption.segment)
        )
        replacement_character_count += card_replacements
        quarantined = card_replacements > 0
        quarantined_card_count += int(quarantined)

        side_rows: List[Dict[str, Any]] = []
        for side, role, message_id, content, segment in (
            ("prompt", "user", prompt_id, prompt_text, prompt_segment),
            ("response", "assistant", response_id, response_text, response_segment),
        ):
            locator = f"{card_locator}/main/{side}"
            references = _with_reference_status(
                _references(segment, side),
                html_path=path,
                staged_root=effective_root,
            )
            record_kind = _segment_record_kind(content, references, segment)
            side_rows.append(
                {
                    "side": side,
                    "role": role,
                    "message_id": message_id,
                    "content": content,
                    "segment": segment,
                    "locator": locator,
                    "references": references,
                    "record_kind": record_kind,
                }
            )
            note_references(references, channel="message")

        auxiliary_segments = {
            "header": card.header.segment,
            "right": middle.segment,
            "caption": caption.segment,
            "timestamp": timestamp_segment,
            "timestamp_delimiter_before": main_split.delimiter_before,
            "timestamp_delimiter_after": main_split.delimiter_after,
        }
        auxiliary_references: Dict[str, List[Dict[str, Any]]] = {}
        for segment_name, segment in auxiliary_segments.items():
            references = _with_reference_status(
                _references(segment, segment_name),
                html_path=path,
                staged_root=effective_root,
            )
            auxiliary_references[segment_name] = references
            note_references(references, channel="metadata")

        prompt_emitted = side_rows[0]["record_kind"] != "empty"
        messages: List[Dict[str, Any]] = []
        for row in side_rows:
            side = row["side"]
            locator = row["locator"]
            record_kind = row["record_kind"]
            if record_kind == "empty":
                empty_slots.append(
                    {"source_reference": f"{source_name}#{locator}", "slot": side}
                )
                continue
            side_kind_counts[side][record_kind] += 1
            message: Dict[str, Any] = {
                "id": row["message_id"],
                "author": row["role"],
                "createdAt": timestamp,
                "timestamp": timestamp_raw.strip(),
                "content": row["content"],
                "content_type": (
                    f"google_takeout_activity_{side}_html_text"
                    if record_kind == "text"
                    else f"google_takeout_activity_{side}_{record_kind}"
                ),
                "takeout_html": _segment_payload(
                    row["segment"], locator, references=row["references"]
                ),
                "integrity_quarantine": quarantined,
                "__integrity_chronicle_source_provenance__": {
                    "source_file": source_name,
                    "source_reference": f"{source_name}#{locator}",
                    "card_ordinal": card.ordinal,
                    "segment": side,
                },
            }
            if side == "response" and prompt_emitted:
                message["parentId"] = prompt_id
            local_references = [
                item for item in row["references"] if item["reference_kind"] == "relative_file"
            ]
            if local_references:
                message["attachments"] = local_references
            messages.append(message)

        conversations.append(
            {
                "id": conversation_id,
                "createdAt": timestamp,
                "timestamp": timestamp_raw.strip(),
                "messages": messages,
                "takeout_html": {
                    "grouping": "one_activity_card",
                    "grouping_unavailable": True,
                    "content_digest": card_content_digest,
                    "integrity_quarantine": quarantined,
                    "card_ordinal": card.ordinal,
                    "scaffold": {
                        "outer": card.attributes,
                        "grid": card.grid_attributes,
                        "header": card.header.attributes,
                        "content_cells": [cell.attributes for cell in card.content_cells],
                    },
                    "header": _segment_payload(
                        card.header.segment,
                        f"{card_locator}/header",
                        references=auxiliary_references["header"],
                    ),
                    "right_cell": _segment_payload(
                        middle.segment,
                        f"{card_locator}/right",
                        references=auxiliary_references["right"],
                    ),
                    "caption": _segment_payload(
                        caption.segment,
                        f"{card_locator}/caption",
                        references=auxiliary_references["caption"],
                    ),
                    "timestamp": _segment_payload(
                        timestamp_segment,
                        f"{card_locator}/main/timestamp",
                        references=auxiliary_references["timestamp"],
                    ),
                    "timestamp_delimiters": {
                        "before": _segment_payload(
                            main_split.delimiter_before,
                            f"{card_locator}/main/timestamp-delimiter-before",
                            references=auxiliary_references[
                                "timestamp_delimiter_before"
                            ],
                        ),
                        "after": _segment_payload(
                            main_split.delimiter_after,
                            f"{card_locator}/main/timestamp-delimiter-after",
                            references=auxiliary_references[
                                "timestamp_delimiter_after"
                            ],
                        ),
                    },
                    "empty_slots": [item["slot"] for item in empty_slots if item["source_reference"].startswith(f"{source_name}#{card_locator}/")],
                },
                "__integrity_chronicle_source_provenance__": {
                    "source_file": source_name,
                    "source_reference": f"{source_name}#{card_locator}",
                    "card_ordinal": card.ordinal,
                },
            }
        )

    prompt_records = sum(side_kind_counts["prompt"].values())
    response_records = sum(side_kind_counts["response"].values())
    counts = {
        "source_cards": len(parser.cards),
        "prompt_records": prompt_records,
        "prompt_text_records": side_kind_counts["prompt"]["text"],
        "prompt_media_only_records": side_kind_counts["prompt"]["media_only"],
        "prompt_reference_only_records": side_kind_counts["prompt"]["reference_only"],
        "prompt_markup_only_records": side_kind_counts["prompt"]["markup_only"],
        "response_records": response_records,
        "response_text_records": side_kind_counts["response"]["text"],
        "response_media_only_records": side_kind_counts["response"]["media_only"],
        "response_reference_only_records": side_kind_counts["response"]["reference_only"],
        "response_markup_only_records": side_kind_counts["response"]["markup_only"],
        "canonical_messages": prompt_records + response_records,
        "empty_prompt_slots": sum(item["slot"] == "prompt" for item in empty_slots),
        "empty_response_slots": sum(item["slot"] == "response" for item in empty_slots),
        "reference_count": reference_count,
        "message_reference_count": message_reference_count,
        "metadata_reference_count": metadata_reference_count,
        "relative_reference_count": relative_reference_count,
        "message_relative_reference_count": message_relative_reference_count,
        "metadata_relative_reference_count": metadata_relative_reference_count,
        "local_image_reference_count": local_image_reference_count,
        "local_media_reference_count": local_media_reference_count,
        "external_reference_count": external_reference_count,
        "document_reference_count": document_reference_count,
        "opaque_reference_count": opaque_reference_count,
        "missing_relative_reference_count": missing_relative_reference_count,
        "existing_relative_reference_count": existing_relative_reference_count,
        "replacement_character_count": replacement_character_count,
        "quarantined_card_count": quarantined_card_count,
    }
    if frozenset(counts) != TAKEOUT_HTML_COUNT_FIELDS:
        raise GeminiTakeoutHtmlError("internal Takeout coverage schema mismatch")
    if len(conversations) != counts["source_cards"]:
        raise GeminiTakeoutHtmlError("Takeout card coverage mismatch")
    if sum(len(item["messages"]) for item in conversations) != counts["canonical_messages"]:
        raise GeminiTakeoutHtmlError("Takeout message coverage mismatch")
    return {
        "schema_version": TAKEOUT_HTML_SCHEMA_VERSION,
        "adapter_origin": TAKEOUT_HTML_ADAPTER_ORIGIN,
        "conversations": conversations,
        "source_shape": "google-takeout-myactivity-html",
        "source_file_sha256": digest.hexdigest(),
        "source_file_bytes": size,
        "takeout_html_counts": counts,
        "empty_slots": empty_slots,
        "grouping_unavailable": True,
        "decode_status": (
            "valid_utf8_with_literal_replacement_characters"
            if replacement_character_count
            else "valid_utf8"
        ),
    }
