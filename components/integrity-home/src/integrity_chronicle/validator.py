"""Hostile-archive validation utilities used by dry-run import."""

from __future__ import annotations

import contextlib
from dataclasses import asdict, dataclass, field
from pathlib import PurePosixPath
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence
import hashlib
import json
import posixpath
import shutil
import stat
import zipfile
import datetime

from .runtime_paths import state_path


MAX_MEMBER_COUNT = 25_000
MAX_TOTAL_UNCOMPRESSED_BYTES = 5 * 1024**3
MAX_MEMBER_SIZE_BYTES = 150 * 1024**2
MAX_COMPRESSION_RATIO = 120.0


def _as_iso8601_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    path: str
    detail: str
    severity: str = "error"


@dataclass(frozen=True)
class MemberStats:
    name: str
    uncompressed_size: int
    compressed_size: int
    compression_method: str
    is_directory: bool
    is_encrypted: bool

    @property
    def compression_ratio(self) -> float:
        if self.compressed_size == 0:
            return float("inf") if self.uncompressed_size else 0.0
        return self.uncompressed_size / self.compressed_size


@dataclass
class ArchiveValidationReport:
    archive_path: str
    members_scanned: int
    member_counts: Dict[str, int]
    total_uncompressed_bytes: int
    total_compressed_bytes: int
    max_member_size_bytes: int
    max_total_uncompressed_bytes: int
    max_member_count: int
    max_compression_ratio: float
    issues: List[ValidationIssue] = field(default_factory=list)
    members: List[MemberStats] = field(default_factory=list)
    provider_guess: str = "unknown"

    @property
    def valid(self) -> bool:
        return all(issue.severity != "error" for issue in self.issues)

    @property
    def issue_count(self) -> int:
        return len(self.issues)

    def to_dict(self) -> Dict:
        payload = {
            "archive_path": self.archive_path,
            "provider_guess": self.provider_guess,
            "members_scanned": self.members_scanned,
            "member_counts": self.member_counts,
            "totals": {
                "uncompressed_bytes": self.total_uncompressed_bytes,
                "compressed_bytes": self.total_compressed_bytes,
                "max_member_size_bytes": self.max_member_size_bytes,
                "max_total_uncompressed_bytes": self.max_total_uncompressed_bytes,
                "max_member_count": self.max_member_count,
                "max_compression_ratio": self.max_compression_ratio,
            },
            "valid": self.valid,
            "issues": [asdict(issue) for issue in self.issues],
            "members": [asdict(member) for member in self.members],
        }
        return payload


@dataclass(frozen=True)
class StagedArchiveWorkspace:
    path: str
    extracted_files: List[str]
    extracted_bytes: int


def _default_staging_root() -> Path:
    return state_path("vault", "tmp")


def _coerce_staging_root(staging_root: Optional[str]) -> Path:
    if staging_root is None:
        return _default_staging_root()
    return Path(staging_root)


def _ensure_staging_parent(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)


@contextlib.contextmanager
def staged_archive_extraction(
    archive_path: str,
    *,
    staging_root: Optional[str] = None,
    max_member_count: int = MAX_MEMBER_COUNT,
    max_member_size_bytes: int = MAX_MEMBER_SIZE_BYTES,
    max_total_uncompressed_bytes: int = MAX_TOTAL_UNCOMPRESSED_BYTES,
    max_compression_ratio: float = MAX_COMPRESSION_RATIO,
) -> Iterator[StagedArchiveWorkspace]:
    report = validate_archive(
        archive_path,
        max_member_count=max_member_count,
        max_member_size_bytes=max_member_size_bytes,
        max_total_uncompressed_bytes=max_total_uncompressed_bytes,
        max_compression_ratio=max_compression_ratio,
    )
    if not report.valid:
        raise RuntimeError("archive failed validation, refusing extraction")

    digest = _sha256_file(archive_path)
    staging_base = _coerce_staging_root(staging_root)
    staging_path = staging_base / digest[:24]
    _ensure_staging_parent(staging_base)
    staging_path.mkdir(parents=True, exist_ok=False)

    extracted: List[str] = []
    extracted_bytes = 0

    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            infos = sorted(zf.infolist(), key=lambda item: item.filename)
            for info in infos:
                if info.is_dir():
                    continue
                if _is_traversal_path(info.filename):
                    raise RuntimeError(f"member path is unsafe: {info.filename}")
                if _is_unsupported_compression(info.compress_type):
                    raise RuntimeError(
                        f"unsupported compression in archive member: {info.filename}"
                    )
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise RuntimeError(f"member is symlink entry: {info.filename}")

                member_output = staging_path / info.filename
                member_output.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as source:
                    bytes_written = 0
                    with open(member_output, "wb") as destination:
                        for chunk in iter(lambda: source.read(1 << 20), b""):
                            bytes_written += len(chunk)
                            if bytes_written > max_member_size_bytes:
                                raise RuntimeError(
                                    f"member exceeds max size while extracting: {info.filename}"
                                )
                            if bytes_written > info.file_size:
                                raise RuntimeError(
                                    f"member expanded beyond declared size: {info.filename}"
                                )
                            destination.write(chunk)

                if bytes_written != info.file_size:
                    raise RuntimeError(
                        f"member expanded to unexpected size: {info.filename} expected "
                        f"{info.file_size} got {bytes_written}"
                    )

                extracted_bytes += bytes_written
                if extracted_bytes > max_total_uncompressed_bytes:
                    raise RuntimeError("archive total uncompressed bytes exceeds limit during extraction")

                extracted.append(info.filename)

        yield StagedArchiveWorkspace(
            path=str(staging_path.resolve()),
            extracted_files=extracted,
            extracted_bytes=extracted_bytes,
        )
    finally:
        shutil.rmtree(staging_path, ignore_errors=True)


def _safe_archive_path(path: str) -> str:
    normal = posixpath.normpath(path)
    return normal.removeprefix("./")


def _is_traversal_path(name: str) -> bool:
    if not name:
        return True
    if name.startswith(("/", "\\")):
        return True
    if "\\" in name:
        return True
    if name.startswith("../") or name.startswith("..\\"):
        return True
    parts = PurePosixPath(name).parts
    if any(part == ".." for part in parts):
        return True
    normalized = posixpath.normpath(name)
    if normalized == ".." or normalized.startswith("../"):
        return True
    return False


def _provider_from_names(names: Sequence[str]) -> str:
    marker_counts = {
        "openai_chatgpt": 0,
        "anthropic_claude": 0,
        "google_gemini": 0,
    }
    lower_names = {name.lower() for name in names}
    if any("chat.html" in name for name in lower_names):
        marker_counts["openai_chatgpt"] += 1
    if any("message_feedback.json" in name for name in lower_names):
        marker_counts["openai_chatgpt"] += 1
    if any("user.json" in name for name in lower_names):
        marker_counts["openai_chatgpt"] += 1
    if any(name.endswith("conversations.json") for name in lower_names):
        marker_counts["anthropic_claude"] += 1
    if any(name.endswith("users.json") for name in lower_names):
        marker_counts["anthropic_claude"] += 1
    if any(name.endswith("memories.json") for name in lower_names):
        marker_counts["anthropic_claude"] += 1
    if any("gemini_export.json" in name for name in lower_names):
        marker_counts["google_gemini"] += 1
    if any("gemini_conversations.json" in name for name in lower_names):
        marker_counts["google_gemini"] += 1
    if any("bard_export.json" in name for name in lower_names):
        marker_counts["google_gemini"] += 1
    gemini_takeout_tails = (
        "my activity/gemini apps/myactivity.html",
        "мої дії/додатки gemini/myactivity.html",
    )
    if any(
        name == tail or name.endswith(f"/{tail}")
        for name in lower_names
        for tail in gemini_takeout_tails
    ):
        marker_counts["google_gemini"] += 1

    matched = [provider for provider, count in marker_counts.items() if count]
    if len(matched) > 1:
        return "ambiguous"
    if matched:
        return matched[0]
    return "unknown"


def _validate_member(info: zipfile.ZipInfo, issue: List[ValidationIssue], seen_names: Dict[str, int]) -> Optional[MemberStats]:
    stats = MemberStats(
        name=info.filename,
        uncompressed_size=info.file_size,
        compressed_size=info.compress_size,
        compression_method=str(info.compress_type),
        is_directory=info.is_dir(),
        is_encrypted=bool(info.flag_bits & 0x1),
    )
    seen = seen_names.get(info.filename, 0)
    seen_names[info.filename] = seen + 1
    if seen > 0:
        issue.append(
            ValidationIssue(
                code="duplicate_member_path",
                path=info.filename,
                detail=f"duplicate zip member name observed {seen + 1} times",
            )
        )
    if _is_traversal_path(info.filename):
        issue.append(
            ValidationIssue(
                code="traversal_or_absolute_path",
                path=info.filename,
                detail="member path is absolute, uses backslashes, or traverses parent directories",
            )
        )
    if _is_unsupported_compression(info.compress_type):
        issue.append(
            ValidationIssue(
                code="unsupported_compression",
                path=info.filename,
                detail=f"unsupported compression method {info.compress_type}",
            )
        )
    if stats.is_encrypted:
        issue.append(
            ValidationIssue(
                code="encrypted_member",
                path=info.filename,
                detail="zip member has unsupported encryption flag",
            )
        )
    mode = (info.external_attr >> 16) & 0xFFFF
    if stat.S_ISLNK(mode):
        issue.append(
            ValidationIssue(
                code="symlink_entry",
                path=info.filename,
                detail="zip member encodes symbolic link mode",
            )
        )
    return stats


def _is_unsupported_compression(compression_type: int) -> bool:
    return compression_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)


def validate_archive(
    archive_path: str,
    max_member_count: int = MAX_MEMBER_COUNT,
    max_member_size_bytes: int = MAX_MEMBER_SIZE_BYTES,
    max_total_uncompressed_bytes: int = MAX_TOTAL_UNCOMPRESSED_BYTES,
    max_compression_ratio: float = MAX_COMPRESSION_RATIO,
) -> ArchiveValidationReport:
    issues: List[ValidationIssue] = []
    member_stats: List[MemberStats] = []
    member_counts: Dict[str, int] = {
        "directories": 0,
        "files": 0,
    }
    seen_names: Dict[str, int] = {}

    total_uncompressed = 0
    total_compressed = 0

    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            infos = zf.infolist()
    except (OSError, zipfile.BadZipFile) as err:
        raise RuntimeError(f"cannot read archive: {err}") from err

    if len(infos) > max_member_count:
        issues.append(
            ValidationIssue(
                code="member_count_exceeded",
                path="__archive__",
                detail=f"archive has {len(infos)} members, above limit {max_member_count}",
            )
        )
    for info in infos:
        m = _validate_member(info, issues, seen_names)
        if m is None:
            continue
        if m.is_directory:
            member_counts["directories"] += 1
        else:
            member_counts["files"] += 1
            total_uncompressed += m.uncompressed_size
            total_compressed += m.compressed_size
            if m.uncompressed_size > max_member_size_bytes:
                issues.append(
                    ValidationIssue(
                        code="member_size_exceeded",
                        path=info.filename,
                        detail=(
                            f"member uncompressed size {m.uncompressed_size} exceeds max "
                            f"{max_member_size_bytes}"
                        ),
                    )
                )
            ratio = m.compression_ratio
            if ratio > max_compression_ratio:
                issues.append(
                    ValidationIssue(
                        code="compression_ratio_exceeded",
                        path=info.filename,
                        detail=(
                            f"compression ratio {ratio:.2f} exceeds limit {max_compression_ratio}"
                        ),
                    )
                )
            member_stats.append(m)
    if total_uncompressed > max_total_uncompressed_bytes:
        issues.append(
            ValidationIssue(
                code="total_uncompressed_exceeded",
                path="__archive__",
                detail=(
                    f"total uncompressed bytes {total_uncompressed} exceeds "
                    f"limit {max_total_uncompressed_bytes}"
                ),
            )
        )

    provider_guess = _provider_from_names([info.filename for info in infos])
    return ArchiveValidationReport(
        archive_path=_safe_archive_path(archive_path),
        members_scanned=len(infos),
        member_counts=member_counts,
        total_uncompressed_bytes=total_uncompressed,
        total_compressed_bytes=total_compressed,
        max_member_size_bytes=max_member_size_bytes,
        max_total_uncompressed_bytes=max_total_uncompressed_bytes,
        max_member_count=max_member_count,
        max_compression_ratio=max_compression_ratio,
        issues=issues,
        members=member_stats,
        provider_guess=provider_guess,
    )


def write_dry_run_manifest(
    report: ArchiveValidationReport,
    archive_path: str,
    *,
    source_id: Optional[str] = None,
) -> Dict:
    digest = _sha256_file(archive_path)
    manifest_source_id = source_id or digest[:24]
    manifest = {
        "schema_version": 1,
        "product": "Integrity Chronicle",
        "processing_state": "dry_run_validated",
        "validated_utc": _as_iso8601_utc(),
        "content_inspected": False,
        "content_extracted": False,
        "model_egress": False,
        "privacy_class": "highly_sensitive_personal_archive",
        "source_id": manifest_source_id,
        "source_sha256": digest,
        "source_size_bytes": Path(archive_path).stat().st_size,
        "archives": [
            {
                "provider": report.provider_guess,
                "original_filename": archive_path,
                "stored_path": archive_path,
                "size_bytes": Path(archive_path).stat().st_size,
                "entry_count": report.members_scanned,
                "identity_method": "zip_member_names_only",
                "zip_validation": report.to_dict(),
            },
        ],
    }
    return manifest


def serialize_manifest(report: ArchiveValidationReport, archive_path: str) -> str:
    payload = write_dry_run_manifest(report, archive_path)
    return json.dumps(payload, sort_keys=True, indent=2)


def write_manifest_file(report: ArchiveValidationReport, archive_path: str, manifest_path: str) -> str:
    data = serialize_manifest(report, archive_path)
    with open(manifest_path, "w", encoding="utf-8") as fp:
        fp.write(data + "\n")
    return manifest_path


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()
