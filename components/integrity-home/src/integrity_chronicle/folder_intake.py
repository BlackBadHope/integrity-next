"""Atomic, content-free intake of a folder containing provider export ZIPs."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Dict, List

from .corpus_index import (
    build_corpus_index,
    inspect_corpus_index,
    resolve_corpus_deletion_ledger_path,
)
from .ingest import build_semantic_extractor, parse_staged_archive, write_canonical_manifest
from .json_integrity import load_json_strict
from .validator import (
    MAX_COMPRESSION_RATIO,
    MAX_MEMBER_COUNT,
    MAX_MEMBER_SIZE_BYTES,
    MAX_TOTAL_UNCOMPRESSED_BYTES,
    staged_archive_extraction,
    validate_archive,
)

FOLDER_RECEIPT_SCHEMA = "integrity-home-folder-intake/4"
DEFAULT_MAX_ARCHIVES = 64
DEFAULT_MAX_ARCHIVE_BYTES = 20 * 1024 * 1024 * 1024


class FolderIntakeError(RuntimeError):
    """The batch is unsafe or cannot be published as one generation."""

    def __init__(self, message: str, *, report: Dict[str, Any] | None = None):
        super().__init__(message)
        self.report = report


def _failure_report(
    *, archive_input_count: int, duplicate_archive_count: int,
    validated_source_count: int, rejected_source_count: int,
) -> Dict[str, Any]:
    unique_count = archive_input_count - duplicate_archive_count
    return {
        "schema_version": "integrity-home-folder-intake-failure/1",
        "accepted_archive_count": 0,
        "archive_input_count": archive_input_count,
        "duplicate_archive_count": duplicate_archive_count,
        "rejected_archive_count": rejected_source_count,
        "validated_source_count": validated_source_count,
        "unprocessed_source_count": max(
            0, unique_count - validated_source_count - rejected_source_count
        ),
        "generation_published": False,
    }


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_link_or_reparse(path: Path) -> bool:
    try:
        return path.is_symlink() or bool(
            getattr(path.lstat(), "st_file_attributes", 0) & 0x400
        )
    except OSError:
        return True


def discover_archives(folder: str) -> List[Path]:
    root = Path(folder)
    if not root.is_dir() or root.is_symlink():
        raise FolderIntakeError("input folder must be a real directory")
    found: List[Path] = []
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda item: item.name.casefold())
        except OSError as err:
            raise FolderIntakeError(f"cannot scan input folder: {err}") from err
        for entry in entries:
            if _is_link_or_reparse(Path(entry.path)):
                raise FolderIntakeError("directory links and reparse points are not allowed")
            if entry.is_dir(follow_symlinks=False):
                pending.append(Path(entry.path))
            elif entry.is_file(follow_symlinks=False) and entry.name.casefold().endswith(".zip"):
                found.append(Path(entry.path))
    return sorted(found, key=lambda path: path.relative_to(root).as_posix().casefold())


def import_archive_folder(
    folder: str,
    output: str,
    *,
    max_archives: int = DEFAULT_MAX_ARCHIVES,
    max_archive_bytes: int = DEFAULT_MAX_ARCHIVE_BYTES,
    max_member_count: int = MAX_MEMBER_COUNT,
    max_member_size_bytes: int = MAX_MEMBER_SIZE_BYTES,
    max_total_uncompressed_bytes: int = MAX_TOTAL_UNCOMPRESSED_BYTES,
    max_compression_ratio: float = MAX_COMPRESSION_RATIO,
    semantic_backend: str = "fake",
    base_generation: str | None = None,
) -> Dict[str, Any]:
    archives = discover_archives(folder)
    if not archives:
        raise FolderIntakeError("input folder contains no ZIP archives")
    if len(archives) > max_archives:
        raise FolderIntakeError("archive count exceeds batch limit")
    total_bytes = sum(path.stat().st_size for path in archives)
    if total_bytes > max_archive_bytes:
        raise FolderIntakeError("archive bytes exceed batch limit")

    target = Path(output).resolve()
    if target.exists():
        raise FolderIntakeError("output generation already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{target.name}.intake-", dir=target.parent))
    try:
        base_receipt: Dict[str, Any] | None = None
        base_root: Path | None = None
        prior_by_digest: Dict[str, Dict[str, Any]] = {}
        if base_generation is not None:
            base_root = Path(base_generation).resolve()
            refresh_archive_generation_receipt(str(base_root))
            base_receipt = _load_object(
                base_root / "folder-intake.receipt.json", "base intake receipt"
            )
            prior_by_digest = {
                record["archive_sha256"]: dict(record)
                for record in base_receipt["archives"]
            }
        by_digest: Dict[str, List[Path]] = {}
        for archive in archives:
            by_digest.setdefault(_file_sha256(archive), []).append(archive)
        batch_new_unique_count = sum(
            1 for digest in by_digest if digest not in prior_by_digest
        )
        batch_duplicate_count = len(archives) - batch_new_unique_count
        extractor = build_semantic_extractor(semantic_backend)
        projections: List[Dict[str, Any]] = []
        archive_receipts: List[Dict[str, Any]] = []
        canonical_root = stage / "canonical"
        canonical_root.mkdir()
        if base_root is not None:
            for canonical in sorted((base_root / "canonical").iterdir()):
                shutil.copyfile(canonical, canonical_root / canonical.name)
                projections.append(_load_object(canonical, "base canonical projection"))
        extraction_root = stage / ".extract"
        validated_source_count = 0
        for digest in sorted(by_digest):
            if digest in prior_by_digest:
                continue
            archive = by_digest[digest][0]
            try:
                report = validate_archive(
                    str(archive), max_member_count=max_member_count,
                    max_member_size_bytes=max_member_size_bytes,
                    max_total_uncompressed_bytes=max_total_uncompressed_bytes,
                    max_compression_ratio=max_compression_ratio,
                )
            except Exception as err:
                raise FolderIntakeError(
                    "archive validation failed",
                    report=_failure_report(
                        archive_input_count=len(archives),
                        duplicate_archive_count=batch_duplicate_count,
                        validated_source_count=validated_source_count,
                        rejected_source_count=1,
                    ),
                ) from err
            if not report.valid:
                raise FolderIntakeError(
                    "archive failed validation",
                    report=_failure_report(
                        archive_input_count=len(archives),
                        duplicate_archive_count=batch_duplicate_count,
                        validated_source_count=validated_source_count,
                        rejected_source_count=1,
                    ),
                )
            try:
                with staged_archive_extraction(
                    str(archive), staging_root=str(extraction_root),
                    max_member_count=max_member_count,
                    max_member_size_bytes=max_member_size_bytes,
                    max_total_uncompressed_bytes=max_total_uncompressed_bytes,
                    max_compression_ratio=max_compression_ratio,
                ) as workspace:
                    projection = parse_staged_archive(workspace.path, semantic_extractor=extractor)
            except Exception as err:
                raise FolderIntakeError(
                    "archive parsing failed",
                    report=_failure_report(
                        archive_input_count=len(archives),
                        duplicate_archive_count=batch_duplicate_count,
                        validated_source_count=validated_source_count,
                        rejected_source_count=1,
                    ),
                ) from err
            validated_source_count += 1
            projections.append(projection)
            canonical_path = canonical_root / f"{projection['source_id']}.json"
            write_canonical_manifest(projection, str(canonical_path))
            archive_receipts.append({
                "archive_sha256": digest,
                "alias_count": len(by_digest[digest]),
                "provider": projection["provider"],
                "source_id": projection["source_id"],
                "conversation_count": projection.get("conversation_count", 0),
                "message_count": projection.get("message_count", 0),
                "projection_sha256": projection.get("projection_sha256"),
            })
        shutil.rmtree(extraction_root, ignore_errors=True)
        corpus_path = stage / "corpus.sqlite"
        if base_root is not None:
            base_corpus = base_root / "corpus.sqlite"
            shutil.copyfile(base_corpus, corpus_path)
            base_ledger = Path(resolve_corpus_deletion_ledger_path(str(base_corpus)))
            shutil.copyfile(
                base_ledger, Path(resolve_corpus_deletion_ledger_path(str(corpus_path)))
            )
        corpus_receipt = (
            build_corpus_index(projections, str(corpus_path))
            if projections else inspect_corpus_index(str(corpus_path))
        )
        ledger_path = Path(resolve_corpus_deletion_ledger_path(str(corpus_path)))
        all_archive_receipts = sorted(
            [*prior_by_digest.values(), *archive_receipts],
            key=lambda record: record["archive_sha256"],
        )
        accepted_count = len(archive_receipts)
        artifact_paths = [corpus_path, ledger_path, *sorted(canonical_root.iterdir())]
        receipt = {
            "schema_version": FOLDER_RECEIPT_SCHEMA,
            "archive_input_count": len(archives),
            "accepted_archive_count": accepted_count,
            "rejected_archive_count": 0,
            "unique_archive_count": accepted_count,
            "duplicate_archive_count": len(archives) - accepted_count,
            "base_source_count": len(prior_by_digest),
            "source_count": len(all_archive_receipts),
            "archives": all_archive_receipts,
            "corpus": corpus_receipt,
            "artifacts": [
                {
                    "path": path.relative_to(stage).as_posix(),
                    "size_bytes": path.stat().st_size,
                    "sha256": _file_sha256(path),
                }
                for path in artifact_paths
            ],
        }
        (stage / "folder-intake.receipt.json").write_text(
            json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        os.replace(stage, target)
        return receipt
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def _load_object(path: Path, label: str) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as stream:
            payload = load_json_strict(stream)
    except (OSError, ValueError, json.JSONDecodeError) as err:
        raise FolderIntakeError(f"invalid {label}") from err
    if not isinstance(payload, dict):
        raise FolderIntakeError(f"invalid {label}")
    return payload


def verify_archive_generation(output: str) -> Dict[str, Any]:
    """Verify one published folder-intake generation without returning paths."""

    root = Path(output)
    if not root.is_dir() or root.is_symlink():
        raise FolderIntakeError("generation must be a real directory")
    receipt = _load_object(root / "folder-intake.receipt.json", "intake receipt")
    if set(receipt) != {
        "schema_version", "archive_input_count", "accepted_archive_count",
        "rejected_archive_count", "unique_archive_count",
        "duplicate_archive_count", "base_source_count", "source_count",
        "archives", "corpus", "artifacts",
    } or receipt.get("schema_version") != FOLDER_RECEIPT_SCHEMA:
        raise FolderIntakeError("invalid intake receipt schema")
    counts = {
        field: receipt.get(field)
        for field in (
            "archive_input_count", "accepted_archive_count",
            "rejected_archive_count", "unique_archive_count",
            "duplicate_archive_count",
            "base_source_count", "source_count",
        )
    }
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts.values()):
        raise FolderIntakeError("invalid intake receipt counts")
    if (
        counts["accepted_archive_count"] != counts["unique_archive_count"]
        or counts["rejected_archive_count"] != 0
        or counts["archive_input_count"]
        != counts["unique_archive_count"] + counts["duplicate_archive_count"]
        or counts["source_count"]
        != counts["base_source_count"] + counts["accepted_archive_count"]
    ):
        raise FolderIntakeError("inconsistent intake receipt counts")
    archives = receipt.get("archives")
    if not isinstance(archives, list) or len(archives) != counts["source_count"]:
        raise FolderIntakeError("invalid intake archive records")
    expected_sources: Dict[str, Dict[str, Any]] = {}
    previous_digest = ""
    for index, record in enumerate(archives):
        if not isinstance(record, dict) or set(record) != {
            "archive_sha256", "alias_count", "provider", "source_id",
            "conversation_count", "message_count", "projection_sha256",
        }:
            raise FolderIntakeError(f"invalid intake archive record {index}")
        digest = record.get("archive_sha256")
        source_id = record.get("source_id")
        if (
            not isinstance(digest, str) or len(digest) != 64
            or digest != digest.lower() or source_id != digest[:24]
            or digest <= previous_digest or source_id in expected_sources
        ):
            raise FolderIntakeError(f"invalid intake archive identity {index}")
        try:
            int(digest, 16)
        except ValueError as err:
            raise FolderIntakeError(f"invalid intake archive digest {index}") from err
        previous_digest = digest
        expected_sources[source_id] = record
    canonical_root = root / "canonical"
    if not canonical_root.is_dir() or canonical_root.is_symlink():
        raise FolderIntakeError("generation canonical directory is missing")
    canonical_files = sorted(canonical_root.iterdir(), key=lambda path: path.name)
    if any(path.is_symlink() or not path.is_file() for path in canonical_files):
        raise FolderIntakeError("generation canonical directory has invalid entries")
    if {path.name for path in canonical_files} != {f"{source_id}.json" for source_id in expected_sources}:
        raise FolderIntakeError("generation canonical source set mismatch")
    for path in canonical_files:
        projection = _load_object(path, "canonical projection")
        source_id = path.stem
        record = expected_sources[source_id]
        for field in ("source_id", "provider", "conversation_count", "message_count", "projection_sha256"):
            if projection.get(field) != record.get(field):
                raise FolderIntakeError(f"canonical projection mismatch: {field}")
    corpus_path = root / "corpus.sqlite"
    live_corpus = inspect_corpus_index(str(corpus_path))
    if receipt.get("corpus") != live_corpus:
        raise FolderIntakeError("corpus summary mismatch")
    ledger_path = Path(resolve_corpus_deletion_ledger_path(str(corpus_path))).resolve()
    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, list):
        raise FolderIntakeError("invalid generation artifact records")
    expected_artifact_paths = {
        "corpus.sqlite", ledger_path.name,
        *[f"canonical/{source_id}.json" for source_id in expected_sources],
    }
    seen_artifacts: set[str] = set()
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict) or set(artifact) != {"path", "size_bytes", "sha256"}:
            raise FolderIntakeError(f"invalid generation artifact record {index}")
        relative = artifact.get("path")
        if not isinstance(relative, str) or relative in seen_artifacts or relative not in expected_artifact_paths:
            raise FolderIntakeError(f"invalid generation artifact path {index}")
        seen_artifacts.add(relative)
        path = root.joinpath(*relative.split("/"))
        if (
            not path.is_file() or path.is_symlink()
            or artifact.get("size_bytes") != path.stat().st_size
            or artifact.get("sha256") != _file_sha256(path)
        ):
            raise FolderIntakeError(f"generation artifact digest mismatch: {relative}")
    if seen_artifacts != expected_artifact_paths:
        raise FolderIntakeError("generation artifact set mismatch")
    allowed = {
        "folder-intake.receipt.json", "corpus.sqlite",
        # The Home common-generation publisher adds this derived, separately
        # sealed projection after the archive generation itself is verified.
        "history.sqlite",
        "history.sqlite.state.lock",
        "corpus.sqlite.state.lock",
        ledger_path.name if ledger_path.parent == root.resolve() else "",
        f"{ledger_path.name}.state.lock" if ledger_path.parent == root.resolve() else "",
    }
    root_files = {path.name for path in root.iterdir() if path.is_file()}
    required = {value for value in allowed if value} - {
        "history.sqlite", "history.sqlite.state.lock",
    }
    if (
        not required.issubset(root_files)
        or not root_files.issubset({value for value in allowed if value})
    ):
        raise FolderIntakeError("generation contains unexpected files")
    root_directories = {path.name for path in root.iterdir() if path.is_dir()}
    if root_directories != {"canonical"}:
        raise FolderIntakeError("generation contains unexpected directories")
    if any(_is_link_or_reparse(path) for path in root.rglob("*")):
        raise FolderIntakeError("generation contains links or reparse points")
    if any(path.suffix.casefold() == ".zip" for path in root.rglob("*")):
        raise FolderIntakeError("generation must not retain raw archives")
    return {
        "schema_version": FOLDER_RECEIPT_SCHEMA,
        "valid": True,
        "archive_input_count": counts["archive_input_count"],
        "accepted_archive_count": counts["accepted_archive_count"],
        "base_source_count": counts["base_source_count"],
        "source_count": counts["source_count"],
        "duplicate_archive_count": counts["duplicate_archive_count"],
        "rejected_archive_count": counts["rejected_archive_count"],
        "provider_count": len({record["provider"] for record in archives}),
        "corpus_id": live_corpus["corpus_id"],
        "index_generation": live_corpus["index_generation"],
        "conversation_count": live_corpus["conversation_count"],
        "message_count": live_corpus["message_count"],
    }


def refresh_archive_generation_receipt(output: str) -> Dict[str, Any]:
    """Refresh mutable corpus evidence after a verified local forget operation."""

    root = Path(output)
    receipt_path = root / "folder-intake.receipt.json"
    previous = receipt_path.read_bytes()
    receipt = _load_object(receipt_path, "intake receipt")
    refreshed_archives: list[dict[str, Any]] = []
    for record in receipt.get("archives", []):
        if not isinstance(record, dict) or not isinstance(record.get("source_id"), str):
            raise FolderIntakeError("invalid intake archive record")
        projection = _load_object(
            root / "canonical" / f"{record['source_id']}.json",
            "canonical projection",
        )
        refreshed_archives.append({
            **record,
            "provider": projection.get("provider"),
            "conversation_count": projection.get("conversation_count", 0),
            "message_count": projection.get("message_count", 0),
            "projection_sha256": projection.get("projection_sha256"),
        })
    receipt["archives"] = refreshed_archives
    corpus_path = root / "corpus.sqlite"
    receipt["corpus"] = inspect_corpus_index(str(corpus_path))
    ledger_path = Path(resolve_corpus_deletion_ledger_path(str(corpus_path)))
    artifact_paths = [
        corpus_path, ledger_path, *sorted((root / "canonical").iterdir())
    ]
    receipt["artifacts"] = [
        {
            "path": path.relative_to(root).as_posix(),
            "size_bytes": path.stat().st_size,
            "sha256": _file_sha256(path),
        }
        for path in artifact_paths
    ]
    fd, temporary_name = tempfile.mkstemp(
        prefix="folder-intake-receipt-", suffix=".json", dir=root
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, receipt_path)
        try:
            return verify_archive_generation(str(root))
        except Exception:
            receipt_path.write_bytes(previous)
            raise
    finally:
        temporary.unlink(missing_ok=True)
