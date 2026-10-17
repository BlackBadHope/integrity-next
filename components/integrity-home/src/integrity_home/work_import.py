"""Tenant-local staged imports for ChatGPT Work file attachments.

The transport-specific downloader is injected.  This core never follows a URL
itself, never accepts a filesystem path from the model, and never extracts an
archive during staging.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
from typing import Any, Protocol
from urllib.parse import urlsplit
import zipfile

from .tenant import TenantVault


MAX_IMPORT_FILES = 8
MAX_IMPORT_FILE_BYTES = 512 * 1024 * 1024
MAX_IMPORT_TOTAL_BYTES = 1024 * 1024 * 1024
_JOB_RE = re.compile(r"^wi_[A-Za-z0-9_-]{24,64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class WorkImportError(ValueError):
    """Safe file-staging or import-boundary failure."""


@dataclass(frozen=True)
class WorkFileRef:
    download_url: str
    file_id: str
    mime_type: str | None
    file_name: str | None

    @classmethod
    def from_mapping(cls, raw: Any) -> "WorkFileRef":
        if not isinstance(raw, Mapping) or set(raw) - {
            "download_url",
            "file_id",
            "mime_type",
            "file_name",
        }:
            raise WorkImportError("file attachment is invalid")
        download_url = raw.get("download_url")
        file_id = raw.get("file_id")
        mime_type = raw.get("mime_type")
        file_name = raw.get("file_name")
        if (
            not isinstance(download_url, str)
            or not download_url
            or len(download_url) > 8_192
            or not isinstance(file_id, str)
            or not file_id
            or len(file_id) > 512
        ):
            raise WorkImportError("file attachment is invalid")
        for value, label, maximum in (
            (mime_type, "mime_type", 256),
            (file_name, "file_name", 512),
        ):
            if value is not None and (
                not isinstance(value, str)
                or not value
                or len(value) > maximum
                or any(ord(character) < 32 for character in value)
            ):
                raise WorkImportError(f"file {label} is invalid")
        parsed = urlsplit(download_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise WorkImportError("file download URL must use HTTPS")
        hostname = parsed.hostname.casefold()
        if hostname == "localhost" or hostname.endswith(".localhost"):
            raise WorkImportError("file download URL host is not allowed")
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            address = None
        if address is not None and not address.is_global:
            raise WorkImportError("file download URL host is not allowed")
        return cls(
            download_url=download_url,
            file_id=file_id,
            mime_type=mime_type,
            file_name=file_name,
        )


@dataclass(frozen=True)
class MaterializedFile:
    byte_length: int
    sha256: str


class FileMaterializer(Protocol):
    """Gateway-owned streaming downloader with redirect and DNS checks."""

    def materialize(
        self,
        source: WorkFileRef,
        destination: Path,
        *,
        max_bytes: int,
    ) -> MaterializedFile: ...


class WorkImportCoordinator:
    """Stage, review, then commit one tenant's provider exports."""

    def __init__(
        self,
        vault: TenantVault,
        materializer: FileMaterializer,
        *,
        commit_batch: Callable[[TenantVault, str], Mapping[str, Any]] | None = None,
    ):
        if not isinstance(vault, TenantVault):
            raise WorkImportError("tenant vault is required")
        self._vault = vault
        self._materializer = materializer
        self._commit_batch = commit_batch

    @staticmethod
    def _manifest_bytes(payload: Mapping[str, Any]) -> bytes:
        return (
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")

    @staticmethod
    def _file_sha256(path: Path) -> str:
        digest = sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    def _job_dir(self, job_id: str) -> Path:
        if not isinstance(job_id, str) or _JOB_RE.fullmatch(job_id) is None:
            raise WorkImportError("import job is invalid or expired")
        path = self._vault.jobs_path / job_id
        try:
            resolved = path.resolve(strict=False)
            resolved.relative_to(self._vault.jobs_path.resolve(strict=True))
        except (OSError, RuntimeError, ValueError) as err:
            raise WorkImportError("import job path is invalid") from err
        return resolved

    def _batch_dir(self, job_id: str) -> Path:
        if not isinstance(job_id, str) or _JOB_RE.fullmatch(job_id) is None:
            raise WorkImportError("import job is invalid or expired")
        path = self._vault.inbox_path / job_id
        try:
            resolved = path.resolve(strict=False)
            resolved.relative_to(self._vault.inbox_path.resolve(strict=True))
        except (OSError, RuntimeError, ValueError) as err:
            raise WorkImportError("import batch path is invalid") from err
        return resolved

    @staticmethod
    def _safe_suffix(
        file_name: str | None, mime_type: str | None = None
    ) -> str:
        if file_name is not None:
            lowered = file_name.casefold()
            for suffix in (
                ".tar.gz",
                ".json.zip",
                ".zip",
                ".json",
                ".html",
                ".tgz",
                ".gz",
            ):
                if lowered.endswith(suffix):
                    return suffix
        normalized_mime = (
            mime_type.split(";", 1)[0].strip().casefold()
            if mime_type is not None
            else None
        )
        if normalized_mime in {
            "application/zip",
            "application/x-zip-compressed",
        }:
            return ".zip"
        if normalized_mime in {"application/json", "text/json"}:
            return ".json"
        if normalized_mime == "text/html":
            return ".html"
        return ".bin"

    def stage(self, files: Any) -> dict[str, Any]:
        if (
            not isinstance(files, Sequence)
            or isinstance(files, (str, bytes, bytearray))
            or not 1 <= len(files) <= MAX_IMPORT_FILES
        ):
            raise WorkImportError(
                f"files must contain between 1 and {MAX_IMPORT_FILES} attachments"
            )
        references = [WorkFileRef.from_mapping(item) for item in files]
        if len({item.file_id for item in references}) != len(references):
            raise WorkImportError("file attachments contain duplicate file ids")
        job_id = "wi_" + secrets.token_urlsafe(24)
        job_dir = self._job_dir(job_id)
        batch_dir = self._batch_dir(job_id)
        job_dir.mkdir(mode=0o700)
        batch_dir.mkdir(mode=0o700)
        staged_files: list[dict[str, Any]] = []
        total = 0
        try:
            for index, reference in enumerate(references):
                safe_suffix = self._safe_suffix(
                    reference.file_name, reference.mime_type
                )
                destination = batch_dir / (
                    f"attachment-{index + 1:02d}"
                    f"{safe_suffix}"
                )
                materialized = self._materializer.materialize(
                    reference,
                    destination,
                    max_bytes=MAX_IMPORT_FILE_BYTES,
                )
                if (
                    not isinstance(materialized, MaterializedFile)
                    or isinstance(materialized.byte_length, bool)
                    or not 0 <= materialized.byte_length <= MAX_IMPORT_FILE_BYTES
                    or _SHA256_RE.fullmatch(materialized.sha256) is None
                    or not destination.is_file()
                    or destination.is_symlink()
                    or destination.stat().st_size != materialized.byte_length
                ):
                    raise WorkImportError("materialized attachment is invalid")
                digest = self._file_sha256(destination)
                if digest != materialized.sha256:
                    raise WorkImportError("materialized attachment digest mismatch")
                if safe_suffix == ".bin" and zipfile.is_zipfile(destination):
                    detected = destination.with_suffix(".zip")
                    if detected.exists() or detected.is_symlink():
                        raise WorkImportError("detected attachment path is unsafe")
                    os.replace(destination, detected)
                    destination = detected
                total += materialized.byte_length
                if total > MAX_IMPORT_TOTAL_BYTES:
                    raise WorkImportError("import attachments exceed the total byte limit")
                try:
                    os.chmod(destination, 0o600)
                except OSError:
                    pass
                staged_files.append(
                    {
                        "slot": index + 1,
                        "file_id_sha256": sha256(
                            reference.file_id.encode("utf-8")
                        ).hexdigest(),
                        "file_name": reference.file_name,
                        "mime_type": reference.mime_type,
                        "byte_length": materialized.byte_length,
                        "sha256": materialized.sha256,
                    }
                )
            manifest = {
                "schema_version": "integrity-work-import-job/1",
                "tenant_id": self._vault.tenant_id,
                "job_id": job_id,
                "state": "staged",
                "file_count": len(staged_files),
                "total_bytes": total,
                "files": staged_files,
            }
            encoded = self._manifest_bytes(manifest)
            manifest_sha256 = sha256(encoded).hexdigest()
            temporary = job_dir / ".manifest.tmp"
            temporary.write_bytes(encoded)
            os.replace(temporary, job_dir / "manifest.json")
            return {
                "job_id": job_id,
                "state": "staged",
                "file_count": len(staged_files),
                "total_bytes": total,
                "manifest_sha256": manifest_sha256,
                "next_action": "review_memory_import",
            }
        except Exception:
            for directory in (job_dir, batch_dir):
                if directory.is_dir() and not directory.is_symlink():
                    for child in directory.iterdir():
                        if child.is_file() and not child.is_symlink():
                            child.unlink()
                    directory.rmdir()
            raise

    def _load_manifest(self, job_id: str) -> tuple[dict[str, Any], str]:
        manifest_path = self._job_dir(job_id) / "manifest.json"
        try:
            encoded = manifest_path.read_bytes()
            payload = json.loads(encoded.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as err:
            raise WorkImportError("import job is invalid or expired") from err
        if (
            not isinstance(payload, dict)
            or payload.get("tenant_id") != self._vault.tenant_id
            or payload.get("job_id") != job_id
            or payload.get("state") != "staged"
        ):
            raise WorkImportError("import job is invalid or expired")
        batch_dir = self._batch_dir(job_id)
        if not batch_dir.is_dir() or batch_dir.is_symlink():
            raise WorkImportError("import job is invalid or expired")
        return payload, sha256(encoded).hexdigest()

    def review(self, job_id: str) -> dict[str, Any]:
        payload, digest = self._load_manifest(job_id)
        return {
            "job_id": job_id,
            "state": "staged",
            "file_count": payload["file_count"],
            "total_bytes": payload["total_bytes"],
            "files": payload["files"],
            "manifest_sha256": digest,
            "ready_to_commit": self._commit_batch is not None,
        }

    def commit(self, job_id: str, expected_manifest_sha256: str) -> dict[str, Any]:
        if _SHA256_RE.fullmatch(expected_manifest_sha256 or "") is None:
            raise WorkImportError("expected manifest digest is invalid")
        _, digest = self._load_manifest(job_id)
        if not secrets.compare_digest(digest, expected_manifest_sha256):
            raise WorkImportError("import manifest changed after review")
        if self._commit_batch is None:
            raise WorkImportError("tenant import commit adapter is unavailable")
        result = self._commit_batch(self._vault, job_id)
        if not isinstance(result, Mapping):
            raise WorkImportError("tenant import commit returned invalid evidence")
        return {
            "job_id": job_id,
            "state": "committed",
            "manifest_sha256": digest,
            "result": dict(result),
        }


def commit_personal_batch(vault: TenantVault, job_id: str) -> Mapping[str, Any]:
    """Commit a staged Work batch through the existing atomic Home importer."""

    from .ops_projection import HomeOpsProjection

    return HomeOpsProjection(str(vault.root)).invoke(
        "home_import_batch",
        {
            "batch_name": job_id,
            "generation_name": job_id,
            "scope_kind": "personal",
        },
    )


WORK_IMPORT_TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "stage_memory_import",
        "description": (
            "Stage ChatGPT, Claude, or Gemini export attachments inside the "
            "authenticated user's isolated memory vault. This does not yet "
            "mutate the searchable corpus."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "files": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": MAX_IMPORT_FILES,
                    "items": {
                        "type": "object",
                        "properties": {
                            "download_url": {"type": "string", "format": "uri"},
                            "file_id": {"type": "string"},
                            "mime_type": {"type": "string"},
                            "file_name": {"type": "string"},
                        },
                        "required": [
                            "download_url",
                            "file_id",
                        ],
                        "additionalProperties": False,
                    },
                }
            },
            "required": ["files"],
            "additionalProperties": False,
        },
        "_meta": {"openai/fileParams": ["files"]},
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "openWorldHint": True,
        },
    },
    {
        "name": "review_memory_import",
        "description": "Review a staged tenant-local import before corpus mutation.",
        "inputSchema": {
            "type": "object",
            "properties": {"job_id": {"type": "string"}},
            "required": ["job_id"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "commit_memory_import",
        "description": (
            "Commit one reviewed import into the authenticated user's unified "
            "memory corpus using the exact reviewed manifest digest."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string"},
                "expected_manifest_sha256": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{64}$",
                },
            },
            "required": ["job_id", "expected_manifest_sha256"],
            "additionalProperties": False,
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    },
)


__all__ = [
    "FileMaterializer",
    "MaterializedFile",
    "MAX_IMPORT_FILE_BYTES",
    "MAX_IMPORT_FILES",
    "MAX_IMPORT_TOTAL_BYTES",
    "WORK_IMPORT_TOOLS",
    "WorkFileRef",
    "WorkImportCoordinator",
    "WorkImportError",
    "commit_personal_batch",
]
