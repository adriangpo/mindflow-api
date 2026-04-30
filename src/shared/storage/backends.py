"""Shared storage backend abstractions."""

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import boto3
from botocore.config import Config

from src.config.settings import settings


@dataclass(frozen=True, slots=True)
class StoredFile:
    """Metadata for a stored file."""

    path: Path | None
    relative_path: Path
    filename: str
    content_type: str


@dataclass(frozen=True, slots=True)
class StorageDownload:
    """Backend-specific download resolution metadata."""

    filename: str
    content_type: str
    path: Path | None = None
    url: str | None = None
    body: bytes | None = None


class StorageBackend(Protocol):
    """Protocol for pluggable binary storage backends."""

    def store_bytes(
        self,
        relative_path: str | Path,
        payload: bytes,
        *,
        content_type: str,
    ) -> StoredFile:
        """Persist bytes and return file metadata."""

    def resolve_download(
        self,
        relative_path: str | Path,
        *,
        filename: str,
        content_type: str,
    ) -> StorageDownload:
        """Resolve a backend-specific download handle."""


class LocalStorageBackend:
    """Filesystem-backed storage implementation."""

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def _resolve_target(self, relative_path: str | Path) -> tuple[Path, Path]:
        relative = Path(relative_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("relative_path must stay within the configured storage root")

        root = self.root.resolve()
        target = (root / relative).resolve()

        if root != target and root not in target.parents:
            raise ValueError("relative_path resolved outside the configured storage root")

        return root, target

    def store_bytes(
        self,
        relative_path: str | Path,
        payload: bytes,
        *,
        content_type: str,
    ) -> StoredFile:
        """Persist bytes under the configured storage root."""
        root, target = self._resolve_target(relative_path)
        root.mkdir(parents=True, exist_ok=True)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)

        relative = target.relative_to(root)
        return StoredFile(
            path=target,
            relative_path=relative,
            filename=target.name,
            content_type=content_type,
        )

    def resolve_download(
        self,
        relative_path: str | Path,
        *,
        filename: str,
        content_type: str,
    ) -> StorageDownload:
        """Resolve one local stored file for download."""
        _, target = self._resolve_target(relative_path)
        if not target.exists():
            raise FileNotFoundError(target)

        return StorageDownload(
            path=target,
            filename=filename,
            content_type=content_type,
        )


class S3StorageBackend:
    """S3-compatible storage implementation used for R2 and similar services."""

    def __init__(
        self,
        *,
        endpoint_url: str,
        bucket_name: str,
        access_key_id: str,
        secret_access_key: str,
        region_name: str,
    ):
        if not endpoint_url:
            raise RuntimeError("S3_ENDPOINT_URL must be configured when STORAGE_BACKEND=s3")
        if "<" in endpoint_url or ">" in endpoint_url:
            raise RuntimeError(
                "S3_ENDPOINT_URL contains an unresolved placeholder. "
                "Replace '<accountid>' with your Cloudflare account ID "
                "(found in the Cloudflare dashboard under R2 > Overview)."
            )
        if not bucket_name:
            raise RuntimeError("S3_BUCKET_NAME must be configured when STORAGE_BACKEND=s3")
        if not access_key_id:
            raise RuntimeError("AWS_ACCESS_KEY_ID must be configured when STORAGE_BACKEND=s3")
        if not secret_access_key:
            raise RuntimeError("AWS_SECRET_ACCESS_KEY must be configured when STORAGE_BACKEND=s3")

        self.endpoint_url = endpoint_url
        self.bucket_name = bucket_name
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.region_name = region_name or "auto"

    def _normalize_key(self, relative_path: str | Path) -> str:
        relative = Path(relative_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("relative_path must stay within the configured storage backend")
        return relative.as_posix()

    def _get_client(self):
        return boto3.client(
            "s3",
            endpoint_url=self.endpoint_url,
            aws_access_key_id=self.access_key_id,
            aws_secret_access_key=self.secret_access_key,
            region_name=self.region_name,
            config=Config(signature_version="s3v4"),
        )

    def store_bytes(
        self,
        relative_path: str | Path,
        payload: bytes,
        *,
        content_type: str,
    ) -> StoredFile:
        """Persist bytes to one S3-compatible bucket object."""
        key = self._normalize_key(relative_path)
        self._get_client().put_object(
            Bucket=self.bucket_name,
            Key=key,
            Body=payload,
            ContentType=content_type,
        )
        normalized_path = Path(key)
        return StoredFile(
            path=None,
            relative_path=normalized_path,
            filename=normalized_path.name,
            content_type=content_type,
        )

    def resolve_download(
        self,
        relative_path: str | Path,
        *,
        filename: str,
        content_type: str,
    ) -> StorageDownload:
        """Fetch bytes from S3 and return them for direct server-side streaming."""
        key = self._normalize_key(relative_path)
        response = self._get_client().get_object(Bucket=self.bucket_name, Key=key)
        body = response["Body"].read()
        return StorageDownload(
            filename=filename,
            content_type=content_type,
            body=body,
        )


def get_local_storage_backend() -> LocalStorageBackend:
    """Build the default local storage backend from application settings."""
    return LocalStorageBackend(settings.storage_root)


def get_storage_backend() -> StorageBackend:
    """Build the default storage backend from application settings."""
    if settings.storage_backend == "s3":
        return S3StorageBackend(
            endpoint_url=settings.s3_endpoint_url,
            bucket_name=settings.s3_bucket_name,
            access_key_id=settings.aws_access_key_id,
            secret_access_key=settings.aws_secret_access_key,
            region_name=settings.aws_region,
        )
    return get_local_storage_backend()
