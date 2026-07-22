"""Blob-storage boundary for pipeline artifacts.

``ArtifactStore`` is the interface; ``LocalArtifactStore`` (filesystem) is used
by the Flask app, the CLI, and tests. ``S3ArtifactStore`` (added separately) is
the only module here permitted to import boto3.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import boto3
from botocore.config import Config as BotoConfig


@runtime_checkable
class ArtifactStore(Protocol):
    """Key→bytes blob store used to hand artifacts between pipeline stages."""

    def put_bytes(self, key: str, data: bytes) -> None: ...
    def get_bytes(self, key: str) -> bytes: ...
    def exists(self, key: str) -> bool: ...
    def upload_from(self, key: str, path: Path) -> None: ...
    def download_to(self, key: str, path: Path) -> None: ...
    def presign_get(self, key: str, expires: int = 900) -> str: ...
    def presign_put(self, key: str, expires: int = 900) -> str: ...


class LocalArtifactStore:
    """Filesystem-backed :class:`ArtifactStore` rooted at a directory."""

    def __init__(self, root: Path):
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _resolve(self, key: str) -> Path:
        # Reject keys that would escape the root (path traversal).
        target = (self._root / key).resolve()
        root = self._root.resolve()
        if root not in target.parents and target != root:
            raise ValueError(f"key escapes store root: {key!r}")
        return target

    def put_bytes(self, key: str, data: bytes) -> None:
        target = self._resolve(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def get_bytes(self, key: str) -> bytes:
        return self._resolve(key).read_bytes()

    def exists(self, key: str) -> bool:
        try:
            return self._resolve(key).is_file()
        except ValueError:
            return False

    def upload_from(self, key: str, path: Path) -> None:
        self.put_bytes(key, Path(path).read_bytes())

    def download_to(self, key: str, path: Path) -> None:
        dst = Path(path)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(self.get_bytes(key))

    def presign_get(self, key: str, expires: int = 900) -> str:
        return self._resolve(key).as_uri()

    def presign_put(self, key: str, expires: int = 900) -> str:
        return self._resolve(key).as_uri()


class S3ArtifactStore:
    """S3-backed :class:`ArtifactStore`.

    The only module member permitted to touch boto3. In GovCloud the client
    reaches S3 through the VPC gateway endpoint; presigned URLs are generated
    for the interface-endpoint host.
    """

    def __init__(self, bucket: str, region: str, client: Any = None):
        self._bucket = bucket
        # SigV4 is mandatory: presigned URLs for SSE-KMS buckets are rejected
        # with InvalidArgument when signed with the legacy default (SigV2).
        self._client = client or boto3.client(
            "s3",
            region_name=region,
            config=BotoConfig(signature_version="s3v4"),
        )

    def put_bytes(self, key: str, data: bytes) -> None:
        self._client.put_object(Bucket=self._bucket, Key=key, Body=data)

    def get_bytes(self, key: str) -> bytes:
        resp = self._client.get_object(Bucket=self._bucket, Key=key)
        return resp["Body"].read()

    def exists(self, key: str) -> bool:
        from botocore.exceptions import ClientError

        try:
            self._client.head_object(Bucket=self._bucket, Key=key)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("404", "NoSuchKey", "NotFound"):
                return False
            raise

    def upload_from(self, key: str, path: Path) -> None:
        self._client.upload_file(str(path), self._bucket, key)

    def download_to(self, key: str, path: Path) -> None:
        dst = Path(path)
        dst.parent.mkdir(parents=True, exist_ok=True)
        self._client.download_file(self._bucket, key, str(dst))

    def presign_get(self, key: str, expires: int = 900) -> str:
        return self._client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self._bucket, "Key": key},
            ExpiresIn=expires,
        )

    def presign_put(self, key: str, expires: int = 900) -> str:
        return self._client.generate_presigned_url(
            "put_object",
            Params={"Bucket": self._bucket, "Key": key},
            ExpiresIn=expires,
        )
