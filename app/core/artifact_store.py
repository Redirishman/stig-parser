"""Blob-storage boundary for pipeline artifacts.

``ArtifactStore`` is the interface; ``LocalArtifactStore`` (filesystem) is used
by the Flask app, the CLI, and tests. ``S3ArtifactStore`` (added separately) is
the only module here permitted to import boto3.
"""
from __future__ import annotations

import contextlib
from pathlib import Path
from typing import IO, Any, Protocol, runtime_checkable

import boto3
from botocore.config import Config


@runtime_checkable
class ArtifactStore(Protocol):
    """Key→bytes blob store used to hand artifacts between pipeline stages."""

    def put_bytes(self, key: str, data: bytes) -> None: ...
    def get_bytes(self, key: str) -> bytes: ...
    def exists(self, key: str) -> bool: ...
    def size(self, key: str) -> int: ...
    def upload_from(self, key: str, path: Path) -> None: ...
    def download_to(self, key: str, path: Path, *, max_bytes: int | None = None) -> None: ...
    def presign_get(self, key: str, expires: int = 900) -> str: ...
    def presign_put(self, key: str, expires: int = 900) -> str: ...


class ObjectTooLarge(Exception):
    """An object held more than the bytes a download may take (``max_bytes``)."""


_CHUNK = 1024 * 1024


def _copy_capped(src: IO[bytes], dst: Path, max_bytes: int) -> None:
    """Write *src* to *dst*, at most *max_bytes*; past that, remove *dst* and raise
    ObjectTooLarge. Counted as read, never taken from a size reported earlier."""
    written = 0
    try:
        with dst.open("wb") as out:
            while chunk := src.read(_CHUNK):
                written += len(chunk)
                if written > max_bytes:
                    raise ObjectTooLarge(f"more than {max_bytes} bytes")
                out.write(chunk)
    except ObjectTooLarge:
        with contextlib.suppress(OSError):
            dst.unlink(missing_ok=True)
        raise


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

    def size(self, key: str) -> int:
        return self._resolve(key).stat().st_size

    def upload_from(self, key: str, path: Path) -> None:
        self.put_bytes(key, Path(path).read_bytes())

    def download_to(self, key: str, path: Path, *, max_bytes: int | None = None) -> None:
        dst = Path(path)
        dst.parent.mkdir(parents=True, exist_ok=True)
        if max_bytes is None:
            dst.write_bytes(self.get_bytes(key))
            return
        with self._resolve(key).open("rb") as src:
            _copy_capped(src, dst, max_bytes)

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

    def __init__(
        self,
        bucket: str,
        region: str,
        client: Any = None,
        presign_endpoint_url: str | None = None,
        presign_client: Any = None,
    ):
        self._bucket = bucket
        self._client = client or boto3.client("s3", region_name=region)
        if presign_client is not None:
            self._presign_client = presign_client
        elif presign_endpoint_url:
            self._presign_client = boto3.client(
                "s3",
                region_name=region,
                endpoint_url=presign_endpoint_url,
                config=Config(
                    signature_version="s3v4",
                    s3={"addressing_style": "path"},
                ),
            )
        else:
            self._presign_client = self._client

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

    def size(self, key: str) -> int:
        resp = self._client.head_object(Bucket=self._bucket, Key=key)
        return int(resp["ContentLength"])

    def upload_from(self, key: str, path: Path) -> None:
        self._client.upload_file(str(path), self._bucket, key)

    def download_to(self, key: str, path: Path, *, max_bytes: int | None = None) -> None:
        dst = Path(path)
        dst.parent.mkdir(parents=True, exist_ok=True)
        if max_bytes is None:
            self._client.download_file(self._bucket, key, str(dst))
            return
        # Ask for one byte more than allowed: S3 sends no more, and one byte over says too large.
        body = self._client.get_object(Bucket=self._bucket, Key=key, Range=f"bytes=0-{max_bytes}")["Body"]
        try:
            _copy_capped(body, dst, max_bytes)
        finally:
            body.close()

    def presign_get(self, key: str, expires: int = 900) -> str:
        return self._presign_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self._bucket, "Key": key},
            ExpiresIn=expires,
        )

    def presign_put(self, key: str, expires: int = 900) -> str:
        return self._presign_client.generate_presigned_url(
            "put_object",
            Params={"Bucket": self._bucket, "Key": key},
            ExpiresIn=expires,
        )
