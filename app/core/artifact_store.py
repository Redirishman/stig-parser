"""Blob-storage boundary for pipeline artifacts.

``ArtifactStore`` is the interface; ``LocalArtifactStore`` (filesystem) is used
by the Flask app, the CLI, and tests. ``S3ArtifactStore`` (added separately) is
the only module here permitted to import boto3.
"""
from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable


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
