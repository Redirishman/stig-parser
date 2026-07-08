"""Job-status boundary.

``JobStore`` is the interface; ``MemoryJobStore`` (thread-safe dict) backs the
Flask app / CLI / tests. ``DynamoJobStore`` (added separately) backs Lambda and
is the only member permitted to import boto3.
"""
from __future__ import annotations

import threading
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class JobStore(Protocol):
    """Stores per-job status records keyed by job id."""

    def create(self, job_id: str, **fields: Any) -> None: ...
    def update(self, job_id: str, **fields: Any) -> None: ...
    def get(self, job_id: str) -> dict: ...
    def delete(self, job_id: str) -> None: ...


class MemoryJobStore:
    """In-process, thread-safe :class:`JobStore`."""

    def __init__(self) -> None:
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()

    def create(self, job_id: str, **fields: Any) -> None:
        with self._lock:
            self._jobs[job_id] = dict(fields)

    def update(self, job_id: str, **fields: Any) -> None:
        with self._lock:
            self._jobs.setdefault(job_id, {}).update(fields)

    def get(self, job_id: str) -> dict:
        with self._lock:
            return dict(self._jobs.get(job_id, {}))

    def delete(self, job_id: str) -> None:
        with self._lock:
            self._jobs.pop(job_id, None)
