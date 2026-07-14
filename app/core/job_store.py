"""Job-status boundary.

``JobStore`` is the interface; ``MemoryJobStore`` (thread-safe dict) backs the
Flask app / CLI / tests. ``DynamoJobStore`` (added separately) backs Lambda and
is the only member permitted to import boto3.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any, Protocol, runtime_checkable

import boto3


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


class DynamoJobStore:
    """DynamoDB-backed :class:`JobStore`.

    The job record is stored as a single item keyed by ``job_id``. Field values
    are JSON-encoded into a ``data`` attribute so arbitrary nested structures
    (warnings lists, summary dicts) round-trip without per-field typing. The
    only member here permitted to touch boto3.

    Concurrency: ``update`` is a non-atomic read-modify-write. Callers must
    serialize updates per ``job_id`` (a single writer per job at a time).
    Concurrent updates to the same job can lose fields (last full-record write
    wins). If the async orchestration ever issues concurrent per-job updates,
    switch this to optimistic concurrency (a ``version`` attribute guarded by a
    ``ConditionExpression``).
    """

    def __init__(
        self,
        table_name: str,
        region: str,
        client: Any = None,
        ttl_days: int | None = None,
    ):
        self._table = table_name
        self._client = client or boto3.client("dynamodb", region_name=region)
        self._ttl_days = ttl_days

    def create(self, job_id: str, **fields: Any) -> None:
        self._put(job_id, dict(fields))

    def update(self, job_id: str, **fields: Any) -> None:
        record = self.get(job_id)
        record.update(fields)
        self._put(job_id, record)

    def get(self, job_id: str) -> dict:
        resp = self._client.get_item(
            TableName=self._table,
            Key={"job_id": {"S": job_id}},
        )
        item = resp.get("Item")
        if not item:
            return {}
        return json.loads(item["data"]["S"])

    def delete(self, job_id: str) -> None:
        self._client.delete_item(
            TableName=self._table,
            Key={"job_id": {"S": job_id}},
        )

    def _put(self, job_id: str, record: dict) -> None:
        item: dict[str, dict] = {
            "job_id": {"S": job_id},
            "data": {"S": json.dumps(record)},
        }
        # The table's TTL policy watches a top-level `expiresAt` attribute, so it
        # cannot live inside the JSON `data` blob. Without this the table expires
        # nothing and job records (CUI) accumulate forever.
        if self._ttl_days is not None:
            expires_at = int(time.time()) + self._ttl_days * 86400
            item["expiresAt"] = {"N": str(expires_at)}
        self._client.put_item(TableName=self._table, Item=item)
