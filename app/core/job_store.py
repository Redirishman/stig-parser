"""Job-status boundary.

``JobStore`` is the interface; ``MemoryJobStore`` (thread-safe dict) backs the
Flask app / CLI / tests. ``DynamoJobStore`` (added separately) backs Lambda and
is the only member permitted to import boto3.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Collection, Mapping
from typing import Any, Protocol, runtime_checkable

import boto3
from botocore.exceptions import ClientError


TERMINAL_STATUSES = frozenset({"complete", "error", "cancelled"})

# The store, rather than each caller, owns the legal lifecycle.  Terminal
# states deliberately have no outgoing edges.
_ALLOWED_STATUS_TRANSITIONS = {
    "pending": frozenset({"queued", "cancelled"}),
    "queued": frozenset({"running", "error", "cancelled"}),
    "running": frozenset({"complete", "error", "cancelled"}),
}
_TRANSITION_TARGETS = frozenset(
    target for targets in _ALLOWED_STATUS_TRANSITIONS.values() for target in targets
)
_MAX_WRITE_ATTEMPTS = 8


class ConcurrentJobUpdateError(RuntimeError):
    """A job stayed contended beyond the store's bounded retry budget."""


def _reject_status_patch(fields: dict[str, Any]) -> None:
    if "status" in fields:
        raise ValueError("use transition() to change a job's status")


def _normalise_statuses(statuses: Collection[str]) -> frozenset[str]:
    if isinstance(statuses, str):
        raise TypeError("expected_statuses must be a collection, not a string")
    return frozenset(statuses)


def _validate_transition_target(to_status: str) -> None:
    if to_status not in _TRANSITION_TARGETS:
        raise ValueError(f"unsupported job status transition target: {to_status!r}")


def _matches_fields(record: dict, expected_fields: Mapping[str, Any] | None) -> bool:
    return expected_fields is None or all(
        record.get(name) == value for name, value in expected_fields.items()
    )


@runtime_checkable
class JobStore(Protocol):
    """Stores per-job status records keyed by job id."""

    def create(self, job_id: str, **fields: Any) -> None: ...
    def update(self, job_id: str, **fields: Any) -> None: ...
    def update_if_status(
        self,
        job_id: str,
        expected_statuses: Collection[str],
        *,
        expected_fields: Mapping[str, Any] | None = None,
        **fields: Any,
    ) -> bool: ...
    def transition(
        self,
        job_id: str,
        to_status: str,
        *,
        expected_fields: Mapping[str, Any] | None = None,
        **fields: Any,
    ) -> bool: ...
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
        _reject_status_patch(fields)
        with self._lock:
            self._jobs.setdefault(job_id, {}).update(fields)

    def update_if_status(
        self,
        job_id: str,
        expected_statuses: Collection[str],
        *,
        expected_fields: Mapping[str, Any] | None = None,
        **fields: Any,
    ) -> bool:
        """Merge fields only while the record has an expected status."""
        _reject_status_patch(fields)
        expected = _normalise_statuses(expected_statuses)
        with self._lock:
            record = self._jobs.get(job_id)
            if (
                record is None
                or record.get("status") not in expected
                or not _matches_fields(record, expected_fields)
            ):
                return False
            record.update(fields)
            return True

    def transition(
        self,
        job_id: str,
        to_status: str,
        *,
        expected_fields: Mapping[str, Any] | None = None,
        **fields: Any,
    ) -> bool:
        """Atomically apply one legal lifecycle edge and its companion fields."""
        _validate_transition_target(to_status)
        _reject_status_patch(fields)
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None:
                return False
            current = record.get("status")
            if to_status not in _ALLOWED_STATUS_TRANSITIONS.get(
                current, ()
            ) or not _matches_fields(record, expected_fields):
                return False
            record.update(fields)
            record["status"] = to_status
            return True

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

    Every mutation uses optimistic concurrency. A top-level numeric ``version``
    guards the JSON record with a DynamoDB ``ConditionExpression``; a losing
    writer rereads and merges its fields onto the winner. Existing rows without
    a version are upgraded on their first successful write, so this change does
    not require a table migration.
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
        """Merge non-status fields without losing a concurrent mutation."""
        _reject_status_patch(fields)
        for _ in range(_MAX_WRITE_ATTEMPTS):
            record, version, exists = self._read(job_id)
            record.update(fields)
            try:
                self._write_conditionally(job_id, record, version, exists)
                return
            except ClientError as exc:
                if not self._is_conflict(exc):
                    raise
        raise ConcurrentJobUpdateError(
            f"job {job_id!r} remained contended after {_MAX_WRITE_ATTEMPTS} writes"
        )

    def update_if_status(
        self,
        job_id: str,
        expected_statuses: Collection[str],
        *,
        expected_fields: Mapping[str, Any] | None = None,
        **fields: Any,
    ) -> bool:
        """Merge fields only while the latest record has an expected status."""
        _reject_status_patch(fields)
        expected = _normalise_statuses(expected_statuses)
        for _ in range(_MAX_WRITE_ATTEMPTS):
            record, version, exists = self._read(job_id)
            if (
                not exists
                or record.get("status") not in expected
                or not _matches_fields(record, expected_fields)
            ):
                return False
            record.update(fields)
            try:
                self._write_conditionally(job_id, record, version, exists)
                return True
            except ClientError as exc:
                if not self._is_conflict(exc):
                    raise
        raise ConcurrentJobUpdateError(
            f"job {job_id!r} remained contended after {_MAX_WRITE_ATTEMPTS} writes"
        )

    def transition(
        self,
        job_id: str,
        to_status: str,
        *,
        expected_fields: Mapping[str, Any] | None = None,
        **fields: Any,
    ) -> bool:
        """Atomically apply one legal lifecycle edge and its companion fields."""
        _validate_transition_target(to_status)
        _reject_status_patch(fields)
        for _ in range(_MAX_WRITE_ATTEMPTS):
            record, version, exists = self._read(job_id)
            if not exists:
                return False
            current = record.get("status")
            if to_status not in _ALLOWED_STATUS_TRANSITIONS.get(
                current, ()
            ) or not _matches_fields(record, expected_fields):
                return False
            record.update(fields)
            record["status"] = to_status
            try:
                self._write_conditionally(job_id, record, version, exists)
                return True
            except ClientError as exc:
                if not self._is_conflict(exc):
                    raise
        raise ConcurrentJobUpdateError(
            f"job {job_id!r} remained contended after {_MAX_WRITE_ATTEMPTS} writes"
        )

    def get(self, job_id: str) -> dict:
        record, _, exists = self._read(job_id)
        return record if exists else {}

    def _read(self, job_id: str) -> tuple[dict, int | None, bool]:
        resp = self._client.get_item(
            TableName=self._table,
            Key={"job_id": {"S": job_id}},
            ConsistentRead=True,
        )
        item = resp.get("Item")
        if not item:
            return {}, None, False
        version_attr = item.get("version")
        version = int(version_attr["N"]) if version_attr is not None else None
        return json.loads(item["data"]["S"]), version, True

    def delete(self, job_id: str) -> None:
        self._client.delete_item(
            TableName=self._table,
            Key={"job_id": {"S": job_id}},
        )

    def _put(self, job_id: str, record: dict) -> None:
        item: dict[str, dict] = {
            "job_id": {"S": job_id},
            "data": {"S": json.dumps(record)},
            "version": {"N": "0"},
        }
        # The table's TTL policy watches a top-level `expiresAt` attribute, so it
        # cannot live inside the JSON `data` blob. Without this the table expires
        # nothing and job records (CUI) accumulate forever.
        if self._ttl_days is not None:
            expires_at = int(time.time()) + self._ttl_days * 86400
            item["expiresAt"] = {"N": str(expires_at)}
        self._client.put_item(TableName=self._table, Item=item)

    def _write_conditionally(
        self,
        job_id: str,
        record: dict,
        version: int | None,
        exists: bool,
    ) -> None:
        names = {
            "#job_id": "job_id",
            "#data": "data",
            "#version": "version",
        }
        values: dict[str, dict] = {
            ":data": {"S": json.dumps(record)},
        }

        if not exists:
            next_version = 0
            condition = "attribute_not_exists(#job_id)"
        elif version is None:
            # Legacy item: only one writer may claim the missing version.
            next_version = 1
            condition = "attribute_exists(#job_id) AND attribute_not_exists(#version)"
        else:
            next_version = version + 1
            condition = "attribute_exists(#job_id) AND #version = :expected_version"
            values[":expected_version"] = {"N": str(version)}

        values[":next_version"] = {"N": str(next_version)}
        assignments = ["#data = :data", "#version = :next_version"]
        if self._ttl_days is not None:
            names["#expires_at"] = "expiresAt"
            values[":expires_at"] = {
                "N": str(int(time.time()) + self._ttl_days * 86400)
            }
            assignments.append("#expires_at = :expires_at")

        self._client.update_item(
            TableName=self._table,
            Key={"job_id": {"S": job_id}},
            UpdateExpression=f"SET {', '.join(assignments)}",
            ConditionExpression=condition,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )

    @staticmethod
    def _is_conflict(exc: ClientError) -> bool:
        return exc.response.get("Error", {}).get("Code") == (
            "ConditionalCheckFailedException"
        )
