import json

import boto3
import pytest
from moto import mock_aws

from app.core.job_store import DynamoJobStore

TABLE = "stig-jobs"


@pytest.fixture
def jobs_table():
    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-gov-west-1")
        client.create_table(
            TableName=TABLE,
            KeySchema=[{"AttributeName": "job_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "job_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield client


class _BeforeFirstUpdateClient:
    """Dynamo client proxy that injects one deterministic competing write."""

    def __init__(self, client, callback):
        self._client = client
        self._callback = callback
        self._called = False

    def update_item(self, **kwargs):
        if not self._called:
            self._called = True
            self._callback()
        return self._client.update_item(**kwargs)

    def __getattr__(self, name):
        return getattr(self._client, name)


def test_create_then_get(jobs_table):
    store = DynamoJobStore(TABLE, region="us-gov-west-1")
    store.create("job1", status="running", progress="Starting…")
    job = store.get("job1")
    assert job["status"] == "running"
    assert job["progress"] == "Starting…"


def test_update_merges_fields(jobs_table):
    store = DynamoJobStore(TABLE, region="us-gov-west-1")
    store.create("job1", status="running")
    store.update("job1", progress="Parsing…", warnings=["w1"])
    job = store.get("job1")
    assert job["status"] == "running"
    assert job["progress"] == "Parsing…"
    assert job["warnings"] == ["w1"]


def test_get_missing_returns_empty_dict(jobs_table):
    assert DynamoJobStore(TABLE, region="us-gov-west-1").get("nope") == {}


def test_delete_removes_job(jobs_table):
    store = DynamoJobStore(TABLE, region="us-gov-west-1")
    store.create("job1", status="running")
    store.delete("job1")
    assert store.get("job1") == {}


def test_legal_lifecycle_transitions_are_versioned(jobs_table):
    store = DynamoJobStore(TABLE, region="us-gov-west-1")
    store.create("job1", status="pending")

    assert store.transition("job1", "queued") is True
    assert store.transition("job1", "running") is True
    assert store.transition("job1", "complete", summary={"findings": 1}) is True

    item = jobs_table.get_item(TableName=TABLE, Key={"job_id": {"S": "job1"}})["Item"]
    assert item["version"]["N"] == "3"
    assert store.get("job1")["status"] == "complete"


def test_cancel_winning_before_conditional_write_is_not_overwritten(jobs_table):
    winner = DynamoJobStore(TABLE, region="us-gov-west-1", client=jobs_table)
    winner.create("job1", status="running", progress="Exporting.")

    racing_client = _BeforeFirstUpdateClient(
        jobs_table,
        lambda: winner.transition("job1", "cancelled", progress="Cancelled."),
    )
    stale_writer = DynamoJobStore(TABLE, region="us-gov-west-1", client=racing_client)

    assert (
        stale_writer.transition(
            "job1", "complete", progress="Done.", summary={"findings": 1}
        )
        is False
    )
    assert winner.get("job1") == {
        "status": "cancelled",
        "progress": "Cancelled.",
    }


def test_metadata_update_racing_with_cancel_preserves_both(jobs_table):
    winner = DynamoJobStore(TABLE, region="us-gov-west-1", client=jobs_table)
    winner.create("job1", status="running")

    racing_client = _BeforeFirstUpdateClient(
        jobs_table,
        lambda: winner.transition("job1", "cancelled", progress="Cancelled."),
    )
    stale_writer = DynamoJobStore(TABLE, region="us-gov-west-1", client=racing_client)

    stale_writer.update("job1", ai="failed")

    assert winner.get("job1") == {
        "status": "cancelled",
        "progress": "Cancelled.",
        "ai": "failed",
    }


def test_transition_upgrades_legacy_unversioned_item(jobs_table):
    expires_at = "2000000000"
    jobs_table.put_item(
        TableName=TABLE,
        Item={
            "job_id": {"S": "legacy"},
            "data": {"S": json.dumps({"status": "pending"})},
            "expiresAt": {"N": expires_at},
        },
    )
    store = DynamoJobStore(TABLE, region="us-gov-west-1", client=jobs_table)

    assert store.transition("legacy", "queued") is True

    item = jobs_table.get_item(TableName=TABLE, Key={"job_id": {"S": "legacy"}})["Item"]
    assert item["version"]["N"] == "1"
    assert item["expiresAt"]["N"] == expires_at
    assert json.loads(item["data"]["S"])["status"] == "queued"


def test_status_cannot_bypass_transition_contract(jobs_table):
    store = DynamoJobStore(TABLE, region="us-gov-west-1", client=jobs_table)
    store.create("job1", status="running")

    with pytest.raises(ValueError, match="transition"):
        store.update("job1", status="complete")


def test_expected_phase_blocks_stale_transition_fields(jobs_table):
    store = DynamoJobStore(TABLE, region="us-gov-west-1", client=jobs_table)
    store.create("job1", status="running", phase="parsing")

    assert (
        store.transition(
            "job1",
            "complete",
            expected_fields={"phase": "exporting"},
            summary={"findings": 1},
        )
        is False
    )
    assert store.get("job1") == {"status": "running", "phase": "parsing"}
