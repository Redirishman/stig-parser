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
        yield


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
