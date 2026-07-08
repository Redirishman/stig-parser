import boto3
import pytest
from moto import mock_aws

from app.core.artifact_store import S3ArtifactStore

BUCKET = "test-artifacts"


@pytest.fixture
def s3_bucket():
    with mock_aws():
        client = boto3.client("s3", region_name="us-gov-west-1")
        client.create_bucket(
            Bucket=BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "us-gov-west-1"},
        )
        yield client


def test_put_then_get_bytes_roundtrip(s3_bucket):
    store = S3ArtifactStore(BUCKET, region="us-gov-west-1")
    store.put_bytes("jobs/1/findings.json", b'{"a":1}')
    assert store.get_bytes("jobs/1/findings.json") == b'{"a":1}'


def test_exists(s3_bucket):
    store = S3ArtifactStore(BUCKET, region="us-gov-west-1")
    assert store.exists("nope") is False
    store.put_bytes("yes", b"x")
    assert store.exists("yes") is True


def test_upload_from_and_download_to(s3_bucket, tmp_path):
    store = S3ArtifactStore(BUCKET, region="us-gov-west-1")
    src = tmp_path / "s.bin"
    src.write_bytes(b"payload")
    store.upload_from("k/o.bin", src)
    dst = tmp_path / "d" / "o.bin"
    store.download_to("k/o.bin", dst)
    assert dst.read_bytes() == b"payload"


def test_presign_get_returns_https_url(s3_bucket):
    store = S3ArtifactStore(BUCKET, region="us-gov-west-1")
    store.put_bytes("k/o", b"z")
    url = store.presign_get("k/o")
    assert url.startswith("https://")
    assert "k/o" in url
