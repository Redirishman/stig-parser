from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

import boto3
import pytest
from botocore.config import Config
from moto import mock_aws

from app.core.artifact_store import S3ArtifactStore

BUCKET = "test-artifacts"
PRIVATE_ENDPOINT = (
    "https://bucket.vpce-test.s3.us-gov-west-1.vpce.amazonaws.com"
)


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


def test_presign_operations_use_the_dedicated_client():
    runtime_client = Mock()
    presign_client = Mock()
    presign_client.generate_presigned_url.side_effect = ["put-url", "get-url"]
    store = S3ArtifactStore(
        BUCKET,
        region="us-gov-west-1",
        client=runtime_client,
        presign_client=presign_client,
    )

    assert store.presign_put("jobs/1/input.xml", expires=60) == "put-url"
    assert store.presign_get("jobs/1/report.xlsx", expires=120) == "get-url"
    assert presign_client.generate_presigned_url.call_args_list == [
        (
            ("put_object",),
            {
                "Params": {"Bucket": BUCKET, "Key": "jobs/1/input.xml"},
                "ExpiresIn": 60,
            },
        ),
        (
            ("get_object",),
            {
                "Params": {"Bucket": BUCKET, "Key": "jobs/1/report.xlsx"},
                "ExpiresIn": 120,
            },
        ),
    ]
    runtime_client.generate_presigned_url.assert_not_called()


def test_private_endpoint_signer_is_sigv4_and_path_style():
    runtime_client = Mock()
    signer = Mock()
    with patch("app.core.artifact_store.boto3.client", return_value=signer) as factory:
        store = S3ArtifactStore(
            BUCKET,
            region="us-gov-west-1",
            client=runtime_client,
            presign_endpoint_url=PRIVATE_ENDPOINT,
        )

    factory.assert_called_once()
    _, kwargs = factory.call_args
    assert kwargs["endpoint_url"] == PRIVATE_ENDPOINT
    assert kwargs["region_name"] == "us-gov-west-1"
    assert isinstance(kwargs["config"], Config)
    assert kwargs["config"].signature_version == "s3v4"
    assert kwargs["config"].s3 == {"addressing_style": "path"}

    store.presign_put("jobs/1/input.xml")
    signer.generate_presigned_url.assert_called_once()


def test_private_endpoint_url_uses_literal_bucket_host_and_sigv4(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)

    store = S3ArtifactStore(
        BUCKET,
        region="us-gov-west-1",
        client=Mock(),
        presign_endpoint_url=PRIVATE_ENDPOINT,
    )
    url = store.presign_put("jobs/1/input.xml")
    parsed = urlparse(url)

    assert parsed.netloc == urlparse(PRIVATE_ENDPOINT).netloc
    assert parsed.path == f"/{BUCKET}/jobs/1/input.xml"
    assert parse_qs(parsed.query)["X-Amz-Algorithm"] == ["AWS4-HMAC-SHA256"]
