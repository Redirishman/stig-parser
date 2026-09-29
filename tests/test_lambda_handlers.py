"""Lambda handler shims: env wiring, stage-failure propagation, API routes.

The stage logic itself is already covered by test_stages.py; what matters here
is the translation layer — that a failed stage becomes a raised exception (so
Step Functions' Catch fires rather than the job silently reporting success),
and that the API handler enforces the upload allow-list and the AI gate.
"""

import json

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from app.core.job_store import DynamoJobStore
from app.lambdas import api, common, enricher, exporter, mark_error, parser

REGION = "us-gov-west-1"
TABLE = "stig-jobs"
UPLOADS = "stig-uploads"
ARTIFACTS = "stig-artifacts"


@pytest.fixture
def aws(monkeypatch):
    """Mocked S3 + DynamoDB, with the environment the compute module sets."""
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        for bucket in (UPLOADS, ARTIFACTS):
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={"LocationConstraint": REGION},
            )
        dynamo = boto3.client("dynamodb", region_name=REGION)
        dynamo.create_table(
            TableName=TABLE,
            KeySchema=[{"AttributeName": "job_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "job_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        monkeypatch.setenv("AWS_REGION", REGION)
        monkeypatch.setenv("UPLOADS_BUCKET", UPLOADS)
        monkeypatch.setenv("ARTIFACTS_BUCKET", ARTIFACTS)
        monkeypatch.setenv("JOB_TABLE", TABLE)
        monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)
        monkeypatch.delenv("AI_KILLSWITCH_PARAM", raising=False)
        monkeypatch.delenv("IDENTITY_HEADER", raising=False)
        monkeypatch.delenv("S3_PRESIGN_ENDPOINT_URL", raising=False)
        yield


@pytest.fixture
def jobs(aws):
    return DynamoJobStore(TABLE, region=REGION)


class TestCommon:
    def test_missing_env_var_is_a_clear_error(self, aws, monkeypatch):
        monkeypatch.delenv("JOB_TABLE")
        with pytest.raises(RuntimeError, match="JOB_TABLE"):
            common.job_store()

    def test_ttl_written_only_when_configured(self, aws, monkeypatch):
        client = boto3.client("dynamodb", region_name=REGION)

        DynamoJobStore(TABLE, region=REGION).create("no-ttl", status="pending")
        item = client.get_item(TableName=TABLE, Key={"job_id": {"S": "no-ttl"}})["Item"]
        assert "expiresAt" not in item

        DynamoJobStore(TABLE, region=REGION, ttl_days=30).create(
            "ttl", status="pending"
        )
        item = client.get_item(TableName=TABLE, Key={"job_id": {"S": "ttl"}})["Item"]
        assert int(item["expiresAt"]["N"]) > 0

    def test_job_store_reads_ttl_days_from_env(self, aws, monkeypatch):
        monkeypatch.setenv("JOB_TTL_DAYS", "7")
        assert common.job_store()._ttl_days == 7


class TestStageHandlers:
    def test_parse_stage_failure_raises(self, aws, jobs):
        """A stage returning False must not look like success to Step Functions."""
        jobs.create("job1", status="queued")
        # No input object was ever uploaded, so the download fails.
        with pytest.raises(common.StageFailed):
            parser.handler({"jobId": "job1", "inputFilenames": ["scan.xml"]}, None)
        assert jobs.get("job1")["status"] == "error"

    def test_parse_rejects_event_with_no_filenames(self, aws, jobs):
        with pytest.raises(RuntimeError, match="no input filenames"):
            parser.handler({"jobId": "job1", "inputFilenames": []}, None)

    def test_export_stage_failure_raises(self, aws, jobs):
        jobs.create("job1", status="running")  # no findings.json exists
        with pytest.raises(common.StageFailed):
            exporter.handler({"jobId": "job1"}, None)
        assert jobs.get("job1")["status"] == "error"

    def test_missing_job_id_is_a_clear_error(self, aws):
        with pytest.raises(RuntimeError, match="jobId"):
            exporter.handler({}, None)

    def test_enricher_degrades_loudly_without_a_model(self, aws, jobs):
        jobs.create("job1", status="running")
        enricher.handler({"jobId": "job1"}, None)
        assert jobs.get("job1")["ai"] == "disabled-globally"

    def test_enricher_records_unavailability_not_silence(self, aws, jobs, monkeypatch):
        monkeypatch.setenv("BEDROCK_MODEL_ID", "some.model")
        jobs.create("job1", status="running")
        enricher.handler({"jobId": "job1"}, None)

        record = jobs.get("job1")
        # Enrichment is unimplemented, but the job still carries the report and
        # says plainly that AI did not run.
        assert record["ai"] == "failed"
        assert record["ai_model_id"] == "some.model"
        assert record["status"] != "error"


class TestApiUploads:
    def test_presigns_a_url_per_file_and_creates_the_job(self, aws, jobs):
        event = {
            "httpMethod": "POST",
            "resource": "/uploads",
            "body": json.dumps({"filenames": ["scan.xml", "bench.zip"]}),
        }
        resp = api.handler(event, None)
        body = json.loads(resp["body"])

        assert resp["statusCode"] == 201
        assert [u["filename"] for u in body["uploads"]] == ["scan.xml", "bench.zip"]
        assert all(u["url"].startswith("https://") for u in body["uploads"])
        assert jobs.get(body["jobId"])["status"] == "pending"

    @pytest.mark.parametrize(
        "filename",
        ["payload.exe", "../../etc/passwd", "nested/scan.xml", ""],
    )
    def test_rejects_disallowed_filenames(self, aws, filename):
        event = {
            "httpMethod": "POST",
            "resource": "/uploads",
            "body": json.dumps({"filenames": [filename]}),
        }
        resp = api.handler(event, None)
        assert resp["statusCode"] == 400

    def test_rejects_empty_request(self, aws):
        resp = api.handler(
            {"httpMethod": "POST", "resource": "/uploads", "body": "{}"}, None
        )
        assert resp["statusCode"] == 400

    def test_records_identity_header_when_configured(self, aws, jobs, monkeypatch):
        monkeypatch.setenv("IDENTITY_HEADER", "x-forwarded-user")
        event = {
            "httpMethod": "POST",
            "resource": "/uploads",
            "headers": {"X-Forwarded-User": "operator@example.mil"},
            "body": json.dumps({"filenames": ["scan.xml"]}),
        }
        body = json.loads(api.handler(event, None)["body"])
        assert jobs.get(body["jobId"])["submitted_by"] == "operator@example.mil"


class TestApiJobs:
    def _start(self, monkeypatch, calls):
        """Capture the Step Functions StartExecution call without a real client."""
        monkeypatch.setenv("STATE_MACHINE_ARN", "arn:aws-us-gov:states:::sm")

        class FakeSfn:
            def start_execution(self, **kwargs):
                calls.append(kwargs)
                return {"executionArn": "arn:aws-us-gov:states:::exec"}

        real_client = boto3.client

        def fake_client(service, **kwargs):
            if service == "stepfunctions":
                return FakeSfn()
            return real_client(service, **kwargs)

        monkeypatch.setattr(api.boto3, "client", fake_client)

    def test_starts_execution_named_for_the_job(self, aws, jobs, monkeypatch):
        calls = []
        self._start(monkeypatch, calls)
        jobs.create("job1", status="pending", input_filenames=["scan.xml"])

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs",
                "body": json.dumps({"jobId": "job1"}),
            },
            None,
        )

        assert resp["statusCode"] == 202
        # Name + canonical input form the Standard-workflow idempotency key, so
        # a double-submit resumes the same execution instead of starting two.
        assert calls[0]["name"] == "job1"
        assert json.loads(calls[0]["input"])["inputFilenames"] == ["scan.xml"]
        assert jobs.get("job1")["status"] == "queued"

    def test_owner_can_start_their_job(self, aws, jobs, monkeypatch):
        calls = []
        self._start(monkeypatch, calls)
        monkeypatch.setenv("IDENTITY_HEADER", "x-forwarded-user")
        jobs.create(
            "job1",
            status="pending",
            input_filenames=["scan.xml"],
            submitted_by="owner@example.mil",
        )

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs",
                "headers": {"X-Forwarded-User": "owner@example.mil"},
                "body": json.dumps({"jobId": "job1"}),
            },
            None,
        )

        assert resp["statusCode"] == 202
        assert len(calls) == 1
        assert jobs.get("job1")["status"] == "queued"

    def test_owner_can_resume_their_queued_job(self, aws, jobs, monkeypatch):
        calls = []
        self._start(monkeypatch, calls)
        monkeypatch.setenv("IDENTITY_HEADER", "x-forwarded-user")
        launch_input = json.dumps(
            {
                "jobId": "job1",
                "inputFilenames": ["scan.xml"],
                "aiEnabled": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        jobs.create(
            "job1",
            status="queued",
            input_filenames=["scan.xml"],
            submitted_by="owner@example.mil",
            ai="disabled-globally",
            execution_input=launch_input,
        )

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs",
                "headers": {"X-Forwarded-User": "owner@example.mil"},
                "body": json.dumps({"jobId": "job1"}),
            },
            None,
        )

        assert resp["statusCode"] == 202
        assert calls[0]["input"] == launch_input

    @pytest.mark.parametrize(
        ("status", "headers"),
        [
            pytest.param(
                "pending",
                {"X-Forwarded-User": "other@example.mil"},
                id="different-owner",
            ),
            pytest.param("queued", {}, id="missing-identity"),
        ],
    )
    def test_non_owner_cannot_start_or_resume_job(
        self, aws, jobs, monkeypatch, status, headers
    ):
        calls = []
        self._start(monkeypatch, calls)
        monkeypatch.setenv("IDENTITY_HEADER", "x-forwarded-user")
        queued_fields = {"ai": "disabled-globally"} if status == "queued" else {}
        jobs.create(
            "job1",
            status=status,
            input_filenames=["scan.xml"],
            submitted_by="owner@example.mil",
            **queued_fields,
        )

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs",
                "headers": headers,
                "body": json.dumps({"jobId": "job1"}),
            },
            None,
        )

        assert resp["statusCode"] == 404
        assert json.loads(resp["body"]) == {"error": "Unknown job."}
        assert calls == []
        record = jobs.get("job1")
        assert record["status"] == status
        assert "execution_input" not in record

    def test_legacy_unowned_job_remains_startable(self, aws, jobs, monkeypatch):
        calls = []
        self._start(monkeypatch, calls)
        monkeypatch.setenv("IDENTITY_HEADER", "x-forwarded-user")
        jobs.create("job1", status="pending", input_filenames=["scan.xml"])

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs",
                "headers": {"X-Forwarded-User": "operator@example.mil"},
                "body": json.dumps({"jobId": "job1"}),
            },
            None,
        )

        assert resp["statusCode"] == 202
        assert len(calls) == 1
        assert jobs.get("job1")["status"] == "queued"

    def test_queued_launch_intent_is_resumable_with_exact_same_input(
        self, aws, jobs, monkeypatch
    ):
        """A crash after queueing but before StartExecution must be recoverable."""
        calls = []
        self._start(monkeypatch, calls)
        launch_input = json.dumps(
            {
                "jobId": "job1",
                "inputFilenames": ["scan.xml"],
                "aiEnabled": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        jobs.create(
            "job1",
            status="queued",
            input_filenames=["scan.xml"],
            ai="disabled-globally",
            execution_input=launch_input,
        )

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs",
                "body": json.dumps({"jobId": "job1", "ai": True}),
            },
            None,
        )

        assert resp["statusCode"] == 202
        assert calls[0]["input"] == launch_input
        assert jobs.get("job1")["status"] == "queued"

    def test_uncertain_start_is_retried_with_same_idempotency_key(
        self, aws, jobs, monkeypatch
    ):
        monkeypatch.setenv("STATE_MACHINE_ARN", "arn:aws-us-gov:states:::sm")
        calls = []

        class FakeSfn:
            def start_execution(self, **kwargs):
                calls.append(kwargs)
                if len(calls) == 1:
                    raise RuntimeError("connection dropped after send")
                return {"executionArn": "arn:aws-us-gov:states:::exec"}

        real_client = boto3.client
        monkeypatch.setattr(
            api.boto3,
            "client",
            lambda service, **kwargs: (
                FakeSfn()
                if service == "stepfunctions"
                else real_client(service, **kwargs)
            ),
        )
        jobs.create("job1", status="pending", input_filenames=["scan.xml"])

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs",
                "body": json.dumps({"jobId": "job1"}),
            },
            None,
        )

        assert resp["statusCode"] == 202
        assert len(calls) == 2
        assert calls[0]["name"] == calls[1]["name"] == "job1"
        assert calls[0]["input"] == calls[1]["input"]

    def test_eventually_consistent_not_found_keeps_launch_queued(
        self, aws, jobs, monkeypatch
    ):
        monkeypatch.setenv("STATE_MACHINE_ARN", "arn:aws-us-gov:states:::sm")

        class _ExecutionDoesNotExist(Exception):
            pass

        class FakeExceptions:
            ExecutionDoesNotExist = _ExecutionDoesNotExist

        class FakeSfn:
            exceptions = FakeExceptions()

            def start_execution(self, **kwargs):
                raise RuntimeError("not accepted")

            def describe_execution(self, **kwargs):
                raise _ExecutionDoesNotExist()

        real_client = boto3.client
        monkeypatch.setattr(
            api.boto3,
            "client",
            lambda service, **kwargs: (
                FakeSfn()
                if service == "stepfunctions"
                else real_client(service, **kwargs)
            ),
        )
        jobs.create("job1", status="pending", input_filenames=["scan.xml"])

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs",
                "body": json.dumps({"jobId": "job1"}),
            },
            None,
        )

        assert resp["statusCode"] == 202
        assert jobs.get("job1")["status"] == "queued"

    def test_legacy_running_execution_is_recovered_without_reclassification(
        self, aws, jobs, monkeypatch
    ):
        monkeypatch.setenv("STATE_MACHINE_ARN", "arn:aws-us-gov:states:::sm")
        calls = []

        class _ExecutionDoesNotExist(Exception):
            pass

        class FakeExceptions:
            ExecutionDoesNotExist = _ExecutionDoesNotExist

        class FakeSfn:
            exceptions = FakeExceptions()

            def start_execution(self, **kwargs):
                calls.append(kwargs)
                raise ClientError(
                    {
                        "Error": {
                            "Code": "ExecutionAlreadyExists",
                            "Message": "same name is already running",
                        }
                    },
                    "StartExecution",
                )

            def describe_execution(self, **kwargs):
                return {"status": "RUNNING"}

        real_client = boto3.client
        monkeypatch.setattr(
            api.boto3,
            "client",
            lambda service, **kwargs: (
                FakeSfn()
                if service == "stepfunctions"
                else real_client(service, **kwargs)
            ),
        )
        jobs.create(
            "job1",
            status="queued",
            input_filenames=["scan.xml"],
            ai="disabled-globally",
        )
        old_input = json.dumps(
            {
                "jobId": "job1",
                "inputFilenames": ["scan.xml"],
                "aiEnabled": False,
            }
        )

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs",
                "body": json.dumps({"jobId": "job1"}),
            },
            None,
        )

        assert resp["statusCode"] == 202
        assert calls[0]["input"] == old_input
        assert jobs.get("job1")["execution_input"] == old_input
        assert jobs.get("job1")["status"] == "queued"

    def test_cancel_during_start_stops_late_execution(self, aws, jobs, monkeypatch):
        monkeypatch.setenv("STATE_MACHINE_ARN", "arn:aws-us-gov:states:::sm")
        stops = []

        class _ExecutionDoesNotExist(Exception):
            pass

        class FakeExceptions:
            ExecutionDoesNotExist = _ExecutionDoesNotExist

        class FakeSfn:
            exceptions = FakeExceptions()

            def start_execution(self, **kwargs):
                assert jobs.transition("job1", "cancelled", progress="Cancelled.")
                return {"executionArn": "arn:aws-us-gov:states:::exec"}

            def stop_execution(self, **kwargs):
                stops.append(kwargs)

        real_client = boto3.client
        monkeypatch.setattr(
            api.boto3,
            "client",
            lambda service, **kwargs: (
                FakeSfn()
                if service == "stepfunctions"
                else real_client(service, **kwargs)
            ),
        )
        jobs.create("job1", status="pending", input_filenames=["scan.xml"])

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs",
                "body": json.dumps({"jobId": "job1"}),
            },
            None,
        )

        assert resp["statusCode"] == 409
        assert jobs.get("job1")["status"] == "cancelled"
        assert len(stops) == 1

    def test_unknown_job_is_404(self, aws, monkeypatch):
        self._start(monkeypatch, [])
        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs",
                "body": json.dumps({"jobId": "nope"}),
            },
            None,
        )
        assert resp["statusCode"] == 404

    def test_cancelled_job_is_not_started_by_an_in_flight_submit(
        self, aws, jobs, monkeypatch
    ):
        """The cancel-beats-start race: a cancelled record must stay cancelled.

        POST /jobs/{id}/cancel can land while POST /jobs is still in flight. The
        operator has already been told the job was cancelled and no longer holds
        the job id — so the late start must be refused, or the pipeline runs a job
        nobody can see or reach.
        """
        calls = []
        self._start(monkeypatch, calls)
        jobs.create("job1", status="pending", input_filenames=["scan.xml"])

        # The cancel wins the race.
        jobs.transition("job1", "cancelled", progress="Cancelled.")

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs",
                "body": json.dumps({"jobId": "job1"}),
            },
            None,
        )

        assert resp["statusCode"] == 409
        assert calls == []  # no execution started
        assert jobs.get("job1")["status"] == "cancelled"  # not flipped to queued
        assert "cancelled" in json.loads(resp["body"])["error"]

    def test_cancel_winning_after_start_read_does_not_launch_execution(
        self, aws, jobs, monkeypatch
    ):
        """Reproduce the vulnerable read/write interleaving deterministically."""
        calls = []
        self._start(monkeypatch, calls)
        jobs.create("job1", status="pending", input_filenames=["scan.xml"])

        class CancelBeforeQueue:
            def __init__(self, wrapped):
                self._wrapped = wrapped
                self._injected = False

            def transition(self, job_id, to_status, **fields):
                if to_status == "queued" and not self._injected:
                    self._injected = True
                    assert self._wrapped.transition(
                        job_id, "cancelled", progress="Cancelled."
                    )
                return self._wrapped.transition(job_id, to_status, **fields)

            def __getattr__(self, name):
                return getattr(self._wrapped, name)

        monkeypatch.setattr(api.common, "job_store", lambda: CancelBeforeQueue(jobs))

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs",
                "body": json.dumps({"jobId": "job1"}),
            },
            None,
        )

        assert resp["statusCode"] == 409
        assert calls == []
        assert jobs.get("job1")["status"] == "cancelled"

    @pytest.mark.parametrize("status", ["complete", "error"])
    def test_settled_job_is_not_restarted(self, aws, jobs, monkeypatch, status):
        calls = []
        self._start(monkeypatch, calls)
        jobs.create("job1", status=status, input_filenames=["scan.xml"])

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs",
                "body": json.dumps({"jobId": "job1"}),
            },
            None,
        )

        assert resp["statusCode"] == 409
        assert calls == []
        assert jobs.get("job1")["status"] == status

    def test_pending_job_still_starts_normally(self, aws, jobs, monkeypatch):
        """The guard must not break the ordinary path."""
        calls = []
        self._start(monkeypatch, calls)
        jobs.create("job1", status="pending", input_filenames=["scan.xml"])

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs",
                "body": json.dumps({"jobId": "job1"}),
            },
            None,
        )

        assert resp["statusCode"] == 202
        assert len(calls) == 1
        assert jobs.get("job1")["status"] == "queued"

    def test_ai_off_when_no_model_configured(self, aws, jobs, monkeypatch):
        calls = []
        self._start(monkeypatch, calls)
        jobs.create("job1", status="pending", input_filenames=["scan.xml"])

        api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs",
                "body": json.dumps({"jobId": "job1", "ai": True}),
            },
            None,
        )

        # Asked for AI, but none is configured — say so, don't silently drop it.
        assert json.loads(calls[0]["input"])["aiEnabled"] is False
        assert jobs.get("job1")["ai"] == "disabled-globally"

    def test_ai_off_by_request(self, aws, jobs, monkeypatch):
        calls = []
        self._start(monkeypatch, calls)
        monkeypatch.setenv("BEDROCK_MODEL_ID", "some.model")
        jobs.create("job1", status="pending", input_filenames=["scan.xml"])

        api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs",
                "body": json.dumps({"jobId": "job1", "ai": False}),
            },
            None,
        )
        assert json.loads(calls[0]["input"])["aiEnabled"] is False
        assert jobs.get("job1")["ai"] == "disabled-by-request"

    def test_ai_on_when_model_configured_and_requested(self, aws, jobs, monkeypatch):
        calls = []
        self._start(monkeypatch, calls)
        monkeypatch.setenv("BEDROCK_MODEL_ID", "some.model")
        jobs.create("job1", status="pending", input_filenames=["scan.xml"])

        api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs",
                "body": json.dumps({"jobId": "job1", "ai": True}),
            },
            None,
        )
        assert json.loads(calls[0]["input"])["aiEnabled"] is True

    def test_killswitch_failure_disables_ai(self, aws, monkeypatch):
        """An unreadable killswitch must fail closed, not ignore the operator."""
        monkeypatch.setenv("BEDROCK_MODEL_ID", "some.model")
        monkeypatch.setenv("AI_KILLSWITCH_PARAM", "/stig/ai-enabled")
        # No SSM parameter exists, so the read raises.
        enabled, reason = api._ai_gate(requested=True)
        assert enabled is False
        assert reason == "disabled-globally"


class TestApiStatusAndResult:
    def test_status_returns_the_record(self, aws, jobs):
        jobs.create("job1", status="running", progress="Parsing…")
        resp = api.handler(
            {
                "httpMethod": "GET",
                "resource": "/jobs/{job_id}",
                "pathParameters": {"job_id": "job1"},
            },
            None,
        )
        body = json.loads(resp["body"])
        assert resp["statusCode"] == 200
        assert body["status"] == "running"
        assert body["progress"] == "Parsing…"

    def test_result_presigns_the_report(self, aws, jobs):
        jobs.create("job1", status="complete")
        boto3.client("s3", region_name=REGION).put_object(
            Bucket=ARTIFACTS, Key="jobs/job1/report.xlsx", Body=b"xlsx"
        )
        resp = api.handler(
            {
                "httpMethod": "GET",
                "resource": "/jobs/{job_id}/result",
                "pathParameters": {"job_id": "job1"},
            },
            None,
        )
        assert resp["statusCode"] == 200
        assert json.loads(resp["body"])["url"].startswith("https://")

    def test_result_conflicts_while_still_running(self, aws, jobs):
        jobs.create("job1", status="running")
        resp = api.handler(
            {
                "httpMethod": "GET",
                "resource": "/jobs/{job_id}/result",
                "pathParameters": {"job_id": "job1"},
            },
            None,
        )
        assert resp["statusCode"] == 409

    def test_expired_report_is_gone_not_a_broken_url(self, aws, jobs):
        """Retention (D5) can expire the object while the job row survives."""
        jobs.create("job1", status="complete")  # no object in the bucket
        resp = api.handler(
            {
                "httpMethod": "GET",
                "resource": "/jobs/{job_id}/result",
                "pathParameters": {"job_id": "job1"},
            },
            None,
        )
        assert resp["statusCode"] == 410

    def test_unknown_route_is_404(self, aws):
        resp = api.handler({"httpMethod": "DELETE", "resource": "/jobs"}, None)
        assert resp["statusCode"] == 404

    def test_internal_errors_do_not_leak_detail(self, aws, jobs, monkeypatch):
        def boom(*a, **kw):
            raise RuntimeError("secret internal detail")

        monkeypatch.setattr(api.common, "job_store", boom)
        resp = api.handler(
            {
                "httpMethod": "GET",
                "resource": "/jobs/{job_id}",
                "pathParameters": {"job_id": "job1"},
            },
            None,
        )
        assert resp["statusCode"] == 500
        assert "secret internal detail" not in resp["body"]


class TestMarkError:
    def test_records_failure_when_a_stage_died_hard(self, aws, jobs):
        """An OOM/timeout kill never reaches a stage's own error path, so the job
        would otherwise sit at `running` forever."""
        jobs.create("job1", status="running", progress="Parsing…")

        mark_error.handler(
            {"jobId": "job1", "error": {"Cause": "Runtime exited: out of memory"}}, None
        )

        record = jobs.get("job1")
        assert record["status"] == "error"
        assert record["error"] == mark_error.GENERIC_ERROR

    def test_keeps_the_specific_reason_a_stage_already_recorded(self, aws, jobs):
        jobs.create("job1", status="error", error="Unsupported file type: 'x.exe'")

        mark_error.handler({"jobId": "job1", "error": {"Cause": "StageFailed"}}, None)

        # The stage's curated message is more useful than the generic one.
        assert jobs.get("job1")["error"] == "Unsupported file type: 'x.exe'"

    def test_never_leaks_the_raw_cause_to_the_operator(self, aws, jobs):
        jobs.create("job1", status="running")

        mark_error.handler(
            {"jobId": "job1", "error": {"Cause": 'Traceback... File "/var/task/app"'}},
            None,
        )

        assert "Traceback" not in jobs.get("job1")["error"]

    def test_cancelled_job_is_not_reclassified_as_error(self, aws, jobs):
        jobs.create("job1", status="cancelled", progress="Cancelled.")

        mark_error.handler({"jobId": "job1", "error": {"Cause": "StageFailed"}}, None)

        assert jobs.get("job1") == {
            "status": "cancelled",
            "progress": "Cancelled.",
        }


class TestAiGateSettles:
    def _seed_findings(self, job_id="job1"):
        """Seed one real finding — the exporter refuses to build an empty workbook."""
        from app.core.findings_io import findings_to_json
        from app.core.stages import FINDINGS_KEY
        from app.parsers.base import Finding

        finding = Finding(
            stig_title="Example STIG",
            vuln_id="V-12345",
            rule_id="SV-12345r1_rule",
            severity="CAT II",
            status="Open",
            server="host1",
            ip_address="192.0.2.10",
            check_text="Check it.",
            fix_text="Fix it.",
        )
        boto3.client("s3", region_name=REGION).put_object(
            Bucket=ARTIFACTS,
            Key=FINDINGS_KEY.format(job_id=job_id),
            Body=findings_to_json([finding]).encode("utf-8"),
        )

    def test_unresolved_gate_becomes_failed_before_completion(
        self, aws, jobs, monkeypatch
    ):
        """If the enricher dies hard, `ai` would still read `requested` on a
        finished job — which reads as 'AI ran' to the UI."""
        jobs.create("job1", status="running", ai="requested", source_file_count=1)
        self._seed_findings()

        class AssertSettledBeforeComplete:
            def transition(self, job_id, to_status, **fields):
                if to_status == "complete":
                    assert jobs.get(job_id)["ai"] == "failed"
                return jobs.transition(job_id, to_status, **fields)

            def __getattr__(self, name):
                return getattr(jobs, name)

        monkeypatch.setattr(
            exporter.common, "job_store", lambda: AssertSettledBeforeComplete()
        )

        exporter.handler({"jobId": "job1"}, None)

        record = jobs.get("job1")
        assert record["status"] == "complete"
        assert record["ai"] == "failed"
        assert record["ai_error"]

    def test_a_resolved_gate_is_left_alone(self, aws, jobs):
        jobs.create(
            "job1", status="running", ai="disabled-by-request", source_file_count=1
        )
        self._seed_findings()

        exporter.handler({"jobId": "job1"}, None)

        assert jobs.get("job1")["ai"] == "disabled-by-request"


class TestApiConfig:
    """The client cannot render the AI control or validate a file without these."""

    def test_reports_ai_unavailable_with_a_reason(self, aws):
        resp = api.handler({"httpMethod": "GET", "resource": "/config"}, None)
        body = json.loads(resp["body"])

        assert resp["statusCode"] == 200
        assert body["aiAvailable"] is False
        # A bare "false" would leave the UI unable to say WHY — the silent gate
        # the spec forbids.
        assert body["aiReason"] == "disabled-globally"

    def test_reports_ai_available_when_a_model_is_configured(self, aws, monkeypatch):
        monkeypatch.setenv("BEDROCK_MODEL_ID", "some.model")
        body = json.loads(
            api.handler({"httpMethod": "GET", "resource": "/config"}, None)["body"]
        )
        assert body["aiAvailable"] is True
        assert body["aiReason"] is None

    def test_serves_the_shared_upload_allow_list(self, aws):
        """Served, not hardcoded in the client — otherwise the list forks."""
        from app.core.uploads import ALLOWED_UPLOAD_EXT, MAX_UPLOAD_BYTES

        body = json.loads(
            api.handler({"httpMethod": "GET", "resource": "/config"}, None)["body"]
        )
        assert set(body["allowedExtensions"]) == ALLOWED_UPLOAD_EXT
        assert body["maxUploadBytes"] == MAX_UPLOAD_BYTES


class TestApiCancel:
    def _fake_sfn(
        self,
        monkeypatch,
        calls,
        raises=None,
        raise_missing=False,
        on_stop=None,
    ):
        monkeypatch.setenv(
            "STATE_MACHINE_ARN",
            "arn:aws-us-gov:states:us-gov-west-1:111111111111:stateMachine:stig",
        )

        class _ExecutionDoesNotExist(Exception):
            pass

        class FakeExceptions:
            # Bound to a differently-named outer class on purpose: inside a class
            # body, `X = X` resolves the right-hand side in the global scope, not
            # the enclosing function's, and would raise NameError.
            ExecutionDoesNotExist = _ExecutionDoesNotExist

        class FakeSfn:
            exceptions = FakeExceptions()

            def stop_execution(self, **kwargs):
                calls.append(kwargs)
                if on_stop:
                    on_stop()
                if raise_missing:
                    # Must be raised from THIS fake's class — the handler catches
                    # sfn.exceptions.ExecutionDoesNotExist off the same client.
                    raise _ExecutionDoesNotExist()
                if raises:
                    raise raises

        real_client = boto3.client

        def fake_client(service, **kwargs):
            if service == "stepfunctions":
                return FakeSfn()
            return real_client(service, **kwargs)

        monkeypatch.setattr(api.boto3, "client", fake_client)
        return _ExecutionDoesNotExist

    def test_stops_the_execution_and_marks_the_job(self, aws, jobs, monkeypatch):
        calls = []
        self._fake_sfn(monkeypatch, calls)
        jobs.create("job1", status="running")

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs/{job_id}/cancel",
                "pathParameters": {"job_id": "job1"},
            },
            None,
        )

        assert resp["statusCode"] == 200
        assert json.loads(resp["body"])["status"] == "cancelled"
        assert jobs.get("job1")["status"] == "cancelled"
        # StopExecution takes an EXECUTION arn, not the state machine arn.
        assert calls[0]["executionArn"] == (
            "arn:aws-us-gov:states:us-gov-west-1:111111111111:execution:stig:job1"
        )

    def test_finished_job_reports_its_real_status_not_cancelled(
        self, aws, jobs, monkeypatch
    ):
        """The job can finish between the click and StopExecution landing.
        Claiming a completed job was cancelled is a lie the operator acts on."""
        calls = []
        self._fake_sfn(monkeypatch, calls)
        jobs.create("job1", status="complete")

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs/{job_id}/cancel",
                "pathParameters": {"job_id": "job1"},
            },
            None,
        )

        assert json.loads(resp["body"])["status"] == "complete"
        assert not calls  # nothing to stop
        assert jobs.get("job1")["status"] == "complete"

    def test_missing_execution_still_settles_the_job(self, aws, jobs, monkeypatch):
        """The execution can age out; the job record is still ours to settle."""
        calls = []
        self._fake_sfn(monkeypatch, calls, raise_missing=True)
        jobs.create("job1", status="running")

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs/{job_id}/cancel",
                "pathParameters": {"job_id": "job1"},
            },
            None,
        )

        assert resp["statusCode"] == 200
        assert jobs.get("job1")["status"] == "cancelled"

    def test_completion_winning_during_stop_reports_actual_status(
        self, aws, jobs, monkeypatch
    ):
        calls = []
        jobs.create("job1", status="running")
        self._fake_sfn(
            monkeypatch,
            calls,
            on_stop=lambda: jobs.transition(
                "job1", "complete", progress="Done.", summary={"findings": 1}
            ),
        )

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs/{job_id}/cancel",
                "pathParameters": {"job_id": "job1"},
            },
            None,
        )

        assert resp["statusCode"] == 200
        assert json.loads(resp["body"])["status"] == "complete"
        assert jobs.get("job1")["status"] == "complete"

    def test_unknown_job_is_404(self, aws, monkeypatch):
        self._fake_sfn(monkeypatch, [])
        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs/{job_id}/cancel",
                "pathParameters": {"job_id": "nope"},
            },
            None,
        )
        assert resp["statusCode"] == 404

    def test_stop_failure_does_not_claim_success(self, aws, jobs, monkeypatch):
        self._fake_sfn(monkeypatch, [], raises=RuntimeError("boom"))
        jobs.create("job1", status="running")

        resp = api.handler(
            {
                "httpMethod": "POST",
                "resource": "/jobs/{job_id}/cancel",
                "pathParameters": {"job_id": "job1"},
            },
            None,
        )

        assert resp["statusCode"] == 500
        # The job is still running — do not mark it cancelled when it is not.
        assert jobs.get("job1")["status"] == "running"
