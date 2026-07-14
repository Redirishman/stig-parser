"""Shared environment wiring for the Lambda handlers.

Every value the handlers need comes from the environment (Terraform
``modules/compute`` sets them). Missing required values raise at import-time of
the first call rather than failing deep inside a stage with a confusing error.
"""
from __future__ import annotations

import os
from pathlib import Path

from app.core.artifact_store import S3ArtifactStore
from app.core.job_store import DynamoJobStore

# Job records and artifacts are keyed off the job id; a stage re-run overwrites
# rather than appends (spec §6 idempotency contract), so /tmp reuse is safe.
WORK_ROOT = Path("/tmp")


class StageFailed(RuntimeError):
    """A stage returned False.

    The stage has already written a user-safe message onto the job record; this
    exception exists to make Step Functions' ``Catch`` fire. Stage entrypoints
    deliberately return ``bool`` instead of raising (so the Flask path can keep
    running in-process), which means a handler that ignored the return value
    would report success on a failed job.
    """


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required environment variable {name} is not set")
    return value


def region() -> str:
    # AWS_REGION is set by the Lambda runtime itself.
    return os.environ.get("AWS_REGION", "us-gov-west-1")


def artifact_store() -> S3ArtifactStore:
    """Store for generated artifacts (findings.json, report.xlsx)."""
    return S3ArtifactStore(_require("ARTIFACTS_BUCKET"), region())


def upload_store() -> S3ArtifactStore:
    """Store for raw operator uploads — a separate bucket with its own, shorter
    retention (D5), which is why the parse stage takes an ``input_store``."""
    return S3ArtifactStore(_require("UPLOADS_BUCKET"), region())


def job_store() -> DynamoJobStore:
    ttl_days = os.environ.get("JOB_TTL_DAYS")
    return DynamoJobStore(
        _require("JOB_TABLE"),
        region(),
        ttl_days=int(ttl_days) if ttl_days else None,
    )


def work_dir(job_id: str) -> Path:
    path = WORK_ROOT / job_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def job_id_from(event: dict) -> str:
    job_id = event.get("jobId")
    if not job_id:
        raise RuntimeError("event is missing required field 'jobId'")
    return str(job_id)
