"""Parse stage Lambda: uploads bucket -> findings.json in the artifacts bucket.

Step Functions passes the state input straight through, so the handler returns
its event unchanged and the next state sees the same shape.
"""
from __future__ import annotations

from app.core.stages import run_parse_stage
from app.lambdas import common


def handler(event: dict, context: object = None) -> dict:
    job_id = common.job_id_from(event)
    filenames = event.get("inputFilenames") or []
    if not filenames:
        raise RuntimeError(f"job {job_id} has no input filenames")

    ok = run_parse_stage(
        job_id,
        list(filenames),
        common.artifact_store(),
        common.job_store(),
        work_dir=common.work_dir(job_id),
        input_store=common.upload_store(),
    )
    if not ok:
        # The stage already recorded a user-safe error on the job record.
        raise common.StageFailed(f"parse stage failed for job {job_id}")
    return event
