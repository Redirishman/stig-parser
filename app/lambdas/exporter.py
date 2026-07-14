"""Export stage Lambda: findings.json -> report.xlsx, and mark the job complete."""
from __future__ import annotations

from app.core.stages import run_export_stage
from app.lambdas import common


def handler(event: dict, context: object = None) -> dict:
    job_id = common.job_id_from(event)

    ok = run_export_stage(
        job_id,
        common.artifact_store(),
        common.job_store(),
        work_dir=common.work_dir(job_id),
    )
    if not ok:
        # The stage already recorded a user-safe error on the job record.
        raise common.StageFailed(f"export stage failed for job {job_id}")
    return event
