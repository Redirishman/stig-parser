"""Export stage Lambda: findings.json -> report.xlsx, and mark the job complete."""
from __future__ import annotations

import logging

from app.core.stages import run_export_stage
from app.lambdas import common

log = logging.getLogger(__name__)


def handler(event: dict, context: object = None) -> dict:
    job_id = common.job_id_from(event)
    jobs = common.job_store()

    ok = run_export_stage(
        job_id,
        common.artifact_store(),
        jobs,
        work_dir=common.work_dir(job_id),
    )
    if not ok:
        # The stage already recorded a user-safe error on the job record.
        raise common.StageFailed(f"export stage failed for job {job_id}")

    _settle_ai_gate(job_id, jobs)
    return event


def _settle_ai_gate(job_id: str, jobs) -> None:
    """Resolve an `ai` field still reading `requested` once export is done.

    The API sets ai=requested when it starts the pipeline; the enricher then
    overwrites it. If the enricher was skipped by the Choice state or died hard
    enough to skip its own error path, the field would still say `requested` on
    a finished job — which reads as "AI ran" to the UI. Spec §4.1 requires the
    gate to state what actually happened, so an unresolved gate becomes `failed`.
    """
    record = jobs.get(job_id)
    if record.get("ai") != "requested":
        return
    log.warning("job %s finished with an unresolved AI gate — recording failure", job_id)
    jobs.update(
        job_id,
        ai="failed",
        ai_error="AI enrichment did not complete.",
    )
