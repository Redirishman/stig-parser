"""Bedrock enrichment stage — shell only; prompt logic lands in sub-project #4.

The state machine only routes here when the API gate decided AI is on, so
reaching this handler with no model configured is a misconfiguration, not a
normal path.

Spec §4.1 (AI determinism/provenance) is binding on this stage:

* Availability degrades **loudly, never silently.** Enrichment failing must not
  fail the job — the operator still gets their findings report — but the job
  record must say so via the ``ai`` gate field rather than quietly omitting the
  AI sections.
* Model + region provenance is recorded on the job so a reviewer can tell which
  model drafted any AI text.
* Any AI-authored text is labeled AI-drafted downstream (#4's contract).
"""
from __future__ import annotations

import logging
import os

from app.lambdas import common

log = logging.getLogger(__name__)


def handler(event: dict, context: object = None) -> dict:
    job_id = common.job_id_from(event)
    jobs = common.job_store()

    model_id = os.environ.get("BEDROCK_MODEL_ID", "")
    if not model_id:
        # Reached only if the Choice state let an unconfigured job through.
        log.warning("enricher invoked for job %s with no BEDROCK_MODEL_ID", job_id)
        jobs.update(
            job_id,
            ai="disabled-globally",
            ai_error="No Bedrock model is configured for this deployment.",
        )
        return event

    # Sub-project #4 replaces this branch with the real Bedrock call. Until it
    # lands, say so on the record instead of pretending enrichment happened.
    log.warning("enrichment requested for job %s but is not implemented yet", job_id)
    jobs.update(
        job_id,
        ai="failed",
        ai_error="AI enrichment is not available in this build.",
        ai_model_id=model_id,
        ai_region=os.environ.get("BEDROCK_REGION", common.region()),
    )
    return event
