"""Terminal error handler — the target of every Step Functions Catch.

The stage handlers already write a user-safe error onto the job record before
raising, so on an orderly failure this is a no-op. It exists for the *disorderly*
ones: an OOM kill, a timeout, or an unhandled crash never reaches the stage's
own error path, and without this the job record would sit at `running` forever
while the operator watched a progress bar that would never move.
"""

from __future__ import annotations

import logging

from app.lambdas import common

log = logging.getLogger(__name__)

GENERIC_ERROR = "Processing failed — see server logs."


def handler(event: dict, context: object = None) -> dict:
    job_id = common.job_id_from(event)
    jobs = common.job_store()

    # The Catch puts the exception under `error` (see the ResultPath in the
    # orchestration module). Log the cause; never surface it to the operator —
    # it is a raw Python traceback.
    cause = (event.get("error") or {}).get("Cause")
    log.error("job %s failed: %s", job_id, cause)

    # Only queued/running records may enter error. A stage-specific error,
    # cancellation, or successful completion is terminal and therefore wins
    # this race without a separate read/check/write window.
    jobs.transition(job_id, "error", error=GENERIC_ERROR)
    return event
