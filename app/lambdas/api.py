"""API Lambda: the only synchronous handler, behind the Private API Gateway.

Routes (REST API proxy integration):

    GET  /config                 -> AI gate + upload limits (the client needs
                                    both BEFORE it can render or validate)
    POST /uploads                -> create a job, return presigned PUT urls
    POST /jobs                   -> start the Step Functions execution
    GET  /jobs/{job_id}          -> job status record
    GET  /jobs/{job_id}/result   -> presigned GET url for report.xlsx
    POST /jobs/{job_id}/cancel   -> stop the execution, mark the job cancelled

Uploads never pass through this function: the browser PUTs straight to S3 with
a presigned url, which keeps the 29-second API Gateway timeout and the Lambda
payload cap off the critical path for a 200 MB scan file.

Auth is upstream (VPN + whatever the org fronts this with). The identity header
named by ``IDENTITY_HEADER`` is recorded on the job for audit and used for
defense-in-depth job ownership checks. It is *not* the primary trust boundary;
the header must be injected by the trusted upstream identity layer.
"""

from __future__ import annotations

import json
import logging
import os
import uuid

import boto3

from app.core.job_store import TERMINAL_STATUSES
from app.core.stages import REPORT_KEY
from app.core.uploads import ALLOWED_UPLOAD_EXT, MAX_UPLOAD_BYTES, reject_filename
from app.lambdas import common

log = logging.getLogger(__name__)

PRESIGN_EXPIRY_SECONDS = 900

# Gate-transparency values for the job record's `ai` field (spec §4.1). The UI
# reports which of these applies, so AI being off is never silent.
AI_DISABLED_BY_REQUEST = "disabled-by-request"
AI_DISABLED_GLOBALLY = "disabled-globally"


def _response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _ai_gate(requested: bool) -> tuple[bool, str]:
    """Decide whether enrichment runs, and say why. Returns (enabled, reason).

    Off wins: no model configured, or the SSM killswitch thrown, disables AI
    regardless of what the caller asked for.
    """
    if not os.environ.get("BEDROCK_MODEL_ID"):
        return False, AI_DISABLED_GLOBALLY
    if _killswitch_thrown():
        return False, AI_DISABLED_GLOBALLY
    if not requested:
        return False, AI_DISABLED_BY_REQUEST
    return True, "requested"


def _killswitch_thrown() -> bool:
    """True if the SSM killswitch parameter says AI is off.

    Fails closed: if the parameter cannot be read, AI stays off. An operator
    who threw the killswitch must not have it silently ignored because of an
    unrelated SSM outage.
    """
    param = os.environ.get("AI_KILLSWITCH_PARAM")
    if not param:
        return False
    try:
        ssm = boto3.client("ssm", region_name=common.region())
        value = ssm.get_parameter(Name=param)["Parameter"]["Value"]
    except Exception:
        log.exception(
            "could not read AI killswitch %s — treating AI as disabled", param
        )
        return True
    return value.strip().lower() != "enabled"


def _identity(event: dict) -> str | None:
    header = os.environ.get("IDENTITY_HEADER")
    if not header:
        return None
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    return headers.get(header.lower())


def _owns(record: dict, event: dict) -> bool:
    """Defense-in-depth ownership check for job-scoped reads/actions.

    When identity capture is configured (``IDENTITY_HEADER`` set) and the job
    recorded a submitter, only that identity may access the job. This is a
    second layer, not the trust boundary — the header is network-injected and
    the VPC endpoint remains the primary gate — but it stops one operator, or
    anyone who obtains a job id, from reading another's compliance data.

    Allows access when the record has no ``submitted_by`` (identity capture was
    off when it was created) so existing jobs and single-user deployments are
    unaffected.
    """
    owner = record.get("submitted_by")
    if not owner:
        return True
    return _identity(event) == owner


def _body(event: dict) -> dict:
    raw = event.get("body") or "{}"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def _get_config() -> dict:
    """Everything the client must know before it can render or validate anything.

    Two things live only on the server, and a client that guesses at either is
    wrong:

    * **The AI gate.** Whether enrichment is available depends on the configured
      Bedrock model and the SSM killswitch. Without this endpoint the UI could
      only learn the gate *after* submitting a job — too late to tell the
      operator why the AI control is unavailable, which is the silent-failure
      mode the spec (§4.1) exists to prevent.
    * **The upload allow-list.** The client validates files for fast feedback.
      Hardcoding the extensions and size cap there would fork the list that
      app/core/uploads.py exists to keep single. Serving it means one source of
      truth.

    Client-side validation is a courtesy, never a control: every filename is
    re-validated server-side in _post_uploads, because a client check is
    bypassable by definition.
    """
    ai_available, ai_reason = _ai_gate(requested=True)
    return _response(
        200,
        {
            "aiAvailable": ai_available,
            # Why AI is unavailable, in the same vocabulary the job record uses.
            "aiReason": None if ai_available else ai_reason,
            "maxUploadBytes": MAX_UPLOAD_BYTES,
            "allowedExtensions": sorted(ALLOWED_UPLOAD_EXT),
        },
    )


def _post_cancel(job_id: str, event: dict) -> dict:
    """Stop a running execution and mark the job cancelled.

    Reports the job's ACTUAL resulting status rather than asserting "cancelled":
    an execution can finish in the window between the operator's click and
    StopExecution landing, and claiming a completed job was cancelled would be a
    lie the operator then acts on.
    """
    jobs = common.job_store()
    record = jobs.get(job_id)
    if not record or not _owns(record, event):
        return _response(404, {"error": "Unknown job."})

    status = record.get("status")
    if status in TERMINAL_STATUSES:
        # Already finished — nothing to stop. Report what actually happened.
        return _response(200, {"jobId": job_id, "status": status})

    sfn = boto3.client("stepfunctions", region_name=common.region())
    execution_arn = _execution_arn(job_id)
    try:
        sfn.stop_execution(
            executionArn=execution_arn,
            error="CancelledByOperator",
            cause="The operator cancelled this job.",
        )
    except sfn.exceptions.ExecutionDoesNotExist:
        # The execution finished and aged out, or never started. The job record
        # is still ours to settle.
        log.info("no live execution to stop for job %s", job_id)
    except Exception:
        # Completion may have won while StopExecution was in flight. Do not
        # turn that truthful terminal result into a cancellation error.
        latest = jobs.get(job_id)
        latest_status = latest.get("status")
        if latest_status in TERMINAL_STATUSES:
            return _response(200, {"jobId": job_id, "status": latest_status})
        log.exception("StopExecution failed for job %s", job_id)
        return _response(500, {"error": "Could not cancel the job — see server logs."})

    if jobs.transition(job_id, "cancelled", progress="Cancelled."):
        return _response(200, {"jobId": job_id, "status": "cancelled"})

    # A stage may have committed complete/error after our initial read. Return
    # that authoritative winner rather than claiming cancellation succeeded.
    latest = jobs.get(job_id)
    if not latest:
        return _response(404, {"error": "Unknown job."})
    latest_status = latest.get("status")
    if latest_status in TERMINAL_STATUSES:
        return _response(200, {"jobId": job_id, "status": latest_status})
    return _response(
        409,
        {
            "jobId": job_id,
            "status": latest_status,
            "error": "The job changed state before cancellation could complete.",
        },
    )


def _execution_arn(job_id: str) -> str:
    """The execution ARN for a job.

    Executions are named for the job id (see _post_jobs), so the ARN is derivable
    rather than something we must store.
    """
    state_machine_arn = os.environ["STATE_MACHINE_ARN"]
    # arn:<partition>:states:<region>:<account>:stateMachine:<name>
    #   -> arn:<partition>:states:<region>:<account>:execution:<name>:<job_id>
    prefix, _, name = state_machine_arn.rpartition(":stateMachine:")
    return f"{prefix}:execution:{name}:{job_id}"


def _execution_input(job_id: str, record: dict, ai_enabled: bool) -> str:
    """Return the canonical Step Functions input persisted with a launch intent.

    Standard-workflow ``StartExecution`` is idempotent only when both its name
    and input are identical. Persisting this exact string lets a retry resume a
    queued job after the first API invocation died between the DynamoDB commit
    and the AWS call.
    """
    return json.dumps(
        {
            "jobId": job_id,
            "inputFilenames": record.get("input_filenames", []),
            "aiEnabled": ai_enabled,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _legacy_execution_input(job_id: str, record: dict, ai_enabled: bool) -> str:
    """Reproduce the pre-launch-intent JSON bytes for an already-queued row."""
    return json.dumps(
        {
            "jobId": job_id,
            "inputFilenames": record.get("input_filenames", []),
            "aiEnabled": ai_enabled,
        }
    )


def _start_conflict(job_id: str, record: dict) -> dict:
    status = record.get("status", "unknown")
    log.info("refusing to start job %s — already %s", job_id, status)
    return _response(
        409,
        {
            "jobId": job_id,
            "status": status,
            "error": f"This job is already {status} and cannot be started.",
        },
    )


def _stop_late_cancelled_execution(sfn, job_id: str) -> None:
    """Best-effort compensation when cancellation wins during launch."""
    try:
        sfn.stop_execution(
            executionArn=_execution_arn(job_id),
            error="CancelledByOperator",
            cause="The operator cancelled this job before launch completed.",
        )
    except sfn.exceptions.ExecutionDoesNotExist:
        pass
    except Exception:
        # The parser's queued→running guard remains the final safety net.
        log.exception("could not stop late execution for cancelled job %s", job_id)


def _post_uploads(event: dict) -> dict:
    filenames = _body(event).get("filenames") or []
    if not isinstance(filenames, list) or not filenames:
        return _response(400, {"error": "Provide a non-empty 'filenames' list."})

    for name in filenames:
        rejection = reject_filename(str(name))
        if rejection:
            return _response(400, {"error": rejection})

    job_id = str(uuid.uuid4())
    uploads = common.upload_store()
    urls = [
        {
            "filename": name,
            "url": uploads.presign_put(
                f"jobs/{job_id}/input/{name}", expires=PRESIGN_EXPIRY_SECONDS
            ),
        }
        for name in filenames
    ]

    common.job_store().create(
        job_id,
        status="pending",
        progress="Awaiting upload…",
        input_filenames=[str(n) for n in filenames],
        submitted_by=_identity(event),
    )
    return _response(201, {"jobId": job_id, "uploads": urls})


def _post_jobs(event: dict) -> dict:
    body = _body(event)
    job_id = body.get("jobId")
    if not job_id:
        return _response(400, {"error": "Provide 'jobId'."})

    jobs = common.job_store()
    record = jobs.get(str(job_id))
    # Keep ownership failures indistinguishable from unknown ids and enforce the
    # check before queueing, persisting launch intent, or calling Step Functions.
    if not record or not _owns(record, event):
        return _response(404, {"error": "Unknown job."})

    job_id = str(job_id)
    if record.get("status") == "pending":
        # The read above supplies immutable input fields, but it is not the
        # start guard. This conditional transition arbitrates start vs cancel.
        ai_enabled, ai_reason = _ai_gate(bool(body.get("ai")))
        launch_input = _execution_input(job_id, record, ai_enabled)
        jobs.transition(
            job_id,
            "queued",
            progress="Queued…",
            ai=ai_reason if not ai_enabled else "requested",
            execution_input=launch_input,
        )
        # Whether this invocation won or another starter/canceller did, use the
        # authoritative record and its persisted launch intent from here on.
        record = jobs.get(job_id)

    if not record:
        return _response(404, {"error": "Unknown job."})
    if record.get("status") != "queued":
        return _start_conflict(job_id, record)

    ai_reason = record.get("ai", AI_DISABLED_GLOBALLY)
    launch_input = record.get("execution_input")
    if not isinstance(launch_input, str):
        # Backward compatibility for a queued row created before launch intents
        # were persisted. Its existing AI decision is the stable source of truth.
        launch_input = _legacy_execution_input(
            job_id, record, ai_enabled=ai_reason == "requested"
        )
        if not jobs.update_if_status(job_id, {"queued"}, execution_input=launch_input):
            latest = jobs.get(job_id)
            if not latest:
                return _response(404, {"error": "Unknown job."})
            return _start_conflict(job_id, latest)

    # Close the common queue-then-cancel window before making the external call.
    # A cancellation can still land one instruction later, so we reconcile again
    # after StartExecution and compensate there.
    latest = jobs.get(job_id)
    if latest.get("status") != "queued":
        return _start_conflict(job_id, latest)

    sfn = boto3.client("stepfunctions", region_name=common.region())
    start_error: Exception | None = None
    for attempt in range(2):
        try:
            sfn.start_execution(
                stateMachineArn=os.environ["STATE_MACHINE_ARN"],
                # A Standard workflow returns the original response for the same
                # running name+input, making a queued launch safely resumable.
                name=job_id,
                input=launch_input,
            )
            start_error = None
            break
        except Exception as exc:
            start_error = exc
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "ExecutionAlreadyExists":
                break
            if attempt == 0:
                log.warning(
                    "StartExecution outcome was uncertain for job %s; retrying "
                    "the persisted idempotent launch intent",
                    job_id,
                )

    if start_error is not None:
        # Both idempotent attempts failed (or the prior same-name execution may
        # already exist). Describe the deterministic ARN, but never treat one
        # not-found response as definitive: Step Functions documents this read
        # as eventually consistent. The durable queued intent remains retryable.
        try:
            execution = sfn.describe_execution(executionArn=_execution_arn(job_id))
        except sfn.exceptions.ExecutionDoesNotExist:
            current = jobs.get(job_id)
            if current.get("status") in TERMINAL_STATUSES:
                return _start_conflict(job_id, current)
            log.warning(
                "execution for queued job %s is not visible yet; leaving its "
                "launch intent queued for reconciliation",
                job_id,
            )
        except Exception:
            # Do not misclassify an execution that may be running. Status polling
            # periodically re-POSTs the persisted intent until it is confirmed.
            log.exception(
                "could not confirm Step Functions execution for job %s", job_id
            )
            current = jobs.get(job_id)
            if current.get("status") == "cancelled":
                _stop_late_cancelled_execution(sfn, job_id)
                return _start_conflict(job_id, current)
            if current.get("status") in TERMINAL_STATUSES:
                return _start_conflict(job_id, current)
        else:
            if execution.get("status") != "RUNNING":
                current = jobs.get(job_id)
                if current.get("status") in {"running", "complete"}:
                    return _response(202, {"jobId": job_id, "ai": ai_reason})
                if current.get("status") in TERMINAL_STATUSES:
                    return _start_conflict(job_id, current)
                jobs.transition(
                    job_id,
                    "error",
                    progress="Processing stopped before it could begin.",
                    error="The workflow ended before processing started.",
                )
                return _response(
                    500,
                    {"error": "Could not start the job — see server logs."},
                )

    # Cancellation can win after the queue commit but before StartExecution.
    # If so, stop the just-created execution and report the authoritative state
    # instead of returning a contradictory 202 after cancellation returned 200.
    current = jobs.get(job_id)
    if not current:
        return _response(404, {"error": "Unknown job."})
    if current.get("status") == "cancelled":
        _stop_late_cancelled_execution(sfn, job_id)
        return _start_conflict(job_id, current)
    if current.get("status") == "error":
        return _start_conflict(job_id, current)

    return _response(202, {"jobId": job_id, "ai": ai_reason})


def _get_job(job_id: str, event: dict) -> dict:
    record = common.job_store().get(job_id)
    # 404 (not 403) on an ownership mismatch so the response can't be used to
    # confirm a job id exists.
    if not record or not _owns(record, event):
        return _response(404, {"error": "Unknown job."})
    return _response(200, {"jobId": job_id, **record})


def _get_result(job_id: str, event: dict) -> dict:
    jobs = common.job_store()
    record = jobs.get(job_id)
    if not record or not _owns(record, event):
        return _response(404, {"error": "Unknown job."})
    if record.get("status") != "complete":
        return _response(409, {"error": "Report is not ready."})

    store = common.artifact_store()
    key = REPORT_KEY.format(job_id=job_id)
    if not store.exists(key):
        # Status says complete but the object is gone — most likely the artifact
        # retention window (D5) expired it. Say that rather than handing back a
        # presigned url that 404s.
        return _response(
            410, {"error": "Report has expired and is no longer available."}
        )

    return _response(
        200,
        {"url": store.presign_get(key, expires=PRESIGN_EXPIRY_SECONDS)},
    )


def handler(event: dict, context: object = None) -> dict:
    method = (event.get("httpMethod") or "").upper()
    resource = event.get("resource") or event.get("path") or ""
    job_id = (event.get("pathParameters") or {}).get("job_id")

    try:
        if method == "GET" and resource.endswith("/config"):
            return _get_config()
        if method == "POST" and resource.endswith("/uploads"):
            return _post_uploads(event)
        # Checked before the bare /jobs route: "/jobs/{job_id}/cancel" would
        # otherwise never match, since endswith("/jobs") is false but the
        # ordering below is what makes the distinction legible.
        if method == "POST" and resource.endswith("/cancel") and job_id:
            return _post_cancel(str(job_id), event)
        if method == "POST" and resource.endswith("/jobs"):
            return _post_jobs(event)
        if method == "GET" and resource.endswith("/result") and job_id:
            return _get_result(str(job_id), event)
        if method == "GET" and job_id:
            return _get_job(str(job_id), event)
    except Exception:
        # Never leak a stack trace or internal detail through the API.
        log.exception("unhandled error in API handler (%s %s)", method, resource)
        return _response(500, {"error": "Internal error — see server logs."})

    return _response(404, {"error": "No such route."})
