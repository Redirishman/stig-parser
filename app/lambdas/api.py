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
named by ``IDENTITY_HEADER`` is recorded on the job for audit; it is *not* a
trust boundary — this function never makes an authorization decision from it.
"""
from __future__ import annotations

import json
import logging
import os
import uuid

import boto3

from app.core.stages import REPORT_KEY
from app.core.uploads import ALLOWED_UPLOAD_EXT, MAX_UPLOAD_BYTES, reject_filename
from app.lambdas import common

log = logging.getLogger(__name__)

PRESIGN_EXPIRY_SECONDS = 900

# Gate-transparency values for the job record's `ai` field (spec §4.1). The UI
# reports which of these applies, so AI being off is never silent.
AI_DISABLED_BY_REQUEST = "disabled-by-request"
AI_DISABLED_GLOBALLY = "disabled-globally"

# A job in one of these states is finished; there is nothing left to cancel.
TERMINAL_STATUSES = frozenset({"complete", "error", "cancelled"})


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
        log.exception("could not read AI killswitch %s — treating AI as disabled", param)
        return True
    return value.strip().lower() != "enabled"


def _identity(event: dict) -> str | None:
    header = os.environ.get("IDENTITY_HEADER")
    if not header:
        return None
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    return headers.get(header.lower())


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


def _post_cancel(job_id: str) -> dict:
    """Stop a running execution and mark the job cancelled.

    Reports the job's ACTUAL resulting status rather than asserting "cancelled":
    an execution can finish in the window between the operator's click and
    StopExecution landing, and claiming a completed job was cancelled would be a
    lie the operator then acts on.
    """
    jobs = common.job_store()
    record = jobs.get(job_id)
    if not record:
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
        log.exception("StopExecution failed for job %s", job_id)
        return _response(500, {"error": "Could not cancel the job — see server logs."})

    jobs.update(job_id, status="cancelled", progress="Cancelled.")
    return _response(200, {"jobId": job_id, "status": "cancelled"})


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
    if not record:
        return _response(404, {"error": "Unknown job."})

    # DO NOT REMOVE — this guard closes a real race, not a theoretical one.
    #
    # The client does POST /uploads -> upload -> POST /jobs. If the operator hits
    # Cancel while POST /jobs is still in flight, POST /jobs/{id}/cancel can land
    # FIRST: it finds no execution to stop (none started yet), marks the record
    # `cancelled`, and returns 200. The UI then drops the job id and tells the
    # operator the job was cancelled. The in-flight POST /jobs then arrives.
    #
    # Without this check that late request would flip the record back to `queued`
    # and start the pipeline anyway — a job the operator was told was cancelled
    # runs to completion, burning Step Functions and Lambda, and its report is
    # unreachable because the client no longer holds the id. A client-side abort
    # cannot fix this: the two requests race at the server, so the server has to
    # be the authority. Refuse to resurrect a record that has already settled.
    status = record.get("status")
    if status in TERMINAL_STATUSES:
        log.info("refusing to start job %s — already %s", job_id, status)
        return _response(
            409,
            {
                "jobId": str(job_id),
                "status": status,
                "error": f"This job is already {status} and cannot be started.",
            },
        )

    ai_enabled, ai_reason = _ai_gate(bool(body.get("ai")))
    jobs.update(
        str(job_id),
        status="queued",
        progress="Queued…",
        ai=ai_reason if not ai_enabled else "requested",
    )

    sfn = boto3.client("stepfunctions", region_name=common.region())
    sfn.start_execution(
        stateMachineArn=os.environ["STATE_MACHINE_ARN"],
        # Execution names are unique per state machine, so a duplicate submit of
        # the same job is rejected by Step Functions rather than running the
        # pipeline twice.
        name=str(job_id),
        input=json.dumps(
            {
                "jobId": str(job_id),
                "inputFilenames": record.get("input_filenames", []),
                "aiEnabled": ai_enabled,
            }
        ),
    )
    return _response(202, {"jobId": job_id, "ai": ai_reason})


def _get_job(job_id: str) -> dict:
    record = common.job_store().get(job_id)
    if not record:
        return _response(404, {"error": "Unknown job."})
    return _response(200, {"jobId": job_id, **record})


def _get_result(job_id: str) -> dict:
    jobs = common.job_store()
    record = jobs.get(job_id)
    if not record:
        return _response(404, {"error": "Unknown job."})
    if record.get("status") != "complete":
        return _response(409, {"error": "Report is not ready."})

    store = common.artifact_store()
    key = REPORT_KEY.format(job_id=job_id)
    if not store.exists(key):
        # Status says complete but the object is gone — most likely the artifact
        # retention window (D5) expired it. Say that rather than handing back a
        # presigned url that 404s.
        return _response(410, {"error": "Report has expired and is no longer available."})

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
            return _post_cancel(str(job_id))
        if method == "POST" and resource.endswith("/jobs"):
            return _post_jobs(event)
        if method == "GET" and resource.endswith("/result") and job_id:
            return _get_result(str(job_id))
        if method == "GET" and job_id:
            return _get_job(str(job_id))
    except Exception:
        # Never leak a stack trace or internal detail through the API.
        log.exception("unhandled error in API handler (%s %s)", method, resource)
        return _response(500, {"error": "Internal error — see server logs."})

    return _response(404, {"error": "No such route."})
