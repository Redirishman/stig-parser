"""API Lambda: the only synchronous handler, behind the Private API Gateway.

Routes (REST API proxy integration):

    POST /uploads            -> create a job, return presigned PUT urls
    POST /jobs               -> start the Step Functions execution
    GET  /jobs/{job_id}      -> job status record
    GET  /jobs/{job_id}/result -> presigned GET url for report.xlsx

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
from app.core.uploads import reject_filename
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
        if method == "POST" and resource.endswith("/uploads"):
            return _post_uploads(event)
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
