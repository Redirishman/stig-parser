"""Async stage entrypoints composed over the storage and job-state boundaries.

The future Lambda handlers (sub-project #2) call these. Each function is
AWS-agnostic: it takes an ``ArtifactStore`` and a ``JobStore`` and returns a
bool indicating success, updating job status as it goes. Errors are captured
into the job record (never raised out) so the orchestrator can branch on
status rather than on exceptions.
"""

from __future__ import annotations

import logging
from pathlib import Path

from app.core.artifact_store import ArtifactStore
from app.core.findings_io import findings_from_json, findings_to_json
from app.core.job_store import JobStore
from app.core.pipeline import (
    PipelineError,
    compute_summary,
    default_output_name,
    export_stage,
    parse_stage,
)
from app.core.uploads import MAX_UPLOAD_BYTES

log = logging.getLogger(__name__)

INPUT_PREFIX = "jobs/{job_id}/input"
FINDINGS_KEY = "jobs/{job_id}/findings.json"
REPORT_KEY = "jobs/{job_id}/report.xlsx"

_PARSE_COMPLETE_PHASES = frozenset({"parsed", "enriching", "exporting"})
_EXPORT_INPUT_PHASES = frozenset({None, "parsed", "enriching", "exporting"})


def _is_safe_name(name: str) -> bool:
    """True if ``name`` is a bare filename safe to join onto a local path.

    Input filenames originate from user uploads; a value containing path
    separators or ``..`` (or an absolute path) could escape the job work
    directory when joined, so those are rejected outright.
    """
    return (
        bool(name)
        and "/" not in name
        and "\\" not in name
        and ".." not in name
        and not Path(name).is_absolute()
    )


def _parse_already_succeeded(record: dict) -> bool:
    return record.get("status") == "complete" or (
        record.get("status") == "running"
        and record.get("phase") in _PARSE_COMPLETE_PHASES
    )


def _record_stage_error(
    jobs: JobStore,
    job_id: str,
    *,
    phase: str,
    message: str,
) -> bool:
    """Record an active stage error; return True if a newer stage already won."""
    if jobs.transition(
        job_id,
        "error",
        expected_fields={"phase": phase},
        error=message,
    ):
        return False

    record = jobs.get(job_id)
    if phase == "parsing":
        return _parse_already_succeeded(record)
    return record.get("status") == "complete"


def run_parse_stage(
    job_id: str,
    input_filenames: list[str],
    store: ArtifactStore,
    jobs: JobStore,
    *,
    work_dir: Path,
    input_store: ArtifactStore | None = None,
) -> bool:
    """Download inputs, parse+match+filter, upload ``findings.json``.

    Inputs are read from ``input_store`` and ``findings.json`` is written to
    ``store``. They default to the same store (the Flask and CLI paths use one
    local root); the GovCloud deployment passes a separate uploads bucket so
    raw uploads can carry a shorter retention than generated artifacts.

    Returns True on success. On failure sets job status to ``error`` with a
    user-safe message and returns False.
    """
    source = input_store or store
    work_dir = Path(work_dir)

    # A Lambda retry may re-enter after the first invocation already moved the
    # job to running. Confirm that state atomically in either case. A cancelled
    # job stops here, before any upload is read or local work directory created.
    if not jobs.transition(
        job_id, "running", progress="Parsing files…", phase="parsing"
    ):
        record = jobs.get(job_id)
        if _parse_already_succeeded(record):
            return True
        phase = record.get("phase")
        if record.get("status") != "running" or phase not in {None, "parsing"}:
            return False
        if not jobs.update_if_status(
            job_id,
            {"running"},
            expected_fields={"phase": phase},
            progress="Parsing files…",
            phase="parsing",
        ):
            return _parse_already_succeeded(jobs.get(job_id))

    input_dir = work_dir / "input"
    extract_dir = work_dir / "extract"
    input_dir.mkdir(parents=True, exist_ok=True)

    # Validate up front: reject any filename that could traverse out of the
    # job work directory when joined onto a local path.
    for name in input_filenames:
        if not _is_safe_name(name):
            log.warning("rejected unsafe input filename for job %s: %r", job_id, name)
            return _record_stage_error(
                jobs,
                job_id,
                phase="parsing",
                message="Invalid input filename.",
            )

    prefix = INPUT_PREFIX.format(job_id=job_id)
    try:
        local_inputs: list[Path] = []
        for name in input_filenames:
            key = f"{prefix}/{name}"
            # Enforce the per-file cap server-side. The presigned-PUT upload path
            # cannot bound object size, so a client can PUT an arbitrarily large
            # object; check the size (cheap HEAD) before pulling it into the
            # size-limited Lambda /tmp. The Flask path enforces this at upload.
            obj_size = source.size(key)
            if obj_size > MAX_UPLOAD_BYTES:
                log.warning(
                    "rejected oversized upload for job %s: %r (%d bytes)",
                    job_id,
                    name,
                    obj_size,
                )
                return _record_stage_error(
                    jobs,
                    job_id,
                    phase="parsing",
                    message=f"File too large: {name!r} (max 200 MB each).",
                )
            dest = input_dir / name
            source.download_to(key, dest)
            local_inputs.append(dest)
        result = parse_stage(local_inputs, [], extract_dir)
    except PipelineError as exc:
        # PipelineError messages are curated and user-safe.
        return _record_stage_error(jobs, job_id, phase="parsing", message=str(exc))
    except Exception:  # unexpected — capture without leaking internal detail
        log.exception("parse stage failed for job %s", job_id)
        return _record_stage_error(
            jobs,
            job_id,
            phase="parsing",
            message="Parsing failed — see server logs.",
        )

    store.put_bytes(
        FINDINGS_KEY.format(job_id=job_id),
        findings_to_json(result.findings).encode("utf-8"),
    )
    if jobs.update_if_status(
        job_id,
        {"running"},
        expected_fields={"phase": "parsing"},
        progress="Parsed.",
        phase="parsed",
        warnings=result.warnings,
        source_file_count=result.source_file_count,
    ):
        return True
    return _parse_already_succeeded(jobs.get(job_id))


def run_export_stage(
    job_id: str,
    store: ArtifactStore,
    jobs: JobStore,
    *,
    work_dir: Path,
) -> bool:
    """Read ``findings.json``, export to xlsx, upload ``report.xlsx``.

    Returns True on success. On failure sets job status to ``error`` and
    returns False.
    """
    record = jobs.get(job_id)
    if record.get("status") == "complete":
        # A successful Lambda whose response was lost may be retried by Step
        # Functions. Completion is idempotent; do not rebuild or reclassify it.
        return True
    phase = record.get("phase")
    if record.get("status") != "running" or phase not in _EXPORT_INPUT_PHASES:
        return False
    if not jobs.update_if_status(
        job_id,
        {"running"},
        expected_fields={"phase": phase},
        progress="Generating Excel workbook…",
        phase="exporting",
    ):
        # Another retry may have completed after the read above but before this
        # guarded patch. Treat the authoritative terminal success as idempotent.
        latest = jobs.get(job_id)
        return latest.get("status") == "complete" or (
            latest.get("status") == "running" and latest.get("phase") == "exporting"
        )

    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    try:
        raw = store.get_bytes(FINDINGS_KEY.format(job_id=job_id)).decode("utf-8")
        findings = findings_from_json(raw)
        out_path = work_dir / default_output_name()
        export_stage(findings, out_path)
        store.upload_from(REPORT_KEY.format(job_id=job_id), out_path)
        source_file_count = jobs.get(job_id).get("source_file_count", 0)
        summary = compute_summary(findings, source_file_count)
    except Exception:  # unexpected — capture without leaking internal detail
        log.exception("export stage failed for job %s", job_id)
        return _record_stage_error(
            jobs,
            job_id,
            phase="exporting",
            message="Export failed — see server logs.",
        )

    if jobs.transition(
        job_id,
        "complete",
        expected_fields={"phase": "exporting"},
        progress=f"Done — {len(findings)} findings exported.",
        summary=summary,
    ):
        return True

    # A concurrent duplicate exporter may have committed the same terminal
    # state first. Cancellation and error remain failures and are never changed.
    return jobs.get(job_id).get("status") == "complete"
