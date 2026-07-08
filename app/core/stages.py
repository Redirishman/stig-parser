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

log = logging.getLogger(__name__)

INPUT_PREFIX = "jobs/{job_id}/input"
FINDINGS_KEY = "jobs/{job_id}/findings.json"
REPORT_KEY = "jobs/{job_id}/report.xlsx"


def run_parse_stage(
    job_id: str,
    input_filenames: list[str],
    store: ArtifactStore,
    jobs: JobStore,
    *,
    work_dir: Path,
) -> bool:
    """Download inputs, parse+match+filter, upload ``findings.json``.

    Returns True on success. On failure sets job status to ``error`` with a
    user-safe message and returns False.
    """
    work_dir = Path(work_dir)
    input_dir = work_dir / "input"
    extract_dir = work_dir / "extract"
    input_dir.mkdir(parents=True, exist_ok=True)

    jobs.update(job_id, status="running", progress="Parsing files…")

    local_inputs: list[Path] = []
    prefix = INPUT_PREFIX.format(job_id=job_id)
    for name in input_filenames:
        dest = input_dir / name
        store.download_to(f"{prefix}/{name}", dest)
        local_inputs.append(dest)

    try:
        result = parse_stage(local_inputs, [], extract_dir)
    except PipelineError as exc:
        jobs.update(job_id, status="error", error=str(exc))
        return False
    except Exception as exc:  # unexpected — capture, don't leak a stack trace
        log.exception("parse stage failed for job %s", job_id)
        jobs.update(job_id, status="error", error=f"Parsing failed: {exc}")
        return False

    store.put_bytes(
        FINDINGS_KEY.format(job_id=job_id),
        findings_to_json(result.findings).encode("utf-8"),
    )
    jobs.update(
        job_id,
        progress="Parsed.",
        warnings=result.warnings,
        source_file_count=result.source_file_count,
    )
    return True


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
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    jobs.update(job_id, progress="Generating Excel workbook…")

    try:
        raw = store.get_bytes(FINDINGS_KEY.format(job_id=job_id)).decode("utf-8")
        findings = findings_from_json(raw)
        out_path = work_dir / default_output_name()
        export_stage(findings, out_path)
        store.upload_from(REPORT_KEY.format(job_id=job_id), out_path)
    except Exception as exc:
        log.exception("export stage failed for job %s", job_id)
        jobs.update(job_id, status="error", error=f"Export failed: {exc}")
        return False

    source_file_count = jobs.get(job_id).get("source_file_count", 0)
    summary = compute_summary(findings, source_file_count)
    jobs.update(
        job_id,
        status="complete",
        progress=f"Done — {len(findings)} findings exported.",
        summary=summary,
    )
    return True
