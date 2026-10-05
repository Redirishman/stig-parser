"""Async stage entrypoints composed over the storage and job-state boundaries.

The future Lambda handlers (sub-project #2) call these. Each function is
AWS-agnostic: it takes an ``ArtifactStore`` and a ``JobStore`` and returns a
bool indicating success, updating job status as it goes. Errors are captured
into the job record (never raised out) so the orchestrator can branch on
status rather than on exceptions.
"""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path

from app.core.artifact_store import ArtifactStore, ObjectTooLarge
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
from app.reference.enrich import EnrichmentReport
from app.reference.normalize import clip

log = logging.getLogger(__name__)

INPUT_PREFIX = "jobs/{job_id}/input"
FINDINGS_KEY = "jobs/{job_id}/findings.json"
# What reference enrichment filled and could not fill: the workbook's Reference
# sources table. Written by the parse stage, read by the export stage.
ENRICHMENT_KEY = "jobs/{job_id}/enrichment.json"
REPORT_KEY = "jobs/{job_id}/report.xlsx"

_PARSE_COMPLETE_PHASES = frozenset({"parsed", "enriching", "exporting"})
_EXPORT_INPUT_PHASES = frozenset({None, "parsed", "enriching", "exporting"})
# What a job record keeps of a run's warnings, on success and on failure: a job
# record is one DynamoDB item (400 KB at most), and parse_stage's warnings are
# not bounded. Lines, characters per line, and bytes in all, counted as the
# record is stored: as JSON, which escapes non-ASCII text (an emoji costs 12
# bytes there). With the file names the upload API allows (at most 32,000 bytes,
# stored three times: the names, the reference hint, the launch input) the item
# stays under 400 KB.
_MAX_RECORD_WARNINGS = 200
_MAX_WARNING_CHARS = 500
_MAX_RECORD_WARNING_BYTES = 200_000
_SUMMARY_RESERVE = 64   # room kept for the "… and N more warnings not shown" line


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


def _stored_size(line: str) -> int:
    """What *line* adds to the stored record: its JSON (quotes and escapes) and a separator."""
    return len(json.dumps(line)) + 2


def _bounded_warnings(lines: list[str]) -> list[str]:
    """The first of *lines*, each clipped to _MAX_WARNING_CHARS, while they fit
    _MAX_RECORD_WARNINGS lines and _MAX_RECORD_WARNING_BYTES stored bytes; when
    any is left out, a last line says how many."""
    kept: list[str] = []
    size = 0
    for i, line in enumerate(lines):
        last = i == len(lines) - 1
        line = clip(line, _MAX_WARNING_CHARS)
        # Room for the summary line is kept whenever a line could still follow.
        room = _MAX_RECORD_WARNING_BYTES - (0 if last else _SUMMARY_RESERVE)
        if len(kept) == _MAX_RECORD_WARNINGS - (0 if last else 1) or size + _stored_size(line) > room:
            break
        kept.append(line)
        size += _stored_size(line)
    if len(kept) < len(lines):
        kept.append(f"… and {len(lines) - len(kept)} more warnings not shown")
    return kept


def _record_stage_error(
    jobs: JobStore,
    job_id: str,
    *,
    phase: str,
    message: str,
    warnings: list[str] | None = None,
) -> bool:
    """Record an active stage error, with the *warnings* that explain it (bounded);
    return True if a newer stage already won."""
    extra = {} if warnings is None else {"warnings": _bounded_warnings(warnings)}
    if jobs.transition(
        job_id,
        "error",
        expected_fields={"phase": phase},
        error=message,
        **extra,
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
    reference_filenames: list[str] | None = None,
) -> bool:
    """Download inputs, parse+match+filter+enrich, upload ``findings.json`` and
    ``enrichment.json``.

    Inputs are read from ``input_store`` and the artifacts are written to
    ``store``. They default to the same store (the Flask and CLI paths use one
    local root); the GovCloud deployment passes a separate uploads bucket so
    raw uploads can carry a shorter retention than generated artifacts.

    *reference_filenames* are the names from *input_filenames* the operator
    supplied as STIG references (the upload API records them). Routing is by
    content; this only decides the slot a file starts in, which is what makes
    a checklist, or a ZIP's checklists, a reference instead of a scan.

    Returns True on success. On failure sets job status to ``error`` with a
    user-safe message, and the warnings that explain it, and returns False.
    The job record keeps at most _MAX_RECORD_WARNINGS warnings either way.

    *work_dir* holds the downloaded inputs and extracted archive members; it is
    removed on return, whatever the outcome (a warm Lambda keeps its /tmp).
    """
    work_dir = Path(work_dir)
    try:
        return _run_parse_stage(
            job_id, input_filenames, store, jobs, work_dir=work_dir, input_store=input_store,
            reference_filenames=reference_filenames or [],
        )
    finally:
        _remove_work_dir(work_dir, job_id)


def _remove_work_dir(work_dir: Path, job_id: str) -> None:
    try:
        shutil.rmtree(work_dir)
    except FileNotFoundError:
        pass
    except OSError:
        log.warning("could not remove the work directory of job %s", job_id, exc_info=True)


def _run_parse_stage(
    job_id: str,
    input_filenames: list[str],
    store: ArtifactStore,
    jobs: JobStore,
    *,
    work_dir: Path,
    input_store: ArtifactStore | None,
    reference_filenames: list[str],
) -> bool:
    """:func:`run_parse_stage` without the work directory's removal."""
    source = input_store or store

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
            try:
                # The size above is what the store reported then: a presigned PUT stays
                # valid for a while, so the object may have been replaced since. The bytes
                # actually read are capped too.
                source.download_to(key, dest, max_bytes=MAX_UPLOAD_BYTES)
            except ObjectTooLarge:
                log.warning("rejected upload of job %s that grew past the cap while read: %r", job_id, name)
                return _record_stage_error(
                    jobs,
                    job_id,
                    phase="parsing",
                    message=f"File too large: {name!r} (max 200 MB each).",
                )
            local_inputs.append(dest)
        # Split by the names the upload API recorded (it refuses two files with one name).
        references = set(reference_filenames)
        downloaded = list(zip(input_filenames, local_inputs, strict=True))
        result = parse_stage(
            [path for name, path in downloaded if name not in references],
            [path for name, path in downloaded if name in references],
            extract_dir,
        )
    except PipelineError as exc:
        # PipelineError messages are curated and user-safe; its warnings are the diagnosis.
        return _record_stage_error(
            jobs, job_id, phase="parsing", message=str(exc), warnings=exc.warnings
        )
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
    store.put_bytes(
        ENRICHMENT_KEY.format(job_id=job_id),
        json.dumps(result.enrichment.to_dict()).encode("utf-8"),
    )
    if jobs.update_if_status(
        job_id,
        {"running"},
        expected_fields={"phase": "parsing"},
        progress="Parsed.",
        phase="parsed",
        warnings=_bounded_warnings(result.warnings),
        source_file_count=result.source_file_count,
        # The exporter reads enrichment.json only when this says it was written: its
        # role cannot list the bucket, so S3 answers a missing key with 403, not 404.
        enrichment_stored=True,
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
    """Read ``findings.json`` (and ``enrichment.json``), export to xlsx, upload
    ``report.xlsx``.

    Returns True on success. On failure sets job status to ``error`` and
    returns False. The workbook is removed from *work_dir* once it is in the
    store, or once the export has failed (a warm Lambda keeps its /tmp).
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
    out_path = work_dir / default_output_name()

    try:
        raw = store.get_bytes(FINDINGS_KEY.format(job_id=job_id)).decode("utf-8")
        findings = findings_from_json(raw)
        enrichment = _load_enrichment(store, job_id) if record.get("enrichment_stored") else None
        # The parse stage's warnings, as it stored them (bounded) on the job record.
        warnings = [w for w in record.get("warnings") or [] if isinstance(w, str)]
        export_stage(findings, out_path, enrichment=enrichment, warnings=warnings)
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
    finally:
        _remove_file(out_path, job_id)

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


def _load_enrichment(store: ArtifactStore, job_id: str) -> EnrichmentReport:
    """The enrichment report the parse stage stored for *job_id*.

    Called only for a job whose record says it was stored (``enrichment_stored``):
    the store is never asked whether the key exists, which S3 refuses (403) to a
    role that cannot list the bucket. A job parsed by a build older than
    ``enrichment.json`` has no flag; that build filled nothing from references,
    and its workbook simply omits the Reference sources table.
    """
    key = ENRICHMENT_KEY.format(job_id=job_id)
    return EnrichmentReport.from_dict(json.loads(store.get_bytes(key).decode("utf-8")))


def _remove_file(path: Path, job_id: str) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        log.warning("could not remove the workbook of job %s from its work directory", job_id, exc_info=True)
