"""Flask web application — upload, process, download."""
from __future__ import annotations

import glob as glob_module
import logging
import os
import shutil
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    send_file,
    session,
)

from app.exporters.excel_exporter import ExcelExporter
from app.parsers.benchmark_parser import BenchmarkParser
from app.parsers.xccdf_parser import XCCDFResultsParser
from app.processors.filter import filter_findings
from app.processors.matcher import match_results_to_benchmarks
from app.utils.zip_extract import expand_benchmark_paths

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Job state — in-memory store keyed by job UUID
# ---------------------------------------------------------------------------
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()

_TEMP_DIR = Path(os.environ.get("STIG_TEMP_DIR", Path(__file__).parent.parent / "tmp"))
_ORPHAN_MAX_AGE_HOURS = 8


def _job_dir(job_id: str) -> Path:
    return _TEMP_DIR / job_id


def _set_job(job_id: str, **fields) -> None:
    with _jobs_lock:
        _jobs.setdefault(job_id, {}).update(fields)


def _get_job(job_id: str) -> dict:
    with _jobs_lock:
        return dict(_jobs.get(job_id, {}))


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(secret_key: str | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = secret_key or os.environ.get("FLASK_SECRET_KEY", os.urandom(32))
    app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500 MB total upload

    _sweep_orphaned_jobs()

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    @app.route("/")
    def index():
        job_id = session.get("job_id")
        return render_template("index.html", existing_job_id=job_id)

    @app.route("/api/process", methods=["POST"])
    def process():
        results_files = request.files.getlist("results")
        benchmark_files = request.files.getlist("benchmarks")

        if not results_files or all(f.filename == "" for f in results_files):
            return jsonify({"error": "No results files uploaded."}), 400
        if not benchmark_files or all(f.filename == "" for f in benchmark_files):
            return jsonify({"error": "No benchmark files uploaded."}), 400

        job_id = str(uuid.uuid4())
        job_dir = _job_dir(job_id)
        results_dir = job_dir / "results"
        benchmarks_dir = job_dir / "benchmarks"
        results_dir.mkdir(parents=True)
        benchmarks_dir.mkdir(parents=True)

        # Save uploaded files to disk
        saved_results: list[Path] = []
        saved_benchmarks: list[Path] = []

        for f in results_files:
            if f.filename:
                dest = results_dir / Path(f.filename).name
                f.save(str(dest))
                saved_results.append(dest)

        for f in benchmark_files:
            if f.filename:
                dest = benchmarks_dir / Path(f.filename).name
                f.save(str(dest))
                saved_benchmarks.append(dest)

        session["job_id"] = job_id
        _set_job(
            job_id,
            status="running",
            progress="Starting…",
            warnings=[],
            output_path=None,
            created_at=time.time(),
        )

        t = threading.Thread(
            target=_run_job,
            args=(job_id, saved_results, saved_benchmarks),
            daemon=True,
        )
        t.start()

        return jsonify({"job_id": job_id, "status": "running"})

    @app.route("/api/status/<job_id>")
    def job_status(job_id: str):
        job = _get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found."}), 404
        return jsonify({
            "status": job.get("status", "unknown"),
            "progress": job.get("progress", ""),
            "warnings": job.get("warnings", []),
            "error": job.get("error", ""),
        })

    @app.route("/api/download/<job_id>")
    def download(job_id: str):
        job = _get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found."}), 404
        if job.get("status") != "complete":
            return jsonify({"error": "Job not complete."}), 400

        output_path = job.get("output_path")
        if not output_path or not Path(output_path).exists():
            return jsonify({"error": "Output file missing."}), 500

        response = send_file(
            output_path,
            as_attachment=True,
            download_name=Path(output_path).name,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

        # Clean up after response is sent
        @response.call_on_close
        def _cleanup():
            _delete_job(job_id)

        return response

    return app


# ---------------------------------------------------------------------------
# Background processing
# ---------------------------------------------------------------------------

def _run_job(job_id: str, results_paths: list[Path], benchmark_paths: list[Path]) -> None:
    warnings: list[str] = []
    log_handler = _WarningCollector(warnings)
    logging.getLogger("app").addHandler(log_handler)

    try:
        # Expand any uploaded .zip benchmarks (DISA STIG distribution format)
        _set_job(job_id, progress="Extracting benchmark archives…")
        extract_dir = _job_dir(job_id) / "benchmarks_extracted"
        benchmark_paths, zip_warnings = expand_benchmark_paths(benchmark_paths, extract_dir)
        warnings.extend(zip_warnings)

        # Parse benchmarks
        _set_job(job_id, progress="Parsing benchmark files…", warnings=list(warnings))
        benchmark_parser = BenchmarkParser()
        benchmarks = []
        for path in benchmark_paths:
            bm = benchmark_parser.parse(path)
            if bm:
                benchmarks.append(bm)
            else:
                warnings.append(f"Could not parse benchmark: {path.name}")

        # Parse results files
        results_parser = XCCDFResultsParser()
        scan_results = []
        total = len(results_paths)
        for i, path in enumerate(results_paths, start=1):
            _set_job(job_id, progress=f"Parsing file {i} of {total}: {path.name}", warnings=list(warnings))
            sr = results_parser.parse(path)
            if sr:
                scan_results.append(sr)
            else:
                warnings.append(f"Could not parse results file: {path.name}")

        if not scan_results:
            _set_job(job_id, status="error", error="No valid results files could be parsed.", warnings=list(warnings))
            return

        # Match and filter
        _set_job(job_id, progress="Matching results to benchmarks…", warnings=list(warnings))
        findings = match_results_to_benchmarks(scan_results, benchmarks)

        _set_job(job_id, progress="Filtering findings…")
        findings = filter_findings(findings)

        if not findings:
            _set_job(job_id, status="error", error="No actionable findings after filtering.", warnings=list(warnings))
            return

        # Export
        _set_job(job_id, progress="Generating Excel workbook…")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = _job_dir(job_id) / f"stig_findings_{timestamp}.xlsx"
        ExcelExporter().export(findings, output_path)

        _set_job(
            job_id,
            status="complete",
            progress=f"Done — {len(findings)} findings exported.",
            output_path=str(output_path),
            warnings=list(warnings),
        )

    except Exception as exc:
        log.exception("Job %s failed with unhandled exception", job_id)
        _set_job(job_id, status="error", error=str(exc), warnings=list(warnings))
    finally:
        logging.getLogger("app").removeHandler(log_handler)


class _WarningCollector(logging.Handler):
    """Captures WARNING+ log messages from app.* loggers into a list."""

    def __init__(self, target: list[str]):
        super().__init__(level=logging.WARNING)
        self._target = target

    def emit(self, record: logging.LogRecord) -> None:
        self._target.append(self.format(record))


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def _delete_job(job_id: str) -> None:
    job_dir = _job_dir(job_id)
    if job_dir.exists():
        shutil.rmtree(job_dir, ignore_errors=True)
    with _jobs_lock:
        _jobs.pop(job_id, None)


def _sweep_orphaned_jobs() -> None:
    """Delete job temp dirs older than _ORPHAN_MAX_AGE_HOURS on app startup."""
    if not _TEMP_DIR.exists():
        _TEMP_DIR.mkdir(parents=True, exist_ok=True)
        return
    cutoff = time.time() - _ORPHAN_MAX_AGE_HOURS * 3600
    for entry in _TEMP_DIR.iterdir():
        if entry.is_dir():
            try:
                if entry.stat().st_mtime < cutoff:
                    shutil.rmtree(entry, ignore_errors=True)
                    log.info("Swept orphaned job dir: %s", entry.name)
            except OSError:
                pass


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, host="0.0.0.0", port=5000)
