"""Flask web application — upload, process, download."""
from __future__ import annotations

import glob as glob_module
import logging
import os
import shutil
import threading
import time
import uuid
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
from werkzeug.utils import secure_filename

from app.core.pipeline import (
    PipelineError,
    compute_summary,
    default_output_name,
    export_stage,
    parse_stage,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Job state — in-memory store keyed by job UUID
# ---------------------------------------------------------------------------
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()

# In-process submission rate limit, per client IP. Caps trivial DoS / disk
# exhaustion from unauthenticated job spam without adding a dependency; not a
# replacement for an upstream WAF or reverse-proxy limit.
_RATE_MAX = 10
_RATE_WINDOW = 60.0
_rate_hits: dict[str, list[float]] = {}


def _rate_limited(client_ip: str) -> bool:
    now = time.time()
    with _jobs_lock:
        hits = [t for t in _rate_hits.get(client_ip, []) if now - t < _RATE_WINDOW]
        if len(hits) >= _RATE_MAX:
            _rate_hits[client_ip] = hits
            return True
        hits.append(now)
        _rate_hits[client_ip] = hits
    return False

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
    _secret = secret_key or os.environ.get("FLASK_SECRET_KEY")
    if not _secret:
        log.warning(
            "FLASK_SECRET_KEY is not set — using an ephemeral key. Sessions "
            "will not survive a restart and will not work across multiple "
            "workers. Set FLASK_SECRET_KEY for any non-local deployment."
        )
        _secret = os.urandom(32).hex()
    app.secret_key = _secret
    app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500 MB total upload

    _sweep_orphaned_jobs()

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    @app.route("/")
    def index():
        job_id = session.get("job_id")
        return render_template("index.html", existing_job_id=job_id)

    @app.route("/readme")
    def readme():
        readme_path = Path(__file__).parent.parent / "README.md"
        if not readme_path.is_file():
            return Response(
                "README not bundled with this deployment. "
                "See the project repository for documentation.",
                status=404,
                mimetype="text/plain",
            )
        return Response(
            readme_path.read_text(encoding="utf-8"),
            mimetype="text/plain; charset=utf-8",
        )

    @app.route("/api/process", methods=["POST"])
    def process():
        if _rate_limited(request.remote_addr or "unknown"):
            return jsonify({"error": "Too many requests — slow down."}), 429

        results_files = request.files.getlist("results")
        benchmark_files = request.files.getlist("benchmarks")

        if not results_files or all(f.filename == "" for f in results_files):
            return jsonify({"error": "No results files uploaded."}), 400

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
                safe_name = secure_filename(f.filename) or "upload.xml"
                dest = results_dir / safe_name
                f.save(str(dest))
                saved_results.append(dest)

        for f in benchmark_files:
            if f.filename:
                safe_name = secure_filename(f.filename) or "benchmark.xml"
                dest = benchmarks_dir / safe_name
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
        if session.get("job_id") != job_id:
            return jsonify({"error": "Job not found."}), 404
        job = _get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found."}), 404
        return jsonify({
            "status": job.get("status", "unknown"),
            "progress": job.get("progress", ""),
            "warnings": job.get("warnings", []),
            "error": job.get("error", ""),
            "summary": job.get("summary"),
        })

    @app.route("/api/cancel/<job_id>", methods=["POST"])
    def cancel(job_id: str):
        if session.get("job_id") != job_id:
            return jsonify({"error": "Job not found."}), 404
        job = _get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found."}), 404
        if job.get("status") != "running":
            # Already finished — report the final state so the UI can proceed.
            return jsonify({"status": job.get("status")})
        _set_job(job_id, cancelled=True)
        return jsonify({"status": "cancelling"})

    @app.route("/api/download/<job_id>")
    def download(job_id: str):
        if session.get("job_id") != job_id:
            return jsonify({"error": "Job not found."}), 404
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

class _JobCancelled(Exception):
    """Raised inside the worker thread when the user cancels the job."""


def _raise_if_cancelled(job_id: str) -> None:
    if _get_job(job_id).get("cancelled"):
        raise _JobCancelled()


def _run_job(job_id: str, results_paths: list[Path], benchmark_paths: list[Path]) -> None:
    warnings: list[str] = []
    log_handler = _WarningCollector(warnings)
    logging.getLogger("app").addHandler(log_handler)

    try:
        def _cancel_check() -> None:
            _raise_if_cancelled(job_id)

        _set_job(job_id, progress="Parsing files…")
        try:
            result = parse_stage(
                results_paths,
                benchmark_paths,
                _job_dir(job_id) / "benchmarks_extracted",
                cancel_check=_cancel_check,
            )
        except PipelineError as exc:
            _set_job(
                job_id,
                status="error",
                error=str(exc),
                warnings=list(warnings),
            )
            return

        warnings.extend(result.warnings)

        _raise_if_cancelled(job_id)
        _set_job(job_id, progress="Generating Excel workbook…", warnings=list(warnings))
        output_path = _job_dir(job_id) / default_output_name()
        export_stage(result.findings, output_path)

        summary = compute_summary(result.findings, result.source_file_count)

        _set_job(
            job_id,
            status="complete",
            progress=f"Done — {len(result.findings)} findings exported.",
            output_path=str(output_path),
            warnings=list(warnings),
            summary=summary,
        )

    except _JobCancelled:
        # Keep the job entry so status polls see "cancelled"; drop the files.
        shutil.rmtree(_job_dir(job_id), ignore_errors=True)
        _set_job(job_id, status="cancelled", progress="Cancelled.", warnings=list(warnings))
    except Exception:
        # Never surface internal exception detail to the client (leaks paths,
        # library internals, etc.). The full traceback goes to the server log.
        log.exception("Job %s failed with unhandled exception", job_id)
        _set_job(
            job_id,
            status="error",
            error="Processing failed — see server logs.",
            warnings=list(warnings),
        )
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
    app.run(debug=False, host="127.0.0.1", port=5000)
