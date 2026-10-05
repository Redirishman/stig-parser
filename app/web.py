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
from app.core.uploads import reject_filename, reject_size

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
# Statuses with no outgoing edges: the worker is done touching the job's files.
# A dir whose in-memory status is anything else (chiefly "running", including a
# job mid-cancellation) is still owned by a live worker thread and must never be
# swept, regardless of how stale its mtime looks.
_TERMINAL_STATUSES = frozenset({"complete", "error", "cancelled"})

def _reject_upload(fs) -> str | None:
    """Return a user-safe rejection message for a bad upload, else None.

    The allow-list and size cap live in app.core.uploads so the Lambda API
    handler enforces the same rules.
    """
    rejection = reject_filename(fs.filename or "")
    if rejection:
        return rejection
    # Measure the stream without loading it: seek to end, read position, rewind.
    fs.stream.seek(0, os.SEEK_END)
    size = fs.stream.tell()
    fs.stream.seek(0)
    return reject_size(fs.filename, size)


def _saved_name(filename: str, fallback_stem: str) -> str:
    """The name an upload is saved under, which is the name the operator reads.

    secure_filename's, as long as it keeps the extension: the pipeline routes a
    ZIP, a checklist or a Nessus scan by its suffix, and secure_filename keeps
    ASCII only ("отчёт.zip" becomes "zip"). Otherwise *fallback_stem* plus the
    upload's own extension, which _reject_upload has already allowed.
    """
    suffix = Path(filename).suffix.lower()
    safe = secure_filename(filename)
    if len(safe) > len(suffix) and safe.lower().endswith(suffix):
        return safe
    return fallback_stem + suffix


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
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        # SESSION_COOKIE_SECURE stays False: the tool ships over local http.
        # Full CSRF tokens skipped — single-user localhost tool; SameSite=Strict
        # blocks cross-site cookie send. Revisit if deployed multi-user.
    )

    @app.after_request
    def _security_headers(resp: Response) -> Response:
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        # Strict CSP — no inline script/style. The page's JS lives in
        # static/app.js and its CSS in static/style.css, so 'self' suffices.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'; "
            "base-uri 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'"
        )
        return resp

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

        # Validate every upload before creating any job dir — a bad type or
        # oversized file must not leave an orphan directory on disk.
        for f in (*results_files, *benchmark_files):
            if not f.filename:
                continue
            msg = _reject_upload(f)
            if msg:
                return jsonify({"error": msg}), 400

        job_id = str(uuid.uuid4())
        job_dir = _job_dir(job_id)
        results_dir = job_dir / "results"
        benchmarks_dir = job_dir / "benchmarks"
        results_dir.mkdir(parents=True)
        benchmarks_dir.mkdir(parents=True)

        # Save uploaded files to disk, each in a numbered folder of its own: two
        # uploads may share a name, and one must not overwrite the other. The
        # file keeps its own name, which is what the operator reads.
        saved_results: list[Path] = []
        saved_benchmarks: list[Path] = []
        # Saved under a safe name; reported under the operator's own (see classify_inputs).
        supplied_names: dict[Path, str] = {}

        def _unique_dest(parent: Path, name: str) -> Path:
            folder = parent / f"{len(saved_results) + len(saved_benchmarks):03d}"
            folder.mkdir()
            return folder / name

        for f in results_files:
            if f.filename:
                dest = _unique_dest(results_dir, _saved_name(f.filename, "upload"))
                f.save(str(dest))
                saved_results.append(dest)
                supplied_names[dest] = f.filename

        for f in benchmark_files:
            if f.filename:
                dest = _unique_dest(benchmarks_dir, _saved_name(f.filename, "reference"))
                f.save(str(dest))
                saved_benchmarks.append(dest)
                supplied_names[dest] = f.filename

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
            kwargs={"display_names": supplied_names},
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


def _run_job(
    job_id: str, results_paths: list[Path], reference_paths: list[Path],
    display_names: dict[Path, str] | None = None,
) -> None:
    warnings: list[str] = []
    log_handler = _WarningCollector(warnings)
    logging.getLogger("app").addHandler(log_handler)

    try:
        def _cancel_check() -> None:
            _raise_if_cancelled(job_id)

        def _progress(msg: str) -> None:
            _set_job(job_id, progress=msg)

        _set_job(job_id, progress="Parsing files…")
        extract_dir = _job_dir(job_id) / "benchmarks_extracted"
        try:
            result = parse_stage(
                results_paths,
                reference_paths,
                extract_dir,
                cancel_check=_cancel_check,
                progress_cb=_progress,
                display_names=display_names or {},
            )
        except PipelineError as exc:
            # Its warnings are the diagnosis ("x.ckl: … not supported").
            log_handler.add_new(exc.warnings)
            # Purge BEFORE reporting: once a poller sees "error" the uploaded
            # scan files must already be gone.
            _purge_job_files(job_id)
            _set_job(
                job_id,
                status="error",
                error=str(exc),
                warnings=list(warnings),
            )
            return
        finally:
            # Archive members are needed only while parsing, and a run may
            # extract gigabytes: never keep them until download or the sweep.
            shutil.rmtree(extract_dir, ignore_errors=True)

        # Through the collector, as on the failure path: within its cap, and a line
        # already captured from the log is not shown twice.
        log_handler.add_new(result.warnings)

        _raise_if_cancelled(job_id)
        _set_job(job_id, progress="Generating Excel workbook…", warnings=list(warnings))
        output_path = _job_dir(job_id) / default_output_name()
        export_stage(result.findings, output_path, enrichment=result.enrichment, warnings=result.warnings)

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
        _purge_job_files(job_id)
        _set_job(job_id, status="cancelled", progress="Cancelled.", warnings=list(warnings))
    except Exception:
        # Never surface internal exception detail to the client (leaks paths,
        # library internals, etc.). The full traceback goes to the server log.
        log.exception("Job %s failed with unhandled exception", job_id)
        # Same rule as the PipelineError path: files go first, status second.
        # (This path used to leave the uploads on disk until the orphan sweep.)
        _purge_job_files(job_id)
        _set_job(
            job_id,
            status="error",
            error="Processing failed — see server logs.",
            warnings=list(warnings),
        )
    finally:
        logging.getLogger("app").removeHandler(log_handler)


_MAX_COLLECTED = 200     # log warnings shown for one job; the rest are counted
# Lines counted past the cap whose hash is kept, so that add_new does not count
# one twice. A flood (90,000 archive entries gave 89,800 lines) is not all kept:
# past this many, de-duplication stops and the count may over-state, never
# under-state, how many more there were.
_MAX_DROPPED_REMEMBERED = 5000


class _WarningCollector(logging.Handler):
    """Captures WARNING+ log messages from app.* loggers into a list.

    Only those of the thread that made it, the job's worker: every job's
    collector hangs on the one "app" logger, and one job must never show
    another's file names. At most _MAX_COLLECTED, then a single line saying
    how many more there were, kept up to date in place.
    """

    def __init__(self, target: list[str]):
        super().__init__(level=logging.WARNING)
        self._target = target
        self._thread = threading.get_ident()
        self._kept = 0
        self._dropped = 0
        self._summary_at: int | None = None
        # What add_new compares against: the lines kept (at most _MAX_COLLECTED)
        # and a hash of each line counted past the cap, the first
        # _MAX_DROPPED_REMEMBERED of them. A line whose hash only matches would
        # have been counted past the cap anyway.
        self._kept_lines: set[str] = set()
        self._dropped_hashes: set[int] = set()

    def emit(self, record: logging.LogRecord) -> None:
        # A record without a thread id (logging.logThreads off) cannot be
        # told apart from another job's: it is not kept.
        if record.thread != self._thread:
            return
        # The message only: format() would append a logged exception's
        # traceback, which names files and directories on this server.
        self._add(record.getMessage())

    def add_new(self, lines: list[str]) -> None:
        """Collect each of *lines* not collected already, kept or counted past
        the cap, within the same cap."""
        for line in lines:
            if line not in self._kept_lines and hash(line) not in self._dropped_hashes:
                self._add(line)

    def _add(self, line: str) -> None:
        if self._kept < _MAX_COLLECTED:
            self._kept += 1
            self._kept_lines.add(line)
            self._target.append(line)
            return
        self._dropped += 1
        if len(self._dropped_hashes) < _MAX_DROPPED_REMEMBERED:
            self._dropped_hashes.add(hash(line))
        summary = f"… and {self._dropped} more warnings not shown"
        if self._summary_at is None:
            self._summary_at = len(self._target)
            self._target.append(summary)
        else:
            self._target[self._summary_at] = summary


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def _delete_job(job_id: str) -> None:
    job_dir = _job_dir(job_id)
    if job_dir.exists():
        shutil.rmtree(job_dir, ignore_errors=True)
    with _jobs_lock:
        _jobs.pop(job_id, None)


def _purge_job_files(job_id: str) -> None:
    """Remove a job's on-disk working dir, keeping its in-memory status entry.

    Used on the error and cancel paths: the files are useless once a job fails
    (no output workbook is produced), but status polls still need the job entry
    to report the terminal state. Only a successful download hits _delete_job.
    """
    shutil.rmtree(_job_dir(job_id), ignore_errors=True)


def _sweep_orphaned_jobs() -> None:
    """Delete job temp dirs older than _ORPHAN_MAX_AGE_HOURS.

    Reaps two classes of orphan: dirs left by a previous process (run once at
    startup) and dirs from completed jobs the user never downloaded (reaped by
    the periodic sweeper on a long-lived server).
    """
    if not _TEMP_DIR.exists():
        _TEMP_DIR.mkdir(parents=True, exist_ok=True)
        return
    cutoff = time.time() - _ORPHAN_MAX_AGE_HOURS * 3600
    for entry in _TEMP_DIR.iterdir():
        if entry.is_dir():
            # Never reap a job a live worker still owns. A dir with no in-memory
            # entry (status "") is a true orphan from a prior process and is
            # eligible; a non-terminal status means the worker is still using
            # these files even if the dir's mtime has gone stale (e.g. a slow
            # parse of a large archive that hasn't written for hours).
            status = _get_job(entry.name).get("status", "")
            if status and status not in _TERMINAL_STATUSES:
                continue
            try:
                if entry.stat().st_mtime < cutoff:
                    shutil.rmtree(entry, ignore_errors=True)
                    log.info("Swept orphaned job dir: %s", entry.name)
            except OSError:
                pass


_SWEEP_INTERVAL_SECONDS = 30 * 60  # periodic orphan sweep cadence


def _start_orphan_sweeper(interval_seconds: float = _SWEEP_INTERVAL_SECONDS) -> threading.Thread:
    """Run _sweep_orphaned_jobs() on a loop in a daemon thread.

    The startup sweep only reaps orphans from a prior process. A long-lived
    server must also reap jobs abandoned during its own uptime — chiefly
    completed jobs the user never downloaded — without waiting for a restart.
    Started from the __main__ entrypoint only, so create_app() stays free of
    background threads (tests build many apps per process).
    """
    def _loop() -> None:
        while True:
            time.sleep(interval_seconds)
            try:
                _sweep_orphaned_jobs()
            except Exception:
                log.exception("Periodic orphan sweep failed")

    thread = threading.Thread(target=_loop, name="orphan-sweeper", daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    app = create_app()
    _start_orphan_sweeper()
    app.run(debug=False, host="127.0.0.1", port=5000)
