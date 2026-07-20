"""Tests for app.web — Flask routes, job pipeline, optional benchmarks."""
from __future__ import annotations

import io
import time
from pathlib import Path

import pytest

from app.web import create_app

FIXTURES = Path(__file__).parent / "fixtures"


def _make_upload(file_path: Path) -> tuple[io.BytesIO, str]:
    """Return (BytesIO, filename) suitable for Flask test-client multipart upload."""
    return io.BytesIO(file_path.read_bytes()), file_path.name


def _wait_for_completion(client, job_id: str, timeout: float = 10.0) -> dict:
    """Poll /api/status until the job leaves the running state or *timeout* elapses."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/api/status/{job_id}")
        data = r.get_json()
        if data.get("status") in ("complete", "error"):
            return data
        time.sleep(0.05)
    pytest.fail(f"Job {job_id} did not finish within {timeout}s")


@pytest.fixture()
def app(tmp_path, monkeypatch):
    """Build a Flask app whose job temp dir lives inside the test's tmp_path."""
    monkeypatch.setenv("STIG_TEMP_DIR", str(tmp_path / "jobs"))
    # Re-import so the new env var takes effect at module load.
    import importlib
    import app.web as web_module
    importlib.reload(web_module)
    flask_app = web_module.create_app(secret_key="test")
    flask_app.config["TESTING"] = True
    return flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


# ---------------------------------------------------------------------------
# Static routes
# ---------------------------------------------------------------------------

class TestIndexRoute:
    def test_index_renders_200(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert b"STIG Compliance Parser" in r.data

    def test_index_includes_optional_benchmark_hint(self, client):
        r = client.get("/")
        # The "Optional for SCC" badge wording was added when benchmarks became optional.
        assert b"Optional for SCC" in r.data


# ---------------------------------------------------------------------------
# /api/process validation
# ---------------------------------------------------------------------------

class TestProcessValidation:
    def test_no_results_returns_400(self, client):
        r = client.post("/api/process", data={})
        assert r.status_code == 400
        assert "No results" in r.get_json()["error"]

    def test_empty_results_filename_returns_400(self, client):
        data = {"results": (io.BytesIO(b""), "")}
        r = client.post("/api/process", data=data, content_type="multipart/form-data")
        assert r.status_code == 400


# ---------------------------------------------------------------------------
# End-to-end job execution
# ---------------------------------------------------------------------------

class TestProcessWithSeparateBenchmark:
    def test_traditional_upload_completes(self, client):
        data = {
            "results": _make_upload(FIXTURES / "scc_results.xml"),
            "benchmarks": _make_upload(FIXTURES / "sample_benchmark.xml"),
        }
        r = client.post("/api/process", data=data, content_type="multipart/form-data")
        assert r.status_code == 200
        job_id = r.get_json()["job_id"]

        final = _wait_for_completion(client, job_id)
        assert final["status"] == "complete", f"Job failed: {final}"

    def test_download_returns_xlsx(self, client):
        data = {
            "results": _make_upload(FIXTURES / "scc_results.xml"),
            "benchmarks": _make_upload(FIXTURES / "sample_benchmark.xml"),
        }
        post = client.post("/api/process", data=data, content_type="multipart/form-data")
        job_id = post.get_json()["job_id"]
        _wait_for_completion(client, job_id)

        r = client.get(f"/api/download/{job_id}")
        assert r.status_code == 200
        assert r.mimetype == (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
        # XLSX is a ZIP — magic bytes "PK"
        assert r.data[:2] == b"PK"


class TestProcessWithoutBenchmark:
    """SCC self-contained flow — no benchmark upload."""

    def test_results_only_upload_accepted(self, client):
        data = {"results": _make_upload(FIXTURES / "scc_results.xml")}
        r = client.post("/api/process", data=data, content_type="multipart/form-data")
        assert r.status_code == 200
        assert "job_id" in r.get_json()

    def test_results_only_pipeline_completes(self, client):
        data = {"results": _make_upload(FIXTURES / "scc_results.xml")}
        post = client.post("/api/process", data=data, content_type="multipart/form-data")
        job_id = post.get_json()["job_id"]

        final = _wait_for_completion(client, job_id)
        # The fabricated SCC fixture has rule-results but no inline benchmark
        # definitions (it follows the 1.1 split-file pattern), so the pipeline
        # finishes — either complete with findings, or with an informative error
        # message about missing matches. Both are acceptable; what matters is
        # that no 400 was returned and the worker thread ran end to end.
        assert final["status"] in ("complete", "error")


# ---------------------------------------------------------------------------
# /api/status edge cases
# ---------------------------------------------------------------------------

class TestStatusRoute:
    def test_unknown_job_returns_404(self, client):
        r = client.get("/api/status/nonexistent-job-id")
        assert r.status_code == 404


class TestDownloadRoute:
    def test_unknown_job_returns_404(self, client):
        r = client.get("/api/download/nonexistent-job-id")
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# /api/cancel
# ---------------------------------------------------------------------------

class TestCancelRoute:
    def test_unknown_job_returns_404(self, client):
        r = client.post("/api/cancel/nonexistent-job-id")
        assert r.status_code == 404

    def test_cancel_finished_job_reports_final_status(self, client):
        data = {"results": _make_upload(FIXTURES / "scc_results.xml")}
        post = client.post("/api/process", data=data, content_type="multipart/form-data")
        job_id = post.get_json()["job_id"]
        final = _wait_for_completion(client, job_id)

        r = client.post(f"/api/cancel/{job_id}")
        assert r.status_code == 200
        assert r.get_json()["status"] == final["status"]

    def test_cancel_running_job_sets_flag_and_worker_honors_it(self, client):
        import app.web as web

        job_id = "cancel-test-job"
        web._set_job(job_id, status="running", progress="working", warnings=[])
        with client.session_transaction() as sess:
            sess["job_id"] = job_id

        r = client.post(f"/api/cancel/{job_id}")
        assert r.status_code == 200
        assert r.get_json()["status"] == "cancelling"
        assert web._get_job(job_id).get("cancelled") is True

        with pytest.raises(web._JobCancelled):
            web._raise_if_cancelled(job_id)

    def test_status_endpoint_reports_cancelled(self, client):
        import app.web as web

        job_id = "cancelled-status-job"
        web._set_job(job_id, status="cancelled", progress="Cancelled.", warnings=[])
        with client.session_transaction() as sess:
            sess["job_id"] = job_id

        r = client.get(f"/api/status/{job_id}")
        assert r.get_json()["status"] == "cancelled"


# ---------------------------------------------------------------------------
# CKLB upload (Evaluate-STIG / STIG Viewer 3 checklists)
# ---------------------------------------------------------------------------

class TestCklbUpload:
    def test_cklb_only_upload_completes_with_findings(self, client):
        data = {"results": _make_upload(FIXTURES / "evaluate_stig_checklist.cklb")}
        post = client.post("/api/process", data=data, content_type="multipart/form-data")
        assert post.status_code == 200
        job_id = post.get_json()["job_id"]

        final = _wait_for_completion(client, job_id)
        assert final["status"] == "complete"
        summary = final["summary"]
        assert summary["findings"] == 3
        assert summary["cat1"] == 1
        assert summary["cat2"] == 2  # includes the severity-override rule
        assert summary["hosts"] == 1

    def test_mixed_xml_and_cklb_upload_completes(self, client):
        data = {
            "results": [
                _make_upload(FIXTURES / "scc_results.xml"),
                _make_upload(FIXTURES / "evaluate_stig_checklist.cklb"),
            ]
        }
        post = client.post("/api/process", data=data, content_type="multipart/form-data")
        job_id = post.get_json()["job_id"]
        final = _wait_for_completion(client, job_id)
        assert final["status"] == "complete"
        assert final["summary"]["files"] == 2


class TestNessusUpload:
    def test_nessus_upload_completes_with_findings(self, client):
        data = {"results": _make_upload(FIXTURES / "nessus_compliance.nessus")}
        post = client.post("/api/process", data=data, content_type="multipart/form-data")
        assert post.status_code == 200
        job_id = post.get_json()["job_id"]
        final = _wait_for_completion(client, job_id)
        assert final["status"] == "complete"
        summary = final["summary"]
        assert summary["findings"] == 4
        assert summary["cat1"] == 1
        assert summary["hosts"] == 1


# ---------------------------------------------------------------------------
# Upload allow-list + size cap (RESIDUALS #2)
# ---------------------------------------------------------------------------

class TestUploadValidation:
    def test_disallowed_extension_rejected(self, client):
        data = {"results": (io.BytesIO(b"malware"), "evil.exe")}
        r = client.post("/api/process", data=data, content_type="multipart/form-data")
        assert r.status_code == 400
        assert "Unsupported file type" in r.get_json()["error"]

    def test_disallowed_benchmark_extension_rejected(self, client):
        data = {
            "results": _make_upload(FIXTURES / "scc_results.xml"),
            "benchmarks": (io.BytesIO(b"nope"), "notes.txt"),
        }
        r = client.post("/api/process", data=data, content_type="multipart/form-data")
        assert r.status_code == 400
        assert "Unsupported file type" in r.get_json()["error"]

    def test_oversized_file_rejected(self, client, monkeypatch):
        import app.core.uploads as uploads
        monkeypatch.setattr(uploads, "MAX_UPLOAD_BYTES", 16)
        data = {"results": (io.BytesIO(b"x" * 64), "big.xml")}
        r = client.post("/api/process", data=data, content_type="multipart/form-data")
        assert r.status_code == 400
        assert "too large" in r.get_json()["error"]

    def test_rejection_leaves_no_job_dir(self, client, tmp_path):
        data = {"results": (io.BytesIO(b"x"), "evil.exe")}
        client.post("/api/process", data=data, content_type="multipart/form-data")
        jobs_root = tmp_path / "jobs"
        # Validation runs before any mkdir — no orphan job directory created.
        assert not jobs_root.exists() or not any(jobs_root.iterdir())


# ---------------------------------------------------------------------------
# Security response headers (RESIDUALS #3)
# ---------------------------------------------------------------------------

class TestSecurityHeaders:
    def test_headers_present_on_index(self, client):
        r = client.get("/")
        assert r.headers["X-Frame-Options"] == "DENY"
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["Referrer-Policy"] == "no-referrer"
        csp = r.headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
        assert "'unsafe-inline'" not in csp

    def test_no_inline_script_in_template(self, client):
        # Strict CSP forbids inline JS — the page must load app.js externally.
        r = client.get("/")
        assert b"/static/app.js" in r.data


# ---------------------------------------------------------------------------
# Temp-dir cleanup (orphan reaping)
# ---------------------------------------------------------------------------

class TestJobCleanup:
    def test_errored_job_purges_its_dir(self, client, tmp_path):
        # A file that parses as XML-ish but yields no findings -> job errors.
        data = {"results": (io.BytesIO(b"<broken"), "bad.xml")}
        r = client.post("/api/process", data=data, content_type="multipart/form-data")
        assert r.status_code == 200
        job_id = r.get_json()["job_id"]

        final = _wait_for_completion(client, job_id)
        assert final["status"] == "error"

        # Status entry survives (poll returned "error"), but on-disk files are gone.
        job_dir = tmp_path / "jobs" / job_id
        assert not job_dir.exists()

    def test_sweep_removes_old_dirs_keeps_fresh(self, tmp_path, monkeypatch):
        import importlib
        import os
        monkeypatch.setenv("STIG_TEMP_DIR", str(tmp_path / "jobs"))
        import app.web as web_module
        importlib.reload(web_module)

        temp_dir = tmp_path / "jobs"
        temp_dir.mkdir(parents=True)
        old = temp_dir / "old-job"
        fresh = temp_dir / "fresh-job"
        old.mkdir()
        fresh.mkdir()

        # Age the old dir past the orphan cutoff.
        stale = time.time() - (web_module._ORPHAN_MAX_AGE_HOURS + 1) * 3600
        os.utime(old, (stale, stale))

        web_module._sweep_orphaned_jobs()

        assert not old.exists()
        assert fresh.exists()

    def test_sweep_spares_stale_dir_of_running_job(self, tmp_path, monkeypatch):
        """A job still 'running' must not be reaped no matter how stale its dir.

        Guards against the sweeper deleting a live worker's inputs out from under
        it — e.g. a slow parse of a huge archive that hasn't touched disk in >8h.
        """
        import importlib
        import os
        monkeypatch.setenv("STIG_TEMP_DIR", str(tmp_path / "jobs"))
        import app.web as web_module
        importlib.reload(web_module)

        temp_dir = tmp_path / "jobs"
        temp_dir.mkdir(parents=True)
        running = temp_dir / "running-job"
        orphan = temp_dir / "orphan-job"
        running.mkdir()
        orphan.mkdir()

        # Both dirs are equally stale; only status distinguishes them.
        stale = time.time() - (web_module._ORPHAN_MAX_AGE_HOURS + 1) * 3600
        os.utime(running, (stale, stale))
        os.utime(orphan, (stale, stale))

        # The running job has a live, non-terminal in-memory status; the orphan
        # has no entry at all (as if left by a prior process).
        web_module._set_job("running-job", status="running")

        web_module._sweep_orphaned_jobs()

        assert running.exists(), "sweeper deleted a running job's working dir"
        assert not orphan.exists()

        # A terminal status is fair game once stale (e.g. a completed, never
        # downloaded report).
        web_module._set_job("running-job", status="complete")
        web_module._sweep_orphaned_jobs()
        assert not running.exists()

    def test_start_orphan_sweeper_runs_sweep(self, tmp_path, monkeypatch):
        import importlib
        import os
        monkeypatch.setenv("STIG_TEMP_DIR", str(tmp_path / "jobs"))
        import app.web as web_module
        importlib.reload(web_module)

        temp_dir = tmp_path / "jobs"
        temp_dir.mkdir(parents=True)
        old = temp_dir / "old-job"
        old.mkdir()
        stale = time.time() - (web_module._ORPHAN_MAX_AGE_HOURS + 1) * 3600
        os.utime(old, (stale, stale))

        # A tiny interval means the daemon sweeps almost immediately.
        web_module._start_orphan_sweeper(interval_seconds=0.05)

        deadline = time.time() + 5.0
        while old.exists() and time.time() < deadline:
            time.sleep(0.05)
        assert not old.exists()
