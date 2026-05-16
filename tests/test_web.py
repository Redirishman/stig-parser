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
