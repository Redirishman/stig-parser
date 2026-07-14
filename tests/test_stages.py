from pathlib import Path

from app.core.artifact_store import LocalArtifactStore
from app.core.findings_io import findings_from_json
from app.core.job_store import MemoryJobStore
from app.core.stages import (
    FINDINGS_KEY,
    INPUT_PREFIX,
    REPORT_KEY,
    run_export_stage,
    run_parse_stage,
)


def _seed_input(store, job_id, filename, data: bytes):
    store.put_bytes(f"{INPUT_PREFIX.format(job_id=job_id)}/{filename}", data)


def test_run_parse_stage_errors_on_garbage_input(tmp_path):
    store = LocalArtifactStore(tmp_path / "artifacts")
    jobs = MemoryJobStore()
    job_id = "job1"
    jobs.create(job_id, status="running")
    _seed_input(store, job_id, "bad.xml", b"<html></html>")

    result = run_parse_stage(
        job_id, ["bad.xml"], store, jobs, work_dir=tmp_path / "w"
    )
    assert result is False
    assert jobs.get(job_id)["status"] == "error"
    assert jobs.get(job_id)["error"]


def test_run_export_stage_reads_findings_and_writes_report(tmp_path):
    store = LocalArtifactStore(tmp_path / "artifacts")
    jobs = MemoryJobStore()
    job_id = "job2"
    jobs.create(job_id, status="running")

    # Seed a findings.json directly (bypassing parse) to test export in isolation.
    findings_json = (
        '[{"stig_title":"T","vuln_id":"V-1","rule_id":"r","severity":"CAT II",'
        '"status":"Open","server":"h","ip_address":"1.1.1.1","check_text":"c",'
        '"fix_text":"f"}]'
    )
    store.put_bytes(FINDINGS_KEY.format(job_id=job_id), findings_json.encode())

    ok = run_export_stage(job_id, store, jobs, work_dir=tmp_path / "w")
    assert ok is True
    assert store.exists(REPORT_KEY.format(job_id=job_id))
    job = jobs.get(job_id)
    assert job["status"] == "complete"
    assert job["summary"]["findings"] == 1


def test_run_parse_stage_rejects_traversal_filename(tmp_path):
    store = LocalArtifactStore(tmp_path / "artifacts")
    jobs = MemoryJobStore()
    job_id = "jobT"
    jobs.create(job_id, status="running")

    outside = tmp_path / "outside_target.xml"
    result = run_parse_stage(
        job_id,
        ["../../outside_target.xml"],
        store,
        jobs,
        work_dir=tmp_path / "w",
    )
    assert result is False
    assert jobs.get(job_id)["status"] == "error"
    assert jobs.get(job_id)["error"] == "Invalid input filename."
    # Nothing was written outside the job work dir.
    assert not outside.exists()


def test_run_parse_stage_error_message_is_generic_on_unexpected_failure(tmp_path):
    # findings path is fine, but force an unexpected failure by pointing the
    # export stage at un-decodable findings JSON; assert no internal detail leaks.
    store = LocalArtifactStore(tmp_path / "artifacts")
    jobs = MemoryJobStore()
    job_id = "jobG"
    jobs.create(job_id, status="running")
    store.put_bytes(FINDINGS_KEY.format(job_id=job_id), b"not valid json{")

    ok = run_export_stage(job_id, store, jobs, work_dir=tmp_path / "w")
    assert ok is False
    err = jobs.get(job_id)["error"]
    assert err == "Export failed — see server logs."
    # Must not contain exception/library internals.
    assert "json" not in err.lower()
    assert "Traceback" not in err


def test_findings_key_roundtrips_through_store(tmp_path):
    store = LocalArtifactStore(tmp_path / "artifacts")
    job_id = "job3"
    findings_json = "[]"
    store.put_bytes(FINDINGS_KEY.format(job_id=job_id), findings_json.encode())
    loaded = findings_from_json(
        store.get_bytes(FINDINGS_KEY.format(job_id=job_id)).decode()
    )
    assert loaded == []


def test_run_parse_stage_reads_inputs_from_a_separate_store(tmp_path):
    """GovCloud keeps raw uploads in their own bucket (shorter retention), so
    inputs may come from a different store than the one findings are written to."""
    uploads = LocalArtifactStore(tmp_path / "uploads")
    artifacts = LocalArtifactStore(tmp_path / "artifacts")
    jobs = MemoryJobStore()
    job_id = "job1"
    jobs.create(job_id, status="running")

    scan = Path(__file__).parent / "fixtures" / "scc_results.xml"
    _seed_input(uploads, job_id, "scan.xml", scan.read_bytes())

    result = run_parse_stage(
        job_id,
        ["scan.xml"],
        artifacts,
        jobs,
        work_dir=tmp_path / "w",
        input_store=uploads,
    )

    assert result is True
    # Findings land in the artifacts store; the uploads store stays input-only.
    assert artifacts.exists(FINDINGS_KEY.format(job_id=job_id))
    assert not uploads.exists(FINDINGS_KEY.format(job_id=job_id))
