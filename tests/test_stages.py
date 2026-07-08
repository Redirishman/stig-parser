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


def test_findings_key_roundtrips_through_store(tmp_path):
    store = LocalArtifactStore(tmp_path / "artifacts")
    job_id = "job3"
    findings_json = "[]"
    store.put_bytes(FINDINGS_KEY.format(job_id=job_id), findings_json.encode())
    loaded = findings_from_json(
        store.get_bytes(FINDINGS_KEY.format(job_id=job_id)).decode()
    )
    assert loaded == []
