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
    jobs.create(job_id, status="queued")
    _seed_input(store, job_id, "bad.xml", b"<html></html>")

    result = run_parse_stage(job_id, ["bad.xml"], store, jobs, work_dir=tmp_path / "w")
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
    jobs.create(job_id, status="queued")

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
    jobs.create(job_id, status="queued")

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


def test_cancelled_job_does_not_enter_parse_stage(tmp_path):
    class ReadForbiddenStore(LocalArtifactStore):
        def size(self, key):
            raise AssertionError(f"cancelled job read input {key}")

    store = ReadForbiddenStore(tmp_path / "artifacts")
    jobs = MemoryJobStore()
    jobs.create("jobC", status="cancelled", progress="Cancelled.")
    work_dir = tmp_path / "work"

    assert (
        run_parse_stage("jobC", ["scan.xml"], store, jobs, work_dir=work_dir) is False
    )
    assert jobs.get("jobC")["status"] == "cancelled"
    assert not work_dir.exists()


def test_export_completion_does_not_overwrite_midflight_cancel(tmp_path):
    jobs = MemoryJobStore()
    job_id = "jobC"

    class CancelOnUploadStore(LocalArtifactStore):
        def upload_from(self, key, source):
            super().upload_from(key, source)
            assert jobs.transition(job_id, "cancelled", progress="Cancelled.")

    store = CancelOnUploadStore(tmp_path / "artifacts")
    jobs.create(job_id, status="running", source_file_count=1)
    findings_json = (
        '[{"stig_title":"T","vuln_id":"V-1","rule_id":"r",'
        '"severity":"CAT II","status":"Open","server":"h",'
        '"ip_address":"1.1.1.1","check_text":"c","fix_text":"f"}]'
    )
    store.put_bytes(FINDINGS_KEY.format(job_id=job_id), findings_json.encode())

    assert run_export_stage(job_id, store, jobs, work_dir=tmp_path / "w") is False
    record = jobs.get(job_id)
    assert record["status"] == "cancelled"
    assert record["progress"] == "Cancelled."
    assert "summary" not in record


def test_duplicate_export_after_completion_is_idempotent(tmp_path):
    class ReadForbiddenStore(LocalArtifactStore):
        def get_bytes(self, key):
            raise AssertionError(f"completed job reread artifact {key}")

    store = ReadForbiddenStore(tmp_path / "artifacts")
    jobs = MemoryJobStore()
    jobs.create("jobD", status="complete", summary={"findings": 1})

    assert run_export_stage("jobD", store, jobs, work_dir=tmp_path / "w") is True
    assert jobs.get("jobD")["status"] == "complete"


def test_parse_retry_after_parsed_phase_does_not_touch_inputs(tmp_path):
    class ReadForbiddenStore(LocalArtifactStore):
        def size(self, key):
            raise AssertionError(f"parsed job reread input {key}")

    jobs = MemoryJobStore()
    jobs.create("jobP", status="running", phase="parsed", progress="Parsed.")

    assert (
        run_parse_stage(
            "jobP",
            ["scan.xml"],
            ReadForbiddenStore(tmp_path / "artifacts"),
            jobs,
            work_dir=tmp_path / "w",
        )
        is True
    )
    assert jobs.get("jobP")["phase"] == "parsed"


def test_delayed_parse_failure_cannot_reclassify_exporting_job(tmp_path):
    jobs = MemoryJobStore()
    jobs.create("jobP", status="running", phase="parsing")

    class AdvanceThenFailStore(LocalArtifactStore):
        def size(self, key):
            assert jobs.update_if_status(
                "jobP",
                {"running"},
                expected_fields={"phase": "parsing"},
                phase="exporting",
            )
            raise RuntimeError("stale parser failed")

    assert (
        run_parse_stage(
            "jobP",
            ["scan.xml"],
            AdvanceThenFailStore(tmp_path / "artifacts"),
            jobs,
            work_dir=tmp_path / "w",
        )
        is True
    )
    assert jobs.get("jobP")["status"] == "running"
    assert jobs.get("jobP")["phase"] == "exporting"


def test_export_guard_losing_to_completion_is_idempotent(tmp_path):
    wrapped = MemoryJobStore()
    wrapped.create("jobR", status="running")

    class CompleteBeforeGuard:
        def __init__(self):
            self._injected = False

        def get(self, job_id):
            return wrapped.get(job_id)

        def update_if_status(self, job_id, expected_statuses, **fields):
            if not self._injected:
                self._injected = True
                assert wrapped.transition(
                    job_id, "complete", progress="Done.", summary={"findings": 1}
                )
            return wrapped.update_if_status(job_id, expected_statuses, **fields)

    class ReadForbiddenStore(LocalArtifactStore):
        def get_bytes(self, key):
            raise AssertionError(f"completed peer should prevent artifact read {key}")

    assert (
        run_export_stage(
            "jobR",
            ReadForbiddenStore(tmp_path / "artifacts"),
            CompleteBeforeGuard(),
            work_dir=tmp_path / "w",
        )
        is True
    )
    assert wrapped.get("jobR")["status"] == "complete"
