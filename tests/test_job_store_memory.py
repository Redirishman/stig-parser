import pytest

from app.core.job_store import MemoryJobStore


def test_create_then_get():
    store = MemoryJobStore()
    store.create("job1", status="running", progress="Starting…")
    job = store.get("job1")
    assert job["status"] == "running"
    assert job["progress"] == "Starting…"


def test_update_merges_fields():
    store = MemoryJobStore()
    store.create("job1", status="running")
    store.update("job1", progress="Parsing…", warnings=["w1"])
    job = store.get("job1")
    assert job["status"] == "running"
    assert job["progress"] == "Parsing…"
    assert job["warnings"] == ["w1"]


def test_get_missing_returns_empty_dict():
    assert MemoryJobStore().get("nope") == {}


def test_delete_removes_job():
    store = MemoryJobStore()
    store.create("job1", status="running")
    store.delete("job1")
    assert store.get("job1") == {}


def test_get_returns_a_copy():
    store = MemoryJobStore()
    store.create("job1", status="running")
    job = store.get("job1")
    job["status"] = "mutated"
    assert store.get("job1")["status"] == "running"


def test_legal_lifecycle_transitions_are_atomic():
    store = MemoryJobStore()
    store.create("job1", status="pending")

    assert store.transition("job1", "queued", progress="Queued.") is True
    assert store.transition("job1", "running", progress="Parsing.") is True
    assert store.transition("job1", "complete", summary={"findings": 1}) is True

    assert store.get("job1") == {
        "status": "complete",
        "progress": "Parsing.",
        "summary": {"findings": 1},
    }


@pytest.mark.parametrize(
    ("initial_status", "late_status", "late_fields"),
    [
        ("pending", "queued", {"progress": "Queued."}),
        ("queued", "running", {"progress": "Parsing."}),
        ("running", "complete", {"summary": {"findings": 1}}),
        ("running", "error", {"error": "late failure"}),
    ],
)
def test_cancelled_job_rejects_stale_transition(
    initial_status, late_status, late_fields
):
    store = MemoryJobStore()
    store.create("job1", status=initial_status)

    assert store.transition("job1", "cancelled", progress="Cancelled.") is True
    assert store.transition("job1", late_status, **late_fields) is False

    record = store.get("job1")
    assert record["status"] == "cancelled"
    assert record["progress"] == "Cancelled."
    for field in late_fields:
        if field != "progress":
            assert field not in record


def test_terminal_status_rejects_companion_field_patch():
    store = MemoryJobStore()
    store.create("job1", status="cancelled", progress="Cancelled.")

    assert (
        store.update_if_status(
            "job1", {"running"}, progress="Parsed.", source_file_count=2
        )
        is False
    )
    assert store.get("job1") == {
        "status": "cancelled",
        "progress": "Cancelled.",
    }


def test_status_cannot_bypass_transition_contract():
    store = MemoryJobStore()
    store.create("job1", status="running")

    with pytest.raises(ValueError, match="transition"):
        store.update("job1", status="complete")


def test_expected_phase_blocks_stale_transition_fields():
    store = MemoryJobStore()
    store.create("job1", status="running", phase="parsing")

    assert (
        store.transition(
            "job1",
            "complete",
            expected_fields={"phase": "exporting"},
            summary={"findings": 1},
        )
        is False
    )
    assert store.get("job1") == {"status": "running", "phase": "parsing"}
