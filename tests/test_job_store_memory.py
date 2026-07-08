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
