from app.core.artifact_store import LocalArtifactStore


def test_put_then_get_bytes_roundtrip(tmp_path):
    store = LocalArtifactStore(tmp_path)
    store.put_bytes("jobs/1/findings.json", b'{"a":1}')
    assert store.get_bytes("jobs/1/findings.json") == b'{"a":1}'


def test_exists(tmp_path):
    store = LocalArtifactStore(tmp_path)
    assert store.exists("missing/key") is False
    store.put_bytes("present/key", b"x")
    assert store.exists("present/key") is True


def test_download_to_and_upload_from(tmp_path):
    store = LocalArtifactStore(tmp_path)
    src = tmp_path / "src.bin"
    src.write_bytes(b"payload")
    store.upload_from("k/obj.bin", src)
    dst = tmp_path / "out" / "obj.bin"
    store.download_to("k/obj.bin", dst)
    assert dst.read_bytes() == b"payload"


def test_presign_get_returns_file_uri(tmp_path):
    store = LocalArtifactStore(tmp_path)
    store.put_bytes("k/o", b"z")
    url = store.presign_get("k/o")
    assert url.startswith("file://")


def test_keys_are_sandboxed_within_root(tmp_path):
    store = LocalArtifactStore(tmp_path)
    # Path-traversal keys must not escape the root.
    import pytest
    with pytest.raises(ValueError):
        store.put_bytes("../escape.txt", b"nope")
