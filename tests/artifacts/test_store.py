from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from argus.artifacts.store import ArtifactStore
from argus.domain.errors import ArtifactCorruptionError


def test_json_is_canonical_and_same_content_is_deduplicated(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "runs")

    left = store.put_json({"b": 2, "a": 1})
    right = store.put_json({"a": 1, "b": 2})

    assert left == right
    assert store.read_bytes(left.content_hash) == b'{"a":1,"b":2}'
    payloads = list(store.root.rglob("payload"))
    assert len(payloads) == 1


def test_store_supports_jsonl_text_binary_and_sqlite(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "runs")
    jsonl = store.put_jsonl([{"b": 2, "a": 1}, {"line": 2}])
    text = store.put_text("hello\n")
    binary_path = tmp_path / "payload.bin"
    binary_path.write_bytes(b"\x00\x01\xff")
    binary = store.put_file(binary_path)
    sqlite_path = tmp_path / "fixture.db"
    connection = sqlite3.connect(sqlite_path)
    connection.execute("CREATE TABLE demo (id INTEGER PRIMARY KEY)")
    connection.commit()
    connection.close()
    sqlite_blob = store.put_file(sqlite_path)

    assert store.read_bytes(jsonl.content_hash) == b'{"a":1,"b":2}\n{"line":2}\n'
    assert store.read_bytes(text.content_hash) == b"hello\n"
    assert store.read_bytes(binary.content_hash) == b"\x00\x01\xff"
    assert store.verify(sqlite_blob.content_hash).size_bytes == sqlite_path.stat().st_size


def test_read_handle_is_read_only(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "runs")
    blob = store.put_text("immutable")

    with store.open_read(blob.content_hash) as handle:
        assert handle.read() == b"immutable"
        assert handle.writable() is False


def test_corrupted_payload_is_detected(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "runs")
    blob = store.put_text("original")
    payload = store.root / blob.content_hash[:2] / blob.content_hash / "payload"
    payload.write_text("corrupted", encoding="utf-8")

    with pytest.raises(ArtifactCorruptionError, match="hash mismatch"):
        store.read_bytes(blob.content_hash, expected_size=blob.size_bytes)


def test_missing_and_wrong_size_are_detected(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "runs")
    blob = store.put_text("content")

    with pytest.raises(ArtifactCorruptionError, match="size mismatch"):
        store.verify(blob.content_hash, expected_size=999)
    payload = store.root / blob.content_hash[:2] / blob.content_hash / "payload"
    payload.unlink()
    with pytest.raises(ArtifactCorruptionError, match="missing"):
        store.verify(blob.content_hash)


def test_materialize_verifies_and_atomically_copies_payload(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "runs")
    blob = store.put_bytes(b"database")
    destination = tmp_path / "snapshot" / ".codegraph" / "codegraph.db"

    store.materialize(blob.content_hash, destination, expected_size=blob.size_bytes)

    assert destination.read_bytes() == b"database"
    assert not list(destination.parent.glob(".codegraph.db.*"))


def test_failed_atomic_publish_leaves_no_payload_or_temp_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ArtifactStore(tmp_path / "runs")

    def fail_replace(_source: object, _destination: object) -> None:
        raise OSError("fixture replace failure")

    monkeypatch.setattr("argus.artifacts.store.os.replace", fail_replace)
    with pytest.raises(OSError, match="fixture replace failure"):
        store.put_bytes(b"not-published")

    assert list(store.root.rglob("payload")) == []
    assert list(store.root.rglob(".payload.*")) == []


def test_read_json_rejects_non_json_payload(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "runs")
    blob = store.put_text("not json")

    with pytest.raises(ArtifactCorruptionError, match="not valid JSON"):
        store.read_json(blob.content_hash)


def test_storage_uri_does_not_expose_filesystem_path(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "runs")
    blob = store.put_text("opaque")

    assert blob.storage_uri == f"artifact://sha256/{blob.content_hash}"
    assert str(tmp_path) not in blob.storage_uri
    assert json.loads(json.dumps(blob.model_dump(mode="json")))["storage_uri"] == blob.storage_uri
