"""Atomic content-addressed storage for immutable artifact payloads."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

from pydantic import JsonValue

from argus.artifacts.codecs import encode_json, encode_jsonl, encode_text
from argus.artifacts.schemas import BlobInfo
from argus.domain.errors import ArtifactCorruptionError

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_URI_PREFIX = "artifact://sha256/"
_CHUNK_SIZE = 1024 * 1024


class ArtifactStore:
    def __init__(self, runs_root: str | Path = "runs") -> None:
        self.root = Path(runs_root).resolve() / "_data" / "artifacts" / "sha256"
        self.staging_root = self.root.parent / ".tmp"

    @staticmethod
    def uri(content_hash: str) -> str:
        if not _SHA256.fullmatch(content_hash):
            raise ValueError("content hash must be lowercase SHA-256")
        return f"{_URI_PREFIX}{content_hash}"

    @staticmethod
    def hash_from_uri(storage_uri: str) -> str:
        if not storage_uri.startswith(_URI_PREFIX):
            raise ArtifactCorruptionError(f"unsupported artifact URI: {storage_uri}")
        content_hash = storage_uri.removeprefix(_URI_PREFIX)
        if not _SHA256.fullmatch(content_hash):
            raise ArtifactCorruptionError(f"invalid artifact URI: {storage_uri}")
        return content_hash

    def _payload_path(self, content_hash: str) -> Path:
        if not _SHA256.fullmatch(content_hash):
            raise ValueError("content hash must be lowercase SHA-256")
        return self.root / content_hash[:2] / content_hash / "payload"

    def put_bytes(self, payload: bytes) -> BlobInfo:
        content_hash = hashlib.sha256(payload).hexdigest()
        destination = self._payload_path(content_hash)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            return self.verify(content_hash, expected_size=len(payload))

        descriptor, temporary_name = tempfile.mkstemp(prefix=".payload.", dir=destination.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        return BlobInfo(
            content_hash=content_hash,
            size_bytes=len(payload),
            storage_uri=self.uri(content_hash),
        )

    def put_file(self, source: str | Path) -> BlobInfo:
        source_path = Path(source)
        self.staging_root.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix="artifact.", dir=self.staging_root)
        temporary = Path(temporary_name)
        digest = hashlib.sha256()
        size = 0
        try:
            with os.fdopen(descriptor, "wb") as output_handle:
                with source_path.open("rb") as input_handle:
                    while chunk := input_handle.read(_CHUNK_SIZE):
                        digest.update(chunk)
                        size += len(chunk)
                        output_handle.write(chunk)
                    output_handle.flush()
                    os.fsync(output_handle.fileno())
            content_hash = digest.hexdigest()
            destination = self._payload_path(content_hash)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                temporary.unlink()
                return self.verify(content_hash, expected_size=size)
            os.replace(temporary, destination)
            return BlobInfo(
                content_hash=content_hash,
                size_bytes=size,
                storage_uri=self.uri(content_hash),
            )
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise

    def put_json(self, value: JsonValue) -> BlobInfo:
        return self.put_bytes(encode_json(value))

    def put_jsonl(self, records: list[JsonValue]) -> BlobInfo:
        return self.put_bytes(encode_jsonl(records))

    def put_text(self, value: str) -> BlobInfo:
        return self.put_bytes(encode_text(value))

    def verify(self, content_hash: str, *, expected_size: int | None = None) -> BlobInfo:
        path = self._payload_path(content_hash)
        try:
            handle = path.open("rb")
        except FileNotFoundError as exc:
            raise ArtifactCorruptionError(f"artifact payload is missing: {content_hash}") from exc
        digest = hashlib.sha256()
        size = 0
        with handle:
            while chunk := handle.read(_CHUNK_SIZE):
                digest.update(chunk)
                size += len(chunk)
        actual_hash = digest.hexdigest()
        if actual_hash != content_hash:
            raise ArtifactCorruptionError(f"artifact hash mismatch: expected {content_hash}, got {actual_hash}")
        if expected_size is not None and size != expected_size:
            raise ArtifactCorruptionError(
                f"artifact size mismatch for {content_hash}: expected {expected_size}, got {size}"
            )
        return BlobInfo(content_hash=content_hash, size_bytes=size, storage_uri=self.uri(content_hash))

    def verified_path(
        self,
        content_hash: str,
        *,
        expected_size: int | None = None,
    ) -> Path:
        """Return the local immutable payload path after full hash verification."""
        self.verify(content_hash, expected_size=expected_size)
        return self._payload_path(content_hash)

    @contextmanager
    def open_read(self, content_hash: str, *, expected_size: int | None = None) -> Iterator[BinaryIO]:
        self.verify(content_hash, expected_size=expected_size)
        with self._payload_path(content_hash).open("rb") as handle:
            yield handle

    def read_bytes(self, content_hash: str, *, expected_size: int | None = None) -> bytes:
        with self.open_read(content_hash, expected_size=expected_size) as handle:
            return handle.read()

    def read_json(self, content_hash: str, *, expected_size: int | None = None) -> JsonValue:
        payload = self.read_bytes(content_hash, expected_size=expected_size)
        try:
            value: JsonValue = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ArtifactCorruptionError(f"artifact is not valid JSON: {content_hash}") from exc
        return value

    def materialize(
        self,
        content_hash: str,
        destination: str | Path,
        *,
        expected_size: int | None = None,
    ) -> None:
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                with self.open_read(content_hash, expected_size=expected_size) as source:
                    while chunk := source.read(_CHUNK_SIZE):
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            os.replace(temporary, target)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
