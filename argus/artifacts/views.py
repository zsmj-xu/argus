"""Typed artifact publication and read-only views."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, JsonValue

from argus.artifacts.codecs import encode_json, encode_jsonl, encode_text
from argus.artifacts.schemas import ArtifactPublication, BlobInfo
from argus.artifacts.store import ArtifactStore
from argus.control.repositories import ArtifactRepository
from argus.domain.errors import ArtifactCorruptionError
from argus.domain.models import Artifact


class ArtifactPublisher:
    def __init__(self, store: ArtifactStore, repository: ArtifactRepository) -> None:
        self.store = store
        self.repository = repository

    def _create(self, blob: BlobInfo, publication: ArtifactPublication) -> Artifact:
        artifact = Artifact(
            id=publication.artifact_id or uuid4(),
            scan_id=publication.scan_id,
            snapshot_id=publication.snapshot_id,
            task_id=publication.task_id,
            artifact_type=publication.artifact_type,
            schema_version=publication.schema_version,
            capabilities=publication.capabilities,
            producer_plugin_id=publication.producer_plugin_id,
            producer_plugin_version=publication.producer_plugin_version,
            media_type=publication.media_type,
            content_hash=blob.content_hash,
            size_bytes=blob.size_bytes,
            storage_uri=blob.storage_uri,
            metadata=publication.metadata,
        )
        return self.repository.create(artifact)

    def publish_bytes(self, payload: bytes, publication: ArtifactPublication) -> Artifact:
        return self._create(self.store.put_bytes(payload), publication)

    def publish_json(self, value: JsonValue | BaseModel, publication: ArtifactPublication) -> Artifact:
        return self.publish_bytes(encode_json(value), publication)

    def publish_jsonl(
        self,
        records: list[JsonValue | BaseModel],
        publication: ArtifactPublication,
    ) -> Artifact:
        return self.publish_bytes(encode_jsonl(records), publication)

    def publish_text(self, value: str, publication: ArtifactPublication) -> Artifact:
        return self.publish_bytes(encode_text(value), publication)

    def publish_file(self, source: str | Path, publication: ArtifactPublication) -> Artifact:
        return self._create(self.store.put_file(source), publication)


class ArtifactView:
    def __init__(self, store: ArtifactStore) -> None:
        self.store = store

    def read_bytes(self, artifact: Artifact) -> bytes:
        uri_hash = self.store.hash_from_uri(artifact.storage_uri)
        if uri_hash != artifact.content_hash:
            raise ArtifactCorruptionError(
                f"artifact metadata hash mismatch: URI={uri_hash}, metadata={artifact.content_hash}"
            )
        return self.store.read_bytes(artifact.content_hash, expected_size=artifact.size_bytes)

    def read_json(self, artifact: Artifact) -> JsonValue:
        self.read_bytes(artifact)
        return self.store.read_json(artifact.content_hash, expected_size=artifact.size_bytes)
