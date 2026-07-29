"""Stable application errors for the V2 domain and control store."""

from __future__ import annotations


class ArgusV2Error(Exception):
    """Base class for expected V2 application failures."""


class NotFoundError(ArgusV2Error):
    """The requested domain object does not exist."""


class ConflictError(ArgusV2Error):
    """A uniqueness or optimistic-concurrency constraint was violated."""


class InvalidTransitionError(ArgusV2Error):
    """A state machine transition is not allowed."""


class SchemaValidationError(ArgusV2Error):
    """Persisted or incoming data failed its Pydantic schema."""


class SnapshotError(ArgusV2Error):
    """A source snapshot could not be created safely."""


class ArtifactCorruptionError(ArgusV2Error):
    """Artifact content is missing or does not match its recorded digest."""
