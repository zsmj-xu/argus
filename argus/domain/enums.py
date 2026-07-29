"""Closed enums used by the Argus V2 control plane."""

from __future__ import annotations

from enum import Enum


class ScanStatus(str, Enum):
    CREATED = "created"
    SNAPSHOTTING = "snapshotting"
    PLANNING = "planning"
    READY = "ready"
    RUNNING = "running"
    WAITING_REVIEW = "waiting_review"
    STATIC_COMPLETED = "static_completed"
    WAITING_VERIFICATION_INPUT = "waiting_verification_input"
    WAITING_APPROVAL = "waiting_approval"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


class TaskStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    WAITING_REVIEW = "waiting_review"
    INTERRUPTED = "interrupted"
    FAILED_RETRYABLE = "failed_retryable"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELED = "canceled"


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"
    STATIC_SUPPORTED = "static_supported"
    REJECTED_STATIC = "rejected_static"
    UNVERIFIED = "unverified"


class ScanEngine(str, Enum):
    LEGACY = "legacy"
    V2 = "v2"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class StaticConfidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EventLevel(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class VcsType(str, Enum):
    GIT = "git"
    DIRECTORY = "directory"


class PluginKind(str, Enum):
    GRAPH_PROVIDER = "graph_provider"
    ENRICHER = "enricher"
    SEMANTIC_ADAPTER = "semantic_adapter"
    DETECTOR = "detector"
    EXPERT = "expert"
    AGGREGATOR = "aggregator"
    REPORTER = "reporter"
    LEGACY_ANALYZER = "legacy_analyzer"
    REVIEW_GATE = "review_gate"
    VERIFIER = "verifier"


class AttemptStatus(str, Enum):
    RUNNING = "running"
    WAITING_REVIEW = "waiting_review"
    SUCCEEDED = "succeeded"
    FAILED_RETRYABLE = "failed_retryable"
    FAILED = "failed"
    INTERRUPTED = "interrupted"
    CANCELED = "canceled"


class ReviewSubjectType(str, Enum):
    ARTIFACT = "artifact"
    FINDING_SET = "finding_set"


class ReviewStatus(str, Enum):
    OPEN = "open"
    APPROVED = "approved"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"
