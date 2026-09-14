"""Self-contained API-key scanning service core.

This package deliberately does not import the legacy Argus domain.  It is a
small queue-backed service boundary which can be connected to a real scanner
by implementing the protocols in :mod:`argus.service.worker`.
"""

from .app import create_app
from .integration import (
    GitWorkspaceProvider,
    OpenCodeReviewServiceRunner,
    PreparedWorkspace,
    RepositoryFetchError,
    RepositoryLimitError,
)
from .models import (
    FindingCreate,
    FindingResponse,
    ReportFormat,
    ScanCreateRequest,
    ScanResponse,
    ScanProgress,
    ServiceScanResult,
    ScanStatus,
)
from .store import (
    IdempotencyConflict,
    LeaseLost,
    QueueFull,
    ScanNotFound,
    ScanStore,
    ScanStateError,
    resolve_scan_database,
)
from .store import WorkerScan
from .worker import OcrRunner, ScanWorker, WorkspaceProvider

__all__ = [
    "FindingCreate",
    "FindingResponse",
    "GitWorkspaceProvider",
    "IdempotencyConflict",
    "LeaseLost",
    "OcrRunner",
    "ReportFormat",
    "ScanCreateRequest",
    "ScanNotFound",
    "ScanResponse",
    "ScanProgress",
    "ServiceScanResult",
    "ScanStateError",
    "ScanStatus",
    "ScanStore",
    "ScanWorker",
    "OpenCodeReviewServiceRunner",
    "PreparedWorkspace",
    "RepositoryFetchError",
    "RepositoryLimitError",
    "QueueFull",
    "resolve_scan_database",
    "WorkerScan",
    "WorkspaceProvider",
    "create_app",
]
