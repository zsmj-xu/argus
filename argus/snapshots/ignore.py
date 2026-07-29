"""Deterministic ignore rules for source snapshots."""

from __future__ import annotations

import fnmatch
from pathlib import Path, PurePosixPath

DEFAULT_IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".codegraph",
        ".mypy_cache",
        ".nox",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "venv",
    }
)
DEFAULT_IGNORED_FILES = ("*.pyc", "*.pyo", ".DS_Store", ".coverage")


def _normalize_pattern(pattern: str) -> str:
    normalized = pattern.strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.rstrip("/")


class IgnoreMatcher:
    def __init__(
        self,
        repository_root: str | Path,
        *,
        runs_root: str | Path,
        custom_patterns: list[str] | None = None,
    ) -> None:
        self.repository_root = Path(repository_root).resolve()
        self.custom_patterns = tuple(
            normalized for pattern in (custom_patterns or []) if (normalized := _normalize_pattern(pattern))
        )
        resolved_runs = Path(runs_root).resolve()
        self.runs_relative: str | None
        try:
            self.runs_relative = resolved_runs.relative_to(self.repository_root).as_posix()
        except ValueError:
            self.runs_relative = None

    def ignores(self, relative_path: str, *, is_directory: bool) -> bool:
        normalized = relative_path.replace("\\", "/").strip("/")
        if not normalized:
            return False
        parts = PurePosixPath(normalized).parts
        if any(part in DEFAULT_IGNORED_DIRECTORIES for part in parts):
            return True
        if self.runs_relative is not None and (
            normalized == self.runs_relative or normalized.startswith(f"{self.runs_relative}/")
        ):
            return True
        if not is_directory and any(fnmatch.fnmatch(parts[-1], pattern) for pattern in DEFAULT_IGNORED_FILES):
            return True
        return any(self._matches_custom(normalized, pattern) for pattern in self.custom_patterns)

    @staticmethod
    def _matches_custom(relative_path: str, pattern: str) -> bool:
        if relative_path == pattern or relative_path.startswith(f"{pattern}/"):
            return True
        if fnmatch.fnmatch(relative_path, pattern):
            return True
        return PurePosixPath(relative_path).match(pattern)
