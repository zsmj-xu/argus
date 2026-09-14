"""Architecture checks for the final white-box service shape."""

from __future__ import annotations

import ast
from pathlib import Path


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_application_code_has_no_retired_argus_imports() -> None:
    root = _root() / "argus"
    retired = {
        "argus.analyzers",
        "argus.control",
        "argus.detection",
        "argus.domain",
        "argus.execution",
        "argus.graph",
        "argus.llm",
        "argus.orchestration",
        "argus.planning",
        "argus.plugins",
        "argus.reporting",
        "argus.review",
        "argus.security_ir",
        "argus.snapshots",
        "argus.verification",
    }
    violations: list[str] = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported = {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported = {node.module or ""}
            else:
                continue
            if any(item in retired or any(item.startswith(prefix + ".") for prefix in retired) for item in imported):
                violations.append(path.relative_to(root.parent).as_posix())
    assert violations == []


def test_final_package_contains_only_service_boundaries() -> None:
    root = _root() / "argus"
    top_level = {path.name for path in root.iterdir() if path.is_dir() and path.name != "__pycache__"}
    assert top_level == {"service"}
