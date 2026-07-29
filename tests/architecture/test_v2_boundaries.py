"""Architecture guards for the incremental Argus V2 migration."""

from __future__ import annotations

import ast
from pathlib import Path


V2_NAMESPACES = {
    "artifacts",
    "control",
    "detection",
    "domain",
    "execution",
    "legacy",
    "planning",
    "plugins",
    "security_ir",
    "snapshots",
    "verification",
    "web_api",
}
FORBIDDEN_MODULE = "argus.orchestration.pipeline"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _imports_fixed_pipeline(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name == FORBIDDEN_MODULE for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module in {FORBIDDEN_MODULE, "orchestration.pipeline"}:
                return True
            if module in {"argus.orchestration", "orchestration"} and any(
                alias.name == "pipeline" for alias in node.names
            ):
                return True
    return False


def test_v2_namespaces_do_not_depend_on_fixed_pipeline() -> None:
    """Future V2 modules must remain independent of the legacy six-node graph."""
    argus_root = _repo_root() / "argus"
    violations = [
        path.relative_to(_repo_root()).as_posix()
        for namespace in sorted(V2_NAMESPACES)
        for path in sorted((argus_root / namespace).rglob("*.py"))
        if _imports_fixed_pipeline(path)
    ]

    assert violations == [], (
        f"V2 namespaces must use explicit legacy adapters instead of importing {FORBIDDEN_MODULE}: {violations}"
    )
