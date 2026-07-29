from __future__ import annotations

from pathlib import Path

import pytest

from argus.domain.errors import SnapshotError
from argus.snapshots.hashing import build_manifest
from argus.snapshots.ignore import IgnoreMatcher


def _manifest(root: Path, *, runs_root: Path | None = None, ignore: list[str] | None = None) -> str:
    matcher = IgnoreMatcher(root, runs_root=runs_root or root.parent / "runs", custom_patterns=ignore)
    return build_manifest(root, matcher).tree_hash


def test_same_source_tree_has_same_hash(tmp_path: Path) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    for root in (left, right):
        (root / "src").mkdir(parents=True)
        (root / "src" / "app.py").write_text("print('ok')\n", encoding="utf-8")
        (root / "empty").mkdir()

    assert _manifest(left) == _manifest(right)


@pytest.mark.parametrize("mutation", ["modify", "add", "delete"])
def test_tree_mutations_change_hash(tmp_path: Path, mutation: str) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    original = root / "app.py"
    original.write_text("one\n", encoding="utf-8")
    before = _manifest(root)

    if mutation == "modify":
        original.write_text("two\n", encoding="utf-8")
    elif mutation == "add":
        (root / "new.py").write_text("new\n", encoding="utf-8")
    else:
        original.unlink()

    assert _manifest(root) != before


def test_default_custom_and_runs_ignores_are_deterministic(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "keep.py").write_text("keep\n", encoding="utf-8")
    (root / "secret.txt").write_text("secret\n", encoding="utf-8")
    (root / ".git").mkdir()
    (root / ".git" / "index").write_bytes(b"git")
    (root / ".codegraph").mkdir()
    (root / ".codegraph" / "codegraph.db").write_bytes(b"graph")
    runs_root = root / "runs"
    runs_root.mkdir()
    (runs_root / "control.db").write_bytes(b"control")

    manifest = build_manifest(
        root,
        IgnoreMatcher(root, runs_root=runs_root, custom_patterns=["secret.txt"]),
    )

    assert [entry.path for entry in manifest.entries] == ["keep.py"]


def test_symlink_that_escapes_repository_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    (root / "escape").symlink_to(outside)

    with pytest.raises(SnapshotError, match="symlink escapes repository"):
        build_manifest(root, IgnoreMatcher(root, runs_root=tmp_path / "runs"))
