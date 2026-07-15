"""注册表发现机制测试。

M1 阶段没有任何分析器目录,discover_analyzers() 应优雅返回空 dict;
一旦出现分析器目录,收集到的每个实例都必须符合 Analyzer 协议。

另外守护一个易踩的坑:注册表必须区分「目录里没有 analyzer.py」(跳过,约定行为)
与「analyzer.py 存在但它内部 import 失败」(真 bug,必须暴露而非静默丢弃)。
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

import argus.analyzers as analyzers_pkg
from argus.contracts import Analyzer
from argus.orchestration.registry import discover_analyzers


def test_discover_returns_dict() -> None:
    reg = discover_analyzers()
    assert isinstance(reg, dict)


def test_discovered_values_satisfy_protocol() -> None:
    reg = discover_analyzers()
    for name, analyzer in reg.items():
        assert isinstance(name, str)
        assert isinstance(analyzer, Analyzer)
        assert analyzer.name == name


def _make_subpackage(root: Path, name: str, analyzer_src: str | None) -> None:
    """在 root 下造一个子包 <name>/;analyzer_src 为 None 时不写 analyzer.py。"""
    sub = root / name
    sub.mkdir(parents=True)
    (sub / "__init__.py").write_text("")
    if analyzer_src is not None:
        (sub / "analyzer.py").write_text(analyzer_src)


def _purge_submodules(monkeypatch: pytest.MonkeyPatch) -> None:
    """清掉 import 机器为临时子包缓存的条目,避免测试间串味。"""
    prefix = f"{analyzers_pkg.__name__}."
    for mod_name in [m for m in sys.modules if m.startswith(prefix)]:
        monkeypatch.delitem(sys.modules, mod_name, raising=False)


def test_skips_directory_without_analyzer_py(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """(a) 子包存在但没有 analyzer.py —— 正常跳过,不报错,不进注册表。"""
    _make_subpackage(tmp_path, "no_analyzer_here", analyzer_src=None)

    # 把 argus.analyzers 的搜索路径重定向到临时目录,让 iter_modules / import 只看它。
    monkeypatch.setattr(analyzers_pkg, "__path__", [str(tmp_path)])
    _purge_submodules(monkeypatch)

    reg = discover_analyzers()
    assert "no_analyzer_here" not in reg
    assert isinstance(reg, dict)


def test_surfaces_import_failure_inside_analyzer_py(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """(b) analyzer.py 存在但内部 import 了不存在的模块 —— 必须抛错而非静默跳过。"""
    _make_subpackage(
        tmp_path,
        "broken_analyzer",
        analyzer_src="import totally_missing_dependency_xyz  # noqa: F401\n",
    )

    monkeypatch.setattr(analyzers_pkg, "__path__", [str(tmp_path)])
    _purge_submodules(monkeypatch)

    with pytest.raises(ModuleNotFoundError) as excinfo:
        discover_analyzers()

    # 错误信息应指向真正缺失的依赖,而不是 analyzer 模块本身。
    assert "totally_missing_dependency_xyz" in str(excinfo.value)
