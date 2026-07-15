"""注册表发现机制测试。

M1 阶段没有任何分析器目录,discover_analyzers() 应优雅返回空 dict;
一旦出现分析器目录,收集到的每个实例都必须符合 Analyzer 协议。
"""

from __future__ import annotations

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
