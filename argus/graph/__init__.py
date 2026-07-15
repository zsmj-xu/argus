"""codegraph 代码图封装 —— 分析器通过 GraphHandle 读图,不直接碰 SQLite。"""

from __future__ import annotations

from argus.graph.build import build_graph
from argus.graph.codegraph import CodegraphHandle

__all__ = ["CodegraphHandle", "build_graph"]
