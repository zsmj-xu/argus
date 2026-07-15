"""CodegraphHandle 测试 —— 对 tests/fixtures/mini.db 读图。

mini.db 由 tests/fixtures/make_mini_db.py 生成:
- file 节点 `file:api/auth.py`
- function 节点 `api/auth.py::login`(name='login')
- function 节点 `api/auth.py::authenticate`(name='authenticate')
- calls 边:authenticate -> login
"""

from __future__ import annotations

import os

import pytest

from argus.contracts import GraphHandle
from argus.graph.codegraph import CodegraphHandle

FIXTURE_DB = os.path.join(os.path.dirname(__file__), "..", "fixtures", "mini.db")


def _handle() -> CodegraphHandle:
    return CodegraphHandle(FIXTURE_DB)


def test_query_finds_node() -> None:
    rows = _handle().query("login")
    assert any(r["name"] == "login" for r in rows)


def test_query_is_case_insensitive() -> None:
    rows = _handle().query("LOGIN")
    assert any(r["name"] == "login" for r in rows)


def test_query_returns_expected_columns() -> None:
    rows = _handle().query("login")
    row = next(r for r in rows if r["name"] == "login")
    for col in ("id", "kind", "name", "file_path", "start_line"):
        assert col in row
    assert row["kind"] == "function"


def test_node_returns_none_for_unknown() -> None:
    assert _handle().node("nope:does-not-exist") is None


def test_node_returns_details_with_edges() -> None:
    node = _handle().node("api/auth.py::login")
    assert node is not None
    assert node["name"] == "login"
    # login 被 authenticate 调用 -> 应出现在 incoming edges
    assert "edges" in node
    kinds = {e["kind"] for e in node["edges"]}
    assert "calls" in kinds


def test_callers_of_login() -> None:
    callers = _handle().callers("login")
    assert any(c["name"] == "authenticate" for c in callers)


def test_callees_of_authenticate() -> None:
    callees = _handle().callees("authenticate")
    assert any(c["name"] == "login" for c in callees)


def test_callers_of_unknown_is_empty() -> None:
    assert _handle().callers("does-not-exist") == []


def test_explore_returns_str() -> None:
    # explore 回退到 DB 组装(fixture 不是真实 codegraph 项目)
    out = _handle().explore("login")
    assert isinstance(out, str)
    assert "login" in out


def test_satisfies_graphhandle_protocol() -> None:
    assert isinstance(_handle(), GraphHandle)


def test_missing_db_raises_clear_error_without_creating_file(tmp_path: object) -> None:
    """db 不存在时应抛清晰错误,且不在磁盘上留下空文件。"""
    missing = os.path.join(str(tmp_path), "does-not-exist.db")
    assert not os.path.exists(missing)

    with pytest.raises(FileNotFoundError, match="codegraph db not found"):
        CodegraphHandle(missing)

    assert not os.path.exists(missing), "不存在的 db 路径不应被静默创建"
