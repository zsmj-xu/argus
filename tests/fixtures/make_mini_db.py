"""生成测试用的最小 codegraph SQLite 图 (tests/fixtures/mini.db)。

schema 对齐真实 codegraph.db(2026-07-15 核查):nodes / edges 两表,列齐全。
造 2 个节点(1 file、1 function `login`)+ 1 条 calls 边,供 GraphHandle 测试。

复现:`python tests/fixtures/make_mini_db.py`(幂等,会重建 mini.db)。
"""

from __future__ import annotations

import os
import sqlite3

FIXTURE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(FIXTURE_DIR, "mini.db")

# 真实 codegraph nodes 表列定义
NODES_SCHEMA = """
CREATE TABLE nodes (
    id TEXT PRIMARY KEY,
    kind TEXT,
    name TEXT,
    qualified_name TEXT,
    file_path TEXT,
    language TEXT,
    start_line INT,
    end_line INT,
    start_column INT,
    end_column INT,
    docstring TEXT,
    signature TEXT,
    visibility TEXT,
    is_exported INT,
    is_async INT,
    is_static INT,
    is_abstract INT,
    decorators TEXT,
    type_parameters TEXT,
    return_type TEXT,
    updated_at INT
)
"""

# 真实 codegraph edges 表列定义
EDGES_SCHEMA = """
CREATE TABLE edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT,
    target TEXT,
    kind TEXT,
    metadata TEXT,
    line INT,
    col INT,
    provenance TEXT,
    FOREIGN KEY (source) REFERENCES nodes (id),
    FOREIGN KEY (target) REFERENCES nodes (id)
)
"""


def build() -> None:
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(NODES_SCHEMA)
        conn.execute(EDGES_SCHEMA)

        # 1 个 file 节点
        conn.execute(
            "INSERT INTO nodes (id, kind, name, qualified_name, file_path, language, "
            "start_line, end_line) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "file:api/auth.py",
                "file",
                "auth.py",
                "api/auth.py",
                "api/auth.py",
                "python",
                1,
                42,
            ),
        )

        # 1 个 function 节点,name='login'
        conn.execute(
            "INSERT INTO nodes (id, kind, name, qualified_name, file_path, language, "
            "start_line, end_line, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "api/auth.py::login",
                "function",
                "login",
                "api.auth.login",
                "api/auth.py",
                "python",
                10,
                25,
                "def login(username: str, password: str) -> bool",
            ),
        )

        # 另一个 function 节点,作为 login 的调用者
        conn.execute(
            "INSERT INTO nodes (id, kind, name, qualified_name, file_path, language, "
            "start_line, end_line, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "api/auth.py::authenticate",
                "function",
                "authenticate",
                "api.auth.authenticate",
                "api/auth.py",
                "python",
                28,
                42,
                "def authenticate(request) -> Response",
            ),
        )

        # 1 条 calls 边:authenticate -> login
        conn.execute(
            "INSERT INTO edges (source, target, kind, line, col) VALUES (?, ?, ?, ?, ?)",
            ("api/auth.py::authenticate", "api/auth.py::login", "calls", 30, 8),
        )

        conn.commit()
    finally:
        conn.close()

    print(f"wrote {DB_PATH}")


if __name__ == "__main__":
    build()
