"""CodegraphHandle —— codegraph SQLite 图的只读句柄。

实现 `argus.contracts.GraphHandle` 协议:query / node / callers / callees / explore。
分析器只通过本句柄读图,不直接碰 SQLite。

底层 schema(真实 codegraph.db,2026-07-15 核查):
- nodes(id, kind, name, qualified_name, file_path, language, start_line, end_line, ...)
- edges(id, source, target, kind, metadata, line, col, provenance);source/target -> nodes.id
- edges.kind ∈ {calls, contains, imports, instantiates, references}
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
from typing import Any

# codegraph CLI 路径(Homebrew 软链)。找不到时回退用 PATH 里的 codegraph。
CODEGRAPH_BIN = "/opt/homebrew/bin/codegraph"


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    """把 sqlite3.Row 转成普通 dict[str, Any]。"""
    return {key: row[key] for key in row.keys()}


class CodegraphHandle:
    """codegraph.db 的只读句柄。构造只记录路径,每次查询开一个短连接。"""

    def __init__(self, db_path: str) -> None:
        # db 不存在时立即报错。否则 sqlite3.connect 会静默建一个空 db,
        # 后续 query 只会抛出误导性的 "no such table: nodes"。
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"codegraph db not found: {db_path}")
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        # 只读 URI 模式:句柄本身只读,且杜绝对已被删除的 db 静默重建。
        conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    def query(self, search: str) -> list[dict[str, Any]]:
        """按符号名/关键词搜索节点(大小写不敏感的 LIKE 匹配)。对应 codegraph query。"""
        pattern = f"%{search.lower()}%"
        conn = self._connect()
        try:
            cursor = conn.execute(
                "SELECT * FROM nodes WHERE lower(name) LIKE ? OR lower(qualified_name) LIKE ? ORDER BY name",
                (pattern, pattern),
            )
            return [_row_to_dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def node(self, node_id: str) -> dict[str, Any] | None:
        """取单个节点详情,附带关联 edges(incoming + outgoing)。不存在返回 None。"""
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
            if row is None:
                return None

            node = _row_to_dict(row)
            edge_rows = conn.execute(
                "SELECT * FROM edges WHERE source = ? OR target = ?",
                (node_id, node_id),
            ).fetchall()
            node["edges"] = [_row_to_dict(edge) for edge in edge_rows]
            return node
        finally:
            conn.close()

    def callers(self, symbol: str) -> list[dict[str, Any]]:
        """谁调用了该符号。symbol 可以是节点 id 或 name。对应 codegraph callers。"""
        return self._call_neighbors(symbol, direction="callers")

    def callees(self, symbol: str) -> list[dict[str, Any]]:
        """该符号调用了谁。symbol 可以是节点 id 或 name。对应 codegraph callees。"""
        return self._call_neighbors(symbol, direction="callees")

    def _resolve_node_ids(self, conn: sqlite3.Connection, symbol: str) -> list[str]:
        """把 symbol 解析成节点 id 列表:先按 id 精确匹配,否则按 name 匹配。"""
        by_id = conn.execute("SELECT id FROM nodes WHERE id = ?", (symbol,)).fetchall()
        if by_id:
            return [row["id"] for row in by_id]

        by_name = conn.execute("SELECT id FROM nodes WHERE name = ?", (symbol,)).fetchall()
        return [row["id"] for row in by_name]

    def _call_neighbors(self, symbol: str, *, direction: str) -> list[dict[str, Any]]:
        """沿 calls 边取邻居节点。direction='callers' 取 source,'callees' 取 target。"""
        conn = self._connect()
        try:
            node_ids = self._resolve_node_ids(conn, symbol)
            if not node_ids:
                return []

            placeholders = ",".join("?" for _ in node_ids)
            if direction == "callers":
                # 谁指向了 symbol:edges.target ∈ node_ids,取 source 节点
                sql = (
                    f"SELECT n.* FROM edges e JOIN nodes n ON n.id = e.source "
                    f"WHERE e.kind = 'calls' AND e.target IN ({placeholders})"
                )
            else:
                # symbol 指向了谁:edges.source ∈ node_ids,取 target 节点
                sql = (
                    f"SELECT n.* FROM edges e JOIN nodes n ON n.id = e.target "
                    f"WHERE e.kind = 'calls' AND e.source IN ({placeholders})"
                )

            rows = conn.execute(sql, tuple(node_ids)).fetchall()
            return [_row_to_dict(row) for row in rows]
        finally:
            conn.close()

    def explore(self, query: str) -> str:
        """探索一个区域:相关符号源码 + 调用路径,一次返回。对应 codegraph explore。

        优先 subprocess 调 `codegraph explore <query>`;不可用或失败时回退到 DB 组装。
        """
        cli_output = self._explore_via_cli(query)
        if cli_output is not None:
            return cli_output
        return self._explore_via_db(query)

    def _explore_via_cli(self, query: str) -> str | None:
        """尝试用 codegraph CLI 探索。找不到二进制/非零退出/异常都返回 None(触发回退)。"""
        binary = CODEGRAPH_BIN if shutil.which(CODEGRAPH_BIN) else shutil.which("codegraph")
        if binary is None:
            return None

        try:
            result = subprocess.run(
                [binary, "explore", query],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None

        if result.returncode != 0 or not result.stdout.strip():
            return None
        return result.stdout

    def _explore_via_db(self, query: str) -> str:
        """回退实现:从 DB 组装匹配节点及其 calls 邻居的文本摘要。"""
        matches = self.query(query)
        if not matches:
            return f"No nodes found for query: {query!r}"

        lines: list[str] = [f"# explore: {query!r} ({len(matches)} match(es))", ""]
        for node in matches:
            node_id = str(node.get("id", ""))
            lines.append(f"## {node.get('name')} [{node.get('kind')}] {node_id}")
            location = f"{node.get('file_path')}:{node.get('start_line')}"
            lines.append(f"location: {location}")

            signature = node.get("signature")
            if signature:
                lines.append(f"signature: {signature}")

            callers = self.callers(node_id)
            callees = self.callees(node_id)
            if callers:
                lines.append("callers: " + ", ".join(str(c.get("name")) for c in callers))
            if callees:
                lines.append("callees: " + ", ".join(str(c.get("name")) for c in callees))
            lines.append("")

        return "\n".join(lines)
