"""报告渲染测试。

覆盖:
- brief Step 1 的基础断言(标题 / severity / file:line 链接)。
- 空 findings 时产出合法"未发现"报告(不崩)。
- 多 severity 时按 critical→high→medium→low→info 降序分组。
- severity/confidence 退化成字符串(checkpoint round-trip)时仍能渲染。
- 按 severity 的汇总计数正确。

findings 用契约 Finding 的字段结构;node_id 用任意字符串(报告不校验其真实性)。
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote

from argus.contracts import ArgusState, Confidence, Finding, Severity
from argus.reporting.report import render_report

# 位置链接形如 [file:line](<target>);捕获尖括号内的链接目标(含 #L 行号锚点)。
_LINK_RE = re.compile(r"\[[^\]]+\]\(<([^>]+)>\)")


def _link_targets(md: str) -> list[str]:
    """从渲染出的 markdown 里抽出所有位置链接的目标(尖括号内内容)。"""
    return _LINK_RE.findall(md)


def _finding(
    *,
    fid: str = "f1",
    analyzer: str = "authz",
    vuln_class: str = "authz",
    title: str = "X",
    severity: Any = Severity.HIGH,
    confidence: Any = Confidence.MEDIUM,
    locations: list[dict[str, Any]] | None = None,
    data_flow: str = "",
    rationale: str = "r",
    evidence: str = "e",
    remediation: str = "m",
) -> Finding:
    """构造一条 Finding。severity/confidence 用 Any 以便传入字符串模拟退化场景。"""
    loc = locations if locations is not None else [{"file": "api/o.py", "line": 10, "node_id": "n1"}]
    finding: dict[str, Any] = {
        "id": fid,
        "analyzer": analyzer,
        "vuln_class": vuln_class,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "locations": loc,
        "data_flow": data_flow,
        "rationale": rationale,
        "evidence": evidence,
        "remediation": remediation,
    }
    return cast(Finding, finding)


def _state(**overrides: Any) -> ArgusState:
    base: dict[str, Any] = {
        "repo_path": "/x",
        "workspace": "w",
        "config": {},
        "source_mode": "raw",
        "graph_db_path": "/x/.codegraph/codegraph.db",
        "enriched_graph_path": "runs/w/enriched-graph.json",
        "findings_path": "runs/w/findings.json",
        "report_path": "runs/w/report.md",
        "enriched": {},
        "findings": [],
        "completed_nodes": [],
    }
    base.update(overrides)
    return cast(ArgusState, base)


def test_report_groups_by_severity_and_links_nodes() -> None:
    findings = [
        _finding(
            fid="a",
            title="X",
            severity="high",
            confidence="medium",
            locations=[{"file": "api/o.py", "line": 10, "node_id": "n1"}],
        )
    ]
    md = render_report(findings, _state(repo_path="/x", workspace="w"))
    assert "# Argus 安全报告" in md
    assert "高危" in md
    # 位置必须是可点击的 Markdown 链接,而非纯反引号代码文本。
    # 链接文本仍是 file:line;目标用尖括号包裹,以 <...#L10> 结尾。
    assert "[api/o.py:10](<" in md
    assert "api/o.py#L10>)" in md


def test_empty_findings_renders_valid_report() -> None:
    md = render_report([], _state())
    assert "# " in md
    assert md.strip() != ""
    # 明确表达未发现漏洞,且不含任何 finding 分节标题。
    assert "未发现" in md or "No findings" in md or "no findings" in md.lower()


def test_severity_groups_ordered_descending() -> None:
    findings = [
        _finding(fid="lo", title="LowOne", severity=Severity.LOW),
        _finding(fid="cr", title="CritOne", severity=Severity.CRITICAL),
        _finding(fid="hi", title="HighOne", severity=Severity.HIGH),
    ]
    md = render_report(findings, _state())
    # critical 段必须出现在 high 段之前,high 段在 low 段之前。
    idx_crit = md.index("严重")
    idx_high = md.index("高危")
    idx_low = md.index("低危")
    assert idx_crit < idx_high < idx_low


def test_string_severity_and_confidence_do_not_crash() -> None:
    # checkpoint round-trip 后枚举可能退化成字符串。
    findings = [
        _finding(fid="s1", title="StrSev", severity="critical", confidence="high"),
    ]
    md = render_report(findings, _state())
    assert "StrSev" in md
    assert "严重" in md
    assert "置信度：** 高" in md


def test_static_finding_report_separates_confidence_from_verification() -> None:
    finding = cast(
        Finding,
        {
            **_finding(title="Static SQL injection"),
            "static_confidence": "high",
            "verification_status": "unverified",
        },
    )

    md = render_report([finding], _state())

    assert "静态置信度：** 高" in md
    assert "验证状态：** 未验证" in md


def test_severity_counts_summary() -> None:
    findings = [
        _finding(fid="h1", title="H1", severity=Severity.HIGH),
        _finding(fid="h2", title="H2", severity=Severity.HIGH),
        _finding(fid="l1", title="L1", severity=Severity.LOW),
    ]
    md = render_report(findings, _state())
    # 总数为 3。
    assert "3" in md
    # 汇总里 high 记 2、low 记 1。
    assert "高危" in md
    assert "低危" in md
    # 每条 finding 标题都出现。
    for title in ("H1", "H2", "L1"):
        assert title in md


def test_all_finding_fields_rendered() -> None:
    findings = [
        _finding(
            fid="full",
            analyzer="injection",
            vuln_class="injection",
            title="SQLi in login",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            locations=[
                {"file": "app/db.py", "line": 42, "node_id": "func:query"},
                {"file": "app/views.py", "line": 7, "node_id": "func:login"},
            ],
            data_flow="request.form -> query()",
            rationale="unsanitized input reaches SQL",
            evidence="cursor.execute(f'... {user}')",
            remediation="use parameterized queries",
        ),
    ]
    md = render_report(findings, _state())
    assert "SQLi in login" in md
    assert "injection" in md
    # 两条位置都渲染成可点击 Markdown 链接(链接文本 file:line,目标尖括号包裹)。
    assert "[app/db.py:42](<" in md
    assert "app/db.py#L42>)" in md
    assert "[app/views.py:7](<" in md
    assert "app/views.py#L7>)" in md
    assert "request.form -> query()" in md
    assert "unsanitized input reaches SQL" in md
    assert "cursor.execute" in md
    assert "use parameterized queries" in md


def test_report_labels_are_simplified_chinese() -> None:
    md = render_report(
        [
            _finding(
                title="未授权读取订单",
                rationale="处理函数没有校验订单归属。",
                evidence="order = Order.query.get(order_id)",
                remediation="按当前用户过滤订单。",
                data_flow="请求参数 -> 订单查询 -> 响应",
            )
        ],
        _state(),
    )

    for label in (
        "Argus 安全报告",
        "风险等级汇总",
        "漏洞详情",
        "代码位置",
        "数据流",
        "风险说明",
        "证据",
        "修复建议",
    ):
        assert label in md


def test_locations_render_as_clickable_markdown_links() -> None:
    """位置必须是 Markdown 链接 [file:line](file#Lline),不是纯反引号代码文本。"""
    findings = [
        _finding(fid="lnk", locations=[{"file": "src/pay.py", "line": 88, "node_id": "n1"}]),
    ]
    md = render_report(findings, _state())
    assert "[src/pay.py:88](<" in md
    assert "src/pay.py#L88>)" in md
    # 不应再是旧的纯反引号写法。
    assert "`src/pay.py:88`" not in md


def test_evidence_fence_escapes_embedded_backticks() -> None:
    """evidence 自身含 ``` 时,围栏必须更长以免提前闭合。"""
    evidence_with_fence = "before\n```\ninner code\n```\nafter"
    findings = [_finding(fid="ev", evidence=evidence_with_fence)]
    md = render_report(findings, _state())
    # evidence 全文完整保留,内部的三反引号没有把外层围栏提前截断。
    assert "inner code" in md
    assert "before" in md
    assert "after" in md
    # 外层围栏至少 4 个反引号(比内容里最长的 3 连反引号多一个)。
    assert "````" in md


def test_finding_numbering_is_globally_unique() -> None:
    """finding 编号跨 severity 分组全局连续,而非每组从 1 重开。"""
    findings = [
        _finding(fid="c1", title="CritOne", severity=Severity.CRITICAL),
        _finding(fid="h1", title="HighOne", severity=Severity.HIGH),
        _finding(fid="h2", title="HighTwo", severity=Severity.HIGH),
    ]
    md = render_report(findings, _state())
    # 三条 finding 应编号 1、2、3(而不是 critical 组 1、high 组 1、2)。
    assert "#### 1. CritOne" in md
    assert "#### 2. HighOne" in md
    assert "#### 3. HighTwo" in md


def test_location_link_resolves_from_report_dir_to_source_file(tmp_path: Path) -> None:
    """链接目标相对 report_path 解析后,必须落到 repo_path 下的真实源码文件。

    Markdown 相对链接从报告所在目录解析。报告写在 runs/<ws>/report.md,而源码在
    repo_path 下,两者不同目录——链接目标若只写 file 会指向 runs/<ws>/file(不存在)。
    本测试用真实磁盘路径构造 state,断言 os.path.normpath(join(report_dir, target))
    去掉 #L 锚点后确实等于 repo_path/file,即点击可跳到源码。
    """
    repo_path = tmp_path / "repo"
    src_file = repo_path / "api" / "orders.py"
    src_file.parent.mkdir(parents=True)
    src_file.write_text("# source\n", encoding="utf-8")

    report_path = tmp_path / "runs" / "ws" / "report.md"
    report_dir = report_path.parent

    findings = [
        _finding(fid="lk", locations=[{"file": "api/orders.py", "line": 42, "node_id": "n1"}]),
    ]
    state = _state(repo_path=str(repo_path), report_path=str(report_path))
    md = render_report(findings, state)

    targets = _link_targets(md)
    assert len(targets) == 1
    # 拆掉行号锚点,还原 URL 编码,再相对 report_dir 解析。
    rel_path = unquote(targets[0].rsplit("#L", 1)[0])
    assert targets[0].endswith("#L42")
    resolved = os.path.normpath(os.path.join(str(report_dir), rel_path))
    # 解析结果必须正好是 repo_path 下的真实源码文件,且该文件确实存在。
    assert resolved == os.path.normpath(str(src_file))
    assert os.path.isfile(resolved)


def test_location_link_url_encodes_special_characters(tmp_path: Path) -> None:
    """路径含空格 / `#` / `)` 时必须正确 URL 编码,且仍解析回真实源码文件。

    - 空格:裸写会在部分渲染器里破坏链接。
    - `#`:未编码会被当成 fragment 分隔符,截断路径。
    - `)`:未编码会提前闭合 Markdown 链接目标。
    编码后经 unquote + 相对 report_dir 解析,应还原到磁盘上的真实文件。
    """
    repo_path = tmp_path / "repo"
    weird_rel = "weird dir/pay )end #1.py"
    src_file = repo_path / weird_rel
    src_file.parent.mkdir(parents=True)
    src_file.write_text("# tricky\n", encoding="utf-8")

    report_path = tmp_path / "runs" / "ws" / "report.md"
    report_dir = report_path.parent

    findings = [
        _finding(fid="wx", locations=[{"file": weird_rel, "line": 7, "node_id": "n1"}]),
    ]
    state = _state(repo_path=str(repo_path), report_path=str(report_path))
    md = render_report(findings, state)

    targets = _link_targets(md)
    assert len(targets) == 1
    target = targets[0]
    # 特殊字符必须被编码掉:目标里不得出现裸空格 / 裸 `#`(除行号锚点)/ 裸 `)`。
    assert " " not in target
    assert ")" not in target
    path_part = target.rsplit("#L", 1)[0]
    assert "#" not in path_part
    assert target.endswith("#L7")
    # 解码后相对 report_dir 解析,必须还原到真实文件。
    rel_path = unquote(path_part)
    resolved = os.path.normpath(os.path.join(str(report_dir), rel_path))
    assert resolved == os.path.normpath(str(src_file))
    assert os.path.isfile(resolved)
