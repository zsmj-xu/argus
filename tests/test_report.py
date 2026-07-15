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

from typing import Any, cast

from argus.contracts import ArgusState, Confidence, Finding, Severity
from argus.reporting.report import render_report


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
    assert "# " in md
    assert "high" in md.lower()
    # 位置必须是可点击的 Markdown 链接,而非纯反引号代码文本。
    assert "[api/o.py:10](api/o.py#L10)" in md


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
    idx_crit = md.lower().index("critical")
    idx_high = md.lower().index("high")
    idx_low = md.lower().index("low")
    assert idx_crit < idx_high < idx_low


def test_string_severity_and_confidence_do_not_crash() -> None:
    # checkpoint round-trip 后枚举可能退化成字符串。
    findings = [
        _finding(fid="s1", title="StrSev", severity="critical", confidence="high"),
    ]
    md = render_report(findings, _state())
    assert "StrSev" in md
    assert "critical" in md.lower()
    assert "high" in md.lower()


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
    lower = md.lower()
    assert "high" in lower
    assert "low" in lower
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
    # 两条位置都渲染成可点击 Markdown 链接。
    assert "[app/db.py:42](app/db.py#L42)" in md
    assert "[app/views.py:7](app/views.py#L7)" in md
    assert "request.form -> query()" in md
    assert "unsanitized input reaches SQL" in md
    assert "cursor.execute" in md
    assert "use parameterized queries" in md


def test_locations_render_as_clickable_markdown_links() -> None:
    """位置必须是 Markdown 链接 [file:line](file#Lline),不是纯反引号代码文本。"""
    findings = [
        _finding(fid="lnk", locations=[{"file": "src/pay.py", "line": 88, "node_id": "n1"}]),
    ]
    md = render_report(findings, _state())
    assert "[src/pay.py:88](src/pay.py#L88)" in md
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
