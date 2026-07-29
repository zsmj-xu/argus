"""AnalyzerBase —— 分析器实现的共享基类。

提供两个便利方法:
- `_load_prompt()`:从分析器所在目录读取 prompt.txt(约定同目录同名)。
- `_make_finding(...)`:统一构造合法 Finding,自动生成稳定 id、校验必填字段。

具体分析器继承本类,声明 name/phase/requires,并实现 run()。基类不实现 run(),
子类必须自己实现;这样基类本身不会被注册表误当成可用分析器。
"""

from __future__ import annotations

import hashlib
import inspect
import os
from typing import TYPE_CHECKING

from argus.contracts import CodeLocation, Confidence, Finding, Phase, Severity

if TYPE_CHECKING:
    from argus.contracts import AnalysisContext, AnalyzerResult

_SIMPLIFIED_CHINESE_OUTPUT_POLICY = """

输出语言要求（必须遵守）：
- 所有面向人的自然语言内容必须使用简体中文，包括漏洞标题、风险说明、证据说明、
  数据流说明、修复建议、业务规则、业务流程和不变量描述。
- JSON 字段名以及 severity、confidence、vuln_class 等枚举值保持契约规定的英文。
- 代码标识符、函数名、类名、文件路径、HTTP 路径、参数名、CWE 编号和代码片段保持原样，
  不要翻译或改写。
"""


class AnalyzerBase:
    """分析器基类。子类须设置 name/phase/requires 并实现 run()。"""

    name: str
    phase: Phase
    requires: list[str]

    def _load_prompt(self, filename: str = "prompt.txt") -> str:
        """从子类模块所在目录读取 prompt 模板。

        默认读同目录下的 prompt.txt。找不到抛 FileNotFoundError —— 分析器必须自带 prompt。
        """
        module_file = inspect.getfile(type(self))
        prompt_path = os.path.join(os.path.dirname(module_file), filename)
        with open(prompt_path, encoding="utf-8") as handle:
            return handle.read().rstrip() + _SIMPLIFIED_CHINESE_OUTPUT_POLICY

    def _make_finding(
        self,
        *,
        vuln_class: str,
        title: str,
        severity: Severity,
        confidence: Confidence,
        locations: list[CodeLocation],
        rationale: str,
        evidence: str,
        remediation: str,
        data_flow: str = "",
    ) -> Finding:
        """统一构造合法 Finding,自动生成稳定 id 并校验必填字段。

        id 形如 f"{analyzer}:{vuln_class}:{短哈希}",哈希基于 analyzer/vuln_class/title
        及首个 location,保证同一漏洞跨运行 id 稳定。locations 至少一条。
        """
        if not locations:
            raise ValueError("finding must have at least one location")

        anchor = locations[0]
        digest_source = f"{self.name}|{vuln_class}|{title}|{anchor['node_id']}|{anchor['line']}"
        short_hash = hashlib.sha1(digest_source.encode("utf-8")).hexdigest()[:12]

        return {
            "id": f"{self.name}:{vuln_class}:{short_hash}",
            "analyzer": self.name,
            "vuln_class": vuln_class,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "locations": locations,
            "data_flow": data_flow,
            "rationale": rationale,
            "evidence": evidence,
            "remediation": remediation,
        }

    def run(self, ctx: AnalysisContext) -> AnalyzerResult:  # noqa: ARG002
        """子类必须实现。基类不提供默认行为。"""
        raise NotImplementedError(f"{type(self).__name__} must implement run()")
