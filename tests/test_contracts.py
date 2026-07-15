from pathlib import Path

import pytest

import argus.contracts as c

# 权威契约文件的显式 fallback(当前 worktree 尚未纳入 docs/ 时用得上)。
_AUTHORITATIVE_FALLBACK = Path("/Users/hetao/work/project/argus/docs/contracts/interfaces.py")


def _repo_root() -> Path:
    """从测试文件定位仓库根:tests/test_contracts.py 的上一级即 repo root。"""
    return Path(__file__).resolve().parents[1]


def _locate_authoritative() -> Path | None:
    """定位权威 interfaces.py。

    优先假设合并后的布局:<repo_root>/docs/contracts/interfaces.py 与
    <repo_root>/argus/contracts.py 同处一个仓库。若当前 worktree 里该路径还不存在
    (docs/ 尚未进 worktree),回退到主仓库的绝对路径。两者都不存在则返回 None。
    """
    in_repo = _repo_root() / "docs" / "contracts" / "interfaces.py"
    if in_repo.exists():
        return in_repo
    if _AUTHORITATIVE_FALLBACK.exists():
        return _AUTHORITATIVE_FALLBACK
    return None


def test_contracts_matches_authoritative_interfaces_byte_for_byte() -> None:
    """argus/contracts.py 必须与权威 docs/contracts/interfaces.py 逐字节一致。

    整个协作模型的前提就是这两个文件逐字一致 —— 这个测试是它唯一的守护。
    合并到 main 后 docs/contracts/interfaces.py 与 argus/contracts.py 同仓,测试生效;
    当前 worktree 若还没有 docs/,优雅 skip 而非误报失败。
    """
    authoritative = _locate_authoritative()
    if authoritative is None:
        pytest.skip("authoritative contract not present in this worktree")

    contracts_py = _repo_root() / "argus" / "contracts.py"
    assert contracts_py.exists(), f"缺少 {contracts_py}"

    authoritative_bytes = authoritative.read_bytes()
    contracts_bytes = contracts_py.read_bytes()

    assert contracts_bytes == authoritative_bytes, (
        f"契约漂移:{contracts_py} 与权威文件 {authoritative} 不再逐字节一致。"
        " 契约变更须走 docs/COLLABORATION.md 流程并同步更新两处。"
    )


def test_exports_present():
    for name in [
        "Phase",
        "Severity",
        "Confidence",
        "SourceMode",
        "CodeLocation",
        "Finding",
        "GraphHandle",
        "SourceAccess",
        "LLMClient",
        "AnalysisContext",
        "AnalyzerResult",
        "Analyzer",
        "ArgusState",
    ]:
        assert hasattr(c, name), f"缺少 {name}"


def test_phase_values():
    assert c.Phase.ENRICHMENT.value == "enrichment"
    assert c.Phase.VULN_ANALYSIS.value == "vuln_analysis"


def test_analyzer_is_runtime_checkable():
    class Dummy:
        name = "d"
        phase = c.Phase.VULN_ANALYSIS
        requires: list[str] = []

        def run(self, ctx):
            return {"analyzer": "d", "findings": [], "enrichment": {}}

    assert isinstance(Dummy(), c.Analyzer)
