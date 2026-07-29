"""All analyzer prompts share the product's Simplified Chinese output policy."""

from __future__ import annotations

import pytest

from argus.analyzers.auth.analyzer import ANALYZER as AUTH
from argus.analyzers.authz.analyzer import ANALYZER as AUTHZ
from argus.analyzers.baseline.analyzer import ANALYZER as BASELINE
from argus.analyzers.business_flow.analyzer import ANALYZER as BUSINESS_FLOW
from argus.analyzers.business_logic.analyzer import ANALYZER as BUSINESS_LOGIC
from argus.analyzers.injection.analyzer import ANALYZER as INJECTION
from argus.analyzers.invariant.analyzer import ANALYZER as INVARIANT
from argus.analyzers.ssrf.analyzer import ANALYZER as SSRF
from argus.analyzers.xss.analyzer import ANALYZER as XSS


@pytest.mark.parametrize(
    "analyzer",
    [AUTH, AUTHZ, BASELINE, BUSINESS_FLOW, BUSINESS_LOGIC, INJECTION, INVARIANT, SSRF, XSS],
)
def test_prompt_requires_simplified_chinese_natural_language(analyzer: object) -> None:
    prompt = analyzer._load_prompt()

    assert "所有面向人的自然语言内容必须使用简体中文" in prompt
    assert "JSON 字段名" in prompt
    assert "代码标识符" in prompt
