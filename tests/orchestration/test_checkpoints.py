"""Checkpoint 序列化 round-trip 测试。

关键回归:Finding 里的 severity(Severity)与 confidence(Confidence)是自定义
(str, Enum)。若未登记进 msgpack allowlist,checkpoint 序列化 → resume 反序列化
会把它们退化成普通 str,report 节点里 finding['severity'].value 就会抛 AttributeError。

这里直接测 make_checkpointer 所用 serde 的 dumps_typed / loads_typed round-trip,
不必跑整个 pipeline —— 断言枚举类型在往返后保持不变(仍是 Severity/Confidence)。
"""

from __future__ import annotations

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

from argus.contracts import Confidence, Finding, Severity, SourceMode
from argus.orchestration.checkpoints import _ALLOWED_MSGPACK_MODULES


def _serde() -> JsonPlusSerializer:
    """复刻 make_checkpointer 里 SqliteSaver 使用的 serde 构造方式。"""
    return JsonPlusSerializer(allowed_msgpack_modules=_ALLOWED_MSGPACK_MODULES)


def _sample_finding() -> Finding:
    return {
        "id": "injection:sqli:abc123",
        "analyzer": "injection",
        "vuln_class": "injection",
        "title": "SQL injection in coupon lookup",
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "locations": [{"file": "api/coupons.py", "line": 42, "node_id": "file:api/coupons.py"}],
        "data_flow": "request.args -> raw f-string -> cursor.execute",
        "rationale": "用户输入未参数化拼进 SQL。",
        "evidence": 'cursor.execute(f"... {code} ...")',
        "remediation": "使用参数化查询。",
    }


def test_finding_enums_survive_serde_roundtrip() -> None:
    serde = _serde()
    finding = _sample_finding()

    restored: Finding = serde.loads_typed(serde.dumps_typed(finding))

    # 关键:枚举类型必须保持,而不是退化成 str。
    assert isinstance(restored["severity"], Severity)
    assert isinstance(restored["confidence"], Confidence)
    assert restored["severity"] is Severity.HIGH
    assert restored["confidence"] is Confidence.MEDIUM

    # .value 可用(这正是 report 节点里会做的事,退化成 str 时会抛 AttributeError)。
    assert restored["severity"].value == "high"
    assert restored["confidence"].value == "medium"


def test_findings_list_in_state_survive_roundtrip() -> None:
    """更贴近真实:findings 以 list 形式落在 state 里被 checkpoint 持久化。"""
    serde = _serde()
    state_slice = {
        "source_mode": SourceMode.STRIPPED,
        "findings": [_sample_finding()],
    }

    restored = serde.loads_typed(serde.dumps_typed(state_slice))

    assert isinstance(restored["source_mode"], SourceMode)
    finding = restored["findings"][0]
    assert isinstance(finding["severity"], Severity)
    assert isinstance(finding["confidence"], Confidence)
    assert finding["severity"].value == "high"
