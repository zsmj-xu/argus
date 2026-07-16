# 评审请求:T14 invariant 富化器(Codex 实现 → Claude 评审)

**分支**:`codex/T14`;实现 commit `371c801`,base `09f995d`(另含本评审请求文档提交)。
**评审者**:Claude
**任务**:T14 invariant 富化器(实验性)
**契约**:未修改 `docs/contracts/interfaces.py` 或 `argus/contracts.py`。

## 改动范围

- `argus/analyzers/invariant/__init__.py`
- `argus/analyzers/invariant/analyzer.py`
- `argus/analyzers/invariant/prompt.txt`
- `tests/analyzers/test_invariant.py`

## 实现摘要

- 导出模块级 `ANALYZER`,元数据为 `name="invariant"`、`phase=ENRICHMENT`、
  `requires=[]`;继承 `AnalyzerBase`。
- 从 codegraph 读取全部真实 function/method 节点与源码片段,逐 handler 走查
  logic-graph 实际采用的五类不变量:`ownership / authentication / role / replay /
  trust_boundary`。
- 只产 `enrichment["invariants"]`,不产 Finding。每条规整为:

  ```json
  {
    "id": "stable id",
    "kind": "ownership|authentication|role|replay|trust_boundary",
    "statement": "业务断言",
    "handler": "codegraph 中的真实 handler 名",
    "handler_node_id": "codegraph 中的真实 node id",
    "resource": "string|null",
    "inferred_from": "真实 handler 文件:范围内行号",
    "confidence": "high|medium|low",
    "enforced_by": "guard/check|null"
  }
  ```

- LLM 输出按不可信数据处理:畸形 JSON 降级为空;非五类 kind、空 statement、未知或
  无法消歧的 handler 均丢弃;幻觉 node id 不采信;文件以图为准,行号夹到 handler
  真实范围;非法 confidence/enforced_by 规整到安全默认;重复 id 去重。
- 实验性默认关闭:`DEFAULT_CONFIG.analyzers.enrichment` 不包含 `invariant`;只有显式选择
  才进入 pipeline。另外支持 `config.invariant.enabled=false` 直接返回空产物。
- 不对 handler 列表做静默截断,避免大仓中排序靠后的安全关键 handler 永久漏建不变量。

## 测试覆盖

- Analyzer 协议、注册元数据与默认关闭。
- 五类不变量完整产出,每条恒有 nullable `enforced_by`。
- 幻觉 node id 被替换为真实 handler node id;越界行号被纠正到真实范围。
- 非法 kind、未知 handler 与畸形 JSON 被安全丢弃/降级。
- prompt 明确包含五类逐 handler checklist。

## 验证

```text
uv run pytest -q                    90 passed
uv run mypy argus/                  Success: no issues found in 34 source files
uv run ruff check .                 All checks passed
uv run ruff format --check .        57 files already formatted
```

## 请重点评审

1. `enrichment["invariants"]` 的字段是否足够清晰、稳定,能供后续 M5 对照实验与人工检查使用。
2. 五类 checklist 是否完整移植 logic-graph 的当前口径,没有沿用旧计划中的
   `state_machine/rate` 过时分类。
3. handler/node/line 锚定是否足以阻止 LLM 幻觉污染 enriched-graph。
4. “不截断全部 handler”对召回有利,但大仓 prompt 体量可能偏大;当前实验性实现是否接受,
   或是否应在后续单独任务中引入可证明不漏候选的分批策略。

## 评审结论(Claude 填写)

> 请给两个裁决(Spec ✅/❌ + Quality Approved/需修改),并列出分级 findings。

（待 Claude 填写）
