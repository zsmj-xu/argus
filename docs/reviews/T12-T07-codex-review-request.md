# 评审请求:T12 + T07(补 Codex 回审)

**背景**:T12(business-flow 富化器)与 T07(报告生成)由 Claude 实现,在交叉评审流程确立前已合入 `main`,仅经 Claude 自审。现按 `COLLABORATION.md` §5.1 补 **Codex 交叉评审**。这两个任务**已在 main 上**,本次回审目的是补齐独立视角,不是拦合并——若发现问题,开后续修复任务处理,不回滚。

**评审者**:Codex
**被审代码位置**:已在 `main`,无需切分支。相关文件:
- T12:`argus/analyzers/business_flow/{analyzer.py,prompt.txt,SCHEMA.md,__init__.py}`、`tests/analyzers/test_business_flow.py`
- T07:`argus/reporting/report.py`、`argus/reporting/__init__.py`、`tests/test_report.py`、`argus/orchestration/pipeline.py` 的 report 节点

**如何验证(在 main 的 worktree 里,用 uv)**:
```
uv run --extra dev pytest -q
uv run --extra dev mypy argus/
uv run --extra dev ruff check . && uv run --extra dev ruff format --check .
```

---

## 请重点看(T12 business-flow)

1. **产出 schema 是你的 T13 要消费的隐性契约** —— `argus/analyzers/business_flow/SCHEMA.md` 定义的 enrichment 六段(endpoints/handlers/resources/operations/edges/business_flows)。**作为 T13 的实现者,这个契约你用着顺手吗?** 字段够不够、`business_flows` 的 `trust_boundaries`(带 `validated` 标记)能不能支撑你抓"改金额/越权"那类漏洞?如果不够,现在提比 T13 做到一半再提代价小 —— 走契约变更流程或在此登记建议。
2. **功能解耦**:business-flow 是否严格不产 `invariants`(那是 T14 的职责)?
3. **node_id 锚回**:endpoints/handlers 的 node_id 是否真锚回 codegraph 真实节点、LLM 幻觉的 id 有没有被过滤?
4. **`query("")` 拉全表**:大 repo 上的性能隐患,评估严重度。

## 请重点看(T07 报告)

1. **枚举/字符串兼容**:`render_report` 对 severity/confidence 同时兼容枚举与字符串(应对 checkpoint round-trip 退化)。这个处理对不对、够不够?
2. **你的 findings 会被这个报告正确渲染吗?** 作为 authz/injection 等分析器的实现者,你产出的 Finding 结构喂进 `render_report` 会不会有字段缺失导致的 KeyError 或渲染异常?
3. report 节点是否只改了 report 这一处、没影响 pipeline 其它节点?

---

## 评审结论(Codex 填写)

> 格式:两个裁决(Spec ✅/❌ + Quality Approved/需修改)+ 分级 findings(Critical/Important/Minor)。
> 若有对 SCHEMA 的契约变更建议,单独列出。

（待 Codex 填写）
