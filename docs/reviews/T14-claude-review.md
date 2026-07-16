# 评审:T14 invariant 富化器(Codex 实现,Claude 评审)

**分支**:`codex/T14`(head `aa88a40`,实现 commit `371c801`,base `09f995d`)
**评审者**:Claude
**评审方式**:独立 worktree 检出 codex/T14,建 uv 环境跑全门禁 + 实证核查防幻觉/降级/默认关闭 + 通读 analyzer.py 与测试。

---

## 评审结论

### 裁决 1 — Spec 合规:✅ 通过
invariant 富化器实现 `Analyzer` 契约(name="invariant"/phase=ENRICHMENT/requires=[],继承 AnalyzerBase),逐 handler 走查 logic-graph 当前口径的五类不变量(ownership/authentication/role/replay/trust_boundary,**未沿用过时的 state_machine/rate**)。只产 `enrichment["invariants"]`,不产 Finding、不越界产 T12 的 endpoints/business_flows。实验性默认关闭。净改动仅 invariant/ + 测试,未碰契约/共享文件。

### 裁决 2 — 代码质量:Approved
实证核查(用 codex 声称的场景实测,非读代码猜):
- **防幻觉严格**:4 条输入(含幻觉 node_id、非法 kind、空 statement、未知 handler)→ 只留 1 条合法;幻觉 `HALLUCINATED::xxx` 被替换为真实 `api/orders.py::checkout`。✅
- **降级**:畸形 JSON → 空 list,不崩。✅
- **默认关闭**:DEFAULT_CONFIG.analyzers.enrichment 不含 invariant;`config.invariant.enabled=False` 也直接空产出。✅
- **功能解耦**:只产 invariants,findings 恒空。✅
- 门禁全绿:90 passed / mypy 34 files clean / ruff check + format 全过。

### 对 codex 4 个评审问题的回答
1. **字段够清晰稳定供 M5 对照/人工检查吗?** 够。每条含 id/kind/statement/handler/handler_node_id/resource/inferred_from/confidence/enforced_by,`enforced_by` 可为 null(悬空=候选漏洞信号,对齐 logic-graph 的核心检测模式)。
2. **五类 checklist 是否对齐 logic-graph 当前口径?** 是,ownership/authentication/role/replay/trust_boundary,无过时分类。
3. **锚定是否足以阻止幻觉污染?** 足够——已实证幻觉 node_id 被替换、未知 handler 被丢弃、行号夹到真实范围。
4. **不截断全部 handler 的大仓 prompt 体量?** 当前实验性实现**接受**(不静默截断保证召回,符合实验目的)。与 T12 的同类性能项一致,留待后续统一的分批策略优化。

### Findings
- **Critical / Important**:无。
- **Minor(不阻塞)**:与 T12 相同的已知模式——`query("")` 拉全表 + 不截断 handler,大仓 prompt 可能偏大。建议后续统一为"按 endpoint/连通分量分批且可证明不漏候选"的策略,一次性覆盖 business-flow 和 invariant 两个富化器。

**结论**:可合并。实现严谨、防幻觉到位、实验性开关设计合理。

> 注:`codex/T14` 落后于当前 main(基于 09f995d,不含 T07F/T12F/T09 请求等)。合并前请 codex 先 `git rebase main`,确认 invariant 目录 + 测试无冲突(应无,因它只新增独立目录)。
