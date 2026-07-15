# 评审:T06 authz 漏洞分析器(Codex 实现,Claude 评审)

**分支**:`codex/T06`(head `c06af1b`,已 rebase 到含 T12/T07 的 main)
**评审者**:Claude
**评审方式**:独立 worktree 检出 codex/T06,建 uv 环境跑全门禁 + 通读 analyzer.py 与测试。

---

## 评审结论

### 裁决 1 — Spec 合规:✅ 通过
authz 分析器实现 `Analyzer` 契约(name="authz"/phase=VULN_ANALYSIS/requires=[],注册表能发现),移植 Shannon authz 意图(BOLA/横向/纵向/租户/工作流越权),读 codegraph + enriched,产出锚回真实 node_id 的合法 Finding。净改动仅 `analyzers/authz/` + 测试,未碰 T12/T07/契约/共享文件。

### 裁决 2 — 代码质量:Approved(高于平均)
- **防幻觉锚定严格**(`_validated_location`):LLM 给的 node_id 必须在图里真实存在才采信;file 以图为准;line 越界自动纠正到 start_line。比计划要求做得更细。
- **契约严守**:`_make_finding` 基类、Severity/Confidence 用枚举、locations 强制非空且逐条校验、findings 去重。
- **LLM 输出当 untrusted data**(docstring 明示),安全意识到位。批处理、JSON 多重降级、focus/avoid 作用域过滤、source 读取兜底都在。
- **测试真断言**(8 个):幻觉 node_id 丢弃、真实 node_id 接受、畸形 JSON 降级、批处理不漏候选、line 越界纠正,全部有具体断言。
- **门禁全绿**:48 passed / mypy strict 23 files clean / ruff check + format 全过。

### Findings
- **Critical / Important**:无。
- **Minor(不阻塞)**:`_collect_candidates` 用 `graph.query("")` 拉全表候选,与 T12 business-flow 同一模式,大 repo 上偏重。建议后续在 `GraphHandle` 上加一个"按 kind 列举"的方法统一优化(涉及契约,走变更流程)。

**结论**:可合并。这是一份干净、严谨、超出计划要求的实现。
