# 评审请求:T16 评测打分(Codex 实现 → Claude 评审)

**分支**:`codex/T16`(实现 commit `bef8315`,基于 `main@1030f31`)
**评审者**:Claude
**状态**:等待交叉评审;通过后方可合入 main 并解锁 T17。

## 实现范围

- 新增 `argus/eval/score.py`:
  `score(findings, ground_truth) -> {recall, precision, tp, fp, fn, matched}`。
- 新增 `argus/eval/__init__.py` 导出 `score`。
- 新增 `tests/eval/test_score.py`,7 个测试覆盖旧任务卡 schema、T15 真实 schema、
  out-of-scope 过滤、路径/行邻近、类别/位置不匹配、一对一最大命中和真实资产闭环。
- 未修改冻结契约、分析器、编排、报告或 ground truth。

## 匹配规则

评分器是纯确定性的,不调用 LLM:

1. ground truth 同时兼容任务卡的 `vulns + vuln_class/file/line` 和 T15 的
   `vulnerabilities + invariant_kind/location/handler/source`。
2. `in_scope=false` 在匹配和 FN 分母之前过滤;四份真实资产共 18 条 in-scope,
   7 条 `n/a` / out-of-scope 不计分。
3. 类别必须兼容。显式 `vuln_class` 默认精确匹配;T15 的五类 invariant 允许
   `business-logic` 通用 Finding,并有限兼容 authz→ownership/role、
   auth→authentication。
4. 文件路径先规范化,允许绝对路径/扫描根前缀与 ground truth 相对路径做后缀匹配。
5. ground truth 有行号时要求同文件且相差不超过 10 行;T15 的行号可从 `source`
   中提取。无数字行号时要求同文件且 handler 出现在 Finding 标题/证据/data flow/
   node_id 等锚定文本中;只有行号和 handler 都没有时才退化为同文件。
6. 使用二分图增广匹配保证一对一最大命中:一条 Finding 和一条 ground truth 都最多
   计一次,重复 Finding 计 FP。
7. 无 ground truth 或无 Finding 的对应比率定义为 `0.0`,不制造空集满分。

`matched` 只返回经本地规则验证的 `{ground_truth_id,finding_index,finding_id}`,
便于 T17/T18 和人工复核消费。

## 与 logic-graph Stage 3 的差异

参考实现把 finding↔ground-truth 语义匹配交给 LLM,再严格过滤 LLM 返回的未知 id、
越界 index 和重复匹配。T16 任务卡明确要求按 `file + 行邻近 + vuln_class` 自动打分,
因此本实现保留“一对一、防重复、只算 in_scope”的方法论,但移除评测阶段的 LLM
非确定性和额外成本。handler fallback 用于 T15 中没有数值行号的 flowmart 条目。

## 请重点评审

1. `business-logic` 对五类 invariant 的广义兼容是否合理,是否可能让同文件的不同业务
   漏洞误配;行号/handler 锚定是否足够约束。
2. 10 行邻近阈值和绝对路径后缀匹配是否稳健,是否存在 basename/目录碰撞。
3. 增广匹配是否真正保证最大 TP 且不重复消费任一侧;matched 顺序是否稳定。
4. 从 `source` 提取行号、无行号时 handler token fallback 是否覆盖四份真实资产。
5. `in_scope=false` 过滤和零分母 `0.0` 是否适合 T17/T18 对照表。

## 独立验证

```bash
git checkout codex/T16
uv run pytest -q
uv run mypy argus/
uv run ruff check .
uv run ruff format --check .
```

Codex 在 rebase 后的结果:

- `uv run pytest -q`:**122 passed**
- `uv run pytest tests/eval/test_score.py -q`:**7 passed**
- mypy:**Success, no issues found in 38 source files**
- ruff check:**All checks passed**
- ruff format:**67 files already formatted**
- 真实资产闭环:四份 ground truth 的 18 条 in-scope 均可被对应 Finding 命中;
  7 条 out-of-scope 均不进入 FN。

## 评审结论(Claude 填写)

> 请给出 Spec ✅/❌、Quality Approved/需修改,以及按 Critical/Important/Minor
> 分级的 findings。

（待 Claude 填写）
