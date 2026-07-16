# 评审请求:T11 改产物文件后 continue(Claude 实现 → Codex 评审)

**背景**:M3 人在环路第三种(也是最后一种)介入方式。人停在检查点时手动编辑落盘的产物文件(enriched-graph.json / findings.json),continue 放行后下游节点读到编辑后的版本。**至此 M3 三种介入方式齐全:①停等(T09)②命令行注入(T10)③改产物文件(T11)。**
**分支**:`claude/T11`(head `5bc8219`,已 rebase 到含 T09/T10 的最新 main)。评审通过后合入 main。
**评审者**:Codex
**改动范围**:仅 `argus/orchestration/checkpoints.py` + `tests/orchestration/test_edit_artifact.py`。未碰契约/分析器/reporting/cli.py/pipeline.py。

**如何验证(检出 claude/T11,用 uv)**:
```
uv run --extra dev pytest -q                                       # 期望 111 passed
uv run --extra dev pytest tests/orchestration/test_edit_artifact.py -v   # 4 passed
uv run --extra dev mypy argus/ && uv run --extra dev ruff check . && uv run --extra dev ruff format --check .
```

## 实现(Claude 已实证)

1. **放行后重载**:`_run_review` 里 `interrupt()` 返回之后(=放行后,人可能已编辑磁盘)从磁盘 `json.load` 重载对应产物,作为节点 state 更新交给 LangGraph,下游自然读到新值。**pipeline.py 未改**。
2. **两检查点产物映射**:`_CheckpointArtifact(NamedTuple)` 持有 path_key + state_key。REVIEW_ENRICHMENT→enriched_graph_path/enriched;REVIEW_FINDINGS→findings_path/findings。payload 与重载共用这份映射。
3. **--yolo 不重载**:checkpoints=False 不进 interrupt 分支,既不 interrupt 也不读盘(测试用 spy 断言 reload 调用 0 次)。
4. **容错**:文件不存在 / JSON 解析失败(OSError/JSONDecodeError)时记 warning 并保留内存 state,不崩 pipeline。
5. **findings 字符串 severity 链路**:磁盘上 severity 是字符串,重载后不转回枚举,report 的 `_as_str`(T07)已兼容。

**Claude 已实证**:手改 enriched-graph.json 加 endpoint → continue → vuln 节点 ctx["enriched"] 含手改内容。

## 请重点看 + 我如实标注的两个设计边界(实现者提出,我认可但请你判断)
1. **整文件替换语义**:人误删磁盘上某 finding,重载后内存旧值也被覆盖(符合"磁盘为准"直觉,按 brief 预期)。你认可吗?
2. **无 schema 校验**:只做 JSON 语法容错,不校验 schema。若人把 findings.json 编辑成非 list,重载成功但类型不符契约,下游可能异常。是否需要现在加基本 schema 校验(如 findings 必须是 list、enriched 必须是 dict),还是留后续任务?

## 评审结论(Codex 填写)

> 两个裁决(Spec ✅/❌ + Quality Approved/需修改)+ 分级 findings。对上面两个设计边界给出判断。

**Spec: ❌ 需一轮边界修复。** 主路径符合 T11 意图,但磁盘内容未经最小验证/
归一化就写回 `ArgusState`,尚未满足冻结契约。

**Quality:需修改。** 无 Critical;有 2 条 Important。修复后可快速复审。

独立验证结果:

- `uv run pytest -q`:111 passed
- `uv run pytest tests/orchestration/test_edit_artifact.py -q`:4 passed
- `uv run mypy argus/`:clean
- `uv run ruff check .`:passed
- `uv run ruff format --check .`:passed

### Important 1 —— 合法 JSON 的错误形状会污染 state 并在下游崩溃

`argus/orchestration/checkpoints.py:153-155` 把任何 `json.load()` 成功的值直接写到
`enriched` / `findings`。因此 `enriched-graph.json` 为 `[]`、`findings.json` 为
`null`/对象/字符串列表时都被视为成功;随后分析器调用 `enriched.get(...)` 或报告读取
`finding["severity"]` 时才异常。这与当前对 JSON 语法错误“warning + 保留内存 state”
的安全兜底不一致。

本任务内应增加**边界层最小校验**:

- enrichment 顶层必须是 dict;
- findings 顶层必须是 list,每项必须是满足冻结 `Finding` 形状的 mapping(至少验证
  报告/评测必读字段与 locations 的容器形状);
- 任一项不合法时整份拒绝,warning 后保留内存值,不要部分替换。

需补两类测试:两个产物的错误顶层类型;合法 list 中包含畸形 finding。完整的
business-flow 六段领域 schema **不应**在这里验证,否则 orchestration 会耦合具体分析器。

### Important 2 —— findings 重载后枚举退化,违反冻结 Finding 契约

`tests/orchestration/test_edit_artifact.py:208-209` 当前把 `severity == "high"` 当成预期,
但 `Finding.severity/confidence` 和 `ArgusState.findings` 的冻结定义要求
`Severity` / `Confidence` 枚举。报告层 `_as_str` 的兼容只能避免当前 renderer 崩溃,
不能使共享 state 重新满足契约,后续 T16 评测也不应被迫接收平行类型。

重载 findings 时应验证字符串值并构造成 `Severity(value)` / `Confidence(value)`;
未知枚举值按无效整份拒绝并保留内存 state。测试应断言放行后的 state 中两字段是枚举,
而磁盘 JSON 仍保持字符串表示。

## 两个设计边界的判断

1. **整文件替换语义:认可。** 人删除 finding 或 enrichment 条目应能表达“驳回/修正”;若做
   merge,删除反而无法生效。空 `[]` / `{}` 也应作为合法的明确替换。替换应以“整份通过
   最小校验”为原子边界,不要部分接受。
2. **schema 校验:现在加最小契约校验,完整领域校验留后续。** 顶层容器、Finding 必需形状、
   locations 形状和枚举恢复属于磁盘→冻结 state 的反序列化责任,应随 T11 完成;T12F 的
   business-flow 深层引用完整性等领域规则不属于 T11,不应在 checkpoint 层复制。

## 其他观察

- interrupt 返回后再读盘的时机正确,下游能看到人工版本并持久化到 checkpoint。
- `checkpoints=False` 不读盘、文件缺失/JSON 语法错误保留内存值,行为正确。
- 分支当前相对 main 为 `1 1`,修复完成后合并前仍需 rebase 最新 main。
