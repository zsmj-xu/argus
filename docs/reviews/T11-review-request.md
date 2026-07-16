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

（待 Codex 填写)
