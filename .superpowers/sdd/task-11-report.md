# T11 报告:检查点放行后从磁盘重载产物,人工编辑生效

## 目标
补齐"人可引导"的第三种介入方式:人在检查点手动编辑落盘的产物文件
(enriched-graph.json / findings.json)后 `continue`,下游节点应读到编辑后的版本,
而非内存 state 里的旧值。

## 重载逻辑放哪
放在 `argus/orchestration/checkpoints.py` 的 `_run_review`,`interrupt()` **返回之后**。

- `interrupt()` 在 resume/continue 放行时**返回**(不抛),其后代码只在放行后执行 ——
  这正是"人可能已就地编辑磁盘文件"的时间窗。此时从产物路径重载、覆盖内存 state,
  作为节点返回的 state 更新(`updates[state_key] = value`)交给 LangGraph 落库,
  下游节点(vuln / report)自然读到新值。
- pipeline.py 未改动:下游 vuln 通过 `_build_context` 读 `state["enriched"]`、report 读
  `state["findings"]`,重载已经覆盖了这两个 key,链路不变。

## 怎么区分两个检查点的产物
把原来的 `_CHECKPOINT_ARTIFACT_KEYS: dict[str, str]`(只存 path key)升级为
`_CheckpointArtifact(NamedTuple)`,同时持有两个 ArgusState key,单一数据源:

- `REVIEW_ENRICHMENT` → path_key=`enriched_graph_path`,state_key=`enriched`
- `REVIEW_FINDINGS` → path_key=`findings_path`,state_key=`findings`

`_review_payload`(payload 展示的产物路径)与重载逻辑共用这份映射,不会漂移。

## --yolo 不重载
重载放在 `if _checkpoint_enabled(...)` 分支内、`interrupt()` 之后。checkpoints=False
(--yolo)或该检查点不在启用列表时不进此分支 —— 既不 interrupt(人没机会编辑),也不
读磁盘,避免多余磁盘 IO。测试用 spy 断言此路径下 `_reload_artifact` 调用 0 次。

## JSON 坏时容错
`_reload_artifact(path) -> (loaded, value)`:

- 文件不存在 → `(False, None)`:不重载,保留内存 state(安全兜底)。
- `json.load` 抛 `OSError`/`JSONDecodeError` → 记 `logger.warning` 后返回 `(False, None)`:
  人手抖写坏 JSON 不会崩整条 pipeline,继续用内存 state 跑到底。
- 成功 → `(True, obj)`:调用方 `if loaded:` 才覆盖内存 state。

## findings 字符串 severity 链路
磁盘上的 findings.json 里 severity/confidence 是**字符串**(T09 落盘时 `_json_default` 取
`.value` 转的)。重载回 state 后不转回枚举 —— report 节点(T07)的 `_as_str` 已同时兼容
枚举与字符串,渲染不崩。测试显式断言重载后 `findings[0]["severity"] == "high"`(字符串)
且 report.md 正常渲染出手改标题。

## 新测试(tests/orchestration/test_edit_artifact.py,4 条)
1. `test_edited_enriched_graph_is_reloaded`:停 review-enrichment → 磁盘 enriched-graph.json
   增一个 endpoint → continue → 断言 vuln 的 `ctx["enriched"]` 含手改的 `added_by_human`
   (mock 深拷贝记录 run() 时看到的 enriched,真验证"编辑生效",非恒真)。
2. `test_edited_findings_is_reloaded`:停 review-findings → 磁盘 findings.json 改 title →
   continue → 断言最终 state.findings 与 report.md 用的是手改标题,原标题消失。
3. `test_yolo_does_not_reload_artifacts`:checkpoints=False → spy 断言 `_reload_artifact`
   调用 0 次,行为不变(跑到底、无 interrupt)。
4. `test_corrupt_artifact_json_keeps_in_memory_state`:磁盘写非法 JSON → 不崩、保留内存
   enriched、记 warning。

## 四门禁实际输出
- `uv run --extra dev pytest -q` → `111 passed`(107 原有 + 4 新增)。
- `uv run --extra dev mypy argus/` → `Success: no issues found in 36 source files`。
- `uv run --extra dev ruff check .` → `All checks passed!`。
- `uv run --extra dev ruff format --check .` → `63 files already formatted`。
- ruff 版本:0.15.21(pin 一致)。

## 改动文件
- `argus/orchestration/checkpoints.py`(重载逻辑 + NamedTuple 映射)。
- `tests/orchestration/test_edit_artifact.py`(新建)。
- pipeline.py 未改;契约 / 分析器 / reporting / registry / cli.py 未碰。

## concerns
- 重载覆盖是"整文件替换"语义:人删掉磁盘上某 finding,重载后 state 里也没了 —— 符合
  "磁盘为准"的直觉,但若人误删则不可逆(内存旧值被覆盖)。当前按 brief 预期行为处理。
- 若人把 findings.json 编辑成非 list(如写成对象),重载会成功但类型与 ArgusState
  契约不符,下游 report 可能异常。本任务只做 JSON 语法层容错,不做 schema 校验 ——
  更严格的产物 schema 校验可留作后续任务。
