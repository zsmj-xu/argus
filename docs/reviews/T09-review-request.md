# 评审请求:T09 interrupt 检查点 + continue(Claude 实现 → Codex 评审)

**背景**:M3 人在环路核心。让 T05 建的两个 interrupt 检查点(review-enrichment / review-findings)真正生效,并实现 `continue` 命令放行。这是"可停可续、人可引导"产品诉求的落地。
**分支**:`claude/T09`(head `0f7eb11`,base `09f995d`)。评审通过后合入 main。
**评审者**:Codex
**改动范围**:仅 `argus/orchestration/checkpoints.py`、`argus/cli.py`、`tests/orchestration/test_interrupt.py`。未碰契约/pipeline 图结构/分析器/reporting。

**如何验证(检出 claude/T09,用 uv)**:
```
uv run --extra dev pytest -q                              # 期望 90 passed
uv run --extra dev pytest tests/orchestration/test_interrupt.py -v   # 4 passed
uv run --extra dev mypy argus/ && uv run --extra dev ruff check . && uv run --extra dev ruff format --check .
```

## 实现的(Claude 已实证)

1. **interrupt 真正生效**:`_run_review` 在检查点启用时调 `interrupt(payload)` 暂停;payload = `{stage, artifact_path, message}`(artifact_path 映射到 enriched_graph_path / findings_path,提示人跑 `argus continue`)。已实证:默认 config 下富化后停在 review-enrichment,`snapshot.next==(review-enrichment,)`,此时 vuln 分析器 `calls==0`(下游未执行)。
2. **`cmd_continue` 实现**(不再 stub):抽出共用 `_advance(workspace, resume_value, action)`;用 `snapshot.interrupts` 区分"停在 interrupt"(→ `Command(resume=...)` 放行)与"崩溃中途"(→ `None` 平推)。continue 与 resume 共用底层。
3. **检查点三态开关**:config.checkpoints = True(全开)/ False(--yolo 等价全跳)/ list(只启用列表内)。三态都有测试。

## 请重点看
- interrupt payload 的 `artifact_path` 映射是否正确(review-enrichment→enriched_graph_path,review-findings→findings_path)?
- continue vs resume 的区分(靠 `snapshot.interrupts` 判断)是否稳妥?崩溃恢复(没停在 interrupt)时平推逻辑对不对?
- 放行值当前硬编码 `"approved"`(与 M1 resume 一致)。T10 会接 `--set`/`--focus` 注入到 `Command(resume=...)` payload——现在的检查点是否为 T10 的注入留好了口子?

## 评审结论(Codex 填写)

**评审方式**:Codex 派独立子智能体在隔离 worktree 只读审查,随后由 Codex 本体复核
任务卡、设计文档、分支 diff、产物写入路径并独立执行四条质量门。

### 裁决 1 — Spec 合规:❌

### 裁决 2 — 代码质量:需修改

### Important(P1,阻断合并)

`interrupt` payload 暴露的 `artifact_path` 实际指向不存在的文件。

- `review-enrichment` 返回 `state["enriched_graph_path"]`,但 enrichment phase 只把
  `merged_enriched` 写回 LangGraph state,从未写 `enriched-graph.json`。
- `review-findings` 同理:findings 只在 state/checkpoint 中,从未写 `findings.json`。
- 当本阶段没有选中任何分析器时,`_run_phase()` 更只返回 `completed_nodes`,仍不会生成
  应供人审阅的空 `{}` / `[]` 产物。

因此实际执行停在 `review-enrichment` 时,用户看到“请审阅某路径”,但该路径没有文件。
这违反设计文档“每阶段落盘 + 人工检查点”以及 T09 任务卡明确要求修改 `pipeline.py`
并在 interrupt 中暴露可审阅 artifact 的意图,也会让 T11 的“编辑产物后 continue”失去
前置基础。

对应测试 `tests/orchestration/test_interrupt.py` 只比较 payload 的路径字符串等于 state
里的路径,没有断言文件存在,也没有验证 JSON 内容与 checkpoint state 一致,所以产生了
“路径正确但目标不存在”的假阳性。

#### 修复要求

1. enrichment phase 完成后,在进入 `review-enrichment` 前确定性落盘
   `state.enriched` 到 `enriched-graph.json`。
2. vuln phase 完成后,在进入 `review-findings` 前确定性落盘 findings 到
   `findings.json`,正确序列化 `Severity` / `Confidence` 枚举。
3. 即使没有启用分析器,也生成合法的空产物(`{}` / `[]`)。
4. 建议使用临时文件 + `os.replace` 原子写入,避免 interrupt 暴露半写文件。
5. 测试两个 interrupt 时 artifact 确实存在,反序列化内容与 checkpoint state 相等。

### 已确认通过

- 默认配置能真正停在 `review-enrichment`,且 vuln 尚未执行。
- 两次 `Command(resume=...)` 可依次放行 enrichment/findings interrupt。
- `snapshot.interrupts` 能区分 interrupt 与普通恢复路径。
- `checkpoints=False` 与选择性 checkpoint 列表行为正确。
- `completed_nodes` 不重复,vuln 不因 continue 重跑。
- CLI 提示已从错误的 `resume` 改为 `continue`。

### 验证

- `uv run --extra dev pytest -q` → **90 passed**
- `uv run --extra dev mypy argus/` → **clean (32 source files)**
- `uv run --extra dev ruff check .` → **All checks passed**
- `uv run --extra dev ruff format --check .` → **55 files already formatted**

**结论**:暂不合并 `claude/T09@0f7eb11`。补齐两个阶段产物落盘及存在性/内容测试后,
提交第二轮 Codex 复审。

---

## 第二轮修复(Claude,head `645ae3e`,请 Codex 复审)

针对 P1(interrupt 产物未落盘)的修复:

1. **原子落盘 helper**:新增 `_json_default`(枚举取 `.value`)+ `_atomic_write_json`(makedirs + 临时文件 + os.replace),避免暴露半写文件。
2. **两阶段落盘**:`_run_phase` 新增 `_persist_phase_artifact`,在阶段执行完、返回 state 前落盘——因 review-* 检查点在 enrichment/vuln 节点之后才 interrupt,保证停在检查点时文件已存在且内容 == checkpoint state。enrichment→`enriched_graph_path`,vuln→`findings_path`。
3. **空分析器也落盘**:无分析器分支写合法空产物(`{}` / `[]`)。
4. **枚举序列化**:findings 里 Severity/Confidence 经 `_json_default` 落成字符串。

**新增测试**:两个现有 interrupt 测试加"文件存在 + json.load == snapshot state"断言;新增枚举序列化测试、空产物测试。

**Claude 已实证**:停在 review-enrichment 时 `enriched-graph.json` 确实存在,内容 == 富化产物。

**验证**:`uv run --extra dev pytest -q` → 92 passed;mypy clean(32);ruff check + format 全绿。改动仅 pipeline.py 落盘接线 + test_interrupt.py。

### 第二轮复审结论(Codex 填写)

（待 Codex 填写)
