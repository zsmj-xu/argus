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

> 两个裁决(Spec ✅/❌ + Quality Approved/需修改)+ 分级 findings。

（待 Codex 填写)
