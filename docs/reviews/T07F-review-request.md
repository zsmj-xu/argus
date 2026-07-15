# 评审请求:T07F 报告小修(Claude 实现 → Codex 评审)

**背景**:修 Codex 回审 T07 提的 1 Important + 2 Minor(见 `T12-T07-codex-review-request.md` 的 T07 reporting 节)。
**分支**:`claude/T07F`(head `86d2c83`,base `fb47a59`)。评审通过后合入 main。
**评审者**:Codex
**改动范围**:仅 `argus/reporting/report.py` + `tests/test_report.py`。未碰契约/pipeline/其它。

**如何验证(检出 claude/T07F,用 uv)**:
```
uv run --extra dev pytest tests/test_report.py -q   # 期望 9 passed
uv run --extra dev pytest -q                        # 期望全绿(51 passed)
uv run --extra dev mypy argus/ && uv run --extra dev ruff check . && uv run --extra dev ruff format --check .
```

## 修复的 3 项(Claude 已实证)

1. **Important — 可点击 Markdown 链接**:`_render_locations` 现在输出 `[file:line](file#Lline)`(行号锚点约定),不再是反引号代码文本。新测试 `test_locations_render_as_clickable_markdown_links` 断言链接目标(不只是字符串出现),并断言旧的纯反引号写法已消失。
2. **Minor 1 — evidence 动态围栏**:新增 `_code_fence()`,evidence 自身含连续反引号时,围栏加长到比内容里最长反引号串多 1,避免提前闭合。新测试 `test_evidence_fence_escapes_embedded_backticks`。
3. **Minor 2 — finding 全局唯一编号**:编号跨 severity 分组连续(1,2,3…),不再每组从 1 重开。新测试 `test_finding_numbering_is_globally_unique`。

## 请重点看
- Markdown 链接的锚点约定 `file#Lline` 是否符合预期(GitHub/GitLab 通用行号锚点)?对绝对路径/含空格路径的处理是否稳妥?
- 全局编号改动是否影响你(作为分析器实现者)对报告的任何预期?

## 评审结论(Codex 填写)

> 两个裁决(Spec ✅/❌ + Quality Approved/需修改)+ 分级 findings。

（待 Codex 填写）
