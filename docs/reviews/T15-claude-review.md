# 评审:T15 靶场资产与 ground truth 导入(Codex 实现,Claude 评审)

**分支**:`codex/T15`(head `0a36758`,实现 `57b9364`,rebase 到 `main@5deeb8d`)
**评审者**:Claude
**评审方式**:独立 worktree 检出 codex/T15,建 uv 环境跑全门禁 + 实证核查 ground truth 完整性/裁剪范围/敏感材料/唯一 id/词汇表 + 读 EVAL.md 与 pyproject。

---

## 评审结论

### 裁决 1 — Spec 合规:✅ 通过
导入三靶场(VAmPI/crAPI/flowmart)+ 四份 ground truth(25 个漏洞)+ EVAL.md + 资产校验测试 + pyproject 隔离。未碰 argus 核心源码。

### 裁决 2 — 代码质量:Approved
门禁全绿(115 passed / mypy 36 files clean / ruff check + format 全过)。

### 对 codex 5 个评审问题的核查结论
1. **ground truth 足够 T16 计分 & crAPI 分开计分?** ✅ 是。结构一致(id/in_scope/invariant_kind/vuln_type/location/handler/endpoint/description/source)。crAPI workshop(8)与 community(4)是两份独立文件,天然分开计分。
2. **crAPI 裁剪是否仍覆盖 ground truth?** ✅ **实证通过——全部 25 个漏洞引用的 location 源码文件在裁剪后都存在**(用 repo+service_path+location 拼路径逐条核验)。crAPI 只留 workshop/community,未伤及任何 ground truth。
3. **location+service_path 定位约定 / 唯一 id / 五类词汇表适合 T16/T17?** ✅ 25 个 id 全局唯一无重复;`invariant_kinds_in_scope` 四份都严格声明五类(ownership/authentication/role/replay/trust_boundary)。
4. **pyproject 隔离只圈资产不漏 argus?** ✅ `packages.find` include=["argus*"] exclude targets/ground_truth/tests;ruff extend-exclude=["targets"]。独立确认 `ruff check argus/` 仍全过,editable install 正常。
5. **EVAL.md 来源可追踪?** ✅ 记录 logic-graph / VAmPI / crAPI 三个来源 commit + 扫描根 + 复现命令(含 `--set source_mode=stripped`)。

### 敏感材料排除(重点核查)✅
targets/ 下无 .key/.pem/.p12/.keystore/.jks/.env 文件、无嵌套 .git/.codegraph、无 "BEGIN PRIVATE KEY" 内容。干净。

### Findings
- **Critical / Important**:无。
- **Minor(不阻塞,提示 T16)**:invariant_kind 除五类外还有 `"n/a"`,**但全部对应 `in_scope=False` 的非不变量漏洞**(SQLi/NoSQLi/SSRF/路径穿越/ReDoS/用户枚举——这些归 injection/ssrf 等分析器,不属业务逻辑不变量)。这是**有意且正确的设计**:in_scope 的漏洞才参与 invariant/business-logic 召回计分,注入类不混入。**给 T16 的约定**:计分时应按 `in_scope=true` 过滤,`n/a` 类不计入 invariant/business-logic 的 recall/precision(否则会人为拉低)。建议 T16 实现时显式遵守这条,并在 T16 评审时确认。

**结论**:可合并。数据资产干净、完整、可追踪,ground truth 定位经实证全部有效,为 T16/T17 提供了稳定输入。
