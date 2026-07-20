# 评审:T17 图组/无图组对照 + 隔离 baseline(Codex 实现,Claude Code 正式交叉评审)

**实现者**:Codex
**评审者**:Claude Code(正式独立交叉评审——此前仅 Codex 子 Agent 自审,不满足 `docs/COLLABORATION.md` 协作规范,本份为补齐的正式评审)
**评审方式**:main 分支只读通读 `compare.py` / `baseline/` / `source.py` + pipeline SourceAccess / business-logic invariant 消费 / `test_compare.py`;独立跑全门禁;逐项核查 6 个隔离边界 + 误配置 fail-closed;并对最关键的 I-1 泄露面与账目归属亲自 git/数据核实。

---

## 评审裁决

- **Spec:✅ 通过** —— 图/baseline 对照 + 三重隔离 + line-preserving stripping + 可信 node_id 映射均落地且防御到位。
- **Quality:Approved(附 1 条 Important 前置)** —— 无 Critical 隔离绕过。存在一个 fail-open 泄露面(I-1),当前四靶场不触发,但 T18 组装 baseline 文件清单前须定性。

代码质量高:双重防御(analyzer 不信任 `source.mode`,拿到 read 结果**再 strip 一次**)、隔离校验在任何 read/LLM 调用**之前**、可信锚点映射与模型自述完全解耦。fail-closed 贯彻到底。

### 独立验证(在 main 实跑)
- `pytest tests/eval/test_compare.py`:**8 passed**
- `pytest` 全量:**168 passed**(codex 自述 160,实际更高,无回归)
- `mypy argus/`:clean(42 files)
- `ruff check`:clean

---

## 六个隔离边界逐项核查

**1. graph/enriched/source-mode 三重隔离 —— ✅ 无绕过**
`_validate_isolation`(baseline/analyzer.py:67-100)用 `type(ctx["graph"]) is not NoGraphHandle`(严格类型,连子类都拒)、`enriched != {}`、`source.mode is not STRIPPED` 三重把关,且在读源码/调 LLM 前执行(test:217-229 证实 read/llm 零调用)。analyzer 全程只用 `ctx["source"].read`,从不触碰 `ctx["graph"]`;`NoGraphHandle` 五方法全抛 `BaselineIsolationError`(test:232-244)。真实 pipeline 只注入真实 `CodegraphHandle`,误配置必在类型检查处 fail-closed。

**2. stripping 去教学答案 + 保留行号 —— ✅(Python/Go/C-style),⚠️ 见 I-1**
- Python:tokenize 收 COMMENT + ast 定位真 docstring;**token 或 parse 失败即整文件空白化**(source.py:60-61,fail-closed)。字符串内 `#`、普通 block 字符串、括号/拼接 docstring 均正确处理。
- C-style:状态机处理行/块注释、字符串(含 Go backtick 原始串),字符串内 `//`(URL)不误删。
- 所有路径只把注释字符替换为空格、从不删 `\n`/`\r`,行号严格保留。

**3. node_id 可信映射不进 prompt —— ✅ 无绕过**
prompt.txt 无任何 node_id/graph/enriched/config,明确 "Do not return node ids"。analyzer 只把 `{path, stripped source}` 塞进 prompt。Finding 的 node_id 由 runner 可信 `config.baseline.anchors[path]` 按行经 `_anchor_for_line` 选真实 callable node;模型伪造的 node_id 被忽略(test:189-196)。**未命中任何 anchor 的行直接丢弃**(analyzer.py:135-137)—— 对 T18 正确 fail-closed。

**4. 越界/跨文件/畸形 JSON 安全丢弃 —— ✅ 代码 fail-closed,测试薄(M-1)**
`_json_payload` 畸形→None→`[]`;`file not in allowed` 跳过;`_valid_line` 卡 `1..line_count`(排除 bool);`_safe_relative_path` 拒 `..`/绝对路径。逻辑全部 fail-closed。但 test_compare.py 未直接断言这三种情形(覆盖缺口,非绕过)。

**5. invariant 只进对应 handler component,关闭无 stale —— ✅**
`_invariants_enabled`(business_logic/analyzer.py:149-157)在 `invariant.enabled is False` 或 enrichment 未启用 invariant 时返回 False → 采集阶段 `invariants=[]`,源头即空。双重门:`_component_semantics` 只选本 component 的 handler node,再经 `_retain_verified_invariants` 按 codegraph `allowed_node_ids` 过滤。关闭时无残留,开/关确实改变输入 —— T18 对照前提成立。
> **账目归属订正**:此段 invariant 消费代码实际由 T13 提交 `3c7256f` 落地,**不在** T17 两个提交(`75787ce`/`bccafa8`)里。评审请求把它列为 T17 改动。功能正确,仅归属需订正。

**6. compare 保持两组输入与 GT 不变 —— ✅**
compare.py 只对同一 GT 调两次 `score()`,零改写。test_compare:158/168 用 `deepcopy` 断言三方入参调用后不变。

**额外(误配置 fail-closed)—— ✅**:`baseline` 不在 `DEFAULT_CONFIG.analyzers.vuln`(test:247-249),误加也会因真实 GraphHandle 在读码/调 LLM 前抛错。

---

## Findings

### Critical
**无。** 未发现任何可用的隔离绕过。

### Important

**I-1. 不支持语言的源码 fail-OPEN 泄露** — `argus/source.py:36`
`strip_source` 只对 `.py/.pyw` 及 C-style 扩展名集合(`.go/.js/.ts/.java/.c/.cpp/.h/.kt/.rs/.swift/.jsx/.tsx/.cc`)剥离,**其它扩展名(`.rb`/`.php`/`.cs`/`.scala`/`.pl` 等)`return text` 原样返回**——教学注释/docstring 直接进 baseline prompt。方向是 fail-**open** 而非 closed。
- **影响**:若 T18 的 `config.baseline.files` 含任一不支持语言的文件,弱 baseline 会偷看到教学答案 → recall 虚高 → 对照结论不可信(正是本评审最担心的失效模式)。
- **当前不触发(已核实)**:四靶场 ground_truth 的 location 扩展名分布为 `.py`×21 + `.go`×4,**两者都在支持列表内**,故本轮 T18 跑批不受影响,定级 Important。**一旦 T18 纳入不支持语言的文件即升级为 Critical。**
- **建议**:为未知扩展名 fail-closed(整文件空白化)或显式拒绝,而非返回原文。

### Minor
- **M-1. 边界 4 测试缺口** — `tests/eval/test_compare.py`:越界行/跨文件 file/畸形 JSON 三种丢弃路径代码正确但无直接断言。T18 重度依赖前建议补对抗用例。
- **M-2. JS/TS 正则字面量可能被误当块注释** — `source.py:120-169` 状态机不识别 regex 字面量(如 `/*/`),可能过度剥离。方向安全(不泄露,只损保真度),仅影响 JS/TS baseline 输入质量。
- **M-3. f-string docstring 不被剥离** — `source.py:81-83` 仅剥 `ast.Constant` 纯字符串 docstring,f-string(`ast.JoinedStr`)不剥。构造极不现实,风险极低,仅记录。

---

## 结论
三重隔离、stripping、可信 node_id 映射、compare 不变性、invariant 组件作用域全部独立验证通过,**无 Critical 绕过**。**批准 T17,解锁 T18。**

**T18 开跑前的唯一前置**:runner 组装 `config.baseline.files` 时须确保所有文件属 `strip_source` 支持的语言(当前四靶场 `.py`/`.go` 已满足);若未来纳入不支持语言的文件,须先修 I-1(未知扩展名 fail-closed)否则 baseline 会偷看教学答案毁掉对照。M-1 建议同批补测。
