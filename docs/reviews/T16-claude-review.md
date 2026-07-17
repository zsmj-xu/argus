# 评审:T16 评测打分(Codex 实现,Claude 评审)

**分支**:`codex/T16`(实现 `bef8315`,基于 `main@1030f31`)
**评审者**:Claude
**评审方式**:独立 worktree(`argus-codex-t16`)检出 codex/T16,建 uv 环境跑全门禁 + 决定论压测(竞争匹配 200 次)+ 构造误配负例实证核查匹配规则边界。

---

## 评审结论

### 裁决 1 — Spec 合规:✅ 通过
满足任务卡:`score(findings, ground_truth) -> {recall, precision, tp, fp, fn, matched}`,按 file + 行邻近(10 行)+ vuln_class 自动打分,纯确定性,无 LLM。

### 裁决 2 — 代码质量:**需修改**
核心算法(二分图增广匹配、一对一不重复消费、`in_scope=false` 过滤、零分母 `0.0`)**正确且稳健**,无需改动。但 **handler token 匹配过松**,存在一个会污染 T17/T18 对照实验的 recall 虚高缺陷(C1),且测试完全没覆盖误配负例(I3)。合入前需修 C1 + I3。

### 独立验证(在 worktree `argus-codex-t16` 实跑)
- `pytest tests/eval/test_score.py`:**7 passed**
- `pytest` 全量:**122 passed**
- `mypy argus/`:**Success, 38 files**
- `ruff check .`:**All checks passed**
- 决定论:竞争匹配场景跑 200 次,输出唯一(`matched` 稳定);确认无随机、无 dict 遍历顺序依赖,纯确定性 ✅
- codex 自述数字全部属实。工作树已切回 main,干净。

---

## Critical

### C1. handler token 用无分隔的子串匹配 → 同文件多 handler 交叉误配,recall 虚高
`argus/eval/score.py:283`(`_token` 去掉所有非字母数字)+ `:221`(`handler_token in finding_text`)

`_token("list_users")` → `"listusers"`,`finding_text` 也是全部拼接去分隔后的长串,判断用裸 `in` 子串包含,**无词边界**。实测(flowmart `api/users.py` 有 register/list_users/get_wallet 三个**无数字行号**的 GT,全走 handler fallback):3 条实际都在讲 register 的重复 finding(evidence 里顺带提到 list_users/get_wallet)→ `tp=3 fp=0 fn=0 recall=1.00`。

一条 finding 的 evidence/data_flow 里提到对照 handler 名(真实分析文本极常见,GT 的 source 自己就在写"对照 xxx")就会命中错误的 GT。旁证(`SUBSTRING-HANDLER TEST`):`get_wallet` 的 finding 标题写 "for registered users" 就命中了 `register` handler(`register` ⊂ `registered`)。

**影响 T17/T18**:这是给对照实验打分的地基。handler 子串误配会让弱 analyzer 蹭到 TP,recall 虚高,直接**污染对照结论**(无法区分"真检出"和"文本里提了一嘴")。flowmart 全部 6 条都靠 handler fallback,正是最脆弱的资产。**标 Critical。**

**建议**:token 化后按分隔切词做集合成员判断(`handler in token_set`),而非裸子串。

> **修订(第二轮项目整体审核补充)**:原建议里"优先用 `node_id`(含真实 handler 名)做锚"的前提**有误,勿照做**。核查真实 codegraph 数据(`targets/VAmPI/.codegraph/codegraph.db`),function/method 节点 id 形如 `function:1682a981641aa8ebc0e9623f49e0af4f|get_all_books`——handler 名在 `|` 分隔符之后,**node_id 主体是内容哈希,不是可直接子串匹配的结构化名**。因此:
> 1. 正确修法是**用 finding 的 `location.node_id` 反查 codegraph 取该节点的 `name`/`qualified_name`**,再和 GT handler 做 token 集合匹配;而非对 node_id 字符串裸锚。
> 2. `tests/eval/test_score.py:212` 的 `test_real_ground_truth_entries_are_matchable` 用 `node_id=f"function:{location}:{handler}"` **伪造了含明文 handler 名的 node_id**,是假绿灯——真实分析器产出的哈希 node_id 会全部落空。补 I3 时必须把此测试改成真实 node_id 形态(`function:<hash>|<name>`)。

---

## Important

### I1. business-logic 对任意 invariant「近行即命中」,忽略具体 invariant 语义
`argus/eval/score.py:188` + `:213`

`_compatible_class` 让 `business-logic` 兼容全部五类 invariant;当 GT 有数字行号时,`_anchor_quality` 只看文件 + 10 行邻近,**完全不校验 invariant 语义**。实测(`BL-ANY-INVARIANT`):一条标题为"replay bug"的 business-logic finding,落在 ownership GT 的 ±2 行内 → tp=1。

同文件同区域有多个不同 invariant 漏洞时(如 crapi-community `coupon_controller.go` 的 role@32 与 trust_boundary@43,仅差 11 行),任一 business-logic finding 会就近抢占。目前靠 10 行阈值勉强隔开(11 > 10)是**巧合而非约束**。属对照可信度问题。

### I2. 路径后缀匹配的 basename 碰撞
`argus/eval/score.py:278-279`

`_same_file` 用双向 `endswith(f"/{...}")`。实测(`BASENAME-COLLISION`):GT 写裸 `users.py`、finding 在 `api/admin/users.py` → 判同文件 tp=1。真实 GT 目前都是带目录的相对路径(如 `api/users.py`),碰撞概率低,但一旦 GT 或 finding 只给 basename 就会误配。建议要求后缀匹配至少对齐一个目录段,或规范到扫描根相对路径后精确比较。

### I3. 测试零覆盖"误配负例"中的关键场景
`tests/eval/test_score.py`

`test_requires_compatible_class_and_location` 只测了 wrong-class / wrong-file / too-far 三种**行号模式**下的负例。完全没有:
- handler fallback 模式下 handler **不**出现在文本时应判 FN
- handler 子串误配(C1)
- business-logic 跨 invariant 近行误配(I1)
- basename 碰撞(I2)

评分器的价值全在负例防护,而 handler fallback(覆盖 flowmart 全部 + vampi/crapi 部分)这条最脆弱的路径**一个负例测试都没有**。

---

## Minor

### M1. `source` 行号提取对 flowmart 全失效,静默退化
`_line_from_source`(`:150`)要求 `文件名:数字` 紧邻。flowmart 的 source 全是 `api/orders.py ship_order VULN...`(路径与行号不相邻/无行号),提取返回 None,全部退化到 handler fallback——功能上按设计工作,但意味着 flowmart 6 条全靠 C1 里那条最松的路径评分,放大了 C1 的实际影响面。非 bug,值得让 T17/T18 使用者知晓。

### M2. crapi source 形如 `views.py:109 ... put(:236)有` 含次要行号
`crapi.json` 的 source 里有对照行号(如 `put(:236)`)。当前 `_ground_truth_location` 优先用结构化 `location`/`line`,crapi 走 `location` 字段(无数字行)→ handler fallback,不会误取 236。行为正确,仅记录确认无隐患。

---

## 给 codex 的最小修复清单(解锁合入)
1. **C1(必修)**:handler 匹配改词边界 / token 集合成员。**用 node_id 反查 codegraph 拿 `name` 再 token 匹配**(见 C1 修订块,勿裸锚 node_id 字符串);补 handler 子串误配负例测试。
2. **I3(必修)**:补三条负例——handler 缺失判 FN、handler 子串不误配、business-logic 跨 invariant 不近行误配;并把 `test_real_ground_truth_entries_are_matchable` 的伪造 node_id 改成真实哈希形态(见 C2)。
3. **I4(建议必修)**:`_anchor_quality`(`score.py:199-207`)对 `title`/`data_flow`/`rationale`/`evidence`/`node_id` 缺键直接 KeyError,对外部 findings.json 无防御——评测地基应对畸形输入稳健,改用 `.get(...)`。
4. I1/I2 建议修(收紧 business-logic 语义锚定 + 路径至少对齐一段目录),或至少在 T17/T18 文档标注为已知松弛点。

算法骨架(增广匹配、一对一、决定论、in_scope、零分母)无需改动,实现正确。

---

## 第二轮项目整体审核补充(6 视角并行审计)

本份评审最初只看了 `codex/T16` 分支。项目整体审核后补充以下与评测可信度直接相关的新发现:

- **C0 · eval 代码尚未合入 main,C1/I3 仍未修**:`git merge-base --is-ancestor bef8315 main` = NOT on main。`codex/T16`、`codex/T16-fix`、`codex/T17` 三分支的 `score.py` blob 哈希完全相同(`0578af6…`),即 "T16-fix" 分支**没有任何修复提交**。**任何基于当前代码跑出的 T17/T18 数字都建立在未修复的评分器上,不可采信。** 合入 T17 的前置就是先真正落地 C1+I3+C2 修复。
- **C2 · C1 原修复建议前提错误**(已在 C1 修订块详述):真实 node_id 是 `function:<hash>|<name>`,不含可裸锚的明文 handler;测试用伪造 node_id 造假绿灯。
- **I5 · C1 的实际暴露面 = flowmart 6 条**:实测 crapi(5)/vampi(4)/community(3) 因 source 带行号走 LINE-ANCHOR,只有 flowmart 6 条走 HANDLER-FALLBACK(其 GT 全无行号且 `api/users.py` 同文件三 handler)。**给 flowmart 的 GT 补行号即可让它脱离 fallback、直接绕开 C1**,是成本最低的止血法。
- **确定性复核认同**:`score.py` 纯确定性(无 LLM/无随机/enumerate+显式 sort,不依赖 dict 顺序),增广匹配算法正确。

---

## 评审裁定
**Spec ✅ / Quality 需修改。** 修完 C1(按修订后的正确方案)+ I3 + C2 测试修正后可合入并解锁 T17。**注意 C0:目前 eval 尚未上主干,修复动作尚未发生。**
