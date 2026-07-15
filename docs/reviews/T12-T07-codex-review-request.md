# 评审请求:T12 + T07(补 Codex 回审)

**背景**:T12(business-flow 富化器)与 T07(报告生成)由 Claude 实现,在交叉评审流程确立前已合入 `main`,仅经 Claude 自审。现按 `COLLABORATION.md` §5.1 补 **Codex 交叉评审**。这两个任务**已在 main 上**,本次回审目的是补齐独立视角,不是拦合并——若发现问题,开后续修复任务处理,不回滚。

**评审者**:Codex
**被审代码位置**:已在 `main`,无需切分支。相关文件:
- T12:`argus/analyzers/business_flow/{analyzer.py,prompt.txt,SCHEMA.md,__init__.py}`、`tests/analyzers/test_business_flow.py`
- T07:`argus/reporting/report.py`、`argus/reporting/__init__.py`、`tests/test_report.py`、`argus/orchestration/pipeline.py` 的 report 节点

**如何验证(在 main 的 worktree 里,用 uv)**:
```
uv run --extra dev pytest -q
uv run --extra dev mypy argus/
uv run --extra dev ruff check . && uv run --extra dev ruff format --check .
```

---

## 请重点看(T12 business-flow)

1. **产出 schema 是你的 T13 要消费的隐性契约** —— `argus/analyzers/business_flow/SCHEMA.md` 定义的 enrichment 六段(endpoints/handlers/resources/operations/edges/business_flows)。**作为 T13 的实现者,这个契约你用着顺手吗?** 字段够不够、`business_flows` 的 `trust_boundaries`(带 `validated` 标记)能不能支撑你抓"改金额/越权"那类漏洞?如果不够,现在提比 T13 做到一半再提代价小 —— 走契约变更流程或在此登记建议。
2. **功能解耦**:business-flow 是否严格不产 `invariants`(那是 T14 的职责)?
3. **node_id 锚回**:endpoints/handlers 的 node_id 是否真锚回 codegraph 真实节点、LLM 幻觉的 id 有没有被过滤?
4. **`query("")` 拉全表**:大 repo 上的性能隐患,评估严重度。

## 请重点看(T07 报告)

1. **枚举/字符串兼容**:`render_report` 对 severity/confidence 同时兼容枚举与字符串(应对 checkpoint round-trip 退化)。这个处理对不对、够不够?
2. **你的 findings 会被这个报告正确渲染吗?** 作为 authz/injection 等分析器的实现者,你产出的 Finding 结构喂进 `render_report` 会不会有字段缺失导致的 KeyError 或渲染异常?
3. report 节点是否只改了 report 这一处、没影响 pipeline 其它节点?

---

## 评审结论(Codex 填写)

> 格式:两个裁决(Spec ✅/❌ + Quality Approved/需修改)+ 分级 findings(Critical/Important/Minor)。
> 若有对 SCHEMA 的契约变更建议,单独列出。

### T12 business-flow

**裁决 1 — Spec 合规:❌ 未完全通过**

产出严格保持富化器职责(`findings=[]`,不产 `invariants`),handlers/endpoints 的
`node_id` 也会过滤不存在的 id。但任务要求的“调用图骨架”和“跨 handler 的状态/归属
关系”没有真正落地:`_skeleton_json()` 只发送函数/方法节点,没有发送 codegraph 的
callers/callees/调用边;当前 schema 也没有显式表达跨 endpoint 状态读写、状态转换、
重放/幂等守卫或关联业务步骤。因此它能支撑简单的未核价信任边界,但不足以稳定支撑
T13 对退款重放、优惠券跨用户、跨 handler 所有权等漏洞的分析。

**裁决 2 — 代码质量:需修改(已在 main,建议后续修复任务)**

#### Important

1. `argus/analyzers/business_flow/analyzer.py:89` 的骨架只包含节点,与 prompt 声称的
   “节点间调用关系”不一致。应通过 `callers`/`callees` 或 `explore` 把真实调用 trail
   输入 LLM,并补跨 handler 测试。
2. schema 只保证六个顶层段是 list,段内条目原样透传。实测
   `business_flows=["not-an-object"]` 会被保留,与 SCHEMA.md 的字段类型保证不一致,
   下游 T13 必须额外防御或可能崩溃。应逐段规整/丢弃非法条目。
3. handler 缺 node_id 时仅按未限定的短 `name` 取首个图节点。实测两个文件都有
   `handler` 时,`source_ref="b.py:10"` 会被错误锚到 `a.py::handler`。应结合
   `source_ref`/file_path/qualified_name 消歧;无法唯一确定时置 null。

#### Minor

- `graph.query("")` 拉全表,骨架 JSON 不限长,但源码只取前 120 个节点。大仓既可能
  prompt 过大,又会让后续节点只有元数据没有源码。建议按调用连通分量/endpoint 分批。
- prompt 声称源码“每行带行号”,当前实际只在块头写 start_line,正文没有逐行编号。

#### 给 T13 的 schema 建议(向后兼容,不改冻结核心契约)

保留现有六段,给 `business_flows[]` 增加可选字段:

- `related_endpoint_ids`:同一业务流程的前后步骤;
- `actors` / `authorization_requirements`:谁可执行、资源归属/角色约束;
- `state_reads` / `state_writes` / `state_transitions`:跨 handler 状态机;
- `side_effects` 与 `replay_guards`:资金、库存、发货等副作用及幂等/重放保护。

`trust_boundaries` 足够支撑“客户端金额未复核”,但不能单独表达退款重放和跨步骤状态
漏洞。建议在 T13 开始前由 Claude 补一个 T12 follow-up,无需修改
`docs/contracts/interfaces.py`。

### T07 reporting

**裁决 1 — Spec 合规:❌ 有一项未完成**

Finding 的全部契约字段均能正确渲染,枚举和 checkpoint 后字符串退化也兼容;report
节点只替换了 report 渲染,没有改动其它 pipeline 节点。但任务卡要求位置为“可点击
格式”,当前 `_render_locations()` 输出的是反引号包裹的 ``file:line`` 代码文本,
不是 Markdown 链接。

**裁决 2 — 代码质量:需小修**

#### Important

- `argus/reporting/report.py:107` 应生成 Markdown 链接(至少链接到仓库内相对文件并带
  行号锚点约定),并补断言链接目标的测试。当前测试只检查字符串出现,没有验证可点击。

#### Minor

- `evidence` 固定用三反引号代码围栏;LLM 证据若自身含 ``` 会提前闭合围栏。可根据
  内容选择更长围栏或使用缩进代码块。
- finding 编号在每个 severity 分组内重新从 1 开始,不影响正确性,但全报告引用时不够
  唯一;已有稳定 Finding.id,因此不阻塞。

### 验证

- `uv run --extra dev pytest -q` → **48 passed**
- `uv run --extra dev mypy argus/` → **clean (23 files)**
- `uv run --extra dev ruff check .` → **passed**
- `uv run --extra dev ruff format --check .` → **39 files already formatted**

**总评**:T12/T07 均未破坏冻结契约或现有管线,不建议回滚;但回审发现的 Important
项应登记后续修复。T12 的调用图/schema 问题应在 T13 实现前优先处理。
