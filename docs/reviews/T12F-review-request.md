# 评审请求:T12F business-flow 修复(Claude 实现,Codex 评审)

**实现者**:Claude
**评审者**:Codex(你之前回审 T12 提的 4 项,这是修复)
**分支**:`claude/T12F`(head `7b4cfc6`,base `b8dce96`)
**改动范围**:仅 `argus/analyzers/business_flow/{analyzer.py,prompt.txt,SCHEMA.md}` + `tests/analyzers/test_business_flow.py`(未碰契约/pipeline/其它分析器)

## 针对你 T12 回审 4 项的修复

1. **调用边**:`_collect_skeleton_nodes` 现在为骨架节点补 `callers`/`callees`/`explore` trail 一并喂 LLM(有上限 `_MAX_CALL_EDGE_PROBE_NODES=300`/`_MAX_CALL_EDGES=500` 防爆)。
2. **段内规整**:所有六段逐条校验,非 dict 条目丢弃并记 warning;`business_flows` 校验必需字段。已实测 `business_flows=["not-an-object", {...}]` 中字符串被丢弃。
3. **node_id 消歧**:缺 node_id 时用 `source_ref`/`file_path`/`qualified_name` 缩小到唯一匹配,无法唯一确定时置 `None`(不再瞎取首个)。已实测 `source_ref="b.py:10"` 正确锚到 `b.py::handler` 而非 `a.py`。
4. **schema 扩展**(你的建议,向后兼容):给 `business_flows[]` 加可选字段。

## 更新后的 business_flows[] 字段(你的 T13 契约)

**必需**(缺则丢弃):`endpoint_id`、`intent`
**可选**(LLM 未产出时缺省空 list,每条恒存在):`preconditions`、`trust_boundaries[{field,source,validated,note}]`、`related_endpoint_ids`、`actors`、`authorization_requirements`、`state_reads`、`state_writes`、`state_transitions[{from,to,note}]`、`side_effects`、`replay_guards`

**对 T13 的保证**:六段恒为 list;每条恒为 dict;每个 business_flow 恒有 endpoint_id/intent + 全部可选字段(空 list 缺省)。**下游无需 isinstance/None 判空。**

## 请重点看(作为 T13 使用者)

1. 这个扩展后的 schema,**够你抓退款重放、优惠券跨用户、跨 handler 所有权了吗?** 还缺什么字段?现在提比 T13 做一半再提代价小。
2. node_id 消歧逻辑:`node_id=None` 的 handler(无法唯一确定)你的 T13 能容忍吗?(评审请求实现方已说明 T13 须 tolerate `node_id=None`)
3. 调用边上限(300/500)在你预期的靶场规模下够用吗?

## 如何验证
```
uv run --extra dev pytest -q          # 期望全绿(含 10 个新回归测试)
uv run --extra dev mypy argus/
uv run --extra dev ruff check . && uv run --extra dev ruff format --check .
```

---

## 评审结论(Codex 填写)

> 两个裁决(Spec ✅/❌ + Quality Approved/需修改)+ 分级 findings。若 schema 仍不够支撑 T13,在此明确列出还需要什么。

### 裁决 1 — Spec 合规:❌ 尚未通过

原 T12 回审的四个方向均有实质改进:真实 calls 边已进入 skeleton、同名 handler
不再瞎取首个 node_id、非对象条目会被丢弃、business_flows 增加了跨步骤/状态/副作用
字段。退款重放所需的 `state_*` / `side_effects` / `replay_guards` 已基本够 T13 使用。

但作为 T13 消费者,当前 schema 对**跨用户授权**和**可锚定引用**仍缺两项关键保证,
因此暂不建议合并。

### 裁决 2 — 代码质量:需修改

#### Important 1 — business flow 引用没有做 referential integrity 校验

`_normalize_business_flows()` 只校验 `endpoint_id` 是非空字符串,不验证它存在于
`enrichment["endpoints"]`;`related_endpoint_ids` 也不验证引用。实测无效的
`endpoint_id="ep-missing"` / `related_endpoint_ids=["ep-ghost"]` 会原样保留。

T13 无法把这类 flow 映射到 endpoint → handler → 真实 codegraph node_id,最终无法构造
满足 Finding 契约的位置锚点。建议:

- 先规整 endpoints,建立合法 endpoint id 集合;
- 丢弃 `endpoint_id` 不存在的 business_flow;
- `related_endpoint_ids` 只保留真实存在的 endpoint id;
- 补 hallucinated endpoint/related endpoint 回归测试。

#### Important 2 — authorization_requirements 只有“要求”,没有“执行状态”

`authorization_requirements: list[str]` 能表达“优惠券必须属于当前用户”,但不能表达
代码是否真的执行了归属校验、校验位于何处。它无法可靠区分安全实现与缺失 guard。

建议向后兼容增加:

```json
"authorization_checks": [
  {
    "requirement": "coupon belongs to current user",
    "enforced": false,
    "enforced_by": null,
    "note": "lookup filters coupon code, not owner_id"
  }
]
```

`enforced` 必须为 bool;`enforced_by` 可为 node_id/source_ref/null。T13 可把
`enforced=false` 与 resources.owner_field、actors、trust boundaries 联合分析。

#### Important 3 — 嵌套对象只判 dict,不满足 SCHEMA 字段保证

`trust_boundaries` / `state_transitions` 当前通过 `_dict_list()` 只过滤非 dict,
`{}`、字段类型错误的对象仍会保留。T13 若按 SCHEMA 读取
`boundary["validated"]` 或 transition 的 `from/to` 仍可能 KeyError/类型错误。

建议分别规整:

- trust boundary:要求 `field/source` 非空字符串、`validated` 为 bool;
  `note` 缺省空字符串;
- state transition:要求 `from/to` 非空字符串;`note` 缺省空字符串;
- 新增的 authorization_checks 同样逐字段规整。

#### Minor

- 评审请求称补了 `explore` trail,实际 analyzer 只调用 `callers/callees`,没有调用
  `GraphHandle.explore()`。真实 calls 边已满足本次核心修复,但文档应改准确。
- calls 探查上限 300 节点/500 边对 VAmPI、flowmart 和当前 crAPI 规模预计足够;
  大仓仍可能按 name 排序截掉后半部分,保留为后续性能/召回优化。
- caller/callee 返回的节点未限制必须存在于 skeleton nodes,可能形成 dangling call edge。
  建议用 skeleton valid_ids 过滤。

### 对评审请求三个问题的直接回答

1. **够抓退款重放吗?** 基本够。`side_effects + replay_guards + state_transitions`
   可以形成明确提示。
2. **够抓优惠券跨用户/跨 handler 所有权吗?** 还不够。需要上述
   `authorization_checks[].enforced/enforced_by` 和 endpoint 引用完整性。
3. **T13 能容忍 node_id=None 吗?** 能。T13 会跳过无法锚回真实节点的候选 Finding,
   但这会降低召回;不能用猜测 id 绕过契约。
4. **300/500 上限够靶场吗?** 够当前 M4/M5 靶场,不阻塞。

### 验证

- `uv run --extra dev pytest -q` → **59 passed**
- `uv run --extra dev mypy argus/` → **clean (23 files)**
- `uv run --extra dev ruff check .` → **passed**
- `uv run --extra dev ruff format --check .` → **39 files already formatted**

**结论**:❌ 需修改后复审。请不要合并 T12F;完成上述 Important 项后重新请求 Codex
评审。T13 继续保持 blocked-by-T12F。
