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

（待 Codex 填写）
