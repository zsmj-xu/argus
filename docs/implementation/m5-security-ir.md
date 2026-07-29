# M5：Security IR 与受限 Graph Slice

状态：已实现。M5 只迁移语义事实层，不重写现有 business-flow Analyzer、Prompt 或漏洞检测器。

## 分层与 Artifact

Codegraph 和 Security Graph 是两个独立、不可互换的 Artifact：

```text
code.graph.codegraph.v1
  media type: application/vnd.sqlite3
  producer: graph.codegraph

legacy.enrichment.business-flow.v1 + code.graph.codegraph.v1
  ↓ semantic.business-flow-to-security-ir

security.routes.v1
security.business-flow.v1
security.authorization.v1
security.resources.v1
security.graph.v1
  media type: application/vnd.sqlite3
  producer: semantic.business-flow-to-security-ir
```

当 V2 配置选择 `business-flow` enrichment 时，Legacy Adapter 自动选择语义适配插件；
Planner 仍只处理 Manifest 和 Capability，不包含 business-flow 特例。适配器直接消费已经规整的
business-flow Artifact 和 Codegraph Artifact，不再次调用 LLM。

四个 JSON Artifact 是按用途裁剪的投影；`security.graph.v1` SQLite Artifact 是完整、
可查询的事实来源。五个输出沿用 M4 的批量 Artifact 提交流程，全部验证成功后才一次性提交
metadata。

## Security IR 契约

`SecurityNode` 与 `SecurityEdge` 使用严格 Pydantic 模型。核心 kind 来自 M5 词汇表；扩展 kind
必须带命名空间，未知的裸字符串会被拒绝。

每个节点和边都强制包含：

- `snapshot_id`；
- producer plugin ID/version；
- source Artifact IDs；
- 原始 Codegraph node IDs；
- extraction method：`deterministic`、`llm_inferred` 或 `imported`；
- evidence references；
- confidence：`CONFIRMED`、`INFERRED` 或 `POSSIBLE`。

适配规则不会把 LLM 语义升级成确定性事实：

| 输入 | Security IR | confidence / extraction |
| --- | --- | --- |
| 已验证存在的 Codegraph handler | `code.function` | `CONFIRMED / deterministic` |
| Codegraph `calls` edge | `calls` | `CONFIRMED / deterministic` |
| endpoint、resource、operation、flow | 对应语义节点 | `INFERRED / llm_inferred` |
| business-flow 关系 | 语义边 | `INFERRED / llm_inferred` |
| 明确缺失的 authorization check | `auth.policy` | `POSSIBLE / llm_inferred` |

所有 ID 由 snapshot、实体类别和规范化源身份确定性计算。相同 Scan 输入重复转换得到相同的
节点、边和 provenance。

## 独立 SQLite 图存储

每个 `security.graph.v1` Artifact 是独立 SQLite 文件，包含：

```text
nodes
edges
node_locations
provenance
original_codegraph_nodes
graph_metadata
```

必要索引覆盖 node kind/name、edge kind/source/target、file/line、location Codegraph ID 和
原始 Codegraph node ID。写入时先在相邻临时文件中建立完整数据库，再检查：

1. node/edge ID 唯一；
2. edge 两端存在；
3. SQLite foreign key check；
4. SQLite integrity check；
5. Security Graph application ID 和 schema version。

全部通过后才原子替换目标文件。Control Store 只保存 Artifact metadata，不把完整图塞入 JSON
列。

## 查询与 Graph Slice 上限

`SecurityGraphQuery` 提供：

```text
get_node
find_nodes
neighbors
find_paths
subgraph
slice_for_finding
```

所有遍历都有服务端硬上限：

- nodes：最多 500；
- depth/radius：最多 8；
- paths：最多 100；
- 单次展开 edges：最多 2,000；
- kind filter：最多 100；
- source、target 和 seed ID 集合：最多 500。

结果通过 `truncated=true` 明确表示被上限裁剪。路径查询只沿有向边前进；incoming、
outgoing 和 both 邻居使用各自 SQL 条件，不会因另一方向的高出度边而漏掉结果。

`FindingSliceService` 从 `StaticFindingV2.source_node_ids` 和 `sink_node_ids` 构造有限
Graph Slice。M6 的 Candidate/Expert 迁移已复用同一存储和查询层，并继续受这些上限约束。

## Web 预留数据 API

M5 只增加数据层和只读 API，不建设 Graph Explorer 前端：

```text
GET /api/scans/{scan_id}/graph/nodes
GET /api/scans/{scan_id}/graph/nodes/{node_id}
GET /api/scans/{scan_id}/graph/slice
```

节点列表支持 `kind`、`name`、`file`、`line` 和 `max_nodes`。Slice 支持重复
`seed_id`、`radius`、重复 `allowed_kind` 和 `max_nodes`。Artifact 在打开前重新校验内容
哈希，Graph Artifact 必须属于请求 Scan 的 Snapshot。

## M6 完成后的边界

- injection 和 authorization 已有 Candidate Generator、有限 Graph Slice 与严格
  ExpertAssessment；旧 Analyzer 仍由 `analysisMode=legacy|compare` 保留；
- business-logic 等其他 Analyzer 尚未迁移；
- `business.flow` 仍来自现有 LLM enrichment，因此保持 `INFERRED`；
- M6 的新 Finding 使用不含标题的稳定指纹并保持 `UNVERIFIED`；
- Web 仅有只读数据 API，完整 Control Plane 和 Graph Explorer 属于 M7；
- 不包含 PoC、目标网络请求、凭据、浏览器或验证 Broker。
