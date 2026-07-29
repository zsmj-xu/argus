# M6：候选驱动的 Injection 与 Authorization 检测

状态：已实现。M6 只迁移静态检测链，不建设 M7 Web Control Plane，也不加入任何
PoC、目标网络、凭据或动态验证能力。

## 执行链

两条迁移规则共享四层运行边界：

```text
CandidateProvider
  → BoundedGraphSliceBuilder + SourceContextBuilder
  → StrictExpertEvaluator
  → StaticFindingNormalizer + deterministic deduplication
```

`Candidate` 包含稳定 ID、规则和版本、候选类型、主/source/sink/route/identity
节点、原因码、静态分数、root cause key 与完整 provenance。Candidate ID 和
root cause key 只使用稳定事实，不使用 LLM 标题或自然语言说明。

Graph Slice 默认最多 60 个节点、半径 2，并受 Security IR 的 500 节点/8 层硬上限
约束。Source Context 默认最多 12 个 excerpt、每段 3,000 字符、总计 12,000 字符；
可在 `detection` 配置中下调或在系统硬上限内调整：

```yaml
detection:
  graphSliceMaxNodes: 60
  graphSliceRadius: 2
  sourceMaxExcerpts: 12
  sourceExcerptChars: 3000
  sourceTotalChars: 12000
  expertMaxTokens: 8192
```

Expert 只收到 Candidate、有限 Graph Slice 和有限 Source Context。响应必须是严格
JSON，并通过 `ExpertAssessment` 校验；未知字段、非法枚举、缺失的支持证据、切片外
节点引用都会失败。Prompt 明确禁止仓库、网络、凭据、工具假设，禁止创建 Finding ID
或声称动态验证。

## 迁移规则

### Injection

`detector.injection` 从已知 SQL、命令和模板 sink 开始，查询有限 callers，并排除明显
参数化 SQL 和无 shell 的 argv 列表等安全模式。确定性阶段只生成候选和原因码；
是否存在可利用的外部输入流由 Expert 在有限证据内判断。没有 sink 或候选时不构造、
也不调用 LLM。

### Authorization / IDOR

`detector.authorization` 消费 `security.graph.v1`，从 `business.flow` 关联的 route、
外部资源标识、resource reads/writes、identity/guard/policy 生成候选。存在匹配的
ownership、tenant 或当前用户保护时确定性排除；声明但未执行的 policy 会成为额外
原因码。该规则要求先选择 `business-flow` enrichment，以便 Planner 通过 capability
自动加入 Security IR adapter。

## Artifact 与 Finding

每个候选分别保存：

- `candidate.<rule>.v1`
- `graph.slice.<rule>.v1`
- `source.context.<rule>.v1`
- `assessment.<rule>.v1`

同时生成对应 index Artifact 和 `finding.static.<rule>.v2`。单记录 Artifact 使用
Manifest 的 supplemental output 声明，不改变 Planner 或 Executor 的漏洞规则知识。
所有证据 Artifact 与引用它们的 Finding 在同一个 Control Store 事务中提交；任何
Artifact 冲突会回滚整个批次。

Normalizer 只接受 `supported=true` 且有真实 Graph Slice 代码锚点的 Assessment。
Finding ID 由 Normalizer 创建，指纹使用规则、候选类型、位置和 source/sink 节点，
不包含标题。相同指纹会合并证据、位置、前置条件和 rationale，保留最高静态置信度；
`root_cause_key` 用于跨规则关联。所有 M6 Finding 均为 `UNVERIFIED`，报告分别展示
Static Confidence 和 Verification Status。

## 迁移模式

V2 Scan 的 `analysisMode` 默认为 `v2`：

- `legacy`：只运行原 Injection/Authz Analyzer；
- `v2`：只运行对应 Candidate 检测插件；
- `compare`：新旧插件同时运行，并生成 `comparison.*.v1`。

Comparison Artifact 记录 matched、legacy-only、v2-only 和计数，并明确写入
`affects_main_report=false`。Compare 模式下主报告采用 V2 Finding，不重复加入旧规则
结果。固定 Pipeline 和旧 Analyzer 没有删除或重构。

## 验证

离线测试覆盖：

- Candidate 确定性与明显安全模式排除；
- 无 sink/候选时零 LLM 调用；
- Graph Slice 和源码上下文上限；
- 非法 JSON、未知字段和切片外证据拒绝；
- Finding 的图锚点、未验证状态、标题无关指纹和重复证据合并；
- supplemental Artifact 与 Finding 原子提交、冲突回滚；
- `legacy|v2|compare` 选择和 Comparison 旁路语义；
- fixture recall/false-positive 基线；
- 旧 Control Store Finding 升级保留和 Markdown 报告兼容。

测试不运行真实扫描、不调用真实 LLM，也不进行目标网络请求。

## M7 完成后的边界

- business-logic、auth、XSS、SSRF 等仍使用 Legacy Analyzer；
- Security IR 仍由现有 business-flow LLM enrichment 输入，推断事实不会升级为确定性；
- Web 已在 M7 接入持久化任务 DAG、Artifact/Finding、有限 Graph Slice、审核和 Event；
- M8 已增加离线验证需求、环境、身份、策略和 Approval；HTTP Broker/Evidence 仍属于 M9；
- M10 已允许显式启用的 external plugin 在独立进程执行，并拒绝其
  network、secret 和 subprocess 权限。
