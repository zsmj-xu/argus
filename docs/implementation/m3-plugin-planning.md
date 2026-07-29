# M3：Manifest 插件注册与确定性 TaskPlan

状态：M3 完成时的规划层记录。M4 已在不修改 Planner 核心语义的前提下增加执行路径；
当前运行状态见 `m4-local-executor.md`。

## 启动路径

新扫描在 M2 的 SourceSnapshot 和兼容任务准备完成后执行以下只读规划步骤：

```text
discover existing V1 Analyzers
  → read built-in plugin.yaml files
  → adapt Analyzer metadata to PluginSpec
  → resolve required Capabilities
  → compile deterministic TaskPlan DAG
  → persist pending Tasks + task.plan.v1 Artifact
  → invoke unchanged V1 Pipeline
```

因此一次 legacy Scan 同时拥有两组可区分的任务：

- `plan_id IS NULL`：M2 创建并由旧 Pipeline 推进的五个兼容任务；
- `plan_id = scans.plan_id`：M3 编译的计划任务，其中业务任务保持 `PENDING`；
- `core.plan-compiler`：记录计划编译过程并在 Artifact 发布后变为 `SUCCEEDED`。

M4 之前不会根据 TaskPlan 导入或调用插件入口。

## PluginSpec 与 Manifest

`argus/plugins/contracts.py` 定义严格、不可变的 Pydantic 契约：

- semantic plugin ID 和 version；
- `PluginKind`；
- `module:object` entrypoint；
- required/optional input Capabilities；
- output Capability、Artifact type 和 schema version；
- source、network、subprocess、secrets 权限；
- isolation mode 和 timeout；
- config/output schemas。

Capability 使用带版本的稳定名称，例如 `code.graph.codegraph.v1`。重复输入、重复输出、
required/optional 重叠、非法版本和未知字段均 fail closed。

Registry 的发现阶段只递归读取 `plugin.yaml`，不导入 entrypoint。当前自动发现只包含
仓库内置插件。外部目录必须显式设置 `allow_external=true` 才能登记；即使已登记，
M10 后 external plugin 强制使用独立进程，且不能申请 network、secret 或 subprocess；
入口不会在 Control Plane 主进程加载。

内置 Codegraph Manifest 是唯一允许申请受限 subprocess 权限的当前插件。Network 和
Secrets 权限当前只有 `none`。

## Capability Planner

Planner 输入：

- selected plugin IDs；
- initial Capabilities；
- Registry；
- 显式 provider 选择；
- 每插件 JSON config。

Planner 递归补齐 required producer，并在下列情况直接失败：

- 选中插件不存在；
- required Capability 没有 producer；
- 存在多个 producer 但未显式选择；
- 指定 provider 不存在或不生产目标 Capability；
- 依赖形成循环。

Optional Capability 不会主动拉入额外插件；如果其 producer 已在计划中，则建立依赖边。
拓扑排序按层执行 Kahn 算法，同层按 plugin ID 和 semantic version 稳定排序。

每个任务 ID 由 Scan ID、插件身份和 config hash 确定性生成。`plan_hash` 来自规范化任务
序列，不包含创建时间。相同 Scan ID、选择、配置和 Registry 会产生相同 Task ID、
顺序、依赖和 plan hash。

Planner 不理解任何漏洞类型，也不包含 `injection`、`authz` 或 `business-flow` 等名称。
新增普通内置插件只需要 Manifest、runtime 和测试。

## Legacy Adapter

`argus/plugins/legacy_adapter.py` 是自由字符串兼容语义的唯一边界：

- enrichment Analyzer 消费图，生产 `legacy.enrichment.<name>.v1`；
- vuln Analyzer 消费图和 enrichment aggregate，生产
  `legacy.findings.<name>.v1`；
- enrichment/findings aggregate 的 optional inputs 根据已发现 Analyzer 动态生成；
- `Analyzer.requires == ["enriched-graph"]` 在适配器内映射，Planner 不处理该字符串；
- 适配器不认识的 legacy requirement 会明确失败，不会静默丢弃依赖；
- Markdown reporter 由内置 Manifest 声明。

M3 完成时适配器 runtime 不执行；M4 通过独立 `legacy_runtime.py` 执行这些计划任务。

## Control Store 与 Artifact

`0003_task_plans` migration 新增：

```text
task_plans(id, scan_id, plan_hash, artifact_id, created_at)
```

每个 Scan 最多一个计划。完整规范化计划发布为内容寻址
`task.plan.v1` Artifact，Capability 同为 `task.plan.v1`，并通过 `scans.plan_id`、
`tasks.plan_id`、Artifact 和 `plan.compiled` Event 建立追踪关系。

计划任务仅登记为 `PENDING`。Planner 不包含运行、重试、并发、Review Gate 或恢复逻辑。

## 安全和兼容边界

- 不替换、不删除或重构固定六节点 Pipeline。
- Manifest 发现不执行第三方 Python。
- M3 不增加网络验证、PoC、凭据、浏览器或 Shell 能力。
- Codegraph 仍只在 M2 的 SourceSnapshot 内构建。
- 旧 Workspace、checkpoint、Finding 和报告格式不变。

## M3 完成时的限制（历史）

- 计划持久化由多个短数据库事务组成，尚不是 Executor 级原子状态机。
- 计划任务不会运行，状态恢复和失败重试仍属于 M4。
- V1 兼容任务与 V2 计划任务并存；调用方应使用 `plan_id` 区分。
- 外部插件只有受控登记能力，没有安全执行能力。
- TaskPlan 表保存索引元数据；完整不可变表示以 Artifact 为准。
