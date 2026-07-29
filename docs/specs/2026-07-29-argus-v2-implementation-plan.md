# Argus V2 落地实施计划

> 归档状态：M0–M10 已于 2026-07-29 实现并通过本地质量门禁。本文件保留原始迁移
> 顺序和验收依据，不是现役待办或 Agent 指令。当前用法以 `README.md` 为准，现役
> 架构与后续边界见 `docs/architecture/argus-v2-overview.md` 和
> `docs/implementation/m10-hardening-retirement.md`。固定 Legacy Pipeline 的物理
> 删除仍需按计划作为独立、人工审查的后续变更。

> 文档用途：直接交给本地 Codex，按里程碑逐步改造 `zsmj-xu/argus`。
>
> 文档版本：1.0
> 日期：2026-07-29

---

## 0. Codex 执行规则

### 0.1 必须遵守

1. **一次只执行一个里程碑。** 不要在同一次任务里跨越多个里程碑。
2. 每个里程碑开始前，先读取相关现有实现、测试和本文档；先输出改动清单，再开始修改。
3. 保留现有行为作为兼容路径，直到 V2 路径通过对等测试。不要先删除旧 Pipeline、旧 Contract 或旧 Web API。
4. 新代码优先放在新命名空间中，不要继续扩大 `argus/contracts.py`、`argus/orchestration/pipeline.py` 和共享 `enriched` 字典。
5. 每个里程碑结束时必须执行：

   ```bash
   python -m pytest
   python -m ruff check .
   python -m mypy argus
   ```

6. 不允许通过降低类型检查、删除测试、扩大 `# type: ignore`、吞掉异常或静默回退来“修复”问题。
7. 配置、插件依赖、Artifact Schema 和执行权限必须 **fail closed**：不合法就报错，不得静默跳过。
8. 不要进行无关的大规模格式化、重命名或前端重写。
9. 每个里程碑都要补充：
   - 单元测试；
   - 至少一个集成测试；
   - 文档；
   - 迁移或兼容说明。
10. 每次完成后输出：修改文件、设计取舍、测试结果、已知限制、下一里程碑前置条件。

### 0.2 当前阶段明确禁止

在进入 M8/M9 前，不得加入以下能力：

- 自动执行 PoC；
- Agent 直接访问目标网络；
- Agent 直接使用 Shell、浏览器、真实凭据；
- 自动创建、删除或修改目标数据；
- OAST、SSRF 回连、DoS、持久化、权限变更；
- Temporal、Neo4j、Kubernetes、消息队列；
- 外部第三方插件在 Argus 主进程中直接执行。

---

## 1. 改造目标

Argus V2 的目标不是把现有固定 Workflow 换成另一套固定 Workflow，而是建立以下平台能力：

```text
Source Snapshot
      ↓
Graph / Extractor Plugins
      ↓
Typed Artifacts + Security IR
      ↓
Capability-based Plan Compiler
      ↓
Dynamic Task DAG
      ↓
Candidate Generator + Expert Evaluator
      ↓
Canonical Static Finding
      ↓
Optional Verification Requirement
      ↓
Verification Plan + Policy + Human Approval
      ↓
Restricted Tool Broker + Evidence
```

最终系统应满足：

1. 源码、图、语义结果、Finding 和验证证据都有明确版本、来源和哈希。
2. 新增插件不需要修改核心编排代码。
3. 插件通过 `consumes/produces` 能力声明形成动态 DAG。
4. 报告只是 Finding Store 的视图，不再作为 Agent 之间的协议。
5. 静态扫描可以独立完成；验证默认关闭。
6. 验证必须先形成结构化计划，并由策略与人工审批控制。
7. Web 可以查看 Project、Scan、Task DAG、Artifact、Security Graph Slice、Finding、Review、Approval 和事件。

---

## 2. 当前代码基线与迁移原则

### 2.1 当前基线

当前实现的核心特征：

- `argus/orchestration/pipeline.py` 定义固定顺序：
  `build_graph → enrichment → review-enrichment → vuln → review-findings → report`。
- `Analyzer.requires` 已经存在于协议中，但当前 Pipeline 未据此进行依赖解析和拓扑排序。
- enrichment 结果通过一个共享 `dict[str, Any]` 浅合并，存在键冲突和来源丢失问题。
- Codegraph 默认写入被扫描仓库的 `.codegraph/codegraph.db`，并可能仅根据文件存在性复用。
- 当前 Finding 已经是结构化对象，报告是确定性渲染；这一方向应保留。
- `business-flow` 已形成 Endpoint、Handler、Resource、Authorization Check、State Transition 等早期安全语义，应迁移到正式 Security IR。
- Web Job 状态主要由内存中的子进程管理器维护，服务重启后无法可靠恢复运行状态。
- 当前人工检查点审核 enrichment/Finding 文件，但不是 PoC 执行审批。

### 2.2 迁移原则

1. **Strangler Pattern**：V2 先与 V1 并存，再切换默认路径，最后删除旧实现。
2. **先领域模型，后运行时**：先有 `SourceSnapshot / Artifact / PluginSpec / TaskPlan`，再替换 Pipeline。
3. **先静态，后验证**：静态平台稳定前不接入 PoC。
4. **先本地执行，后分布式**：第一版使用 SQLite + 本地 Worker。
5. **先图切片，后“大图平台”**：不引入 Neo4j，不构建万能 CPG。
6. **LLM 只做语义判断**：确定性工具负责候选发现、锚定、Schema 校验和证据管理。
7. **所有状态持久化**：进程内对象不是事实来源。

---

## 3. 目标模块边界

建议最终目录：

```text
argus/
├── domain/
│   ├── enums.py
│   ├── ids.py
│   ├── models.py
│   ├── hashing.py
│   └── errors.py
├── control/
│   ├── db.py
│   ├── orm.py
│   ├── repositories.py
│   ├── services.py
│   ├── events.py
│   └── migrations/
├── snapshots/
│   ├── service.py
│   ├── hashing.py
│   ├── materialize.py
│   └── ignore.py
├── artifacts/
│   ├── store.py
│   ├── codecs.py
│   ├── schemas.py
│   └── views.py
├── plugins/
│   ├── contracts.py
│   ├── manifest.py
│   ├── registry.py
│   ├── loader.py
│   ├── legacy_adapter.py
│   └── builtin/
├── planning/
│   ├── capabilities.py
│   ├── planner.py
│   ├── validation.py
│   └── serialization.py
├── execution/
│   ├── contracts.py
│   ├── local.py
│   ├── runner.py
│   ├── state_machine.py
│   └── review_gate.py
├── security_ir/
│   ├── models.py
│   ├── store.py
│   ├── query.py
│   ├── slices.py
│   └── business_flow_adapter.py
├── detection/
│   ├── contracts.py
│   ├── candidates.py
│   ├── experts.py
│   ├── normalization.py
│   ├── deduplication.py
│   └── builtin/
├── verification/
│   ├── models.py
│   ├── requirements.py
│   ├── planning.py
│   ├── policy.py
│   ├── approvals.py
│   ├── broker.py
│   ├── evidence.py
│   └── executors/
├── reporting/
├── web.py
├── web_api/
│   ├── projects.py
│   ├── scans.py
│   ├── tasks.py
│   ├── artifacts.py
│   ├── graph.py
│   ├── findings.py
│   └── reviews.py
└── legacy/
    └── ... optional adapters only
```

说明：现有目录不需要一次性搬迁。上面是目标边界，按里程碑逐渐形成。

---

## 4. 核心领域对象

所有 V2 领域对象使用 Pydantic v2；数据库对象使用 SQLAlchemy 2，二者通过 Repository 映射。不要把 SQLAlchemy ORM 对象直接传给插件。

### 4.1 Project

```text
Project
- id: UUID
- name: str
- repository_path: str
- default_config: dict
- created_at: datetime UTC
- updated_at: datetime UTC
- archived_at: datetime UTC | null
```

### 4.2 Scan

```text
Scan
- id: UUID
- project_id: UUID
- snapshot_id: UUID
- plan_id: UUID | null
- status: ScanStatus
- config: dict
- config_hash: sha256
- engine: legacy | v2
- created_at / started_at / finished_at
- error_code / error_message
```

建议状态：

```text
CREATED
SNAPSHOTTING
PLANNING
READY
RUNNING
WAITING_REVIEW
STATIC_COMPLETED
WAITING_VERIFICATION_INPUT
WAITING_APPROVAL
VERIFYING
COMPLETED
FAILED
CANCELED
```

### 4.3 SourceSnapshot

```text
SourceSnapshot
- id: UUID
- project_id: UUID
- repository_path: str
- vcs_type: git | directory
- commit_sha: str | null
- tree_hash: sha256
- dirty: bool
- materialized_path: str
- manifest_artifact_id: UUID
- created_at: datetime UTC
```

### 4.4 Artifact

```text
Artifact
- id: UUID
- scan_id: UUID
- snapshot_id: UUID
- task_id: UUID
- artifact_type: namespaced str
- schema_version: str
- capabilities: list[str]
- producer_plugin_id: str
- producer_plugin_version: str
- media_type: str
- content_hash: sha256
- size_bytes: int
- storage_uri: str
- metadata: dict
- created_at: datetime UTC
```

Artifact 文件采用内容寻址：

```text
runs/_data/artifacts/sha256/ab/abcdef.../payload
```

数据库只保存元数据和 URI，不把大型图数据库、源码快照或完整 LLM 输出塞进 JSON 字段。

### 4.5 PluginSpec

```text
PluginSpec
- id: str                 # 例如 detector.authorization.idor
- version: semantic version
- kind: PluginKind
- entrypoint: module:object
- consumes: list[CapabilityRequirement]
- optional_consumes: list[CapabilityRequirement]
- produces: list[CapabilityDeclaration]
- permissions: PermissionSpec
- runtime: RuntimeSpec
- config_schema: dict
- output_schemas: dict
```

第一阶段 PluginKind：

```text
GRAPH_PROVIDER
ENRICHER
SEMANTIC_ADAPTER
DETECTOR
EXPERT
AGGREGATOR
REPORTER
LEGACY_ANALYZER
```

M8 后再加入：

```text
VERIFIER
ENVIRONMENT_ADAPTER
IDENTITY_ADAPTER
```

### 4.6 TaskPlan / Task

```text
TaskPlan
- id: UUID
- scan_id: UUID
- tasks: list[PlannedTask]
- plan_hash: sha256
- created_at

PlannedTask
- id: UUID
- plugin_id / plugin_version
- kind
- depends_on: list[task_id]
- required_capabilities
- expected_capabilities
- config_hash
- cache_key
```

Task 状态：

```text
PENDING
READY
RUNNING
WAITING_REVIEW
SUCCEEDED
FAILED
SKIPPED
CANCELED
```

### 4.7 StaticFindingV2

```text
StaticFindingV2
- id: UUID
- fingerprint: sha256
- scan_id
- snapshot_id
- rule_id
- rule_version
- title
- weakness_id: CWE / internal taxonomy
- vuln_class
- severity
- static_confidence
- status: CANDIDATE | STATIC_SUPPORTED | REJECTED_STATIC | UNVERIFIED
- locations: list[CodeLocation]
- source_node_ids: list[str]
- sink_node_ids: list[str]
- graph_slice_artifact_id: UUID | null
- evidence_artifact_ids: list[UUID]
- preconditions: list[str]
- rationale
- remediation
- created_at / updated_at
```

Finding 指纹不得依赖 LLM 标题或自然语言描述。建议：

```text
sha256(
  rule_id
  + rule_version
  + canonical_primary_location
  + canonical_source_nodes
  + canonical_sink_nodes
  + normalized_graph_path
  + affected_asset
)
```

### 4.8 Event

```text
Event
- id: UUID
- project_id / scan_id / task_id / finding_id 可空
- event_type: namespaced str
- level
- payload: dict
- created_at UTC
```

Canonical Event 存数据库；现有 `progress.jsonl` 作为兼容投影继续生成。

---

# 5. 里程碑计划

---

## M0：冻结基线与建立 V2 ADR

### 目标

在不改变运行行为的前提下，记录基线和迁移边界。

### 新增文件

```text
docs/architecture/ADR-0001-argus-v2-evolution.md
docs/architecture/argus-v2-overview.md
docs/implementation/baseline.md
docs/implementation/codex-rules.md
```

### 任务

1. 运行完整测试、ruff、mypy，将结果写入 `baseline.md`。
2. 记录当前 CLI 命令、默认配置、Workspace 产物布局和 Web API。
3. ADR 明确：
   - V1 Contract 暂时冻结；
   - V2 放入独立命名空间；
   - 本地 SQLite 是首个 Control Store；
   - 不引入 Temporal/Neo4j；
   - 验证默认关闭；
   - V1/V2 并行迁移。
4. 增加架构测试，确保 V2 尚未反向依赖 `argus/orchestration/pipeline.py`。

### 验收标准

- 无运行行为变化。
- 所有现有测试通过。
- ADR 清楚列出迁移阶段和非目标。

### Codex 提示词

```text
执行 ARGUS_V2_IMPLEMENTATION_PLAN.md 的 M0，且只执行 M0。
不要修改现有运行行为。先读取 contracts.py、orchestration/pipeline.py、orchestration/state.py、web.py、现有测试与文档。
建立 ADR、基线文档和必要的架构边界测试。完成后运行 pytest、ruff、mypy，并报告结果。
```

---

## M1：V2 领域模型与 Control Store

### 目标

建立 Project、Scan、Task、Artifact、Finding、Event 的持久化骨架，但暂不接管现有 Pipeline。

### 依赖调整

在 `pyproject.toml` 增加：

```text
pydantic>=2.8,<3
sqlalchemy>=2.0,<3
alembic>=1.13,<2
packaging>=24,<26
```

版本范围可根据当前环境调整，但必须固定主版本上限。

### 新增文件

```text
argus/domain/enums.py
argus/domain/models.py
argus/domain/hashing.py
argus/domain/errors.py
argus/control/db.py
argus/control/orm.py
argus/control/repositories.py
argus/control/services.py
argus/control/events.py
argus/control/migrations/
tests/domain/
tests/control/
```

### 数据库

默认：

```text
<runs_root>/control.db
```

必须具备 migration 表，不允许在应用启动时通过 `create_all()` 隐式改变生产 Schema。测试可以创建临时数据库并执行 migration。

### 实现要求

1. 定义 4.1～4.8 中当前阶段需要的模型。
2. Repository 接口至少包括：
   - create/get/list Project；
   - create/get/update Scan；
   - create/list/update Task；
   - create/get/list Artifact metadata；
   - upsert/list Finding；
   - append/list Event。
3. 所有时间为 timezone-aware UTC。
4. 状态转移通过 Service 层完成，不允许 Web/CLI 直接改 ORM 字段。
5. 为 Scan 和 Task 建立合法状态转移检查。
6. JSON 字段进入数据库前必须经过 Pydantic 校验。
7. 定义统一错误：`NotFoundError`、`ConflictError`、`InvalidTransitionError`、`SchemaValidationError`。

### 测试

- migration 从空库创建成功；
- migration 可重复执行；
- Project/Scan/Task CRUD；
- 非法状态转移被拒绝；
- Event 追加顺序稳定；
- SQLite 重启后数据仍存在；
- 并发更新使用乐观锁或明确事务，不能静默覆盖。

### 验收标准

- 现有 Pipeline 完全不依赖新 Control Store。
- 新模型不使用宽泛 `dict[str, Any]` 表示核心对象。
- `pytest/ruff/mypy` 全通过。

### Codex 提示词

```text
执行计划 M1，且只执行 M1。保留现有 pipeline、contracts.py 和 web 行为不变。
使用 Pydantic v2 定义领域 DTO，使用 SQLAlchemy 2 + Alembic 持久化，建立 Repository 与 Service 边界。
不要把 ORM 对象暴露给插件，不要使用 create_all 代替 migration。补齐状态转移和数据库重启测试。
```

---

## M2：SourceSnapshot 与 Artifact Store

### 目标

确保每次扫描分析的是明确、不可混淆的源码快照；所有中间产物独立存储并带来源与哈希。

### 新增文件

```text
argus/snapshots/service.py
argus/snapshots/hashing.py
argus/snapshots/materialize.py
argus/snapshots/ignore.py
argus/artifacts/store.py
argus/artifacts/codecs.py
argus/artifacts/schemas.py
argus/artifacts/views.py
tests/snapshots/
tests/artifacts/
```

### Snapshot 行为

1. Git 仓库记录：
   - HEAD commit；
   - clean/dirty；
   - 所有纳入扫描文件的确定性 tree hash。
2. 非 Git 目录也计算确定性 tree hash。
3. 默认忽略：
   - `.git/`；
   - `.codegraph/`；
   - Argus `runs_root`；
   - 常见构建缓存；
   - 可由配置补充 ignore。
4. Snapshot 物化到：

   ```text
   runs/_data/snapshots/<snapshot_id>/source/
   ```

5. 使用完整复制保证后续源码变化不会影响扫描；后续可优化为平台相关的 CoW，但本里程碑不做。
6. 生成 `snapshot-manifest.json`，列出相对路径、类型、大小和内容哈希。
7. 扫描和图构建只能读取 snapshot 目录，不能再读取原始工作树。

### Artifact Store 行为

1. 支持 JSON、JSONL、文本、SQLite、二进制文件。
2. 内容哈希后原子写入内容寻址目录。
3. 同内容去重，但每次产出仍创建独立 Artifact metadata。
4. Artifact 必须绑定：scan、snapshot、task、producer、schema、capability。
5. JSON 使用规范化序列化：UTF-8、键排序、稳定分隔符。
6. 读取时校验文件存在、大小和 hash；不一致则抛 `ArtifactCorruptionError`。
7. 禁止插件直接拼接 Artifact 文件路径；通过 Store API 获取只读句柄。

### 与现有代码的最小集成

1. 新增 V1 兼容入口：启动现有扫描前创建 Project/Scan/SourceSnapshot 记录。
2. 将现有 Pipeline 的 `repo_path` 指向物化后的 snapshot source。
3. Codegraph 因而写入 snapshot 的 `.codegraph`，不再污染用户原仓库。
4. 图构建完成后，将 DB 注册为 `code.graph.codegraph.v1` Artifact。
5. enriched、findings、report 保留原文件，同时注册为 legacy Artifact。
6. 图复用必须同时匹配：
   - snapshot tree hash；
   - graph provider ID；
   - provider version；
   - provider config hash。

### 测试

- 相同源码产生相同 tree hash；
- 修改文件、增加文件、删除文件都会改变 tree hash；
- 扫描期间修改原仓库不影响 snapshot；
- 原仓库不会出现新的 `.codegraph`；
- Artifact 原子写入与 hash 校验；
- 损坏 Artifact 会被检测；
- 图缓存不会跨 snapshot 错误复用。

### 验收标准

- 所有现有扫描仍能运行。
- 原始仓库在扫描前后文件树不被 Argus 修改。
- 每个现有产物可在 Control Store 中追溯到 Scan 和 Snapshot。

### Codex 提示词

```text
执行计划 M2，且只执行 M2。实现不可混淆的 SourceSnapshot 与内容寻址 Artifact Store。
将现有扫描改为读取 snapshot 物化目录，禁止 codegraph 写入用户原仓库。
保持旧产物文件和 CLI 可用，并把旧产物注册为 legacy Artifact。补齐 hash、缓存失效、原子写与污染原仓库测试。
```

---

## M3：PluginSpec、Capability 与动态 TaskPlan 编译器

### 目标

把“分析器目录自动发现”升级为“Manifest 驱动、能力匹配、可验证的动态 DAG”。本阶段只编译计划，不执行计划。

### 新增文件

```text
argus/plugins/contracts.py
argus/plugins/manifest.py
argus/plugins/registry.py
argus/plugins/loader.py
argus/plugins/legacy_adapter.py
argus/planning/capabilities.py
argus/planning/planner.py
argus/planning/validation.py
argus/planning/serialization.py
tests/plugins/
tests/planning/
```

### Manifest 格式

内置插件使用 `plugin.yaml`：

```yaml
apiVersion: argus.security/v2
kind: detector

metadata:
  id: detector.authorization.idor
  version: 1.0.0

entrypoint: argus.detection.builtin.idor.plugin:PLUGIN

consumes:
  - capability: security.routes.v1
    required: true
  - capability: security.authorization.v1
    required: true
  - capability: security.resource-ownership.v1
    required: true

produces:
  - capability: finding.static.v2
    artifactType: finding.static.v2
    schemaVersion: "2.0"

permissions:
  source: read
  network: none
  subprocess: none
  secrets: none

runtime:
  isolation: in_process
  timeoutSeconds: 300
```

### Registry 要求

1. 发现阶段只读取并校验 Manifest，不导入插件 Python 模块。
2. 检查：
   - ID 唯一；
   - semantic version 合法；
   - kind 合法；
   - capability 名称规范；
   - entrypoint 格式合法；
   - permissions 不能超出当前运行模式。
3. 只有任务真正执行时才导入 entrypoint。
4. 第一阶段只允许内置插件；外部目录必须显式启用，并在 M10 前不得在主进程直接执行。

### Planner 算法

输入：

```text
selected plugin IDs
initial capabilities
project/scan config
available plugin registry
```

输出：确定性的 `TaskPlan`。

步骤：

1. 校验所有选中插件存在，未知插件直接失败，禁止静默跳过。
2. 对每个 required capability 查找生产者。
3. 没有生产者：抛 `MissingCapabilityError`。
4. 多个生产者且未配置 provider：抛 `AmbiguousCapabilityError`。
5. 建立任务依赖边。
6. Kahn 拓扑排序，检测循环并输出可读的循环路径。
7. 同层任务按 plugin ID + version 稳定排序。
8. 对规范化计划计算 `plan_hash`。
9. 将 TaskPlan 写入 Control Store 和 Artifact Store。

### Legacy 适配

为每个现有 Analyzer 生成内置 Legacy PluginSpec，但不要修改原 Analyzer：

- enrichment Analyzer：消费 `code.graph.codegraph.v1`，生产 `legacy.enrichment.<name>.v1`；
- vuln Analyzer：消费图和 `legacy.enrichment.aggregate.v1`，生产 `legacy.findings.<name>.v1`；
- 增加一个内置 aggregate 插件，将选中的 enrichment Artifact 生成旧式 merged view；
- 增加 reporter 插件，消费规范化 Finding 集合。

`Analyzer.requires` 仅作为 Legacy Adapter 的输入，不再由核心 Planner 直接理解其自由字符串语义。

### 测试

- 未知插件失败；
- 缺少 capability 失败；
- 多生产者歧义失败；
- 循环依赖失败并显示路径；
- 同一输入生成相同 plan hash；
- 添加一个 fixture 插件不需要修改 Planner；
- Manifest 发现阶段不会导入恶意/抛异常的 entrypoint；
- Legacy Analyzer 能被映射到 TaskPlan。

### 验收标准

- Planner 不包含 injection/authz/business-flow 等具体漏洞名称。
- 新增内置插件只需 Manifest、runtime 和测试，不需要修改 Planner。
- 暂不替换现有 Pipeline。

### Codex 提示词

```text
执行计划 M3，且只执行 M3。实现 Manifest 驱动的插件注册表、Capability 模型和确定性 TaskPlan 编译器。
发现插件时不得导入 entrypoint。未知插件、缺失能力、能力歧义和循环依赖必须 fail closed。
为现有 Analyzer 建立 Legacy PluginSpec 适配，但不要切换执行路径。
```

---

## M4：DB-backed LocalPlanExecutor 与 V1 对等迁移

### 目标

执行 M3 生成的动态 DAG，支持持久化状态、失败恢复和静态 Review Gate；先与 V1 并行，再切换默认引擎。

### 新增文件

```text
argus/execution/contracts.py
argus/execution/local.py
argus/execution/runner.py
argus/execution/state_machine.py
argus/execution/review_gate.py
argus/plugins/legacy_runtime.py
tests/execution/
tests/integration/test_v1_v2_parity.py
```

### ExecutionBackend 协议

```text
prepare(plan)
run_ready_tasks(scan_id)
resume(scan_id)
cancel(scan_id)
get_status(scan_id)
```

第一版只实现 `LocalPlanExecutor`。

### 执行语义

1. Task 的事实状态来自 Control Store，不来自进程内字典。
2. 仅当所有依赖 SUCCEEDED 时，任务才能 READY。
3. 执行前创建 TaskAttempt，记录：
   - plugin/version；
   - input artifact IDs/hashes；
   - config hash；
   - started_at；
   - worker PID。
4. 插件输出先写临时 Artifact，Schema 校验成功后提交并把 Task 标记 SUCCEEDED。
5. 进程崩溃后，重启时将无心跳的 RUNNING 任务标为 INTERRUPTED/FAILED_RETRYABLE，再按策略恢复。
6. 第一版串行执行；TaskPlan 保留并行层级信息，但不要现在实现线程池。
7. 失败策略默认 fail scan；可选插件可以配置 `continue_on_failure`，但必须在 plan 中显式体现。
8. 重跑时已成功任务仅在输入 hashes、plugin version、config hash 完全相同时复用。

### Review Gate

Review 是 Control Plane 对象，不是一个让 Agent自由执行的节点。

```text
ReviewRequest
- id
- scan_id
- subject_type: artifact | finding_set
- subject_ids
- subject_hash
- status: OPEN | APPROVED | REJECTED | SUPERSEDED
- reviewer
- reason
- created_at / decided_at
```

- 旧 `review-enrichment` 和 `review-findings` 映射为两个可配置 Review Gate。
- 审批必须绑定 subject hash；Artifact/Finding 集合变化后原审批自动失效。
- CLI `continue` 先创建明确的 ReviewDecision，再调用 executor resume。

### CLI 迁移

增加：

```text
argus scan ... --engine legacy|v2
argus scan-status --scan-id ...
argus scan-resume --scan-id ...
argus scan-cancel --scan-id ...
argus review approve --review-id ... --reason ...
argus review reject --review-id ... --reason ...
```

迁移顺序：

1. 先默认 `legacy`；
2. 对等测试通过后默认 `v2`；
3. 保留 `--engine legacy` 至少一个版本周期；
4. 暂不删除 LangGraph 旧路径。

### 对等测试

在固定 fixture、固定 mock LLM 响应下比较：

- Analyzer 运行顺序；
- enrichment 内容；
- Finding 内容；
- Markdown report；
- Review pause/resume；
- 失败传播。

允许 metadata、时间和 V2 ID 不同，但业务产物必须等价。

### 验收标准

- V2 动态执行不依赖固定六节点 Pipeline。
- 服务/进程重启后可从 Control Store 恢复。
- V1/V2 对等测试通过后，CLI 默认改为 V2。
- 旧路径仍可显式使用。

### Codex 提示词

```text
执行计划 M4，且只执行 M4。实现 DB-backed LocalPlanExecutor、TaskAttempt、持久化恢复和 ReviewRequest。
先保留 legacy 默认路径，建立固定 fixture 的 V1/V2 对等测试；对等通过后再切换默认引擎。
不要删除 LangGraph 旧实现，不要实现并发或分布式 Worker。
```

---

## M5：Security IR 与 Graph Slice 查询层

### 目标

将 Codegraph 原始结构图与安全语义分层；把现有 business-flow 结果迁移成正式的 Security IR。

### 新增文件

```text
argus/security_ir/models.py
argus/security_ir/store.py
argus/security_ir/query.py
argus/security_ir/slices.py
argus/security_ir/provenance.py
argus/security_ir/business_flow_adapter.py
tests/security_ir/
```

### Security IR 模型

节点和边使用 namespaced kind，允许扩展但必须通过 Schema 校验。

```text
SecurityNode
- id
- kind: code.function | http.route | auth.guard | auth.policy |
        identity.role | tenant | resource.entity | data.source |
        data.sink | sanitizer | business.operation | state.transition
- name
- code_locations
- attributes
- provenance
- confidence: CONFIRMED | INFERRED | POSSIBLE

SecurityEdge
- id
- kind: handled_by | calls | guarded_by | authorizes |
        reads | writes | owns | belongs_to | flows_to |
        sanitized_by | transitions_to | triggers
- source_id
- target_id
- attributes
- provenance
- confidence
```

Provenance：

```text
- snapshot_id
- producer_plugin_id/version
- source_artifact_ids
- original_codegraph_node_ids
- extraction_method: deterministic | llm_inferred | imported
- evidence_refs
```

### 存储

第一版用每个 Security Graph Artifact 独立 SQLite 文件：

```text
nodes(id, kind, name, attributes_json, confidence, ...)
edges(id, kind, source_id, target_id, attributes_json, confidence, ...)
node_locations(...)
provenance(...)
```

必要索引：kind、source、target、file/line、原始 codegraph node ID。

不要将 Security Graph 全部放进 Control Store 的 JSON 字段。

### Query API

```text
get_node(id)
find_nodes(kind, name, location)
neighbors(id, edge_kinds, direction, max_nodes)
find_paths(source_ids, target_ids, edge_kinds, max_depth, max_paths)
subgraph(seed_ids, radius, allowed_kinds, max_nodes)
slice_for_finding(finding_id)
```

所有图查询必须有节点、深度和路径数量上限。

### business-flow 迁移

新增 `BusinessFlowToSecurityIRPlugin`：

- 消费 `legacy.enrichment.business-flow.v1` 和 code graph；
- 生产：
  - `security.routes.v1`；
  - `security.business-flow.v1`；
  - `security.authorization.v1`；
  - `security.resources.v1`；
  - 一个 `security.graph.v1` Artifact。
- 复用现有 normalization/锚定逻辑，不在本阶段重写 Prompt。
- 无法确认的 LLM 关系标记 `INFERRED`，不得伪装为确定性事实。

### Web 预留 API

本阶段只实现 service/API 数据层，不要求完整前端：

```text
GET /api/scans/{scan_id}/graph/nodes
GET /api/scans/{scan_id}/graph/nodes/{node_id}
GET /api/scans/{scan_id}/graph/slice
```

### 验收标准

- Codegraph DB 与 Security Graph 是两个不同 Artifact。
- business-flow 可以稳定转换为 Security IR。
- 每个节点/边都可追溯到 producer 和 snapshot。
- 图查询有硬上限，不能因大图拖垮 Web。

### Codex 提示词

```text
执行计划 M5，且只执行 M5。建立 Security IR、独立 SQLite 图 Artifact、查询服务和 Graph Slice。
将现有 business-flow enrichment 通过适配插件映射成安全语义；保留原 Analyzer 与 Prompt，不在本阶段重写。
所有推断关系必须带 provenance 和 confidence，图查询必须有资源上限。
```

---

## M6：Candidate Generator / Expert Evaluator 分层与首批规则迁移

### 目标

结束“每个漏洞专家遍历全部函数”的主要模式。确定性组件先产生候选和图切片，LLM 只判断有限上下文。

### 新增文件

```text
argus/detection/contracts.py
argus/detection/candidates.py
argus/detection/experts.py
argus/detection/normalization.py
argus/detection/deduplication.py
argus/detection/fingerprints.py
argus/detection/builtin/injection/
argus/detection/builtin/authorization/
tests/detection/
```

### 接口

```text
CandidateProvider.generate(ctx) -> list[Candidate]
GraphSliceBuilder.build(candidate) -> GraphSlice Artifact
ExpertEvaluator.evaluate(candidate, graph_slice, source_context) -> ExpertAssessment
FindingNormalizer.normalize(...) -> StaticFindingV2
```

Candidate：

```text
- id
- rule_id / rule_version
- candidate_type
- primary_node_ids
- source_node_ids
- sink_node_ids
- route_ids
- identity_context_ids
- reason_codes
- static_score
- provenance
```

ExpertAssessment 不得直接产生最终 Finding ID，只提供：

```text
- supported: bool
- confidence
- rationale
- preconditions
- evidence claims
- remediation hints
```

### 第一条规则：Injection

第一版不追求完整跨语言数据流，使用可解释的候选策略：

1. 从 Codegraph/Security IR 识别 SQL、命令、模板等 sink 候选。
2. 获取有限 caller/callee 路径、Route/Input 语义和源码片段。
3. 识别已知 parameterized API/sanitizer；确定性排除明显安全路径。
4. 每条 Candidate 生成有限 Graph Slice。
5. LLM 判断拼接语义、可达性和 sanitizer 是否有效。

### 第二条规则：Authorization / IDOR

候选来源：

1. Route/Business Operation 访问 Resource；
2. Resource ID 来自外部输入或路径参数；
3. Security IR 中没有明确 ownership/tenant/policy check，或 check 与 resource 不匹配；
4. 构造 actor、resource、operation、authorization check 的图切片；
5. LLM 判断是否存在合理框架隐式保护或业务前置条件。

### Finding 规范化与去重

1. 使用 V2 fingerprint，不含标题。
2. 相同 fingerprint 的多插件结果合并 evidence，不重复显示。
3. 不同规则但同根因可通过 `root_cause_key` 关联，不强制合并。
4. 保存每个候选和 Assessment Artifact，便于复现。
5. 状态为 `STATIC_SUPPORTED/UNVERIFIED`，不能标记动态已确认。

### 比较模式

增加配置：

```yaml
analysisMode: legacy | v2 | compare
```

compare 模式同时运行旧 Shannon Analyzer 与新 detector，将差异写入 Comparison Artifact，不影响主报告。

### 测试

- Candidate 生成确定性；
- 明显无 sink 的函数不进入 LLM；
- Graph Slice 大小受限；
- LLM 无效输出被拒绝；
- Finding fingerprint 不受标题措辞变化影响；
- compare 模式产出差异；
- injection/authz fixture 的召回与误报有基线记录。

### 验收标准

- 新 injection/authz 不遍历所有函数并逐批直接交给 LLM。
- LLM 输入包含有限、可审计、可重建的 Graph Slice。
- 报告明确区分 Static Confidence 和 Verification Status。

### Codex 提示词

```text
执行计划 M6，且只执行 M6。实现 CandidateProvider → GraphSlice → ExpertEvaluator → FindingNormalizer 分层。
先迁移 injection 和 authorization/IDOR，保留旧 Analyzer 并增加 compare 模式。
候选生成必须确定性，LLM 不得自行遍历全仓或直接决定 Finding ID；所有 Finding 保持 UNVERIFIED。
```

---

## M7：Web Control Plane

### 目标

把当前 Workspace 查看器升级为持久化的 Project/Scan/Task/Artifact/Finding 控制台，同时保留 local-only 安全边界。

### 后端改造

继续使用现有 HTTP Server，暂不迁移 FastAPI，避免同时重写运行时和 Web 框架。

新增 service/API 模块，`web.py` 只负责路由、输入边界和响应。

### API

```text
GET/POST   /api/projects
GET/PATCH  /api/projects/{project_id}
GET/POST   /api/projects/{project_id}/scans
GET        /api/scans/{scan_id}
POST       /api/scans/{scan_id}/resume
POST       /api/scans/{scan_id}/cancel
GET        /api/scans/{scan_id}/tasks
GET        /api/scans/{scan_id}/plan
GET        /api/scans/{scan_id}/events
GET        /api/scans/{scan_id}/artifacts
GET        /api/artifacts/{artifact_id}
GET        /api/scans/{scan_id}/findings
GET/PATCH  /api/findings/{finding_id}
GET        /api/scans/{scan_id}/graph/...
GET/POST   /api/reviews
POST       /api/reviews/{review_id}/approve
POST       /api/reviews/{review_id}/reject
```

### UI 页面

1. **Projects**：仓库、默认配置、历史扫描。
2. **Scan Overview**：状态、snapshot、config hash、统计。
3. **Task DAG**：任务、依赖、状态、耗时、错误、输入/输出 Artifact。
4. **Artifacts**：类型、producer、schema、hash、下载/预览。
5. **Graph Explorer**：只展示受限 Graph Slice，不默认渲染全图。
6. **Findings**：静态置信度、验证状态、图路径、源码位置、证据。
7. **Reviews**：subject hash、审核人、理由、状态历史。
8. **Events/Logs**：结构化事件与现有日志联动。

### Job 持久化

1. `JobManager._jobs` 不再是事实来源。
2. 子进程只是 Local Executor 的承载体；Scan/Task 状态写数据库。
3. Web 重启后：
   - 读取 RUNNING Task；
   - 检查 worker PID/heartbeat；
   - 标记失联任务并允许恢复。
4. 第一版继续轮询 API，不必立即实现 SSE/WebSocket。

### 安全

- 继续只允许 loopback bind；
- 所有 ID/path 参数严格校验；
- Artifact 下载不能路径穿越；
- API 不返回 API Key、凭据或完整敏感 Prompt；
- 所有变更动作写 Event。

### 验收标准

- Web 重启后 Project/Scan/Task 状态仍完整。
- 可以从 Finding 跳转到 Graph Slice 和源码位置。
- 用户能清楚看到“人工静态审核”与“动态验证”是不同状态。
- Web 不依赖读取目录名猜测 Scan 状态。

### Codex 提示词

```text
执行计划 M7，且只执行 M7。基于现有 local-only HTTP Server 建立持久化 Web Control Plane。
不要迁移 FastAPI，不要重写整套前端。把 Project/Scan/Task/Artifact/Finding/Review/Event 接入现有 UI，并加入受限 Graph Slice 页面。
进程内 JobManager 不得再作为状态事实来源。
```

---

## M8：验证领域模型、需求解析和审批中心（不执行网络请求）

### 目标

先建立验证所需的强类型对象和审批语义，但不实现任何 PoC 执行。

### 新增文件

```text
argus/verification/models.py
argus/verification/requirements.py
argus/verification/planning.py
argus/verification/policy.py
argus/verification/approvals.py
argus/verification/secrets.py
tests/verification/
```

### 模型

```text
EnvironmentProfile
- id
- project_id
- kind: existing_url | docker_compose | custom
- target_base_url
- scope_allowlist
- health_checks
- reset_capability
- source_snapshot_binding
- enabled

IdentityProfile
- id
- project_id
- handle
- role
- tenant
- attributes
- credential_ref
- enabled

VerificationRequirement
- finding_id
- required_environment_capabilities
- required_identity_roles
- required_test_data
- missing_fields

VerificationPlan
- id
- finding_id
- snapshot_id
- environment_id
- identity_handles
- actions
- request_budget
- expected_observations
- expected_side_effects
- rollback_strategy
- health_checks
- abort_conditions
- risk_class
- plan_hash
- status

Approval
- id
- plan_id
- plan_hash
- decision
- reviewer
- reason
- created_at / decided_at / expires_at
```

### 风险等级

```text
R0_STATIC
R1_SAFE_READ
R2_REVERSIBLE_WRITE
R3_HIGH_IMPACT
R4_PROHIBITED
```

默认策略：

- R0 自动允许；
- R1 仍需项目配置允许，并默认人工审批；
- R2 仅可重置环境，逐计划审批；
- R3 默认拒绝；
- R4 永久拒绝。

### 要求

1. `verification.enabled` 默认 false。
2. Finding 可以存在而不创建 VerificationPlan。
3. Verifier 插件只声明需求与计划，不获得网络权限。
4. 凭据不进入数据库、Artifact、LLM Prompt 或审计日志；只保存 `credential_ref`。
5. 第一版 SecretProvider：环境变量引用；接口预留 OS Keychain。
6. plan hash 基于规范化完整计划；计划任何实质字段变化都产生新 hash，并使旧 Approval 失效。
7. Web 展示缺少哪些环境、身份和测试数据。

### 验收标准

- 不能执行任何网络动作。
- 可以针对 Finding 生成“缺少输入”或“Plan Ready”状态。
- 审批绑定 plan hash；修改计划后旧审批变为 SUPERSEDED。
- 静态扫描不配置验证时不受影响。

### Codex 提示词

```text
执行计划 M8，且只执行 M8。只建立验证领域模型、需求解析、风险策略、plan hash 和审批中心。
本阶段严禁添加网络请求、浏览器、Shell 或 PoC 执行。凭据只能以 credential_ref 存在，不能进入数据库明文、Artifact、Prompt 或日志。
```

---

## M9：只读 HTTP Verification MVP

### 目标

在人工批准、测试环境、明确身份和严格预算下，支持第一种低风险动态验证。

### 范围

只支持：

- `existing_url` 测试环境；
- HTTP/HTTPS；
- GET/HEAD/OPTIONS；
- R1_SAFE_READ；
- 明确 allowlist；
- 手工审批；
- Authorization/IDOR 的差异性读取验证。

明确不支持：

- POST/PUT/PATCH/DELETE；
- 浏览器自动化；
- Shell；
- 文件上传；
- OAST；
- SSRF；
- DoS；
- SQL 注入破坏性 payload；
- 自动注册用户；
- 真实生产环境。

### 新增文件

```text
argus/verification/broker.py
argus/verification/http_policy.py
argus/verification/evidence.py
argus/verification/executors/http_readonly.py
argus/verification/identity_broker.py
argus/verification/health.py
tests/verification/test_broker_*.py
tests/integration/test_readonly_authz_verification.py
```

### Tool Broker 强制检查

每个请求执行前：

1. VerificationPlan 状态为 APPROVED；
2. Approval 的 plan hash 与当前 plan hash 完全一致且未过期；
3. Finding、snapshot、environment 绑定一致；
4. URL scheme/host/port/path 在 allowlist；
5. 禁止重定向到 allowlist 外；
6. HTTP method 允许；
7. 请求数量和总字节未超预算；
8. identity handle 在计划中；
9. 健康检查正常；
10. 未触发 abort condition。

LLM 和 Verifier Plugin 不得直接持有 `httpx.Client`。网络只能经 Broker。

### Identity Broker

- LLM 只看到 `identity_handle`；
- CredentialProvider 在执行时解析 secret；
- Identity Broker 生成 Header/Cookie，但不把原始 secret 返回给插件；
- 日志对 Authorization、Cookie、CSRF、Token 做不可逆脱敏。

### Evidence

```text
VerificationAttempt
- id
- plan_id / plan_hash
- status
- started_at / finished_at
- environment health before/after

Evidence
- request summary（脱敏）
- response status/headers（脱敏）
- response body hash
- 受限 body excerpt 或结构化观察
- identity handle
- timestamp
- artifact hash
- success predicate result
```

验证结论由确定性 success predicate 产生：

```text
CONFIRMED
REJECTED
INCONCLUSIVE
ABORTED
```

LLM 不能自行把 Finding 改成 CONFIRMED。

### 首个验证器：Authorization Differential Read

示例逻辑：

1. owner identity GET 自有测试资源；
2. peer identity GET 同一资源；
3. 根据计划定义的状态码、响应 schema、资源标识和敏感字段判断；
4. peer 获得不应访问的数据则 CONFIRMED；
5. 401/403/404 或数据隔离符合预期则 REJECTED/INCONCLUSIVE，按规则配置；
6. 不允许猜测资源 ID，不允许枚举。

### 健康熔断

- 执行前和每 N 个请求后 health check；
- 连续 5xx、连接失败、响应异常变慢或健康检查失败立即终止；
- 标记 Attempt ABORTED；
- 不自动重试危险动作。

### 验收标准

- 未审批无法产生任何网络请求。
- 修改计划后旧审批无法使用。
- Broker 单测覆盖 URL 绕过、重定向、DNS/host、预算、method、secret 脱敏。
- 只读授权验证可产生结构化 Evidence，并由 predicate 更新 Verification Status。

### Codex 提示词

```text
执行计划 M9，且只执行 M9。实现只读 HTTP Tool Broker 和 Authorization Differential Read 验证。
所有网络必须经过 Broker；未审批、hash 不一致、越界 URL、非只读方法或超预算必须在发请求前拒绝。
禁止浏览器、Shell、写请求、OAST、SSRF 和自动枚举。结论必须由确定性 predicate 产生，不得由 LLM 直接确认。
```

---

## M10：安全加固、插件隔离与 V1 退场

### 目标

在 V2 稳定后收紧安全边界，形成可发布版本。

### 任务

1. 插件 Runtime 改为独立进程；通过 JSON-RPC/stdio 传递 Artifact references，不传文件系统任意路径。
2. 按 PermissionSpec 构造运行环境：
   - 默认无网络；
   - 只读 snapshot；
   - 独立临时目录；
   - 超时、内存、输出大小限制；
   - 清理环境变量和 secrets。
3. Audit Level：

   ```text
   metadata
   redacted
   full（显式启用）
   ```

4. 配置全面 Pydantic 化；非法 `source_mode` 等配置直接失败。
5. 增加数据库备份、migration 回滚说明和 Artifact GC。
6. 增加 SARIF/JSON 导出，但仍从 Canonical Finding 生成。
7. 建立性能基线：
   - snapshot；
   - graph build；
   - candidate count；
   - LLM calls/tokens；
   - task resume；
   - Web graph query。
8. V2 连续通过对等、恢复和安全测试后：
   - 标记 Legacy Engine deprecated；
   - 文档迁移；
   - 最后单独 PR 删除固定 LangGraph Pipeline 和旧 Workspace 推断逻辑。

### 验收标准

- 插件默认不在 Control Plane 主进程执行。
- 无网络插件无法访问网络。
- 审计日志默认不落完整源码与秘密。
- 所有核心配置 fail closed。
- 删除 Legacy 后，所有 V2 测试与迁移测试通过。

---

# 6. 跨里程碑测试策略

## 6.1 测试金字塔

### 单元测试

- Hash、ID、状态机；
- Manifest Schema；
- Planner；
- Artifact Store；
- Security Graph Query；
- Finding Fingerprint；
- Policy/Broker。

### 集成测试

- Project → Snapshot → Plan → Execute → Finding → Report；
- 进程中断和恢复；
- Review pause/approve/resume；
- Web 重启；
- V1/V2 对等；
- 只读验证审批链。

### Golden 测试

固定 fixture 和 mock LLM 输出：

- business-flow Artifact；
- Security IR；
- Candidate；
- Finding；
- report；
- Verification Evidence。

Golden 更新必须显式审查，不能在测试失败时自动覆盖。

## 6.2 必须长期保留的回归测试

1. 原仓库不会被扫描器写入。
2. Snapshot 改变会使图缓存失效。
3. 未知插件不会被静默跳过。
4. 插件循环依赖会失败。
5. Artifact 损坏会失败。
6. LLM 产生不存在的 node ID 会被拒绝。
7. Finding 标题改变不会改变 fingerprint。
8. Web 重启后 Task 状态仍存在。
9. 无 Approval 不会发出网络请求。
10. Secret 不出现在 Event、Artifact、Prompt Audit 和 HTTP 日志。

---

# 7. 配置迁移

## 7.1 V2 配置示例

```yaml
schemaVersion: "2"

project:
  name: demo

source:
  mode: stripped
  ignore:
    - node_modules/
    - dist/

engine:
  type: local

plugins:
  enabled:
    - graph.codegraph
    - enrichment.business-flow
    - semantic.business-flow-to-security-ir
    - detector.injection
    - detector.authorization.idor
    - reporter.markdown
  providers:
    code.graph.v1: graph.codegraph

reviews:
  staticArtifacts: false
  findings: true

verification:
  enabled: false

llm:
  modelRef: default
  auditLevel: redacted
```

## 7.2 兼容策略

- 读取旧配置时通过 `LegacyConfigAdapter` 转换为 V2 DTO；
- 转换结果写 Event 和迁移警告；
- 非法值不再回退；
- 旧 `analyzers.enrichment/vuln` 转换成 `plugins.enabled`；
- `--yolo` 仅代表跳过静态 Review，绝不能自动开启或批准动态验证。

---

# 8. 事件命名建议

```text
project.created
scan.created
snapshot.started
snapshot.completed
plan.compiled
plan.failed
task.ready
task.started
task.succeeded
task.failed
task.interrupted
artifact.created
artifact.corrupted
review.requested
review.approved
review.rejected
finding.created
finding.updated
verification.requirements_missing
verification.plan_created
verification.approval_requested
verification.approved
verification.denied
verification.attempt_started
verification.request_allowed
verification.request_denied
verification.evidence_captured
verification.attempt_aborted
verification.finding_confirmed
scan.completed
scan.failed
```

Event payload 不应保存完整源码或 secret。

---

# 9. 每个 PR 的通用验收清单

Codex 在每个里程碑结束时逐项回答：

```text
[ ] 是否只完成了当前里程碑？
[ ] 是否保留现有兼容路径？
[ ] 是否新增或更新了 migration？
[ ] 是否新增单元测试和集成测试？
[ ] 是否存在新的静默跳过或静默回退？
[ ] 是否引入未经类型化的核心 dict[str, Any]？
[ ] 是否把 secret、源码或大型 Artifact 写入错误位置？
[ ] 是否更新了相关文档？
[ ] pytest 是否通过？
[ ] ruff 是否通过？
[ ] mypy 是否通过？
[ ] 是否列出了已知限制？
```

---

# 10. 整体 Definition of Done

Argus V2 可视为第一阶段落地完成，必须同时满足：

1. 一次扫描有 Project、Scan、SourceSnapshot、TaskPlan、Task、Artifact、Finding、Event 的完整记录。
2. 原始代码仓库不被 Argus 写入。
3. 图和所有分析产物绑定 snapshot、producer version 和 content hash。
4. Planner 根据 Capability 动态形成 DAG，核心代码不知道具体漏洞名称。
5. 新增插件不修改 Planner/Executor。
6. V2 执行支持进程重启恢复。
7. business-flow 已进入正式 Security IR。
8. 至少 injection 和 authorization 使用 Candidate + Graph Slice + Expert 模式。
9. Web 可查看 Task DAG、Artifact、Graph Slice、Finding 和 Review。
10. 静态扫描可在验证完全关闭时独立完成。
11. 动态验证必须具备 Environment、Identity、Plan、Policy、Approval、Broker 和 Evidence。
12. 未审批或计划变化后绝不执行网络请求。
13. LLM 无法直接获取真实凭据，也无法直接把 Finding 标为动态确认。
14. 所有核心路径有回归、恢复和安全测试。

---

# 11. 推荐的首次 Codex 任务

不要让 Codex 一次执行全文。首次只发送：

```text
请读取仓库和 ARGUS_V2_IMPLEMENTATION_PLAN.md。
先执行 M0，完成后停止，不要进入 M1。
要求：不改变运行行为；建立 ADR、基线记录、架构边界和测试结果。完成后给出文件级 diff 摘要、测试结果和 M1 风险点。
```

M0 审核通过后，再单独执行 M1。M1～M4 是基础迁移链，M5～M7 是静态平台化，M8～M9 才是受控验证。
