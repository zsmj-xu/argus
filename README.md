# Argus

Argus 是一个 AI 辅助的白盒源代码扫描器。它构建本地代码图，
运行选定的代码富化和漏洞分析器，支持人工审查检查点，
并输出结构化发现和 Markdown 报告。

## 环境需求

- Python 3.11 或更新版本以及 [uv](https://docs.astral.sh/uv/)
- `PATH` 中的 `codegraph` CLI（或位于 `/opt/homebrew/bin/codegraph`）
- 兼容 OpenAI 的聊天完成端点

安装环境：

```bash
uv sync --extra dev
cp .env.example .env
```

使用 `ARGUS_LLM_BASE_URL`、`ARGUS_LLM_API_KEY` 和
`ARGUS_LLM_MODEL` 配置 `.env`。Argus 将选定的源代码上下文发送到该端点，
因此请仅扫描您获得授权披露给所配置提供商的存储库。

## 可视化操作台

从存储库根目录启动仅监听本机的 Web Console：

```bash
uv run argus web
```

然后打开 `http://127.0.0.1:8765`。操作台以 `runs/control.db` 为 V2 状态事实来源，
提供 Project、Scan Overview、Task DAG、Artifact、有限 Graph Slice、Finding、
静态审核和 Event 视图。Web 重启后会从 Control Store 恢复这些资源，并把失效的
运行 Attempt 变为可恢复状态；进程内 Job 句柄不再决定 Scan/Task 状态。

Legacy Workspace 文件仍显示在兼容视图中，但不是 V2 状态事实来源。新建扫描前必须
确认你有权向当前配置的 LLM 披露所选源码上下文。Web Console 没有远程认证，因此
拒绝绑定到非 loopback 地址。敏感 prompt/credential/audit Artifact 不允许通过
页面预览或下载。M8 可以离线声明验证需求、环境/身份引用、计划和 hash 绑定审批；
M9 只允许对显式标记为测试环境的 `existing_url`，在当前 plan hash 获得人工批准后
执行 GET/HEAD/OPTIONS。所有请求都经过 allowlist、DNS/IP、预算和凭据 Broker。

## 运行扫描

从存储库根目录运行命令，为每个新扫描使用新的工作区名称：

```bash
uv run argus scan \
  -r /absolute/path/to/target \
  -w my-project-authz-001 \
  --yolo \
  --set 'source_mode=stripped'
```

### 主要参数说明

- `-r /absolute/path/to/target`：扫描目标的绝对路径
- `-w my-project-authz-001`：工作区名称，用于保存扫描结果和状态
- `--yolo`：跳过人工审查检查点，自动执行整个扫描（省略此参数会在检查点暂停）
- `--set 'source_mode=stripped'`：源代码模式，`stripped` 表示仅发送必要的代码片段到 LLM（节省 token）
- `--focus src/orders`：仅关注特定目录或文件（用于 `continue` 命令时）

默认的漏洞分析器是 `authz`。可以显式启用代码富化和漏洞分析器进行更广泛的扫描：

```bash
uv run argus scan \
  -r /absolute/path/to/target \
  -w my-project-full-001 \
  --yolo \
  --set 'source_mode=stripped' \
  --set 'analysisMode=v2' \
  --set 'analyzers.enrichment=["business-flow","invariant"]' \
  --set 'analyzers.vuln=["auth","authz","injection","xss","ssrf","business-logic"]' \
  --set 'strict_outputs=true' \
  --set 'business-flow.batch_size=8' \
  --set 'authz.batch_size=8'
```

### 高级参数说明

**分析器配置：**
- `analysisMode`：`legacy`、`v2` 或 `compare`。V2 Scan 默认 `v2`；
  当前只迁移 `injection` 和 `authz`，其他 Analyzer 继续走 Legacy Adapter。
  `compare` 同时运行新旧规则并生成独立 Comparison Artifact，不改变主报告。
- `analyzers.enrichment`：代码富化分析器列表
  - `business-flow`：分析业务流程和数据流
- `invariant`：分析代码不变量和约束

- `analyzers.vuln`：漏洞分析器列表
  - `auth`：认证漏洞
  - `authz`：授权漏洞（默认启用）
  - `injection`：注入攻击（SQL、命令注入等）
  - `xss`：跨站脚本攻击
  - `ssrf`：服务端请求伪造
  - `business-logic`：业务逻辑漏洞

**性能和输出：**
- `strict_outputs=true`：启用严格的输出验证和过滤
- `business-flow.batch_size=8`：业务流分析的批处理大小（越大越快但消耗更多 token）
- `authz.batch_size=8`：授权分析的批处理大小
- 普通漏洞分析默认从 32K 输出额度开始，`business-flow` 和 `invariant` 默认从 64K 开始
- 当网关返回 `finish_reason=length` 时，Argus 会自动翻倍重试，默认最高到 384K
- `ARGUS_LLM_MAX_OUTPUT_TOKENS`：覆盖自动重试上限，例如 `131072`
- 漏洞标题、风险说明、证据说明、数据流和修复建议默认使用简体中文；代码标识符、
  文件路径、HTTP 路径、枚举值和代码片段保持原样

省略 `--yolo` 时，V2 会创建绑定当前 Artifact hash 的持久化 ReviewRequest。
审批后按 Scan ID 恢复：

```bash
uv run argus scan-status --scan-id <scan-uuid>
uv run argus review approve \
  --review-id <review-uuid> \
  --reviewer alice \
  --reason "已核对静态产物"
uv run argus scan-resume --scan-id <scan-uuid>
uv run argus scan-cancel --scan-id <scan-uuid>
uv run argus workspaces
```

### 运行管理命令

- `argus scan ...`：默认使用 DB-backed V2 LocalPlanExecutor
- `argus scan-status --scan-id <id>`：从 Control Store 查询 Scan、Task 和开放审核
- `argus scan-resume --scan-id <id>`：恢复中断或已获批准的 V2 Scan
- `argus scan-cancel --scan-id <id>`：持久化取消 Scan 和未完成 Task
- `argus review approve|reject ...`：记录带 reviewer、reason 和 subject hash 的审核决定
- `argus findings-export ...`：从 Canonical Finding 确定性导出 JSON/SARIF
- `argus performance-baseline ...`：汇总 Snapshot、图、Candidate、LLM 和恢复指标
- `argus control-backup ...`：创建拒绝覆盖的 SQLite 一致性备份
- `argus artifact-gc`：默认 dry-run；`--apply` 将未引用 blob 移入可恢复隔离区
- `argus workspaces`：列出所有已有的工作区

固定 LangGraph Pipeline 仍作为显式 legacy 路径保留：

```bash
uv run argus scan \
  -r /absolute/path/to/target \
  -w legacy-run-001 \
  --engine legacy
uv run argus continue -w legacy-run-001
uv run argus resume -w legacy-run-001
```

Legacy 引擎已 deprecated。原有 `argus start/continue/resume` 暂留迁移窗口；
固定 Pipeline 的删除将由后续独立 PR 完成，不与本次安全边界变更混合。

每次新扫描都会先把纳入扫描的源码完整复制到不可混淆的 SourceSnapshot：

```text
runs/_data/snapshots/<snapshot-id>/source/
```

V2 Codegraph 在隔离的 Task 临时目录中从该快照副本构建，再作为 Artifact 发布；
Legacy 兼容路径也只操作隔离快照。两者都不再向用户的原始源码仓库写入
`.codegraph`。扫描期间原仓库发生的后续变化不会影响已物化快照。

兼容工作区仍在 `runs/<workspace>/` 下保留：

- `report.md`：人类可读的报告
- `findings.json`：结构化发现
- `enriched-graph.json`：代码富化输出
- `state.db`：仅 legacy 引擎使用的 LangGraph 检查点

V2 Control Store 和内容寻址数据位于：

```text
runs/control.db
runs/_data/artifacts/sha256/<prefix>/<content-hash>/payload
```

Graph、enrichment、findings 和 report 会同时注册为带 Scan、Snapshot、Task、
producer、schema、capability 和内容哈希的 Artifact。旧 Workspace 文件继续作为
人工审核和兼容视图使用。

每次 V2 扫描通过 Manifest Registry 和 Capability Planner 编译确定性的 TaskPlan，
并以 `task.plan.v1` Artifact 保存。LocalPlanExecutor 串行执行该 DAG；TaskAttempt、
输入 Artifact hash、心跳、重试、审核和恢复状态均来自 Control Store。完整边界见
[M4 说明](docs/implementation/m4-local-executor.md)。

选择 `business-flow` enrichment 时，V2 会在原有规整结果和 Codegraph 之上确定性生成
`security.graph.v1`：Codegraph 结构图和 Security IR 分别保存为独立 SQLite Artifact。
路由、业务流、授权与资源也会生成独立的 capability 投影。所有推断关系保留
`INFERRED/POSSIBLE` confidence、producer、snapshot、源 Artifact 和 Codegraph 锚点；
不会被升级成确定性事实。图查询和 Graph Slice 强制限制节点、深度、路径和展开边数量。
完整契约见 [M5 说明](docs/implementation/m5-security-ir.md)。

`injection` 和 `authz` 在 `analysisMode=v2` 下采用候选驱动链路：

```text
deterministic Candidate
  → bounded Graph Slice + bounded Source Context
  → strict ExpertAssessment
  → normalized StaticFindingV2
```

Injection 从危险 sink 反向生成候选，不再让多个专家重复遍历全部函数；
Authorization/IDOR 从 `business.flow`、外部资源 ID、资源访问和所有权/租户保护关系
生成候选。Candidate、Graph Slice、Source Context 和 ExpertAssessment 均保存为
Artifact。LLM 只能判断给定候选，不能创建 Finding ID 或声明动态确认；所有 M6
Finding 的验证状态均为 `UNVERIFIED`，报告会把静态置信度与验证状态分别展示。
完整边界见 [M6 说明](docs/implementation/m6-candidate-detection.md)。

### 动态验证规划与只读 HTTP MVP

M8 默认关闭动态验证规划：

```yaml
verification:
  enabled: false
  allow_safe_read: false
  allow_reversible_write: false
```

显式开启后，Verifier 只能声明环境能力、身份角色和测试数据键，并编译不可执行的
`VerificationPlan`。计划包含预算、预期观察/副作用、回滚、abort condition、风险等级
和规范化 `plan_hash`。计划发生实质变化时旧 Approval 自动变为 `SUPERSEDED`。

数据库只保存 `env:NAME`/`keychain:NAME` 形式的 `credential_ref`，不保存 secret。
R1/R2 默认需要逐计划人工审批，R3 默认拒绝，R4 永久拒绝。M8 的 `APPROVED` 本身
不会发请求。M9 另需人工显式执行，且只接受 `test_only: true` 的 `existing_url`、
R1_SAFE_READ、GET/HEAD/OPTIONS、精确 host/port/path allowlist 和显式测试数据。
私网/loopback 默认拒绝；本地或内网测试环境还需显式设置
`allow_private_addresses: true`。完整边界见
[M8 说明](docs/implementation/m8-verification-planning.md) 和
[M9 说明](docs/implementation/m9-http-readonly-verification.md)。

```bash
uv run argus verification-status --finding-id <finding-uuid>
uv run argus verification-approval request --plan-id <plan-uuid>
uv run argus verification-approval approve \
  --approval-id <approval-uuid> \
  --reviewer alice \
  --reason "已核对环境、身份引用、预算与 plan hash"
uv run argus verification-execute \
  --plan-id <plan-uuid> \
  --test-data resource_id=<prepared-test-fixture-id>
```

M7 Control Plane 提供持久化资源 API；完整边界见
[M7 说明](docs/implementation/m7-web-control-plane.md)。核心入口包括：

```text
GET|POST /api/projects
GET|PATCH /api/projects/{project-id}
GET /api/scans/{scan-id}
GET /api/scans/{scan-id}/tasks
GET /api/scans/{scan-id}/artifacts
GET /api/scans/{scan-id}/findings
GET|POST /api/reviews
GET /api/scans/{scan-id}/events

GET /api/scans/{scan-id}/graph/nodes?kind=http.route&max_nodes=100
GET /api/scans/{scan-id}/graph/nodes/{node-id}
GET /api/scans/{scan-id}/graph/slice?seed_id={node-id}&radius=2&max_nodes=100
GET /api/artifacts/{graph-slice-artifact-id}/graph-slice
GET /api/findings/{finding-id}/verification
GET /api/verification/approvals
POST /api/verification/plans/{plan-id}/execute
```

### M10 插件与审计安全

V2 默认插件在独立 worker 进程运行，通过 JSON-RPC/stdio 交换 Artifact reference。
默认权限为无网络、无 secret、无 subprocess 和不可读源码；需要 LLM 或 Codegraph
能力的内置插件必须在 Manifest 中显式声明。external plugin 强制进程隔离，并禁止
申请网络、secret 或 subprocess。

LLM 审计默认 `redacted`，只保存字符数和内容 hash；只有显式设置
`llm.auditLevel=full` 才保存正文。Event 和错误持久化统一脱敏。完整的隔离模型、
运维恢复流程和 Legacy 删除前置条件见
[M10 说明](docs/implementation/m10-hardening-retirement.md)。

## 存储库结构

```text
argus/
├── argus/          可安装的产品包
├── evaluation/     基准测试运行器、基础事实和易受攻击的目标
├── tests/          产品和评估测试
├── docs/           设计、评估、状态和历史审查
└── runs/           生成的扫描工作区（被 Git 忽略）
```

`argus/eval/` 是可复用的评分库。基准测试应用程序和评估编排位于 `evaluation/` 下。

有关评估命令和当前限制，请参阅
[evaluation/README.md](evaluation/README.md) 和
[扩展状态](docs/comparisons/EXPANSION-STATUS.md)。
架构、运维、里程碑与历史记录的入口见
[文档索引](docs/README.md)。

## 开发检查

```bash
uv run pytest -q
uv run ruff check argus evaluation/scripts tests
uv run ruff format --check argus evaluation/scripts tests
uv run mypy argus evaluation/scripts
git diff --check
```
