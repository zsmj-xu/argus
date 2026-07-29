# ADR-0001：以渐进迁移方式演进 Argus V2

- 状态：已接受
- 日期：2026-07-29
- 决策范围：Argus V2 平台化改造

## 背景

Argus V1 由 `argus/orchestration/pipeline.py` 中的固定 LangGraph 六节点流程驱动：

```text
build_graph
  → enrichment
  → review-enrichment
  → vuln
  → review-findings
  → report
```

现有实现已经提供分析器发现、SQLite checkpoint、人工静态审核、结构化 Finding、
确定性 Markdown 报告和本地 Web Console。这些能力必须在迁移期间保持可用。同时，
当前实现有几项不适合作为平台边界的约束：

- `Analyzer.requires` 是 Contract 的一部分，但固定 Pipeline 不解析依赖或编译 DAG；
- enrichment 通过共享 `dict[str, Any]` 浅合并，缺少类型、来源和冲突边界；
- Codegraph 默认写入目标源码目录的 `.codegraph/`；
- Web 子进程任务状态主要保存在 `JobManager._jobs` 内存字典；
- Workspace 文件和 LangGraph checkpoint 同时承担运行状态与交换协议。

完整迁移路线和安全约束见仓库根目录的
`docs/specs/2026-07-29-argus-v2-implementation-plan.md`。

## 决策

### 1. 使用渐进替换，而非一次性重写

V1 和 V2 在迁移期并行存在。V2 通过 Legacy Adapter 接入现有 Analyzer 和产物，
先建立对等测试，再切换默认执行路径。固定 LangGraph Pipeline 在独立退场里程碑
之前不得删除。

### 2. 暂时冻结 V1 Contract

`argus/contracts.py` 及其权威镜像 `docs/contracts/interfaces.py` 继续作为 V1
编排器、分析器和报告层的兼容契约，两者必须保持字节一致。V2 领域 DTO、插件协议
和执行协议放入独立命名空间，不继续扩大 V1 Contract。

### 3. V2 使用独立、单向的模块边界

V2 从 `argus/domain`、`argus/control`、`argus/snapshots`、
`argus/artifacts`、`argus/plugins`、`argus/planning`、
`argus/execution`、`argus/security_ir`、`argus/detection`、
`argus/verification` 和 `argus/web_api` 等命名空间逐步形成。

这些命名空间不得依赖 `argus.orchestration.pipeline`。兼容依赖只能通过明确的
Legacy Adapter 从 V2 边界指向 V1 协议或调用入口，不能把固定 Pipeline 变成
V2 的核心依赖。

### 4. 首个 Control Store 使用本地 SQLite

Project、Scan、Task、Artifact metadata、Finding 和 Event 的首个持久化事实来源
采用 SQLite。第一阶段只实现本地执行器，不引入分布式调度基础设施。

### 5. 静态分析与动态验证分离

静态扫描必须能在验证完全关闭时独立完成。`verification.enabled` 默认关闭。
验证能力在静态平台稳定之后单独引入，并受强类型计划、策略、人工审批、受限
Broker 和确定性结论约束。

### 6. 保留现有用户可见能力

迁移必须保留：

- 现有 CLI 和 Workspace 兼容路径；
- 结构化 Finding 和确定性报告；
- 两个人工静态审核检查点；
- `progress.jsonl` 进度投影与审计能力；
- local-only Web 安全边界。

## 迁移阶段

1. M0 冻结和记录 V1 基线。
2. M1–M4 建立领域模型、存储、快照、Artifact、动态规划和本地执行。
3. M5–M7 建立 Security IR、候选检测链和持久化 Web Control Plane。
4. M8 只建立验证领域模型、策略和审批，不执行网络请求。
5. M9 只在测试环境、人工审批和严格预算下提供只读 HTTP 验证。
6. M10 完成插件隔离、安全加固，并在单独变更中退场 V1。

每个里程碑单独实施和审核，不跨里程碑预埋运行能力。

## 非目标

当前决策不包含：

- 重写或删除现有 Pipeline、Analyzer、Contract、CLI 或 Web Console；
- 在 M8 前实现 PoC、目标网络访问、浏览器、Shell 或真实凭据使用；
- 在 M9 中支持写请求、自动枚举、OAST、SSRF 回连、DoS 或生产环境验证；
- 立即引入 Temporal、Neo4j、Kubernetes、消息队列或分布式 Worker；
- 立即支持外部第三方插件在 Argus 主进程执行；
- 把报告重新定义为 Agent 之间的交换协议；
- 在 M0 创建 V2 领域模型、数据库 Schema 或执行代码。

## 后果

正面影响：

- 迁移可按里程碑回归，现有用户路径不会被一次性替换；
- V2 的核心规划和执行不受固定六节点 Pipeline 约束；
- 动态验证与静态判断之间形成明确的权限和状态边界；
- 未来替换存储或执行后端时有稳定领域边界。

代价与风险：

- 迁移期会同时维护 V1/V2 表示和 Legacy Adapter；
- 对等测试通过前不能快速删除重复路径；
- SQLite 适合首个本地 Control Store，但不是分布式执行方案；
- Contract 冻结意味着兼容修复必须经过显式契约变更流程。

## 执行约束

M0 的架构测试扫描规划中的 V2 顶层命名空间，禁止其静态导入
`argus.orchestration.pipeline`。更细的层级规则将在相应命名空间实际出现时，
由后续里程碑逐步增加。
