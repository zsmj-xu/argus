# Argus V2 架构迁移总览

本文记录 M0 时的架构事实和 V2 迁移边界，不定义新的运行行为。
当前用户使用说明仍以 `README.md` 为准，完整实施顺序以
`docs/specs/2026-07-29-argus-v2-implementation-plan.md` 为准。

## M0 基线中的 V1 运行链

```text
CLI / local-only Web Console
              |
              v
      make_initial_state
              |
              v
  fixed LangGraph Pipeline
              |
    +---------+----------+
    |                    |
    v                    v
target/.codegraph   runs/<workspace>/
codegraph.db        state.db
                    enriched-graph.json
                    findings.json
                    report.md
                    progress.jsonl
                    audit/llm.jsonl
```

固定 Pipeline 的节点顺序为：

```text
build_graph → enrichment → review-enrichment
            → vuln → review-findings → report
```

`start` 创建初始状态并首次执行；`continue` 放行人工检查点；`resume`
从已有 checkpoint 推进。LangGraph 的 `thread_id` 是 Workspace 名。

## M0 基线中的职责边界

| 边界 | 当前实现 | 迁移时必须保留的事实 |
| --- | --- | --- |
| Contract | `argus/contracts.py` | Finding 为结构化对象；V1 镜像保持字节一致 |
| 编排 | `argus/orchestration/pipeline.py` | 六节点串行顺序与失败传播 |
| 状态 | `ArgusState` + `runs/<workspace>/state.db` | checkpoint 可继续/恢复 |
| Analyzer | `argus/analyzers/*` + 自动发现 | 按配置选择，输出 enrichment/Finding |
| 图 | `argus/graph/*` | `GraphHandle` 提供只读查询接口 |
| 源码 | `_FileSourceAccess` | `raw`/`stripped` 模式及行号保持 |
| 审核 | `review-enrichment`、`review-findings` | 审核的是静态产物，不是动态验证授权 |
| 报告 | `argus/reporting/report.py` | 从 Finding 确定性渲染 Markdown |
| 进度 | `argus/progress.py` | 追加写入 `progress.jsonl` |
| Web | `argus/web.py` + `argus/control_plane/` | 仅 loopback；Control Store 为 V2 事实来源，Workspace 为 legacy 兼容投影 |

## M0 已确认的 V1 限制

### 固定编排

Pipeline 直接装配六个节点。`Analyzer.requires` 虽然存在于协议中，当前注册表和
Pipeline 不根据它解析生产者、检测循环或拓扑排序。配置中不存在的 Analyzer 名
会在 `_run_phase` 中被静默跳过。

### 共享 enrichment

每个 enrichment Analyzer 的结果通过 `dict.update()` 浅合并到
`ArgusState.enriched`。相同键以后写覆盖先写，产物没有独立 schema、producer、
version 或 content hash。

### 源码和图的耦合

初始 `graph_db_path` 是 `<repo>/.codegraph/codegraph.db`。存在的 DB 可直接复用；
当前状态没有 SourceSnapshot tree hash、provider version 和配置 hash 组成的完整
缓存键。

### M7 前的运行状态双重来源（已完成迁移）

CLI 的 checkpoint 在 SQLite 中持久化，但 Web 的活跃子进程信息保存在
`JobManager._jobs`。Web 重启后，会回退为根据 Workspace 文件存在性推断状态，
不能可靠恢复进程级任务事实。M7 已将 V2 Web 状态切换为 Control Store 的
Scan/Task/Attempt，并在启动时协调失效 worker；`JobManager` 仅保留当前进程句柄。

## V2 目标数据流

```text
SourceSnapshot
      ↓
typed, content-addressed Artifacts
      ↓
PluginSpec + Capability registry
      ↓
deterministic TaskPlan DAG
      ↓
DB-backed LocalPlanExecutor
      ↓
Security IR + bounded Graph Slice
      ↓
Candidate → Expert Assessment → Canonical Finding
      ↓
optional Verification Requirement / Plan / Approval / Broker / Evidence
```

Control Store 保存可查询的领域状态和 Artifact metadata；大型源码、图和模型产物
由 Artifact Store 保存。报告和 `progress.jsonl` 是兼容投影，不是事实来源。

## 依赖方向

允许的迁移方向是：

```text
CLI / Web adapters
        ↓
V2 application services
        ↓
domain + ports
        ↑
storage / plugin / execution adapters

legacy adapter → frozen V1 contracts and entry points
```

V2 领域、控制、规划和执行模块不得导入固定 Pipeline。V1 也不应在 M0 被迫依赖
尚不存在的 V2 模块。切换执行入口只在后续明确里程碑发生。

## 安全边界

- 扫描源码可能被发送到配置的 LLM；真实扫描必须获得披露授权。
- M0–M8 的迁移验证使用离线 fixture 和 Stub LLM，不运行真实扫描，也不发起目标网络验证。
- M9 集成验证只使用进程内 loopback 测试服务；不访问生产或外部目标。
- Web Console 无远程认证，只允许 loopback bind。
- 静态审核只表示人工接受当前静态产物，不能授权或确认动态验证。
- `--yolo` 只跳过静态 Review，不得在未来隐式开启验证。
- 明文凭据始终不得进入模型、Control Store、Artifact 或 Event。

## M10 后的状态

M1 已建立 SQLite Control Store 和领域 DTO；M2 已将新扫描切换到不可变
SourceSnapshot，并把兼容产物注册到内容寻址 Artifact Store；M3 已建立 Manifest
Registry、Capability Planner、Legacy PluginSpec Adapter，以及可追踪的
`task.plan.v1`。

M4 已增加串行、DB-backed LocalPlanExecutor、TaskAttempt 心跳恢复和哈希绑定的
ReviewRequest。`argus scan` 默认使用 V2，固定 LangGraph Pipeline 仍通过
`--engine legacy` 和旧 `start` 入口显式保留。

M5 已增加严格 Security IR、独立 `security.graph.v1` SQLite Artifact、受限查询与
Graph Slice，以及 `semantic.business-flow-to-security-ir` 适配插件。现有
business-flow Analyzer 和 Prompt 保持不变；LLM 推断关系保留 provenance 和
`INFERRED/POSSIBLE` confidence。

M6 已把 injection 和 authorization/IDOR 迁移为
`Candidate → Graph Slice → ExpertAssessment → StaticFindingV2`。候选生成是确定性的，
图和源码上下文有硬上限，Expert 输出严格校验且不能创建 Finding ID。每一阶段均保存为
Artifact；Finding 指纹不依赖标题，状态保持 `UNVERIFIED`。`analysisMode` 支持
`legacy|v2|compare`，对照结果为不参与主报告的旁路 Artifact。其他旧 Analyzer 和固定
Pipeline 仍保留。

M7 已增加持久化 Web Control Plane 应用服务和 API。Projects、Scan、Task DAG、
TaskPlan、Artifact、Finding、ReviewRequest 和 Event 均从 Control Store 查询；
Artifact 内容通过哈希和大小验证，敏感 prompt/credential/audit 内容禁止暴露。
Finding 可跳转源码位置和自身绑定的有界 Graph Slice Artifact，静态审核与动态验证
状态始终分离。Web 启动时协调失效 Attempt，轮询和进程内 Job 句柄不再成为事实来源。
完整边界见 `docs/implementation/m7-web-control-plane.md`。

M8 已增加强类型 `EnvironmentProfile`、`IdentityProfile`、
`VerificationRequirement`、`VerificationPlan` 和 `Approval`，以及缺失输入解析、
规范化 plan hash、R0–R4 默认拒绝策略和 Web/CLI 审批入口。`verification.enabled`
默认 false；凭据只保存引用。计划修改会使旧 Approval 失效。M8 没有 Broker、
Executor、Evidence 或网络访问，Approval 不能触发执行。完整边界见
`docs/implementation/m8-verification-planning.md`。

M9 已增加唯一网络出口 `VerificationBroker`、DNS 固定解析的只读 HTTP Executor、
`IdentityBroker`、请求/响应预算、健康检查、`VerificationAttempt` 和内容寻址
Evidence。执行仅接受当前 hash 的未过期人工 Approval、`test_only` existing_url、
R1_SAFE_READ 和 GET/HEAD/OPTIONS；重定向逐跳重验，跨 origin、link-local、写方法、
自动枚举、浏览器、Shell、OAST 和生产环境均拒绝。Authorization/IDOR 结论由
owner/peer 差异谓词确定，LLM 不能设置 `CONFIRMED`。完整边界见
`docs/implementation/m9-http-readonly-verification.md`。

M10 已把默认 Plugin Runtime 切换到独立 worker 进程和 Artifact-reference
JSON-RPC/stdio 协议，增加 PermissionSpec、清洁环境、临时目录、资源/输出限制、
网络/文件/子进程封锁及进程组终止。LLM audit 默认 redacted，Event、错误和 URL
统一脱敏；核心配置非法值 fail closed。Control Store 一致性备份、可恢复 Artifact
GC、Canonical Finding JSON/SARIF 与持久化性能基线均提供 CLI。Legacy 引擎已标记
deprecated；固定 Pipeline 的物理删除按 ADR 边界留给通过迁移清单后的独立 PR。
完整边界见 `docs/implementation/m10-hardening-retirement.md`。
