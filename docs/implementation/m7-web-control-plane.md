# M7：持久化 Web Control Plane

状态：已实现。M7 将本地 Web Console 接入 V2 Control Store、Artifact Store 和
LocalPlanExecutor 恢复语义，但不增加验证需求、凭据、网络访问或 PoC 能力。

## 事实来源与进程边界

`ControlPlaneService` 是 Web 的应用服务边界。它为每次操作打开 Control Store，
通过 Repository 和既有领域服务读取或变更 `Project`、`Scan`、`Task`、
`Artifact`、`Finding`、`ReviewRequest` 和 `Event`。HTTP Handler 只负责路由、
UUID/查询参数校验、JSON 编解码和安全文件流。

`JobManager._jobs` 只描述当前 Web 进程启动的子进程句柄，不再决定 Scan 或 Task
状态。服务启动时会调用 `LocalPlanExecutor.recover_stale()`：Control Store 中仍为
`RUNNING`、但 PID/心跳已失效的 Attempt 会变为 `INTERRUPTED`，对应 Task 回到可恢复
状态，并追加 `web.reconciled_lost_workers` Event。Web 重启后项目、DAG、产物、发现、
审核和事件均从数据库恢复。

Legacy Workspace 文件视图仍保留为兼容页面，但明确标记为旧 Pipeline 投影，不是
V2 状态事实来源。

## HTTP API

Control Plane 继续使用标准库 `ThreadingHTTPServer`，仅允许 loopback 监听：

```text
GET|POST   /api/projects
GET|PATCH  /api/projects/{project-id}
GET        /api/projects/{project-id}/scans
POST       /api/projects/{project-id}/scans

GET        /api/scans/{scan-id}
POST       /api/scans/{scan-id}/resume
POST       /api/scans/{scan-id}/cancel
GET        /api/scans/{scan-id}/tasks
GET        /api/scans/{scan-id}/plan
GET        /api/scans/{scan-id}/events
GET        /api/scans/{scan-id}/artifacts
GET        /api/scans/{scan-id}/findings

GET        /api/artifacts/{artifact-id}
GET        /api/artifacts/{artifact-id}?download=1
GET        /api/artifacts/{artifact-id}/graph-slice
GET|PATCH  /api/findings/{finding-id}

GET|POST   /api/reviews
POST       /api/reviews/{review-id}/approve
POST       /api/reviews/{review-id}/reject
```

M5 的有界 Security Graph 查询 API 继续可用。Finding 优先通过自身绑定的
`graph_slice_artifact_id` 打开精确的 `graph.slice.v1`，并再次校验内容哈希、大小、
schema 和节点上限；只有没有切片 Artifact 的兼容 Finding 才回退到按 seed 查询。

## UI

本地操作台增加以下持久化视图：

- Projects：登记仓库、默认配置和历史 Scan；
- Scan Overview：数据库状态、Snapshot、静态审核和动态验证状态；
- Task DAG：依赖、Attempt、耗时、输入和输出 Artifact；
- Artifacts：metadata、受限预览和内容寻址下载；
- Graph Explorer：只接受半径和节点数有上限的切片；
- Findings：静态证据、源码位置和精确 Graph Slice；
- Reviews：创建、批准或拒绝哈希绑定的静态审核；
- Events：持久化的状态与审计事件。

页面使用轮询刷新。轮询只是传输策略，状态仍来自 Control Store。

## 安全边界

- Web 只能绑定 `127.0.0.1`、`::1` 或等价 loopback 地址，不提供远程认证；
- 路由中的领域 ID 必须是完整 UUID；项目仓库必须是已存在的绝对目录；
- Artifact 下载只使用内容哈希反查并验证大小，HTTP 路径不能指定文件系统路径；
- prompt、credential、secret 和 audit 类 Artifact 禁止预览和下载；
- API 响应递归脱敏 credential/token/key/password、prompt 和 messages 字段；
- Project 默认配置拒绝任何层级的凭据字段；
- Project、Scan 动作、Finding 和 Review 的变更均追加 Event；
- Finding PATCH 只改变静态字段，响应和事件明确标记动态验证未改变；
- M7 不保存或传递 LLM 凭据，也不执行目标网络请求。

## 验收证据

自动化测试覆盖：

- Web/服务重启后的项目、Scan、Task、Artifact、Finding、Review 和 Event 持久性；
- 失效 worker 的 Attempt/Task 恢复；
- UUID、项目配置、Artifact 路径和敏感内容边界；
- Finding 静态审核与动态验证状态分离；
- Finding 到源码位置及精确 Graph Slice Artifact 的跳转；
- HTTP CRUD、DAG/事件/产物/发现资源和内容寻址下载。

此外以真实 loopback Server 和应用内浏览器检查 Projects、Scan Overview、Task DAG、
Findings、Graph Slice 和暗色布局，浏览器控制台无错误。测试使用本地 fixture，
没有运行真实扫描、调用真实 LLM 或发起目标网络请求。

## M8 完成后的边界

- Web 已显示 VerificationRequirement、Environment、Identity、VerificationPlan、
  Policy 和动态 Approval，但静态审核仍不能改变动态状态；
- 没有凭据代理、HTTP Broker 或 PoC 执行；
- business-logic、auth、XSS、SSRF 等仍使用 Legacy Analyzer；
- 外部插件进程隔离和最终安全加固已由 M10 完成；Web 仍不直接加载插件入口。
