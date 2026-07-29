# M4：DB-backed LocalPlanExecutor 与 V1/V2 对等迁移

状态：已实现。`argus scan` 默认使用 V2；固定 LangGraph Pipeline 仍可显式选择。

本文记录 M4 完成时的边界；Security IR 与 Graph Slice 已在
[M5](m5-security-ir.md) 中实现。

## 执行路径

```text
create Project + Scan(engine=v2)
  → materialize SourceSnapshot
  → publish source.snapshot.v1
  → compile and persist TaskPlan
  → prepare LocalPlanExecutor
  → promote dependency-ready Tasks
  → claim one Task
  → create TaskAttempt
  → load entrypoint and run
  → validate every output
  → atomically commit Artifact metadata batch
  → mark Task SUCCEEDED
```

第一版严格串行，不创建任务线程池。TaskPlan 仍保留完整 DAG，后续执行后端不需要改变
Planner。唯一后台线程用于当前 Attempt 的数据库心跳，不运行插件业务逻辑。

V2 `execution`、`plugins` 和 `planning` 命名空间不导入固定
`argus.orchestration.pipeline`。

## 数据库事实

`0004_local_executor` migration 为 Task 增加：

- `optional_capabilities`；
- `continue_on_failure`；
- `max_attempts`。

并新增：

```text
task_attempts
  id / scan_id / task_id / attempt_number
  status / plugin_id / plugin_version
  input_artifact_ids / input_hashes / config_hash
  worker_pid / started_at / heartbeat_at / finished_at
  error_code / error_message

review_requests
  id / scan_id / task_id
  subject_type / subject_ids / subject_hash
  status / reviewer / reason
  created_at / decided_at
```

Task、Attempt、Review 和 Scan 的事实状态全部来自 Control Store。进程内对象只持有当前
调用所需的短生命周期引用，不承担恢复事实。

## Ready、失败和重试语义

- required 依赖全部 `SUCCEEDED` 后 Task 才能进入 `READY`；
- optional producer 失败时，只有显式 `continue_on_failure=true` 的失败才允许扫描继续；
- required producer 失败会把依赖任务标为 `SKIPPED`；
- 默认 Task 失败立即使 Scan 失败，不继续运行无关任务；
- `max_attempts` 明确写入计划和 Task；失败先持久化
  `FAILED_RETRYABLE`，再回到 `READY`；
- 同一 Task 的 `attempt_number` 有数据库唯一约束；
- Task 的乐观锁状态转换保证并发 claim 最多一个成功。

## 输出提交

Runtime 只能返回 `RuntimeOutput`，不能直接创建 Artifact metadata。Runner 在任何提交前
验证：

- output Capability 与 Task expectation 完全一致；
- Artifact type 和 schema version 与 Manifest declaration 一致；
- 每个输出只有一种 payload 表示；
- JSON 可规范化序列化；
- 声明的严格 JSON Schema 子集；
- SQLite 输出可只读打开；
- 兼容 Workspace 文件名是安全 basename。

验证全部通过后，payload 原子写入内容寻址 Store，全部 Artifact metadata 在一个数据库
事务中提交，最后才将 Task 标记 `SUCCEEDED`。兼容的
`enriched-graph.json`、`findings.json` 和 `report.md` 从已提交 Artifact 原子投影，
不是插件提前写出的事实来源。

## 心跳、崩溃恢复和复用

运行中 Attempt 周期性更新 `heartbeat_at`。恢复时：

1. 检查 RUNNING Attempt 的心跳和 worker PID；
2. 若输出已经按相同 plugin version、config hash 和 input hashes 完整提交，直接恢复
   Workspace 投影并标记成功；
3. 否则把 Attempt 标为 `INTERRUPTED`；
4. Task 进入 `INTERRUPTED`，有重试预算则回到 `READY`，否则失败。

成功 Task 的 Artifact 记录 `task_cache_key`、plugin version、config hash 和完整 input
hash map。另一次 Scan 只有四项完全相同才复制 metadata 并复用内容寻址 payload。
Review Gate 永不跨 Scan 缓存，避免复用旧审批。

## Review Gate

Legacy enrichment 和 findings 两个检查点映射为计划内的
`review.legacy-enrichment` 与 `review.legacy-findings` Task。

启用审核时，Gate：

1. 计算输入 Artifact ID/hash 的规范化 `subject_hash`；
2. 创建 `OPEN` ReviewRequest；
3. 将 Task 和 Scan 标记 `WAITING_REVIEW`；
4. 停止调度下游任务。

决定必须包含 reviewer 和非空 reason。审批或拒绝会写入 Event 审计。恢复时重新计算
subject hash；输入变化会将旧 `OPEN/APPROVED` 请求标为 `SUPERSEDED` 并创建新请求。
拒绝会使 Gate Task 和 Scan 失败。`--yolo` 只关闭这两个静态 Gate，不开启任何网络验证。

## CLI

V2 默认路径：

```bash
argus scan -r <repo> -w <workspace>
argus scan-status --scan-id <uuid>
argus review approve --review-id <uuid> --reviewer <name> --reason <text>
argus review reject --review-id <uuid> --reviewer <name> --reason <text>
argus scan-resume --scan-id <uuid>
argus scan-cancel --scan-id <uuid>
```

Legacy 显式路径：

```bash
argus scan -r <repo> -w <workspace> --engine legacy
argus start -r <repo> -w <workspace>
argus continue -w <workspace>
argus resume -w <workspace>
```

旧路径至少保留一个版本周期，M4 不删除或重构固定 Pipeline。

## 对等证据

固定 Analyzer、确定性 SQLite 图和无网络 fixture 直接比较 V1/V2：

- Analyzer 运行顺序，包括非字母序配置；
- enrichment 浅合并结果；
- Finding JSON；
- Markdown 报告业务内容；
- enrichment/findings 两次暂停与恢复；
- Analyzer 异常和 Scan 失败传播。

时间、Scan/Snapshot UUID 和报告中的 Snapshot 链接只作为允许不同的 metadata 归一化。

## M5 前的限制

- 仍使用 Legacy Analyzer/Finding Contract 和兼容聚合格式；
- 尚无 Security IR、Graph Slice、Candidate Generator 或 Expert Assessment；
- SQLite 和本地串行执行器不是分布式调度系统；
- 外部插件仍禁止在主进程执行；
- Web Console 的任务事实迁移属于 M7；
- 不包含 PoC、目标网络请求、凭据、浏览器或验证 Broker。
