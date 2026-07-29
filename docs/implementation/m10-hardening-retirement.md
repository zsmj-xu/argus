# M10：插件隔离、审计加固与 Legacy 退场准备

状态：已实现。本里程碑完成 V2 默认路径的运行时加固并将 Legacy 标记为 deprecated；
固定 Pipeline 的物理删除按计划留给后续独立 PR。

## 插件进程边界

默认和内置 Manifest 均使用 `runtime.isolation: process`。Executor 通过
JSON-RPC/stdio 启动独立 Python worker，请求只包含领域 ID、Artifact metadata 和
content hash；不向插件传递调用方提供的任意文件路径。worker 从受控 Artifact Store
读取输入，在独立临时目录写输出，父进程重新验证 reference、路径、大小、SHA-256、
JSON schema 和 Canonical Finding 后才发布 Artifact。

Manifest 的 `PermissionSpec` 控制 source、network、subprocess 和 secrets：

- 默认无网络、无 secret、无 subprocess、不可读 SourceSnapshot；
- `source: read` 只开放当前只读快照；
- `network: llm` 和 `secrets: llm` 只授予内置、已注册的 LLM 插件；
- external plugin 强制进程隔离，且不能申请 network、secret 或 subprocess；
- `subprocess: restricted` 只允许图插件调用固定的 `codegraph` 可执行文件；
- worker 使用清理后的环境、独立临时目录、超时、内存、CPU、文件和输出上限；
- 超时或输出溢出终止整个 worker 进程组。

Python audit hook 和 API 封锁为文件、网络及子进程策略提供跨平台强制。它不是针对
恶意原生扩展的完整容器沙箱；部署不应把能加载任意 native code 的外部插件视为
不可信租户。external plugin 的高权限请求因此默认拒绝，进一步的 OS sandbox/
container 隔离属于部署加固项。

## 审计和脱敏

LLM 审计级别为 `metadata|redacted|full`，默认 `redacted`：

- metadata：只保留字符数和调用 metadata；
- redacted：增加内容 SHA-256，不保存正文；
- full：只有显式配置时保存 system、prompt 和 response。

base URL 审计只保留 scheme/host/port，移除 userinfo、path 和 query。Event payload 对 credential、token、cookie、
authorization、prompt 等敏感键递归替换为不可逆 marker；持久化 Task/Scan 错误只保存
异常类型和通用安全摘要。worker 也拒绝把注入环境的 secret 写入输出 Artifact。

## 配置、备份、GC 和导出

核心配置通过 Pydantic 校验。`source_mode`、`source.mode`、`analysisMode`、
`llm.auditLevel`、verification 布尔值、engine 和 external plugin 开关非法时立即失败。

运维入口：

```bash
argus control-backup --output backups/control-20260729.db
argus artifact-gc
argus artifact-gc --apply
argus findings-export --scan-id <uuid> --format json --output findings.json
argus findings-export --scan-id <uuid> --format sarif --output findings.sarif
argus performance-baseline --scan-id <uuid>
```

备份使用 SQLite online backup，拒绝覆盖已有目标。GC 默认 dry-run；`--apply` 也不删除，
而是把超过最小年龄且 Control Store 未引用的 blob 移入
`runs/_data/artifacts/.trash/<timestamp>/`。恢复和最终清理由运维人员显式完成。
JSON/SARIF 都只从 `StaticFindingV2` 生成并按 fingerprint 排序。

性能基线汇总快照阶段、图任务时间、Candidate 数、LLM 调用/token、Task attempt/resume
以及 Control Store 查询耗时。它用于版本间回归比较，不自动改变执行策略。

## Legacy 退场边界

`argus scan` 继续默认 V2。显式 `--engine legacy` 会输出 deprecated 警告；
`argus start/continue/resume` 暂时保留迁移窗口。删除固定 LangGraph Pipeline 必须是
后续独立 PR，并且只有在以下证据持续通过后进行：

1. V1/V2 对等、恢复、Review 和确定性报告测试；
2. 插件隔离、无网络、secret 脱敏和故障注入测试；
3. Control Store 迁移升级、备份恢复和 Artifact GC 演练；
4. V2 Web、Finding、Graph Slice 和 Verification 测试；
5. 下游用户已迁移，不再依赖 Workspace 推断或 `state.db`。

删除 PR 不得同时改变 Finding contract、审批语义或网络验证边界。
