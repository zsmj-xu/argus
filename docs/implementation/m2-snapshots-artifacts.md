# M2：SourceSnapshot 与 Artifact Store

状态：已实现，并通过 legacy Pipeline 兼容入口接管新扫描的源码路径。

## 运行路径

`argus start` 的新顺序是：

```text
load config
  → create/reuse Project
  → create Scan + legacy compatibility Tasks
  → materialize SourceSnapshot
  → register snapshot manifest Artifact
  → optionally restore exact graph cache
  → invoke unchanged legacy Pipeline on snapshot/source
  → register graph/enrichment/findings/report Artifacts
```

旧 Pipeline 的节点、Analyzer Contract、人工检查点和 Workspace 文件格式没有重写。
传给 `make_initial_state()` 的 `repo_path` 现在是物化快照，不是原始工作树。

## SourceSnapshot

物化布局：

```text
runs/_data/snapshots/<snapshot-id>/
├── snapshot-manifest.json
└── source/
```

Manifest 对每个纳入扫描的目录、文件和安全 symlink 记录：

- 相对路径；
- 类型；
- 大小；
- SHA-256；
- 文件模式；
- symlink target（仅 symlink）。

`tree_hash` 由规范化 Manifest entries 计算，不包含绝对源码路径或随机 Snapshot ID，
因此相同内容产生相同 hash。创建期间会在复制前后各构建一次 Manifest，并对每个复制
文件复核大小和 hash；期间增加、删除或修改源码都会使创建失败并清理未完成快照。

Git 仓库额外记录 HEAD commit 和创建前的 dirty 状态。非 Git 目录记录为
`vcs_type=directory`。

默认忽略：

- `.git/`、`.codegraph/`；
- 配置的 `runs_root`（当它位于目标仓库内）；
- `.venv/`、`venv/`、`node_modules/`、`build/`、`dist/`；
- Python、pytest、mypy、Ruff、tox、nox 等常见缓存。

配置可通过 `source.ignore` 增加路径或 glob。指向仓库外部的 symlink 会 fail closed，
不会把外部文件意外纳入快照。

## Artifact Store

内容布局：

```text
runs/_data/artifacts/sha256/ab/<full-sha256>/payload
```

数据库保存的 URI 为：

```text
artifact://sha256/<full-sha256>
```

URI 不暴露本地路径。Artifact Store 支持：

- canonical JSON；
- canonical JSONL；
- UTF-8 text；
- SQLite；
- 任意 binary/file。

写入过程使用同文件系统临时文件、flush、`fsync` 和 `os.replace`。相同内容只保存一份
payload，但每次发布都创建独立 Artifact metadata。读取和物化前必须同时验证文件
存在、SHA-256 和记录的大小，不一致抛 `ArtifactCorruptionError`。

插件和上层服务通过 `ArtifactStore.open_read()`、`ArtifactView` 或
`ArtifactPublisher` 使用 payload，不通过数据库 URI 拼接文件系统路径。

## Control Store

`0002_source_snapshots` migration 新增 `source_snapshots` 表。SourceSnapshot 包含：

- Project、原始 repository path；
- Git/directory 身份；
- commit、dirty、tree hash；
- snapshot source path；
- manifest Artifact ID；
- UTC 创建时间。

每个 legacy Scan 预建五个兼容 Task：

1. SourceSnapshot；
2. Codegraph；
3. enrichment aggregate；
4. findings aggregate；
5. Markdown report。

Workspace 的 `control-link.json` 只保存 V1 checkpoint 与 V2 ID 的本地关联，不保存
源码、凭据或模型内容。`continue`/`resume` 通过它继续向同一 Scan 注册产物。

## Graph 缓存

跨扫描图复用键是以下字段的规范化 SHA-256：

```text
snapshot tree hash
codegraph provider ID
exact provider binary SHA-256
provider config hash
```

只有四项全部一致才会从 Artifact Store 验证并物化
`source/.codegraph/codegraph.db`。源码、provider binary 或 provider config 任一变化
都会重新建图。损坏的缓存不会静默回退为重建，而是 fail closed。

## 人工检查点与恢复

- 第一个检查点前注册 manifest、graph 和 enrichment；
- 第二个检查点前增加 findings；
- 完成后增加 report；
- 审核时更新 `focus` 或 Analyzer 配置会同步到尚未运行 Task 的 config hash；
- graph 已完成后不允许修改 `source` 或 `codegraph` 配置；
- legacy Analyzer 中断时，已经完成的 Artifact 仍会注册，并记录
  `scan.legacy_interrupted`；旧 checkpoint 仍可 `resume`。

M4 之前 Control Store 尚无正式的 `INTERRUPTED/FAILED_RETRYABLE` 状态，因此 legacy
中断时 Scan 暂时保持 RUNNING 以保留现有恢复语义；这不是持久化 Executor 的最终状态机。

## 兼容与安全边界

- 旧 Workspace JSON/Markdown 文件继续生成并供人工编辑/查看。
- 旧 `state.db` 仍由 LangGraph 管理。
- 旧 Analyzer、Finding 和报告渲染器不变。
- 报告和代码位置现在锚向冻结快照，保证审核看到的是实际分析版本。
- 新扫描不会在原仓库创建 `.codegraph`。
- M2 不执行真实网络验证，也不增加 PoC、浏览器、Shell 或凭据能力。

## M3 前的限制

- 任务仍由 legacy 兼容入口预建，不是 Capability Planner 编译的 DAG。
- SourceSnapshot 关系由 Service 保证；M1 的 `scans.snapshot_id` 和
  `artifacts.snapshot_id` 尚未通过 SQLite 外键重建。
- Artifact GC、备份和外部插件隔离尚未实现。
- Control Store 尚未成为 Web Job 状态事实来源。
- Codegraph 仍会在快照内部生成 `.codegraph`；图随后复制为独立 Artifact。
