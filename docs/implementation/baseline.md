# Argus M0 实现基线

- 记录日期：2026-07-29
- 基线提交：`d8a9858e4da5ac00b6a3d90ee0925a8f418cedca`
- 基线分支：`main`
- Python 环境：`.venv/bin/python` 3.11.15
- 项目版本：`0.1.0`

本文冻结 M0 开始时可观察到的行为。它是迁移对照记录，不替代 `README.md`，
也不把历史文档重新解释为当前任务。

## 未修改代码时的质量基线

实施计划指定的命令在此环境中的结果：

| 命令 | 退出码 | 结果 |
| --- | ---: | --- |
| `python -m pytest` | 127 | shell 中没有名为 `python` 的可执行文件 |
| `python -m ruff check .` | 127 | shell 中没有名为 `python` 的可执行文件 |
| `python -m mypy argus` | 127 | shell 中没有名为 `python` 的可执行文件 |

仓库约定的等价 `uv run` 基线：

| 命令 | 退出码 | 结果 |
| --- | ---: | --- |
| `uv run pytest -q` | 0 | 245 passed, 1 skipped in 1.44s |
| `uv run ruff check .` | 0 | All checks passed |
| `uv run mypy argus` | 0 | 44 个源码文件无类型错误 |

跳过项来自可选运行时依赖测试；它不影响上述通过计数。M0 完成后的结果单独记录在
下节，避免把新增架构测试混入“未修改代码”基线。

## M0 完成验证

新增架构测试后，系统 shell 中的三条原始 `python -m ...` 命令仍因没有
`python` 可执行文件而以 127 退出。使用项目 `.venv` 中的 Python 3.11.15 执行
相同模块命令，结果如下：

| 命令 | 退出码 | 结果 |
| --- | ---: | --- |
| `.venv/bin/python -m pytest` | 0 | 246 passed, 1 skipped in 1.16s |
| `.venv/bin/python -m ruff check .` | 0 | All checks passed |
| `.venv/bin/python -m mypy argus` | 0 | 44 个产品源码文件无类型错误 |

仓库 `AGENTS.md` 的扩展门禁也通过：

| 命令 | 退出码 | 结果 |
| --- | ---: | --- |
| `.venv/bin/ruff check argus evaluation/scripts tests` | 0 | All checks passed |
| `.venv/bin/ruff format --check argus evaluation/scripts tests` | 0 | 91 files already formatted |
| `.venv/bin/mypy argus evaluation/scripts` | 0 | 49 个源码文件无类型错误 |
| `git diff --check` | 0 | 无空白错误 |

## CLI 基线

入口为 `argus = argus.cli:main`。

| 命令 | 当前语义 |
| --- | --- |
| `argus start -r REPO -w WORKSPACE [-c YAML] [--set ...] [--yolo]` | 创建/使用 Workspace，同步执行固定 Pipeline |
| `argus resume -w WORKSPACE [--set ...] [--focus PATH]` | 从已有 LangGraph checkpoint 恢复 |
| `argus continue -w WORKSPACE [--set ...] [--focus PATH]` | 放行人工 interrupt 后继续 |
| `argus stop` | 同步执行模型下的占位命令，不停止常驻 Worker |
| `argus workspaces` | 枚举 `runs/` 下的 Workspace 目录 |
| `argus web [--host 127.0.0.1] [--port 8765] [--runs-root runs]` | 启动仅本机 Web Console |

`start` 不拒绝 CLI 中已存在的 Workspace；README 要求新扫描使用新的名称，Web
入口则显式拒绝已存在目录。

## 默认配置

`argus/config.py` 中的默认值：

```yaml
analyzers:
  enrichment: []
  vuln:
    - authz
checkpoints: true
source_mode: raw
```

配置合并顺序为默认值、YAML 深合并、重复的 `--set` 点路径覆盖。`--yolo`
追加 `checkpoints=false`。`source_mode` 非法时，当前状态构造会回退为 `raw`；
这是需要在后续 V2 配置边界中改为 fail closed 的既有行为，M0 不改变它。

## Pipeline 和状态基线

固定顺序：

```text
build_graph
  → enrichment
  → review-enrichment
  → vuln
  → review-findings
  → report
```

- 节点串行执行，并把名称追加到 `completed_nodes`。
- `build_graph` 在 `graph_db_path` 已存在时直接复用。
- Analyzer 由配置选中；未注册名称被静默跳过。
- enrichment 结果通过浅层 `dict.update()` 合并。
- Finding 追加到共享列表，再由报告层确定性渲染。
- 任一 Analyzer 抛出的异常会记录失败进度并继续向上抛出。
- 两个 Review 节点按 `config.checkpoints` 决定是否 interrupt。
- 人工编辑的 JSON 只有在形状校验通过时才覆盖 checkpoint 内的值；无效编辑保留
  内存状态并记录 warning。

## Workspace 与产物布局

默认布局：

```text
<target>/
└── .codegraph/
    └── codegraph.db

runs/
└── <workspace>/
    ├── state.db
    ├── enriched-graph.json
    ├── findings.json
    ├── report.md
    ├── progress.jsonl
    ├── web-console.log
    └── audit/
        └── llm.jsonl
```

并非所有文件都会在每个阶段存在。`state.db` 是 LangGraph SQLite checkpoint；
`progress.jsonl` 是追加式安全进度事件；Web 通过产物文件、checkpoint 和内存 Job
的组合推断 Workspace 状态。

## Web API 基线

服务器为标准库 `ThreadingHTTPServer`，没有远程认证，并拒绝非 loopback 地址。

GET：

```text
/api/health
/api/dashboard
/api/workspaces
/api/analyzers
/api/findings
/api/settings
/api/workspaces/{workspace}
/api/workspaces/{workspace}/findings
/api/workspaces/{workspace}/report
/api/workspaces/{workspace}/log
/api/workspaces/{workspace}/progress
/api/workspaces/{workspace}/runtime
```

POST：

```text
/api/scans
/api/workspaces/{workspace}/continue
/api/workspaces/{workspace}/resume
/api/workspaces/{workspace}/findings/review
```

`JobManager` 为每个 Workspace 启动一个本地子进程，并仅在当前 Web 进程内保存
PID、return code 和活跃状态。Web 重启后没有持久化 Job 事实来源。

## Contract 基线

- `docs/contracts/interfaces.py` 必须与 `argus/contracts.py` 字节一致。
- `Finding` 是报告和评估共同使用的结构化 V1 对象。
- `AnalysisContext.enriched` 与 Analyzer enrichment 仍是宽泛字典。
- `Analyzer.requires` 已声明，但固定 Pipeline 未消费它。
- `ArgusState` 同时保存路径、配置、累积产物和编排游标。

## 迁移时必须对等验证的行为

- Analyzer 选择和执行顺序；
- enrichment 与 Finding 的业务内容；
- Markdown 报告；
- Review pause、人工编辑、continue 和 resume；
- Analyzer 失败传播；
- `raw`/`stripped` 源码读取及代码位置锚定；
- CLI、Web、进度和审计的既有兼容投影。

## 已知限制

- Codegraph 默认污染目标源码树，且缓存复用键不足。
- `requires` 不参与调度，未知 Analyzer 会静默跳过。
- enrichment 键可能冲突且不能追溯 producer。
- Web Job 状态不跨服务重启持久化。
- Workspace 目录名同时承担用户标识和 checkpoint thread ID。
- `source_mode` 当前存在静默回退。
- 当前人工审核没有 subject hash，也不代表动态验证审批。
- M0 没有 SourceSnapshot、Artifact Store、Control Store、动态 DAG 或 Verification。
