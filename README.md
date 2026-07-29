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

然后打开 `http://127.0.0.1:8765`。操作台会读取 `runs/` 下的真实工作区，
展示发现和报告，并可在后台创建、继续或恢复扫描。新建扫描前必须确认你有权
向当前配置的 LLM 披露所选源码上下文。Web Console 没有远程认证，因此拒绝
绑定到非 loopback 地址。

## 运行扫描

从存储库根目录运行命令，为每个新扫描使用新的工作区名称：

```bash
uv run argus start \
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
uv run argus start \
  -r /absolute/path/to/target \
  -w my-project-full-001 \
  --yolo \
  --set 'source_mode=stripped' \
  --set 'analyzers.enrichment=["business-flow","invariant"]' \
  --set 'analyzers.vuln=["auth","authz","injection","xss","ssrf","business-logic"]' \
  --set 'strict_outputs=true' \
  --set 'business-flow.batch_size=8' \
  --set 'authz.batch_size=8'
```

### 高级参数说明

**分析器配置：**
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

省略 `--yolo` 以在审查检查点停止。继续或恢复运行：

```bash
uv run argus continue -w my-project-authz-001
uv run argus continue -w my-project-authz-001 --focus src/orders
uv run argus resume -w my-project-authz-001
uv run argus workspaces
```

### 运行管理命令

- `argus continue -w <workspace>`：在上次审查检查点之后继续运行
- `argus continue -w <workspace> --focus <path>`：在指定目录继续扫描（进行增量分析）
- `argus resume -w <workspace>`：从上次中断处恢复（保留所有状态）
- `argus workspaces`：列出所有已有的工作区

每次扫描都会创建 `target/.codegraph/` 并在 `runs/<workspace>/` 下写入自己的工作区：

- `report.md`：人类可读的报告
- `findings.json`：结构化发现
- `enriched-graph.json`：代码富化输出
- `state.db`：检查点状态

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

## 开发检查

```bash
uv run pytest -q
uv run ruff check argus evaluation/scripts tests
uv run ruff format --check argus evaluation/scripts tests
uv run mypy argus evaluation/scripts
git diff --check
```
