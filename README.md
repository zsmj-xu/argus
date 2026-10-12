# Argus 白盒代码扫描

Argus 是内部部署、API Key 保护的仓库扫描工具。一个项目由 **仓库地址＋分支** 唯一确定，同一仓库的不同分支分别创建项目。

OpenCodeReview 是唯一审查引擎。Argus 管理项目、扫描队列、临时 Git checkout、漏洞去重、人工处理状态和报告，不安装、构建、测试或执行目标仓库。

## 使用流程

1. 创建项目，填写仓库地址、分支、业务背景及可选的包含/排除路径。
2. 确认本次源码披露授权，启动首次全仓分析；Argus 自动记录分支最新 commit。
3. 后续手动触发增量分析，审查最近成功扫描的 commit 到分支最新 commit 的累计差异。
4. 在项目漏洞列表修改处理状态，或查看扫描历史及下载报告。

失败、取消、部分完成都不推进增量起点；重试固定原来的版本，从头执行。没有代码变化时不调用模型。
修改背景或扫描范围会清除增量基线，下次自动全仓扫描。历史分叉或旧 commit 不可获取时，需要手动重新全仓分析。

项目漏洞按文件、类别和归一化证据去重，重复发现不会覆盖人工状态；未再次发现也不自动关闭。
状态包括待处理、处理中、已修复、误报、接受风险。每次扫描保留独立结果和报告；项目报告汇总去重漏洞及人工状态。

本期不提供修复验证、修复记录、断点续传或详细扫描过程展示。页面只展示基本状态及失败原因，后台保留脱敏诊断。

## 启动

复制配置并填写 API Key 和模型配置：

```bash
cp .env.example .env
docker compose up --build -d
```

必需配置：

```dotenv
ARGUS_API_KEY=replace-with-a-long-random-value
ARGUS_LLM_BASE_URL=https://llm.example/v1
ARGUS_LLM_API_KEY=replace-me
ARGUS_LLM_MODEL=model-name
```

页面和 API 默认监听 `127.0.0.1:8000`。API 与 Worker 是独立进程，共享 `ARGUS_DATA_DIR`。
API Key 只保留在浏览器内存，不进入 URL、浏览器持久存储或报告。

扫描没有累计 token 预算，旧的 `OCR_MAX_TOKENS_BUDGET` 不再生效。扫描总执行时限和单文件时限默认关闭，支持手动取消。`OCR_PROCESS_TIMEOUT_SECONDS`、`OCR_TIMEOUT_MINUTES` 为 0 时不限时，正数可显式启用相应时限；单次模型请求和 Git 操作仍有独立的网络超时。

扫描中持续保存模型返回的 token 用量，失败或取消仍保留。页面区分最终已报告用量与可能不完整的中间记录；没有收到用量时显示未知。任务重试累计不同执行的已知用量，缓存命中不重复计入总量。用量事件默认开启，不保存模型原始响应。

全局同时执行一个扫描，其他任务排队。扫描结束后删除源码和临时 OCR session；重启后清理未被进程使用的孤儿目录。本地仓库数量随执行并发控制，不随项目数量增长。
默认工作区容量上限为 1 GiB，源码文件上限为 50,000；Git 历史也受工作区容量约束。空间不足时任务明确失败。

## 公司 GitLab：启动时配置只读 Token

在 `.env` 中配置非敏感信息：

```dotenv
ARGUS_GITLAB_HOST=gitlab.company.example
ARGUS_GITLAB_USERNAME=read-only-user
```

使用只读账号的仓库读取 Token（或项目组 Deploy Token 的 `read_repository` 权限），启动前在 zsh 中隐藏输入：

```zsh
read -rs "ARGUS_GITLAB_TOKEN?GitLab read-only token: "; print
export ARGUS_GITLAB_TOKEN
docker compose -f docker-compose.yml -f docker-compose.gitlab.yml up --build -d
```

Token 通过 secret 只给 Worker；用户名和主机启动时校验，填写相同主机的 HTTPS 仓库地址时自动认证。
Token 不进入 API 容器、请求、数据库、OCR 环境或报告，也不写入 `.env`。重建 Worker 时需再次提供启动环境中的 Token。

先验证仓库和分支读取，不触发扫描：

```bash
docker compose -f docker-compose.yml -f docker-compose.gitlab.yml exec worker \
  argus git-check https://gitlab.company.example/group/project.git --branch main
```

此命令使用与扫描相同的凭据配置，只输出成功或脱敏失败分类。公司私有 CA 需要加入 Worker 信任链，不能关闭证书验证。

## API

所有业务接口要求 `Authorization: Bearer <ARGUS_API_KEY>`。

```bash
curl -X POST http://127.0.0.1:8000/v1/projects \
  -H "Authorization: Bearer $ARGUS_API_KEY" -H 'Content-Type: application/json' \
  -d '{"name":"Example","repository_url":"https://gitlab.company.example/group/project.git","branch":"main","include":["src"]}'

curl -X POST http://127.0.0.1:8000/v1/projects/<project_id>/scans \
  -H "Authorization: Bearer $ARGUS_API_KEY" -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: unique-scan-request' \
  -d '{"mode":"auto","source_disclosure_confirmed":true}'
```

`mode=auto` 根据基线选择首次全仓或后续增量；`mode=full` 强制全仓。每个项目最多一个排队或运行任务。
首次请求返回 202，相同幂等键和请求返回原任务。重试不会获取新的分支版本。

| 接口 | 用途 |
| --- | --- |
| `POST/GET /v1/projects` | 创建项目、分页列表 |
| `GET/PATCH /v1/projects/{id}` | 项目详情、编辑名称/背景/范围 |
| `POST/GET /v1/projects/{id}/scans` | 提交扫描、分页历史 |
| `GET /v1/projects/{id}/vulnerabilities` | 分页漏洞，按状态/风险/类别/标题或路径过滤 |
| `PATCH /v1/projects/{id}/vulnerabilities/{vulnerability_id}` | 修改人工状态 |
| `GET /v1/projects/{id}/report?format=markdown\|json\|sarif` | 项目报告 |
| `GET /v1/scans/{id}`、`/findings`、`/report` | 单次扫描详情、发现与报告 |
| `POST /v1/scans/{id}/cancel`、`/retry` | 取消、从头重试原版本 |
| `GET /v1/scans/{id}/diagnostics`、`/events` | 后台脱敏排障 |
| `GET /healthz`、`/readyz` | 健康与就绪检查 |

原 `POST /v1/scans` 返回 410，提示改用项目扫描接口。
人工状态值为 `open/in_progress/fixed/false_positive/accepted_risk`。

## 开发与验证

```bash
uv sync --extra dev
uv run pytest -q
uv run ruff check argus tests
uv run ruff format --check argus tests
uv run mypy argus
git diff --check
docker compose config -q
cd frontend
pnpm install --frozen-lockfile
pnpm run build
```

真实 OCR 集成测试设置 `ARGUS_OCR_TEST_BINARY`，使用合成 Git 仓库与本地模型 stub，不向外部模型发送源码。
真实公司仓库扫描必须另行明确仓库/范围和目标模型的披露授权。

固定引擎版本及结果合同见 [OCR 集成](docs/integration/ocr-v1.md)。公开靶场评测记录保存在 [评测目录](docs/evaluations/)，历史局部扫描只作参考。
