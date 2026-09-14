# Argus White-box Scan Service

Argus 是一个内部部署的白盒代码扫描服务。调用方提交 Git 仓库地址和 ref，服务在一次性隔离 checkout 中运行固定版本的 OpenCodeReview 全文件扫描，然后提供带文件和行号的静态发现、Markdown、JSON 与 SARIF 报告。

OpenCodeReview 是唯一的源码审查引擎；Argus 提供 API Key、任务队列、Git 获取、Worker、持久化、覆盖状态和简洁网页。服务不会执行目标仓库的安装、构建、测试、Dockerfile、脚本或动态验证。

## 启动

复制环境文件并设置 API Key 与 LLM：

```bash
cp .env.example .env
docker compose up --build -d
```

API 默认监听 `127.0.0.1:8000`。内网反向代理或受控网络入口可以通过 `ARGUS_BIND` 暴露它。

必需配置：

```dotenv
ARGUS_API_KEY=replace-with-a-long-random-value
ARGUS_LLM_BASE_URL=https://llm.example/v1
ARGUS_LLM_API_KEY=replace-me
ARGUS_LLM_MODEL=model-name
```

API 请求使用：

```text
Authorization: Bearer <ARGUS_API_KEY>
```

健康检查不需要 API Key：`GET /healthz`；就绪检查为 `GET /readyz`。

## 扫描 API

提交一次全仓库扫描：

```bash
curl -X POST http://127.0.0.1:8000/v1/scans \
  -H "Authorization: Bearer $ARGUS_API_KEY" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: project-main-20260914' \
  -d '{
    "repository_url": "https://github.com/example/project.git",
    "ref": "main",
    "include": ["src"],
    "exclude": ["**/generated/*", "vendor"],
    "background": "重点审查认证、授权和输入处理",
    "source_disclosure_confirmed": true
  }'
```

`source_disclosure_confirmed` 必须明确设为 `true`，表示调用方已获准将这次扫描选中的源码发送给配置的 LLM。

查询扫描：

```bash
curl -H "Authorization: Bearer $ARGUS_API_KEY" \
  http://127.0.0.1:8000/v1/scans/<scan_id>

curl -H "Authorization: Bearer $ARGUS_API_KEY" \
  http://127.0.0.1:8000/v1/scans/<scan_id>/findings

curl -H "Authorization: Bearer $ARGUS_API_KEY" \
  'http://127.0.0.1:8000/v1/scans/<scan_id>/report?format=markdown' \
  -o report.md
```

可用接口：

- `POST /v1/scans`：提交扫描，返回 `202`；相同 `Idempotency-Key` 会复用原任务；
- `GET /v1/scans`：查看扫描列表；
- `GET /v1/scans/{id}`：查看状态、commit、阶段、覆盖率和错误；
- `GET /v1/scans/{id}/findings`：查看静态发现；
- `GET /v1/scans/{id}/report?format=json|markdown|sarif`：下载报告；
- `POST /v1/scans/{id}/cancel`：取消排队或执行中的任务；
- `POST /v1/scans/{id}/retry`：重试失败、部分完成、取消或跳过的任务。

状态包括 `queued`、`running`、`completed`、`partial`、`failed`、`canceled` 和 `skipped`。部分覆盖会明确记录原因，不会被报告为完整扫描。

## 输入与安全边界

- Git URL 支持 HTTPS、SSH、Git 和 SCP 风格地址；URL 不允许嵌入用户名密码或 Token；
- 私有仓库凭据由部署环境的 Git Credential Helper 或 SSH Agent 提供，不由 API 请求提交；
- 每次扫描使用独立临时 checkout，扫描完成后清理源码目录；
- 分支或 tag 在第一次获取时解析为 commit，重试使用已记录的 commit；
- 仓库中的 `.opencodereview` 配置会被移除；仓库自带规则、MCP、hooks 和提示词不会被信任；
- LLM 配置只通过容器环境变量传入，API Key、LLM Key 和 Git 凭据不会写入数据库或报告；
- 每次请求必须显式确认源码披露授权；确认字段也参与幂等请求指纹；
- 扫描结果是静态审查发现，不能表述为动态确认漏洞；没有可靠位置的评论不会伪造行号。

## 目录

```text
argus/
  cli.py                 API/Worker 命令入口
  ocr_adapter.py         OpenCodeReview 进程和 JSON 适配
  repositories.py        Git URL 校验
  service/
    app.py               FastAPI 与简洁网页
    models.py            API、队列和发现合同
    store.py             SQLite 持久化队列
    worker.py            独立 Worker
    integration.py       Git checkout 与 OCR 结果归一化
    reports.py           Markdown、JSON、SARIF
```

OpenCodeReview 的固定构建版本、Compose 配置和部署限制见
[白盒服务文档](docs/white-box-service.md) 与
[服务架构](docs/architecture/white-box-service.md)。
