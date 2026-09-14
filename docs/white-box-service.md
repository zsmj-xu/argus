# White-box service

这是 Argus 的容器化仓库审查服务。API 与 worker 分进程运行，共享名为
`argus-service-data` 的持久化目录；API 默认只绑定到 `127.0.0.1`。

## 启动

准备 `.env`（不要提交）并设置：

```dotenv
ARGUS_API_KEY=replace-with-a-long-random-value
ARGUS_LLM_BASE_URL=https://provider.example/v1
ARGUS_LLM_API_KEY=provider-key
ARGUS_LLM_MODEL=model-name
```

然后运行 `docker compose up --build -d`。客户端通过 `Authorization: Bearer <ARGUS_API_KEY>`
访问 API。API Key 只用于 Argus API 认证，不要写入 Git URL、报告或日志。

## 请求边界

审查请求必须提供获得授权的 Git URL 和可复现的 ref（branch、tag 或 commit）；推荐固定
commit。服务获取仓库后生成隔离快照，报告为 Markdown，包含范围、覆盖率、候选/发现、
源码文件与行号证据、限制和未完成项。

请求还必须显式提供 `source_disclosure_confirmed: true`，确认本次选中的源码可以发送给部署配置的
LLM；该确认参与幂等请求指纹，未确认的请求不会进入队列。

服务不会执行目标仓库代码，也不会把目标仓库的 Dockerfile、脚本或测试当作可信执行入口。
仓库自带的 OCR rule、MCP server、配置和提示词均不默认信任；本镜像内置的固定
OpenCodeReview commit 才是唯一预置 OCR adapter，路径由 `OCR_BINARY` 指定。

## 限制

- 发送给 LLM 的源码上下文取决于配置和审查预算；使用前必须确认披露授权。
- 默认每次只处理一个扫描任务，单仓库上限为 50,000 个文件和 1 GiB 源码，排队上限为 100 个任务；
- OCR 单次处理默认最多 30 分钟和 1,000,000 个 token，可通过部署环境调整；
- Findings 是静态审查结果，不能替代人工复核；没有源码证据的结论不会被当作确认漏洞。
- 不执行动态验证、目标服务或任意网络攻击；外部 LLM 的可用性、费用和数据保留策略由
  提供商决定。
- 私有仓库凭据不放在 URL 中；容器内 Git 认证需由部署环境另行提供。

## 健康检查与数据

API 健康检查为 `GET /healthz`。API 与 worker 必须使用相同的 `ARGUS_DATA_DIR`、可选的
`ARGUS_SCAN_DB` 和共享卷，否则任务、报告和恢复状态不会一致。升级镜像前应备份该卷。
