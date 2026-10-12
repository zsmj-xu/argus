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

项目由获得授权的 Git URL 和分支唯一确定；用户不选择 commit，Worker 自动获取并记录
分支最新 commit。首次全仓扫描，后续从上次成功 commit 到最新 commit 累计增量审查。报告包含范围、覆盖率、发现、
源码文件与行号证据、限制和未完成项。

请求还必须显式提供 `source_disclosure_confirmed: true`，确认本次选中的源码可以发送给部署配置的
LLM；该确认参与幂等请求指纹，未确认的请求不会进入队列。

服务不会执行目标仓库代码，也不会把目标仓库的 Dockerfile、脚本或测试当作可信执行入口。
仓库自带的 OCR rule、MCP server、配置和提示词均不默认信任；本镜像内置的固定
OpenCodeReview commit 才是唯一预置 OCR adapter，路径由 `OCR_BINARY` 指定。

## 限制

- 发送给 LLM 的源码上下文取决于项目配置；使用前必须确认披露授权。
- 默认每次只处理一个扫描任务，单仓库上限为 50,000 个文件和 1 GiB 源码，排队上限为 100 个任务；
- OCR 无累计 token 预算；总执行时限和单文件时限默认关闭（部署变量为 0），保留手动取消和独立网络操作超时；
- Findings 是静态审查结果，不能替代人工复核；没有源码证据的结论不会被当作确认漏洞。
- 不执行动态验证、目标服务或任意网络攻击；外部 LLM 的可用性、费用和数据保留策略由
  提供商决定。
- 私有仓库凭据不放在 URL 中；GitLab 通过 Worker 专用 secret 和主机匹配 helper 自动认证，配置见 README。

项目漏洞合并去重，人工处理状态不会被扫描覆盖。失败/部分完成不推进基线；重试从头执行原来的版本。
源码与临时 OCR HOME 在结束后清理，跨进程锁限制全局同时一个 checkout，并保护重启后的孤儿目录清理。

## 控制台结果展示

项目扫描历史和漏洞列表支持分页，筛选结果以接口返回的 total 为准。漏洞详情展示问题说明、
源码位置、证据和修复建议；空字段显示明确空状态。界面不翻译源码或路径，处理状态由人工修改。
扫描详情的 token 数量区分最终已报告用量、可能不完整的已记录用量与未知值；失败不抹去已记录消耗。

## 健康检查与数据

API 健康检查为 `GET /healthz`。API 与 worker 必须使用相同的 `ARGUS_DATA_DIR`、可选的
`ARGUS_SCAN_DB` 和共享卷，否则任务、报告和恢复状态不会一致。升级镜像前应备份该卷。
