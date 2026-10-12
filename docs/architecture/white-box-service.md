# White-box service architecture

```text
Project (Git URL + branch) + API Key + disclosure confirmation
          |
          v
       API :8000  ---- shared service data ----  worker
          |                                      |
          +---------- Markdown report <----------+
                               |
                       fixed OCR adapter
                  first: scan / next: review A -> B
                    /usr/local/bin/ocr (pinned commit)
```

## 构建与运行

Dockerfile 有四个阶段：Go builder 从 `zsmj-xu/open-code-review` 的固定 commit
`16f10f1efeb69d6f3cd2391511e225ad54809e2e` 构建 OCR；前端 builder 编译 React；Python builder 安装 Argus 与 Uvicorn；runtime
只保留 Python 服务、Git、证书和 OCR 可执行文件。运行时以非 root 用户启动。

Compose 将 API 和 worker 分开，二者共享新的 `argus-service-data` named volume。API 通过
`argus.service.app:create_app` 工厂启动；worker 调用 `argus.service.worker:main`。
`OCR_BINARY` 是 adapter 的唯一可执行文件配置点。

SQLite 保存 projects、scans、单次 findings 和去重 vulnerabilities。项目身份为仓库＋分支，人工漏洞状态独立于扫描结果。
成功扫描以事务更新漏洞和基线；失败、取消或部分完成不推进基线。历史分叉必须重新全仓扫描。
Worker 获取跨进程执行锁，Git/OCR 子进程继承锁；只有没有任务使用时才清理孤儿 checkout。源码和 OCR session 不长期保存。

## 信任与安全边界

服务是 white-box review：读取仓库内容并形成静态证据，不执行目标代码。Git URL/ref 是
外部输入，必须由调用者确认授权；API 请求必须明确确认源码披露，URL 中禁止携带凭据。LLM 配置通过环境变量注入，API
Key 不进入源码、命令行参数或报告。

仓库中的 OCR rule、MCP server、hooks、配置文件和提示词属于不受信任输入，不会默认启用或
执行。内置 OCR 版本由镜像构建时的 ref 与完整 commit 双重固定；变更版本必须修改构建参数并
重新审阅。

## 输出合同

全仓采用 `ocr.scan-result/v1`，增量采用 `ocr.run-manifest/v1`，校验输入 commit 和覆盖分区。
报告支持 Markdown、JSON、SARIF，保留审查范围、分支、起止 commit、覆盖/延后原因、每个结论的文件和行号
证据、风险说明、修复建议及“未执行目标代码/动态验证”的限制声明。部分覆盖必须明确标记，
不能伪装成完整扫描。
