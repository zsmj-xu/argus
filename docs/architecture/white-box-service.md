# White-box service architecture

```text
Git URL + ref + API Key + disclosure confirmation
          |
          v
       API :8000  ---- shared service data ----  worker
          |                                      |
          +---------- Markdown report <----------+
                               |
                       fixed OCR adapter
                    /usr/local/bin/ocr (fixed main commit)
```

## 构建与运行

Dockerfile 有三个阶段：Go builder 从 `alibaba/open-code-review` 的固定 main commit
`1f5caf4d5b7d5324c6e4c836c971136e4010192e` 构建 OCR；Python builder 安装 Argus 与 Uvicorn；runtime
只保留 Python 服务、Git、证书和 OCR 可执行文件。运行时以非 root 用户启动。

Compose 将 API 和 worker 分开，二者共享新的 `argus-service-data` named volume。API 通过
`argus.service.app:create_app` 工厂启动；worker 调用 `argus.service.worker:main`。
`OCR_BINARY` 是 adapter 的唯一可执行文件配置点。

## 信任与安全边界

服务是 white-box review：读取仓库内容并形成静态证据，不执行目标代码。Git URL/ref 是
外部输入，必须由调用者确认授权；API 请求必须明确确认源码披露，URL 中禁止携带凭据。LLM 配置通过环境变量注入，API
Key 不进入源码、命令行参数或报告。

仓库中的 OCR rule、MCP server、hooks、配置文件和提示词属于不受信任输入，不会默认启用或
执行。内置 OCR 版本由镜像构建时的 ref 与完整 commit 双重固定；变更版本必须修改构建参数并
重新审阅。

## 输出合同

报告使用 Markdown，至少保留审查范围、Git ref、覆盖/延后原因、每个结论的文件和行号
证据、风险说明、修复建议及“未执行目标代码/动态验证”的限制声明。部分覆盖必须明确标记，
不能伪装成完整扫描。
