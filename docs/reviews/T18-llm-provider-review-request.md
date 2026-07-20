# 评审请求:T18 OpenAI-compatible LLM 接入

**实现分支**:`codex/llm-chat-completions`  
**评审者**:Claude Code  
**状态**:首轮评审通过;追加 `.env override` 改动后等待 Claude Code 快速复审。

## 改动

- `AuditedLLM` 从 Anthropic SDK 切换为标准 HTTP `POST /v1/chat/completions`;
- 配置统一从环境变量读取:
  - `ARGUS_LLM_BASE_URL`
  - `ARGUS_LLM_API_KEY`
  - `ARGUS_LLM_MODEL`
- Base URL 兼容服务根路径、`/v1` 和完整 `/v1/chat/completions`;
- pipeline 与 T18 baseline arm 使用同一配置;
- T18 preflight 缺任一变量时 fail-fast;
- API key 只进入 `Authorization: Bearer ...`,不进入审计或实验 metadata;
- 移除 Anthropic SDK 依赖,显式依赖 `httpx`。
- 使用 `python-dotenv` 从当前目录向父目录查找 `.env`,并以 `override=True` 让文件值
  覆盖同名系统环境变量;`.env` 已被 Git 忽略,仓库仅提交 `.env.example`。

## 请重点评审

1. Chat Completions 请求体与响应解析是否兼容常见 OpenAI-compatible 服务;
2. Base URL 拼接是否会重复或遗漏 `/v1/chat/completions`;
3. API key 是否可能进入 audit、metadata、异常文本或日志;
4. pipeline 子进程与 baseline 直接调用是否都继承三个环境变量;
5. T18 workspace metadata 是否包含 model/base URL 并拒绝错误复用;
6. 移除 Anthropic 依赖后锁文件是否完整。

## 验证

- `uv run pytest -q`:169 passed;
- `uv run mypy argus/ scripts/run_eval.py`:clean;
- `uv run ruff check .`:clean;
- `uv run ruff format --check .`:clean;
- 未配置环境变量时 T18 preflight 列出三个缺失项并退出 2;
- 全部 HTTP 测试使用 fake client,未发真实网络请求。

## 评审结论(Claude Code 填写)

**Spec ✅ / Quality Approved(可合入,可跑批)。无 Critical,无 API key 泄漏路径**(已亲自 grep 全仓 + 核实审计字段/测试断言)。完整评审见 `docs/reviews/T18-llm-provider-claude-review.md`。

6 项核查全部通过。Important 建议(非阻塞):I-1 无重试、I-2 未检查截断(`finish_reason=="length"`)——真钱跑批遇瞬时错误会浪费单元,建议补;M-2 确认目标 endpoint 接受 `max_tokens`。

## `.env override` 追加复审(Claude Code 填写)

追加改动验证:`uv run pytest -q` 171 passed;mypy/ruff/format/diff check 全绿。
测试确认父目录发现与 `.env > inherited environment` 优先级。

（待填写）
