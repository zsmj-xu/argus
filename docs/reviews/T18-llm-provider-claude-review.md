# 评审:T18 OpenAI-compatible LLM 接入(Codex 实现,Claude Code 正式交叉评审)

**实现者**:Codex(提交 `1f5a444`,已在 main)
**评审者**:Claude Code(正式独立交叉评审)
**评审方式**:main 只读通读 `client.py` / `pipeline.py` / `run_eval.py` / `audit.py` / 测试;独立跑全门禁 + preflight;对最高优先项(API key 泄漏面)亲自 grep 全仓追查每处去向 + 核实审计记录字段与测试断言。

---

## 评审裁决

- **Spec:✅ 满足** —— 6 项改动目标全部达成(Anthropic SDK → HTTP chat-completions、三环境变量、base URL 兼容、pipeline/baseline 同源配置、preflight fail-fast、key 只进 Authorization)。
- **Quality:Approved(可合入 / 可跑批)** —— 无 Critical,**无 API key 泄漏路径**(已亲自核实)。若干 Important/Minor 健壮性建议多为从旧 Anthropic 客户端继承的既有缺口,非本次引入。

### 独立验证(在 main 实跑)
- `pytest tests/test_llm.py tests/eval/test_run_eval.py`:10 passed
- `pytest` 全量:169 passed
- `mypy argus/ scripts/run_eval.py`:clean
- `ruff check`:clean
- 无环境变量时 preflight:列出三个缺失项,**exit 2** ✅
- 测试全用 `_FakeClient`/`_FakeResponse`,无真实 httpx.Client、无网络请求 ✅

---

## 六项核查

**1. 请求体/响应解析兼容性 —— 基本 OK,有既有缺口**
请求体 `{model, max_tokens, messages:[system,user]}` 是标准 OpenAI 格式。`_extract_text`(client.py:28-41)健壮:choices 空/message 缺失/content 非 str 非 list 均转成明确 RuntimeError,非静默空串或裸 KeyError;content 为数组时只拼 `type=="text"` 段。**仍缺失(与旧 Anthropic 客户端同)**:无重试、未检查 `finish_reason=="length"`(截断静默返回部分文本)、未处理 refusal;`http_response.json()` 对 2xx 非 JSON 响应抛未捕获 JSONDecodeError。

**2. Base URL 拼接 —— ✅ 无重复/漏拼**
`_chat_completions_url`(client.py:17-25)先 `rstrip("/")`,三分支:已含 `/v1/chat/completions` 原样返回、含 `/v1` 补 `/chat/completions`、否则补 `/v1/chat/completions`。带/不带尾斜杠、Azure 式 `/openai/v1` 前缀均正确;空串抛 ValueError。测试参数化覆盖三种输入。

**3. API key 泄漏面 —— ✅ 无泄漏(最高优先项,已亲自核实)**
grep 全仓 `api_key/Authorization/Bearer/LLM_API_KEY`,key 仅两处:`client.py:59` 存 `self.api_key`(供第 72 行空值检查)、`client.py:67` 进 `Authorization: Bearer`。独立核实全部落盘/输出路径:
- **审计 JSONL**(client.py:91-98 record + audit.py:26 `json.dumps` 原样序列化):字段仅 `timestamp/model/base_url/system/prompt/response`,**无 api_key**;`test_llm.py:72` 显式断言 `"test-key" not in json.dumps(record)`。
- **实验 metadata**(run_eval.py `_expected_meta`):只记 model/base_url,**无 key**。
- **异常文本**:`raise_for_status()` 抛 httpx.HTTPStatusError,消息含 method+url+status **不含 header**;key 在 header 不在 query,URL 不含 key。
key 不进请求体、不进任何落盘文件。

**4. 子进程/baseline 环境变量继承 —— ✅**
graph arm `subprocess.run(command, cwd=ROOT, check=False)`(run_eval.py:206)未传 `env=`,默认继承父进程 `os.environ`,三变量透传子 `argus.cli`。baseline arm 直接 `AuditedLLM(api_key=os.environ[ENV_API_KEY], ...)`(run_eval.py:270)。两路径都拿得到。

**5. workspace metadata 校验 —— ✅**
`_expected_meta` 含 model 与 base_url。`_prepare_workspace_meta` 对 stored vs expected 逐键比对,任一不符(含 model/base_url)抛 `RuntimeError: workspace metadata does not match`;有产物但无 meta 也拒绝复用。换 model/endpoint 复用旧结果会 fail-fast(保护对照不被污染)。

**6. 锁文件完整性 —— ✅**
`uv.lock` 无 `anthropic` 条目;`httpx` 在(直接依赖 + langgraph-sdk/langsmith 传递)。pyproject 声明 `httpx>=0.27`,已移除 anthropic。`uv lock --check` 干净。

---

## Findings

### Critical
**无。** 无 API key 泄漏路径,凭据安全无虞。

### Important(建议跑批前补,非阻塞)
- **I-1. 无重试** — `client.py:71-89`:真实跑批 12 单元花真钱,遇瞬时 429/5xx 单元直接判 failed,无退避重试。旧客户端也无,但跑批场景值得补一层轻量重试。
- **I-2. 未检查截断** — `client.py:88-89`:未检查 `finish_reason=="length"`。分析器依赖完整 JSON 输出,截断静默返回半截文本 → 下游 JSON 解析失败或漏报,且难归因。建议截断时显式报错/告警。

### Minor
- **M-1. 2xx 非 JSON** — `client.py:89` `http_response.json()` 对网关返回 HTML 等抛未捕获 JSONDecodeError。建议包一层给明确 endpoint 上下文(勿把响应体原样塞进消息,避免二次泄漏面)。
- **M-2. `max_tokens` 参数名** — `client.py:81`:个别新版 OpenAI 兼容端点转向 `max_completion_tokens`。多数兼容服务无碍,跑批前确认目标 endpoint 接受 `max_tokens`。
- **M-3. refusal 未单独处理** — 会当普通文本返回。

---

## 结论
6 项改动目标全部达成,**无 Critical,无 API key 泄漏**(已亲自 grep 全仓 + 核实审计字段/测试断言)。**批准合入,可用于 T18 真实跑批。**

**跑批前提示**:I-1(重试)/I-2(截断检测)非阻塞但建议补——否则真钱跑批中途遇瞬时错误会浪费单元;M-2 确认目标 endpoint 接受 `max_tokens`。这些不阻塞跑批,可作为跑批中若出现失败单元时的首要排查/加固点。
