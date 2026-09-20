# OCR events v1：独立 OCR 的可选 NDJSON

这是 Argus 固定 OpenCodeReview fork commit 实现的 opt-in 事件协议。Argus 的产品
仍只有一个源码审查引擎：OpenCodeReview。镜像内的 binary 支持该协议，但部署默认
保持 `ARGUS_OCR_EVENT_PROTOCOL=0`；最终 stdout JSON 与进程退出状态仍是唯一的
OCR 结果合同。

## 开关和进程边界

只有同时满足以下条件时，worker 才为 OCR 创建并传递事件 pipe：

```text
ARGUS_OCR_EVENT_PROTOCOL=1
ARGUS_OCR_EVENTS_FD=<decimal inherited file descriptor>
```

服务从 `ARGUS_OCR_EVENT_PROTOCOL` **精确等于** `1` 推导 enablement；其它值按
关闭处理，并把 child 环境规范化为 `0`。启用时父进程创建 pipe、用
`pass_fds` 让写端继承，并把实际写端 FD 写入 `ARGUS_OCR_EVENTS_FD`；服务会先
删除调用方环境里残留的旧 FD 值。关闭时普通 OCR 没有 inherited diagnostics
channel。

三个 child stream 必须独立处理：

| stream | 内容 | 是否可作为 API 原文 |
| --- | --- | --- |
| event FD | v1 NDJSON 事件 | 否，只能经过 parser/allowlist/sanitize |
| stdout | 最终 OCR JSON envelope | 否，服务只保存/导出安全摘要 |
| stderr | 进程诊断 | 否，只记录有界字节计数/安全错误 |

父进程必须在线程中同时 drain stdout、stderr 和 event FD；不能等 child 退出后才
读 pipe。reader 只保留有界 buffer，事件流每行最多 8 KiB、最多接收 10,000
行，队列也有界。这样 fake OCR 写出远超操作系统 pipe buffer 的 stderr 后仍能
继续到 final JSON；reader/writer 因未 drain 而互相阻塞是此次已修复的历史缺陷。

## child wire frame 的实际 parser 合同

当前 `OpenCodeReviewRunner` 的 v1 reader 接受的顶层字段是：

```json
{
  "version": 1,
  "type": "file.completed",
  "data": {"path": "app.py", "reviewed_files": 1, "duration_ms": 4}
}
```

这里的 child discriminator 是当前 reader 实际实现的 `version: 1`；它不要和
公共 API `ScanEvent.schema_version: 1` 混用。child frame 不携带 `scan_id`、
`attempt` 或 `event_id`；`timestamp` 可以作为可选的 RFC 3339 字符串出现，当前
reader 只校验它，归一后的 worker event 不把它当作公共事件 ID/时间，store 会
补齐自己的 `timestamp`。公共事件同时输出 `schema_version`、`event_id`、
`timestamp` 以及 `id/cursor/created_at` 别名。

顶层除 `version`、`type`、可选 `timestamp`、`data` 外的字段会被拒绝；`version`
必须存在、必须是整数 1（不能是 boolean）；`timestamp` 若存在必须是 RFC 3339
字符串；`data` 必须是 object，最多 32 个 key。type 必须是
下表的精确字符串；不存在的 type、非法 JSON、超长 line 和不安全 data 都静默
丢弃并计入 reader 的 rejected/dropped 计数，不会改变最终 OCR 结果。

## type 与 data whitelist（实际代码）

以下是 parser 当前实现的完整 type 列表；列表之外没有任意 progress child type、
任意 `message`、源码、prompt 或 raw response 通道。

| type | 允许的 data key |
| --- | --- |
| `file.started` | `index`, `ordinal`, `total`, `bytes`, `size`, `size_bytes`, `files_total`, `path`, `file_id` |
| `file.completed` | 上行全部字段，加 `duration_ms`, `comments`, `tokens`, `reviewed_files`, `files_reviewed` |
| `file.failed` | `index`, `ordinal`, `total`, `duration_ms`, `exit_code`, `status_code`, `failed_files`, `path`, `file_id` |
| `scan.inventory` | `files`, `files_total`, `directories`, `bytes`, `size_bytes`, `candidates`, `unsupported`, `skipped`, `count`, `total_files`, `reviewed_files`, `files_reviewed`, `failed_files`, `files_failed`, `skipped_files`, `files_skipped`, `session_id` |
| `llm.request.started` | `retry_count`, `count`, `request_id`, `session_id`, `provider`, `model` |
| `llm.request.headers` | `headers_count`, `count`, `bytes`, `http_status`, `status_code`, `request_id`, `session_id`, `provider`, `model`；header 内容本身不允许 |
| `llm.request.completed` | `duration_ms`, `status_code`, `http_status`, `prompt_tokens`, `completion_tokens`, `input_tokens`, `output_tokens`, `total_tokens`, `bytes`, `request_id`, `session_id`, `provider`, `model` |
| `llm.request.failed` | `duration_ms`, `status_code`, `http_status`, `retry_count`, `bytes`, `request_id`, `session_id`, `provider`, `model` |
| `llm.request.retry` | `retry_count`, `duration_ms`, `count`, `request_id`, `session_id`, `provider`, `model` |
| `tool.started` | `count`, `tool`, `tool_id`, `request_id`, `session_id` |
| `tool.completed` | `duration_ms`, `status_code`, `exit_code`, `count`, `tool`, `tool_id`, `request_id`, `session_id` |
| `tool.failed` | 同 `tool.completed` |
| `session.started` | `pid`, `count`, `session_id`, `provider`, `model` |

数值字段必须是有限、非 boolean、非负整数（`exit_code` 可为负），并受最大值
限制。文本字段只有 `path`、`file_id`、`request_id`、`session_id`、`provider`、
`model`、`tool`、`tool_id` 可通过；label 有界，path 必须为相对路径且不能 traversal。
其它 data key 会被忽略。parser 归一后转给 worker 的内部 event 恰好只有：

```json
{
  "source": "ocr",
  "type": "file.completed",
  "stage": "ocr_running",
  "level": "info",
  "code": "file_completed",
  "message": "OCR reported a file completion.",
  "data": {"path": "app.py", "reviewed_files": 1, "duration_ms": 4}
}
```

这七个内部字段随后由 store 包成公共 `ScanEvent`，补上
`schema_version/event_id/timestamp` 和兼容别名。child 的 `session.started`、
`llm.request.*`、`file.*` 等 type 是可观察事实；它们不能单独证明最终生成成功。

## 服务事件与能力更新

child type 与 Argus 自己产生的事件分开：

| 服务事件 | source | data/作用 |
| --- | --- | --- |
| `scan.created`, `scan.claimed`, `scan.phase`, `scan.commit` | `api`/`worker` | 队列、lease、阶段和固定 commit 事实 |
| `progress` | `worker` | `total_files`、`reviewed_files`、`failed_files`、`skipped_files` 的兼容覆盖率更新 |
| `ocr.started`, `ocr.parse_started`, `ocr.parse_finished`, `ocr.parse_error` | `ocr` | 进程启动/最终 stdout 解析阶段；不含原文 |
| `ocr.output_activity` | `ocr` | stdout/stderr/event bytes 和结构化事件计数等有界数字；不表示文件进度 |
| `ocr.timeout`, `ocr.canceled`, `ocr.output_limit`, `ocr.exited` | `ocr` | 外层进程终止事实与有界计数/exit code |
| whitelist child type | `ocr` | 通过 v1 parser 的安全 data |
| `scan.completed`, `scan.partial`, `scan.failed`, `scan.canceled`, `scan.skipped` | `worker`/`ocr` | 最终状态、finding count、retryable/suggestion 摘要 |
| `observability.truncated` | `store` | 事件上限导致的 dropped count |

`ScanCapabilities` 的三个值按正面事实更新：收到合法且有 coverage 的 file/scan
事件才可使 `file_progress=true`；收到合法 `llm.request.*` 才可使
`llm_requests=true`；收到合法 child v1 frame 才可使 `event_protocol=true`。
`ScanCoverage` 对 `total` 和 `percent` 保持 nullable；heartbeat、bytes、phase
和 elapsed 都不能填充它们。

## malformed frame、callback 和持有权失败

协议的 fail-open 只适用于单条 telemetry frame：malformed、未知 type、错误版本、
不合规 data 或超长行被忽略，reader 继续 drain，最终 stdout envelope 仍可产生
`completed`/`partial`/`failed`/`skipped`。

以下情况不是“可忽略的 malformed frame”：

- OCR 内部 callback 抛错时，adapter 返回稳定的 `OCR event callback failed`，
  并杀掉 OCR process group，不能把不完整执行当成功；
- worker 的 event store/SQLite append 失败，或 lease token 不再匹配时，当前
  fenced attempt 必须停止，旧 worker 不得继续写 terminal 状态；新的 attempt
  由 recovery/queue 路径重新 claim；
- child writer 自己遇到关闭的可选 FD，只能停止发事件，不能把原始异常、key 或
  source 写进诊断；父进程的最终 JSON/进程状态仍按正常 adapter 合同处理。

这种区分防止“单条坏 telemetry 被忽略”和“持有权/持久化失败被静默吞掉”混为一谈。

## 当前 OCR JSON 兼容合同

没有 v1 FD 时，当前 adapter 仍执行命令：

```text
<OCR_BINARY> scan --format json --audience agent
```

stdout 顶层 JSON 必须是 object，含字符串 `status` 和 `comments` array；可选
`warnings`、`summary`、`session_id`、`message`、`llm`。归一后的 `OCRStatus` 是
`complete`、`partial`、`skipped`、`failed`；`success`/`completed` 等完成别名、
warning-bearing partial、skipped 和 failed/error aliases 按现有 parser 处理。
非零退出、无法解析最终 JSON、outer timeout、cancel、reader/output limit 都不能
被 v1 事件补成成功。

默认外层 `OCR_PROCESS_TIMEOUT_SECONDS=1800`（30 分钟），`OCR_TIMEOUT_MINUTES=30`
是每文件 `--timeout`。stdout/stderr 进程 buffer 也有 8 MiB 上限；这与服务事件
单条 8 KiB 限制不同。当前固定 binary 不会因为没有 event FD 而失败。

## 安全、保留与验收

child frame 及其归一事件一律不允许 API key、LLM token、Git credential、Cookie、
Authorization header、源码、prompt、raw request/response 或 raw stdout/stderr。
`llm.request.headers` 只允许 headers_count/count/bytes/http_status 等数字摘要。

公共事件仍遵循 14 天、每次 attempt 10,000 条、每条序列化内容 8 KiB 的限制；
容量中预留终态事件和截断 marker slot，避免 event flood 隐藏 final event；非
essential 输入可 dropped，计数会在 observation/diagnostic 暴露。TTL/容量损失在
事件页通过 `oldest_cursor`、`history_truncated`、`expired_event_count` 明示，
导出中的 `events_truncated` 也会包含 retention loss。历史旧 scan 没有事件回填。

主验收使用 fake OCR + 本地 Git + 分离 API/worker + 共享 SQLite：协议开启时验证
所有 whitelist type 的安全 data、坏帧被忽略、事件可在运行中读取、最终报告仍由
stdout 决定；协议关闭时验证默认 pinned binary 路径和无 inherited FD。大 stderr
并发 drain 必须通过；不能用 `/models 200` 代替真实业务路径。

历史 `fbd...` 只证明曾在 30 分钟后超时，不能证明 pipe 是根因。pipe deadlock
是此次已修复的历史缺陷记录，不应再次归因给新的历史 incident。
