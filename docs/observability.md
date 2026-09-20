# Argus 可观测性

这是 Argus 扫描服务当前实现的可观测性合同。它描述 API、worker、SQLite
事件记录、OCR 进程边界，以及仓库内 `frontend/` 控制台使用的公共字段。

Argus 是仓库级 white-box review 服务，OpenCodeReview 是唯一的源码审查引擎。
可观测性回答任务处于哪个生命周期阶段、哪些运行事实已经被观察到、报告是否
可用；它不增加第二个分析器，也不把静态 finding 说成动态确认的漏洞。

默认镜像使用固定 fork commit 构建的 OpenCodeReview binary；该 binary 支持事件
协议，但部署默认通过 `ARGUS_OCR_EVENT_PROTOCOL=0` 保持关闭。独立 OCR NDJSON pipe 见
[OCR events v1](ocr-events-v1.md)。

每次真实 OCR 调用使用独立临时 HOME，结束或失败后清理引擎原生会话正文。
服务只保留规范化发现与安全事件；升级前旧引擎已写入的会话不由迁移自动删除。
最终评论中的 `thinking` 不属于发现合同，会直接丢弃，长度不影响有效发现入库。

## OpenAPI 与实际响应示例

父级从当前 `app.openapi()` 生成了 [OpenAPI 快照](openapi.json)。运行中的服务
也提供 [`/openapi.json`](/openapi.json)；以这两个来源核对路径、参数、必填字段
和 response model，不要从旧文档推断字段。

下列 JSON 是用 `TestClient(create_app(ScanStore(":memory:")))` 直接捕获的公共
响应，fixture 中没有 API key、源码或原始 provider 内容：

- [running unknown：`GET /v1/scans/{id}`](examples/observability/running-unknown.json)
- [Git authentication failure：`GET /v1/scans/{id}/diagnostics`](examples/observability/git-auth-failure-diagnostics.json)
- [partial：`GET /v1/scans/{id}`](examples/observability/partial.json)
- [complete：`GET /v1/scans/{id}`](examples/observability/complete.json)
- [event page：`GET /v1/scans/{id}/events?after=0&limit=100`](examples/observability/events-page.json)

这些 fixture 使用 ephemeral SQLite，只验证当前 Pydantic response model 和
TestClient 路由形状；其中的 scan ID、时间和计数是捕获时的 fixture 值。

## 客户端流程与认证

除 `GET /healthz` 和 `GET /readyz` 外，扫描、事件、诊断和报告接口都必须带：

```http
Authorization: Bearer <ARGUS_API_KEY>
```

客户端在 `queued` 或 `running` 期间每 2 秒读取一次详情和增量事件。事件游标
是整数：请求使用 `after`，服务返回 `next_cursor`；`after` 是排他的，空结果时
`next_cursor` 保持请求的 `after`。`has_more=true` 时继续用最新游标读取。
`oldest_cursor`、`history_truncated` 和 `expired_event_count` 明确表示 TTL/容量
造成的历史损失，不能把缺口当作“没有发生过事件”。

报告是受保护的下载响应。浏览器必须把同一个 Bearer header 放在 fetch 请求中，
再调用 `response.blob()`；不能因为报告最终保存为文件就去掉认证。

API Key 只在客户端内存中短暂存在：不要放进 query string、Git URL、Blob URL、
`localStorage`、`sessionStorage`、复制链接、前端埋点或日志。URL 里只允许出现
`scan_id`、`format`、`after` 和 `limit` 等非秘密参数。

```js
// 只从当前页面内存读取；不要写入浏览器存储。
const apiKey = readKeyFromMemoryOnly();
const auth = { Authorization: `Bearer ${apiKey}` };
const terminal = new Set(["completed", "partial", "failed", "canceled", "skipped"]);

async function jsonGet(url) {
  const response = await fetch(url, { headers: auth });
  if (!response.ok) throw new Error(`Argus 请求失败: ${response.status}`);
  return response.json();
}

async function watchScan(scanId) {
  let after = 0;
  for (;;) {
    const detail = await jsonGet(`/v1/scans/${encodeURIComponent(scanId)}`);
    let page;
    do {
      const query = new URLSearchParams({ after: String(after), limit: "100" });
      page = await jsonGet(
        `/v1/scans/${encodeURIComponent(scanId)}/events?${query.toString()}`,
      );
      after = page.next_cursor;
      renderDetailAndEvents(detail, page); // 不把 apiKey 传入 render/log
    } while (page.has_more);
    if (terminal.has(detail.status)) return detail;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
}

async function fetchReportBlob(scanId, format = "json") {
  const url = `/v1/scans/${encodeURIComponent(scanId)}/report?format=${encodeURIComponent(format)}`;
  const response = await fetch(url, { headers: auth });
  if (!response.ok) throw new Error(`报告下载失败: ${response.status}`);
  return response.blob();
}
```

收到 `401` 不要定时重试或回显凭据；`404` 表示 scan 不存在；事件分页错误
返回 `400`，应修正参数。空事件页不等于 worker 失败、OCR 零 finding 或模型
生成成功。

## API 路径和公共模型

| 接口 | 当前返回/用途 | 认证 |
| --- | --- | --- |
| `GET /v1/scans/{scan_id}` | `ScanResponse`：状态、阶段、兼容进度和 `observation` | Bearer 必须 |
| `GET /v1/scans/{scan_id}/events?after=&limit=` | `ScanEventsResponse` 增量事件页 | Bearer 必须 |
| `GET /v1/scans/{scan_id}/diagnostics` | `ScanDiagnosticsResponse` 脱敏诊断快照 | Bearer 必须 |
| `GET /v1/scans/{scan_id}/diagnostics/export` | JSON 附件，带 `Content-Disposition` | Bearer 必须 |
| `GET /v1/scans/{scan_id}/export` | 诊断导出的兼容路径 | Bearer 必须 |
| `GET /v1/scans/{scan_id}/report?format=json\|markdown\|sarif` | 认证的报告 Blob | Bearer 必须 |

事件参数当前边界是 `after >= 0`，`limit` 默认 100，范围 1–500。事件页外层
有 `items`、`next_cursor`、`has_more`、`oldest_cursor`、`history_truncated`、
`expired_event_count`。

### `ScanResponse` 和 `ScanObservation`

`ScanResponse` 当前字段为：

```text
id, repository_url, ref, commit_sha, include, exclude, background,
status, phase, progress, finding_count, attempt, idempotency_key,
session_id, metadata, error, created_at, updated_at, started_at,
finished_at, observation
```

`observation` 当前字段为：

```text
stage, stage_started_at, elapsed_seconds, stage_elapsed_seconds,
last_output_at, last_progress_at, worker_heartbeat_at, deadline_at,
activity_state, capabilities, coverage, report_ready, history_available,
error_summary, warnings, event_count, dropped_event_count,
truncated_event_count
```

嵌套模型的实际字段是：

- `capabilities`: `file_progress`、`llm_requests`、`event_protocol` 三个 boolean；
  只有正面观察到相应事实才为 `true`；
- `coverage`: `total`（未知时 `null`）、`reviewed`、`failed`、`skipped`、
  `percent`（未知时 `null`）；
- `error_summary`: `code`、`message`、`retryable`、`suggestion`、`source`。

`report_ready` 对 `completed`、`partial`、`skipped` 为 `true`，对 `failed`、
`canceled` 为 `false`。`history_available=false` 表示没有可回放的历史，不能
从时间戳合成事件。

现有 `progress` 是兼容的整数模型：`total_files`、`reviewed_files`、
`failed_files`、`skipped_files`、`percent`。覆盖率展示必须使用
`observation.coverage`；不要使用心跳次数、输出字节、耗时、finding 数量或
兼容字段的百分比猜测覆盖率。`running` 且 `coverage.total=null`、`percent=null`
是合法的未知状态。

### `ScanEvent` 和事件页

`ScanEvent` 的 canonical 字段是 `schema_version`、`event_id`、`timestamp`；当前
公共 JSON 同时包含兼容字段 `id`、`cursor`、`created_at`：

| 字段 | 当前语义 |
| --- | --- |
| `schema_version` | 公共事件模型版本 `1` |
| `event_id` | SQLite 自增事件 ID，也是 `after` 游标；持久化事件非空 |
| `timestamp` | 公共 canonical 时间 |
| `id`、`cursor` | 等于 `event_id` 的兼容别名 |
| `created_at` | 等于 `timestamp` 的兼容时间别名 |
| `scan_id`、`attempt` | 任务和尝试序号；初始 API event 可为 attempt 0，worker 首次 claim 为 1 |
| `source`、`type`、`stage`、`level`、`code`、`message` | 已清洗的事件摘要 |
| `data` | allowlist 内的运行计数/标识 |
| `truncated` | 公共序列化内容被 8 KiB 限制裁剪时为 `true` |
| `accepted`、`dropped` | 是否接收/落库；落库行是 `true`/`false`，超限输入不会落库 |

`ScanEventsResponse` 的实际形状是：

```json
{"items": [], "next_cursor": 0, "has_more": false, "oldest_cursor": null, "history_truncated": false, "expired_event_count": 0}
```

`next_cursor` 不是时间戳；没有事件时保持请求的 `after`。事件删除或保留造成
的游标间隙由 `oldest_cursor`、`history_truncated` 和 `expired_event_count` 明示，
不应被前端当作 worker 失败。

### `ScanDiagnosticsResponse` 和导出

`GET /v1/scans/{id}/diagnostics` 返回：

```text
scan_id, observation, summary, recent_errors, evidence, suggestions
```

`recent_errors` 是 `ScanEvent` 数组；`evidence` 只有有界的 `event_id`、
`timestamp`、`stage`、`code` 和清洗过的 `data`。导出 JSON 还包括脱敏的
`repository_url`、`ref`、`commit_sha`、状态、阶段、attempt、上述诊断字段、
最多 500 条事件、`events_next_cursor`、`events_truncated` 和
`expired_event_count`。导出中的 `events_truncated` 在事件页 `has_more=true`
或 `history_truncated=true` 时为 `true`。导出路径同样受
Bearer 认证保护。

## 生命周期、活动信号和能力

`ScanStatus` 的完整集合是：

| 状态 | 含义 |
| --- | --- |
| `queued` | 已接受，等待 worker claim |
| `running` | worker 持有本次 lease，可能在 Git、源码检查或 OCR 阶段 |
| `completed` | OCR 返回完整结果且覆盖率可用 |
| `partial` | 有 warning、失败项或不完整覆盖；不是完整扫描 |
| `failed` | 没有权威完整结果，例如超时、非零退出、最终 JSON 无法解析或 worker 失败 |
| `canceled` | 调用方请求取消且 worker 完成取消 |
| `skipped` | OCR 明确跳过；不同于完整扫描且零 finding |

worker 的阶段顺序是：

```text
queued -> git_fetching -> source_checking -> ocr_starting
       -> ocr_running -> parsing -> persisting -> terminal status
```

取消请求可能暂时显示 `cancel_requested`，终态阶段使用终态名称。未知阶段不能
映射为终态。

三个运行信号不能互相冒充：

| 信号 | 能证明什么 | 不能证明什么 |
| --- | --- | --- |
| worker heartbeat | worker 刷新 lease，更新 `heartbeat_at` 和生产 health 文件 | OCR 读文件、LLM 生成或 coverage 增长 |
| `ocr.output_activity` | 父进程从 OCR stdout/stderr/event stream 读取到字节，并记录有界计数 | 字节是合法 JSON、产生 finding 或有文件进度 |
| `progress` / `last_progress_at` | 阶段推进或实际覆盖计数变化 | 模型生成成功或全部文件已审查 |
| whitelist OCR event | OCR 报告了文件、LLM request、tool 或 session 的结构化事实 | 最终 OCR envelope 合法；最终 envelope 决定 status |

`file_progress`、`llm_requests`、`event_protocol` 只按正面事实置 true；provider
`/models` 的 `200` 只证明该 HTTP 路由回答，不证明 generation 或 scan 成功。

## 120/300 秒警告与 30 分钟截止

当前默认值为：

- `ARGUS_ACTIVITY_WARN_SECONDS=120`：连续 120 秒没有 OCR output 或结构化
  progress 时，`activity_state=idle_warning`；
- `ARGUS_ACTIVITY_STALE_SECONDS=300`：连续 300 秒没有 output/progress 时，
  `activity_state=stale_warning`；
- 两者都是诊断警告，不转成 `failed`、不自动取消、不制造进度；
- `OCR_PROCESS_TIMEOUT_SECONDS=1800` 是 outer OCR subprocess 的 30 分钟硬截止，
  会产生 `ocr.timeout` 并走失败路径；
- `OCR_TIMEOUT_MINUTES=30` 是传给 OCR 的每文件 `--timeout`；worker lease 默认
  300 秒是 fencing/recovery，不等同于 30 分钟 OCR 截止；
- `observation.deadline_at` 在 OCR starting event 带有 timeout 时表示计算出的
  outer process deadline；没有该事实时保持 `null`，不是 ETA。

## 错误、脱敏和 fenced attempt

错误摘要固定提供 `source`、`code`、`retryable`、`suggestion` 和有界 `message`。
当前 Git 分类包括 `git_dns`、`git_connect`、`git_tls`、`git_auth`、
`git_repo_missing`、`git_ref_missing`、`git_timeout`、`git_cancel`、`git_limit`
和 `git_unknown`；建议随错误一起返回，例如：

| 代码 | retryable | 建议 |
| --- | --- | --- |
| `git_dns`、`git_connect`、`git_timeout` | 是 | 检查 DNS/网络后重试 |
| `git_auth` | 否 | 检查 worker 的 Git credential helper 或 SSH agent |
| `git_repo_missing`、`git_ref_missing` | 否 | 修正仓库 URL 或 branch/tag/commit |
| `git_tls`、`git_limit` | 否 | 检查证书/代理或仓库安全上限 |
| `ocr_timeout` | 有条件 | 检查 provider 延迟和预算，重复超时需调查 |
| `ocr_incomplete_coverage` | 有条件 | 检查 coverage/warnings，需要完整覆盖时 retry |
| `worker lease_lost` / `lease_expired` | 是 | 让 recovery worker 用新 lease/token 接管 |
| `scan_partial` / `scan_failed` | 取决于摘要 | 读取 suggestion，不能当作完整结果 |

API、worker 日志和导出都不得包含：

- `ARGUS_API_KEY`、LLM token/key、Git credential、Cookie、Authorization header 或事件 FD；
- 源码字节/片段、prompt、background 原文、原始 OCR stdout/stderr、原始 model
  request/response 或原始 Git diagnostic；
- 未清洗 exception、带 userinfo 的 URL 或无界任意 metadata。

`sanitize_event` 只保留当前 allowlist 的运行字段，并在 8 KiB 前裁剪；日志只写
稳定的事件摘要和计数。诊断导出移除 repository URL 的 userinfo、query、fragment。

单条 OCR frame 的错误和 fenced worker 错误必须分开：

1. malformed JSON、错误 `version`、未知 type、超长行、字段超限或不在 whitelist
   的 data：reader 丢弃该 frame 并继续 drain，最终 stdout envelope 仍可决定
   `completed`/`partial`/`failed`/`skipped`；
2. event callback、SQLite event append 或 lease token 失败：这不是 malformed frame。
   当前 fenced attempt 必须停止，旧 worker 不能继续写 terminal 状态；新 worker
   只能使用新 lease/token；
3. 最终 stdout JSON 无法解析、outer timeout、OCR callback 失败、进程 reader 失败
   或 output limit：没有权威结果，走 `failed`，不能用事件页补成功。

## 保留、裁剪和旧 scan

默认配置：

- `ARGUS_EVENT_RETENTION_DAYS=14`；
- `ARGUS_EVENT_LIMIT=10000`，按每个 scan attempt 计数，含 essential reserve；
- 每条事件公共序列化内容最多 8 KiB。

超出普通事件容量时会为终态事件和截断 marker 预留 slot，再保留 essential 空间；
这样 event flood 不能遮住 final event。非 essential 输入返回内部
`accepted=false,dropped=true` 而不落库，并写入 `observability.truncated` 标记
和 dropped/truncated 计数。裁剪后的事件带 `truncated=true` 以及安全的
`original_bytes`、`truncated_fields`/`truncated_bytes`（如适用），原始内容不会
另存。按年龄清理只删除 event rows，不删除 scan、finding 或 report；TTL 删除的
数量累计到 `expired_event_count`，事件页的 `history_truncated=true`，导出的
`events_truncated=true`。

旧版本 scan 没有事件回填：`history_available=false`，事件页为空，服务不从旧
时间戳合成 `scan.created` 或 `scan.completed`。

## 离线端到端验收

主验收是离线 end-to-end，不运行真实 LLM，也不把 `/models 200` 当作生成成功。
使用本地 Git fixture、fake OCR executable、分开的 API/worker 进程和同一 SQLite
文件，验证：

1. `queued -> running`、2 秒认证轮询和运行中事件；
2. fake OCR 同时写出远超 pipe buffer 的 stdout/stderr、短暂 sleep、再写 final
   JSON，证明父进程并发 drain、无 pipe deadlock；
3. `ocr.output_activity`、worker `progress`、全部 v1 whitelist type、未知
   coverage、三种报告格式和带 Bearer 的 Blob fetch；
4. 401、`git_auth` 失败及 suggestion、诊断导出脱敏、SQLite 重开、事件保留和
   disposable checkout 清理；
5. `ARGUS_OCR_EVENT_PROTOCOL=1` 的 inherited event FD，以及关闭协议时默认
   pinned binary 的兼容路径。

历史上只知道 `fbd...` 那次扫描在 30 分钟后超时，证据稀疏，不能据此断言 pipe
是根因。pipe reader/writer 因未 drain 而 deadlock 是此次已修复的历史缺陷记录，
不应再次归因给新的历史 incident。
