# M9：人工审批的只读 HTTP 验证 MVP

状态：已实现。M9 不扩展到 M10 的进程隔离，也不提供通用 PoC 执行器。

## 唯一允许的执行范围

- 环境必须是启用的 `existing_url`，并显式设置 `test_only: true`。
- 计划必须是 `R1_SAFE_READ`，只包含 `GET`、`HEAD` 或 `OPTIONS`。
- 当前规范化 `plan_hash` 必须存在未过期的人工 `APPROVED` 记录。
- Finding、SourceSnapshot、Project、Environment 和 Identity 绑定必须仍然一致。
- 调用方必须提供已准备的测试数据；Broker 不猜测或枚举资源 ID。
- 仅内网/loopback 测试环境可显式设置 `allow_private_addresses: true`。link-local、
  multicast、unspecified 和 reserved 地址始终拒绝。

M9 明确不支持 POST/PUT/PATCH/DELETE、浏览器自动化、Shell、上传、OAST、SSRF、
账号注册、DoS、破坏性载荷、生产环境或自动重试。

## Broker 边界

`argus/verification/broker.py` 是 Plan 到网络 I/O 的唯一入口。每次请求（包括每个
重定向和健康检查）都会重新检查：

1. Plan 状态、risk class 和安全方法；
2. 当前 hash 的未过期 Approval；
3. Finding/Snapshot/Environment/Identity 绑定；
4. Attempt 尚未终止；
5. 原子请求数和响应字节预算；
6. scheme/host/port/path allowlist；
7. DNS 结果的地址类别。

DNS 解析发生在审批和预算校验之后。解析结果作为固定 IP 交给自定义 network backend，
而 HTTP Host 与 TLS SNI/证书校验仍使用原始主机名，避免解析后由底层客户端再次解析
造成 rebinding/TOCTOU。连接不复用，不重试；重定向逐跳重新授权、扣预算、解析和固定，
跨 origin 重定向拒绝。

## 身份与脱敏

Plan、UI、插件和 Evidence 只看到 identity handle。`IdentityBroker` 在 Broker 内部
通过 `env:`/未来的 `keychain:` provider 解析 secret，并生成 Bearer、受控 Header
或 Cookie。解析后的 secret 不返回给调用方。

Authorization、Cookie、Set-Cookie、CSRF 和 token/api-key 头在证据中替换为不可逆
SHA-256 标记；JSON body excerpt 对敏感键递归脱敏。请求证据只记录 method 和 path，
不记录认证头或 query。

## Attempt、Evidence 与确定性结论

Alembic `0007_http_verification` 增加 `verification_attempts` 和
`verification_evidence`，并为 Environment 增加测试环境与私网显式开关。
每份 Evidence 同时写入内容寻址 Artifact Store，Control Store 只保存 hash、大小和
结构化的脱敏摘要。

第一版 verifier 只实现 Authorization/IDOR differential read：

- owner 不能读取 fixture：`INCONCLUSIVE`；
- peer 得到 401/403/404：`REJECTED`；
- owner 与 peer 都成功读取完全相同的 fixture：`CONFIRMED`；
- 其他差异：`INCONCLUSIVE`；
- 预算、健康、5xx、连接或策略失败：`ABORTED`。

结论由代码谓词生成；LLM 或 UI 不能写入 `CONFIRMED`。

## 操作入口

```bash
argus verification-execute \
  --plan-id <uuid> \
  --test-data resource_id=<prepared-test-fixture-id>
```

```text
POST /api/verification/plans/{plan-id}/execute
{"test_data":{"resource_id":"prepared-test-fixture-id"}}
```

控制台仅在 Approval 已批准时显示显式执行表单。按钮不会自动填充、枚举或触发请求，
并在执行中禁用以避免重复提交。

## 验证边界

自动化测试覆盖无审批/过期审批零 DNS、URL 编码绕过、跨 host、私网/link-local、
方法、请求数/字节预算、敏感头与 JSON 脱敏、迁移一致性，以及仅绑定
`127.0.0.1` 临时端口的 owner/peer 集成路径。测试不访问外部网络。
