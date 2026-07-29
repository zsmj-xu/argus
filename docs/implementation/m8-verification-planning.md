# M8：验证需求、计划、策略与审批（离线）

状态：已实现。M8 只建立动态验证所需的强类型领域对象、缺失输入解析、
规范化 plan hash、默认拒绝策略和审批中心。本阶段没有 Tool Broker、HTTP Client、
浏览器、Shell、PoC 执行器、Evidence 或动态验证结论。

## 默认开关

所有配置入口默认包含：

```yaml
verification:
  enabled: false
  allow_safe_read: false
  allow_reversible_write: false
```

因此已有静态扫描不会自动创建 `VerificationRequirement` 或
`VerificationPlan`。Finding 可以永久保持静态 `UNVERIFIED`，且不受 M8 影响。

## 领域对象

`argus/verification/models.py` 定义：

- `EnvironmentProfile`：项目、环境种类、目标基址、scope allowlist、能力、
  health check 声明、重置能力和可选 Snapshot 绑定；
- `IdentityProfile`：稳定 handle、角色、tenant、非敏感 attributes 和
  `credential_ref`；
- `VerificationRequirement`：所需环境能力、身份角色、测试数据名称和
  `missing_fields`；
- `VerificationPlan`：Finding/Snapshot/Environment/Identity 绑定、声明式 action、
  request budget、预期观察/副作用、回滚、health check、abort condition、风险等级、
  plan hash 和生命周期状态；
- `Approval`：plan ID/hash、决定、审核者、理由和到期时间。

计划中的 HTTP action 只是不可执行的数据契约。它不能构造 Client、解析 secret 或
发起请求。

## 需求解析

`VerifierDeclaration` 只声明：

- 支持的 Finding 类别；
- 环境能力；
- 身份角色；
- 测试数据键名。

`RequirementResolver` 将声明与启用的 Environment/Identity 和已有测试数据键比较，
产生例如：

```text
environment.capability:readonly_http
identity.role:owner
identity.role:peer
test_data:resource_id
```

只保存测试数据名称，不保存测试值或凭据。缺失列表非空时，
`VerificationPlanCompiler` 拒绝生成计划。

## Plan hash 与不可变修订

plan hash 使用规范化 JSON 对全部实质字段计算 SHA-256，包括：

- Finding、Snapshot、Environment 和 Identity 绑定；
- actions、budget、observations 和 side effects；
- rollback、health checks 和 abort conditions；
- risk class。

ID、status 和时间戳等生命周期 metadata 不进入 hash。实质字段变化会生成新的
Plan ID/hash；Control Store 原子地把同 Finding 的旧计划和所有 pending/approved
Approval 标记为 `SUPERSEDED`。相同规范化计划不会重复使审批失效。

## 风险策略

`VerificationPolicy` 的默认矩阵：

| 风险 | 默认决定 |
| --- | --- |
| `R0_STATIC` | 自动允许，但没有网络 budget |
| `R1_SAFE_READ` | 需要 `enabled + allow_safe_read`，并逐计划人工审批 |
| `R2_REVERSIBLE_WRITE` | 需要显式允许、自动重置环境和逐计划审批 |
| `R3_HIGH_IMPACT` | 默认拒绝 |
| `R4_PROHIBITED` | 永久拒绝 |

策略结果只是 `ALLOW_AUTOMATIC`、`REQUIRE_APPROVAL` 或 `DENY`，没有执行方法。
M8 Approval 即使为 `APPROVED`，也只表示该 plan hash 已审核，不能改变 Finding 的
动态验证状态，更不能产生网络请求。

## 凭据边界

- 数据库、Artifact、Prompt 和 Event 不保存 secret，只保存形如
  `env:ARGUS_TEST_OWNER_TOKEN` 的 `credential_ref`；
- URL 拒绝嵌入 username/password；
- Environment、Identity、Action、HealthCheck 和 Plan 均为 `extra=forbid`，
  没有 header、cookie、token 或 body 字段；
- Identity attributes 递归拒绝 credential/token/key/password 字段；
- `EnvironmentSecretProvider` 是第一版 provider，只在显式调用时解析 `env:`；
- `KeychainSecretProvider` 仅为未来适配器保留 Protocol；
- M8 没有任何代码消费解析后的 secret。

## 持久化与 API

Alembic `0006_verification_planning` 增加：

```text
verification_environments
verification_identities
verification_requirements
verification_plans
verification_approvals
```

本地 Control Plane 提供：

```text
GET|POST /api/projects/{project-id}/verification/environments
GET|POST /api/projects/{project-id}/verification/identities

GET  /api/findings/{finding-id}/verification
POST /api/findings/{finding-id}/verification/requirements
POST /api/findings/{finding-id}/verification/plans

GET  /api/verification/plans/{plan-id}
POST /api/verification/plans/{plan-id}/approval
GET  /api/verification/approvals
POST /api/verification/approvals/{approval-id}/approve
POST /api/verification/approvals/{approval-id}/reject
```

所有变更写入 Event。Web 审批中心分别展示静态 Review 和动态 Verification
Approval，并显示 Environment/Identity 数量、缺失字段、plan hash、到期时间与
`M8 无网络执行能力`。

CLI 提供：

```bash
argus verification-status --finding-id <uuid>
argus verification-approval request --plan-id <uuid>
argus verification-approval approve --approval-id <uuid> --reviewer NAME --reason TEXT
argus verification-approval reject --approval-id <uuid> --reviewer NAME --reason TEXT
```

## 验收证据

自动化测试覆盖：

- 默认配置关闭且 Finding 不隐式创建验证对象；
- Environment/Identity/Requirement/Plan/Approval 的迁移与重启持久性；
- 缺少输入与 Plan Ready；
- plan hash 稳定性和实质字段变化；
- 旧 Approval 自动 `SUPERSEDED`；
- 审批到期和 stale hash 拒绝；
- R0–R4 默认策略；
- URL/credential/identity attribute 边界；
- verifier 插件权限保持 `network=none`；
- `argus/verification/` 不导入网络、浏览器或 subprocess 执行模块。

真实 loopback Server 和应用内浏览器验证了 Plan Ready、请求审批、pending/
superseded 展示和 Finding 动态规划状态；页面无前端告警。测试没有运行真实扫描、
调用真实 LLM、解析真实凭据或发出目标网络请求。

## M9 前的限制

- 没有 Broker、Identity Broker、HTTP Executor、重定向/DNS/URL 再校验或预算计数；
- 没有 VerificationAttempt、Evidence 或确定性动态结论；
- Approval 不能被任何 M8 组件用于执行；
- 不支持 POST/PUT/PATCH/DELETE 等真实动作；
- M9 只能在重新审核安全边界后增加受控、只读 HTTP MVP。
