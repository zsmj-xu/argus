# VAmPI 对照实验:Shannon vs Argus 漏洞检测能力

**日期**:2026-07-20
**靶场**:VAmPI(Flask 单体 API,`vulnerable=1` 模式)
**状态**:完成(Shannon + Argus 双侧跑通,对照表 + 结论已出)

> 设计文档见 `docs/superpowers/specs/2026-07-20-argus-vs-shannon-comparison-design.md`。
> 本轮目标:先在 VAmPI 上跑通「Shannon ⟷ Argus」端到端对照链路,验证 Argus 复刻 Shannon 检测能力的实际差异。先跑通、可扩展,不追求完整评测。

---

## 1. 公平对照口径(关键)

只比**漏洞发现层**(Shannon Phase 3 `vuln-*` vs Argus vuln 分析器)。为消除口径错位:

| 维度 | Shannon | Argus |
|---|---|---|
| 分析方式 | 黑盒动态 + 读源码 | 纯白盒静态 |
| 需要运行中目标 | 是(`-u <url>` 探活+攻击) | 否(只读源码+代码图) |
| Exploitation 验证层 | **本轮关闭**(`exploit: "false"`) | 设计上不做(YAGNI) |
| 启用分析器 | 5 类(injection/xss/auth/authz/ssrf) | 5 类(同,移植自 Shannon) |
| 图富化 | Shannon 自有 recon | business-flow(事实层,不加新漏洞类) |

- Shannon 侧 config:`docs/comparisons/configs/shannon-vampi.yaml`(`exploit: "false"`)
- Argus 侧 config:`docs/comparisons/configs/argus-vampi-5class.yaml`(5 类 + business-flow)
- 共同标尺:`ground_truth/vampi.json`(4 条 in_scope,属 5 类不变量范围)
- 打分器:同一个 `argus/eval/score.py`,唯一变量是"哪个工具检出的"

## 2. 范式差异声明(须写入结论,非隐藏)

**Shannon** 是黑盒动态 + 源码分析,原生带 Exploitation 验证层(Phase 4:对活目标真实发起攻击验证影响)。本轮按公平口径**关闭**该层,只到发现层。

**Argus** 是纯白盒静态,设计上明确**不做**动态验证(YAGNI),只输出候选漏洞清单。

这一差异意味着:
- Shannon(即便关 exploit)仍会读运行时行为、OpenAPI、HTTP 响应,可能发现 Argus 静态看不到的(如运行时配置缺陷)。
- Argus 静态能看到未部署代码、全调用链,可能发现 Shannon 黑盒触达不了的路径。
- 对照表只计入 GT 内的 5 类,范式差异写进结论而非隐藏。

## 3. 方法论

```
① 部署 VAmPI(Docker, :5002 vulnerable=1)
    ├── ② Shannon 跑批(exploit=false) → *_exploitation_queue.json
    │       └── ⑥ 归一(normalize_shannon.py) → list[Finding]
    └── ④ Argus 跑批(5 类 arm) → findings.json
            └── ⑦ 同一 score.py + 同一 vampi.json 打分 → 对照表
```

- Shannon 产物归一:`scripts/normalize_shannon.py` 把 5 个 `*_exploitation_queue.json` 转成 `score()` 可消费的 `Finding`(文件名编码 vuln_class,`vulnerable_code_location` 拆成 file+line)。
- 对照打分:`scripts/compare_shannon_argus.py` 给两边分别打分,输出 recall/precision + GT 命中交集/独有。

## 4. Ground Truth(`ground_truth/vampi.json`)

| GT id | invariant_kind | vuln_type | handler | in_scope |
|---|---|---|---|---|
| vampi-bola-books-get | ownership | BOLA | get_by_title | ✓ |
| vampi-bola-update-password | ownership | BOLA / Unauthorized password update | update_password | ✓ |
| vampi-auth-debug | authentication | Missing authentication / Excessive data exposure | debug | ✓ |
| vampi-massassign-admin | trust_boundary | Mass assignment / Privilege escalation | register_user | ✓ |
| vampi-user-enum-login | n/a | User enumeration | login_user | ✗(通用,仅记录) |
| vampi-redos-email | n/a | ReDoS | update_email | ✗(通用,仅记录) |
| vampi-sqli-getuser | n/a | SQL Injection | get_user | ✗(通用,仅记录) |

**计入指标的 4 条**全部属于业务不变量类(ownership/authentication/trust_boundary)。3 条 out_scope 是注入/DoS/枚举等通用漏洞,本轮不做。

## 5. Argus 侧结果(已完成)

- **配置**:`docs/comparisons/configs/argus-vampi-5class.yaml`(injection/xss/auth/authz/ssrf + business-flow 富化,source_mode=stripped)
- **模型**:`ds.public.deepseek-v4-pro`(推理模型,HTTP 超时 600s)
- **产物**:`runs/vampi-5class/findings.json`(12 条)+ `report.md`
- **跑批**:全 6 节点完成(build_graph → enrichment → vuln → report)

### 5.1 Argus 检出的 12 条 finding

| # | vuln_class | severity | title | 位置 |
|---|---|---|---|---|
| 0 | injection | high | SQL Injection in User::get_user | models/user_model.py:73 |
| 1 | auth | critical | Plaintext Password Storage | models/user_model.py:21 |
| 2 | auth | medium | User Enumeration via Distinct Login Error Messages | api_views/users.py:85 |
| 3 | auth | high | Self-Registration Privilege Escalation via Admin Flag | api_views/users.py:52 |
| 4 | auth | critical | Arbitrary Password Change via IDOR in update_password | api_views/users.py:179 |
| 5 | authz | high | IDOR: Any authenticated user can read any book's secret content | api_views/books.py:51 |
| 6 | authz | critical | BFLA: Unauthenticated user can register with admin privileges | api_views/users.py:59 |
| 7 | authz | critical | IDOR: Authenticated user can change any user's password | api_views/users.py:189 |
| 8 | authz | high | Missing Authorization: Unauthenticated access to debug endpoint | api_views/users.py:25 |
| 9 | authz | medium | Missing Authorization: Unauthenticated user enumeration via get_all_users | api_views/users.py:20 |
| 10 | authz | medium | Missing Authorization: Unauthenticated user email disclosure via get_by_username | api_views/users.py:46 |
| 11 | authz | critical | Missing Authorization: Unauthenticated database reset via populate_db | api_views/main.py:6 |

### 5.2 Argus 打分

| findings 数 | TP | FP | FN | Recall | Precision |
|---:|---:|---:|---:|---:|---:|
| 12 | 2 | 10 | 2 | 0.500 | 0.167 |

**TP(命中 GT)**:
- `vampi-bola-books-get` ← finding[5](IDOR books,authz)
- `vampi-bola-update-password` ← finding[7](IDOR update_password,authz)

**FN(未命中 GT)**:
- `vampi-auth-debug` — Argus finding[8] 检出了(debug 端点无授权),但 vuln_class 归为 `authz`,GT 是 `authentication`,score.py 只让 `auth`(不是 `authz`)兼容 `authentication`(见 §6 口径限制)。
- `vampi-massassign-admin` — Argus finding[3]/[6] 检出了(admin flag 提权),但 GT 是 `trust_boundary`,score.py 只让 `business_logic` 兼容 `trust_boundary`,本轮 Argus 不启用 business-logic 分析器(公平口径)。

**结论**:Argus 实际检出了全部 4 条 in_scope 漏洞,2 个 FN 是 score.py 的 invariant 兼容口径导致,非检测遗漏(见 §6)。

### 5.3 人工核对(绕过 score.py 口径)

人工按 file + handler 匹配,Argus 对 4 条 in_scope GT 的实际检出:

| GT id | handler | 检出? | finding |
|---|---|---|---|
| vampi-bola-books-get | get_by_title | ✅ | finding[5] authz: IDOR books |
| vampi-bola-update-password | update_password | ✅ | finding[4] auth / finding[7] authz |
| vampi-auth-debug | debug | ✅ | finding[8] authz: debug endpoint 无授权 |
| vampi-massassign-admin | register_user | ✅ | finding[3] auth / finding[6] authz |

**人工核对 recall = 4/4 = 1.0**(Argus 检出全部 in_scope GT)。但注意:score.py 口径下 Argus recall=0.500,低于 Shannon 的 0.750——差距见 §8/§9,主要在 auth-debug 的分类口径(authz vs auth)和 auth 覆盖广度。

## 6. 口径限制(score.py invariant 兼容)

`argus/eval/score.py` 的 `_compatible_class` 为内部消融(T17,含 business-logic)设计:
- `authentication` 只兼容 `auth`(不兼容 `authz`)
- `trust_boundary` 只兼容 `business_logic`(不兼容 `auth`/`authz`)
- `ownership`/`role` 兼容 `authz` 和 `business_logic`

阶段 C 公平口径明确**不启用** business-logic 分析器,导致 Argus 用 auth/authz 检出的 massassign(trust_boundary)和部分 debug(authentication)无法匹配到 invariant 类 GT。这是口径限制,非检测能力缺陷。本轮在对照表中如实标注,不改 score.py(改 score.py 属契约变更,影响 T17 已评审的内部消融结果)。

## 7. Shannon 侧结果(待 C3 跑批完成)

Shannon 跑批完成,产物在 `../shannon/workspaces/vampi-shannon/deliverables/`,经 `normalize_shannon.py` 归一后打分。

### 7.1 Shannon 检出的 finding(20 条,归一后)

| vuln_class | 条数 | 代表性 finding |
|---|---:|---|
| injection | 1 | INJ-VULN-01: SQLi(无 code_location,定位不到行) |
| xss | 0 | (VAmPI 无 XSS sink) |
| auth | 12 | AUTH-VULN-06(debug 无认证)、AUTH-VULN-08(mass-assign admin)、密码明文存储、JWT secret 弱、无 rate limit 等 |
| authz | 7 | AUTHZ-VULN-01(BOLA books)、AUTHZ-VULN-02(BOLA update_password)、AUTHZ-VULN-03(debug 无授权)、AUTHZ-VULN-04(mass-assign) |
| ssrf | 0 | (VAmPI 无 SSRF 端点) |

Shannon 的 auth 分析器拆得很细(12 条):Token 管理、传输安全、登录逻辑、密码存储、认证绕过等各自独立成条。Argus 同类问题合并更粗(auth 5 条)。

### 7.2 Shannon 打分

| findings 数 | TP | FP | FN | Recall | Precision |
|---:|---:|---:|---:|---:|---:|
| 20 | 3 | 17 | 1 | 0.750 | 0.150 |

**TP(命中 GT)**:
- `vampi-bola-books-get` ← AUTHZ-VULN-01(authz, api_views/books.py:50)
- `vampi-bola-update-password` ← AUTHZ-VULN-02(authz, api_views/users.py:186)
- `vampi-auth-debug` ← AUTH-VULN-06(**auth**, api_views/users.py:24, Authentication_Bypass)

**FN(未命中 GT)**:
- `vampi-massassign-admin` — Shannon AUTHZ-VULN-04/AUTH-VULN-08 检出了(admin flag 提权 @ api_views/users.py:60),但 GT 是 `trust_boundary`,score.py 只让 `business_logic` 兼容(§6),`auth`/`authz` 都不匹配。

### 7.3 人工核对(绕过 score.py 口径)

Shannon 对 4 条 in_scope GT 的实际检出(按 file+line 匹配):

| GT id | 检出? | finding |
|---|---|---|
| vampi-bola-books-get | ✅ | AUTHZ-VULN-01 authz @ api_views/books.py:50 |
| vampi-bola-update-password | ✅ | AUTHZ-VULN-02 authz @ api_views/users.py:186 |
| vampi-auth-debug | ✅ | AUTH-VULN-06 auth + AUTHZ-VULN-03 authz @ api_views/users.py:24 |
| vampi-massassign-admin | ✅ | AUTHZ-VULN-04 authz + AUTH-VULN-08 auth @ api_views/users.py:60 |

**人工核对 recall = 4/4 = 1.0**(Shannon 检出全部 in_scope GT)。

## 8. 对照表

| 工具 | findings 数 | TP | FP | FN | Recall | Precision |
|---|---:|---:|---:|---:|---:|---:|
| Shannon | 20 | 3 | 17 | 1 | **0.750** | 0.150 |
| Argus | 12 | 2 | 10 | 2 | 0.500 | 0.167 |

### GT 命中交集

- **两边都命中**: `vampi-bola-books-get`, `vampi-bola-update-password`
- **仅 Shannon**: `vampi-auth-debug`(Shannon 归 `auth` 命中;Argus 归 `authz` 不兼容 `authentication` 未命中)
- **仅 Argus**: 无

### 逐条 GT 对比

| GT | Shannon | Argus | 差异原因 |
|---|---|---|---|
| vampi-bola-books-get | ✅ authz L50 | ✅ authz L51 | 平 |
| vampi-bola-update-password | ✅ authz L186 | ✅ auth L179 + authz L189 | 平 |
| **vampi-auth-debug** | ✅ **auth L24** | ❌ authz L25 | **Shannon 归 auth(兼容 authentication),Argus 归 authz(不兼容)** |
| vampi-massassign-admin | ❌ FN(trust_boundary 口径) | ❌ FN(同口径) | 平(口径限制,非检测遗漏) |

## 9. 结论

### 9.1 核心发现:Argus 未达到 Shannon 的检测效果

在 VAmPI 靶场上,score.py 口径下 **Shannon recall (0.750) > Argus recall (0.500)**,Argus 落后一条。人工核对两边都检出了全部 4 条 in_scope GT(均 4/4),但 score.py 的 class 兼容口径让 Argus 的 auth-debug 归类(`authz`)不匹配 GT(`authentication`),而 Shannon 的归类(`auth`)匹配——这一差异在评分上体现为 Argus 少命中一条。

**这不是单纯的评分口径问题**——它反映了两个真实差距:

1. **分类口径差距**:同一个"debug 端点无认证"漏洞,Shannon 的 auth 分析器识别为"认证缺失"(Authentication_Bypass, auth class),Argus 的 authz 分析器识别为"授权缺失"(Missing Authorization, authz class)。score.py 只让 `auth` 兼容 `authentication` invariant,所以 Shannon 命中、Argus 不命中。Argus 的 auth/authz 分析器对"认证 vs 授权"的边界划分与 Shannon 不一致。

2. **覆盖广度差距**:Shannon 的 auth 分析器产出 12 条细分问题(JWT secret 弱、明文密码存储、无 rate limit、传输无 SSL、token 无 jti、Bearer scheme 未校验等),Argus 的 auth 分析器只产出 5 条。Shannon 覆盖了 token 管理、传输安全、限流、登录逻辑等多个 Argus 未触及的维度。这些虽不在 GT 的 invariant 范围内(算 FP),但都是真实安全问题。

### 9.2 范式差异的实际影响(§2 声明的验证)

| 维度 | 预期 | 实际观察 |
|---|---|---|
| Shannon 黑盒能看运行时 | 可能发现静态看不到的 | Shannon 报了 Transport_Exposure(无 SSL)、Abuse_Defenses_Missing(无 rate limit)等运行时缺陷,Argus 静态未报——符合预期,且这是 Argus 范式上的固有限制 |
| Argus 静态能看全调用链 | 可能发现黑盒触达不了的 | 本轮 VAmPI 单体小应用,未观察到 Argus 独有的调用链发现——需更大靶场(crAPI)验证 |
| Shannon 有 exploit 验证层 | 本轮关闭(公平口径) | 两边均无验证,只比发现层——口径对齐 |

### 9.3 口径限制的影响(§6)

score.py 的 invariant 兼容表对两边**不完全对称**:
- `vampi-auth-debug`(authentication):Shannon 归 `auth` 命中,Argus 归 `authz` 未命中 → **偏向 Shannon**
- `vampi-massassign-admin`(trust_boundary):两边都归 `auth`/`authz`,都不兼容 `business_logic` → 对称 FN

即 auth-debug 这条的口径限制**不对称地**有利于 Shannon。但即便排除口径因素(人工核对两边都 4/4),Argus 在覆盖广度上仍落后(12 条 auth 细分 vs 5 条)。

### 9.4 本轮结论

**Argus 在 VAmPI 上未达到 Shannon 的检测效果。** 端到端对照链路跑通(部署 → 跑批 → 归一 → 同一 score.py 打分 → 对照表),但在 5 类漏洞发现层:
- recall 落后(0.500 vs 0.750),差在 auth-debug 的分类口径
- 覆盖广度落后(Shannon auth 12 条细分 vs Argus 5 条),多个维度未覆盖
- 范式固有限制:Shannon 黑盒能报运行时缺陷(SSL/rate limit),Argus 纯静态看不到

本轮验证了设计文档的目标(先跑通、可扩展),并识别出 Argus 相对 Shannon 的具体差距,为后续改进提供方向。

### 9.5 Argus 改进方向(基于本轮差距)

1. **auth 分析器扩展**:补 token 管理(JWT secret 强度/jti/撤销)、传输安全(SSL/TLS)、限流、Bearer scheme 校验等 Shannon 覆盖而 Argus 缺失的维度。
2. **auth/authz 分类边界对齐**:debug 端点无认证这类问题,考虑让 authz 分析器也兼容 `authentication` invariant,或在 auth 分析器里覆盖(需走 score.py 契约变更或分析器调整)。
3. **更大靶场验证**:crAPI/flowmart 上验证 Argus 静态全调用链优势是否能弥补运行时缺陷的盲区。

### 9.6 局限

- **单靶场**:仅 VAmPI,需 crAPI/flowmart 验证泛化性。
- **GT 范围窄**:vampi.json 仅 4 条 in_scope(全 invariant 类),5 类分析器里 injection/xss/ssrf 无 in_scope GT 可对照。
- **归一层曾有 bug**:初版正则 `\s*$` 锚定结尾,导致 Shannon auth 类 12 条多段 location 全部无锚点,一度把 Shannon recall 压到 0.500(与 Argus 持平的假象)。已修复(取行首首个 `路径:数字`),修复后 Shannon recall=0.750。**这一 bug 曾导致过早下"对等"结论。**

## 10. 复现步骤

```bash
# ① 部署 VAmPI
docker compose -f targets/VAmPI/docker-compose.yaml --project-directory targets/VAmPI up -d --build
# 验证 :5002(vulnerable=1)
curl -s http://localhost:5002/openapi.json | python -m json.tool

# ② Shannon 跑批(需 ../shannon/.env 配 Anthropic 凭据)
cd ../shannon
./shannon start -u http://localhost:5002 -r /Users/hetao/work/project/argus/targets/VAmPI \
  -c /Users/hetao/work/project/argus/docs/comparisons/configs/shannon-vampi.yaml \
  -w vampi-shannon

# ④ Argus 跑批
uv run python -m argus.cli start -r targets/VAmPI -w vampi-5class \
  -c docs/comparisons/configs/argus-vampi-5class.yaml --yolo

# ⑦ 对照打分
uv run python scripts/compare_shannon_argus.py \
  --shannon-deliverables targets/VAmPI/.shannon/deliverables \
  --argus-findings runs/vampi-5class/findings.json \
  --ground-truth ground_truth/vampi.json \
  --output docs/comparisons/vampi-comparison.json \
  --markdown docs/comparisons/_comparison-snippet.md
```

## 11. 本轮非目标

- crAPI/flowmart 扩展(VAmPI 跑通后再谈)
- business-logic/invariant 对照(Argus 新功能,本轮不参与)
- Shannon Exploitation 验证层对照(公平口径已关闭)
- 性能/成本对照
