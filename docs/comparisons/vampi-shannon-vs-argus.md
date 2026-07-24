# VAmPI 对照实验:Shannon vs Argus 漏洞检测能力

**日期**:2026-07-22
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
| 图/语义富化 | Shannon 自有 recon | 本正式 arm 不启用额外 business-flow/invariant,五类分析器直接读同一 codegraph + source |

- Shannon 侧 config:`docs/comparisons/configs/shannon-vampi.yaml`(`exploit: "false"`)
- Argus 侧 config:`docs/comparisons/configs/argus-vampi-5class.yaml`(纯 5 类,`strict_outputs=true`,不启用额外富化)
- 共同标尺:`evaluation/ground_truth/vampi.json`(6 条 comparison-scope 漏洞: injection/auth/authz)
- 主指标:`score_detection()` 按源码锚点判断已知漏洞是否检出,不把分类标签差异算作漏检
- 辅助诊断:原 `score()` 保留分类兼容评分,但不再代表漏洞检出能力

## 2. 范式差异声明(须写入结论,非隐藏)

**Shannon** 是黑盒动态 + 源码分析,原生带 Exploitation 验证层(Phase 4:对活目标真实发起攻击验证影响)。本轮按公平口径**关闭**该层,只到发现层。

**Argus** 是纯白盒静态,设计上明确**不做**动态验证(YAGNI),只输出候选漏洞清单。

这一差异意味着:
- Shannon(即便关 exploit)仍会读运行时行为、OpenAPI、HTTP 响应,可能发现 Argus 静态看不到的(如运行时配置缺陷)。
- Argus 静态能看到未部署代码、全调用链,可能发现 Shannon 黑盒触达不了的路径。
- 对照表只计入 GT 中明确标为 `comparison_in_scope` 的 6 条漏洞,范式差异写进结论而非隐藏。

## 3. 方法论

```
① 部署 VAmPI(Docker, :5002 vulnerable=1)
    ├── ② Shannon 跑批(exploit=false) → *_exploitation_queue.json
    │       └── ⑥ 归一(normalize_shannon.py) → list[Finding]
    └── ④ Argus 跑批(5 类 arm) → findings.json
            └── ⑦ 同一 vampi.json 检出评分 → 对照表
```

- Shannon 产物归一:`evaluation/scripts/normalize_shannon.py` 把 5 个 `*_exploitation_queue.json` 转成 `score()` 可消费的 `Finding`(文件名编码 vuln_class,`vulnerable_code_location` 拆成 file+line)。
- 对照打分:`evaluation/scripts/compare_shannon_argus.py` 给两边计算 Detection Recall + GT 命中交集/独有。
- 检出与分类分离:主指标只要求 finding 与 GT 的源码位置/handler 锚点一致;原分类兼容分仅作为标签差异诊断。
- GT 不完整,未匹配 finding 标为“未裁决”,不直接判作 FP,因此本轮不报告 Precision。

## 4. Ground Truth(`evaluation/ground_truth/vampi.json`)

| GT id | invariant_kind | vuln_type | handler | business scope | comparison scope |
|---|---|---|---|---|
| vampi-bola-books-get | ownership | BOLA | get_by_title | ✓ | ✓ authz |
| vampi-bola-update-password | ownership | BOLA / Unauthorized password update | update_password | ✓ | ✓ authz |
| vampi-auth-debug | authentication | Missing authentication / Excessive data exposure | debug | ✓ | ✓ auth |
| vampi-massassign-admin | trust_boundary | Mass assignment / Privilege escalation | register_user | ✓ | ✓ authz |
| vampi-user-enum-login | n/a | User enumeration | login_user | ✗ | ✓ auth |
| vampi-redos-email | n/a | ReDoS | update_email | ✗ | ✗(无对应分析类) |
| vampi-sqli-getuser | n/a | SQL Injection | get_user | ✗ | ✓ injection |

**comparison scope 的 6 条**覆盖 injection、auth、authz 三个有正样本的分析类。VAmPI 没有 XSS/SSRF 正样本,所以这两类报告 `N/A`; ReDoS 没有对应的五类分析器。business scope 仍保留原来的 4 条不变量,不被跨工具 scope 改写。当前 GT 能衡量 6 条已知漏洞的召回,不能支持完整 Precision。

## 5. Argus 侧结果(已完成)

- **配置**:`docs/comparisons/configs/argus-vampi-5class.yaml`(injection/xss/auth/authz/ssrf,source_mode=stripped,strict structured output)
- **模型**:`ds.public.deepseek-v4-pro`(推理模型,HTTP 超时 600s)
- **产物**:`runs/vampi-5class-final/findings.json`(14 条)+ `report.md`
- **跑批**:全 6 节点完成(build_graph → enrichment → vuln → report)

### 5.1 Argus 检出的 14 条 finding

| # | vuln_class | severity | title | 位置 |
|---|---|---|---|---|
| 0 | injection | high | SQL Injection in User.get_user | models/user_model.py:72 |
| 1 | auth | high | Missing authentication on user information endpoint | api_views/users.py:24 |
| 2 | auth | critical | Unauthenticated exposure of all credentials via debug endpoint | api_views/users.py:24 |
| 3 | auth | high | Passwords stored in plaintext | models/user_model.py:21 |
| 4 | auth | medium | User enumeration via login error messages | api_views/users.py:85 |
| 5 | auth | medium | No token invalidation / logout capability | api_views/users.py:85 |
| 6 | authz | high | Unauthenticated access to all books list | api_views/books.py:20 |
| 7 | authz | high | IDOR in get book by title | api_views/books.py:53 |
| 8 | authz | medium | Unauthenticated user listing | api_views/users.py:20 |
| 9 | authz | medium | Unauthenticated debug disclosure of all user credentials | api_views/users.py:25 |
| 10 | authz | medium | Unauthenticated user lookup by username | api_views/users.py:46 |
| 11 | authz | high | Horizontal password change for arbitrary user | api_views/users.py:189 |
| 12 | authz | critical | Privilege escalation via unauthenticated admin creation | api_views/users.py:65 |
| 13 | authz | critical | Unauthenticated database population/reset | api_views/main.py:8 |

### 5.2 Argus 检出评分

| findings 数 | 已检出 GT | 未检出 GT | Detection Recall |
|---:|---:|---:|---:|
| 14 | 6 | 0 | **1.000** |

按 file + line/handler 一对一匹配,Argus 对 6 条 comparison-scope GT 的检出如下:

| GT id | handler | 检出? | finding |
|---|---|---|---|
| vampi-bola-books-get | get_by_title | ✅ | finding[5] authz: IDOR books |
| vampi-bola-update-password | update_password | ✅ | finding[4] auth / finding[7] authz |
| vampi-auth-debug | debug | ✅ | finding[8] authz: debug endpoint 无授权 |
| vampi-massassign-admin | register_user | ✅ | finding[3] auth / finding[6] authz |
| vampi-user-enum-login | login_user | ✅ | finding[2] auth: user enumeration |
| vampi-sqli-getuser | get_user | ✅ | finding[0] injection: SQLi |

Argus 检出全部 6 条 comparison-scope GT。未匹配的其余 finding 因 GT 不完整而保持“未裁决”,不标记为 FP。分类诊断同样为 `6/6`。

本正式 arm 的 14 条输出已逐条裁决为 13 个独立真实问题、1 个重复问题、0 个 false；重复项是 authz 对 debug 暴露的重复报告。有效性 precision 为 `1.000`。

## 6. 评分方案修正:检出与分类分离

原 `score()` 的 `_compatible_class` 为内部消融(T17,含 business-logic)设计:
- `authentication` 只兼容 `auth`(不兼容 `authz`)
- `trust_boundary` 只兼容 `business_logic`(不兼容 `auth`/`authz`)
- `ownership`/`role` 兼容 `authz` 和 `business_logic`

直接用该规则评价跨工具检出能力会混淆两个问题:工具是否发现漏洞,以及工具使用了什么分类标签。例如 Argus 已发现 debug 无认证,但因标成 `authz` 被旧规则算作 FN。

修正后的方案:
1. **主指标 Detection Recall**:`score_detection()` 使用相同源码锚点和一对一匹配,忽略工具自身 taxonomy,回答“已知漏洞是否被发现”。
2. **分类诊断**:原 `score()` 的分类兼容命中结果保留在 JSON 的 `taxonomy_agreement`,只用于观察标签兼容性,不包含 FP/Precision,也不作为检测能力排名。
3. **Precision 分层**:自动 GT 不把未匹配项直接当 FP;另用 `vampi-final-adjudication.json` 对最终 34 条 finding 逐条标注 true/duplicate/false,单独报告有效率与重复率。

## 7. Shannon 侧结果(已完成)

Shannon 跑批完成,产物在 `../shannon/workspaces/vampi-shannon/deliverables/`,经 `normalize_shannon.py` 归一后打分。

### 7.1 Shannon 检出的 finding(20 条,归一后)

| vuln_class | 条数 | 代表性 finding |
|---|---:|---|
| injection | 1 | INJ-VULN-01: SQLi(归一后锚定 sink models/user_model.py:73) |
| xss | 0 | (VAmPI 无 XSS sink) |
| auth | 12 | AUTH-VULN-06(debug 无认证)、AUTH-VULN-08(mass-assign admin)、密码明文存储、JWT secret 弱、无 rate limit 等 |
| authz | 7 | AUTHZ-VULN-01(BOLA books)、AUTHZ-VULN-02(BOLA update_password)、AUTHZ-VULN-03(debug 无授权)、AUTHZ-VULN-04(mass-assign) |
| ssrf | 0 | (VAmPI 无 SSRF 端点) |

Shannon 的 auth 分析器拆得很细(12 条):Token 管理、传输安全、登录逻辑、密码存储、认证绕过等各自独立成条。Argus 同类问题合并更粗(auth 5 条)。

### 7.2 Shannon 检出评分

| findings 数 | 已检出 GT | 未检出 GT | Detection Recall |
|---:|---:|---:|---:|
| 20 | 6 | 0 | **1.000** |

Shannon 对 6 条 comparison-scope GT 的检出(按 file + line/handler 匹配):

| GT id | 检出? | finding |
|---|---|---|
| vampi-bola-books-get | ✅ | AUTHZ-VULN-01 authz @ api_views/books.py:50 |
| vampi-bola-update-password | ✅ | AUTHZ-VULN-02 authz @ api_views/users.py:186 |
| vampi-auth-debug | ✅ | AUTH-VULN-06 auth + AUTHZ-VULN-03 authz @ api_views/users.py:24 |
| vampi-massassign-admin | ✅ | AUTHZ-VULN-04 authz + AUTH-VULN-08 auth @ api_views/users.py:60 |
| vampi-user-enum-login | ✅ | AUTH-VULN-07 auth @ api_views/users.py:101-106 |
| vampi-sqli-getuser | ✅ | INJ-VULN-01 injection, sink @ models/user_model.py:73 |

Shannon 检出全部 6 条 comparison-scope GT。未匹配的其余 finding 同样保持“未裁决”。

## 8. 对照表

| 工具 | findings 数 | 已检出 GT | 未检出 GT | Detection Recall |
|---|---:|---:|---:|---:|
| Shannon | 20 | 6 | 0 | **1.000** |
| Argus | 14 | 6 | 0 | **1.000** |

> `findings 数`只描述输出规模。两边报告拆分粒度不同,且未匹配项未完成真假裁决,不能据此计算 Precision 或判断覆盖优劣。

### GT 命中交集

- **两边都命中**: `vampi-bola-books-get`, `vampi-bola-update-password`, `vampi-auth-debug`, `vampi-massassign-admin`, `vampi-user-enum-login`, `vampi-sqli-getuser`
- **仅 Shannon**: 无
- **仅 Argus**: 无

### 逐条 GT 对比

| GT | Shannon | Argus | 差异原因 |
|---|---|---|---|
| vampi-bola-books-get | ✅ authz L50 | ✅ authz L51 | 平 |
| vampi-bola-update-password | ✅ authz L186 | ✅ auth L179 + authz L189 | 平 |
| vampi-auth-debug | ✅ auth/authz L24 | ✅ authz L25 | 都检出,分类标签不同 |
| vampi-massassign-admin | ✅ auth/authz L60 | ✅ auth/authz L52/L59 | 都检出 |
| vampi-user-enum-login | ✅ auth L101-106 | ✅ auth L85 | 都检出 |
| vampi-sqli-getuser | ✅ injection sink L73 | ✅ injection L73 | 都检出 |

## 9. 结论

### 9.1 核心发现:当前 GT 范围内检出能力持平

在 VAmPI 当前 6 条 comparison-scope GT 上,**Shannon 与 Argus 均检出 6/6,Detection Recall 都是 1.000**。按类别看,injection、auth、authz 三个有正样本的类别也都是两边全检出;XSS/SSRF 因无正样本为 N/A。

在显式 comparison taxonomy 下,Shannon 与 Argus taxonomy agreement 均为 6/6；本正式纯五类 arm 未出现影响 GT 命中的 taxonomy 差异。

两边仍有可观察差异:
1. **分类口径不同**:对认证与授权边界的标签选择不同,应作为分类质量单独评价。
2. **输出覆盖和粒度不同**:Shannon 报告更多 token、传输和限流问题,但当前 GT 未完整裁决这些 finding,且两边拆分粒度不同,所以只能作为后续评测线索,不能据此证明 Shannon 整体检测更强。

### 9.2 范式差异的实际影响(§2 声明的验证)

| 维度 | 预期 | 实际观察 |
|---|---|---|
| Shannon 黑盒能看运行时 | 可能发现静态看不到的 | Shannon 报了 Transport_Exposure(无 SSL)、Abuse_Defenses_Missing(无 rate limit)等运行时缺陷,Argus 静态未报——符合预期,且这是 Argus 范式上的固有限制 |
| Argus 静态能看全调用链 | 可能发现黑盒触达不了的 | 本轮 VAmPI 单体小应用,未观察到 Argus 独有的调用链发现——需更大靶场(crAPI)验证 |
| Shannon 有 exploit 验证层 | 本轮关闭(公平口径) | 两边均无验证,只比发现层——口径对齐 |

### 9.3 旧评分口径的影响(§6)

旧 invariant 兼容表把分类标签当成检出前置条件,使已发现的漏洞被计为 FN,其中 auth-debug 还不对称地有利于 Shannon。修正后主指标不再受该 taxonomy 差异影响;旧结果仅保留为分类兼容诊断。

### 9.4 本轮结论

**在 VAmPI 当前 6 条 comparison-scope GT 范围内,Argus 与 Shannon 的漏洞检出能力一致,均为 6/6。** 自动评分曾出现的差距由分类兼容规则造成,现已将检出与分类拆分。

这一结论不能外推为两者整体能力完全一致:本轮只有单靶场和 6 条已知漏洞,XSS/SSRF 没有有效正样本,额外 findings 也未完成真假裁决。整体能力比较需要扩大 GT 和靶场后再下结论。

### 9.5 Argus 改进方向(基于本轮差距)

1. **补齐缺失正样本**:当前已完成所有 finding 的 true/duplicate/false 裁决;下一步重点补 XSS/SSRF 正样本。
2. **分类质量单独评估**:定义跨工具统一 taxonomy,单独报告 classification accuracy,不再污染 Detection Recall。
3. **更大靶场验证**:在 crAPI/flowmart 上扩充样本,验证结论的泛化性。

### 9.6 局限

- **单靶场**:仅 VAmPI,需 crAPI/flowmart 验证泛化性。
- **GT 范围窄**:vampi.json 有 6 条 comparison-scope 正样本,但 XSS/SSRF 无正样本,仍需 flowmart/crAPI 完成跨靶场验证。
- **自动 Precision 暂缺**:GT 不完整,不能把未匹配 finding 直接当作 FP;逐条人工裁决显示 Shannon 20 条、Argus 14 条均为真实问题或同根因重复,Validity precision 均为 1.000。
- **历史评分不可作检测结论**:旧分类兼容分只反映标签映射差异;当前显式 taxonomy agreement 与 Detection Recall 分开报告。

## 10. 复现步骤

```bash
# ① 部署 VAmPI
docker compose -f evaluation/targets/VAmPI/docker-compose.yaml --project-directory evaluation/targets/VAmPI up -d --build
# 验证 :5002(vulnerable=1)
curl -s http://localhost:5002/openapi.json | python -m json.tool

# ② Shannon 跑批(需 ../shannon/.env 配 Anthropic 凭据)
cd ../shannon
./shannon start -u http://localhost:5002 -r /Users/hetao/work/project/argus/evaluation/targets/VAmPI \
  -c /Users/hetao/work/project/argus/docs/comparisons/configs/shannon-vampi.yaml \
  -w vampi-shannon

# ③ Argus 跑批
uv run python -m argus.cli start -r evaluation/targets/VAmPI -w vampi-5class-final \
  -c docs/comparisons/configs/argus-vampi-5class.yaml --yolo

# ④ 对照打分
uv run python evaluation/scripts/compare_shannon_argus.py \
  --shannon-deliverables ../shannon/workspaces/vampi-shannon/deliverables \
  --argus-findings runs/vampi-5class-final/findings.json \
  --ground-truth evaluation/ground_truth/vampi.json \
  --output docs/comparisons/vampi-comparison.json \
  --markdown docs/comparisons/_comparison-snippet.md
```

对比脚本默认读取 `docs/comparisons/vampi-final-adjudication.json`,将逐条人工裁决统计写入 JSON 和 Markdown。

## 11. 本轮非目标

- crAPI/flowmart 扩展结果(当前进度和外部阻塞见 `docs/comparisons/EXPANSION-STATUS.md`)
- business-logic/invariant 对照(Argus 新功能,本轮不参与)
- Shannon Exploitation 验证层对照(公平口径已关闭)
- 性能/成本对照
