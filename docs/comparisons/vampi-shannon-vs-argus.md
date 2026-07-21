# VAmPI 对照实验:Shannon vs Argus 漏洞检测能力

**日期**:2026-07-20
**靶场**:VAmPI(Flask 单体 API,`vulnerable=1` 模式)
**状态**:进行中(Argus 侧已完成,Shannon 侧跑批中)

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

**人工核对 recall = 4/4 = 1.0**(vs score.py 算出的 0.500)。差距全部来自 §6 口径限制:score.py 的 invariant 兼容表让 `authz` 不匹配 `authentication`、`auth`/`authz` 不匹配 `trust_boundary`。这一差距在 §9 结论中需显式声明,避免误读为"Argus 检测能力只有 Shannon 一半"。

## 6. 口径限制(score.py invariant 兼容)

`argus/eval/score.py` 的 `_compatible_class` 为内部消融(T17,含 business-logic)设计:
- `authentication` 只兼容 `auth`(不兼容 `authz`)
- `trust_boundary` 只兼容 `business_logic`(不兼容 `auth`/`authz`)
- `ownership`/`role` 兼容 `authz` 和 `business_logic`

阶段 C 公平口径明确**不启用** business-logic 分析器,导致 Argus 用 auth/authz 检出的 massassign(trust_boundary)和部分 debug(authentication)无法匹配到 invariant 类 GT。这是口径限制,非检测能力缺陷。本轮在对照表中如实标注,不改 score.py(改 score.py 属契约变更,影响 T17 已评审的内部消融结果)。

## 7. Shannon 侧结果(待 C3 跑批完成)

> **占位**:C3 跑批完成后填入。Shannon 产物在 `targets/VAmPI/.shannon/deliverables/`,经 `normalize_shannon.py` 归一后打分。

### 7.1 Shannon 检出的 finding

<!-- TODO(C3): 填入 Shannon *_exploitation_queue.json 归一后的 finding 清单 -->

### 7.2 Shannon 打分

<!-- TODO(C3): 填入 Shannon recall/precision/TP/FP/FN -->

## 8. 对照表(待 Shannon 侧完成)

<!-- TODO(C7): 填入 compare_shannon_argus.py 产出的对照表 -->

| 工具 | findings 数 | TP | FP | FN | Recall | Precision |
|---|---:|---:|---:|---:|---:|---:|
| Shannon | TBD | TBD | TBD | TBD | TBD | TBD |
| Argus | 12 | 2 | 10 | 2 | 0.500 | 0.167 |

### GT 命中交集

<!-- TODO(C7): 两边都命中 / 仅 Shannon / 仅 Argus -->

## 9. 结论(待对照表完成后补充)

<!-- TODO(C8): 基于 §8 对照表 + §2 范式差异 + §6 口径限制,给出 Argus 复刻 Shannon 检测能力的结论 -->

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
