# Argus 任务看板

规则见 `docs/COLLABORATION.md`。任务卡片详情见 `docs/superpowers/plans/2026-07-15-argus.md`。
状态:`pending` → `in_progress` → `review` → `done`。领取时把归属和状态改掉并提交这条更新。

---

## 契约变更请求

(改契约前在此登记:动机 + 改动 + 影响的 task,待对方确认。当前无。)

---

## 共享文件协调

以下文件多人可能触及,改前在此声明避免撞车:
- `argus/orchestration/pipeline.py`(编排接线)
- `argus/orchestration/registry.py`(注册表)
- `argus/cli.py`(命令分发)

**进行中的声明:**
- 当前无。

---

## 阶段 A —— 地基(Claude 独做,已完成并合并进 main ✅)

| Task | 标题 | 归属 | 依赖 | 里程碑 | 状态 |
|---|---|---|---|---|---|
| T01 | 项目脚手架与工具链 | claude | — | M1 | ✅ done |
| T02 | 契约层落地 | claude | T01 | M1 | ✅ done |
| T03 | GraphHandle codegraph 封装 | claude | T02 | M1 | ✅ done |
| T04 | 配置解析 + 审计型 LLM | claude | T02 | M1 | ✅ done |
| T05 | 注册表+编排+checkpoint+CLI 壳 | claude | T03,T04 | M1 | ✅ done |

**阶段 A 出口**:✅ M1 已合并进 `main`(merge commit `785204d`)。真实 VAmPI + codegraph 冒烟通过;26 测试绿、mypy strict clean、ruff check+format 绿。**阶段 B 现已开放,Codex 可以开始领取任务。**

### 环境说明(开工必读)
- 系统 Python 是 3.9,**必须用 uv**:`uv venv --python 3.11 && uv pip install -e ".[dev]"`,一切命令走 `uv run ...`(如 `uv run pytest -q`)。
- 质量门 4 条都要绿:`uv run pytest -q`、`uv run mypy argus/`、`uv run ruff check .`、`uv run ruff format --check .`。ruff 已 pin 到 `0.15.21`,别升级。
- 目录布局:仓库根有 `pyproject.toml`,Python 包是根下的 `argus/`,测试在根下的 `tests/`。计划里写的 `argus/argus/...` 指的就是 `<repo>/argus/...`。

### 地基给后续任务的注意事项(最终评审留下,务必读)
1. **Finding 里的 `severity`/`confidence` 是枚举**(`Severity`/`Confidence`),已登记进 checkpoint 序列化 allowlist(`argus/orchestration/checkpoints.py`)。构造 Finding 时用枚举而非裸字符串;若给 ArgusState/Finding 新增其它自定义类型,需同步扩 `_ALLOWED_MSGPACK_MODULES`。
2. **每个分析器目录 `argus/analyzers/<name>/analyzer.py` 必须导出一个模块级 `ANALYZER` 实例**(注册表靠这个发现)。analyzer.py 内部若 import 失败,注册表会**抛错**(不再静默吞掉),方便你 debug。
3. **当前分析器在 phase 内串行 for-loop 执行,不是 per-analyzer 的 LangGraph 节点**(T05 按计划的简化)。所以暂时没有 per-analyzer 的并行/独立 checkpoint。若要引入真正并行的分析器节点,`completed_nodes`/`findings`/`enriched` 需要加 reducer(`Annotated[list, operator.add]`)——**那是契约变更,须走契约变更流程**,别自己改。
4. `requires` 字段目前未被拓扑排序真正消费(靠固定的 enrichment→vuln 边序偶然满足)。T13 的 business-logic 依赖 enriched-graph 由 phase 顺序满足。若你的分析器有跨 phase 的新依赖,先在看板提出。
5. `AnalyzerBase`(`argus/analyzers/base.py`)提供 `_load_prompt()` 和 `_make_finding()`,写新分析器时继承它、复用这两个辅助,别各自造 Finding。

---

## 阶段 B —— 并行(M1 合并后开始)

| Task | 标题 | 归属 | 依赖 | 里程碑 | 状态 |
|---|---|---|---|---|---|
| T06 | authz 漏洞分析器 | codex | T05 | M2 | ✅ done |
| T07 | 报告生成 | claude | T05 | M2 | ✅ done |
| T08 | injection/xss/auth/ssrf 分析器 | codex | T06 | M2 | ✅ done |
| T09 | interrupt 检查点 + continue | claude | T05 | M3 | ✅ done |
| T10 | 命令行参数注入 --set/--focus | claude | T09 | M3 | ✅ done |
| T11 | 改产物文件后 continue | claude | T09 | M3 | ✅ done(三轮复审 + 跨进程 CLI 冒烟通过) |
| T12 | business-flow 富化器 | claude | T05 | M4 | ✅ done(T12F 已合并修复) |
| **T12F** | **business-flow 修复(2轮:调用边/段内规整/node_id 消歧/schema 扩展/引用完整性/授权执行状态/嵌套规整)** | **claude** | **T12** | **M4** | **✅ done** |
| T07F | 报告 Markdown 链接小修(2轮:链接解析基准+URL编码) | claude | T07 | M2 | ✅ done |
| T13 | business-logic 漏洞分析器 | codex | **T12F** | M4 | ✅ done |
| T14 | invariant 富化器(实验性) | codex | T12 | M4 | ✅ done |
| T15 | 靶场资产导入 | codex | T05 | M5 | ✅ done |
| T16 | 评测打分 | codex | T15 | M5 | ✅ done(C1/I3/C2 修复 + 独立复审通过) |
| T17 | 图组/无图组对照 + 基线 | codex | T16 | M5 | ✅ done(Claude Code 正式交叉评审通过 Spec✅/Approved;I-1 已知护栏缺口见评审) |
| T18 | 端到端对照实验(**Argus 内部消融**) | claude | T13,T14,T17 | M5 | ⏸ 搁置(run_eval.py 内部消融已完成,方向调整为阶段 C 的 Argus vs Shannon 对照;此内部消融本轮不跑批,保留代码) |

> **T13 依赖已从 T12 改为 T12F**:business-flow 的回审缺陷(段内非法条目不丢弃、同名 node_id 锚错、缺跨 handler 调用边/状态字段)会直接绊到 T13。**codex 请等 T12F 合并后再开 T13。** T14(invariant)不依赖这些,可照旧。

---

## 阶段 C —— Argus vs Shannon 漏洞检测能力对照(VAmPI 先跑通)

**目标**:先在 VAmPI 上跑通「Shannon 结果 ⟷ Argus 结果」端到端对照,验证 Argus 复刻 Shannon **检测**能力的实际差异。先跑通、可扩展,不追求完整评测。
**设计文档(开工必读)**:`docs/superpowers/specs/2026-07-20-argus-vs-shannon-comparison-design.md`

**公平对照口径(关键)**:
- 只比**漏洞发现层**(Shannon Phase 3 `vuln-*` vs Argus vuln 分析器)。Shannon 侧**关闭 Exploitation**(`exploit: "false"`)——因为 Argus 定义上就不做动态验证,带上会口径错位。
- Argus 侧只启用**移植自 Shannon 的 5 类分析器**(injection/xss/auth/authz/ssrf),**不启用** business-logic/invariant 新功能。
- 两边对**同一份 `evaluation/ground_truth/vampi.json`** 打分。检出召回与 taxonomy agreement 分离;未完整裁决的 GT 不直接产生自动 Precision。

**范式差异(须写进结论,非隐藏)**:Shannon 黑盒动态+源码、有 Exploitation 验证层;Argus 纯白盒静态、只输出候选清单、无验证层。

| Task | 标题 | 归属 | 依赖 | 状态 | 说明 |
|---|---|---|---|---|---|
| C1 | 部署 VAmPI 到 Docker | codex | — | ✅ done | 用 `evaluation/targets/VAmPI` 自带 `docker-compose.yaml`/`Dockerfile` 起运行中目标。实际端口:`:5001`(vulnerable=0)/`:5002`(vulnerable=1,对照用此)。OpenAPI 12 端点齐全;`_debug` 无认证返回明文密码→vuln 模式确认;认证链路 register{username,password,email}→login→`auth_token`→Bearer 已通 |
| C2 | 写 Shannon 对照 config | codex | — | ✅ done | `exploit: "false"` + scope 到 5 类 vuln 的 yaml。参考 Shannon `apps/worker/configs/example-config.yaml`。产出 `docs/comparisons/configs/shannon-vampi.yaml`。VAmPI 纯 API 认证用 `login_type: api` + 详细 login_flow(Shannon prompt 对 api 类型无专门章节,C3 跑时迭代) |
| C3 | 跑 Shannon 摸清输出格式 | codex | C1,C2 | ✅ done | **关键前置(风险 R1)**:跑一次 Shannon(exploit=false)对 VAmPI。产物在 `shannon/workspaces/vampi-shannon/deliverables/`:5 个 `*_exploitation_queue.json`(auth/authz/injection/ssrf/xss)+ recon/pre-recon deliverable + comprehensive report。格式与 queue-schemas.ts 预研一致;`vulnerable_code_location` 用 `file:line` 或 `file:line-line`(范围)。踩坑:worker 镜像构建 5 次(buildx daemon 被杀→nohup detach + 网络重试)、preflight 三拦(git init + `<>` 转义 + host.docker.internal) |
| C4 | 配 Argus 5 类 arm | codex | — | ✅ done | 正式 arm 只启用 injection/xss/auth/authz/ssrf，`strict_outputs=true`，不启用额外 business-flow/invariant 富化；配置加载测试通过。 |
| C5 | Argus 跑 VAmPI(5 类 arm) | codex | C4 | ✅ done | `vampi-5class-final` 完成，14 条 findings；Shannon/Argus 对 6 条 comparison GT 均为 6/6。|
| C6 | Shannon 输出归一适配层 | codex | C3 | ✅ done | 把 Shannon findings 转成统一 `Finding`;注入类优先锚定 sink,支持 `file:line-line`。|
| C7 | 对照打分 + 出表 | codex | C5,C6 | ✅ done | Detection Recall 与 taxonomy agreement 分离；VAmPI 两边均检出 6/6、taxonomy agreement 均 6/6；最终裁决为 Shannon 17 true/3 duplicate、Argus 13 true/1 duplicate。|
| C8 | 对照文档落盘 | codex | C7 | ✅ done | `docs/comparisons/vampi-shannon-vs-argus.md`,含范式差异、分类诊断、按类别召回和人工裁决。|

**依赖图**:
```
C1(部署) ──┬─→ C3(跑Shannon摸格式) ─→ C6(归一适配) ─┐
C2(S-config)┘                                        ├─→ C7(打分对照) ─→ C8(文档)
C4(A-config) ─→ C5(Argus跑批) ───────────────────────┘
```
关键路径:C1→C3→C6→C7→C8。C4→C5(Argus 侧)可并行。

**阶段 C 非目标**:crAPI/flowmart 扩展、business-logic/invariant 对照、Shannon 验证层对照、性能/成本对照。crAPI/flowmart 已在阶段 D 接续。

**环境资源(已确认就位)**:VAmPI 自带 Docker;Shannon 支持 `exploit:"false"`;Argus 侧 `.env` 已配 LLM gateway 凭据(`ARGUS_LLM_*`);Shannon 侧需自己的 AI 凭据(见 Shannon `.env`)。

---

## 阶段 D —— 多靶场扩展与可重复矩阵

**目标**:把 VAmPI 单靶场方法扩展到 flowmart 与 crAPI,所有缺失结果显式记为
`unavailable/N/A`,不以 0 分替代外部阻塞。

| Task | 标题 | 状态 | 说明 |
|---|---|---|---|
| D1 | 扩充 VAmPI comparison GT + 裁决 | ✅ done | comparison scope 6 条；final 纯五类 arm 两边 6/6；34 条 finding 全裁决。 |
| D2 | 通用矩阵编排 | ✅ done | `comparison-matrix.yaml` + `run_comparison_matrix.py`;四评测单元 |
| D3 | flowmart 可运行服务 | ✅ done | Flask wrapper、OpenAPI、隔离运行时测试 2/2 通过；Docker Compose 已真实构建启动，`:5012` health/OpenAPI 和 XSS/authz 动态回归通过。 |
| D4 | flowmart 双侧跑批 | 🟡 Argus done, Shannon authorization needed | Argus `flowmart-5class-final` 对 comparison scope 6/6；Shannon 需用户授权向外部 LLM 发送本地源码后执行。 |
| D5 | crAPI comparison scope | ✅ done | workshop 7 条、community 2 条（修正了无证据的公开论坛 ownership 和 coupon amount 条目）;两套 Argus 五类配置 |
| D6 | crAPI 双侧跑批 | 🟡 Argus done, Shannon/deployment needed | workshop Argus 6/7 (0.857)，community Argus 2/2 (1.000)；两侧 Shannon 仍需完整部署与授权，不能伪造双侧结果 |
| D7 | XSS/SSRF 正样本扩展 | ✅ assets done | flowmart 新增 reflected XSS differential GT;crAPI workshop 已有 SSRF GT;待双侧跑批验证 |

状态与恢复命令见 `docs/comparisons/EXPANSION-STATUS.md`。

---

## 归属摘要

- **Claude**:地基全套(T01–T05)、报告(T07)、人在环路(T09–T11)、business-flow 富化(T12)、最终对照实验(T18)。侧重编排、图、富化、人机交互。
- **Codex**:漏洞分析器(T06/T08/T13/T14)、评测体系(T15–T17)。侧重分析器实现与评测。

依赖关系保证:Codex 的 T06 依赖 Claude 的 T05(地基);Codex 的 T13/T14 依赖 Claude 的 T12(富化器)。跨人依赖点已在依赖列标出,领取前确认前置 task 状态为 `done`。

**阶段 C(C1–C8)归属未定**:任务卡归属列留 `—`,领取时按看板约定把归属和状态改掉并提交。C1/C2/C4 无依赖可立即领取并并行;C3 需 C1+C2;C5 需 C4;C6 需 C3;C7 需 C5+C6;C8 需 C7。
