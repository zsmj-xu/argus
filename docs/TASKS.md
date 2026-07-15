# Argus 任务看板

规则见 `docs/COLLABORATION.md`。任务卡片详情见 `docs/superpowers/plans/2026-07-15-argus.md`。
状态:`pending` → `in_progress` → `review` → `done`。领取时把归属和状态改掉并提交这条更新。

---

## 契约变更请求

(改契约前在此登记:动机 + 改动 + 影响的 task,待对方确认。当前无。)

---

## 共享文件协调

以下文件多人可能触及,改前在此声明避免撞车:
- `argus/argus/orchestration/pipeline.py`(编排接线)
- `argus/argus/orchestration/registry.py`(注册表)
- `argus/argus/cli.py`(命令分发)

(当前无进行中的声明。)

---

## 阶段 A —— 地基(Claude 独做,合并进 main 前 Codex 不写实现)

| Task | 标题 | 归属 | 依赖 | 里程碑 | 状态 |
|---|---|---|---|---|---|
| T01 | 项目脚手架与工具链 | claude | — | M1 | pending |
| T02 | 契约层落地 | claude | T01 | M1 | pending |
| T03 | GraphHandle codegraph 封装 | claude | T02 | M1 | pending |
| T04 | 配置解析 + 审计型 LLM | claude | T02 | M1 | pending |
| T05 | 注册表+编排+checkpoint+CLI 壳 | claude | T03,T04 | M1 | pending |

**阶段 A 出口**:T05 合并进 `main`。M1 验收(见计划 T05 Step 6)通过。

---

## 阶段 B —— 并行(M1 合并后开始)

| Task | 标题 | 归属 | 依赖 | 里程碑 | 状态 |
|---|---|---|---|---|---|
| T06 | authz 漏洞分析器 | codex | T05 | M2 | pending |
| T07 | 报告生成 | claude | T05 | M2 | pending |
| T08 | injection/xss/auth/ssrf 分析器 | codex | T06 | M2 | pending |
| T09 | interrupt 检查点 + continue | claude | T05 | M3 | pending |
| T10 | 命令行参数注入 --set/--focus | claude | T09 | M3 | pending |
| T11 | 改产物文件后 continue | claude | T09 | M3 | pending |
| T12 | business-flow 富化器 | claude | T05 | M4 | pending |
| T13 | business-logic 漏洞分析器 | codex | T12 | M4 | pending |
| T14 | invariant 富化器(实验性) | codex | T12 | M4 | pending |
| T15 | 靶场资产导入 | codex | T05 | M5 | pending |
| T16 | 评测打分 | codex | T15 | M5 | pending |
| T17 | 图组/无图组对照 + 基线 | codex | T16 | M5 | pending |
| T18 | 端到端对照实验 | claude | T13,T14,T17 | M5 | pending |

---

## 归属摘要

- **Claude**:地基全套(T01–T05)、报告(T07)、人在环路(T09–T11)、business-flow 富化(T12)、最终对照实验(T18)。侧重编排、图、富化、人机交互。
- **Codex**:漏洞分析器(T06/T08/T13/T14)、评测体系(T15–T17)。侧重分析器实现与评测。

依赖关系保证:Codex 的 T06 依赖 Claude 的 T05(地基);Codex 的 T13/T14 依赖 Claude 的 T12(富化器)。跨人依赖点已在依赖列标出,领取前确认前置 task 状态为 `done`。
