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
- (T07 已完成合并,report 节点占用已释放。当前无进行中的声明。)

> ⚠️ **给 codex 的提醒(重要)**:`codex/T06` 分支是从早期 main 拉的,**落后于当前 main**(现已含 T12 business-flow 富化器 + T07 报告生成)。直接合并会与这些产生冲突/回退。**合并 T06 前请先 `git rebase main` 或 `git merge main`**,把 T12/T07 纳入,确认 business_flow、reporting 目录仍在、report 节点是 render_report 版本。

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
| T06 | authz 漏洞分析器 | codex | T05 | M2 | in_progress |
| T07 | 报告生成 | claude | T05 | M2 | ✅ done |
| T08 | injection/xss/auth/ssrf 分析器 | codex | T06 | M2 | in_progress |
| T09 | interrupt 检查点 + continue | claude | T05 | M3 | pending |
| T10 | 命令行参数注入 --set/--focus | claude | T09 | M3 | pending |
| T11 | 改产物文件后 continue | claude | T09 | M3 | pending |
| T12 | business-flow 富化器 | claude | T05 | M4 | ✅ done |
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
