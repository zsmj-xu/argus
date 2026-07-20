# Argus — 设计文档

**日期**: 2026-07-15
**状态**: 已通过 brainstorming 评审,待实现规划
**技术栈**: Python + LangGraph + codegraph CLI/MCP + OpenAI-compatible Chat Completions API

---

## 1. 项目目标与定位

**Argus 是一个 AI 白盒代码扫描工具**——以 codegraph 代码图为共享事实层,用一组可插拔的分析器发现漏洞,由 LangGraph 编排成一条可随时暂停、人工介入、再恢复的管线。

Argus 沿用 Shannon 的五阶段 subagent 编排模式,但换掉分析的"燃料":不再靠 recon 探活运行中的目标,而是先构建 codegraph 代码图,让 subagent 在图上做静态白盒分析。它复用三个来源的资产:

- **Shannon**(TypeScript/Temporal):提供可移植的**知识**——五阶段编排思路、漏洞 agent 的 prompt(injection/xss/auth/authz/ssrf)、审计/报告/检查点的设计模式。代码跨语言搬不过来,但 prompt 和架构模式能搬。
- **logic-graph**(Python 原型):提供**建图/语义分析原型**和**靶场 + ground-truth + 图组/无图组对照评测**方法论。
- **codegraph**(全局 CLI + MCP server):成熟的第三方代码图工具,生成 SQLite 图(nodes/edges/files + FTS)。不用我们造,直接调 CLI 或挂 MCP。

### 核心价值主张

用一个统一的建图/分析框架,把「移植自 Shannon 的通用漏洞分析」和「新增的业务流语义 + 不变量分析」放在同一套可插拔架构里,专门补 Shannon 覆盖不到的**业务逻辑漏洞**(如商城改购物车金额下单这类)。

### 明确的设计立场

- **分析方法本身是待验证的**。不变量、业务流语义都当作**可对照评测的策略**,用真实靶场数据决定去留,而不是拍脑袋焊死。logic-graph 的实验数据已表明:在公平测试(去注释泄露)下,"带不变量的语义图"未必跑赢"直接读源码"(flowmart 图组 5/6 输给无图组 6/6),且召回好看时精确率极低(crAPI 图组 5/23)。因此 Argus 必须把分析策略做成可插拔、可对照,而非单点押注。

### 明确不做(YAGNI)

- ❌ 不做动态验证 / 实际发起 HTTP 攻击 / 实际漏洞利用(exploitation)——纯静态白盒发现,输出候选漏洞清单。
- ❌ 不集成 Temporal / Docker——用 LangGraph 原生 checkpoint 做持久化。
- ❌ 不做运行中目标的 recon / 攻击面探活 / 浏览器自动化 / TOTP 登录。

---

## 2. 整体架构与数据流

一条 **LangGraph `StateGraph` 编排的白盒分析管线**,五个阶段。

```
目标源码仓库
   │
   ▼
[Phase 0] 建图 (codegraph init)          → 调 codegraph CLI,产出 .codegraph/codegraph.db
   │                                        事实层:nodes/edges/routes 骨架
   ▼
[Phase 1] 语义富化 (Enrichment)          → 可插拔:业务流语义重建、不变量标注
   │                                        在图骨架上补 LLM 语义层,落盘 enriched-graph.json
   ▼  ⏸ 人工检查点 review-enrichment:看富化结果,可修正/注入领域知识/加身份认证上下文
[Phase 2] 漏洞分析 (N 个并行分析器)      → 可插拔:injection/xss/auth/authz/ssrf(移植 Shannon)
   │                                        + business-logic / invariant(新增)
   │                                        每个分析器读 codegraph + enriched-graph
   ▼  ⏸ 人工检查点 review-findings:看候选清单,筛选/补充/调方向
[Phase 3] 验证/定级 (可选)               → LLM 复核候选,降误报,定 severity/confidence
   │
   ▼
[Phase 4] 报告 (Reporting)               → 移植 Shannon 报告风格,产出 markdown 报告
```

### 四条核心设计原则

1. **codegraph 是共享只读事实层**——所有分析器都基于同一张图,不各自重复解析源码。通过 codegraph CLI/MCP 访问。
2. **一切皆可插拔节点**——每个分析器是 LangGraph 图里的一个节点,配置里开关。编排层不认识任何具体分析器。
3. **每阶段落盘 + 人工检查点**——用 LangGraph 的 checkpoint + interrupt。人能在阶段间暂停、看中间产物、注入参数、再放行。
4. **分析方法本身是待验证的**——见第 1 节设计立场。

---

## 3. 可插拔分析器接口

整个项目的心脏。**分析器"可插拔"靠三样东西定死:统一输入契约、统一输出契约、统一注册机制**。三者冻结在 `docs/contracts/`,内部实现随便。

### 3.1 统一契约

```python
class Analyzer(Protocol):
    name: str                 # "injection" / "business-logic" / "invariant" ...
    phase: Phase              # ENRICHMENT 还是 VULN_ANALYSIS
    requires: list[str]       # 依赖的产物,如 ["enriched-graph"];编排据此拓扑排序

    def run(self, ctx: AnalysisContext) -> AnalyzerResult: ...
```

**输入 `AnalysisContext`(只读)**——所有分析器拿到同一份,这是"共享事实层"落地的关键:

- `graph`:codegraph 句柄(查 nodes/edges/routes,调 `explore`/`callers`/`callees`/`node`)
- `enriched`:上一阶段富化产物(业务流语义、不变量标注),可能为空
- `source`:目标仓库只读访问 + `source_mode`(raw / stripped,继承 logic-graph 防泄露)
- `config`:人注入的领域知识(角色映射、身份认证上下文、聚焦/回避规则)
- `llm`:LLM 客户端(带审计包装)

**输出 `AnalyzerResult`(统一 Finding schema)**——无论哪个分析器,产出的 finding 长一个样,报告/评测才能统一处理:

```
Finding {
  id, analyzer, vuln_class, title, severity, confidence,
  locations: [(file, line, node_id)],   # 强制锚回 codegraph 节点
  data_flow, rationale, evidence, remediation
}
```

**强制约束**:所有分析器(包括不变量这类实验性的)产出的 Finding 都必须锚回 codegraph 的 `node_id` + 行号。这是报告和对照评测统一的前提,也是契约一致性测试的校验点。

### 3.2 两类分析器(功能解耦)

分成两类,职责清晰,后续分析和评测都更好处理:

| 类 | phase | 来源 | 说明 |
|---|---|---|---|
| **富化器** | ENRICHMENT | 新增 | `business-flow`(重建请求→执行的业务意图/信任边界)、`invariant`(标注业务不变量)。产出写进 `enriched-graph`,供下游漏洞分析器读。都可单独开关。 |
| **漏洞分析器** | VULN_ANALYSIS | 移植 Shannon + 新增 | `injection`/`xss`/`auth`/`authz`/`ssrf`(移植 Shannon prompt,改成读图而非探活)+ `business-logic`(吃富化产物,专抓改金额那类)。并行跑。 |

### 3.3 注册与开关

- 分析器放在 `argus/analyzers/<name>/`,每个目录含实现 + prompt 模板。
- **注册表**(类似 Shannon 的 `AGENTS` record)自动发现。
- YAML 配置控制启用哪些、并行度、依赖顺序:
  ```yaml
  analyzers:
    enrichment: [business-flow]        # 关掉 invariant 试试
    vuln: [authz, business-logic, injection]
  ```
- **编排层完全不认识具体分析器**——只按 `requires` 拓扑排序、并行调度、收集 `AnalyzerResult`。加一个新分析器 = 加一个目录 + 注册,不碰编排代码。

---

## 4. 可停可续 + 人在环路

本项目最核心的诉求。机制:**LangGraph 的 checkpointer + interrupt**。

### 4.1 状态与持久化

- 整条管线是一个 **LangGraph `StateGraph`**,共享一个 `ArgusState`(TypedDict):目标仓库、配置、各阶段产物路径、findings 累积、当前阶段游标。
- 用 **`SqliteSaver` checkpointer** 持久化到 `runs/<workspace>/state.db`。每个节点执行完自动落 checkpoint。
- **可续**:进程崩了/手动停了,`argus resume -w <workspace>` 从最后一个 checkpoint 继续,不重跑已完成节点。节点级粒度(比 Shannon 的阶段级更细)。
- **可停**:`Ctrl-C` 或 `argus stop`,当前节点跑完即落盘退出。

### 4.2 人工检查点(两个 interrupt)

用 LangGraph 的 **`interrupt()`**——图执行到检查点节点时挂起,把中间产物暴露给人,等人放行:

```
Phase 1 富化完 ──▶ ⏸ interrupt("review-enrichment")
                     人可以:看 enriched-graph.json / 编辑它 /
                             注入身份认证上下文、角色映射、领域规则 /
                             调整下游要跑哪些分析器
                     然后 argus continue -w <ws> 放行

Phase 2 候选清单 ─▶ ⏸ interrupt("review-findings")
                     人可以:筛掉误报 / 补充方向 / 让某分析器重跑 /
                             决定要不要进 Phase 3 验证
```

### 4.3 人如何介入(三种方式,全部要做)

1. **停在检查点被动等**(默认)——上面的 interrupt。
2. **命令行注入参数**——`argus continue -w <ws> --set auth.roles=./roles.yaml --focus src/orders/`,把人的引导写进 `ArgusState.config`,下游节点读得到。
3. **直接改产物文件**——中间产物都落盘为 JSON/MD,人可手动编辑 `enriched-graph.json` 再 continue,图会读改过的版本。

### 4.4 检查点可配置

- `--yolo` / 配置 `checkpoints: false`:跳过所有 interrupt,一路跑完(CI 场景)。
- 也能配 `checkpoints: [review-enrichment]`:只在富化后停。
- **默认全开**。

---

## 5. 测试、验收标准、评测方法论

分三层,从"代码对不对"到"漏洞找得准不准"。

### 5.1 单元/集成测试(每个 PR 必过)

- **契约测试**:所有分析器跑"契约一致性测试"——输入 `AnalysisContext`、输出必须是合法 `Finding`(schema 校验、locations 锚回真实 node_id)。这是"可插拔"的护栏:新分析器只要过契约测试,就能挂进编排。
- **编排测试**:checkpoint 落盘/resume、interrupt 挂起/continue、节点级不重跑——用 mock 分析器验证,不依赖真 LLM。
- **工具层**:codegraph 封装、Finding 序列化、配置解析。
- 质量门:`ruff` + 类型检查(mypy/pyright)+ `pytest` 绿。

### 5.2 端到端验收(靶场对照,继承 logic-graph 方法论)

复用 logic-graph 已验证的靶场资产:**VAmPI、crAPI、自造 flowmart**,都带 ground-truth。

- **召回率/精确率**:findings vs ground-truth,自动打分(logic-graph 的 Stage 3 evaluator 可移植)。
- **对照实验**:图组 vs 无图组、开/关某分析器——用数据回答"业务流富化到底有没有用、不变量值不值得留"。
- **防泄露**:强制 `source_mode=stripped`(去注释/docstring),避免靶场教学注释泄露答案(logic-graph 踩过的坑)。

### 5.3 验收标准(项目级里程碑)

| 里程碑 | 验收标准 |
|---|---|
| **M1 骨架可跑(地基,由 Claude 先立)** | codegraph 建图 → 空跑编排 → 落 checkpoint → resume 成功;契约层冻结;契约测试绿 |
| **M2 单分析器闭环** | 至少 1 个漏洞分析器(建议 authz)在 VAmPI 上产出合法 Finding + 报告 |
| **M3 人在环路** | 两个 interrupt 生效;三种介入方式(停等/命令行注入/改产物文件)都验证通过 |
| **M4 富化 + 业务逻辑** | business-flow 富化 + business-logic 分析器跑通,在 flowmart 上找到跨 handler 漏洞 |
| **M5 对照评测** | VAmPI + crAPI + flowmart 三靶场跑出召回/精确率;开/关富化的对照数据成表 |

每个 task 卡片的验收标准挂到对应里程碑,交付时对着勾。

---

## 6. Claude + Codex 协作规范

详细流程见 `docs/COLLABORATION.md`,此处记录设计决策。

### 6.1 物理隔离:git worktree

Argus 是独立 git 仓库(`/Users/hetao/work/project/argus`)。两个 agent 各在自己的 worktree 工作,通过 PR 合回 main,合并前交叉评审。

### 6.2 节奏:先立地基,再并行

- **M1 地基由 Claude 先做并合并**——契约层 + 空编排 + checkpoint。这是两人并行的地基。
- M1 合并后,**Claude 和 Codex 对半分模块并行**。

### 6.3 分工:按垂直切片

契约层是唯一耦合点,必须在任何人写实现前**冻结在 `docs/contracts/`**。契约不动,两边并行写实现就不冲突。契约变更需双方同意(改契约 = 改 spec,不能私自改)。

### 6.4 交互协议:通过文件,不靠实时对话

所有协调通过 git 仓库里的文件,codex 自行读取:`docs/specs/`(设计)、`docs/plan/`(带验收标准的 task 卡片)、`docs/contracts/`(冻结的接口契约)、`docs/COLLABORATION.md`(协作规范)、`docs/TASKS.md`(任务看板)。

### 6.5 质量门(合并前必过)

`ruff` + 类型检查 + 该模块单测 + **对方 agent 交叉评审**。
