# Argus 项目整体审核报告(6 视角并行审计)

**日期**:2026-07-17
**基线**:main @ ff66cc7
**方式**:6 个独立只读审核 Agent 并行,分领域审计;主控对每条 Critical 亲自 git/数据核实。
**范围**:架构与契约 / 编排·人在环路·CLI / 分析器矩阵 / 图·LLM·报告 / 测试与门禁 / 安全与评测体系。

---

## 一句话结论

**地基(契约冻结、解耦、防幻觉主线、GT 质量、安全姿态)是扎实的;但 main 上有两条卖点级功能实为"分支已实现、主干缺失",且贯穿评测与图层的"决定论/可复现性"主线尚未坐实——在补齐前,M5 对照实验(T17/T18)的数字不可采信。**

---

## 跨领域系统性主线(比单条 finding 更重要)

### 主线 A — "已实现"与"已上主干"脱节(最高风险)
两处核心能力的实现只在分支上,main 缺失,且都被误认为已完成:

1. **T11「编辑产物文件后 continue 生效」在 main 上不存在**(编排 C1)。main 的 `checkpoints.py` 仅 109 行,放行后**不读盘**;report 节点渲染内存 checkpoint 态而非 `findings.json`。`claude/T11` 三个 commit(含核心 `feat: 从磁盘重载产物`)**NOT MERGED**。更危险的是 interrupt 提示语引导用户去改文件,而 continue 静默忽略——**用户以为剔除了误报,报告里原样保留**。
   > 已核实。并纠正上一轮结论:此前"T11 冒烟验证 ✅"是在 `argus-claude-t11`(=未合并分支)上做的,证明的是分支能用,**不代表 main**。
2. **T16 评测打分 eval 代码在 main 上不存在**(评测 C0、测试 I1)。`argus/eval/score.py` 仅存于 `codex/T16*` 分支;三分支 blob 哈希相同,"T16-fix" **无任何修复**。C1/I3 至今未修。主干上评分/召回/精确率**零源码零测试**。

**含义**:项目的"完成度"需要按 main 重新对账,不能按分支 review 文档。TASKS.md 里标 done/review 的任务,要逐一确认是否真的合入 main。

### 主线 B — 决定论/可复现性未坐实(威胁 T17/T18 对照实验)
对照实验的地基是"同输入→同输出",目前有三个未落定的裂缝:

1. **node_id 决定论完全外包给外部 codegraph 二进制**(图 G1)。Argus 不生成 node_id,只读 `codegraph.db`。同库两次构建是否同 id,取决于 `/opt/homebrew/bin/codegraph` 是否用稳定内容哈希——**已实测确认真实 id 形如 `function:<hash>|<name>`,是内容哈希,可复现性大概率 OK,但仍应对该外部工具单独立项确认**(换机器/换 checkout 路径是否稳定)。
2. **评分器匹配缺陷**(评测 C1/C2/I5)。handler 裸子串误配(flowmart 6 条暴露面),且原修复方案基于"node_id 含明文 handler"的错误前提。
3. **评分器对畸形输入非确定性崩溃**(评测 I4):缺键 KeyError 而非计 FP。

### 主线 C — 两人分工留下的一致性裂缝(可一次性收敛)
1. **authz 是唯一自成一套、防幻觉更弱的分析器**(分析器 C1)。缺 batch 级 `allowed_node_ids` 白名单(可锚到全图任意节点)、接受 LLM 自带 file 路径(I1)、邻居不做 focus/avoid 过滤(I2)。**修法统一:把 authz 收敛到 `ShannonAnalyzerBase`,一次性消除 C1/I1/I2/M1/M4。**
2. **`kind` 匹配大小写处理分裂**(分析器 I3):business_flow/invariant 无 `.lower()`,某些 codegraph 后端产 `"Function"` 会静默漏掉全部节点。收敛到统一 `_is_callable_kind()`。
3. **`requires` 是死契约**(架构 I1):编排从不消费,阶段顺序靠写死调用序偶然满足。要么实现拓扑排序兑现契约,要么降级为文档注释。

---

## 按严重度汇总(去重后)

### Critical(阻断 M5 / 数据可信度)
| # | 领域 | 问题 | 状态 |
|---|---|---|---|
| A1 | 编排 | T11「编辑产物后 continue」未合入 main,人工编辑静默失效 | 已核实,claude/T11 NOT MERGED |
| A2 | 评测/测试 | T16 eval 代码未合入 main,C1/I3 未修 | 已核实,codex/T16* only |
| B1 | 图 | node_id 决定论外包给外部 codegraph,本仓库不保证 | 已核实 id 为内容哈希,需对外部工具立项确认 |
| C1 | 分析器 | authz 缺 batch node_id 白名单,防幻觉弱一档 | 已核实 |
| — | 评测 | C1 handler 裸子串误配 + C2 修复前提错误 | 见 T16-claude-review.md(已修订) |

### Important(收窄影响 / 一致性)
- 编排 I1:分析器串行执行无错误隔离,一个崩全阶段产物丢弃 + resume 重复付 LLM 成本
- 编排 I2:`start` 对已存在 workspace 无保护,会在旧 checkpoint 上乱跑并覆盖产物
- 编排 I3:`--set checkpoints=false` 可一键关掉所有人工关卡,无告警
- 分析器 I1/I2/I3:authz 接受 LLM file 路径 / 邻居不过滤作用域 / kind 大小写分裂
- 图 G2/G3/G4:同名符号错连边 / `explore` 忽略 db_path 查错图 / LIKE 通配符未转义精度 bug
- LLM L1/L2/L3:无重试 / 无成本 token 追踪 / 未处理 refusal 与截断(静默空串或坏 JSON)
- 报告 R1:title/rationale 等自由文本未转义,Markdown 结构注入面
- 架构 I1/I2:`requires` 死契约 + key 语义域未定义
- 评测 I4/I5:缺键 KeyError / C1 暴露面锁定 flowmart
- 测试 I2/I3/I4:test_contracts 硬编码绝对路径 / cli.py 命令层无测试 / graph/build.py 无测试

### Minor(加固项)
- 测试 C1(实为脆弱断言):`test_ground_truth_assets.py:49` rglob 活文件系统撞本地 `.codegraph/` 残留 → 开发机误红(CI 干净 checkout 会过)。**主干唯一的 pytest 失败源于此,非产品缺陷。**
- 编排 M1:workspace 名 `../foo` 可越出 runs/;M2:`--set` YAML 类型静默转换;M3:损坏 db 存在即跳过重建
- 架构 M1/M2/M3:vuln_class 自由字符串无枚举 / AnalyzerBase 软基类 / source_mode 双份
- 图 G5/G6、LLM L4/L5/L6、报告 R3/R4/R5:见各分报告
- 安全:靶场含演示弱口令(属评测标的,非泄密);`_FileSourceAccess.read` 缺 repo_path root 边界护栏(当前调用方路径均可信,无实际风险,建议加断言)

---

## 通过项(明确的健康信号)
- **契约冻结纪律到位**:contracts.py 与 docs/contracts/interfaces.py 逐字一致,历史仅 2 次改动且无破坏性变更。
- **分析器↔编排零反向耦合**:registry 纯协议发现,"加分析器=加目录+导出 ANALYZER"是真的。
- **防幻觉主线在 5/6 漏洞分析器一致到位**(Shannon 系 batch 白名单),仅 authz 例外。
- **报告渲染确定且忠实**,T07F 链接/URL 编码/围栏转义经独立核查可靠。
- **LLM 非确定性未泄漏到确定路径**(报告是纯函数,不调 LLM)。
- **GT 质量高**:25 条 id 唯一、in_scope 划分合理、25/25 location 实证可定位。
- **无敏感材料泄露**:无私钥/.env/嵌套 .git 被跟踪。
- **安全姿态保守**:Argus 用 Messages API 单轮文本补全,LLM 无工具/文件权限,不存在 bypassPermissions(`--yolo` 仅跳过人工 checkpoint)。
- **测试测真行为**:analyzer 给输入断言输出,orchestration 用真 SqliteSaver 跑真 LangGraph 验证 resume 不重跑;三个静态门禁(mypy strict / ruff check / ruff format)真绿。

---

## 建议的修复优先级
1. **对账主干**(主线 A):确认 T11、T16 是否漏合并 / 是否被回退;TASKS.md 状态按 main 校准。这是其它一切的前提。
2. **修 authz 收敛到 ShannonBase**(主线 C1):一次性消除防幻觉裂缝,机械改动、收益最高。
3. **真正修 T16 C1+I3+C2**(主线 B):按修订后的正确方案(node_id 反查 name),补负例,改假绿灯测试。合入前 T17/T18 数字不采信。
4. **确认外部 codegraph 决定论**(主线 B1):对该二进制单独验证 node_id 跨环境稳定性。
5. Important 逐条排期(错误隔离、start 保护、图错连边、LLM 重试/成本)。
