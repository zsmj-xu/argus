# Argus 冻结契约 (Contracts)

这个目录定义 Argus 的**核心接口契约**。它是编排层与分析器之间唯一的耦合点。

## 铁律

1. **契约冻结后,任何人写实现前不得私自修改。** 改契约 = 改 spec,必须走 `docs/COLLABORATION.md` 里的契约变更流程,双方同意。
2. 这里的定义是**权威**。实现代码里的 `argus/contracts.py` 必须与本目录逐字一致(M1 任务会把它落成可导入的 Python 模块并加契约测试)。
3. 所有分析器的产出(Finding)必须锚回 codegraph 的 `node_id` + 行号。这是报告和对照评测统一的前提。

## 文件

- `interfaces.py` —— Analyzer 协议、AnalysisContext、AnalyzerResult、Finding、ArgusState、枚举。权威定义。

## codegraph 事实层的现实约束

基于对真实 `codegraph.db` 的核查(2026-07-15):

- **节点类型 (kind)**:`class` / `file` / `function` / `import` / `method` / `struct` / `type_alias` / `variable`
- **边类型 (kind)**:`calls` / `contains` / `imports` / `instantiates` / `references`
- **codegraph 没有 endpoint/route 节点,也没有数据流边**。

结论:HTTP 路由骨架(endpoint → handler)、业务流语义、信任边界、不变量,**codegraph 里都没有**,必须由 ENRICHMENT 阶段的富化器补出来,写进 `enriched-graph`。这是富化阶段存在的根本理由,也是 `AnalysisContext.enriched` 字段的来源。
