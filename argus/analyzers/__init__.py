"""分析器包。

每个分析器放在 argus/analyzers/<name>/ 子包里,其 analyzer.py 导出一个名为
`ANALYZER` 的实例(实现 argus.contracts.Analyzer 协议),由注册表自动发现。
M1 阶段尚无任何分析器子包。
"""
