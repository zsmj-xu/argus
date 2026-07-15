"""business-flow 富化器子包。

在 codegraph 的调用图骨架之上,用 LLM 重建"从请求到执行"的业务流语义:
路由骨架(endpoint→handler)、每个 handler 对资源的操作、以及每条入口的业务
意图与信任边界。产出被合并进 enriched-graph,供下游业务逻辑漏洞分析器(T13)消费。

analyzer.py 导出模块级 `ANALYZER` 实例,由 argus.orchestration.registry 自动发现。
产出结构的权威说明见同目录 SCHEMA.md。
"""
