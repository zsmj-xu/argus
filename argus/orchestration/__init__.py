"""编排层 —— 注册表发现 + LangGraph 管道 + checkpoint + 初始状态构造。

编排层只认 argus.contracts 里的协议,不认识任何具体分析器。
加分析器 = 加 argus/analyzers/<name>/ 目录 + 导出 ANALYZER,不碰编排。
"""
