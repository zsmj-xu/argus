"""分析器注册表 —— 自动发现 argus/analyzers/ 下的分析器子包。

约定:每个分析器目录 argus/analyzers/<name>/ 有一个 analyzer.py,导出一个名为
`ANALYZER` 的模块级实例(实现 argus.contracts.Analyzer 协议)。注册表遍历子包、
导入其 analyzer.py、收集 ANALYZER。M1 阶段没有任何分析器子包,返回空 dict 是正常的。
"""

from __future__ import annotations

import importlib
import pkgutil

import argus.analyzers as analyzers_pkg
from argus.contracts import Analyzer


def discover_analyzers() -> dict[str, Analyzer]:
    """扫描 argus/analyzers/ 的子包,收集其 analyzer.py 导出的 ANALYZER 实例。

    - 只看子包(有 __init__ 的目录),忽略 base.py 等模块级文件。
    - 子包无 analyzer.py 或无 ANALYZER 属性时静默跳过。
    - 收集到的实例必须满足 Analyzer 协议且 name 唯一,否则抛错(尽早暴露配置错误)。
    返回 {analyzer.name: instance}。M1 阶段无子包时返回 {}。
    """
    registry: dict[str, Analyzer] = {}

    for module_info in pkgutil.iter_modules(analyzers_pkg.__path__):
        if not module_info.ispkg:
            continue

        submodule_name = f"{analyzers_pkg.__name__}.{module_info.name}.analyzer"
        try:
            module = importlib.import_module(submodule_name)
        except ModuleNotFoundError:
            # 子包没有 analyzer.py —— 不是分析器目录,跳过。
            continue

        instance = getattr(module, "ANALYZER", None)
        if instance is None:
            continue

        if not isinstance(instance, Analyzer):
            raise TypeError(
                f"{submodule_name}.ANALYZER does not satisfy the Analyzer protocol"
            )

        if instance.name in registry:
            raise ValueError(f"duplicate analyzer name: {instance.name!r}")

        registry[instance.name] = instance

    return registry
