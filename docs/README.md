# Argus 文档索引

`README.md` 是安装、配置、CLI、Web Console 和安全边界的现役使用权威。本目录按
“当前合同”和“历史交付证据”分层，避免里程碑记录被误当成待办。

## 当前合同

- [V2 架构总览](architecture/argus-v2-overview.md)：现役数据流、边界和 M10 后状态。
- [M10 安全与退场边界](implementation/m10-hardening-retirement.md)：插件隔离、
  审计、备份、GC、导出、性能基线和 Legacy 删除前置条件。
- [V2 Control Store migrations](../argus/control/migrations/README.md)：升级、备份和回滚。
- [Contract 镜像说明](contracts/README.md)：`argus/contracts.py` 的字节一致镜像规则。
- [评估运行指南](EVAL.md) 与
  [扩展状态](comparisons/EXPANSION-STATUS.md)：可运行方式和仍需外部授权/环境的缺口。

## 已交付里程碑

`implementation/m1-*` 至 `implementation/m9-*` 记录各阶段当时的范围、兼容边界和
验证证据。它们用于理解迁移过程；如果其中的阶段性限制与现役行为冲突，以
`README.md`、V2 架构总览和 M10 文档为准。

`architecture/ADR-0001-argus-v2-evolution.md` 保留“不一次重写、V1/V2 并行迁移、
Legacy 最后单独删除”的决策依据。

## 历史记录

- `TASKS.md`、`superpowers/`：早期规格和实施计划。
- [V2 落地实施计划](specs/2026-07-29-argus-v2-implementation-plan.md)：
  M0–M10 的已完成迁移计划和验收依据。
- `reviews/`：阶段性审查请求与结果。
- `EVAL-RESULTS.md`、`comparisons/` 中的对比报告：特定日期和环境下的评估证据。

这些文件不是当前 Agent 指令或开放待办。当前项目规则只在根目录 `AGENTS.md`。
