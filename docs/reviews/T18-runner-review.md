# T18 可恢复对照实验 runner 复审

## 当前裁决

Runner **Spec ✅ / Quality Approved**,可以提交。T18 的最终数据交付仍等待外部
`ANTHROPIC_API_KEY` 与出站 API 网络,因此任务保持 `in_progress`,不伪标 done。

## 已实现

- 4 个物理 scan unit(VAmPI、crAPI workshop/community、flowmart) × 3 个有效 arm:
  graph+invariant、graph-no-invariant、严格隔离 baseline;
- graph arm 强制 `source_mode=stripped`,并用不匹配 `avoid` sentinel 关闭
  `codegraph explore` 原始源码旁路;
- baseline 通过 `NoGraphHandle + enriched={} + STRIPPED SourceAccess` 专用 context
  执行,模型仅看到 stripped source;
- 模型 file+line 候选在调用后映射到 codegraph 中真实 callable node,锚点映射不进入
  prompt;
- graph checkpoint resume、完成 artifact 复用、baseline 原子落盘;
- experiment metadata 在任何 artifact 前原子写入,复用时校验 revision、ground-truth
  SHA、arm/config/model;无 metadata 或签名不符的陈旧 workspace 拒绝复用;
- crAPI 两个 scan unit 先汇总 TP/FP/FN 再计算比率,不平均 recall/precision;
- 单元失败显示不可用(`—`),不会伪造成 0 分。

## 独立验证

- T18/T17 聚焦:13 passed;
- 全量:164 passed;
- dry-run:12/12 matrix;
- 无 API key execute preflight:退出码 2,只报告缺 key,不创建 workspace;
- mypy、ruff check/format、diff check 全绿。

## 待完成

配置 API key 与网络后运行:

```bash
uv run python scripts/run_eval.py --run-id <git-sha-or-experiment-id>
```

脚本将增量更新 `docs/EVAL-RESULTS.md`;全部 12 个单元完成并产出三靶场汇总后,
T18/M5 方可标记 done。
