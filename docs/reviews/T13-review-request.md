# 评审请求:T13 business-logic 漏洞分析器(Codex 实现 → Claude 评审)

**分支**:`codex/T13`;实现 commit `a857c68`,base `47e3527`(另含本评审请求文档提交)。
**评审者**:Claude
**任务**:T13 business-logic 漏洞分析器
**契约**:未修改 `docs/contracts/interfaces.py` 或 `argus/contracts.py`。

## 改动范围

- `argus/analyzers/business_logic/__init__.py`
- `argus/analyzers/business_logic/analyzer.py`
- `argus/analyzers/business_logic/prompt.txt`
- `tests/analyzers/test_business_logic.py`

未触碰 T09 正在修复的 pipeline/checkpoints/CLI,也未改 registry、配置或共享契约。

## 实现摘要

- 模块级导出 `ANALYZER`,元数据:
  `name="business-logic" / phase=VULN_ANALYSIS / requires=["enriched-graph"]`。
- 继承 `ShannonAnalyzerBase`,复用统一 JSON 解析、枚举 severity/confidence、
  `_make_finding()`、真实 node_id/file/line 校验与稳定 Finding id。
- 消费 T12F 已冻结的 business-flow 六段 schema,覆盖:
  - 客户端金额/价格/数量篡改;
  - 优惠券、购物车、订单、退款等跨用户/跨租户归属绕过;
  - 退款、支付、优惠券和库存等重放/幂等缺失;
  - 非法状态转换/跳步骤;
  - role/admin/owner/price/status 等 mass assignment/trust-boundary 问题。
- enriched-graph 只是候选信号。prompt 明确禁止仅凭 `validated=false`、
  `enforced=false` 或 `replay_guards=[]` 直接报告,必须结合源码与 codegraph trail 复核。

## 跨 handler 分组与防幻觉

T13 不按函数列表机械切批。它把 `business_flows[].related_endpoint_ids` 视为无向关系,
构造连通业务流程分析单元:

- 下单→支付→退款等相关 endpoints/handlers 始终在同一单元,不会被批次拆断。
- 互不相关的业务流程强制“一单元一次 LLM 调用”;即使配置要求大 batch 也不会合并,
  防止模型拿 A 流程的证据锚到 B 流程的真实 node_id。
- 每个单元从 endpoint 出发沿 enriched edges 闭包收集 handler→operation→resource 语义。
- endpoint/handler 的 node_id 必须经 `graph.node()` 证明真实存在、类型为 function/method、
  且满足 focus/avoid;无法锚定的 flow 安全跳过,不猜 node id。
- Finding locations 只能使用当前业务单元的 `allowed_node_ids`;真实但属于其它流程的节点
  也会被拒绝。file 以 codegraph 为准,越界/无界 line 锚回真实 start_line。

## 测试覆盖

1. Analyzer/registry 元数据与 `requires=["enriched-graph"]`。
2. 未核价 amount 产出枚举 Finding,幻觉 file/越界 line 被真实图位置纠正。
3. related endpoints 保持同组,跨 checkout/refund 的多 location Finding 合法。
4. codegraph 中真实但不属于 enriched flow 的节点被拒绝。
5. node_id 全为空时不调用 LLM,安全返回空结果。
6. 畸形 JSON 降级为空结果。
7. 三个互不相关 flow 即使配置 `batch_size=99` 仍各自分析,不截断也不串锚点。

## 验证(rebase 最新 main 后)

```text
uv run pytest -q                    97 passed
uv run mypy argus/                  Success: no issues found in 36 source files
uv run ruff check .                 All checks passed
uv run ruff format --check .        60 files already formatted
```

## 请重点评审

1. 基于 `related_endpoint_ids` 的连通分量是否正确覆盖退款重放、优惠券跨用户和跨 handler
   所有权场景,且不会错误合并无关流程。
2. “一连通业务流程一次 LLM 调用”的隔离是否值得保留,即使它牺牲部分请求吞吐。
3. `allowed_node_ids` 的 scope 是否足够严格,有无途径让 LLM 用其它真实节点绕过锚定。
4. prompt 是否明确要求从源码确认 enrichment 信号,避免 malformed/误判的
   `enforced=false` 直接制造 Finding。
5. T13 有意只依赖 T12F business-flow schema;T14 invariants 为实验性可选产物,
   不作为 T13 正确性的前置条件。这个解耦是否符合预期。

## 评审结论(Claude 填写)

> 请给两个裁决(Spec ✅/❌ + Quality Approved/需修改),并列出分级 findings。

（待 Claude 填写）
