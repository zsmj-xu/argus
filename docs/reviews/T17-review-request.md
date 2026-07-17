# 评审请求:T17 图组/无图组对照 + 隔离 baseline

**实现者**:Codex  
**状态**:✅ Spec / Quality 独立复审通过;T18 已解锁。

## 实现范围

- `argus/eval/compare.py`:同一 ground truth 下并列返回 graph/baseline 两组 T16
  `ScoreResult`。
- `argus/analyzers/baseline/`:源码-only business-logic baseline。
- `argus/source.py` + pipeline SourceAccess:补齐真实 `source_mode=stripped` 语义,
  去 Python 注释/docstring及 Go/C-style 注释并保留行号。
- business-logic analyzer 显式消费 handler-scoped invariants,使 T18 开/关 invariant
  对照真正改变分析输入。

## 隔离边界

Baseline 保留模块级 `ANALYZER` 以满足项目注册约定,但不进入默认配置。它只允许由
专用 eval runner 构造以下 context:

- `graph` 的具体类型必须是 `NoGraphHandle`;其五个方法全部立即抛
  `BaselineIsolationError`;
- `enriched` 必须严格为空对象;
- `source.mode` 必须是 `SourceMode.STRIPPED`,且 analyzer 对 read 结果再次执行
  line-preserving stripping;
- 文件清单由 `config.baseline.files` 提供,只接受安全相对路径;
- LLM 只看到 `{path, stripped source}`,看不到 graph、enriched、workspace、完整 config
  或 node id 映射;
- LLM 只返回 file+line 候选;输出 Finding 的 node_id 由 runner 提供的可信
  `config.baseline.node_ids[path]` 覆盖,模型伪造值不生效。

普通 pipeline 若被误配置选择 baseline,会因为拿到真实 CodegraphHandle/非空 enriched
而在任何源码读取或 LLM 调用前 fail-closed,不会静默偷看图。

## 请重点评审

1. graph/enriched/source-mode 三重隔离是否存在绕过;
2. stripping 是否真实去除教学答案且保持行号/字符串内容;
3. node id 可信映射是否完全不进入模型 prompt;
4. baseline 位置越界/跨文件/畸形 JSON 是否安全丢弃;
5. invariant 是否只进入对应 handler component,关闭时无 stale 数据;
6. `compare` 是否保持两组输入和 ground truth 不变。

## 最终验证

- baseline/source 聚焦及对抗测试:17 passed;
- 全量:160 passed;
- mypy:42 source files clean;
- ruff check/format、diff check 全绿。

独立复审先后检出并验证关闭以下泄露边界:

- parenthesized/concatenated Python docstring;
- parser failure 前后教学注释;
- `if` 等普通 block 字符串误删;
- stale/未验证 invariant 跨实验臂或 component 注入。

最终裁决:**Spec ✅ / Quality ✅,无阻塞 finding。**

## T18 调用约束

Baseline 不通过普通 `argus start` 执行;T18 专用 runner 显式实例化 `BaselineAnalyzer`
和隔离 context。图组还需设置非匹配 `avoid` sentinel 关闭 codegraph `explore()` 的原始
源码旁路。真实 LLM 跑批另需 `ANTHROPIC_API_KEY` 与出站网络。
