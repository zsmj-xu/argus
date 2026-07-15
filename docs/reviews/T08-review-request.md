# 评审请求:T08 injection / xss / auth / ssrf 分析器

**实现者**:Codex  
**评审者**:Claude  
**分支**:`codex/T08`  
**base commit**:`b8dce96`(包含 T06、T07、T12 及 T12F/T07F 协调提交)  
**head commits**:`7a83f4c` + `bc30c13`

## 实现范围

- 新增四个分析器目录:
  - `argus/analyzers/injection/`
  - `argus/analyzers/xss/`
  - `argus/analyzers/auth/`
  - `argus/analyzers/ssrf/`
- 新增 T08 私有共享实现:`argus/analyzers/shannon.py`
- 新增四份 Shannon 意图迁移 prompt,全部改为读取 codegraph + enriched-graph,
  禁止探活/动态利用。
- 新增 `tests/analyzers/helpers.py`、四个分析器测试和共享核心对抗测试。

未修改 `docs/contracts/interfaces.py`、`argus/contracts.py`、pipeline、registry、CLI
或 T06 authz 实现。

## 核心行为

1. 每个具体 `analyzer.py` 间接继承 `AnalyzerBase`,导出模块级 `ANALYZER`,
   `phase=VULN_ANALYSIS`, `requires=[]`。
2. 全量收集 scope 内 function/method,按配置分批调用 LLM,不截断后续节点。
3. 每个候选加入源码、callers/callees 摘要和 `graph.explore` trail,缓解跨函数
   source-to-sink 被批次拆断的问题。
4. LLM 输出按 untrusted data 处理:JSON 降级解析、必填字段校验、Severity/Confidence
   枚举转换、稳定 Finding ID 去重。
5. location 只接受当前 batch 候选或其 scope 内 caller/callee 的真实 node_id;
   file 以图为准;必须有真实 start_line,越界/缺 end_line 时回退 start_line。
6. 注册表集成测试明确要求五个漏洞分析器
   `authz/injection/xss/auth/ssrf` 同时可发现。

## 已处理的独立审查问题

- T06 未合入导致五分析器验收缺失 → 已先合 T06,再 rebase T08。
- 真实但 off-scope node_id 可被接受 → 增加 batch/scope allowlist。
- 固定切批拆断调用链 → 每个候选补 `graph.explore` trail。
- 缺 start_line 时接受任意行号 → 无真实 start_line 直接丢弃。
- injection 类别不完整 → 补 LDAP/XPath/XML/表达式/响应头等静态检查意图。
- 新增 `test_shannon.py` 覆盖 scope、行号、分批 trail、围栏 JSON。

## 验证

```text
uv run pytest -q
61 passed

uv run mypy argus/
Success: no issues found in 32 source files

uv run ruff check .
All checks passed!

uv run ruff format --check .
54 files already formatted
```

## 请重点评审

1. 四份 prompt 是否准确保留 Shannon 的 injection/XSS/auth/SSRF 核心检测意图,
   同时彻底移除了动态探活/利用要求。
2. `ShannonAnalyzerBase` 的共享抽象是否仍满足“每个分析器独立可插拔”,有没有把
   某类漏洞特有逻辑错误地统一化。
3. batch allowlist 是否过严或过松:当前允许候选本身及 scope 内一跳 callers/callees。
4. `graph.explore` 的上下文量和 focus/avoid 行为是否合理:存在 focus/avoid 时为避免
   越界泄露,当前不注入 explore 文本。
5. T08 测试是否足以证明五分析器注册、枚举 Finding、真实 node_id/line 锚定和
   malformed/off-scope 输出降级。

## 已知剩余风险

- 没有在本任务中执行真实 VAmPI + 真 LLM 跑批;当前验收使用真实 mini.db + mock LLM。
- 项目尚未显式配置非 editable wheel 的 `prompt.txt` package-data;这是 T06/T08 共用的
  打包风险,建议后续工具链任务统一处理。

---

## 评审结论(Claude 填写)

（待 Claude 填写:Spec ✅/❌、Quality Approved/需修改、Critical/Important/Minor findings）
