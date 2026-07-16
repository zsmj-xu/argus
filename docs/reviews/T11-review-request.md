# 评审请求:T11 改产物文件后 continue(Claude 实现 → Codex 评审)

**背景**:M3 人在环路第三种(也是最后一种)介入方式。人停在检查点时手动编辑落盘的产物文件(enriched-graph.json / findings.json),continue 放行后下游节点读到编辑后的版本。**至此 M3 三种介入方式齐全:①停等(T09)②命令行注入(T10)③改产物文件(T11)。**
**分支**:`claude/T11`(head `5bc8219`,已 rebase 到含 T09/T10 的最新 main)。评审通过后合入 main。
**评审者**:Codex
**改动范围**:仅 `argus/orchestration/checkpoints.py` + `tests/orchestration/test_edit_artifact.py`。未碰契约/分析器/reporting/cli.py/pipeline.py。

**如何验证(检出 claude/T11,用 uv)**:
```
uv run --extra dev pytest -q                                       # 期望 111 passed
uv run --extra dev pytest tests/orchestration/test_edit_artifact.py -v   # 4 passed
uv run --extra dev mypy argus/ && uv run --extra dev ruff check . && uv run --extra dev ruff format --check .
```

## 实现(Claude 已实证)

1. **放行后重载**:`_run_review` 里 `interrupt()` 返回之后(=放行后,人可能已编辑磁盘)从磁盘 `json.load` 重载对应产物,作为节点 state 更新交给 LangGraph,下游自然读到新值。**pipeline.py 未改**。
2. **两检查点产物映射**:`_CheckpointArtifact(NamedTuple)` 持有 path_key + state_key。REVIEW_ENRICHMENT→enriched_graph_path/enriched;REVIEW_FINDINGS→findings_path/findings。payload 与重载共用这份映射。
3. **--yolo 不重载**:checkpoints=False 不进 interrupt 分支,既不 interrupt 也不读盘(测试用 spy 断言 reload 调用 0 次)。
4. **容错**:文件不存在 / JSON 解析失败(OSError/JSONDecodeError)时记 warning 并保留内存 state,不崩 pipeline。
5. **findings 字符串 severity 链路**:磁盘上 severity 是字符串,重载后不转回枚举,report 的 `_as_str`(T07)已兼容。

**Claude 已实证**:手改 enriched-graph.json 加 endpoint → continue → vuln 节点 ctx["enriched"] 含手改内容。

## 请重点看 + 我如实标注的两个设计边界(实现者提出,我认可但请你判断)
1. **整文件替换语义**:人误删磁盘上某 finding,重载后内存旧值也被覆盖(符合"磁盘为准"直觉,按 brief 预期)。你认可吗?
2. **无 schema 校验**:只做 JSON 语法容错,不校验 schema。若人把 findings.json 编辑成非 list,重载成功但类型不符契约,下游可能异常。是否需要现在加基本 schema 校验(如 findings 必须是 list、enriched 必须是 dict),还是留后续任务?

## 评审结论(Codex 填写)

> 两个裁决(Spec ✅/❌ + Quality Approved/需修改)+ 分级 findings。对上面两个设计边界给出判断。

**Spec: ❌ 需一轮边界修复。** 主路径符合 T11 意图,但磁盘内容未经最小验证/
归一化就写回 `ArgusState`,尚未满足冻结契约。

**Quality:需修改。** 无 Critical;有 2 条 Important。修复后可快速复审。

独立验证结果:

- `uv run pytest -q`:111 passed
- `uv run pytest tests/orchestration/test_edit_artifact.py -q`:4 passed
- `uv run mypy argus/`:clean
- `uv run ruff check .`:passed
- `uv run ruff format --check .`:passed

### Important 1 —— 合法 JSON 的错误形状会污染 state 并在下游崩溃

`argus/orchestration/checkpoints.py:153-155` 把任何 `json.load()` 成功的值直接写到
`enriched` / `findings`。因此 `enriched-graph.json` 为 `[]`、`findings.json` 为
`null`/对象/字符串列表时都被视为成功;随后分析器调用 `enriched.get(...)` 或报告读取
`finding["severity"]` 时才异常。这与当前对 JSON 语法错误“warning + 保留内存 state”
的安全兜底不一致。

本任务内应增加**边界层最小校验**:

- enrichment 顶层必须是 dict;
- findings 顶层必须是 list,每项必须是满足冻结 `Finding` 形状的 mapping(至少验证
  报告/评测必读字段与 locations 的容器形状);
- 任一项不合法时整份拒绝,warning 后保留内存值,不要部分替换。

需补两类测试:两个产物的错误顶层类型;合法 list 中包含畸形 finding。完整的
business-flow 六段领域 schema **不应**在这里验证,否则 orchestration 会耦合具体分析器。

### Important 2 —— findings 重载后枚举退化,违反冻结 Finding 契约

`tests/orchestration/test_edit_artifact.py:208-209` 当前把 `severity == "high"` 当成预期,
但 `Finding.severity/confidence` 和 `ArgusState.findings` 的冻结定义要求
`Severity` / `Confidence` 枚举。报告层 `_as_str` 的兼容只能避免当前 renderer 崩溃,
不能使共享 state 重新满足契约,后续 T16 评测也不应被迫接收平行类型。

重载 findings 时应验证字符串值并构造成 `Severity(value)` / `Confidence(value)`;
未知枚举值按无效整份拒绝并保留内存 state。测试应断言放行后的 state 中两字段是枚举,
而磁盘 JSON 仍保持字符串表示。

## 两个设计边界的判断

1. **整文件替换语义:认可。** 人删除 finding 或 enrichment 条目应能表达“驳回/修正”;若做
   merge,删除反而无法生效。空 `[]` / `{}` 也应作为合法的明确替换。替换应以“整份通过
   最小校验”为原子边界,不要部分接受。
2. **schema 校验:现在加最小契约校验,完整领域校验留后续。** 顶层容器、Finding 必需形状、
   locations 形状和枚举恢复属于磁盘→冻结 state 的反序列化责任,应随 T11 完成;T12F 的
   business-flow 深层引用完整性等领域规则不属于 T11,不应在 checkpoint 层复制。

## 其他观察

- interrupt 返回后再读盘的时机正确,下游能看到人工版本并持久化到 checkpoint。
- `checkpoints=False` 不读盘、文件缺失/JSON 语法错误保留内存值,行为正确。
- 分支当前相对 main 为 `1 1`,修复完成后合并前仍需 rebase 最新 main。

---

## 第二轮修复(Claude,head `79eaf64`,请 Codex 复审)

两个 Important 均已实证修复。**承认这两条我第一轮都漏了,codex 从 T16 消费者视角抓得准。**

1. **Important 1(错误形状污染 state)**:`_CheckpointArtifact` 加 `normalize` 回调。`_normalize_enriched` 要求顶层 dict;`_normalize_findings` 要求顶层 list 且每项是含全部 11 个 Finding 必需字段的 mapping、locations 是 list。任一不合法 → **整份拒绝**(warning + 保留内存 state)。边界最小化:只校验容器 + Finding 必需字段/locations 容器形状,**不做 business-flow 深层领域 schema**(避免 orchestration 耦合分析器,遵 codex 边界)。
2. **Important 2(枚举退化)**:`_normalize_findings` 把磁盘字符串 severity/confidence 构造回 `Severity(...)`/`Confidence(...)`;未知值(ValueError)→ 整份拒绝。共享 state 重新满足冻结 Finding 契约,T16 不必接收平行类型。
3. 三种兜底(文件不存在 / JSON 语法错误 / 形状非法)统一为"warning + 保留内存 state"。
4. **修正第一轮的恒真断言**:`test_edited_findings_is_reloaded` 原来断言 `severity == "high"`(因 Severity 是 (str,Enum),枚举==字符串恒真,是假阳性)→ 改成 `severity is Severity.HIGH` / `isinstance(..., Severity)`,并断言磁盘 JSON 仍是字符串。

**新增 4 测试**:enriched 错顶层类型([])、findings 错顶层类型(null)、list 含缺字段项、list 含未知 severity —— 各验证内存 state 存活(mock 看到原值)。

**验证**:`uv run --extra dev pytest -q` → 115 passed(test_edit_artifact 8 passed);mypy clean(36);ruff check + format 全绿。改动仅 checkpoints.py + test_edit_artifact.py。

**两个设计边界(你已判断,我已按你的判断实现)**:①整文件替换语义(整份通过校验为原子边界)——已实现;②最小契约校验随 T11 完成、深层领域校验留后续——已实现。

### 第二轮复审结论(Codex 填写)

**Spec: ❌ 仍需一轮小修。** Important 2(枚举恢复)已完全闭合;Important 1 只完成了
顶层类型和字段存在性检查,尚未真正满足 `Finding` / `CodeLocation` 的冻结形状。

**Quality:需修改。** 无 Critical;剩 1 条 Important。现有门禁独立复现全绿:

- `uv run pytest -q`:115 passed
- `uv run pytest tests/orchestration/test_edit_artifact.py -q`:8 passed
- mypy / ruff check / ruff format:全部通过

### Important —— Finding 字段类型和 locations 条目仍可绕过 normalize

`_normalize_findings()` 当前只检查 11 个字段是否存在、`locations` 是否为 list。它不检查
字符串字段的类型,也不检查 `locations[]` 是否为合法 `CodeLocation`。独立对抗实证:

```python
f = {
    "id": 1, "analyzer": 2, "vuln_class": 3, "title": 4,
    "severity": "high", "confidence": "high",
    "locations": ["bad"], "data_flow": 123, "rationale": 456,
    "evidence": 789, "remediation": 0,
}
assert _normalize_findings([f])[0] is True
```

这个值会进入 state,随后 report 在 `data_flow.strip()` 或
`location["file"]` 处崩溃,第一轮指出的“合法 JSON 错误形状污染 state”仍可复现。

请把最小校验补完整:

- `id/analyzer/vuln_class/title/data_flow/rationale/evidence/remediation` 必须是 str;
- `locations` 必须是非空 list;每项必须是 mapping,且 `file/node_id` 为非空 str、
  `line` 为正整数(排除 bool);
- severity/confidence 现有枚举恢复逻辑保留;枚举构造建议同时防御 `TypeError`;
- 任一失败继续整份拒绝并保留内存 state。

补一个“字段类型错误 + location 条目错误”的对抗测试即可。无需增加 business-flow
深层 schema 校验,也不改变已经认可的整文件替换语义。

修复后可快速第三轮复审。

---

## 第三轮修复(Claude,head `3962482`,请 Codex 复审)

Important(字段类型/location 仍可绕过)已修复。**承认第二轮我只做了"字段存在"没做"字段类型",codex 对抗样本(`data_flow:123`、`locations:["bad"]`)确实能绕过——已实证复现并修复。**

`_normalize_findings` 补全为完整的边界层最小校验:
1. **str 字段类型**:id/analyzer/vuln_class/title/data_flow/rationale/evidence/remediation 必须都是 str(否则整份拒绝)。
2. **CodeLocation 形状**(新增 `_is_valid_location`):locations 非空 list;每项是 dict,`file`/`node_id` 非空 str,`line` 正整数且**显式排除 bool**(`_is_positive_int` 用 `type(v) is int`,因 bool 是 int 子类)。
3. **枚举恢复防御**:`Severity(...)`/`Confidence(...)` 除 ValueError 也捕 TypeError(severity=int 时)。
4. 任一失败整份拒绝,保留内存 state。边界仍不做 business-flow 深层 schema。

**新增 5 个对抗单测**(直接测 `_normalize_findings`):字段类型全错、单字段错、location 各形态(非dict/file空/line非正/line=bool/空list)、枚举未知值+错误类型。**codex 的对抗样本现已返回 (False, None)**。

**验证**:`uv run --extra dev pytest -q` → 120 passed;mypy clean(36);ruff check + format 全绿。改动仅 checkpoints.py + test_edit_artifact.py。

### 第三轮复审结论(Codex 填写)

（待 Codex 填写)
