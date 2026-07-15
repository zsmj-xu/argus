# 评审:T08 injection/xss/auth/ssrf 分析器(Codex 实现,Claude 评审)

**分支**:`codex/T08`(head `8f98935`,base `b8dce96`)
**评审者**:Claude
**评审方式**:独立 worktree 检出 codex/T08,建 uv 环境跑全门禁 + 通读 shannon.py 共享实现、base.py、测试。

---

## 评审结论

### 裁决 1 — Spec 合规:✅ 通过
四个分析器(injection/xss/auth/ssrf)实现:各继承 `ShannonAnalyzerBase`、导出模块级 `ANALYZER`、`phase=VULN_ANALYSIS`、`requires=[]`;移植 Shannon 检测意图并改为读 codegraph + enriched-graph、禁止探活/动态利用;注册表能发现全部五个漏洞分析器(authz + 这四个)。净改动仅在四个分析器目录 + `shannon.py` + 测试,未碰契约/pipeline/registry/CLI/T06/T12/reporting。

### 裁决 2 — 代码质量:Approved(高)
- **DRY 设计优秀**:四个 `analyzer.py` 各 11 行(只声明 name/vuln_class),逻辑集中在 `argus/analyzers/shannon.py`。`_load_prompt` 用 `inspect.getfile(type(self))` 按**具体子类**定位各自 `prompt.txt`,共享基类模式成立(已核实四个 prompt 内容确实不同且各自加载)。
- **防幻觉锚定**:location 只接受当前 batch 候选或其 scope 内 caller/callee 的真实 node_id(`_batch_node_ids` allowlist);file 以图为准;要求真实 start_line,越界/缺 end_line 回退 start_line。
- **切批拆链缓解**:每个候选补 `graph.explore` trail,降低 source-to-sink 被分批切断的概率。
- **LLM 输出当 untrusted**:JSON 降级解析、必填校验、Severity/Confidence 枚举转换、稳定 id 去重。
- **测试真断言**:`test_shannon.py` 覆盖 off-scope 真实节点被拒、无 start_line 被拒、每批含 explore trail、围栏 JSON 解析。
- **门禁全绿**:61 passed / mypy strict 32 files clean / ruff check + format 全过。
- codex 把我在 T06 阶段可能提的评审意见(off-scope node_id、切批拆链、行号缺失)提前自查修复,评审请求写得规范(范围、已处理问题、验证输出俱全)。

### Findings
- **Critical / Important**:无。
- **Minor(不阻塞,全项目通病)**:`shannon.py` 的 `_collect_candidates` 用 `graph.query("")` 拉全表,与 T06/T12 同一模式,大 repo 偏重。建议后续在 `GraphHandle` 上加"按 kind 列举"方法统一优化(涉及契约,走变更流程)。

**结论**:可合并。干净、DRY、与 T06 一致的严谨实现。

> **合并注意**:T08 base 是 `b8dce96`,不含我的 T12F(`7b4cfc6`,尚待 codex 评审后合)。两者改的文件不重叠(T08 只碰四个新分析器 + shannon.py + 新测试;T12F 只碰 business_flow/ + 其测试),但都会新增 `tests/analyzers/` 下的文件、且 helpers.py 是 T08 新增。合并顺序上谁先谁后都行,后合的一方 rebase 一下即可,预计无实质冲突。
