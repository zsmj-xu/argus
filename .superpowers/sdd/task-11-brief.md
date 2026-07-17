## Task T11: 直接改产物文件后 continue(M3 收口)

**Files:**
- Modify: `argus/argus/orchestration/pipeline.py`(检查点后重新从磁盘读产物)
- Test: `argus/tests/orchestration/test_edit_artifact.py`

**Interfaces:**
- Consumes: `enriched_graph_path`, `findings_path`
- Produces: continue 时,若人编辑过 `enriched-graph.json` / `findings.json`,pipeline 读磁盘上的最新版而非仅内存 state。

- [ ] **Step 1: 写失败测试**

```python
def test_edited_enriched_graph_is_reloaded(tmp_path):
    # 停在 review-enrichment → 手改 enriched-graph.json 增一条 → continue
    # 断言:下游漏洞分析器拿到的 ctx["enriched"] 含手改内容
    ...
```

- [ ] **Step 2–4:** 失败 → 实现(检查点放行后的第一个节点先从产物路径重新加载,覆盖内存)→ 通过。

- [ ] **Step 5: 端到端(M3 验收)**

三种介入方式各验证一遍:①默认停等 continue;②`--set`/`--focus` 注入;③手改 `enriched-graph.json` 后 continue 生效。

- [ ] **Step 6: Commit** `feat(T11): 改产物文件后 continue 生效(M3)`

---

