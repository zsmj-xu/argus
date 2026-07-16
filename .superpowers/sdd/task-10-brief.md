## Task T10: 命令行参数注入(--set / --focus)

**Files:**
- Modify: `argus/argus/cli.py`, `argus/argus/config.py`, `pipeline.py`
- Test: `argus/tests/test_inject.py`

**Interfaces:**
- Consumes: T04 `apply_overrides`
- Produces: `argus continue -w <ws> --set auth.roles=./roles.yaml --focus src/orders/` 把注入写进 `ArgusState.config`,下游节点读得到。

- [ ] **Step 1: 写失败测试**

```python
def test_continue_injects_config_into_state(tmp_path):
    # continue --set auth.roles=x --focus y 后,resume 的 state.config 里能读到 auth.roles==x
    ...
```

- [ ] **Step 2–4:** 失败 → 实现(continue 时把 overrides 合并进 checkpoint 的 state.config,再 resume)→ 通过。

- [ ] **Step 5: Commit** `feat(T10): 命令行参数注入`

---

