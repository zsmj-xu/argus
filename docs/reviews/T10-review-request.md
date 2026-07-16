# 评审请求:T10 命令行参数注入 --set/--focus(Claude 实现 → Codex 评审)

**背景**:M3 人在环路第二种介入方式。让人在 continue 时通过 `--set a.b=c` / `--focus path` 注入配置,放行后下游分析器读得到。(第一种"停等"已在 T09 完成;第三种"改产物文件"是 T11。)
**分支**:`claude/T10`(head `86f3757`,base `34d2ffb`)。评审通过后合入 main。
**评审者**:Codex
**改动范围**:仅 `argus/cli.py` + `tests/orchestration/test_inject.py`。未碰契约/分析器/pipeline 图结构/reporting/registry。

**如何验证(检出 claude/T10,用 uv)**:
```
uv run --extra dev pytest -q                                # 期望 107 passed
uv run --extra dev pytest tests/orchestration/test_inject.py -v   # 4 passed
uv run --extra dev mypy argus/ && uv run --extra dev ruff check . && uv run --extra dev ruff format --check .
```

## 实现(Claude 已实证)

1. **continue 子命令加 `--set`/`--focus`**:`--set`(action="append",点路径如 `auth.roles=./roles.yaml`,可多次);`--focus`(路径,映射成 `config["focus"]`)。
2. **注入合并进 state.config**(用方案 a:update_state,不改 checkpoints.py):放行 interrupt 前,`_inject_into_state` 用 `app.get_state()` 读当前 config、深拷贝、复用 T04 的 `apply_overrides` 打 `--set`、`--focus` 映射成 `config["focus"]`、再 `app.update_state(cfg, {"config": merged})` 写回,最后 `Command(resume=...)` 放行。
3. `_advance` 加可选 `overrides`/`focus` 参数:resume 不传(行为不变),continue 传。

**Claude 已实证**:continue --set auth.roles=x 后,放行执行的 vuln 节点在 `ctx["config"]["auth"]["roles"]` 读到 "x",且持久化进 state(resume 也可见)。

## 请重点看
- `app.update_state()` 在 interrupt 挂起态下更新 state.config 是否稳妥?会不会与 checkpointer 的版本管理冲突?
- 无注入时是否零副作用(提前返回,原 resume/continue 语义不变)?
- `--focus` 映射成 `config["focus"]` 是否与你的分析器读 focus 的方式一致(business_flow/authz 里 `config.get("focus")`)?

## 评审结论(Codex 填写)

> 两个裁决(Spec ✅/❌ + Quality Approved/需修改)+ 分级 findings。

（待 Codex 填写)
