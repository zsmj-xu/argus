# T10 报告:命令行参数注入(--set / --focus)

## 实现概述

给 `continue` 子命令加了 `--set`(action="append", default=[])和 `--focus`(路径,default=None)
两个参数,放行 interrupt 检查点的同时把注入合并进 checkpoint 持久化的 `state["config"]`,
让放行后执行的下游节点(vuln 等)及后续 resume 都读得到。

只改了 `argus/cli.py`。没有碰契约、分析器、reporting、registry、pipeline 图结构。
`ArgusState` 未改(config 已有 `config: dict` 字段)。

## 注入怎么合并进 state —— 用 update_state(方案 a)

新增 `_inject_into_state(app, cfg, overrides, focus)`:

1. 无注入(空 overrides 且 focus is None)时直接返回,不触碰 state。
2. `app.get_state(cfg)` 读当前 state,深拷贝 `values["config"]`(避免就地改持久化对象)。
3. 复用 T04 的 `apply_overrides(merged_config, overrides)` 打 `--set` 点路径覆盖。
4. `--focus` 映射(见下)。
5. `app.update_state(cfg, {"config": merged_config})` 把合并后的 config 写回 state。

写回后进入 checkpointer 持久化,因此下游节点从 `state["config"]` → `ctx["config"]` 读到的
就是合并值,且后续 resume 也看得到(要求 3:持久化)。

选 update_state 而非 Command payload:更干净,不需要改检查点节点(`checkpoints.py` 未改),
也不与现有 `Command(resume="approved")` 放行语义耦合。resume 仍走原路径,注入是可选参数。

## --focus 怎么映射

`--focus src/orders/` 等价于 `--set focus=src/orders/`:直接 `merged_config["focus"] = focus`。
现有分析器(shannon / authz / business_logic)都读 `config.get("focus")` 做 scope,所以 focus 就是
config 的一个顶层键,写进去即可被消费。

## _advance 签名变化

`_advance` 现在被 resume 和 continue 共用,加了两个可选参数:
`overrides: list[str] | None = None, focus: str | None = None`。
`cmd_resume` 不传(保持 "approved" 放行,行为不变);`cmd_continue` 传 `args.set` / `args.focus`。
放行前调 `_inject_into_state`。

## 新测试(tests/orchestration/test_inject.py,4 个)

用 `ConfigCapturingVuln` mock 分析器(run() 里深拷贝记录 `ctx["config"]`)+ tmp_path SqliteSaver +
fixture mini.db。monkeypatch `argus.cli.RUNS_ROOT` 和 `discover_analyzers` 让 `_advance` 用同一 mock 实例。
只开 review-enrichment 检查点,放行一次即跑到 vuln。

- `test_continue_set_injects_into_downstream_config`:`--set auth.roles=x` → vuln 看到
  `ctx["config"]["auth"]["roles"] == "x"`,且持久化到 state.config。
- `test_continue_focus_injects_into_downstream_config`:`--focus src/orders/` → `config["focus"]`。
- `test_continue_set_and_focus_together`:两者同时注入都到位。
- `test_continue_without_injection_leaves_config_unchanged`:不传注入,config 不变,仍正常放行。

关键:断言的是**放行后执行的下游节点**看到的 config(mock.seen_config),不是本地变量。

## 四门禁实际输出

- `pytest -q`:`107 passed in 1.00s`(原 103 + 新 4)
- `mypy argus/`:`Success: no issues found in 36 source files`
- `ruff check .`:`All checks passed!`
- `ruff format --check .`:`62 files already formatted`

## commit

`feat(T10): continue 命令 --set/--focus 参数注入到 state.config`

## concerns

- 无注入时 `_inject_into_state` 提前返回,零 update_state 调用,原 resume/continue 行为完全不变。
- `--set` 右值走 `apply_overrides` → YAML 标量解析(如 `true`→bool);字符串路径(`./roles.yaml`)保持字符串,符合预期。
- 若 workspace 已完成(无 next),`_advance` 在注入前就 return,注入不会生效——这是合理的(已完成无处可注入)。
- 注入在放行时才写入,只影响放行后执行的节点;已完成的上游节点(enrichment)不会因注入重跑,符合语义。
