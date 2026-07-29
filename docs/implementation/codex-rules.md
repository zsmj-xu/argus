# Argus V2 Codex 实施规则

本文把归档计划 `docs/specs/2026-07-29-argus-v2-implementation-plan.md`
的执行边界固化为仓库内检查清单。
计划原文和根目录 `AGENTS.md` 优先；若两者冲突，先停止并请求人工决策。

## 里程碑纪律

1. 一次只执行一个被明确授权的里程碑。
2. 开始前阅读该里程碑涉及的实现、测试、文档和 ADR。
3. 修改前给出文件级改动清单；完成后报告实际 diff、验证结果、限制和下一阶段风险。
4. 不提前创建下一里程碑的运行能力或依赖。
5. 保留无关工作树改动，不做无关格式化、重命名或清理。

## 兼容和依赖边界

- V1 Pipeline、Contract、CLI、Web API 和 Workspace 产物保持兼容，直到对等测试通过。
- `argus/contracts.py` 与 `docs/contracts/interfaces.py` 必须字节一致。
- 新领域模型和协议进入独立 V2 命名空间，不继续扩大共享 `enriched` 字典。
- V2 顶层命名空间不得导入 `argus.orchestration.pipeline`。
- Legacy Adapter 是迁移桥梁，不得让 Planner 或 Executor 理解具体漏洞名称。
- 新插件最终通过 capability 声明接入，不要求修改 Planner 或 Executor。

## 安全边界

- 未经授权不得运行真实扫描，因为选定源码上下文可能发送给配置的 LLM。
- M8 前不得增加 PoC、目标网络、浏览器、Shell、真实凭据或副作用动作。
- M8 只允许领域模型、需求、策略和审批；不得执行网络请求。
- M9 只允许测试环境、人工审批、allowlist 和预算约束下的只读 HTTP。
- `--yolo` 只能跳过静态 Review，不能开启或批准验证。
- LLM 不得直接获得凭据、网络客户端或动态确认 Finding 的权限。
- 新权限、配置、Schema 和依赖解析必须 fail closed。

## 数据与状态

- 原始源码仓库最终不得由 Argus 写入 `.codegraph` 或其他扫描产物。
- SourceSnapshot、Artifact、Finding 和验证证据必须绑定版本、来源和哈希。
- 大型源码、图和模型输出不得塞入 Control Store JSON 字段。
- 进程内对象不得作为 Scan 或 Task 的事实来源。
- Finding 指纹不得依赖 LLM 标题或自然语言描述。
- 报告和 `progress.jsonl` 是兼容投影，不是跨组件协议。

## 每次交付验证

优先使用仓库根目录 `AGENTS.md` 中的完整质量门：

```bash
uv run pytest -q
uv run ruff check argus evaluation/scripts tests
uv run ruff format --check argus evaluation/scripts tests
uv run mypy argus evaluation/scripts
git diff --check
```

实施计划另要求：

```bash
python -m pytest
python -m ruff check .
python -m mypy argus
```

若系统没有 `python` 命令，应明确记录环境失败，并使用项目管理的 Python
解释器或等价 `uv run` 命令验证；不得把“命令不可用”写成测试通过。

## 交付清单

- [ ] 只完成当前里程碑。
- [ ] 保留现有兼容路径和无关改动。
- [ ] 新增了该阶段要求的单元、集成或架构测试。
- [ ] 文档与实际代码和运行结果一致。
- [ ] 没有新增静默跳过、静默回退或宽泛核心字典。
- [ ] 没有泄露 secret、源码或大型 Artifact。
- [ ] pytest、Ruff、格式、mypy 和 `git diff --check` 的结果已记录。
- [ ] 已列出限制、未完成项和下一里程碑风险。
