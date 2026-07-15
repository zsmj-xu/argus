# Argus 协作规范 (Claude + Codex)

两个 AI agent 并行开发 Argus。本文件是**唯一的协调协议**——不靠实时对话,一切通过 git 仓库里的文件。Codex 可自行读取本文件与 `docs/plan/`,领取任务后独立执行。

---

## 1. 仓库与隔离

- 主仓库:`/Users/hetao/work/project/argus`(分支 `main`)。
- 两个 agent 各在自己的 **git worktree** 工作,互不干扰工作区:

```bash
# Claude 的工作树
git worktree add ../argus-claude -b claude/<task-id>
# Codex 的工作树
git worktree add ../argus-codex -b codex/<task-id>
```

- 分支命名:`claude/<task-id>` 或 `codex/<task-id>`,`task-id` 用 `docs/TASKS.md` 里的 task 编号(如 `codex/T07`)。
- 一个 task 一个分支一个 PR。完成后合回 `main`。

---

## 2. 节奏:先立地基,再并行

- **阶段 A(地基,Claude 独做)**:M1 骨架——契约层 + 空编排 + checkpoint + CLI 壳。合并进 `main` 后地基才算立好。
- **阶段 B(并行)**:M1 合并后,Claude 与 Codex 按 `docs/TASKS.md` 的归属**对半并行**领取任务。

**在阶段 A 完成(M1 合并)之前,Codex 不要开始写实现代码**,可以先读 spec / 契约 / 计划熟悉。

---

## 3. 契约是唯一耦合点

- 权威契约在 `docs/contracts/interfaces.py`。M1 会把它落成可导入的 `argus/contracts.py`,两者逐字一致。
- **所有跨模块的类型、函数签名、schema 都以契约为准。** 写实现时先读契约,不要自造平行类型。
- **契约变更流程**(改契约 = 改 spec):
  1. 想改契约的一方,在 `docs/TASKS.md` 顶部的「契约变更请求」区写一条:动机 + 具体改动 + 影响哪些 task。
  2. 另一方确认(在同一条下回复同意/异议)。
  3. 双方同意后,才改 `docs/contracts/interfaces.py` + `argus/contracts.py` + 相关 spec,并在一个独立 PR 里完成。
  4. 未经此流程,不得私自改契约文件。

---

## 4. 任务领取

1. 读 `docs/TASKS.md`,找 **归属是自己、状态 `pending`、依赖已满足** 的最小编号 task。
2. 把该 task 状态改成 `in_progress`、填上自己(claude/codex),提交这条看板更新。
3. 读 `docs/plan/` 里对应 task 卡片(含验收标准、涉及文件、接口签名)。
4. 建 worktree + 分支,按 TDD 执行(先写失败测试)。
5. 完成后:质量门全绿 → 开 PR → 状态改 `review`。

任务卡片给的是**细而全的方向 + 验收标准**,不是逐行抄写脚本——实现细节可自由发挥,只要过验收标准和质量门。

---

## 5. 质量门(PR 合并前必过)

```bash
ruff check . && ruff format --check .   # lint + 格式
mypy argus/                              # 类型检查(或 pyright)
pytest -q                                # 全部测试绿
```

外加:**对方 agent 交叉评审**。Claude 写的由 Codex 评审,反之亦然。评审看:是否符合契约、验收标准是否真的达到、有无破坏其他模块。

### 5.1 交叉评审是合并前的硬门槛(强制流程)

**任何一方的任务分支,未经对方 agent 交叉评审,不得合并进 `main`。** 自己派的 subagent 评审**不能替代**对方 agent 评审——交叉评审的价值就在于另一个独立模型、独立视角。

标准流程(每个任务都走):
1. 实现方完成任务,四条质量门全绿,把分支状态在看板改成 `review`。
2. 实现方在 `docs/reviews/` 下建一个评审请求文件 `T<NN>-review-request.md`(内容:分支名、base commit、改了哪些文件、如何验证、要重点看什么)。
3. **对方 agent** 检出该分支、独立评审,把结论写进同一文件的「评审结论」区(✅/❌ + 分级 findings)。
4. 评审通过 → 实现方(或评审方)合并进 main、看板标 `done`。评审不通过 → 实现方修复后回到第 3 步。
5. 因为两个 agent 通过你(人)中转驱动,评审的"派发"和"回传"由你协调:一方写好评审请求后告知你,你让另一方去审。

> **历史欠账**:T12、T07(Claude 写)在本流程确立前已合入 main 且仅经 Claude 自审。需补 Codex 回审——见 `docs/reviews/`。

---

## 6. 提交与 PR 约定

- Commit 用 conventional commits(`feat:` / `fix:` / `test:` / `docs:` / `refactor:`)。
- Commit message 末尾加:
  ```
  Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
  ```
  (Codex 用它自己的署名。)
- PR 标题带 task 编号,如 `feat(T07): authz 漏洞分析器`。
- PR 描述列:实现了哪张卡片、如何验证(贴命令与输出)、是否触及契约(应为否)。

---

## 7. 冲突预防

- 按 `docs/TASKS.md` 的**文件归属**work,不碰不属于自己 task 的文件。
- 若发现必须改公共文件(如注册表、CLI 分发),在 `docs/TASKS.md` 的「共享文件协调」区先声明,避免两边同时改同一处。
- 每个分析器自成目录(`argus/analyzers/<name>/`),天然隔离,这是主要的并行安全保证。
