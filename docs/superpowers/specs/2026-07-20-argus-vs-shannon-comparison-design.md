# Argus vs Shannon 漏洞检测能力对照 — 设计文档

**日期**：2026-07-20
**状态**：待用户审核
**目标**：先在 VAmPI 上跑通 `Shannon 结果 ⟷ Argus 结果` 的端到端对照链路，验证 Argus 复刻 Shannon 漏洞**检测**能力的实际差异。先跑通、可扩展，不追求完整评测。

---

## 1. 背景与方向修正

Argus 是 Shannon 的白盒静态重构版。M5 里**原有的** `run_eval.py` 做的是 **Argus 内部消融对照**（graph-invariant / graph-no-invariant / baseline 三 arm，回答"图/不变量值不值得留"）。

**本设计是不同方向**：对照对象是**两个工具**——新项目 Argus vs 旧项目 Shannon，回答"Argus 复刻 Shannon 的检测能力达到什么程度"。业务逻辑/不变量等 Argus 新功能**本轮不参与对照**（留待以后）。

**原 `run_eval.py`（内部消融）不删、不改**，本设计新开独立链路，两者并存、互不干扰。

## 2. 关键范式差异（决定对照口径）

| 维度 | Shannon | Argus |
|---|---|---|
| 分析方式 | 黑盒动态 + 读源码 | 纯白盒静态 |
| 需要运行中目标 | **是**（`-u <url>` 探活+攻击） | 否（只读源码+代码图） |
| 五阶段 | pre-recon→recon→**vuln**→**exploit**→report | build-graph→enrich→**vuln**→report |
| 漏洞验证（Exploitation） | **有**（Phase 4：对活目标真实发起攻击验证影响） | **明确不做**（设计 YAGNI：纯静态，输出候选清单） |

**结论 —— 公平对照口径**：只比"**漏洞发现层**"（Shannon Phase 3 `vuln-*` vs Argus vuln 分析器）。Shannon 侧**关闭 Exploitation**（config `exploit: "false"`），因为 Argus 定义上就不做验证，带上会造成不公平的口径错位。这一差异在报告中显式声明，而非隐藏。

## 3. 对照范围（本轮）

- **靶场**：VAmPI（单体 Flask，自带 `Dockerfile` + `docker-compose.yaml`，最易起）
- **Argus 侧 arm**：只用**移植自 Shannon 的 5 类漏洞分析器**（injection/xss/auth/authz/ssrf），**不启用** business-logic/invariant 新功能。图富化用 business-flow（喂给漏洞分析器的事实层），但不加新漏洞类。
- **共同标尺**：`ground_truth/vampi.json`（已存在，18 条 in-scope 中属于这 5 类的子集）
- **Shannon 侧**：`exploit: "false"`，只跑到 vuln 发现层

## 4. 端到端流程（四阶段）

```
┌─ ① 部署 VAmPI ──────────────────────────────────────┐
│  docker compose up (targets/VAmPI) → http://localhost:5000  │
│  产出：活的 URL + 源码路径(已在 targets/VAmPI)          │
└──────────────────────────────────────────────────────┘
                        │
        ┌───────────────┴───────────────┐
        ▼                                ▼
┌─ ② Shannon 跑批 ──────────┐   ┌─ ③ Argus 跑批 ───────────┐
│ ./shannon start           │   │ Argus vuln arm(5类)       │
│   -u http://localhost:5000│   │ 对 targets/VAmPI 源码      │
│   -r targets/VAmPI        │   │ 白盒静态分析               │
│   -c exploit-false.yaml   │   │ (复用已跑通的管线)         │
│ 产出：Shannon findings     │   │ 产出：Argus findings.json  │
└────────────────────────────┘   └────────────────────────────┘
        │                                │
        └───────────────┬────────────────┘
                        ▼
┌─ ④ 对照 ────────────────────────────────────────────┐
│  归一两边 findings → 对同一 ground_truth 打分         │
│  产出对照表：各自 recall/precision + 交集/独有漏洞     │
│  + 范式差异声明(Shannon有验证层/Argus无)              │
└──────────────────────────────────────────────────────┘
```

## 5. 组件与产出

**新增（独立于现有 eval）**：
- `docs/comparisons/` —— 对照结果目录
- 一个对照编排脚本（暂定 `scripts/compare_shannon.py` 或手动分步，见任务拆分）：归一 Shannon 输出格式 → 对齐到 Argus 的 `score()` 可消费的 findings 形态 → 复用 `argus/eval/score.py` 对同一 GT 打分
- Shannon 侧 config：`exploit: "false"` + scope 到 5 类 vuln
- Argus 侧 config：只启用 5 类移植分析器的 arm 配置

**复用**：
- `argus/eval/score.py`（T16，已评审）—— 两边共用的打分器，保证同一把尺
- `ground_truth/vampi.json`（T15）
- Argus 已跑通的 vuln 管线

## 6. 关键设计决策

1. **只比发现层，Shannon 关 exploit** —— 公平口径（§2）。
2. **两边用同一个 `score.py` 对同一 GT 打分** —— 消除评分口径差异，唯一变量是"哪个工具检出的"。
3. **Shannon 输出需归一**：Shannon 产 Markdown 报告 / `*_findings.md` / `*_exploitation_queue.json`；需一个适配层把它转成 `score()` 能吃的 `{vuln_class, file, line/handler}` 形态。这是本对照的主要新代码。
4. **超时**：Argus 侧推理模型慢（曾 120s ReadTimeout），**先在现有 120s 下试跑**（用户 Q3 决定），失败再最小化调超时。
5. **先跑通，再扩展**：VAmPI 单靶场验证方法闭环后，才谈 crAPI/flowmart。

## 7. 测试与验收

**跑通标准**（本轮）：
- [ ] VAmPI 在 Docker 起来，URL 可访问
- [ ] Shannon 对 VAmPI 跑完（exploit=false），产出可解析的 findings
- [ ] Argus 5 类 arm 对 VAmPI 跑完，产出 findings.json
- [ ] 两边对同一 `vampi.json` 打分，产出一张对照表
- [ ] 对照文档落盘，含范式差异声明

**非目标（本轮不做）**：crAPI/flowmart 扩展、business-logic/invariant 对照、Shannon exploit 验证层的对照、性能/成本对照。

## 8. 风险

- **R1 Shannon 输出格式不确定**：需先真跑一次看实际产物结构，适配层才能写准。→ 任务里先做"跑一次 Shannon 摸清输出"再写适配。
- **R2 Argus 超时**：推理模型可能仍超时。→ 先试，失败则最小调 `client.py` 超时。
- **R3 口径可比性**：Shannon 黑盒可能报出 Argus 静态看不到的（如运行时配置），反之 Argus 静态能看到未部署代码。→ 对照表标注"仅计入 GT 内的 5 类"，范式差异写进结论。
