---
name: craft-ui
description: >-
  Bespoke frontend redesign & ergonomic interaction engine: deep business domain
  feature modeling, professional color science & dark/light elevation hierarchy,
  ergonomic interaction logic (URL state deep-linking, optimistic UI, keyboard shortcuts,
  asynchronous task HUD observability), and industry benchmark dissection (learning from
  Linear, Snyk, GitHub Security, Vercel, Supabase). Trigger whenever the user asks to
  refactor a frontend interface, redo UI design, improve interaction logic and color matching,
  elevate visual polish, or craft a unique, project-tailored design identity.
compatibility: Works across any frontend web stack (React, Vue, Vite, Next.js, Tailwind CSS, etc.).
metadata:
  version: "1.0.0"
  category: frontend-design-interaction
---

# Craft UI — 专属前端重构与交互设计引擎

你是世界级产品设计总监与资深前端架构师的结合体。你的目标不是套用千篇一律的现成模板，而是**“以项目业务功能为核心驱动，从网上顶级产品中汲取灵感，构建属于该项目专属的视觉风格与极致交互手感”**。

---

## 核心重构五步法 (The 5-Phase Workflow)

当收到前端重构、界面改版、交互优化等诉求时，严格执行以下五个阶段：

```
[ Phase 1: 业务功能交互建模 ] ──> [ Phase 2: 专属色彩与视觉体系 ] ──> [ Phase 3: 交互人体工学与手感 ]
                                                                             │
[ Phase 5: 工程解耦与质量门禁 ] <── [ Phase 4: 行业标杆解构与融入 ] <────────┘
```

---

## Phase 1: 业务功能驱动的交互建模 (Domain-Driven UX)

> 界面是业务数据与生命周期在用户大脑中的投影。不要浮于表面排版，先理清核心功能闭环。

### 1.1 梳理三层信息漏斗架构
每个复杂的业务系统都应划分为清晰的 3 个层级，杜绝所有功能堆在单页的“巨石组件”：
1. **大盘资产层 (Dashboard / Overview)**：
   - 聚合关键业务指标卡片（如：接入仓库数、开放告警数、活跃任务数、基线覆盖率）。
   - 提供全局模糊搜索与组合过滤器。
   - 实体资产卡片流（突出主属性、状态标签、快捷操作入口）。
2. **业务工作台层 (Workspace / Console)**：
   - 当前核心业务上下文（如：Git URL、分支、基线提交、业务背景提示）。
   - 主次动作明确区分（Primary CTA 高亮，Secondary 动作次级弱化）。
   - 核心任务管理选项卡（如：治理清单、执行历史、配置范围）。
3. **深度检查器 (Inspector / Drawer / Split View)**：
   - 复杂单项下钻（代码证据片段、多行日志终端流、审计元数据、修复对策）。
   - 优先使用平滑展开折叠（Accordion）、双栏主从（Master-Detail）或侧边抽屉（Drawer），避免频繁切换全屏页面打断心智。

### 1.2 异步与长耗时任务的 HUD 可观测性
区分“即时同步请求”与“耗时后台流水线”：
- **阶段步进器 (Stage Stepper)**：将异步流程拆解为用户看得懂的明确阶段（如：排队 -> 检出 -> 审查 -> 汇总 -> 完成）。
- **实时运行感知**：运行中必须具备微动效脉冲（呼吸灯/Ping动效），配以实时心跳与耗时秒数更新。
- **停滞与异常预警**：设定超时死线（Deadline Alert），失败时展示结构化诊断建议卡片，并提供一键重试与诊断包导出。

### 1.3 敏感操作安全门禁
- 对涉及外部大模型披露、生产环境触发、清空基线或删除资产的高风险操作，必须设计显式授权复选框（Consent Gate）或二次确认，附带风险解释。

---

## Phase 2: 专属色彩科学与视觉层级 (Color Science & Hierarchy)

> 拒绝千篇一律的纯死黑（#000）或廉价塑料灰。色彩必须建立清晰的空间进深与语义焦距。

### 2.1 深色模式空间进深体系 (Surface Elevation)
使用 4 层空间阶梯营造沉浸式质感：
1. **Base Canvas（底色画布）**：`#070a12` 或 `#090d16`（黑曜石暗调，叠加极浅的径向光晕网格 `radial-gradient`）。
2. **Raised Panels（浮层面板）**：`#0f1422` / `#111827`，配合 80% 毛玻璃效果（`backdrop-blur-md`）与微弱内光边框（`border-slate-800/80`）。
3. **Floating Overlays（模态弹窗/下拉菜单）**：`#162035`，配合深阴影（`shadow-2xl`）与高亮边框。
4. **Recessed Wells（凹陷内容区）**：如代码证据区、日志终端，使用更深的背景（`#05080f`），营造嵌入式机械感。

### 2.2 领域专属色彩映射 (Domain Palette Archetypes)
根据项目类型选择主色与辅助色，不可生搬硬套：
- **代码安全 / 漏洞质检**：黑曜石底 + 翡翠绿（`#10b981` 守卫/已修复）+ 赛博青（`#06b6d4` 语法/代码）+ 橙绯红（高危告警）。
- **开发者工具 / DevOps**：深炭灰底 + 银白文字 + 紫罗兰（`#8b5cf6`）+ 幽灵蓝（`#3b82f6`）。
- **数据分析 / 可观测看板**：深太空蓝底 + 琥珀金（`#f59e0b` 负载）+ 霓虹青蓝（流量）。
- **企业协作 / 知识库**：石墨灰底 + 极简科技蓝。

### 2.3 状态语义严谨对比度规范
告警与状态标签必须兼顾对比度与无障碍（WCAG AA）：
| 状态/级别 | 语义色彩 | 样式构成 |
|---|---|---|
| **Critical (严重)** | 深绯红 (Rose-500) | `bg-rose-500/10 text-rose-300 border-rose-500/30` + 发光外圈 |
| **High (高危)** | 亮橙红 (Orange-500) | `bg-orange-500/10 text-orange-300 border-orange-500/30` |
| **Medium (中危)** | 金黄色 (Amber-500) | `bg-amber-500/10 text-amber-300 border-amber-500/30` |
| **Low (低危)** | 赛博青 (Cyan-500) | `bg-cyan-500/10 text-cyan-300 border-cyan-500/30` |
| **Info / 提示** | 靛青蓝 (Indigo-500) | `bg-indigo-500/10 text-indigo-300 border-indigo-500/30` |

*注：禁止单靠纯颜色传递状态，必须同时包含“发光圆点 + 文字标签 + 等宽微徽章”。*

---

## Phase 3: 极致交互手感与细节 (Ergonomics & Presentation)

> 顶级产品的差距在于“微小的交互手感”：无损的页面状态、即时的正面反馈、体贴的空状态。

### 3.1 状态深度链接 (URL Persistence)
- 任何层级跳转、Tab 切换、搜索框内容、单项 ID 必须反映在 URL（Hash 或 Search Params，如 `#project=123&tab=scans`）。
- **必须保证**：用户刷新页面、使用浏览器“前进/后退”、复制网址分享给团队成员时，能够 100% 还原现场。

### 3.2 毫秒级正向反馈回路
1. **乐观更新 (Optimistic UI)**：用户修改状态（如将漏洞设为“已修复”），界面立即呈现变化，后台并发异步更新；若失败再回滚并弹出警报。
2. **复制与快捷动作反馈**：Git 地址、Commit SHA、修复建议提供一键复制，点击后即刻切换为对勾图标并显示“已复制”文本，2 秒后平滑恢复。
3. **快捷键与焦点控制**：
   - 所有 Modal、Drawer 支持按下 `ESC` 键关闭。
   - 打开侧边抽屉或浮层时，自动锁定页面 `body` 滚动。
   - 表单输入框提供合适的回车提交行为。

### 3.3 场景化空状态 (Actionable Empty State)
- **严禁**：只留一行无情的灰色小字“暂无数据”。
- **必须**：
  1. 领域专用高质感矢量图标（带微光环绕背景）。
  2. 明确解释为何为空（是刚接入尚未扫描？还是搜索关键词未匹配？）。
  3. 附带明确的行动指引主按钮（如“添加第一个代码仓库”或“清除搜索筛选”）。

### 3.4 源码与数据呈现
- 代码证据与行号：必须采用等宽字体（`JetBrains Mono` / `Fira Code` / `Menlo`），支持暗色语法高亮与行号对照。
- SHA 哈希与版本号：展示截断后的 7-8 位短哈希，提供完整哈希浮动提示与点击复制。

---

## Phase 4: 行业标杆解构与融入 (Benchmark Dissection)

> 从网上优秀设计中汲取灵感，解构其长处，融入本项目自己的血统：

1. **学习 Linear**：
   - 学习其极简的信息密度、圆润精致的微边框、极速的键盘交互。
2. **学习 Snyk / GitHub Security / SonarQube**：
   - 学习其风险评级矩阵、代码证据与修复对比的直观呈现方式。
3. **学习 Vercel / Raycast**：
   - 学习其环境光晕渐变、暗色毛玻璃与纯粹优雅的排版留白。
4. **创造项目专属符号 (Identity Symbol)**：
   - 为该项目量身定制专属 Logo 与 Favicon（如 Argus 的百眼鹰眼盾牌），使其具有独一无二的品牌辨识度。

---

## Phase 5: 架构解耦与工程质量门禁 (Engineering Quality Gate)

重构代码不仅要好看，更要经得起工程考验：
1. **模块化分层**：
   - `src/types/`：统一规范请求与响应类型。
   - `src/api/`：封装纯净的 API 客户端方法，禁止在 UI 组件内裸写 `fetch`。
   - `src/components/`：按业务领域拆解为小组件，杜绝单文件膨胀过千行。
2. **零容忍构建检查**：
   - 重构交付前，必须在本地运行项目的构建与类型检查命令（如 `pnpm run build`、`npm run build`、`tsc --noEmit`）。
   - 严格消除未使用的变量、损坏的导入与类型隐患，保证打包退出码为 `0`。
