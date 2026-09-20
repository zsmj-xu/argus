# Gemini 前端改造单：告警详情可发现性与完整加载

> 状态：本文对应的前端改造已并入当前 `frontend/`，现作为验收边界与字段说明保留。

## 已确认的事实

- 后端详情接口已经存在：`GET /v1/scans/{scan_id}/findings`。
- 每条记录已返回 `title`、`message`、`evidence`、`remediation`、`file`、`start_line`、`end_line`、`severity`、`category` 等完整字段。
- 当前 `FindingWorkbench.tsx` 只在 Tailwind `lg`（1024px）以上使用左右分栏。在约 958px 的窗口中，详情会被排到最高 720px 的列表下方，用户看起来像是“只有列表、没有详情”。
- `useFindings` 默认只取 50 条，页面没有翻页或继续加载入口；当告警超过 50 条时会静默缺失。
- 后端已负责让新扫描的自然语言结论使用简体中文，并把 Markdown 报告固定文案改成中文。前端不得对源码证据、路径或代码做机器翻译。

## 必须改造

1. 在 768px 及以上显示真正的列表/详情双栏，避免常见桌面窗口宽度下详情落到长列表之后。
2. 在窄屏中，点击告警后用可访问的抽屉或对话框立即展示详情；不得要求用户滚过整个列表。
3. 告警卡片使用真实 `button`，支持键盘操作，并通过 `aria-selected` 表达选中状态。
4. 详情必须完整展示问题说明、代码位置、源码证据、修复建议、分类、风险等级和规则 ID；字段为空时显示明确的中文空状态。
5. 对 `/findings` 的 `total` 实现分页或“加载更多”，确保超过 50 条时不会丢失记录。切换风险等级筛选时重置分页并保持合理的选中项。
6. 风险等级和常见分类的界面标签改为中文；API 原始值可作为辅助技术信息保留。
7. 搜索范围应覆盖所有已加载结果；如果采用服务端分页，应清楚提示搜索范围或改用后端筛选，不能让用户误以为搜索了全部告警。

## 验收条件

- 在 958px 宽窗口中，点击任一告警无需向下滚动即可看到对应详情。
- 在 390px 宽窗口中，点击告警后立即出现可关闭的详情视图，焦点管理和 Escape 关闭正常。
- 构造 51 条以上告警时，用户可以访问最后一条，且页面显示数量与后端 `total` 一致。
- 切换风险等级、搜索、翻页后，不出现详情与选中卡片不一致。
- `pnpm run typecheck` 与 `pnpm run build` 通过。

## 涉及文件

- `frontend/src/components/findings/FindingWorkbench.tsx`
- `frontend/src/components/findings/CodeEvidenceViewer.tsx`
- `frontend/src/hooks/useFindings.ts`
- 必要时增加独立的详情抽屉、分页组件和对应测试。
