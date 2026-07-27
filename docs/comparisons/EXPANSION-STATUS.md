# Argus vs Shannon 对比扩展状态

**更新日期**: 2026-07-27

## 已完成

- 评测 runner 已增加 LLM 截断检测：`finish_reason=length` 会保留审计并让 workspace 失败，
  不再静默折算为空 findings；business-flow 与 baseline 支持分批上下文，避免单次请求耗尽
  推理模型预算。
- 分批 VAmPI business-logic 验证已完成：5 条 finding，TP=3、FP=2、FN=1，Recall=0.750、
  Precision=0.600。该结果是单靶场诊断，不替换正式 Shannon 对照结果。

- VAmPI comparison scope 从 4 条业务不变量扩充到 6 条已知漏洞:
  injection 1、auth 2、authz 3。
- Shannon 与 Argus 对 6 条均为 6/6,Detection Recall=1.000。
- 正式纯五类 arm 不启用 business-flow/invariant 等额外富化，严格要求五类分析器返回可解析结构化输出。
- VAmPI final：Shannon 与 Argus 都是 6/6，Detection Recall=1.000，taxonomy agreement=1.000，6 条 GT 命中集合完全一致。
- VAmPI final 逐条裁决：Shannon 17 true + 3 duplicate；Argus 13 true + 1 duplicate；两边 0 false，validity precision=1.000。
- flowmart final Argus：10 条 finding，comparison scope 6/6，Detection Recall=1.000；taxonomy agreement=5/6（钱包缺鉴权的 auth/authz 标签边界）。
- crAPI workshop Argus：26 条 finding，comparison scope 6/7，Detection Recall=0.857；community Argus：7 条 finding，comparison scope 2/2，Detection Recall=1.000。
- 矩阵支持单侧产物展示：整体仍标为 `unavailable`，但已存在一侧的 recall 会显示，缺失侧保持 `N/A`，不会把单侧结果误读为双侧对照。
- authz 分析器 prompt 已补充 mass-assignment / server-authoritative 字段规则；现有正式 crAPI workspace 未静默重跑，待获得外发源码授权后再以新契约复测并替换结果。
- 2026-07-27 最近一次完整门禁：210 passed、1 skipped；mypy strict、Ruff lint、
  Ruff format、git diff check 均通过。

## 多靶场扩展

flowmart 现已增加不改变原 handler 的 Flask 装配层、Docker Compose、运行时回归测试、
Shannon discovery-only 配置和 Argus 五类配置。其 comparison scope 包含 6 条:
auth/authz 5 + reflected XSS 1;refund replay 因不属于当前五类分析器而明确排除。
Flask test client 强验证已在独立 Python 3.14 环境通过 2/2。Docker Compose 已真实构建并启动
`flowmart-vulnerable`，端口 `:5012` 的 `/health`、`/openapi.json` 均为 200；动态回归还确认
未授权钱包、任意 role 注册和 reflected XSS 与 GT 一致。
矩阵会把 `flowmart-refund-replay` 列为 business-scope excluded,防止 5/5 被误读为
flowmart 全部 6 条业务漏洞均已纳入五类对照。该 replay 样本由独立 business-logic
workspace 评估。

flowmart 已完成正式 Argus workspace：`flowmart-5class-final`。
旧 workspace 的 business-flow 富化请求曾因 deepseek reasoning 输出预算耗尽而失败；正式五类 arm
按设计移除该可选事实层，避免把辅助富化器故障混入检测召回。

Shannon flowmart workspace 尚未生成：虽然容器和 URL 已就绪，Shannon 运行会把本地源码发送到外部
Anthropic-compatible LLM，需用户明确授权后再执行。T18 Argus 多靶场跑批也需要同类外发授权；
当前环境安全策略已拦截向 `.env` 网关发送四个靶场源码的完整跑批。重新运行 Argus 的 authz
定向复核同样需要该类外发授权。

crAPI workshop 包含服务 Dockerfile,但导入资产缺少协调 Postgres、Mongo、identity
和 workshop 的 `deploy/docker` 编排。Argus workshop 静态 arm 已完成（6/7）；其 comparison scope 已映射为 7 条正样本:
auth/authz 5、injection 1、SSRF 1,并已增加 Argus 五类配置。在不补充与导入 commit
一致的完整运行栈前,不能声称已经完成 crAPI 的公平双侧跑批。
community Go 服务保留 2 条 comparison-scope 正样本(authz 1、injection 1),独立 Argus 五类 arm
已完成并命中 2/2；公开论坛评论 ownership 和 coupon amount 因缺乏独立策略证据已明确排除，避免与 workshop 的源码相对路径和指标混算。
Shannon 共用 `shannon-crapi.yaml`,但必须指向与当前导入源码版本一致的完整本地 crAPI
部署;不能用缺失 identity 服务的半套源码代替。

`comparison-matrix.yaml` 与 `evaluation/scripts/run_comparison_matrix.py` 统一编排四个评测单元。
只有两侧产物都存在时才标为 `complete` 并生成双侧对照；单侧产物会独立评分展示，
但整体仍标为 `unavailable`，缺失侧为 `N/A`，不会转换成零召回。

## 后续验收条件

1. 获得外发源码授权后运行 Shannon flowmart 五类 discovery-only arm，并把 deliverables 接入矩阵。
2. 若要评估 flowmart business-logic arm，单独解决 business-flow reasoning 输出预算限制；不与五类 arm 混算。
3. 为 crAPI 准备与导入源码版本一致的运行栈,再跑 Shannon。
4. 跑批验证跨靶场新增类别:flowmart XSS 与 crAPI workshop SSRF。

## 当前诊断产物

- `eval-expansion-20260723-r2`：已完成部分 baseline/community arm；图 arm 暴露 provider
  8192 reasoning-token 硬上限，已标记失败，不作为最终指标。
- `eval-r4-vampi-graph-batched`：分批策略的单靶场验证产物，可用于复核上述 3/4 结果。
- 完整 `expansion-20260723-r3` 尚未启动：需要明确允许将项目源码发送到外部 LLM 网关。
