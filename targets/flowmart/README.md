# flowmart — 多步业务流逻辑漏洞靶场

一个**自造**的钱包 + 二手市场 API(Flask/Connexion,与 VAmPI 同栈),专门用来验证
logic-graph 的核心假设:

> 语义图能否发现那些**必须跨多个 handler 追踪业务流程**才能判定的逻辑漏洞——
> 这类漏洞,只读单个 handler 的源码看不出来。

## 为什么这样造

crAPI/VAmPI 的漏洞大多在**单个 handler 内**就能判定(这一处缺个 owner 校验、
那一处信了客户端字段),无图组直读源码同样能发现,图的"跨 handler 关联"价值发挥
不出来。flowmart 刻意混入两类漏洞:

- **跨 handler 漏洞(判别性)**:漏洞的"不变量"在 A handler 建立(如 coupon 归属在
  签发时确定、订单状态机在多个 handler 间流转),却在 B handler 被绕过。只看 B 看
  不出问题,必须把 A 的业务约束接到 B 上。
- **单 handler 漏洞(对照)**:register 的 mass-assignment、admin 列表的 BFLA、
  缺鉴权等。无图组应当也能发现,用来做基线。

每个漏洞都遵循**非对称原则**:总有一个"兄弟 handler"把这条校验写对了
(如 `update_listing` 校验了 owner,而 `ship_order` 没校验 seller),对照即证据,
不是稻草人。

## vuln 开关

`VULN=1`(默认)启用有漏洞分支;`VULN=0` 为修复版。ground-truth 即两版之差。
所有漏洞都落在 logic-graph 的 5 类不变量内:
ownership / authentication / role / replay / trust_boundary。

## 运行(仅静态分析用,无需真起服务)

logic-graph 只做静态图分析,不需要真的跑起来。目录结构与 VAmPI 一致,
骨架抽取器按 Connexion `operationId` + `security` 解析路由。
