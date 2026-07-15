# business-flow enrichment schema

`business-flow` 富化器(`phase=ENRICHMENT`)的产出。它在 codegraph 的通用调用图骨架
(函数/方法节点 + 沿 `calls` 边补出的真实"谁调用谁"调用关系)之上,用 LLM 重建
"从请求到执行"的业务流语义,支撑跨 handler 分析。产物经编排层合并进 enriched-graph,
是下游业务逻辑漏洞分析器(T13 `business-logic`)的**隐性契约**——本文件是该契约的
权威说明。

## 顶层形状

`AnalyzerResult`:

```json
{
  "analyzer": "business-flow",
  "findings": [],
  "enrichment": { ... 见下 ... }
}
```

- `findings` **恒为空 `[]`**:富化器只重建业务流事实,不下漏洞结论。
- `enrichment` 被合并进 `state.enriched`,顶层 key 为下述六段。

## 稳定性保证

- `enrichment` **总是包含全部六个段**(`endpoints` / `handlers` / `resources` /
  `operations` / `edges` / `business_flows`),且**每段总是 list**。
- **每段的条目都保证是对象(dict)**:富化器逐条校验,LLM 返回里混入的非对象条目
  (字符串、数字、`null` 等)会被**丢弃并记 warning**,不会原样透传给下游——消费者
  遍历时无需再判 `isinstance(item, dict)`。
- `business_flows` 的条目额外保证**至少含 `endpoint_id` 与 `intent`(均为非空字符串)**;
  缺任一必需字段的条目被丢弃。其 list 型字段(见下)保证是 list(可空),list 内元素
  类型也已规整——字符串列表字段只含字符串,对象列表字段只含 dict。
- **引用完整性**:`business_flows` 的 `endpoint_id` 保证指向本次产出 `endpoints` 段里
  **真实存在**的 `id`——`endpoint_id` 悬空(引用一个不存在/已被丢弃的 endpoint)的整条 flow
  被丢弃并记 warning。`related_endpoint_ids` 同样只保留指向真实 `endpoints[].id` 的 id,
  悬空 id 被过滤掉。下游(T13)可放心用这些 id 直接映射到真实节点,无需再判引用是否有效。
- **嵌套对象逐字段规整**:`trust_boundaries` / `state_transitions` / `authorization_checks`
  的每个 dict 条目都经**逐字段**校验——必需子字段(见下各表)缺失或非空校验不过的条目被丢弃,
  其余子字段强制到稳定类型(`bool` 字段缺省 `false`,`note` 缺省空串,可空 string 字段归 `null`)。
  消费者读 `boundary["validated"]` 恒得 `bool`、读 `transition["from"]` 恒得非空 string,无需再判型。
- LLM 返回不可解析时,各段降级为**空 list**(而非缺失或 `null`)——消费者无需判空,
  直接遍历即可。
- 富化器**不产** `invariants` / `checks` / `findings` 段:不变量提取是 invariant 富化器
  (T14)的职责,漏洞判定是漏洞分析器的职责。功能解耦。

## 各段字段

### `endpoints` — HTTP 路由骨架

codegraph 没有路由节点,靠本段补。每个入口一条。

| 字段 | 类型 | 含义 |
|---|---|---|
| `id` | string | 富化内部稳定 id(如 `"ep-login"`),供 `edges` / `business_flows.endpoint_id` 引用 |
| `method` | string \| null | HTTP 方法(`GET`/`POST`/...) |
| `path` | string \| null | 路由路径(如 `/orders/{id}`) |
| `auth_required` | bool \| null | 是否需要鉴权(据装饰器/中间件判断) |
| `source_ref` | string \| null | `相对路径:行号` |
| `node_id` | string \| null | **锚回 codegraph 真实节点**。优先取 LLM 给的真实 id;否则经 `handled_by` 边取其 handler 的 `node_id`(该 handler 已消歧);无法唯一确定则 `null` |

### `handlers` — 处理函数/方法

| 字段 | 类型 | 含义 |
|---|---|---|
| `id` | string | 富化内部稳定 id(如 `"h-login"`) |
| `name` | string \| null | 处理函数/方法名(尽量与 codegraph 节点 name 一致) |
| `source_ref` | string \| null | `相对路径:行号` |
| `node_id` | string \| null | **锚回 codegraph 真实节点**。优先取 LLM 给的真实 id(须在图中存在);否则按 `name` 在骨架中解析,同名跨文件时用 `source_ref`/`file_path`/`qualified_name` 消歧到唯一节点;**无法唯一确定则 `null`(不猜首个同名)** |

> `node_id` 是与 codegraph 的黏合点:非空即可作为 `CodeLocation.node_id` 直接用于
> 下游 Finding 的定位锚点。

### `resources` — 业务资源

| 字段 | 类型 | 含义 |
|---|---|---|
| `id` | string | 富化内部稳定 id(如 `"r-order"`) |
| `name` | string | 资源名(如 `Order`) |
| `owner_field` | string \| null | 归属字段(如 `user_id`);判定越权(BOLA/IDOR)的关键 |
| `source_ref` | string \| null | `相对路径:行号` |

### `operations` — handler 对资源的操作

| 字段 | 类型 | 含义 |
|---|---|---|
| `id` | string | 富化内部稳定 id(如 `"op-create-order"`) |
| `verb` | string | `read` / `create` / `update` / `delete` |
| `target_resource` | string | 目标资源名(对应某 `resources[].name`) |
| `source_ref` | string \| null | `相对路径:行号` |

### `edges` — 关系边

原样保留 LLM 给出的关系边,连接上面各节点的 `id`。

| 字段 | 类型 | 含义 |
|---|---|---|
| `from` | string | 源节点 id |
| `rel` | string | 关系:`handled_by`(endpoint→handler)/ `performs`(handler→operation)/ `targets`(operation→resource) |
| `to` | string | 目标节点 id |

> 富化器用 `handled_by` 边把 endpoint 的 `node_id` 传导到其 handler 的真实节点。

### `business_flows` — 业务流(T12 相对通用调用图的核心增值)

每个 endpoint 一条,描述该请求的**业务意图**、**前置状态**与**信任边界**。这是抓
业务逻辑漏洞(如改购物车金额下单)的地基。

**必需字段**(条目缺任一即被丢弃):

| 字段 | 类型 | 含义 |
|---|---|---|
| `endpoint_id` | string | 对应的 `endpoints[].id`,**保证指向真实存在的 endpoint**(悬空引用的整条 flow 被丢弃) |
| `intent` | string | 一句话业务意图(用业务语言,非复述代码) |

**可选字段**(LLM 未产出时**规整为空 list**,保证类型稳定、向后兼容):

| 字段 | 类型 | 含义 |
|---|---|---|
| `preconditions` | list[string] | 进入危险/写操作前**本应成立**的前置状态(如"购物车非空""当前用户是订单所有者") |
| `trust_boundaries` | list[object] | 信任边界,见下 |
| `related_endpoint_ids` | list[string] | 同一业务流程的前后步骤端点 id(如下单→支付→退款),支撑跨端点/跨 handler 分析。**只保留指向真实 `endpoints[].id` 的 id**,悬空 id 被过滤 |
| `actors` | list[string] | 谁可发起该流程(如 `buyer` / `seller` / `admin` / `anonymous`) |
| `authorization_requirements` | list[string] | 执行前**应满足**的授权/归属约束(如"必须是订单所有者""需 admin 角色")。表达"要求",不表达代码是否真校验了——后者见 `authorization_checks` |
| `authorization_checks` | list[object] | 代码里**实际存在(或缺失)**的授权校验,见下。区分"授权要求"与"是否真执行了校验" |
| `state_reads` | list[string] | 该流程读取的持久化/会话状态(如 `order.status` / `coupon.used`) |
| `state_writes` | list[string] | 该流程写入/变更的状态(如 `order.status` / `wallet.balance`) |
| `state_transitions` | list[object] | 状态机转换,每项形如 `{"from": "paid", "to": "refunded", "note": ...}`;跨步骤状态绕过的抓手 |
| `side_effects` | list[string] | 资金/库存/发货等**不可逆副作用**(如"扣款""减库存""触发发货") |
| `replay_guards` | list[string] | 幂等/防重放机制(如 `idempotency_key` / `nonce` / 状态机拦截);**有 side_effect 而此项为空即重放风险** |

`trust_boundaries[]` 每项(逐字段规整;`field`/`source` 非空 string 校验不过的条目被丢弃):

| 字段 | 类型 | 含义 |
|---|---|---|
| `field` | string | 字段名(如 `amount` / `role` / `user_id`);**必需**,空即丢该条 |
| `source` | string | 数据来源:`request_body` / `query` / `path` / `header` / `session` / `server`;**必需**,空即丢该条 |
| `validated` | bool | 服务端是否**独立复核**了该字段;强制 bool,缺省 `false` |
| `note` | string | 说明;`validated=false` 时点明可被如何滥用;缺省空串 |

`state_transitions[]` 每项(逐字段规整;`from`/`to` 非空 string 校验不过的条目被丢弃):

| 字段 | 类型 | 含义 |
|---|---|---|
| `from` | string | 起始状态(如 `paid`);**必需**,空即丢该条 |
| `to` | string | 目标状态(如 `refunded`);**必需**,空即丢该条 |
| `note` | string | 该转换应受什么前置约束;缺省空串 |

`authorization_checks[]` 每项(逐字段规整;`requirement` 非空 string 校验不过的条目被丢弃)。
它表达代码里**实际有没有**执行某项授权校验,和 `authorization_requirements`(仅陈述"应满足什么")
互补——最危险的是**要求存在但 `enforced=false`(悬空校验)**:

| 字段 | 类型 | 含义 |
|---|---|---|
| `requirement` | string | 该处应满足的授权/归属约束(如"coupon belongs to current user");**必需**,空即丢该条 |
| `enforced` | bool | 代码里**是否真的执行了**该校验;强制 bool,缺省 `false`。`false` = 悬空校验,是业务逻辑漏洞的直接信号 |
| `enforced_by` | string \| null | 若执行了,由谁执行(如 `require_login` 装饰器 / `check_owner()`);未执行则 `null` |
| `note` | string | 说明;`enforced=false` 时点明可被如何绕过;缺省空串 |

> **`validated=false` 且 `source` 为客户端(request_body/query/path/header)的字段,
> 就是业务逻辑漏洞的入口**——例如"下单金额 `amount` 来自 `request_body`、未核价"。
> 下游分析器应据此重点审查。同理,**`authorization_checks` 里 `enforced=false` 的条目**
> 直接标出"该授权要求代码根本没校验",是越权/优惠券跨用户等漏洞的抓手。
>
> 可选扩展字段用于表达**跨 handler 的业务逻辑漏洞**:退款重放(`side_effects` 有扣款/退款
> 但 `replay_guards` 为空)、优惠券跨用户(`authorization_checks` 里归属校验 `enforced=false`)、
> 跨步骤状态绕过(`state_transitions` 允许非法跃迁)。它们默认空 list,老消费者可忽略。

## 示例(单个 endpoint 的完整产出)

```json
{
  "endpoints": [
    {"id": "ep-checkout", "method": "POST", "path": "/checkout",
     "auth_required": true, "source_ref": "api/orders.py:40",
     "node_id": "api/orders.py::checkout"}
  ],
  "handlers": [
    {"id": "h-checkout", "name": "checkout", "source_ref": "api/orders.py:40",
     "node_id": "api/orders.py::checkout"}
  ],
  "resources": [
    {"id": "r-order", "name": "Order", "owner_field": "user_id",
     "source_ref": "models/order.py:5"}
  ],
  "operations": [
    {"id": "op-create-order", "verb": "create", "target_resource": "Order",
     "source_ref": "api/orders.py:52"}
  ],
  "edges": [
    {"from": "ep-checkout", "rel": "handled_by", "to": "h-checkout"},
    {"from": "h-checkout", "rel": "performs", "to": "op-create-order"},
    {"from": "op-create-order", "rel": "targets", "to": "r-order"}
  ],
  "business_flows": [
    {
      "endpoint_id": "ep-checkout",
      "intent": "已登录用户用购物车内容下单结算",
      "preconditions": ["用户已登录", "购物车非空", "库存充足"],
      "trust_boundaries": [
        {"field": "amount", "source": "request_body", "validated": false,
         "note": "下单金额直接采信请求体、服务端未按单价×数量重新核价,可低价下单"},
        {"field": "user_id", "source": "session", "validated": true,
         "note": "从会话取,未采信客户端传入"}
      ],
      "related_endpoint_ids": ["ep-cart", "ep-pay", "ep-refund"],
      "actors": ["buyer"],
      "authorization_requirements": ["购物车属于当前用户"],
      "authorization_checks": [
        {"requirement": "购物车属于当前用户", "enforced": false, "enforced_by": null,
         "note": "结算直接按传入 cart_id 取车,未校验 cart.user_id == session.user_id,可结算他人购物车"}
      ],
      "state_reads": ["cart.items", "inventory.stock"],
      "state_writes": ["order.status", "inventory.stock"],
      "state_transitions": [
        {"from": "cart", "to": "order_created", "note": "只应由持有该购物车的用户触发一次"}
      ],
      "side_effects": ["扣减库存", "生成待支付订单"],
      "replay_guards": []
    }
  ]
}
```

> 上例中 `side_effects` 有"扣减库存"而 `replay_guards` 为空 —— 下游可据此怀疑重复下单/
> 重放;`related_endpoint_ids` 把结算与支付、退款串成一条链,供跨 handler 业务分析。
