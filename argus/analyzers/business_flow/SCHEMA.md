# business-flow enrichment schema

`business-flow` 富化器(`phase=ENRICHMENT`)的产出。它在 codegraph 的通用调用图骨架
之上,用 LLM 重建"从请求到执行"的业务流语义。产物经编排层合并进 enriched-graph,
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
| `node_id` | string \| null | **锚回 codegraph 真实节点**。优先取 LLM 给的真实 id;否则经 `handled_by` 边取其 handler 的 `node_id`;都无则 `null` |

### `handlers` — 处理函数/方法

| 字段 | 类型 | 含义 |
|---|---|---|
| `id` | string | 富化内部稳定 id(如 `"h-login"`) |
| `name` | string \| null | 处理函数/方法名(尽量与 codegraph 节点 name 一致) |
| `source_ref` | string \| null | `相对路径:行号` |
| `node_id` | string \| null | **锚回 codegraph 真实节点**。优先取 LLM 给的真实 id;否则按 `name` 在骨架中兜底解析;都无则 `null` |

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

| 字段 | 类型 | 含义 |
|---|---|---|
| `endpoint_id` | string | 对应的 `endpoints[].id` |
| `intent` | string | 一句话业务意图(用业务语言,非复述代码) |
| `preconditions` | list[string] | 进入危险/写操作前**本应成立**的前置状态(如"购物车非空""当前用户是订单所有者") |
| `trust_boundaries` | list[object] | 信任边界,见下 |

`trust_boundaries[]` 每项:

| 字段 | 类型 | 含义 |
|---|---|---|
| `field` | string | 字段名(如 `amount` / `role` / `user_id`) |
| `source` | string | 数据来源:`request_body` / `query` / `path` / `header` / `session` / `server` |
| `validated` | bool | 服务端是否**独立复核**了该字段 |
| `note` | string | 说明;`validated=false` 时点明可被如何滥用 |

> **`validated=false` 且 `source` 为客户端(request_body/query/path/header)的字段,
> 就是业务逻辑漏洞的入口**——例如"下单金额 `amount` 来自 `request_body`、未核价"。
> 下游分析器应据此重点审查。

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
      ]
    }
  ]
}
```
