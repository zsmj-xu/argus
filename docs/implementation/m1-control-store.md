# M1：V2 领域模型与 Control Store

状态：已实现。本文记录 M1 边界；SourceSnapshot 和 Artifact Store 的后续状态见
`docs/implementation/m2-snapshots-artifacts.md`。

## 范围

M1 新增 Project、Scan、Task、Artifact metadata、StaticFindingV2 和 Event 的
Pydantic DTO，以及对应的本地 SQLite Control Store。现有 CLI、Web、
`argus/contracts.py`、LangGraph Pipeline 和 `runs/<workspace>/state.db` 均未接入
或改写。

默认 Control Store 路径约定为：

```text
<runs_root>/control.db
```

M1 不会在应用启动时自动创建或升级这个数据库。调用方必须显式执行 migration。

## 模块

```text
argus/domain/
├── enums.py       # Scan/Task/Finding/Event 等闭合枚举
├── errors.py      # 稳定应用错误
├── hashing.py     # 规范化 JSON 与 SHA-256
└── models.py      # 严格、不可变的 Pydantic DTO

argus/control/
├── db.py          # Engine、Session 和显式 Alembic upgrade
├── orm.py         # 仅持久化层可见的 SQLAlchemy Row
├── repositories.py
├── services.py    # Scan/Task 状态机
├── events.py      # Canonical Event 追加接口
└── migrations/
    └── versions/0001_control_store.py
```

ORM Row 不会从 Repository 返回。Repository 的输入和输出都是
`argus.domain.models` 中的 Pydantic DTO。

## 初始化

```python
from argus.control.db import Database, control_db_path, upgrade_database
from argus.control.repositories import Repositories
from argus.control.services import ControlServices

path = control_db_path("runs")
upgrade_database(path)

database = Database(path)
repositories = Repositories(database)
services = ControlServices(repositories)
```

`Database(path)` 只打开连接和 Session factory，不调用
`Base.metadata.create_all()`，也不隐式运行 migration。`upgrade_database(path)`
可以对空库执行，也可以重复执行到 Alembic `head`。

## 数据约束

- ID 在 DTO 中使用 UUID，在 SQLite 中保存为规范 UUID 字符串。
- 所有 DTO 时间必须 timezone-aware；进入数据库前统一为 UTC ISO 8601。
- JSON 字段使用 Pydantic `JsonValue` 递归类型，不接受任意 Python 对象。
- SHA-256 字段必须是 64 位小写十六进制。
- Project 名称唯一。
- Finding 在同一 Scan 内以 `(scan_id, fingerprint)` 唯一。
- Event 使用数据库自增 `sequence` 提供稳定追加顺序，事件 UUID 仍保持全局身份。

## 状态转换

Scan 和 Task 状态只能通过 `ScanService.transition()` 和
`TaskService.transition()` 表达。Service 会：

- 拒绝未列入状态图的转换；
- 首次进入 RUNNING 时记录 `started_at`；
- 进入终态时记录 `finished_at`；
- 只允许 FAILED 状态携带错误信息；
- 拒绝 naive datetime。

Repository 的 `update()` 使用 DTO 中的 `version` 执行 compare-and-swap：

```text
UPDATE ... WHERE id = :id AND version = :expected_version
```

成功后版本递增；旧 DTO 再写入会抛 `ConflictError`，不会静默覆盖。

## 错误边界

对外稳定错误为：

- `NotFoundError`
- `ConflictError`
- `InvalidTransitionError`
- `SchemaValidationError`

数据库唯一约束、外键约束和 stale version 会转换为这些应用错误，不把 ORM
对象或数据库实现细节交给调用方。

## V1 兼容

M1 与 V1 完全并行：

- V1 继续使用 `ArgusState` 和每个 Workspace 的 `state.db`；
- V1 Finding、报告、审核和进度格式不变；
- V1 Pipeline 不导入 `argus.domain` 或 `argus.control`；
- Web/CLI 不直接写 Control Store；
- `docs/contracts/interfaces.py` 与 `argus/contracts.py` 未修改。

## M1 完成时的限制与 M2/M3 前置条件

- M1 完成时只保存 `snapshot_id`，尚无 SourceSnapshot 表或物化服务；M2 已补齐。
- M1 完成时 Artifact 只保存 metadata 和 URI；M2 已补齐内容寻址 Store 和完整性校验。
- Task 保存未来规划所需的插件和 capability 字段，但本阶段没有 PluginSpec、
  TaskPlan 编译器或执行器；它们分别属于 M3/M4。
- Control Store 尚未接管 CLI/Web/Pipeline；不能将其中的数据解释为当前 V1
  Workspace 的事实来源。
- 当前只有初始 migration。未来 Schema 变化必须新增 revision，不能修改已发布
  revision，也不能用 `create_all()` 替代 migration。
