# VAmPI：默认整仓扫描人工核对

正式扫描：`1371b4ed88e747a1bc75de3eb74f95d7`，commit `f16052dce83f05847133ec98f01c5193a41de7d8`。include/exclude 为空，background 为 null。仅使用本次新结果。

20/20 个 OCR 可审查文件完成，无失败或跳过；OCR 执行约 5 分 20 秒，使用 412,334 token（输入 329,132，输出 83,202；输入中 cache read 为 276,608，不另加到总数）。

## 已知问题命中

| 已知案例 | 本次结果 |
| --- | --- |
| SQL 注入 | 命中 |
| 未授权修改其他用户密码 | **漏报**；报告仅指出该函数的 JSON-null 异常，没有识别缺失的属主检查 |
| 读取其他用户书籍 secret 的 BOLA | 命中 |
| 注册时 mass assignment / admin 提权 | 命中 |
| debug 接口泄露密码 | 命中；接口与模型各报一次 |
| 登录区分用户不存在与密码错误 | **漏报** |
| 邮箱 RegexDOS | 命中 |
| 弱 JWT 签名密钥 | 命中 |
| 明文存储密码 | 命中；存储与登录比较各报一次 |

预设正例命中 **7/9**。这是已知锚点召回，不是全仓所有可能漏洞的召回率。3 个指定负例没有触发对应错误攻击类型报告。

## 输出质量

共 49 条发现，其中 18 条被 OCR 分类为 security。逐条静态核对安全类后，保守归为：9 个不同的代码安全问题、2 条重复描述、7 条加固建议或部署依赖提示。debugger 访问依赖部署与 PIN 条件，弱种子凭据属于靶场默认设置；不据此声称已动态验证 RCE 或生产环境泄露。

其余一般代码审查输出不全部算漏洞。其中确认两条事实错误：

1. `3da44a758c46d60710eec9de100bea12`：报 Critical，声称 CI 必须 checkout，否则 Docker 构建失败。实际 `docker/build-push-action@v3` 未设置 context 时默认使用 Git context，**无需 checkout**。[对应版本官方说明](https://github.com/docker/build-push-action/tree/v3#git-context)
2. `7decf0205a7dc8110390a31dd9ed7801`：声称 SQLite QueuePool 会因默认同线程检查报错。项目固定 SQLAlchemy 2.0.2，其文件数据库默认自动设置 `check_same_thread=False`，该报告与对应版本行为矛盾。[2.0.2 官方源码](https://github.com/sqlalchemy/sqlalchemy/blob/rel_2_0_2/lib/sqlalchemy/dialects/sqlite/pysqlite.py)

另外 29 条为一般 bug、维护性或性能输出，本评测没有逐条证明其实际功能影响，不将它们统计为已确认安全漏洞，也不虚构一个覆盖全部输出的精确率。

## 结论

能识别明显注入、敏感数据泄露和明文口令，但**完整文件覆盖并不代表关键业务授权逻辑没有漏检**。默认报告混合安全、质量与加固建议，存在重复和版本行为误判；适合人工审查的线索来源，不能把 49 条发现直接当成 49 个漏洞。

所有匹配的发现 ID、重复组及逐条安全分类见 [VAmPI-review.json](VAmPI-review.json)。原始规范化发现及三个格式的报告保存在同目录；没有执行目标应用或攻击。
