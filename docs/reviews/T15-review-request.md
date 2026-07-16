# 评审请求:T15 靶场资产与 ground truth 导入(Codex 实现 → Claude 评审)

**分支**:`codex/T15`(实现 commit `57b9364`,已 rebase 到 `main@5deeb8d`)
**评审者**:Claude
**状态**:等待交叉评审;通过后方可合入 main 并解锁 T16。

## 改动范围

- 导入 `targets/VAmPI`、`targets/crAPI`、`targets/flowmart`。
- 导入四份 ground truth:`vampi.json`、`crapi.json`、
  `crapi-community.json`、`flowmart.json`。
- 新增 `docs/EVAL.md`,记录资产来源、schema、扫描根目录和复现命令。
- 新增 `tests/eval/test_ground_truth_assets.py`,校验 schema、源码位置、全局唯一
  vulnerability id、元数据清理和私钥材料排除。
- `pyproject.toml` 限制 setuptools 只发现 `argus*` 包,并让 ruff 排除上游靶场源码。

crAPI 仅保留评测需要的 workshop/community 服务、OpenAPI、README 与许可证。
嵌套 `.git`、`.codegraph`、缓存、demo `.env`、`.key`/`.pem`/`.p12`/
`.keystore`/`.jks` 和 private JWKS 均已排除。VAmPI 与 crAPI 的公共证书保留。

## 请重点评审

1. 四份 ground truth 的漏洞类别、源码位置和 `in_scope` 标记是否足以供 T16
   计算 precision/recall,尤其 crAPI workshop/community 是否应保持分开计分。
2. crAPI 的裁剪范围是否仍完整覆盖 ground truth,同时没有携带无关部署资产、
   前端依赖或敏感 demo 材料。
3. `location + service_path` 的定位约定、全局唯一 id 和五类 invariant vocabulary
   是否适合作为 T16/T17 的稳定输入。
4. `pyproject.toml` 的 package discovery / ruff 排除是否只隔离基准资产,不会漏掉
   Argus 自身代码质量检查或影响 editable install。
5. `docs/EVAL.md` 的来源 commit 与复现说明是否清楚、可追踪。

## 独立验证

```bash
git checkout codex/T15
uv run pytest -q
uv run mypy argus/
uv run ruff check .
uv run ruff format --check .
```

Codex 在 rebase 后的结果:

- pytest:**115 passed**
- mypy:**Success, no issues found in 36 source files**
- ruff check:**All checks passed**
- ruff format:**64 files already formatted**
- 内容级凭据扫描未发现 private key、AWS access key 或 client secret 模式。

## 评审结论(Claude 填写)

> 请给出 Spec ✅/❌、Quality Approved/需修改,以及按 Critical/Important/Minor
> 分级的 findings。

（待 Claude 填写）
