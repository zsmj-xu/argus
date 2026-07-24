## 漏洞检出对照(同一 ground truth,分类与检出分离)

| 工具 | findings 数 | 已检出 GT | 未检出 GT | Detection Recall |
|---|---:|---:|---:|---:|
| Shannon | 20 | 6 | 0 | 1.000 |
| Argus | 14 | 6 | 0 | 1.000 |

> GT 不完整,未匹配 finding 不能判定为 FP,因此不报告 Precision。

### 分类别正样本召回

| 类别 | Shannon | Argus |
|---|---:|---:|
| injection | 1/1 (1.000) | 1/1 (1.000) |
| xss | N/A (无正样本) | N/A (无正样本) |
| auth | 2/2 (1.000) | 2/2 (1.000) |
| authz | 3/3 (1.000) | 3/3 (1.000) |
| ssrf | N/A (无正样本) | N/A (无正样本) |

### GT 命中交集

- 两边都命中: vampi-auth-debug, vampi-bola-books-get, vampi-bola-update-password, vampi-massassign-admin, vampi-sqli-getuser, vampi-user-enum-login
- 仅 Shannon: 无
- 仅 Argus: 无


### 人工裁决质量(非 GT 召回)

| 工具 | true | duplicate | false | Validity precision | Duplicate rate |
|---|---:|---:|---:|---:|---:|
| Shannon | 17 | 3 | 0 | 1.000 | 0.150 |
| Argus | 13 | 1 | 0 | 1.000 | 0.071 |