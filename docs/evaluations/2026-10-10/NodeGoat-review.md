# NodeGoat：默认整仓扫描人工核对

正式扫描 `5af058937a134c6791dfd94a95b21a6a`，commit `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`。include/exclude 为空，background 为 null，未缩小范围。

94/94 个 OCR 可审查文件完成；OCR 运行约 20 分 53 秒，3,085,257 token（输入 2,536,004，输出 549,253，输入中 cache read 为 2,041,344）。

## 核心命中

10/10 个预设案例被新扫描命中：请求字段 eval、MongoDB `$where` 注入、资产配置 IDOR、research SSRF、benefits 缺管理员校验、明文口令、session fixation、缺 CSRF token 防护、开放重定向、静态会话签名密钥。

这是已知案例命中率，不是所有潜在漏洞的召回率。CSRF 可利用条件依赖浏览器/同站与部署环境；未做动态攻击验证。指定 `getUserById(parseInt(...))` 负例没有被错误地当作 NoSQL operator 注入。

## 噪声和重复

325 条总发现中，security 80、bug 101、maintainability 101，其余为 documentation/test/style/other/performance。不能把 325 全部叫作漏洞。

至少五组核心问题在不同文件被重复描述：NoSQL 注入（DAO/路由）、资产 IDOR（handler/route）、benefits 授权（route/handler/template）、明文口令（存储/比较）、CSRF（全局 middleware/多个 form）。项目的文件＋代码指纹去重不能自动合并这些跨文件根因。

还核对到明确的事实错误：

- 登录密码“回填泄露”：当前 login handler 所有渲染分支的 password 均为空字符串，模板有 `value` 占位并不意味着传入了密码。
- URL/XSS 数据流错位：profile 链接使用 `firstNameSafeString`，报告却把 `doc.website` 当作 href 来源。真正的 firstName 链接风险有另一条报告，不能把变量追踪错误也算一个新漏洞。
- Cookie 报告的一部分错误：锁定的 express-session 1.15.6 默认 `httpOnly=true`，不能因没有显式设置就断言 Cookie 可被 XSS 读取；该条其余配置风险另论。[固定版本官方实现](https://github.com/expressjs/session/blob/v1.15.6/session/cookie.js)
- 开发 live-reload 常量脚本使用 `document.write`，没有识别出不可信输入链，不能直接推断 XSS。

开放重定向被标为 Critical，但报告展示的是钓鱼/导航风险，并未支持 RCE 或提权级别的影响。旧库里的 eval/HTML primitives、教程示例和测试凭据仍需上下文核对，不能直接当成生产环境漏洞。没有声称逐条验证所有 325 条输出，因此不提供虚构的全局精确率。

结果还有一条 `invalid_output` 警告：完整的文件覆盖和定位质量是不同指标，执行修复前应核对具体代码位置。

发现 ID、核心匹配和重复组见 [NodeGoat-review.json](NodeGoat-review.json)。本评测只使用正式新扫描结果，未安装、构建或执行目标应用。
