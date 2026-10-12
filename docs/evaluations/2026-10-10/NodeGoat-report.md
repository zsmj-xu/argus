# Argus 白盒扫描报告 `5af058937a134c6791dfd94a95b21a6a`

- 代码仓库：`https://github.com/OWASP/NodeGoat.git`
- 分支或版本：`master`
- 提交：`c5cb68a7084e4ae7dcc60e6a98768720a81841e8`
- 扫描方式：`全仓`
- 增量起点：`不适用`
- 状态：`已完成`
- 阶段：`已完成`
- 文件：已审查 `94/94`
- 告警：`325` 条

> 本报告来自静态白盒审查。Argus 未执行目标代码，也未进行动态验证。

## 覆盖范围警告

- invalid\_output

## 1. XSS 风险：\`doc.website\` 在模板中被用于 URL 链接（href）上下文，\`encodeForHTML\` 只做 HTML 实体编码，无法阻止 \`javascript:\` 等协议注入，用户点击链接时仍可能执行脚本。应按代码注释所述改用 \`encodeForURL\`，或为 URL 上下文引入单独的模板变量。

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/routes/profile.js:28`

XSS 风险：\`doc.website\` 在模板中被用于 URL 链接（href）上下文，\`encodeForHTML\` 只做 HTML 实体编码，无法阻止 \`javascript:\` 等协议注入，用户点击链接时仍可能执行脚本。应按代码注释所述改用 \`encodeForURL\`，或为 URL 上下文引入单独的模板变量。

### 代码证据

```text
doc.website = ESAPI.encoder().encodeForHTML(doc.website);
```

### 修复建议

```text
doc.website = ESAPI.encoder().encodeForURL(doc.website);
```

## 2. 此处 \`&lt;pre&gt;\` 直接写在未闭合的 \`&lt;p&gt;\` 内部，HTML 解析器会在 \`&lt;pre&gt;\` 处自动闭合 \`&lt;p&gt;\`，导致其后的说明文本与 \`&lt;pre&gt;\` 都脱离段落结构；同时示例命令中的 \`&amp;password\`、\`&amp;\_csrf=\` 未转义为 \`&amp;amp;\`，不符合 HTML 规范。建议先闭合 \`&lt;p&gt;\` 再放置 \`&lt;pre&gt;\`，并对 \`&amp;\` 做实体转义。

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/views/tutorial/a1.html:349-353`

此处 \`&lt;pre&gt;\` 直接写在未闭合的 \`&lt;p&gt;\` 内部，HTML 解析器会在 \`&lt;pre&gt;\` 处自动闭合 \`&lt;p&gt;\`，导致其后的说明文本与 \`&lt;pre&gt;\` 都脱离段落结构；同时示例命令中的 \`&amp;password\`、\`&amp;\_csrf=\` 未转义为 \`&amp;amp;\`，不符合 HTML 规范。建议先闭合 \`&lt;p&gt;\` 再放置 \`&lt;pre&gt;\`，并对 \`&amp;\` 做实体转义。

### 代码证据

```text
&lt;p&gt;When user input is unsanitized and the output mechanism is an ordinary terminal stdout facility then the application will be vulnerable to CRLF injection, where an attacker can create a malicious payload as follows:
                        &lt;pre&gt;
curl http://localhost:4000/login -X POST --data 'userName=vyva%0aError: alex moldovan failed $1,000,000 transaction&amp;password=Admin_123&amp;_csrf='
                        &lt;/pre&gt;
                        Where the &lt;code&gt;userName&lt;/code&gt; parameter is encoding in the request the LF symbol which will result in a new line to begin. Resulting log output will look as follows:
```

### 修复建议

```text
&lt;p&gt;When user input is unsanitized and the output mechanism is an ordinary terminal stdout facility then the application will be vulnerable to CRLF injection, where an attacker can create a malicious payload as follows:&lt;/p&gt;
                        &lt;pre&gt;
curl http://localhost:4000/login -X POST --data 'userName=vyva%0aError: alex moldovan failed $1,000,000 transaction&amp;amp;password=Admin_123&amp;amp;_csrf='
                        &lt;/pre&gt;
                        &lt;p&gt;Where the &lt;code&gt;userName&lt;/code&gt; parameter is encoding in the request the LF symbol which will result in a new line to begin. Resulting log output will look as follows:&lt;/p&gt;
```

## 3. \`researchDAO\` 声明后从未被读取或使用，属于死代码。若暂不需要请删除该声明，否则应在此处实际使用它。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/routes/research.js:10`

\`researchDAO\` 声明后从未被读取或使用，属于死代码。若暂不需要请删除该声明，否则应在此处实际使用它。

### 代码证据

```text
const researchDAO = new ResearchDAO(db);
```

## 4. 将完整的 error 对象（包含 message、stack 等内部细节）直接传入模板渲染，可能把堆栈信息、文件路径等敏感内部信息泄露给客户端；若模板对 error.stack/message 未做转义直接输出，还存在 XSS 风险。建议只向前端传递经过脱敏的通用提示信息，详细信息仅记录在服务端日志中。

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/routes/error.js:10-12`

将完整的 error 对象（包含 message、stack 等内部细节）直接传入模板渲染，可能把堆栈信息、文件路径等敏感内部信息泄露给客户端；若模板对 error.stack/message 未做转义直接输出，还存在 XSS 风险。建议只向前端传递经过脱敏的通用提示信息，详细信息仅记录在服务端日志中。

### 代码证据

```text
res.render("error-template", {
        error: err
    });
```

### 修复建议

```text
res.render("error-template", {
        message: "Internal Server Error"
    });
```

## 5. email 字段同样将用户输入通过 {{email}} 未转义地插入 value 属性，配合全局 autoescape: false 可被用于反射型 XSS（例如通过 " onfocus=... 等负载跳出属性值）。建议使用 {{email|escape}} 或开启模板自动转义。

- 分类：`安全`
- 风险等级：`严重`
- 位置：`app/views/signup.html:102`

email 字段同样将用户输入通过 {{email}} 未转义地插入 value 属性，配合全局 autoescape: false 可被用于反射型 XSS（例如通过 " onfocus=... 等负载跳出属性值）。建议使用 {{email|escape}} 或开启模板自动转义。

### 代码证据

```text
&lt;input type="email" class="form-control" id="email" name="email" value="{{email}}" placeholder="Enter email"&gt;
```

### 修复建议

```text
&lt;input type="email" class="form-control" id="email" name="email" value="{{email|escape}}" placeholder="Enter email"&gt;
```

## 6. devDependencies 中 grunt-env 使用了 "latest" 作为版本号，不符合版本固定要求。latest 会随远端发布内容变化，导致安装结果不可复现、构建不稳定，也可能引入未经评审的破坏性变更。请改为具体的版本号（或明确的范围版本）。

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`package.json:50`

devDependencies 中 grunt-env 使用了 "latest" 作为版本号，不符合版本固定要求。latest 会随远端发布内容变化，导致安装结果不可复现、构建不稳定，也可能引入未经评审的破坏性变更。请改为具体的版本号（或明确的范围版本）。

### 代码证据

```text
"grunt-env": "latest",
```

### 修复建议

```text
"grunt-env": "0.4.4",
```

## 7. updateUser 将 ssn、dob 以及 bankAcc、bankRouting 等敏感字段以明文直接写入 users 集合，存在敏感数据暴露风险。文件中被注释掉的 encrypt/decrypt 逻辑表明原本有针对 A6 的加密修复，但当前已被禁用。建议重新启用加密存储（至少对 ssn、dob、bankAcc、bankRouting 加密或脱敏），避免敏感信息明文落库。

- 分类：`安全`
- 风险等级：`严重`
- 位置：`app/data/profile-dao.js:61-66`

updateUser 将 ssn、dob 以及 bankAcc、bankRouting 等敏感字段以明文直接写入 users 集合，存在敏感数据暴露风险。文件中被注释掉的 encrypt/decrypt 逻辑表明原本有针对 A6 的加密修复，但当前已被禁用。建议重新启用加密存储（至少对 ssn、dob、bankAcc、bankRouting 加密或脱敏），避免敏感信息明文落库。

### 代码证据

```text
if (ssn) {
            user.ssn = ssn;
        }
        if (dob) {
            user.dob = dob;
        }
```

## 8. \`(using &lt;code&gt;req.session.userId&lt;/code&gt;)instead of\` 中 \`)\` 与 \`instead\` 之间缺少空格；同时这里只描述了更安全的修复思路，没有给出对应的修复代码示例，建议补充完整代码以便学习者对照。

- 分类：`documentation`
- 风险等级：`低`
- 位置：`app/views/tutorial/a4.html:73-74`

\`(using &lt;code&gt;req.session.userId&lt;/code&gt;)instead of\` 中 \`)\` 与 \`instead\` 之间缺少空格；同时这里只描述了更安全的修复思路，没有给出对应的修复代码示例，建议补充完整代码以便学习者对照。

### 代码证据

```text
A safer alternative is to always retrieve allocations for logged in user (using
                    &lt;code&gt;req.session.userId&lt;/code&gt;)instead of taking it from url.
```

### 修复建议

```text
A safer alternative is to always retrieve allocations for logged in user (using
                    &lt;code&gt;req.session.userId&lt;/code&gt;) instead of taking it from url.
```

## 9. 密码输入框使用 value="{{password}}" 将密码回显到 HTML/DOM 中，存在被浏览器缓存、历史记录、自动填充或页面脚本读取的风险；即使当前错误路径未回填密码，这也是不应保留的敏感信息处理模式。密码字段不应回显，建议移除该 value 属性，verify 字段同理。

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/views/signup.html:91`

密码输入框使用 value="{{password}}" 将密码回显到 HTML/DOM 中，存在被浏览器缓存、历史记录、自动填充或页面脚本读取的风险；即使当前错误路径未回填密码，这也是不应保留的敏感信息处理模式。密码字段不应回显，建议移除该 value 属性，verify 字段同理。

### 代码证据

```text
&lt;input type="password" class="form-control" id="password" name="password" value="{{password}}" placeholder="Enter password"&gt;
```

### 修复建议

```text
&lt;input type="password" class="form-control" id="password" name="password" placeholder="Enter password"&gt;
```

## 10. 存在重复代码：\`adminSignIn\` 与 \`userSignIn\` 的实现几乎完全一致，仅 fixture 文件路径不同。建议抽取一个参数化的通用命令（例如 \`signInWithFixture(fixturePath)\`），传入 \`users/admin.json\` / \`users/user.json\`，减少维护成本，避免后续修改登录逻辑时遗漏同步。

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`test/e2e/support/commands.js:11-23`

存在重复代码：\`adminSignIn\` 与 \`userSignIn\` 的实现几乎完全一致，仅 fixture 文件路径不同。建议抽取一个参数化的通用命令（例如 \`signInWithFixture(fixturePath)\`），传入 \`users/admin.json\` / \`users/user.json\`，减少维护成本，避免后续修改登录逻辑时遗漏同步。

### 代码证据

```text
Cypress.Commands.add("adminSignIn", () =&gt; {
    cy.fixture("users/admin.json").as("admin");
    cy.get("@admin").then(admin =&gt; {
      cy.signIn(admin.user, admin.pass);
    });
  });

  Cypress.Commands.add("userSignIn", () =&gt; {
    cy.fixture("users/user.json").as("user");
    cy.get("@user").then(user =&gt; {
      cy.signIn(user.user, user.pass);
    });
  });
```

### 修复建议

```text
Cypress.Commands.add("signInWithFixture", fixturePath =&gt; {
    cy.fixture(fixturePath).as("credentials");
    cy.get("@credentials").then(credentials =&gt; {
      cy.signIn(credentials.user, credentials.pass);
    });
  });

  Cypress.Commands.add("adminSignIn", () =&gt; {
    cy.signInWithFixture("users/admin.json");
  });

  Cypress.Commands.add("userSignIn", () =&gt; {
    cy.signInWithFixture("users/user.json");
  });
```

## 11. toArray 的回调忽略了 err 参数，无论查询是否失败都调用 callback(null, users)。当数据库查询出错时 users 可能为 undefined，错误被静默吞掉，下游还会误以为查询成功。建议把错误传递给回调，例如先判断 err 再返回。

- 分类：`bug`
- 风险等级：`高`
- 位置：`app/data/benefits-dao.js:20`

toArray 的回调忽略了 err 参数，无论查询是否失败都调用 callback(null, users)。当数据库查询出错时 users 可能为 undefined，错误被静默吞掉，下游还会误以为查询成功。建议把错误传递给回调，例如先判断 err 再返回。

### 代码证据

```text
}).toArray((err, users) =&gt; callback(null, users));
```

### 修复建议

```text
}).toArray((err, users) =&gt; {
            if (err) {
                return callback(err);
            }
            return callback(null, users);
        });
```

## 12. \`input\` 是 HTML 空元素（void element），不允许写 \`&lt;/input&gt;\` 闭合标签（本文件中的隐藏字段与日期输入均有此写法），会影响 HTML 结构合法性。建议改为 \`&lt;input ... /&gt;\` 或直接去掉闭合标签。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/views/benefits.html:57`

\`input\` 是 HTML 空元素（void element），不允许写 \`&lt;/input&gt;\` 闭合标签（本文件中的隐藏字段与日期输入均有此写法），会影响 HTML 结构合法性。建议改为 \`&lt;input ... /&gt;\` 或直接去掉闭合标签。

### 代码证据

```text
&lt;input type="date" class="form-control" name="benefitStartDate" value="{{user.benefitStartDate}}"&gt;&lt;/input&gt;
```

### 修复建议

```text
&lt;input type="date" class="form-control" name="benefitStartDate" value="{{user.benefitStartDate}}" /&gt;
```

## 13. “Estimated Retirement Income / Month”的 $15,630 同样是写死的静态值，应替换为后端计算结果变量（如 {{ estimated\_monthly\_income }}），保证仪表盘展示的是用户真实数据。

- 分类：`bug`
- 风险等级：`高`
- 位置：`app/views/dashboard.html:87`

“Estimated Retirement Income / Month”的 $15,630 同样是写死的静态值，应替换为后端计算结果变量（如 {{ estimated\_monthly\_income }}），保证仪表盘展示的是用户真实数据。

### 代码证据

```text
&lt;p class="announcement-heading text-right"&gt;$15,630&lt;/p&gt;
```

### 修复建议

```text
&lt;p class="announcement-heading text-right"&gt;${{ estimated_monthly_income }}&lt;/p&gt;
```

## 14. 示例中间件 \`isAdminUserMiddleware\` 完全忽略了 \`userDAO.getUserById\` 回调中的 \`err\` 参数。虽然查询失败时 \`user\` 为 undefined 会跳转到 \`/login\`（fail-closed），但错误被静默吞掉，不利于排障，也不是良好的错误处理示例。建议显式处理错误，例如 \`if (err) return next(err);\` 或记录日志

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/views/tutorial/a7.html:70-71`

示例中间件 \`isAdminUserMiddleware\` 完全忽略了 \`userDAO.getUserById\` 回调中的 \`err\` 参数。虽然查询失败时 \`user\` 为 undefined 会跳转到 \`/login\`（fail-closed），但错误被静默吞掉，不利于排障，也不是良好的错误处理示例。建议显式处理错误，例如 \`if (err) return next(err);\` 或记录日志后返回 500。

### 代码证据

```text
userDAO.getUserById(req.session.userId, function(err, user) {
             if(user &amp;&amp; user.isAdmin) {
```

## 15. 重定向目标（/login、/benefits、/dashboard、/ 等）以硬编码字符串散落在多处路由中。建议集中定义为常量，便于统一维护，避免路径变更时遗漏修改。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/routes/session.js:31-32`

重定向目标（/login、/benefits、/dashboard、/ 等）以硬编码字符串散落在多处路由中。建议集中定义为常量，便于统一维护，避免路径变更时遗漏修改。

### 代码证据

```text
console.log("redirecting to login");
        return res.redirect("/login");
```

## 16. 存在业务相关的硬编码 URL 路径（\`/tutorial\`、\`/signup\` 及 \`benefits\`/\`dashboard\` 等断言值）。E2E 断言路由属于常见做法，但若存在集中的路由/常量定义，建议统一引用，避免路由变更时多处散落修改。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/e2e/integration/login\_spec.js:19-21`

存在业务相关的硬编码 URL 路径（\`/tutorial\`、\`/signup\` 及 \`benefits\`/\`dashboard\` 等断言值）。E2E 断言路由属于常见做法，但若存在集中的路由/常量定义，建议统一引用，避免路由变更时多处散落修改。

### 代码证据

```text
cy.get("a[href='/tutorial']")
      .should("have.attr", "target", "_blank")
      .and("be.visible");
```

## 17. 这里将用户提交的 memo 直接交给 marked 渲染并原样输出。由于 swig 模板引擎被配置为 autoescape: false，而项目使用的 marked@0.3.5 的 sanitize 过滤存在已知绕过方式，攻击者可以在 memo 中植入恶意 HTML/JavaScript，形成存储型 XSS。建议：开启模板自动转义，并/或对 marked 渲染结果使用可靠的 HTML 消毒库（如

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/views/memos.html:31`

这里将用户提交的 memo 直接交给 marked 渲染并原样输出。由于 swig 模板引擎被配置为 autoescape: false，而项目使用的 marked@0.3.5 的 sanitize 过滤存在已知绕过方式，攻击者可以在 memo 中植入恶意 HTML/JavaScript，形成存储型 XSS。建议：开启模板自动转义，并/或对 marked 渲染结果使用可靠的 HTML 消毒库（如 sanitize-html、DOMPurify）做二次过滤，仅允许白名单标签和属性。

### 代码证据

```text
{{ marked(doc.memo) }}
```

## 18. 这里保留了调试用的 console.log("in if symbol") 语句，会污染生产日志并可能泄露内部执行路径信息。建议移除，或改用正式的日志框架并按级别输出。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/data/research-dao.js:18`

这里保留了调试用的 console.log("in if symbol") 语句，会污染生产日志并可能泄露内部执行路径信息。建议移除，或改用正式的日志框架并按级别输出。

### 代码证据

```text
console.log("in if symbol");
```

## 19. \`require(...) || {}\` 的兜底逻辑无法生效：当对应环境配置文件（例如 NODE\_ENV=staging 时对应的 staging.js）不存在时，\`require\` 会直接抛出 MODULE\_NOT\_FOUND 异常导致进程崩溃，而不会返回 falsy 值触发 \`|| {}\`。建议显式检查文件是否存在（如 fs.existsSync）或在 try/catch 中回退到 \`{}\`，

- 分类：`bug`
- 风险等级：`中`
- 位置：`config/config.js:8`

\`require(...) || {}\` 的兜底逻辑无法生效：当对应环境配置文件（例如 NODE\_ENV=staging 时对应的 staging.js）不存在时，\`require\` 会直接抛出 MODULE\_NOT\_FOUND 异常导致进程崩溃，而不会返回 falsy 值触发 \`|| {}\`。建议显式检查文件是否存在（如 fs.existsSync）或在 try/catch 中回退到 \`{}\`，并给出明确的缺失提示。

### 代码证据

```text
const envConf = require(path.resolve(__dirname + "/../config/env/" + finalEnv.toLowerCase() + ".js")) || {};
```

### 修复建议

```text
const envFile = path.join(__dirname, "../config/env", finalEnv.toLowerCase() + ".js");
const envConf = fs.existsSync(envFile) ? require(envFile) : {};
```

## 20. app/data/profile-dao.js 使用 config.iv 作为 createCipheriv/decipheriv 的初始化向量，但本配置文件（以及 development/production/test 环境配置）均未导出 iv 属性，iv 为 undefined 时 CBC 模式会抛错，加密功能无法使用。请补充 iv 配置（如从环境变量读取并校验为 16 字节），或改用无需 I

- 分类：`bug`
- 风险等级：`中`
- 位置：`config/env/all.js:10-11`

app/data/profile-dao.js 使用 config.iv 作为 createCipheriv/decipheriv 的初始化向量，但本配置文件（以及 development/production/test 环境配置）均未导出 iv 属性，iv 为 undefined 时 CBC 模式会抛错，加密功能无法使用。请补充 iv 配置（如从环境变量读取并校验为 16 字节），或改用无需 IV 的加密方式。

### 代码证据

```text
cryptoAlgo: "aes256",
    hostName: "localhost",
```

### 修复建议

```text
cryptoAlgo: "aes-256-cbc",
    iv: process.env.CRYPTO_IV, // 必须为 16 字节
    hostName: "localhost",
```

## 21. 断言 \`include("a1")\` 使用子串包含匹配，而 \`/tutorial/a10\` 也包含 \`"a1"\`，因此 a1 用例即使实际跳转到 a10 也会通过，存在假阳性风险。建议使用精确断言，例如 \`cy.url().should("eq", Cypress.config("baseUrl") + "/tutorial/a1")\`，或用正则锚定路径结尾（如 \`/tutorial\\/a1$/\`

- 分类：`test`
- 风险等级：`中`
- 位置：`test/e2e/integration/tutorial\_spec.js:17`

断言 \`include("a1")\` 使用子串包含匹配，而 \`/tutorial/a10\` 也包含 \`"a1"\`，因此 a1 用例即使实际跳转到 a10 也会通过，存在假阳性风险。建议使用精确断言，例如 \`cy.url().should("eq", Cypress.config("baseUrl") + "/tutorial/a1")\`，或用正则锚定路径结尾（如 \`/tutorial\\/a1$/\`）。

### 代码证据

```text
cy.url().should("include", "a1");
```

## 22. 敏感信息暴露：校验失败时会把 \`ssn\`、\`bankAcc\`、\`bankRouting\` 等敏感字段原样回显到页面，尤其是银行账号和路由号属于高敏感信息。建议不要回显完整敏感字段，或先做脱敏处理后再展示。

- 分类：`安全`
- 风险等级：`中`
- 位置：`app/routes/profile.js:67-74`

敏感信息暴露：校验失败时会把 \`ssn\`、\`bankAcc\`、\`bankRouting\` 等敏感字段原样回显到页面，尤其是银行账号和路由号属于高敏感信息。建议不要回显完整敏感字段，或先做脱敏处理后再展示。

### 代码证据

```text
firstNameSafeString,
                lastName,
                ssn,
                dob,
                address,
                bankAcc,
                bankRouting,
                environmentalScripts
```

## 23. 该文档指向的 David DM 服务（david-dm.org）已停止维护，链接已失效；同时文中多个链接固定指向 npm CLI v6 文档（如 npm audit、npm outdated），与当前版本脱节，可能误导学习者。建议移除已失效的 David DM 链接，并将 npm 文档链接更新为当前版本（如 https://docs.npmjs.com/cli/ 下的最新命令文档），以保证教程内容

- 分类：`documentation`
- 风险等级：`低`
- 位置：`app/views/tutorial/a9.html:57`

该文档指向的 David DM 服务（david-dm.org）已停止维护，链接已失效；同时文中多个链接固定指向 npm CLI v6 文档（如 npm audit、npm outdated），与当前版本脱节，可能误导学习者。建议移除已失效的 David DM 链接，并将 npm 文档链接更新为当前版本（如 https://docs.npmjs.com/cli/ 下的最新命令文档），以保证教程内容的准确性和可用性。

### 代码证据

```text
&lt;a href="https://david-dm.org/"&gt;David DM&lt;/a&gt; gets you an overview of your project dependencies, the version you use and the latest available, so you can quickly see what's drifting
```

## 24. @font-face 中引用的字形图标字体文件（glyphicons-halflings-regular.eot/.woff/.ttf/.svg）在仓库中不存在（已在代码库中搜索确认）。页面使用 .glyphicon 图标时会请求 ../fonts/ 目录下的字体，因资源缺失导致图标无法正常显示。请将字体资源补入 app/assets/vendor/bootstrap/fonts/ 目录，或将 s

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/assets/vendor/bootstrap/bootstrap.css:2138-2139`

@font-face 中引用的字形图标字体文件（glyphicons-halflings-regular.eot/.woff/.ttf/.svg）在仓库中不存在（已在代码库中搜索确认）。页面使用 .glyphicon 图标时会请求 ../fonts/ 目录下的字体，因资源缺失导致图标无法正常显示。请将字体资源补入 app/assets/vendor/bootstrap/fonts/ 目录，或将 src 路径改为实际存在的资源位置。

### 代码证据

```text
src: url('../fonts/glyphicons-halflings-regular.eot');
  src: url('../fonts/glyphicons-halflings-regular.eot?#iefix') format('embedded-opentype'), url('../fonts/glyphicons-halflings-regular.woff') format('woff'), url('../fonts/glyphicons-halflings-regular.ttf') format('truetype'), url('../fonts/glyphicons-halflings-regular.svg#glyphicons-halflingsregular') format('svg');
```

## 25. 用户可控的 userName 直接写入日志，存在日志注入/日志伪造（CRLF）风险，攻击者可通过输入换行符伪造日志条目。建议在记录前过滤换行符或使用安全的编码方式。

- 分类：`安全`
- 风险等级：`中`
- 位置：`app/routes/session.js:64`

用户可控的 userName 直接写入日志，存在日志注入/日志伪造（CRLF）风险，攻击者可通过输入换行符伪造日志条目。建议在记录前过滤换行符或使用安全的编码方式。

### 代码证据

```text
console.log("Error: attempt to login with invalid user: ", userName);
```

### 修复建议

```text
console.log("Error: attempt to login with invalid user: ", userName.replace(/(\r\n|\r|\n)/g, "_"));
```

## 26. 当前使用的是 2013 年发布的 Bootstrap v3.0.0，版本过旧且已停止维护。建议升级到受支持的 Bootstrap 3.4.x（若需保持 3.x 兼容）或更新的大版本，以获取安全修复、浏览器兼容性及无障碍改进。注意升级会带来样式变化，需要做回归测试。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/assets/vendor/bootstrap/bootstrap.css:2`

当前使用的是 2013 年发布的 Bootstrap v3.0.0，版本过旧且已停止维护。建议升级到受支持的 Bootstrap 3.4.x（若需保持 3.x 兼容）或更新的大版本，以获取安全修复、浏览器兼容性及无障碍改进。注意升级会带来样式变化，需要做回归测试。

### 代码证据

```text
* Bootstrap v3.0.0
```

## 27. \`threshold\` 直接取自 \`req.query\`，未经任何校验、类型转换或默认值处理就传入 \`allocationsDAO.getByUserIdAndThreshold\`。下游 DAO 会将其原样拼接进 \`$where\` 字符串（\`this.stocks &gt; '${threshold}'\`），存在 NoSQL 注入风险（A1）。建议在路由层对 threshold 做白名单/范围校验（例如

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/routes/allocations.js:19-23`

\`threshold\` 直接取自 \`req.query\`，未经任何校验、类型转换或默认值处理就传入 \`allocationsDAO.getByUserIdAndThreshold\`。下游 DAO 会将其原样拼接进 \`$where\` 字符串（\`this.stocks &gt; '${threshold}'\`），存在 NoSQL 注入风险（A1）。建议在路由层对 threshold 做白名单/范围校验（例如 \`parseInt(threshold, 10)\` 并限制在 0-99），非法值时返回友好的错误信息，而不是透传给数据访问层。

### 代码证据

```text
const {
            threshold
        } = req.query;

        allocationsDAO.getByUserIdAndThreshold(userId, threshold, (err, allocations) =&gt; {
```

### 修复建议

```text
const {
            threshold
        } = req.query;

        const parsedThreshold = threshold ? parseInt(threshold, 10) : null;
        if (parsedThreshold !== null &amp;&amp; (Number.isNaN(parsedThreshold) || parsedThreshold &lt; 0 || parsedThreshold &gt; 99)) {
            return next(new Error("threshold 参数不合法"));
        }

        allocationsDAO.getByUserIdAndThreshold(userId, parsedThreshold, (err, allocations) =&gt; {
```

## 28. 该表单通过 POST 提交到 /contributions，但 CSRF token 的隐藏输入框被注释掉了（\`&lt;!-- ... --&gt;\` 内的 \`&lt;input type="hidden" name="\_csrf" ...&gt;\` 不会渲染），因此表单实际不会携带 CSRF token，存在跨站请求伪造（CSRF）风险：攻击者可诱导已登录用户提交恶意修改缴费比例的请求。注释中标注了 “Fix for

- 分类：`安全`
- 风险等级：`严重`
- 位置：`app/views/contributions.html:89-92`

该表单通过 POST 提交到 /contributions，但 CSRF token 的隐藏输入框被注释掉了（\`&lt;!-- ... --&gt;\` 内的 \`&lt;input type="hidden" name="\_csrf" ...&gt;\` 不会渲染），因此表单实际不会携带 CSRF token，存在跨站请求伪造（CSRF）风险：攻击者可诱导已登录用户提交恶意修改缴费比例的请求。注释中标注了 “Fix for A8 - CSRF”，说明该修复并未真正生效。建议取消注释，并确认 token 字段名与后端校验逻辑一致（如 \`\_csrf\`）。

### 代码证据

```text
&lt;!-- Fix for A8 - CSRF --&gt;
                        &lt;!--
                        &lt;input type="hidden" name="_csrf" value="{{csrftoken}}"&gt;&lt;/input&gt;
                        --&gt;
```

### 修复建议

```text
&lt;input type="hidden" name="_csrf" value="{{csrftoken}}"&gt;&lt;/input&gt;
```

## 29. matrix 中的 Node.js 10.x/12.x/14.x 均已结束生命周期（EOL），较新的依赖（如 Cypress）可能不再支持这些版本。建议替换为受支持的 LTS 版本，例如 18.x/20.x/22.x。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`.github/workflows/e2e-test.yml:12`

matrix 中的 Node.js 10.x/12.x/14.x 均已结束生命周期（EOL），较新的依赖（如 Cypress）可能不再支持这些版本。建议替换为受支持的 LTS 版本，例如 18.x/20.x/22.x。

### 代码证据

```text
node-version: ["10.x", "12.x", "14.x"]
```

### 修复建议

```text
node-version: ["18.x", "20.x", "22.x"]
```

## 30. \`crypto.pbkdf2Sync\` 的第四个参数 512 表示派生 512 位（64 字节）输出，而 AES-CBC/GCM 要求 IV 固定为 16 字节，直接把该结果作为 IV 会触发 \`ERR\_CRYPTO\_INVALID\_IV\`。另外 IV 应当每次加密随机生成并随密文保存，不应通过 KDF 从口令派生；AES 密钥本身也应通过 KDF 派生为 32 字节。

- 分类：`bug`
- 风险等级：`高`
- 位置：`app/views/tutorial/a6.html:90-94`

\`crypto.pbkdf2Sync\` 的第四个参数 512 表示派生 512 位（64 字节）输出，而 AES-CBC/GCM 要求 IV 固定为 16 字节，直接把该结果作为 IV 会触发 \`ERR\_CRYPTO\_INVALID\_IV\`。另外 IV 应当每次加密随机生成并随密文保存，不应通过 KDF 从口令派生；AES 密钥本身也应通过 KDF 派生为 32 字节。

### 代码证据

```text
var createIV = function() {
    // create a random salt for the PBKDF2 function - 16 bytes is the minimum length according to NIST
    var salt = crypto.randomBytes(16);
    return crypto.pbkdf2Sync(config.cryptoKey, salt, 100000, 512, "sha512");
};
```

### 修复建议

```text
var createKey = function(salt) {
    return crypto.pbkdf2Sync(config.cryptoKey, salt, 100000, 32, "sha512");
};
var createIV = function() {
    return crypto.randomBytes(16);
};
```

## 31. 远端响应内容未经转义即以 \`text/html\` 写回，且目标地址可由用户控制，等于把任意第三方内容以本应用同源方式渲染，存在 XSS/内容注入风险；同时 needle 在远端返回 JSON 时可能将 \`body\` 解析为对象，\`res.write(object)\` 会抛出 TypeError 导致 500。建议对 \`body\` 做 HTML 转义，或改用 \`text/plain\`/\`res.js

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/routes/research.js:24-26`

远端响应内容未经转义即以 \`text/html\` 写回，且目标地址可由用户控制，等于把任意第三方内容以本应用同源方式渲染，存在 XSS/内容注入风险；同时 needle 在远端返回 JSON 时可能将 \`body\` 解析为对象，\`res.write(object)\` 会抛出 TypeError 导致 500。建议对 \`body\` 做 HTML 转义，或改用 \`text/plain\`/\`res.json\`，并校验响应类型后再写回。

### 代码证据

```text
if (body) {
                    res.write(body);
                }
```

## 32. 在 \`grunt-if\` 的 \`test\` 函数里抛异常会导致整个 multi-task 直接失败，\`ifFalse\` 中配置的 \`npm-install:chromedriver@^2.21.2\` 不会被当作 false 分支执行，与“未安装则自动安装后运行安全测试”的意图相悖。检测失败时应 \`return false\`，让 grunt-if 执行 ifFalse 分支。

- 分类：`bug`
- 风险等级：`高`
- 位置：`Gruntfile.js:106`

在 \`grunt-if\` 的 \`test\` 函数里抛异常会导致整个 multi-task 直接失败，\`ifFalse\` 中配置的 \`npm-install:chromedriver@^2.21.2\` 不会被当作 false 分支执行，与“未安装则自动安装后运行安全测试”的意图相悖。检测失败时应 \`return false\`，让 grunt-if 执行 ifFalse 分支。

### 代码证据

```text
throw e;
```

### 修复建议

```text
return false;
```

## 33. ReDoS 漏洞：正则 \`/(\[0-9\]+)+\\\#/\` 中的嵌套量词 \`(\[0-9\]+)+\` 在遇到超长数字串但末尾不是 \`\#\` 的输入（例如 \`1111111111111111111111111111111111!\`）时会发生灾难性回溯，导致 CPU 资源耗尽。注释中虽然给出了修复方案，但当前代码仍在使用存在漏洞的表达式。建议改为 \`/^\[0-9\]+\#$/\`，同时锚定开头与结尾，也更符合“仅数字

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/routes/profile.js:59`

ReDoS 漏洞：正则 \`/(\[0-9\]+)+\\\#/\` 中的嵌套量词 \`(\[0-9\]+)+\` 在遇到超长数字串但末尾不是 \`\#\` 的输入（例如 \`1111111111111111111111111111111111!\`）时会发生灾难性回溯，导致 CPU 资源耗尽。注释中虽然给出了修复方案，但当前代码仍在使用存在漏洞的表达式。建议改为 \`/^\[0-9\]+\#$/\`，同时锚定开头与结尾，也更符合“仅数字+\#”的格式要求。

### 代码证据

```text
const regexPattern = /([0-9]+)+\#/;
```

### 修复建议

```text
const regexPattern = /^[0-9]+#$/;
```

## 34. \`&lt;pre&gt;\` 中的 \`&amp;&amp;\` 与 \`&gt;\` 未做 HTML 实体转义（应写作 \`&amp;amp;&amp;amp;\` 与 \`&amp;gt;\`）。虽然浏览器大多能容错显示，但会产生非法 HTML，可能被校验工具或编辑器误报。

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/views/tutorial/a1.html:260`

\`&lt;pre&gt;\` 中的 \`&amp;&amp;\` 与 \`&gt;\` 未做 HTML 实体转义（应写作 \`&amp;amp;&amp;amp;\` 与 \`&amp;gt;\`）。虽然浏览器大多能容错显示，但会产生非法 HTML，可能被校验工具或编辑器误报。

### 代码证据

```text
&lt;pre&gt; db.allocationsCollection.find({ $where: "this.userId == '" + parsedUserId + "' &amp;&amp; " + "this.stocks &gt; " + "'" + threshold + "'" }); &lt;/pre&gt;
```

### 修复建议

```text
&lt;pre&gt; db.allocationsCollection.find({ $where: "this.userId == '" + parsedUserId + "' &amp;amp;&amp;amp; " + "this.stocks &amp;gt; " + "'" + threshold + "'" }); &lt;/pre&gt;
```

## 35. 当 \`options.html\` 为 \`true\` 时，\`setContent\` 使用 \`.html()\` 直接插入 \`data-original-title\`/\`data-content\` 或 title/content 值；若这些值可被用户控制，则存在 XSS 风险。默认 \`html:false\` 尚安全，但一旦通过 \`data-html\` 或 \`html:true\` 启用，需保证内容经过转义

- 分类：`安全`
- 风险等级：`中`
- 位置：`app/assets/vendor/bootstrap/bootstrap.js`

当 \`options.html\` 为 \`true\` 时，\`setContent\` 使用 \`.html()\` 直接插入 \`data-original-title\`/\`data-content\` 或 title/content 值；若这些值可被用户控制，则存在 XSS 风险。默认 \`html:false\` 尚安全，但一旦通过 \`data-html\` 或 \`html:true\` 启用，需保证内容经过转义/白名单过滤，或改用 \`.text()\`。popover 的 \`setContent\` 存在同样模式。

### 代码证据

```text
a.find(".tooltip-inner")[this.options.html?"html":"text"](b)
```

## 36. 请求失败（\`error\` 为真）或状态码非 200 时，仍会向下执行并输出成功提示，最终以默认 200 状态返回，缺少错误处理和用户友好的错误信息。建议在 \`error\` 或 \`newResponse.statusCode !== 200\` 时设置相应状态码（如 400/502）并返回错误页面；同时 \`req.query.url\` 未做空值校验，\`undefined + symbol\` 会拼接出非

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/routes/research.js:17-21`

请求失败（\`error\` 为真）或状态码非 200 时，仍会向下执行并输出成功提示，最终以默认 200 状态返回，缺少错误处理和用户友好的错误信息。建议在 \`error\` 或 \`newResponse.statusCode !== 200\` 时设置相应状态码（如 400/502）并返回错误页面；同时 \`req.query.url\` 未做空值校验，\`undefined + symbol\` 会拼接出非法地址。

### 代码证据

```text
if (!error &amp;&amp; newResponse.statusCode === 200) {
                    res.writeHead(200, {
                        "Content-Type": "text/html"
                    });
                }
```

## 37. 测试用例名称语法有误："Should exists" 应为 "Should exist"。

- 分类：`代码风格`
- 风险等级：`低`
- 位置：`test/e2e/integration/memos\_spec.js:25`

测试用例名称语法有误："Should exists" 应为 "Should exist"。

### 代码证据

```text
it("Should exists a textarea", () =&gt; {
```

### 修复建议

```text
it("Should exist a textarea", () =&gt; {
```

## 38. \`&lt;script&gt;\` 标签缺少闭合的 \`&lt;/script&gt;\`。该条件注释目标浏览器是 IE9 及以下，在这些浏览器中解析器进入脚本内容状态后会一直吞掉后续 HTML，直到页面底部 jQuery 的 \`&lt;/script&gt;\` 才结束，导致中间内容无法正常渲染。应补上 \`&lt;/script&gt;\`。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/views/tutorial/layout.html:18`

\`&lt;script&gt;\` 标签缺少闭合的 \`&lt;/script&gt;\`。该条件注释目标浏览器是 IE9 及以下，在这些浏览器中解析器进入脚本内容状态后会一直吞掉后续 HTML，直到页面底部 jQuery 的 \`&lt;/script&gt;\` 才结束，导致中间内容无法正常渲染。应补上 \`&lt;/script&gt;\`。

### 代码证据

```text
&lt;!--[if lt IE 9]&gt;&lt;script src="../vendor/html5shiv.js"&gt;&lt;![endif]--&gt;
```

### 修复建议

```text
&lt;!--[if lt IE 9]&gt;&lt;script src="../vendor/html5shiv.js"&gt;&lt;/script&gt;&lt;![endif]--&gt;
```

## 39. 文件中大量使用 \`var\` 声明变量，不符合“禁止使用 \`var\`，应使用 \`let\`/\`const\`”的规范。这些顶层配置变量的值都不会被重新赋值，建议统一改为 \`const\`（如 \`const exec = require("child\_process").exec;\`）。

- 分类：`代码风格`
- 风险等级：`低`
- 位置：`Gruntfile.js:3-11`

文件中大量使用 \`var\` 声明变量，不符合“禁止使用 \`var\`，应使用 \`let\`/\`const\`”的规范。这些顶层配置变量的值都不会被重新赋值，建议统一改为 \`const\`（如 \`const exec = require("child\_process").exec;\`）。

### 代码证据

```text
var exec = require("child_process").exec;

var APP_JS_FILES = ["app/assets/js/**/*.js", "config/**/*.js", "app/data/**/*.js",
    "app/routes/**/*.js", "server.js"
];

var SUPPORT_JS_FILES = ["Gruntfile.js", "artifacts/**/*.js", "test/**/*.js"];

var JS_FILES = APP_JS_FILES.concat(SUPPORT_JS_FILES);
```

### 修复建议

```text
const exec = require("child_process").exec;

const APP_JS_FILES = ["app/assets/js/**/*.js", "config/**/*.js", "app/data/**/*.js",
    "app/routes/**/*.js", "server.js"
];

const SUPPORT_JS_FILES = ["Gruntfile.js", "artifacts/**/*.js", "test/**/*.js"];

const JS_FILES = APP_JS_FILES.concat(SUPPORT_JS_FILES);
```

## 40. \`smarttabs\` 为 \`false\` 表示\*\*不\*\*抑制混用 tab/空格的对齐告警，与注释「Suppresses warnings about mixed tabs and spaces.」相反。若希望抑制该告警应改为 \`true\`；否则请修正注释。

- 分类：`bug`
- 风险等级：`低`
- 位置：`.jshintrc:19`

\`smarttabs\` 为 \`false\` 表示\*\*不\*\*抑制混用 tab/空格的对齐告警，与注释「Suppresses warnings about mixed tabs and spaces.」相反。若希望抑制该告警应改为 \`true\`；否则请修正注释。

### 代码证据

```text
"smarttabs": false, // Suppresses warnings about mixed tabs and spaces.
```

### 修复建议

```text
"smarttabs": true, // Suppresses warnings about mixed tabs and spaces.
```

## 41. \`offset.top = offset.top;\` 与 \`offset.left = offset.left;\` 是自赋值空操作，无任何效果，属于死代码，建议删除。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/assets/vendor/bootstrap-tour.js`

\`offset.top = offset.top;\` 与 \`offset.left = offset.left;\` 是自赋值空操作，无任何效果，属于死代码，建议删除。

### 代码证据

```text
offset.top = offset.top;
      offset.left = offset.left;
```

## 42. {{error}} 通过 Swig 模板引擎输出时未做 HTML 转义。结合 server.js 中 \`swig.setDefaults({ autoescape: false })\` 显式关闭自动转义（且注释表明这是 A3 - XSS 的已知风险点），一旦 err.message 中包含用户可控内容（例如将用户输入拼入错误信息后抛出），就会形成反射型 XSS。建议启用 autoescape、显式

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/views/error-template.html:11`

{{error}} 通过 Swig 模板引擎输出时未做 HTML 转义。结合 server.js 中 \`swig.setDefaults({ autoescape: false })\` 显式关闭自动转义（且注释表明这是 A3 - XSS 的已知风险点），一旦 err.message 中包含用户可控内容（例如将用户输入拼入错误信息后抛出），就会形成反射型 XSS。建议启用 autoescape、显式转义输出，或仅在页面展示通用错误文案。

### 代码证据

```text
&lt;br&gt;{{error}}
```

### 修复建议

```text
&lt;br&gt;{{ error|escape }}
```

## 43. CSS 属性选择器缺少右括号 \`\]\`，\`input\[name='benefitStartDate'\` 不是合法选择器，\`cy.get\` 执行时会抛出语法错误，导致该用例无法运行。请补全为 \`input\[name='benefitStartDate'\]\`。

- 分类：`bug`
- 风险等级：`严重`
- 位置：`test/e2e/integration/benefits\_spec.js:40-42`

CSS 属性选择器缺少右括号 \`\]\`，\`input\[name='benefitStartDate'\` 不是合法选择器，\`cy.get\` 执行时会抛出语法错误，导致该用例无法运行。请补全为 \`input\[name='benefitStartDate'\]\`。

### 代码证据

```text
cy.get("input[name='benefitStartDate'")
      .first()
      .type("2099-01-10");
```

### 修复建议

```text
cy.get("input[name='benefitStartDate']")
      .first()
      .type("2099-01-10");
```

## 44. 对 404 页面正文做整段精确匹配（包含前后换行符）非常脆弱：只要错误页模板、Express 版本或尾部换行数稍有变化，断言就会失败。建议只校验关键信息，例如使用 include/contain 断言：.should("include", "Cannot GET /invented") 或 cy.get("body").contains("Cannot GET /invented")，以提升测试的

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/e2e/integration/general\_spec.js:73-75`

对 404 页面正文做整段精确匹配（包含前后换行符）非常脆弱：只要错误页模板、Express 版本或尾部换行数稍有变化，断言就会失败。建议只校验关键信息，例如使用 include/contain 断言：.should("include", "Cannot GET /invented") 或 cy.get("body").contains("Cannot GET /invented")，以提升测试的可维护性。

### 代码证据

```text
cy.get("body")
      .invoke("text")
      .should("eq", "\nCannot GET /invented\n\n\n");
```

### 修复建议

```text
cy.get("body")
      .invoke("text")
      .should("include", "Cannot GET /invented");
```

## 45. \`userId\` 通过隐藏字段由客户端直接提交，普通登录用户可以篡改该值，从而修改任意其他用户的 \`benefitStartDate\`（对应后端 \`updateBenefits\` 仅按 \`parseInt(userId)\` 直接更新，未校验当前会话是否为管理员或目标是否本人）。建议不要在客户端信任 \`userId\`，应由服务端基于会话与授权确定可修改的目标用户，或至少严格校验权限后再更新。

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/views/benefits.html:56`

\`userId\` 通过隐藏字段由客户端直接提交，普通登录用户可以篡改该值，从而修改任意其他用户的 \`benefitStartDate\`（对应后端 \`updateBenefits\` 仅按 \`parseInt(userId)\` 直接更新，未校验当前会话是否为管理员或目标是否本人）。建议不要在客户端信任 \`userId\`，应由服务端基于会话与授权确定可修改的目标用户，或至少严格校验权限后再更新。

### 代码证据

```text
&lt;input type="hidden" name="userId" value="{{user._id.toString()}}"&gt;&lt;/input&gt;
```

## 46. \`state.error\` 在初始化后从未被赋值，而所有 \`...Done(state.error, ...)\` 回调都把恒为 \`null\` 的 \`state.error\` 作为错误参数传递，导致 Zap 回调中的真实 \`err\` 被静默丢弃。\`onCompletion\` 中的 \`if (!error)\` 分支因此永远成立，真实失败不会被感知；且一旦 \`error\` 非空走 \`throw erro

- 分类：`bug`
- 风险等级：`高`
- 位置：`test/security/profile-test.js:31-34`

\`state.error\` 在初始化后从未被赋值，而所有 \`...Done(state.error, ...)\` 回调都把恒为 \`null\` 的 \`state.error\` 作为错误参数传递，导致 Zap 回调中的真实 \`err\` 被静默丢弃。\`onCompletion\` 中的 \`if (!error)\` 分支因此永远成立，真实失败不会被感知；且一旦 \`error\` 非空走 \`throw error\`，\`done()\` 不会被调用，测试会挂起。建议在每个 Zap 回调中直接处理错误，例如 \`if (err) return spiderDone(err);\`，不要再依赖这个永不更新的 \`state.error\`。

### 代码证据

```text
var state = {
    description: "",
    error: null
};
```

### 修复建议

```text
var state = {
    description: "",
    error: null
};

function handleZapError(err, done) {
    if (err) return done(err);
    done();
}
```

## 47. 测试用例名称中的 "accesible" 拼写错误，应为 "accessible"，影响可读性。

- 分类：`代码风格`
- 风险等级：`低`
- 位置：`test/e2e/integration/research\_spec.js:15`

测试用例名称中的 "accesible" 拼写错误，应为 "accessible"，影响可读性。

### 代码证据

```text
it("Should be accesible for a logged user", () =&gt; {
```

### 修复建议

```text
it("Should be accessible for a logged user", () =&gt; {
```

## 48. \`db-reset\` 执行失败时（\`err\` 非空）仅记录日志，随后仍调用 \`done()\`，Grunt 会把该任务标记为成功，掩盖了真实失败。失败时应调用 \`done(false)\`（成功路径调用 \`done(true)\`），以便 CI/构建能感知失败。

- 分类：`bug`
- 风险等级：`中`
- 位置：`Gruntfile.js:175`

\`db-reset\` 执行失败时（\`err\` 非空）仅记录日志，随后仍调用 \`done()\`，Grunt 会把该任务标记为成功，掩盖了真实失败。失败时应调用 \`done(false)\`（成功路径调用 \`done(true)\`），以便 CI/构建能感知失败。

### 代码证据

```text
done();
```

### 修复建议

```text
done(!err);
```

## 49. 业务相关的 URL 路径（如 "/allocations/1"、"/logout"、"login"）被硬编码在多个用例中，建议提取为集中管理的常量或路由配置，便于路由变更时统一维护。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/e2e/integration/allocations\_spec.js:11`

业务相关的 URL 路径（如 "/allocations/1"、"/logout"、"login"）被硬编码在多个用例中，建议提取为集中管理的常量或路由配置，便于路由变更时统一维护。

### 代码证据

```text
cy.visitPage("/logout");
```

### 修复建议

```text
cy.visitPage(ROUTES.LOGOUT);
```

## 50. parseInt(userId) 未指定进制，且未校验解析结果。userId 不是合法数字时会得到 NaN，导致按 \_id 查询不到记录却仍返回成功；以 "0x" 开头的字符串还会被按十六进制误解析。建议使用 parseInt(userId, 10) 并校验 NaN。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/data/benefits-dao.js:25`

parseInt(userId) 未指定进制，且未校验解析结果。userId 不是合法数字时会得到 NaN，导致按 \_id 查询不到记录却仍返回成功；以 "0x" 开头的字符串还会被按十六进制误解析。建议使用 parseInt(userId, 10) 并校验 NaN。

### 代码证据

```text
_id: parseInt(userId)
```

### 修复建议

```text
_id: parseInt(userId, 10)
```

## 51. 模板引擎在 server.js 中配置了 autoescape: false，因此此处的 {{userName}} 未经 HTML 转义便直接输出到 value 属性。注册校验失败时服务端会将用户提交的 userName 原样回显（见 app/routes/session.js 的 handleSignup），攻击者可构造如 " autofocus onfocus="alert(document.

- 分类：`安全`
- 风险等级：`严重`
- 位置：`app/views/signup.html:75`

模板引擎在 server.js 中配置了 autoescape: false，因此此处的 {{userName}} 未经 HTML 转义便直接输出到 value 属性。注册校验失败时服务端会将用户提交的 userName 原样回显（见 app/routes/session.js 的 handleSignup），攻击者可构造如 " autofocus onfocus="alert(document.cookie) 的负载跳出属性上下文，造成反射型 XSS。建议全局开启 autoescape，或至少对这些变量显式使用 escape 过滤器。

### 代码证据

```text
&lt;input type="text" class="form-control" id="userName" value="{{userName}}" name="userName" placeholder="Enter user name"&gt;
```

### 修复建议

```text
&lt;input type="text" class="form-control" id="userName" value="{{userName|escape}}" name="userName" placeholder="Enter user name"&gt;
```

## 52. describe 描述为 "/login behaviour"，但文件内用例实际测试的是 /benefits 页面，疑似复制粘贴遗留，建议改为 "/benefits behaviour"，避免误导。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/e2e/integration/benefits\_spec.js:3`

describe 描述为 "/login behaviour"，但文件内用例实际测试的是 /benefits 页面，疑似复制粘贴遗留，建议改为 "/benefits behaviour"，避免误导。

### 代码证据

```text
describe("/login behaviour", () =&gt; {
```

### 修复建议

```text
describe("/benefits behaviour", () =&gt; {
```

## 53. \`npx --no-install jshint@2.12.0 .\` 在没有任何依赖安装步骤的情况下会直接失败：\`--no-install\` 禁止 npx 自动下载缺失的包，而工作流既没有 \`npm ci\`/\`npm install\` 步骤，runner 上也没有全局安装 jshint，因此该步骤会报“找不到包/命令”。建议先添加依赖安装步骤（并配合缓存），或去掉 \`--no-install\` 让

- 分类：`bug`
- 风险等级：`高`
- 位置：`.github/workflows/lint.yml:25-26`

\`npx --no-install jshint@2.12.0 .\` 在没有任何依赖安装步骤的情况下会直接失败：\`--no-install\` 禁止 npx 自动下载缺失的包，而工作流既没有 \`npm ci\`/\`npm install\` 步骤，runner 上也没有全局安装 jshint，因此该步骤会报“找不到包/命令”。建议先添加依赖安装步骤（并配合缓存），或去掉 \`--no-install\` 让 npx 拉取指定版本。

### 代码证据

```text
- name: Run linter
        run: npx --no-install jshint@2.12.0 .
```

### 修复建议

```text
- name: Run linter
        run: npx jshint@2.12.0 .
```

## 54. 该用例依赖前一个用例“Should new user be added to the system”通过 UI 创建的新用户才能登录；若用 .only 单独运行、随机顺序运行或前一个用例失败，此用例必然失败，破坏了 E2E 用例的独立性。建议在本用例内通过 API（cy.request 或自定义命令）自行创建该用户，或将注册与登录合并为同一个用例，避免用例间的隐式依赖。

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`test/e2e/integration/signup\_spec.js:68-71`

该用例依赖前一个用例“Should new user be added to the system”通过 UI 创建的新用户才能登录；若用 .only 单独运行、随机顺序运行或前一个用例失败，此用例必然失败，破坏了 E2E 用例的独立性。建议在本用例内通过 API（cy.request 或自定义命令）自行创建该用户，或将注册与登录合并为同一个用例，避免用例间的隐式依赖。

### 代码证据

```text
it("Should new user be able to login in the system", () =&gt; {
    cy.fixture("users/new_user.json").as("newUser");
    cy.get("@newUser").then(newUser =&gt; {
      cy.signIn(newUser.user, newUser.pass);
```

## 55. 存在 SSRF（服务端请求伪造）风险：\`req.query.url\` 完全由用户控制，攻击者可构造任意目标地址（如 \`http://127.0.0.1:xxx/\`、\`http://169.254.169.254/latest/meta-data/\`、内网服务等），让服务器代替其发起请求。建议不要接收用户提供的完整 URL：只接收 \`symbol\`，在服务端使用白名单/固定域名拼接可信接口地址，并校

- 分类：`安全`
- 风险等级：`严重`
- 位置：`app/routes/research.js:15`

存在 SSRF（服务端请求伪造）风险：\`req.query.url\` 完全由用户控制，攻击者可构造任意目标地址（如 \`http://127.0.0.1:xxx/\`、\`http://169.254.169.254/latest/meta-data/\`、内网服务等），让服务器代替其发起请求。建议不要接收用户提供的完整 URL：只接收 \`symbol\`，在服务端使用白名单/固定域名拼接可信接口地址，并校验协议（仅允许 https）与目标主机。

### 代码证据

```text
const url = req.query.url + req.query.symbol;
```

## 56. 与 update 方法相同，\`userDAO.getUserById\` 在用户不存在时会回调 \`(null, null)\`，这里未对 \`user\` 做空值判断就访问 \`user.userName\`，可能抛出 TypeError。建议增加空值判断。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/data/contributions-dao.js:71`

与 update 方法相同，\`userDAO.getUserById\` 在用户不存在时会回调 \`(null, null)\`，这里未对 \`user\` 做空值判断就访问 \`user.userName\`，可能抛出 TypeError。建议增加空值判断。

### 代码证据

```text
userDAO.getUserById(userId, (err, user) =&gt; {
```

### 修复建议

```text
userDAO.getUserById(userId, (err, user) =&gt; {

                    if (err) return callback(err, null);
                    if (!user) return callback(new Error("User not found"), null);
```

## 57. 业务相关的 URL 路径 \`"/login"\` 被硬编码在命令中，后续路由调整时需要在代码里全局查找替换，容易遗漏。建议将路由路径集中到统一的配置/常量文件（如 \`routes\`/\`urls\` 配置）中引用。

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`test/e2e/support/commands.js:5`

业务相关的 URL 路径 \`"/login"\` 被硬编码在命令中，后续路由调整时需要在代码里全局查找替换，容易遗漏。建议将路由路径集中到统一的配置/常量文件（如 \`routes\`/\`urls\` 配置）中引用。

### 代码证据

```text
cy.visitPage("/login");
```

## 58. 此处通过 \`Function\` 构造器以字符串拼接方式动态生成可执行函数（\`a.createDocumentFragment = Function(...)\`），命中项目 Code Injection Protection 规则（禁止使用 \`Function()\` 构造器）。该字符串为库内静态内容、不包含用户输入，实际注入风险较低；但 html5shiv 属于第三方 vendor 库，不建议在 v

- 分类：`安全`
- 风险等级：`中`
- 位置：`app/assets/vendor/html5shiv.js`

此处通过 \`Function\` 构造器以字符串拼接方式动态生成可执行函数（\`a.createDocumentFragment = Function(...)\`），命中项目 Code Injection Protection 规则（禁止使用 \`Function()\` 构造器）。该字符串为库内静态内容、不包含用户输入，实际注入风险较低；但 html5shiv 属于第三方 vendor 库，不建议在 vendor 目录内直接改写（改写会破坏其对旧版 IE 的兼容性）。建议将 app/assets/vendor 纳入扫描豁免/依赖白名单并锁定版本，或评估升级到不使用动态构造函数的上游实现。

### 代码证据

```text
a.createDocumentFragment=Function("h","f","return function(){var n=f.cloneNode(),c=n.createElement;h.shivMethods&amp;&amp;("+m().join().replace(/\w+/g,function(a){b.createElem(a);b.frag.createElement(a);return'c("'+a+'"')'})+");return n}")(e,b.frag)
```

## 59. 安全问题（越权/IDOR）：\`updateBenefits\` 直接使用请求体中的 \`userId\` 调用 DAO，既未校验当前登录用户是否为管理员，也未校验该 \`userId\` 是否属于当前会话用户，任何已登录用户都可能修改任意用户的 \`benefitStartDate\`。同时 \`displayBenefits\`/\`updateBenefits\` 渲染时硬编码 \`user: { isAdmin:

- 分类：`安全`
- 风险等级：`严重`
- 位置：`app/routes/benefits.js:35`

安全问题（越权/IDOR）：\`updateBenefits\` 直接使用请求体中的 \`userId\` 调用 DAO，既未校验当前登录用户是否为管理员，也未校验该 \`userId\` 是否属于当前会话用户，任何已登录用户都可能修改任意用户的 \`benefitStartDate\`。同时 \`displayBenefits\`/\`updateBenefits\` 渲染时硬编码 \`user: { isAdmin: true }\`，使模板把所有访问者都当作管理员。建议从会话（如 \`req.session\`/\`req.user\`）获取并校验真实角色，据此渲染 \`isAdmin\`，并且非管理员只能修改自己的数据。

### 代码证据

```text
benefitsDAO.updateBenefits(userId, benefitStartDate, (error) =&gt; {
```

## 60. 错误直接通过 \`next(err)\` 透传给默认错误处理器，缺少用户友好的错误提示，查询失败时页面也不会给出可理解的反馈；同时本文件整体使用回调风格，与项目规范中“优先 async/await、避免回调嵌套”的要求不一致。建议对错误做友好封装（或统一错误中间件处理），并逐步改造为 async/await 写法。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/routes/memos.js:25-26`

错误直接通过 \`next(err)\` 透传给默认错误处理器，缺少用户友好的错误提示，查询失败时页面也不会给出可理解的反馈；同时本文件整体使用回调风格，与项目规范中“优先 async/await、避免回调嵌套”的要求不一致。建议对错误做友好封装（或统一错误中间件处理），并逐步改造为 async/await 写法。

### 代码证据

```text
memosDAO.getAllMemos((err, docs) =&gt; {
            if (err) return next(err);
```

## 61. SSN、银行账号、路由号等敏感信息直接以明文渲染在 \`value\` 中，页面 DOM、浏览器历史以及自动填充缓存都会留下这些信息；一旦页面存在其他 XSS，这些数据也更容易被读取。建议至少为这些敏感输入框添加 \`autocomplete="off"\`，并考虑对敏感字段做脱敏展示或要求用户重新输入。

- 分类：`安全`
- 风险等级：`中`
- 位置：`app/views/profile.html:49`

SSN、银行账号、路由号等敏感信息直接以明文渲染在 \`value\` 中，页面 DOM、浏览器历史以及自动填充缓存都会留下这些信息；一旦页面存在其他 XSS，这些数据也更容易被读取。建议至少为这些敏感输入框添加 \`autocomplete="off"\`，并考虑对敏感字段做脱敏展示或要求用户重新输入。

### 代码证据

```text
&lt;input type="text" class="form-control" id="ssn" name="ssn" value="{{ssn}}" placeholder="Enter SSN"&gt;
```

### 修复建议

```text
&lt;input type="text" class="form-control" id="ssn" name="ssn" value="{{ssn}}" placeholder="Enter SSN" autocomplete="off"&gt;
```

## 62. \`devel\` 为 \`false\` 时不会声明 \`console\`、\`alert\` 等开发期全局；在 \`browser\` 环境下配合 \`undef: true\`，使用 \`console.log()\` 会被报为未定义，与注释「Allow development statements e.g. \`console.log();\`」相反。如需允许开发语句应改为 \`true\`；否则请修正注释。

- 分类：`bug`
- 风险等级：`中`
- 位置：`.jshintrc:22`

\`devel\` 为 \`false\` 时不会声明 \`console\`、\`alert\` 等开发期全局；在 \`browser\` 环境下配合 \`undef: true\`，使用 \`console.log()\` 会被报为未定义，与注释「Allow development statements e.g. \`console.log();\`」相反。如需允许开发语句应改为 \`true\`；否则请修正注释。

### 代码证据

```text
"devel": false, // Allow development statements e.g. `console.log();`.
```

### 修复建议

```text
"devel": true, // Allow development statements e.g. `console.log();`.
```

## 63. 当 \`counters\` 集合中不存在名为 \`name\` 的文档时，\`findAndModify\` 返回的 \`data\` 或 \`data.value\` 可能为 \`null/undefined\`，直接访问 \`data.value.seq\` 会抛出 TypeError。建议增加空值判断并返回明确的错误信息。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/data/user-dao.js:119`

当 \`counters\` 集合中不存在名为 \`name\` 的文档时，\`findAndModify\` 返回的 \`data\` 或 \`data.value\` 可能为 \`null/undefined\`，直接访问 \`data.value.seq\` 会抛出 TypeError。建议增加空值判断并返回明确的错误信息。

### 代码证据

```text
(err, data) =&gt;  err ? callback(err, null) : callback(null, data.value.seq));
```

### 修复建议

```text
(err, data) =&gt; {
                if (err) return callback(err, null);
                if (!data || !data.value) return callback(new Error("counter not found: " + name), null);
                return callback(null, data.value.seq);
            });
```

## 64. grunt-if 直接引用了 GitHub master 分支的 tarball，指向持续变化的代码，无法保证可复现构建，且与 "latest"/"\*" 类似的不可固定风险。建议固定到具体 commit 或发布版本的 tarball。

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`package.json:51`

grunt-if 直接引用了 GitHub master 分支的 tarball，指向持续变化的代码，无法保证可复现构建，且与 "latest"/"\*" 类似的不可固定风险。建议固定到具体 commit 或发布版本的 tarball。

### 代码证据

```text
"grunt-if": "https://github.com/binarymist/grunt-if/tarball/master",
```

### 修复建议

```text
"grunt-if": "https://github.com/binarymist/grunt-if/tarball/&lt;commit-hash&gt;",
```

## 65. 模板末尾存在一个多余的 \`&lt;/div&gt;\` 闭合标签。当前文件中实际打开了 14 个 \`&lt;div&gt;\`，却关闭了 15 个 \`&lt;div&gt;\`，这个多余的闭合标签没有任何对应的开标签，会生成无效 HTML，可能导致浏览器对页面结构的解析出现偏差。建议删除该多余标签，只保留 \`{% endblock %}\`。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/views/tutorial/redos.html:64`

模板末尾存在一个多余的 \`&lt;/div&gt;\` 闭合标签。当前文件中实际打开了 14 个 \`&lt;div&gt;\`，却关闭了 15 个 \`&lt;div&gt;\`，这个多余的闭合标签没有任何对应的开标签，会生成无效 HTML，可能导致浏览器对页面结构的解析出现偏差。建议删除该多余标签，只保留 \`{% endblock %}\`。

### 代码证据

```text
&lt;/div&gt;{% endblock %}
```

### 修复建议

```text
{% endblock %}
```

## 66. job 未设置 \`timeout-minutes\`，若 \`npm start\` 等待或测试挂起，任务可能无限期占用 runner。建议添加合理的超时，例如 \`timeout-minutes: 30\`。

- 分类：`other`
- 风险等级：`低`
- 位置：`.github/workflows/e2e-test.yml:6-7`

job 未设置 \`timeout-minutes\`，若 \`npm start\` 等待或测试挂起，任务可能无限期占用 runner。建议添加合理的超时，例如 \`timeout-minutes: 30\`。

### 代码证据

```text
name: Node.js
    runs-on: ubuntu-latest
```

### 修复建议

```text
name: Node.js
    runs-on: ubuntu-latest
    timeout-minutes: 30
```

## 67. form 标签重复声明了 method="post"，属于无效的重复属性，浏览器只会采用其中一个，容易造成困惑。建议删除重复的 method 属性。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/views/signup.html:72`

form 标签重复声明了 method="post"，属于无效的重复属性，浏览器只会采用其中一个，容易造成困惑。建议删除重复的 method 属性。

### 代码证据

```text
&lt;form method="post" role="form" method="post"&gt;
```

### 修复建议

```text
&lt;form method="post" role="form"&gt;
```

## 68. label 的 for 属性指向不存在的 id="lastname"，实际输入框 id 为 password，导致点击标签无法聚焦到密码输入框，也影响无障碍访问。同样，Email 输入框的 label for="verify" 应改为 for="email"。建议修正这些 for 属性与对应输入框 id 的关联。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/views/signup.html:90`

label 的 for 属性指向不存在的 id="lastname"，实际输入框 id 为 password，导致点击标签无法聚焦到密码输入框，也影响无障碍访问。同样，Email 输入框的 label for="verify" 应改为 for="email"。建议修正这些 for 属性与对应输入框 id 的关联。

### 代码证据

```text
&lt;label for="lastname"&gt;Password&lt;/label&gt;
```

### 修复建议

```text
&lt;label for="password"&gt;Password&lt;/label&gt;
```

## 69. 该条件注释中的 \`&lt;script&gt;\` 缺少闭合标签 \`&lt;/script&gt;\`。在 IE &lt; 9（该注释的目标浏览器）中解析时，未闭合的 script 元素会导致后续页面内容被当作脚本内容，破坏页面结构。应补全闭合标签。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/views/layout.html:19`

该条件注释中的 \`&lt;script&gt;\` 缺少闭合标签 \`&lt;/script&gt;\`。在 IE &lt; 9（该注释的目标浏览器）中解析时，未闭合的 script 元素会导致后续页面内容被当作脚本内容，破坏页面结构。应补全闭合标签。

### 代码证据

```text
&lt;!--[if lt IE 9]&gt;&lt;script src="/vendor/html5shiv.js"&gt;&lt;![endif]--&gt;
```

### 修复建议

```text
&lt;!--[if lt IE 9]&gt;&lt;script src="/vendor/html5shiv.js"&gt;&lt;/script&gt;&lt;![endif]--&gt;
```

## 70. \`COPY --from=0\` 复制 \`node\_modules\` 时未指定 \`--chown\`，而随后的 \`RUN chown $USER:$USER $WORKDIR\` 只修改 \`$WORKDIR\` 目录本身（非递归），导致 \`node\_modules\` 及其内容仍属 root。最终以非 root 的 \`node\` 用户运行时，应用若需写入 \`node\_modules\`（如原生模块编译、缓存）

- 分类：`bug`
- 风险等级：`中`
- 位置：`Dockerfile:11-12`

\`COPY --from=0\` 复制 \`node\_modules\` 时未指定 \`--chown\`，而随后的 \`RUN chown $USER:$USER $WORKDIR\` 只修改 \`$WORKDIR\` 目录本身（非递归），导致 \`node\_modules\` 及其内容仍属 root。最终以非 root 的 \`node\` 用户运行时，应用若需写入 \`node\_modules\`（如原生模块编译、缓存）会因权限不足失败。建议使用 \`COPY --from=0 --chown=node:node /usr/src/app/node\_modules node\_modules\`，或改用 \`chown -R $USER:$USER $WORKDIR\`。

### 代码证据

```text
COPY --from=0 /usr/src/app/node_modules node_modules
RUN chown $USER:$USER $WORKDIR
```

### 修复建议

```text
COPY --from=0 --chown=node:node /usr/src/app/node_modules node_modules
RUN chown -R $USER:$USER $WORKDIR
```

## 71. 当仓库中存在 \`package-lock.json\` 时，建议使用 \`npm ci --production\` 替代 \`npm install --production --no-cache\`：\`npm ci\` 会严格按 lock 文件安装、先清空 \`node\_modules\`，可复现性更强且安装更快。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`Dockerfile:5`

当仓库中存在 \`package-lock.json\` 时，建议使用 \`npm ci --production\` 替代 \`npm install --production --no-cache\`：\`npm ci\` 会严格按 lock 文件安装、先清空 \`node\_modules\`，可复现性更强且安装更快。

### 代码证据

```text
RUN npm install --production --no-cache
```

### 修复建议

```text
RUN npm ci --production
```

## 72. 默认缴费比例（preTax/afterTax/roth 均为 2）属于业务数字硬编码，建议抽取为命名常量或配置项，便于集中维护。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/data/contributions-dao.js:64-68`

默认缴费比例（preTax/afterTax/roth 均为 2）属于业务数字硬编码，建议抽取为命名常量或配置项，便于集中维护。

### 代码证据

```text
contributions = contributions || {
                    preTax: 2,
                    afterTax: 2,
                    roth: 2
                };
```

## 73. 每次点击都会调用 redirectsTour.init()。bootstrap-tour 的 init() 不会检查 \_inited 标志，\_setupKeyboardNavigation() 和 \_onResize() 每次都直接使用 $(document).on(...) / $(window).on(...) 追加监听器（只有 \_setupMouseNavigation() 通过 .off(

- 分类：`bug`
- 风险等级：`高`
- 位置：`app/assets/js/tour/redirects-steps.js:25-29`

每次点击都会调用 redirectsTour.init()。bootstrap-tour 的 init() 不会检查 \_inited 标志，\_setupKeyboardNavigation() 和 \_onResize() 每次都直接使用 $(document).on(...) / $(window).on(...) 追加监听器（只有 \_setupMouseNavigation() 通过 .off().on() 保证幂等）。多次点击后，键盘事件和窗口 resize 会重复触发 next()/end()/showStep()，导致步骤被跳过或弹层异常。restart() 内部会调用 start()，而 start() 在未初始化时会自动调用 init()，因此这里手动调用 init() 是多余且有副作用的。

### 代码证据

```text
$("#redirects-tour").on("click", () =&gt; {
    "use strict";
    redirectsTour.init();
    redirectsTour.restart();
});
```

### 修复建议

```text
$("#redirects-tour").on("click", () =&gt; {
    "use strict";
    redirectsTour.restart();
});
```

## 74. \`target="\_blank"\` 打开的外链可以通过 \`window.opener\` 控制当前页面，存在反向 tabnabbing 风险。建议补充 \`rel="noopener noreferrer"\`。

- 分类：`安全`
- 风险等级：`低`
- 位置：`app/views/tutorial/a8.html`

\`target="\_blank"\` 打开的外链可以通过 \`window.opener\` 控制当前页面，存在反向 tabnabbing 风险。建议补充 \`rel="noopener noreferrer"\`。

### 代码证据

```text
available &lt;a target="_blank" href="https://github.com/ckarande/nodegoat-csrf-attack"&gt;here&lt;/a&gt;.
```

### 修复建议

```text
available &lt;a target="_blank" rel="noopener noreferrer" href="https://github.com/ckarande/nodegoat-csrf-attack"&gt;here&lt;/a&gt;.
```

## 75. \`toArray\` 在查询无结果时回调的是空数组 \`\[\]\`（空数组为 truthy），因此 \`!memos\` 这个条件永远不会成立，\`"ERROR: No memos found"\` 分支属于死代码；同时以字符串作为 \`err\` 回传与常规 \`Error\` 对象类型不一致。建议删除该判断，或改为基于 \`memos.length === 0\` 判断并使用 \`new Error(...)\` 返回。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/data/memos-dao.js:32-33`

\`toArray\` 在查询无结果时回调的是空数组 \`\[\]\`（空数组为 truthy），因此 \`!memos\` 这个条件永远不会成立，\`"ERROR: No memos found"\` 分支属于死代码；同时以字符串作为 \`err\` 回传与常规 \`Error\` 对象类型不一致。建议删除该判断，或改为基于 \`memos.length === 0\` 判断并使用 \`new Error(...)\` 返回。

### 代码证据

```text
if (!memos) return callback("ERROR: No memos found", null);
            callback(null, memos);
```

### 修复建议

```text
if (!memos || memos.length === 0) return callback(new Error("ERROR: No memos found"), null);
            callback(null, memos);
```

## 76. 按项目规则应禁止使用 \`var\`，改用 \`let\`/\`const\`。此处 \`document\` 后续会被重新赋值，可用 \`let\` 声明。

- 分类：`代码风格`
- 风险等级：`低`
- 位置：`app/assets/vendor/bootstrap-tour.js`

按项目规则应禁止使用 \`var\`，改用 \`let\`/\`const\`。此处 \`document\` 后续会被重新赋值，可用 \`let\` 声明。

### 代码证据

```text
var Tour, document;
```

### 修复建议

```text
let Tour, document;
```

## 77. \`&lt;p&gt;\` 的内容模型是 phrasing content，不能包含块级元素 \`&lt;pre&gt;\`。浏览器在解析到 \`&lt;p&gt;\` 内的第一个 \`&lt;pre&gt;\` 时会自动闭合 \`&lt;p&gt;\`，导致后续的 \`&lt;/p&gt;\` 成为孤立闭合标签，破坏预期的段落结构。建议将文本与 \`&lt;pre&gt;\` 拆分为并列的块级元素（例如一段 \`&lt;p&gt;\` 加多个 \`&lt;pre&gt;\`，或用 \`&lt;div&gt;\` 包裹整个示例区）。

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/views/tutorial/redos.html:48-51`

\`&lt;p&gt;\` 的内容模型是 phrasing content，不能包含块级元素 \`&lt;pre&gt;\`。浏览器在解析到 \`&lt;p&gt;\` 内的第一个 \`&lt;pre&gt;\` 时会自动闭合 \`&lt;p&gt;\`，导致后续的 \`&lt;/p&gt;\` 成为孤立闭合标签，破坏预期的段落结构。建议将文本与 \`&lt;pre&gt;\` 拆分为并列的块级元素（例如一段 \`&lt;p&gt;\` 加多个 \`&lt;pre&gt;\`，或用 \`&lt;div&gt;\` 包裹整个示例区）。

### 代码证据

```text
&lt;p&gt;
                Even simple regex patterns are vulnerable to ReDoS. The NodeGoat project uses the following source code to validate text format from the user based on a regex pattern:

                &lt;pre&gt;
```

## 78. 仅校验了登录状态而未校验管理员角色，普通用户也能访问并修改 benefits 数据，存在功能级访问控制缺失（下方被注释的修复代码表明该功能本应仅管理员可用）。建议在 \`isLoggedIn\` 后追加 \`isAdmin\` 中间件。

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/routes/index.js:55-56`

仅校验了登录状态而未校验管理员角色，普通用户也能访问并修改 benefits 数据，存在功能级访问控制缺失（下方被注释的修复代码表明该功能本应仅管理员可用）。建议在 \`isLoggedIn\` 后追加 \`isAdmin\` 中间件。

### 代码证据

```text
app.get("/benefits", isLoggedIn, benefitsHandler.displayBenefits);
    app.post("/benefits", isLoggedIn, benefitsHandler.updateBenefits);
```

### 修复建议

```text
app.get("/benefits", isLoggedIn, isAdmin, benefitsHandler.displayBenefits);
    app.post("/benefits", isLoggedIn, isAdmin, benefitsHandler.updateBenefits);
```

## 79. globalEval 使用 e.eval.call(e,t) 执行字符串，属于 eval 用法，存在代码注入风险。该逻辑用于执行脚本片段（如通过 ajax dataType:'script' 加载的响应），若输入来源不可信可导致任意代码执行。建议通过升级 jQuery 3.x 处理，并在业务侧避免将不可信字符串传入会触发 globalEval 的路径。

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/assets/vendor/jquery.min.js`

globalEval 使用 e.eval.call(e,t) 执行字符串，属于 eval 用法，存在代码注入风险。该逻辑用于执行脚本片段（如通过 ajax dataType:'script' 加载的响应），若输入来源不可信可导致任意代码执行。建议通过升级 jQuery 3.x 处理，并在业务侧避免将不可信字符串传入会触发 globalEval 的路径。

### 代码证据

```text
e.eval.call(e,t)
```

## 80. 会话配置存在多处安全/性能隐患：\`saveUninitialized: true\` 会为未认证请求也创建会话（增加会话固定风险与存储开销），\`resave: true\` 会导致每个请求都回写会话；同时未设置 \`cookie: { httpOnly: true, secure: true }\`，会话 ID 可被 XSS 脚本读取，且会在 HTTP 明文链路上传输。建议改为 \`saveUninitia

- 分类：`安全`
- 风险等级：`高`
- 位置：`server.js:82-85`

会话配置存在多处安全/性能隐患：\`saveUninitialized: true\` 会为未认证请求也创建会话（增加会话固定风险与存储开销），\`resave: true\` 会导致每个请求都回写会话；同时未设置 \`cookie: { httpOnly: true, secure: true }\`，会话 ID 可被 XSS 脚本读取，且会在 HTTP 明文链路上传输。建议改为 \`saveUninitialized: false\`、\`resave: false\`，并显式设置 \`cookie: { httpOnly: true, secure: true }\`（启用 HTTPS 后）。

### 代码证据

```text
secret: cookieSecret,
        // Both mandatory in Express v4
        saveUninitialized: true,
        resave: true
```

### 修复建议

```text
secret: cookieSecret,
        saveUninitialized: false,
        resave: false,
        cookie: {
            httpOnly: true,
            secure: true
        }
```

## 81. selenium-webdriver 的 \`findElement\` 只接受 \`By\` 定位器或 \`{using, value}\` 形式的 \`Locator\`，这里传入的普通对象 \`{tagName, type}\` 不是合法定位器，运行时会导致无效定位器错误，\`test.before\` 无法正常登录。应改用 \`By.css('button\[type="submit"\]')\`。

- 分类：`bug`
- 风险等级：`中`
- 位置：`test/security/profile-test.js:65-68`

selenium-webdriver 的 \`findElement\` 只接受 \`By\` 定位器或 \`{using, value}\` 形式的 \`Locator\`，这里传入的普通对象 \`{tagName, type}\` 不是合法定位器，运行时会导致无效定位器错误，\`test.before\` 无法正常登录。应改用 \`By.css('button\[type="submit"\]')\`。

### 代码证据

```text
webDriver.findElement({
        tagName: "button",
        type: "submit"
    }).click();
```

### 修复建议

```text
webDriver.findElement(By.css('button[type="submit"]')).click();
```

## 82. 敏感信息泄露：源码中硬编码了 ZAP API Key（zapApiKey）。API Key 属于敏感凭据，不应提交到版本控制中，即使这是测试环境配置也存在泄露风险（例如仓库公开、历史提交、日志或构建产物泄露）。建议改用环境变量或密钥管理方案注入，例如：\`zapApiKey: process.env.ZAP\_API\_KEY\`，并确保该值不落入仓库。

- 分类：`安全`
- 风险等级：`高`
- 位置：`config/env/test.js:6`

敏感信息泄露：源码中硬编码了 ZAP API Key（zapApiKey）。API Key 属于敏感凭据，不应提交到版本控制中，即使这是测试环境配置也存在泄露风险（例如仓库公开、历史提交、日志或构建产物泄露）。建议改用环境变量或密钥管理方案注入，例如：\`zapApiKey: process.env.ZAP\_API\_KEY\`，并确保该值不落入仓库。

### 代码证据

```text
zapApiKey: "v9dn0balpqas1pcc281tn5ood1",
```

### 修复建议

```text
zapApiKey: process.env.ZAP_API_KEY,
```

## 83. 此处硬编码了业务相关的学习资源 URL。该 URL 同时在 app/views/layout.html 中以相同方式硬编码，测试与页面模板各自维护一份副本，一旦链接更新需要同步修改多处，容易出现不一致（已通过全局搜索确认两处硬编码一致）。建议将外部学习链接集中到配置/常量或 fixture 中，测试与模板引用同一来源，避免重复维护与漂移。

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`test/e2e/integration/general\_spec.js:36-37`

此处硬编码了业务相关的学习资源 URL。该 URL 同时在 app/views/layout.html 中以相同方式硬编码，测试与页面模板各自维护一份副本，一旦链接更新需要同步修改多处，容易出现不一致（已通过全局搜索确认两处硬编码一致）。建议将外部学习链接集中到配置/常量或 fixture 中，测试与模板引用同一来源，避免重复维护与漂移。

### 代码证据

```text
const learnUrl = "https://www.khanacademy.org/" +
      "economics-finance-domain/core-finance/investment-vehicles-tutorial/ira-401ks/v/traditional-iras";
```

### 修复建议

```text
// 从统一的配置/fixture 读取学习链接，避免与模板中的硬编码 URL 重复维护
    const learnUrl = Cypress.env("LEARN_URL");
```

## 84. 表格中 URI Encoding 一行的编码建议有误：在 URL/href 上下文中应使用百分号编码 \`%HH\`，而不是 HTML Entity（\`&amp;\#xHH;\`）。HTML 实体编码无法阻止 \`javascript:\` 等伪协议注入，按此处示例实现仍会留下 XSS 风险。建议将该行改为使用 \`%HH\` percent-encoding 格式。

- 分类：`documentation`
- 风险等级：`中`
- 位置：`app/views/tutorial/a3.html:92-96`

表格中 URI Encoding 一行的编码建议有误：在 URL/href 上下文中应使用百分号编码 \`%HH\`，而不是 HTML Entity（\`&amp;\#xHH;\`）。HTML 实体编码无法阻止 \`javascript:\` 等伪协议注入，按此处示例实现仍会留下 XSS 风险。建议将该行改为使用 \`%HH\` percent-encoding 格式。

### 代码证据

```text
&lt;td&gt;URI Encoding&lt;/td&gt;
                                    &lt;td&gt;&amp;lt;a href="/site/search?value=
                                        &lt;span style="color:red;"&gt;UNTRUSTED DATA&lt;/span&gt;"&amp;gt;clickme&amp;lt;/a&amp;gt;&lt;/td&gt;
                                    &lt;td&gt;Except for alphanumeric characters, escape all characters with ASCII values less
                                        than 256 with the HTML Entity &amp;amp;#xHH; format, including spaces. (HH = Hex Value)
```

### 修复建议

```text
&lt;td&gt;Except for alphanumeric characters, escape all characters with ASCII values less
                                        than 256 with the %HH percent-encoding format, including spaces. (HH = Hex Value)
```

## 85. \`admin\` 与 \`non-admin\` 两个用例的校验逻辑完全相同，仅登录方式不同，属于重复代码。建议提取一个参数化的辅助函数（例如 \`verifyLogoutAfterSignIn(signInFn)\`），分别传入 \`cy.adminSignIn\` 与 \`cy.userSignIn\`，减少后续维护成本。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/e2e/integration/logout\_spec.js:15-29`

\`admin\` 与 \`non-admin\` 两个用例的校验逻辑完全相同，仅登录方式不同，属于重复代码。建议提取一个参数化的辅助函数（例如 \`verifyLogoutAfterSignIn(signInFn)\`），分别传入 \`cy.adminSignIn\` 与 \`cy.userSignIn\`，减少后续维护成本。

### 代码证据

```text
it("Should be working if the user is an admin", () =&gt; {
    cy.adminSignIn();
    cy.visitPage("/logout");
    cy.url().should("include", "login");
    cy.visitPage("/dashboard");
    cy.url().should("include", "login");
  });

  it("Should be working if the user is not an admin", () =&gt; {
    cy.userSignIn();
    cy.visitPage("/logout");
    cy.url().should("include", "login");
    cy.visitPage("/dashboard");
    cy.url().should("include", "login");
  });
```

## 86. \`&lt;iframe&gt;\` 缺少 \`title\` 属性，不利于无障碍访问，屏幕阅读器无法向用户说明嵌入内容。建议补充描述性 \`title\`，例如 \`title="Unvalidated Redirects and Forwards 讲解视频"\`。

- 分类：`代码风格`
- 风险等级：`低`
- 位置：`app/views/tutorial/a10.html:31`

\`&lt;iframe&gt;\` 缺少 \`title\` 属性，不利于无障碍访问，屏幕阅读器无法向用户说明嵌入内容。建议补充描述性 \`title\`，例如 \`title="Unvalidated Redirects and Forwards 讲解视频"\`。

### 代码证据

```text
&lt;iframe width="560" height="315" src="//www.youtube.com/embed/z98AQF8J_zg?rel=0" frameborder="0" allowfullscreen&gt;&lt;/iframe&gt;
```

### 修复建议

```text
&lt;iframe width="560" height="315" src="//www.youtube.com/embed/z98AQF8J_zg?rel=0" frameborder="0" allowfullscreen title="Unvalidated Redirects and Forwards 讲解视频"&gt;&lt;/iframe&gt;
```

## 87. tryDropCollection 中 reject 参数和回调的 data 参数从未使用（死代码），且无论 drop 成功或失败都 resolve，真实错误（如权限、连接异常）会被静默吞掉。建议区分“集合不存在”这一预期失败与其他错误：预期失败 resolve，其他错误 reject 并交由 Promise.all 处理，同时移除未使用的参数。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`artifacts/db-reset.js:40-41`

tryDropCollection 中 reject 参数和回调的 data 参数从未使用（死代码），且无论 drop 成功或失败都 resolve，真实错误（如权限、连接异常）会被静默吞掉。建议区分“集合不存在”这一预期失败与其他错误：预期失败 resolve，其他错误 reject 并交由 Promise.all 处理，同时移除未使用的参数。

### 代码证据

```text
return new Promise((resolve, reject) =&gt; {
        db.dropCollection(name, (err, data) =&gt; {
```

### 修复建议

```text
return new Promise((resolve, reject) =&gt; {
        db.dropCollection(name, (err) =&gt; {
            if (err &amp;&amp; err.code !== 26) { // 26 = NamespaceNotFound
                reject(err);
                return;
            }
            console.log(`Dropped collection: ${name}`);
            resolve();
        });
    });
```

## 88. \`actions/checkout@v2\` 已弃用（v2/v3 均已弃用，当前可用 v4）。建议升级到 \`actions/checkout@v4\`，以获取安全与功能更新。

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`.github/workflows/e2e-test.yml:16`

\`actions/checkout@v2\` 已弃用（v2/v3 均已弃用，当前可用 v4）。建议升级到 \`actions/checkout@v4\`，以获取安全与功能更新。

### 代码证据

```text
uses: actions/checkout@v2
```

### 修复建议

```text
uses: actions/checkout@v4
```

## 89. countersCol.insert 与 usersCol.insertMany 是并发发起的，但脚本在 allocations.insertMany 回调中直接调用 process.exit(0)。如果 counters 写入尚未完成，process.exit 会强制终止进程，导致 userId 计数器可能未被写入。建议将 counters 写入纳入同一条 Promise 链/await，确保所

- 分类：`bug`
- 风险等级：`中`
- 位置：`artifacts/db-reset.js:90-95`

countersCol.insert 与 usersCol.insertMany 是并发发起的，但脚本在 allocations.insertMany 回调中直接调用 process.exit(0)。如果 counters 写入尚未完成，process.exit 会强制终止进程，导致 userId 计数器可能未被写入。建议将 counters 写入纳入同一条 Promise 链/await，确保所有写操作全部完成后再退出。

### 代码证据

```text
countersCol.insert({
            _id: "userId",
            seq: 3
        }, (err, data) =&gt; {
            parseResponse(err, data, "countersCol.insert");
        });
```

### 修复建议

```text
const countersInsert = new Promise((resolve) =&gt; {
            countersCol.insert({
                _id: "userId",
                seq: 3
            }, (err, data) =&gt; {
                parseResponse(err, data, "countersCol.insert");
                resolve();
            });
        });
```

## 90. 存在大段被注释掉的旧实现（sessionDAO.startSession、ESAPI 日志编码示例、强密码正则等），属于死代码。建议清理或明确标注保留意图，避免误导维护者。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/routes/session.js:226-227`

存在大段被注释掉的旧实现（sessionDAO.startSession、ESAPI 日志编码示例、强密码正则等），属于死代码。建议清理或明确标注保留意图，避免误导维护者。

### 代码证据

```text
/*
                    sessionDAO.startSession(user._id, (err, sessionId) =&gt; {
```

## 91. 测试用例名称存在拼写错误："accesible" 应为 "accessible"，影响可读性，建议修正。

- 分类：`代码风格`
- 风险等级：`低`
- 位置：`test/e2e/integration/profile\_spec.js:19`

测试用例名称存在拼写错误："accesible" 应为 "accessible"，影响可读性，建议修正。

### 代码证据

```text
it("Should be accesible for logged user", () =&gt; {
```

### 修复建议

```text
it("Should be accessible for logged user", () =&gt; {
```

## 92. 断言中硬编码了业务相关的外部 URL（https://finance.yahoo.com/quote/ 的 URL 编码形式），并且与 app/views/research.html 中隐藏输入 url 的值重复。当业务 URL 变更时容易出现两处不一致，建议提取为共享常量或 fixture 复用，避免硬编码。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/e2e/integration/research\_spec.js:44`

断言中硬编码了业务相关的外部 URL（https://finance.yahoo.com/quote/ 的 URL 编码形式），并且与 app/views/research.html 中隐藏输入 url 的值重复。当业务 URL 变更时容易出现两处不一致，建议提取为共享常量或 fixture 复用，避免硬编码。

### 代码证据

```text
cy.url().should("include", "https%3A%2F%2Ffinance.yahoo.com%2Fquote%2F&amp;symbol=AAPL");
```

### 修复建议

```text
const researchUrl = encodeURIComponent("https://finance.yahoo.com/quote/");
    cy.url().should("include", `${researchUrl}&amp;symbol=${stockSymbol}`);
```

## 93. 存在不安全的直接对象引用（IDOR）：路由将 \`userId\` 作为 URL 路径参数传入，仅校验了登录状态，未校验该 \`userId\` 是否等于当前会话用户，任何登录用户都可以枚举他人 userId 查看其资产配置。建议从 \`req.session.userId\` 获取当前用户并移除路径参数。

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/routes/index.js:63`

存在不安全的直接对象引用（IDOR）：路由将 \`userId\` 作为 URL 路径参数传入，仅校验了登录状态，未校验该 \`userId\` 是否等于当前会话用户，任何登录用户都可以枚举他人 userId 查看其资产配置。建议从 \`req.session.userId\` 获取当前用户并移除路径参数。

### 代码证据

```text
app.get("/allocations/:userId", isLoggedIn, allocationsHandler.displayAllocations);
```

### 修复建议

```text
app.get("/allocations", isLoggedIn, allocationsHandler.displayAllocations);
```

## 94. 该工作流由 \`push\` 和 \`pull\_request\` 触发，但未配置 \`concurrency\`，同一分支的连续提交会产生多个冗余并发运行。建议添加并发控制，例如 \`concurrency:   group: ${{ github.workflow }}-${{ github.ref }}   cancel-in-progress: true\`。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`.github/workflows/lint.yml:2`

该工作流由 \`push\` 和 \`pull\_request\` 触发，但未配置 \`concurrency\`，同一分支的连续提交会产生多个冗余并发运行。建议添加并发控制，例如 \`concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true\`。

### 代码证据

```text
on: [push, pull_request]
```

### 修复建议

```text
on: [push, pull_request]

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

## 95. \`forEach\` 中对每条分配记录发起异步 \`getUserById\`，存在并发与重复回调问题：多个请求同时进行，\`userAllocations\` 的最终顺序由异步完成顺序决定（不稳定）；若某个请求失败会提前调用 \`callback(err)\`，但其他仍在进行的请求之后仍可能继续调用 \`callback\`，导致回调被多次触发。建议使用 \`Promise.all\` 并行处理并保留顺序，同时用一次

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/data/allocations-dao.js:93-95`

\`forEach\` 中对每条分配记录发起异步 \`getUserById\`，存在并发与重复回调问题：多个请求同时进行，\`userAllocations\` 的最终顺序由异步完成顺序决定（不稳定）；若某个请求失败会提前调用 \`callback(err)\`，但其他仍在进行的请求之后仍可能继续调用 \`callback\`，导致回调被多次触发。建议使用 \`Promise.all\` 并行处理并保留顺序，同时用一次性错误处理避免重复回调：
\`\`\`js
Promise.all(allocations.map(alloc =&gt; new Promise((resolve, reject) =&gt; {
    userDAO.getUserById(alloc.userId, (err, user) =&gt; {
        if (err) return reject(err);
        alloc.userName = user.userName;
        alloc.firstName = user.firstName;
        alloc.lastName = user.lastName;
        resolve(alloc);
    });
})))
    .then(userAllocations =&gt; callback(null, userAllocations))
    .catch(err =&gt; callback(err, null));
\`\`\`

### 代码证据

```text
allocations.forEach( alloc =&gt; {
                userDAO.getUserById(alloc.userId, (err, user) =&gt; {
                    if (err) return callback(err, null);
```

### 修复建议

```text
Promise.all(allocations.map(alloc =&gt; new Promise((resolve, reject) =&gt; {
                userDAO.getUserById(alloc.userId, (err, user) =&gt; {
                    if (err) return reject(err);
```

## 96. 缺少空值校验：若请求体缺失或字段为空，\`userId\`/\`benefitStartDate\` 会是 \`undefined\`，传入 DAO 后 \`parseInt(undefined)\` 会得到 \`NaN\`；若 \`req.body\` 本身为 \`undefined\`，该解构会直接抛出 \`TypeError\`。建议使用 \`req.body || {}\` 并显式校验 \`userId\`、\`benefitSt

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/routes/benefits.js:33`

缺少空值校验：若请求体缺失或字段为空，\`userId\`/\`benefitStartDate\` 会是 \`undefined\`，传入 DAO 后 \`parseInt(undefined)\` 会得到 \`NaN\`；若 \`req.body\` 本身为 \`undefined\`，该解构会直接抛出 \`TypeError\`。建议使用 \`req.body || {}\` 并显式校验 \`userId\`、\`benefitStartDate\` 是否存在及格式合法后再调用 DAO。

### 代码证据

```text
} = req.body;
```

## 97. 测试中直接硬编码了业务 URL 路径（\`/dashboard\`、\`/logout\`、\`/contributions\`），按规范业务相关 URL 路径不应硬编码，建议统一提取到路由常量中，便于路径变更时集中维护。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/e2e/integration/dashboard\_spec.js:6-8`

测试中直接硬编码了业务 URL 路径（\`/dashboard\`、\`/logout\`、\`/contributions\`），按规范业务相关 URL 路径不应硬编码，建议统一提取到路由常量中，便于路径变更时集中维护。

### 代码证据

```text
afterEach(() =&gt; {
    cy.visitPage("/logout");
  });
```

## 98. \`isNaN\` 会先做类型强制转换，\`isNaN(null)\`、\`isNaN('')\`、\`isNaN(false)\`、\`isNaN(\[\])\` 均返回 false，配合 eval 可提交 null/空串/布尔值等绕过“非法贡献比例”校验，后续写入数据库的将是 null 等非法值。建议改用 \`Number.isNaN\`，并在显式转换为数字后校验。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/routes/contributions.js:47`

\`isNaN\` 会先做类型强制转换，\`isNaN(null)\`、\`isNaN('')\`、\`isNaN(false)\`、\`isNaN(\[\])\` 均返回 false，配合 eval 可提交 null/空串/布尔值等绕过“非法贡献比例”校验，后续写入数据库的将是 null 等非法值。建议改用 \`Number.isNaN\`，并在显式转换为数字后校验。

### 代码证据

```text
const validations = [isNaN(preTax), isNaN(afterTax), isNaN(roth), preTax &lt; 0, afterTax &lt; 0, roth &lt; 0];
```

### 修复建议

```text
const validations = [Number.isNaN(preTax), Number.isNaN(afterTax), Number.isNaN(roth), preTax &lt; 0, afterTax &lt; 0, roth &lt; 0];
```

## 99. 未对 \`err\` 和 \`resp\` 做判空：当 Zap 创建扫描失败（网络异常、API 返回错误等）时，\`resp\` 为 \`undefined\`，访问 \`resp.scan\` 会抛出 \`TypeError\` 导致测试崩溃，而不是以可读的错误信息失败。建议先 \`if (err) return activeScanDone(err);\`，再校验 \`resp &amp;&amp; resp.scan\` 存在。

- 分类：`bug`
- 风险等级：`高`
- 位置：`test/security/profile-test.js:224`

未对 \`err\` 和 \`resp\` 做判空：当 Zap 创建扫描失败（网络异常、API 返回错误等）时，\`resp\` 为 \`undefined\`，访问 \`resp.scan\` 会抛出 \`TypeError\` 导致测试崩溃，而不是以可读的错误信息失败。建议先 \`if (err) return activeScanDone(err);\`，再校验 \`resp &amp;&amp; resp.scan\` 存在。

### 代码证据

```text
scanId = resp.scan;
```

### 修复建议

```text
if (err) return activeScanDone(err);
                        if (!resp || !resp.scan) return activeScanDone(new Error("Failed to start active scan"));
                        scanId = resp.scan;
```

## 100. \`config.cryptoKey\` 是长度 28 字节的字符串，不满足 aes-256 需要的 32 字节密钥；同时 \`encrypt\` 返回的密文中没有携带 IV，解密端无法获得每条记录对应的 IV。建议先通过 KDF 派生 32 字节密钥、随机生成 16 字节 IV，并把 IV 与密文一起保存（例如 \`iv + ':' + ciphertext\`）。

- 分类：`bug`
- 风险等级：`高`
- 位置：`app/views/tutorial/a6.html:97-101`

\`config.cryptoKey\` 是长度 28 字节的字符串，不满足 aes-256 需要的 32 字节密钥；同时 \`encrypt\` 返回的密文中没有携带 IV，解密端无法获得每条记录对应的 IV。建议先通过 KDF 派生 32 字节密钥、随机生成 16 字节 IV，并把 IV 与密文一起保存（例如 \`iv + ':' + ciphertext\`）。

### 代码证据

```text
var encrypt = function(toEncrypt) {
    config.iv = createIV();
    var cipher = crypto.createCipheriv(config.cryptoAlgo, config.cryptoKey, config.iv);
    return cipher.update(toEncrypt, "utf8", "hex") + cipher.final("hex");
};
```

## 101. 密码校验正则仅要求 1-20 个任意字符，与下方错误提示“8 到 18 位且包含数字、大小写字母”完全不符，属于弱密码策略。建议启用注释中的强密码规则，并同步修正错误提示文案。

- 分类：`安全`
- 风险等级：`中`
- 位置：`app/routes/session.js:144`

密码校验正则仅要求 1-20 个任意字符，与下方错误提示“8 到 18 位且包含数字、大小写字母”完全不符，属于弱密码策略。建议启用注释中的强密码规则，并同步修正错误提示文案。

### 代码证据

```text
const PASS_RE = /^.{1,20}$/;
```

### 修复建议

```text
const PASS_RE = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/;
```

## 102. 安全修复示例将会话密钥硬编码为弱口令 \`"s3Cur3"\`，容易诱导读者直接复制到生产代码。建议改为从环境变量/配置读取强随机密钥，例如本项目 \`config/config.js\` 导出的 \`cookieSecret\`。

- 分类：`安全`
- 风险等级：`低`
- 位置：`app/views/tutorial/a2.html:153`

安全修复示例将会话密钥硬编码为弱口令 \`"s3Cur3"\`，容易诱导读者直接复制到生产代码。建议改为从环境变量/配置读取强随机密钥，例如本项目 \`config/config.js\` 导出的 \`cookieSecret\`。

### 代码证据

```text
secret: "s3Cur3",
```

### 修复建议

```text
secret: cookieSecret,
```

## 103. 缺少安全响应头配置：未禁用 \`x-powered-by\`（泄露 Express 技术栈信息），也未启用 frameguard（点击劫持防护）、noCache、CSP、HSTS、nosniff 等。建议取消注释并启用 helmet 与 nosniff 中间件。

- 分类：`安全`
- 风险等级：`中`
- 位置：`server.js:67-68`

缺少安全响应头配置：未禁用 \`x-powered-by\`（泄露 Express 技术栈信息），也未启用 frameguard（点击劫持防护）、noCache、CSP、HSTS、nosniff 等。建议取消注释并启用 helmet 与 nosniff 中间件。

### 代码证据

```text
// Adding/ remove HTTP Headers for security
    app.use(favicon(__dirname + "/app/assets/favicon.ico"));
```

### 修复建议

```text
app.disable("x-powered-by");
    app.use(helmet.frameguard());
    app.use(helmet.noCache());
    app.use(helmet.contentSecurityPolicy());
    app.use(helmet.hsts());
    app.use(nosniff());
```

## 104. \`userDAO.getUserById\` 在用户不存在时会回调 \`(null, null)\`，此处仅判断了 \`err\` 就直接访问 \`user.userName\`，会抛出 TypeError。建议增加 \`user\` 的空值判断并返回友好错误。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/data/contributions-dao.js:38`

\`userDAO.getUserById\` 在用户不存在时会回调 \`(null, null)\`，此处仅判断了 \`err\` 就直接访问 \`user.userName\`，会抛出 TypeError。建议增加 \`user\` 的空值判断并返回友好错误。

### 代码证据

```text
userDAO.getUserById(parsedUserId, (err, user) =&gt; {
```

### 修复建议

```text
userDAO.getUserById(parsedUserId, (err, user) =&gt; {

                        if (err) return callback(err, null);
                        if (!user) return callback(new Error("User not found"), null);
```

## 105. 当前忽略列表没有排除敏感文件（如 \`.env\`、\`.env.\*\`、\`\*.pem\`、\`\*.key\`、\`.npmrc\` 等）。结合 Dockerfile 第 13 行 \`COPY --chown=node . $WORKDIR\`，整个构建上下文都会被复制进镜像；如果仓库中残留 \`.env\` 等文件，密钥/凭据会永久写入镜像层，存在泄露风险。建议补充这些敏感文件的排除项。

- 分类：`安全`
- 风险等级：`高`
- 位置：`.dockerignore:4-6`

当前忽略列表没有排除敏感文件（如 \`.env\`、\`.env.\*\`、\`\*.pem\`、\`\*.key\`、\`.npmrc\` 等）。结合 Dockerfile 第 13 行 \`COPY --chown=node . $WORKDIR\`，整个构建上下文都会被复制进镜像；如果仓库中残留 \`.env\` 等文件，密钥/凭据会永久写入镜像层，存在泄露风险。建议补充这些敏感文件的排除项。

### 代码证据

```text
.git
.github
.gitignore
```

### 修复建议

```text
.git
.github
.gitignore
.env
.env.*
*.pem
*.key
.npmrc
```

## 106. 测试描述存在拼写错误：\`accesible\` 应为 \`accessible\`，影响测试输出信息的可读性。

- 分类：`代码风格`
- 风险等级：`低`
- 位置：`test/e2e/integration/learn\_spec.js:15`

测试描述存在拼写错误：\`accesible\` 应为 \`accessible\`，影响测试输出信息的可读性。

### 代码证据

```text
it("Should be accesible for a logged user", () =&gt; {
```

### 修复建议

```text
it("Should be accessible for a logged user", () =&gt; {
```

## 107. \`COPY . $WORKDIR\` 会把整个构建上下文复制进镜像；如果上下文中包含本机的 \`node\_modules\`，会覆盖上面从阶段 0 复制过来的生产依赖，且 \`.git\`、\`.env\*\`、日志等文件也可能被打包进镜像。建议在项目根目录添加 \`.dockerignore\`（至少排除 \`node\_modules\`、\`.git\`、\`\*.log\`、\`.env\*\`、\`Dockerfile\` 等），并

- 分类：`bug`
- 风险等级：`中`
- 位置：`Dockerfile:13`

\`COPY . $WORKDIR\` 会把整个构建上下文复制进镜像；如果上下文中包含本机的 \`node\_modules\`，会覆盖上面从阶段 0 复制过来的生产依赖，且 \`.git\`、\`.env\*\`、日志等文件也可能被打包进镜像。建议在项目根目录添加 \`.dockerignore\`（至少排除 \`node\_modules\`、\`.git\`、\`\*.log\`、\`.env\*\`、\`Dockerfile\` 等），并尽量只复制运行所需文件。

### 代码证据

```text
COPY --chown=node . $WORKDIR
```

## 108. \`return\` 之后的 \`break\` 永远不会执行，属于死代码，建议删除。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/assets/vendor/bootstrap-tour.js`

\`return\` 之后的 \`break\` 永远不会执行，属于死代码，建议删除。

### 代码证据

```text
if (_this._isLast()) {
              return _this.next();
            } else {
              return _this.end();
            }
            break;
```

## 109. 直接将未校验的 \`arg\` / \`process.env.NODE\_ENV\` 拼接到 shell 命令中，存在命令注入风险（例如 \`grunt db-reset:'dev; rm -rf ...'\`）。同时 Windows 分支使用 \`&amp;\` 分隔命令，即使 NODE\_ENV 设置失败，后续命令仍会执行。建议对 \`finalEnv\` 做白名单校验（如 \`/^\[A-Za-z0-9\_-\]+$/\`），或改

- 分类：`安全`
- 风险等级：`高`
- 位置：`Gruntfile.js:163`

直接将未校验的 \`arg\` / \`process.env.NODE\_ENV\` 拼接到 shell 命令中，存在命令注入风险（例如 \`grunt db-reset:'dev; rm -rf ...'\`）。同时 Windows 分支使用 \`&amp;\` 分隔命令，即使 NODE\_ENV 设置失败，后续命令仍会执行。建议对 \`finalEnv\` 做白名单校验（如 \`/^\[A-Za-z0-9\_-\]+$/\`），或改用 \`execFile\` 配合 \`env\` 参数传递环境变量，避免手工拼接 shell 字符串。

### 代码证据

```text
var cmd = process.platform === "win32" ? "NODE_ENV=" + finalEnv + " &amp; " : "NODE_ENV=" + finalEnv + " ";
```

### 修复建议

```text
if (!/^[A-Za-z0-9_-]+$/.test(finalEnv)) {
            grunt.fail.fatal("Invalid NODE_ENV value: " + finalEnv);
        }
        var cmd = process.platform === "win32" ? "set NODE_ENV=" + finalEnv + " &amp;&amp; " : "NODE_ENV=" + finalEnv + " ";
```

## 110. 公告中的收入替代率 80% 和 61% 被硬编码在模板里，所有用户都会看到完全相同的数字，无法反映各自账户的真实测算结果。建议从后端传入模板变量（如 {{ recommended\_rate }} / {{ current\_rate }}），由服务端计算后渲染，避免展示误导性数据。

- 分类：`bug`
- 风险等级：`高`
- 位置：`app/views/dashboard.html:11`

公告中的收入替代率 80% 和 61% 被硬编码在模板里，所有用户都会看到完全相同的数字，无法反映各自账户的真实测算结果。建议从后端传入模板变量（如 {{ recommended\_rate }} / {{ current\_rate }}），由服务端计算后渲染，避免展示误导性数据。

### 代码证据

```text
&lt;p class="announcement-text"&gt;Experts recommend having &lt;b&gt;80%&lt;/b&gt; income replacement saved for retirement. You are estimated to have &lt;b&gt;61%&lt;/b&gt; income replacement given your current information and contribution rate.&lt;/p&gt;
```

### 修复建议

```text
&lt;p class="announcement-text"&gt;Experts recommend having &lt;b&gt;{{ recommended_rate }}%&lt;/b&gt; income replacement saved for retirement. You are estimated to have &lt;b&gt;{{ current_rate }}%&lt;/b&gt; income replacement given your current information and contribution rate.&lt;/p&gt;
```

## 111. 本行及文件中多处使用非严格相等比较（\`1==a.childNodes.length\`、\`"undefined"==typeof c.cloneNode\`、\`"string"==typeof a\` 等），违反「使用 === / !==」的规则。由于这是压缩后的第三方 vendor 库，建议不要手工改写，而是通过 lint/静态扫描配置将 vendor 目录排除在严格相等检查之外。

- 分类：`代码风格`
- 风险等级：`低`
- 位置：`app/assets/vendor/html5shiv.js`

本行及文件中多处使用非严格相等比较（\`1==a.childNodes.length\`、\`"undefined"==typeof c.cloneNode\`、\`"string"==typeof a\` 等），违反「使用 === / !==」的规则。由于这是压缩后的第三方 vendor 库，建议不要手工改写，而是通过 lint/静态扫描配置将 vendor 目录排除在严格相等检查之外。

### 代码证据

```text
if(!(b=1==a.childNodes.length)){f.createElement("a");var c=f.createDocumentFragment();b="undefined"==typeof c.cloneNode||
```

## 112. 测试名称中 "accesible" 拼写错误，应为 "accessible"。

- 分类：`代码风格`
- 风险等级：`低`
- 位置：`test/e2e/integration/benefits\_spec.js:25`

测试名称中 "accesible" 拼写错误，应为 "accessible"。

### 代码证据

```text
it("Should be accesible if the user is not an admin", () =&gt; {
```

### 修复建议

```text
it("Should be accessible if the user is not an admin", () =&gt; {
```

## 113. \`update\` 的回调存在重复调用问题：当 \`err\` 为空时，先异步发起 \`userDAO.getUserById\`，随后代码继续向下执行到末尾的 \`return callback(err, null)\`（此时 \`err\` 为 \`null\`），导致外层回调先以 \`(null, null)\` 被调用一次；待 \`getUserById\` 完成后又会以 \`(null, allocations)\` 再

- 分类：`bug`
- 风险等级：`严重`
- 位置：`app/data/allocations-dao.js:35-39`

\`update\` 的回调存在重复调用问题：当 \`err\` 为空时，先异步发起 \`userDAO.getUserById\`，随后代码继续向下执行到末尾的 \`return callback(err, null)\`（此时 \`err\` 为 \`null\`），导致外层回调先以 \`(null, null)\` 被调用一次；待 \`getUserById\` 完成后又会以 \`(null, allocations)\` 再次调用 \`callback\`。调用方可能因此收到两次响应或重复执行后续逻辑。建议把错误分支放到 \`else\`，或成功分支直接 \`return\` 并移除末尾的无条件回调：
\`\`\`js
if (err) return callback(err, null);

console.log("Updated allocations");

userDAO.getUserById(userId, (err, user) =&gt; {
    if (err) return callback(err, null);
    // ...
    return callback(null, allocations);
});
\`\`\`

### 代码证据

```text
if (!err) {

                console.log("Updated allocations");

                userDAO.getUserById(userId, (err, user) =&gt; {
```

### 修复建议

```text
if (err) return callback(err, null);

            console.log("Updated allocations");

            userDAO.getUserById(userId, (err, user) =&gt; {
```

## 114. \`userId\` 类型不一致会导致 upsert 和查询失效：查询条件使用 \`parsedUserId\`（\`parseInt\` 后为数字），但写入的文档 \`allocations.userId\` 仍是原始字符串 \`userId\`。MongoDB 中数字 \`123\` 与字符串 \`"123"\` 不相等，因此 upsert 永远匹配不到已有文档（每次都插入新文档），而 \`getByUserIdAndTh

- 分类：`bug`
- 风险等级：`高`
- 位置：`app/data/allocations-dao.js:22-27`

\`userId\` 类型不一致会导致 upsert 和查询失效：查询条件使用 \`parsedUserId\`（\`parseInt\` 后为数字），但写入的文档 \`allocations.userId\` 仍是原始字符串 \`userId\`。MongoDB 中数字 \`123\` 与字符串 \`"123"\` 不相等，因此 upsert 永远匹配不到已有文档（每次都插入新文档），而 \`getByUserIdAndThreshold\` 用数字 \`userId\` 查询也查不到这些以字符串 \`userId\` 存储的文档。建议统一存储 \`userId: parsedUserId\`（或全流程统一为字符串）。

### 代码证据

```text
const allocations = {
            userId: userId,
            stocks: stocks,
            funds: funds,
            bonds: bonds
        };
```

### 修复建议

```text
const allocations = {
            userId: parsedUserId,
            stocks: stocks,
            funds: funds,
            bonds: bonds
        };
```

## 115. 此处同样存在选择器缺少右括号的问题，\`input\[name='benefitStartDate'\` 会导致该断言步骤失败，需一并修复为 \`input\[name='benefitStartDate'\]\`。

- 分类：`bug`
- 风险等级：`严重`
- 位置：`test/e2e/integration/benefits\_spec.js:49-52`

此处同样存在选择器缺少右括号的问题，\`input\[name='benefitStartDate'\` 会导致该断言步骤失败，需一并修复为 \`input\[name='benefitStartDate'\]\`。

### 代码证据

```text
cy.get("input[name='benefitStartDate'")
      .first()
      .invoke("val")
      .should("eq", "2099-01-10");
```

### 修复建议

```text
cy.get("input[name='benefitStartDate']")
      .first()
      .invoke("val")
      .should("eq", "2099-01-10");
```

## 116. 存在 XSS 风险：\`this.el.html(e)\` 通过 jQuery 直接注入 HTML，而 \`e\` 来自 \`hoverContentForRow\` 拼装的字符串（包含数据 label 与格式化后的数值），未做任何 HTML 转义。若图表数据 label 来源于用户输入（如用户昵称、搜索词等），攻击者可注入 \`&lt;img onerror=...&gt;\` 等载荷，造成脚本执行。建议对进入 HTML

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/assets/vendor/chart/morris-0.4.3.min.js`

存在 XSS 风险：\`this.el.html(e)\` 通过 jQuery 直接注入 HTML，而 \`e\` 来自 \`hoverContentForRow\` 拼装的字符串（包含数据 label 与格式化后的数值），未做任何 HTML 转义。若图表数据 label 来源于用户输入（如用户昵称、搜索词等），攻击者可注入 \`&lt;img onerror=...&gt;\` 等载荷，造成脚本执行。建议对进入 HTML 的内容做 HTML 实体转义（至少转义 \`&amp; &lt; &gt; " '\`），或在纯文本场景改用 \`.text(e)\`。由于这是 vendor 目录中的第三方压缩文件，建议同时考虑升级/替换为官方修复版本或使用转义包装。

### 代码证据

```text
n.prototype.html=function(e){return this.el.html(e)}
```

## 117. 用户名和口令以明文硬编码在源码中并随仓库提交，属于敏感信息泄露风险。建议改为从环境变量或未纳入版本控制的本地配置文件读取（如 \`process.env.SUT\_USER\_NAME\`），避免将凭据写死在测试代码里。

- 分类：`安全`
- 风险等级：`中`
- 位置：`test/security/profile-test.js:36-37`

用户名和口令以明文硬编码在源码中并随仓库提交，属于敏感信息泄露风险。建议改为从环境变量或未纳入版本控制的本地配置文件读取（如 \`process.env.SUT\_USER\_NAME\`），避免将凭据写死在测试代码里。

### 代码证据

```text
var sutUserName = "user1";
var sutUserPassword = "User1_123";
```

### 修复建议

```text
var sutUserName = process.env.SUT_USER_NAME || "user1";
var sutUserPassword = process.env.SUT_USER_PASSWORD || "User1_123";
```

## 118. 静态资源中间件注册在 \`session\` 之后，导致每次静态资源请求都会经过并可能创建/回写会话（在 \`saveUninitialized: true\` 下更明显），增加不必要开销。建议将 \`express.static\` 移到 \`app.use(session(...))\` 之前注册。

- 分类：`性能`
- 风险等级：`低`
- 位置：`server.js:121`

静态资源中间件注册在 \`session\` 之后，导致每次静态资源请求都会经过并可能创建/回写会话（在 \`saveUninitialized: true\` 下更明显），增加不必要开销。建议将 \`express.static\` 移到 \`app.use(session(...))\` 之前注册。

### 代码证据

```text
app.use(express.static(`${__dirname}/app/assets`));
```

### 修复建议

```text
// 将静态资源中间件移到 session 中间件之前注册
    app.use(express.static(`${__dirname}/app/assets`));
```

## 119. \`\_\`（underscore）被引入但从未使用，属于未使用的变量/死代码，且会增加不必要的依赖加载。建议删除该 require。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`config/config.js:1`

\`\_\`（underscore）被引入但从未使用，属于未使用的变量/死代码，且会增加不必要的依赖加载。建议删除该 require。

### 代码证据

```text
const _ = require("underscore");
```

## 120. \`parseInt\` 未指定进制，建议显式传入 \`10\`；同时建议校验解析结果是否为 NaN，避免非法 userId（如 "abc"）被写入数据库或用于查询。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/data/contributions-dao.js:18`

\`parseInt\` 未指定进制，建议显式传入 \`10\`；同时建议校验解析结果是否为 NaN，避免非法 userId（如 "abc"）被写入数据库或用于查询。

### 代码证据

```text
const parsedUserId = parseInt(userId);
```

### 修复建议

```text
const parsedUserId = parseInt(userId, 10);
```

## 121. \`&lt;pre&gt;\` 是块级元素，不能嵌套在 \`&lt;p&gt;\` 内部；浏览器解析时会在遇到 \`&lt;pre&gt;\` 前自动闭合 \`&lt;p&gt;\`，导致后面的 \`&lt;/p&gt;\` 成为孤立标签，HTML 标记不合法。本页三个示例（x-powered-by、session、helmet）都应将 \`&lt;pre&gt;\` 移到 \`&lt;p&gt;\` 之外。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/views/tutorial/a5.html:88`

\`&lt;pre&gt;\` 是块级元素，不能嵌套在 \`&lt;p&gt;\` 内部；浏览器解析时会在遇到 \`&lt;pre&gt;\` 前自动闭合 \`&lt;p&gt;\`，导致后面的 \`&lt;/p&gt;\` 成为孤立标签，HTML 标记不合法。本页三个示例（x-powered-by、session、helmet）都应将 \`&lt;pre&gt;\` 移到 \`&lt;p&gt;\` 之外。

### 代码证据

```text
&lt;p&gt;The default HTTP header x-powered-by can reveal implementation details to an attacker. It can be taken out by including this code in
```

## 122. 重复代码：\`res.render("profile", { ... })\` 在多个分支中重复出现，且都附带 \`environmentalScripts\`，建议抽取公共渲染函数，避免后续新增字段时出现遗漏或不一致。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/routes/profile.js:65-67`

重复代码：\`res.render("profile", { ... })\` 在多个分支中重复出现，且都附带 \`environmentalScripts\`，建议抽取公共渲染函数，避免后续新增字段时出现遗漏或不一致。

### 代码证据

```text
return res.render("profile", {
                updateError: "Bank Routing number does not comply with requirements for format specified",
                firstNameSafeString,
```

## 123. \`actions/checkout@v2\` 和 \`actions/setup-node@v1\` 均为已弃用版本：checkout v2/v3 已被 v4 取代，setup-node@v1 基于已下线的 Node 12 运行时，在现代 \`ubuntu-latest\` runner 上可能直接失败。建议升级为 \`actions/checkout@v4\` 和 \`actions/setup-node@v4

- 分类：`可维护性`
- 风险等级：`高`
- 位置：`.github/workflows/lint.yml:15-21`

\`actions/checkout@v2\` 和 \`actions/setup-node@v1\` 均为已弃用版本：checkout v2/v3 已被 v4 取代，setup-node@v1 基于已下线的 Node 12 运行时，在现代 \`ubuntu-latest\` runner 上可能直接失败。建议升级为 \`actions/checkout@v4\` 和 \`actions/setup-node@v4\`（如需更严格的供应链安全，可进一步固定到完整 commit SHA）。

### 代码证据

```text
- name: Checkout https://github.com/${{ github.repository }}@${{ github.ref }}
        uses: actions/checkout@v2
        with:
          persist-credentials: false

      - name: Set up Node.js ${{ matrix.node-version }}
        uses: actions/setup-node@v1
```

### 修复建议

```text
- name: Checkout https://github.com/${{ github.repository }}@${{ github.ref }}
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Set up Node.js ${{ matrix.node-version }}
        uses: actions/setup-node@v4
```

## 124. usersCol.update 在 MongoDB Node.js 驱动 2.x 中已废弃（后续版本会移除），且 update 的更新语义不如 updateOne/updateMany 明确。这里按 \_id 更新单个用户，建议改用 updateOne。

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`app/data/benefits-dao.js:24-26`

usersCol.update 在 MongoDB Node.js 驱动 2.x 中已废弃（后续版本会移除），且 update 的更新语义不如 updateOne/updateMany 明确。这里按 \_id 更新单个用户，建议改用 updateOne。

### 代码证据

```text
usersCol.update({
                _id: parseInt(userId)
            }, {
```

### 修复建议

```text
usersCol.updateOne({
                _id: parseInt(userId)
            }, {
```

## 125. 示例代码中的 \`value="{{ csrftoken } }"\` 有两处问题：1) 右括号 \`}}\` 之间多了一个空格，\`{{ csrftoken } }\` 不是合法的模板结束标记，Swig/Nunjucks 会因找不到 \`}}\` 而抛出解析错误，导致整个教程页面渲染失败；2) 即使改成 \`{{ csrftoken }}\`，模板引擎仍会把它当作变量求值（若全局设置了 csrftoken 会输出真

- 分类：`bug`
- 风险等级：`高`
- 位置：`app/views/tutorial/a8.html`

示例代码中的 \`value="{{ csrftoken } }"\` 有两处问题：1) 右括号 \`}}\` 之间多了一个空格，\`{{ csrftoken } }\` 不是合法的模板结束标记，Swig/Nunjucks 会因找不到 \`}}\` 而抛出解析错误，导致整个教程页面渲染失败；2) 即使改成 \`{{ csrftoken }}\`，模板引擎仍会把它当作变量求值（若全局设置了 csrftoken 会输出真实 token，否则输出空字符串），无法在页面上原样展示示例代码。建议使用 \`{% raw %}{{ csrftoken }}{% endraw %}\` 包裹变量语法，并去掉多余空格。

### 代码证据

```text
&amp;lt;input type="hidden" name="_csrf" value="{{ csrftoken } }"&amp;gt;
```

### 修复建议

```text
&amp;lt;input type="hidden" name="_csrf" value="{% raw %}{{ csrftoken }}{% endraw %}"&amp;gt;
```

## 126. \`addStep\` 返回的是 \`this.\_steps.push(step)\`（数组的新长度），\`addSteps\` 则返回长度数组，与该库其他方法（\`init\`/\`start\`/\`setCurrentStep\` 返回 \`this\`）的链式风格不一致。建议返回 \`this\` 以支持链式调用，或明确公开其返回类型。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/assets/vendor/bootstrap-tour.js`

\`addStep\` 返回的是 \`this.\_steps.push(step)\`（数组的新长度），\`addSteps\` 则返回长度数组，与该库其他方法（\`init\`/\`start\`/\`setCurrentStep\` 返回 \`this\`）的链式风格不一致。建议返回 \`this\` 以支持链式调用，或明确公开其返回类型。

### 代码证据

```text
Tour.prototype.addStep = function(step) {
      return this._steps.push(step);
    };
```

### 修复建议

```text
Tour.prototype.addStep = function(step) {
      this._steps.push(step);
      return this;
    };
```

## 127. 配置中明文硬编码了 ZAP 的 API Key（\`v9dn0balpqas1pcc281tn5ood1\`），属于敏感凭据。即使这是开发环境配置，一旦提交到版本库或被他人访问，凭据仍会直接泄露，且该 key 看起来是真实可用的密钥。建议改为从环境变量或密钥管理系统读取，例如 \`process.env.ZAP\_API\_KEY\`，并在文档中说明本地如何配置。

- 分类：`安全`
- 风险等级：`高`
- 位置：`config/env/development.js:6`

配置中明文硬编码了 ZAP 的 API Key（\`v9dn0balpqas1pcc281tn5ood1\`），属于敏感凭据。即使这是开发环境配置，一旦提交到版本库或被他人访问，凭据仍会直接泄露，且该 key 看起来是真实可用的密钥。建议改为从环境变量或密钥管理系统读取，例如 \`process.env.ZAP\_API\_KEY\`，并在文档中说明本地如何配置。

### 代码证据

```text
zapApiKey: "v9dn0balpqas1pcc281tn5ood1",
```

### 修复建议

```text
zapApiKey: process.env.ZAP_API_KEY,
```

## 128. 模板引擎 Swig 已在 server.js 中将 \`autoescape\` 设为 \`false\`，因此 \`{{userName}}\` 会被原样拼入 \`value\` 属性。\`userName\` 直接来自 \`req.body\`（登录失败时被回显），攻击者可提交类似 \`" autofocus onfocus="alert(document.cookie)\` 的值闭合属性并注入脚本，形成反射型 XSS。

- 分类：`安全`
- 风险等级：`严重`
- 位置：`app/views/login.html:110`

模板引擎 Swig 已在 server.js 中将 \`autoescape\` 设为 \`false\`，因此 \`{{userName}}\` 会被原样拼入 \`value\` 属性。\`userName\` 直接来自 \`req.body\`（登录失败时被回显），攻击者可提交类似 \`" autofocus onfocus="alert(document.cookie)\` 的值闭合属性并注入脚本，形成反射型 XSS。建议启用自动转义（\`autoescape: true\`）或至少对属性上下文做 HTML 属性编码（如 \`{{userName | escape}}\`）后再输出。

### 代码证据

```text
&lt;input type="text" class="form-control" id="userName" name="userName" value="{{userName}}" placeholder="Enter User Name"&gt;
```

### 修复建议

```text
&lt;input type="text" class="form-control" id="userName" name="userName" value="{{userName | escape}}" placeholder="Enter User Name"&gt;
```

## 129. 示例代码中变量命名大小写不一致：声明的是 \`SessionHandler\`（首字母大写），但使用时写成了 \`sessionHandler\`（首字母小写）。学习者照此代码运行会得到 \`ReferenceError: sessionHandler is not defined\`，属于文档示例中的正确性错误，可能误导读者。建议统一改为 \`var sessionHandler = require("./s

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/views/tutorial/a7.html:85-87`

示例代码中变量命名大小写不一致：声明的是 \`SessionHandler\`（首字母大写），但使用时写成了 \`sessionHandler\`（首字母小写）。学习者照此代码运行会得到 \`ReferenceError: sessionHandler is not defined\`，属于文档示例中的正确性错误，可能误导读者。建议统一改为 \`var sessionHandler = require("./session");\`，并保持使用 \`sessionHandler.isAdminUserMiddleware\`。

### 代码证据

```text
var SessionHandler = require("./session");
//Middleware to check if user has admin rights
var isAdmin = sessionHandler.isAdminUserMiddleware;
```

### 修复建议

```text
var sessionHandler = require("./session");
//Middleware to check if user has admin rights
var isAdmin = sessionHandler.isAdminUserMiddleware;
```

## 130. \`/logout\`、\`/dashboard\`、\`login\` 等 URL 路径和关键字被直接硬编码在多个用例中，路由调整时需要多处同步修改，容易遗漏。建议集中定义路由常量（如 \`const ROUTES = { logout: '/logout', dashboard: '/dashboard', login: '/login' }\`）统一复用。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/e2e/integration/logout\_spec.js:16-19`

\`/logout\`、\`/dashboard\`、\`login\` 等 URL 路径和关键字被直接硬编码在多个用例中，路由调整时需要多处同步修改，容易遗漏。建议集中定义路由常量（如 \`const ROUTES = { logout: '/logout', dashboard: '/dashboard', login: '/login' }\`）统一复用。

### 代码证据

```text
cy.adminSignIn();
    cy.visitPage("/logout");
    cy.url().should("include", "login");
    cy.visitPage("/dashboard");
```

## 131. \`res.render("contributions", { ... })\` 在三个分支重复出现（成功、非法比例、超过上限），仅传入的额外字段不同。可提取一个局部渲染函数（如 \`renderContributions(res, data)\`）复用，减少重复代码。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/routes/contributions.js:50-54`

\`res.render("contributions", { ... })\` 在三个分支重复出现（成功、非法比例、超过上限），仅传入的额外字段不同。可提取一个局部渲染函数（如 \`renderContributions(res, data)\`）复用，减少重复代码。

### 代码证据

```text
return res.render("contributions", {
                updateError: "Invalid contribution percentages",
                userId,
                environmentalScripts
            });
```

## 132. tour 文案仍为占位符（"Contents here"、"Title of my popover1"、"Content of my popover1"、"Title of my popover lo "、"Content of my popover oi"），且存在多余空格与不完整文本（如 "lo "、"oi"），正式功能上线前应替换为真实文案，避免把演示文本展示给用户。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/assets/js/tour/redirects-steps.js:13-14`

tour 文案仍为占位符（"Contents here"、"Title of my popover1"、"Content of my popover1"、"Title of my popover lo "、"Content of my popover oi"），且存在多余空格与不完整文本（如 "lo "、"oi"），正式功能上线前应替换为真实文案，避免把演示文本展示给用户。

### 代码证据

```text
title: "Title of my popover1",
    content: "Content of my popover1"
```

## 133. 该 \`&lt;li&gt;\`（Limit HTTP Request Body size）在开启下一个 \`&lt;li&gt;\` 之前未闭合 \`&lt;/li&gt;\`，导致后续列表项在源码层面被嵌套进本项，形成不合法的 HTML 结构。请在 \`multipart middleware.\` 之后补上 \`&lt;/li&gt;\`，再开始 \`If using multipart middleware...\` 这一项。

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`app/views/tutorial/a5.html:64-65`

该 \`&lt;li&gt;\`（Limit HTTP Request Body size）在开启下一个 \`&lt;li&gt;\` 之前未闭合 \`&lt;/li&gt;\`，导致后续列表项在源码层面被嵌套进本项，形成不合法的 HTML 结构。请在 \`multipart middleware.\` 之后补上 \`&lt;/li&gt;\`，再开始 \`If using multipart middleware...\` 这一项。

### 代码证据

```text
&lt;code&gt;limit&lt;/code&gt;middleware. Include only required middleware. For example if application doesn't need to support file uploads, do not include multipart middleware.
                        &lt;li&gt;
```

### 修复建议

```text
&lt;code&gt;limit&lt;/code&gt;middleware. Include only required middleware. For example if application doesn't need to support file uploads, do not include multipart middleware.
                    &lt;/li&gt;
                    &lt;li&gt;
```

## 134. 该注释内容有误：此处创建的是 memo 文档，\`allocations\` 疑似从其他 DAO 复制粘贴遗留，容易误导后续维护者。建议改为 \`// Create memo document\`。

- 分类：`documentation`
- 风险等级：`低`
- 位置：`app/data/memos-dao.js:17`

该注释内容有误：此处创建的是 memo 文档，\`allocations\` 疑似从其他 DAO 复制粘贴遗留，容易误导后续维护者。建议改为 \`// Create memo document\`。

### 代码证据

```text
// Create allocations document
```

### 修复建议

```text
// Create memo document
```

## 135. 按项目规则应禁止使用 \`!=\`/\`==\`，使用严格相等。注意 \`x != null\` 同时匹配 \`null\` 与 \`undefined\`，改为严格相等时需要显式覆盖两种情况（如 \`!== null &amp;&amp; !== undefined\`），避免遗漏 \`undefined\`。

- 分类：`代码风格`
- 风险等级：`低`
- 位置：`app/assets/vendor/bootstrap-tour.js`

按项目规则应禁止使用 \`!=\`/\`==\`，使用严格相等。注意 \`x != null\` 同时匹配 \`null\` 与 \`undefined\`，改为严格相等时需要显式覆盖两种情况（如 \`!== null &amp;&amp; !== undefined\`），避免遗漏 \`undefined\`。

### 代码证据

```text
if (this._steps[i] != null) {
```

### 修复建议

```text
if (this._steps[i] !== null &amp;&amp; this._steps[i] !== undefined) {
```

## 136. 该用例名为 "Should first name be modified"，但真正验证 \`firstName\` 被修改的断言被整体注释掉了，当前只校验了成功提示，无法证明字段值确实已更新，用例名与验证内容不符。建议修复 CI 问题后重新启用断言，或删除这段注释代码以免误导。

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`test/e2e/integration/profile\_spec.js:54-59`

该用例名为 "Should first name be modified"，但真正验证 \`firstName\` 被修改的断言被整体注释掉了，当前只校验了成功提示，无法证明字段值确实已更新，用例名与验证内容不符。建议修复 CI 问题后重新启用断言，或删除这段注释代码以免误导。

### 代码证据

```text
// @TODO: Just commented for CI, this MUST be improved
    /*
    cy.get("#firstName")
      .invoke("val")
      .should("eq", newName);
    */
```

### 修复建议

```text
cy.get("#firstName")
      .invoke("val")
      .should("eq", newName);
```

## 137. 静态资源使用相对路径 \`../vendor/...\`，当页面以带尾斜杠的 URL（如 \`/tutorial/a1/\`）访问时，会解析成 \`/tutorial/vendor/...\` 导致资源 404。建议改为以 \`/\` 开头的绝对路径（如 \`/vendor/bootstrap/bootstrap.css\`），与导航栏中的绝对链接保持一致。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/views/tutorial/layout.html:13`

静态资源使用相对路径 \`../vendor/...\`，当页面以带尾斜杠的 URL（如 \`/tutorial/a1/\`）访问时，会解析成 \`/tutorial/vendor/...\` 导致资源 404。建议改为以 \`/\` 开头的绝对路径（如 \`/vendor/bootstrap/bootstrap.css\`），与导航栏中的绝对链接保持一致。

### 代码证据

```text
&lt;link href="../vendor/bootstrap/bootstrap.css" rel="stylesheet"&gt;
```

## 138. \`insure\` 拼写错误，此处应为 \`insecure\`（“不安全的演示应用”），否则与上下文含义不符。

- 分类：`documentation`
- 风险等级：`低`
- 位置：`app/views/tutorial/a4.html:31`

\`insure\` 拼写错误，此处应为 \`insecure\`（“不安全的演示应用”），否则与上下文含义不符。

### 代码证据

```text
For example, the insure demo application uses userid as part of the url to access the allocations (/allocations/{id}). An attacker can manipulate id value and access other user's allocation information.
```

## 139. 文件中保留了大段被注释掉的代码（createIV/encrypt/decrypt 辅助函数以及 A6/A7 修复逻辑），属于 dead code，影响可读性与维护；其中注释里的 'encryt' 还存在拼写错误。建议明确取舍：要么删除这些注释块，要么取消注释并恢复加密逻辑。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/data/profile-dao.js:15-17`

文件中保留了大段被注释掉的代码（createIV/encrypt/decrypt 辅助函数以及 A6/A7 修复逻辑），属于 dead code，影响可读性与维护；其中注释里的 'encryt' 还存在拼写错误。建议明确取舍：要么删除这些注释块，要么取消注释并恢复加密逻辑。

### 代码证据

```text
/* Fix for A6 - Sensitive Data Exposure

    // Use crypto module to save sensitive data such as ssn, dob in encrypted format
```

## 140. 面板数量 \`5\` 属于业务相关的硬编码数字，当面板结构变化时该断言会静默失效且不易体现意图，建议提取为有语义的常量（如 \`EXPECTED\_PANEL\_COUNT\`）。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/e2e/integration/dashboard\_spec.js:25-27`

面板数量 \`5\` 属于业务相关的硬编码数字，当面板结构变化时该断言会静默失效且不易体现意图，建议提取为有语义的常量（如 \`EXPECTED\_PANEL\_COUNT\`）。

### 代码证据

```text
cy.get(".panel")
      .should("be.visible")
      .should("have.length", 5);
```

### 修复建议

```text
cy.get(".panel")
      .should("be.visible")
      .should("have.length", EXPECTED_PANEL_COUNT);
```

## 141. 数据 API 点击处理中 \`b.preventDefault()\` 被放在 \`||\` 表达式中作为副作用执行：当元素带有 \`data-target\` 属性时表达式短路，\`preventDefault()\` 根本不会执行，\`&lt;a&gt;\` 标签的默认跳转仍会发生（页面滚动/URL hash 被修改），导致折叠面板切换异常。应无条件先调用 \`b.preventDefault()\`，再解析目标选择器。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/assets/vendor/bootstrap/bootstrap.js`

数据 API 点击处理中 \`b.preventDefault()\` 被放在 \`||\` 表达式中作为副作用执行：当元素带有 \`data-target\` 属性时表达式短路，\`preventDefault()\` 根本不会执行，\`&lt;a&gt;\` 标签的默认跳转仍会发生（页面滚动/URL hash 被修改），导致折叠面板切换异常。应无条件先调用 \`b.preventDefault()\`，再解析目标选择器。

### 代码证据

```text
e=c.attr("data-target")||b.preventDefault()||(d=c.attr("href"))&amp;&amp;d.replace(/.*(?=#[^\s]+$)/,"")
```

### 修复建议

```text
b.preventDefault();var c=a(this),d,e=c.attr("data-target")||(d=c.attr("href"))&amp;&amp;d.replace(/.*(?=#[^\s]+$)/,"")
```

## 142. 用例名 "Google search this profile by name" 与实际断言不符：当前只验证了表单内链接可见且存在 \`href\` 属性，并未校验链接是否指向 Google 搜索。建议补充对 \`href\` 值的断言，或调整用例名称以反映实际验证内容。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/e2e/integration/profile\_spec.js:62`

用例名 "Google search this profile by name" 与实际断言不符：当前只验证了表单内链接可见且存在 \`href\` 属性，并未校验链接是否指向 Google 搜索。建议补充对 \`href\` 值的断言，或调整用例名称以反映实际验证内容。

### 代码证据

```text
it("Google search this profile by name", () =&gt; {
```

## 143. 根路由 '/' 的渲染逻辑与下方 for 循环中的渲染逻辑完全重复，且模板名 'a1' 被硬编码（该名称已存在于 pages 数组中）。若后续调整首页教程名称，容易漏改根路由，导致 '/' 与 '/a1' 渲染结果不一致。建议抽取公共渲染函数复用，并从数据源（如 pages\[0\]）获取首页模板名，避免重复代码和硬编码。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/routes/tutorial.js:8-13`

根路由 '/' 的渲染逻辑与下方 for 循环中的渲染逻辑完全重复，且模板名 'a1' 被硬编码（该名称已存在于 pages 数组中）。若后续调整首页教程名称，容易漏改根路由，导致 '/' 与 '/a1' 渲染结果不一致。建议抽取公共渲染函数复用，并从数据源（如 pages\[0\]）获取首页模板名，避免重复代码和硬编码。

### 代码证据

```text
router.get("/", (req, res) =&gt; {
    "use strict";
    return res.render("tutorial/a1", {
        environmentalScripts
    });
});
```

### 修复建议

```text
const renderPage = (page) =&gt; (req, res) =&gt;
    res.render(`tutorial/${page}`, { environmentalScripts });

router.get("/", renderPage(pages[0]));

for (const page of pages) {
    router.get(`/${page}`, renderPage(page));
}
```

## 144. 存在 XSS 风险：Bar 图的 \`hoverContentForRow\` 同样将 \`r.label\` 直接拼入 HTML 字符串，并最终经 \`Hover.html\` 的 \`.html()\` 渲染，未做转义。若柱状图 label 来自用户输入，可触发脚本注入。建议与 Line 图保持一致，统一对 label 与格式化输出做 HTML 转义后再拼接。

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/assets/vendor/chart/morris-0.4.3.min.js`

存在 XSS 风险：Bar 图的 \`hoverContentForRow\` 同样将 \`r.label\` 直接拼入 HTML 字符串，并最终经 \`Hover.html\` 的 \`.html()\` 渲染，未做转义。若柱状图 label 来自用户输入，可触发脚本注入。建议与 Line 图保持一致，统一对 label 与格式化输出做 HTML 转义后再拼接。

### 代码证据

```text
r.prototype.hoverContentForRow=function(e){var t,n,r,i,s,o,u,a;r=this.data[e],t="&lt;div class='morris-hover-row-label'&gt;"+r.label+"&lt;/div&gt;",a=r.y;
```

## 145. 回调参数 db 与文件顶部从 config/config 解构出的 db（连接串）同名，回调内部使用被遮蔽后的参数，可读性差且易在后续维护中误用连接串。建议将回调参数重命名（如 database），避免变量遮蔽。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`artifacts/db-reset.js:63`

回调参数 db 与文件顶部从 config/config 解构出的 db（连接串）同名，回调内部使用被遮蔽后的参数，可读性差且易在后续维护中误用连接串。建议将回调参数重命名（如 database），避免变量遮蔽。

### 代码证据

```text
MongoClient.connect(db, (err, db) =&gt;  {
```

### 修复建议

```text
MongoClient.connect(db, (err, database) =&gt;  {
```

## 146. form 标签中重复声明了 \`method="post"\`，属于无效的重复属性；浏览器虽然会采用第一个值，但会让意图不清且不符合 HTML 规范，应删除其中一个。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/views/login.html:107`

form 标签中重复声明了 \`method="post"\`，属于无效的重复属性；浏览器虽然会采用第一个值，但会让意图不清且不符合 HTML 规范，应删除其中一个。

### 代码证据

```text
&lt;form method="post" role="form" method="post" id="loginform"&gt;
```

### 修复建议

```text
&lt;form method="post" role="form" id="loginform"&gt;
```

## 147. 测试用例名称中的 "accesible" 存在拼写错误，应为 "accessible"，会影响测试报告的可读性，建议修正。

- 分类：`documentation`
- 风险等级：`低`
- 位置：`test/e2e/integration/dashboard\_spec.js:15`

测试用例名称中的 "accesible" 存在拼写错误，应为 "accessible"，会影响测试报告的可读性，建议修正。

### 代码证据

```text
it("Should be accesible for a logged user", () =&gt; {
```

### 修复建议

```text
it("Should be accessible for a logged user", () =&gt; {
```

## 148. \`oneYearAgo + "-11-31"\` 会拼出类似 \`2025-11-31\` 的日期，但 11 月没有 31 日。Morris 通过 \`Date.parse\` 解析 x 轴日期，无效日期会得到 \`NaN\`，导致最后一个数据点无法正确渲染或位置异常。建议改为有效日期（如 \`"-11-30"\`），并统一使用零填充的 \`YYYY-MM-DD\` 格式以避免不同浏览器的解析差异。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/assets/js/chart/chart-data-morris.js:106`

\`oneYearAgo + "-11-31"\` 会拼出类似 \`2025-11-31\` 的日期，但 11 月没有 31 日。Morris 通过 \`Date.parse\` 解析 x 轴日期，无效日期会得到 \`NaN\`，导致最后一个数据点无法正确渲染或位置异常。建议改为有效日期（如 \`"-11-30"\`），并统一使用零填充的 \`YYYY-MM-DD\` 格式以避免不同浏览器的解析差异。

### 代码证据

```text
d: oneYearAgo + "-11-31",
```

### 修复建议

```text
d: oneYearAgo + "-11-30",
```

## 149. .progress.active .progress-bar 使用了 -ms-animation 引用 progress-bar-stripes，但文件中只定义了 @-webkit-keyframes、@-moz-keyframes、@-o-keyframes 和无前缀 @keyframes，缺少 @-ms-keyframes。在仍需要前缀的旧版 IE 中进度条条纹动画将不会生效。建议补充 @-m

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/assets/vendor/bootstrap/bootstrap.css:4329`

.progress.active .progress-bar 使用了 -ms-animation 引用 progress-bar-stripes，但文件中只定义了 @-webkit-keyframes、@-moz-keyframes、@-o-keyframes 和无前缀 @keyframes，缺少 @-ms-keyframes。在仍需要前缀的旧版 IE 中进度条条纹动画将不会生效。建议补充 @-ms-keyframes progress-bar-stripes，并使其 from/to 方向与标准 @keyframes 保持一致（40px 0 → 0 0）。

### 代码证据

```text
-ms-animation: progress-bar-stripes 2s linear infinite;
```

## 150. 验证密码字段同样回显 {{verify}}，与 password 字段存在相同的敏感信息泄露风险，建议移除 value 属性。

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/views/signup.html:96`

验证密码字段同样回显 {{verify}}，与 password 字段存在相同的敏感信息泄露风险，建议移除 value 属性。

### 代码证据

```text
&lt;input type="password" class="form-control" id="verify" name="verify" value="{{verify}}" placeholder="Enter password"&gt;
```

### 修复建议

```text
&lt;input type="password" class="form-control" id="verify" name="verify" placeholder="Enter password"&gt;
```

## 151. \`parseInt(userId)\` 未对 \`userId\` 做存在性校验：当 \`req.session.userId\` 缺失或为 \`undefined\` 时，结果为 \`NaN\`，可能导致查询行为异常。建议先校验 session 中的 \`userId\` 是否存在。

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/routes/profile.js:20`

\`parseInt(userId)\` 未对 \`userId\` 做存在性校验：当 \`req.session.userId\` 缺失或为 \`undefined\` 时，结果为 \`NaN\`，可能导致查询行为异常。建议先校验 session 中的 \`userId\` 是否存在。

### 代码证据

```text
profile.getByUserId(parseInt(userId), (err, doc) =&gt; {
```

## 152. 文件中保留了多个大段被注释的安全加固代码（helmet、CSRF、HTTPS、cookie 配置等）。虽有“修复方案”注释意图，但长期保留大块注释代码会降低可维护性，且容易让人误以为防护已生效。建议删除，或将修复方案迁移到文档/独立配置开关中。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`server.js:38-40`

文件中保留了多个大段被注释的安全加固代码（helmet、CSRF、HTTPS、cookie 配置等）。虽有“修复方案”注释意图，但长期保留大块注释代码会降低可维护性，且容易让人误以为防护已生效。建议删除，或将修复方案迁移到文档/独立配置开关中。

### 代码证据

```text
/*
    // Fix for A5 - Security MisConfig
    // TODO: Review the rest of helmet options, like "xssFilter"
```

## 153. 第一个 \`&lt;p&gt;\` 未闭合，紧接着又开启新的 \`&lt;p&gt;\`，且下方该段内容没有对应的 \`&lt;/p&gt;\`。建议为每个段落补全结束标签，避免非法嵌套。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/views/tutorial/a2.html:173`

第一个 \`&lt;p&gt;\` 未闭合，紧接着又开启新的 \`&lt;p&gt;\`，且下方该段内容没有对应的 \`&lt;/p&gt;\`。建议为每个段落补全结束标签，避免非法嵌套。

### 代码证据

```text
&lt;p&gt;The insecure demo application does not regenerate a new session id upon user's login, therefore rendering a vulnerability of session hijacking if an attacker is able to somehow steal the cookie with the session id and use it.
```

### 修复建议

```text
&lt;p&gt;The insecure demo application does not regenerate a new session id upon user's login, therefore rendering a vulnerability of session hijacking if an attacker is able to somehow steal the cookie with the session id and use it.&lt;/p&gt;
```

## 154. \`\_scrollIntoView\` 依赖 \`$("body,html")\` 两个元素的动画回调恰好各触发一次（\`++counter === 2\`）才执行 \`callback\`。若其中任一动画被中断、被 \`stop(true, true)\` 取消，或某个环境下只有单个元素真正完成动画，回调可能永远不触发，导致后续 \`\_showPopover\` 不执行、引导流程卡死。建议改为单一目标元素动画，或使用更

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/assets/vendor/bootstrap-tour.js`

\`\_scrollIntoView\` 依赖 \`$("body,html")\` 两个元素的动画回调恰好各触发一次（\`++counter === 2\`）才执行 \`callback\`。若其中任一动画被中断、被 \`stop(true, true)\` 取消，或某个环境下只有单个元素真正完成动画，回调可能永远不触发，导致后续 \`\_showPopover\` 不执行、引导流程卡死。建议改为单一目标元素动画，或使用更可靠的完成判定（例如仅监听一个确定的滚动容器，或用超时兜底）。

### 代码证据

```text
return $("body,html").stop(true, true).animate({
        scrollTop: Math.ceil(scrollTop)
      }, function() {
        if (++counter === 2) {
          callback();
          return _this._debug("Scroll into view. Animation end element offset: " + ($element.offset().top) + ". Window height: " + ($window.height()) + ".");
        }
      });
```

## 155. 阈值输入框使用 \`type="text"\` 且没有任何 \`min\`/\`max\` 校验，而上方的注释明确说明此处本应改为 \`type="number" min="0" max="99"\` 来修复 NoSQL 注入问题（该修复被注释掉/回退了）。前端校验只是 UX 层面的防护，攻击者仍可绕过浏览器直接向 \`/allocations/{{userId}}?threshold=...\` 提交任意字符串（如

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/views/allocations.html:22`

阈值输入框使用 \`type="text"\` 且没有任何 \`min\`/\`max\` 校验，而上方的注释明确说明此处本应改为 \`type="number" min="0" max="99"\` 来修复 NoSQL 注入问题（该修复被注释掉/回退了）。前端校验只是 UX 层面的防护，攻击者仍可绕过浏览器直接向 \`/allocations/{{userId}}?threshold=...\` 提交任意字符串（如 \`$gt\`、\`$ne\` 等 NoSQL 操作符），如果服务端未做类型/范围校验，仍存在 NoSQL 注入风险。建议：1) 恢复 number 输入并设置 \`min="0" max="99"\` 以改善体验；2) 更重要的是必须在服务端（allocations-dao.js）对 threshold 做白名单校验，仅允许 0-99 的纯数字，否则前端修改无法真正阻止注入。

### 代码证据

```text
&lt;input type="text" class="form-control" placeholder="Stocks Threshold" name="threshold" /&gt;
```

### 修复建议

```text
&lt;input type="number" min="0" max="99" class="form-control" placeholder="Stocks Threshold" name="threshold" /&gt;
```

## 156. 工作流未声明 \`permissions\`，GitHub 会为 GITHUB\_TOKEN 授予默认的广泛权限（对 push 事件默认包含 \`contents: write\`）。本流程实际上仅需检出代码和上传产物，建议按最小权限声明，例如 \`permissions: contents: read\`，以降低令牌泄露后的影响面。

- 分类：`安全`
- 风险等级：`中`
- 位置：`.github/workflows/e2e-test.yml:7`

工作流未声明 \`permissions\`，GitHub 会为 GITHUB\_TOKEN 授予默认的广泛权限（对 push 事件默认包含 \`contents: write\`）。本流程实际上仅需检出代码和上传产物，建议按最小权限声明，例如 \`permissions: contents: read\`，以降低令牌泄露后的影响面。

### 代码证据

```text
runs-on: ubuntu-latest
```

### 修复建议

```text
runs-on: ubuntu-latest
    permissions:
      contents: read
```

## 157. \`validateLogin\` 使用明文字符串相等来比较密码，且参数命名 \`fromDB/fromUser\` 与调用处 \`comparePassword(password, user.password)\` 相反，容易误导。应改用 bcrypt 对数据库中的哈希进行校验（\`bcrypt.compareSync(用户输入, 数据库哈希)\`）。

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/data/user-dao.js:60-61`

\`validateLogin\` 使用明文字符串相等来比较密码，且参数命名 \`fromDB/fromUser\` 与调用处 \`comparePassword(password, user.password)\` 相反，容易误导。应改用 bcrypt 对数据库中的哈希进行校验（\`bcrypt.compareSync(用户输入, 数据库哈希)\`）。

### 代码证据

```text
const comparePassword = (fromDB, fromUser) =&gt; {
            return fromDB === fromUser;
```

### 修复建议

```text
const comparePassword = (fromUser, fromDB) =&gt; {
            return bcrypt.compareSync(fromUser, fromDB);
        };
```

## 158. \`const href =\` 与其赋值表达式被拆成两行，且缩进不一致，可读性差。建议合并为单行：\`const href = $a.prop("href");\`。

- 分类：`代码风格`
- 风险等级：`低`
- 位置：`test/e2e/integration/login\_spec.js:26-27`

\`const href =\` 与其赋值表达式被拆成两行，且缩进不一致，可读性差。建议合并为单行：\`const href = $a.prop("href");\`。

### 代码证据

```text
const href =
      $a.prop("href");
```

### 修复建议

```text
const href = $a.prop("href");
```

## 159. 密码输入框不应通过服务端模板回填 \`value="{{password}}"\`。密码属于敏感信息，回显后会出现在页面源码、浏览器缓存及 DOM 中，增加泄露风险；在 \`autoescape: false\` 的情况下，若密码内容被回填还可能引入 XSS。建议移除 \`value\` 属性，登录失败时保持密码框为空。

- 分类：`安全`
- 风险等级：`中`
- 位置：`app/views/login.html:115`

密码输入框不应通过服务端模板回填 \`value="{{password}}"\`。密码属于敏感信息，回显后会出现在页面源码、浏览器缓存及 DOM 中，增加泄露风险；在 \`autoescape: false\` 的情况下，若密码内容被回填还可能引入 XSS。建议移除 \`value\` 属性，登录失败时保持密码框为空。

### 代码证据

```text
&lt;input type="password" class="form-control" id="password" name="password" value="{{password}}" placeholder="Enter Password"&gt;
```

## 160. \`\_isLast\` 的命名与实现语义相反：它返回的是 \`this.\_current &lt; this.\_steps.length - 1\`，即“是否还有下一步”，而不是“是否为最后一步”。当前 \`resume\`、\`\_showPopover\`、键盘导航等调用处都依赖这个反直觉的返回值（为 true 时执行 next，为 false 时执行 end），后续维护极易误用。建议重命名为 \`\_hasNext\`，

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`app/assets/vendor/bootstrap-tour.js`

\`\_isLast\` 的命名与实现语义相反：它返回的是 \`this.\_current &lt; this.\_steps.length - 1\`，即“是否还有下一步”，而不是“是否为最后一步”。当前 \`resume\`、\`\_showPopover\`、键盘导航等调用处都依赖这个反直觉的返回值（为 true 时执行 next，为 false 时执行 end），后续维护极易误用。建议重命名为 \`\_hasNext\`，或将返回值改为 \`this.\_current === this.\_steps.length - 1\` 并同步修正所有调用处。

### 代码证据

```text
Tour.prototype._isLast = function() {
      return this._current &lt; this._steps.length - 1;
    };
```

## 161. \`&lt;pre&gt;\` 元素不能嵌套在 \`&lt;p&gt;\` 元素内：\`&lt;p&gt;\` 只能包含 phrasing content，浏览器解析到 \`&lt;pre&gt;\` 时会自动隐式闭合前面的 \`&lt;p&gt;\`，使后面的 \`&lt;/p&gt;\` 成为孤立结束标签，可能导致页面布局异常。建议将 \`&lt;pre&gt;\` 移到 \`&lt;p&gt;\` 之外或改用 \`&lt;div&gt;\` 包裹。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/views/tutorial/a4.html:59-62`

\`&lt;pre&gt;\` 元素不能嵌套在 \`&lt;p&gt;\` 元素内：\`&lt;p&gt;\` 只能包含 phrasing content，浏览器解析到 \`&lt;pre&gt;\` 时会自动隐式闭合前面的 \`&lt;p&gt;\`，使后面的 \`&lt;/p&gt;\` 成为孤立结束标签，可能导致页面布局异常。建议将 \`&lt;pre&gt;\` 移到 \`&lt;p&gt;\` 之外或改用 \`&lt;div&gt;\` 包裹。

### 代码证据

```text
&lt;p&gt;
                    In
                    &lt;code&gt;routes/allocations.js&lt;/code&gt;, the insecure application takes user id from url to fetch the allocations.
                    &lt;pre&gt;
```

### 修复建议

```text
&lt;p&gt;
                    In
                    &lt;code&gt;routes/allocations.js&lt;/code&gt;, the insecure application takes user id from url to fetch the allocations.
                &lt;/p&gt;
                &lt;pre&gt;
```

## 162. getBySymbol 方法接收了 callback 参数但从未调用，也没有使用传入的 db 执行任何数据库查询；内部定义的 searchCriteria 函数只声明不调用，导致该方法实际上是一个空操作。调用方传入的回调永远不会被触发（若外层将回调包装成 Promise 则会永久 pending）。应根据 symbol 构造查询条件、调用 db 执行查询，并在查询完成后（含错误分支）调用 call

- 分类：`bug`
- 风险等级：`严重`
- 位置：`app/data/research-dao.js:13-24`

getBySymbol 方法接收了 callback 参数但从未调用，也没有使用传入的 db 执行任何数据库查询；内部定义的 searchCriteria 函数只声明不调用，导致该方法实际上是一个空操作。调用方传入的回调永远不会被触发（若外层将回调包装成 Promise 则会永久 pending）。应根据 symbol 构造查询条件、调用 db 执行查询，并在查询完成后（含错误分支）调用 callback。

### 代码证据

```text
this.getBySymbol = (symbol, callback) =&gt; {

        const searchCriteria = () =&gt; {

            if (symbol) {
                console.log("in if symbol");
                return {
                    symbol
                };
            }
        };
    };
```

## 163. \`should("have.length", 9)\` 硬编码了输入框数量 9，属于脆弱的魔法数字，表单字段增减时该用例会静默失败且难以定位原因。建议改为对具体字段（如 \`\#firstName\`、\`\#bankRouting\`）做存在性断言，或将数量提取为具名常量。

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`test/e2e/integration/profile\_spec.js:29-30`

\`should("have.length", 9)\` 硬编码了输入框数量 9，属于脆弱的魔法数字，表单字段增减时该用例会静默失败且难以定位原因。建议改为对具体字段（如 \`\#firstName\`、\`\#bankRouting\`）做存在性断言，或将数量提取为具名常量。

### 代码证据

```text
.find("input")
      .should("have.length", 9);
```

## 164. update 的查询过滤器使用了原始字符串 \`userId\`，而写入文档 \`contributions.userId\` 是 \`parseInt\` 之后的数字。MongoDB 中字符串 "123" 与数字 123 属于不同类型，后续调用无法匹配到已插入的文档，\`upsert: true\` 会导致每次调用都重复插入新记录；同时方法末尾又把 \`contributions.userId = userId\`

- 分类：`bug`
- 风险等级：`高`
- 位置：`app/data/contributions-dao.js:28-30`

update 的查询过滤器使用了原始字符串 \`userId\`，而写入文档 \`contributions.userId\` 是 \`parseInt\` 之后的数字。MongoDB 中字符串 "123" 与数字 123 属于不同类型，后续调用无法匹配到已插入的文档，\`upsert: true\` 会导致每次调用都重复插入新记录；同时方法末尾又把 \`contributions.userId = userId\` 改回字符串，类型不一致。建议过滤器统一使用 \`parsedUserId\`。另外 \`update\` 在 MongoDB Node 驱动中已废弃，可考虑改用 \`updateOne\` 并配合 \`$set\`。

### 代码证据

```text
contributionsDB.update({
            userId
            },
```

### 修复建议

```text
contributionsDB.update({
            userId: parsedUserId
            },
```

## 165. 解密依赖全局可变状态 \`config.iv\`：多用户数据先后加密时 \`config.iv\` 会被最后一条记录覆盖，服务重启后又变为空字符串，历史密文将无法解密或用错误 IV 解密。应把 IV 作为密文的一部分存储并在解密时解析。此外 CBC 模式未配合 HMAC（或直接使用 GCM）时无法检测密文篡改。

- 分类：`bug`
- 风险等级：`高`
- 位置：`app/views/tutorial/a6.html:103-106`

解密依赖全局可变状态 \`config.iv\`：多用户数据先后加密时 \`config.iv\` 会被最后一条记录覆盖，服务重启后又变为空字符串，历史密文将无法解密或用错误 IV 解密。应把 IV 作为密文的一部分存储并在解密时解析。此外 CBC 模式未配合 HMAC（或直接使用 GCM）时无法检测密文篡改。

### 代码证据

```text
var decrypt = function(toDecrypt) {
    var decipher = crypto.createDecipheriv(config.cryptoAlgo, config.cryptoKey, config.iv);
    return decipher.update(toDecrypt, "hex", "utf8") + decipher.final("utf8");
};
```

## 166. \`parseInt(userId)\` 未指定进制且未做有效性校验：非数字输入会得到 \`NaN\`，从而用 \`\_id: NaN\` 查询数据库；形如 \`"12abc"\` 的输入还会被静默解析为 \`12\`。建议指定 \`parseInt(userId, 10)\`，并在 \`Number.isNaN\` 时直接回调错误。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/data/user-dao.js:98-100`

\`parseInt(userId)\` 未指定进制且未做有效性校验：非数字输入会得到 \`NaN\`，从而用 \`\_id: NaN\` 查询数据库；形如 \`"12abc"\` 的输入还会被静默解析为 \`12\`。建议指定 \`parseInt(userId, 10)\`，并在 \`Number.isNaN\` 时直接回调错误。

### 代码证据

```text
usersCol.findOne({
            _id: parseInt(userId)
        }, callback);
```

### 修复建议

```text
const id = parseInt(userId, 10);
        if (Number.isNaN(id)) {
            return callback(new Error("Invalid user id"), null);
        }
        usersCol.findOne({
            _id: id
        }, callback);
```

## 167. \`.DS\_Store?\` 中的 \`?\` 是单字符通配符，无法匹配 \`.DS\_Store\` 本身（它已被上一行忽略），只会额外忽略如 \`.DS\_Store1\` 这类文件。该规则基本无效且容易误导，如无特殊用途建议删除，仅保留上一行的 \`.DS\_Store\`。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`.gitignore:9-10`

\`.DS\_Store?\` 中的 \`?\` 是单字符通配符，无法匹配 \`.DS\_Store\` 本身（它已被上一行忽略），只会额外忽略如 \`.DS\_Store1\` 这类文件。该规则基本无效且容易误导，如无特殊用途建议删除，仅保留上一行的 \`.DS\_Store\`。

### 代码证据

```text
.DS_Store
.DS_Store?
```

### 修复建议

```text
.DS_Store
```

## 168. 直接解构 \`req.session\` 未做空值检查：若 session 中间件未生效或 \`req.session\` 为 null，会抛出 TypeError。并且 \`displayMemos\` 在 \`addMemos\` 的数据库回调中被调用，此时抛出的异常发生在异步回调里，Express 无法捕获，可能导致进程级未处理异常。建议改为 \`const userId = req.session &amp;&amp; r

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/routes/memos.js:21-23`

直接解构 \`req.session\` 未做空值检查：若 session 中间件未生效或 \`req.session\` 为 null，会抛出 TypeError。并且 \`displayMemos\` 在 \`addMemos\` 的数据库回调中被调用，此时抛出的异常发生在异步回调里，Express 无法捕获，可能导致进程级未处理异常。建议改为 \`const userId = req.session &amp;&amp; req.session.userId;\`。

### 代码证据

```text
const {
            userId
        } = req.session;
```

### 修复建议

```text
const userId = req.session &amp;&amp; req.session.userId;
```

## 169. 回调参数 \`db\` 遮蔽了外层从 config 解构的 \`db\` 配置变量，可读性差且后续维护时容易误用（例如误以为仍在操作连接串）。建议将回调参数重命名为 \`database\` 或 \`client\`（视驱动版本而定）。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`server.js:30`

回调参数 \`db\` 遮蔽了外层从 config 解构的 \`db\` 配置变量，可读性差且后续维护时容易误用（例如误以为仍在操作连接串）。建议将回调参数重命名为 \`database\` 或 \`client\`（视驱动版本而定）。

### 代码证据

```text
MongoClient.connect(db, (err, db) =&gt; {
```

### 修复建议

```text
MongoClient.connect(db, (err, database) =&gt; {
```

## 170. 存在不安全直接对象引用（Insecure DOR，A4）漏洞：\`userId\` 从 URL 参数 \`req.params\` 获取，攻击者只需修改 URL 中的 \`userId\` 即可查看其他用户的资产配置（allocations），造成越权访问敏感数据。代码中注释掉的修复方案已明确指出应从会话中获取用户身份，但当前实现并未落地。建议改为从 \`req.session\` 获取当前登录用户的 userI

- 分类：`安全`
- 风险等级：`严重`
- 位置：`app/routes/allocations.js:16-18`

存在不安全直接对象引用（Insecure DOR，A4）漏洞：\`userId\` 从 URL 参数 \`req.params\` 获取，攻击者只需修改 URL 中的 \`userId\` 即可查看其他用户的资产配置（allocations），造成越权访问敏感数据。代码中注释掉的修复方案已明确指出应从会话中获取用户身份，但当前实现并未落地。建议改为从 \`req.session\` 获取当前登录用户的 userId，而不是信任客户端传入的参数。

### 代码证据

```text
const {
            userId
        } = req.params;
```

### 修复建议

```text
const {
            userId
        } = req.session;
```

## 171. \`\_isRedirect\` 在比较路径时只对 \`path\` 去除了查询串和末尾斜杠，而 \`current\_path\` 拼接了 \`document.location.hash\` 且未剔除 hash。当当前页面为 \`/page\#anchor\`、step 路径为 \`/page\` 时会被误判为需要跳转。建议比较前对 \`current\_path\` 同样剔除 hash（如 \`.split("\#")\[0\]\`）后

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/assets/vendor/bootstrap-tour.js`

\`\_isRedirect\` 在比较路径时只对 \`path\` 去除了查询串和末尾斜杠，而 \`current\_path\` 拼接了 \`document.location.hash\` 且未剔除 hash。当当前页面为 \`/page\#anchor\`、step 路径为 \`/page\` 时会被误判为需要跳转。建议比较前对 \`current\_path\` 同样剔除 hash（如 \`.split("\#")\[0\]\`）后再比较。

### 代码证据

```text
current_path = [document.location.pathname, document.location.hash].join("");
```

## 172. 示例代码使用的是 Express 3.x 已废弃的 API：\`express.cookieParser()\` 与下文的 \`express.session()\`。本项目 \`package.json\` 使用 \`express ^4.13.4\`，实际通过 \`express-session\` 的 \`app.use(session({...}))\` 初始化会话（见 \`server.js\`），照抄此教程会直接

- 分类：`documentation`
- 风险等级：`中`
- 位置：`app/views/tutorial/a2.html:146`

示例代码使用的是 Express 3.x 已废弃的 API：\`express.cookieParser()\` 与下文的 \`express.session()\`。本项目 \`package.json\` 使用 \`express ^4.13.4\`，实际通过 \`express-session\` 的 \`app.use(session({...}))\` 初始化会话（见 \`server.js\`），照抄此教程会直接运行报错；并且 \`cookieParser()\` 本身并不能实现会话超时。建议将示例更新为 \`cookie-parser\` 与 \`express-session\` 的 Express 4 用法。

### 代码证据

```text
app.use(express.cookieParser());
```

### 修复建议

```text
const cookieParser = require("cookie-parser");
app.use(cookieParser());
```

## 173. 残留的调试日志 \`console.log(typeof(id))\` 建议移除，避免在生产环境输出无关信息。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/data/user-dao.js:42`

残留的调试日志 \`console.log(typeof(id))\` 建议移除，避免在生产环境输出无关信息。

### 代码证据

```text
console.log(typeof(id));
```

## 174. 登录成功后直接设置 req.session.userId 而未重新生成会话 ID，存在会话固定（Session Fixation）风险。建议在设置 userId 前调用 req.session.regenerate() 使旧会话失效。

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/routes/session.js:116-117`

登录成功后直接设置 req.session.userId 而未重新生成会话 ID，存在会话固定（Session Fixation）风险。建议在设置 userId 前调用 req.session.regenerate() 使旧会话失效。

### 代码证据

```text
req.session.userId = user._id;
            return res.redirect(user.isAdmin ? "/benefits" : "/dashboard");
```

### 修复建议

```text
req.session.regenerate(() =&gt; {
                req.session.userId = user._id;
                return res.redirect(user.isAdmin ? "/benefits" : "/dashboard");
            });
```

## 175. 该用例仅通过 \`cy.get(...)\` 依赖 Cypress 的隐式重试失败机制，缺少明确的断言，测试意图不够清晰。建议补充显式断言，例如 \`.should("be.visible")\` 或 \`.should("have.length", 1)\`。

- 分类：`test`
- 风险等级：`低`
- 位置：`test/e2e/integration/allocations\_spec.js:28`

该用例仅通过 \`cy.get(...)\` 依赖 Cypress 的隐式重试失败机制，缺少明确的断言，测试意图不够清晰。建议补充显式断言，例如 \`.should("be.visible")\` 或 \`.should("have.length", 1)\`。

### 代码证据

```text
cy.get("input[name='threshold']");
```

### 修复建议

```text
cy.get("input[name='threshold']").should("be.visible");
```

## 176. 未对 err 做空值/类型校验。当 err 为 null、undefined 或被抛出的非 Error 值（如字符串）时，访问 err.message / err.stack 可能抛出异常或记录 undefined，导致错误处理中间件自身崩溃，无法完成响应。建议先判断 err 是否为 Error 实例或字段是否存在。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/routes/error.js:7-8`

未对 err 做空值/类型校验。当 err 为 null、undefined 或被抛出的非 Error 值（如字符串）时，访问 err.message / err.stack 可能抛出异常或记录 undefined，导致错误处理中间件自身崩溃，无法完成响应。建议先判断 err 是否为 Error 实例或字段是否存在。

### 代码证据

```text
console.error(err.message);
    console.error(err.stack);
```

### 修复建议

```text
if (err &amp;&amp; err.stack) {
        console.error(err.message);
        console.error(err.stack);
    }
```

## 177. 新增成功后直接渲染页面（而非重定向），缺少 POST-Redirect-GET 语义：用户在提交后刷新浏览器会重复执行 POST，导致同一条 memo 被重复插入。建议插入成功后 \`res.redirect("/memos")\`，由 GET 路由调用 \`displayMemos\` 展示列表。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/routes/memos.js:15`

新增成功后直接渲染页面（而非重定向），缺少 POST-Redirect-GET 语义：用户在提交后刷新浏览器会重复执行 POST，导致同一条 memo 被重复插入。建议插入成功后 \`res.redirect("/memos")\`，由 GET 路由调用 \`displayMemos\` 展示列表。

### 代码证据

```text
this.displayMemos(req, res, next);
```

### 修复建议

```text
return res.redirect("/memos");
```

## 178. 构造函数中 \`this.backdrop\` 是普通状态对象（含 \`$element\`、\`$background\`、\`backgroundShown\`、\`overlayElementShown\` 等字段），这里却将其整体替换为 jQuery 元素，随后又把 \`$element\`/\`$background\`/\`backgroundShown\` 等状态挂到该 jQuery 对象上，\`overlay\` 字

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/assets/vendor/bootstrap-tour.js`

构造函数中 \`this.backdrop\` 是普通状态对象（含 \`$element\`、\`$background\`、\`backgroundShown\`、\`overlayElementShown\` 等字段），这里却将其整体替换为 jQuery 元素，随后又把 \`$element\`/\`$background\`/\`backgroundShown\` 等状态挂到该 jQuery 对象上，\`overlay\` 字段因此失去意义，逻辑脆弱且难以维护。建议保持 \`this.backdrop\` 为状态对象，用独立字段保存遮罩元素。

### 代码证据

```text
this.backdrop = $("&lt;div/&gt;", {
        "class": "tour-backdrop"
      });
```

## 179. 示例代码中 \`nosniff()\` 缺少 \`helmet.\` 前缀，页面中并未定义该函数，用户直接复制运行会抛出 ReferenceError。应改为 \`app.use(helmet.nosniff());\`。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/views/tutorial/a5.html:124`

示例代码中 \`nosniff()\` 缺少 \`helmet.\` 前缀，页面中并未定义该函数，用户直接复制运行会抛出 ReferenceError。应改为 \`app.use(helmet.nosniff());\`。

### 代码证据

```text
app.use(nosniff());
```

### 修复建议

```text
app.use(helmet.nosniff());
```

## 180. parseInt(userId) 未指定 radix，且当 userId 为 undefined、null 或非数字字符串时会得到 NaN，导致更新匹配不到任何文档；同时 updateUser 未校验更新结果（nModified/nMatched），匹配失败时仍会回调成功。建议显式指定基数并校验 userId 为有效整数，例如使用 Number.isInteger(Number(userId))

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/data/profile-dao.js:78-80`

parseInt(userId) 未指定 radix，且当 userId 为 undefined、null 或非数字字符串时会得到 NaN，导致更新匹配不到任何文档；同时 updateUser 未校验更新结果（nModified/nMatched），匹配失败时仍会回调成功。建议显式指定基数并校验 userId 为有效整数，例如使用 Number.isInteger(Number(userId)) 判断后再执行更新。

### 代码证据

```text
users.update({
                _id: parseInt(userId)
            }, {
```

## 181. cryptoKey 默认值 "a\_secure\_key\_for\_crypto\_here" 长度为 28 字节，而 cryptoAlgo 为 aes256（AES-256-CBC）要求 32 字节密钥；app/data/profile-dao.js 中 createCipheriv 会因此抛出 ERR\_CRYPTO\_INVALID\_KEYLEN，导致默认配置下加密/解密直接失败。同时建议显式指定算法

- 分类：`bug`
- 风险等级：`高`
- 位置：`config/env/all.js:9-10`

cryptoKey 默认值 "a\_secure\_key\_for\_crypto\_here" 长度为 28 字节，而 cryptoAlgo 为 aes256（AES-256-CBC）要求 32 字节密钥；app/data/profile-dao.js 中 createCipheriv 会因此抛出 ERR\_CRYPTO\_INVALID\_KEYLEN，导致默认配置下加密/解密直接失败。同时建议显式指定算法模式（如 aes-256-cbc 或 aes-256-gcm），避免依赖 OpenSSL 别名。

### 代码证据

```text
cryptoKey: "a_secure_key_for_crypto_here",
    cryptoAlgo: "aes256",
```

### 修复建议

```text
cryptoKey: process.env.CRYPTO_KEY, // 必须为 32 字节
    cryptoAlgo: "aes-256-cbc",
```

## 182. 测试用例名称中的 "accesible" 存在拼写错误，应为 "accessible"，会影响测试报告输出的可读性。

- 分类：`documentation`
- 风险等级：`低`
- 位置：`test/e2e/integration/allocations\_spec.js:19`

测试用例名称中的 "accesible" 存在拼写错误，应为 "accessible"，会影响测试报告输出的可读性。

### 代码证据

```text
it("Should be accesible for a logged user", () =&gt; {
```

### 修复建议

```text
it("Should be accessible for a logged user", () =&gt; {
```

## 183. \`target="\_blank"\` 未配合 \`rel="noopener noreferrer"\`，而该链接最终会跳转到外部站点（/learn?url=...）。新打开的页面可通过 \`window.opener\` 访问并操纵当前页面（tabnabbing/reverse tabnabbing）。建议添加 \`rel="noopener noreferrer"\`。

- 分类：`安全`
- 风险等级：`低`
- 位置：`app/views/layout.html:62`

\`target="\_blank"\` 未配合 \`rel="noopener noreferrer"\`，而该链接最终会跳转到外部站点（/learn?url=...）。新打开的页面可通过 \`window.opener\` 访问并操纵当前页面（tabnabbing/reverse tabnabbing）。建议添加 \`rel="noopener noreferrer"\`。

### 代码证据

```text
&lt;li&gt;&lt;a id="learn-menu-link" target="_blank" href="/learn?url=https://www.khanacademy.org/economics-finance-domain/core-finance/investment-vehicles-tutorial/ira-401ks/v/traditional-iras"&gt;&lt;i class="fa fa-edit"&gt;&lt;/i&gt; Learning Resources&lt;/a&gt;
```

### 修复建议

```text
&lt;li&gt;&lt;a id="learn-menu-link" target="_blank" rel="noopener noreferrer" href="/learn?url=https://www.khanacademy.org/economics-finance-domain/core-finance/investment-vehicles-tutorial/ira-401ks/v/traditional-iras"&gt;&lt;i class="fa fa-edit"&gt;&lt;/i&gt; Learning Resources&lt;/a&gt;
```

## 184. \`symbol\` 输入缺少客户端校验（无 \`required\`、长度限制与字符白名单），空提交或超长/异常字符会直接透传给后端拼接 URL。建议至少补充 \`required\`、\`maxlength\` 与 \`pattern\` 提升可用性；注意客户端校验仅作体验优化，服务端仍需进行严格校验。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/views/research.html:18`

\`symbol\` 输入缺少客户端校验（无 \`required\`、长度限制与字符白名单），空提交或超长/异常字符会直接透传给后端拼接 URL。建议至少补充 \`required\`、\`maxlength\` 与 \`pattern\` 提升可用性；注意客户端校验仅作体验优化，服务端仍需进行严格校验。

### 代码证据

```text
&lt;input type="text" class="form-control" placeholder="Stock Symbol" name="symbol" /&gt;
```

### 修复建议

```text
&lt;input type="text" class="form-control" placeholder="Stock Symbol" name="symbol" required maxlength="10" pattern="[A-Za-z0-9.\-^]+" /&gt;
```

## 185. 应用使用明文 HTTP 提供服务，登录凭据、会话 Cookie 等敏感数据在传输过程中可被窃听或篡改。仓库中已注释了 HTTPS 证书与 https 服务示例，建议启用 HTTPS（同时将 Cookie 的 \`secure\` 置为 \`true\`），或至少在敏感路由上强制重定向到 HTTPS。

- 分类：`安全`
- 风险等级：`高`
- 位置：`server.js:145-147`

应用使用明文 HTTP 提供服务，登录凭据、会话 Cookie 等敏感数据在传输过程中可被窃听或篡改。仓库中已注释了 HTTPS 证书与 https 服务示例，建议启用 HTTPS（同时将 Cookie 的 \`secure\` 置为 \`true\`），或至少在敏感路由上强制重定向到 HTTPS。

### 代码证据

```text
http.createServer(app).listen(port, () =&gt; {
        console.log(`Express http server listening on port ${port}`);
    });
```

### 修复建议

```text
https.createServer(httpsOptions, app).listen(port, () =&gt; {
        console.log(`Express https server listening on port ${port}`);
    });
```

## 186. 前三个 \`.panel\` 都位于 \`.col-lg-12\` 列容器内，而 "Source Code Example" 面板直接作为 \`.row\` 的子元素，没有 Bootstrap 列容器包裹。\`.row\` 自带负外边距，裸放的 \`.panel\` 会缺少正确的列内边距，在栅格布局下显示错位。建议将该面板也放入 \`.col-lg-12\`（或合适的列宽）中，保持结构一致。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/views/tutorial/redos.html:42-45`

前三个 \`.panel\` 都位于 \`.col-lg-12\` 列容器内，而 "Source Code Example" 面板直接作为 \`.row\` 的子元素，没有 Bootstrap 列容器包裹。\`.row\` 自带负外边距，裸放的 \`.panel\` 会缺少正确的列内边距，在栅格布局下显示错位。建议将该面板也放入 \`.col-lg-12\`（或合适的列宽）中，保持结构一致。

### 代码证据

```text
&lt;/div&gt;
    &lt;div class="panel panel-info"&gt;
        &lt;div class="panel-heading"&gt;
            &lt;h3 class="panel-title"&gt;Source Code Example&lt;/h3&gt;
```

## 187. 回调中忽略了 err 参数，数据库查询失败时会被误判为“非管理员”并重定向到 /login，掩盖真实错误且难以排查。建议先处理错误：if (err) return next(err);

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/routes/session.js:28`

回调中忽略了 err 参数，数据库查询失败时会被误判为“非管理员”并重定向到 /login，掩盖真实错误且难以排查。建议先处理错误：if (err) return next(err);

### 代码证据

```text
return user &amp;&amp; user.isAdmin ? next() : res.redirect("/login");
```

### 修复建议

```text
if (err) return next(err);
                return user &amp;&amp; user.isAdmin ? next() : res.redirect("/login");
```

## 188. \`.env.local\` 和 \`.env\` 仅覆盖这两个文件名，无法忽略 \`.env.development.local\`、\`.env.production.local\`、\`.env.test.local\` 等常见环境变量文件。若项目后续使用 Next.js 等多环境配置，这些文件可能包含密钥被提交到仓库。建议补充 \`.env\*.local\` 与 \`.env.\*\` 规则，并通过 \`!.env.ex

- 分类：`安全`
- 风险等级：`中`
- 位置：`.gitignore:27-28`

\`.env.local\` 和 \`.env\` 仅覆盖这两个文件名，无法忽略 \`.env.development.local\`、\`.env.production.local\`、\`.env.test.local\` 等常见环境变量文件。若项目后续使用 Next.js 等多环境配置，这些文件可能包含密钥被提交到仓库。建议补充 \`.env\*.local\` 与 \`.env.\*\` 规则，并通过 \`!.env.example\` 保留示例文件。

### 代码证据

```text
.env.local
.env
```

### 修复建议

```text
.env.local
.env
.env*.local
.env.*
!.env.example
```

## 189. 使用已废弃的 &lt;xmp&gt; 元素来展示攻击载荷会导致在现代浏览器中渲染不一致，并且 &lt;xmp&gt; 属于原始文本元素，其内部的字符引用（如 &amp;\#58; 和 &amp;\#41;）会原样显示为字面文本，而不是被解析为冒号和右括号。这会直接破坏本教程的核心目的：学习者看到的是 \`javascript&amp;\#58;alert(1&amp;\#41;\` 而不是 \`javascript:alert(1)\`，无法理解第 2、3 个示例的编

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`app/views/tutorial/a9.html:154-158`

使用已废弃的 &lt;xmp&gt; 元素来展示攻击载荷会导致在现代浏览器中渲染不一致，并且 &lt;xmp&gt; 属于原始文本元素，其内部的字符引用（如 &amp;\#58; 和 &amp;\#41;）会原样显示为字面文本，而不是被解析为冒号和右括号。这会直接破坏本教程的核心目的：学习者看到的是 \`javascript&amp;\#58;alert(1&amp;\#41;\` 而不是 \`javascript:alert(1)\`，无法理解第 2、3 个示例的编码绕过原理。建议改用 &lt;pre&gt;&lt;code&gt; 并在内容中对 HTML 特殊字符进行转义（如 &amp;lt;、&amp;gt;、&amp;amp;），或直接使用文本字符串展示，以保持示例的准确性和跨浏览器一致性。

### 代码证据

```text
&lt;code&gt;
                                        &lt;xmp&gt;
                                            [Hi there](javascript&amp;#58;alert(1&amp;#41;)
                                        &lt;/xmp&gt;
                                    &lt;/code&gt;
```

## 190. 此注释为复制粘贴错误：\`app.disable("x-powered-by")\` 的作用是移除 X-Powered-By 响应头，并非防止点击劫持。建议改为类似 \`// Remove X-Powered-By response header\`。

- 分类：`documentation`
- 风险等级：`低`
- 位置：`app/views/tutorial/a5.html:108-109`

此注释为复制粘贴错误：\`app.disable("x-powered-by")\` 的作用是移除 X-Powered-By 响应头，并非防止点击劫持。建议改为类似 \`// Remove X-Powered-By response header\`。

### 代码证据

```text
// Prevent opening page in frame or iframe to protect from clickjacking
        app.disable("x-powered-by");
```

### 修复建议

```text
// Remove X-Powered-By response header
        app.disable("x-powered-by");
```

## 191. 测试中硬编码了业务 URL 路径（如 "/logout"、"/contributions"），按规则应避免直接写死业务 URL；建议抽取路由常量统一管理，降低路由变更时多个测试同步修改的维护成本。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/e2e/integration/contributions\_spec.js:11`

测试中硬编码了业务 URL 路径（如 "/logout"、"/contributions"），按规则应避免直接写死业务 URL；建议抽取路由常量统一管理，降低路由变更时多个测试同步修改的维护成本。

### 代码证据

```text
cy.visitPage("/logout");
```

### 修复建议

```text
const ROUTES = { contributions: "/contributions", logout: "/logout" };

// 使用方式
cy.visitPage(ROUTES.logout);
```

## 192. 存在 NoSQL 注入漏洞：\`threshold\` 未经任何校验/转义就直接拼接进 \`$where\` 字符串，攻击者可注入任意 JavaScript 代码（例如 \`1';while(true){}'\`）造成拒绝服务或绕过过滤条件。文件中被注释掉的修复代码也印证了该问题。建议改用 MongoDB 原生查询操作符，并将 \`threshold\` 解析为整数并校验范围，避免使用 \`$where\`： \`\`\`

- 分类：`安全`
- 风险等级：`严重`
- 位置：`app/data/allocations-dao.js:77-79`

存在 NoSQL 注入漏洞：\`threshold\` 未经任何校验/转义就直接拼接进 \`$where\` 字符串，攻击者可注入任意 JavaScript 代码（例如 \`1';while(true){}'\`）造成拒绝服务或绕过过滤条件。文件中被注释掉的修复代码也印证了该问题。建议改用 MongoDB 原生查询操作符，并将 \`threshold\` 解析为整数并校验范围，避免使用 \`$where\`：
\`\`\`js
const parsedThreshold = parseInt(threshold, 10);
if (Number.isInteger(parsedThreshold) &amp;&amp; parsedThreshold &gt;= 0 &amp;&amp; parsedThreshold &lt;= 99) {
    return { userId: parsedUserId, stocks: { $gt: parsedThreshold } };
}
throw new Error(\`The user supplied threshold: ${threshold} was not valid.\`);
\`\`\`
另外，把 \`threshold\` 作为字符串参与数值比较（\`this.stocks &gt; '${threshold}'\`）也不严谨，应按数值类型进行比较。

### 代码证据

```text
return {
                    $where: `this.userId == ${parsedUserId} &amp;&amp; this.stocks &gt; '${threshold}'`
                };
```

### 修复建议

```text
const parsedThreshold = parseInt(threshold, 10);
                if (Number.isInteger(parsedThreshold) &amp;&amp; parsedThreshold &gt;= 0 &amp;&amp; parsedThreshold &lt;= 99) {
                    return { userId: parsedUserId, stocks: { $gt: parsedThreshold } };
                }
                throw new Error(`The user supplied threshold: ${threshold} was not valid.`);
```

## 193. \`-m 5\` 将 forever 的重启次数上限设为 5。当 server.js 因内存泄漏、未捕获异常等原因连续崩溃 5 次后，forever 会直接退出，此后只能依赖平台再次拉起整个 dyno/容器，期间引入额外的不可用时间，并会掩盖崩溃根因。若必须保留进程级自动重启，应去掉该上限或交给平台统一处理。

- 分类：`bug`
- 风险等级：`中`
- 位置：`Procfile:1`

\`-m 5\` 将 forever 的重启次数上限设为 5。当 server.js 因内存泄漏、未捕获异常等原因连续崩溃 5 次后，forever 会直接退出，此后只能依赖平台再次拉起整个 dyno/容器，期间引入额外的不可用时间，并会掩盖崩溃根因。若必须保留进程级自动重启，应去掉该上限或交给平台统一处理。

### 代码证据

```text
web: ./node_modules/.bin/forever -m 5 server.js
```

## 194. \`node:12-alpine\` 使用的 Node.js 12 已于 2022-04-30 结束生命周期（EOL），不再接收安全更新，存在已知未修复漏洞的风险。建议升级到仍在维护的 LTS 版本，例如 \`node:20-alpine\` 或 \`node:22-alpine\`，并同步验证应用兼容性。

- 分类：`安全`
- 风险等级：`高`
- 位置：`Dockerfile:1`

\`node:12-alpine\` 使用的 Node.js 12 已于 2022-04-30 结束生命周期（EOL），不再接收安全更新，存在已知未修复漏洞的风险。建议升级到仍在维护的 LTS 版本，例如 \`node:20-alpine\` 或 \`node:22-alpine\`，并同步验证应用兼容性。

### 代码证据

```text
FROM node:12-alpine
```

### 修复建议

```text
FROM node:20-alpine
```

## 195. 密码以明文形式直接存入数据库（\`password\` 来自请求参数，未做任何哈希/加盐处理），存在严重的安全风险（Broken Auth）。代码中已注释掉的 bcrypt 哈希逻辑（\`bcrypt.hashSync(password, bcrypt.genSaltSync())\`）应启用。

- 分类：`安全`
- 风险等级：`严重`
- 位置：`app/data/user-dao.js:24-25`

密码以明文形式直接存入数据库（\`password\` 来自请求参数，未做任何哈希/加盐处理），存在严重的安全风险（Broken Auth）。代码中已注释掉的 bcrypt 哈希逻辑（\`bcrypt.hashSync(password, bcrypt.genSaltSync())\`）应启用。

### 代码证据

```text
benefitStartDate: this.getRandomFutureDate(),
            password //received from request param
```

### 修复建议

```text
benefitStartDate: this.getRandomFutureDate(),
            password: bcrypt.hashSync(password, bcrypt.genSaltSync())
```

## 196. \`firstNameSafeString\` 只是对 \`firstName\` 的简单赋值，并未进行任何编码/转义，变量名具有误导性；用户输入被原样传入模板渲染，若模板未自动转义则存在 XSS 风险。建议使用 ESAPI 编码（与本文件中 \`website\` 的处理方式一致），或确保模板引擎对这些字段进行显式转义。

- 分类：`安全`
- 风险等级：`中`
- 位置：`app/routes/profile.js:64`

\`firstNameSafeString\` 只是对 \`firstName\` 的简单赋值，并未进行任何编码/转义，变量名具有误导性；用户输入被原样传入模板渲染，若模板未自动转义则存在 XSS 风险。建议使用 ESAPI 编码（与本文件中 \`website\` 的处理方式一致），或确保模板引擎对这些字段进行显式转义。

### 代码证据

```text
const firstNameSafeString = firstName;
```

### 修复建议

```text
const firstNameSafeString = ESAPI.encoder().encodeForHTML(firstName);
```

## 197. 源码中硬编码了明文密码（Admin\_123 / User1\_123 / User2\_123），属于敏感信息泄露；同时注释掉的 bcrypt 哈希行也暴露了哈希方案，降低了破解难度。建议移除明文与注释中的哈希串，密码通过环境变量/配置注入，并在入库前使用 bcrypt 等算法哈希存储。

- 分类：`安全`
- 风险等级：`中`
- 位置：`artifacts/db-reset.js:18-19`

源码中硬编码了明文密码（Admin\_123 / User1\_123 / User2\_123），属于敏感信息泄露；同时注释掉的 bcrypt 哈希行也暴露了哈希方案，降低了破解难度。建议移除明文与注释中的哈希串，密码通过环境变量/配置注入，并在入库前使用 bcrypt 等算法哈希存储。

### 代码证据

```text
"password": "Admin_123",
        //"password" : "$2a$10$8Zo/1e8KM8QzqOKqbDlYlONBOzukWXrM.IiyzqHRYDXqwB3gzDsba", // Admin_123
```

### 修复建议

```text
"password": "$2a$10$8Zo/1e8KM8QzqOKqbDlYlONBOzukWXrM.IiyzqHRYDXqwB3gzDsba", // Admin_123（已哈希，勿使用明文）
```

## 198. \`cy.userSignIn()\` 与 \`cy.visitPage("/memos")\` 在 3 个用例中重复出现，属于重复代码，建议抽取为 Cypress 自定义命令（如 \`cy.signInAndVisit("/memos")\`）或在 \`beforeEach\` 中统一执行。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/e2e/integration/memos\_spec.js:20-21`

\`cy.userSignIn()\` 与 \`cy.visitPage("/memos")\` 在 3 个用例中重复出现，属于重复代码，建议抽取为 Cypress 自定义命令（如 \`cy.signInAndVisit("/memos")\`）或在 \`beforeEach\` 中统一执行。

### 代码证据

```text
cy.userSignIn();
    cy.visitPage("/memos");
```

## 199. ln 函数通过 document.write 向 iframe 写入内容来探测元素的默认 display 值。document.write 会阻塞解析、触发页面重排，且现代浏览器对第三方脚本使用 document.write 会告警甚至拦截，存在性能与安全风险。这是旧版 jQuery 的兼容性探测逻辑，升级 jQuery 3.x 后该路径将不再执行；如需保留旧版本，请确认目标浏览器均能容忍此行为。

- 分类：`安全`
- 风险等级：`中`
- 位置：`app/assets/vendor/jquery.min.js`

ln 函数通过 document.write 向 iframe 写入内容来探测元素的默认 display 值。document.write 会阻塞解析、触发页面重排，且现代浏览器对第三方脚本使用 document.write 会告警甚至拦截，存在性能与安全风险。这是旧版 jQuery 的兼容性探测逻辑，升级 jQuery 3.x 后该路径将不再执行；如需保留旧版本，请确认目标浏览器均能容忍此行为。

### 代码证据

```text
t.write("&lt;!doctype html&gt;&lt;html&gt;&lt;body&gt;")
```

## 200. 链接文案 \`shrinkwarp\` 拼写错误，应为 \`shrinkwrap\`，与 href 指向的包名保持一致。

- 分类：`documentation`
- 风险等级：`低`
- 位置：`app/views/tutorial/a5.html:72`

链接文案 \`shrinkwarp\` 拼写错误，应为 \`shrinkwrap\`，与 href 指向的包名保持一致。

### 代码证据

```text
Lock versions of all npm packages used, for example using &lt;a href="https://www.npmjs.org/doc/cli/npm-shrinkwrap.html"&gt; shrinkwarp&lt;/a&gt;, to have full control over when to install a new version of the package.
```

### 修复建议

```text
Lock versions of all npm packages used, for example using &lt;a href="https://www.npmjs.org/doc/cli/npm-shrinkwrap.html"&gt; shrinkwrap&lt;/a&gt;, to have full control over when to install a new version of the package.
```

## 201. \`overrides\` 不是 JSHint（本项目使用 jshint 2.12.0 / grunt-contrib-jshint 3.x）支持的 \`.jshintrc\` 配置项，该块会被静默忽略。结果是 \`test/e2e/\*\*\` 下的 \`cy\`、\`Cypress\`、\`describe\`、\`it\` 等全局在 \`undef: true\` 下会被误报为未定义。建议改为在 \`test/e2e/\` 目录放

- 分类：`bug`
- 风险等级：`高`
- 位置：`.jshintrc:24-25`

\`overrides\` 不是 JSHint（本项目使用 jshint 2.12.0 / grunt-contrib-jshint 3.x）支持的 \`.jshintrc\` 配置项，该块会被静默忽略。结果是 \`test/e2e/\*\*\` 下的 \`cy\`、\`Cypress\`、\`describe\`、\`it\` 等全局在 \`undef: true\` 下会被误报为未定义。建议改为在 \`test/e2e/\` 目录放置独立的 \`.jshintrc\` 声明这些 globals，或在 Grunt 任务对应 target 的 \`options.globals\` 中配置。

### 代码证据

```text
"overrides": {
        "test/e2e/**": {
```

## 202. CSRF 防护（csurf）被注释掉，所有状态变更请求缺少 CSRF token 校验，攻击者可通过跨站请求伪造执行未授权操作（如转账、修改资料）。建议启用 \`app.use(csrf())\` 并将 \`req.csrfToken()\` 注入模板。

- 分类：`安全`
- 风险等级：`高`
- 位置：`server.js:131-132`

CSRF 防护（csurf）被注释掉，所有状态变更请求缺少 CSRF token 校验，攻击者可通过跨站请求伪造执行未授权操作（如转账、修改资料）。建议启用 \`app.use(csrf())\` 并将 \`req.csrfToken()\` 注入模板。

### 代码证据

```text
// Application routes
    routes(app, db);
```

### 修复建议

```text
app.use(csrf());
    app.use((req, res, next) =&gt; {
        res.locals.csrftoken = req.csrfToken();
        next();
    });
    // Application routes
    routes(app, db);
```

## 203. 模板引擎在 server.js 中配置了 \`autoescape: false\`，因此 \`{{script}}\` 会原样输出 HTML，未做任何转义。虽然当前 \`environmentalScripts\` 来自服务端配置（如 livereload 脚本），但一旦该数据源被外部输入污染，就会形成存储型 XSS 注入点。建议仅对白名单内的可信脚本显式使用 \`| safe\`，并在全局启用 autoesc

- 分类：`安全`
- 风险等级：`低`
- 位置：`app/views/tutorial/layout.html:95-97`

模板引擎在 server.js 中配置了 \`autoescape: false\`，因此 \`{{script}}\` 会原样输出 HTML，未做任何转义。虽然当前 \`environmentalScripts\` 来自服务端配置（如 livereload 脚本），但一旦该数据源被外部输入污染，就会形成存储型 XSS 注入点。建议仅对白名单内的可信脚本显式使用 \`| safe\`，并在全局启用 autoescape。

### 代码证据

```text
{% for script in environmentalScripts %}
    {{script}}
    {% endfor %}
```

## 204. 存在开放重定向（Open Redirect）漏洞：\`req.query.url\` 直接来自查询参数且未做任何校验，攻击者可构造 \`?url=//evil.com\` 或 \`?url=https://evil.com\` 诱导已登录用户跳转到钓鱼站点；若请求未携带 \`url\` 参数，\`res.redirect(undefined)\` 还会抛出 TypeError。建议对跳转目标做同源/白名单校验，仅允许

- 分类：`安全`
- 风险等级：`严重`
- 位置：`app/routes/index.js:70-73`

存在开放重定向（Open Redirect）漏洞：\`req.query.url\` 直接来自查询参数且未做任何校验，攻击者可构造 \`?url=//evil.com\` 或 \`?url=https://evil.com\` 诱导已登录用户跳转到钓鱼站点；若请求未携带 \`url\` 参数，\`res.redirect(undefined)\` 还会抛出 TypeError。建议对跳转目标做同源/白名单校验，仅允许站内相对路径。

### 代码证据

```text
app.get("/learn", isLoggedIn, (req, res) =&gt; {
        // Insecure way to handle redirects by taking redirect url from query string
        return res.redirect(req.query.url);
    });
```

### 修复建议

```text
app.get("/learn", isLoggedIn, (req, res) =&gt; {
        const { url } = req.query;
        if (typeof url !== "string" || !url.startsWith("/") || url.startsWith("//")) {
            return res.redirect("/");
        }
        return res.redirect(url);
    });
```

## 205. 对 .user-dropdown a 重复查询了三次，且 .invoke("text") 使用包含前后空格的精确字符串断言（" Node Goat Admin "、" Profile"、" Log Out"），对模板空白变化非常敏感。建议使用 .as() 别名复用元素，并对文本断言改用 contain 或先 trim 再比较，减少重复查询并提升健壮性。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/e2e/integration/general\_spec.js:53-68`

对 .user-dropdown a 重复查询了三次，且 .invoke("text") 使用包含前后空格的精确字符串断言（" Node Goat Admin "、" Profile"、" Log Out"），对模板空白变化非常敏感。建议使用 .as() 别名复用元素，并对文本断言改用 contain 或先 trim 再比较，减少重复查询并提升健壮性。

### 代码证据

```text
cy.get(".user-dropdown a")
      .eq(0)
      .invoke("text")
      .should("eq", " Node Goat Admin ");

    cy.get(".user-dropdown a")
      .eq(1)
      .should("have.attr", "href", "/profile")
      .invoke("text")
      .should("eq", " Profile");

    cy.get(".user-dropdown a")
      .eq(2)
      .should("have.attr", "href", "/logout")
      .invoke("text")
      .should("eq", " Log Out");
```

### 修复建议

```text
cy.get(".user-dropdown a").as("dropdownLinks");

    cy.get("@dropdownLinks")
      .eq(0)
      .invoke("text")
      .should("contain", "Node Goat Admin");

    cy.get("@dropdownLinks")
      .eq(1)
      .should("have.attr", "href", "/profile")
      .invoke("text")
      .should("contain", "Profile");

    cy.get("@dropdownLinks")
      .eq(2)
      .should("have.attr", "href", "/logout")
      .invoke("text")
      .should("contain", "Log Out");
```

## 206. \`slide()\` 在触发 \`slide.bs.carousel\` 事件之前就把 \`this.sliding\` 置为 \`true\`；若事件被 \`preventDefault()\` 取消（两个分支的 \`if(j.isDefaultPrevented())return;\`）或目标项已是 active，函数直接 \`return\`，\`sliding\` 不会被复位，后续 \`next/prev/to\` 都被

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/assets/vendor/bootstrap/bootstrap.js`

\`slide()\` 在触发 \`slide.bs.carousel\` 事件之前就把 \`this.sliding\` 置为 \`true\`；若事件被 \`preventDefault()\` 取消（两个分支的 \`if(j.isDefaultPrevented())return;\`）或目标项已是 active，函数直接 \`return\`，\`sliding\` 不会被复位，后续 \`next/prev/to\` 都被 \`if(this.sliding)return\` 挡住，轮播会被永久锁死。需在每条提前返回路径上复位 \`this.sliding=false\`。

### 代码证据

```text
this.sliding=!0,f&amp;&amp;this.pause();var j=a.Event("slide.bs.carousel",{relatedTarget:e[0],direction:g});if(e.hasClass("active"))return;
```

### 修复建议

```text
this.sliding=!0,f&amp;&amp;this.pause();var j=a.Event("slide.bs.carousel",{relatedTarget:e[0],direction:g});if(e.hasClass("active")){this.sliding=!1;return;}
```

## 207. 使用相对路径 \`./node\_modules/.bin/forever\` 依赖进程的当前工作目录，不够便携；通常平台会把 node\_modules/.bin 加入 PATH，直接写 \`forever\` 即可。不过更推荐去掉 forever，改用 \`node server.js\` 由平台直接托管。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`Procfile:1`

使用相对路径 \`./node\_modules/.bin/forever\` 依赖进程的当前工作目录，不够便携；通常平台会把 node\_modules/.bin 加入 PATH，直接写 \`forever\` 即可。不过更推荐去掉 forever，改用 \`node server.js\` 由平台直接托管。

### 代码证据

```text
web: ./node_modules/.bin/forever -m 5 server.js
```

## 208. 只处理了 \`ECONNREFUSED\` 这一种错误：当 Zap API 返回其他错误（如 5xx、超时、非法 scanId）时，\`zapError\` 被赋值为空字符串（假值），\`statusValue\` 也不会更新，\`setInterval\` 永远不会被清除；而 \`this.timeout(0)\` 已禁用超时，测试会无限挂起。建议对所有 \`err\` 统一终止轮询并回调失败，避免静默挂死。

- 分类：`bug`
- 风险等级：`高`
- 位置：`test/security/profile-test.js:229`

只处理了 \`ECONNREFUSED\` 这一种错误：当 Zap API 返回其他错误（如 5xx、超时、非法 scanId）时，\`zapError\` 被赋值为空字符串（假值），\`statusValue\` 也不会更新，\`setInterval\` 永远不会被清除；而 \`this.timeout(0)\` 已禁用超时，测试会无限挂起。建议对所有 \`err\` 统一终止轮询并回调失败，避免静默挂死。

### 代码证据

```text
if (err) zapError = (err.code === "ECONNREFUSED") ? err : "";
```

### 修复建议

```text
if (err) {
                                    zapError = err;
                                    clearInterval(zapInProgressIntervalId);
                                    return activeScanDone(err);
                                }
```

## 209. 文件存在字符编码错乱（mojibake）：\`RaphaÃ«l\` 应为 \`Raphaël\`，\`â€œ\` 应为 \`“\` 等。这些乱码会出现在 title/tooltip 以及日志输出等用户可见字符串中。建议以 UTF-8 重新保存该文件，或从上游获取未损坏的副本。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/assets/vendor/chart/raphael-min.js`

文件存在字符编码错乱（mojibake）：\`RaphaÃ«l\` 应为 \`Raphaël\`，\`â€œ\` 应为 \`“\` 等。这些乱码会出现在 title/tooltip 以及日志输出等用户可见字符串中。建议以 UTF-8 重新保存该文件，或从上游获取未损坏的副本。

### 代码证据

```text
i.title="RaphaÃ«l Colour Picker",i.style.display="none"
```

## 210. 存在安全风险（SSRF 敞口）：隐藏字段 \`url\` 作为 GET 参数随表单提交，客户端可任意篡改，且 \`symbol\` 是自由文本输入。后端（app/routes/research.js）直接将二者拼接后发起请求（\`req.query.url + req.query.symbol\`），攻击者可通过构造 \`/research?url=http://127.0.0.1/&amp;symbol=...\` 探

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/views/research.html:17`

存在安全风险（SSRF 敞口）：隐藏字段 \`url\` 作为 GET 参数随表单提交，客户端可任意篡改，且 \`symbol\` 是自由文本输入。后端（app/routes/research.js）直接将二者拼接后发起请求（\`req.query.url + req.query.symbol\`），攻击者可通过构造 \`/research?url=http://127.0.0.1/&amp;symbol=...\` 探测内网或发起任意请求。建议不要通过客户端表单传递 base URL，应在服务端硬编码请求基址，并对 \`symbol\`（以及任何外部 URL）做协议/主机白名单校验。

### 代码证据

```text
&lt;input type="hidden" id="url" name="url" value="https://finance.yahoo.com/quote/"/&gt;
```

### 修复建议

```text
&lt;form action="/research" method="get" role="search"&gt;
    &lt;div class="form-group"&gt;
        &lt;input type="text" class="form-control" placeholder="Stock Symbol" name="symbol" /&gt;
```

## 211. find("input") 之后没有显式断言。虽然 Cypress 的 find 在找不到元素时会超时失败，但缺少 .should(...) 使得用例意图不够明确（例如未校验输入框是否可见/可用）。建议补充显式断言，如 .should("exist") 或 .should("be.visible")。

- 分类：`test`
- 风险等级：`低`
- 位置：`test/e2e/integration/research\_spec.js:24-25`

find("input") 之后没有显式断言。虽然 Cypress 的 find 在找不到元素时会超时失败，但缺少 .should(...) 使得用例意图不够明确（例如未校验输入框是否可见/可用）。建议补充显式断言，如 .should("exist") 或 .should("be.visible")。

### 代码证据

```text
cy.get("form[role='search']")
      .find("input");
```

### 修复建议

```text
cy.get("form[role='search']")
      .find("input")
      .should("exist");
```

## 212. 会话签名密钥 cookieSecret 和加密密钥 cryptoKey 被硬编码在源码中，所有部署环境共享同一密钥，源码或产物泄露后攻击者即可伪造会话、解密敏感数据（server.js 与 profile-dao.js 均直接使用这两个值）。应从环境变量读取，并在缺失时启动失败或生成随机值，切勿使用可预测的默认密钥。

- 分类：`安全`
- 风险等级：`高`
- 位置：`config/env/all.js:8-9`

会话签名密钥 cookieSecret 和加密密钥 cryptoKey 被硬编码在源码中，所有部署环境共享同一密钥，源码或产物泄露后攻击者即可伪造会话、解密敏感数据（server.js 与 profile-dao.js 均直接使用这两个值）。应从环境变量读取，并在缺失时启动失败或生成随机值，切勿使用可预测的默认密钥。

### 代码证据

```text
cookieSecret: "session_cookie_secret_key_here",
    cryptoKey: "a_secure_key_for_crypto_here",
```

### 修复建议

```text
cookieSecret: process.env.COOKIE_SECRET,
    cryptoKey: process.env.CRYPTO_KEY, // 启动时校验必须存在，避免使用默认密钥
```

## 213. catch 分支中调用了 \`this.debug(...)\`，但 Tour 原型上只定义了 \`\_debug\`，\`debug\` 方法并不存在。一旦 localStorage 写入触发 QUOTA\_EXCEEDED\_ERR，这里会抛出 \`TypeError: this.debug is not a function\`，导致 try/catch 的容错逻辑失效并向调用方冒泡异常。建议改为 \`this.\_

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/assets/vendor/bootstrap-tour.js`

catch 分支中调用了 \`this.debug(...)\`，但 Tour 原型上只定义了 \`\_debug\`，\`debug\` 方法并不存在。一旦 localStorage 写入触发 QUOTA\_EXCEEDED\_ERR，这里会抛出 \`TypeError: this.debug is not a function\`，导致 try/catch 的容错逻辑失效并向调用方冒泡异常。建议改为 \`this.\_debug(...)\`；同时 \`DOMException\` 在部分旧浏览器中可能未定义，建议加上 \`typeof DOMException !== "undefined"\` 保护。

### 代码证据

```text
if (e.code === DOMException.QUOTA_EXCEEDED_ERR) {
            this.debug("LocalStorage quota exceeded. setState failed.");
          }
```

### 修复建议

```text
if (typeof DOMException !== "undefined" &amp;&amp; e.code === DOMException.QUOTA_EXCEEDED_ERR) {
            this._debug("LocalStorage quota exceeded. setState failed.");
          }
```

## 214. 登录失败时对“用户名不存在”和“密码错误”返回不同提示，属于用户枚举漏洞（Broken Authentication），攻击者可据此探测有效用户名。建议统一返回通用错误消息，如 "Invalid username and/or password"。

- 分类：`安全`
- 风险等级：`中`
- 位置：`app/routes/session.js:60-61`

登录失败时对“用户名不存在”和“密码错误”返回不同提示，属于用户枚举漏洞（Broken Authentication），攻击者可据此探测有效用户名。建议统一返回通用错误消息，如 "Invalid username and/or password"。

### 代码证据

```text
const invalidUserNameErrorMessage = "Invalid username";
            const invalidPasswordErrorMessage = "Invalid password";
```

### 修复建议

```text
const invalidUserNameErrorMessage = "Invalid username and/or password";
            const invalidPasswordErrorMessage = "Invalid username and/or password";
```

## 215. 这里保留了一整段被注释掉的 NoSQL 注入修复代码（dead code），既没有实际修复漏洞，也增加了维护噪音。建议直接应用其中的修复逻辑（并结合上面的安全修复建议）后删除这段注释代码。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/data/allocations-dao.js:63-64`

这里保留了一整段被注释掉的 NoSQL 注入修复代码（dead code），既没有实际修复漏洞，也增加了维护噪音。建议直接应用其中的修复逻辑（并结合上面的安全修复建议）后删除这段注释代码。

### 代码证据

```text
/*
                // Fix for A1 - 2 NoSQL Injection - escape the threshold parameter properly
```

## 216. 该文件为 2013 年发布的 jQuery 1.10.2，存在多个已知且已公开的安全漏洞：CVE-2015-9251（跨域 Ajax 在未指定 dataType 时执行 text/javascript 响应的 XSS）、CVE-2019-11358（$.extend 深拷贝时的原型链污染）、CVE-2020-11022（.html() 的 htmlPrefilter XSS）、CVE-2020-1

- 分类：`安全`
- 风险等级：`严重`
- 位置：`app/assets/vendor/jquery.min.js:1`

该文件为 2013 年发布的 jQuery 1.10.2，存在多个已知且已公开的安全漏洞：CVE-2015-9251（跨域 Ajax 在未指定 dataType 时执行 text/javascript 响应的 XSS）、CVE-2019-11358（$.extend 深拷贝时的原型链污染）、CVE-2020-11022（.html() 的 htmlPrefilter XSS）、CVE-2020-11023（DOM 操作时 option/select 相关的 XSS）等，且该版本已停止维护。建议升级到受支持的 jQuery 3.7.x（或至少 3.5.0 以上）并同步回归测试；如短期无法升级，需评估上述漏洞在应用中的实际暴露面并增加输入过滤/WAF 缓解。

### 代码证据

```text
/*! jQuery v1.10.2 | (c) 2005, 2013 jQuery Foundation, Inc. | jquery.org/license
```

## 217. 回调嵌套（callback hell）：\`updateBenefits\` 在更新回调中又嵌套了 \`getAllNonAdminUsers\` 回调，可读性和错误处理变差。建议将 DAO 的 callback 风格封装为 Promise 并改用 \`async/await\`，用 \`try/catch\` 统一捕获错误，避免多层嵌套。

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`app/routes/benefits.js:15-17`

回调嵌套（callback hell）：\`updateBenefits\` 在更新回调中又嵌套了 \`getAllNonAdminUsers\` 回调，可读性和错误处理变差。建议将 DAO 的 callback 风格封装为 Promise 并改用 \`async/await\`，用 \`try/catch\` 统一捕获错误，避免多层嵌套。

### 代码证据

```text
benefitsDAO.getAllNonAdminUsers((error, users) =&gt; {
                if (error) return next(error);
```

## 218. 未排除 \`node\_modules\` 等依赖/构建产物目录。Dockerfile 第 13 行 \`COPY .\` 会把本地 \`node\_modules\` 复制进最终镜像，覆盖第一阶段 \`npm install --production\` 的结果，导致镜像体积膨胀并可能带入开发依赖。建议添加 \`node\_modules\`、\`dist\`、\`build\`、\`coverage\` 等目录。

- 分类：`性能`
- 风险等级：`中`
- 位置：`.dockerignore:1-3`

未排除 \`node\_modules\` 等依赖/构建产物目录。Dockerfile 第 13 行 \`COPY .\` 会把本地 \`node\_modules\` 复制进最终镜像，覆盖第一阶段 \`npm install --production\` 的结果，导致镜像体积膨胀并可能带入开发依赖。建议添加 \`node\_modules\`、\`dist\`、\`build\`、\`coverage\` 等目录。

### 代码证据

```text
Dockerfile
docker-compose.yml
.dockerignore
```

### 修复建议

```text
Dockerfile
docker-compose.yml
.dockerignore
node_modules
dist
build
coverage
```

## 219. 该链接的 \`href\` 直接拼接了用户可控的 \`firstNameSafeString\`（在 \`app/routes/profile.js\` 中它就是用户提交的 \`firstName\` 原值）。模板引擎的 HTML 自动转义只能防止引号闭合，无法阻止 \`javascript:\`、\`data:\` 等危险 URL 协议——攻击者把 firstName 设为 \`javascript:alert(docu

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/views/profile.html:78`

该链接的 \`href\` 直接拼接了用户可控的 \`firstNameSafeString\`（在 \`app/routes/profile.js\` 中它就是用户提交的 \`firstName\` 原值）。模板引擎的 HTML 自动转义只能防止引号闭合，无法阻止 \`javascript:\`、\`data:\` 等危险 URL 协议——攻击者把 firstName 设为 \`javascript:alert(document.cookie)\` 即可构造点击触发的 XSS；同时该值也没有按 URL 上下文做百分号编码。此外，当前 href 只是名字本身，点击后并不会真正跳转到 Google 搜索。建议在控制器中生成经过 URL 编码并做协议白名单校验的变量（如 \`firstNameSafeURLString\`），并拼接完整的搜索地址。

### 代码证据

```text
&lt;a href="{{firstNameSafeString}}"&gt;Google search this profile by name&lt;/a&gt;
```

### 修复建议

```text
&lt;a href="https://www.google.com/search?q={{firstNameSafeURLString}}"&gt;Google search this profile by name&lt;/a&gt;
```

## 220. 硬编码 500 会忽略错误对象上已有的状态码（如 404/401/403 等 4xx），导致所有错误都被当作服务器内部错误返回，客户端无法获得正确的 HTTP 状态码。建议优先使用 err.status / err.statusCode，仅在缺失时回退为 500。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/routes/error.js:9`

硬编码 500 会忽略错误对象上已有的状态码（如 404/401/403 等 4xx），导致所有错误都被当作服务器内部错误返回，客户端无法获得正确的 HTTP 状态码。建议优先使用 err.status / err.statusCode，仅在缺失时回退为 500。

### 代码证据

```text
res.status(500);
```

### 修复建议

```text
res.status(err.status || err.statusCode || 500);
```

## 221. 测试名称中的 "accesible" 拼写错误，应为 "accessible"，影响测试报告可读性。

- 分类：`documentation`
- 风险等级：`低`
- 位置：`test/e2e/integration/contributions\_spec.js:19`

测试名称中的 "accesible" 拼写错误，应为 "accessible"，影响测试报告可读性。

### 代码证据

```text
it("Should be accesible for a logged user", () =&gt; {
```

### 修复建议

```text
it("Should be accessible for a logged user", () =&gt; {
```

## 222. 项目规范禁止使用 \`var\`，应统一使用 \`const\`/\`let\`。本文件存在大量 \`var\` 声明（如 \`webDriver\`、\`config\`、\`state\`、\`sutUserName\`、\`sutUserPassword\`、\`overWrite\`、\`enabled\`、\`numberOfAlerts\` 等），请一并替换为 \`const\`（不会重新赋值的变量）或 \`let\`（会重新赋值的变量）。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/security/profile-test.js:9-13`

项目规范禁止使用 \`var\`，应统一使用 \`const\`/\`let\`。本文件存在大量 \`var\` 声明（如 \`webDriver\`、\`config\`、\`state\`、\`sutUserName\`、\`sutUserPassword\`、\`overWrite\`、\`enabled\`、\`numberOfAlerts\` 等），请一并替换为 \`const\`（不会重新赋值的变量）或 \`let\`（会重新赋值的变量）。

### 代码证据

```text
var seleniumWebdriver = require("selenium-webdriver");
var webDriver;
var chrome = require("selenium-webdriver/chrome");
var test = require("selenium-webdriver/testing");
var proxy = require("selenium-webdriver/proxy");
```

### 修复建议

```text
const seleniumWebdriver = require("selenium-webdriver");
let webDriver;
const chrome = require("selenium-webdriver/chrome");
const test = require("selenium-webdriver/testing");
const proxy = require("selenium-webdriver/proxy");
```

## 223. 文档中的函数名 \`setTimeOut()\` 拼写有误，JavaScript 实际函数名为 \`setTimeout()\`（\`t\` 小写），可能误导读者。

- 分类：`documentation`
- 风险等级：`低`
- 位置：`app/views/tutorial/a1.html:130`

文档中的函数名 \`setTimeOut()\` 拼写有误，JavaScript 实际函数名为 \`setTimeout()\`（\`t\` 小写），可能误导读者。

### 代码证据

```text
&lt;code&gt;setTimeOut()&lt;/code&gt;,
```

### 修复建议

```text
&lt;code&gt;setTimeout()&lt;/code&gt;,
```

## 224. 模板直接向最终用户渲染原始错误对象（error: err），可能泄露内部实现细节、文件路径或业务逻辑等敏感信息。建议在服务端通过 console.error 等记录完整错误，页面只展示通用提示，不要输出 err 的详细信息。

- 分类：`安全`
- 风险等级：`中`
- 位置：`app/views/error-template.html:11`

模板直接向最终用户渲染原始错误对象（error: err），可能泄露内部实现细节、文件路径或业务逻辑等敏感信息。建议在服务端通过 console.error 等记录完整错误，页面只展示通用提示，不要输出 err 的详细信息。

### 代码证据

```text
&lt;br&gt;{{error}}
```

### 修复建议

```text
&lt;br&gt;系统发生内部错误，请稍后重试
```

## 225. SVG 引擎在处理 href/title/target 属性时未做协议校验，直接将外部传入的值通过 setAttributeNS(n, o, p) 写入 xlink:href。若该值来自用户输入（例如 javascript:alert(1)），点击元素即可触发 XSS。建议在此处只允许 http/https/mailto 等安全协议，或在上游调用方对用户输入进行过滤。

- 分类：`安全`
- 风险等级：`中`
- 位置：`app/assets/vendor/chart/raphael-min.js`

SVG 引擎在处理 href/title/target 属性时未做协议校验，直接将外部传入的值通过 setAttributeNS(n, o, p) 写入 xlink:href。若该值来自用户输入（例如 javascript:alert(1)），点击元素即可触发 XSS。建议在此处只允许 http/https/mailto 等安全协议，或在上游调用方对用户输入进行过滤。

### 代码证据

```text
o=="target"?u.setAttributeNS(n,"show",p=="blank"?"new":p):u.setAttributeNS(n,o,p);break;
```

## 226. 认证 URL 路径（\`login\`）、\`profile\`、\`/dashboard\`、\`formBasedAuthentication\` 以及扫描请求体等业务相关字符串直接硬编码在测试逻辑中，路由或字段一旦变更需要多处同步修改。建议将这些路径和表单字段抽取到 \`config\` 或常量集中管理，避免散落硬编码。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/security/profile-test.js:149-151`

认证 URL 路径（\`login\`）、\`profile\`、\`/dashboard\`、\`formBasedAuthentication\` 以及扫描请求体等业务相关字符串直接硬编码在测试逻辑中，路由或字段一旦变更需要多处同步修改。建议将这些路径和表单字段抽取到 \`config\` 或常量集中管理，避免散落硬编码。

### 代码证据

```text
"loginUrl=" +
                    zapTargetApp +
                    "login&amp;loginRequestData=" +
```

### 修复建议

```text
"loginUrl=" +
                    config.loginUrl +
                    "loginRequestData=" +
```

## 227. 该回调在成功时未调用 next()，导致 prepareUserData 永远不会正常结束；而 handleSignup 中调用 prepareUserData(user, next) 后未等待其完成即渲染页面，若 update 异步失败，会在响应已发送后再调用 next(err)，触发“Cannot set headers after they are sent”。建议改为 Promise 或成

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/routes/session.js:20-22`

该回调在成功时未调用 next()，导致 prepareUserData 永远不会正常结束；而 handleSignup 中调用 prepareUserData(user, next) 后未等待其完成即渲染页面，若 update 异步失败，会在响应已发送后再调用 next(err)，触发“Cannot set headers after they are sent”。建议改为 Promise 或成功时调用 next()，并在 handleSignup 中等待更新完成后再渲染。

### 代码证据

```text
allocationsDAO.update(user._id, stocks, funds, bonds, (err) =&gt; {
            if (err) return next(err);
        });
```

### 修复建议

```text
allocationsDAO.update(user._id, stocks, funds, bonds, (err) =&gt; {
            if (err) return next(err);
            next();
        });
```

## 228. \`actions/setup-node@v1\` 已弃用，较新版本默认支持 Node 版本管理与缓存。建议升级到 \`actions/setup-node@v4\`。

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`.github/workflows/e2e-test.yml:21`

\`actions/setup-node@v1\` 已弃用，较新版本默认支持 Node 版本管理与缓存。建议升级到 \`actions/setup-node@v4\`。

### 代码证据

```text
uses: actions/setup-node@v1
```

### 修复建议

```text
uses: actions/setup-node@v4
```

## 229. 该示例将加密密钥硬编码在源码中，一旦源码或页面泄露，加密即失去保护作用；同时 \`aes256\` 不是 \`crypto.createCipheriv\` 规范支持的算法名（Node 中应使用 \`aes-256-cbc\`/\`aes-256-gcm\` 等完整名称），并且当前密钥长度不满足 AES-256 要求，示例实际运行时会抛错。建议密钥从环境变量或密钥管理服务读取，算法使用 Node 支持的完整名称。

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/views/tutorial/a6.html:82-86`

该示例将加密密钥硬编码在源码中，一旦源码或页面泄露，加密即失去保护作用；同时 \`aes256\` 不是 \`crypto.createCipheriv\` 规范支持的算法名（Node 中应使用 \`aes-256-cbc\`/\`aes-256-gcm\` 等完整名称），并且当前密钥长度不满足 AES-256 要求，示例实际运行时会抛错。建议密钥从环境变量或密钥管理服务读取，算法使用 Node 支持的完整名称。

### 代码证据

```text
var config = {
    cryptoKey: "a_secure_key_for_crypto_here",
    cryptoAlgo: "aes256", // or other secure encryption algo here
    iv: ""
};
```

### 修复建议

```text
var config = {
    cryptoKey: process.env.CRYPTO_KEY,
    cryptoAlgo: "aes-256-gcm"
};
```

## 230. 全局设置 \`grunt.option("force", true)\` 会让所有任务失败都被忽略，包括 \`jshint\`、\`mochaTest\` 等校验/测试任务，容易让 CI 在存在错误的情况下仍然通过。建议移除全局 force，仅在确实需要容错的特定任务上按需处理。

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`Gruntfile.js:156`

全局设置 \`grunt.option("force", true)\` 会让所有任务失败都被忽略，包括 \`jshint\`、\`mochaTest\` 等校验/测试任务，容易让 CI 在存在错误的情况下仍然通过。建议移除全局 force，仅在确实需要容错的特定任务上按需处理。

### 代码证据

```text
grunt.option("force", true);
```

## 231. \`bitwise\` 取值为 \`false\` 表示\*\*关闭\*\*对位运算符的检查，与行末注释「Prohibit bitwise operators (&amp;, |, ^, etc.)」表达的意图相反。若确实想禁止位运算，应改为 \`true\`；否则请修正注释，避免后续维护者误解。

- 分类：`bug`
- 风险等级：`中`
- 位置：`.jshintrc:5`

\`bitwise\` 取值为 \`false\` 表示\*\*关闭\*\*对位运算符的检查，与行末注释「Prohibit bitwise operators (&amp;, |, ^, etc.)」表达的意图相反。若确实想禁止位运算，应改为 \`true\`；否则请修正注释，避免后续维护者误解。

### 代码证据

```text
"bitwise": false, // Prohibit bitwise operators (&amp;, |, ^, etc.).
```

### 修复建议

```text
"bitwise": true, // Prohibit bitwise operators (&amp;, |, ^, etc.).
```

## 232. 文件大量使用 \`var\` 声明变量（如 \`var k=l.html5||{},...\`、\`var e={...}\`、\`for(var b=...)\` 等），违反「禁止使用 var，应使用 let/const」的规则。注意该库是面向旧版浏览器的 ES5 polyfill，改写为 let/const 会失去 IE8/9 兼容性；建议将 vendor 目录加入 lint 豁免，而不是直接修改代码。

- 分类：`代码风格`
- 风险等级：`低`
- 位置：`app/assets/vendor/html5shiv.js`

文件大量使用 \`var\` 声明变量（如 \`var k=l.html5||{},...\`、\`var e={...}\`、\`for(var b=...)\` 等），违反「禁止使用 var，应使用 let/const」的规则。注意该库是面向旧版浏览器的 ES5 polyfill，改写为 let/const 会失去 IE8/9 兼容性；建议将 vendor 目录加入 lint 豁免，而不是直接修改代码。

### 代码证据

```text
var k=l.html5||{},s=/^&lt;|^(?:button|map|select|textarea|object|iframe|option|optgroup)$/i,r=
```

## 233. 该 POST 表单缺少 CSRF 令牌，且服务端未启用 csurf 等 CSRF 防护中间件。攻击者可构造恶意页面诱导已登录用户提交 memo，造成跨站请求伪造（CSRF）。建议在表单中加入隐藏的 csrf token 字段（例如 &lt;input type="hidden" name="\_csrf" value="{{ csrftoken }}"&gt;），并在服务端启用并校验 CSRF 中间件。

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/views/memos.html:15`

该 POST 表单缺少 CSRF 令牌，且服务端未启用 csurf 等 CSRF 防护中间件。攻击者可构造恶意页面诱导已登录用户提交 memo，造成跨站请求伪造（CSRF）。建议在表单中加入隐藏的 csrf token 字段（例如 &lt;input type="hidden" name="\_csrf" value="{{ csrftoken }}"&gt;），并在服务端启用并校验 CSRF 中间件。

### 代码证据

```text
&lt;form action="/memos" method="post" role="search"&gt;
```

### 修复建议

```text
&lt;form action="/memos" method="post" role="search"&gt;
                    &lt;input type="hidden" name="_csrf" value="{{ csrftoken }}"&gt;
```

## 234. 用例名 "Should exists" 存在语法错误：exists 是第三人称单数形式，不能跟在 should 后，应改为 "Should exist"。此问题在所有同类用例名中重复出现，建议统一修正，以保证测试报告可读性。

- 分类：`代码风格`
- 风险等级：`低`
- 位置：`test/e2e/integration/tutorial\_spec.js:15`

用例名 "Should exists" 存在语法错误：exists 是第三人称单数形式，不能跟在 should 后，应改为 "Should exist"。此问题在所有同类用例名中重复出现，建议统一修正，以保证测试报告可读性。

### 代码证据

```text
it("Should exists /tutorial/a1", () =&gt; {
```

## 235. 工作流由 \`push\` 和 \`pull\_request\` 同时触发且没有 \`concurrency\` 控制，同一分支/PR 的连续提交会并发产生冗余运行并可能互相覆盖产物。建议添加 \`concurrency\` 分组，并在新提交到来时取消旧运行。

- 分类：`other`
- 风险等级：`低`
- 位置：`.github/workflows/e2e-test.yml:2`

工作流由 \`push\` 和 \`pull\_request\` 同时触发且没有 \`concurrency\` 控制，同一分支/PR 的连续提交会并发产生冗余运行并可能互相覆盖产物。建议添加 \`concurrency\` 分组，并在新提交到来时取消旧运行。

### 代码证据

```text
on: [push, pull_request]
```

### 修复建议

```text
on: [push, pull_request]

concurrency:
  group: e2e-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

## 236. 日期生成逻辑有误：\`today.getDay()\` 返回的是星期几（0-6）而非当月日期，导致 \`day\` 可能为 0（如 \`2026-10-00\`）且永远不会大于 15；\`today.getMonth()\` 是 0 基的且未 +1，会产生 \`00\` 月，并且模 12 后仅能生成 00-08 月。应改用 \`getDate()\`，并对月份做 +1 处理。

- 分类：`bug`
- 风险等级：`高`
- 位置：`app/data/user-dao.js:51-52`

日期生成逻辑有误：\`today.getDay()\` 返回的是星期几（0-6）而非当月日期，导致 \`day\` 可能为 0（如 \`2026-10-00\`）且永远不会大于 15；\`today.getMonth()\` 是 0 基的且未 +1，会产生 \`00\` 月，并且模 12 后仅能生成 00-08 月。应改用 \`getDate()\`，并对月份做 +1 处理。

### 代码证据

```text
const day = (Math.floor(Math.random() * 10) + today.getDay()) % 29;
        const month = (Math.floor(Math.random() * 10) + today.getMonth()) % 12;
```

### 修复建议

```text
const day = (Math.floor(Math.random() * 10) + today.getDate()) % 28 + 1;
        const month = (Math.floor(Math.random() * 10) + today.getMonth() + 1) % 12 + 1;
```

## 237. “Total Retirement Savings”金额 $89,925.12 是写死的静态值，任何用户打开仪表盘都会看到同一金额，属于数据正确性问题。应改为后端传入的变量（例如 {{ total\_retirement\_savings }}），并统一金额格式化逻辑。

- 分类：`bug`
- 风险等级：`高`
- 位置：`app/views/dashboard.html:40`

“Total Retirement Savings”金额 $89,925.12 是写死的静态值，任何用户打开仪表盘都会看到同一金额，属于数据正确性问题。应改为后端传入的变量（例如 {{ total\_retirement\_savings }}），并统一金额格式化逻辑。

### 代码证据

```text
&lt;p class="announcement-heading text-right"&gt;$89,925.12&lt;/p&gt;
```

### 修复建议

```text
&lt;p class="announcement-heading text-right"&gt;${{ total_retirement_savings }}&lt;/p&gt;
```

## 238. @-o-keyframes progress-bar-stripes 的 from/to 与标准 @keyframes 方向相反（此处为 0 0 → 40px 0，标准为 40px 0 → 0 0），会导致旧版 Opera 中条纹动画方向与其他浏览器不一致。建议调换 from/to 值以与标准实现保持一致。

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/assets/vendor/bootstrap/bootstrap.css:4281-4288`

@-o-keyframes progress-bar-stripes 的 from/to 与标准 @keyframes 方向相反（此处为 0 0 → 40px 0，标准为 40px 0 → 0 0），会导致旧版 Opera 中条纹动画方向与其他浏览器不一致。建议调换 from/to 值以与标准实现保持一致。

### 代码证据

```text
@-o-keyframes progress-bar-stripes {
  from {
    background-position: 0 0;
  }
  to {
    background-position: 40px 0;
  }
}
```

### 修复建议

```text
@-o-keyframes progress-bar-stripes {
  from {
    background-position: 40px 0;
  }
  to {
    background-position: 0 0;
  }
}
```

## 239. Popover 配置了 \`html: true\`，\`step.title\` 与 \`step.content\` 会作为原始 HTML 渲染。若 step 内容来自不可信输入（如 URL 参数、用户提交数据），存在 XSS 风险。建议对动态内容进行转义，或在确需富文本时对输入做白名单过滤/消毒。

- 分类：`安全`
- 风险等级：`低`
- 位置：`app/assets/vendor/bootstrap-tour.js`

Popover 配置了 \`html: true\`，\`step.title\` 与 \`step.content\` 会作为原始 HTML 渲染。若 step 内容来自不可信输入（如 URL 参数、用户提交数据），存在 XSS 风险。建议对动态内容进行转义，或在确需富文本时对输入做白名单过滤/消毒。

### 代码证据

```text
title: step.title,
        content: step.content,
        html: true,
```

## 240. “Required Retirement Income / Month”的 $20,600 为硬编码数值，无法对应当前登录用户的实际情况。应从后端传入变量（如 {{ required\_monthly\_income }}）进行渲染，避免所有用户看到相同的错误金额。

- 分类：`bug`
- 风险等级：`高`
- 位置：`app/views/dashboard.html:67`

“Required Retirement Income / Month”的 $20,600 为硬编码数值，无法对应当前登录用户的实际情况。应从后端传入变量（如 {{ required\_monthly\_income }}）进行渲染，避免所有用户看到相同的错误金额。

### 代码证据

```text
&lt;p class="announcement-heading text-right"&gt;$20,600&lt;/p&gt;
```

### 修复建议

```text
&lt;p class="announcement-heading text-right"&gt;${{ required_monthly_income }}&lt;/p&gt;
```

## 241. \`&lt;pre&gt;\` 属于流式内容（block-level），不能嵌套在只允许 phrasing content 的 \`&lt;p&gt;\` 元素内部。浏览器解析时会在 \`&lt;pre&gt;\` 前自动闭合 \`&lt;p&gt;\`，导致 \`&lt;pre&gt;\` 后面的说明文字脱离段落结构，可能造成样式和布局异常。建议将描述文字与代码块拆分为独立的 \`&lt;p&gt;\` 和 \`&lt;pre&gt;\` 元素。

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/views/tutorial/a10.html:32-34`

\`&lt;pre&gt;\` 属于流式内容（block-level），不能嵌套在只允许 phrasing content 的 \`&lt;p&gt;\` 元素内部。浏览器解析时会在 \`&lt;pre&gt;\` 前自动闭合 \`&lt;p&gt;\`，导致 \`&lt;pre&gt;\` 后面的说明文字脱离段落结构，可能造成样式和布局异常。建议将描述文字与代码块拆分为独立的 \`&lt;p&gt;\` 和 \`&lt;pre&gt;\` 元素。

### 代码证据

```text
&lt;p&gt;Here is code from
                    &lt;code&gt;routes/index.js&lt;/code&gt;,
                    &lt;pre&gt;
```

### 修复建议

```text
&lt;p&gt;Here is code from &lt;code&gt;routes/index.js&lt;/code&gt;,&lt;/p&gt;
                &lt;pre&gt;
```

## 242. 顶部注释说明“786px 及以上屏幕宽度使用媒体查询”，但实际断点写在 \`@media (min-width:768px)\`，两者不一致（786px vs 768px），容易误导后续维护者。建议将注释中的数值统一为 768px。

- 分类：`documentation`
- 风险等级：`低`
- 位置：`app/assets/vendor/theme/sb-admin.css:9`

顶部注释说明“786px 及以上屏幕宽度使用媒体查询”，但实际断点写在 \`@media (min-width:768px)\`，两者不一致（786px vs 768px），容易误导后续维护者。建议将注释中的数值统一为 768px。

### 代码证据

```text
/* ATTN: This is mobile first CSS - to update 786px and up screen width use the media query near the bottom of the document! */
```

### 修复建议

```text
/* ATTN: This is mobile first CSS - to update 768px and up screen width use the media query near the bottom of the document! */
```

## 243. 该表单是修改数据的 POST 请求，但缺少 \`\_csrf\` 隐藏字段（对比 \`profile.html\`、\`login.html\` 等表单均带有 \`\_csrf\`）。同时 \`server.js\` 中 CSRF 中间件被注释禁用，攻击者可在受害者登录状态下伪造跨站请求，篡改福利开始日期。建议在表单内加入 \`&lt;input type="hidden" name="\_csrf" value="{{csrft

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/views/benefits.html:54`

该表单是修改数据的 POST 请求，但缺少 \`\_csrf\` 隐藏字段（对比 \`profile.html\`、\`login.html\` 等表单均带有 \`\_csrf\`）。同时 \`server.js\` 中 CSRF 中间件被注释禁用，攻击者可在受害者登录状态下伪造跨站请求，篡改福利开始日期。建议在表单内加入 \`&lt;input type="hidden" name="\_csrf" value="{{csrftoken}}" /&gt;\`，并在服务端启用 CSRF 校验中间件。

### 代码证据

```text
&lt;form method="POST" action="/benefits"&gt;
```

### 修复建议

```text
&lt;form method="POST" action="/benefits"&gt;
                                &lt;input type="hidden" name="_csrf" value="{{csrftoken}}" /&gt;
```

## 244. 进入该分支时 \`user\` 一定是 \`null\`，因此错误信息会显示为 \`User: null does not exist\`，不利于排查问题。应使用 \`userName\` 拼接错误信息。

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/data/user-dao.js:84`

进入该分支时 \`user\` 一定是 \`null\`，因此错误信息会显示为 \`User: null does not exist\`，不利于排查问题。应使用 \`userName\` 拼接错误信息。

### 代码证据

```text
const noSuchUserError = new Error("User: " + user + " does not exist");
```

### 修复建议

```text
const noSuchUserError = new Error("User: " + userName + " does not exist");
```

## 245. Procfile 中不应使用 forever 托管进程。在 Heroku 等 PaaS 平台（或 Docker/systemd 环境）下，平台本身已经负责进程保活、崩溃重启与信号管理；再套一层 forever 会与平台的重启机制叠加，容易导致 SIGTERM 优雅退出处理、崩溃日志上报等行为异常，且 forever 并非为这类托管环境设计的进程管理器。建议让平台直接管理 server.js 进程。

- 分类：`可维护性`
- 风险等级：`高`
- 位置：`Procfile:1`

Procfile 中不应使用 forever 托管进程。在 Heroku 等 PaaS 平台（或 Docker/systemd 环境）下，平台本身已经负责进程保活、崩溃重启与信号管理；再套一层 forever 会与平台的重启机制叠加，容易导致 SIGTERM 优雅退出处理、崩溃日志上报等行为异常，且 forever 并非为这类托管环境设计的进程管理器。建议让平台直接管理 server.js 进程。

### 代码证据

```text
web: ./node_modules/.bin/forever -m 5 server.js
```

### 修复建议

```text
web: node server.js
```

## 246. 存在 XSS 风险：\`hoverContentForRow\` 将 \`r.label\` 和 \`this.yLabelFormat(i)\` 的结果直接拼接到 HTML 字符串中（\`t="&lt;div class='morris-hover-row-label'&gt;"+r.label+"&lt;/div&gt;"\`）。\`label\` 通常来自业务数据，未转义即渲染进 hover 浮层。建议在拼接前对 label 和格式化

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/assets/vendor/chart/morris-0.4.3.min.js`

存在 XSS 风险：\`hoverContentForRow\` 将 \`r.label\` 和 \`this.yLabelFormat(i)\` 的结果直接拼接到 HTML 字符串中（\`t="&lt;div class='morris-hover-row-label'&gt;"+r.label+"&lt;/div&gt;"\`）。\`label\` 通常来自业务数据，未转义即渲染进 hover 浮层。建议在拼接前对 label 和格式化值调用统一的 HTML 转义函数，避免用户输入被当作 HTML 执行。

### 代码证据

```text
n.prototype.hoverContentForRow=function(e){var t,n,r,i,s,o,u;r=this.data[e],t="&lt;div class='morris-hover-row-label'&gt;"+r.label+"&lt;/div&gt;",u=r.y;
```

## 247. 该链接使用了 \`target="\_blank"\` 但未添加 \`rel="noopener noreferrer"\`，新页面可通过 \`window.opener\` 重定向或控制当前登录页（反向标签劫持）。本文件中的其他 \`target="\_blank"\` 链接（如 OWASP Top 10 链接）也建议一并补充该属性。

- 分类：`安全`
- 风险等级：`低`
- 位置：`app/views/login.html:79`

该链接使用了 \`target="\_blank"\` 但未添加 \`rel="noopener noreferrer"\`，新页面可通过 \`window.opener\` 重定向或控制当前登录页（反向标签劫持）。本文件中的其他 \`target="\_blank"\` 链接（如 OWASP Top 10 链接）也建议一并补充该属性。

### 代码证据

```text
&lt;a href="/tutorial" target="_blank"&gt; &lt;b&gt;&lt;span class="fa fa-book"&gt;&lt;/span&gt; Tutorial Guide:&lt;/b&gt; Learn OWASP Top 10
```

### 修复建议

```text
&lt;a href="/tutorial" target="_blank" rel="noopener noreferrer"&gt; &lt;b&gt;&lt;span class="fa fa-book"&gt;&lt;/span&gt; Tutorial Guide:&lt;/b&gt; Learn OWASP Top 10
```

## 248. \`curly\` 取值为 \`false\` 表示不强制为每个 block/scope 添加 \`{}\`，与注释「Require {} for every new block or scope.」相反。\`false\` 会放行容易出错的单行块；若意图是强制花括号，应改为 \`true\`。

- 分类：`bug`
- 风险等级：`中`
- 位置：`.jshintrc:7`

\`curly\` 取值为 \`false\` 表示不强制为每个 block/scope 添加 \`{}\`，与注释「Require {} for every new block or scope.」相反。\`false\` 会放行容易出错的单行块；若意图是强制花括号，应改为 \`true\`。

### 代码证据

```text
"curly": false, // Require {} for every new block or scope.
```

### 修复建议

```text
"curly": true, // Require {} for every new block or scope.
```

## 249. 下方三个统计面板中的 &lt;a href="\#"&gt; 是空链接且内部 panel-footer 无任何内容，属于无效交互元素，容易误导用户点击。建议移除这些 &lt;a&gt; 包裹，或补充真实的目标地址与可点击内容。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/views/dashboard.html:72-76`

下方三个统计面板中的 &lt;a href="\#"&gt; 是空链接且内部 panel-footer 无任何内容，属于无效交互元素，容易误导用户点击。建议移除这些 &lt;a&gt; 包裹，或补充真实的目标地址与可点击内容。

### 代码证据

```text
&lt;a href="#"&gt;
                &lt;div class="panel-footer announcement-bottom"&gt;

                &lt;/div&gt;
            &lt;/a&gt;
```

## 250. 缺少空值检查：\`updateUser\` 回调在 \`err\` 为空时，\`user\` 仍可能为 \`null\`/\`undefined\`，访问 \`user.updateSuccess\` 会抛出 TypeError。建议在渲染前对 \`user\` 判空。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/routes/profile.js:97-98`

缺少空值检查：\`updateUser\` 回调在 \`err\` 为空时，\`user\` 仍可能为 \`null\`/\`undefined\`，访问 \`user.updateSuccess\` 会抛出 TypeError。建议在渲染前对 \`user\` 判空。

### 代码证据

```text
user.updateSuccess = true;
                user.userId = userId;
```

### 修复建议

```text
if (!user) {
                    return next(new Error("更新用户失败"));
                }

                user.updateSuccess = true;
                user.userId = userId;
```

## 251. \`&lt;ol&gt;\` 是块级元素，不能嵌套在 \`&lt;p&gt;\` 内部；浏览器会在 \`&lt;ol&gt;\` 前自动闭合 \`&lt;p&gt;\`，且 \`&lt;/ol&gt;\` 之后的“There were no additional contexts...”文字也缺少闭合标签，导致 HTML 结构混乱。建议先闭合说明用的 \`&lt;p&gt;\`，再放置 \`&lt;ol&gt;\`，结尾文字单独使用一个 \`&lt;p&gt;\`。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/views/tutorial/a3.html:159-161`

\`&lt;ol&gt;\` 是块级元素，不能嵌套在 \`&lt;p&gt;\` 内部；浏览器会在 \`&lt;ol&gt;\` 前自动闭合 \`&lt;p&gt;\`，且 \`&lt;/ol&gt;\` 之后的“There were no additional contexts...”文字也缺少闭合标签，导致 HTML 结构混乱。建议先闭合说明用的 \`&lt;p&gt;\`，再放置 \`&lt;ol&gt;\`，结尾文字单独使用一个 \`&lt;p&gt;\`。

### 代码证据

```text
&lt;p&gt;Two measures can be taken to mitigate XSS risk:

                    &lt;ol&gt;
```

### 修复建议

```text
&lt;p&gt;Two measures can be taken to mitigate XSS risk:&lt;/p&gt;

                    &lt;ol&gt;
```

## 252. \`bcrypt\` 已引入但当前代码并未使用（哈希逻辑被注释掉），属于未使用的依赖/死代码。应启用哈希逻辑，或移除该引入。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/data/user-dao.js:1`

\`bcrypt\` 已引入但当前代码并未使用（哈希逻辑被注释掉），属于未使用的依赖/死代码。应启用哈希逻辑，或移除该引入。

### 代码证据

```text
const bcrypt = require("bcrypt-nodejs");
```

## 253. \`&lt;pre&gt;\` 不能嵌套在 \`&lt;p&gt;\` 内部（HTML 规范中 \`&lt;p&gt;\` 遇到块级元素会被浏览器自动闭合），当前写法会导致 \`&lt;p&gt;\` 被提前闭合、结构错乱。请将 \`&lt;pre&gt;\` 移到 \`&lt;p&gt;\` 之外。本文件内多处存在同样问题（如“File System Access”、“Source Code Example”以及 Log Injection 部分）。

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/views/tutorial/a1.html:90-93`

\`&lt;pre&gt;\` 不能嵌套在 \`&lt;p&gt;\` 内部（HTML 规范中 \`&lt;p&gt;\` 遇到块级元素会被浏览器自动闭合），当前写法会导致 \`&lt;p&gt;\` 被提前闭合、结构错乱。请将 \`&lt;pre&gt;\` 移到 \`&lt;p&gt;\` 之外。本文件内多处存在同样问题（如“File System Access”、“Source Code Example”以及 Log Injection 部分）。

### 代码证据

```text
&lt;p&gt;
                            An alternative DoS attack would be to simply exit or kill the running process:
                            &lt;pre&gt;process.exit()&lt;/pre&gt; or &lt;pre&gt;process.kill(process.pid) &lt;/pre&gt;
                        &lt;/p&gt;
```

### 修复建议

```text
&lt;p&gt;An alternative DoS attack would be to simply exit or kill the running process:&lt;/p&gt;
                        &lt;pre&gt;process.exit()&lt;/pre&gt; or &lt;pre&gt;process.kill(process.pid)&lt;/pre&gt;
```

## 254. 依赖 \`marked\` 0.3.5 的 \`sanitize: true\` 对 Markdown 输出做清洗：该选项基于不完整的正则清洗，存在已知 XSS 绕过风险，且在新版 marked 中已被废弃/移除。建议升级依赖，并在渲染输出后使用 DOMPurify 等可信的 HTML 消毒库进行二次清洗。

- 分类：`安全`
- 风险等级：`中`
- 位置：`server.js:126-128`

依赖 \`marked\` 0.3.5 的 \`sanitize: true\` 对 Markdown 输出做清洗：该选项基于不完整的正则清洗，存在已知 XSS 绕过风险，且在新版 marked 中已被废弃/移除。建议升级依赖，并在渲染输出后使用 DOMPurify 等可信的 HTML 消毒库进行二次清洗。

### 代码证据

```text
marked.setOptions({
        sanitize: true
    });
```

### 修复建议

```text
marked.setOptions({
        sanitize: true
    });
    // 渲染结果应再经过 DOMPurify 等可信消毒库处理后再输出
```

## 255. 30% 是业务规则中的魔法数字，且错误提示里还重复出现了“30 %”，两处容易不一致。建议提取为命名常量（如 \`const MAX\_CONTRIBUTION\_PERCENT = 30;\`）并统一引用。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/routes/contributions.js:57`

30% 是业务规则中的魔法数字，且错误提示里还重复出现了“30 %”，两处容易不一致。建议提取为命名常量（如 \`const MAX\_CONTRIBUTION\_PERCENT = 30;\`）并统一引用。

### 代码证据

```text
if (preTax + afterTax + roth &gt; 30) {
```

### 修复建议

```text
if (preTax + afterTax + roth &gt; MAX_CONTRIBUTION_PERCENT) {
```

## 256. \`unused\` 为 \`false\` 时不会对未使用变量发出告警，与注释「Warn unused variables.」相反。如需启用该检查，应改为 \`true\`（或 \`"vars"\`/\`"strict"\`）；否则请修正注释。

- 分类：`bug`
- 风险等级：`低`
- 位置：`.jshintrc:16`

\`unused\` 为 \`false\` 时不会对未使用变量发出告警，与注释「Warn unused variables.」相反。如需启用该检查，应改为 \`true\`（或 \`"vars"\`/\`"strict"\`）；否则请修正注释。

### 代码证据

```text
"unused": false, // Warn unused variables.
```

### 修复建议

```text
"unused": true, // Warn unused variables.
```

## 257. \`environmentalScripts\` 中的内联脚本使用了 \`document.write\` 动态注入 \`&lt;script&gt;\` 标签，这是被明确禁止的危险方法：它会触发页面重排/重绘并破坏已有 DOM，且将 \`location.host\` 直接拼接进脚本 URL 存在脚本注入/XSS 风险。建议改用 DOM API 创建 script 元素后追加（如 \`document.createEleme

- 分类：`安全`
- 风险等级：`中`
- 位置：`config/env/development.js:11`

\`environmentalScripts\` 中的内联脚本使用了 \`document.write\` 动态注入 \`&lt;script&gt;\` 标签，这是被明确禁止的危险方法：它会触发页面重排/重绘并破坏已有 DOM，且将 \`location.host\` 直接拼接进脚本 URL 存在脚本注入/XSS 风险。建议改用 DOM API 创建 script 元素后追加（如 \`document.createElement('script')\` 配合 \`appendChild\`），或改为引用静态脚本文件。

### 代码证据

```text
`&lt;script&gt;document.write("&lt;script src='http://" + (location.host || "localhost").split(":")[0] + ":35729/livereload.js'&gt;&lt;/" + "script&gt;");&lt;/script&gt;`
```

### 修复建议

```text
`&lt;script&gt;(function(){var s=document.createElement('script');s.src='http://'+(location.host||'localhost').split(':')[0]+':35729/livereload.js';document.body.appendChild(s);}());&lt;/script&gt;`
```

## 258. 工作流未声明 \`permissions\`，GitHub 默认会授予 \`GITHUB\_TOKEN\` 较大的写权限；本工作流只执行静态检查，无需写权限。建议在作业或工作流层级显式最小化权限，例如 \`permissions:   contents: read\`。

- 分类：`安全`
- 风险等级：`中`
- 位置：`.github/workflows/lint.yml:4-7`

工作流未声明 \`permissions\`，GitHub 默认会授予 \`GITHUB\_TOKEN\` 较大的写权限；本工作流只执行静态检查，无需写权限。建议在作业或工作流层级显式最小化权限，例如 \`permissions:
  contents: read\`。

### 代码证据

```text
jobs:
  lint:
    name: Node.js
    runs-on: ubuntu-latest
```

### 修复建议

```text
jobs:
  lint:
    name: Node.js
    runs-on: ubuntu-latest
    permissions:
      contents: read
```

## 259. 镜像缺少 \`CMD\`/\`ENTRYPOINT\`，运行容器时会继承基础镜像 \`node:12-alpine\` 的默认命令（启动 \`node\` REPL），应用不会自动启动。请补充启动命令，例如 \`CMD \["npm", "start"\]\` 或 \`CMD \["node", "server.js"\]\`（取决于实际入口文件）。

- 分类：`bug`
- 风险等级：`高`
- 位置：`Dockerfile:17-18`

镜像缺少 \`CMD\`/\`ENTRYPOINT\`，运行容器时会继承基础镜像 \`node:12-alpine\` 的默认命令（启动 \`node\` REPL），应用不会自动启动。请补充启动命令，例如 \`CMD \["npm", "start"\]\` 或 \`CMD \["node", "server.js"\]\`（取决于实际入口文件）。

### 代码证据

```text
USER $USER
EXPOSE 4000
```

### 修复建议

```text
USER $USER
EXPOSE 4000
CMD ["npm", "start"]
```

## 260. 错误提示的显示条件判断的是 \`updateError\`，但输出的是 \`data.updateError\`，两者不一致；且当前 handler 渲染时并未传入 \`data\` 对象（只传了 \`updateSuccess\`），因此该错误提示无法正确展示内容。建议统一变量，例如判断与输出都使用 \`updateError\`，或都使用 \`data.updateError\`。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/views/benefits.html:20`

错误提示的显示条件判断的是 \`updateError\`，但输出的是 \`data.updateError\`，两者不一致；且当前 handler 渲染时并未传入 \`data\` 对象（只传了 \`updateSuccess\`），因此该错误提示无法正确展示内容。建议统一变量，例如判断与输出都使用 \`updateError\`，或都使用 \`data.updateError\`。

### 代码证据

```text
{{data.updateError}}
```

### 修复建议

```text
{{updateError}}
```

## 261. \`getState\` 调用 \`afterGetState(key, value)\` 时传入的是原始 \`key\`，而 \`setState\`/\`removeState\` 分别传入带 \`name\_\` 前缀的 \`keyName\`，回调参数约定不一致。依赖该回调匹配存储项 key 的使用方可能拿到错误的值。建议统一传 \`keyName\`（或至少在文档中明确两者差异）。

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/assets/vendor/bootstrap-tour.js`

\`getState\` 调用 \`afterGetState(key, value)\` 时传入的是原始 \`key\`，而 \`setState\`/\`removeState\` 分别传入带 \`name\_\` 前缀的 \`keyName\`，回调参数约定不一致。依赖该回调匹配存储项 key 的使用方可能拿到错误的值。建议统一传 \`keyName\`（或至少在文档中明确两者差异）。

### 代码证据

```text
this._options.afterGetState(key, value);
```

### 修复建议

```text
this._options.afterGetState(keyName, value);
```

## 262. 示例代码片段缺少 \`needle.get(...)\` 回调函数及调用本身的闭合 \`});\`，作为 \`routes/research.js\` 的代码片段展示时是不完整的 JavaScript，容易误导学习者。建议补全闭合括号，或明确标注该片段为伪代码。

- 分类：`documentation`
- 风险等级：`低`
- 位置：`app/views/tutorial/ssrf.html:30`

示例代码片段缺少 \`needle.get(...)\` 回调函数及调用本身的闭合 \`});\`，作为 \`routes/research.js\` 的代码片段展示时是不完整的 JavaScript，容易误导学习者。建议补全闭合括号，或明确标注该片段为伪代码。

### 代码证据

```text
needle.get(url, function(error, newResponse) { ... }
```

### 修复建议

```text
needle.get(url, function (error, newResponse) {
            // ...
        });
```

## 263. searchCriteria 函数在 symbol 为假值（如 undefined、空字符串）时没有返回值（隐式返回 undefined），并且该函数声明后从未被调用，属于死代码。建议删除该函数，或在 getBySymbol 中实际调用它并根据 symbol 的合法性进行处理。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/data/research-dao.js:15-23`

searchCriteria 函数在 symbol 为假值（如 undefined、空字符串）时没有返回值（隐式返回 undefined），并且该函数声明后从未被调用，属于死代码。建议删除该函数，或在 getBySymbol 中实际调用它并根据 symbol 的合法性进行处理。

### 代码证据

```text
const searchCriteria = () =&gt; {

            if (symbol) {
                console.log("in if symbol");
                return {
                    symbol
                };
            }
        };
```

## 264. VML 文本转义顺序有误：先替换 \`&lt;\` 为 \`&amp;\#60;\`，再替换 \`&amp;\` 为 \`&amp;\#38;\`，会把刚生成的 \`&amp;\#60;\` 中的 \`&amp;\` 再次替换，最终把含 \`&lt;\` 的文本渲染为字面量 \`&amp;\#60;\`（双重转义显示异常）。正确顺序应先转义 \`&amp;\`，再转义 \`&lt;\`。

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/assets/vendor/chart/raphael-min.js`

VML 文本转义顺序有误：先替换 \`&lt;\` 为 \`&amp;\#60;\`，再替换 \`&amp;\` 为 \`&amp;\#38;\`，会把刚生成的 \`&amp;\#60;\` 中的 \`&amp;\` 再次替换，最终把含 \`&lt;\` 的文本渲染为字面量 \`&amp;\#60;\`（双重转义显示异常）。正确顺序应先转义 \`&amp;\`，再转义 \`&lt;\`。

### 代码证据

```text
X.innerHTML=c(t.textpath.string).replace(/&lt;/g,"&amp;#60;").replace(/&amp;/g,"&amp;#38;").replace(/\n/g,"&lt;br&gt;");
```

### 修复建议

```text
X.innerHTML=c(t.textpath.string).replace(/&amp;/g,"&amp;#38;").replace(/&lt;/g,"&amp;#60;").replace(/\n/g,"&lt;br&gt;");
```

## 265. 登出是状态变更操作，但这里通过 GET 链接（\`href="/logout"\`）触发，既容易受登出 CSRF 影响，也不符合 HTTP 语义。建议改为 POST 表单并携带 CSRF token（下拉菜单中的 \`/logout\` 链接同样需要处理）。

- 分类：`安全`
- 风险等级：`低`
- 位置：`app/views/layout.html:67`

登出是状态变更操作，但这里通过 GET 链接（\`href="/logout"\`）触发，既容易受登出 CSRF 影响，也不符合 HTTP 语义。建议改为 POST 表单并携带 CSRF token（下拉菜单中的 \`/logout\` 链接同样需要处理）。

### 代码证据

```text
&lt;li&gt;&lt;a id="logout-menu-link" href="/logout"&gt;&lt;i class="fa fa-power-off"&gt;&lt;/i&gt; Logout&lt;/a&gt;
```

## 266. 三个输入框的 value 被硬编码为 "0"，未预填当前缴费比例。用户打开页面后即使只修改其中一个字段，未修改的字段也会以 0 提交，从而意外将其他缴费比例清零，属于数据完整性/正确性风险。建议用当前值预填（\`value="{{ preTax }}"\`，roth、afterTax 同理），并优先使用 \`type="number"\`（配合 min/step）限制输入，避免提交非法字符。

- 分类：`bug`
- 风险等级：`高`
- 位置：`app/views/contributions.html:67`

三个输入框的 value 被硬编码为 "0"，未预填当前缴费比例。用户打开页面后即使只修改其中一个字段，未修改的字段也会以 0 提交，从而意外将其他缴费比例清零，属于数据完整性/正确性风险。建议用当前值预填（\`value="{{ preTax }}"\`，roth、afterTax 同理），并优先使用 \`type="number"\`（配合 min/step）限制输入，避免提交非法字符。

### 代码证据

```text
&lt;input type="text" name="preTax" value="0"&gt;&lt;/input&gt;
```

### 修复建议

```text
&lt;input type="number" name="preTax" value="{{ preTax }}" min="0" max="100" step="0.01"&gt;
```

## 267. a1 到 a10 共 10 个用例逻辑完全相同，仅路径参数不同，属于明显的重复代码，维护时需同步修改 10 处。建议提取为数据驱动写法（如 \`const paths = \['a1', ..., 'a10'\]; paths.forEach(p =&gt; { it(\\\`Should exist /tutorial/${p}\\\`, () =&gt; { ... }) })\`），并同时将硬编码的 URL 路径集中为

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/e2e/integration/tutorial\_spec.js:20-23`

a1 到 a10 共 10 个用例逻辑完全相同，仅路径参数不同，属于明显的重复代码，维护时需同步修改 10 处。建议提取为数据驱动写法（如 \`const paths = \['a1', ..., 'a10'\]; paths.forEach(p =&gt; { it(\\\`Should exist /tutorial/${p}\\\`, () =&gt; { ... }) })\`），并同时将硬编码的 URL 路径集中为常量，避免路径散落各处。

### 代码证据

```text
it("Should exists /tutorial/a2", () =&gt; {
    cy.visitPage("/tutorial/a2");
    cy.url().should("include", "a2");
  });
```

## 268. \`Collection.insert\` 在 MongoDB Node.js 驱动 3.x 中已被废弃，建议改用 \`insertOne\`，避免后续升级驱动后接口被移除导致运行时报错。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/data/memos-dao.js:23`

\`Collection.insert\` 在 MongoDB Node.js 驱动 3.x 中已被废弃，建议改用 \`insertOne\`，避免后续升级驱动后接口被移除导致运行时报错。

### 代码证据

```text
memosCol.insert(memos, (err, result) =&gt; !err ? callback(null, result) : callback(err, null));
```

### 修复建议

```text
memosCol.insertOne(memos, (err, result) =&gt; !err ? callback(null, result) : callback(err, null));
```

## 269. 当浏览器不提供原生 JSON.parse 时，parseJSON 回退使用 Function("return "+n)() 解析 JSON，等价于 eval。若被解析的 JSON 来自不可信输入（例如通过 ajax dataType:'json' 接收的响应），存在代码注入风险。该回退逻辑来自旧版 jQuery，无法在此处安全修复，建议升级 jQuery 3.x 移除该路径，并确保业务代码不向 p

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/assets/vendor/jquery.min.js`

当浏览器不提供原生 JSON.parse 时，parseJSON 回退使用 Function("return "+n)() 解析 JSON，等价于 eval。若被解析的 JSON 来自不可信输入（例如通过 ajax dataType:'json' 接收的响应），存在代码注入风险。该回退逻辑来自旧版 jQuery，无法在此处安全修复，建议升级 jQuery 3.x 移除该路径，并确保业务代码不向 parseJSON 传入不可信字符串。

### 代码证据

```text
Function("return "+n)()
```

## 270. \`&lt;pre&gt;\` 以及后续的 \`&lt;h3&gt;\` 不能嵌套在 \`&lt;p&gt;\` 内：HTML 解析器遇到块级元素会隐式关闭 \`&lt;p&gt;\`，导致 \`&lt;/p&gt;\` 缺失/孤立，产生非法 DOM，并可能影响折叠面板内容的渲染与可访问性。建议先闭合 \`&lt;p&gt;\`，再把 \`&lt;pre&gt;\`、说明文本和 \`&lt;h3&gt;\` 移出段落。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/views/tutorial/a2.html:161-163`

\`&lt;pre&gt;\` 以及后续的 \`&lt;h3&gt;\` 不能嵌套在 \`&lt;p&gt;\` 内：HTML 解析器遇到块级元素会隐式关闭 \`&lt;p&gt;\`，导致 \`&lt;/p&gt;\` 缺失/孤立，产生非法 DOM，并可能影响折叠面板内容的渲染与可访问性。建议先闭合 \`&lt;p&gt;\`，再把 \`&lt;pre&gt;\`、说明文本和 \`&lt;h3&gt;\` 移出段落。

### 代码证据

```text
&lt;p&gt;
                            3. When user clicks logout, destroy the session and session cookie
                            &lt;pre&gt;
```

### 修复建议

```text
&lt;p&gt;
                            3. When user clicks logout, destroy the session and session cookie
                        &lt;/p&gt;
                        &lt;pre&gt;
```

## 271. 存在竞态：\`numberOfAlerts\` 只在 \`status()\` 内嵌的 \`zaproxy.core.numberOfAlerts\` 异步回调中被赋值，而 \`activeScanDone\` 在 \`htmlreport\` 写完后立即触发 \`onCompletion\`，两者没有同步关系。断言执行时 \`numberOfAlerts\` 可能还是旧的告警数，甚至是未初始化的 \`undefined\`，导

- 分类：`bug`
- 风险等级：`高`
- 位置：`test/security/profile-test.js:125`

存在竞态：\`numberOfAlerts\` 只在 \`status()\` 内嵌的 \`zaproxy.core.numberOfAlerts\` 异步回调中被赋值，而 \`activeScanDone\` 在 \`htmlreport\` 写完后立即触发 \`onCompletion\`，两者没有同步关系。断言执行时 \`numberOfAlerts\` 可能还是旧的告警数，甚至是未初始化的 \`undefined\`，导致误判或 \`TypeError\`。建议把最终断言放进 \`numberOfAlerts\` 回调内，或用 Promise/\`await\` 等机制确保拿到最终值后再断言。

### 代码证据

```text
numberOfAlerts.should.be.lessThanOrEqual(alertThreshold);
```

### 修复建议

```text
if (numberOfAlerts === undefined) return done(new Error("numberOfAlerts was not initialized"));
            numberOfAlerts.should.be.lessThanOrEqual(alertThreshold);
```

## 272. 校验失败时 errors 对象只回填 userName 和 email，firstName、lastName 未回填，导致 signup 表单出错时丢失用户已填写的内容。建议将 firstName、lastName 一并放入 errors 对象回传。

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/routes/session.js:201-204`

校验失败时 errors 对象只回填 userName 和 email，firstName、lastName 未回填，导致 signup 表单出错时丢失用户已填写的内容。建议将 firstName、lastName 一并放入 errors 对象回传。

### 代码证据

```text
const errors = {
            "userName": userName,
            "email": email
        };
```

### 修复建议

```text
const errors = {
            "userName": userName,
            "email": email,
            "firstName": firstName,
            "lastName": lastName
        };
```

## 273. \`util.inspect(config, false, null)\` 会递归打印完整配置对象，若配置中包含 API key、数据库密码、第三方密钥等敏感信息，会被明文输出到日志，存在敏感信息泄露风险。建议对敏感字段脱敏后再输出，或仅在明确开启 debug/非生产环境下才打印完整配置。

- 分类：`安全`
- 风险等级：`高`
- 位置：`config/config.js:12-13`

\`util.inspect(config, false, null)\` 会递归打印完整配置对象，若配置中包含 API key、数据库密码、第三方密钥等敏感信息，会被明文输出到日志，存在敏感信息泄露风险。建议对敏感字段脱敏后再输出，或仅在明确开启 debug/非生产环境下才打印完整配置。

### 代码证据

```text
console.log(`Current Config:`);
console.log(util.inspect(config, false, null));
```

## 274. 该文件打包的是 Raphaël 2.1.0（2012 年发布），该版本已停止维护，且存在公开披露的 XSS 安全公告（例如通过 href/src 等属性注入 javascript: 协议）。建议升级到官方最新版本或安全修复版本，而不是继续使用此旧版本。

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/assets/vendor/chart/raphael-min.js`

该文件打包的是 Raphaël 2.1.0（2012 年发布），该版本已停止维护，且存在公开披露的 XSS 安全公告（例如通过 href/src 等属性注入 javascript: 协议）。建议升级到官方最新版本或安全修复版本，而不是继续使用此旧版本。

### 代码证据

```text
a.version="2.1.0",a.eve=eve;
```

## 275. 该用例描述为“在另一个标签页中打开教程”，但实际通过 \`cy.visit(href)\` 在当前标签页导航并断言 \`cy.url()\`，并未真正验证新标签页打开的行为；同时前面的用例已校验过 \`target="\_blank"\`。此断言与用例意图不符，无法捕获链接新标签页行为回归。建议改为断言链接的 \`href\`/\`target\` 属性，或使用 \`cy.window()\` 移除 \`target\` 后再

- 分类：`bug`
- 风险等级：`中`
- 位置：`test/e2e/integration/login\_spec.js:26-29`

该用例描述为“在另一个标签页中打开教程”，但实际通过 \`cy.visit(href)\` 在当前标签页导航并断言 \`cy.url()\`，并未真正验证新标签页打开的行为；同时前面的用例已校验过 \`target="\_blank"\`。此断言与用例意图不符，无法捕获链接新标签页行为回归。建议改为断言链接的 \`href\`/\`target\` 属性，或使用 \`cy.window()\` 移除 \`target\` 后再验证同页跳转，避免测试意图与断言不一致。

### 代码证据

```text
const href =
      $a.prop("href");
      cy.visit(href);
      cy.url().should("include", "tutorial");
```

### 修复建议

```text
cy.wrap($a).should("have.attr", "href").and("include", "tutorial");
      cy.wrap($a).invoke("removeAttr", "target").click();
      cy.url().should("include", "tutorial");
```

## 276. 图表数据（\`balance\` 业务数值）全部硬编码在脚本中，且日期由 \`new Date().getFullYear()\` 动态拼装，属于一次性演示数据：随时间推移图表内容会整体偏移，也无法反映真实业务数据。建议改为从接口获取数据，或至少将数据抽离到独立的配置/数据源文件中，便于维护和替换。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/assets/js/chart/chart-data-morris.js:15`

图表数据（\`balance\` 业务数值）全部硬编码在脚本中，且日期由 \`new Date().getFullYear()\` 动态拼装，属于一次性演示数据：随时间推移图表内容会整体偏移，也无法反映真实业务数据。建议改为从接口获取数据，或至少将数据抽离到独立的配置/数据源文件中，便于维护和替换。

### 代码证据

```text
data: [{
```

## 277. 教程中的源码示例与当前 \`app/routes/allocations.js\` 实际实现不一致：现在实际调用的是 \`allocationsDAO.getByUserIdAndThreshold(userId, threshold, ...)\`，且 \`res.render\` 传入的是 \`{ userId, allocations, environmentalScripts }\` 对象。示例中 \`re

- 分类：`documentation`
- 风险等级：`中`
- 位置：`app/views/tutorial/a4.html:63-69`

教程中的源码示例与当前 \`app/routes/allocations.js\` 实际实现不一致：现在实际调用的是 \`allocationsDAO.getByUserIdAndThreshold(userId, threshold, ...)\`，且 \`res.render\` 传入的是 \`{ userId, allocations, environmentalScripts }\` 对象。示例中 \`res.render("allocations", allocations)\` 直接把 \`allocations\`（可能是数组）作为 locals 传入，不符合 Express \`res.render(view, locals)\` 的约定，学习者照抄可能导致模板渲染异常。建议同步更新示例代码并展示正确的对象传参。

### 代码证据

```text
var userId = req.params.userId;
    allocationsDAO.getByUserId(userId, function(error, allocations) {

        if (error) return next(error);

        return res.render("allocations", allocations);
    });
```

### 修复建议

```text
const { userId } = req.params;
    allocationsDAO.getByUserIdAndThreshold(userId, threshold, (err, allocations) =&gt; {
        if (err) return next(err);
        return res.render("allocations", { userId, allocations });
    });
```

## 278. \`&lt;pre&gt;\` 是块级元素，不能作为 \`&lt;p&gt;\` 的子元素。浏览器解析时会在 \`&lt;pre&gt;\` 之前隐式闭合 \`&lt;p&gt;\`，后续的 \`&lt;/p&gt;\` 会成为孤立结束标签，导致 HTML 结构无效，可能影响样式和后续内容渲染。建议先闭合 \`&lt;p&gt;\`，再将 \`&lt;pre&gt;\` 作为独立块级元素放置。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/views/tutorial/a3.html:135`

\`&lt;pre&gt;\` 是块级元素，不能作为 \`&lt;p&gt;\` 的子元素。浏览器解析时会在 \`&lt;pre&gt;\` 之前隐式闭合 \`&lt;p&gt;\`，后续的 \`&lt;/p&gt;\` 会成为孤立结束标签，导致 HTML 结构无效，可能影响样式和后续内容渲染。建议先闭合 \`&lt;p&gt;\`，再将 \`&lt;pre&gt;\` 作为独立块级元素放置。

### 代码证据

```text
&lt;pre&gt;Content-Security-Policy: default-src 'self' *.mydomain.com&lt;/pre&gt;
```

### 修复建议

```text
&lt;/p&gt;
                        &lt;pre&gt;Content-Security-Policy: default-src 'self' *.mydomain.com&lt;/pre&gt;
```

## 279. \`&lt;ul&gt;\` 不能作为 \`&lt;p&gt;\` 的子元素：HTML 解析器会在 \`&lt;ul&gt;\` 前隐式关闭 \`&lt;p&gt;\`，使文档结构非法并产生孤立标签。建议移除包裹列表的空 \`&lt;p&gt;\`，或将容器改为 \`&lt;div&gt;\`。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/views/tutorial/a2.html:276-277`

\`&lt;ul&gt;\` 不能作为 \`&lt;p&gt;\` 的子元素：HTML 解析器会在 \`&lt;ul&gt;\` 前隐式关闭 \`&lt;p&gt;\`，使文档结构非法并产生孤立标签。建议移除包裹列表的空 \`&lt;p&gt;\`，或将容器改为 \`&lt;div&gt;\`。

### 代码证据

```text
&lt;p&gt;
                            &lt;ul&gt;
```

### 修复建议

```text
&lt;ul&gt;
```

## 280. 该用例名称为“Should not redirect if the user has logged in”（用户已登录时不应跳转），但用例体内并未执行任何登录操作，与上一个未登录场景的用例完全重复，导致“已登录用户访问 /signup”的场景实际未被覆盖。建议先用已知用户执行 cy.signIn 登录后再访问 /signup 进行断言；若本意只是验证未登录场景，则应修正用例名称以免误导。

- 分类：`bug`
- 风险等级：`中`
- 位置：`test/e2e/integration/signup\_spec.js:19-22`

该用例名称为“Should not redirect if the user has logged in”（用户已登录时不应跳转），但用例体内并未执行任何登录操作，与上一个未登录场景的用例完全重复，导致“已登录用户访问 /signup”的场景实际未被覆盖。建议先用已知用户执行 cy.signIn 登录后再访问 /signup 进行断言；若本意只是验证未登录场景，则应修正用例名称以免误导。

### 代码证据

```text
it("Should not redirect if the user has logged in", () =&gt; {
    cy.visitPage("/signup");
    cy.url().should("include", "signup");
  });
```

## 281. getUserById 在用户不存在时可能返回 null，此处未做判空直接访问 doc.userId 会抛出 TypeError 导致 500。建议先判空并处理（如重定向到 /login 或返回错误）。

- 分类：`bug`
- 风险等级：`高`
- 位置：`app/routes/session.js:268`

getUserById 在用户不存在时可能返回 null，此处未做判空直接访问 doc.userId 会抛出 TypeError 导致 500。建议先判空并处理（如重定向到 /login 或返回错误）。

### 代码证据

```text
doc.userId = userId;
```

### 修复建议

```text
if (!doc) {
                return res.redirect("/login");
            }
            doc.userId = userId;
```

## 282. swig 模板引擎显式关闭了自动转义（\`autoescape: false\`）。用户可控数据（如用户名、评论等）渲染到模板时会被当作原始 HTML 输出，导致存储型/反射型 XSS。建议恢复默认值 \`autoescape: true\`，或对不可信变量显式使用 \`| escape\` 过滤器。

- 分类：`安全`
- 风险等级：`严重`
- 位置：`server.js:135-137`

swig 模板引擎显式关闭了自动转义（\`autoescape: false\`）。用户可控数据（如用户名、评论等）渲染到模板时会被当作原始 HTML 输出，导致存储型/反射型 XSS。建议恢复默认值 \`autoescape: true\`，或对不可信变量显式使用 \`| escape\` 过滤器。

### 代码证据

```text
swig.setDefaults({
        // Autoescape disabled
        autoescape: false
```

### 修复建议

```text
swig.setDefaults({
        // 开启自动转义，防止 XSS
        autoescape: true
```

## 283. addUser 回调返回的 user 文档包含 password 字段（且为明文存储，见 user-dao.js），此处使用 ...user 展开后传入 dashboard 渲染上下文，可能将密码暴露给视图/模板，后续任何模板改动都可能泄露敏感信息。建议显式挑选需要渲染的字段，避免展开整个用户对象；displayWelcomePage 中的 ...doc 也存在同样风险。

- 分类：`安全`
- 风险等级：`高`
- 位置：`app/routes/session.js:239-242`

addUser 回调返回的 user 文档包含 password 字段（且为明文存储，见 user-dao.js），此处使用 ...user 展开后传入 dashboard 渲染上下文，可能将密码暴露给视图/模板，后续任何模板改动都可能泄露敏感信息。建议显式挑选需要渲染的字段，避免展开整个用户对象；displayWelcomePage 中的 ...doc 也存在同样风险。

### 代码证据

```text
return res.render("dashboard", {
                            ...user,
                            environmentalScripts
                        });
```

### 修复建议

```text
return res.render("dashboard", {
                            userName: user.userName,
                            firstName: user.firstName,
                            lastName: user.lastName,
                            benefitStartDate: user.benefitStartDate,
                            userId: user._id,
                            environmentalScripts
                        });
```

## 284. 多个用例重复执行 \`cy.userSignIn()\` 与 \`cy.visitPage("/allocations/1")\`，建议提取到 \`beforeEach\`（首个未登录重定向用例除外）或公共辅助函数中，避免后续维护时重复修改或遗漏。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/e2e/integration/allocations\_spec.js:20-21`

多个用例重复执行 \`cy.userSignIn()\` 与 \`cy.visitPage("/allocations/1")\`，建议提取到 \`beforeEach\`（首个未登录重定向用例除外）或公共辅助函数中，避免后续维护时重复修改或遗漏。

### 代码证据

```text
cy.userSignIn();
    cy.visitPage("/allocations/1");
```

### 修复建议

```text
beforeEach(() =&gt; {
    cy.userSignIn();
    cy.visitPage("/allocations/1");
  });
```

## 285. 这段循环用于注入 environmentalScripts 中的 \`&lt;script&gt;\` 标签（如 livereload），它依赖全局 autoescape:false 才能以原始 HTML 输出。一旦为修复 XSS 启用自动转义，这里会被转义成纯文本导致脚本失效。建议对这类受信任的服务端配置显式使用 \`safe\` 过滤器：\`{{ script|safe }}\`，从而避免模板依赖全局关闭转义，并确保

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`app/views/layout.html:125-127`

这段循环用于注入 environmentalScripts 中的 \`&lt;script&gt;\` 标签（如 livereload），它依赖全局 autoescape:false 才能以原始 HTML 输出。一旦为修复 XSS 启用自动转义，这里会被转义成纯文本导致脚本失效。建议对这类受信任的服务端配置显式使用 \`safe\` 过滤器：\`{{ script|safe }}\`，从而避免模板依赖全局关闭转义，并确保该变量不会被用户输入污染。

### 代码证据

```text
{% for script in environmentalScripts %}
    {{script}}
    {% endfor %}
```

### 修复建议

```text
{% for script in environmentalScripts %}
    {{ script|safe }}
    {% endfor %}
```

## 286. 存在多余的 \`&lt;/p&gt;\` 闭合标签：上一行已经关闭了 \`&lt;p&gt;\`，这一行是孤立的闭合标签，会导致 HTML 结构错误。请删除这个多余的 \`&lt;/p&gt;\`。

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/views/tutorial/a1.html:115-117`

存在多余的 \`&lt;/p&gt;\` 闭合标签：上一行已经关闭了 \`&lt;p&gt;\`，这一行是孤立的闭合标签，会导致 HTML 结构错误。请删除这个多余的 \`&lt;/p&gt;\`。

### 代码证据

```text
&lt;code&gt;child_process&lt;/code&gt;modules.
                        &lt;/p&gt;
                        &lt;/p&gt;
```

### 修复建议

```text
&lt;code&gt;child_process&lt;/code&gt;modules.
                        &lt;/p&gt;
```

## 287. 注释拼写错误：\`defualt\` 应为 \`default\`。

- 分类：`documentation`
- 风险等级：`低`
- 位置：`app/data/contributions-dao.js:63`

注释拼写错误：\`defualt\` 应为 \`default\`。

### 代码证据

```text
// Set defualt contributions if not set
```

### 修复建议

```text
// Set default contributions if not set
```

## 288. 业务相关的 URL 路径 "/logout"（以及各用例中的 "/memos"）被硬编码，建议提取为常量或集中配置，避免路径变更时需要多处修改。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/e2e/integration/memos\_spec.js:11`

业务相关的 URL 路径 "/logout"（以及各用例中的 "/memos"）被硬编码，建议提取为常量或集中配置，避免路径变更时需要多处修改。

### 代码证据

```text
cy.visitPage("/logout");
```

## 289. \`cy.url().should("include", "login")\` 使用子串匹配过于宽松：只要 URL 中包含 "login" 就会通过（例如 \`/login?redirect=...\`、\`/foo?login\_failed=1\` 等），无法准确验证重定向目标路径，存在误判风险。建议改为精确断言路径，例如 \`cy.location("pathname").should("eq", "/lo

- 分类：`test`
- 风险等级：`中`
- 位置：`test/e2e/integration/logout\_spec.js:10-13`

\`cy.url().should("include", "login")\` 使用子串匹配过于宽松：只要 URL 中包含 "login" 就会通过（例如 \`/login?redirect=...\`、\`/foo?login\_failed=1\` 等），无法准确验证重定向目标路径，存在误判风险。建议改为精确断言路径，例如 \`cy.location("pathname").should("eq", "/login")\`。本文件中三处相同断言都建议一并修改。

### 代码证据

```text
it("Should redirect if the user has not logged in", () =&gt; {
    cy.visitPage("/logout");
    cy.url().should("include", "login");
  });
```

### 修复建议

```text
it("Should redirect if the user has not logged in", () =&gt; {
    cy.visitPage("/logout");
    cy.location("pathname").should("eq", "/login");
  });
```

## 290. \`&lt;pre&gt;\` 是块级元素，不能嵌套在 \`&lt;p&gt;\` 段落内部。浏览器解析时会自动提前闭合 \`&lt;p&gt;\`，导致 \`&lt;/pre&gt;\` 之后的文本（An attacker can change the ...）脱离段落结构，末尾的 \`&lt;/p&gt;\` 也变成多余标签，HTML 结构不符合规范。建议将 \`&lt;pre&gt;\` 移到 \`&lt;p&gt;\` 之外，并让后续说明文字独立成段。

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/views/tutorial/ssrf.html:24-26`

\`&lt;pre&gt;\` 是块级元素，不能嵌套在 \`&lt;p&gt;\` 段落内部。浏览器解析时会自动提前闭合 \`&lt;p&gt;\`，导致 \`&lt;/pre&gt;\` 之后的文本（An attacker can change the ...）脱离段落结构，末尾的 \`&lt;/p&gt;\` 也变成多余标签，HTML 结构不符合规范。建议将 \`&lt;pre&gt;\` 移到 \`&lt;p&gt;\` 之外，并让后续说明文字独立成段。

### 代码证据

```text
&lt;p&gt;Here is a code snippet from
                    &lt;code&gt;routes/research.js&lt;/code&gt;,
                    &lt;pre&gt;
```

### 修复建议

```text
&lt;p&gt;Here is a code snippet from &lt;code&gt;routes/research.js&lt;/code&gt;:&lt;/p&gt;
                &lt;pre&gt;
    // If a stock symbol has been submitted, concatenate the symbol to the URL and return the HTTP Response
    if (req.query.symbol) {
        var url = req.query.url + req.query.symbol;
        needle.get(url, function (error, newResponse) {
            // ...
        });
    }
                &lt;/pre&gt;
                &lt;p&gt;An attacker can change the &lt;code&gt;url&lt;/code&gt; and &lt;code&gt;symbol&lt;/code&gt; parameters to point to an attacker-controlled website to interact with the server.&lt;/p&gt;
```

## 291. 未对 \`req.body.memo\` 做空值/有效性校验：当请求缺少 body 或未提交 \`memo\` 字段时，会向数据库插入 \`undefined\`/空字符串内容，产生脏数据。建议在插入前校验 \`req.body\` 与 \`memo\` 非空，并做长度限制后再写入。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/routes/memos.js:13`

未对 \`req.body.memo\` 做空值/有效性校验：当请求缺少 body 或未提交 \`memo\` 字段时，会向数据库插入 \`undefined\`/空字符串内容，产生脏数据。建议在插入前校验 \`req.body\` 与 \`memo\` 非空，并做长度限制后再写入。

### 代码证据

```text
memosDAO.insert(req.body.memo, (err, docs) =&gt; {
```

### 修复建议

```text
const memo = req.body &amp;&amp; req.body.memo;
        if (!memo || !memo.trim()) {
            return next(new Error("Memo content is required"));
        }
        memosDAO.insert(memo, (err, docs) =&gt; {
```

## 292. 重复代码：\`displayBenefits\` 与 \`updateBenefits\` 都执行 \`getAllNonAdminUsers\` 并以几乎相同的 \`data\` 结构渲染 \`benefits\` 模板，建议抽取公共渲染辅助函数（例如 \`renderBenefitsPage(res, extraData)\`），减少重复、避免两处逻辑后续不一致。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/routes/benefits.js:42-51`

重复代码：\`displayBenefits\` 与 \`updateBenefits\` 都执行 \`getAllNonAdminUsers\` 并以几乎相同的 \`data\` 结构渲染 \`benefits\` 模板，建议抽取公共渲染辅助函数（例如 \`renderBenefitsPage(res, extraData)\`），减少重复、避免两处逻辑后续不一致。

### 代码证据

```text
const data = {
                    users,
                    user: {
                        isAdmin: true
                    },
                    updateSuccess: true,
                    environmentalScripts
                };

                return res.render("benefits", data);
```

## 293. 在 server.js 中 \`swig.setDefaults({ autoescape: false })\` 已关闭模板自动转义，因此这里直接输出 \`{{firstName}} {{lastName}}\` 时，用户资料中可控的姓名会原样进入 HTML，攻击者可在 profile 中植入恶意脚本，形成存储型 XSS（所有访问页面的人都会执行）。建议对用户输入显式转义：\`{{ firstName|e

- 分类：`安全`
- 风险等级：`严重`
- 位置：`app/views/layout.html:75`

在 server.js 中 \`swig.setDefaults({ autoescape: false })\` 已关闭模板自动转义，因此这里直接输出 \`{{firstName}} {{lastName}}\` 时，用户资料中可控的姓名会原样进入 HTML，攻击者可在 profile 中植入恶意脚本，形成存储型 XSS（所有访问页面的人都会执行）。建议对用户输入显式转义：\`{{ firstName|escape }} {{ lastName|escape }}\`，或全局启用 autoescape。

### 代码证据

```text
&lt;a href="#" class="dropdown-toggle" data-toggle="dropdown"&gt;&lt;i class="fa fa-user"&gt;&lt;/i&gt; {{firstName}} {{lastName}} &lt;b class="caret"&gt;&lt;/b&gt;&lt;/a&gt;
```

### 修复建议

```text
&lt;a href="#" class="dropdown-toggle" data-toggle="dropdown"&gt;&lt;i class="fa fa-user"&gt;&lt;/i&gt; {{ firstName|escape }} {{ lastName|escape }} &lt;b class="caret"&gt;&lt;/b&gt;&lt;/a&gt;
```

## 294. 大段被注释的代码没有明确的保留意图，且与当前实际行为不一致，容易误导维护者。建议删除该注释块；如确需管理员访问控制，请取消注释并启用 \`isAdmin\` 中间件。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/routes/index.js:57-60`

大段被注释的代码没有明确的保留意图，且与当前实际行为不一致，容易误导维护者。建议删除该注释块；如确需管理员访问控制，请取消注释并启用 \`isAdmin\` 中间件。

### 代码证据

```text
/* Fix for A7 - checks user role to implement  Function Level Access Control
     app.get("/benefits", isLoggedIn, isAdmin, benefitsHandler.displayBenefits);
     app.post("/benefits", isLoggedIn, isAdmin, benefitsHandler.updateBenefits);
     */
```

## 295. \`helmet.csp()\`、\`helmet.xframe()\`、\`helmet.noCache()\`、\`helmet.hsts()\` 等独立方法在较新版本的 helmet 中已废弃或移除；而本页同时建议使用最新稳定版依赖，示例代码可能无法直接运行。建议改为新版 API（如 \`helmet.contentSecurityPolicy()\`、\`helmet.frameguard()\` 等）或统一使用

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/views/tutorial/a5.html:118`

\`helmet.csp()\`、\`helmet.xframe()\`、\`helmet.noCache()\`、\`helmet.hsts()\` 等独立方法在较新版本的 helmet 中已废弃或移除；而本页同时建议使用最新稳定版依赖，示例代码可能无法直接运行。建议改为新版 API（如 \`helmet.contentSecurityPolicy()\`、\`helmet.frameguard()\` 等）或统一使用 \`helmet({ ... })\` 配置。

### 代码证据

```text
app.use(helmet.csp());
```

## 296. 最后一个 \`&lt;li&gt;\` 缺少闭合标签 \`&lt;/li&gt;\`。虽然 HTML5 允许在父元素结束前省略，但与其他列表项风格不一致，建议补全以保持一致并降低后续维护时误改的风险。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/views/tutorial/a3.html:139-141`

最后一个 \`&lt;li&gt;\` 缺少闭合标签 \`&lt;/li&gt;\`。虽然 HTML5 允许在父元素结束前省略，但与其他列表项风格不一致，建议补全以保持一致并降低后续维护时误改的风险。

### 代码证据

```text
&lt;li&gt; &lt;b&gt;Apply encoding on both client and server side: &lt;/b&gt; It is essential to apply encoding on both
                        client and server side to mitigate DOM based XSS attack, in which untrusted data never leaves the
                        browser.
```

### 修复建议

```text
&lt;li&gt; &lt;b&gt;Apply encoding on both client and server side: &lt;/b&gt; It is essential to apply encoding on both
                        client and server side to mitigate DOM based XSS attack, in which untrusted data never leaves the
                        browser.&lt;/li&gt;
```

## 297. \`lint\` 作业未设置 \`timeout-minutes\`，一旦 linter 挂起会无限占用 runner 资源。建议按实际耗时添加超时，例如 \`timeout-minutes: 10\`。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`.github/workflows/lint.yml:7`

\`lint\` 作业未设置 \`timeout-minutes\`，一旦 linter 挂起会无限占用 runner 资源。建议按实际耗时添加超时，例如 \`timeout-minutes: 10\`。

### 代码证据

```text
runs-on: ubuntu-latest
```

### 修复建议

```text
runs-on: ubuntu-latest
    timeout-minutes: 10
```

## 298. \`cy.userSignIn()\`、\`cy.visitPage("/dashboard")\` 和 \`cy.url().should("include", "dashboard")\` 这段“登录并进入 dashboard”的公共逻辑在多个测试中重复出现，属于重复代码，建议提取为 \`beforeEach\` 或自定义命令（如 \`cy.signInAndVisitDashboard()\`），降低维护成本。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/e2e/integration/dashboard\_spec.js:21-24`

\`cy.userSignIn()\`、\`cy.visitPage("/dashboard")\` 和 \`cy.url().should("include", "dashboard")\` 这段“登录并进入 dashboard”的公共逻辑在多个测试中重复出现，属于重复代码，建议提取为 \`beforeEach\` 或自定义命令（如 \`cy.signInAndVisitDashboard()\`），降低维护成本。

### 代码证据

```text
it("Should display information", () =&gt; {
    cy.userSignIn();
    cy.visitPage("/dashboard");
    cy.url().should("include", "dashboard");
```

### 修复建议

```text
beforeEach(() =&gt; {
    cy.userSignIn();
    cy.visitPage("/dashboard");
    cy.url().should("include", "dashboard");
  });
```

## 299. \`\_this = this;\` 重复赋值，第二行是无意义代码，建议删除。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/assets/vendor/bootstrap-tour.js`

\`\_this = this;\` 重复赋值，第二行是无意义代码，建议删除。

### 代码证据

```text
Tour.prototype._setupMouseNavigation = function() {
      var _this = this;
      _this = this;
```

## 300. \`&lt;code&gt;url&lt;/code&gt;\` 与 \`query\` 之间缺少空格，页面最终会渲染为 “urlquery”。建议在两个标签之间补一个空格：\`&lt;code&gt;url&lt;/code&gt; query parameter ...\`。

- 分类：`documentation`
- 风险等级：`低`
- 位置：`app/views/tutorial/a10.html:40`

\`&lt;code&gt;url&lt;/code&gt;\` 与 \`query\` 之间缺少空格，页面最终会渲染为 “urlquery”。建议在两个标签之间补一个空格：\`&lt;code&gt;url&lt;/code&gt; query parameter ...\`。

### 代码证据

```text
&lt;code&gt;url&lt;/code&gt;query parameter to point to malicious website and share it. Victims are more likely to click on it, as the initial part of the link (before query parameters) points to a trusted site.
```

### 修复建议

```text
&lt;code&gt;url&lt;/code&gt; query parameter to point to malicious website and share it. Victims are more likely to click on it, as the initial part of the link (before query parameters) points to a trusted site.
```

## 301. \`&lt;ol&gt;\` 不能嵌套在 \`&lt;p&gt;\` 内部；HTML 解析器会在遇到 \`&lt;ol&gt;\` 之前自动闭合 \`&lt;p&gt;\`，导致文档结构错乱，末尾的 \`&lt;/p&gt;\` 也会变成多余标签。建议将外层 \`&lt;p&gt;\` 改为 \`&lt;div&gt;\`，或在 \`&lt;p&gt;\` 结束之后再放置 \`&lt;ol&gt;\`。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/views/tutorial/a8.html:43-44`

\`&lt;ol&gt;\` 不能嵌套在 \`&lt;p&gt;\` 内部；HTML 解析器会在遇到 \`&lt;ol&gt;\` 之前自动闭合 \`&lt;p&gt;\`，导致文档结构错乱，末尾的 \`&lt;/p&gt;\` 也会变成多余标签。建议将外层 \`&lt;p&gt;\` 改为 \`&lt;div&gt;\`，或在 \`&lt;p&gt;\` 结束之后再放置 \`&lt;ol&gt;\`。

### 代码证据

```text
&lt;p&gt;To exploit it:
                    &lt;ol&gt;
```

## 302. 变量 db 声明后从未被重新赋值，应使用 const 保持不可变，避免后续被意外修改。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`config/env/all.js:3`

变量 db 声明后从未被重新赋值，应使用 const 保持不可变，避免后续被意外修改。

### 代码证据

```text
let db = process.env.MONGODB_URI || "mongodb://localhost:27017/nodegoat";
```

### 修复建议

```text
const db = process.env.MONGODB_URI || "mongodb://localhost:27017/nodegoat";
```

## 303. 这里（以及下方 envConf 行）使用 \`\_\_dirname + "/../..."\` 手工拼接路径，可读性和跨平台可维护性较差。建议统一改用 \`path.join(\_\_dirname, "../config/env", "all.js")\`。同时 \`finalEnv\` 直接来自 \`process.env.NODE\_ENV\` 参与路径拼接，建议将其限制为白名单环境名，避免加载预期之外的文件。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`config/config.js:7`

这里（以及下方 envConf 行）使用 \`\_\_dirname + "/../..."\` 手工拼接路径，可读性和跨平台可维护性较差。建议统一改用 \`path.join(\_\_dirname, "../config/env", "all.js")\`。同时 \`finalEnv\` 直接来自 \`process.env.NODE\_ENV\` 参与路径拼接，建议将其限制为白名单环境名，避免加载预期之外的文件。

### 代码证据

```text
const allConf = require(path.resolve(__dirname + "/../config/env/all.js"));
```

### 修复建议

```text
const allConf = require(path.join(__dirname, "../config/env", "all.js"));
```

## 304. 测试名称中 "accesible" 拼写错误，应为 "accessible"。

- 分类：`代码风格`
- 风险等级：`低`
- 位置：`test/e2e/integration/benefits\_spec.js:19`

测试名称中 "accesible" 拼写错误，应为 "accessible"。

### 代码证据

```text
it("Should be accesible by default if the user is an admin", () =&gt; {
```

### 修复建议

```text
it("Should be accessible by default if the user is an admin", () =&gt; {
```

## 305. 未对 \`memo\` 参数做空值/类型校验，若调用方传入 \`undefined\` 或 \`null\`，会向数据库写入 \`{ memo: undefined, timestamp: ... }\` 这类无效数据。建议在插入前显式校验 \`memo\` 是否有效。

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/data/memos-dao.js:18-21`

未对 \`memo\` 参数做空值/类型校验，若调用方传入 \`undefined\` 或 \`null\`，会向数据库写入 \`{ memo: undefined, timestamp: ... }\` 这类无效数据。建议在插入前显式校验 \`memo\` 是否有效。

### 代码证据

```text
const memos = {
            memo,
            timestamp: new Date()
        };
```

## 306. \`navigator.cookieEnabled\` 的取值是布尔值（老旧浏览器为 \`undefined\`），永远不会等于 \`null\`；同时前面的 \`if (!cookieEnabled) return false;\` 会在其为 \`undefined\` 时提前返回，导致这里的“测试 cookie”回退分支永远不可达，不支持 \`navigator.cookieEnabled\` 的浏览器会被误判为未启

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/views/login.html:153-158`

\`navigator.cookieEnabled\` 的取值是布尔值（老旧浏览器为 \`undefined\`），永远不会等于 \`null\`；同时前面的 \`if (!cookieEnabled) return false;\` 会在其为 \`undefined\` 时提前返回，导致这里的“测试 cookie”回退分支永远不可达，不支持 \`navigator.cookieEnabled\` 的浏览器会被误判为未启用 Cookie。建议改为先检测 \`cookieEnabled === undefined\` 时写入测试 cookie 验证，再处理 \`false\` 的情况。

### 代码证据

```text
if (!cookieEnabled) return false;

        // try to set a test cookie if we can't see any cookies and we're using
        // either a browser that doesn't support navigator.cookieEnabled
        // or IE (which always returns true for navigator.cookieEnabled)
        if (!document.cookie &amp;&amp; cookieEnabled === null) {
```

### 修复建议

```text
if (cookieEnabled === undefined) {
            document.cookie = "testcookie=1";
            const supported = document.cookie.indexOf("testcookie=1") !== -1;
            document.cookie = "testcookie=1; expires=" + new Date(0).toUTCString();
            return supported;
        }

        return cookieEnabled;
```

## 307. findOne 在用户不存在时返回 null，当前代码直接执行 callback(null, user)，调用方拿到的 user 可能为 null；一旦后续访问 user 的字段（例如被注释掉的 user.ssn 解密逻辑）就会抛出空指针异常。建议在返回前判断 user 是否存在，不存在时返回明确的错误或错误码。

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/data/profile-dao.js:98-99`

findOne 在用户不存在时返回 null，当前代码直接执行 callback(null, user)，调用方拿到的 user 可能为 null；一旦后续访问 user 的字段（例如被注释掉的 user.ssn 解密逻辑）就会抛出空指针异常。建议在返回前判断 user 是否存在，不存在时返回明确的错误或错误码。

### 代码证据

```text
(err, user) =&gt; {
                if (err) return callback(err, null);
```

## 308. 多个登录用例重复实现相同的表单填写与提交逻辑（读取 fixture → \`\#userName\` → \`\#password\` → 提交）。项目已在 \`test/e2e/support/commands.js\` 中提供 \`signIn\`/\`adminSignIn\`/\`userSignIn\` 自定义命令，建议复用这些命令以消除重复，降低后续维护成本。

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`test/e2e/integration/login\_spec.js:35-40`

多个登录用例重复实现相同的表单填写与提交逻辑（读取 fixture → \`\#userName\` → \`\#password\` → 提交）。项目已在 \`test/e2e/support/commands.js\` 中提供 \`signIn\`/\`adminSignIn\`/\`userSignIn\` 自定义命令，建议复用这些命令以消除重复，降低后续维护成本。

### 代码证据

```text
cy.get("@admin").then(admin =&gt; {
      cy.get("#userName").type(admin.user);
      cy.get("#password").type(admin.pass);
      cy.get("[type='submit']").click();
      cy.url().should("include", "benefits");
    });
```

### 修复建议

```text
cy.adminSignIn();
    cy.url().should("include", "benefits");
```

## 309. 用例名称为 "Should be a table with rows"，但 \`cy.get("table tr")\` 仅隐式断言至少存在一个 tr，建议增加显式断言以校验行数，例如 \`.should("have.length.greaterThan", 0)\`。

- 分类：`test`
- 风险等级：`低`
- 位置：`test/e2e/integration/benefits\_spec.js:34`

用例名称为 "Should be a table with rows"，但 \`cy.get("table tr")\` 仅隐式断言至少存在一个 tr，建议增加显式断言以校验行数，例如 \`.should("have.length.greaterThan", 0)\`。

### 代码证据

```text
cy.get("table tr");
```

### 修复建议

```text
cy.get("table tr").should("have.length.greaterThan", 0);
```

## 310. \`cy.get("textarea\[name='memo'\]")\` 缺少显式断言；虽然 \`cy.get\` 在元素不存在时会自动失败，但添加 \`.should("exist")\` 能更清晰地表达测试意图并提高可读性。

- 分类：`test`
- 风险等级：`低`
- 位置：`test/e2e/integration/memos\_spec.js:28`

\`cy.get("textarea\[name='memo'\]")\` 缺少显式断言；虽然 \`cy.get\` 在元素不存在时会自动失败，但添加 \`.should("exist")\` 能更清晰地表达测试意图并提高可读性。

### 代码证据

```text
cy.get("textarea[name='memo']");
```

### 修复建议

```text
cy.get("textarea[name='memo']").should("exist");
```

## 311. 由于 benefits 路由的管理员校验被注释掉了，\`isAdmin\` 声明后未被任何地方使用，属于死代码。若恢复管理员访问控制应使用该中间件，否则应删除此声明。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/routes/index.js:27`

由于 benefits 路由的管理员校验被注释掉了，\`isAdmin\` 声明后未被任何地方使用，属于死代码。若恢复管理员访问控制应使用该中间件，否则应删除此声明。

### 代码证据

```text
const isAdmin = sessionHandler.isAdminUserMiddleware;
```

### 修复建议

```text
// 恢复管理员访问控制时启用：
    const isAdmin = sessionHandler.isAdminUserMiddleware;
```

## 312. \`.side-nav\` 使用 \`position: fixed\`，此时百分比高度相对于视口（initial containing block）解析。\`top: 50px\` 与 \`height: 100%\` 叠加后，侧边栏底部会超出视口底部 50px，导致底部内容与滚动条末端被裁切、无法完整看到。建议改为 \`height: calc(100% - 50px)\`（或同时设置 \`bottom: 0\` 并

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/assets/vendor/theme/sb-admin.css:106-107`

\`.side-nav\` 使用 \`position: fixed\`，此时百分比高度相对于视口（initial containing block）解析。\`top: 50px\` 与 \`height: 100%\` 叠加后，侧边栏底部会超出视口底部 50px，导致底部内容与滚动条末端被裁切、无法完整看到。建议改为 \`height: calc(100% - 50px)\`（或同时设置 \`bottom: 0\` 并移除固定高度）。

### 代码证据

```text
top: 50px;
	height: 100%;
```

### 修复建议

```text
top: 50px;
	height: calc(100% - 50px);
```

## 313. 该文件为第三方 vendor 压缩代码（Bootstrap 3.0.0），通篇使用 \`var\` 以及 \`==\`/\`!=\`，不符合项目「使用 let/const、严格相等」的规范。建议将 \`vendor\` 目录从 lint/审查规则中排除，或改由包管理器引入而非提交压缩源码，避免对第三方代码做风格改造。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`app/assets/vendor/bootstrap/bootstrap.js`

该文件为第三方 vendor 压缩代码（Bootstrap 3.0.0），通篇使用 \`var\` 以及 \`==\`/\`!=\`，不符合项目「使用 let/const、严格相等」的规范。建议将 \`vendor\` 目录从 lint/审查规则中排除，或改由包管理器引入而非提交压缩源码，避免对第三方代码做风格改造。

### 代码证据

```text
var b='[data-dismiss="alert"]'
```

## 314. 该 \`&lt;p&gt;\` 标签未闭合（缺少 \`&lt;/p&gt;\`），会导致 HTML 结构不合法；同时 \`&lt;a target="\_blank"&gt;\` 未添加 \`rel="noopener noreferrer"\`，新窗口可通过 \`window.opener\` 反向操作当前页面（reverse tabnabbing）。建议补上 \`&lt;/p&gt;\` 并为外链/新窗口链接添加 \`rel="noopener noreferrer"

- 分类：`安全`
- 风险等级：`低`
- 位置：`app/views/tutorial/a7.html:31`

该 \`&lt;p&gt;\` 标签未闭合（缺少 \`&lt;/p&gt;\`），会导致 HTML 结构不合法；同时 \`&lt;a target="\_blank"&gt;\` 未添加 \`rel="noopener noreferrer"\`，新窗口可通过 \`window.opener\` 反向操作当前页面（reverse tabnabbing）。建议补上 \`&lt;/p&gt;\` 并为外链/新窗口链接添加 \`rel="noopener noreferrer"\`。

### 代码证据

```text
&lt;p&gt;In the insecure demo application, this vulnerability exists in benefits module, which allows changing benefit start date for employees. The link to the benefits module is visible only to the admin user (user: admin, password: Admin_123). However, an attacker can access this module simply by logging in as any non-admin user and accessing &lt;a id="benefits-menu-link" target="_blank" href="/benefits"&gt;benefits url&lt;/a&gt; directly.
```

## 315. \`update\` 中写入数据库的 \`userId\` 是 \`parseInt\` 后的数字，而这里使用原始字符串 \`userId\` 查询，类型不一致会导致永远匹配不到记录、始终返回默认值。建议先解析 userId 再查询，并与其他方法保持类型一致。

- 分类：`bug`
- 风险等级：`高`
- 位置：`app/data/contributions-dao.js:57-59`

\`update\` 中写入数据库的 \`userId\` 是 \`parseInt\` 后的数字，而这里使用原始字符串 \`userId\` 查询，类型不一致会导致永远匹配不到记录、始终返回默认值。建议先解析 userId 再查询，并与其他方法保持类型一致。

### 代码证据

```text
contributionsDB.findOne({
                userId: userId
            },
```

### 修复建议

```text
const parsedUserId = parseInt(userId, 10);
        contributionsDB.findOne({
                userId: parsedUserId
            },
```

## 316. 这里使用 eval() 直接执行用户可控的 req.body 输入，属于严重的 SSJS（服务端 JavaScript 注入）漏洞：攻击者可提交如 \`require('child\_process').execSync(...)\` 之类的表达式在服务端执行任意代码；同时 eval 抛出的异常还会导致请求 500。\`/\*jslint evil: true \*/\` 只是关闭了 lint 告警，并不能消除

- 分类：`安全`
- 风险等级：`严重`
- 位置：`app/routes/contributions.js:32-34`

这里使用 eval() 直接执行用户可控的 req.body 输入，属于严重的 SSJS（服务端 JavaScript 注入）漏洞：攻击者可提交如 \`require('child\_process').execSync(...)\` 之类的表达式在服务端执行任意代码；同时 eval 抛出的异常还会导致请求 500。\`/\*jslint evil: true \*/\` 只是关闭了 lint 告警，并不能消除风险。建议改用 \`parseInt\`/\`Number\` 配合严格校验（下方注释掉的修复思路方向正确）。

### 代码证据

```text
const preTax = eval(req.body.preTax);
        const afterTax = eval(req.body.afterTax);
        const roth = eval(req.body.roth);
```

### 修复建议

```text
const preTax = parseInt(req.body.preTax);
        const afterTax = parseInt(req.body.afterTax);
        const roth = parseInt(req.body.roth);
```

## 317. 缺少空值检查：当 \`getByUserId\` 未查询到用户时，\`doc\` 可能为 \`null\`/\`undefined\`，直接执行 \`doc.userId = userId\` 会抛出 TypeError。建议在赋值前判空并返回 404 或友好的错误提示。

- 分类：`bug`
- 风险等级：`中`
- 位置：`app/routes/profile.js:21-22`

缺少空值检查：当 \`getByUserId\` 未查询到用户时，\`doc\` 可能为 \`null\`/\`undefined\`，直接执行 \`doc.userId = userId\` 会抛出 TypeError。建议在赋值前判空并返回 404 或友好的错误提示。

### 代码证据

```text
if (err) return next(err);
            doc.userId = userId;
```

### 修复建议

```text
if (err) return next(err);
            if (!doc) {
                return next(new Error("用户不存在"));
            }
            doc.userId = userId;
```

## 318. 业务相关 URL 路径 \`/learn?url=/dashboard\` 在两个测试中重复硬编码，容易出现路径漂移且不便维护。建议提取为模块级常量（如 \`const LEARN\_DASHBOARD\_URL = "/learn?url=/dashboard";\`）统一引用。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`test/e2e/integration/learn\_spec.js:11`

业务相关 URL 路径 \`/learn?url=/dashboard\` 在两个测试中重复硬编码，容易出现路径漂移且不便维护。建议提取为模块级常量（如 \`const LEARN\_DASHBOARD\_URL = "/learn?url=/dashboard";\`）统一引用。

### 代码证据

```text
cy.visitPage("/learn?url=/dashboard");
```

## 319. \`actions/cache@v2\` 已弃用，建议升级到 \`actions/cache@v4\`。

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`.github/workflows/e2e-test.yml:26`

\`actions/cache@v2\` 已弃用，建议升级到 \`actions/cache@v4\`。

### 代码证据

```text
uses: actions/cache@v2
```

### 修复建议

```text
uses: actions/cache@v4
```

## 320. 测试用例名称存在拼写错误："accesible" 应为 "accessible"。

- 分类：`代码风格`
- 风险等级：`低`
- 位置：`test/e2e/integration/memos\_spec.js:19`

测试用例名称存在拼写错误："accesible" 应为 "accessible"。

### 代码证据

```text
it("Should be accesible for a logged user", () =&gt; {
```

### 修复建议

```text
it("Should be accessible for a logged user", () =&gt; {
```

## 321. 该用例把表单 action 从 /research 改成 /skip 后再提交，但 /skip 并非应用中定义的路由（代码库中不存在该路由）。这样绕过了真实的 /research 提交逻辑：断言仅检查浏览器 URL 中的查询串，即使后端 /research 处理逻辑损坏或 /skip 返回 404，URL 仍会包含这些查询参数，测试依然通过。用例名 "valid stock symbol" 与实际

- 分类：`test`
- 风险等级：`中`
- 位置：`test/e2e/integration/research\_spec.js:36-38`

该用例把表单 action 从 /research 改成 /skip 后再提交，但 /skip 并非应用中定义的路由（代码库中不存在该路由）。这样绕过了真实的 /research 提交逻辑：断言仅检查浏览器 URL 中的查询串，即使后端 /research 处理逻辑损坏或 /skip 返回 404，URL 仍会包含这些查询参数，测试依然通过。用例名 "valid stock symbol" 与实际验证的行为不符，无法真正覆盖研究页提交流程。建议直接断言隐藏输入、symbol 输入值及表单 action，或使用 cy.intercept 拦截 "/research\*" 请求并断言查询参数，而不是修改 action 到不存在的路由。

### 代码证据

```text
cy.get("form")
      .should("have.attr", "action", "/research")
      .invoke("attr", "action", "/skip");
```

### 修复建议

```text
cy.get("form")
      .should("have.attr", "action", "/research");

    cy.get("input[name='url']")
      .should("have.value", "https://finance.yahoo.com/quote/");
    cy.get("input[name='symbol']")
      .should("have.value", stockSymbol);
```

## 322. \`err\` 与 \`resp\` 均未判空：当新建用户失败（如用户已存在、Zap 不可达）时，\`resp\` 为 \`undefined\`，\`resp.userId\` 会抛 \`TypeError\`，并且 \`userId\` 将保持 \`undefined\`，后续 \`setForcedUser\`、\`setAuthenticationCredentials\` 都会基于无效用户继续执行。建议先检查 \`err\` 和

- 分类：`bug`
- 风险等级：`高`
- 位置：`test/security/profile-test.js:178-179`

\`err\` 与 \`resp\` 均未判空：当新建用户失败（如用户已存在、Zap 不可达）时，\`resp\` 为 \`undefined\`，\`resp.userId\` 会抛 \`TypeError\`，并且 \`userId\` 将保持 \`undefined\`，后续 \`setForcedUser\`、\`setAuthenticationCredentials\` 都会基于无效用户继续执行。建议先检查 \`err\` 和 \`resp.userId\` 再赋值。

### 代码证据

```text
zaproxy.users.newUser(contextId, sutUserName, zapApiKey, function(err, resp) {
                    userId = resp.userId;
```

### 修复建议

```text
zaproxy.users.newUser(contextId, sutUserName, zapApiKey, function(err, resp) {
                    if (err) return newUserDone(err);
                    if (!resp || !resp.userId) return newUserDone(new Error("Failed to create user"));
                    userId = resp.userId;
```

## 323. \`dbReset\` 中设置了 \`failOnNonZeroExit: false\`，当 \`npm run db:seed\` 执行失败（非零退出码）时会被静默忽略，导致后续用例在未正确重置的数据库上运行，产生难以排查的偶发失败。建议移除该配置（默认失败即抛出）或至少在失败时输出明确提示，避免隐藏测试前置条件错误。

- 分类：`bug`
- 风险等级：`中`
- 位置：`test/e2e/support/commands.js:30-33`

\`dbReset\` 中设置了 \`failOnNonZeroExit: false\`，当 \`npm run db:seed\` 执行失败（非零退出码）时会被静默忽略，导致后续用例在未正确重置的数据库上运行，产生难以排查的偶发失败。建议移除该配置（默认失败即抛出）或至少在失败时输出明确提示，避免隐藏测试前置条件错误。

### 代码证据

```text
cy.exec("npm run db:seed", {
      timeout: 6000,
      failOnNonZeroExit: false
    });
```

### 修复建议

```text
cy.exec("npm run db:seed", {
      timeout: 6000
    });
```

## 324. 存在多层嵌套回调（dropPromises.then -&gt; insertMany -&gt; insertMany），不符合“优先 async/await、禁止回调地狱”的规范，错误处理分散。建议封装 Promise 或使用 async/await 串接各步骤，提高可读性与可维护性。同时 data.ops 是旧版驱动（^2.1.18）特有的返回结构，升级驱动后会失效，建议改用版本无关的返回字段（如 in

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`artifacts/db-reset.js:101`

存在多层嵌套回调（dropPromises.then -&gt; insertMany -&gt; insertMany），不符合“优先 async/await、禁止回调地狱”的规范，错误处理分散。建议封装 Promise 或使用 async/await 串接各步骤，提高可读性与可维护性。同时 data.ops 是旧版驱动（^2.1.18）特有的返回结构，升级驱动后会失效，建议改用版本无关的返回字段（如 insertedIds/返回值）。

### 代码证据

```text
usersCol.insertMany(USERS_TO_INSERT, (err, data) =&gt; {
```

## 325. 直接调用全局对象 \`Morris.Area\` 前未校验 \`Morris\` 是否已加载。如果 morris.js 加载失败或脚本加载顺序不正确，会抛出 \`ReferenceError: Morris is not defined\`，并可能中断页面其他初始化逻辑。建议在调用前增加 \`typeof Morris !== "undefined" &amp;&amp; Morris.Area\` 的判断。

- 分类：`bug`
- 风险等级：`低`
- 位置：`app/assets/js/chart/chart-data-morris.js:11`

直接调用全局对象 \`Morris.Area\` 前未校验 \`Morris\` 是否已加载。如果 morris.js 加载失败或脚本加载顺序不正确，会抛出 \`ReferenceError: Morris is not defined\`，并可能中断页面其他初始化逻辑。建议在调用前增加 \`typeof Morris !== "undefined" &amp;&amp; Morris.Area\` 的判断。

### 代码证据

```text
Morris.Area({
```
