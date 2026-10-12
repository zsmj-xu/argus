# Argus 白盒扫描报告 `1f55d5d925e447b79f558a79d878f581`

- 代码仓库：`https://github.com/WebGoat/WebGoat.git`
- 分支或版本：`main`
- 提交：`044948d057b249735be2bfc14eccc9e3dc2eac34`
- 扫描方式：`全仓`
- 增量起点：`不适用`
- 状态：`已完成`
- 阶段：`已完成`
- 文件：已审查 `43/43`
- 告警：`75` 条

> 本报告来自静态白盒审查。Argus 未执行目标代码，也未进行动态验证。

## 1. 路径穿越 / 任意文件写入：\`username\` 来自 \`@CurrentUsername\`（认证主体用户名），未经任何校验或规范化即直接拼接进文件路径，随后由 \`PrintWriter\` 打开写入。由于子路径以 \`/\` 开头，\`new File(parent, child)\` 会忽略父目录 \`webGoatHomeDirectory\`，实际路径以文件系统根目录下的 \`/XXE/\` 为基准；一旦用

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/xxe/Ping.java:32`

路径穿越 / 任意文件写入：\`username\` 来自 \`@CurrentUsername\`（认证主体用户名），未经任何校验或规范化即直接拼接进文件路径，随后由 \`PrintWriter\` 打开写入。由于子路径以 \`/\` 开头，\`new File(parent, child)\` 会忽略父目录 \`webGoatHomeDirectory\`，实际路径以文件系统根目录下的 \`/XXE/\` 为基准；一旦用户名包含 \`../\` 或路径分隔符（例如 OAuth 注册分支未按 \`\[a-z0-9-\]\*\` 白名单校验用户名），即可逃逸出 \`/XXE\` 目录，写入/覆盖任意 \`.txt\` 文件。另外注意：\`Ping\` 类目前缺少 \`@RestController\`/\`@Component\` 等注解，\`WebGoat\` 的 \`@ComponentScan\` 使用默认过滤器，不会将该类注册为 Spring bean，因此该 \`@GetMapping\` 实际未暴露为 HTTP 端点；但盲注 XXE 答案（sol.MD/sol.txt）引用了 \`/XXE/ping\`，一旦补上注册即可被触发。建议使用 \`Path\` + \`normalize\`/\`toRealPath\` 校验最终路径仍位于允许目录内，并对用户名做白名单校验。

### 代码证据

```text
File logFile = new File(webGoatHomeDirectory, "/XXE/log" + username + ".txt");
```

### 修复建议

```text
Path base = Path.of(webGoatHomeDirectory, "XXE").toAbsolutePath().normalize();
    Path logPath = base.resolve("log" + username + ".txt").normalize();
    if (!logPath.startsWith(base)) {
      throw new IllegalArgumentException("Invalid username");
    }
    File logFile = logPath.toFile();
```

## 2. 实际入口：\`POST /SqlInjection/attack3\` 的 \`@RequestParam String query\` 完全由客户端控制；数据流：\`query\` 未经任何校验或参数化，直接传入 \`Statement.executeUpdate(query)\` 执行。危险操作：攻击者可提交任意 SQL（例如 \`UPDATE employees SET department='Sales'

- 分类：`安全`
- 风险等级：`严重`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson3.java:47`

实际入口：\`POST /SqlInjection/attack3\` 的 \`@RequestParam String query\` 完全由客户端控制；数据流：\`query\` 未经任何校验或参数化，直接传入 \`Statement.executeUpdate(query)\` 执行。危险操作：攻击者可提交任意 SQL（例如 \`UPDATE employees SET department='Sales' WHERE last\_name='Barnett'; DROP TABLE employees;--\` 或基于子查询/布尔盲注的载荷），获得对数据库的任意读写甚至 DDL 权限。缺失防护：应使用 \`PreparedStatement\` 参数化查询（仅参数化值），并配合白名单校验与最小权限数据库账号；同时避免执行客户端提供的整段 SQL。注：该文件位于 WebGoat 教学关卡，漏洞可能是故意设计的演示，但当前实现若被部署即为真实高危漏洞。

### 代码证据

```text
statement.executeUpdate(query);
```

### 修复建议

```text
try (PreparedStatement statement = connection.prepareStatement(
            "UPDATE employees SET department = ? WHERE last_name = ?")) {
          statement.setString(1, department); // department 为白名单校验后的受控值
          statement.setString(2, lastName);
          statement.executeUpdate();
```

## 3. 该接口将用户可控的 \`column\` 参数直接字符串拼接进 \`ORDER BY\` 子句。虽然查询主体使用了 \`PreparedStatement\`，但预编译参数只能绑定“值”，无法绑定列名/排序表达式，因此这里的拼接仍然构成 SQL 注入。实际攻击入口为 \`GET /SqlInjectionMitigations/servers?column=&lt;payload&gt;\`，数据流为：HTTP 参数 → 字

- 分类：`安全`
- 风险等级：`严重`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/Servers.java:51-53`

该接口将用户可控的 \`column\` 参数直接字符串拼接进 \`ORDER BY\` 子句。虽然查询主体使用了 \`PreparedStatement\`，但预编译参数只能绑定“值”，无法绑定列名/排序表达式，因此这里的拼接仍然构成 SQL 注入。实际攻击入口为 \`GET /SqlInjectionMitigations/servers?column=&lt;payload&gt;\`，数据流为：HTTP 参数 → 字符串拼接 → \`prepareStatement\` → \`executeQuery\`，属于实际执行代码而非注释示例。攻击者可注入任意 SQL（如基于 ORDER BY 的报错注入/盲注，或 \`1; drop table ...\` 等）。缺失的防护：未对 \`column\` 做白名单校验。建议仅允许固定的列名集合，或在排序前将用户输入映射到安全常量。

### 代码证据

```text
"select id, hostname, ip, mac, status, description from SERVERS where status &lt;&gt; 'out"
                  + " of order' order by "
                  + column)) {
```

### 修复建议

```text
"select id, hostname, ip, mac, status, description from SERVERS where status &lt;&gt; 'out"
                  + " of order' order by "
                  + validateColumn(column))) {
```

## 4. \`sqle.getMessage()\` 直接作为失败结果返回给客户端，可能泄露数据库类型、SQL 语句片段、驱动版本、表结构等敏感信息，辅助攻击者进一步进行 SQL 注入。缺失防护：应返回通用错误提示，将详细异常信息只记录在服务端日志中；外层 \`catch (Exception e)\` 返回的 \`e.getMessage()\` 同理。

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson3.java:62`

\`sqle.getMessage()\` 直接作为失败结果返回给客户端，可能泄露数据库类型、SQL 语句片段、驱动版本、表结构等敏感信息，辅助攻击者进一步进行 SQL 注入。缺失防护：应返回通用错误提示，将详细异常信息只记录在服务端日志中；外层 \`catch (Exception e)\` 返回的 \`e.getMessage()\` 同理。

### 代码证据

```text
return failed(this).output(sqle.getMessage()).build();
```

### 修复建议

```text
log.error("SQL execution failed", sqle);
        return failed(this).output("Invalid SQL query").build();
```

## 5. 敏感信息泄露：\`injectableQuery\` 的异常分支把类名、原始异常信息 \`e.getMessage()\`（可能包含 SQL 错误、数据库/表结构提示）以及拼接出的完整 SQL 原样返回给客户端；\`executeSqlInjection\` 中 \`sqle.getMessage() + YOUR\_QUERY\_WAS + query\` 也存在同样问题。攻击者可借此获取数据库细节并进一步微调注入

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java:57-61`

敏感信息泄露：\`injectableQuery\` 的异常分支把类名、原始异常信息 \`e.getMessage()\`（可能包含 SQL 错误、数据库/表结构提示）以及拼接出的完整 SQL 原样返回给客户端；\`executeSqlInjection\` 中 \`sqle.getMessage() + YOUR\_QUERY\_WAS + query\` 也存在同样问题。攻击者可借此获取数据库细节并进一步微调注入 payload。建议：将详细异常仅记录到服务端日志，对外返回通用错误信息，且不要回显构造出的 SQL 语句。

### 代码证据

```text
} catch (Exception e) {
      return failed(this)
          .output(this.getClass().getName() + " : " + e.getMessage() + YOUR_QUERY_WAS + query)
          .build();
    }
```

### 修复建议

```text
} catch (Exception e) {
      log.error("query execution failed", e);
      return failed(this).output("Invalid input or query execution failed.").build();
    }
```

## 6. 可预测的直接对象引用（IDOR 基础）：登录成功后把 Map 中可预测、近似连续的内部标识符（2342384、2342388）直接写入会话 \`idor-authenticated-user-id\`，未附带任何属主或授权校验信息。数据流上该值被同课程的 profile 端点直接读取后按 id 取用户信息，攻击者枚举/递增 id 即可访问他人资料。缺失防护：对象访问前应做服务端属主（authoriza

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/idor/IDORLogin.java:55`

可预测的直接对象引用（IDOR 基础）：登录成功后把 Map 中可预测、近似连续的内部标识符（2342384、2342388）直接写入会话 \`idor-authenticated-user-id\`，未附带任何属主或授权校验信息。数据流上该值被同课程的 profile 端点直接读取后按 id 取用户信息，攻击者枚举/递增 id 即可访问他人资料。缺失防护：对象访问前应做服务端属主（authorization）校验，或使用随机不可预测的标识符（UUID）/间接引用映射。

### 代码证据

```text
lessonSession.setValue("idor-authenticated-user-id", idorUserInfo.get(username).get("id"));
```

## 7. 空格检测 \`userId.contains(" ")\` 仅匹配单个空格字符（U+0020）。攻击者可使用制表符 \`\\t\`、换行 \`\\n\`、回车 \`\\r\` 或 SQL 注释（如 \`/\*\*/\`、\`--%0a\`）替代空格，从而绕过检查注入多关键字 SQL 语句。应改用参数化查询，或对输入执行覆盖所有空白字符的严格白名单校验。

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlOnlyInputValidationOnKeywords.java:38`

空格检测 \`userId.contains(" ")\` 仅匹配单个空格字符（U+0020）。攻击者可使用制表符 \`\\t\`、换行 \`\\n\`、回车 \`\\r\` 或 SQL 注释（如 \`/\*\*/\`、\`--%0a\`）替代空格，从而绕过检查注入多关键字 SQL 语句。应改用参数化查询，或对输入执行覆盖所有空白字符的严格白名单校验。

### 代码证据

```text
if (userId.contains(" ")) {
```

### 修复建议

```text
if (userId.matches(".*[\\s].*")) {
```

## 8. 敏感信息泄露。异常处理分支将 \`this.getClass().getName()\`（内部类全限定名）和 \`e.getMessage()\`（数据库/驱动原始异常信息，可能包含表结构、SQL 语法、数据库版本等）直接返回给客户端，为攻击者提供内部实现细节。建议对客户端返回通用错误提示（如 “Invalid query”），将详细异常信息仅记录到服务端日志，避免直接回显异常堆栈/数据库错误。

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5.java:72-75`

敏感信息泄露。异常处理分支将 \`this.getClass().getName()\`（内部类全限定名）和 \`e.getMessage()\`（数据库/驱动原始异常信息，可能包含表结构、SQL 语法、数据库版本等）直接返回给客户端，为攻击者提供内部实现细节。建议对客户端返回通用错误提示（如 “Invalid query”），将详细异常信息仅记录到服务端日志，避免直接回显异常堆栈/数据库错误。

### 代码证据

```text
return failed(this)
          .output(
              this.getClass().getName() + " : " + e.getMessage() + "&lt;br&gt; Your query was: " + query)
          .build();
```

### 修复建议

```text
return failed(this).output("Invalid query").build();
```

## 9. SQL 注入（实际执行代码，非注释示例）。入口：\`@PostMapping("/SqlInjection/attack5")\` 的 \`completed(String query)\` 直接接收用户提交的 \`query\` 参数。数据流：\`query\` 未经过任何校验/过滤，原样传入 \`injectableQuery(query)\`，最终被 \`Statement.executeQuery(query)

- 分类：`安全`
- 风险等级：`严重`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5.java:65`

SQL 注入（实际执行代码，非注释示例）。入口：\`@PostMapping("/SqlInjection/attack5")\` 的 \`completed(String query)\` 直接接收用户提交的 \`query\` 参数。数据流：\`query\` 未经过任何校验/过滤，原样传入 \`injectableQuery(query)\`，最终被 \`Statement.executeQuery(query)\` 执行。危险操作：使用 \`Statement\` 拼接并执行用户可控 SQL，攻击者可改写查询语义（如 UNION 子查询、修改 WHERE 条件，或依赖驱动特性执行多语句/提权语句），进而读取/篡改数据库数据。缺失防护：未使用 \`PreparedStatement\` 参数化，也无输入校验、白名单或最小权限隔离。注意：该端点属于 WebGoat 的教学漏洞，但它是真实可执行代码，构成实际 SQL 注入风险；生产环境必须参数化并校验输入。

### 代码证据

```text
statement.executeQuery(query);
```

### 修复建议

```text
try (PreparedStatement statement =
          connection.prepareStatement("SELECT ... FROM ... WHERE ... = ?")) {
        statement.setString(1, query);
        statement.executeQuery();
```

## 10. 【二次 SQL 注入】\`log(connection, query)\` 将包含用户输入（\`name\`/\`auth\_tan\`）的完整查询串传入 \`log\`，仅用 \`action.replace('\\'', '"')\` 清洗后继续以字符串拼接构造 \`INSERT INTO access\_log ...\`。危险操作：\`action\` 仍是用户可控数据，\`executeUpdate(logQuery)\`

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson8.java:131-132`

【二次 SQL 注入】\`log(connection, query)\` 将包含用户输入（\`name\`/\`auth\_tan\`）的完整查询串传入 \`log\`，仅用 \`action.replace('\\'', '"')\` 清洗后继续以字符串拼接构造 \`INSERT INTO access\_log ...\`。危险操作：\`action\` 仍是用户可控数据，\`executeUpdate(logQuery)\` 直接执行。\`'\`→\`"\` 并非可靠转义——MySQL 默认模式下双引号同为字符串定界符，攻击者可直接用双引号突破引号闭合注入；其他数据库也存在反斜杠等逃逸方式。缺失防护：应将 \`action\` 作为参数绑定（PreparedStatement 占位符）写入 \`access\_log\`，而不是拼接 SQL。

### 代码证据

```text
public static void log(Connection connection, String action) {
    action = action.replace('\'', '"');
```

### 修复建议

```text
public static void log(Connection connection, String action) {
    String logQuery = "INSERT INTO access_log (time, action) VALUES (?, ?)";
    try (PreparedStatement statement =
        connection.prepareStatement(logQuery, TYPE_SCROLL_SENSITIVE, CONCUR_UPDATABLE)) {
      statement.setString(1, time);
      statement.setString(2, action);
      statement.executeUpdate();
```

## 11. 敏感信息泄露（CWE-209）：将 \`sqle.getMessage()\`（以及外层 catch 中的 \`e.getMessage()\` 和类名）原始异常信息直接返回给客户端，可能泄露数据库表结构、列名等细节，辅助攻击者进一步注入。建议对客户端返回通用错误提示，将详细异常记录到服务端日志。

- 分类：`安全`
- 风险等级：`低`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5b.java:102-105`

敏感信息泄露（CWE-209）：将 \`sqle.getMessage()\`（以及外层 catch 中的 \`e.getMessage()\` 和类名）原始异常信息直接返回给客户端，可能泄露数据库表结构、列名等细节，辅助攻击者进一步注入。建议对客户端返回通用错误提示，将详细异常记录到服务端日志。

### 代码证据

```text
return failed(this)
            .output(
                sqle.getMessage() + "&lt;br&gt; Your query was: " + queryString.replace("?", login_count))
            .build();
```

## 12. 实际执行代码（非注释示例）：\`authUserId\` 直接从 \`userSessionData.getValue("idor-authenticated-user-id")\` 读取，未做 null 校验。数据流：当用户未完成 IDOR 登录（会话中无该键）时 \`authUserId\` 为 null，随后进入 \`if (userSubmittedProfile.getUserId() != null

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/idor/IDOREditOtherProfile.java:45`

实际执行代码（非注释示例）：\`authUserId\` 直接从 \`userSessionData.getValue("idor-authenticated-user-id")\` 读取，未做 null 校验。数据流：当用户未完成 IDOR 登录（会话中无该键）时 \`authUserId\` 为 null，随后进入 \`if (userSubmittedProfile.getUserId() != null &amp;&amp; !userSubmittedProfile.getUserId().equals(authUserId))\`；由于 \`String.equals(null)\` 恒为 false，任意非 null 的 body \`userId\` 都会使 \`!false\` 为 true，从而进入“修改他人资料”分支并执行 \`setColor\`/\`setRole\`。缺失防护：未认证会话应被直接拒绝。建议在读取后立即校验 \`authUserId == null\` 并返回失败结果，而不是依赖后续 equals 判断。

### 代码证据

```text
String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
```

## 13. 安全漏洞：类型校验发生在 readObject() 之后，无法阻止攻击。反序列化的副作用（如 readObject() 中的命令执行）在 readObject() 返回前就已经发生，因此此处对 o instanceof VulnerableTaskHolder 的校验只能决定返回给用户的 feedback 文案，并不能阻止恶意对象在反序列化阶段被加载和执行。修复建议：应通过 ObjectInput

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/deserialization/InsecureDeserializationTask.java:46`

安全漏洞：类型校验发生在 readObject() 之后，无法阻止攻击。反序列化的副作用（如 readObject() 中的命令执行）在 readObject() 返回前就已经发生，因此此处对 o instanceof VulnerableTaskHolder 的校验只能决定返回给用户的 feedback 文案，并不能阻止恶意对象在反序列化阶段被加载和执行。修复建议：应通过 ObjectInputFilter 在反序列化过程中按类名白名单拦截（或在构造 ObjectInputStream 前对原始字节流做安全校验），而不是在反序列化完成之后再校验对象类型。

### 代码证据

```text
if (!(o instanceof VulnerableTaskHolder)) {
```

## 14. 反射型 XSS 与信息泄露：\`catch (SQLException e)\` 将 \`e.getMessage()\` 未做 HTML 转义直接拼入 \`.output(...)\`，该内容会作为 HTML 回显给客户端。SQL 语法错误的异常消息通常包含原始 SQL 语句文本，而该文本又包含用户可控的 \`name\`/\`auth\_tan\` 输入，攻击者可注入 \`&lt;script&gt;\` 等标签触发反射型 XSS

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson9.java:85-89`

反射型 XSS 与信息泄露：\`catch (SQLException e)\` 将 \`e.getMessage()\` 未做 HTML 转义直接拼入 \`.output(...)\`，该内容会作为 HTML 回显给客户端。SQL 语法错误的异常消息通常包含原始 SQL 语句文本，而该文本又包含用户可控的 \`name\`/\`auth\_tan\` 输入，攻击者可注入 \`&lt;script&gt;\` 等标签触发反射型 XSS；同时异常信息会泄露数据库/表结构等内部细节。建议返回固定、脱敏的错误提示，详细异常仅记录到服务端日志，或至少对 \`e.getMessage()\` 做 HTML 转义。

### 代码证据

```text
} catch (SQLException e) {
      return failed(this)
          .output("&lt;br&gt;&lt;span class='feedback-negative'&gt;" + e.getMessage() + "&lt;/span&gt;")
          .build();
    }
```

### 修复建议

```text
} catch (SQLException e) {
      return failed(this)
          .output("&lt;br&gt;&lt;span class='feedback-negative'&gt;SQL execution failed&lt;/span&gt;")
          .build();
    }
```

## 15. 此处存在 SQL 注入漏洞（实际执行的代码，非注释示例）。入口：PUT /SqlInjectionAdvanced/register 的 username\_reg 参数。数据流：username 仅经过 checkArguments 的非空与长度校验（未做任何过滤/转义/白名单），随后直接通过字符串拼接进入 checkUserQuery。危险操作：使用 Statement.executeQuery

- 分类：`安全`
- 风险等级：`严重`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java:59-62`

此处存在 SQL 注入漏洞（实际执行的代码，非注释示例）。入口：PUT /SqlInjectionAdvanced/register 的 username\_reg 参数。数据流：username 仅经过 checkArguments 的非空与长度校验（未做任何过滤/转义/白名单），随后直接通过字符串拼接进入 checkUserQuery。危险操作：使用 Statement.executeQuery 执行拼接后的 SQL，攻击者可在 username 中注入任意 SQL（例如 \`' OR '1'='1' --\`），绕过“用户已存在”检查，进而读取、篡改 sql\_challenge\_users 表数据，或借助数据库能力扩大危害。缺失防护：未使用参数化查询。修复建议：改用 PreparedStatement 将 username 作为绑定参数，避免拼接。

### 代码证据

```text
String checkUserQuery =
            "select userid from sql_challenge_users where userid = '" + username + "'";
        Statement statement = connection.createStatement();
        ResultSet resultSet = statement.executeQuery(checkUserQuery);
```

### 修复建议

```text
String checkUserQuery =
            "select userid from sql_challenge_users where userid = ?";
        PreparedStatement statement = connection.prepareStatement(checkUserQuery);
        statement.setString(1, username);
        ResultSet resultSet = statement.executeQuery();
```

## 16. SQL 注入（实际执行代码，非注释示例）：HTTP 入口 POST /SqlInjection/attack9 的 \`name\`、\`auth\_tan\` 参数未做任何校验，直接通过字符串拼接进入 \`queryInjection\`，随后由 \`statement.execute(queryInjection)\` 在数据库中执行。攻击者可用单引号闭合 \`last\_name\`/\`auth\_tan\` 字面量并

- 分类：`安全`
- 风险等级：`严重`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson9.java:50-55`

SQL 注入（实际执行代码，非注释示例）：HTTP 入口 POST /SqlInjection/attack9 的 \`name\`、\`auth\_tan\` 参数未做任何校验，直接通过字符串拼接进入 \`queryInjection\`，随后由 \`statement.execute(queryInjection)\` 在数据库中执行。攻击者可用单引号闭合 \`last\_name\`/\`auth\_tan\` 字面量并注入任意 SQL 子句或语句（如 \`UPDATE employees SET salary=...\`、\`DELETE\`/\`TRUNCATE\` 等），从而篡改数据、破坏完整性。缺失防护：应改用 \`PreparedStatement\` 参数化查询，使输入只作为数据值而非 SQL 代码执行。

### 代码证据

```text
String queryInjection =
        "SELECT * FROM employees WHERE last_name = '"
            + name
            + "' AND auth_tan = '"
            + auth_tan
            + "'";
```

### 修复建议

```text
String query = "SELECT * FROM employees WHERE last_name = ? AND auth_tan = ?";
    try (PreparedStatement statement = connection.prepareStatement(query)) {
      statement.setString(1, name);
      statement.setString(2, auth_tan);
      statement.execute();
```

## 17. setProfileFromId 仅凭调用方传入的 id 直接查询并返回用户资料（name/color/size/role），没有任何所有权或授权校验，构成越权访问（IDOR）。实际数据流：GET/PUT /IDOR/profile/{userId} 的 @PathVariable userId → new UserProfile(userId) → 本方法 → profileToMap()/to

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/idor/UserProfile.java:26-28`

setProfileFromId 仅凭调用方传入的 id 直接查询并返回用户资料（name/color/size/role），没有任何所有权或授权校验，构成越权访问（IDOR）。实际数据流：GET/PUT /IDOR/profile/{userId} 的 @PathVariable userId → new UserProfile(userId) → 本方法 → profileToMap()/toHTMLString() 输出；攻击者把 userId 改成他人 id（如 2342388）即可读取或覆盖他人资料。缺失防护：查询前应校验该 id 属于当前认证用户（水平访问控制），编辑操作还需角色校验。建议：将当前认证用户身份传入本方法，或在调用处完成授权检查后再取数。

### 代码证据

```text
private void setProfileFromId(String id) {
    // emulate look up from database
    if (id.equals("2342384")) {
```

## 18. 此处将原始 \`SQLException\` 异常信息（\`sqle.getMessage()\`）直接返回给客户端，造成敏感信息泄露。攻击者可通过错误回显获取数据库表名、列名、方言及查询结构等信息，辅助进一步实施 SQL 注入利用。建议：对外返回通用的失败提示，将详细异常信息记录到服务端日志中。

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson4.java:58`

此处将原始 \`SQLException\` 异常信息（\`sqle.getMessage()\`）直接返回给客户端，造成敏感信息泄露。攻击者可通过错误回显获取数据库表名、列名、方言及查询结构等信息，辅助进一步实施 SQL 注入利用。建议：对外返回通用的失败提示，将详细异常信息记录到服务端日志中。

### 代码证据

```text
return failed(this).output(sqle.getMessage()).build();
```

### 修复建议

```text
return failed(this).output("SQL execution failed").build();
```

## 19. 路径穿越：\`user.getUsername()\` 来自注册用户输入，而 \`UserValidator\` 仅校验用户名是否重复、两次密码是否一致，未对用户名做字符白名单或规范化校验。该值被直接拼接到 \`new File(webGoatHomeDirectory, "/XXE/" + user.getUsername())\`，随后 \`mkdirs()\` 创建目录并向其中的 \`secret.txt\`

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/xxe/BlindSendFileAssignment.java:56`

路径穿越：\`user.getUsername()\` 来自注册用户输入，而 \`UserValidator\` 仅校验用户名是否重复、两次密码是否一致，未对用户名做字符白名单或规范化校验。该值被直接拼接到 \`new File(webGoatHomeDirectory, "/XXE/" + user.getUsername())\`，随后 \`mkdirs()\` 创建目录并向其中的 \`secret.txt\` 写入内容。攻击者可注册包含 \`../\` 或路径分隔符的用户名，使目录和文件落到预期 \`XXE/\` 目录之外（进程权限允许时可创建目录并覆盖任意同名 \`secret.txt\`）。建议对用户名做白名单过滤（如仅允许 \`\[A-Za-z0-9\_-\]\`），并在写入前校验规范化后的真实路径必须位于 \`webGoatHomeDirectory/XXE/\` 之下。

### 代码证据

```text
File targetDirectory = new File(webGoatHomeDirectory, "/XXE/" + user.getUsername());
```

### 修复建议

```text
String safeUsername = user.getUsername().replaceAll("[^A-Za-z0-9_-]", "_");
    File targetDirectory = new File(webGoatHomeDirectory, "XXE/" + safeUsername);
```

## 20. XSS 防护失效：正则 \`\\\\&lt;.\*?&gt;\` 中的 \`.\` 默认不匹配换行符，因此标签中插入换行（如 \`&lt;img\\nsrc=x onerror=...&gt;\`）或使用其它变形即可绕过标签剥离；而后续编译诊断/异常信息通过 output(...) 返回，前端 LessonContentView.renderOutput 使用 jQuery 的 \`.html()\` 直接将 output 作为 HTML 渲染

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlInjectionLesson10b.java:48`

XSS 防护失效：正则 \`\\\\&lt;.\*?&gt;\` 中的 \`.\` 默认不匹配换行符，因此标签中插入换行（如 \`&lt;img\\nsrc=x onerror=...&gt;\`）或使用其它变形即可绕过标签剥离；而后续编译诊断/异常信息通过 output(...) 返回，前端 LessonContentView.renderOutput 使用 jQuery 的 \`.html()\` 直接将 output 作为 HTML 渲染（AttackResult 中仅做了 escapeJson，不会转义 \`&lt;\`/\`&gt;\`）。缺失防护：输出端没有 HTML 编码，输入端依赖可被绕过的正则。建议在渲染时使用 textContent/.text() 输出，或在服务端对返回内容做 HTML 转义，不应依赖该正则作为 XSS 防线。

### 代码证据

```text
editor = editor.replaceAll("\\&lt;.*?&gt;", "");
```

### 修复建议

```text
// 不要依赖可被换行/变形绕过的标签剥离做 XSS 防护；
      // 应在输出端进行 HTML 转义或以纯文本方式渲染。
```

## 21. 数据流：\`query\` 是攻击者可控的请求参数，在成功路径（department 为 Sales）被直接拼入 \`&lt;span class='feedback-positive'&gt;" + query + "&lt;/span&gt;\` 并作为 HTML 返回。攻击者可构造既能通过 SQL 执行、又携带 HTML/JS 的载荷（例如在 SQL 注释后追加 \`&lt;script&gt;alert(document.cookie

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson3.java:54`

数据流：\`query\` 是攻击者可控的请求参数，在成功路径（department 为 Sales）被直接拼入 \`&lt;span class='feedback-positive'&gt;" + query + "&lt;/span&gt;\` 并作为 HTML 返回。攻击者可构造既能通过 SQL 执行、又携带 HTML/JS 的载荷（例如在 SQL 注释后追加 \`&lt;script&gt;alert(document.cookie)&lt;/script&gt;\`），输出未做 HTML 转义即回显，构成反射型 XSS。缺失防护：对所有用户输入在输出前进行 HTML 实体编码（如 \`HtmlUtils.htmlEscape(query)\`）或使用模板引擎的自动转义。

### 代码证据

```text
output.append("&lt;span class='feedback-positive'&gt;" + query + "&lt;/span&gt;");
```

### 修复建议

```text
output.append("&lt;span class='feedback-positive'&gt;" + HtmlUtils.htmlEscape(query) + "&lt;/span&gt;");
```

## 22. 存在水平越权（IDOR）漏洞。实际入口为 GET /IDOR/profile/{userId}：请求者通过路径变量 userId 直接指定目标用户，代码随后执行 \`new UserProfile(userId)\`，并在命中 2342388 时把 \`requestedProfile.profileToMap().toString()\` 作为 success 的 output 返回。数据流为 user

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOtherProfile.java:49-53`

存在水平越权（IDOR）漏洞。实际入口为 GET /IDOR/profile/{userId}：请求者通过路径变量 userId 直接指定目标用户，代码随后执行 \`new UserProfile(userId)\`，并在命中 2342388 时把 \`requestedProfile.profileToMap().toString()\` 作为 success 的 output 返回。数据流为 userId → UserProfile.setProfileFromId → profileToMap → 响应体，危险操作是把目标用户（如 2342388/Buffalo Bill）的 userId、name、color、size、role 返回给任意请求者。当前唯一的“授权”判断是 \`!userId.equals(authUserId)\`，它只保证请求的 id 与当前会话用户 id 不同，并未验证会话用户是否有权读取该资料；且当 authUserId 为 null 时 \`userId.equals(null)\` 恒为 false，该条件恒成立。真正的服务端水平访问控制完全缺失——注释中“secure code would ensure…”只是注释，不是实际执行的校验。建议在返回资料前执行服务端授权：例如仅允许 \`authUserId != null &amp;&amp; userId != null &amp;&amp; userId.equals(authUserId)\`（查看本人），或基于角色/管理员权限校验后再返回目标 profile。

### 代码证据

```text
if (userId != null &amp;&amp; !userId.equals(authUserId)) {
        // on the right track
        UserProfile requestedProfile = new UserProfile(userId);
        // secure code would ensure there was a horizontal access control check prior to dishing up
        // the requested profile
```

## 23. 实际入口为 \`POST /SqlInjection/assignment5a\`：\`completed()\` 将用户可控的 \`account\`、\`operator\`、\`injection\` 三个参数直接拼接成 \`accountName\`，随后在 \`injectableQuery()\` 中再次通过字符串拼接嵌入 SQL 并交给 \`Statement.executeQuery(query)\` 执行。这里

- 分类：`安全`
- 风险等级：`严重`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5a.java:47-52`

实际入口为 \`POST /SqlInjection/assignment5a\`：\`completed()\` 将用户可控的 \`account\`、\`operator\`、\`injection\` 三个参数直接拼接成 \`accountName\`，随后在 \`injectableQuery()\` 中再次通过字符串拼接嵌入 SQL 并交给 \`Statement.executeQuery(query)\` 执行。这里没有任何参数化查询（\`PreparedStatement\`）、白名单校验或输入转义，\`accountName\` 中的 \`'\`、\`OR '1'='1\` 等内容可以直接改变查询语义，属于真实可触发的 SQL 注入。建议改用 \`PreparedStatement\` 占位符绑定用户输入，例如 \`last\_name = ?\` 并通过 \`setString(1, accountName)\` 传参；若确需动态拼接标识符（表名/列名），也应使用白名单映射。

### 代码证据

```text
query =
          "SELECT * FROM user_data WHERE first_name = 'John' and last_name = '" + accountName + "'";
      try (Statement statement =
          connection.createStatement(
              ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE)) {
        ResultSet results = statement.executeQuery(query);
```

### 修复建议

```text
query = "SELECT * FROM user_data WHERE first_name = 'John' and last_name = ?";
      try (PreparedStatement statement =
          connection.prepareStatement(
              query, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE)) {
        statement.setString(1, accountName);
        ResultSet results = statement.executeQuery();
```

## 24. XXE 漏洞（教学端点但为实际执行代码）：入口是 \`POST /xxe/blind\`，\`commentStr\` 直接来自 \`@RequestBody String\` 请求体，未做任何过滤便传入 \`comments.parseXml(commentStr, false)\`。\`CommentsCache.parseXml\` 中 \`securityEnabled=false\` 会跳过 \`XMLConst

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/xxe/BlindSendFileAssignment.java:79`

XXE 漏洞（教学端点但为实际执行代码）：入口是 \`POST /xxe/blind\`，\`commentStr\` 直接来自 \`@RequestBody String\` 请求体，未做任何过滤便传入 \`comments.parseXml(commentStr, false)\`。\`CommentsCache.parseXml\` 中 \`securityEnabled=false\` 会跳过 \`XMLConstants.ACCESS\_EXTERNAL\_DTD\` 与 \`XMLConstants.ACCESS\_EXTERNAL\_SCHEMA\` 的防护设置，JAXB/StAX 解组时允许解析外部 DTD/外部实体，攻击者可读取服务器本地文件（如 \`/XXE/&lt;user&gt;/secret.txt\`、\`/etc/passwd\`）、发起 SSRF，甚至通过实体扩展造成 DoS。该行为属于 XXE 课程故意保留的可利用点，但确实是真实执行的不安全解析；若部署环境不允许该风险，应改为 \`parseXml(commentStr, true)\`，或至少在受限沙箱中运行并限制外部实体解析与资源消耗。

### 代码证据

```text
Comment comment = comments.parseXml(commentStr, false);
```

### 修复建议

```text
Comment comment = comments.parseXml(commentStr, true);
```

## 25. 安全风险（任意代码编译，CWE-94/CWE-400）：入口是 POST /SqlInjectionMitigations/attack10b 的 editor 参数（未经验证的用户输入）。数据流：editor → replaceAll 净化后 → compileFromString() → getJavaFileContentsAsString() 将用户源码拼接进 TestClass.main

- 分类：`安全`
- 风险等级：`严重`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlInjectionLesson10b.java:97-99`

安全风险（任意代码编译，CWE-94/CWE-400）：入口是 POST /SqlInjectionMitigations/attack10b 的 editor 参数（未经验证的用户输入）。数据流：editor → replaceAll 净化后 → compileFromString() → getJavaFileContentsAsString() 将用户源码拼接进 TestClass.main() → JavaCompiler.getTask(...).call() 在服务器 JVM 内真实编译任意 Java 源码。危险操作：虽然这里只编译、不执行 main 方法，但攻击者可用 \`}}\` 提前闭合 main/类，注入任意顶层类、静态初始化块等结构；每次请求都会触发完整的 javac 编译，可造成 CPU/内存耗尽 DoS；在部分 JDK/部署下编译产物（class 文件）可能被写入应用工作目录，一旦被后续加载或结合编译器/注解处理器漏洞即可升级为 RCE。缺失防护：无输入长度限制、无代码白名单、无沙箱隔离、对编译产物无加载限制。建议不要直接编译用户提交的源码，改为与固定答案比对，或在独立受限沙箱中编译并限制资源与产物落盘。

### 代码证据

```text
JavaCompiler.CompilationTask task =
        compiler.getTask(null, fileManager, diagnosticsCollector, null, null, fileObjects);
    Boolean result = task.call();
```

### 修复建议

```text
// 不要直接编译用户提交的源码：改为比对固定答案，或在独立沙箱中
    // 限制输入长度、禁止编译产物落盘，并确保绝不加载/执行编译结果。
```

## 26. \`getPassword()\` 在数据库查询失败时吞掉 \`SQLException\` 并返回硬编码默认值 \`"dave"\`，导致 \`/SqlInjectionAdvanced/attack6b\` 在数据库不可用或查询出错时出现 fail-open：攻击者无需获取真实密码（\`passW0rD\`），只需提交 \`dave\` 即可通过校验。应将失败路径改为 fail-closed，例如抛出异常/返回失败，

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6b.java:54-57`

\`getPassword()\` 在数据库查询失败时吞掉 \`SQLException\` 并返回硬编码默认值 \`"dave"\`，导致 \`/SqlInjectionAdvanced/attack6b\` 在数据库不可用或查询出错时出现 fail-open：攻击者无需获取真实密码（\`passW0rD\`），只需提交 \`dave\` 即可通过校验。应将失败路径改为 fail-closed，例如抛出异常/返回失败，而不是回退到已知的默认凭据。

### 代码证据

```text
} catch (SQLException sqle) {
        sqle.printStackTrace();
        // do nothing
      }
```

### 修复建议

```text
} catch (SQLException sqle) {
        throw new IllegalStateException("Unable to verify password", sqle);
      }
```

## 27. 并发写入非线程安全的共享集合：\`idorUserInfo\` 是单例控制器（\`@RestController\`）的实例字段 \`HashMap\`，而 \`completed()\` 每次请求都会调用 \`initIDORInfo()\` 重新 put 并逐项填充。多线程并发请求下存在 check-then-act（\`containsKey\` 后再 \`get\`）与并发写 HashMap：一个线程在 \`put("

- 分类：`bug`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/idor/IDORLogin.java:34-35`

并发写入非线程安全的共享集合：\`idorUserInfo\` 是单例控制器（\`@RestController\`）的实例字段 \`HashMap\`，而 \`completed()\` 每次请求都会调用 \`initIDORInfo()\` 重新 put 并逐项填充。多线程并发请求下存在 check-then-act（\`containsKey\` 后再 \`get\`）与并发写 HashMap：一个线程在 \`put("tom", new HashMap())\` 之后、尚未 \`put("password",...)\` 时，另一线程可能读到空 Map，\`get("password")\` 返回 null 后在 \`.equals(password)\` 处抛出 NPE；并发 put 还可能破坏 HashMap 内部结构造成服务异常/拒绝服务。缺失防护：使用 \`ConcurrentHashMap\`，或在构造器中一次性初始化后只读，或对初始化逻辑加同步。

### 代码证据

```text
idorUserInfo.put("tom", new HashMap&lt;String, String&gt;());
    idorUserInfo.get("tom").put("password", "cat");
```

## 28. 【存储型 XSS】\`generateTable\` 将 \`resultsMetaData.getColumnName(i)\` 与 \`results.getString(i)\` 直接拼入 HTML，未做任何 HTML 转义。数据流：\`employees\` 表内容（以及表头列名）→ \`generateTable\` → \`output\` → \`AttackResult.output\` → 前端以 HTML

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson8.java:118`

【存储型 XSS】\`generateTable\` 将 \`resultsMetaData.getColumnName(i)\` 与 \`results.getString(i)\` 直接拼入 HTML，未做任何 HTML 转义。数据流：\`employees\` 表内容（以及表头列名）→ \`generateTable\` → \`output\` → \`AttackResult.output\` → 前端以 HTML 渲染。危险操作：若数据库字段含 \`&lt;script&gt;\`、\`onerror\` 等恶意内容，将被原样执行。缺失防护：所有动态内容在拼接前应做 HTML 编码（如 Spring 的 \`HtmlUtils.htmlEscape\` 或 OWASP Encoder）。

### 代码证据

```text
table.append("&lt;td&gt;" + results.getString(i) + "&lt;/td&gt;");
```

### 修复建议

```text
table.append("&lt;td&gt;" + HtmlUtils.htmlEscape(results.getString(i)) + "&lt;/td&gt;");
```

## 29. 外层 catch 块捕获所有 \`Exception\` 后仅调用 \`printStackTrace()\` 并继续执行（\`// do nothing\`）。这会把包含内部类名、SQL 调用栈等信息的异常输出到标准错误/日志，可能造成信息泄露，同时掩盖了底层错误。建议记录必要的日志而非打印完整堆栈，并在无法验证时应向上层传播异常（fail-closed）。

- 分类：`安全`
- 风险等级：`低`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6b.java:58-61`

外层 catch 块捕获所有 \`Exception\` 后仅调用 \`printStackTrace()\` 并继续执行（\`// do nothing\`）。这会把包含内部类名、SQL 调用栈等信息的异常输出到标准错误/日志，可能造成信息泄露，同时掩盖了底层错误。建议记录必要的日志而非打印完整堆栈，并在无法验证时应向上层传播异常（fail-closed）。

### 代码证据

```text
} catch (Exception e) {
      e.printStackTrace();
      // do nothing
    }
```

## 30. 授权检查直接对可能为 null 的会话值调用 equals：未登录时 session 中不存在 \`idor-authenticated-as\`，\`userSessionData.getValue("idor-authenticated-as")\` 返回 null，\`null.equals("tom")\` 会抛出 NullPointerException，随后被底部 \`catch (Exceptio

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOwnProfileAltUrl.java:36`

授权检查直接对可能为 null 的会话值调用 equals：未登录时 session 中不存在 \`idor-authenticated-as\`，\`userSessionData.getValue("idor-authenticated-as")\` 返回 null，\`null.equals("tom")\` 会抛出 NullPointerException，随后被底部 \`catch (Exception)\` 吞掉并返回通用错误 "an error occurred with your request"。这意味着授权判断依赖异常控制流而非显式校验，且与同包 \`IDORViewOtherProfile\` 中 \`obj != null &amp;&amp; obj.equals("tom")\` 的防护写法不一致。建议先取 Object 判空或使用常量调用 equals，避免未授权请求进入异常路径。

### 代码证据

```text
if (userSessionData.getValue("idor-authenticated-as").equals("tom")) {
```

### 修复建议

```text
Object auth = userSessionData.getValue("idor-authenticated-as");
      if (auth != null &amp;&amp; auth.equals("tom")) {
```

## 31. \`url\` 为完全由请求方控制的参数，\`url.split("/")\` 之后未校验结果数组长度便直接按下标 0~3 访问。以 tom 登录后提交 \`/\`、\`WebGoat\`、\`WebGoat/IDOR\` 或 \`WebGoat/IDOR/profile\` 等短输入，会触发 ArrayIndexOutOfBoundsException，被通用 \`catch (Exception)\` 捕获后仅返回通用错

- 分类：`bug`
- 风险等级：`低`
- 位置：`src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOwnProfileAltUrl.java:40-44`

\`url\` 为完全由请求方控制的参数，\`url.split("/")\` 之后未校验结果数组长度便直接按下标 0~3 访问。以 tom 登录后提交 \`/\`、\`WebGoat\`、\`WebGoat/IDOR\` 或 \`WebGoat/IDOR/profile\` 等短输入，会触发 ArrayIndexOutOfBoundsException，被通用 \`catch (Exception)\` 捕获后仅返回通用错误，缺少对输入路径段数的防护和明确反馈。建议在索引访问前先校验 \`urlParts.length &gt;= 4\`，并对空值或畸形 \`url\` 提前返回失败信息。

### 代码证据

```text
String[] urlParts = url.split("/");
        if (urlParts[0].equals("WebGoat")
            &amp;&amp; urlParts[1].equals("IDOR")
            &amp;&amp; urlParts[2].equals("profile")
            &amp;&amp; urlParts[3].equals(authUserId)) {
```

### 修复建议

```text
String[] urlParts = url.split("/");
        if (urlParts.length &lt; 4) {
          return failed(this).feedback("idor.view.own.profile.failure1").build();
        }
        if (urlParts[0].equals("WebGoat")
```

## 32. 日志注入 / CRLF 注入：攻击者完全可控的 \`User-Agent\` 请求头和 \`text\` 查询参数未经任何过滤或编码，被拼接为 \`logLine\` 后既写入日志文件（\`pw.println\`）又通过 \`log.debug\` 记录。\`text\` 是盲注 XXE 的文件内容回传通道，可包含文件内容中的换行/控制字符；构造 \`\\r\\n\` 或 \`\\n\` 即可伪造日志条目、污染审计数据。建议在记录前

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/xxe/Ping.java:30`

日志注入 / CRLF 注入：攻击者完全可控的 \`User-Agent\` 请求头和 \`text\` 查询参数未经任何过滤或编码，被拼接为 \`logLine\` 后既写入日志文件（\`pw.println\`）又通过 \`log.debug\` 记录。\`text\` 是盲注 XXE 的文件内容回传通道，可包含文件内容中的换行/控制字符；构造 \`\\r\\n\` 或 \`\\n\` 即可伪造日志条目、污染审计数据。建议在记录前对换行符等控制字符进行转义或移除（例如 \`replaceAll("\[\\\\r\\\\n\]", "\_")\`）。同样地，该端点当前因类缺少 \`@RestController\` 注解而未被注册，修复注册后此问题即被暴露。

### 代码证据

```text
String logLine = String.format("%s %s %s", "GET", userAgent, text);
```

### 修复建议

```text
String safeUserAgent = userAgent == null ? "" : userAgent.replaceAll("[\\r\\n]", "_");
    String safeText = text == null ? "" : text.replaceAll("[\\r\\n]", "_");
    String logLine = String.format("%s %s %s", "GET", safeUserAgent, safeText);
```

## 33. 反射型 XSS 风险。该行将用户可控的 \`query\` 参数未做 HTML 转义直接拼接进 \`output\`；且同一方法的异常分支还拼接了 \`&lt;br&gt;\` HTML 标签，说明 \`output\` 预期会以 HTML 渲染。若前端确实以 HTML 方式展示 \`AttackResult.output\`，攻击者可在 \`query\` 中注入 \`&lt;script&gt;\` 等标签导致脚本执行。\`AttackResul

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5.java:69`

反射型 XSS 风险。该行将用户可控的 \`query\` 参数未做 HTML 转义直接拼接进 \`output\`；且同一方法的异常分支还拼接了 \`&lt;br&gt;\` HTML 标签，说明 \`output\` 预期会以 HTML 渲染。若前端确实以 HTML 方式展示 \`AttackResult.output\`，攻击者可在 \`query\` 中注入 \`&lt;script&gt;\` 等标签导致脚本执行。\`AttackResult\` 中的 \`escapeJson\` 仅做 JSON 转义，不防护 HTML 注入。建议对回显内容做 HTML 转义（如 \`StringEscapeUtils.escapeHtml4\`），或改用结构化数据/纯文本渲染，避免直接拼接 HTML。

### 代码证据

```text
return failed(this).output("Your query was: " + query).build();
```

### 修复建议

```text
return failed(this).output("Your query was: " + StringEscapeUtils.escapeHtml4(query)).build();
```

## 34. toHTMLString 将 userId/name/size/isAdmin 等字段直接拼接成 HTML，未做任何 HTML 编码，属于反射型 XSS 危险 sink。当前代码库未发现该方法的调用点（潜在隐患而非当前实际执行路径）；一旦被用于渲染经 setter 注入的用户可控数据（userId/name 等）即可触发 XSS。缺失防护：输出编码。建议使用 OWASP Java Encoder

- 分类：`安全`
- 风险等级：`低`
- 位置：`src/main/java/org/owasp/webgoat/lessons/idor/UserProfile.java:57-60`

toHTMLString 将 userId/name/size/isAdmin 等字段直接拼接成 HTML，未做任何 HTML 编码，属于反射型 XSS 危险 sink。当前代码库未发现该方法的调用点（潜在隐患而非当前实际执行路径）；一旦被用于渲染经 setter 注入的用户可控数据（userId/name 等）即可触发 XSS。缺失防护：输出编码。建议使用 OWASP Java Encoder 的 forHtml 逐字段转义，或避免手工拼接 HTML。

### 代码证据

```text
public String toHTMLString() {
    String htmlBreak = "&lt;br/&gt;";
    return "userId"
        + this.userId
```

## 35. 安全漏洞：答题校验可被轻易绕过。入口为 POST /SqlInjectionAdvanced/quiz，数据流为：用户提交的 question\_0\_solution 到 question\_4\_solution 数组 → 取每个数组的第 0 个元素作为 givenAnswers\[i\] → 使用 contains(solutions\[i\]) 判断“提交答案是否包含正确解”，而非精确匹配。由于 solu

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionQuiz.java:49-50`

安全漏洞：答题校验可被轻易绕过。入口为 POST /SqlInjectionAdvanced/quiz，数据流为：用户提交的 question\_0\_solution 到 question\_4\_solution 数组 → 取每个数组的第 0 个元素作为 givenAnswers\[i\] → 使用 contains(solutions\[i\]) 判断“提交答案是否包含正确解”，而非精确匹配。由于 solutions 只有 "Solution 2"、"Solution 3"、"Solution 4" 三种取值，攻击者只需对五个参数都提交包含全部取值的超集字符串（如 "Solution 2 Solution 3 Solution 4"），contains 对全部 5 题都会返回 true，从而在不知道每题正确答案的情况下直接得到 success。缺失的防护：应按精确值比较（或按选项 ID 精确匹配），而不是子串包含判断。

### 代码证据

```text
for (int i = 0; i &lt; solutions.length; i++) {
      if (givenAnswers[i].contains(solutions[i])) {
```

### 修复建议

```text
for (int i = 0; i &lt; solutions.length; i++) {
      if (solutions[i].equals(givenAnswers[i])) {
```

## 36. 实际执行代码（非注释示例）：POST /xxe/simple 直接接收攻击者可控的 @RequestBody String commentStr，并以 false 作为 securityEnabled 参数调用 comments.parseXml(commentStr, false)。在 CommentsCache.parseXml 中，securityEnabled=false 时不会设置 XM

- 分类：`安全`
- 风险等级：`严重`
- 位置：`src/main/java/org/owasp/webgoat/lessons/xxe/SimpleXXE.java:54`

实际执行代码（非注释示例）：POST /xxe/simple 直接接收攻击者可控的 @RequestBody String commentStr，并以 false 作为 securityEnabled 参数调用 comments.parseXml(commentStr, false)。在 CommentsCache.parseXml 中，securityEnabled=false 时不会设置 XMLConstants.ACCESS\_EXTERNAL\_DTD 与 XMLConstants.ACCESS\_EXTERNAL\_SCHEMA 限制，外部实体解析保持开启，随后由 JAXB Unmarshaller 解析该 XML。攻击者可提交带外部实体的 XML（如 file:///etc/passwd 或本课 sampledtd 中的外带 DTD），导致任意本地文件读取与 SSRF（XXE）。修复建议：生产代码应传入 true 启用限制，并在 XMLInputFactory 上进一步关闭 DTD/外部实体、限制实体扩展，同时对输入做白名单校验。

### 代码证据

```text
var comment = comments.parseXml(commentStr, false);
```

### 修复建议

```text
var comment = comments.parseXml(commentStr, true);
```

## 37. 实际入口：GET /IDOR/own 与 GET /IDOR/profile。数据流：请求进入 invoke() 后，先校验会话属性 idor-authenticated-as 是否为 "tom"，随后直接读取另一个会话属性 idor-authenticated-user-id，并将其作为对象引用传入 new UserProfile(authUserId) 查询并返回对应用户的资料（userId/

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOwnProfile.java:32-35`

实际入口：GET /IDOR/own 与 GET /IDOR/profile。数据流：请求进入 invoke() 后，先校验会话属性 idor-authenticated-as 是否为 "tom"，随后直接读取另一个会话属性 idor-authenticated-user-id，并将其作为对象引用传入 new UserProfile(authUserId) 查询并返回对应用户的资料（userId/name/color/size/role）。危险操作：授权主体（idor-authenticated-as）与用于取数的对象引用（idor-authenticated-user-id）是两个相互独立、可变的会话字段，代码没有验证 authUserId 是否确实属于已认证用户 tom，缺少水平访问控制（IDOR）。一旦 idor-authenticated-user-id 被篡改或与认证身份不一致（例如变为 2342388，即 Buffalo Bill），就会返回他人资料，造成跨用户敏感信息泄露。缺失的防护：应使用服务端认证身份作为查询键（由 authenticated-as 在服务端查询其真实ID），或在查询前做归属校验（确认 authUserId 与 tom 绑定的ID一致），不要信任可变的会话字段作为授权对象引用。

### 代码证据

```text
if (userSessionData.getValue("idor-authenticated-as").equals("tom")) {
        // going to use session auth to view this one
        String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
        UserProfile userProfile = new UserProfile(authUserId);
```

### 修复建议

```text
Object authAs = userSessionData.getValue("idor-authenticated-as");
      if ("tom".equals(authAs)) {
        // 从已认证身份派生用户ID，而不是直接信任可变的会话字段
        String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
        if (!"2342384".equals(authUserId)) {
          details.put("error", "Access denied");
          return details;
        }
        UserProfile userProfile = new UserProfile(authUserId);
```

## 38. 实际入口：POST /SqlInjectionAdvanced/login 的 username\_login / password\_login 参数。数据流：password\_login 经 statement.setString(2, password) 直接参与 SQL 条件 \`password = ?\` 的比较。危险操作：登录查询将用户提交的口令原文与数据库 password 列直接比较，结

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallengeLogin.java:34-37`

实际入口：POST /SqlInjectionAdvanced/login 的 username\_login / password\_login 参数。数据流：password\_login 经 statement.setString(2, password) 直接参与 SQL 条件 \`password = ?\` 的比较。危险操作：登录查询将用户提交的口令原文与数据库 password 列直接比较，结合迁移脚本中的种子数据（如 tom 的 \`thisisasecretfortomonly\`）可确认口令以明文存储。缺失防护：生产系统应存储加盐哈希（bcrypt/Argon2）并在服务端做常量时间校验，而不是让数据库直接比较明文口令。虽然这是教学性 SQL 注入课程的有意设计，但该查询体现了明文凭据处理这一严重缺陷（CWE-256）。

### 代码证据

```text
connection.prepareStatement(
              "select password from sql_challenge_users where userid = ? and password = ?");
      statement.setString(1, username);
      statement.setString(2, password);
```

## 39. 信息泄露（实际执行代码）：解析异常时通过 output(error) 将 ExceptionUtils.getStackTrace(e) 的完整堆栈返回给客户端，泄露服务端内部类名、库路径等实现细节。建议服务端记录完整异常日志，对客户端仅返回通用错误信息。

- 分类：`安全`
- 风险等级：`低`
- 位置：`src/main/java/org/owasp/webgoat/lessons/xxe/ContentTypeAssignment.java:66-67`

信息泄露（实际执行代码）：解析异常时通过 output(error) 将 ExceptionUtils.getStackTrace(e) 的完整堆栈返回给客户端，泄露服务端内部类名、库路径等实现细节。建议服务端记录完整异常日志，对客户端仅返回通用错误信息。

### 代码证据

```text
String error = ExceptionUtils.getStackTrace(e);
        attackResult = failed(this).feedback("xxe.content.type.feedback.xml").output(error).build();
```

## 40. 安全漏洞：敏感信息泄露。\`SQLException\` 的原始异常信息 \`e.getMessage()\` 被直接拼入返回前端的 HTML，攻击者可借助数据库报错内容（表名、列名、SQL 语法细节等）辅助进行基于报错的 SQL 注入探测；外层 \`catch (Exception e)\` 同样把 \`e.getMessage()\` 回显给客户端。缺失防护：异常详情应只记录在服务端日志，前端仅返回通用错误提

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson10.java:79-82`

安全漏洞：敏感信息泄露。\`SQLException\` 的原始异常信息 \`e.getMessage()\` 被直接拼入返回前端的 HTML，攻击者可借助数据库报错内容（表名、列名、SQL 语法细节等）辅助进行基于报错的 SQL 注入探测；外层 \`catch (Exception e)\` 同样把 \`e.getMessage()\` 回显给客户端。缺失防护：异常详情应只记录在服务端日志，前端仅返回通用错误提示。建议：\`log.error("SQL execution failed", e); return failed(this).output("&lt;span class='feedback-negative'&gt;请求处理失败&lt;/span&gt;").build();\`。

### 代码证据

```text
"&lt;span class='feedback-negative'&gt;"
                      + e.getMessage()
                      + "&lt;/span&gt;&lt;br&gt;"
                      + output.toString())
```

### 修复建议

```text
"&lt;span class='feedback-negative'&gt;请求处理失败&lt;/span&gt;")
```

## 41. 失败开放导致校验绕过：\`userToFileContents.getOrDefault(user, "")\` 在映射不存在时返回空字符串（例如用户未先经过 \`initialize\`，或 \`HashMap\` 以 \`WebGoatUser\` 对象身份为键、鉴权注入的实例不同导致查找失败）。随后 \`commentStr.contains("")\` 恒为 \`true\`，攻击者无需真正读取 \`secret.

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/xxe/BlindSendFileAssignment.java:71`

失败开放导致校验绕过：\`userToFileContents.getOrDefault(user, "")\` 在映射不存在时返回空字符串（例如用户未先经过 \`initialize\`，或 \`HashMap\` 以 \`WebGoatUser\` 对象身份为键、鉴权注入的实例不同导致查找失败）。随后 \`commentStr.contains("")\` 恒为 \`true\`，攻击者无需真正读取 \`secret.txt\` 即可直接获得 \`success\`，绕过整个 XXE 教学/校验流程。建议改为失败关闭：使用 \`get(user)\` 并在结果为 \`null\` 时返回 \`failed\`，不要用空字符串作为默认值。

### 代码证据

```text
var fileContentsForUser = userToFileContents.getOrDefault(user, "");
```

### 修复建议

```text
String fileContentsForUser = userToFileContents.get(user);
    if (fileContentsForUser == null) {
      return failed(this).output("Lesson not initialized for this user").build();
    }
```

## 42. 此处使用 \`String.equals\` 对用户提交的 \`userid\_6b\` 与数据库中的真实密码 \`getPassword()\` 进行比较。\`String.equals\` 会在首个不匹配字符处提前返回，比较耗时与正确前缀长度相关，攻击者可通过该端点反复探测响应时间侧信道，逐字符还原密码（WebGoat 自身的 Timing Attack 课程也把 \`MessageDigest.isEqual\`

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6b.java:34`

此处使用 \`String.equals\` 对用户提交的 \`userid\_6b\` 与数据库中的真实密码 \`getPassword()\` 进行比较。\`String.equals\` 会在首个不匹配字符处提前返回，比较耗时与正确前缀长度相关，攻击者可通过该端点反复探测响应时间侧信道，逐字符还原密码（WebGoat 自身的 Timing Attack 课程也把 \`MessageDigest.isEqual\` 作为正确修复方式）。建议改为常量时间比较，例如：\`MessageDigest.isEqual(userid\_6b.getBytes(StandardCharsets.UTF\_8), expected.getBytes(StandardCharsets.UTF\_8))\`。

### 代码证据

```text
if (userid_6b.equals(getPassword())) {
```

### 修复建议

```text
String expected = getPassword();
    if (MessageDigest.isEqual(userid_6b.getBytes(StandardCharsets.UTF_8),
        expected.getBytes(StandardCharsets.UTF_8))) {
```

## 43. 实际执行代码存在 SQL 注入（CWE-89）：\`accountName\`（来源于 \`userid\` 请求参数）通过字符串拼接直接进入 SQL 语句，\`PreparedStatement\` 仅对 \`Login\_Count\` 使用了 \`?\` 占位符，\`userid\` 未通过 \`setString\` 绑定，攻击者可通过构造 \`userid\`（如 \`' OR '1'='1'\` 或 \`UNION SELE

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5b.java:45`

实际执行代码存在 SQL 注入（CWE-89）：\`accountName\`（来源于 \`userid\` 请求参数）通过字符串拼接直接进入 SQL 语句，\`PreparedStatement\` 仅对 \`Login\_Count\` 使用了 \`?\` 占位符，\`userid\` 未通过 \`setString\` 绑定，攻击者可通过构造 \`userid\`（如 \`' OR '1'='1'\` 或 \`UNION SELECT ...\`）读取/篡改查询结果。建议将 \`userid\` 也改为 \`?\` 占位符并调用 \`query.setString(2, accountName)\` 进行参数绑定。

### 代码证据

```text
String queryString = "SELECT * From user_data WHERE Login_Count = ? and userid= " + accountName;
```

### 修复建议

```text
String queryString = "SELECT * From user_data WHERE Login_Count = ? and userid= ?";
    ...
    query.setInt(1, count);
    query.setString(2, accountName);
```

## 44. \`writeTable()\` 将 \`results.getString(i)\` 取出的数据库内容直接 \`append\` 到 \`&lt;p&gt;\`/\`&lt;br /&gt;\` 组成的 HTML 片段中，未做任何 HTML 编码。当 \`user\_data\` 表中的数据可由其他 SQL 注入练习写入时，这些值会成为存储型 XSS 的回显点，最终在页面中以 HTML 形式渲染。建议在拼接输出前对每列值进行 HTML 转义（或

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5a.java:106-109`

\`writeTable()\` 将 \`results.getString(i)\` 取出的数据库内容直接 \`append\` 到 \`&lt;p&gt;\`/\`&lt;br /&gt;\` 组成的 HTML 片段中，未做任何 HTML 编码。当 \`user\_data\` 表中的数据可由其他 SQL 注入练习写入时，这些值会成为存储型 XSS 的回显点，最终在页面中以 HTML 形式渲染。建议在拼接输出前对每列值进行 HTML 转义（或使用白名单只输出纯文本）。

### 代码证据

```text
for (int i = 1; i &lt; (numColumns + 1); i++) {
          t.append(results.getString(i));
          t.append(", ");
        }
```

## 45. 安全漏洞：不安全的反序列化（可导致远程代码执行）。实际入口为 POST /InsecureDeserialization/task 的 token 参数，数据流为 token → replace('-','+').replace('\_','/') → Base64.getDecoder().decode → ByteArrayInputStream → ObjectInputStream.read

- 分类：`安全`
- 风险等级：`严重`
- 位置：`src/main/java/org/owasp/webgoat/lessons/deserialization/InsecureDeserializationTask.java:45`

安全漏洞：不安全的反序列化（可导致远程代码执行）。实际入口为 POST /InsecureDeserialization/task 的 token 参数，数据流为 token → replace('-','+').replace('\_','/') → Base64.getDecoder().decode → ByteArrayInputStream → ObjectInputStream.readObject()。这里直接反序列化攻击者完全可控的字节流，且没有对 ois 设置 ObjectInputFilter 白名单，攻击者可通过恶意 gadget 链（例如本课程自带的 org.dummy.insecure.framework.VulnerableTaskHolder.readObject 中会执行 Runtime.getRuntime().exec(taskAction)）实现任意命令执行（RCE）。修复建议：在 readObject() 之前对 ObjectInputStream 设置 ObjectInputFilter 白名单（仅允许 org.dummy.insecure.framework.VulnerableTaskHolder 等受信类，其余拒绝），或改用 ValidatingObjectInputStream/JSON 等受控的反序列化方式。

### 代码证据

```text
Object o = ois.readObject();
```

### 修复建议

```text
ois.setObjectInputFilter(
          ObjectInputFilter.Config.createFilter(
              "org.dummy.insecure.framework.VulnerableTaskHolder;!*"));
      Object o = ois.readObject();
```

## 46. XXE 漏洞（实际执行代码）：入口是 POST /xxe/content-type，当请求头 Content-Type 包含 application/xml 时，用户完全可控的 commentStr 被直接传入 comments.parseXml(commentStr, false)。第二个参数 false 会让 CommentsCache.parseXml 跳过 XMLConstants.ACC

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/xxe/ContentTypeAssignment.java:60`

XXE 漏洞（实际执行代码）：入口是 POST /xxe/content-type，当请求头 Content-Type 包含 application/xml 时，用户完全可控的 commentStr 被直接传入 comments.parseXml(commentStr, false)。第二个参数 false 会让 CommentsCache.parseXml 跳过 XMLConstants.ACCESS\_EXTERNAL\_DTD / ACCESS\_EXTERNAL\_SCHEMA 的防护设置，随后 JAXB Unmarshaller 直接解析未受保护的 XML，且未禁用 DOCTYPE/外部实体。攻击者可构造外部实体读取本地文件（如 file:///etc/passwd）、发起 SSRF，或通过实体膨胀造成 DoS。本文件是 WebGoat 的教学性漏洞示例，但若在真实环境运行会构成文件读取/SSRF 风险。修复建议：非教学场景将 false 改为 true，并进一步设置 FEATURE\_SECURE\_PROCESSING、禁用 DOCTYPE（http://apache.org/xml/features/disallow-doctype-decl）或改用安全解析器。

### 代码证据

```text
Comment comment = comments.parseXml(commentStr, false);
```

### 修复建议

```text
Comment comment = comments.parseXml(commentStr, true);
```

## 47. 【敏感信息泄露】捕获 SQLException 后将 \`sqle.getMessage()\` 原样返回给客户端，可能泄露数据库类型、版本、表结构、SQL 片段等内部信息，既构成信息泄露，也为攻击者进行基于报错的注入提供了便利。建议：客户端返回通用的失败提示，将真实的异常信息记录到服务端日志。

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson2.java:66`

【敏感信息泄露】捕获 SQLException 后将 \`sqle.getMessage()\` 原样返回给客户端，可能泄露数据库类型、版本、表结构、SQL 片段等内部信息，既构成信息泄露，也为攻击者进行基于报错的注入提供了便利。建议：客户端返回通用的失败提示，将真实的异常信息记录到服务端日志。

### 代码证据

```text
return failed(this).feedback("sql-injection.2.failed").output(sqle.getMessage()).build();
```

### 修复建议

```text
log.error("SQL injection lesson query failed", sqle);
      return failed(this).feedback("sql-injection.2.failed").build();
```

## 48. 实际执行代码：路径变量 \`userId\` 完全由客户端控制，\`new UserProfile(userId)\` 直接将其作为待修改对象。授权判断只比较请求体中的 \`userSubmittedProfile.getUserId()\` 与 \`authUserId\`，从未比较路径参数 \`userId\` 与 \`authUserId\`；因此登录用户只要在 body 中填入任意不等于自身 ID 的值，即可通过

- 分类：`安全`
- 风险等级：`严重`
- 位置：`src/main/java/org/owasp/webgoat/lessons/idor/IDOREditOtherProfile.java:51-53`

实际执行代码：路径变量 \`userId\` 完全由客户端控制，\`new UserProfile(userId)\` 直接将其作为待修改对象。授权判断只比较请求体中的 \`userSubmittedProfile.getUserId()\` 与 \`authUserId\`，从未比较路径参数 \`userId\` 与 \`authUserId\`；因此登录用户只要在 body 中填入任意不等于自身 ID 的值，即可通过路径指定任意受害者 ID 并对其执行 \`setColor\`/\`setRole\`（典型 IDOR/越权写）。缺失防护：修改前应校验路径 \`userId\` 是否等于 \`authUserId\`（或按角色显式授权），不能信任客户端提交的路径参数。

### 代码证据

```text
UserProfile currentUserProfile = new UserProfile(userId);
    if (userSubmittedProfile.getUserId() != null
        &amp;&amp; !userSubmittedProfile.getUserId().equals(authUserId)) {
```

## 49. 安全漏洞：guesses 是控制器实例字段，而 Spring 的 @RestController 默认是单例 Bean，该数组被所有请求、所有会话共享。入口为 POST /SqlInjectionAdvanced/quiz（写入 guesses）和 GET /SqlInjectionAdvanced/quiz（返回 this.guesses）。数据流：用户 A 的答题结果写入 guesses 后，

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionQuiz.java:27-28`

安全漏洞：guesses 是控制器实例字段，而 Spring 的 @RestController 默认是单例 Bean，该数组被所有请求、所有会话共享。入口为 POST /SqlInjectionAdvanced/quiz（写入 guesses）和 GET /SqlInjectionAdvanced/quiz（返回 this.guesses）。数据流：用户 A 的答题结果写入 guesses 后，用户 B 调用 GET 即可读取到用户 A 的作答判定结果，造成跨用户信息泄露；同时并发 POST 会互相覆盖 guesses，存在竞态导致结果错乱。缺失的防护：应按会话/用户隔离存储（如 Session 或用户维度的缓存），或 POST 直接返回本次判定结果而不保存共享可变状态。

### 代码证据

```text
String[] solutions = {"Solution 4", "Solution 3", "Solution 2", "Solution 3", "Solution 4"};
  boolean[] guesses = new boolean[solutions.length];
```

## 50. 反射型 XSS（CWE-79）：\`login\_count\`（以及经 \`queryString\` 一并回显的 \`accountName\`）未做任何 HTML 转义即被写入 \`AttackResult.output\`。前端 \`LessonContentView.renderOutput\` 使用 jQuery \`.html()\` 渲染该字段（对应攻击输出容器），攻击者提交的 \`&lt;script&gt;\` 或事件

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5b.java:57-58`

反射型 XSS（CWE-79）：\`login\_count\`（以及经 \`queryString\` 一并回显的 \`accountName\`）未做任何 HTML 转义即被写入 \`AttackResult.output\`。前端 \`LessonContentView.renderOutput\` 使用 jQuery \`.html()\` 渲染该字段（对应攻击输出容器），攻击者提交的 \`&lt;script&gt;\` 或事件属性会在受害者浏览器中执行。建议在回显前对输入做 HTML 实体编码，或让前端改用 \`.text()\` / \`textContent\` 渲染输出。

### 代码证据

```text
"Could not parse: "
                    + login_count
```

## 51. 实际执行代码：\`currentUserProfile.setRole(userSubmittedProfile.getRole())\` 将客户端请求体中的 \`role\` 原样写入资料对象，之后又用 \`getRole() &lt;= 1\` 作为成功/管理员条件。数据流：body 的 \`role\` 由攻击者直接控制，可提交 \`role=0\`（或任意 ≤1）实现提权。缺失防护：\`role\` 属于服务端权限数据

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/idor/IDOREditOtherProfile.java:56`

实际执行代码：\`currentUserProfile.setRole(userSubmittedProfile.getRole())\` 将客户端请求体中的 \`role\` 原样写入资料对象，之后又用 \`getRole() &lt;= 1\` 作为成功/管理员条件。数据流：body 的 \`role\` 由攻击者直接控制，可提交 \`role=0\`（或任意 ≤1）实现提权。缺失防护：\`role\` 属于服务端权限数据，不应由客户端指定；应从可信来源（服务端会话/数据库）获取角色，或至少做白名单校验并按权限控制。

### 代码证据

```text
currentUserProfile.setRole(userSubmittedProfile.getRole());
```

## 52. 【SQL 注入（实际执行代码）】入口是 POST /SqlInjection/attack2 的 \`query\` 请求参数，数据流为 \`completed(query)\` → \`injectableQuery(query)\` → \`statement.executeQuery(query)\`。用户可控的 \`query\` 未经任何校验/参数化直接被拼接进 JDBC Statement 执行，攻击者可

- 分类：`安全`
- 风险等级：`严重`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson2.java:49`

【SQL 注入（实际执行代码）】入口是 POST /SqlInjection/attack2 的 \`query\` 请求参数，数据流为 \`completed(query)\` → \`injectableQuery(query)\` → \`statement.executeQuery(query)\`。用户可控的 \`query\` 未经任何校验/参数化直接被拼接进 JDBC Statement 执行，攻击者可以执行任意 SELECT（配合部分驱动还支持多语句 DML），导致数据泄露、篡改或进一步入侵。虽然本课是教学用途、漏洞是有意保留的，但该代码是真实运行的，且缺失输入白名单校验、PreparedStatement 参数绑定以及最小权限的数据库账户等防护。建议：生产场景应使用 PreparedStatement 绑定参数并做白名单校验；教学环境也建议在部署层限制数据库权限、隔离数据源，避免将真实敏感数据暴露给该端点。

### 代码证据

```text
ResultSet results = statement.executeQuery(query);
```

## 53. 【反射型 XSS】\`query\` 由用户完全可控，此处被直接拼接到 HTML 输出中且未做任何转义，而返回的 \`output\` 会作为 AttackResult 在前端以 HTML 形式渲染（该字符串本身包含 \`&lt;span class='feedback-positive'&gt;\` 等 HTML 标记）。攻击者可构造返回 department=Marketing 的 SQL，同时在查询文本中嵌入脚本，

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson2.java:57-59`

【反射型 XSS】\`query\` 由用户完全可控，此处被直接拼接到 HTML 输出中且未做任何转义，而返回的 \`output\` 会作为 AttackResult 在前端以 HTML 形式渲染（该字符串本身包含 \`&lt;span class='feedback-positive'&gt;\` 等 HTML 标记）。攻击者可构造返回 department=Marketing 的 SQL，同时在查询文本中嵌入脚本，例如 \`SELECT 'Marketing' AS department /\*&lt;script&gt;alert(document.cookie)&lt;/script&gt;\*/\`，从而在前端执行任意脚本。建议在回显前对 \`query\` 做 HTML 转义（如 \`org.springframework.web.util.HtmlUtils.htmlEscape(query)\`），或避免将原始查询回显到输出中。

### 代码证据

```text
output.append("&lt;span class='feedback-positive'&gt;")
                .append(query)
                .append("&lt;/span&gt;");
```

### 修复建议

```text
output.append("&lt;span class='feedback-positive'&gt;")
                .append(HtmlUtils.htmlEscape(query))
                .append("&lt;/span&gt;");
```

## 54. 反射型 XSS 风险：失败、无结果、成功多个分支都将包含用户输入 \`accountName\` 的完整 \`query\` 拼入 \`output\`（例如 \`YOUR\_QUERY\_WAS + query\`、\`" Your query was: " + query\`）。该 \`output\` 最终由前端 \`LessonContentView.js\` 的 \`renderOutput\` 通过 jQuery \`.h

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java:89-91`

反射型 XSS 风险：失败、无结果、成功多个分支都将包含用户输入 \`accountName\` 的完整 \`query\` 拼入 \`output\`（例如 \`YOUR\_QUERY\_WAS + query\`、\`" Your query was: " + query\`）。该 \`output\` 最终由前端 \`LessonContentView.js\` 的 \`renderOutput\` 通过 jQuery \`.html()\` 直接插入 DOM，而服务端 \`escapeJson\` 只做 JSON 转义、不转义 HTML 标签。因此攻击者可在 \`userid\_6a\` 中传入 \`&lt;img src=x onerror=...&gt;\` 等 HTML 片段，在页面渲染时执行脚本。建议对输出做 HTML 实体转义后再返回，或前端改用 \`.text()\` 渲染，避免将用户输入作为 HTML 输出。

### 代码证据

```text
} catch (SQLException sqle) {
      return failed(this).output(sqle.getMessage() + YOUR_QUERY_WAS + query).build();
    }
```

### 修复建议

```text
} catch (SQLException sqle) {
      log.error("query execution failed", sqle);
      return failed(this).output("Query execution failed.").build();
    }
```

## 55. 密码以明文形式直接写入数据库。入口：PUT /SqlInjectionAdvanced/register 的 password\_reg 参数。数据流：password 仅经过非空与长度校验后，通过 setString(3, password) 原样写入 sql\_challenge\_users 表，未做任何哈希/加盐。危险操作：凭据以明文存储，一旦数据库被拖库（例如结合前述 SQL 注入），攻击者可

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java:69-72`

密码以明文形式直接写入数据库。入口：PUT /SqlInjectionAdvanced/register 的 password\_reg 参数。数据流：password 仅经过非空与长度校验后，通过 setString(3, password) 原样写入 sql\_challenge\_users 表，未做任何哈希/加盐。危险操作：凭据以明文存储，一旦数据库被拖库（例如结合前述 SQL 注入），攻击者可直接获得用户明文密码。缺失防护：缺少强哈希（如 bcrypt、scrypt、Argon2）加盐处理。修复建议：在服务端使用强哈希算法对密码进行单向哈希（加随机盐）后再入库。

### 代码证据

```text
preparedStatement.setString(1, username);
          preparedStatement.setString(2, email);
          preparedStatement.setString(3, password);
          preparedStatement.execute();
```

## 56. 未认证/未授权的调用者访问该接口时会收到包含具体用户名 "tom" 的错误信息，泄露有效账号，属于用户枚举/信息泄露。建议改为不包含用户名的通用提示（如 "Authentication required"），并统一对未认证/未授权请求返回 401/403，而不是在响应体中暴露账号名。

- 分类：`安全`
- 风险等级：`低`
- 位置：`src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOwnProfile.java:43-44`

未认证/未授权的调用者访问该接口时会收到包含具体用户名 "tom" 的错误信息，泄露有效账号，属于用户枚举/信息泄露。建议改为不包含用户名的通用提示（如 "Authentication required"），并统一对未认证/未授权请求返回 401/403，而不是在响应体中暴露账号名。

### 代码证据

```text
"error",
            "You do not have privileges to view the profile. Authenticate as tom first please.");
```

## 57. role/isAdmin 等特权字段通过公开 setter 暴露，而 UserProfile 被 @RequestBody 反序列化（见 IDOREditOtherProfile），攻击者可在 JSON 中直接写入 role（甚至 admin），使客户端可控角色流入下游授权判断（getRole() &lt;= 1 决定是否成功），造成权限提升。缺失防护：不应接受客户端提交的特权字段，角色应由服务端从权威

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/idor/UserProfile.java:112-122`

role/isAdmin 等特权字段通过公开 setter 暴露，而 UserProfile 被 @RequestBody 反序列化（见 IDOREditOtherProfile），攻击者可在 JSON 中直接写入 role（甚至 admin），使客户端可控角色流入下游授权判断（getRole() &lt;= 1 决定是否成功），造成权限提升。缺失防护：不应接受客户端提交的特权字段，角色应由服务端从权威数据源加载。建议：将请求绑定对象与内部领域对象分离，使用独立 DTO 并禁止对 role/isAdmin 进行绑定（或使用 @JsonIgnore 等保护字段）。

### 代码证据

```text
public void setAdmin(boolean admin) {
    isAdmin = admin;
  }

  public int getRole() {
    return role;
  }

  public void setRole(int role) {
    this.role = role;
  }
```

## 58. SQL 注入（实际执行代码）：入口为 POST /SqlInjectionAdvanced/attack6a 的 \`userid\_6a\` 参数，数据流为 \`completed() -&gt; injectableQuery() -&gt; 字符串拼接 SQL -&gt; Statement.executeQuery()\`。\`accountName\` 未经任何校验或过滤直接拼入 SQL，攻击者可注入 \`' OR '1

- 分类：`安全`
- 风险等级：`严重`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java:54-56`

SQL 注入（实际执行代码）：入口为 POST /SqlInjectionAdvanced/attack6a 的 \`userid\_6a\` 参数，数据流为 \`completed() -&gt; injectableQuery() -&gt; 字符串拼接 SQL -&gt; Statement.executeQuery()\`。\`accountName\` 未经任何校验或过滤直接拼入 SQL，攻击者可注入 \`' OR '1'='1\`、UNION 查询或读取任意表/字段（如 \`user\_system\_data\` 中的 \`password\`）。注意：\`unionQueryChecker()\` 仅用于决定成功提示文案，并不构成任何防护；第 51-52 行注释中的答案是教学提示，不参与实际执行。建议改用 PreparedStatement 参数绑定（\`last\_name = ?\`），或至少对输入做严格白名单校验。

### 代码证据

```text
query = "SELECT * FROM user_data WHERE last_name = '" + accountName + "'";

      return executeSqlInjection(connection, query, usedUnion);
```

### 修复建议

```text
String query = "SELECT * FROM user_data WHERE last_name = ?";
      try (PreparedStatement statement = connection.prepareStatement(query)) {
        statement.setString(1, accountName);
        return executeSqlInjection(statement, query, usedUnion);
      }
```

## 59. 当请求体未包含 \`userId\`（\`userSubmittedProfile.getUserId()\` 为 null）且路径 \`userId\` 不是 "2342384"/"2342388" 时，\`new UserProfile(userId)\` 的构造函数不会设置 \`color\`（保持 null），前两个分支被跳过，执行到此处 \`currentUserProfile.getColor().equa

- 分类：`安全`
- 风险等级：`低`
- 位置：`src/main/java/org/owasp/webgoat/lessons/idor/IDOREditOtherProfile.java:93`

当请求体未包含 \`userId\`（\`userSubmittedProfile.getUserId()\` 为 null）且路径 \`userId\` 不是 "2342384"/"2342388" 时，\`new UserProfile(userId)\` 的构造函数不会设置 \`color\`（保持 null），前两个分支被跳过，执行到此处 \`currentUserProfile.getColor().equals("black")\` 会抛出 NullPointerException 并返回 500。攻击者可用未知 userId + 空 body 触发未处理异常，形成可用性/拒绝服务问题。建议对未查找到的资料提前返回失败结果，或在校验前确保 \`color\` 非 null。

### 代码证据

```text
if (currentUserProfile.getColor().equals("black") &amp;&amp; currentUserProfile.getRole() &lt;= 1) {
```

## 60. 【信息泄露 + 反射型 XSS】内层 \`catch (SQLException e)\` 与外层 \`catch (Exception e)\` 两处都把 \`e.getMessage()\` 直接拼入 \`feedback-negative\` span 返回客户端。危险操作：SQL 异常信息常包含数据库版本、表/列结构等敏感细节；同时 JDBC 驱动的异常消息通常会回显出错 SQL，其中含有攻击者输入，可构

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson8.java:88-90`

【信息泄露 + 反射型 XSS】内层 \`catch (SQLException e)\` 与外层 \`catch (Exception e)\` 两处都把 \`e.getMessage()\` 直接拼入 \`feedback-negative\` span 返回客户端。危险操作：SQL 异常信息常包含数据库版本、表/列结构等敏感细节；同时 JDBC 驱动的异常消息通常会回显出错 SQL，其中含有攻击者输入，可构成反射型 XSS 向量（例如注入 \`' &lt;script&gt;...\` 触发异常后回显）。缺失防护：对外只返回通用错误提示，详细异常仅记录到服务端日志，不进入响应体。

### 代码证据

```text
return failed(this)
            .output("&lt;br&gt;&lt;span class='feedback-negative'&gt;" + e.getMessage() + "&lt;/span&gt;")
            .build();
```

### 修复建议

```text
return failed(this).feedback("sql-injection.8.error").build();
```

## 61. 此处存在 SQL 注入漏洞（实际执行代码，非注释示例）。入口：POST /SqlInjection/attack4，攻击者通过 \`query\` 请求参数传入任意内容；数据流：\`completed()\` → \`injectableQuery()\` → \`statement.executeUpdate(query)\`；危险操作：用户输入被直接拼接并交由 \`Statement.executeUpdate

- 分类：`安全`
- 风险等级：`严重`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson4.java:46`

此处存在 SQL 注入漏洞（实际执行代码，非注释示例）。入口：POST /SqlInjection/attack4，攻击者通过 \`query\` 请求参数传入任意内容；数据流：\`completed()\` → \`injectableQuery()\` → \`statement.executeUpdate(query)\`；危险操作：用户输入被直接拼接并交由 \`Statement.executeUpdate\` 执行，可执行任意 DML/DDL（如 \`DROP\`、\`UPDATE\` 等），且缺少 \`PreparedStatement\` 参数绑定、输入白名单或最小权限等防护。建议：使用 \`PreparedStatement\` 占位符绑定参数；若出于教学目的确需允许任意 SQL 输入，应确保该环境仅用于隔离的演练环境，避免部署到生产。

### 代码证据

```text
statement.executeUpdate(query);
```

### 修复建议

```text
try (PreparedStatement statement =
    connection.prepareStatement(query)) {
  // 若允许任意 SQL 仅限教学环境，生产代码应改为带占位符的参数化查询
  statement.executeUpdate();
}
```

## 62. 安全漏洞（SQL 注入防护缺失）。数据流：入口为 \`@PostMapping("/SqlOnlyInputValidation/attack")\` 的 \`userId\` 参数；此处仅用 \`userId.contains(" ")\` 做黑名单校验（只拦截单个空格），随后第 35 行将原始 \`userId\` 直接传入 \`SqlInjectionLesson6a.injectableQuery(user

- 分类：`安全`
- 风险等级：`严重`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlOnlyInputValidation.java:32-35`

安全漏洞（SQL 注入防护缺失）。数据流：入口为 \`@PostMapping("/SqlOnlyInputValidation/attack")\` 的 \`userId\` 参数；此处仅用 \`userId.contains(" ")\` 做黑名单校验（只拦截单个空格），随后第 35 行将原始 \`userId\` 直接传入 \`SqlInjectionLesson6a.injectableQuery(userId)\`。该校验存在危险：换行符、制表符、\`/\*\*/\` 注释等都能绕过空格检查（例如 \`'OR/\*\*/1=1--\`、\`'UNION%0aSELECT...\`），而 \`injectableQuery\` 使用字符串拼接构造 \`SELECT \* FROM user\_data WHERE last\_name = '" + accountName + "'\` 并通过 \`Statement.executeQuery\` 执行，仍是可注入的原始 SQL。黑名单式输入校验无法阻断注入，建议在 \`injectableQuery\` 中改用 \`PreparedStatement\` 参数绑定；若必须在本层校验，应采用严格白名单（如仅允许合法姓氏字符），而不是仅拒绝空格。

### 代码证据

```text
if (userId.contains(" ")) {
      return failed(this).feedback("SqlOnlyInputValidation-failed").build();
    }
    AttackResult attackResult = lesson6a.injectableQuery(userId);
```

## 63. \`query\` 由用户可控的 \`account\`/\`operator\`/\`injection\` 拼接而来，此处通过 \`output("Your query was: " + query + ...)\` 未经 HTML 编码直接回显到响应中。由于同一文件中大量使用 \`&lt;br&gt;\`、\`&lt;span&gt;\` 等 HTML 片段，响应会按 HTML 渲染，攻击者可在注入参数中携带 \`&lt;script&gt;\` 或事件属性

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5a.java:63-67`

\`query\` 由用户可控的 \`account\`/\`operator\`/\`injection\` 拼接而来，此处通过 \`output("Your query was: " + query + ...)\` 未经 HTML 编码直接回显到响应中。由于同一文件中大量使用 \`&lt;br&gt;\`、\`&lt;span&gt;\` 等 HTML 片段，响应会按 HTML 渲染，攻击者可在注入参数中携带 \`&lt;script&gt;\` 或事件属性，形成反射型 XSS。建议对回显的用户输入做 HTML 转义（例如使用 \`HtmlUtils.htmlEscape\`）或改为纯文本输出；同样的回显问题也存在于 \`failed(...).output(... + query)\` 分支。

### 代码证据

```text
return success(this)
                .feedback("sql-injection.5a.success")
                .output("Your query was: " + query + EXPLANATION)
                .feedbackArgs(output.toString())
                .build();
```

## 64. 登录接口缺少防暴力破解/速率限制：认证入口对任意 \`username\`/\`password\` 无请求频率限制、账户锁定或失败延迟，攻击者可对该端点进行在线口令枚举。缺失防护：增加速率限制、连续失败锁定及审计日志等防护。

- 分类：`安全`
- 风险等级：`低`
- 位置：`src/main/java/org/owasp/webgoat/lessons/idor/IDORLogin.java:47-49`

登录接口缺少防暴力破解/速率限制：认证入口对任意 \`username\`/\`password\` 无请求频率限制、账户锁定或失败延迟，攻击者可对该端点进行在线口令枚举。缺失防护：增加速率限制、连续失败锁定及审计日志等防护。

### 代码证据

```text
@PostMapping("/IDOR/login")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
```

## 65. 数据流：外部输入 \`userid\_sql\_only\_input\_validation\_on\_keywords\` 经黑名单过滤后传入 \`lesson6a.injectableQuery(userId)\`。该方法（\`SqlInjectionLesson6a\#injectableQuery\`）使用字符串拼接构造 \`SELECT \* FROM user\_data WHERE last\_name = '\`

- 分类：`安全`
- 风险等级：`严重`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlOnlyInputValidationOnKeywords.java:41`

数据流：外部输入 \`userid\_sql\_only\_input\_validation\_on\_keywords\` 经黑名单过滤后传入 \`lesson6a.injectableQuery(userId)\`。该方法（\`SqlInjectionLesson6a\#injectableQuery\`）使用字符串拼接构造 \`SELECT \* FROM user\_data WHERE last\_name = '\` + accountName + \`'\` 并通过 \`Statement.executeQuery\` 直接执行，属于可被利用的 SQL 注入危险操作，且缺少参数化查询/预编译语句等根本防护。建议改用 \`PreparedStatement\` 绑定参数，而不是依赖前端的黑名单关键字过滤。

### 代码证据

```text
AttackResult attackResult = lesson6a.injectableQuery(userId);
```

### 修复建议

```text
// 使用 PreparedStatement 绑定参数，避免字符串拼接构造 SQL
    AttackResult attackResult = lesson6a.injectableQuerySafe(userId);
```

## 66. 硬编码数据库口令（CWE-798）。\`CREATE USER unauthorized\_user PASSWORD test\` 在源码中硬编码了可预测的弱口令 \`test\`。若该数据库账号后续被授予权限或 HSQLDB 实例被外部访问，攻击者可利用已知口令登录。建议使用随机生成的强口令，或从外部配置/密钥管理系统获取，避免在源码中明文硬编码口令。

- 分类：`安全`
- 风险等级：`低`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5.java:45`

硬编码数据库口令（CWE-798）。\`CREATE USER unauthorized\_user PASSWORD test\` 在源码中硬编码了可预测的弱口令 \`test\`。若该数据库账号后续被授予权限或 HSQLDB 实例被外部访问，攻击者可利用已知口令登录。建议使用随机生成的强口令，或从外部配置/密钥管理系统获取，避免在源码中明文硬编码口令。

### 代码证据

```text
connection.prepareStatement("CREATE USER unauthorized_user PASSWORD test")) {
```

### 修复建议

```text
connection.prepareStatement("CREATE USER unauthorized_user PASSWORD ?")) {
        // 从安全配置/密钥管理读取随机强口令
```

## 67. 捕获所有异常后，将 ExceptionUtils.getStackTrace(e) 的完整堆栈写入 AttackResult.output 并返回给客户端。攻击者可通过构造恶意 XML 触发异常，从而获取内部类名、包路径、依赖版本等敏感实现信息，辅助后续攻击。建议：服务端记录完整堆栈（日志），接口仅返回通用错误提示信息。

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/xxe/SimpleXXE.java:59-62`

捕获所有异常后，将 ExceptionUtils.getStackTrace(e) 的完整堆栈写入 AttackResult.output 并返回给客户端。攻击者可通过构造恶意 XML 触发异常，从而获取内部类名、包路径、依赖版本等敏感实现信息，辅助后续攻击。建议：服务端记录完整堆栈（日志），接口仅返回通用错误提示信息。

### 代码证据

```text
} catch (Exception e) {
      error = ExceptionUtils.getStackTrace(e);
    }
    return failed(this).output(error).build();
```

### 修复建议

```text
} catch (Exception e) {
      log.error("Failed to parse comment XML", e);
      error = "Invalid XML input";
    }
    return failed(this).output(error).build();
```

## 68. 黑名单关键字过滤可被轻易绕过：\`toUpperCase()\` 仅统一大小写，\`replace("SELECT", "")\` 只删除字面子串。攻击者可用嵌套关键字混淆，例如 \`SELSELECTECT\` 删除中间的 \`SELECT\` 后仍得到 \`SELECT\`，\`FFROMROM\` 同理得到 \`FROM\`。因此该过滤无法阻止 SQL 注入，应改用参数化查询或严格白名单校验。

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlOnlyInputValidationOnKeywords.java:37`

黑名单关键字过滤可被轻易绕过：\`toUpperCase()\` 仅统一大小写，\`replace("SELECT", "")\` 只删除字面子串。攻击者可用嵌套关键字混淆，例如 \`SELSELECTECT\` 删除中间的 \`SELECT\` 后仍得到 \`SELECT\`，\`FFROMROM\` 同理得到 \`FROM\`。因此该过滤无法阻止 SQL 注入，应改用参数化查询或严格白名单校验。

### 代码证据

```text
userId = userId.toUpperCase().replace("FROM", "").replace("SELECT", "");
```

### 修复建议

```text
// 不要依赖关键字删除过滤；应使用 PreparedStatement 绑定参数或严格白名单校验
```

## 69. 实际入口：POST /SqlInjectionAdvanced/login。数据流：executeQuery() 是否返回行决定了响应走向两个不同的失败分支。危险操作：\`ResultsButNotTom\`（凭据有效但用户名不是 tom）与 \`NoResultsMatched\`（凭据无效）给出不同反馈，攻击者可借此区分“某用户名+口令组合确实存在”与“完全不存在”，从而枚举/验证账号凭据（CWE-2

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallengeLogin.java:41-46`

实际入口：POST /SqlInjectionAdvanced/login。数据流：executeQuery() 是否返回行决定了响应走向两个不同的失败分支。危险操作：\`ResultsButNotTom\`（凭据有效但用户名不是 tom）与 \`NoResultsMatched\`（凭据无效）给出不同反馈，攻击者可借此区分“某用户名+口令组合确实存在”与“完全不存在”，从而枚举/验证账号凭据（CWE-204）。缺失防护：登录失败应统一返回通用的“用户名或密码错误”，不区分具体失败原因，并保持响应时间一致。

### 代码证据

```text
return ("tom".equals(username))
            ? success(this).build()
            : failed(this).feedback("ResultsButNotTom").build();
      } else {
        return failed(this).feedback("NoResultsMatched").build();
      }
```

## 70. 安全漏洞：不受信数据反序列化（CWE-502，可能导致 RCE）。  实际执行代码：本方法中的 \`ObjectInputStream.readObject()\` 是真实执行的反序列化操作，并非注释或示例代码。  实际入口：\`fromString(String s)\` 为 \`public static\` 方法，接受 Base64 编码字符串。仓库搜索未发现其他调用点（除测试外），但该方法本身即是对任

- 分类：`安全`
- 风险等级：`严重`
- 位置：`src/main/java/org/owasp/webgoat/lessons/deserialization/SerializationHelper.java:20-23`

安全漏洞：不受信数据反序列化（CWE-502，可能导致 RCE）。

实际执行代码：本方法中的 \`ObjectInputStream.readObject()\` 是真实执行的反序列化操作，并非注释或示例代码。

实际入口：\`fromString(String s)\` 为 \`public static\` 方法，接受 Base64 编码字符串。仓库搜索未发现其他调用点（除测试外），但该方法本身即是对任意调用方开放的通用入口，一旦被 HTTP 端点或其它可达路径暴露即可被利用。

数据流：攻击者可控字符串 \`s\` → \`Base64.getDecoder().decode(s)\` 得到原始字节 → \`ByteArrayInputStream\` → \`ObjectInputStream\` → \`readObject()\` 实例化对象。

危险操作：\`readObject()\` 在无任何类过滤、白名单或完整性校验的情况下执行 Java 反序列化。攻击者可构造 gadget chain 触发任意代码执行（结合本课程中的 \`VulnerableTaskHolder\` 甚至可执行系统命令），反序列化炸弹还可造成 DoS。

缺失的防护：
1. 未使用 \`ObjectInputFilter\`（JEP 290）或全局 \`ObjectInputFilter.Config.setSerialFilter\`；
2. 未设置类白名单/黑名单；
3. 未限制输入数据大小；
4. 未对解码后的数据进行真实性/完整性校验；
5. 未采用安全替代方案（JSON、XML with schema、自定义协议等）。

修复建议：对 \`fromString\` 增加 \`ObjectInputFilter\` 白名单，只允许反序列化预期类型；限制输入长度，拒绝异常大的 Base64 输入；若该方法仅用于教学，应确保其不会被生产环境暴露；如确需使用 Java 序列化，应确保数据来源可信并具备完整性校验（签名/MAC）。

### 代码证据

```text
public static Object fromString(String s) throws IOException, ClassNotFoundException {
    byte[] data = Base64.getDecoder().decode(s);
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    Object o = ois.readObject();
```

### 修复建议

```text
public static Object fromString(String s) throws IOException, ClassNotFoundException {
    byte[] data = Base64.getDecoder().decode(s);
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
        "org.owasp.webgoat.lessons.deserialization.*;!*"));
    Object o = ois.readObject();
```

## 71. 实际入口：POST /SqlInjectionAdvanced/login 接收用户名/口令并直接返回成功或失败。缺失防护：该登录端点没有速率限制、失败次数锁定、验证码或账户锁定机制，配合明文存储的口令和可枚举的响应，攻击者可以无限次进行暴力破解或撞库（CWE-307）。建议增加按 IP/账户的登录失败计数与锁定、速率限制以及异常登录告警。

- 分类：`安全`
- 风险等级：`中`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallengeLogin.java:26-30`

实际入口：POST /SqlInjectionAdvanced/login 接收用户名/口令并直接返回成功或失败。缺失防护：该登录端点没有速率限制、失败次数锁定、验证码或账户锁定机制，配合明文存储的口令和可枚举的响应，攻击者可以无限次进行暴力破解或撞库（CWE-307）。建议增加按 IP/账户的登录失败计数与锁定、速率限制以及异常登录告警。

### 代码证据

```text
@PostMapping("/SqlInjectionAdvanced/login")
  @ResponseBody
  public AttackResult login(
      @RequestParam("username_login") String username,
      @RequestParam("password_login") String password)
```

## 72. XXE（XML External Entity）漏洞：JAXB 反序列化未真正启用外部实体防护。  实际入口： - SimpleXXE 的 \`POST /xxe/simple\`（\`createNewComment(@RequestBody String commentStr, ...)\`） - BlindSendFileAssignment 的 \`POST /xxe/blind\`（\`addComm

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/xxe/CommentsCache.java:73-82`

XXE（XML External Entity）漏洞：JAXB 反序列化未真正启用外部实体防护。

实际入口：
- SimpleXXE 的 \`POST /xxe/simple\`（\`createNewComment(@RequestBody String commentStr, ...)\`）
- BlindSendFileAssignment 的 \`POST /xxe/blind\`（\`addComment(@RequestBody String commentStr, ...)\`）
- ContentTypeAssignment 的 \`POST /xxe/content-type\`（\`createNewUser(@RequestBody String commentStr, ...)\`）

数据流：攻击者可控的 \`commentStr\`（原始 XML 字符串）→ \`CommentsCache.parseXml(xml, false)\` → \`xif.createXMLStreamReader(new StringReader(xml))\` → \`unmarshaller.unmarshal(xsr)\`。

危险操作：\`unmarshaller.unmarshal(xsr)\` 在 \`XMLInputFactory\` 未禁用外部实体/DTD 的情况下解析攻击者提供的 XML，可触发外部实体解析，造成任意文件读取（\`file:\`）、SSRF（\`http:\`）以及实体扩展类 DoS。

缺失/失效的防护：\`ACCESS\_EXTERNAL\_DTD\` 和 \`ACCESS\_EXTERNAL\_SCHEMA\` 的加固被 \`if (securityEnabled)\` 包裹，而全部实际调用点都传入 \`false\`（经确认 SimpleXXE/BlindSendFileAssignment/ContentTypeAssignment 均为 \`parseXml(commentStr, false)\`），因此防护从不生效；\`securityEnabled\` 仅在 SessionService 中被注释掉的代码中提及。

建议：不要在运行时按布尔开关关闭安全配置。若需真正修复，应在创建 \`XMLStreamReader\` 前无条件禁用 DTD 和外部实体，例如：\`xif.setProperty(XMLInputFactory.SUPPORT\_DTD, false); xif.setProperty(XMLInputFactory.IS\_SUPPORTING\_EXTERNAL\_ENTITIES, false);\`，并保留 \`ACCESS\_EXTERNAL\_DTD\`/\`ACCESS\_EXTERNAL\_SCHEMA\` 为空字符串；或改用 \`org.springframework.oxm.jaxb\`/安全的 unmarshaller 配置。注意：本类作为 WebGoat 的 XXE 教学关卡可能有意保留漏洞，但当前代码中的防护开关始终未启用，属于实际可被利用的未防护路径。

### 代码证据

```text
// TODO fix me disabled for now.
    if (securityEnabled) {
      xif.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, ""); // Compliant
      xif.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, ""); // compliant
    }

    var xsr = xif.createXMLStreamReader(new StringReader(xml));

    var unmarshaller = jc.createUnmarshaller();
    return (Comment) unmarshaller.unmarshal(xsr);
```

### 修复建议

```text
var xif = XMLInputFactory.newInstance();
    xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    xif.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    xif.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");

    var xsr = xif.createXMLStreamReader(new StringReader(xml));

    var unmarshaller = jc.createUnmarshaller();
    return (Comment) unmarshaller.unmarshal(xsr);
```

## 73. 硬编码明文凭据：\`initIDORInfo()\` 在源码中硬编码 tom/bill 的口令（"cat"/"buffalo"），登录校验路径为 POST /IDOR/login → \`completed()\` → \`initIDORInfo()\` → \`idorUserInfo.get("tom").get("password").equals(password)\`，直接对明文口令做普通 \`Stri

- 分类：`安全`
- 风险等级：`高`
- 位置：`src/main/java/org/owasp/webgoat/lessons/idor/IDORLogin.java:35`

硬编码明文凭据：\`initIDORInfo()\` 在源码中硬编码 tom/bill 的口令（"cat"/"buffalo"），登录校验路径为 POST /IDOR/login → \`completed()\` → \`initIDORInfo()\` → \`idorUserInfo.get("tom").get("password").equals(password)\`，直接对明文口令做普通 \`String.equals\` 比较。危险操作：凭据以明文形式存在于代码中，任何能获取源码/反编译字节码的人即可获得登录口令；比较也非恒定时间。缺失防护：口令应使用加盐哈希（如 BCrypt）存储并与哈希结果比较，凭据不应硬编码在源码中。

### 代码证据

```text
idorUserInfo.get("tom").put("password", "cat");
```

## 74. 【SQL 注入】实际入口：\`@PostMapping("/SqlInjection/attack8")\` 的 \`@RequestParam String name\`、\`@RequestParam String auth\_tan\`。数据流：HTTP 参数 → 字符串拼接构造 \`query\` → \`statement.executeQuery(query)\`。危险操作：攻击者可通过 \`name\`/\`a

- 分类：`安全`
- 风险等级：`严重`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson8.java:49-54`

【SQL 注入】实际入口：\`@PostMapping("/SqlInjection/attack8")\` 的 \`@RequestParam String name\`、\`@RequestParam String auth\_tan\`。数据流：HTTP 参数 → 字符串拼接构造 \`query\` → \`statement.executeQuery(query)\`。危险操作：攻击者可通过 \`name\`/\`auth\_tan\` 注入如 \`' OR '1'='1' --\` 的片段，任意读写数据库（此处还使用 \`TYPE\_SCROLL\_INSENSITIVE\`/\`CONCUR\_UPDATABLE\` 可更新 ResultSet，可进一步配合 \`executeUpdate\` 修改数据）；同时 \`SELECT \*\` 会把含 \`auth\_tan\` 等敏感列全部回显。缺失防护：应改用 \`PreparedStatement\` 参数化查询（或对输入做严格白名单校验），并且按需取列、避免回显敏感字段。注：该文件为 WebGoat 教学关卡，漏洞为有意设计，但安全审查中仍应识别为真实注入点。

### 代码证据

```text
String query =
        "SELECT * FROM employees WHERE last_name = '"
            + name
            + "' AND auth_tan = '"
            + auth_tan
            + "'";
```

### 修复建议

```text
String query = "SELECT * FROM employees WHERE last_name = ? AND auth_tan = ?";
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement(
                query, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_UPDATABLE)) {
      statement.setString(1, name);
      statement.setString(2, auth_tan);
      ResultSet results = statement.executeQuery();
```

## 75. 安全漏洞：SQL 注入（实际执行代码，非注释示例）。实际入口为 POST /SqlInjection/attack10 的 \`action\_string\` 参数，数据流：\`completed(action\_string)\` → \`injectableQueryAvailability(action)\` → 直接字符串拼接 \`query\` → \`Statement.executeQuery(quer

- 分类：`安全`
- 风险等级：`严重`
- 位置：`src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson10.java:49`

安全漏洞：SQL 注入（实际执行代码，非注释示例）。实际入口为 POST /SqlInjection/attack10 的 \`action\_string\` 参数，数据流：\`completed(action\_string)\` → \`injectableQueryAvailability(action)\` → 直接字符串拼接 \`query\` → \`Statement.executeQuery(query)\` 执行。攻击者可通过 \`action\_string\`（如 \`%' OR '1'='1\`、\`'; DROP TABLE access\_log;--\` 等）改写 SQL 语义。缺失防护：未使用 \`PreparedStatement\` 参数化查询，未做输入校验/转义/白名单。建议改用参数化查询：\`PreparedStatement ps = connection.prepareStatement("SELECT \* FROM access\_log WHERE action LIKE ?"); ps.setString(1, "%" + action + "%");\`。若这是 WebGoat 故意构造的教学漏洞，建议保留代码但加注释明确其教学用途；任何生产用途都必须修复。

### 代码证据

```text
String query = "SELECT * FROM access_log WHERE action LIKE '%" + action + "%'";
```

### 修复建议

```text
String query = "SELECT * FROM access_log WHERE action LIKE ?";
```
