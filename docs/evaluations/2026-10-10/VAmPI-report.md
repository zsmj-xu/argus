# Argus 白盒扫描报告 `1371b4ed88e747a1bc75de3eb74f95d7`

- 代码仓库：`https://github.com/erev0s/VAmPI.git`
- 分支或版本：`master`
- 提交：`f16052dce83f05847133ec98f01c5193a41de7d8`
- 扫描方式：`全仓`
- 增量起点：`不适用`
- 状态：`已完成`
- 阶段：`已完成`
- 文件：已审查 `20/20`
- 告警：`49` 条

> 本报告来自静态白盒审查。Argus 未执行目标代码，也未进行动态验证。

## 1. 镜像标签使用 \`latest\`，无法追溯具体构建版本，重复推送 \`latest\` 也可能与线上版本产生混淆。建议同时/改为使用 commit SHA 或语义化版本标签，例如 \`${{ github.sha }}\` 或 \`v${{ github.ref\_name }}\`。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`.github/workflows/docker-image.yml:31`

镜像标签使用 \`latest\`，无法追溯具体构建版本，重复推送 \`latest\` 也可能与线上版本产生混淆。建议同时/改为使用 commit SHA 或语义化版本标签，例如 \`${{ github.sha }}\` 或 \`v${{ github.ref\_name }}\`。

### 代码证据

```text
tags: ${{ secrets.DOCKERHUB_USERNAME }}/vampi:latest
```

## 2. job 未显式声明 \`permissions\`，GitHub 默认会授予 GITHUB\_TOKEN 较大的读写权限。该工作流仅使用 Docker Hub 凭据构建并推送镜像，并不需要 GITHUB\_TOKEN，建议按最小权限声明（如 \`permissions: contents: read\`，或 \`permissions: {}\`）以降低凭据泄露后的影响面。

- 分类：`安全`
- 风险等级：`中`
- 位置：`.github/workflows/docker-image.yml:11`

job 未显式声明 \`permissions\`，GitHub 默认会授予 GITHUB\_TOKEN 较大的读写权限。该工作流仅使用 Docker Hub 凭据构建并推送镜像，并不需要 GITHUB\_TOKEN，建议按最小权限声明（如 \`permissions: contents: read\`，或 \`permissions: {}\`）以降低凭据泄露后的影响面。

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

## 3. \`\*.log\` 会忽略仓库中所有 log 文件，可能误伤需要纳入版本管理的日志样本、审计日志或变更记录类文件。建议按项目实际情况收敛规则，例如仅忽略明确的运行日志目录或固定模式（如 \`logs/\`、\`\*.runtime.log\`）。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`.gitignore:53`

\`\*.log\` 会忽略仓库中所有 log 文件，可能误伤需要纳入版本管理的日志样本、审计日志或变更记录类文件。建议按项目实际情况收敛规则，例如仅忽略明确的运行日志目录或固定模式（如 \`logs/\`、\`\*.runtime.log\`）。

### 代码证据

```text
*.log
```

### 修复建议

```text
logs/
*.runtime.log
```

## 4. \`get\_user\` 在不同分支返回类型不一致：\`vuln\` 为真时返回字符串（或 \`None\`），否则返回 \`User\` 对象（或 \`None\`）。调用方难以安全使用（例如直接访问 \`.username\` 属性会失败）。同时这里用 \`%\` 手工拼接 JSON 字符串，当用户名/邮箱包含双引号或反斜杠时会生成非法 JSON。建议统一返回 \`User\` 对象或统一返回 JSON 字符串，序列化使用

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`models/user\_model.py:75-81`

\`get\_user\` 在不同分支返回类型不一致：\`vuln\` 为真时返回字符串（或 \`None\`），否则返回 \`User\` 对象（或 \`None\`）。调用方难以安全使用（例如直接访问 \`.username\` 属性会失败）。同时这里用 \`%\` 手工拼接 JSON 字符串，当用户名/邮箱包含双引号或反斜杠时会生成非法 JSON。建议统一返回 \`User\` 对象或统一返回 JSON 字符串，序列化使用 \`json.dumps\`。

### 代码证据

```text
if ret:
                fin_query = '{"username": "%s", "email": "%s"}' % (ret[1], ret[3])
            else:
                fin_query = None
        else:
            fin_query = User.query.filter_by(username=username).first()
        return fin_query
```

## 5. 使用 \`debug=True\` 且监听 \`host='0.0.0.0'\` 会在公网/容器网络可达的接口上启用 Werkzeug 调试器。调试器提供交互式控制台（通过 PIN 即可执行任意 Python 代码），并将堆栈跟踪和源码片段返回给客户端，存在任意代码执行（RCE）和信息泄露风险。即使本项目是故意设计为易受攻击的测试应用，也不应在所有部署环境默认开启调试器。建议通过环境变量控制，生产/非测试

- 分类：`安全`
- 风险等级：`高`
- 位置：`app.py:17`

使用 \`debug=True\` 且监听 \`host='0.0.0.0'\` 会在公网/容器网络可达的接口上启用 Werkzeug 调试器。调试器提供交互式控制台（通过 PIN 即可执行任意 Python 代码），并将堆栈跟踪和源码片段返回给客户端，存在任意代码执行（RCE）和信息泄露风险。即使本项目是故意设计为易受攻击的测试应用，也不应在所有部署环境默认开启调试器。建议通过环境变量控制，生产/非测试环境使用 \`debug=False\`（例如 \`debug=bool(int(os.getenv('flask\_debug', 0)))\`），或改用更安全的 WSGI 服务器运行。

### 代码证据

```text
vuln_app.run(host='0.0.0.0', port=5000, debug=True)
```

### 修复建议

```text
vuln_app.run(host='0.0.0.0', port=5000, debug=bool(int(os.getenv('flask_debug', 0))))
```

## 6. PyInstaller 的 \`.spec\` 文件通常是构建配置的源文件，很多项目会主动提交以保证构建过程可复现；直接忽略 \`\*.spec\` 可能隐藏关键构建配置。若团队确实由模板生成且不纳入版本管理，可保留该规则；否则建议移除，或改为只忽略生成目录。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`.gitignore:30`

PyInstaller 的 \`.spec\` 文件通常是构建配置的源文件，很多项目会主动提交以保证构建过程可复现；直接忽略 \`\*.spec\` 可能隐藏关键构建配置。若团队确实由模板生成且不纳入版本管理，可保留该规则；否则建议移除，或改为只忽略生成目录。

### 代码证据

```text
*.spec
```

### 修复建议

```text
*.manifest
```

## 7. 当 \`vuln\` 为真时，任何已认证用户只要知道书名即可读取任意用户书籍的 \`secret\_content\`，属于 Broken Object Level Authorization（越权访问他人数据）。该开关看起来是用于演示漏洞，但若生产环境误开启，会造成敏感信息泄露。建议生产环境始终按 \`user\` 过滤所有权，并确保该开关默认关闭。

- 分类：`安全`
- 风险等级：`高`
- 位置：`api\_views/books.py:50-51`

当 \`vuln\` 为真时，任何已认证用户只要知道书名即可读取任意用户书籍的 \`secret\_content\`，属于 Broken Object Level Authorization（越权访问他人数据）。该开关看起来是用于演示漏洞，但若生产环境误开启，会造成敏感信息泄露。建议生产环境始终按 \`user\` 过滤所有权，并确保该开关默认关闭。

### 代码证据

```text
if vuln:  # Broken Object Level Authorization
            book = Book.query.filter_by(book_title=str(book_title)).first()
```

### 修复建议

```text
user = User.query.filter_by(username=resp['sub']).first()
            book = Book.query.filter_by(user=user, book_title=str(book_title)).first()
```

## 8. 裸 \`except:\` 会吞掉 \`KeyboardInterrupt\`、\`SystemExit\` 以及所有未预期的数据库/编码异常，并以 200 状态码返回，掩盖真实错误。建议至少改为 \`except Exception as e:\` 并记录日志，且不要把服务器错误伪装成 200。

- 分类：`bug`
- 风险等级：`中`
- 位置：`api\_views/users.py:113-114`

裸 \`except:\` 会吞掉 \`KeyboardInterrupt\`、\`SystemExit\` 以及所有未预期的数据库/编码异常，并以 200 状态码返回，掩盖真实错误。建议至少改为 \`except Exception as e:\` 并记录日志，且不要把服务器错误伪装成 200。

### 代码证据

```text
except:
        return Response(error_message_helper("An error occurred!"), 200, mimetype="application/json")
```

## 9. 缺少 \`actions/checkout\` 步骤：\`docker/build-push-action@v3\` 默认以当前工作目录（\`.\`）作为构建上下文，但该 job 从未 checkout 仓库代码，工作区为空，构建会因找不到 Dockerfile/上下文而失败。建议在 steps 开头添加 \`uses: actions/checkout@v4\`。

- 分类：`bug`
- 风险等级：`严重`
- 位置：`.github/workflows/docker-image.yml:15-16`

缺少 \`actions/checkout\` 步骤：\`docker/build-push-action@v3\` 默认以当前工作目录（\`.\`）作为构建上下文，但该 job 从未 checkout 仓库代码，工作区为空，构建会因找不到 Dockerfile/上下文而失败。建议在 steps 开头添加 \`uses: actions/checkout@v4\`。

### 代码证据

```text
name: Set up QEMU
        uses: docker/setup-qemu-action@v2
```

### 修复建议

```text
-
        name: Checkout
        uses: actions/checkout@v4
      -
        name: Set up QEMU
        uses: docker/setup-qemu-action@v2
```

## 10. \`COPY . /vampi\` 会把整个构建上下文打入镜像；当前 .dockerignore 仅排除了 Dockerfile、.dockerignore、README.md、docker-compose.yaml，未排除 .git、测试代码、\*.env 等敏感文件，存在源码与敏感信息泄露风险。建议在 .dockerignore 中补充 .git、\*.env、tests/ 等条目，或只 COPY 运

- 分类：`安全`
- 风险等级：`中`
- 位置：`Dockerfile:9`

\`COPY . /vampi\` 会把整个构建上下文打入镜像；当前 .dockerignore 仅排除了 Dockerfile、.dockerignore、README.md、docker-compose.yaml，未排除 .git、测试代码、\*.env 等敏感文件，存在源码与敏感信息泄露风险。建议在 .dockerignore 中补充 .git、\*.env、tests/ 等条目，或只 COPY 运行所需文件。

### 代码证据

```text
COPY . /vampi
```

## 11. \`resp\['sub'\]\` 对应的用户可能已被删除，\`user\` 为 \`None\` 时 \`user.admin\` 会抛 \`AttributeError\`。建议先判断用户是否存在并返回 401。

- 分类：`bug`
- 风险等级：`中`
- 位置：`api\_views/users.py:211-212`

\`resp\['sub'\]\` 对应的用户可能已被删除，\`user\` 为 \`None\` 时 \`user.admin\` 会抛 \`AttributeError\`。建议先判断用户是否存在并返回 401。

### 代码证据

```text
user = User.query.filter_by(username=resp['sub']).first()
        if user.admin:
```

## 12. \`apk --update add\` 是已废弃写法且会残留索引缓存；bash、nano 对构建并非必需。建议改为 \`apk add --no-cache g++\` 并移除无关包；同时 \`pip install\` 建议加 \`--no-cache-dir\` 减小缓存层。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`Dockerfile:2`

\`apk --update add\` 是已废弃写法且会残留索引缓存；bash、nano 对构建并非必需。建议改为 \`apk add --no-cache g++\` 并移除无关包；同时 \`pip install\` 建议加 \`--no-cache-dir\` 减小缓存层。

### 代码证据

```text
RUN apk --update add bash nano g++
```

### 修复建议

```text
RUN apk add --no-cache g++
```

## 13. gettext 的 \`.pot\` 翻译模板通常是源码文件，需要提交到版本库以便生成/更新各语言的 \`.po\` 文件。忽略 \`\*.pot\` 会导致翻译模板无法被跟踪。若项目使用 gettext 工作流，建议移除该规则（保留 \`\*.mo\` 即可）。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`.gitignore:50`

gettext 的 \`.pot\` 翻译模板通常是源码文件，需要提交到版本库以便生成/更新各语言的 \`.po\` 文件。忽略 \`\*.pot\` 会导致翻译模板无法被跟踪。若项目使用 gettext 工作流，建议移除该规则（保留 \`\*.mo\` 即可）。

### 代码证据

```text
*.pot
```

### 修复建议

```text
*.mo
```

## 14. \`Book.book\_title\` 在模型中是全局唯一（\`unique=True\`），但这里的重复校验只限定在“当前用户”范围内。当另一个用户已经占用了同一个书名时，此查询会返回空，代码继续执行 \`db.session.commit()\`，从而抛出未捕获的 \`IntegrityError\`，最终返回 500。建议改为按 \`book\_title\` 全局检查重复，或在 \`commit()\` 处捕获 \`

- 分类：`bug`
- 风险等级：`高`
- 位置：`api\_views/books.py:30-32`

\`Book.book\_title\` 在模型中是全局唯一（\`unique=True\`），但这里的重复校验只限定在“当前用户”范围内。当另一个用户已经占用了同一个书名时，此查询会返回空，代码继续执行 \`db.session.commit()\`，从而抛出未捕获的 \`IntegrityError\`，最终返回 500。建议改为按 \`book\_title\` 全局检查重复，或在 \`commit()\` 处捕获 \`IntegrityError\` 并返回友好提示。

### 代码证据

```text
book = Book.query.filter_by(user=user, book_title=request_data.get('book_title')).first()
        if book:
            return Response(error_message_helper("Book Already exists!"), 400, mimetype="application/json")
```

### 修复建议

```text
book = Book.query.filter_by(book_title=request_data.get('book_title')).first()
        if book:
            return Response(error_message_helper("Book Already exists!"), 400, mimetype="application/json")
```

## 15. 当 \`vuln\` 开启时，客户端可以直接提交 \`admin\` 字段注册为管理员，造成权限提升（\`register\_user\_schema\` 未设置 \`additionalProperties: false\`，因此额外字段能通过校验）。即使这是训练用途，服务端也不应信任客户端提供的 \`admin\`，应由服务端决定（例如始终 \`admin=False\` 或忽略该字段）。

- 分类：`安全`
- 风险等级：`严重`
- 位置：`api\_views/users.py:60-64`

当 \`vuln\` 开启时，客户端可以直接提交 \`admin\` 字段注册为管理员，造成权限提升（\`register\_user\_schema\` 未设置 \`additionalProperties: false\`，因此额外字段能通过校验）。即使这是训练用途，服务端也不应信任客户端提供的 \`admin\`，应由服务端决定（例如始终 \`admin=False\` 或忽略该字段）。

### 代码证据

```text
if vuln and 'admin' in request_data:  # User is possible to define if she/he wants to be an admin !!
                if request_data['admin']:
                    admin = True
                else:
                    admin = False
```

## 16. \`vuln\` 分支的邮箱正则 \`^(\[0-9a-zA-Z\](\[-.\\w\]\*\[0-9a-zA-Z\])\*@{1}...\` 存在灾难性回溯（ReDoS），攻击者可构造超长字符串拖垮服务。建议使用线性时间的校验方式（简单的非嵌套正则或库函数）并限制输入长度。

- 分类：`安全`
- 风险等级：`中`
- 位置：`api\_views/users.py:144-146`

\`vuln\` 分支的邮箱正则 \`^(\[0-9a-zA-Z\](\[-.\\w\]\*\[0-9a-zA-Z\])\*@{1}...\` 存在灾难性回溯（ReDoS），攻击者可构造超长字符串拖垮服务。建议使用线性时间的校验方式（简单的非嵌套正则或库函数）并限制输入长度。

### 代码证据

```text
match = re.search(
                r"^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@{1}([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$",
                str(request_data.get('email')))
```

## 17. 多阶段构建把 builder 的 /usr/local/lib 和 /usr/local/bin 整体覆盖到最终镜像，既可能覆盖基础镜像自身文件，也无法携带 builder 中通过 apk 安装到 /usr/lib 的运行时依赖（例如 g++ 提供的 libstdc++.so.6）。一旦某个依赖被编译为 C++ 扩展，最终容器运行时会报 \`Error loading shared library:

- 分类：`bug`
- 风险等级：`中`
- 位置：`Dockerfile:11-12`

多阶段构建把 builder 的 /usr/local/lib 和 /usr/local/bin 整体覆盖到最终镜像，既可能覆盖基础镜像自身文件，也无法携带 builder 中通过 apk 安装到 /usr/lib 的运行时依赖（例如 g++ 提供的 libstdc++.so.6）。一旦某个依赖被编译为 C++ 扩展，最终容器运行时会报 \`Error loading shared library: libstdc++.so.6\`。建议只拷贝 site-packages（如 /usr/local/lib/python3.11/site-packages）及必要的可执行脚本，或使用 \`pip install --target\` 将依赖安装到独立目录后仅拷贝该目录。

### 代码证据

```text
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/local/bin /usr/local/bin
```

### 修复建议

```text
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
```

## 18. \`debug\` 接口未做任何鉴权，直接返回 \`User.get\_all\_users\_debug()\`，其中包含所有用户的明文密码和 \`admin\` 标识，属于严重的信息泄露。建议删除该接口或加管理员鉴权并移除密码字段。

- 分类：`安全`
- 风险等级：`严重`
- 位置：`api\_views/users.py:24-26`

\`debug\` 接口未做任何鉴权，直接返回 \`User.get\_all\_users\_debug()\`，其中包含所有用户的明文密码和 \`admin\` 标识，属于严重的信息泄露。建议删除该接口或加管理员鉴权并移除密码字段。

### 代码证据

```text
def debug():
    return_value = jsonify({'users': User.get_all_users_debug()})
    return return_value
```

## 19. 未配置 \`concurrency\` 控制，连续 push 到 master 会触发多个并发构建，产生冗余镜像构建与推送。建议添加 \`concurrency\` 分组并在新提交到来时取消进行中的旧构建，例如 \`concurrency: { group: docker-image-${{ github.ref }}, cancel-in-progress: true }\`。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`.github/workflows/docker-image.yml:3-5`

未配置 \`concurrency\` 控制，连续 push 到 master 会触发多个并发构建，产生冗余镜像构建与推送。建议添加 \`concurrency\` 分组并在新提交到来时取消进行中的旧构建，例如 \`concurrency: { group: docker-image-${{ github.ref }}, cancel-in-progress: true }\`。

### 代码证据

```text
on:
  push:
    branches: [ "master" ]
```

### 修复建议

```text
on:
  push:
    branches: [ "master" ]

concurrency:
  group: docker-image-${{ github.ref }}
  cancel-in-progress: true
```

## 20. 这里用字符串拼接构造 JSON，未对消息做转义。当 \`msg\` 中包含引号、反斜杠或换行时（例如 jsonschema 的校验消息）会生成非法 JSON，客户端无法解析，且存在注入风险。建议使用 \`json.dumps\` 构造响应。

- 分类：`bug`
- 风险等级：`中`
- 位置：`api\_views/users.py:13-16`

这里用字符串拼接构造 JSON，未对消息做转义。当 \`msg\` 中包含引号、反斜杠或换行时（例如 jsonschema 的校验消息）会生成非法 JSON，客户端无法解析，且存在注入风险。建议使用 \`json.dumps\` 构造响应。

### 代码证据

```text
if isinstance(msg, dict):
        return '{ "status": "fail", "message": "' + msg['error'] + '"}'
    else:
        return '{ "status": "fail", "message": "' + msg + '"}'
```

### 修复建议

```text
return json.dumps({"status": "fail", "message": msg.get("error") if isinstance(msg, dict) else msg})
```

## 21. 最终容器没有 USER 指令，默认以 root 身份运行应用；应用一旦被攻破即可获得容器内 root 权限。建议创建非特权用户并在启动前切换：

- 分类：`安全`
- 风险等级：`中`
- 位置：`Dockerfile:16-17`

最终容器没有 USER 指令，默认以 root 身份运行应用；应用一旦被攻破即可获得容器内 root 权限。建议创建非特权用户并在启动前切换：

### 代码证据

```text
ENTRYPOINT ["python"]
CMD ["app.py"]
```

### 修复建议

```text
RUN addgroup -S app &amp;&amp; adduser -S app -G app &amp;&amp; chown -R app:app /vampi
USER app
```

## 22. 使用 SQLite 时，SQLAlchemy 默认连接池（QueuePool）会在不同线程之间复用同一个连接，而 pysqlite 的 check\_same\_thread 默认为 True。app.py 通过 vuln\_app.run 启动应用，Flask 1.0+ 默认 threaded=True，并发请求下连接会被跨线程复用，触发 ProgrammingError: SQLite object

- 分类：`bug`
- 风险等级：`中`
- 位置：`config.py:10`

使用 SQLite 时，SQLAlchemy 默认连接池（QueuePool）会在不同线程之间复用同一个连接，而 pysqlite 的 check\_same\_thread 默认为 True。app.py 通过 vuln\_app.run 启动应用，Flask 1.0+ 默认 threaded=True，并发请求下连接会被跨线程复用，触发 ProgrammingError: SQLite objects created in a thread can only be used in that same thread。建议显式关闭该检查。

### 代码证据

```text
vuln_app.app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
```

### 修复建议

```text
vuln_app.app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'connect_args': {'check_same_thread': False},
}
```

## 23. \`ENV vulnerable=1\` 使应用默认以漏洞模式启动。若该镜像是故意用于漏洞演示（如 VAmPI）可保留，但一旦被部署到其他环境会带来安全风险；建议通过 ARG 注入并在默认情况下设为 0（或明确仅用于实验环境）。

- 分类：`安全`
- 风险等级：`低`
- 位置：`Dockerfile:13`

\`ENV vulnerable=1\` 使应用默认以漏洞模式启动。若该镜像是故意用于漏洞演示（如 VAmPI）可保留，但一旦被部署到其他环境会带来安全风险；建议通过 ARG 注入并在默认情况下设为 0（或明确仅用于实验环境）。

### 代码证据

```text
ENV vulnerable=1
```

## 24. 初始化逻辑写入了硬编码的管理员弱口令 \`pass1\`，且 \`register\_user\` 以明文保存。若该初始化逻辑被部署到生产环境，攻击者可使用默认凭据直接登录管理员账户。建议使用随机强密码并强制首次登录修改，至少不要在源码中硬编码默认凭据。

- 分类：`安全`
- 风险等级：`中`
- 位置：`models/user\_model.py:101`

初始化逻辑写入了硬编码的管理员弱口令 \`pass1\`，且 \`register\_user\` 以明文保存。若该初始化逻辑被部署到生产环境，攻击者可使用默认凭据直接登录管理员账户。建议使用随机强密码并强制首次登录修改，至少不要在源码中硬编码默认凭据。

### 代码证据

```text
User.register_user("admin", "pass1", "admin@mail.com", True)
```

## 25. \`resp\['sub'\]\` 对应的用户可能已不存在（token 仍有效但用户被删除），\`user\` 为 \`None\` 时访问 \`user.username\` 会抛 \`AttributeError\` 返回 500。建议在访问前判断 \`if not user:\` 并返回 401/404。

- 分类：`bug`
- 风险等级：`中`
- 位置：`api\_views/users.py:33-34`

\`resp\['sub'\]\` 对应的用户可能已不存在（token 仍有效但用户被删除），\`user\` 为 \`None\` 时访问 \`user.username\` 会抛 \`AttributeError\` 返回 500。建议在访问前判断 \`if not user:\` 并返回 401/404。

### 代码证据

```text
user = User.query.filter_by(username=resp['sub']).first()
        responseObject = {
```

## 26. \`user\_id\` 列未设置 \`nullable=False\`，因此当 Book 没有关联用户时 \`self.user\` 为 \`None\`，\`self.user.username\` 会抛出 AttributeError。建议在序列化时做空值兜底。

- 分类：`bug`
- 风险等级：`中`
- 位置：`models/books\_model.py:24`

\`user\_id\` 列未设置 \`nullable=False\`，因此当 Book 没有关联用户时 \`self.user\` 为 \`None\`，\`self.user.username\` 会抛出 AttributeError。建议在序列化时做空值兜底。

### 代码证据

```text
return {'book_title': self.book_title, 'user': self.user.username}
```

### 修复建议

```text
return {'book_title': self.book_title, 'user': self.user.username if self.user else None}
```

## 27. \`request.get\_json()\` 在请求体为 JSON \`null\` 或 JSON 字符串等非对象时返回 \`None\`/字符串，这里在 schema 校验之前就调用 \`request\_data.get('username')\`，会抛出 \`AttributeError\` 导致 500。建议先判断 \`isinstance(request\_data, dict)\` 或先做 schema 校验再取

- 分类：`bug`
- 风险等级：`高`
- 位置：`api\_views/users.py:53-55`

\`request.get\_json()\` 在请求体为 JSON \`null\` 或 JSON 字符串等非对象时返回 \`None\`/字符串，这里在 schema 校验之前就调用 \`request\_data.get('username')\`，会抛出 \`AttributeError\` 导致 500。建议先判断 \`isinstance(request\_data, dict)\` 或先做 schema 校验再取值。

### 代码证据

```text
request_data = request.get_json()
    # check if user already exists
    user = User.query.filter_by(username=request_data.get('username')).first()
```

### 修复建议

```text
request_data = request.get_json()
    if not isinstance(request_data, dict):
        return Response(error_message_helper("Please provide a proper JSON body."), 400, mimetype="application/json")
    user = User.query.filter_by(username=request_data.get('username')).first()
```

## 28. 编码 token 失败时把异常对象本身当作返回值返回（\`return e\`），调用方得到的是 \`Exception\` 实例而非 token 或统一错误结构，类型不一致，极易在后续逻辑中被误当作 token 使用，导致难以定位的问题。建议重新抛出异常，或返回 \`None\`/明确的错误结构并记录日志。

- 分类：`bug`
- 风险等级：`高`
- 位置：`models/user\_model.py:42-43`

编码 token 失败时把异常对象本身当作返回值返回（\`return e\`），调用方得到的是 \`Exception\` 实例而非 token 或统一错误结构，类型不一致，极易在后续逻辑中被误当作 token 使用，导致难以定位的问题。建议重新抛出异常，或返回 \`None\`/明确的错误结构并记录日志。

### 代码证据

```text
except Exception as e:
            return e
```

## 29. 默认参数 \`user\_id=user\_id\` 在类定义时被求值，此时右侧的 \`user\_id\` 是类属性（SQLAlchemy 的 \`Column\` 对象），而不是 \`None\`。调用 \`Book(book\_title, secret\_content)\` 时会把 \`self.user\_id\` 赋值为该 Column 对象，导致后续持久化时报错或写入错误数据。建议默认值改为 \`None\`。

- 分类：`bug`
- 风险等级：`高`
- 位置：`models/books\_model.py:15`

默认参数 \`user\_id=user\_id\` 在类定义时被求值，此时右侧的 \`user\_id\` 是类属性（SQLAlchemy 的 \`Column\` 对象），而不是 \`None\`。调用 \`Book(book\_title, secret\_content)\` 时会把 \`self.user\_id\` 赋值为该 Column 对象，导致后续持久化时报错或写入错误数据。建议默认值改为 \`None\`。

### 代码证据

```text
def __init__(self, book_title, secret_content, user_id=user_id):
```

### 修复建议

```text
def __init__(self, book_title, secret_content, user_id=None):
```

## 30. 通配符导入 \`from models.user\_model import \*\` 会掩盖本模块中 \`db\`、\`User\` 的真实来源，并且一旦 \`models.user\_model\` 的导出内容发生变化，本模块可能静默出现 \`NameError\` 或引入不期望的符号。建议改为显式导入所需名称：\`from models.user\_model import User\` 以及 \`from config i

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`api\_views/main.py:3`

通配符导入 \`from models.user\_model import \*\` 会掩盖本模块中 \`db\`、\`User\` 的真实来源，并且一旦 \`models.user\_model\` 的导出内容发生变化，本模块可能静默出现 \`NameError\` 或引入不期望的符号。建议改为显式导入所需名称：\`from models.user\_model import User\` 以及 \`from config import db\`。

### 代码证据

```text
from models.user_model import *
```

### 修复建议

```text
from models.user_model import User
from config import db
```

## 31. 第三方 action 仅以可变标签引用（\`@v2\`/\`@v3\`），标签可被覆盖导致供应链风险，且这些版本已过时。建议固定到完整 commit SHA，并升级到当前版本（例如 \`docker/setup-qemu-action@v3\`、\`docker/setup-buildx-action@v3\`、\`docker/login-action@v3\`、\`docker/build-push-action@

- 分类：`安全`
- 风险等级：`中`
- 位置：`.github/workflows/docker-image.yml:16`

第三方 action 仅以可变标签引用（\`@v2\`/\`@v3\`），标签可被覆盖导致供应链风险，且这些版本已过时。建议固定到完整 commit SHA，并升级到当前版本（例如 \`docker/setup-qemu-action@v3\`、\`docker/setup-buildx-action@v3\`、\`docker/login-action@v3\`、\`docker/build-push-action@v6\`）。

### 代码证据

```text
uses: docker/setup-qemu-action@v2
```

## 32. 裸 \`except:\` 捕获范围过宽，会吞掉所有异常（包括 \`KeyboardInterrupt\`/\`SystemExit\`），且无法区分校验失败与真正的服务器错误。建议捕获具体的 \`jsonschema.exceptions.ValidationError\`。

- 分类：`bug`
- 风险等级：`中`
- 位置：`api\_views/users.py:134-136`

裸 \`except:\` 捕获范围过宽，会吞掉所有异常（包括 \`KeyboardInterrupt\`/\`SystemExit\`），且无法区分校验失败与真正的服务器错误。建议捕获具体的 \`jsonschema.exceptions.ValidationError\`。

### 代码证据

```text
try:
        jsonschema.validate(request_data, update_email_schema)
    except:
```

## 33. \`\_\_repr\_\_\` 返回的是 \`&lt;User(...)&gt;\`，但当前类是 \`Book\`，日志排查时会产生误导。建议改为 \`&lt;Book(...)&gt;\`。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`models/books\_model.py:21`

\`\_\_repr\_\_\` 返回的是 \`&lt;User(...)&gt;\`，但当前类是 \`Book\`，日志排查时会产生误导。建议改为 \`&lt;Book(...)&gt;\`。

### 代码证据

```text
return f"&lt;User(book_title={self.book_title}, user={self.user})&gt;"
```

### 修复建议

```text
return f"&lt;Book(book_title={self.book_title}, user={self.user})&gt;"
```

## 34. token 校验通过后 \`User.query.filter\_by(username=resp\['sub'\]).first()\` 可能返回 \`None\`（例如用户已被删除但 token 尚未过期），随后访问 \`user.id\` 会抛出 \`AttributeError\`，导致 500。建议先判断 \`user\` 是否存在，不存在时返回 401/404。

- 分类：`bug`
- 风险等级：`中`
- 位置：`api\_views/books.py:27-30`

token 校验通过后 \`User.query.filter\_by(username=resp\['sub'\]).first()\` 可能返回 \`None\`（例如用户已被删除但 token 尚未过期），随后访问 \`user.id\` 会抛出 \`AttributeError\`，导致 500。建议先判断 \`user\` 是否存在，不存在时返回 401/404。

### 代码证据

```text
user = User.query.filter_by(username=resp['sub']).first()

        # check if user already has this book title
        book = Book.query.filter_by(user=user, book_title=request_data.get('book_title')).first()
```

### 修复建议

```text
user = User.query.filter_by(username=resp['sub']).first()
        if not user:
            return Response(error_message_helper("User not found!"), 401, mimetype="application/json")

        # check if user already has this book title
        book = Book.query.filter_by(user=user, book_title=request_data.get('book_title')).first()
```

## 35. \`get\_all\_books\` 中每次调用 \`json\` 都会访问 \`self.user\`，在默认懒加载下会对每本书产生一次额外查询，形成 N+1 查询。建议使用 \`joinedload\` 预加载用户关系。

- 分类：`性能`
- 风险等级：`低`
- 位置：`models/books\_model.py:28`

\`get\_all\_books\` 中每次调用 \`json\` 都会访问 \`self.user\`，在默认懒加载下会对每本书产生一次额外查询，形成 N+1 查询。建议使用 \`joinedload\` 预加载用户关系。

### 代码证据

```text
return [Book.json(user) for user in Book.query.all()]
```

### 修复建议

```text
return [Book.json(book) for book in Book.query.options(joinedload(Book.user)).all()]
```

## 36. job 未设置 \`timeout-minutes\`，构建若出现挂起（如网络/构建问题）会无限期占用 runner。建议为 job 添加合理的超时，例如 \`timeout-minutes: 30\`。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`.github/workflows/docker-image.yml:9`

job 未设置 \`timeout-minutes\`，构建若出现挂起（如网络/构建问题）会无限期占用 runner。建议为 job 添加合理的超时，例如 \`timeout-minutes: 30\`。

### 代码证据

```text
build:
```

### 修复建议

```text
build:
    timeout-minutes: 30
```

## 37. 硬编码了可预测的 SECRET\_KEY（'random'）。该密钥同时用于 Flask session 签名以及 JWT 的 HS256 签发/校验（见 user\_model.py 中的 jwt.decode），攻击者一旦得知这个固定值即可伪造 session 和认证 token，属于可直接利用的认证绕过风险。建议改为从环境变量读取密钥，缺失时使用强随机回退（需在文件顶部 \`import secr

- 分类：`安全`
- 风险等级：`严重`
- 位置：`config.py:13`

硬编码了可预测的 SECRET\_KEY（'random'）。该密钥同时用于 Flask session 签名以及 JWT 的 HS256 签发/校验（见 user\_model.py 中的 jwt.decode），攻击者一旦得知这个固定值即可伪造 session 和认证 token，属于可直接利用的认证绕过风险。建议改为从环境变量读取密钥，缺失时使用强随机回退（需在文件顶部 \`import secrets\`）。

### 代码证据

```text
vuln_app.app.config['SECRET_KEY'] = 'random'
```

### 修复建议

```text
vuln_app.app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
```

## 38. 该规则仅忽略精确名称 \`.env\`。实际项目常使用 \`.env.local\`、\`.env.production\`、\`.env.staging\` 等变体文件存放密钥，这些文件不会被忽略，存在误提交敏感信息的风险。建议增加 \`.env.\*\` 规则，并用 \`!.env.example\` 等例外保留需要提交的示例文件。

- 分类：`安全`
- 风险等级：`中`
- 位置：`.gitignore:83`

该规则仅忽略精确名称 \`.env\`。实际项目常使用 \`.env.local\`、\`.env.production\`、\`.env.staging\` 等变体文件存放密钥，这些文件不会被忽略，存在误提交敏感信息的风险。建议增加 \`.env.\*\` 规则，并用 \`!.env.example\` 等例外保留需要提交的示例文件。

### 代码证据

```text
.env
```

### 修复建议

```text
.env
.env.*
!.env.example
```

## 39. \`jwt\` 在本文件中未被使用（token 编解码在 models/user\_model.py 中完成），\`from config import vuln\_app\` 中的 \`vuln\_app\` 也未使用，属于死代码，建议删除。

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`api\_views/users.py:3`

\`jwt\` 在本文件中未被使用（token 编解码在 models/user\_model.py 中完成），\`from config import vuln\_app\` 中的 \`vuln\_app\` 也未使用，属于死代码，建议删除。

### 代码证据

```text
import jwt
```

## 40. \`basic()\` 通过字符串拼接手工构造 JSON 响应。当前常量值恰好能生成合法 JSON，但一旦 \`help\` 等文本包含双引号或反斜杠，或 \`vuln\` 变为非数值类型（\`str.format\` 输出不再是合法 JSON 字面量），就会在声明 \`mimetype='application/json'\` 的情况下返回非法 JSON。建议使用 \`jsonify\` 或 \`json.dumps\`

- 分类：`可维护性`
- 风险等级：`低`
- 位置：`api\_views/main.py:15-17`

\`basic()\` 通过字符串拼接手工构造 JSON 响应。当前常量值恰好能生成合法 JSON，但一旦 \`help\` 等文本包含双引号或反斜杠，或 \`vuln\` 变为非数值类型（\`str.format\` 输出不再是合法 JSON 字面量），就会在声明 \`mimetype='application/json'\` 的情况下返回非法 JSON。建议使用 \`jsonify\` 或 \`json.dumps\` 构造响应，由序列化器统一处理转义。

### 代码证据

```text
response_text = '{ "message": "VAmPI the Vulnerable API", "help": "VAmPI is a vulnerable on purpose API. It was ' \
                    'created in order to evaluate the efficiency of third party tools in identifying vulnerabilities ' \
                    'in APIs but it can also be used in learning/teaching purposes.", "vulnerable":' + "{}".format(vuln) + "}"
```

### 修复建议

```text
response_text = json.dumps({
        "message": "VAmPI the Vulnerable API",
        "help": "VAmPI is a vulnerable on purpose API. It was created in order to evaluate the efficiency of third party tools in identifying vulnerabilities in APIs but it can also be used in learning/teaching purposes.",
        "vulnerable": vuln,
    })
```

## 41. HTTP 204（No Content）不应携带响应体，部分客户端/代理会丢弃或报错。这里返回 204 却附带了 JSON 正文（\`update\_email\` 中两处也存在同样问题）。建议改为 200。

- 分类：`bug`
- 风险等级：`中`
- 位置：`api\_views/users.py:197-201`

HTTP 204（No Content）不应携带响应体，部分客户端/代理会丢弃或报错。这里返回 204 却附带了 JSON 正文（\`update\_email\` 中两处也存在同样问题）。建议改为 200。

### 代码证据

```text
responseObject = {
                'status': 'success',
                'Password': 'Updated.'
            }
            return Response(json.dumps(responseObject), 204, mimetype="application/json")
```

## 42. 密码以明文形式直接存储（\`register\_user\` 从请求中读取 \`password\` 后原样保存），未做任何哈希或加盐处理。一旦数据库泄露，所有用户凭据将直接暴露。建议使用 \`werkzeug.security.generate\_password\_hash\` / \`check\_password\_hash\` 或 bcrypt 等方案存储密码摘要。

- 分类：`安全`
- 风险等级：`高`
- 位置：`models/user\_model.py:24`

密码以明文形式直接存储（\`register\_user\` 从请求中读取 \`password\` 后原样保存），未做任何哈希或加盐处理。一旦数据库泄露，所有用户凭据将直接暴露。建议使用 \`werkzeug.security.generate\_password\_hash\` / \`check\_password\_hash\` 或 bcrypt 等方案存储密码摘要。

### 代码证据

```text
self.password = password
```

## 43. \`resp\['sub'\]\` 对应的用户可能已被删除，\`user\` 为 \`None\` 时后续 \`user.email = ...\` 会抛 \`AttributeError\` 返回 500。建议先判断用户是否存在。

- 分类：`bug`
- 风险等级：`中`
- 位置：`api\_views/users.py:142-143`

\`resp\['sub'\]\` 对应的用户可能已被删除，\`user\` 为 \`None\` 时后续 \`user.email = ...\` 会抛 \`AttributeError\` 返回 500。建议先判断用户是否存在。

### 代码证据

```text
user = User.query.filter_by(username=resp['sub']).first()
        if vuln:  # Regex DoS
```

## 44. 这里使用了裸 \`except:\`，会吞掉包括 \`KeyboardInterrupt\`、\`SystemExit\` 在内的所有异常，并且无论 JSON 格式错误、schema 校验失败还是其他异常都返回同一句“JSON body”提示，掩盖了真实错误。建议捕获具体的 \`jsonschema.exceptions.ValidationError\` 并返回其 \`message\`（与本项目 users.py

- 分类：`可维护性`
- 风险等级：`中`
- 位置：`api\_views/books.py:19-22`

这里使用了裸 \`except:\`，会吞掉包括 \`KeyboardInterrupt\`、\`SystemExit\` 在内的所有异常，并且无论 JSON 格式错误、schema 校验失败还是其他异常都返回同一句“JSON body”提示，掩盖了真实错误。建议捕获具体的 \`jsonschema.exceptions.ValidationError\` 并返回其 \`message\`（与本项目 users.py 中的写法一致）。

### 代码证据

```text
try:
        jsonschema.validate(request_data, add_book_schema)
    except:
        return Response(error_message_helper("Please provide a proper JSON body."), 400, mimetype="application/json")
```

### 修复建议

```text
try:
        jsonschema.validate(request_data, add_book_schema)
    except jsonschema.exceptions.ValidationError as exc:
        return Response(error_message_helper(exc.message), 400, mimetype="application/json")
```

## 45. \`json\_debug\` 将明文密码直接返回给调用方，配合 \`get\_all\_users\_debug\` 会批量泄露所有用户的密码。对外接口不应暴露 \`password\` 字段，即使调试接口也应返回脱敏后的数据。

- 分类：`安全`
- 风险等级：`高`
- 位置：`models/user\_model.py:58-59`

\`json\_debug\` 将明文密码直接返回给调用方，配合 \`get\_all\_users\_debug\` 会批量泄露所有用户的密码。对外接口不应暴露 \`password\` 字段，即使调试接口也应返回脱敏后的数据。

### 代码证据

```text
def json_debug(self):
        return {'username': self.username, 'password': self.password, 'email': self.email, 'admin': self.admin}
```

## 46. \`request.get\_json()\` 在 body 为 \`null\`/非对象时返回 \`None\`，此处直接 \`request\_data.get('password')\` 会抛 \`AttributeError\`；且非 \`vuln\` 分支未判断 \`user\` 是否存在，\`user.password\` 也会因 \`None\` 崩溃。建议先校验 \`request\_data\` 类型并判断用户是否存在。

- 分类：`bug`
- 风险等级：`高`
- 位置：`api\_views/users.py:185`

\`request.get\_json()\` 在 body 为 \`null\`/非对象时返回 \`None\`，此处直接 \`request\_data.get('password')\` 会抛 \`AttributeError\`；且非 \`vuln\` 分支未判断 \`user\` 是否存在，\`user.password\` 也会因 \`None\` 崩溃。建议先校验 \`request\_data\` 类型并判断用户是否存在。

### 代码证据

```text
if request_data.get('password'):
```

## 47. 该 .dockerignore 仅排除了 Dockerfile、.dockerignore、README.md、docker-compose.yaml 四个文件，缺少对常见敏感文件和体积较大目录的排除规则。构建上下文（build context）会把当前目录下所有未被排除的内容发送给 Docker daemon：若 Dockerfile 中存在 \`COPY . .\` 之类的指令，本地存在的 \`.e

- 分类：`安全`
- 风险等级：`中`
- 位置：`.dockerignore:1-4`

该 .dockerignore 仅排除了 Dockerfile、.dockerignore、README.md、docker-compose.yaml 四个文件，缺少对常见敏感文件和体积较大目录的排除规则。构建上下文（build context）会把当前目录下所有未被排除的内容发送给 Docker daemon：若 Dockerfile 中存在 \`COPY . .\` 之类的指令，本地存在的 \`.env\`、密钥文件等敏感信息会被打进镜像层，造成凭据泄露；同时 \`.git\` 目录会显著增大上下文体积并可能将仓库历史（含已删除的敏感内容）暴露给构建环境。建议至少补充 \`.git\`、\`.env\`、\`\*.log\` 以及依赖/构建产物目录（如 node\_modules、dist，具体按项目技术栈调整）的排除规则。

### 代码证据

```text
Dockerfile
.dockerignore
README.md
docker-compose.yaml
```

### 修复建议

```text
Dockerfile
.dockerignore
README.md
docker-compose.yaml

.git
.env
*.log
node_modules
dist
```

## 48. 密码以明文存储（\`User.password\` 为明文列）并在此处直接用 \`==\` 比较，存在明文密码泄露和登录校验风险。应使用 bcrypt/argon2 等哈希算法存储密码，并用校验函数比较。

- 分类：`安全`
- 风险等级：`严重`
- 位置：`api\_views/users.py:93`

密码以明文存储（\`User.password\` 为明文列）并在此处直接用 \`==\` 比较，存在明文密码泄露和登录校验风险。应使用 bcrypt/argon2 等哈希算法存储密码，并用校验函数比较。

### 代码证据

```text
if user and request_data.get('password') == user.password:
```

## 49. \`username\` 来自外部请求参数（api\_views/users.py 的 \`get\_by\_username\` 直接透传），这里通过 f-string 拼接到 SQL 语句中，存在 SQL 注入漏洞，攻击者可构造恶意用户名执行任意 SQL。应改为参数化查询，避免拼接用户输入。

- 分类：`安全`
- 风险等级：`严重`
- 位置：`models/user\_model.py:72-73`

\`username\` 来自外部请求参数（api\_views/users.py 的 \`get\_by\_username\` 直接透传），这里通过 f-string 拼接到 SQL 语句中，存在 SQL 注入漏洞，攻击者可构造恶意用户名执行任意 SQL。应改为参数化查询，避免拼接用户输入。

### 代码证据

```text
user_query = f"SELECT * FROM users WHERE username = '{username}'"
            query = db.session.execute(text(user_query))
```

### 修复建议

```text
user_query = text("SELECT * FROM users WHERE username = :username")
            query = db.session.execute(user_query, {"username": username})
```
