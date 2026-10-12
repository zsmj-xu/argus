# WebGoat 默认整仓评测

正式扫描：`73d27937e980444e8d32d01f65d575df`；提交：`044948d057b249735be2bfc14eccc9e3dc2eac34`。include/exclude 为空，background 为 null。

## 结果

默认 1800 秒后以 `ocr_timeout` 失败，OCR 运行 1800039 毫秒，退出码 -9。保留的事件进度为 713 个可审查文件中完成 141、失败 1、跳过 0；其余 571 未完成，其中 8 个已开始被中断、563 个未开始。

没有返回终态 `ocr.scan-result/v1`，没有规范化发现，token 用量未知。141/713 来自已持久化结构化事件，不是终态完整覆盖证明。**零交付发现不表示零漏洞。** 失败报告接口可读取，但不是可用的完整漏洞报告。

完成文件包括 33 CSS、73 HTML、35 Java；Java 中 12 位于 src/it、22 位于 src/main，其余 1 个在其他目录。单文件失败是 `src/main/resources/lessons/spoofcookie/lessonSolutions/html/SpoofCookie.html`，事件未给出足以确定原因的说明。没有事件丢弃或拒收记录。

预设 9 个漏洞案例对应文件均未开始。正式端到端案例交付计 0/9；无法据此判断模型对这些漏洞的推理能力。旧局部扫描结果不计入本次成绩。逐案例及事件证据见 [WebGoat-review.json](WebGoat-review.json)、[WebGoat-events.json](WebGoat-events.json) 和 [WebGoat-scan.json](WebGoat-scan.json)。

## 默认流程的限制

固定 OCR 源码的 `internal/config/template/scan_template.json:84` 使用 `by-language`；`internal/scan/batch.go:63` 对语言扩展分组键排序；`internal/scan/agent.go` 依序等待批次。实际事件显示先处理 CSS、HTML，再进入 Java 集成测试和框架代码，超时前没有触及上述核心漏洞课程。这解释了本次默认时间内的覆盖分布，不代表调整顺序一定能保证整仓完成。

超时后保留了文件进度，但已经完成的文件没有交付可用发现，说明当前末尾统一产出结果的方式影响大仓库可用性。建议后续研究中间结果持久化、文件优先级和执行时限配置；本次没有修改扫描实现或缩小范围重跑，也没有实现续传。
