# WebGoat 不限时整仓扫描

扫描 `2ef1360411d245e0a5640e967c98c683` 没有总执行时限或单文件时限；include/exclude 为空，background 为 null。

运行 6,389,551 毫秒（约 106 分钟）。事件显示总文件 726，完成 691、失败 35。OCR 退出码为 0，但 stdout 最终结果 27,015,631 字节，超过 Argus 原有 8 MiB 接收上限；stderr 仅 4,511 字节。结果被截断，服务以 `ocr_output_limit` 失败，交付发现数为 0。文件进度 100% 不代表完整成功，35 个失败文件仍需计入。

证据保存在 [WebGoat-scan.json](WebGoat-scan.json) 和 [WebGoat-events.json](WebGoat-events.json)。没有保留原始 stdout、模型响应或 native OCR transcript，因此不能从这次截断结果恢复完整漏洞报告。

修复：stdout 最终结果接收上限调整为 64 MiB；stderr 诊断上限仍为 8 MiB。仍保留有限内存边界和手动取消，默认没有扫描执行时限。新增真实子进程回归测试验证约 27 MiB 结果完整解析；完整测试 126 通过、3 跳过。

修复后新整仓任务的登记见 [WebGoat-retry-scan.json](WebGoat-retry-scan.json)。原失败记录保留，新任务不排除任何目录。该次重试也已终止：状态 failed，错误 ocr_invalid_output；结果记录为 726 个文件、审查成功 0、失败 726，未交付规范化发现。没有用后续较大输出容量将其改写为成功。用量事件功能是在这次重试后才部署，历史用量仍未知。
