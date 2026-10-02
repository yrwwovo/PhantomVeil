# HTML 输入入口清点

`evidence_input_inventory` 从一个已经保存并通过 SHA-256 校验的 EV 证据中，
读取静态 HTML 里的表单、控件及查询参数名称。整个过程离线运行，不再访问网站。

在 OpenCode 重启并选择 `Phant0mV3il` 后，可以使用：

```text
请用 evidence_input_inventory 分析 EV-20260922075431-d87fbb05，告诉我页面有哪些表单和参数入口。
```

工具只接受 EV 编号，不接受文件路径。它会返回：

- 表单的 GET、POST 或 dialog 方法；
- 去掉查询值和片段后的 action 地址，以及是否与原页面同源；
- `input`、`select`、`textarea`、`button` 的名称、类型、required 和 disabled 状态；
- 普通链接中出现过的查询参数名称，但不返回参数值。

## 安全边界

- 不发送 HTTP 请求、不提交表单、不修改证据或 HYP。
- 不返回 HTML 中的 `value`，链接和 action 的查询值也会被去掉。
- 不执行 JavaScript，因此看不到运行脚本后才生成的控件、XHR、fetch 或 WebSocket 交互。
- 发现外部 action 只会标记 `same_origin: false`，不会因此获得访问授权。
- 最多记录 50 个表单、500 个控件和 100 个查询端点；达到上限会标记 `truncated`。
- 清点结果只是后续测试入口，不表示存在 SQL 注入、XSS、越权或其他漏洞。

单个 EV 可以使用本工具单独复核。受限爬虫也会对本次成功取得的 HTML 页面运行相同解析，
把重复的表单 action 和查询端点合并进 `CRAWL-*.md` 中文报告；仍然不会提交表单或跟进带参数链接。
