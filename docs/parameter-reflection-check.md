# 受限 GET 参数反射检查

这是项目第一个主动但低影响的参数检查。它只对已经出现在可信 HTML 证据中的一个
同源 GET 表单参数发送一次随机标记，例如 `PV-REFLECT-...`，随后观察该标记是否出现
在响应正文中。

## 使用前提

- 来源 EV 必须通过结构和 SHA-256 校验；
- 表单必须来自该 EV 的静态 HTML，方法必须是 GET；
- 参数必须是该表单中可提交的命名控件；
- action 必须有效、同源且不含需要复用的已有查询值；
- 项目 Scope、HTTP IP 策略和独立授权登记必须同时允许目标；
- 授权记录的 `actions` 必须包含 `parameter_reflection_check`。

## 命令行验证

```powershell
npm run reflection:check -- EV-20260922075431-d87fbb05 1 q LOCAL-LAB-EXAMPLE
```

四个参数依次是来源 EV、表单序号、参数名称和本地授权引用。表单序号来自
`evidence_input_inventory`。命令会新增一次 GET 请求、一份 EV 和一份 `RFL-*.md` 报告。

OpenCode 重启后可以说：

```text
请用 authorized_parameter_reflection_check 检查 EV-20260922075431-d87fbb05 中第 1 个表单的 q 参数，授权引用为 LOCAL-LAB-EXAMPLE。只进行一次无害反射检查。
```

该 Tool 在执行函数中调用 OpenCode `context.ask()`，使用独立的
`parameter_reflection_check: ask` 权限逐次询问批准。没有审批接口或用户拒绝时默认停止。
Agent 不得自行猜测授权引用。

## 结果含义

- `reflected`：随机标记出现在响应正文中，只证明输入可能被反射。
- `not_reflected`：本次正文中未出现标记，不能排除存储或异步处理等情况。
- `inconclusive`：HTTP 状态或响应类型不适合判断。

这些结果都不是 XSS、SQL 注入或其他漏洞结论。工具不使用攻击载荷、不执行脚本、
不提交 POST、不测试登录注册、不跟随重定向，也不会自动创建或确认 HYP。
