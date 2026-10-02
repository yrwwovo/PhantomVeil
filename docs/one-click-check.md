# 单 URL 一键检查

目标是让使用者输入一个 URL 就得到中文结果，不必手动传递 EV 编号。

## 流程与边界

`authorized_web_check(url)` 和 `npm run scan -- URL` 共用 `src/workflows/web-check.ts`：

1. 读取本项目的 `configs/scope.local.json` 和 `configs/http.local.json`。
2. 调用原有受限 GET：每次连接都经过范围、解析 IP 和重定向校验。
3. 保存一份 HTTP 证据。
4. 重新校验证据，执行已有五项响应头规则，生成一份中文检查报告。
5. 返回可直接显示的 `user_summary` 与结构化规则结果。`trace` 保存证据和报告编号、路径。

不发生重定向时仅发一次 GET；发生重定向时连接次数遵循原有 `max_redirects` 限制，
不会因为检查不同规则重复请求，也不会自动重试。保留已有超时与响应大小限制。
本入口不枚举页面、提交表单、创建 HYP 或自动确认漏洞，不使用假设创建授权来扩大网络权限。

CLI 无需模型 API，固定从脚本自身位置定位本项目配置。API 密钥与模型提供商无关。
报告中的目标 URL 和返回摘要移除查询串与片段；正文、原始响应头值不进入模型摘要或检查报告。
EV 保留原有证据存储和常见秘密字段脱敏规则；它不是对所有可能秘密的全面识别。

## 运行

```powershell
cd D:\Projects\security-agent-lab
npm run scan -- http://127.0.0.1:5000/
```

目标网站需要运行，且已被本地范围及连接策略允许。OpenCode 中重启项目、选择
`web-security-agent`，直接说“扫描 http://127.0.0.1:5000/，给我中文结果”。
当前单 URL 的响应头检查范围应体现在回答中。若用户要求查看证据，才展开 `trace`。

## 结果与失败

- `WEB_CHECK_COMPLETED`：流程完成，含中文摘要、结果和追溯信息。
- `INVALID_INPUT` / `CONFIG_ERROR`：输入或配置有问题，未启动检查。
- `HTTP_REJECTED`：没有取得可分析响应，包含底层原因码，如范围拒绝或连接失败。
- `EVIDENCE_ERROR`：响应取得，但证据未成功保存。
- `REPORT_ERROR`：证据已保存，报告未完成；`trace` 可用于后续离线分析，避免重发请求。

4xx/5xx 响应也可以检查其响应头，但摘要会说明它不能代表正常业务页面。
CLI 完成返回 `0`，未完成返回 `2`。结果中的 `review` 不属于程序运行失败。
五项规则的限制仍见 `security-header-check.md`；全部通过也不代表网站整体安全。
