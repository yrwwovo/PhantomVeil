# HTTP 安全响应头检查

这是项目的第一项自动安全检查。它读取 `authorized_web_observe` 已保存且通过
SHA-256 校验的 EV 证据，离线分析响应头；不会再次访问网站，也不会修改证据或假设。

## 当前规则

| 规则 | 适用条件 | 通过条件 |
| --- | --- | --- |
| `HDR-CONTENT-TYPE` | 有响应正文 | 存在 `Content-Type` |
| `HDR-NOSNIFF` | 有响应正文 | `X-Content-Type-Options` 为 `nosniff` |
| `HDR-CSP` | 已识别的 HTML/XHTML | 存在 `Content-Security-Policy` |
| `HDR-FRAME-ANCESTORS` | 已识别的 HTML/XHTML | CSP 含 `frame-ancestors`，或 `X-Frame-Options` 为 `DENY`/`SAMEORIGIN` |
| `HDR-HSTS` | HTTPS URL | HSTS 含大于零的 `max-age` |

结果分为 `pass`、`review` 和 `not_applicable`。`review` 表示需要结合页面用途、
资源来源和部署方式复核，不能直接写成“存在漏洞”；`not_applicable` 不算失败。
即使全部通过，也只能说明这组有限规则没有发现问题，不能证明网站整体安全。

规则参考 [OWASP Secure Headers Project](https://owasp.org/projects/secure-headers-project)
及 [W3C Content Security Policy](https://www.w3.org/TR/CSP/)。

## OpenCode 使用

已有证据时，可以直接查询：

```text
请用 evidence_header_check 检查 EV-20260920022526-21bfd896，按通过、需要复核和不适用解释结果。
```

针对一个已授权 URL 做检查时，Agent 使用 `authorized_web_check`，在工具内部完成
受限观察、证据保存、离线规则检查和中文报告；使用者不必传递编号。见 `one-click-check.md`。

工具只接受 EV 编号，并固定读取 `evidence/opencode/`。它拒绝文件路径、未知编号、
哈希不匹配和解析到项目外部的文件链接。返回内容不含响应正文和原始响应头值。

## 与 HYP 的关系

EV 是“实际观察到什么”，检查结果是“规则如何解释这份证据”，HYP 是“接下来要验证的安全猜想”。
当前工具只生成检查结果，不自动创建 HYP。这样缺少安全头不会被直接升级成漏洞结论。
后续自动流程可以在授权允许时，为需要复核的结果创建或关联 HYP，并用 HYP 编号去重、追加证据和跟踪状态。
编号主要供系统追踪和审计；用户在普通对话中不需要记住它，可以让 Agent 根据目标、标题或报告继续任务。

## 限制

- 只分析单次响应保存下来的头，不执行浏览器行为验证。
- 不判断 CSP 是否足够严格，只判断是否存在；`frame-ancestors` 仅检查指令是否有值。
- 不检查 Cookie 属性，因为 Evidence Store 会脱敏 `Set-Cookie`，当前证据不足以作出判断。
- HTTP 证据上的 HSTS 规则标为不适用；需要 HTTPS 响应才能判断。
- 不能发现 SQL 注入、XSS、越权、身份认证或业务逻辑漏洞。
