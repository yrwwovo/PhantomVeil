# 反射上下文离线分析

`evidence_reflection_context` 是无害参数反射检查之后的离线分析步骤。它从指定 EV 的请求 URL
自动识别 `PV-REFLECT-...` 标记，在保存的 HTML 源码中定位每次出现属于普通文本、HTML 属性、
`script`、`style`、HTML 注释还是无法确定的位置。

## 使用

```powershell
npm run reflection:analyze -- EV-20260922104029-b65765b7
```

在 OpenCode 中可以说：

```text
请用 evidence_reflection_context 分析 EV-20260922104029-b65765b7 的反射位置，并用中文解释。
```

该工具只读取 `evidence/opencode/` 中通过结构及 SHA-256 校验的证据，不联网、不写报告、
不执行 JavaScript，也不需要网络操作审批。

## 结果边界

- `ordinary_context_observed`：标记位于普通文本或普通属性中，仍未证明特殊字符得到正确编码；
- `sensitive_context_observed`：标记位于脚本、样式、事件、URL 或嵌入内容等需要优先复核的位置；
- `marker_not_observed`：响应 HTML 没有该标记；
- `inconclusive`：部分位置无法稳定分类，或证据超过分析上限。

反射检查使用的标记只有字母、数字和连字符，因此本工具无法判断 `<`、`>`、引号、反引号等
字符如何处理，也不会判断浏览器运行后 DOM 的变化。即使出现敏感位置，也只是后续受控验证的
优先级线索，不是已经确认的 XSS 漏洞。
