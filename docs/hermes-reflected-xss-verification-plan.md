# Hermes 日常会话：首个可复核漏洞验证切片

## 入口与授权边界

无参 `pveil` 通过 `--configured-target` 读取本地 Scope、HTTP 策略和授权登记。
`web_observe` 只允许进入只读会话；它不授予主动验证权限。公开的
`configs/authorization.loopback5000.example.json` 是仅针对
`http://127.0.0.1:5000/` 的合成示例，不是用户的本机授权文件。

后续在会话中接受「这是已授权目标 URL」时，必须重新核对用户给出的完整 URL：
全局 Scope 和对应授权引用都要允许该目标；拒绝自动扩展 Scope。若目标或动作改变，
建立新任务 ID、隔离工作目录和新预算，并显示目标、路径、动作及请求上限供人类确认。
旧任务的授权和剩余预算不得转移。授权拒绝后不发送请求。

## 首类选择：反射型 XSS 的执行验证

复用现有有界爬取、可信 EV 的 GET 表单/参数清点、无害反射观察、编码观察、
Scope Guard、逐跳预算和中文报告。现有编码观察只能证明字符如何返回，不能证明
JavaScript 执行。新增独立的 `xss_execution_verify` 授权动作和受限验证工具；
不改现有 `authorized_reflected_xss_assessment`。

一次任务的次序：

1. 在已授权路径分支内有界爬取，对哈希验证的页面 EV 离线清点同源 GET 参数。
2. 选择一个非敏感、非状态修改参数，使用唯一无害标记观察反射并保存 EV；
   只对可信反射继续做编码/上下文分析。
3. 人类批准一个精确端点和参数后，项目代码生成固定、无外传、无持久副作用的
   唯一执行信号；模型不能提交任意脚本。请求仍通过受限 HTTP 边界，响应保存 EV。
4. 独立浏览器验证器仅回放该 EV 的响应正文及相关响应头，阻断其他资源、跳转、
   Service Worker 和对外连接；只有观察到与本次唯一标记匹配的脚本执行，才算
   一次执行证明。若无法证明浏览器零外发，则不开启此验证器。
5. 用第二个独立标记复演。两次响应 EV 与浏览器执行信号都能核对时，记录
   「可复现执行」；任一步缺失、CSP 阻断或两次结果不一致则保留 suspected 或
   inconclusive。正式 confirmed 结论仍经人工复核。

验证器是 PhantomVeil 内部固定流程，不向 Agent 提供通用浏览器、终端或任意联网工具。
中文报告列出授权动作、精确端点与参数、请求次数、每个 EV、响应状态、CSP 状态、
执行信号和可复演步骤，并区分已执行、被阻断与未测试的部分。

## 实施门槛

- 先让已有 `web_observe` 授权稳定进入日常会话；主动动作必须另行授权和批准。
- 本机受控正样本、HTML 转义负样本、CSP 阻断样本都要测试；范围外、禁止路径、
  重定向、预算耗尽、伪造 EV 与审批拒绝必须在请求前或验证时失败。
- 浏览器隔离须实测零外发；仅有反射或原样字符时不得称为 XSS。
- 这条新功能链独立开发，不修改已暂停的 assessment、评分器或 key 验证。

参考：[OWASP 反射型 XSS 测试指南](https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting/)、
[Playwright 网络拦截及 Service Worker 限制](https://playwright.dev/docs/network)。
