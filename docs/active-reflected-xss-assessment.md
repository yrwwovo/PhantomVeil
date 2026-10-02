# 任务级反射型 XSS 主动评估

`authorized_reflected_xss_assessment` 用于已经登记授权的目标。用户提供目标 URL 和授权引用后，
工具先离线校验 Scope 与授权记录，然后只显示一次任务级批准。批准后自动执行：

```text
有界同源爬取 → 离线清点表单 → 筛选安全 GET 参数 → 逐个发送无害标记
→ 保存 EV → 对反射结果离线分析 HTML 上下文 → 每个反射参数进行一次非执行编码观察
→ 按确定性规则跳过、创建或复用 suspected HYP → 生成 AXSS 汇总报告
```

## 默认覆盖

- 最多检查 10 个不同的同源 GET 表单参数；
- 参数之间至少间隔 300 毫秒；
- 复用现有爬虫的页面、深度、请求和重定向预算；
- 每个 HTTP 响应仍保存独立 EV，反射和编码观察仍生成单项报告；
- 每个反射参数最多增加一次编码请求，因此参数检查阶段最多为 `2 × max_parameters` 次请求；
- 全部编码时不创建 HYP；原样字符候选按类型、规范化端点和参数名去重；
- 整项任务只进行一次 OpenCode 人工批准，其中明确包含可能的编码观察和 `suspected` HYP 写入，不逐参数询问。

授权引用必须同时允许以下三个动作，任一缺失都会在爬取前拒绝：

- `parameter_reflection_check`
- `xss_encoding_probe`
- `hypothesis_create`

可在被 Git 忽略的 `configs/active-assessment.local.json` 中收紧或调整参数数量和间隔，格式参考
`configs/active-assessment.example.json`。最大参数数不能超过 20，间隔不能低于 100 毫秒。

## 不进入本工作流的操作

- POST、登录、注册或其他状态变更表单；
- 密码、文件、令牌、CSRF 等敏感字段；
- 路径名明显包含删除、退出、重置、撤销或禁用动作的端点；
- JavaScript/XSS 攻击载荷、浏览器执行、Shell、DoS、数据删除或持久化。

这些排除项用于控制业务影响，不代表永远不研究对应漏洞。需要更高影响的验证时，应建立新的
动作类型和独立任务授权，而不是悄悄绕过当前工作流。

## OpenCode 使用

重启 OpenCode 后可以说：

```text
请使用授权反射型 XSS 主动评估检查 http://127.0.0.1:5000/，
授权引用为 LOCAL-LAB-EXAMPLE。整项任务只批准一次，不逐参数询问。
```

结果中的 `reflected`、`sensitive_context_observed` 和 `raw_special_characters_observed` 都是复核线索，
不是已经确认的 XSS。报告会说明编码观察数量及 HYP 是跳过、创建还是复用。
