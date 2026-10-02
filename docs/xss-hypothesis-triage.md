# XSS 候选与 HYP 关联

这一步把已经存在的两份证据整理成系统可追踪的任务，不再访问网站：

```text
反射 EV + 编码观察 EV
        ↓ 完整性、端点、参数和探针校验
全部编码 → 不创建 HYP
结果不稳定 → 保留 EV，暂不创建 HYP
原样边界字符 → 创建或复用 suspected HYP
```

## 输入与运行

```powershell
npm run xss:hypothesis -- <反射EV编号> <编码EV编号> <授权引用>
```

OpenCode 工具名是 `authorized_xss_hypothesis_triage`。授权引用必须允许
`hypothesis_create`，并覆盖证据中的规范化端点。命令本身不发送网络请求；OpenCode 只在确实需要
写 HYP 时显示一次批准，全部编码或证据不足时不会为了“不写入”而询问。

## 去重规则

候选指纹固定由以下三项计算：

1. 漏洞类型：`reflected_xss`。
2. 去掉查询串和片段后的规范化端点 URL。
3. 原始参数名。

因此同一候选重复执行会返回原 HYP 编号。新 EV 可以追加到未结束的原 HYP，并记录
`evidence_attached` 历史事件；不会自动把 `suspected` 变成 `testing` 或 `confirmed`。

## 结果边界

- 原样 `<`、`>` 或引号只说明输出编码值得继续复核，不能证明浏览器中可执行脚本。
- 全部编码只说明这一次响应观察到转义，不能证明整个站点没有 XSS。
- 工具不运行 JavaScript、不发送新载荷、不生成复现攻击步骤，也不改写终态 HYP。
- 候选级短时锁只避免本流程并发重复创建；通用 HYP 状态更新仍以单个本地写入者为前提。
