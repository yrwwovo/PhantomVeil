# Skills 在 PhantomVeil 中的职责

Skill 是 Agent 按需加载的操作手册，Tool 是真正执行检查的受限能力。Skill 不保存授权，
也不能扩大 Scope 或替代 Tool 内的审批。

项目第一个 Skill 位于：

```text
.opencode/skills/authorized-reflected-xss-triage/SKILL.md
```

它把任务级多参数主动评估、单参数无害反射检查、离线上下文分析和按需的单请求编码观察串成一套流程。广泛检查时
优先调用 `authorized_reflected_xss_assessment`，整项任务只批准一次，不逐参数询问。Agent 只被允许加载
这个项目级 Skill；其他全局或以后下载的 Skill 默认隐藏，审核后才能逐项加入允许列表。

## 外部 Skill 接入检查

复用外部 Skill 时至少检查：来源和许可证、适用工具、网络与 Shell 权限、授权假设、载荷强度、
停止条件、秘密信息处理、结果是否会误报为已确认漏洞。优先复用测试方法和报告结构，再把工具名
映射到本项目自己的受限 Tool；不要直接复制能够执行任意命令或默认扫描公网的流程。

Skill 的加载许可只允许 Agent 阅读操作手册，不代表用户批准了网络请求。主动检查仍必须通过
Scope Guard、本地授权登记和对应 Tool 的任务级人工审批。
