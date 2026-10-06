# Hermes / OpenCode 完整评估对照

此脚本只用于比较两个运行时的已知答案任务，不是日常启动 PhantomVeil Agent 的入口。日常交互请使用 `pveil chat --runtime hermes` 或 `scripts/hermes-chat.ps1`，见项目 README。

本机已知答案夹具有两个变体：正样本原样回显无害边界字符，负样本对这些字符编码。根页静态链接到 `/search`，并含一个安全 GET 表单参数 `q`。两端顺序运行同一个 DeepSeek 模型、同一目标与任务文字、同一个受限 MCP 工作流和四次 GET 预算。每端独立创建任务授权、预算、EV、HYP、报告和审计。完整评估的任务级批准仅在此固定 `127.0.0.1` 夹具中预授，评测 MCP 服务会检查任务模式、精确 URL 和四次预算；产品入口仍需 Hermes 的人类审批界面。

在 PowerShell 中运行一次，即可顺序执行原样字符和编码字符两个变体：

```powershell
.\scripts\hermes-assessment-pair.ps1
```

只有当前进程尚无 `DEEPSEEK_API_KEY` 时，脚本才会隐藏询问一次；输入不会显示，也不会写入配置，脚本结束后会清除它临时设置的环境变量。OpenCode 已保存的凭据无需重新配置。评估故意给 Hermes 使用全新隔离的 `HERMES_HOME`，避免日常记忆、Skill 和配置影响同条件对照，因此不会读取日常 Hermes 保存的 key。也可在已设置 key 的同一个 PowerShell 进程中直接运行单个变体：

```powershell
npm run hermes:assessment-pair -- deepseek-flash deepseek both
npm run hermes:assessment-pair -- deepseek-flash deepseek both encoded
```

只验证本地协议接线，不计真实模型成绩：

```powershell
npm run hermes:assessment-pair -- fixture-model local-fixture both
npm run hermes:assessment-pair -- fixture-model local-fixture both encoded
```

运行结果写入仓库外的 `%LOCALAPPDATA%\PhantomVeil\hermes-assessment-eval-runs\`，终端只输出状态、请求数、Token、耗时和结果文件路径。独立评分器从靶站请求复核每份 EV 的请求、状态与正文哈希，再检查审批审计、suspected HYP、报告和最终结论。评分器覆盖这两个单参数变体；通过也不代表漏洞已确认或 Agent 在未知目标上的发现能力。重复运行、更多负例和未见过的第二题仍待加入。

2026-10-05：本机 Hermes v0.21.2 与 OpenCode 使用同一个确定性协议夹具，在正负两个变体各完成 1 次配对；两端每次实际 4 次 GET，独立评分均通过。OpenCode 夹具采用[官方自定义 OpenAI 兼容提供方配置](https://opencode.ai/docs/providers)。用户终端随后运行真实 DeepSeek 原样字符配对：两端均执行四次 GET 并成功退出，但又各执行一次允许的只读 `hypothesis_get`；旧评分器要求恰好一个工具事件，因此原始记录为 `paired_failed`，编码变体未运行。评分器已修复并通过单项测试、两种本机协议夹具配对及完整回归；真实模型尚未重跑，不能称为通过。
