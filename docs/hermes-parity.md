# Hermes 单 Agent 能力对照（2026-10-05）

Hermes 负责对话、决策和工具调用；所有实际 HTTP 请求仍由 PhantomVeil 的受限 MCP 服务执行，并在请求边界核对 Scope、动作授权、重定向下一跳与预算。任务和 Hermes home 独立存于仓库外；OpenCode 原工具与工作流保留。

| OpenCode 工具 | Hermes 接法 | 当前验证 |
|---|---|---|
| `authorized_target_setup` | 启动器 `-NewTarget`，终端确认后登记只读目标 | 合成授权测试 |
| `authorized_web_observe` | 同名 MCP，普通任务精确 URL | 实际 Hermes 协议夹具与真实 DeepSeek 只读配对 |
| `authorized_web_check`、`evidence_header_check` | 同名 MCP，复用响应头工作流 | 受控本机测试 |
| `evidence_link_inventory`、`evidence_input_inventory` | 同名 MCP，另保留合并的 `evidence_entry_inventory` | 可信 EV 离线测试 |
| `authorized_web_crawl` | `-Crawl`，路径分支内有界爬取 | 受控本机测试 |
| `authorized_parameter_reflection_check` | `-Reflection` 或 `-Encoding`，动作授权与人类逐次批准 | 受控本机测试；Hermes 无审批界面时零额外请求 |
| `evidence_reflection_context` | `-Reflection` 或 `-Encoding`，可信 EV 离线分析 | 受控本机测试 |
| `authorized_redirect_probe` | `-Redirect`，仅本机靶场且不访问跳转目的地 | 受控本机测试 |
| `authorized_xss_encoding_probe` | `-Encoding`，可信反射 EV 后一次非执行探针 | 受控本机测试 |
| `authorized_xss_hypothesis_triage` | `-Encoding` 且授权含 `hypothesis_create` 时启用 | 受控本机测试，状态仅 `suspected` |
| `authorized_hypothesis_create`、`hypothesis_get` | 同名 MCP；仅本次精确 URL 创建、仅本次隔离目录读取 | 受控本机测试 |
| `authorized_reflected_xss_assessment` | `-Assessment`，一次任务级批准、最多 20 次 GET | 受控本机正样本与协议夹具；真实双端首轮已执行但原始评分失败，修复后待复验 |

两个运行时对只读观察任务已有一次真实 DeepSeek 同题通过记录。完整评估的正样本和编码负样本已用同一个确定性协议夹具完成 Hermes/OpenCode 双端配对，每端每轮实际四次 GET 并通过 Agent 外评分；这验证接线和门禁，不证明真实模型能自主选对工具，也不证明漏洞发现。完整评估的双端真实模型对照入口见 [评测说明](../benchmarks/hermes-assessment-eval/README.md)。

当前尚缺：完整评估修复后的真实同模型双端评分通过记录、更多已知答案负例与重复运行、未见过的第二题 Grow 对照，以及交互式任务的完整运行事件自动评分。`pveil chat --runtime hermes` 现在可显式启动 Hermes 隔离任务；无参数 `pveil` 与原 TUI 仍由 OpenCode 路径承担，本阶段不删除 OpenCode。
