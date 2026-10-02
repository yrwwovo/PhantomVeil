# PhantomVeil 当前任务交接（2026-10-01）

## 目标

长期目标是面向明确授权目标的红队渗透测试 Agent；当前以 OpenCode 为运行底座，先做面向中文用户的 Web/SRC 测试闭环：从自然语言目标到入口发现、可复核证据、漏洞验证和中文报告。优先提高真实发现与验证效果，以及已知答案任务的成功率；多 Agent 是待验证的架构方案，不是项目目标或成绩指标。开发遵循“先研究复用 → 快速适配原型 → 实测精修”；不以某个靶场或榜单为唯一目标。

评测时，在已知答案的本地靶场统计发现率与解题率；在真实授权目标上记录去重且可复现的有效发现、误报、覆盖、耗时和成本，不宣称未知分母的“发现率”。未来若尝试多 Agent，应在相同目标、工具、模型和预算下与单 Agent 对照，再决定是否保留复杂分工。

## 已完成

- 完成 [整体规划 v0.1](docs/project-plan.md)，明确当前模块边界、10–11 月开发里程碑、12 月答辩交付、真实模型评测与候选多 Agent 对照。日期与指标是计划，未作为已实现能力；整体架构设计与评测同步推进。

- `pveil` 终端入口和 PhantomVeil TUI 标识；已实现单 Agent 的 OpenCode 工具接入。
- Scope Guard、本地授权登记与中文目标登记；受限 GET、同源有界爬取、响应头复核、静态表单/参数清点。
- EV 证据保存与 SHA-256 校验、中文报告、HYP 假设持久化与状态管理。
- 反射型 XSS 初步评估：无害 GET 标记反射、离线上下文分析、一次非执行字符编码观察，以及确定性的 HYP 跳过/创建/复用；不能自动确认 XSS。已有一个项目级 Skill。
- 用户在本地 `127.0.0.1:5000` 靶场完成过整条初步评估：发现并检查 `/search?q`；观察到反射，但特殊字符被编码，因此没有创建 HYP，也没有确认漏洞。
- 完成只读复用审计：比较 [BreachWeave `pentest`](https://github.com/m-sec-org/BreachWeave/blob/pentest/README.md) 的多 Agent/资产管理、[PentestPi](https://github.com/weidutech/PentestPi) 的单 Agent/外部状态，以及 [Katana](https://github.com/projectdiscovery/katana) 的现成发现能力。结论是暂不移植整套 Agent 框架，优先用可测量的实验补入口发现能力。外部项目尚未逐文件源码审计或运行。
- 完成 Katana v1.7.0 的可撤销本地对照实验，结果见 [benchmarks/katana/RESULTS.md](benchmarks/katana/RESULTS.md)：当前配置没有新增业务入口；本地代理拦下一次工具初始化发起的范围外请求，因此停止接入。
- 完成本地 HTTP 出站门禁原型，见 [benchmarks/egress-gate/README.md](benchmarks/egress-gate/README.md)：Docker 内部网络隔离候选与靶场，门禁复用受限 GET；允许请求、范围拒绝、逐跳重定向、预算和直连阻断均通过本地验证。Linux 容器兼容性修复后的项目回归测试为 148/148 通过。
- 建立可重复的本地 Web 工作流基线，见 [benchmarks/web-baseline/README.md](benchmarks/web-baseline/README.md)：同一已知答案靶站连续运行两次，记录候选精确率/召回率、实际请求和禁止路径请求。该脚本未驱动 OpenCode 模型，不能代表 Agent 自主解题率或已确认漏洞发现率。
- 建立首个真实 OpenCode 单 Agent 评测切片，见 [benchmarks/agent-eval/README.md](benchmarks/agent-eval/README.md)：独立工作目录、本地精确授权、JSON 模型/工具事件、EV 完整性校验和 Agent 外评分。`deepseek/deepseek-flash` 在相同源码摘要下独立运行两次，单页观察任务 2/2 通过，每次靶站只收到一次 GET；这是观察任务成功，不是漏洞发现。完整回归测试 150/150 通过。

## 进行中

- Katana 仅在本地隔离站点运行，二进制位于系统临时目录；没有安装到项目、接入 Agent 或用于真实目标。
- 门禁仍仅支持本地合成目标的 HTTP GET；下一轮若继续入口发现研究，先验证 HTTPS、真实 DNS/重定向及独立授权登记能否保持同样的发送前边界，再选本地动态 Web 靶场评测泛化；TSecBench 仍属后续阶段。
- 单 Agent 首个真实模型任务已跑通；接下来扩充安全负例、编码反射与范围/预算任务，比较错误类型和成本。当前一题的 2/2 不能代表一般解题率，本地工作流基线仍只是确定性对照。

## 卡点与限制

- 当前爬虫主要解析静态 HTML，默认 10 页、深度 2；JavaScript 驱动入口和登录后区域未覆盖。已有 5000 靶场结果不足以证明真实 SRC 漏洞发现效果。
- Katana 默认范围和速率不等同于项目策略。**仅在输出后过滤 URL 不能阻止越界请求**；本地 HTTP 门禁通过了有限测试，但接入 Agent 或真实授权站点前仍需验证 HTTPS、DNS 变化、重定向、进程隔离和授权登记的完整边界。
- 已有一个小型本地站点的现有爬虫 vs 候选工具对照，尚无动态靶场或真实 SRC 对照；不能宣称新工具会提升漏洞发现率。项目仍不具备完整漏洞扫描、利用或多 Agent 编排能力。
- 首个模型评测只要求一次观察；多轮自主任务仍缺少跨工具的整次任务请求预算与停止条件。开发期间两种免费模型曾在工具执行前被服务端拒绝，另一次仓库内工作目录错误地继承主项目范围配置并被 Scope Guard 拦截；失败记录保留，不计作有效解题样本。正式评测工作目录现位于仓库外。
- 2026-09-30 并行运行本地基线与完整测试时，`tests/hypothesis-store.test.ts` 的旧版本更新用例首次失败 1 次；该文件单独复跑 9/9，通过后完整测试复跑 148/148。原因未确认；若再次出现，单独定位其时间/文件更新条件。

## 下一步：真实模型单 Agent 评测

1. 在首个任务已经跑通的基础上，为编码反射、不反射、范围/预算拒绝等不同情形补独立评分与隔离任务；按同一模型和预算复演，任务数属于 M1 实验安排，不是架构约束。
2. 多轮自主调用前补跨工具请求总预算和停止条件，并记录正常审批的真实事件；不得以自动批准代替审批。
3. 汇总模型实际失败后设计第一种漏洞的验证规则与人工复核入口。架构 v0.1 现在可使用，具体协作方案等有对照数据再决定。
4. Katana 接入仍暂停；若重试，先完成 HTTPS 与真实网络条件下的发送前边界和授权验证，再评估入口收益。此项不阻塞使用已有受限工具推进评测和独立验证设计。

## 关键文件路径

- 项目约束与阶段：[AGENTS.md](AGENTS.md)、[整体规划](docs/project-plan.md)、[docs/roadmap.md](docs/roadmap.md)、[docs/architecture.md](docs/architecture.md)
- 复用决策与本地对照：[DECISIONS.md](DECISIONS.md)、[benchmarks/katana/RESULTS.md](benchmarks/katana/RESULTS.md)
- 本地门禁原型：[benchmarks/egress-gate/README.md](benchmarks/egress-gate/README.md)、[benchmarks/egress-gate/gate.mjs](benchmarks/egress-gate/gate.mjs)
- 单工作流评测基线：[benchmarks/web-baseline/README.md](benchmarks/web-baseline/README.md)、[benchmarks/web-baseline/run.mjs](benchmarks/web-baseline/run.mjs)
- 真实 Agent 首题：[benchmarks/agent-eval/README.md](benchmarks/agent-eval/README.md)、[benchmarks/agent-eval/run.mjs](benchmarks/agent-eval/run.mjs)、[src/evaluation/observation-score.ts](src/evaluation/observation-score.ts)
- 命令与使用说明：[README.md](README.md)、[package.json](package.json)、[src/cli/pveil.ts](src/cli/pveil.ts)
- 授权边界：[src/scope/scope-guard.ts](src/scope/scope-guard.ts)、[src/scope/authorization-registry.ts](src/scope/authorization-registry.ts)、[capabilities/web/restricted-http-get.ts](capabilities/web/restricted-http-get.ts)
- 发现与评估：[src/workflows/web-crawl.ts](src/workflows/web-crawl.ts)、[src/workflows/reflected-xss-assessment.ts](src/workflows/reflected-xss-assessment.ts)
- 证据与假设：[src/evidence/evidence-store.ts](src/evidence/evidence-store.ts)、[src/hypotheses/hypothesis-store.ts](src/hypotheses/hypothesis-store.ts)
- Agent/Skill：[.opencode/agents/web-security-agent.md](.opencode/agents/web-security-agent.md)、[.opencode/skills/authorized-reflected-xss-triage/SKILL.md](.opencode/skills/authorized-reflected-xss-triage/SKILL.md)
- 本地产物：`configs/*.local.json`、`evidence/`、`reports/`；可能包含敏感信息，不提交仓库。
