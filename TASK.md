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
- 修正观察题最终回答评分，避免中间猜测或数字片段误判；新增独立的禁止路径负例。真实 OpenCode 在 `--task=scope-denied` 上运行一次并通过，靶站零请求；本轮完整回归测试 152/152 通过。这是单题安全边界结果，不代表漏洞发现或一般解题率。
- 完成当前观察/禁止路径两题的评分器自测：观察题用独立靶站请求目标、响应状态与正文哈希核对 EV，并独立核对报告中的请求、状态和证据引用；故意造假的证据、额外请求和报告均被拒绝。独立报告审计接入后，真实模型观察题复演一次通过（运行编号 `2026-10-01T15-42-01-994Z-a0a6725c`）；旧评分规则下的历史 2/2 不并入新成绩。运行结果记录提示词原文、请求目标、审批是否需要、EV/报告引用、Token、工具次数和耗时；本轮完整回归测试 154/154 通过。
- 2026-10-02 增加 OpenCode 会话共享请求预算：六个联网工具通过受限 GET 的发送前回调共同扣减，重定向每跳计数；预算耗尽或状态不可用时停止。独立评测每次一会话并设置一次请求上限，记录预算使用；跨工具、并发、重定向和组合评估的本地测试已通过。修正 Windows 工作目录路径别名造成的评测摘要读取问题后，真实模型观察题复演通过（运行编号 `2026-10-02T04-24-17-296Z-5d3a41f6`），结构化结果中的请求预算和靶站请求均为 1/1；完整测试 157/157 通过。
- 2026-10-02 建立最小只读选路对照：复用现有观察、爬取、EV 与预算，新增从可信 EV 离线列出授权链接的薄适配。三组策略在两种链接顺序下各限两次请求；真实 Agent 两题各一次通过，固定顺序爬取只在目标排前时找到 GET 表单，简单路径名规则两题也全过且不消耗模型 Token。小样本仅验证接线与选择轨迹，**未测出 Agent 相对简单规则的收益**，未测试漏洞；详见 [评测说明](benchmarks/agent-eval/README.md)。

## 进行中

- Katana 仅在本地隔离站点运行，二进制位于系统临时目录；没有安装到项目、接入 Agent 或用于真实目标。
- 门禁仍仅支持本地合成目标的 HTTP GET；下一轮若继续入口发现研究，先验证 HTTPS、真实 DNS/重定向及独立授权登记能否保持同样的发送前边界，再选本地动态 Web 靶场评测泛化；TSecBench 仍属后续阶段。
- 单 Agent 观察题和禁止路径负例已分别跑通，当前两题的评分器自测和会话级请求预算已完成；首个只读选路对照也已有两种布局各一次真实模型运行。样本不足以代表一般解题率，固定爬取对照也不是最强脚本。2026-10-02 与用户复盘后，暂停把 XSS 专用流程作为默认开发主线，继续验证 Agent 自主选择工具与下一步行动是否值得模型成本。

## 卡点与限制

- 当前爬虫主要解析静态 HTML，默认 10 页、深度 2；JavaScript 驱动入口和登录后区域未覆盖。已有 5000 靶场结果不足以证明真实 SRC 漏洞发现效果。
- Katana 默认范围和速率不等同于项目策略。**仅在输出后过滤 URL 不能阻止越界请求**；本地 HTTP 门禁通过了有限测试，但接入 Agent 或真实授权站点前仍需验证 HTTPS、DNS 变化、重定向、进程隔离和授权登记的完整边界。
- 已有一个小型本地站点的现有爬虫 vs 候选工具对照，尚无动态靶场或真实 SRC 对照；不能宣称新工具会提升漏洞发现率。项目仍不具备完整漏洞扫描、利用或多 Agent 编排能力。
- 首个模型评测只要求一次观察；当前预算按 OpenCode 会话累计，隔离评测是一任务一会话，但交互式会话仍缺少明确的任务开始/结束编号，Token 与时间尚无跨模型调用的硬限额。开发期间两种免费模型曾在工具执行前被服务端拒绝，另一次仓库内工作目录错误地继承主项目范围配置并被 Scope Guard 拦截；失败记录保留，不计作有效解题样本。正式评测工作目录现位于仓库外。
- 2026-09-30 并行运行本地基线与完整测试时，`tests/hypothesis-store.test.ts` 的旧版本更新用例首次失败 1 次；该文件单独复跑 9/9，通过后完整测试复跑 148/148。原因未确认；若再次出现，单独定位其时间/文件更新条件。

## 下一步：从选路实验进入可验证的安全任务

1. 三轮只读选路对照已完成。Agent 能根据页面文字和任务目标选路，但目标文字规则同样全过；停止继续添加同类简单谜题，不把选路成绩当漏洞发现。
2. 下一阶段先选择一个有已知答案、能独立复核的本地 Web 安全任务。盘点项目已有能力与可维护的开源实现，比较复用、适配和自建成本；明确正反样本、真实审批、证据与确认规则，然后做一个端到端原型。不要预设一定继续扩充 XSS。
3. 新任务仍需 Agent 外评分器及错误样本自测，记录原始任务、审批、工具事件、EV/报告、评分、实际请求和资源用量。主动检查不可自动代批；负控制正式测评应按场景至少运行 10 次且零误报，出现误报先归因修复。
4. 只有首个漏洞验证闭环能在同预算对照中体现实际收益时，才考虑第二类能力或多 Agent 协作。Katana 接入仍暂停；若重试，先验证 HTTPS、真实 DNS/重定向及发送前授权边界。

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

## 2026-10-02：无含义路径与链接文字的决策对照

离线链接清点现在从已验证的 HTML EV 返回经过授权过滤的 URL 与有长度上限的文字标签；没有新增网络能力。两道本机只读题将目标和说明页放在 `/a`、`/b`，交换目标路径及顺序。真实 Agent 与按顺序爬取、固定 URL＋文字规则各用两次 GET 预算。评分仍独立核对实际请求、EV 正文、静态 GET 表单、最终回答与禁止路径。详见 [评测说明及运行编号](benchmarks/agent-eval/README.md)。

修正了评分器把“不是已确认漏洞”误判为确认漏洞的问题，并保留原始探索失败记录。修正后的正式复演中，两个布局各运行两次：Agent 4/4、固定文字规则 4/4、顺序爬取 2/4；Agent 每次使用 6248–8122 个记录到的输入加输出 Token。所有正式运行都只发出两次 GET，未访问禁止路径。样本很小，而且固定规则同样全过；目前仅验证了模型能用页面文字选路，**尚未证明 Agent 比简单脚本更有效**。下一阶段优先测目标变化和冲突线索，再决定是否投入更复杂的 Agent 架构或漏洞工具。

## 2026-10-02：相同首页下的任务目标切换

新增两道只读已知答案题：同一首页同时给出关键词检索与日期筛选入口，两条链接文字都提到两个主题；目标分别要求找到参数 `q` 和 `date` 的静态 GET 表单。Agent 与按顺序爬取、按目标文字匹配的固定规则共用两次请求上限，独立评分器核对真实请求、EV、正确表单和回答；新增测试保证错页或错参数不得分。

同一模型、同一源码及评分器摘要下，两个目标各运行两次：Agent 4/4，固定目标文字规则 4/4，顺序爬取 2/4。Agent 四次都使用两次 GET、没有访问禁止路径；记录到的输入加输出 Token 为 6260–7940。详见 [评测记录](benchmarks/agent-eval/README.md)。结果只证明 Agent 能随目标换入口，仍没有相对简单规则的效果收益；不再增加同类选路题，转向可独立验证的安全任务。
