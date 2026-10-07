# PhantomVeil 当前任务交接（2026-10-02）

> 2026-10-06 默认运行时切换：`src/cli/pveil.ts` 与 `npm run pveil` 现在默认进入 Hermes。无参数 `pveil`、`pveil chat`、`pveil chat --runtime hermes`（均不带其它参数）都转交 `scripts/hermes-chat.mjs` 无参启动，进入未绑定目标的隔离 Hermes 受限会话（与 PATH 上 fork 的 `pveil` 行为一致，使用原生凭据，不强制终端设置 DEEPSEEK_API_KEY）。显式定向任务 `pveil chat --runtime hermes --url ... --authorization-reference ...`（或 `--new-target` / `--crawl|--reflection|--redirect|--encoding|--assessment`）保持原隔离任务启动器与 DEEPSEEK_API_KEY 门禁不变。`pveil chat --runtime opencode` 为显式回退，仍启动受限 OpenCode TUI。已更新 HELP 文案、`tests/pveil-cli.test.ts`（无参默认改为断言 Hermes，新增 `chat`/`--runtime hermes` 覆盖，OpenCode 缺失用例改用显式回退）与 README 默认说明；`npm test` 213 项 209 通过 0 失败（4 跳过）。本机本地提交，未推送。

> 2026-10-05 日常 Hermes 入口第 2 步：无参 `scripts/hermes-chat.ps1` 现在进入未绑定的隔离 Hermes 会话；用户在聊天中直接说「这是已授权目标 URL」后，受限 MCP `authorized_target_bind` 显示精确目标与路径并请求人类确认。确认前任务没有任何允许 URL，HTTP 工具拒绝；明确禁止主机/路径拒绝绑定；确认后仅在仓库外本次任务登记只读授权、锁定一个精确 URL 和一次请求预算，不修改项目本地配置。旧的配置自动选择入口保留为 `-ConfiguredTarget`，显式 `-Url` 模式不变。定向本机回归 12/12 通过，包含真实 Hermes CLI 读取新 profile、MCP 工具调用和旧只读协议夹具；真实 DeepSeek 中文会话尚未运行，不能声称模型一定会正确选择绑定工具。无参 `pveil` 仍是 OpenCode，默认切换待日常 Hermes 交互验证。

> 2026-10-05 日常 Hermes 入口第 1 步：`scripts/hermes-chat.ps1` 现可无参数启动。Node 启动器离线读取项目本地 Scope、HTTP 策略与授权登记；唯一精确只读目标自动绑定，多目标或宽泛范围启动前询问精确 URL，再优先选择精确匹配、允许动作较少的授权引用。无有效授权拒绝，仍仅创建原有一次请求的只读隔离任务。会话内中文登记目标尚未实现，留待下一步。

> 2026-10-05 真实完整评估首轮：用户终端的 DeepSeek 原样字符正样本双端运行已启动成功；Hermes 和 OpenCode 各执行四次 GET，退出码均为 0，Token/耗时均有记录。两端又各执行一次已允许的只读 `hypothesis_get`，但评分器旧规则要求恰好一次工具调用，故原始配对记录仍为 `paired_failed`。已将评分器收紧为“完整评估一次，之后可选一次对本次 suspected HYP 的只读核对”，并加入不匹配 HYP/额外工具的拒绝测试；修复后本机协议夹具正负两题双端均通过，完整回归 196 通过、3 跳过；尚未重跑真实模型，不能把原始失败改写成通过。完整评估脚本仅为已知答案对照，不是日常 Agent 启动命令。

> 2026-10-05 入口迁移：`npm run pveil -- chat --runtime hermes --url URL --authorization-reference REF` 已显式转交隔离 Hermes 任务启动器；`npm run pveil -- chat --runtime opencode` 为回退。无参数默认仍是 OpenCode，直到真实 DeepSeek 完整评估正负样本双端评分通过。当前 Codex 进程没有 DeepSeek key，未代替用户终端运行真实配对。

> 2026-10-05 Hermes 受限任务进展：已用本地 MCP 接入只读观察、响应头、入口清点、有界爬取、参数反射、本机重定向、非执行编码观察、可信 EV 的 XSS 候选 HYP 关联、通用 HYP 创建/读取和完整低影响反射型 XSS 初步评估。主动操作仍由 PhantomVeil 校验任务路径、独立动作授权、逐次或任务级人类批准及请求预算；HYP 只写 suspected。OpenCode 原工具继续存在。完整评估新增本机 Agent 外评分与双端同题运行器；Hermes/OpenCode 确定性协议夹具在原样字符正样本和编码负样本各完成一轮配对，每端每轮四次真实 GET 且评分通过。真实 DeepSeek 首轮原样字符配对因评分器漏接已允许的只读 HYP 核对而失败，不能把夹具或该失败记录写成漏洞发现率。

> 2026-10-04 Hermes 交互入口：新增 `scripts/hermes-chat.ps1` / `npm run hermes:chat`。调用者给出精确 URL 和已有 `web_observe` 授权引用；启动前离线核对 Scope、HTTP 策略和授权，在仓库外生成独立 Hermes profile、`Phant0mV3il` 中文行为约束、仅两项 MCP 工具、一次请求预算和 EV/报告目录。目标登记新建引用包含 `web_observe`，旧本地授权配置未改动。可继续聊本次观察，新目标需另起任务。合成配置下本机 Hermes v0.21.2 协议夹具完成一次 GET、EV、离线清点；真实 DeepSeek 交互入口尚未在用户授权目标上运行，不能称为漏洞发现。OpenCode Agent 的其余工具尚未迁移。

> 2026-10-04 配对开发：新增 `npm run hermes:pair -- deepseek-flash deepseek`，两端在同一 URL、任务原文、工具、预算和评分器下顺序运行，各自生成新授权；配对评分拒绝不同目标、模型、预算、授权或额外请求。Hermes v0.21.2 已安装到仓库外的 `D:\Projects\.phantomveil-hermes-runtime`，共享路径的本机协议夹具完成两工具、一次 GET、独立评分通过。首次有效真实同模型配对 `pair-2026-10-04T12-57-26-541Z-a4806dd3` 为 `paired_passed`：Hermes 与 OpenCode 各完成两工具、一次实际 GET、EV/报告核对及中文观察结论；只证明这道观察题，不是漏洞发现。提供方后端权重版本及 Token 发送前硬上限仍未验证。此前官方 CLI 和 Codex 应用内虚拟环境的隔离启动失败已留档。回归测试两次复跑 178/178 通过，另有一次未归因的偶发断言失败，见 `benchmarks/hermes-eval/README.md`。

> 2026-10-03 Hermes 补充：已建立 OpenCode 同题隔离 MCP 对照入口，共用两项受限工具、一次请求预算与 Agent 外评分；本机 MCP 连接和事件转换已核查，Hermes 协议夹具复跑通过。真实同模型对照仍因两边可用的共同模型路由缺失而未运行；不能把夹具或旧 OpenCode 历史成绩当成迁移效果。

> 2026-10-03 运行更新：同题 `deepseek-flash` 的 OpenCode 侧新轮次 `2026-10-03T03-48-05-415Z-7ea008e2` 通过，两项工具与一次真实 GET 均由独立评分核对；Hermes 侧 `2026-10-03T03-48-24-218Z-f6afa1af` 因隔离环境缺少 DeepSeek 访问凭据在模型阶段退出，靶站零请求。详见 `benchmarks/hermes-eval/README.md`，目前没有可比较的 Hermes 真实模型成绩。

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
- 单 Agent 观察、禁止路径、只读选路和首个非 XSS 安全任务都已有本地记录。开放重定向的四个接线样本中，Agent 与固定规则同为 4/4；当前没有测出模型相对于简单规则的效果收益。下一步固定独立评分规则，扩充变化场景及负样本重复，继续验证模型成本是否值得。

## 卡点与限制

- 当前爬虫主要解析静态 HTML，默认 10 页、深度 2；JavaScript 驱动入口和登录后区域未覆盖。已有 5000 靶场结果不足以证明真实 SRC 漏洞发现效果。
- Katana 默认范围和速率不等同于项目策略。**仅在输出后过滤 URL 不能阻止越界请求**；本地 HTTP 门禁通过了有限测试，但接入 Agent 或真实授权站点前仍需验证 HTTPS、DNS 变化、重定向、进程隔离和授权登记的完整边界。
- 已有一个小型本地站点的现有爬虫 vs 候选工具对照，尚无动态靶场或真实 SRC 对照；不能宣称新工具会提升漏洞发现率。项目仍不具备完整漏洞扫描、利用或多 Agent 编排能力。
- 首个模型评测只要求一次观察；当前预算按 OpenCode 会话累计，隔离评测是一任务一会话，但交互式会话仍缺少明确的任务开始/结束编号，Token 与时间尚无跨模型调用的硬限额。开发期间两种免费模型曾在工具执行前被服务端拒绝，另一次仓库内工作目录错误地继承主项目范围配置并被 Scope Guard 拦截；失败记录保留，不计作有效解题样本。正式评测工作目录现位于仓库外。
- 2026-09-30 并行运行本地基线与完整测试时，`tests/hypothesis-store.test.ts` 的旧版本更新用例首次失败 1 次；该文件单独复跑 9/9，通过后完整测试复跑 148/148。原因未确认；若再次出现，单独定位其时间/文件更新条件。

## 下一步：扩大首个安全任务的有效对照

1. 开放重定向本机原型及四个单次 Agent 对照已完成接线验证；固定规则同样全过，不能宣称 Agent 更强或已有稳定误报率。
2. 固定评分器版本，加入不同页面线索、多个候选表单与跳转上下文；Agent 与固定规则继续看同一信息、用同一预算。正式负控制按场景至少 10 次且零误报，出现误报先归因修复。
3. 每轮保留任务原文、聊天中的批准依据、工具事件、EV/报告、实际请求、评分、Token、耗时和源码/评分器摘要。仓库外的隔离评测可按该轮明确批准预授权；日常工具的人工审批不可取消。
4. 只有可重复的安全任务收益出现后，才考虑扩大检测能力或多 Agent 协作。Katana 接入仍暂停；若重试，先验证 HTTPS、真实 DNS/重定向及发送前授权边界。

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

## 2026-10-02：首个非 XSS 本地安全任务原型

已选服务端开放重定向观察，并在 [决策记录](DECISIONS.md) 写明复用来源与适配理由。新增 `authorized_redirect_probe`：只对已验证 HTML 中的一个同源 GET 表单参数，在独立授权和一次人工审批后发送两次带不同无害标记的请求；客户端不访问跳转目的地。两次响应各留 EV，只在两个 3xx `Location` 精确匹配各自标记时给出待人工复核的候选，报告不自动确认漏洞。当前工具限制在本机靶场；现有本地授权不会自动升级。

本机已知答案正反样本及授权、预算、EV 完整性、审批边界的局部测试通过，见 [原型说明](benchmarks/redirect-probe/README.md)。原型完成时**尚无真实模型对照**；后续接线结果见下一节。不得把当前本机工具测试写成真实站点发现率。

## 2026-10-02：开放重定向的真实 Agent 对照

已补 Agent 外独立评分、评分器错误样本自测和本地隔离运行器；经用户批准，在 `127.0.0.1` 的正样本及三种负样本上各运行一次真实 OpenCode Agent，并与同信息、同三次 GET 预算的固定规则对照。修正并保留两次回答格式导致的原始评分失败后，四轮原始事件在同一版评分器下重评均通过，固定规则也 4/4。Agent 每轮使用约 5.7–5.9 千输入加输出 Token，模型阶段约 8–10 秒；固定规则约 48–60 毫秒。详见 [评测记录](benchmarks/redirect-probe/README.md)。当前**没有测出 Agent 比固定规则更强**，负样本次数不足以推断稳定误报率；本机观察也不是实际漏洞确认。下一阶段先扩变化场景和重复负例，并保持同预算、独立评分。

## 2026-10-02：Hermes 只读迁移闭环

新增独立的 Hermes v0.21.2 Windows 运行配置、两工具 Node stdio MCP 服务、短时任务授权与逐跳预算核对、会话导出归一化和 Agent 外观察链评分；OpenCode 路径保留。Hermes 在确定性本机模型协议夹具上完成“授权页面观察 → EV → 离线入口清点 → 中文结论”，本机靶站收到一次 GET，独立评分通过，最新运行编号 `2026-10-02T10-47-51-445Z-51ff485c`。范围外、禁止路径、预算耗尽、重定向下一跳、伪造 EV 和无效授权的本机负例通过。夹具不是真实模型；提供方对 Hermes 匿名 OpenCode Free 调用返回 403，OpenRouter 无独立密钥，因此尚未完成同一真实模型的 Hermes/OpenCode 对照，不把本轮结果称为漏洞发现。复现、失败记录及 Grow 隔离模板见 [Hermes 评测说明](benchmarks/hermes-eval/README.md)。
