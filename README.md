# security-agent-lab

一个基于 OpenCode 开发、面向中文使用场景的自动化渗透测试 Agentic AI 项目。项目计划使用 Codex 与 ChatGPT 辅助设计、编码、测试和文档维护，目标是在自建靶场、CTF 和其他明确授权环境中，逐步实现能够自主规划、调用安全工具、保存证据并生成中文报告的渗透测试智能体。

OpenCode 是项目的智能体运行与扩展底座；Codex 和 ChatGPT 是当前主要的开发协作工具，不等同于项目运行时必须绑定的模型或服务。

长期目标与本学期制作安排见 [项目总体规划 v0.1](docs/project-plan.md)，阶段验收见 [路线图](docs/roadmap.md)。项目以授权红队渗透效果为目标，Agent 数量由评测决定；当前实现进度以 [TASK.md](TASK.md) 为准。

首个真实 OpenCode 单 Agent 观察任务可用 `npm run agent:eval -- deepseek/deepseek-flash` 复演；它在仓库外创建独立本地靶站和运行目录，不使用现有目标配置。任务、评分、结果位置和限制见 [评测说明](benchmarks/agent-eval/README.md)。

当前处于基础框架阶段。MedSecure 是首个开发与评测靶场，但核心模块不与某个靶场绑定。项目先实现单 Agent 的受限 Web 测试与证据闭环，再评估共享黑板和多 Agent 协作，最终逐步扩展为可独立使用的个人自动化渗透测试项目。

## 第一条目标链路

1. 接收显式授权的目标 URL。
2. 通过 Scope Guard 校验目标。
3. 发起一次受限 HTTP GET 请求。
4. 保存完整请求、响应和摘要。
5. 生成引用证据编号的 Markdown 报告。

当前已实现受限 GET、证据保存、中文观察报告和 OpenCode 自定义工具调用，并在 OpenCode 1.18.29 中完成本地授权目标的真实验证。漏洞假设状态机及本地持久化已实现；用户已反馈创建工具的缺配置拒绝和正向创建测试成功。按编号只读查询工具 `hypothesis_get` 已实现。确定性检查包括响应头复核、静态输入清点、低影响 GET 参数反射观察和特殊字符编码观察。XSS 候选可离线关联到去重的 `suspected` HYP，但不会自动确认漏洞。项目仍未实现漏洞利用、Shell 执行、共享黑板或多 Agent。

## 目录职责

- `.opencode/`：项目级 Agent、工具、技能、插件和命令。
- `src/adapters/opencode/`：OpenCode 适配层。
- `src/scope/`：授权目标和执行边界。
- `src/evidence/`：证据存储与完整性校验。
- `src/hypotheses/`：漏洞假设及状态流转。
- `src/identity/`：测试身份和会话管理。
- `src/reporting/`：引用证据的报告生成。
- `src/blackboard/`、`src/scheduler/`：后续多 Agent 协作。
- `src/evaluation/`：可重复评测与指标。
- `capabilities/web/`：Web 能力；`capabilities/network/`：后期研究边界。
- `benchmarks/medsecure/`：首个靶场任务定义。
- `evidence/`、`reports/`：本地产物，默认不提交 Git。

## 使用

### Phant0mV3il 终端入口

`pveil` 是 PhantomVeil 的终端入口。它不重新实现对话引擎，而是进入项目内定义的受限 Agent `Phant0mV3il` 的对话。默认运行时为 Hermes：无参数的 `pveil`（等价于 `pveil chat` 或 `pveil chat --runtime hermes`）进入未绑定目标的隔离 Hermes 受限会话。需要回退到 OpenCode TUI 时，显式使用 `pveil chat --runtime opencode`：

```powershell
pveil
```

使用 `pveil chat --runtime opencode` 回退时，当前终端必须能找到兼容的 `opencode` CLI；也可以用 `OPENCODE_BIN` 指定可执行文件。项目已验证的集成基线是 OpenCode 1.18.29。OpenCode 的模型与凭据仍由 OpenCode 自己管理。Hermes 默认会话由 fork 运行时启动，使用其原生凭据。

不需要 LLM 时，可直接复用现有确定性工作流：

```powershell
pveil check http://127.0.0.1:5000/
pveil crawl http://127.0.0.1:5000/
pveil --help
```

首次在本机开发环境注册 `pveil` 命令时，在项目目录运行一次 `npm link`。这只注册命令入口；不会安装 OpenCode，也不会改变授权配置。终端主题暂用容易替换的 PhantomVeil 黑灰幽灵紫方案，项目显示名为 `Phant0mV3il`。

无论从对话还是快捷命令进入，目标访问仍由现有工作流执行并经过 Scope Guard。`pveil` 不启用 OpenCode 的自动批准参数，也不会为 Agent 恢复 Shell、任意网络或文件编辑能力。

OpenCode 会话中的六个联网工具还共享请求尝试预算：默认每会话 20 次，重定向每跳计数，预算耗尽或记录不可用时停止发送。可在首次请求前将 `configs/request-budget.example.json` 复制为 `configs/request-budget.local.json` 并设置 1–100 次上限；本机配置不会提交。`pveil check`、`pveil crawl` 等直接运行的命令继续使用各自上限，不计入 OpenCode 会话预算。一个交互式会话可能包含多次用户任务，当前预算按会话累计。

### 自动发现并检查站内页面

受限爬虫已实现。首次安装依赖后，可以运行：

```powershell
npm ci
npm run crawl -- http://127.0.0.1:5000/
```

默认最多 10 个页面任务、两层链接、20 次请求尝试，每次间隔至少 300 毫秒。
复用已有本地授权配置，只跟进同一协议、主机、端口的普通无查询参数链接。
每页保存证据和响应头检查报告，最后生成中文汇总；报告还会列出静态 HTML 中发现的
表单目标和参数名称，但不会提交表单或保留参数值。无需模型 Token。

OpenCode 重启后说：“受限爬取 http://127.0.0.1:5000/，发现站内页面并检查响应头”。
参数默认就能使用，不必创建新配置；详细限制见 `docs/restricted-crawl.md`。

### 一句话检查一个 URL

首次使用新目标时，不必手写 JSON。可以在 PhantomVeil/OpenCode 对话中用中文说明目标与范围，例如“这是我已获授权的测试站点 `https://example.test/`，包含子域名，排除 `admin.example.test`；先登记任务范围”。Agent 会展示范围并调用目标登记工具请求一次确认；确认后才解析 DNS、保存当前任务配置与七天有效的低影响检查授权引用。若切换目标，原本的本地配置会备份到被 Git 忽略的 `configs/.local-backups/`。登记本身**不发送 HTTP 请求，也不等于扫描**；随后可让 Agent 调用现有单页、同源爬取或初步反射型 XSS 评估工具。

默认只登记输入 URL 的主机和路径分支；只有明确说“包含子域名”才会扩大到根域名及其子域名。IP 白名单记录登记时解析到的地址；其他子域名若解析到不同 IP，现有 HTTP 工具仍会拒绝，这需要后续完善按主机验证的连接策略。当前爬虫也仍只跨同一源，不会因为登记了整个域名就自动爬取子域名。对话入口只是省去手工改配置，**不是完整漏洞扫描器**。

启动自己的本地网站，重启 OpenCode 并选择 `web-security-agent`，直接输入：

```text
扫描 http://127.0.0.1:5000/，给我中文结果。
```

Agent 会调用 `authorized_web_check`，自动串起授权检查、受限 GET、证据保存、响应头检查和中文报告。
默认回复检查摘要；EV 编号等追溯信息保存在工具结果与报告中，不需要手动传递。
当前“扫描”仅覆盖单个 URL 的五项基础响应头规则，按现有策略处理重定向，不会遍历全站。

也可以直接在本项目终端运行，无需模型 API：

```powershell
npm run scan -- http://127.0.0.1:5000/
```

两种入口共用 `configs/scope.local.json` 和 `configs/http.local.json`，不会自动扩大授权范围。
结果写入 `evidence/opencode/` 与 `reports/opencode/`，不创建或修改 HYP。
报告包含通过、需要复核、不适用及证据引用；出现复核项不表示确认了漏洞。
命令退出码 `0` 表示流程完成（允许存在复核项），`2` 表示未完成或用法错误。
本轮没有改变授权配置，也不需要为这一入口新增配置。详见 `docs/one-click-check.md`。

用 OpenCode 打开本目录，选择或提及 `web-security-agent`。该 Agent 可调用 `authorized_web_observe` 完成一次受限 GET、证据保存和中文观察报告；`authorized_hypothesis_create` 只有在工具内核对独立的本地授权登记后，才能为匹配范围的 URL 离线创建 `suspected` 假设。该工具已配置为逐次询问批准（`ask`），但仍待在实际 OpenCode 会话中验证。Shell、文件读取/搜索、编辑及其他网络能力保持禁用。

### Hermes 交互式受限任务入口

统一命令现在默认使用 Hermes 运行时：无参数 `pveil`（或 `pveil chat`、`pveil chat --runtime hermes`，均不带其它参数）进入未绑定目标的隔离 Hermes 受限会话。显式定向任务与 OpenCode 回退如下：

```powershell
npm run pveil -- chat --runtime hermes --url 'http://127.0.0.1:5000/' --authorization-reference 'TASK-你的授权引用'
npm run pveil -- chat --runtime opencode
```

Hermes 的扩展任务在上述命令末尾添加 `--crawl`、`--reflection`、`--redirect`、`--encoding` 或 `--assessment`，每次只能选择一种。新目标的只读登记使用 `--new-target` 代替授权引用；该选项不能与扩展模式组合。`pveil` 只转交到既有隔离启动器，不改变任务授权和实际请求门禁。

日常启动可在项目目录直接运行，不必传 `-Url` 或授权引用：

```powershell
.\scripts\hermes-chat.ps1
```

这会打开尚未绑定目标的 `Phant0mV3il` 受限会话。进入 Hermes 后直接说「这是已授权目标 http://你的目标/」；PhantomVeil 会显示精确目标和路径，请你确认授权。确认前不解析 DNS 或发送 HTTP；确认后只在本次隔离任务登记该目标，允许一次只读观察和离线入口清点。项目现有配置中的明确禁止主机和路径仍会拒绝绑定；项目配置文件不会被改写。会话不能切换到第二个目标。

如需沿用上一阶段“从本地配置自动选择唯一目标并立即观察”的方式，运行 `.\scripts\hermes-chat.ps1 -ConfiguredTarget`；它会读取 `scope.local.json`、`http.local.json` 和 `authorization.local.json`，多目标时仍在启动前询问精确 URL。也可以显式指定已授权目标：

```powershell
.\scripts\hermes-chat.ps1 -Url 'http://127.0.0.1:5000/' -AuthorizationReference 'TASK-你的授权引用'
```

它启动名为 `Phant0mV3il` 的隔离 Hermes 交互会话；只读任务执行“授权页面观察 → EV → 离线入口清点 → 中文结论”。普通任务只允许该精确 URL 的一次 HTTP 请求；继续聊天不会重置预算，也不能切换目标。新目标需另起会话和授权。任务目录在仓库外的 `%LOCALAPPDATA%\PhantomVeil\hermes-chat-runs\`。普通 `hermes` 的 `/agent` 不能加载这套授权与门禁。OpenCode 仍保留供回退。

首次使用新授权目标可运行 `./scripts/hermes-chat.ps1 -Url 'http://127.0.0.1:5000/' -NewTarget`。终端会展示待登记的精确主机和路径，并在 DNS 解析及模型启动前要求确认；生成的配置只在本次仓库外任务目录使用，不覆盖项目现有本地配置。显式要求静态同源爬取时添加 `-Crawl`，整次任务最多 10 次请求；普通单页模式仍只有一次。爬取不执行脚本或提交表单，链接和表单清单不构成漏洞发现。

一次无害 GET 参数反射观察使用 `-Reflection`，要求 `parameter_reflection_check` 动作授权，最多两次请求。本机服务端跳转观察使用 `-Redirect`，要求 `redirect_probe`，最多三次请求且不访问目的地。反射加非执行字符编码观察使用 `-Encoding`，同时要求 `parameter_reflection_check`、`xss_encoding_probe`，最多三次请求；如果本次引用还允许 `hypothesis_create`，可对两份可信 EV 经单独批准创建 suspected HYP。完整低影响反射型 XSS 初步评估使用 `-Assessment`，要求以上三个动作，任务级批准后在起点的同源路径分支内逐请求检查，最多二十次 GET，只创建 suspected HYP。各主动模式互斥；没有审批界面或用户拒绝时，主动请求不会发送。以上均不执行脚本或确认漏洞。`-NewTarget` 只生成只读授权，不能自动用于这些主动模式。

同题完整评估的本机已知答案对照入口与当前验证范围见 [评测说明](benchmarks/hermes-assessment-eval/README.md)。它使用单独的本机四请求夹具，不借用历史任务授权；真实 DeepSeek 双端成绩尚未运行。
逐项工具接线与仍缺的验证见 [Hermes 能力对照](docs/hermes-parity.md)。

本仓库不包含 OpenCode 源码，只使用其公开项目配置和扩展入口。

当前开发环境已安装 OpenCode 1.18.29，并完成了真实模型驱动的本地观察任务复演。操作步骤与验证基线见 `docs/opencode-integration.md`。

OpenCode 工具读取被 Git 忽略的 `configs/scope.local.json` 和 `configs/http.local.json` 作为目标与 HTTP 配置。创建假设还要求 `configs/authorization.local.json` 中有启用、未过期、允许 `hypothesis_create` 且覆盖目标 URL 的授权记录；它与总体 Scope 独立，两者都要通过。仓库中的 `*.example.json` 只用于说明格式，**不是实际授权**；不要把内部资产范围提交 Git。

### Scope Guard 离线演示

需要 Node.js 22.18 或更高版本，不需要安装第三方依赖。

```powershell
npm run scope:demo -- http://127.0.0.1:8080/login
npm run scope:demo -- http://127.0.0.1:9090/
npm test
```

演示读取 `configs/scope.example.json`，只输出结构化授权判断，不发送网络请求。直接运行演示脚本时，拒绝结果使用退出码 `2`，用于以后让工具调用方区分“未授权”和程序错误。

如果授权范围覆盖整个域名及其子域名，可参考 `configs/scope.domain.example.json` 中的 `allowed_domains`。离线验证示例：

```powershell
npm run scope:demo -- https://oa.example.test/ configs/scope.domain.example.json
```

`allowed_hosts` 仍只匹配精确主机；`denied_hosts` 可排除精确主机。示例文件不是实际授权。实际网络工具还要通过本地授权登记、解析后 IP 白名单等检查，当前爬虫也仍只遍历起始 URL 的同一源。

### 受限 HTTP GET 本地演示

```powershell
npm run http:demo
```

该命令临时启动一个只监听 `127.0.0.1` 的本地页面，通过 Scope Guard 和授权 IP 检查后读取页面，再立即关闭测试服务器。也可以在明确授权且配置匹配时传入目标 URL：

```powershell
npm run http:demo -- http://127.0.0.1:5000/
```

HTTP 策略位于 `configs/http.example.json`。当前只发送 GET，不携带 Cookie 或认证信息；响应头中的 Cookie 和认证挑战不会进入演示结果。

### Evidence Store 本地演示

```powershell
npm run evidence:demo
```

该命令访问临时本地页面，把成功的 HTTP 观察保存到被 Git 忽略的 `evidence/demo/`，随后立即验证证据文件的 SHA-256。证据记录包含编号、时间、请求目标、响应状态、响应正文、重定向和完整性字段；敏感查询参数及认证类响应头会被脱敏。

### 中文观察报告演示

```powershell
npm run report:demo
```

该命令完成“本地 GET → 保存证据 → 校验证据 → 生成 Markdown 报告”的完整链路。报告写入被 Git 忽略的 `reports/demo/`，只引用证据编号与摘要字段，不直接嵌入不可信网页正文，也不会自动生成漏洞结论。

### 漏洞假设状态机演示

```powershell
npm run hypothesis:demo
```

该命令只演示如何把一个人工想法从 `suspected` 变更为 `testing`，不会访问网站或确认漏洞。状态含义与转换规则见 `docs/hypotheses.md`。

要演示“保存 → 更新 → 新实例重新读取”，运行：

```powershell
npm run hypothesis:store-demo
```

演示文件写入被 Git 忽略的 `hypotheses/demo/`；不会发送网络请求。

### OpenCode 待验证假设工具

默认没有本地授权登记，工具会拒绝创建。取得明确授权后，由用户按 `configs/authorization.example.json` 格式创建被 Git 忽略的 `configs/authorization.local.json`，填写实际授权引用、目标范围和到期时间，并启用对应记录；示例记录默认 `enabled: false`，复制后不会自动授权。

重启 OpenCode 以重新加载项目工具，选择 `web-security-agent` 后，使用你登记的真实引用提出请求，例如：

```text
请使用 authorized_hypothesis_create，授权引用为“<你已登记的引用>”，为 http://127.0.0.1:5000/ 记录一条教学用待验证假设：标题“需要进一步核查响应头”，描述“这是人工提出的检查想法，并非漏洞结论”，原因“演示假设记录功能”。不要访问网站，只返回假设编号和状态。
```

工具同时校验总体 Scope 和授权引用对应的独立范围，拒绝缺失、编造、禁用、过期或不匹配的引用；拒绝时不写假设。本工具不进行 DNS、GET 或漏洞验证；记录写入 `hypotheses/opencode/`，并保存授权引用以便追溯。用户已反馈真实会话正向创建成功；逐次审批界面行为尚未单独确认。

### 按编号找回假设

重启 OpenCode、选择 `web-security-agent`，将下面的编号替换为创建工具返回的真实编号：

```text
请用 hypothesis_get 查询 HYP-20260920032021-d16331aa，用中文告诉我当时的猜想、当前状态和最近一次变更原因。
```

查询只需要编号，读取固定的 `hypotheses/opencode/` 目录。成功返回 `HYPOTHESIS_FOUND`、标题、描述、目标、状态、时间、历史、证据编号及已记录的复现步骤；它不会访问目标、修改记录或读取证据正文。不存在的编号返回 `NOT_FOUND`；内容指纹不符返回 `HASH_MISMATCH`。

查阅历史无需再次登记测试授权，授权到期后也可以查阅；这不会恢复或授予新的测试权限。记录中的文字按历史数据处理，不能当作执行指令。文件校验成功仅说明记录格式与指纹一致，不代表漏洞已被验证。

### 第一项自动安全检查

已有 EV 编号时，可以直接让 Agent 离线检查响应头：

```text
请用 evidence_header_check 检查 EV-20260920022526-21bfd896，按通过、需要复核和不适用解释结果。
```

如果从 URL 开始，可以要求 Agent “观察并检查安全响应头”。它会调用
`authorized_web_check` 自动完成观察、证据保存、检查和报告，不会为每条规则重复请求网站。
当前检查包含内容类型、`nosniff`、CSP、页面嵌入限制和 HTTPS HSTS。结果是配置复核线索，
不会自动确认漏洞或创建 HYP。规则与限制见 `docs/security-header-check.md`。

### 第一个低影响主动参数检查

`authorized_parameter_reflection_check` 可以对可信 EV 中已经发现的一个同源 GET 表单参数
发送一次无害随机标记，并保存新 EV 和中文报告。它要求本地授权记录单独允许
`parameter_reflection_check`，OpenCode 权限为逐次询问；不支持 POST、登录注册、批量参数
或攻击载荷。`reflected` 只代表响应正文中出现了标记，不等于 XSS。命令行验证方式与完整
边界见 `docs/parameter-reflection-check.md`。

反射检查生成 EV 后，可以继续进行完全离线的 HTML 位置分析：

```powershell
npm run reflection:analyze -- <反射检查生成的EV编号>
```

OpenCode 工具 `evidence_reflection_context` 会区分普通文本、HTML 属性、脚本、样式和注释，
但不会测试特殊字符编码、执行脚本或确认 XSS。详细边界见 `docs/reflection-context-analysis.md`。

### 第一个 Agent Skill

项目级 Skill `authorized-reflected-xss-triage` 已把“发现 GET 参数 → 一次无害反射检查 →
离线上下文分类”整理为 Agent 可按需加载的中文流程。Skill 只负责决定调用顺序和停止条件，
不代替 Scope Guard、授权登记或 Tool 的逐次审批。当前 Agent 只允许加载这个 Skill，其他本地或
全局 Skill 默认隐藏。设计和外部 Skill 接入检查见 `docs/skills.md`。

### 一次批准的主动 XSS 初步评估

`authorized_reflected_xss_assessment` 接收一个已登记授权的目标 URL 和授权引用。它在任务开始前
只询问一次，随后自动完成有界爬取、GET 参数筛选、最多 10 个参数的无害反射检查、离线上下文
分析、每个反射参数的一次非执行编码观察，以及确定性的 HYP 跳过/创建/复用，不再逐参数询问。
每个响应仍保存 EV，最后生成 `AXSS-*.md` 汇总报告。

同一授权引用必须同时允许 `parameter_reflection_check`、`xss_encoding_probe` 和
`hypothesis_create`，缺一项就在任何请求前停止。该工作流不会提交 POST、测试登录注册、发送脚本载荷或修改目标数据；密码、文件、令牌字段及
明显删除、退出、重置类路径会被跳过。参数数量和间隔可通过本地配置收紧或调整，详见
`docs/active-reflected-xss-assessment.md`。

### XSS 特殊字符编码观察

已有一次反射成功的请求 EV 后，可以继续执行一个单请求编码观察：

```powershell
npm run xss:encoding -- <反射EV编号> <授权引用>
```

OpenCode 工具 `authorized_xss_encoding_probe` 会重新校验来源 EV、Scope 和单独的
`xss_encoding_probe` 授权动作，并在网络请求前询问一次批准。探针只包含彼此隔离的 `<`、`>`、
双引号、单引号和 `&`，不包含标签、事件处理器或 JavaScript。它记录字符是原样出现、HTML 实体
编码、URL 编码、被删除还是发生其他转换，并保存新的 EV 与 `ENC-*.md` 报告。

原样字符只是需要结合输出上下文复核的信号，不是已确认 XSS；观察到编码也不能证明网站安全。
完整边界和结果含义见 `docs/xss-encoding-observation.md`。

### 把 XSS 候选关联到 HYP

反射 EV 与对应的编码观察 EV 都存在后，可执行纯离线关联：

```powershell
npm run xss:hypothesis -- <反射EV编号> <编码EV编号> <授权引用>
```

OpenCode 中对应工具为 `authorized_xss_hypothesis_triage`。它重新校验两份 EV，并要求规范化端点和
参数相同。五个字符全部编码时返回“不需要创建 HYP”；观察到原样边界字符时，才在
`hypothesis_create` 授权和一次本地写入批准后创建或复用 `suspected`。去重键是漏洞类型、端点和
参数名，同一候选的新 EV 会追加到原记录，状态不会自动升级。详见
`docs/xss-hypothesis-triage.md`。

### 从已有证据清点输入入口

已有 HTML 类型的 EV 编号时，可以让 Agent 离线识别静态表单和参数：

```text
请用 evidence_input_inventory 分析 EV-20260922075431-d87fbb05，告诉我页面有哪些表单和参数入口。
```

该工具不重新访问网站，不执行 JavaScript，也不提交表单。它只返回表单方法和去掉参数值的
action、控件名称/类型以及链接中出现的参数名称；发现输入入口不代表存在漏洞。动态页面脚本
生成的交互当前无法看到。详细限制见 `docs/input-inventory.md`。

## 开发方式

- 使用 Codex 与 ChatGPT 辅助需求分析、架构设计、代码实现、测试和文档整理。
- 以 OpenCode 的项目级 Agent、工具、技能、插件和命令机制作为主要集成入口。
- 默认使用中文交互、状态说明、审批提示和安全报告；必要的工具参数与原始证据保留其原始语言。
- 每次开发只推进一个可验证的小功能，并记录改动、测试结果、限制和下一步任务。

## 安全边界

- 默认拒绝未显式授权的目标。
- 不自动扩展到公网或第三方系统。
- 当前禁止任意 Shell 命令和漏洞利用。
- 无证据支持的漏洞只能标记为“待验证”。
- API Key、Cookie、密码和原始证据不得提交 Git。

## 状态

- [x] 项目骨架与设计文档
- [x] 受限的 OpenCode 主 Agent
- [x] 离线 Scope Guard
- [x] 受限 HTTP GET 能力
- [x] Evidence Store
- [x] 引用证据的中文观察报告
- [x] OpenCode 自定义工具适配层及本地测试
- [x] 实际 OpenCode 1.18.29 中的工具加载与调用验证
- [x] 离线漏洞假设状态机核心
- [x] 漏洞假设的本地持久化
- [x] OpenCode 待验证假设创建工具及本地测试
- [x] 创建工具真实会话正向调用（用户反馈）
- [x] OpenCode 只读假设查询工具及本地测试
- [x] 基于已有 EV 证据的 HTTP 安全响应头检查及本地测试
- [x] 单 URL 一键检查、中文报告和无模型命令行入口
- [x] 受限同源爬虫、页面/深度/请求/间隔限制和中文汇总
- [x] 基于已有 HTML 证据的只读表单、控件和参数名称清点
- [x] 基于已有 GET 表单证据、独立授权和单次无害标记的参数反射检查
- [x] 基于反射 EV 的离线 HTML 输出上下文分类
- [x] 第一个项目级反射型 XSS 初步排查 Skill
- [x] 一次任务批准后自动检查多个安全 GET 参数的主动评估工作流
- [x] URL 主流程自动衔接反射、编码观察和确定性 HYP 去重
- [ ] 完整 URL 主流程真实 OpenCode 会话验证
- [ ] 受限爬虫真实 OpenCode 会话验证
- [ ] 输入入口清点工具真实 OpenCode 会话验证
- [ ] 参数反射检查工具真实 OpenCode 审批与调用验证
- [ ] 查询工具真实 OpenCode 会话验证
- [x] 响应头检查工具真实 OpenCode 会话验证（用户反馈结果）
- [ ] 一键检查工具真实 OpenCode 会话验证
- [ ] 创建工具逐次审批界面行为确认
- [x] 将 XSS 编码复核候选以授权、确定性去重方式关联到 HYP
- [ ] XSS 候选 HYP 工具真实 OpenCode 会话验证
- [ ] 身份与权限测试
- [ ] 单 Agent 基准评测
- [ ] 共享黑板与多 Agent
