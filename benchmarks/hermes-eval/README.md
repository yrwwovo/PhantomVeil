# Hermes 单 Agent 只读迁移切片

## 本次文件变更

- 新增 `src/adapters/hermes/task-service.ts`、`mcp-server.ts`、`run-events.ts`；新增 `src/evaluation/hermes-observation-score.ts`。
- 新增 `src/workflows/web-observation.ts`、`evidence-link-inventory.ts`、`evidence-input-inventory.ts`；对应的三个 `src/adapters/opencode/` 文件改为薄转发，保持原工具行为和回退路径。
- 修改 `src/evaluation/observation-score.ts` 以允许独立 Hermes 证据目录；修改 `src/scope/authorization-registry.ts` 增加只读 `web_observe` 动作。
- 新增 `benchmarks/hermes-eval/run.mjs`、`fixture-model.mjs`、`profiles/learning-off.yaml`、`profiles/learning-on.yaml`、本说明及 `tests/hermes-task-service.test.ts`。
- 修改 `package.json`、`package-lock.json` 增加 MCP 服务依赖与运行命令；更新 `DECISIONS.md`、`TASK.md`、`docs/architecture.md`。

## 本阶段能复现什么

Hermes v0.21.2 在仓库外的隔离 profile 中运行；本地 stdio MCP 只提供 `authorized_web_observe` 和 `evidence_entry_inventory`。一次任务生成新的短时本机授权、精确 URL 清单和一次请求预算。Agent 先对授权首页执行一次受限 GET，保存 EV 与中文观察报告，再从同一 EV 离线清点链接和 GET 表单。两个工具以外的终端、文件、浏览器、任意联网、代码执行和委派工具均关闭。原 OpenCode 路径保留。

`run.mjs` 在源码仓库外写入任务原文、Hermes 会话导出、工具调用、授权与发送前决定、靶站实际请求、EV/报告引用、独立评分、Token 和耗时。运行目录默认为 `%LOCALAPPDATA%/PhantomVeil/hermes-eval-runs/<run-id>`；不得把其中原始事件、证据和报告复制到 Git。评分器不依赖模型自述，核对靶站请求、EV 哈希与正文、中文报告、离线清点和最终回答。

## 运行

使用官方 Hermes v0.21.2 并安装 MCP extra；本机测试使用 Windows 原生 Python 3.12 和 `uv sync --frozen --extra mcp --no-dev`。当前可在 `D:\Projects\.phantomveil-hermes-runtime\.venv\Scripts\hermes.exe` 找到与项目同级、仓库外的固定版本安装。将 `HERMES_BIN` 设为该可执行文件路径，然后运行：

```powershell
npm test
npm run hermes:eval -- fixture-model local-fixture
```

后一条是真正的 Hermes 会话与 MCP 协议冒烟测试，但模型响应由本机确定性夹具提供；`fixture-model` 的 Token 是夹具数值，不是模型成本，也不能计入真实模型对照。接入一个在隔离环境内已配置的真实提供方后可运行：

```powershell
npm run hermes:eval -- MODEL PROVIDER --learning=off
```

同题 OpenCode 对照入口使用同一 `run.mjs`、本机页面、任务原文、一次请求预算、MCP 服务与独立评分器：

```powershell
npm run hermes:eval -- MODEL PROVIDER --runtime=opencode --opencode-model=PROVIDER/MODEL
```

首个真实同模型对照使用配对入口。它让两端顺序访问**同一个本机 URL**，并在独立运行目录中分别生成新授权、EV 和评分：

```powershell
npm run hermes:pair -- deepseek-flash deepseek
```

若启动进程中没有 `DEEPSEEK_API_KEY`，入口会在启动模型和本机靶站前记录 `blocked_model_credentials`。进程环境变量只由该进程及之后启动的子进程继承；在另一个终端设置它，不会让已启动的 Codex 进程自动取得它。普通 Hermes 保存的凭据也不会进入每轮新建的隔离评测 profile。用户可在设置该变量的同一 PowerShell 终端运行上面的配对命令，或运行 `scripts/hermes-pair.ps1`：脚本优先使用当前终端可见的隔离 Hermes 虚拟环境（包括 Codex 应用实际磁盘路径），最后才使用官方 Windows CLI 启动器，隐藏输入密钥并只在本次进程及其 Hermes 子进程中使用，结束后恢复原先的 `HERMES_BIN` 并清除它临时设置的密钥变量；它不读取 OpenCode 凭据，也不把密钥写入仓库或运行摘要。不要把密钥作为命令行参数或聊天消息传入。配对评分要求 URL、任务原文、两项工具、模型路由、一次请求预算、四步 Agent 上限、150 秒墙钟上限及源码/评分器摘要相同，授权任务编号不同，并分别核对真实请求和 EV。Token 仅记录，尚无跨两运行底座的发送前硬上限；相同模型 ID 也不能证明提供方后端权重版本完全一致。

`--opencode-model` 用于两套客户端的路由名不同的情况；两边实际底层模型须核实为同一版本。OpenCode 隔离配置只允许这两项 MCP 工具。每轮重新生成短时本机授权；历史 OpenCode 观察成绩不计入本轮。该入口已通过事件归一化单测、本机 MCP 连接检查和一次真实同模型配对，结果见下文。

运行器不读取现有的本机授权登记或旧任务证据，给每次任务生成新的授权。真实提供方凭据由 Hermes 的隔离运行环境取得；不要将密钥写入项目文件。`mcp test phantomveil-hermes` 可检查两项工具是否被发现，但它不代表模型任务通过。

## 结果与限制（2026-10-02）

- 本机协议夹具的此前通过轮次：`2026-10-02T10-47-51-445Z-51ff485c`。Hermes 调用两个 MCP 工具，靶站收到 1 次 GET，独立评分通过；记录到 90 输入 / 36 输出夹具 Token、约 17.7 秒。前一通过轮次的隔离 profile 工具清单实查仅启用 `phantomveil-hermes`（1/28 个工具集）。旧轮次均保留。
- 保留早期失败：`2026-10-02T10-17-19-405Z-39cd1194` 为 v0.21.2 不支持文档中的 `--format stream-json`；`2026-10-02T10-35-02-412Z-5902dcd4` 已完成工具链，但首次会话导出解析未识别 Hermes 的不可信工具结果包装，评分失败。修复后新轮次通过，旧轮不改写为通过。
- `opencode-free` 的 `mimo-v2.5-free` 在 Hermes 中被提供方以 403 拒绝，理由是免费层仅供 OpenCode 内使用；`deepseek-v4-flash-free` 被提供方报告模型不可用；OpenRouter 运行环境没有独立 API 密钥。均未发出靶站请求，不计入有效解题样本。
- 历史 OpenCode 观察题与本题的工具链不同，不能并入同模型配对；首次有效配对见 2026-10-04 记录。
- 2026-10-03 新增 OpenCode 隔离对照入口。用故意不存在的 `dummy/dummy` 路由做启动失败演练：未请求靶站；新配置的本地 MCP 服务连接成功。该演练不证明模型能完成任务，不能计作对照样本。
- 此题仅验证观察与离线入口清点，不测试漏洞发现、主动探测、HTTPS 或真实站点泛化。新一轮主动探测必须单独取得授权。
- 2026-10-04 完整项目回归测试：最新 `npm test` 为 178/178 通过；包含配对评分的有效例、不可比配置和环境失败测试。调整配对启动路径期间有一次未归因的偶发断言失败，随后复跑均通过；该偶发性尚未定位。

## 2026-10-03：首次同题启动尝试

- OpenCode v1.18.29 使用 `deepseek/deepseek-flash`，运行 `2026-10-03T03-48-05-415Z-7ea008e2`：两项 MCP 工具依次完成，本机靶站实际收到 1 次 GET，独立评分通过；记录到输入 1361、输出 559 Token，耗时约 6.6 秒。这是观察与离线清点任务成功，不是漏洞发现。
- Hermes v0.21.2 使用隔离 profile 的 `deepseek-flash` / `deepseek`，运行 `2026-10-03T03-48-24-218Z-f6afa1af`：模型访问凭据在该隔离运行环境不可用，进程退出；0 次工具调用、0 次靶站请求，不计为有效模型样本。没有读取或复制 OpenCode 的本机凭据。
- 两端的免费 `mimo-v2.6-flash-free` 也各启动一次，分别记录 `2026-10-03T03-46-55-250Z-32b7237f` 与 `2026-10-03T03-47-36-990Z-d5eeeca5`；均在目标请求前失败，OpenCode 明确收到免费层仅限 OpenCode 内使用的提供方错误。不能把这些失败当成解题表现。
- 因 Hermes 尚未获得可用的独立 DeepSeek 路由，本次没有成对的真实同模型对照结果。下一次应由用户在隔离 Hermes 运行环境私下配置同一模型的访问权限，不把密钥写入仓库或发到对话中；随后重跑两端新任务授权，核对实际模型版本和全部评分记录。
- 2026-10-04 配对入口预检运行 `pair-2026-10-04T03-42-19-599Z-9a4ab98e` 因本次进程未提供 DeepSeek 凭据而停止，0 次模型/靶站调用；不存在模型 `dummy/dummy` 的接线运行 `pair-2026-10-04T03-42-29-688Z-75d5a840` 确认两端使用同一个 URL、提示词和不同任务授权，均在模型阶段失败且均未请求靶站，归类为 `incomplete_environment`。这不是有效模型对照。
- 加入四步 Agent 与 150 秒墙钟上限后，`pair-2026-10-04T03-48-27-612Z-c21ea78a` 再次通过同 URL/同提示词/不同授权的接线核对，仍因假模型归类为环境失败。Hermes 协议夹具新轮次 `2026-10-04T03-46-16-552Z-4300a8c0` 通过（两工具、一次 GET、独立评分通过，夹具 Token 90/36）；OpenCode 的新 DeepSeek 单边轮次 `2026-10-04T03-48-51-519Z-96731f9b` 通过（两工具、一次 GET、独立评分通过，记录 Token 1388/609）。这两轮目标端口不同，不能拼成有效配对。
- 本机终端于 `pair-2026-10-04T04-25-37-559Z-a453fc6e` 创建配对目录，但没有写出结果摘要；检查时已无对应 Node/Hermes 进程，也没有新单边运行目录。这次无法判定具体原因或计入评分。之后修复配对入口的启动异常记录；用故意不存在的 Hermes 可执行文件验证会生成 `launch_failed`、`hermes_binary_check`、`ENOENT` 的摘要，仍未发出模型或靶站请求。真实配对需重新运行。
- 本机终端再次运行 `pair-2026-10-04T04-36-55-614Z-94367ca4`，明确记录 `launch_failed`、`hermes_binary_check`、`ENOENT`，无单边运行。已验证项目隔离 Hermes v0.21.2 可执行文件存在并可启动；此错误指向该终端传入的 Hermes 路径不可访问，尚未读取该终端的环境变量值。随后让 `scripts/hermes-pair.ps1` 临时固定已验证的隔离安装路径并在退出时恢复原值；仍需新一轮真实配对确认。
- 普通 PowerShell 看不到 Codex 应用内可见的隔离 Hermes 路径，因此包装脚本在隔离路径不可访问时使用官方 Windows CLI 安装路径；配对入口也依次检查显式路径、隔离路径和官方路径，并记录实际选用来源。Windows 应用目录映射还使子运行输出的路径文字与父进程路径文字可能不同；父进程现在只接受格式严格的运行编号，从自己的运行目录构造结果路径，再拒绝目录或结果文件的符号链接并核对运行身份。`pair-2026-10-04T12-34-11-394Z-d2ca55a8` 的假模型接线复跑产出两端同 URL、零请求的完整摘要，正确归类 `incomplete_environment`；真实模型成绩仍待运行。
- 首次真实同题配对 `pair-2026-10-04T12-37-07-455Z-b9881a75`：OpenCode 的 DeepSeek 侧两工具、一次实际 GET、独立评分通过（输入 1436 / 输出 746 Token）；Hermes 侧在工具和靶站请求前退出，0 Token、0 请求，状态 `environment_error`。诊断仅作类别提取：官方 CLI 启动器在新的隔离数据目录准备依赖后因 Windows 路径错误退出，不能记为 Hermes 解题失败。随后在普通终端的包装脚本中优先选取 Codex 应用实际磁盘路径下的隔离 v0.21.2 虚拟环境；用 `pair-2026-10-04T12-42-06-169Z-e51a244c` 的无凭据假模型接线验证该可执行文件可在隔离 profile 下启动、两端结果可完整记录，仍需再跑真实模型。
- 第二次真实同题配对 `pair-2026-10-04T12-51-01-978Z-5f9f38f6`：OpenCode 侧两工具、一次实际 GET、独立评分通过（输入 1397 / 输出 654 Token）；Hermes 侧 48 毫秒内退出，0 工具、0 请求、0 Token，诊断为 `uv trampoline failed to canonicalize script path`。这表明原虚拟环境可执行文件不能跨 Codex 应用目录使用，仍不是模型解题成绩。之后从上游固定标签 `v2026.9.11` 克隆到 `D:\Projects\.phantomveil-hermes-runtime`，确认提交 `939e45c91d751fadd94dcd1b873ac3cb44846213`，用 Windows Python 3.12 安装冻结依赖及 MCP extra。共享路径本机夹具运行 `2026-10-04T12-55-58-609Z-4abe7993` 完成两工具、一次 GET、独立评分通过，夹具 Token 为 90/36；这只证明运行与 MCP 接线，不算真实模型对照。
- **首次有效真实同模型配对** `pair-2026-10-04T12-57-26-541Z-a4806dd3`：Hermes `2026-10-04T12-57-26-674Z-febf5268` 与 OpenCode `2026-10-04T12-57-39-918Z-890bdff0` 均使用 DeepSeek `deepseek-flash`、同一任务原文、两项 MCP 工具、同一本机 URL、一次请求预算和四步/150 秒上限，各自有新的授权与 EV。配对评分为 `paired_passed`；两边各有一条批准与发送前记录、一次实际 GET、两项依次完成的工具调用，EV 哈希和报告引用均由 Agent 外评分核对，中文观察结论通过。Hermes 记录输入 3962 / 输出 606 Token、13.1 秒；OpenCode 输入 1416 / 输出 607 Token、7.2 秒。这是一次观察与离线入口清点成功，**不是漏洞发现**；提供方后端权重版本未核实，Token 仍只有记录而无发送前硬上限，单轮数字不支持效率或能力优劣结论。

## Grow 后续配置

`profiles/learning-off.yaml` 关闭内建记忆和背景复盘；`profiles/learning-on.yaml` 为另一独立 `HERMES_HOME` 开启记忆与 Skill，但两种写入均开启审批。运行器可用 `--learning=on` 创建新的开启组任务与 profile；开启组的待写入内容需逐项审查后才能进入后续运行。第一轮训练任务与第二轮评估任务必须不同，第二轮使用未见过的同类任务；目前没有学习收益数据。
