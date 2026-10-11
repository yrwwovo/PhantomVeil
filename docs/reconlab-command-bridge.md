# ReconLab 命令入口接线

2026-10-11 复用决定：适配现有 `prepareHermesAwaitTargetChat`、`HermesTaskService.bindTarget`、受限 MCP、原生 Hermes 凭据解析、一次性 CLI 和会话导出。ReconLab 只发送目标、任务原文和人工批准；不另建模型循环或扫描器。

第一条验收链路：ReconLab 作战台 → 本机 PhantomVeil bridge → 展示精确 URL 并批准 → 独立任务 Scope/一次请求预算 → Hermes 受限 MCP 观察和离线清点 → EV 校验与中文报告 → 网页。

每个任务仅执行一次，审批等待期间不启动 Hermes、不解析目标 DNS、不发目标请求。批准不能修改 URL 或命令；新目标或第二轮执行须新建任务。原生模型密钥只由 Hermes 服务端解析。页面重连可恢复已保存事件。

本机入口只监听 loopback；拒绝未知 Host、远程连接和非白名单网页 Origin。部署到远程 ReconLab 前须另接用户认证、任务所有权与受信任执行节点，不能将本机端口直接公开。

验证区分真实 Hermes + 本机协议模型的接线测试与真实提供方效果。仅当读取到校验通过的 EV、对应任务报告和受限工具调用后，才把任务标为完成；模型文字不能代替执行证据。

## 本机启动

配套源码：[PhantomVeil](https://github.com/yrwwovo/PhantomVeil)、[Hermes 运行时](https://github.com/yrwwovo/phantomveil-hermes/tree/phantomveil/main)、[ReconLab](https://github.com/yrwwovo/ReconLab)。后两个仓库为私有仓库，需要拥有者授权才能克隆。

需保留同级目录 `security-agent-lab`、`phantomveil-hermes` 和 `ReconLab/reconlab-console-orchestrator`。Hermes fork 的 `.venv` 与原生模型配置需已安装。

1. 在 `D:\Projects\security-agent-lab` 运行 `npm run reconlab:bridge`，监听 `127.0.0.1:8092`。
2. 按 ReconLab 原有方式启动 PocketBase（8090），在 `D:\Projects\ReconLab\reconlab-console-orchestrator` 运行 `npm run dev`。
3. 打开 `http://127.0.0.1:5173/`，登入后进入「对话式作战台」。填写规范化 URL（含完整路径、不含查询参数）、任务，提交后确认精确目标授权。
4. 页面展示 PV 任务编号、工具事件、最终说明、EV 编号/哈希与报告。可叫停。服务重启将执行中的任务标为中断，不能自动重跑。

任务及事件默认保存于 `%LOCALAPPDATA%\PhantomVeil\reconlab-bridge`，在源码仓库外。模型密钥沿用原生 Hermes 凭据，仅在服务端解析，不复制到任务配置或发送给网页。健康状态只检查运行入口是否存在，不证明模型凭据可用。

仅允许同一时刻一个执行任务。一次请求预算含重定向；HTTP 403 停止并保留观察证据。现有源 Scope 的明确禁止主机/路径继续生效。

## 本轮验收

- 2026-10-11：命令桥、Hermes 会话准备和工具服务聚焦测试：28 项，25 通过、3 跳过、0 失败。
- 集成测试使用实际 fork Python/Hermes 进程、实际 MCP 与本机 HTTP 目标；模型端使用确定性协议夹具。确认批准前零模型/目标请求，批准后恰好一次 GET、校验通过的 EV、引用该 EV 的报告返回到命令接口；工具集合受限。
- ReconLab `npm run build` 通过。
- 实际浏览器操作新页面组件：提交 → 展示目标授权 → 确认执行 → 工具事件 → 已完成/EV/中文报告，通过。界面使用临时独立挂载夹具；未测试真实 PocketBase 登录。页面复用生产 `/console` 所用组件与 Vite `/phantomveil` 代理。
- Hermes 原生凭据解析回归：5 项通过；集成任务配置未复制原生密钥。
- 复现集成测试：PowerShell 设置 `$env:PVEIL_RECONLAB_INTEGRATION='1'` 后运行 `node --test tests/reconlab-bridge.test.ts`。不需要真实模型密钥。

当前为本机开发入口。尚未验证真实提供方效果；静态部署的网页没有此代理。完整有界爬取/主动检查/APK 任务、PocketBase 扫描/资产/复核队列统一落库、远程执行节点认证与任务所有权仍需后续接线。旧 Python 编排器文件保留，`/console` 页面已改用 PV 入口。
