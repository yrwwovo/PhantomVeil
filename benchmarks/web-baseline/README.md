# 本地 Web 工作流基线 v1

运行：

~~~powershell
node benchmarks/web-baseline/run.mjs
~~~

脚本只启动本机 127.0.0.1 临时 HTTP 靶站，为该端口创建临时 Scope 与动作授权，调用现有的 `runAuthorizedReflectedXssAssessment` 两次，并在退出时删除临时证据与报告。程序化批准仅用于这个内置靶站；它没有调用 OpenCode 模型，也没有对外部目标发送请求。

## 已知答案

| 输入 | 靶站行为 | 预期 |
|---|---|---|
| `/raw?q` | 静态表单，原样反射 | 原样字符候选 |
| `/dynamic?q` | JavaScript 执行后才出现的表单，原样反射 | 原样字符候选 |
| `/escaped?q` | 静态表单，HTML 编码反射 | 不产生原样字符候选 |
| `/quiet?q` | 静态表单，不反射 | 不产生原样字符候选 |

`/logout` 是明显高影响路径，要求不发送请求。脚本比较两次运行中除耗时外的全部指标，不一致就失败。

## 2026-09-30 首次结果

两次运行结果一致：4 个已知输入中检查了 3 个；识别出 `/raw?q`，漏掉 `/dynamic?q`；候选精确率 1/1，候选召回率 1/2；每次 6 个 HTTP 请求、1 次本地任务批准、0 个禁止路径请求、1 个 suspected HYP。漏掉的输入由 JavaScript 动态生成，当前静态 HTML 爬取不会执行脚本。耗时由脚本逐次输出，仅反映本机该次运行。

这些指标衡量**原样字符候选发现**，不是漏洞发现率、漏洞确认率，也不是 Agent 自主解题率。原样字符与 suspected HYP 都不足以确认 XSS。当前工作流没有独立的漏洞确认规则，因此输出 `vulnerability_confirmation_evaluated: false`。

## 复用选择与下一步

本次直接复用项目已有的 Scope Guard、授权登记、反射评估、证据与 HYP 工作流。评估了 [AutoPenBench](https://github.com/lucagioacchini/auto-pen-bench) 的任务/容器基准和 [CAGE](https://github.com/AgentCyberRange/CAGE) 的 Agent 运行与评分框架；它们适合后续端到端 Agent 解题评测，但接入成本超过当前这个本机、单工作流、四个已知输入的实验，因此没有引入依赖或复制代码。

下一个评测层需要实际驱动 OpenCode 单 Agent，在隔离、已知答案的任务上记录模型、提示词、工具调用、Token/耗时、重复尝试与最终任务结果。之后再用相同条件评估多 Agent。对真实授权目标不能用未知的漏洞总数计算发现率。
