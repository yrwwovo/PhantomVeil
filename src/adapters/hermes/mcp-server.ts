import { readFile } from "node:fs/promises";
import path from "node:path";

import { McpServer } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";

import { HermesTaskService, type HermesTaskGrant } from "./task-service.ts";

function response(result: { ok: boolean }) {
  return { isError: !result.ok, content: [{ type: "text" as const, text: JSON.stringify(result) }] };
}

export function createHermesMcpServer(service: HermesTaskService,
  approvalOverride?: (message: string) => Promise<boolean>): McpServer {
  const server = new McpServer({ name: "phantomveil-hermes", version: "0.1.0" });
  const askApproval = async (message: string) => {
    if (approvalOverride) return approvalOverride(message);
    try {
      const decision = await server.server.elicitInput({ message,
        requestedSchema: { type: "object", properties: {} } });
      return decision.action === "accept";
    } catch { return false; }
  };
  server.registerTool("authorized_target_bind", {
    description: "仅在用户直接提出已授权目标后调用；向用户确认精确目标，并将当前未绑定会话锁定为一次只读观察任务。确认前不解析 DNS 或发送 HTTP。",
    inputSchema: z.object({ url: z.url().describe("用户直接给出的完整 HTTP(S) 目标 URL") }),
  }, async ({ url }) => response(await service.bindTarget(url, details => askApproval(
    `你确认已获 ${details.target} 的测试授权，并同意将本次会话仅绑定到路径 ${details.allowed_path} 吗？` +
    "确认后只登记本次隔离任务的只读范围；最多一次受限 GET。拒绝则不解析 DNS、不发送 HTTP。"))));
  server.registerTool("authorized_task_authorize", {
    description: "已绑定后单独确认有界爬取的目标路径、页数和总请求预算；不会发送请求，不重置已用预算。",
    inputSchema: z.object({ max_pages: z.number().int().min(1).max(5).default(5),
      max_requests: z.number().int().min(1).max(20).default(10) }),
  }, async input => response(await service.authorizeTask(input, details => askApproval(
    `确认爬取 ${details.target} 吗？仅同源路径 ${details.path_prefix} 及其子路径，最多 ${details.max_pages} 页、` +
    `深度 ${details.max_depth}、总计 ${details.max_requests} 次请求（含已用请求和重定向）；` +
    "现有 Scope 禁止规则继续生效。只抓取静态页面并离线清点查询参数名，不提交参数。"))));
  server.registerTool("authorized_web_observe", {
    description: "对本次任务明确授权的 URL 执行一次受限只读 GET，保存 EV 和中文观察报告。",
    inputSchema: z.object({ url: z.url().describe("本次任务授权的完整 URL") }),
  }, async ({ url }) => response(await service.observe(url)));
  server.registerTool("evidence_entry_inventory", {
    description: "离线验证本次任务 EV，并清点授权链接与静态表单输入；不发送网络请求。",
    inputSchema: z.object({ evidence_id: z.string().describe("authorized_web_observe 返回的 EV 编号") }),
  }, async ({ evidence_id }) => response(await service.inventory(evidence_id)));
  server.registerTool("evidence_link_inventory", {
    description: "从本次可信 EV 离线清点同源链接，不发送请求。",
    inputSchema: z.object({ evidence_id: z.string() }),
  }, async ({ evidence_id }) => response(await service.linkInventory(evidence_id)));
  server.registerTool("evidence_input_inventory", {
    description: "从本次可信 EV 离线返回页面 URL、查询参数名及来源 EV；不返回参数值，不发送请求。",
    inputSchema: z.object({ evidence_id: z.string() }),
  }, async ({ evidence_id }) => response(await service.inputInventory(evidence_id)));
  server.registerTool("evidence_header_check", {
    description: "按本次任务 EV 离线检查安全响应头；不发送请求，也不确认漏洞。",
    inputSchema: z.object({ evidence_id: z.string().describe("本次任务的 EV 编号") }),
  }, async ({ evidence_id }) => response(await service.headerCheck(evidence_id)));
  server.registerTool("authorized_web_check", {
    description: "对本次授权 URL 执行一次受限 GET，保存 EV、检查响应头并生成中文报告。",
    inputSchema: z.object({ url: z.url().describe("本次任务授权的完整 URL") }),
  }, async ({ url }) => response(await service.webCheck(url)));
  server.registerTool("authorized_web_crawl", {
    description: "仅在本次任务显式启用爬取时，从授权起点执行有界同源静态链接发现；逐跳检查并保存 EV 与中文汇总报告。",
    inputSchema: z.object({ url: z.url().describe("本次任务授权的爬取起点 URL") }),
  }, async ({ url }) => response(await service.crawl(url)));
  server.registerTool("authorized_parameter_reflection_check", {
    description: "从本次已验证页面 EV 选择一个同源 GET 表单参数；人类批准后只发送一次无害反射标记，不确认 XSS。",
    inputSchema: z.object({ evidence_id: z.string(), form_index: z.int(), parameter_name: z.string() }),
  }, async (input) => response(await service.reflection(input, details => askApproval(
    `PhantomVeil 请求一次主动 GET 参数反射检查：${details.endpoint}，参数 ${details.parameter_name}。` +
      "将发送一个无害随机标记并保存 EV；这不是漏洞确认。是否批准本次调用？"))));
  server.registerTool("authorized_redirect_probe", {
    description: "仅对本机授权靶场、可信 EV 中的 GET 跳转参数，在人类批准后发两次无害标记请求；只观察首个 3xx，不访问目的地。",
    inputSchema: z.object({ evidence_id: z.string(), form_index: z.int(), parameter_name: z.string() }),
  }, async (input) => response(await service.redirectProbe(input, details => askApproval(
    `PhantomVeil 请求一次本机重定向参数观察：${details.endpoint}，参数 ${details.parameter_name}。` +
      "将发送两次带不同 .invalid 目的地的 GET，只观察响应 Location，不访问目的地。" +
      "结果仅是待复核候选；是否批准本次两次请求？"))));
  server.registerTool("evidence_reflection_context", {
    description: "只对本次可信反射 EV 离线分析 HTML 位置；敏感上下文不是漏洞确认。",
    inputSchema: z.object({ evidence_id: z.string() }),
  }, async ({ evidence_id }) => response(await service.reflectionContext(evidence_id)));
  server.registerTool("authorized_xss_encoding_probe", {
    description: "在本次已证明反射的 EV 上，经人类批准发送一次非执行特殊字符编码观察；不确认 XSS。",
    inputSchema: z.object({ evidence_id: z.string() }),
  }, async ({ evidence_id }) => response(await service.encodingProbe(evidence_id,
    details => askApproval(`PhantomVeil 请求一次特殊字符编码观察：${details.endpoint}，参数 ${details.parameter_name}。` +
      "将发送一个仅含隔离标点字符的非执行 GET 并保存 EV，不执行脚本或确认 XSS。是否批准？"))));
  server.registerTool("authorized_xss_hypothesis_triage", {
    description: "离线核对同一参数的反射 EV 与编码 EV；仅在授权且人类批准时创建或复用 suspected HYP，不发送请求或确认 XSS。",
    inputSchema: z.object({ reflection_evidence_id: z.string(), encoding_evidence_id: z.string() }),
  }, async ({ reflection_evidence_id, encoding_evidence_id }) => response(
    await service.xssHypothesisTriage(reflection_evidence_id, encoding_evidence_id,
      details => askApproval(`PhantomVeil 检查到待复核 XSS 候选：${details.endpoint}，参数 ${details.parameter_name}。` +
        "是否批准将已验证 EV 关联到本次隔离任务的 suspected HYP？不会确认漏洞或发送请求。"))));
  server.registerTool("authorized_hypothesis_create", {
    description: "仅在本次目标有独立 hypothesis_create 授权且人类逐次批准时，记录 suspected HYP；不联网或确认漏洞。",
    inputSchema: z.object({ target_url: z.url(), title: z.string(),
      description: z.string(), reason: z.string() }),
  }, async input => response(await service.hypothesisCreate(input,
    details => askApproval(`PhantomVeil 请求记录待验证假设：${details.title}，目标 ${details.target}。` +
      "只写本次隔离任务的 suspected HYP，不验证或确认漏洞。是否批准？"))));
  server.registerTool("hypothesis_get", {
    description: "只读取本次隔离任务中的 HYP 历史记录；记录状态不等于重新验证。",
    inputSchema: z.object({ hypothesis_id: z.string() }),
  }, async ({ hypothesis_id }) => response(await service.hypothesisGet(hypothesis_id)));
  server.registerTool("authorized_reflected_xss_assessment", {
    description: "在本次显式授权的路径分支内一次批准后执行有界爬取、无害反射、非执行编码观察及 suspected HYP 关联；每次 GET 都经 PhantomVeil 门禁。",
    inputSchema: z.object({ url: z.url() }),
  }, async ({ url }) => response(await service.reflectedXssAssessment(url,
    details => askApproval(`PhantomVeil 请求完整低影响反射型 XSS 初步评估：${details.target}。` +
      `最多检查 ${details.max_parameters} 个安全 GET 参数，可能写入 suspected HYP。` +
      "整次任务最多 20 次 GET；不执行脚本或确认漏洞。是否批准？"))));
  server.registerTool("verify_hypothesis", {
    description: "对已记录的 suspected 假设运行主链路验证阶段：按漏洞类型自动选择验证器插件执行 verify/judge，并按状态机经 testing 回写 confirmed/rejected/inconclusive。metadata 为插件专属的验证输入（形状取决于插件）。需人工批准。",
    inputSchema: z.object({
      hypothesis_id: z.string().describe("要验证的 HYP 假设编号"),
      kind: z.string().describe("漏洞类型键，如 reflected_xss / open_redirect，用于路由到插件"),
      endpoint: z.url().optional(),
      parameter_name: z.string().optional(),
      metadata: z.record(z.string(), z.unknown()).optional().describe("插件专属验证输入"),
      evidence_ids: z.array(z.string()).optional(),
    }),
  }, async (input) => response(await service.verifyHypothesis(input, details => askApproval(
    `PhantomVeil 将对假设 ${details.hypothesis_id}（类型 ${details.kind}）运行验证器：` +
      "按候选类型自动选插件执行验证，并按状态机经 testing 回写到 confirmed/rejected/inconclusive。是否批准？"))));
  return server;
}

async function main() {
  const root = process.env.PVEIL_HERMES_WORKSPACE;
  const taskFile = process.env.PVEIL_HERMES_TASK_FILE;
  const budgetRoot = process.env.PVEIL_HERMES_BUDGET_DIR;
  const auditFile = process.env.PVEIL_HERMES_AUDIT_FILE;
  const sourceConfigRoot = process.env.PVEIL_HERMES_SOURCE_CONFIG_ROOT;
  if (!root || !taskFile || !budgetRoot || !auditFile) throw new Error("missing Hermes task environment");
  const task = JSON.parse(await readFile(taskFile, "utf8")) as HermesTaskGrant;
  const service = new HermesTaskService({ projectRoot: path.resolve(root), task, taskFile,
    sourceConfigRoot,
    budgetRoot, auditFile });
  await createHermesMcpServer(service).connect(new StdioServerTransport());
}

if (import.meta.filename === process.argv[1]) {
  main().catch(error => { process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1; });
}
