import { readFile } from "node:fs/promises";
import path from "node:path";

import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { createHermesMcpServer } from "../../src/adapters/hermes/mcp-server.ts";
import { HermesTaskService } from "../../src/adapters/hermes/task-service.ts";

const workspace = process.env.PVEIL_HERMES_WORKSPACE;
const taskFile = process.env.PVEIL_HERMES_TASK_FILE;
const budgetRoot = process.env.PVEIL_HERMES_BUDGET_DIR;
const auditFile = process.env.PVEIL_HERMES_AUDIT_FILE;
if (!workspace || !taskFile || !budgetRoot || !auditFile) throw new Error("missing evaluation task");
const task = JSON.parse(await readFile(taskFile, "utf8"));
const target = new URL(task.active?.seed_url ?? "invalid:");
const budget = JSON.parse(await readFile(path.join(workspace, "configs",
  "request-budget.local.json"), "utf8"));
if (!/^eval-[a-z0-9-]+$/u.test(task.task_id) || task.active?.kind !== "assessment" ||
    target.protocol !== "http:" || target.hostname !== "127.0.0.1" ||
    task.allowed_urls?.length !== 1 || task.allowed_urls[0] !== target.href ||
    budget.max_requests !== 4) {
  throw new Error("only the four-request loopback assessment fixture may use task preapproval");
}
const service = new HermesTaskService({ projectRoot: workspace, task, budgetRoot, auditFile });
await createHermesMcpServer(service, async () => true).connect(new StdioServerTransport());
