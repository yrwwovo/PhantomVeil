import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { InMemoryTransport } from "@modelcontextprotocol/server";

import { prepareHermesAwaitTargetChat } from "../scripts/hermes-chat.mjs";
import { createHermesMcpServer } from "../src/adapters/hermes/mcp-server.ts";
import { HermesTaskService } from "../src/adapters/hermes/task-service.ts";

test("未绑定 Hermes 会话须确认目标，绑定后只允许一次精确目标观察", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "pveil-hermes-bind-"));
  const hits: string[] = [];
  const site = createServer((request, response) => {
    hits.push(request.url ?? "");
    response.writeHead(200, { "content-type": "text/html" });
    response.end("<p>local fixture</p>");
  });
  await new Promise<void>(resolve => site.listen(0, "127.0.0.1", resolve));
  const port = (site.address() as { port: number }).port;
  const url = `http://127.0.0.1:${port}/`;
  try {
    const sourceConfigRoot = path.join(root, "source-config");
    await mkdir(path.join(sourceConfigRoot, "configs"), { recursive: true });
    await writeFile(path.join(sourceConfigRoot, "configs", "scope.local.json"), JSON.stringify({
      allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1"], allowed_ports: [port],
      allowed_paths: ["/"], denied_paths: ["/blocked"],
    }));
    const task = await prepareHermesAwaitTargetChat({ runsRoot: root });
    const profile = await readFile(path.join(task.profile, "config.yaml"), "utf8");
    assert.match(profile, /include: \[authorized_target_bind, authorized_web_observe, evidence_entry_inventory, authorized_task_authorize, authorized_web_crawl, evidence_input_inventory\]/u);
    assert.match(profile, /disabled_toolsets: \[web, browser, terminal/u);
    assert.equal("promptFile" in task, false);
    assert.equal((await readdir(task.runDir)).includes("start-prompt.txt"), false);
    assert.match(profile, /初始化时等待用户输入/u);
    assert.match(profile, /未绑定或未经确认时不得请求目标/u);
    const taskFile = path.join(task.runDir, "task.json");
    const pending = JSON.parse(await readFile(taskFile, "utf8"));
    assert.deepEqual(pending.allowed_urls, []);
    const service = new HermesTaskService({ projectRoot: task.workspace, task: pending,
      taskFile, sourceConfigRoot, budgetRoot: path.join(task.runDir, "budget"),
      auditFile: path.join(task.runDir, "request-decisions.jsonl") });

    assert.equal((await service.observe(url)).code, "AUTHORIZATION_DENIED");
    let approvals = 0;
    assert.equal((await service.bindTarget(url, async () => { approvals++; return false; })).code,
      "APPROVAL_DENIED");
    assert.equal(approvals, 1);
    assert.deepEqual(hits, []);
    assert.equal((await service.bindTarget(`${url}?secret=x`, async () => {
      approvals++; return true;
    })).code, "INVALID_INPUT");
    assert.equal(approvals, 1);
    assert.equal((await service.bindTarget(`${url}blocked`, async () => {
      approvals++; return true;
    })).code, "SOURCE_SCOPE_DENIED");
    assert.equal(approvals, 1);

    const bound = await service.bindTarget(url, async details => {
      approvals++;
      assert.equal(details.target, url);
      assert.equal(details.allowed_path, "/");
      return true;
    });
    assert.equal(bound.code, "TARGET_BOUND");
    assert.equal(approvals, 2);
    assert.deepEqual(hits, []);
    const persisted = JSON.parse(await readFile(taskFile, "utf8"));
    assert.deepEqual(persisted.allowed_urls, [url]);
    const registry = JSON.parse(await readFile(path.join(task.workspace, "configs",
      "authorization.local.json"), "utf8"));
    assert.deepEqual(registry.grants[0].actions, ["web_observe"]);
    assert.equal((await service.bindTarget(`${url}other`, async () => true)).code,
      "TARGET_ALREADY_BOUND");
    assert.equal((await service.observe(`${url}other`)).code, "AUTHORIZATION_DENIED");
    assert.deepEqual(hits, []);
    assert.equal((await service.observe(url)).ok, true);
    assert.deepEqual(hits, ["/"]);
    assert.equal((await service.observe(url)).ok, false);
    const resumed = new HermesTaskService({ projectRoot: task.workspace,
      task: JSON.parse(await readFile(taskFile, "utf8")), taskFile, sourceConfigRoot,
      budgetRoot: path.join(task.runDir, "budget"),
      auditFile: path.join(task.runDir, "request-decisions.jsonl") });
    assert.equal((await resumed.observe(url)).ok, false);
    assert.deepEqual(hits, ["/"]);
  } finally {
    await new Promise<void>(resolve => site.close(() => resolve()));
    await rm(root, { recursive: true, force: true });
  }
});

test("Hermes MCP exposes one confirmed in-chat target bind tool", { timeout: 10_000 }, async () => {
  const root = await mkdtemp(path.join(tmpdir(), "pveil-hermes-bind-mcp-"));
  try {
    const task = await prepareHermesAwaitTargetChat({ runsRoot: root });
    const taskFile = path.join(task.runDir, "task.json");
    const service = new HermesTaskService({ projectRoot: task.workspace,
      task: JSON.parse(await readFile(taskFile, "utf8")), taskFile,
      budgetRoot: path.join(task.runDir, "budget"),
      auditFile: path.join(task.runDir, "request-decisions.jsonl") });
    const server = createHermesMcpServer(service, async () => true);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    let nextId = 0;
    const pending = new Map<number, (reply: any) => void>();
    clientTransport.onmessage = message => {
      if ("id" in message && typeof message.id === "number") {
        pending.get(message.id)?.(message);
        pending.delete(message.id);
      }
    };
    await server.connect(serverTransport);
    await clientTransport.start();
    const request = (method: string, params: Record<string, unknown>) => {
      const id = ++nextId;
      return new Promise<any>((resolve, reject) => {
        pending.set(id, resolve);
        clientTransport.send({ jsonrpc: "2.0", id, method, params }).catch(reject);
      });
    };
    try {
      const initialized = await request("initialize", { protocolVersion: "2025-06-18",
        capabilities: {}, clientInfo: { name: "local-bind-test", version: "1" } });
      assert.equal(initialized.error, undefined);
      await clientTransport.send({ jsonrpc: "2.0", method: "notifications/initialized" });
      const listed = await request("tools/list", {});
      for (const name of ["authorized_target_bind", "authorized_task_authorize", "authorized_web_crawl", "evidence_input_inventory"])
        assert.ok(listed.result.tools.some((tool: { name: string }) => tool.name === name));
      const premature = await request("tools/call", { name: "authorized_task_authorize", arguments: {} });
      assert.match(JSON.stringify(premature.result), /TASK_MODE_DENIED/u);
      const bound = await request("tools/call", { name: "authorized_target_bind",
        arguments: { url: "http://127.0.0.1:49152/" } });
      assert.equal(bound.error, undefined);
      assert.match(JSON.stringify(bound.result), /TARGET_BOUND/u);
      const second = await request("tools/call", { name: "authorized_target_bind",
        arguments: { url: "http://127.0.0.1:49153/" } });
      assert.match(JSON.stringify(second.result), /TARGET_ALREADY_BOUND/u);
    } finally {
      await clientTransport.close();
      await server.close();
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("Hermes CLI accepts the unbound restricted profile", {
  skip: !process.env.HERMES_BIN, timeout: 30_000,
}, async () => {
  const root = await mkdtemp(path.join(tmpdir(), "pveil-hermes-bind-config-"));
  try {
    const task = await prepareHermesAwaitTargetChat({ runsRoot: root });
    const child = spawn(process.env.HERMES_BIN!, ["config", "get", "agent.system_prompt"], {
      cwd: task.workspace, env: { ...process.env, HERMES_HOME: task.profile },
      stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
    });
    let output = "";
    child.stdout.on("data", chunk => { output += chunk.toString("utf8"); });
    child.stderr.on("data", chunk => { output += chunk.toString("utf8"); });
    const exitCode = await new Promise<number>((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", code => resolve(code ?? 1));
    });
    assert.equal(exitCode, 0, output.slice(-500));
    assert.match(output, /authorized_target_bind/u);
    const list = spawn(process.env.HERMES_BIN!, ["tools", "list"], {
      cwd: task.workspace, env: { ...process.env, HERMES_HOME: task.profile },
      stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
    });
    let listed = "";
    list.stdout.on("data", chunk => { listed += chunk.toString("utf8"); });
    list.stderr.on("data", chunk => { listed += chunk.toString("utf8"); });
    const listExit = await new Promise<number>((resolve, reject) => {
      list.once("error", reject);
      list.once("exit", code => resolve(code ?? 1));
    });
    assert.equal(listExit, 0, listed.slice(-500));
    assert.match(listed, /authorized_target_bind/u);
  } finally { await rm(root, { recursive: true, force: true }); }
});


test("绑定后单独确认爬取，限制路径/页数并从本任务 EV 只清点参数名", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "pveil-crawl-wire-"));
  const hits: string[] = [];
  const site = createServer((req, res) => {
    hits.push(req.url!);
    res.writeHead(200, { "content-type": "text/html" });
    res.end('<a href="/app/child">child</a><a href="/app/third">third</a>' +
      '<a href="/outside">outside</a><a href="/app/blocked">blocked</a>' +
      '<a href="/app/search?q=PRIVATE_VALUE&page=PRIVATE_PAGE">query</a>');
  });
  await new Promise<void>(resolve => site.listen(0, "127.0.0.1", resolve));
  const port = (site.address() as { port: number }).port;
  const url = `http://127.0.0.1:${port}/app/`;
  try {
    const task = await prepareHermesAwaitTargetChat({ runsRoot: root });
    const taskFile = path.join(task.runDir, "task.json");
    const sourceConfigRoot = path.join(root, "source");
    await mkdir(path.join(sourceConfigRoot, "configs"), { recursive: true });
    await writeFile(path.join(sourceConfigRoot, "configs", "scope.local.json"), JSON.stringify({
      allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1"], allowed_ports: [port],
      allowed_paths: ["/app/"], denied_paths: ["/app/blocked"] }));
    const service = new HermesTaskService({ projectRoot: task.workspace,
      task: JSON.parse(await readFile(taskFile, "utf8")), taskFile, sourceConfigRoot,
      budgetRoot: path.join(task.runDir, "budget"), auditFile: path.join(task.runDir, "audit.jsonl") });
    const limits = { max_pages: 2, max_requests: 3 };
    assert.equal((await service.authorizeTask(limits, async () => true)).code, "TASK_MODE_DENIED");
    assert.equal((await service.bindTarget(url, async () => true)).ok, true);
    assert.equal((await service.crawl(url)).code, "TASK_MODE_DENIED");
    assert.equal((await service.authorizeTask(limits, async () => false)).code, "APPROVAL_DENIED");
    assert.deepEqual(hits, []);
    const observed = await service.observe(url);
    assert.equal(observed.ok, true);
    assert.equal((await service.authorizeTask(limits, async details => {
      assert.equal(details.path_prefix, "/app/"); return true;
    })).ok, true);
    assert.equal(hits.length, 1);
    const result = await service.crawl(url);
    assert.equal(result.ok, true);
    if (!("pages" in result)) throw new Error("missing pages");
    assert.equal(result.pages.length, 2);
    assert.deepEqual(hits, ["/app/", "/app/", "/app/child"]);
    const ev = result.pages[0].evidence_id!;
    const inventory = await service.inputInventory(ev);
    assert.equal(inventory.ok, true);
    assert.match(JSON.stringify(inventory), /parameter_names.*q.*page/u);
    assert.match(JSON.stringify(inventory), new RegExp(ev));
    assert.doesNotMatch(JSON.stringify(inventory), /PRIVATE_VALUE|PRIVATE_PAGE/u);
    if (observed.ok) assert.equal((await service.inputInventory(observed.evidence_id)).code, "EVIDENCE_NOT_IN_TASK");
    assert.equal((await service.inputInventory("EV-20260101000000-12345678")).ok, false);
    assert.equal(hits.length, 3);
    assert.equal((await service.authorizeTask(limits, async () => true)).code, "TASK_MODE_DENIED");
    await service.crawl(url);
    assert.equal(hits.length, 3, "used observation and crawl requests must not reset");
    assert.equal(hits.some(hit => hit.includes("?") || hit.includes("blocked") || hit.includes("outside")), false);
  } finally {
    await new Promise<void>(resolve => site.close(() => resolve()));
    await rm(root, { recursive: true, force: true });
  }
});


test("新爬取接线逐跳拒绝禁止路径与分支外目标，授权事务未完成时拒绝请求", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "pveil-crawl-boundary-"));
  const hits: string[] = [];
  const site = createServer((req, res) => {
    hits.push(req.url!);
    if (req.url === "/app/go") { res.writeHead(302, { location: "/outside" }); res.end(); return; }
    res.writeHead(200, { "content-type": "text/html" });
    res.end('<a href="/app/blocked">blocked</a><a href="/outside">outside</a><a href="/app/go">go</a>');
  });
  await new Promise<void>(resolve => site.listen(0, "127.0.0.1", resolve));
  const port = (site.address() as { port: number }).port;
  const url = `http://127.0.0.1:${port}/app/`;
  try {
    const task = await prepareHermesAwaitTargetChat({ runsRoot: root });
    const taskFile = path.join(task.runDir, "task.json");
    const sourceConfigRoot = path.join(root, "source");
    await mkdir(path.join(sourceConfigRoot, "configs"), { recursive: true });
    await writeFile(path.join(sourceConfigRoot, "configs", "scope.local.json"), JSON.stringify({
      allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1"], allowed_ports: [port],
      allowed_paths: ["/"], denied_paths: ["/app/blocked"] }));
    const options = { projectRoot: task.workspace, taskFile, sourceConfigRoot,
      budgetRoot: path.join(task.runDir, "budget"), auditFile: path.join(task.runDir, "audit.jsonl") };
    const service = new HermesTaskService({ ...options, task: JSON.parse(await readFile(taskFile, "utf8")) });
    assert.equal((await service.bindTarget(url, async () => true)).ok, true);
    await writeFile(`${taskFile}.crawl-pending`, "pending");
    assert.equal((await service.observe(url)).ok, false);
    const resumed = new HermesTaskService({ ...options, task: JSON.parse(await readFile(taskFile, "utf8")) });
    assert.equal((await resumed.observe(url)).ok, false);
    assert.deepEqual(hits, []);
    assert.equal((await service.authorizeTask({ max_pages: 5, max_requests: 5 }, async () => true)).ok, true);
    await service.crawl(url);
    assert.deepEqual(hits, ["/app/", "/app/go"]);
  } finally {
    await new Promise<void>(resolve => site.close(() => resolve()));
    await rm(root, { recursive: true, force: true });
  }
});
