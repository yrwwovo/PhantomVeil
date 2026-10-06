import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { prepareHermesChat, prepareHermesNewTargetChat,
  resolveConfiguredHermesTarget } from "../scripts/hermes-chat.mjs";
import { createFixtureModel } from "../benchmarks/hermes-eval/fixture-model.mjs";

const target = "http://127.0.0.1:49152/";
const scopeFor = (port: number) => ({ allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1"],
  allowed_ports: [port], allowed_paths: ["/"], denied_paths: ["/blocked"] });

async function fixture(port = 49152, reflectionGrant = false, redirectGrant = false,
  encodingGrant = false, hypothesisGrant = false, assessmentGrant = false) {
  const root = await mkdtemp(path.join(tmpdir(), "pveil-hermes-chat-"));
  const sourceRoot = path.join(root, "source");
  const runsRoot = path.join(root, "runs");
  await mkdir(path.join(sourceRoot, "configs"), { recursive: true });
  await mkdir(path.join(sourceRoot, "benchmarks", "hermes-eval", "profiles"), { recursive: true });
  await mkdir(path.join(sourceRoot, "src", "adapters", "hermes"), { recursive: true });
  const write = (name: string, value: unknown) => writeFile(
    path.join(sourceRoot, "configs", name), JSON.stringify(value));
  await Promise.all([
    write("scope.local.json", scopeFor(port)),
    write("http.local.json", { allowed_resolved_ips: ["127.0.0.1"], timeout_ms: 3000,
      max_response_bytes: 16384, max_redirects: 1 }),
    write("authorization.local.json", { schema_version: 1, grants: [
      { reference: "LAB-OBSERVE", enabled: true,
        expires_at: "2099-01-01T00:00:00.000Z",
        actions: assessmentGrant ? ["web_observe", "parameter_reflection_check",
          "xss_encoding_probe", "hypothesis_create"] :
          encodingGrant ? ["web_observe", "parameter_reflection_check", "xss_encoding_probe",
          ...(hypothesisGrant ? ["hypothesis_create"] : [])] :
          reflectionGrant ? ["web_observe", "parameter_reflection_check"] :
          redirectGrant ? ["web_observe", "redirect_probe"] : ["web_observe"],
        scope: scopeFor(port) },
      { reference: "OTHER-GRANT", enabled: true,
        expires_at: "2099-01-01T00:00:00.000Z", actions: ["web_observe"], scope: scopeFor(port) },
    ] }),
    writeFile(path.join(sourceRoot, "benchmarks", "hermes-eval", "profiles", "learning-off.yaml"),
      await readFile(path.resolve(import.meta.dirname, "../benchmarks/hermes-eval/profiles/learning-off.yaml"), "utf8")),
    writeFile(path.join(sourceRoot, "src", "adapters", "hermes", "phantomveil-agent.md"),
      await readFile(path.resolve(import.meta.dirname, "../src/adapters/hermes/phantomveil-agent.md"), "utf8")),
  ]);
  return { root, sourceRoot, runsRoot };
}

test("Hermes default start binds one configured read-only target without prompting", async () => {
  const f = await fixture();
  try {
    const selected = await resolveConfiguredHermesTarget({ sourceRoot: f.sourceRoot,
      askUrl: async () => { throw new Error("unexpected target prompt"); } });
    assert.equal(selected.url, target);
    assert.equal(selected.reference, "LAB-OBSERVE");
    assert.equal(selected.autoSelected, true);
    const task = await prepareHermesChat({ ...f, url: selected.url,
      reference: selected.reference });
    const grant = JSON.parse(await readFile(path.join(task.runDir, "task.json"), "utf8"));
    assert.deepEqual(grant.allowed_urls, [target]);
    assert.equal(grant.authorization_reference, selected.reference);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test("Hermes default start asks for an exact URL when grants cover multiple targets", async () => {
  const f = await fixture();
  try {
    const registryFile = path.join(f.sourceRoot, "configs", "authorization.local.json");
    const registry = JSON.parse(await readFile(registryFile, "utf8"));
    registry.grants[1].scope.allowed_paths = ["/other"];
    await writeFile(registryFile, JSON.stringify(registry));
    let prompts = 0;
    const selected = await resolveConfiguredHermesTarget({ sourceRoot: f.sourceRoot,
      askUrl: async () => { prompts++; return target; } });
    assert.equal(prompts, 1);
    assert.equal(selected.reference, "LAB-OBSERVE");
    assert.equal(selected.autoSelected, false);
    await assert.rejects(resolveConfiguredHermesTarget({ sourceRoot: f.sourceRoot,
      askUrl: async () => `${target}blocked` }), /Scope/u);
    registry.grants[1].scope.allowed_paths = ["/"];
    registry.grants[1].scope.allowed_domains = ["example.test"];
    await writeFile(registryFile, JSON.stringify(registry));
    const broad = await resolveConfiguredHermesTarget({ sourceRoot: f.sourceRoot,
      askUrl: async () => { prompts++; return target; } });
    assert.equal(broad.autoSelected, false);
    assert.equal(prompts, 2);
    registry.grants.forEach((grant: { enabled: boolean }) => { grant.enabled = false; });
    await writeFile(registryFile, JSON.stringify(registry));
    await assert.rejects(resolveConfiguredHermesTarget({ sourceRoot: f.sourceRoot,
      askUrl: async () => target }), /没有有效的只读观察授权/u);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test("Hermes chat prepares one isolated, exact-target, single-request task", async () => {
  const f = await fixture();
  try {
    const task = await prepareHermesChat({ ...f, url: target, reference: "LAB-OBSERVE" });
    assert.ok(task.runDir.startsWith(f.runsRoot));
    const taskGrant = JSON.parse(await readFile(path.join(task.runDir, "task.json"), "utf8"));
    assert.deepEqual(taskGrant.allowed_urls, [target]);
    assert.equal(taskGrant.authorization_reference, "LAB-OBSERVE");
    const registry = JSON.parse(await readFile(path.join(task.workspace, "configs", "authorization.local.json"), "utf8"));
    assert.deepEqual(registry.grants.map((item: { reference: string }) => item.reference), ["LAB-OBSERVE"]);
    const budget = JSON.parse(await readFile(path.join(task.workspace, "configs", "request-budget.local.json"), "utf8"));
    assert.equal(budget.max_requests, 1);
    const config = await readFile(path.join(task.profile, "config.yaml"), "utf8");
    assert.match(config, /include: \[authorized_web_observe, evidence_entry_inventory, evidence_link_inventory, evidence_input_inventory, evidence_header_check, authorized_web_check\]/u);
    assert.match(config, /disabled_toolsets: \[web, browser, terminal/u);
    assert.match(config, /agent_name: "Phant0mV3il"/u);
    assert.match(config, /system_prompt: \|-/u);
    assert.match(config, /你是 Phant0mV3il/u);
    assert.match(await readFile(task.promptFile, "utf8"), /最多一次 HTTP 请求/u);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test("Hermes chat enables bounded crawl only for an explicit crawl task", async () => {
  const f = await fixture();
  try {
    const task = await prepareHermesChat({ ...f, url: target, reference: "LAB-OBSERVE",
      crawl: true });
    const grant = JSON.parse(await readFile(path.join(task.runDir, "task.json"), "utf8"));
    assert.deepEqual(grant.crawl, { seed_url: target, path_prefix: "/" });
    const budget = JSON.parse(await readFile(path.join(task.workspace, "configs",
      "request-budget.local.json"), "utf8"));
    assert.equal(budget.max_requests, 10);
    assert.match(await readFile(path.join(task.profile, "config.yaml"), "utf8"),
      /authorized_web_crawl/u);
    await assert.rejects(prepareHermesChat({ ...f, url: `${target}?q=x`,
      reference: "LAB-OBSERVE", crawl: true }), /查询参数/u);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test("Hermes can register a fresh isolated target after task-level confirmation", async () => {
  const f = await fixture();
  let approvals = 0;
  let resolutions = 0;
  try {
    const task = await prepareHermesNewTargetChat({ sourceRoot: f.sourceRoot,
      runsRoot: f.runsRoot, url: target, approve: async details => {
        approvals++;
        assert.equal(details.target, target);
      }, resolveIps: async () => { resolutions++; return ["127.0.0.1"]; } });
    assert.equal(approvals, 1);
    assert.equal(resolutions, 1);
    const grant = JSON.parse(await readFile(path.join(task.runDir, "task.json"), "utf8"));
    assert.match(grant.authorization_reference, /^TASK-/u);
    assert.deepEqual(grant.allowed_urls, [target]);
    const registry = JSON.parse(await readFile(path.join(task.workspace, "configs",
      "authorization.local.json"), "utf8"));
    assert.deepEqual(registry.grants.map((item: { reference: string }) => item.reference),
      [grant.authorization_reference]);
    assert.deepEqual((await readdir(f.runsRoot)), [task.taskId]);
    await assert.rejects(prepareHermesNewTargetChat({ sourceRoot: f.sourceRoot,
      runsRoot: f.runsRoot, url: target, approve: async () => { throw new Error("no"); },
      resolveIps: async () => { resolutions++; return ["127.0.0.1"]; } }), /APPROVAL_DENIED/u);
    assert.equal(resolutions, 1);
    await assert.rejects(prepareHermesNewTargetChat({ sourceRoot: f.sourceRoot,
      runsRoot: f.runsRoot, url: target, assessment: true,
      approve: async () => { approvals++; },
      resolveIps: async () => { resolutions++; return ["127.0.0.1"]; } }), /只读任务/u);
    assert.equal(approvals, 1);
    assert.equal(resolutions, 1);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test("Hermes reflection profile requires the distinct action grant before launch", async () => {
  const denied = await fixture();
  const allowed = await fixture(49152, true);
  try {
    await assert.rejects(prepareHermesChat({ ...denied, url: target,
      reference: "LAB-OBSERVE", reflection: true }), /ACTION_NOT_ALLOWED/u);
    const task = await prepareHermesChat({ ...allowed, url: target,
      reference: "LAB-OBSERVE", reflection: true });
    const grant = JSON.parse(await readFile(path.join(task.runDir, "task.json"), "utf8"));
    assert.deepEqual(grant.active, { kind: "reflection", seed_url: target, path_prefix: "/" });
    assert.equal(JSON.parse(await readFile(path.join(task.workspace, "configs",
      "request-budget.local.json"), "utf8")).max_requests, 2);
    const config = await readFile(path.join(task.profile, "config.yaml"), "utf8");
    assert.match(config, /authorized_parameter_reflection_check/u);
    assert.match(config, /elicitation:\n      enabled: true/u);
  } finally { await Promise.all([rm(denied.root, { recursive: true, force: true }),
    rm(allowed.root, { recursive: true, force: true })]); }
});

test("Hermes redirect profile has its own action grant and three-request cap", async () => {
  const f = await fixture(49152, false, true);
  try {
    const task = await prepareHermesChat({ ...f, url: target,
      reference: "LAB-OBSERVE", redirect: true });
    const grant = JSON.parse(await readFile(path.join(task.runDir, "task.json"), "utf8"));
    assert.deepEqual(grant.active, { kind: "redirect", seed_url: target, path_prefix: "/" });
    assert.equal(JSON.parse(await readFile(path.join(task.workspace, "configs",
      "request-budget.local.json"), "utf8")).max_requests, 3);
    const config = await readFile(path.join(task.profile, "config.yaml"), "utf8");
    const include = config.match(/^      include: \[([^\]]+)\]$/mu)?.[1] ?? "";
    assert.ok(include.includes("authorized_redirect_probe"));
    assert.equal(include.includes("authorized_parameter_reflection_check"), false);
    await assert.rejects(prepareHermesChat({ ...f, url: "https://example.test/",
      reference: "LAB-OBSERVE", redirect: true }), /本机靶场/u);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test("Hermes encoding profile requires both active grants and exposes only bounded tools", async () => {
  const partial = await fixture(49152, true);
  const complete = await fixture(49152, false, false, true);
  try {
    await assert.rejects(prepareHermesChat({ ...partial, url: target,
      reference: "LAB-OBSERVE", encoding: true }), /ACTION_NOT_ALLOWED/u);
    const task = await prepareHermesChat({ ...complete, url: target,
      reference: "LAB-OBSERVE", encoding: true });
    const grant = JSON.parse(await readFile(path.join(task.runDir, "task.json"), "utf8"));
    assert.deepEqual(grant.active, { kind: "encoding", seed_url: target, path_prefix: "/" });
    assert.equal(JSON.parse(await readFile(path.join(task.workspace, "configs",
      "request-budget.local.json"), "utf8")).max_requests, 3);
    const config = await readFile(path.join(task.profile, "config.yaml"), "utf8");
    const include = config.match(/^      include: \[([^\]]+)\]$/mu)?.[1] ?? "";
    assert.ok(include.includes("authorized_parameter_reflection_check"));
    assert.ok(include.includes("evidence_reflection_context"));
    assert.ok(include.includes("authorized_xss_encoding_probe"));
    assert.equal(include.includes("authorized_redirect_probe"), false);
    assert.equal(include.includes("authorized_xss_hypothesis_triage"), false);
    assert.match(await readFile(task.promptFile, "utf8"), /最多三次 HTTP 请求/u);
    const withHypothesis = await fixture(49152, false, false, true, true);
    try {
      const hypothesisTask = await prepareHermesChat({ ...withHypothesis, url: target,
        reference: "LAB-OBSERVE", encoding: true });
      assert.match(await readFile(path.join(hypothesisTask.profile, "config.yaml"), "utf8"),
        /authorized_xss_hypothesis_triage/u);
    } finally { await rm(withHypothesis.root, { recursive: true, force: true }); }
  } finally { await Promise.all([rm(partial.root, { recursive: true, force: true }),
    rm(complete.root, { recursive: true, force: true })]); }
});

test("Hermes complete assessment profile requires all actions and exposes one bounded workflow", async () => {
  const partial = await fixture(49152, false, false, true, false);
  const complete = await fixture(49152, false, false, false, false, true);
  try {
    await assert.rejects(prepareHermesChat({ ...partial, url: target,
      reference: "LAB-OBSERVE", assessment: true }), /hypothesis_create/u);
    const task = await prepareHermesChat({ ...complete, url: target,
      reference: "LAB-OBSERVE", assessment: true });
    const grant = JSON.parse(await readFile(path.join(task.runDir, "task.json"), "utf8"));
    assert.deepEqual(grant.active, { kind: "assessment", seed_url: target, path_prefix: "/" });
    assert.equal(JSON.parse(await readFile(path.join(task.workspace, "configs",
      "request-budget.local.json"), "utf8")).max_requests, 20);
    const config = await readFile(path.join(task.profile, "config.yaml"), "utf8");
    assert.match(config, /include: \[authorized_reflected_xss_assessment, hypothesis_get\]/u);
    assert.equal(config.includes("include: [authorized_web_observe"), false);
    assert.match(await readFile(task.promptFile, "utf8"), /最多 20 次 GET/u);
  } finally { await Promise.all([rm(partial.root, { recursive: true, force: true }),
    rm(complete.root, { recursive: true, force: true })]); }
});

test("Hermes CLI runs the prepared chat task through restricted MCP", { skip: !process.env.HERMES_BIN,
  timeout: 90_000 }, async () => {
  const hits: string[] = [];
  const site = createServer((request, response) => {
    hits.push(request.url ?? "");
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end('<a href="/next">下一页</a>');
  });
  const modelCalls: unknown[] = [];
  const model = createFixtureModel(item => modelCalls.push(item));
  const listen = (server: typeof site) => new Promise<number>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve((server.address() as { port: number }).port));
  });
  const sitePort = await listen(site);
  const modelPort = await listen(model);
  const f = await fixture(sitePort);
  try {
    const url = `http://127.0.0.1:${sitePort}/`;
    const task = await prepareHermesChat({ ...f, url, reference: "LAB-OBSERVE" });
    const configFile = path.join(task.profile, "config.yaml");
    const config = await readFile(configFile, "utf8");
    const realServer = path.resolve(import.meta.dirname, "../src/adapters/hermes/mcp-server.ts").replaceAll("\\", "/");
    const syntheticServer = path.join(f.sourceRoot, "src/adapters/hermes/mcp-server.ts").replaceAll("\\", "/");
    await writeFile(configFile, `model:\n  default: fixture-model\n  provider: custom\n` +
      `  base_url: "http://127.0.0.1:${modelPort}/v1"\n  api_key: fixture-only\n` +
      config.replace(syntheticServer, realServer));
    const configCheck = spawn(process.env.HERMES_BIN!, ["config", "get", "agent.system_prompt"], {
      cwd: task.workspace, env: { ...process.env, HERMES_HOME: task.profile },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const configOutput: Buffer[] = [];
    configCheck.stdout.on("data", data => configOutput.push(data));
    configCheck.stderr.on("data", data => configOutput.push(data));
    const configExit = await new Promise<number>((resolve, reject) => {
      configCheck.once("error", reject);
      configCheck.once("exit", code => resolve(code ?? 1));
    });
    assert.equal(configExit, 0);
    assert.match(Buffer.concat(configOutput).toString("utf8"), /你是 Phant0mV3il/u);
    const child = spawn(process.env.HERMES_BIN!, ["chat", "--oneshot", "--query-file", task.promptFile,
      "--quiet", "--toolsets", "phantomveil-hermes", "--max-turns", "4",
      "--model", "fixture-model", "--provider", "custom", "--ignore-rules"], {
      cwd: task.workspace, env: { ...process.env, HERMES_HOME: task.profile,
        PYTHONUTF8: "1", PYTHONIOENCODING: "utf-8" }, stdio: ["ignore", "pipe", "pipe"],
    });
    const output: Buffer[] = [];
    child.stdout.on("data", data => output.push(data));
    child.stderr.on("data", data => output.push(data));
    const exit = await new Promise<number>((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", code => resolve(code ?? 1));
    });
    assert.equal(exit, 0, Buffer.concat(output).toString("utf8").slice(-1000));
    assert.deepEqual(hits, ["/"], JSON.stringify({ output: Buffer.concat(output).toString("utf8").slice(-2000),
      modelCalls }));
    assert.equal((await readdir(path.join(task.workspace, "evidence", "hermes"))).length, 1);
    const audit = await readFile(path.join(task.runDir, "request-decisions.jsonl"), "utf8");
    assert.match(audit, /"code":"REQUEST_RESERVED"/u);
    assert.match(audit, /"code":"INVENTORY_COMPLETED"/u);
  } finally {
    await new Promise<void>(resolve => site.close(() => resolve()));
    await new Promise<void>(resolve => model.close(() => resolve()));
    await rm(f.root, { recursive: true, force: true });
  }
});

test("Hermes MCP reflection request fails closed without a human approval surface", {
  skip: !process.env.HERMES_BIN, timeout: 90_000 }, async () => {
  const hits: string[] = [];
  const site = createServer((request, response) => {
    hits.push(request.url ?? "");
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end('<form method="get" action="/search"><input name="q"></form>');
  });
  const modelCalls: Array<{ tool_names: string[] }> = [];
  const model = createFixtureModel(item => modelCalls.push(item), { reflection: true });
  const listen = (server: typeof site) => new Promise<number>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve((server.address() as { port: number }).port));
  });
  const sitePort = await listen(site);
  const modelPort = await listen(model);
  const f = await fixture(sitePort, true);
  try {
    const task = await prepareHermesChat({ ...f, url: `http://127.0.0.1:${sitePort}/`,
      reference: "LAB-OBSERVE", reflection: true });
    const configFile = path.join(task.profile, "config.yaml");
    const config = await readFile(configFile, "utf8");
    const actualMcp = path.resolve(import.meta.dirname, "../src/adapters/hermes/mcp-server.ts")
      .replaceAll("\\", "/");
    const syntheticMcp = path.join(f.sourceRoot, "src/adapters/hermes/mcp-server.ts")
      .replaceAll("\\", "/");
    await writeFile(configFile, `model:\n  default: fixture-model\n  provider: custom\n` +
      `  base_url: "http://127.0.0.1:${modelPort}/v1"\n  api_key: fixture-only\n` +
      config.replace(syntheticMcp, actualMcp));
    const child = spawn(process.env.HERMES_BIN!, ["chat", "--oneshot", "--query-file", task.promptFile,
      "--quiet", "--toolsets", "phantomveil-hermes", "--max-turns", "4",
      "--model", "fixture-model", "--provider", "custom", "--ignore-rules"], {
      cwd: task.workspace, env: { ...process.env, HERMES_HOME: task.profile,
        PYTHONUTF8: "1", PYTHONIOENCODING: "utf-8" }, stdio: ["ignore", "pipe", "pipe"],
    });
    const output: Buffer[] = [];
    child.stdout.on("data", data => output.push(data));
    child.stderr.on("data", data => output.push(data));
    await new Promise<void>((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", () => resolve());
    });
    assert.ok(modelCalls.some(call => call.tool_names.some(name =>
      name.endsWith("authorized_parameter_reflection_check"))),
    Buffer.concat(output).toString("utf8").slice(-1000));
    assert.deepEqual(hits, ["/"]);
    const audit = await readFile(path.join(task.runDir, "request-decisions.jsonl"), "utf8");
    assert.match(audit, /"tool":"authorized_parameter_reflection_check".*"approved":false/u);
  } finally {
    await new Promise<void>(resolve => site.close(() => resolve()));
    await new Promise<void>(resolve => model.close(() => resolve()));
    await rm(f.root, { recursive: true, force: true });
  }
});

test("Hermes MCP complete assessment refuses a missing approval surface before GET", {
  skip: !process.env.HERMES_BIN, timeout: 90_000 }, async () => {
  const hits: string[] = [];
  const site = createServer((request, response) => {
    hits.push(request.url ?? "");
    response.writeHead(200, { "content-type": "text/html" });
    response.end('<form method="get" action="/search"><input name="q"></form>');
  });
  const modelCalls: Array<{ tool_names: string[] }> = [];
  const model = createFixtureModel(item => modelCalls.push(item), { assessment: true });
  const listen = (server: typeof site) => new Promise<number>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve((server.address() as { port: number }).port));
  });
  const sitePort = await listen(site);
  const modelPort = await listen(model);
  const f = await fixture(sitePort, false, false, false, false, true);
  try {
    const task = await prepareHermesChat({ ...f, url: `http://127.0.0.1:${sitePort}/`,
      reference: "LAB-OBSERVE", assessment: true });
    const configFile = path.join(task.profile, "config.yaml");
    const config = await readFile(configFile, "utf8");
    const actualMcp = path.resolve(import.meta.dirname, "../src/adapters/hermes/mcp-server.ts")
      .replaceAll("\\", "/");
    const syntheticMcp = path.join(f.sourceRoot, "src/adapters/hermes/mcp-server.ts")
      .replaceAll("\\", "/");
    await writeFile(configFile, `model:\n  default: fixture-model\n  provider: custom\n` +
      `  base_url: "http://127.0.0.1:${modelPort}/v1"\n  api_key: fixture-only\n` +
      config.replace(syntheticMcp, actualMcp));
    const child = spawn(process.env.HERMES_BIN!, ["chat", "--oneshot", "--query-file", task.promptFile,
      "--quiet", "--toolsets", "phantomveil-hermes", "--max-turns", "4",
      "--model", "fixture-model", "--provider", "custom", "--ignore-rules"], {
      cwd: task.workspace, env: { ...process.env, HERMES_HOME: task.profile,
        PYTHONUTF8: "1", PYTHONIOENCODING: "utf-8" }, stdio: ["ignore", "pipe", "pipe"],
    });
    const output: Buffer[] = [];
    child.stdout.on("data", data => output.push(data));
    child.stderr.on("data", data => output.push(data));
    await new Promise<void>((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", () => resolve());
    });
    assert.ok(modelCalls.some(call => call.tool_names.some(name =>
      name.endsWith("authorized_reflected_xss_assessment"))),
    Buffer.concat(output).toString("utf8").slice(-1000));
    assert.deepEqual(hits, []);
    const audit = await readFile(path.join(task.runDir, "request-decisions.jsonl"), "utf8");
    assert.match(audit, /"tool":"authorized_reflected_xss_assessment".*"approved":false/u);
  } finally {
    await new Promise<void>(resolve => site.close(() => resolve()));
    await new Promise<void>(resolve => model.close(() => resolve()));
    await rm(f.root, { recursive: true, force: true });
  }
});

test("Hermes chat refuses missing action and scope before creating a run", async () => {
  const f = await fixture();
  try {
    await assert.rejects(prepareHermesChat({ ...f, url: target,
      reference: "MISSING-REF" }), /REFERENCE_NOT_FOUND/u);
    await assert.rejects(prepareHermesChat({ ...f,
      url: "http://127.0.0.1:49152/blocked", reference: "LAB-OBSERVE" }), /Scope/u);
    await assert.rejects(prepareHermesChat({ ...f,
      url: "http://127.0.0.1:49153/", reference: "LAB-OBSERVE" }), /Scope/u);
    assert.deepEqual(await readdir(f.root), ["source"]);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});
