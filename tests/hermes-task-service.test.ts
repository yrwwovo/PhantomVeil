import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { createServer, type Server } from "node:http";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";

import { HermesTaskService } from "../src/adapters/hermes/task-service.ts";
import { normalizeHermesEvents } from "../src/adapters/hermes/run-events.ts";
import { normalizeOpenCodeMcpEvents } from "../src/adapters/opencode/run-events.ts";
import { scoreHermesObservationChain } from "../src/evaluation/hermes-observation-score.ts";
import { scoreHermesAssessment } from "../src/evaluation/hermes-assessment-score.ts";

const body = '<!doctype html><a href="/search">检索</a><form method="get" action="/search"><input name="q"></form>' +
  '<form method="get" action="/jump"><input name="next"></form>';
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
let server: Server;
let port: number;
const hits: Array<{ method: string; target: string; status: number; body: string }> = [];
before(async () => {
  server = createServer((req, res) => {
    const status = req.url === "/redirect" || req.url?.startsWith("/jump?next=") ? 302 : 200;
    const output = status === 302 ? "" : req.url?.startsWith("/search?q=")
      ? `<!doctype html><p>${new URL(req.url, "http://127.0.0.1").searchParams.get("q") ?? ""}</p>` : body;
    hits.push({ method: req.method ?? "", target: req.url ?? "", status, body: output });
    const destination = req.url?.startsWith("/jump?next=")
      ? new URL(req.url, "http://127.0.0.1").searchParams.get("next") ?? "/blocked" : "/blocked";
    res.writeHead(status, status === 302 ? { location: destination } : { "content-type": "text/html" });
    res.end(output);
  });
  port = await new Promise<number>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve((server.address() as { port: number }).port));
  });
});
after(() => new Promise<void>(resolve => server.close(() => resolve())));

async function fixture(options: { reference?: string; budget?: number; urls?: string[];
  crawl?: boolean; reflection?: boolean; redirect?: boolean; encoding?: boolean;
  hypothesis?: boolean; assessment?: boolean } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), "pveil-hermes-test-"));
  const url = `http://127.0.0.1:${port}/`;
  const scope = { allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1"],
    allowed_ports: [port], allowed_paths: ["/"], denied_paths: ["/blocked"] };
  await mkdir(path.join(root, "configs"));
  await writeFile(path.join(root, "configs", "scope.local.json"), JSON.stringify(scope));
  await writeFile(path.join(root, "configs", "http.local.json"), JSON.stringify({
    allowed_resolved_ips: ["127.0.0.1"], timeout_ms: 3000,
    max_response_bytes: 16384, max_redirects: 1 }));
  await writeFile(path.join(root, "configs", "request-budget.local.json"),
    JSON.stringify({ max_requests: options.budget ?? 1 }));
  if (options.assessment) await writeFile(path.join(root, "configs", "active-assessment.local.json"),
    JSON.stringify({ max_parameters: 1, delay_ms: 100 }));
  await writeFile(path.join(root, "configs", "authorization.local.json"), JSON.stringify({
    schema_version: 1, grants: [{ reference: "LOCAL-HERMES-OBSERVE", enabled: true,
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      actions: options.assessment ? ["web_observe", "parameter_reflection_check",
        "xss_encoding_probe", "hypothesis_create"] :
        options.encoding ? ["web_observe", "parameter_reflection_check", "xss_encoding_probe",
        ...(options.hypothesis ? ["hypothesis_create"] : [])] :
        options.reflection ? ["web_observe", "parameter_reflection_check"] :
        options.redirect ? ["web_observe", "redirect_probe"] :
          options.hypothesis ? ["web_observe", "hypothesis_create"] : ["web_observe"], scope }],
  }));
  const service = new HermesTaskService({ projectRoot: root, budgetRoot: path.join(root, "budget"),
    task: { task_id: `test-${randomUUID()}`, authorization_reference: options.reference ??
      "LOCAL-HERMES-OBSERVE", allowed_urls: options.urls ?? [url],
      ...(options.crawl ? { crawl: { seed_url: url, path_prefix: "/" } } : {}),
      ...(options.reflection ? { active: { kind: "reflection", seed_url: url, path_prefix: "/" } } : {}),
      ...(options.redirect ? { active: { kind: "redirect", seed_url: url, path_prefix: "/" } } : {}),
      ...(options.encoding ? { active: { kind: "encoding", seed_url: url, path_prefix: "/" } } : {}),
      ...(options.assessment ? { active: { kind: "assessment", seed_url: url, path_prefix: "/" } } : {}) },
    auditFile: path.join(root, "audit.jsonl") });
  return { root, url, service, cleanup: () => rm(root, { recursive: true, force: true }) };
}

test("Hermes 只读任务链保存 EV，离线清点入口，独立评分核对真实请求", async () => {
  const f = await fixture();
  const beforeCount = hits.length;
  try {
    const observed = await f.service.observe(f.url);
    assert.equal(observed.ok, true);
    if (!observed.ok) return;
    const inventory = await f.service.inventory(observed.evidence_id);
    assert.equal(inventory.ok, true);
    if (!inventory.ok) return;
    assert.equal(inventory.links.links.length, 1);
    assert.equal(inventory.inputs.forms[0].parameter_names[0], "q");
    assert.equal((await f.service.linkInventory(observed.evidence_id)).ok, true);
    assert.equal((await f.service.inputInventory(observed.evidence_id)).ok, true);
    assert.equal(hits.length, beforeCount + 1);
    assert.equal(hits.length, beforeCount + 1);
    const raw = await readFile(path.join(f.root, "audit.jsonl"), "utf8");
    const audit = raw.trim().split("\n").map(line => JSON.parse(line));
    const events = { tools: [
      { name: "authorized_web_observe", status: "completed", input: { url: f.url }, output: observed },
      { name: "evidence_entry_inventory", status: "completed",
        input: { evidence_id: observed.evidence_id }, output: inventory },
    ], final_text: `HTTP 200，证据 ${observed.evidence_id}。已离线清点入口。`,
    error: null, token_usage: { input: 1, output: 1 } };
    const score = await scoreHermesObservationChain({ id: "local", url: f.url, expected_status: 200 },
      f.root, events, hits.slice(beforeCount).map(hit => ({ received_at: "", method: hit.method,
        request_target: hit.target, response_status: hit.status, response_body_sha256: hash(hit.body) })), audit);
    assert.equal(score.passed, true, score.reason);
    const forged = structuredClone(events);
    forged.tools[1].output.evidence_id = "EV-20261002000000-deadbeef";
    const rejected = await scoreHermesObservationChain({ id: "local", url: f.url, expected_status: 200 },
      f.root, forged, hits.slice(beforeCount).map(hit => ({ received_at: "", method: hit.method,
        request_target: hit.target, response_status: hit.status, response_body_sha256: hash(hit.body) })), audit);
    assert.equal(rejected.passed, false);
    const evidencePath = path.join(f.root, "evidence", "hermes", `${observed.evidence_id}.json`);
    const altered = JSON.parse(await readFile(evidencePath, "utf8"));
    altered.observation.response.body += "forged";
    await writeFile(evidencePath, JSON.stringify(altered));
    const tampered = await scoreHermesObservationChain({ id: "local", url: f.url, expected_status: 200 },
      f.root, events, hits.slice(beforeCount).map(hit => ({ received_at: "", method: hit.method,
        request_target: hit.target, response_status: hit.status, response_body_sha256: hash(hit.body) })), audit);
    assert.equal(tampered.passed, false);
  } finally { await f.cleanup(); }
});

test("无效授权、任务外 URL、禁止路径在发送前拒绝", async () => {
  const target = `http://127.0.0.1:${port}/`;
  const forbidden = `${target}blocked`;
  const wrongPort = `http://127.0.0.1:${port === 65535 ? port - 1 : port + 1}/`;
  const invalid = await fixture({ reference: "LOCAL-NOT-FOUND" });
  const outside = await fixture({ urls: [target, wrongPort] });
  const denied = await fixture({ urls: [forbidden] });
  const beforeCount = hits.length;
  try {
    assert.equal((await invalid.service.observe(target)).ok, false);
    assert.equal((await outside.service.observe(`${target}other`)).ok, false);
    const outOfScope = await outside.service.observe(wrongPort);
    assert.equal(outOfScope.ok, false);
    assert.equal(outOfScope.authorization_code, "TARGET_NOT_ALLOWED");
    assert.equal((await denied.service.observe(forbidden)).ok, false);
    assert.equal(hits.length, beforeCount);
  } finally { await Promise.all([invalid.cleanup(), outside.cleanup(), denied.cleanup()]); }
});

test("Hermes 离线响应头检查不增请求，单页检查只用一次授权 GET", async () => {
  const f = await fixture();
  const beforeCount = hits.length;
  try {
    const checked = await f.service.webCheck(f.url);
    assert.equal(checked.ok, true);
    if (!checked.ok || !("trace" in checked)) return;
    assert.equal(checked.code, "WEB_CHECK_COMPLETED");
    assert.match(checked.user_summary, /单个 URL 的响应头检查/u);
    assert.equal(hits.length, beforeCount + 1);
    const offline = await f.service.headerCheck(checked.trace.evidence_id);
    assert.equal(offline.ok, true);
    assert.equal(hits.length, beforeCount + 1);
    assert.equal((await f.service.webCheck(f.url)).ok, false);
    assert.equal(hits.length, beforeCount + 1);
    assert.equal((await f.service.headerCheck("EV-20261002000000-deadbeef")).ok, false);
    const audit = await readFile(path.join(f.root, "audit.jsonl"), "utf8");
    assert.match(audit, /"tool":"authorized_web_check"/u);
    assert.match(audit, /"tool":"evidence_header_check"/u);
  } finally { await f.cleanup(); }
});

test("Hermes 显式有界爬取复用逐跳门禁，单页工具不能绕过任务模式", async () => {
  const f = await fixture({ crawl: true, budget: 3 });
  const beforeCount = hits.length;
  try {
    assert.equal((await f.service.observe(f.url)).code, "TASK_MODE_DENIED");
    assert.equal((await f.service.crawl(`${f.url}other`)).code, "TASK_MODE_DENIED");
    const crawl = await f.service.crawl(f.url);
    assert.equal(crawl.ok, true);
    if (!crawl.ok) return;
    assert.equal(crawl.checked, 2);
    assert.equal(crawl.requests, 2);
    assert.equal(hits.length, beforeCount + 2);
    assert.deepEqual(hits.slice(beforeCount).map(hit => hit.target), ["/", "/search"]);
    assert.ok(crawl.report_file.includes(path.join("reports", "hermes")));
    const discovered = crawl.pages.find(page => page.url === `${f.url}search`);
    assert.ok(discovered?.evidence_id);
    assert.equal((await f.service.headerCheck(discovered.evidence_id)).ok, true);
    assert.equal(hits.length, beforeCount + 2);
  } finally { await f.cleanup(); }
});

test("Hermes 参数反射检查需要独立动作授权与逐次批准，并共享两次请求预算", async () => {
  const f = await fixture({ reflection: true, budget: 2 });
  const beforeCount = hits.length;
  try {
    const observed = await f.service.observe(f.url);
    assert.equal(observed.ok, true);
    if (!observed.ok) return;
    const input = { evidence_id: observed.evidence_id, form_index: 1, parameter_name: "q" };
    const refused = await f.service.reflection(input, async details => {
      assert.equal(details.endpoint, `${f.url}search`);
      return false;
    });
    assert.equal(refused.code, "APPROVAL_DENIED");
    assert.equal(hits.length, beforeCount + 1);
    const approved = await f.service.reflection(input, async () => true);
    assert.equal(approved.ok, true);
    if (!approved.ok) return;
    assert.equal(approved.result.outcome, "reflected");
    assert.equal(hits.length, beforeCount + 2);
    assert.match(hits.at(-1)?.target ?? "", /^\/search\?q=PV-REFLECT-/u);
    assert.equal((await f.service.headerCheck(approved.trace.evidence_id)).ok, true);
    const exhausted = await f.service.reflection(input, async () => true);
    assert.equal(exhausted.ok, false);
    assert.equal(hits.length, beforeCount + 2);
    const audit = await readFile(path.join(f.root, "audit.jsonl"), "utf8");
    assert.match(audit, /"kind":"approval".*"approved":false/u);
    assert.match(audit, /"kind":"approval".*"approved":true/u);
  } finally { await f.cleanup(); }
});

test("Hermes 本机重定向观察审批后仅请求两次标记，不访问目的地", async () => {
  const f = await fixture({ redirect: true, budget: 3 });
  const beforeCount = hits.length;
  try {
    const observed = await f.service.observe(f.url);
    assert.equal(observed.ok, true);
    if (!observed.ok) return;
    const input = { evidence_id: observed.evidence_id, form_index: 2, parameter_name: "next" };
    assert.equal((await f.service.redirectProbe(input, async () => false)).code, "APPROVAL_DENIED");
    assert.equal(hits.length, beforeCount + 1);
    const result = await f.service.redirectProbe(input, async details => {
      assert.equal(details.endpoint, `${f.url}jump`);
      return true;
    });
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.result.outcome, "candidate");
    assert.equal(result.result.destination_contacted, false);
    assert.equal(hits.length, beforeCount + 3);
    assert.ok(hits.slice(beforeCount + 1).every(hit => hit.target.startsWith("/jump?next=")));
    assert.ok(!hits.some(hit => hit.target.includes("phantomveil-probe.invalid/")));
    const report = await readFile(result.trace.report_file, "utf8");
    assert.equal(report.includes("待人工复核"), true);
  } finally { await f.cleanup(); }
});

test("Hermes 编码观察与离线 HYP 关联逐次审批且不确认 XSS", async () => {
  const f = await fixture({ encoding: true, hypothesis: true, budget: 3 });
  const beforeCount = hits.length;
  try {
    const observed = await f.service.observe(f.url);
    assert.equal(observed.ok, true);
    if (!observed.ok) return;
    const input = { evidence_id: observed.evidence_id, form_index: 1, parameter_name: "q" };
    const reflected = await f.service.reflection(input, async () => true);
    assert.equal(reflected.ok, true);
    if (!reflected.ok) return;
    assert.equal(reflected.result.outcome, "reflected");
    assert.equal(hits.length, beforeCount + 2);
    const context = await f.service.reflectionContext(reflected.trace.evidence_id);
    assert.equal(context.ok, true);
    assert.equal(hits.length, beforeCount + 2);
    const refused = await f.service.encodingProbe(reflected.trace.evidence_id, async () => false);
    assert.equal(refused.code, "APPROVAL_DENIED");
    assert.equal(hits.length, beforeCount + 2);
    const encoded = await f.service.encodingProbe(reflected.trace.evidence_id, async details => {
      assert.equal(details.endpoint, `${f.url}search`);
      assert.equal(details.parameter_name, "q");
      return true;
    });
    assert.equal(encoded.ok, true);
    if (!encoded.ok) return;
    assert.equal(hits.length, beforeCount + 3);
    assert.match(hits.at(-1)?.target ?? "", /^\/search\?q=PV-ENC-/u);
    assert.equal((await f.service.headerCheck(encoded.trace.evidence_id)).ok, true);
    assert.equal((await f.service.encodingProbe(reflected.trace.evidence_id,
      async () => true)).ok, false);
    assert.equal(hits.length, beforeCount + 3);
    const audit = await readFile(path.join(f.root, "audit.jsonl"), "utf8");
    assert.match(audit, /"tool":"authorized_xss_encoding_probe".*"approved":false/u);
    assert.match(audit, /"tool":"authorized_xss_encoding_probe".*"approved":true/u);
    assert.equal(encoded.user_summary.includes("已确认 XSS"), false);
    const denied = await f.service.xssHypothesisTriage(reflected.trace.evidence_id,
      encoded.trace.evidence_id, async () => false);
    assert.equal(denied.code, "APPROVAL_DENIED");
    const triaged = await f.service.xssHypothesisTriage(reflected.trace.evidence_id,
      encoded.trace.evidence_id, async () => true);
    assert.equal(triaged.ok, true);
    if (!triaged.ok) return;
    assert.equal(triaged.code, "HYPOTHESIS_RECORDED");
    assert.equal(triaged.status, "suspected");
    assert.equal(hits.length, beforeCount + 3);
  } finally { await f.cleanup(); }
});

test("Hermes 通用 HYP 仅写本次目标且只能读本次隔离目录", async () => {
  const f = await fixture({ hypothesis: true });
  const beforeCount = hits.length;
  try {
    const input = { target_url: f.url, title: "待验证的响应头假设",
      description: "需要进一步人工验证", reason: "仅作为候选记录" };
    assert.equal((await f.service.hypothesisCreate(input, async () => false)).code,
      "APPROVAL_DENIED");
    assert.equal((await f.service.hypothesisCreate({ ...input, target_url: `${f.url}other` },
      async () => true)).code, "TASK_TARGET_DENIED");
    const created = await f.service.hypothesisCreate(input, async () => true);
    assert.equal(created.ok, true);
    if (!created.ok) return;
    assert.equal(created.status, "suspected");
    const read = await f.service.hypothesisGet(created.hypothesis_id);
    assert.equal(read.ok, true);
    if (read.ok) assert.equal(read.hypothesis.status, "suspected");
    assert.equal(hits.length, beforeCount);
    assert.equal((await f.service.hypothesisGet("HYP-20261002000000-deadbeef")).ok, false);
  } finally { await f.cleanup(); }
});

test("Hermes 完整反射型 XSS 评估一次审批并逐请求门禁", async () => {
  const f = await fixture({ assessment: true, budget: 4 });
  const beforeCount = hits.length;
  try {
    assert.equal((await f.service.observe(f.url)).code, "TASK_MODE_DENIED");
    assert.equal((await f.service.reflectedXssAssessment(`${f.url}other`,
      async () => true)).code, "TASK_MODE_DENIED");
    const refused = await f.service.reflectedXssAssessment(f.url, async () => false);
    assert.equal(refused.code, "APPROVAL_DENIED");
    assert.equal(hits.length, beforeCount);
    const result = await f.service.reflectedXssAssessment(f.url, async details => {
      assert.equal(details.target, f.url);
      assert.equal(details.max_parameters, 1);
      return true;
    });
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.code, "ASSESSMENT_COMPLETED");
    assert.equal(result.result.checked, 1);
    assert.equal(result.result.hypotheses_linked, 1);
    assert.equal(hits.length, beforeCount + 4);
    assert.deepEqual(hits.slice(beforeCount).map(hit => hit.target.replace(/PV-(?:REFLECT|ENC)-.*/u, "PV-*")),
      ["/", "/search", "/search?q=PV-*", "/search?q=PV-*"]);
    assert.ok(result.trace.report_file.includes(path.join("reports", "hermes")));
    assert.equal(result.user_summary.includes("未确认 XSS"), true);
    const captured = hits.slice(beforeCount).map(hit => ({ method: hit.method,
      request_target: hit.target, response_status: hit.status,
      response_body_sha256: hash(hit.body) }));
    const audit = (await readFile(path.join(f.root, "audit.jsonl"), "utf8")).trim()
      .split("\n").map(line => JSON.parse(line));
    const events = { tools: [{ name: "authorized_reflected_xss_assessment",
      status: "completed", input: { url: f.url }, output: result }],
    final_text: "反射和原样字符是 XSS 待复核候选，未确认漏洞。",
    error: null, token_usage: { input: 1, output: 1 } };
    const task = { id: "local-assessment", url: f.url, endpoint_path: "/search",
      parameter_name: "q", expected_hypothesis: true };
    const score = await scoreHermesAssessment(task, f.root, events, captured, audit);
    assert.equal(score.passed, true, score.reason);
    const hypothesisId = result.result.items[0].hypothesis_id;
    assert.ok(hypothesisId);
    const read = await f.service.hypothesisGet(hypothesisId);
    const withRead = structuredClone(events);
    withRead.tools.push({ name: "hypothesis_get", status: "completed",
      input: { hypothesis_id: hypothesisId }, output: read });
    assert.equal((await scoreHermesAssessment(task, f.root, withRead, captured, audit)).passed, true);
    const unrelatedRead = structuredClone(withRead);
    unrelatedRead.tools[1].input.hypothesis_id = "HYP-20261002000000-deadbeef";
    assert.equal((await scoreHermesAssessment(task, f.root, unrelatedRead, captured, audit)).passed, false);
    const extraTool = structuredClone(withRead);
    extraTool.tools[1].name = "authorized_web_observe";
    assert.equal((await scoreHermesAssessment(task, f.root, extraTool, captured, audit)).passed, false);
    const forged = structuredClone(events);
    forged.tools[0].output.result.items[0].encoding_evidence_id = "EV-20261002000000-deadbeef";
    assert.equal((await scoreHermesAssessment(task, f.root, forged, captured, audit)).passed, false);
    assert.equal((await scoreHermesAssessment(task, f.root, events,
      captured.slice(0, 3), audit)).passed, false);
    assert.equal((await scoreHermesAssessment(task, f.root, events, captured,
      audit.filter(entry => entry.kind !== "approval"))).passed, false);
    assert.equal((await scoreHermesAssessment(task, f.root,
      { ...events, final_text: "已确认 XSS 漏洞。" }, captured, audit)).passed, false);
    const evidenceId = result.result.items[0].encoding_evidence_id;
    const evidenceFile = path.join(f.root, "evidence", "hermes", `${evidenceId}.json`);
    const altered = JSON.parse(await readFile(evidenceFile, "utf8"));
    altered.observation.response.body += "forged";
    await writeFile(evidenceFile, JSON.stringify(altered));
    assert.equal((await scoreHermesAssessment(task, f.root, events, captured, audit)).passed, false);
  } finally { await f.cleanup(); }
});

test("预算耗尽和禁止路径重定向不发送下一跳，伪造 EV 不可清点", async () => {
  const redirect = `http://127.0.0.1:${port}/redirect`;
  const f = await fixture({ urls: [redirect, `http://127.0.0.1:${port}/blocked`] });
  const beforeCount = hits.length;
  try {
    const first = await f.service.observe(redirect);
    assert.equal(first.ok, false);
    assert.equal(first.scope_code, "PATH_DENIED");
    assert.equal(hits.length, beforeCount + 1);
    assert.equal(hits.at(-1)?.target, "/redirect");
    const second = await f.service.observe(redirect);
    assert.equal(second.ok, false);
    assert.equal(second.request_code, "REQUEST_BLOCKED");
    assert.equal(hits.length, beforeCount + 1);
    const fake = await f.service.inventory("EV-20261002000000-deadbeef");
    assert.equal(fake.ok, false);
  } finally { await f.cleanup(); }
});

test("Hermes 会话事件转换保留工具、最终回答和 Token", () => {
  const events = normalizeHermesEvents([
    { type: "tool_use", name: "mcp__phantomveil-hermes__authorized_web_observe", input: { url: "http://example.test/" } },
    { type: "tool_result", name: "mcp__phantomveil-hermes__authorized_web_observe",
      output: { content: [{ type: "text", text: '{"ok":true}' }] } },
    { type: "result", text: "中文结论", tokens: { input: 20, output: 10 }, exit_code: 0 },
  ]);
  assert.equal(events.tools[0].name, "authorized_web_observe");
  assert.deepEqual(events.tools[0].output, { ok: true });
  assert.equal(events.final_text, "中文结论");
  assert.deepEqual(events.token_usage, { input: 20, output: 10 });
  const exported = normalizeHermesEvents([{ input_tokens: 23, output_tokens: 11,
    messages: [
      { role: "user", content: "观察" },
      { role: "assistant", content: "", tool_calls: [{ id: "call-1", function: {
        name: "mcp__phantomveil-hermes__authorized_web_observe",
        arguments: '{"url":"http://example.test/"}' } }] },
      { role: "tool", tool_call_id: "call-1", content: '{"ok":true}' },
      { role: "assistant", content: "中文结论", tool_calls: [] },
    ] }]);
  assert.equal(exported.tools[0].status, "completed");
  assert.deepEqual(exported.tools[0].input, { url: "http://example.test/" });
  assert.equal(exported.final_text, "中文结论");
  assert.deepEqual(exported.token_usage, { input: 23, output: 11 });
});

test("OpenCode MCP 对照事件归一化为同一工具合同", () => {
  const events = normalizeOpenCodeMcpEvents([
    { type: "part.updated", part: { type: "tool", tool: "phantomveil-hermes_authorized_web_observe",
      callID: "call-1", state: { status: "completed", input: { url: "http://example.test/" },
        output: JSON.stringify({ content: [{ type: "text", text: '{"ok":true}' }] }) } } },
    { type: "part.updated", part: { type: "text", id: "text-1", messageID: "message-1",
      text: "HTTP 200，已清点入口。" } },
  ]);
  assert.equal(events.tools[0].name, "authorized_web_observe");
  assert.deepEqual(events.tools[0].output, { ok: true });
  assert.equal(events.final_text, "HTTP 200，已清点入口。");
});
