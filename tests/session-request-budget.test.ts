import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { restrictedHttpGet } from "../capabilities/web/restricted-http-get.ts";
import { readIsolatedRunRequestBudget, readSessionRequestBudget, reserveSessionRequest, sessionRequestControl,
  TASK_BUDGET_EXHAUSTED, TASK_BUDGET_UNAVAILABLE } from "../src/budget/session-request-budget.ts";
import { runWebCheck } from "../src/workflows/web-check.ts";
import { runWebCrawl } from "../src/workflows/web-crawl.ts";

test("同一会话跨调用和并发共享预算；配置只能收紧已开始的会话", async t => {
  const root = await mkdtemp(path.join(tmpdir(), "pveil-budget-project-"));
  const states = await mkdtemp(path.join(tmpdir(), "pveil-budget-state-"));
  t.after(() => Promise.all([rm(root, { recursive: true, force: true }),
    rm(states, { recursive: true, force: true })]));
  await mkdir(path.join(root, "configs"));
  const config = path.join(root, "configs", "request-budget.local.json");
  await writeFile(config, JSON.stringify({ max_requests: 3 }));
  const results = await Promise.all(Array.from({ length: 7 }, (_, i) =>
    reserveSessionRequest(root, "one-session", `http://example.test/${i}`, states)));
  assert.equal(results.filter(item => item.allowed).length, 3);
  assert.ok(results.filter(item => !item.allowed).every(item => item.code === TASK_BUDGET_EXHAUSTED));
  assert.equal((await readSessionRequestBudget(root, "one-session", states))?.used_requests, 3);
  assert.equal((await readIsolatedRunRequestBudget(states, "one-session"))?.used_requests, 3);
  assert.equal((await readSessionRequestBudget(root, "other-session", states)), null);
  assert.equal((await reserveSessionRequest(root, "other-session", "http://example.test/", states)).allowed, true);
  await writeFile(config, JSON.stringify({ max_requests: 2 }));
  assert.equal((await reserveSessionRequest(root, "one-session", "http://example.test/next", states)).code,
    TASK_BUDGET_EXHAUSTED);
  assert.equal((await readSessionRequestBudget(root, "one-session", states))?.max_requests, 2);
  await writeFile(config, JSON.stringify({ max_requests: 10 }));
  assert.equal((await reserveSessionRequest(root, "one-session", "http://example.test/later", states)).code,
    TASK_BUDGET_EXHAUSTED);
  assert.equal((await readSessionRequestBudget(root, "one-session", states))?.attempts.length, 3);
  assert.equal((await reserveSessionRequest(root, "", "http://example.test/", states)).code,
    TASK_BUDGET_UNAVAILABLE);
  await writeFile(config, "invalid json");
  assert.equal((await reserveSessionRequest(root, "fresh", "http://example.test/", states)).code,
    TASK_BUDGET_UNAVAILABLE);
  await writeFile(config, JSON.stringify({ max_requests: 10 }));
  const [projectKey] = await readdir(states);
  const sessionKey = createHash("sha256").update("one-session").digest("hex");
  await writeFile(path.join(states, projectKey, `${sessionKey}.json`), "corrupt state");
  assert.equal((await reserveSessionRequest(root, "one-session", "http://example.test/", states)).code,
    TASK_BUDGET_UNAVAILABLE, "损坏的计数文件必须拒绝后续请求");
});

test("共享预算在真实请求边界阻止跨工具第三次访问及重定向下一跳", async t => {
  const root = await mkdtemp(path.join(tmpdir(), "pveil-budget-workflow-"));
  const states = await mkdtemp(path.join(tmpdir(), "pveil-budget-state-"));
  t.after(() => Promise.all([rm(root, { recursive: true, force: true }),
    rm(states, { recursive: true, force: true })]));
  const hits: string[] = [];
  const server = createServer((request, response) => {
    hits.push(request.url ?? "");
    if (request.url === "/redirect") {
      response.writeHead(302, { location: "/after-redirect" }); response.end(); return;
    }
    response.writeHead(200, { "content-type": "text/html" });
    response.end('<a href="/next">next</a>');
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("fixture server unavailable");
  const base = `http://127.0.0.1:${address.port}`;
  const scope = { allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1"],
    allowed_ports: [address.port], allowed_paths: ["/"], denied_paths: [] };
  const policy = { allowed_resolved_ips: ["127.0.0.1"], timeout_ms: 1000,
    max_response_bytes: 4096, max_redirects: 2 };
  await mkdir(path.join(root, "configs"));
  await writeFile(path.join(root, "configs", "scope.local.json"), JSON.stringify(scope));
  await writeFile(path.join(root, "configs", "http.local.json"), JSON.stringify(policy));
  await writeFile(path.join(root, "configs", "crawl.local.json"), JSON.stringify({
    max_pages: 3, max_depth: 1, max_requests: 4, delay_ms: 100,
  }));
  await writeFile(path.join(root, "configs", "request-budget.local.json"),
    JSON.stringify({ max_requests: 2 }));
  const first = await runWebCheck(root, `${base}/`, sessionRequestControl(root, "same", states));
  assert.equal(first.ok, true);
  const second = await runWebCrawl(root, `${base}/`, sessionRequestControl(root, "same", states));
  assert.equal(second.stop_reason, TASK_BUDGET_EXHAUSTED);
  assert.deepEqual(hits, ["/", "/"]);
  assert.equal((await readSessionRequestBudget(root, "same", states))?.used_requests, 2);

  await writeFile(path.join(root, "configs", "request-budget.local.json"),
    JSON.stringify({ max_requests: 1 }));
  const redirect = await restrictedHttpGet(`${base}/redirect`, scope, policy,
    sessionRequestControl(root, "redirect-session", states));
  assert.equal(redirect.ok, false);
  assert.equal(redirect.code, "REQUEST_BLOCKED");
  assert.equal(redirect.reason, TASK_BUDGET_EXHAUSTED);
  assert.deepEqual(hits, ["/", "/", "/redirect"]);
  const state = await readSessionRequestBudget(root, "redirect-session", states);
  assert.equal(state?.used_requests, 1);
});
