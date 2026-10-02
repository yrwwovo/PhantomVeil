import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";

import tool from "../.opencode/tools/authorized_reflected_xss_assessment.ts";
import { runAuthorizedReflectedXssAssessment } from "../src/workflows/reflected-xss-assessment.ts";

const REFERENCE = "LOCAL-LAB-ACTIVE";

function encodeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;").replaceAll("'", "&#39;");
}

async function fixture(
  t: TestContext,
  body?: string,
  maxParameters = 10,
  encodeOutput = false,
  actions = ["parameter_reflection_check", "xss_encoding_probe", "hypothesis_create"],
) {
  const root = await mkdtemp(path.join(tmpdir(), "security-agent-active-xss-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const hits: string[] = [];
  const defaultBody = [
    '<form action="/search" method="get"><input name="q"></form>',
    '<form action="/lookup" method="get"><input name="term"></form>',
    '<form action="/logout" method="get"><input name="next"></form>',
    '<form action="/admin/delete-user" method="get"><input name="user"></form>',
    '<form action="/upload" method="get"><input name="document" type="file"></form>',
    '<form action="/login" method="post"><input name="username"></form>',
  ].join("\n");
  const server = createServer((request, response) => {
    hits.push(request.url!);
    const url = new URL(request.url!, "http://local.test");
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    if (url.pathname === "/") response.end(body ?? defaultBody);
    else if (url.pathname === "/search") {
      const value = url.searchParams.get("q") ?? "";
      response.end(`<p>${encodeOutput ? encodeHtml(value) : value}</p>`);
    }
    else if (url.pathname.startsWith("/check-")) {
      const value = [...url.searchParams.values()][0] ?? "";
      response.end(`<input value="${value}">`);
    } else response.end("<p>no reflection</p>");
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject); server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("没有测试端口");
  const origin = `http://127.0.0.1:${address.port}`;
  await mkdir(path.join(root, "configs"));
  await writeFile(path.join(root, "configs", "scope.local.json"), JSON.stringify({
    allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1"], allowed_ports: [address.port],
    allowed_paths: ["/"], denied_paths: ["/admin/delete"],
  }));
  await writeFile(path.join(root, "configs", "http.local.json"), JSON.stringify({
    allowed_resolved_ips: ["127.0.0.1"], timeout_ms: 1000,
    max_response_bytes: 16384, max_redirects: 2,
  }));
  await writeFile(path.join(root, "configs", "crawl.local.json"), JSON.stringify({
    max_pages: 3, max_depth: 1, max_requests: 6, delay_ms: 100,
  }));
  await writeFile(path.join(root, "configs", "active-assessment.local.json"), JSON.stringify({
    max_parameters: maxParameters, delay_ms: 100,
  }));
  await writeFile(path.join(root, "configs", "authorization.local.json"), JSON.stringify({
    schema_version: 1,
    grants: [{ reference: REFERENCE, enabled: true, expires_at: "2099-12-31T23:59:59.000Z",
      actions,
      scope: { allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1"],
        allowed_ports: [address.port], allowed_paths: ["/"], denied_paths: ["/admin/delete"] } }],
  }));
  return { root, origin, hits };
}

test("一次任务批准后自动检查多个安全 GET 参数并生成汇总", async t => {
  const f = await fixture(t);
  const approvals: unknown[] = [];
  const result = await runAuthorizedReflectedXssAssessment(f.root, {
    url: `${f.origin}/`, authorization_reference: REFERENCE,
  }, { approve: async details => { approvals.push(details); }, wait: async () => {} });
  assert.ok(result.ok, JSON.stringify(result));
  assert.equal(result.code, "ASSESSMENT_COMPLETED");
  assert.equal(approvals.length, 1);
  assert.equal(result.result.candidates_discovered, 2);
  assert.equal(result.result.checked, 2);
  assert.equal(result.result.reflected, 1);
  assert.equal(result.result.encoding_checked, 1);
  assert.equal(result.result.raw_character_candidates, 1);
  assert.equal(result.result.hypotheses_linked, 1);
  assert.equal(result.result.skipped_high_impact, 3);
  assert.equal(f.hits.length, 4);
  assert.equal(f.hits[0], "/");
  assert.match(f.hits[1], /^\/search\?q=PV-REFLECT-/u);
  assert.match(f.hits[2], /^\/search\?q=PV-ENC-/u);
  assert.match(f.hits[3], /^\/lookup\?term=PV-REFLECT-/u);
  assert.match(result.user_summary, /一次任务批准/u);
  assert.match(result.user_summary, /关联 1 个 HYP/u);
  assert.match(result.user_summary, /本轮未确认 XSS/u);
  assert.match(await readFile(result.trace.report_file, "utf8"), /实际检查：2/u);
  assert.equal((await readdir(path.join(f.root, "hypotheses", "opencode")))
    .filter(name => name.endsWith(".json")).length, 1);
});

test("反射参数全部编码时完成观察但不创建 HYP", async t => {
  const f = await fixture(t, undefined, 10, true);
  const result = await runAuthorizedReflectedXssAssessment(f.root, {
    url: `${f.origin}/`, authorization_reference: REFERENCE,
  }, { approve: async () => {}, wait: async () => {} });
  assert.ok(result.ok, JSON.stringify(result));
  assert.equal(result.result.reflected, 1);
  assert.equal(result.result.encoding_checked, 1);
  assert.equal(result.result.raw_character_candidates, 0);
  assert.equal(result.result.hypotheses_linked, 0);
  assert.equal(result.result.items[0].hypothesis_action, "NO_HYPOTHESIS_NEEDED");
  await assert.rejects(readdir(path.join(f.root, "hypotheses")), { code: "ENOENT" });
});

test("同一 URL 主流程重复运行复用原 HYP 并追加新 EV", async t => {
  const f = await fixture(t);
  const first = await runAuthorizedReflectedXssAssessment(f.root, {
    url: `${f.origin}/`, authorization_reference: REFERENCE,
  }, { approve: async () => {}, wait: async () => {} });
  const second = await runAuthorizedReflectedXssAssessment(f.root, {
    url: `${f.origin}/`, authorization_reference: REFERENCE,
  }, { approve: async () => {}, wait: async () => {} });
  assert.ok(first.ok && second.ok, JSON.stringify([first, second]));
  const firstItem = first.result.items.find(item => item.hypothesis_id);
  const secondItem = second.result.items.find(item => item.hypothesis_id);
  assert.ok(firstItem?.hypothesis_id);
  assert.equal(secondItem?.hypothesis_id, firstItem.hypothesis_id);
  assert.equal(secondItem?.hypothesis_action, "HYPOTHESIS_EVIDENCE_LINKED");
  assert.equal((await readdir(path.join(f.root, "hypotheses", "opencode")))
    .filter(name => name.endsWith(".json")).length, 1);
});

test("任务未批准或授权引用无效时不发送任何请求", async t => {
  const denied = await fixture(t);
  const rejected = await runAuthorizedReflectedXssAssessment(denied.root, {
    url: `${denied.origin}/`, authorization_reference: REFERENCE,
  }, { approve: async () => { throw new Error("rejected"); } });
  assert.equal(rejected.code, "APPROVAL_DENIED");
  assert.equal(denied.hits.length, 0);

  const unauthorized = await fixture(t);
  let asked = false;
  const invalid = await runAuthorizedReflectedXssAssessment(unauthorized.root, {
    url: `${unauthorized.origin}/`, authorization_reference: "UNKNOWN-REFERENCE",
  }, { approve: async () => { asked = true; } });
  assert.equal(invalid.code, "AUTHORIZATION_DENIED");
  assert.equal(asked, false);
  assert.equal(unauthorized.hits.length, 0);

  const incomplete = await fixture(t, undefined, 10, false, ["parameter_reflection_check"]);
  let incompleteAsked = false;
  const missingActions = await runAuthorizedReflectedXssAssessment(incomplete.root, {
    url: `${incomplete.origin}/`, authorization_reference: REFERENCE,
  }, { approve: async () => { incompleteAsked = true; } });
  assert.equal(missingActions.code, "AUTHORIZATION_DENIED");
  assert.match(missingActions.reason, /xss_encoding_probe/u);
  assert.equal(incompleteAsked, false);
  assert.equal(incomplete.hits.length, 0);
});

test("参数上限限制单次任务请求量但不要求逐参数批准", async t => {
  const forms = Array.from({ length: 6 }, (_, index) =>
    `<form action="/check-${index}" method="get"><input name="p${index}"></form>`).join("\n");
  const f = await fixture(t, forms, 3);
  let approvals = 0;
  const result = await runAuthorizedReflectedXssAssessment(f.root, {
    url: `${f.origin}/`, authorization_reference: REFERENCE,
  }, { approve: async () => { approvals++; }, wait: async () => {} });
  assert.ok(result.ok);
  assert.equal(approvals, 1);
  assert.equal(result.result.candidates_discovered, 6);
  assert.equal(result.result.checked, 3);
  assert.equal(result.result.reflected, 3);
  assert.equal(result.result.encoding_checked, 3);
  assert.equal(result.result.hypotheses_linked, 3);
  assert.equal(f.hits.length, 7);
  assert.match(result.user_summary, /达到本次参数上限 3/u);
});

test("OpenCode 组合工具只接受目标和授权引用，并执行一次任务级审批", async () => {
  assert.deepEqual(Object.keys(tool.args).sort(), ["authorization_reference", "url"]);
  const source = await readFile(new URL("../.opencode/tools/authorized_reflected_xss_assessment.ts", import.meta.url), "utf8");
  assert.equal((source.match(/await ask\(/gu) ?? []).length, 1);
  assert.match(source, /permission:\s*"reflected_xss_assessment"/u);
  assert.match(source, /max_encoding_probes/u);
  assert.match(source, /may_write_suspected_hypotheses/u);
  assert.doesNotMatch(source, /bash|shell|exec\(/iu);
});
