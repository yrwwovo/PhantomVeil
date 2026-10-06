import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";

import tool from "../.opencode/tools/authorized_redirect_probe.ts";
import { runAuthorizedRedirectProbe } from "../src/adapters/opencode/authorized-redirect-probe.ts";
import { EvidenceStore, verifyEvidenceFile } from "../src/evidence/evidence-store.ts";

const REFERENCE = "LOCAL-LAB-REDIRECT";

async function fixture(t: TestContext, mode: "external" | "internal" | "body" | "static" = "external",
  options: { actions?: string[]; form?: string; sourceUrl?: string } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), "pveil-redirect-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const hits: string[] = [];
  const server = createServer((request, response) => {
    hits.push(request.url ?? "");
    const destination = new URL(request.url ?? "/", "http://local.test").searchParams.get("next") ?? "";
    if (mode === "body") {
      response.writeHead(200, { "content-type": "text/html" });
      response.end(`<p>${destination}</p>`);
    } else {
      response.writeHead(302, { location: mode === "external" ? destination :
        mode === "internal" ? "/safe" : "https://phantomveil-probe.invalid/static" });
      response.end();
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject); server.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("missing test port");
  const origin = `http://127.0.0.1:${address.port}`;
  const scope = { allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1"],
    allowed_ports: [address.port], allowed_paths: ["/"], denied_paths: ["/admin"] };
  await mkdir(path.join(root, "configs"));
  await writeFile(path.join(root, "configs", "scope.local.json"), JSON.stringify(scope));
  await writeFile(path.join(root, "configs", "http.local.json"), JSON.stringify({
    allowed_resolved_ips: ["127.0.0.1"], timeout_ms: 1000,
    max_response_bytes: 8192, max_redirects: 3,
  }));
  await writeFile(path.join(root, "configs", "authorization.local.json"), JSON.stringify({
    schema_version: 1, grants: [{ reference: REFERENCE, enabled: true,
      expires_at: "2099-12-31T23:59:59.000Z", actions: options.actions ?? ["redirect_probe"], scope }],
  }));
  const body = options.form ?? '<form action="/go" method="get"><input name="next"></form>';
  const saved = await new EvidenceStore({ output_dir: path.join(root, "evidence", "opencode") })
    .saveHttpGet({ ok: true, code: "HTTP_RESPONSE", reason: "source", redirects: [],
      response: { url: options.sourceUrl ?? `${origin}/`, status: 200, headers: { "content-type": "text/html" },
        body, body_bytes: Buffer.byteLength(body), resolved_ip: "127.0.0.1" } });
  assert.ok(saved.ok);
  return { root, origin, hits, saved };
}

function input(evidenceId: string) {
  return { evidence_id: evidenceId, form_index: 1, parameter_name: "next",
    authorization_reference: REFERENCE };
}

test("两次不同标记都精确出现在外站 Location 才给待复核候选", async t => {
  const f = await fixture(t);
  const result = await runAuthorizedRedirectProbe(f.root, input(f.saved.evidence_id));
  assert.ok(result.ok, JSON.stringify(result));
  assert.equal(result.result.outcome, "candidate");
  assert.equal(result.result.matched_count, 2);
  assert.equal(result.result.destination_contacted, false);
  assert.equal(f.hits.length, 2);
  assert.ok(f.hits.every(hit => hit.startsWith("/go?next=")));
  assert.notEqual(f.hits[0], f.hits[1]);
  for (const id of result.result.probe_evidence_ids) {
    assert.equal((await verifyEvidenceFile(path.join(f.root, "evidence", "opencode", `${id}.json`))).ok, true);
  }
  assert.match(await readFile(result.trace.report_file, "utf8"), /不自动确认漏洞/u);
});

test("站内跳转、正文回显和固定外站跳转均不能成为候选", async t => {
  for (const mode of ["internal", "body", "static"] as const) {
    const f = await fixture(t, mode);
    const result = await runAuthorizedRedirectProbe(f.root, input(f.saved.evidence_id));
    assert.ok(result.ok, JSON.stringify(result));
    assert.equal(result.result.outcome, "not_observed");
    assert.equal(f.hits.length, 2);
  }
});

test("无动作授权、敏感表单和预算耗尽均不能产出候选", async t => {
  const denied = await fixture(t, "external", { actions: [] });
  assert.equal((await runAuthorizedRedirectProbe(denied.root,
    input(denied.saved.evidence_id))).code, "AUTHORIZATION_DENIED");
  assert.equal(denied.hits.length, 0);
  const sensitive = await fixture(t, "external", {
    form: '<form action="/admin/delete" method="get"><input name="next"></form>',
  });
  assert.equal((await runAuthorizedRedirectProbe(sensitive.root,
    input(sensitive.saved.evidence_id))).code, "FORM_NOT_ALLOWED");
  assert.equal(sensitive.hits.length, 0);
  const limited = await fixture(t);
  let count = 0;
  const incomplete = await runAuthorizedRedirectProbe(limited.root, input(limited.saved.evidence_id),
    { before_request: async () => ++count > 1 ? "TASK_BUDGET_EXHAUSTED" : undefined });
  assert.equal(incomplete.code, "HTTP_REJECTED");
  assert.equal(limited.hits.length, 1);
  assert.equal(incomplete.probe_evidence_ids?.length, 1);
});

test("非本机目标和被篡改的来源 EV 都在发请求前停止", async t => {
  const remote = await fixture(t, "external", { sourceUrl: "https://example.test/",
    form: '<form action="https://example.test/go" method="get"><input name="next"></form>' });
  assert.equal((await runAuthorizedRedirectProbe(remote.root,
    input(remote.saved.evidence_id))).code, "LOCAL_LAB_ONLY");
  assert.equal(remote.hits.length, 0);

  const changed = await fixture(t);
  const file = path.join(changed.root, "evidence", "opencode", `${changed.saved.evidence_id}.json`);
  await writeFile(file, (await readFile(file, "utf8")).replace("/go", "/admin/go"));
  assert.equal((await runAuthorizedRedirectProbe(changed.root,
    input(changed.saved.evidence_id))).ok, false);
  assert.equal(changed.hits.length, 0);
});

test("OpenCode 工具缺少或拒绝人工审批时不执行请求", async () => {
  const agent = await readFile(path.resolve(import.meta.dirname,
    "../.opencode/agents/web-security-agent.md"), "utf8");
  assert.match(agent, /authorized_redirect_probe: allow/u);
  assert.match(agent, /redirect_probe: ask/u);
  assert.deepEqual(Object.keys(tool.args).sort(),
    ["authorization_reference", "evidence_id", "form_index", "parameter_name"]);
  const args = input("EV-20261002000000-12345678");
  const missing = JSON.parse(await tool.execute(args, {} as never) as string);
  const rejected = JSON.parse(await tool.execute(args,
    { ask: async () => { throw new Error("denied"); } } as never) as string);
  assert.equal(missing.code, "APPROVAL_UNAVAILABLE");
  assert.equal(rejected.code, "APPROVAL_DENIED");
  const approvals: unknown[] = [];
  const approved = JSON.parse(await tool.execute(args,
    { ask: async (details: unknown) => { approvals.push(details); } } as never) as string);
  assert.equal(approvals.length, 1);
  assert.equal((approvals[0] as { permission: string }).permission, "redirect_probe");
  assert.deepEqual((approvals[0] as { always: unknown[] }).always, []);
  assert.match((approvals[0] as { metadata: { title: string } }).metadata.title, /两次/u);
  assert.equal(approved.code, "EVIDENCE_NOT_FOUND");
});
