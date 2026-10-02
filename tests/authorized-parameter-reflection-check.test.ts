import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";

import tool from "../.opencode/tools/authorized_parameter_reflection_check.ts";
import { runAuthorizedParameterReflectionCheck } from "../src/adapters/opencode/authorized-parameter-reflection-check.ts";
import { EvidenceStore, verifyEvidenceFile } from "../src/evidence/evidence-store.ts";

const REFERENCE = "LOCAL-LAB-REFLECT";

async function fixture(
  t: TestContext,
  options: { form?: string; actions?: string[]; response?: "reflect" | "plain" | "redirect" } = {},
) {
  const root = await mkdtemp(path.join(tmpdir(), "security-agent-reflection-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const hits: string[] = [];
  const server = createServer((request, response) => {
    hits.push(request.url!);
    if (options.response === "redirect") {
      response.writeHead(302, { location: "/result" }); response.end(); return;
    }
    const marker = new URL(request.url!, "http://local.test").searchParams.get("q") ?? "";
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(options.response === "plain" ? "<p>no echo</p>" : `<p>${marker}</p>`);
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
    allowed_paths: ["/"], denied_paths: ["/denied"],
  }));
  await writeFile(path.join(root, "configs", "http.local.json"), JSON.stringify({
    allowed_resolved_ips: ["127.0.0.1"], timeout_ms: 1000,
    max_response_bytes: 8192, max_redirects: 3,
  }));
  await writeFile(path.join(root, "configs", "authorization.local.json"), JSON.stringify({
    schema_version: 1,
    grants: [{ reference: REFERENCE, enabled: true, expires_at: "2099-12-31T23:59:59.000Z",
      actions: options.actions ?? ["parameter_reflection_check"],
      scope: { allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1"],
        allowed_ports: [address.port], allowed_paths: ["/"], denied_paths: ["/denied"] } }],
  }));
  const body = options.form ?? `<form action="/search" method="get"><input name="q"></form>`;
  const saved = await new EvidenceStore({ output_dir: path.join(root, "evidence", "opencode") }).saveHttpGet({
    ok: true, code: "HTTP_RESPONSE", reason: "source", redirects: [],
    response: { url: `${origin}/`, status: 200, headers: { "content-type": "text/html" },
      body, body_bytes: Buffer.byteLength(body), resolved_ip: "127.0.0.1" },
  });
  assert.ok(saved.ok);
  return { root, origin, saved, hits };
}

function input(evidenceId: string) {
  return { authorization_reference: REFERENCE, evidence_id: evidenceId, form_index: 1, parameter_name: "q" };
}

test("只对证据中发现的 GET 参数发送一次无害标记并保存反射证据", async t => {
  const f = await fixture(t);
  const result = await runAuthorizedParameterReflectionCheck(f.root, input(f.saved.evidence_id));
  assert.ok(result.ok, JSON.stringify(result));
  assert.equal(result.code, "REFLECTION_CHECK_COMPLETED");
  assert.equal(result.result.outcome, "reflected");
  assert.equal(result.result.reflected_in_body, true);
  assert.equal(result.result.occurrence_count, 1);
  assert.equal(f.hits.length, 1);
  assert.match(f.hits[0], /^\/search\?q=PV-REFLECT-[a-f0-9]{16}$/u);
  assert.equal((await verifyEvidenceFile(result.trace.evidence_file)).ok, true);
  assert.match(await readFile(result.trace.report_file, "utf8"), /不等于可以执行脚本/u);
  await assert.rejects(readdir(path.join(f.root, "hypotheses")), { code: "ENOENT" });
});

test("未反射只记录观察结果，不误报漏洞", async t => {
  const f = await fixture(t, { response: "plain" });
  const result = await runAuthorizedParameterReflectionCheck(f.root, input(f.saved.evidence_id));
  assert.ok(result.ok);
  assert.equal(result.result.outcome, "not_reflected");
  assert.match(result.result.conclusion, /不能排除/u);
  assert.doesNotMatch(JSON.stringify(result), /XSS 漏洞|已确认漏洞/u);
});

test("POST、未知参数和含查询值的 action 在联网前被拒绝", async t => {
  for (const [form, expected] of [
    [`<form action="/login" method="post"><input name="q"></form>`, "METHOD_NOT_ALLOWED"],
    [`<form action="/search" method="get"><input name="other"></form>`, "PARAMETER_NOT_FOUND"],
    [`<form action="/search?fixed=secret" method="get"><input name="q"></form>`, "ACTION_NOT_ALLOWED"],
  ]) {
    const f = await fixture(t, { form });
    const result = await runAuthorizedParameterReflectionCheck(f.root, input(f.saved.evidence_id));
    assert.equal(result.code, expected);
    assert.equal(f.hits.length, 0);
  }
});

test("独立授权未允许主动参数检查时默认拒绝", async t => {
  const f = await fixture(t, { actions: ["hypothesis_create"] });
  const result = await runAuthorizedParameterReflectionCheck(f.root, input(f.saved.evidence_id));
  assert.equal(result.code, "AUTHORIZATION_DENIED");
  assert.equal(f.hits.length, 0);
});

test("反射检查不跟随重定向，确保一次调用只发送一次请求", async t => {
  const f = await fixture(t, { response: "redirect" });
  const result = await runAuthorizedParameterReflectionCheck(f.root, input(f.saved.evidence_id));
  assert.equal(result.code, "HTTP_REJECTED");
  assert.equal("cause" in result && result.cause, "TOO_MANY_REDIRECTS");
  assert.equal(f.hits.length, 1);
});

test("OpenCode 主动检查工具参数固定且需要逐次批准", async () => {
  assert.deepEqual(Object.keys(tool.args).sort(),
    ["authorization_reference", "evidence_id", "form_index", "parameter_name"]);
  const approvals: unknown[] = [];
  const output = await tool.execute({ authorization_reference: REFERENCE, evidence_id: "../outside",
    form_index: 1, parameter_name: "q" }, { ask: async input => { approvals.push(input); } } as never);
  assert.equal(JSON.parse(output as string).code, "INVALID_INPUT");
  assert.equal(approvals.length, 1);
  assert.deepEqual((approvals[0] as { always: string[] }).always, []);
  assert.equal((approvals[0] as { permission: string }).permission, "parameter_reflection_check");
  const agent = await readFile(new URL("../.opencode/agents/web-security-agent.md", import.meta.url), "utf8");
  assert.match(agent, /parameter_reflection_check: ask/u);
});

test("OpenCode 审批被拒绝或不可用时不进入工作流", async () => {
  const args = { authorization_reference: REFERENCE, evidence_id: "EV-20260922000000-12345678",
    form_index: 1, parameter_name: "q" };
  const rejected = JSON.parse(await tool.execute(args, {
    ask: async () => { throw new Error("rejected"); },
  } as never) as string);
  assert.equal(rejected.code, "APPROVAL_DENIED");
  const unavailable = JSON.parse(await tool.execute(args, {} as never) as string);
  assert.equal(unavailable.code, "APPROVAL_UNAVAILABLE");
});
