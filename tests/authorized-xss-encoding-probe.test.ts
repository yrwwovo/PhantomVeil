import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";

import tool from "../.opencode/tools/authorized_xss_encoding_probe.ts";
import { analyzeXssEncodingObservation, createXssEncodingProbe } from "../capabilities/web/xss-encoding-observation.ts";
import { runAuthorizedXssEncodingProbe } from "../src/adapters/opencode/authorized-xss-encoding-probe.ts";
import { EvidenceStore, verifyEvidenceFile } from "../src/evidence/evidence-store.ts";

const REFERENCE = "LOCAL-LAB-ENCODING";
const REFLECTION_MARKER = "PV-REFLECT-1234567890abcdef";

function encodeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;").replaceAll("'", "&#39;");
}

function encodeProbeCharacters(value: string): string {
  return value.replace(/[<>"'&]/gu, character => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

async function fixture(
  t: TestContext,
  options: { response?: "raw" | "html" | "percent" | "plain" | "redirect"; actions?: string[];
    sourceReflected?: boolean } = {},
) {
  const root = await mkdtemp(path.join(tmpdir(), "security-agent-xss-encoding-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const hits: string[] = [];
  const server = createServer((request, response) => {
    hits.push(request.url!);
    if (options.response === "redirect") {
      response.writeHead(302, { location: "/elsewhere" }); response.end(); return;
    }
    const value = new URL(request.url!, "http://local.test").searchParams.get("q") ?? "";
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    if (options.response === "plain") response.end("<p>not reflected</p>");
    else if (options.response === "html") response.end(`<p>${encodeHtml(value)}</p>`);
    else if (options.response === "percent") response.end(`<p>${encodeProbeCharacters(value)}</p>`);
    else response.end(`<p>${value}</p>`);
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
    max_response_bytes: 32768, max_redirects: 3,
  }));
  await writeFile(path.join(root, "configs", "authorization.local.json"), JSON.stringify({
    schema_version: 1,
    grants: [{ reference: REFERENCE, enabled: true, expires_at: "2099-12-31T23:59:59.000Z",
      actions: options.actions ?? ["xss_encoding_probe"],
      scope: { allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1"],
        allowed_ports: [address.port], allowed_paths: ["/"], denied_paths: ["/denied"] } }],
  }));
  const sourceBody = options.sourceReflected === false ? "<p>no marker</p>" : `<p>${REFLECTION_MARKER}</p>`;
  const saved = await new EvidenceStore({ output_dir: path.join(root, "evidence", "opencode") }).saveHttpGet({
    ok: true, code: "HTTP_RESPONSE", reason: "source", redirects: [],
    response: { url: `${origin}/search?q=${REFLECTION_MARKER}`, status: 200,
      headers: { "content-type": "text/html" }, body: sourceBody,
      body_bytes: Buffer.byteLength(sourceBody), resolved_ip: "127.0.0.1" },
  });
  assert.ok(saved.ok);
  return { root, origin, saved, hits };
}

function input(evidenceId: string) {
  return { evidence_id: evidenceId, authorization_reference: REFERENCE };
}

test("从已反射 EV 发送一次非执行标点探针并记录原样字符", async t => {
  const f = await fixture(t);
  const result = await runAuthorizedXssEncodingProbe(f.root, input(f.saved.evidence_id));
  assert.ok(result.ok, JSON.stringify(result));
  assert.equal(result.code, "XSS_ENCODING_PROBE_COMPLETED");
  assert.equal(result.result.parameter_name, "q");
  assert.equal(result.result.observation.outcome, "raw_special_characters_observed");
  assert.equal(result.result.observation.observed_characters, 5);
  assert.ok(result.result.observation.characters.every(item => item.observed_forms.includes("raw")));
  assert.equal(f.hits.length, 1);
  assert.match(f.hits[0], /^\/search\?q=PV-ENC-/u);
  assert.doesNotMatch(decodeURIComponent(f.hits[0]), /script|javascript|onerror|onclick/iu);
  assert.equal((await verifyEvidenceFile(result.trace.evidence_file)).ok, true);
  assert.match(await readFile(result.trace.report_file, "utf8"), /没有确认漏洞/u);
  await assert.rejects(readdir(path.join(f.root, "hypotheses")), { code: "ENOENT" });
});

test("区分 HTML 实体编码、URL 编码和未观察到探针", async t => {
  for (const [response, expected] of [
    ["html", "all_observed_characters_encoded"],
    ["percent", "all_observed_characters_encoded"],
    ["plain", "probe_not_observed"],
  ] as const) {
    const f = await fixture(t, { response });
    const result = await runAuthorizedXssEncodingProbe(f.root, input(f.saved.evidence_id));
    assert.ok(result.ok, JSON.stringify(result));
    assert.equal(result.result.observation.outcome, expected);
  }
});

test("离线分析器不会把编码或原样字符直接判定为 XSS", () => {
  const probe = createXssEncodingProbe("1234567890abcdef");
  const raw = analyzeXssEncodingObservation(probe.payload, probe);
  assert.equal(raw.outcome, "raw_special_characters_observed");
  assert.match(raw.conclusion, /没有确认 XSS/u);
  const missing = analyzeXssEncodingObservation("<p>ordinary</p>", probe);
  assert.equal(missing.outcome, "probe_not_observed");
  assert.doesNotMatch(JSON.stringify([raw, missing]), /已确认 XSS|确认存在 XSS/u);
});

test("来源未证明反射、缺少动作授权和重定向都不会扩大请求", async t => {
  const notReflected = await fixture(t, { sourceReflected: false });
  assert.equal((await runAuthorizedXssEncodingProbe(
    notReflected.root, input(notReflected.saved.evidence_id))).code, "REFLECTION_NOT_PROVEN");
  assert.equal(notReflected.hits.length, 0);

  const unauthorized = await fixture(t, { actions: ["parameter_reflection_check"] });
  assert.equal((await runAuthorizedXssEncodingProbe(
    unauthorized.root, input(unauthorized.saved.evidence_id))).code, "AUTHORIZATION_DENIED");
  assert.equal(unauthorized.hits.length, 0);

  const redirect = await fixture(t, { response: "redirect" });
  const redirected = await runAuthorizedXssEncodingProbe(redirect.root, input(redirect.saved.evidence_id));
  assert.equal(redirected.code, "HTTP_REJECTED");
  assert.equal(redirect.hits.length, 1);
});

test("OpenCode 编码工具只接受 EV 和授权引用，并在一次请求前审批", async () => {
  assert.deepEqual(Object.keys(tool.args).sort(), ["authorization_reference", "evidence_id"]);
  const approvals: unknown[] = [];
  const output = JSON.parse(await tool.execute({ evidence_id: "invalid", authorization_reference: REFERENCE }, {
    ask: async details => { approvals.push(details); },
  } as never) as string);
  assert.equal(output.code, "INVALID_INPUT");
  assert.equal(approvals.length, 1);
  assert.equal((approvals[0] as { permission: string }).permission, "xss_encoding_probe");
  assert.deepEqual((approvals[0] as { always: string[] }).always, []);

  const rejected = JSON.parse(await tool.execute({ evidence_id: "EV-20260929000000-12345678",
    authorization_reference: REFERENCE }, { ask: async () => { throw new Error("rejected"); } } as never) as string);
  assert.equal(rejected.code, "APPROVAL_DENIED");
  const unavailable = JSON.parse(await tool.execute({ evidence_id: "EV-20260929000000-12345678",
    authorization_reference: REFERENCE }, {} as never) as string);
  assert.equal(unavailable.code, "APPROVAL_UNAVAILABLE");

  const agent = await readFile(new URL("../.opencode/agents/web-security-agent.md", import.meta.url), "utf8");
  assert.match(agent, /xss_encoding_probe: ask/u);
});
