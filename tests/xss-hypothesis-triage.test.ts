import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";

import tool from "../.opencode/tools/authorized_xss_hypothesis_triage.ts";
import { createXssEncodingProbe } from "../capabilities/web/xss-encoding-observation.ts";
import { EvidenceStore } from "../src/evidence/evidence-store.ts";
import { HypothesisStore } from "../src/hypotheses/hypothesis-store.ts";
import { runXssHypothesisTriage } from "../src/workflows/xss-hypothesis-triage.ts";

const REFERENCE = "LOCAL-LAB-XSS-HYP";
const MARKER = "PV-REFLECT-1234567890abcdef";

function encodeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;").replaceAll("'", "&#39;");
}

async function saveEvidence(root: string, url: string, body: string) {
  const saved = await new EvidenceStore({ output_dir: path.join(root, "evidence", "opencode") })
    .saveHttpGet({
      ok: true, code: "HTTP_RESPONSE", reason: "offline fixture", redirects: [],
      response: { url, status: 200, headers: { "content-type": "text/html; charset=utf-8" },
        body, body_bytes: Buffer.byteLength(body), resolved_ip: "127.0.0.1" },
    });
  assert.ok(saved.ok);
  return saved;
}

async function fixture(t: TestContext, outcome: "raw" | "encoded" = "raw") {
  const root = await mkdtemp(path.join(tmpdir(), "security-agent-xss-hyp-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "configs"));
  await writeFile(path.join(root, "configs", "scope.local.json"), JSON.stringify({
    allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1"], allowed_ports: [5000],
    allowed_paths: ["/"], denied_paths: ["/denied"],
  }));
  await writeFile(path.join(root, "configs", "authorization.local.json"), JSON.stringify({
    schema_version: 1,
    grants: [{ reference: REFERENCE, enabled: true, expires_at: "2099-12-31T23:59:59.000Z",
      actions: ["hypothesis_create"],
      scope: { allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1"], allowed_ports: [5000],
        allowed_paths: ["/"], denied_paths: ["/denied"] } }],
  }));
  const reflection = await saveEvidence(root,
    `http://127.0.0.1:5000/search?q=${MARKER}`,
    `<input value="${MARKER}"><p>${MARKER}</p>`);
  const probe = createXssEncodingProbe("fedcba0987654321");
  const target = new URL("http://127.0.0.1:5000/search");
  target.searchParams.set("q", probe.payload);
  const bodyValue = outcome === "raw" ? probe.payload : encodeHtml(probe.payload);
  const encoding = await saveEvidence(root, target.href, `<p>${bodyValue}</p>`);
  return { root, reflection, encoding };
}

function input(reflectionId: string, encodingId: string) {
  return { reflection_evidence_id: reflectionId, encoding_evidence_id: encodingId,
    authorization_reference: REFERENCE };
}

test("字符全部编码时不创建 HYP，也不请求写入批准", async t => {
  const f = await fixture(t, "encoded");
  let approvals = 0;
  const result = await runXssHypothesisTriage(f.root,
    input(f.reflection.evidence_id, f.encoding.evidence_id),
    { approve: async () => { approvals++; } });
  assert.equal(result.ok, true);
  assert.equal(result.code, "NO_HYPOTHESIS_NEEDED");
  assert.equal(approvals, 0);
  await assert.rejects(readdir(path.join(f.root, "hypotheses")), { code: "ENOENT" });
});

test("原样字符候选创建 suspected HYP 并关联两份 EV", async t => {
  const f = await fixture(t);
  const approvals: unknown[] = [];
  const result = await runXssHypothesisTriage(f.root,
    input(f.reflection.evidence_id, f.encoding.evidence_id),
    { approve: async details => { approvals.push(details); } });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.code, "HYPOTHESIS_RECORDED");
  assert.equal(approvals.length, 1);
  if (!("hypothesis_id" in result)) return;
  const loaded = await new HypothesisStore(path.join(f.root, "hypotheses", "opencode"))
    .load(result.hypothesis_id);
  assert.equal(loaded.ok, true);
  if (!loaded.ok) return;
  assert.equal(loaded.hypothesis.status, "suspected");
  assert.equal(loaded.hypothesis.candidate_identity?.kind, "reflected_xss");
  assert.deepEqual(loaded.hypothesis.evidence.map(item => item.evidence_id).sort(),
    [f.reflection.evidence_id, f.encoding.evidence_id].sort());
});

test("相同候选重复运行复用 HYP，不重复写入或再次批准", async t => {
  const f = await fixture(t);
  let approvals = 0;
  const first = await runXssHypothesisTriage(f.root,
    input(f.reflection.evidence_id, f.encoding.evidence_id),
    { approve: async () => { approvals++; } });
  assert.equal(first.ok, true);
  assert.equal(first.code, "HYPOTHESIS_RECORDED");
  const second = await runXssHypothesisTriage(f.root,
    input(f.reflection.evidence_id, f.encoding.evidence_id),
    { approve: async () => { approvals++; } });
  assert.equal(second.ok, true);
  assert.equal(second.code, "HYPOTHESIS_REUSED");
  assert.equal(approvals, 1);
  assert.equal("hypothesis_id" in first && "hypothesis_id" in second &&
    first.hypothesis_id, second.hypothesis_id);
  assert.equal((await readdir(path.join(f.root, "hypotheses", "opencode")))
    .filter(name => name.endsWith(".json")).length, 1);
});

test("同一候选的新编码 EV 追加到原 HYP，状态保持不变", async t => {
  const f = await fixture(t);
  let approvals = 0;
  const first = await runXssHypothesisTriage(f.root,
    input(f.reflection.evidence_id, f.encoding.evidence_id),
    { approve: async () => { approvals++; } });
  assert.equal(first.ok, true);
  const probe = createXssEncodingProbe("0011223344556677");
  const target = new URL("http://127.0.0.1:5000/search");
  target.searchParams.set("q", probe.payload);
  const next = await saveEvidence(f.root, target.href, `<p>${probe.payload}</p>`);
  const linked = await runXssHypothesisTriage(f.root,
    input(f.reflection.evidence_id, next.evidence_id),
    { approve: async () => { approvals++; } });
  assert.equal(linked.ok, true, JSON.stringify(linked));
  assert.equal(linked.code, "HYPOTHESIS_EVIDENCE_LINKED");
  assert.equal(approvals, 2);
  assert.ok("hypothesis_id" in first && "hypothesis_id" in linked);
  if (!("hypothesis_id" in linked)) return;
  const loaded = await new HypothesisStore(path.join(f.root, "hypotheses", "opencode"))
    .load(linked.hypothesis_id);
  assert.equal(loaded.ok, true);
  if (!loaded.ok) return;
  assert.equal(loaded.hypothesis.status, "suspected");
  assert.equal(loaded.hypothesis.evidence.length, 3);
  assert.equal(loaded.hypothesis.history.at(-1)?.event, "evidence_attached");
});

test("证据端点或参数不匹配时拒绝关联，篡改文件也不能使用", async t => {
  const f = await fixture(t);
  const probe = createXssEncodingProbe("abcdef0123456789");
  const otherTarget = new URL("http://127.0.0.1:5000/other");
  otherTarget.searchParams.set("q", probe.payload);
  const mismatched = await saveEvidence(f.root, otherTarget.href, `<p>${probe.payload}</p>`);
  const mismatchResult = await runXssHypothesisTriage(f.root,
    input(f.reflection.evidence_id, mismatched.evidence_id),
    { approve: async () => { throw new Error("must not approve"); } });
  assert.equal(mismatchResult.ok, false);
  assert.equal(mismatchResult.code, "EVIDENCE_MISMATCH");

  const record = JSON.parse(await readFile(f.encoding.file_path, "utf8"));
  record.observation.request.url = record.observation.request.url.replace("/search?", "/other?");
  await writeFile(f.encoding.file_path, JSON.stringify(record));
  const result = await runXssHypothesisTriage(f.root,
    input(f.reflection.evidence_id, f.encoding.evidence_id),
    { approve: async () => { throw new Error("must not approve"); } });
  assert.equal(result.ok, false);
  assert.equal(result.code, "HASH_MISMATCH");
});

test("候选写入在批准不可用或拒绝时保持关闭", async t => {
  const f = await fixture(t);
  const unavailable = await runXssHypothesisTriage(f.root,
    input(f.reflection.evidence_id, f.encoding.evidence_id));
  assert.equal(unavailable.code, "APPROVAL_UNAVAILABLE");
  const denied = await runXssHypothesisTriage(f.root,
    input(f.reflection.evidence_id, f.encoding.evidence_id),
    { approve: async () => { throw new Error("denied"); } });
  assert.equal(denied.code, "APPROVAL_DENIED");
  assert.deepEqual(await readdir(path.join(f.root, "hypotheses", "opencode"))
    .catch(() => []), []);
});

test("OpenCode 工具参数固定，并仅在候选写入时使用专用批准项", async () => {
  assert.deepEqual(Object.keys(tool.args).sort(),
    ["authorization_reference", "encoding_evidence_id", "reflection_evidence_id"]);
  const output = JSON.parse(await tool.execute({
    reflection_evidence_id: "bad", encoding_evidence_id: "also-bad",
    authorization_reference: REFERENCE,
  }, {} as never) as string);
  assert.equal(output.code, "INVALID_INPUT");
  const agent = await readFile(new URL("../.opencode/agents/web-security-agent.md", import.meta.url), "utf8");
  assert.match(agent, /authorized_xss_hypothesis_triage: allow/u);
  assert.match(agent, /xss_hypothesis_record: ask/u);
});
