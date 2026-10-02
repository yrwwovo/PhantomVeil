import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";

import tool from "../.opencode/tools/evidence_reflection_context.ts";
import { analyzeReflectionContext } from "../capabilities/web/reflection-context.ts";
import { runEvidenceReflectionContext } from "../src/adapters/opencode/evidence-reflection-context.ts";
import { EvidenceStore } from "../src/evidence/evidence-store.ts";

const MARKER = "PV-REFLECT-1234567890abcdef";

async function fixture(t: TestContext, options: { body?: string; contentType?: string; url?: string } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), "security-agent-context-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const body = options.body ?? `<p>${MARKER}</p>`;
  const saved = await new EvidenceStore({
    output_dir: path.join(root, "evidence", "opencode"),
    now: () => new Date("2026-09-24T08:00:00.000Z"),
    id_factory: () => "12345678-0000-0000-0000-000000000000",
  }).saveHttpGet({
    ok: true, code: "HTTP_RESPONSE", reason: "test", redirects: [],
    response: {
      url: options.url ?? `http://127.0.0.1:5000/search?q=${MARKER}`,
      status: 200, headers: { "content-type": options.contentType ?? "text/html; charset=utf-8" },
      body, body_bytes: Buffer.byteLength(body), resolved_ip: "127.0.0.1",
    },
  });
  assert.ok(saved.ok);
  return { root, saved };
}

test("离线区分文本、属性、脚本、样式和注释上下文", () => {
  const html = [
    `<p>${MARKER}</p>`, `<input value="${MARKER}">`,
    `<script>const value = "${MARKER}";</script>`,
    `<style>.x { content: "${MARKER}" }</style>`, `<!-- ${MARKER} -->`,
    `<a onclick="show('${MARKER}')">x</a>`,
  ].join("\n");
  const result = analyzeReflectionContext(html, MARKER);
  assert.equal(result.outcome, "sensitive_context_observed");
  assert.equal(result.marker_occurrences, 6);
  assert.equal(result.mapped_occurrences, 6);
  assert.deepEqual(result.contexts.map(item => item.context), [
    "html_text", "html_attribute", "script_data", "style_data", "html_comment", "html_attribute",
  ]);
  assert.equal(result.summary.sensitive, 3);
  assert.equal(result.contexts.at(-1)?.attribute_name, "onclick");
  assert.ok(result.contexts.every(item => item.encoding_assessment === "not_tested"));
  assert.doesNotMatch(JSON.stringify(result), /XSS 漏洞已确认|确认存在 XSS|编码安全/u);
});

test("普通文本反射只记录位置，不误报 XSS", () => {
  const result = analyzeReflectionContext(`<p>结果：${MARKER}</p>`, MARKER);
  assert.equal(result.outcome, "ordinary_context_observed");
  assert.equal(result.contexts[0].context, "html_text");
  assert.match(result.conclusion, /无法证明/u);
});

test("空白或伪造标记不会进入 HTML 遍历", () => {
  for (const marker of ["", "MARK", "PV-REFLECT-../../outside"]) {
    const result = analyzeReflectionContext(`<p>${marker}</p>`, marker);
    assert.equal(result.outcome, "inconclusive");
    assert.match(result.conclusion, /格式无效/u);
  }
});

test("适配层自动从请求 URL 提取标记并只读分析可信 EV", async t => {
  const { root, saved } = await fixture(t, { body: `<input value="${MARKER}"><p>${MARKER}</p>` });
  const before = await readFile(saved.file_path, "utf8");
  const result = await runEvidenceReflectionContext(root, { evidence_id: saved.evidence_id });
  assert.equal(result.ok, true);
  assert.equal(result.code, "REFLECTION_CONTEXT_COMPLETED");
  if (result.ok) {
    assert.equal(result.result.summary.html_attribute, 1);
    assert.equal(result.result.summary.html_text, 1);
  }
  assert.equal(await readFile(saved.file_path, "utf8"), before);
});

test("非 HTML、普通 EV、多个标记和篡改证据均被拒绝", async t => {
  const notHtml = await fixture(t, { contentType: "application/json" });
  assert.equal((await runEvidenceReflectionContext(notHtml.root,
    { evidence_id: notHtml.saved.evidence_id })).code, "NOT_HTML");

  const ordinary = await fixture(t, { url: "http://127.0.0.1:5000/search?q=hello" });
  assert.equal((await runEvidenceReflectionContext(ordinary.root,
    { evidence_id: ordinary.saved.evidence_id })).code, "MARKER_NOT_FOUND");

  const second = "PV-REFLECT-fedcba0987654321";
  const ambiguous = await fixture(t, { url: `http://127.0.0.1:5000/search?q=${MARKER}&other=${second}` });
  assert.equal((await runEvidenceReflectionContext(ambiguous.root,
    { evidence_id: ambiguous.saved.evidence_id })).code, "AMBIGUOUS_MARKER");

  const tampered = await fixture(t);
  const record = JSON.parse(await readFile(tampered.saved.file_path, "utf8"));
  record.observation.response.body += MARKER;
  await writeFile(tampered.saved.file_path, JSON.stringify(record), "utf8");
  assert.equal((await runEvidenceReflectionContext(tampered.root,
    { evidence_id: tampered.saved.evidence_id })).code, "HASH_MISMATCH");
});

test("OpenCode 工具只接受 EV 编号且不要求网络审批", async () => {
  assert.deepEqual(Object.keys(tool.args), ["evidence_id"]);
  const output = JSON.parse(await tool.execute({ evidence_id: "../outside" }, {} as never) as string);
  assert.equal(output.code, "INVALID_ID");
  const source = await readFile(new URL("../.opencode/tools/evidence_reflection_context.ts", import.meta.url), "utf8");
  assert.match(source, /new URL\("\.\.\/\.\.\/", import\.meta\.url\)/u);
  assert.doesNotMatch(source, /context\.ask|fetch\(/u);
});
