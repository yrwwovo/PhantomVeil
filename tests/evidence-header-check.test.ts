import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";

import tool from "../.opencode/tools/evidence_header_check.ts";
import { checkHttpSecurityHeaders } from "../capabilities/web/security-header-check.ts";
import { runEvidenceHeaderCheck } from "../src/adapters/opencode/evidence-header-check.ts";
import { EvidenceStore, loadVerifiedEvidenceFile } from "../src/evidence/evidence-store.ts";

async function fixture(
  t: TestContext,
  url = "http://127.0.0.1:5000/",
  headers: Record<string, string | string[]> = { "content-type": "text/html; charset=utf-8" },
) {
  const root = await mkdtemp(path.join(tmpdir(), "security-agent-header-check-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const outputDir = path.join(root, "evidence", "opencode");
  const saved = await new EvidenceStore({
    output_dir: outputDir,
    now: () => new Date("2026-09-22T00:00:00.000Z"),
    id_factory: () => "12345678-0000-0000-0000-000000000000",
  }).saveHttpGet({
    ok: true,
    code: "HTTP_RESPONSE",
    reason: "test",
    redirects: [],
    response: {
      url,
      status: 200,
      headers,
      body: "<html>lab</html>",
      body_bytes: 16,
      resolved_ip: "127.0.0.1",
    },
  });
  assert.ok(saved.ok);
  return { root, saved, input: { evidence_id: saved.evidence_id } };
}

test("HTML 证据缺少安全头时只标记需要复核，不确认漏洞", async (t) => {
  const { saved } = await fixture(t);
  const loaded = await loadVerifiedEvidenceFile(saved.file_path);
  assert.ok(loaded.ok);
  const result = checkHttpSecurityHeaders(loaded.record);
  assert.deepEqual(result.summary, { pass: 1, review: 3, not_applicable: 1 });
  assert.equal(result.classification, "configuration_review");
  assert.match(result.conclusion, /不是已确认漏洞/u);
  assert.ok(result.findings.every((item) => item.evidence_id === saved.evidence_id));
  assert.equal(result.findings.find((item) => item.rule_id === "HDR-HSTS")?.status, "not_applicable");
});

test("HTTPS HTML 的有效头组合通过五项规则，大小写名称也能识别", async (t) => {
  const { saved } = await fixture(t, "https://127.0.0.1:5000/", {
    "Content-Type": "text/html; charset=UTF-8",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  });
  const loaded = await loadVerifiedEvidenceFile(saved.file_path);
  assert.ok(loaded.ok);
  const result = checkHttpSecurityHeaders(loaded.record);
  assert.deepEqual(result.summary, { pass: 5, review: 0, not_applicable: 0 });
  assert.match(result.conclusion, /不代表目标不存在其他安全问题/u);
});

test("非 HTML 响应不套用 CSP 和页面嵌入规则", async (t) => {
  const { saved } = await fixture(t, "http://127.0.0.1:5000/api", {
    "content-type": "application/json",
    "x-content-type-options": "nosniff",
  });
  const loaded = await loadVerifiedEvidenceFile(saved.file_path);
  assert.ok(loaded.ok);
  const result = checkHttpSecurityHeaders(loaded.record);
  assert.deepEqual(result.summary, { pass: 2, review: 0, not_applicable: 3 });
});

test("适配层只读分析已有证据且不改变文件", async (t) => {
  const { root, saved, input } = await fixture(t);
  const before = await readFile(saved.file_path, "utf8");
  const files = await readdir(path.dirname(saved.file_path));
  const result = await runEvidenceHeaderCheck(root, input);
  assert.ok(result.ok);
  assert.equal(result.code, "HEADER_CHECK_COMPLETED");
  assert.equal(result.result.evidence_id, input.evidence_id);
  assert.equal(await readFile(saved.file_path, "utf8"), before);
  assert.deepEqual(await readdir(path.dirname(saved.file_path)), files);
});

test("错误编号、路径形式及被修改的证据均被拒绝", async (t) => {
  const { root, saved, input } = await fixture(t);
  for (const id of ["../evidence.json", "C:\\evidence.json", "", "EV-x", null, 123]) {
    const result = await runEvidenceHeaderCheck(root, { evidence_id: id as string });
    assert.equal(result.code, "INVALID_ID");
  }
  const record = JSON.parse(await readFile(saved.file_path, "utf8"));
  record.observation.response.headers["content-security-policy"] = "default-src 'self'";
  await writeFile(saved.file_path, JSON.stringify(record), "utf8");
  const tampered = await runEvidenceHeaderCheck(root, input);
  assert.equal(tampered.code, "HASH_MISMATCH");
  assert.equal("result" in tampered, false);
});

test("目录链接不能将证据检查重定向到其他项目", async (t) => {
  const { root, input } = await fixture(t);
  const linkedRoot = await mkdtemp(path.join(tmpdir(), "security-agent-evidence-linked-"));
  t.after(() => rm(linkedRoot, { recursive: true, force: true }));
  await symlink(path.join(root, "evidence"), path.join(linkedRoot, "evidence"),
    process.platform === "win32" ? "junction" : "dir");
  const result = await runEvidenceHeaderCheck(linkedRoot, input);
  assert.equal(result.code, "PATH_REJECTED");
});

test("OpenCode 工具只接受 EV 编号并从工具位置定位项目", async () => {
  assert.deepEqual(Object.keys(tool.args), ["evidence_id"]);
  const output = await tool.execute({ evidence_id: "../outside" }, { directory: "D:\\" } as never);
  assert.equal(JSON.parse(output as string).code, "INVALID_ID");
  const source = await readFile(new URL("../.opencode/tools/evidence_header_check.ts", import.meta.url), "utf8");
  assert.match(source, /new URL\("\.\.\/\.\.\/", import\.meta\.url\)/u);
  const agent = await readFile(new URL("../.opencode/agents/web-security-agent.md", import.meta.url), "utf8");
  assert.match(agent, /evidence_header_check: allow/u);
  assert.match(agent, /review.*需要复核/u);
});
