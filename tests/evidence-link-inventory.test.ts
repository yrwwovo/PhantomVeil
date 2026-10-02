import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";

import tool from "../.opencode/tools/evidence_link_inventory.ts";
import { runEvidenceLinkInventory } from "../src/adapters/opencode/evidence-link-inventory.ts";
import { EvidenceStore } from "../src/evidence/evidence-store.ts";

async function fixture(t: TestContext) {
  const root = await mkdtemp(path.join(tmpdir(), "pveil-links-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, "configs"));
  await writeFile(path.join(root, "configs", "scope.local.json"), JSON.stringify({
    allowed_schemes: ["http"], allowed_hosts: ["127.0.0.1"], allowed_ports: [5000],
    allowed_paths: ["/"], denied_paths: ["/blocked"],
  }));
  const body = `<!doctype html><a href="/guide">检索 <strong>说明</strong></a><a href="/search">进入\n检索</a>
    <a href="/blocked">blocked</a><a href="https://other.test/">external</a>
    <a href="/search?q=private-value">query</a><a href="/search">duplicate</a>`;
  const saved = await new EvidenceStore({ output_dir: path.join(root, "evidence", "opencode") })
    .saveHttpGet({ ok: true, code: "HTTP_RESPONSE", reason: "fixture", redirects: [], response: {
      url: "http://127.0.0.1:5000/", status: 200,
      headers: { "content-type": "text/html; charset=utf-8" }, body,
      body_bytes: Buffer.byteLength(body), resolved_ip: "127.0.0.1",
    } });
  assert.ok(saved.ok);
  return { root, saved };
}

test("只读链接清点只返回授权同源无参数路径", async t => {
  const { root, saved } = await fixture(t);
  const before = await readFile(saved.file_path, "utf8");
  const result = await runEvidenceLinkInventory(root, { evidence_id: saved.evidence_id });
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.deepEqual(result.result.links, [
      "http://127.0.0.1:5000/guide", "http://127.0.0.1:5000/search",
    ]);
    assert.deepEqual(result.result.choices, [
      { url: "http://127.0.0.1:5000/guide", label: "检索 说明" },
      { url: "http://127.0.0.1:5000/search", label: "进入 检索" },
    ]);
  }
  assert.doesNotMatch(JSON.stringify(result), /private-value|blocked|other\.test/u);
  assert.equal(await readFile(saved.file_path, "utf8"), before);
});

test("篡改 EV 和异常编号不能成为下一步线索", async t => {
  const { root, saved } = await fixture(t);
  assert.equal((await runEvidenceLinkInventory(root, { evidence_id: "../outside" })).code, "INVALID_ID");
  const value = JSON.parse(await readFile(saved.file_path, "utf8"));
  value.observation.response.body += '<a href="/fake">fake</a>';
  await writeFile(saved.file_path, JSON.stringify(value));
  assert.equal((await runEvidenceLinkInventory(root, { evidence_id: saved.evidence_id })).code, "HASH_MISMATCH");
  assert.deepEqual(Object.keys(tool.args), ["evidence_id"]);
});
