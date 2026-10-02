import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";

import tool from "../.opencode/tools/evidence_input_inventory.ts";
import { inventoryPageInputs } from "../capabilities/web/input-inventory.ts";
import { runEvidenceInputInventory } from "../src/adapters/opencode/evidence-input-inventory.ts";
import { EvidenceStore } from "../src/evidence/evidence-store.ts";

const HTML = `<!doctype html><html><head><base href="/app/"></head><body>
  <form id="login" action="login?flow=visible-value" method="POST">
    <input name="username" value="DO_NOT_RETURN">
    <input name="password" type="password" required value="SECRET_PASSWORD">
    <input name="csrf" type="hidden" value="SECRET_TOKEN" disabled>
    <button name="clicked" value="yes">登录</button>
  </form>
  <input form="login" name="outside" type="text">
  <form action="https://other.test/upload"><input name="file" type="file"></form>
  <form action="javascript:alert(1)"><input name="bad"></form>
  <a href="/search?q=secret-value&lang=zh">search</a>
  <a href="/search?page=2&q=another-secret">next</a>
  <script>const x = '<form action="/script"><input name="scripted"></form>'</script>
  <template><form action="/template"><input name="templated"></form></template>
</body></html>`;

async function fixture(t: TestContext, contentType = "text/html; charset=utf-8") {
  const root = await mkdtemp(path.join(tmpdir(), "security-agent-input-inventory-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const saved = await new EvidenceStore({
    output_dir: path.join(root, "evidence", "opencode"),
    now: () => new Date("2026-09-22T08:00:00.000Z"),
    id_factory: () => "12345678-0000-0000-0000-000000000000",
  }).saveHttpGet({
    ok: true,
    code: "HTTP_RESPONSE",
    reason: "test",
    redirects: [],
    response: {
      url: "http://127.0.0.1:5000/",
      status: 200,
      headers: { "content-type": contentType },
      body: HTML,
      body_bytes: Buffer.byteLength(HTML),
      resolved_ip: "127.0.0.1",
    },
  });
  assert.ok(saved.ok);
  return { root, saved };
}

test("静态 HTML 中的表单、外部关联控件和查询参数名称可被清点", () => {
  const result = inventoryPageInputs(HTML, "http://127.0.0.1:5000/");
  assert.deepEqual(result.summary, {
    forms: 3,
    controls: 7,
    named_form_parameters: 5,
    query_endpoints: 1,
  });
  assert.equal(result.forms[0].method, "post");
  assert.equal(result.forms[0].action, "http://127.0.0.1:5000/app/login");
  assert.deepEqual(result.forms[0].action_query_parameters, ["flow"]);
  assert.deepEqual(result.forms[0].parameter_names, ["username", "password", "outside"]);
  assert.equal(result.forms[0].controls.find(item => item.name === "password")?.required, true);
  assert.equal(result.forms[1].same_origin, false);
  assert.equal(result.forms[2].action_valid, false);
  assert.deepEqual(result.query_endpoints, [{
    endpoint: "http://127.0.0.1:5000/search",
    same_origin: true,
    parameter_names: ["q", "lang", "page"],
  }]);
  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /DO_NOT_RETURN|SECRET_PASSWORD|SECRET_TOKEN|secret-value|another-secret/u);
  assert.doesNotMatch(serialized, /scripted|templated/u);
  assert.match(result.conclusion, /不表示存在漏洞/u);
});

test("适配层只读分析完整性校验通过的 HTML 证据", async (t) => {
  const { root, saved } = await fixture(t);
  const before = await readFile(saved.file_path, "utf8");
  const files = await readdir(path.dirname(saved.file_path));
  const result = await runEvidenceInputInventory(root, { evidence_id: saved.evidence_id });
  assert.equal(result.ok, true);
  assert.equal(result.code, "INPUT_INVENTORY_COMPLETED");
  if (result.ok) assert.equal(result.result.summary.forms, 3);
  assert.equal(await readFile(saved.file_path, "utf8"), before);
  assert.deepEqual(await readdir(path.dirname(saved.file_path)), files);
});

test("非 HTML 证据不会套用页面输入清点", async (t) => {
  const { root, saved } = await fixture(t, "application/json");
  const result = await runEvidenceInputInventory(root, { evidence_id: saved.evidence_id });
  assert.equal(result.ok, false);
  assert.equal(result.code, "NOT_HTML");
});

test("错误编号、篡改证据和目录链接均被拒绝", async (t) => {
  const { root, saved } = await fixture(t);
  for (const evidenceId of ["../record.json", "C:\\record.json", "", "EV-x"] as string[]) {
    const result = await runEvidenceInputInventory(root, { evidence_id: evidenceId });
    assert.equal(result.code, "INVALID_ID");
  }
  const record = JSON.parse(await readFile(saved.file_path, "utf8"));
  record.observation.response.body += "<form><input name='tampered'></form>";
  await writeFile(saved.file_path, JSON.stringify(record), "utf8");
  const tampered = await runEvidenceInputInventory(root, { evidence_id: saved.evidence_id });
  assert.equal(tampered.code, "HASH_MISMATCH");

  const linkedRoot = await mkdtemp(path.join(tmpdir(), "security-agent-input-linked-"));
  t.after(() => rm(linkedRoot, { recursive: true, force: true }));
  await symlink(path.join(root, "evidence"), path.join(linkedRoot, "evidence"),
    process.platform === "win32" ? "junction" : "dir");
  const linked = await runEvidenceInputInventory(linkedRoot, { evidence_id: saved.evidence_id });
  assert.equal(linked.code, "PATH_REJECTED");
});

test("OpenCode 工具只接受 EV 编号并使用模块位置定位项目", async () => {
  assert.deepEqual(Object.keys(tool.args), ["evidence_id"]);
  const output = await tool.execute({ evidence_id: "../outside" }, { directory: "D:\\" } as never);
  assert.equal(JSON.parse(output as string).code, "INVALID_ID");
  const source = await readFile(new URL("../.opencode/tools/evidence_input_inventory.ts", import.meta.url), "utf8");
  assert.match(source, /new URL\("\.\.\/\.\.\/", import\.meta\.url\)/u);
});
