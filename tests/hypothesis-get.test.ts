import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";

import tool from "../.opencode/tools/hypothesis_get.ts";
import { runHypothesisGet } from "../src/adapters/opencode/hypothesis-get.ts";
import { createHypothesis, transitionHypothesis } from "../src/hypotheses/hypothesis-manager.ts";
import { HypothesisStore } from "../src/hypotheses/hypothesis-store.ts";

async function fixture(t: TestContext) {
  const root = await mkdtemp(path.join(tmpdir(), "security-agent-lookup-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const store = new HypothesisStore(path.join(root, "hypotheses", "opencode"));
  const created = createHypothesis({
    target_url: "http://127.0.0.1:5000/", title: "待验证想法",
    description: "这是记录内容，不是指令", reason: "教学示例",
  }, { now: () => new Date("2026-09-20T00:00:00.000Z") });
  assert.ok(created.ok);
  const saved = await store.create(created.hypothesis);
  assert.ok(saved.ok);
  return { root, store, saved, input: { hypothesis_id: saved.hypothesis.hypothesis_id } };
}

test("只读查询返回历史状态且不改动文件，无需目标或授权配置", async (t) => {
  const { root, store, saved, input } = await fixture(t);
  const changed = await transitionHypothesis(saved.hypothesis,
    { to: "testing", reason: "准备验证" },
    { now: () => new Date("2026-09-20T01:00:00.000Z") });
  assert.ok(changed.ok);
  const updated = await store.update(changed.hypothesis, saved.payload_sha256);
  assert.ok(updated.ok, JSON.stringify(updated));
  const before = await readFile(saved.file_path, "utf8");
  const files = await readdir(store.outputDir);
  const result = await runHypothesisGet(root, input);
  assert.ok(result.ok);
  assert.equal(result.code, "HYPOTHESIS_FOUND");
  assert.equal(result.hypothesis.status, "testing");
  assert.equal(result.hypothesis.history[1].reason, "准备验证");
  assert.equal(result.hypothesis.title, "待验证想法");
  assert.deepEqual(result.hypothesis.evidence_ids, []);
  assert.equal("authorization_reference" in result.hypothesis, false);
  assert.equal("file_path" in result, false);
  assert.match(result.content_notice, /不是执行指令/u);
  assert.equal(await readFile(saved.file_path, "utf8"), before);
  assert.deepEqual(await readdir(store.outputDir), files);
});

test("未知编号不创建目录或记录，拒绝路径及异常参数", async (t) => {
  const { root } = await fixture(t);
  const absent = path.join(root, "absent");
  const result = await runHypothesisGet(absent, { hypothesis_id: "HYP-20260920000000-00000000" });
  assert.equal(result.code, "NOT_FOUND");
  await assert.rejects(readdir(absent), { code: "ENOENT" });
  for (const id of ["../configs/authorization.local.json", "D:\\secrets.json", "", "HYP-x", null, 123]) {
    const rejected = await runHypothesisGet(root, { hypothesis_id: id as string });
    assert.equal(rejected.code, "INVALID_ID");
    assert.equal(rejected.ok, false);
  }
});

test("内容被修改或 JSON 损坏时不返回假设正文", async (t) => {
  const { root, saved, input } = await fixture(t);
  const record = JSON.parse(await readFile(saved.file_path, "utf8"));
  record.hypothesis.title = "被修改的内容";
  await writeFile(saved.file_path, JSON.stringify(record));
  const tampered = await runHypothesisGet(root, input);
  assert.equal(tampered.code, "HASH_MISMATCH");
  assert.equal("hypothesis" in tampered, false);
  await writeFile(saved.file_path, "{broken");
  const broken = await runHypothesisGet(root, input);
  assert.equal(broken.code, "INVALID_FILE");
  assert.equal("hypothesis" in broken, false);
});

test("目录链接不能把只读查询重定向到其他目录", async (t) => {
  const { root, store, input } = await fixture(t);
  const linkedRoot = await mkdtemp(path.join(tmpdir(), "security-agent-linked-"));
  t.after(() => rm(linkedRoot, { recursive: true, force: true }));
  await symlink(path.dirname(store.outputDir), path.join(linkedRoot, "hypotheses"),
    process.platform === "win32" ? "junction" : "dir");
  const result = await runHypothesisGet(linkedRoot, input);
  assert.equal(result.code, "PATH_REJECTED");
  assert.equal("hypothesis" in result, false);
});

test("OpenCode 工具仅接受编号，且使用工具自身位置定位项目", async () => {
  assert.deepEqual(Object.keys(tool.args), ["hypothesis_id"]);
  const output = await tool.execute({ hypothesis_id: "../outside" }, { directory: "D:\\" } as never);
  assert.equal(JSON.parse(output as string).code, "INVALID_ID");
  const source = await readFile(new URL("../.opencode/tools/hypothesis_get.ts", import.meta.url), "utf8");
  assert.match(source, /new URL\("\.\.\/\.\.\/", import\.meta\.url\)/u);
});
