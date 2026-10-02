import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";

import {
  createHypothesis,
  transitionHypothesis,
} from "../src/hypotheses/hypothesis-manager.ts";
import { HypothesisStore } from "../src/hypotheses/hypothesis-store.ts";

async function temporaryStore(context: TestContext): Promise<HypothesisStore> {
  const root = await mkdtemp(path.join(tmpdir(), "security-agent-hypothesis-store-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  return new HypothesisStore(path.join(root, "hypotheses"));
}

function exampleHypothesis() {
  const created = createHypothesis({
    title: "待验证的安全猜想",
    description: "仅用于持久化测试",
    target_url: "http://127.0.0.1:5000/",
    reason: "人工提出测试想法",
  });
  assert.equal(created.ok, true);
  if (!created.ok) throw new Error("无法创建测试假设");
  return created.hypothesis;
}

test("假设保存后可由新 Store 实例重新加载", async (context) => {
  const store = await temporaryStore(context);
  const hypothesis = exampleHypothesis();
  const saved = await store.create(hypothesis);
  assert.equal(saved.ok, true);
  if (!saved.ok) return;

  const reopened = await new HypothesisStore(store.outputDir).load(hypothesis.hypothesis_id);
  assert.equal(reopened.ok, true);
  if (!reopened.ok) return;
  assert.deepEqual(reopened.hypothesis, hypothesis);
  assert.equal(reopened.payload_sha256, saved.payload_sha256);
  assert.equal(reopened.hypothesis.status, "suspected");
});

test("更新只追加一次合法状态变化，重启后仍保留历史", async (context) => {
  const store = await temporaryStore(context);
  const first = await store.create(exampleHypothesis());
  assert.equal(first.ok, true);
  if (!first.ok) return;
  const transitioned = await transitionHypothesis(first.hypothesis, {
    to: "testing",
    reason: "开始进行只读验证",
  });
  assert.equal(transitioned.ok, true);
  if (!transitioned.ok) return;

  const updated = await store.update(transitioned.hypothesis, first.payload_sha256);
  assert.equal(updated.ok, true);
  if (!updated.ok) return;
  const reopened = await new HypothesisStore(store.outputDir).load(first.hypothesis.hypothesis_id);
  assert.equal(reopened.ok, true);
  if (!reopened.ok) return;
  assert.equal(reopened.hypothesis.status, "testing");
  assert.equal(reopened.hypothesis.history.length, 2);
  assert.equal(reopened.payload_sha256, updated.payload_sha256);
  assert.deepEqual(await readdir(store.outputDir), [`${first.hypothesis.hypothesis_id}.json`]);
});

test("旧版本不能覆盖已更新的假设", async (context) => {
  const store = await temporaryStore(context);
  const first = await store.create(exampleHypothesis());
  assert.equal(first.ok, true);
  if (!first.ok) return;
  const transitioned = await transitionHypothesis(first.hypothesis, {
    to: "testing", reason: "开始验证",
  });
  assert.equal(transitioned.ok, true);
  if (!transitioned.ok) return;
  const updated = await store.update(transitioned.hypothesis, first.payload_sha256);
  assert.equal(updated.ok, true);
  if (!updated.ok) return;

  const stale = await store.update(transitioned.hypothesis, first.payload_sha256);
  assert.equal(stale.ok, false);
  assert.equal(stale.code, "VERSION_CONFLICT");
  const loaded = await store.load(first.hypothesis.hypothesis_id);
  assert.equal(loaded.ok, true);
  if (loaded.ok) assert.equal(loaded.payload_sha256, updated.payload_sha256);
});

test("修改文件正文后拒绝加载", async (context) => {
  const store = await temporaryStore(context);
  const saved = await store.create(exampleHypothesis());
  assert.equal(saved.ok, true);
  if (!saved.ok) return;
  const record = JSON.parse(await readFile(saved.file_path, "utf8")) as {
    hypothesis: { title: string };
  };
  record.hypothesis.title = "未经授权修改的标题";
  await writeFile(saved.file_path, JSON.stringify(record), "utf8");

  const loaded = await store.load(saved.hypothesis.hypothesis_id);
  assert.equal(loaded.ok, false);
  assert.equal(loaded.code, "HASH_MISMATCH");
});

test("错误 JSON 被拒绝，非法状态历史不能更新", async (context) => {
  const store = await temporaryStore(context);
  const saved = await store.create(exampleHypothesis());
  assert.equal(saved.ok, true);
  if (!saved.ok) return;
  await writeFile(saved.file_path, "{broken json", "utf8");
  const broken = await store.load(saved.hypothesis.hypothesis_id);
  assert.equal(broken.ok, false);
  assert.equal(broken.code, "INVALID_FILE");

  const altered = structuredClone(saved.hypothesis);
  altered.status = "confirmed";
  const rejected = await store.update(altered, saved.payload_sha256);
  assert.equal(rejected.ok, false);
  assert.equal(rejected.code, "INVALID_HYPOTHESIS");
});

test("即使重新计算指纹，非法状态历史也不能加载", async (context) => {
  const store = await temporaryStore(context);
  const saved = await store.create(exampleHypothesis());
  assert.equal(saved.ok, true);
  if (!saved.ok) return;
  const record = JSON.parse(await readFile(saved.file_path, "utf8")) as {
    schema_version: number;
    hypothesis: { history: Array<{ to: string }> };
    integrity: { payload_sha256: string };
  };
  record.hypothesis.history[0].to = "confirmed";
  record.integrity.payload_sha256 = createHash("sha256")
    .update(JSON.stringify({
      schema_version: record.schema_version,
      hypothesis: record.hypothesis,
    }))
    .digest("hex");
  await writeFile(saved.file_path, JSON.stringify(record), "utf8");

  const loaded = await store.load(saved.hypothesis.hypothesis_id);
  assert.equal(loaded.ok, false);
  assert.equal(loaded.code, "INVALID_FILE");
});

test("拒绝路径穿越和重复编号，不覆盖已有文件", async (context) => {
  const store = await temporaryStore(context);
  const hypothesis = exampleHypothesis();
  const first = await store.create(hypothesis);
  assert.equal(first.ok, true);
  if (!first.ok) return;
  const duplicate = await store.create(hypothesis);
  assert.equal(duplicate.ok, false);
  assert.equal(duplicate.code, "ALREADY_EXISTS");

  const traversal = await store.load("../../scope.local.json");
  assert.equal(traversal.ok, false);
  assert.equal(traversal.code, "INVALID_ID");
  const original = await store.load(hypothesis.hypothesis_id);
  assert.equal(original.ok, true);
  if (original.ok) assert.equal(original.payload_sha256, first.payload_sha256);
});

test("伪造证据引用不能随更新写入", async (context) => {
  const store = await temporaryStore(context);
  const saved = await store.create(exampleHypothesis());
  assert.equal(saved.ok, true);
  if (!saved.ok) return;
  const transitioned = await transitionHypothesis(saved.hypothesis, {
    to: "testing", reason: "开始验证",
  });
  assert.equal(transitioned.ok, true);
  if (!transitioned.ok) return;
  transitioned.hypothesis.evidence.push({
    evidence_id: "EV-fake",
    file_path: path.join(store.outputDir, "missing-evidence.json"),
    payload_sha256: "0".repeat(64),
  });
  const result = await store.update(transitioned.hypothesis, saved.payload_sha256);
  assert.equal(result.ok, false);
  assert.equal(result.code, "INVALID_HYPOTHESIS");
});

test("超过大小限制的假设不会生成无法再次读取的文件", async (context) => {
  const store = await temporaryStore(context);
  const hypothesis = exampleHypothesis();
  hypothesis.description = "x".repeat(1024 * 1024);
  const result = await store.create(hypothesis);
  assert.equal(result.ok, false);
  assert.equal(result.code, "INVALID_HYPOTHESIS");
});
