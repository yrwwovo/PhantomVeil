import assert from "node:assert/strict";
import { readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import type { HttpGetResult } from "../capabilities/web/restricted-http-get.ts";
import { EvidenceStore } from "../src/evidence/evidence-store.ts";
import {
  createHypothesis,
  transitionHypothesis,
} from "../src/hypotheses/hypothesis-manager.ts";

const observedResponse: HttpGetResult = {
  ok: true,
  code: "HTTP_RESPONSE",
  reason: "test",
  redirects: [],
  response: {
    url: "http://127.0.0.1:5000/",
    status: 200,
    headers: { "content-type": "text/html" },
    body: "test body",
    body_bytes: 9,
    resolved_ip: "127.0.0.1",
  },
};

function createExample() {
  return createHypothesis(
    {
      title: "安全响应头可能缺失",
      description: "等待独立规则验证",
      target_url: "http://127.0.0.1:5000/",
      reason: "人工提出待验证想法",
    },
    {
      now: () => new Date("2026-09-18T09:30:00.000Z"),
      id_factory: () => "abcdef12-0000-0000-0000-000000000000",
    },
  );
}

test("新建内容只能是 suspected，不会自动确认漏洞", () => {
  const result = createExample();
  assert.equal(result.ok, true);
  if (!result.ok) {
    return;
  }
  assert.equal(result.hypothesis.hypothesis_id, "HYP-20260918093000-abcdef12");
  assert.equal(result.hypothesis.status, "suspected");
  assert.equal(result.hypothesis.evidence.length, 0);
});

test("拒绝无效 URL 和空白创建原因", () => {
  const result = createHypothesis({
    title: "test",
    description: "test",
    target_url: "not-a-url",
    reason: " ",
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "INVALID_INPUT");
});

test("允许 suspected 进入 testing 并记录历史", async () => {
  const created = createExample();
  assert.equal(created.ok, true);
  if (!created.ok) {
    return;
  }
  const result = await transitionHypothesis(
    created.hypothesis,
    { to: "testing", reason: "开始验证" },
    { now: () => new Date("2026-09-18T09:31:00.000Z") },
  );
  assert.equal(result.ok, true);
  if (!result.ok) {
    return;
  }
  assert.equal(result.hypothesis.status, "testing");
  assert.equal(result.hypothesis.history.length, 2);
});

test("禁止从 suspected 跳过 testing 直接 confirmed", async () => {
  const created = createExample();
  assert.equal(created.ok, true);
  if (!created.ok) {
    return;
  }
  const result = await transitionHypothesis(created.hypothesis, {
    to: "confirmed",
    reason: "错误地直接确认",
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "INVALID_TRANSITION");
});

test("没有证据和复现步骤时不能 confirmed", async () => {
  const created = createExample();
  assert.equal(created.ok, true);
  if (!created.ok) {
    return;
  }
  const testing = await transitionHypothesis(created.hypothesis, {
    to: "testing",
    reason: "开始验证",
  });
  assert.equal(testing.ok, true);
  if (!testing.ok) {
    return;
  }
  const result = await transitionHypothesis(testing.hypothesis, {
    to: "confirmed",
    reason: "尝试确认",
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "CONFIRMATION_REQUIREMENTS_MISSING");
});

test("只有完整证据和复现步骤才能 confirmed", async (context) => {
  const outputDir = path.join(
    tmpdir(),
    `security-agent-hypothesis-${process.pid}-${Date.now()}`,
  );
  context.after(() => rm(outputDir, { recursive: true, force: true }));
  const saved = await new EvidenceStore({ output_dir: outputDir }).saveHttpGet(
    observedResponse,
  );
  assert.equal(saved.ok, true);
  if (!saved.ok) {
    return;
  }
  const created = createExample();
  assert.equal(created.ok, true);
  if (!created.ok) {
    return;
  }
  const testing = await transitionHypothesis(created.hypothesis, {
    to: "testing",
    reason: "开始验证",
  });
  assert.equal(testing.ok, true);
  if (!testing.ok) {
    return;
  }
  const result = await transitionHypothesis(testing.hypothesis, {
    to: "confirmed",
    reason: "已按步骤复现并保留证据",
    evidence_files: [saved.file_path],
    reproduction_steps: ["对授权目标执行一次可重复的只读请求"],
  });
  assert.equal(result.ok, true);
  if (!result.ok) {
    return;
  }
  assert.equal(result.hypothesis.status, "confirmed");
  assert.deepEqual(
    result.hypothesis.evidence.map((item) => item.evidence_id),
    [saved.evidence_id],
  );
});

test("证据被修改后不能用于确认", async (context) => {
  const outputDir = path.join(
    tmpdir(),
    `security-agent-hypothesis-tamper-${process.pid}-${Date.now()}`,
  );
  context.after(() => rm(outputDir, { recursive: true, force: true }));
  const saved = await new EvidenceStore({ output_dir: outputDir }).saveHttpGet(
    observedResponse,
  );
  assert.equal(saved.ok, true);
  if (!saved.ok) {
    return;
  }
  const record = JSON.parse(await readFile(saved.file_path, "utf8")) as {
    observation: { response: { body: string } };
  };
  record.observation.response.body = "tampered";
  await writeFile(saved.file_path, JSON.stringify(record), "utf8");

  const created = createExample();
  assert.equal(created.ok, true);
  if (!created.ok) {
    return;
  }
  const testing = await transitionHypothesis(created.hypothesis, {
    to: "testing",
    reason: "开始验证",
  });
  assert.equal(testing.ok, true);
  if (!testing.ok) {
    return;
  }
  const result = await transitionHypothesis(testing.hypothesis, {
    to: "confirmed",
    reason: "尝试确认",
    evidence_files: [saved.file_path],
    reproduction_steps: ["重复请求"],
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "EVIDENCE_INVALID");
});

test("confirmed 是终态，不能再随意改写", async (context) => {
  const outputDir = path.join(
    tmpdir(),
    `security-agent-hypothesis-terminal-${process.pid}-${Date.now()}`,
  );
  context.after(() => rm(outputDir, { recursive: true, force: true }));
  const saved = await new EvidenceStore({ output_dir: outputDir }).saveHttpGet(
    observedResponse,
  );
  assert.equal(saved.ok, true);
  if (!saved.ok) {
    return;
  }
  const created = createExample();
  assert.equal(created.ok, true);
  if (!created.ok) {
    return;
  }
  const testing = await transitionHypothesis(created.hypothesis, {
    to: "testing",
    reason: "开始验证",
  });
  assert.equal(testing.ok, true);
  if (!testing.ok) {
    return;
  }
  const confirmed = await transitionHypothesis(testing.hypothesis, {
    to: "confirmed",
    reason: "已复现",
    evidence_files: [saved.file_path],
    reproduction_steps: ["重复只读观察"],
  });
  assert.equal(confirmed.ok, true);
  if (!confirmed.ok) {
    return;
  }
  const result = await transitionHypothesis(confirmed.hypothesis, {
    to: "rejected",
    reason: "尝试覆盖结论",
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "INVALID_TRANSITION");
});
