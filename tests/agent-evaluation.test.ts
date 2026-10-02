import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { normalizeOpenCodeEvents } from "../src/adapters/opencode/run-events.ts";
import { EvidenceStore } from "../src/evidence/evidence-store.ts";
import { scoreObservationRun } from "../src/evaluation/observation-score.ts";

test("真实运行事件保留最终工具状态、回答和 Token 计数", () => {
  const result = normalizeOpenCodeEvents([
    { type: "tool_use", part: { type: "tool", callID: "call-1", tool: "authorized_web_observe",
      state: { status: "running", input: { url: "http://127.0.0.1/" } } } },
    { type: "tool_use", part: { type: "tool", callID: "call-1", tool: "authorized_web_observe",
      state: { status: "completed", output: "{\"ok\":true}" } } },
    { type: "text", part: { type: "text", text: "HTTP 200" } },
    { type: "step_finish", part: { type: "step-finish", tokens: { input: 12, output: 3 } } },
  ]);
  assert.equal(result.tools.length, 1);
  assert.equal(result.tools[0].status, "completed");
  assert.equal(result.final_text, "HTTP 200");
  assert.deepEqual(result.token_usage, { input: 12, output: 3 });
});

test("独立评分要求实际请求、完整证据和正确回答；篡改证据或空口回答失败", async context => {
  const workspace = await mkdtemp(path.join(tmpdir(), "pveil-agent-score-"));
  context.after(() => rm(workspace, { recursive: true, force: true }));
  const evidenceDir = path.join(workspace, "evidence", "opencode");
  await mkdir(evidenceDir, { recursive: true });
  const url = "http://127.0.0.1:5000/";
  const saved = await new EvidenceStore({ output_dir: evidenceDir }).saveHttpGet({
    ok: true, redirects: [], response: {
      url, status: 200, headers: { "content-type": "text/html" },
      body: "<p>fixture</p>", body_bytes: 14, resolved_ip: "127.0.0.1",
    },
  } as never);
  assert.equal(saved.ok, true);
  if (!saved.ok) return;
  const task = { id: "observation-test", url, expected_status: 200 };
  const events = normalizeOpenCodeEvents([
    { type: "tool_use", part: { type: "tool", callID: "call-1", tool: "authorized_web_observe",
      state: { status: "completed", output: JSON.stringify({
        ok: true, evidence_id: saved.evidence_id, evidence_file: saved.file_path,
      }) } } },
    { type: "text", part: { type: "text", text: "观察到 HTTP 200" } },
  ]);
  const hits = [{ method: "GET", pathname: "/" }];
  assert.equal((await scoreObservationRun(task, workspace, events, hits)).passed, true);
  assert.equal((await scoreObservationRun(task, workspace,
    { ...events, tools: [] }, hits)).passed, false);
  assert.equal((await scoreObservationRun(task, workspace, events,
    [...hits, ...hits])).passed, false);

  const raw = await readFile(saved.file_path, "utf8");
  await writeFile(saved.file_path, raw.replace('"status": 200', '"status": 500'));
  const tampered = await scoreObservationRun(task, workspace, events, hits);
  assert.equal(tampered.passed, false);
  assert.match(tampered.reason, /证据完整性/u);
});
