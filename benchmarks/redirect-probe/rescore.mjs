import { createHash, randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import { normalizeOpenCodeEvents } from "../../src/adapters/opencode/run-events.ts";
import { scoreRedirectProbeRun } from "../../src/evaluation/redirect-probe-score.ts";

const resultFile = process.argv[2];
if (!resultFile || path.basename(resultFile) !== "result.json" || process.argv.length !== 3) {
  throw new Error("用法：node benchmarks/redirect-probe/rescore.mjs <本机运行目录/result.json>");
}
const raw = await readFile(resultFile);
const result = JSON.parse(raw.toString("utf8"));
const lines = (await readFile(result.raw_events_file, "utf8")).trim().split(/\r?\n/u);
const events = normalizeOpenCodeEvents(lines.map(line => JSON.parse(line)));
let score = await scoreRedirectProbeRun(result.task, result.isolated_workspace ??
  path.join(path.dirname(resultFile), "agent-workspace"), events,
result.fixture_requests, result.approval);
if (score.passed && (!result.request_budget.state_recorded ||
    result.request_budget.used_requests !== result.fixture_requests.length ||
    result.request_budget.used_requests > 3)) {
  score = { ...score, passed: false, reason: "会话请求预算与靶站实际请求不一致" };
}
const scorerFile = path.resolve(import.meta.dirname, "../../src/evaluation/redirect-probe-score.ts");
const record = { run_id: result.run_id, original_result_sha256: createHash("sha256").update(raw).digest("hex"),
  scorer_sha256: createHash("sha256").update(await readFile(scorerFile)).digest("hex"),
  rescored_at: new Date().toISOString(), original_score: result.score, score };
const outputFile = path.join(path.dirname(resultFile), `rescore-${randomUUID().slice(0, 8)}.json`);
await writeFile(outputFile, `${JSON.stringify(record, null, 2)}\n`, { flag: "wx", mode: 0o600 });
console.log(JSON.stringify({ run_id: result.run_id, rescore_file: outputFile,
  original_passed: result.score.passed, passed: score.passed, reason: score.reason }, null, 2));
if (!score.passed) process.exitCode = 1;
